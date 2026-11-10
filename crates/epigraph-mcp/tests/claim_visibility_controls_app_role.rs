//! User-level claim visibility controls (docs/tenancy/claim-visibility-controls.md,
//! migration 206) on the APPLICATION ROLE.
//!
//! Every server here is built from ONE `ScopedPool` downgraded to `epigraph_app`
//! (NOSUPERUSER, NOBYPASSRLS), and every "who can read it" question is asked on
//! a connection of that pool stamped as the reader. A superuser pool would
//! admit every row and prove nothing. Seeding runs on the superuser pool.
//!
//! What is pinned:
//! * a write that names no visibility lands in the author's team; a teammate
//!   reads it and a non-member cannot; its evidence and trace follow it;
//! * `private` and `public` writes;
//! * a `reader` membership is refused a team write, with nothing written, and
//!   so is a non-member;
//! * D-V1's fallbacks: several teams and no default go private with a note, and
//!   `set_default_group` picks the team;
//! * D-V3: an operated agent writes into a team its live human writes;
//! * D-V4: a resubmit of the same content with another visibility returns the
//!   existing claim unchanged, flagged;
//! * `publicize_claims`: a team admin publishes (claim, unpinned evidence,
//!   trace and the incident edge become public, a pinned evidence row does not,
//!   one audit row); a plain writer is refused; a non-member gets not-found; a
//!   sealed claim is refused; a direct app-role UPDATE is still refused by 074;
//! * `share_claims_with_team`: a private claim moves into a team the author
//!   writes, and not into one it does not;
//! * neither act can be steered by temporary tables the calling session
//!   created first.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::submit_claim;
use epigraph_mcp::tools::memory::memorize;
use epigraph_mcp::tools::visibility::{
    publicize_claims, set_default_group, share_claims_with_team,
};
use epigraph_mcp::types::{
    MemorizeParams, PublicizeClaimsParams, SetDefaultGroupParams, ShareClaimsWithTeamParams,
    SubmitClaimParams,
};
use sqlx::PgPool;
use uuid::Uuid;

struct AppRole {
    server: EpiGraphMcpFull,
    scoped: ScopedPool,
}

async fn app_role(pool: &PgPool) -> AppRole {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped.clone());
    server.server_agent_id().await.expect("server agent");
    AppRole { server, scoped }
}

fn token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

/// A keyed TEAM group (kind 'team' carries a 32-byte key), with no members.
async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

fn submit(content: &str, visibility: Option<&str>, group: Option<Uuid>) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.to_string(),
        methodology: "direct_observation".to_string(),
        evidence_data: format!("evidence for {content}"),
        evidence_type: "empirical".to_string(),
        confidence: 0.8,
        source_url: None,
        reasoning: None,
        labels: vec![],
        novelty_threshold: Some(0.0),
        visibility: visibility.map(str::to_string),
        group_id: group.map(|g| g.to_string()),
    }
}

/// `agent` submits; the parsed response.
async fn write_as(
    pool: &PgPool,
    s: &AppRole,
    agent: Uuid,
    params: SubmitClaimParams,
) -> Result<serde_json::Value, epigraph_mcp::errors::McpError> {
    submit_claim(
        &s.server,
        &viewer(pool, agent).await,
        params,
        Some(&token(agent)),
    )
    .await
    .map(|r| first_text(&r))
}

fn claim_of(body: &serde_json::Value) -> Uuid {
    parse_uuid_field(body, "claim_id")
}

/// `(visibility, owner_group_id)` as stored.
async fn tenancy(pool: &PgPool, table: &str, id: Uuid) -> (String, Uuid) {
    sqlx::query_as(&format!(
        "SELECT visibility::text, owner_group_id FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("tenancy")
}

/// Can `agent` read `claim` on an app-role connection stamped as `agent`?
async fn reads(pool: &PgPool, s: &AppRole, agent: Uuid, claim: Uuid) -> bool {
    let v = viewer(pool, agent).await;
    let mut conn = s.scoped.acquire_as(&v).await.expect("stamped connection");
    ClaimRepository::get_by_id(&mut *conn, &v, ClaimId::from_uuid(claim))
        .await
        .expect("read")
        .is_some()
}

async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count")
}

/// Every evidence and trace row of `claim`: `(visibility, owner)`.
async fn derived_tenancy(pool: &PgPool, claim: Uuid) -> Vec<(String, Uuid)> {
    sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM evidence WHERE claim_id = $1 \
         UNION ALL \
         SELECT visibility::text, owner_group_id FROM reasoning_traces WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("derived rows")
}

// ─────────────────────────────────────────────────────────────────────────────
// Part A: write-time visibility
// ─────────────────────────────────────────────────────────────────────────────

/// The owner's ask: a write that names nothing lands in the author's team. A
/// teammate (even a reader) reads it; a non-member does not. Its evidence and
/// trace carry the same tenancy.
#[sqlx::test(migrations = "../../migrations")]
async fn a_default_write_lands_in_the_team_and_only_members_read_it(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "nanodynamics").await;
    let (alice, _) = fixture::seed_agent_with_group(&pool, "vis-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "vis-bob").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "vis-carol").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;

    let body = write_as(&pool, &s, alice, submit("team default claim", None, None))
        .await
        .expect("a default write by a team writer lands");
    let c = claim_of(&body);
    assert_eq!(body["visibility"], "team", "{body}");
    assert_eq!(body["owner_group_id"], t.to_string(), "{body}");
    assert!(body.get("visibility_note").is_none(), "{body}");
    assert_eq!(tenancy(&pool, "claims", c).await, ("group".to_string(), t));
    let derived = derived_tenancy(&pool, c).await;
    assert_eq!(
        derived.len(),
        2,
        "one evidence row and one trace: {derived:?}"
    );
    assert!(
        derived.iter().all(|d| *d == ("group".to_string(), t)),
        "{derived:?}"
    );

    assert!(reads(&pool, &s, alice, c).await, "the author reads it");
    assert!(
        reads(&pool, &s, bob, c).await,
        "a teammate (reader) reads it"
    );
    assert!(!reads(&pool, &s, carol, c).await, "a non-member does not");
}

/// `private` lands in the author's home group (a teammate cannot read it);
/// `public` lands public over the home group (a stranger can).
#[sqlx::test(migrations = "../../migrations")]
async fn private_and_public_writes(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "vis-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "vis-bob").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "vis-carol").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "writer").await;

    let body = write_as(
        &pool,
        &s,
        alice,
        submit("private claim", Some("private"), None),
    )
    .await
    .expect("private");
    let p = claim_of(&body);
    assert_eq!(body["visibility"], "private", "{body}");
    assert_eq!(
        tenancy(&pool, "claims", p).await,
        ("group".to_string(), home)
    );
    assert!(reads(&pool, &s, alice, p).await);
    assert!(
        !reads(&pool, &s, bob, p).await,
        "a teammate cannot read a private claim"
    );

    let body = write_as(
        &pool,
        &s,
        alice,
        submit("public claim", Some("public"), None),
    )
    .await
    .expect("public");
    let q = claim_of(&body);
    assert_eq!(body["visibility"], "public", "{body}");
    assert_eq!(
        tenancy(&pool, "claims", q).await,
        ("public".to_string(), home)
    );
    assert!(
        reads(&pool, &s, carol, q).await,
        "anyone authenticated reads a public claim"
    );

    // memorize takes the same parameters.
    let r = memorize(
        &s.server,
        &viewer(&pool, alice).await,
        MemorizeParams {
            content: "a private memory".to_string(),
            confidence: None,
            tags: None,
            novelty_threshold: Some(0.0),
            visibility: Some("private".to_string()),
            group_id: None,
        },
        Some(&token(alice)),
    )
    .await
    .expect("memorize private");
    let m = claim_of(&first_text(&r));
    assert_eq!(
        tenancy(&pool, "claims", m).await,
        ("group".to_string(), home)
    );
}

/// A `reader` membership does not admit a team write; neither does no
/// membership. Nothing is written either way. A group beside `public` is a
/// malformed request.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_and_a_non_member_are_refused_a_team_write(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "vis-reader").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "vis-stranger").await;
    add_member(&pool, t, bob, "reader").await;

    for (who, content) in [
        (bob, "a reader's team claim"),
        (carol, "a stranger's team claim"),
    ] {
        let err = write_as(&pool, &s, who, submit(content, None, Some(t)))
            .await
            .expect_err("refused");
        assert!(
            err.message.contains("not a team you may write")
                && err
                    .message
                    .contains("reader membership does not admit writes"),
            "{err:?}"
        );
        assert_eq!(
            claims_with_content(&pool, content).await,
            0,
            "nothing written"
        );
    }

    let err = write_as(
        &pool,
        &s,
        carol,
        submit("contradiction", Some("public"), Some(t)),
    )
    .await
    .expect_err("a group beside public is refused");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert_eq!(claims_with_content(&pool, "contradiction").await, 0);
}

/// D-V1. With two teams and no default, a default write is PRIVATE and the
/// response says why; `set_default_group` then routes default writes to the
/// chosen team. A default naming a team the agent cannot write is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn several_teams_go_private_until_a_default_is_set(pool: PgPool) {
    let s = app_role(&pool).await;
    let t1 = team(&pool, "t1").await;
    let t2 = team(&pool, "t2").await;
    let other = team(&pool, "not-mine").await;
    let (dave, home) = fixture::seed_agent_with_group(&pool, "vis-dave").await;
    add_member(&pool, t1, dave, "writer").await;
    add_member(&pool, t2, dave, "admin").await;

    let body = write_as(&pool, &s, dave, submit("ambiguous default", None, None))
        .await
        .expect("lands private");
    assert_eq!(body["visibility"], "private", "{body}");
    assert!(
        body["visibility_note"]
            .as_str()
            .unwrap_or("")
            .contains("2 teams"),
        "{body}"
    );
    assert_eq!(
        tenancy(&pool, "claims", claim_of(&body)).await,
        ("group".to_string(), home),
        "never public"
    );

    let dv = viewer(&pool, dave).await;
    let err = set_default_group(
        &s.server,
        &dv,
        SetDefaultGroupParams {
            group_id: Some(other.to_string()),
        },
        Some(&token(dave)),
    )
    .await
    .expect_err("a team dave does not write");
    assert!(err.message.contains("VIS02"), "{err:?}");

    set_default_group(
        &s.server,
        &dv,
        SetDefaultGroupParams {
            group_id: Some(t2.to_string()),
        },
        Some(&token(dave)),
    )
    .await
    .expect("set default");
    let body = write_as(&pool, &s, dave, submit("default team now", None, None))
        .await
        .expect("lands in t2");
    assert_eq!(body["owner_group_id"], t2.to_string(), "{body}");
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'agent.default_group_set' \
         AND agent_id = $1",
    )
    .bind(dave)
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(audited, 1);
}

/// D-V3: an agent operated by a human writes into a team its human writes,
/// though the agent itself is not a member. Its stamped transaction carries the
/// team (`Viewer::with_team_write_grant`), so the write and its derived rows
/// land.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_writes_into_its_humans_team(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "human's team").await;
    let (human, _) = fixture::seed_human_operator(&pool, "vis-human").await;
    let (crew, _) = fixture::seed_agent_with_group(&pool, "vis-crew").await;
    add_member(&pool, t, human, "writer").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, crew, human)
            .await
            .expect("live link");
    }
    let body = write_as(
        &pool,
        &s,
        crew,
        submit("crew claim for the team", None, None),
    )
    .await
    .expect("the crew agent writes into its human's team");
    let c = claim_of(&body);
    assert_eq!(tenancy(&pool, "claims", c).await, ("group".to_string(), t));
    assert!(derived_tenancy(&pool, c)
        .await
        .iter()
        .all(|d| *d == ("group".to_string(), t)));
    assert!(reads(&pool, &s, human, c).await, "the human reads it");
}

/// D-V4: the same content resubmitted with another visibility returns the
/// existing claim, unchanged, and says so.
#[sqlx::test(migrations = "../../migrations")]
async fn a_resubmit_with_another_visibility_returns_the_existing_claim_flagged(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "vis-alice").await;
    add_member(&pool, t, alice, "writer").await;
    let first = write_as(&pool, &s, alice, submit("said once", Some("public"), None))
        .await
        .expect("public first");
    // New evidence (a byte-identical evidence row is refused as a duplicate on
    // any resubmit, whatever the visibility).
    let mut second = submit("said once", None, None);
    second.evidence_data = "a second observation".to_string();
    let again = write_as(&pool, &s, alice, second)
        .await
        .expect("team second");
    assert_eq!(claim_of(&first), claim_of(&again), "no second row");
    assert_eq!(again["visibility"], "public", "{again}");
    assert!(
        again["visibility_note"]
            .as_str()
            .unwrap_or("")
            .contains("NOT re-scoped"),
        "{again}"
    );
    assert_eq!(
        tenancy(&pool, "claims", claim_of(&again)).await,
        ("public".to_string(), home)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Part B: publicize and share
// ─────────────────────────────────────────────────────────────────────────────

async fn publicize(
    pool: &PgPool,
    s: &AppRole,
    agent: Uuid,
    ids: &[Uuid],
) -> Result<serde_json::Value, epigraph_mcp::errors::McpError> {
    publicize_claims(
        &s.server,
        &viewer(pool, agent).await,
        PublicizeClaimsParams {
            claim_ids: ids.iter().map(Uuid::to_string).collect(),
            reason: "ready for the open-science core".to_string(),
        },
        Some(&token(agent)),
    )
    .await
    .map(|r| first_text(&r))
}

async fn publicized_events(pool: &PgPool) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT agent_id, details FROM security_events WHERE event_type = 'claim.publicized'",
    )
    .fetch_all(pool)
    .await
    .expect("events")
}

/// A team admin publishes a team claim. The claim, its unpinned evidence and
/// its trace become public; an edge from a public claim to it becomes public;
/// an evidence row an operator pinned stays group-only; one audit row names the
/// admin. Before that: a plain writer is refused and a non-member is told
/// "not found", and neither changes anything.
#[sqlx::test(migrations = "../../migrations")]
async fn a_team_admin_publicizes_and_others_are_refused(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, _) = fixture::seed_agent_with_group(&pool, "vis-writer").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "vis-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "vis-stranger").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, eve, "admin").await;

    let c = claim_of(
        &write_as(&pool, &s, alice, submit("finding to publish", None, None))
            .await
            .expect("team claim"),
    );
    let p = claim_of(
        &write_as(
            &pool,
            &s,
            carol,
            submit("a public neighbour", Some("public"), None),
        )
        .await
        .expect("public claim"),
    );
    let edge = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports')",
    )
    .bind(edge)
    .bind(p)
    .bind(c)
    .execute(&pool)
    .await
    .expect("edge");
    assert_eq!(
        tenancy(&pool, "edges", edge).await.0,
        "group",
        "meet: group"
    );
    // A second evidence row, hidden by an operator (migration 110's pin).
    let hidden: Uuid = sqlx::query_scalar("SELECT id FROM evidence WHERE claim_id = $1 LIMIT 1")
        .bind(c)
        .fetch_one(&pool)
        .await
        .expect("evidence");
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test hide')",
    )
    .bind(hidden)
    .bind(eve)
    .execute(&pool)
    .await
    .expect("pin");

    let err = publicize(&pool, &s, alice, &[c])
        .await
        .expect_err("a writer is not an admin");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_REQUEST, "{err:?}");
    assert!(err.message.contains("only a live admin"), "{err:?}");
    let err = publicize(&pool, &s, carol, &[c])
        .await
        .expect_err("a stranger");
    let random = Uuid::new_v4();
    let err_random = publicize(&pool, &s, carol, &[random])
        .await
        .expect_err("random");
    assert_eq!(
        err.message.replace(&c.to_string(), "<id>"),
        err_random.message.replace(&random.to_string(), "<id>"),
        "an unreadable claim answers like a missing one"
    );
    assert_eq!(tenancy(&pool, "claims", c).await, ("group".to_string(), t));
    assert!(publicized_events(&pool).await.is_empty(), "nothing audited");

    let body = publicize(&pool, &s, eve, &[c, p])
        .await
        .expect("the admin publishes");
    let outcomes: Vec<(String, String)> = body["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| {
            (
                r["claim_id"].as_str().unwrap().to_string(),
                r["outcome"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        outcomes.contains(&(c.to_string(), "publicized".to_string())),
        "{body}"
    );
    assert!(
        outcomes.contains(&(p.to_string(), "already_public".to_string())),
        "{body}"
    );

    assert_eq!(
        tenancy(&pool, "claims", c).await,
        ("public".to_string(), t),
        "owner kept"
    );
    assert!(reads(&pool, &s, carol, c).await, "now anyone reads it");
    let pinned = tenancy(&pool, "evidence", hidden).await;
    assert_eq!(pinned.0, "group", "the pinned evidence stays hidden");
    let rest: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM evidence WHERE claim_id = $1 AND id <> $2 \
         UNION ALL SELECT visibility::text, owner_group_id FROM reasoning_traces WHERE claim_id = $1",
    )
    .bind(c)
    .bind(hidden)
    .fetch_all(&pool)
    .await
    .expect("rest");
    assert!(rest.iter().all(|r| r.0 == "public"), "{rest:?}");
    assert_eq!(
        tenancy(&pool, "edges", edge).await.0,
        "public",
        "the edge widened"
    );

    let events = publicized_events(&pool).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].0, Some(eve));
    assert_eq!(events[0].1["evidence_kept_private"], 1, "{events:?}");
    assert_eq!(events[0].1["claim_ids"], serde_json::json!([c.to_string()]));
}

/// A sealed claim is refused, even for the admin, and stays group-only. The
/// app role still cannot widen a claim by a direct UPDATE: 074 holds.
#[sqlx::test(migrations = "../../migrations")]
async fn a_sealed_claim_is_refused_and_074_still_holds(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "vis-admin").await;
    add_member(&pool, t, eve, "admin").await;
    let c = claim_of(
        &write_as(&pool, &s, eve, submit("sealed finding", None, None))
            .await
            .expect("team claim"),
    );
    // Seal it. Test-only shortcut: skip the key-epoch FK with replica mode.
    let mut tx = pool.begin().await.expect("tx");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)",
    )
    .bind(c)
    .bind(t)
    .execute(&mut *tx)
    .await
    .expect("seal");
    tx.commit().await.expect("commit");

    let err = publicize(&pool, &s, eve, &[c]).await.expect_err("sealed");
    assert!(err.message.contains("sealed"), "{err:?}");
    assert_eq!(tenancy(&pool, "claims", c).await, ("group".to_string(), t));

    // 074 without the definer: the app role, stamped as the admin, may update
    // the row (it writes the group), and the trigger still refuses the widening.
    let other = claim_of(
        &write_as(&pool, &s, eve, submit("not sealed", None, None))
            .await
            .expect("team claim"),
    );
    let v = viewer(&pool, eve).await;
    let mut wtx = s.scoped.begin_as(&v).await.expect("stamped tx");
    let err = sqlx::query("UPDATE claims SET visibility = 'public' WHERE id = $1")
        .bind(other)
        .execute(&mut *wtx)
        .await
        .expect_err("074 refuses a direct widening");
    assert!(err.to_string().contains("declassify"), "{err}");
}

/// `share_claims_with_team`: a private claim moves into a team its author
/// writes, after which a teammate reads it; a team the author does not write is
/// refused; a claim the caller cannot read is not found.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_claim_is_shared_with_a_team_the_author_writes(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let other = team(&pool, "not-mine").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "vis-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "vis-bob").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;
    let c = claim_of(
        &write_as(
            &pool,
            &s,
            alice,
            submit("draft finding", Some("private"), None),
        )
        .await
        .expect("private"),
    );
    let bobs = claim_of(
        &write_as(
            &pool,
            &s,
            bob,
            submit("bob's private note", Some("private"), None),
        )
        .await
        .expect("bob private"),
    );
    let av = viewer(&pool, alice).await;
    let share = |ids: Vec<Uuid>, g: Uuid| ShareClaimsWithTeamParams {
        claim_ids: ids.iter().map(Uuid::to_string).collect(),
        group_id: g.to_string(),
        reason: "share the draft".to_string(),
    };

    let err = share_claims_with_team(&s.server, &av, share(vec![c], other), Some(&token(alice)))
        .await
        .expect_err("not a team alice writes");
    assert!(err.message.contains("not a team you may write"), "{err:?}");
    let err = share_claims_with_team(&s.server, &av, share(vec![bobs], t), Some(&token(alice)))
        .await
        .expect_err("bob's private claim is invisible to alice");
    assert!(err.message.contains("not found"), "{err:?}");
    assert_eq!(
        tenancy(&pool, "claims", c).await,
        ("group".to_string(), home)
    );

    share_claims_with_team(&s.server, &av, share(vec![c], t), Some(&token(alice)))
        .await
        .expect("shared");
    assert_eq!(tenancy(&pool, "claims", c).await, ("group".to_string(), t));
    assert!(derived_tenancy(&pool, c)
        .await
        .iter()
        .all(|d| *d == ("group".to_string(), t)));
    assert!(reads(&pool, &s, bob, c).await, "the teammate reads it now");
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'claim.shared_with_team'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(audited, 1);
}

/// A definer must not keep its working state in a relation the CALLING session
/// can create first: a temporary table belongs to the session, not to the
/// definer's owner. Here the caller plants same-named temporary tables, with
/// rows of its own and a BEFORE INSERT trigger that would rewrite a
/// classification, then calls both definers on that same session. Each answer
/// is the definer's own refusal, neither claim moves, the trigger never runs,
/// and the planted rows are left exactly as planted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_temp_table_planted_by_the_caller_cannot_steer_publicize_or_share(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let other = team(&pool, "not-mine").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "vis-alice").await;
    add_member(&pool, t, alice, "writer").await;
    let team_claim = claim_of(
        &write_as(&pool, &s, alice, submit("team finding", None, None))
            .await
            .expect("team claim"),
    );
    let private_claim = claim_of(
        &write_as(
            &pool,
            &s,
            alice,
            submit("private draft", Some("private"), None),
        )
        .await
        .expect("private claim"),
    );
    let decoy = Uuid::new_v4();

    let v = viewer(&pool, alice).await;
    let mut tx = s.scoped.begin_as(&v).await.expect("stamped tx");
    let ran_as: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *tx)
        .await
        .expect("session user");
    assert_eq!(ran_as, "epigraph_app", "the plant must run as the app role");
    sqlx::raw_sql(&format!(
        r#"
        CREATE TEMP TABLE hijack_log (ran_as text, tbl text);
        CREATE TEMP TABLE vis_publicize (
            claim_id uuid PRIMARY KEY, outcome text NOT NULL, owner uuid);
        CREATE TEMP TABLE vis_share (claim_id uuid PRIMARY KEY, outcome text NOT NULL);
        INSERT INTO vis_publicize VALUES ('{decoy}', 'publicize', '{t}');
        INSERT INTO vis_share VALUES ('{decoy}', 'share');
        CREATE FUNCTION pg_temp.hijack() RETURNS trigger LANGUAGE plpgsql AS $h$
        BEGIN
            INSERT INTO pg_temp.hijack_log VALUES (current_user::text, TG_TABLE_NAME);
            NEW.outcome := CASE TG_TABLE_NAME WHEN 'vis_publicize' THEN 'publicize'
                                              ELSE 'share' END;
            RETURN NEW;
        END $h$;
        CREATE TRIGGER hijack BEFORE INSERT ON vis_publicize
            FOR EACH ROW EXECUTE FUNCTION pg_temp.hijack();
        CREATE TRIGGER hijack BEFORE INSERT ON vis_share
            FOR EACH ROW EXECUTE FUNCTION pg_temp.hijack();
        GRANT ALL ON hijack_log, vis_publicize, vis_share TO epigraph_maintenance;
        "#
    ))
    .execute(&mut *tx)
    .await
    .expect("the app role plants temporary tables");

    let published: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT claim_id, outcome FROM public.epigraph_publicize_claims($1, 'planted')",
    )
    .bind(vec![team_claim])
    .fetch_all(&mut *tx)
    .await
    .expect("publicize answers");
    let shared: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT claim_id, outcome FROM public.epigraph_share_claims_with_team($1, $2, 'planted')",
    )
    .bind(vec![private_claim])
    .bind(other)
    .fetch_all(&mut *tx)
    .await
    .expect("share answers");
    let fired: Vec<(String, String)> = sqlx::query_as("SELECT ran_as, tbl FROM pg_temp.hijack_log")
        .fetch_all(&mut *tx)
        .await
        .expect("trigger log");
    let planted_p: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT claim_id, outcome FROM pg_temp.vis_publicize ORDER BY 1")
            .fetch_all(&mut *tx)
            .await
            .expect("planted publicize rows");
    let planted_s: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT claim_id, outcome FROM pg_temp.vis_share ORDER BY 1")
            .fetch_all(&mut *tx)
            .await
            .expect("planted share rows");
    // The pooled session outlives the test's transaction: take the plant down
    // with it.
    sqlx::raw_sql(
        "DROP TABLE pg_temp.vis_publicize, pg_temp.vis_share, pg_temp.hijack_log; \
         DROP FUNCTION pg_temp.hijack()",
    )
    .execute(&mut *tx)
    .await
    .expect("drop the plant");
    tx.commit().await.expect("commit");

    assert_eq!(
        published,
        vec![(team_claim, "refused_not_admin".to_string())],
        "a writer who is not an admin is refused, whatever the session planted"
    );
    assert_eq!(
        shared,
        vec![(private_claim, "refused_not_team_writer".to_string())],
        "a team the author does not write is refused, whatever the session planted"
    );
    assert!(
        fired.is_empty(),
        "no definer statement touched the planted tables: {fired:?}"
    );
    assert_eq!(planted_p, vec![(decoy, "publicize".to_string())]);
    assert_eq!(planted_s, vec![(decoy, "share".to_string())]);
    assert_eq!(
        tenancy(&pool, "claims", team_claim).await,
        ("group".to_string(), t)
    );
    assert_eq!(
        tenancy(&pool, "claims", private_claim).await,
        ("group".to_string(), home)
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type IN ('claim.publicized', 'claim.shared_with_team')",
    )
    .fetch_one(&pool)
    .await
    .expect("audit");
    assert_eq!(audited, 0, "nothing was acted on, so nothing is audited");
}
