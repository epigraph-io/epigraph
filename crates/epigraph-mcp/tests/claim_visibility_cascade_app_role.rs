//! What `publicize_claims` and `share_claims_with_team` carry with a moved
//! claim, on the APPLICATION ROLE (migration 215, `epigraph_engine::
//! visibility_act`; spec `docs/tenancy/share-with-team.md` section 4.6).
//!
//! Every server is built from ONE `ScopedPool` downgraded to `epigraph_app`
//! (NOSUPERUSER, NOBYPASSRLS), and every "who can read it" question is asked
//! on a connection of that pool stamped as the reader: a superuser pool would
//! read every row and prove nothing. Seeding runs on the superuser pool.
//!
//! What is pinned, each against migration 206 as built (which fails it):
//! * backlog 3b505b5c (1): an edge whose endpoint is a moved claim's EVIDENCE
//!   is re-met. After a share the team reads it; after a publicize a stranger
//!   does. An edge on a PINNED evidence row stays with the pin owner.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::submit_claim;
use epigraph_mcp::tools::visibility::{publicize_claims, share_claims_with_team};
use epigraph_mcp::types::{PublicizeClaimsParams, ShareClaimsWithTeamParams, SubmitClaimParams};
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

fn submit(content: &str, visibility: &str, group: Option<Uuid>) -> SubmitClaimParams {
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
        visibility: Some(visibility.to_string()),
        group_id: group.map(|g| g.to_string()),
    }
}

/// `agent` submits a claim through MCP; its id.
async fn write(
    pool: &PgPool,
    s: &AppRole,
    agent: Uuid,
    content: &str,
    visibility: &str,
    group: Option<Uuid>,
) -> Uuid {
    let body = submit_claim(
        &s.server,
        &viewer(pool, agent).await,
        submit(content, visibility, group),
        Some(&token(agent)),
    )
    .await
    .map(|r| first_text(&r))
    .unwrap_or_else(|e| panic!("submit {content:?}: {e:?}"));
    parse_uuid_field(&body, "claim_id")
}

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

async fn share(
    pool: &PgPool,
    s: &AppRole,
    agent: Uuid,
    ids: &[Uuid],
    group: Uuid,
) -> Result<serde_json::Value, epigraph_mcp::errors::McpError> {
    share_claims_with_team(
        &s.server,
        &viewer(pool, agent).await,
        ShareClaimsWithTeamParams {
            claim_ids: ids.iter().map(Uuid::to_string).collect(),
            group_id: group.to_string(),
            reason: "share the draft".to_string(),
        },
        Some(&token(agent)),
    )
    .await
    .map(|r| first_text(&r))
}

/// `(visibility, owner_group_id)` as stored.
async fn tenancy(pool: &PgPool, table: &str, id: Uuid) -> (String, Uuid) {
    sqlx::query_as(&format!(
        "SELECT visibility::text, owner_group_id FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("tenancy of {table} {id}: {e}"))
}

/// Can `agent` read row `id` of `table`, on an app-role connection stamped as
/// `agent` (row security is the only filter)?
async fn reads_row(pool: &PgPool, s: &AppRole, agent: Uuid, table: &str, id: Uuid) -> bool {
    let v = viewer(pool, agent).await;
    let mut conn = s.scoped.acquire_as(&v).await.expect("stamped connection");
    let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE id = $1"))
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("read {table} as {agent}: {e}"));
    n == 1
}

/// The claim's one evidence row from its submit.
async fn evidence_of(pool: &PgPool, claim: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM evidence WHERE claim_id = $1 ORDER BY created_at LIMIT 1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("the submit's evidence row")
}

/// Hide `evidence` as `epigraph-operator hide-evidence` does (migration 110):
/// its owner is fixed from now on, and neither act moves or widens it.
async fn pin(pool: &PgPool, evidence: Uuid, by: Uuid) {
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden')",
    )
    .bind(evidence)
    .bind(by)
    .execute(pool)
    .await
    .expect("pin");
}

/// An `evidence -> claim` edge, stamped from its endpoints by 070's trigger.
async fn evidence_edge(pool: &PgPool, evidence: Uuid, claim: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'evidence', $3, 'claim', 'supports')",
    )
    .bind(id)
    .bind(evidence)
    .bind(claim)
    .execute(pool)
    .await
    .expect("evidence edge");
    id
}

fn group(g: Uuid) -> (String, Uuid) {
    ("group".to_string(), g)
}

async fn audit(pool: &PgPool, event: &str) -> Vec<serde_json::Value> {
    sqlx::query_scalar("SELECT details FROM security_events WHERE event_type = $1")
        .bind(event)
        .fetch_all(pool)
        .await
        .expect("audit rows")
}

// ─────────────────────────────────────────────────────────────────────────────
// 3b505b5c (1): edges on a moved claim's evidence
// ─────────────────────────────────────────────────────────────────────────────

/// Share: the edge from the moved claim's evidence to a public claim follows
/// the evidence into the team, so a teammate reads it; the edge on a pinned
/// evidence row stays the home group's, and the teammate does not.
#[sqlx::test(migrations = "../../migrations")]
async fn share_re_meets_the_edges_on_the_moved_claims_evidence(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "casc-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "casc-bob").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "casc-carol").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;
    let c = write(&pool, &s, alice, "draft finding", "private", None).await;
    let p = write(&pool, &s, carol, "a public neighbour", "public", None).await;
    let ev = evidence_of(&pool, c).await;
    let hidden = fixture::seed_evidence(&pool, c, "reference").await;
    pin(&pool, hidden, alice).await;
    let moved_edge = evidence_edge(&pool, ev, p).await;
    let pinned_edge = evidence_edge(&pool, hidden, p).await;
    assert_eq!(tenancy(&pool, "edges", moved_edge).await, group(home));
    assert_eq!(tenancy(&pool, "edges", pinned_edge).await, group(home));
    assert!(
        !reads_row(&pool, &s, bob, "edges", moved_edge).await,
        "PREMISE: the teammate cannot read the home group's edge"
    );

    share(&pool, &s, alice, &[c], t).await.expect("shared");

    assert_eq!(tenancy(&pool, "evidence", ev).await, group(t), "arm (d)");
    assert_eq!(
        tenancy(&pool, "edges", moved_edge).await,
        group(t),
        "the edge on the moved evidence takes the meet of (team evidence, public claim)"
    );
    assert!(
        reads_row(&pool, &s, bob, "edges", moved_edge).await,
        "the teammate reads the edge on the evidence it now reads"
    );
    assert!(
        !reads_row(&pool, &s, carol, "edges", moved_edge).await,
        "a stranger still does not"
    );
    assert_eq!(tenancy(&pool, "evidence", hidden).await, group(home));
    assert_eq!(
        tenancy(&pool, "edges", pinned_edge).await,
        group(home),
        "the edge on the pinned evidence stays where the pin keeps the evidence"
    );
    assert!(!reads_row(&pool, &s, bob, "edges", pinned_edge).await);
    let events = audit(&pool, "claim.shared_with_team").await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["evidence_edges_rewritten"], 1, "{events:?}");
}

/// Publicize: the edge from the moved claim's evidence to a public claim
/// becomes public, so a stranger reads it; the edge on a pinned evidence row
/// stays the team's.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_re_meets_the_edges_on_the_moved_claims_evidence(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "casc-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "casc-stranger").await;
    add_member(&pool, t, eve, "admin").await;
    let c = write(&pool, &s, eve, "finding to publish", "team", Some(t)).await;
    let p = write(&pool, &s, carol, "a public neighbour", "public", None).await;
    let ev = evidence_of(&pool, c).await;
    let hidden = fixture::seed_evidence(&pool, c, "reference").await;
    pin(&pool, hidden, eve).await;
    let moved_edge = evidence_edge(&pool, ev, p).await;
    let pinned_edge = evidence_edge(&pool, hidden, p).await;
    assert_eq!(tenancy(&pool, "edges", moved_edge).await, group(t));
    assert!(
        !reads_row(&pool, &s, carol, "edges", moved_edge).await,
        "PREMISE: a stranger cannot read the team's edge"
    );

    publicize(&pool, &s, eve, &[c]).await.expect("publicized");

    assert_eq!(tenancy(&pool, "evidence", ev).await.0, "public", "arm (d)");
    assert_eq!(
        tenancy(&pool, "edges", moved_edge).await.0,
        "public",
        "both endpoints are public now"
    );
    assert!(reads_row(&pool, &s, carol, "edges", moved_edge).await);
    assert_eq!(tenancy(&pool, "edges", pinned_edge).await, group(t));
    assert!(!reads_row(&pool, &s, carol, "edges", pinned_edge).await);
    let events = audit(&pool, "claim.publicized").await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["evidence_edges_rewritten"], 1, "{events:?}");
    assert_eq!(events[0]["evidence_kept_private"], 1, "{events:?}");
}
