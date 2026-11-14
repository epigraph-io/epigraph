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
//! * backlog 3b505b5c (2): a `harvester_sources` row whose fragments all moved
//!   follows them (team / public); one whose fragments still disagree stays
//!   and is counted as held.
//! * backlog 31285392: the moved claim's cached belief is refolded for its new
//!   audience. A claim whose cache folded a BBA citing evidence that stays
//!   behind (pinned) serves, after the act, exactly the value of a control
//!   claim that never had that BBA. Its stored scoped folds
//!   (`ds_combined_beliefs`, `ds_bayesian_divergence`) are deleted as stale,
//!   and another claim's are kept.
//! * the refold fails closed: an operated agent whose session does not itself
//!   write the target team is refused, and nothing moves.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, PerspectiveRepository, ScopedPool, SessionGucMode};
use epigraph_engine::edge_factor::recompute_claim_cached_belief;
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

// ─────────────────────────────────────────────────────────────────────────────
// 3b505b5c (2): harvester_sources follow their fragments
// ─────────────────────────────────────────────────────────────────────────────

/// A harvester source with one fragment cited by `claim`, both stamped with
/// the claim's current tenancy. `(source, fragment)`.
async fn harvested(pool: &PgPool, claim: Uuid) -> (Uuid, Uuid) {
    let (v, g) = tenancy(pool, "claims", claim).await;
    let source: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_sources (content_hash, modality, status, visibility, \
                                        owner_group_id) \
         VALUES ($1, 'text', 'completed', $2, $3) RETURNING id",
    )
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .bind(&v)
    .bind(g)
    .fetch_one(pool)
    .await
    .expect("seed harvester source");
    let fragment = fragment_of(pool, source, claim).await;
    (source, fragment)
}

/// A fragment of `source` cited by `claim`, stamped with the claim's tenancy.
async fn fragment_of(pool: &PgPool, source: Uuid, claim: Uuid) -> Uuid {
    let fragment: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_fragments (source_id, content_hash, content_text, \
                                          context_window, status, visibility, owner_group_id) \
         SELECT $1, $2, 'fragment text', 'fragment text', 'completed', c.visibility, \
                c.owner_group_id \
           FROM claims c WHERE c.id = $3 RETURNING id",
    )
    .bind(source)
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("seed harvester fragment");
    sqlx::query(
        "INSERT INTO harvester_claim_provenance (claim_id, fragment_id, visibility, \
                                                 owner_group_id) \
         SELECT $1, $2, c.visibility, c.owner_group_id FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .bind(fragment)
    .execute(pool)
    .await
    .expect("seed harvester provenance");
    fragment
}

/// Share: a source whose only fragment moved goes to the team (a teammate
/// reads it); a source with a second fragment cited by a claim that stays
/// private keeps its owner and is reported held.
#[sqlx::test(migrations = "../../migrations")]
async fn share_carries_a_source_whose_fragments_all_moved_and_holds_a_mixed_one(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "casc-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "casc-bob").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;
    let c = write(&pool, &s, alice, "harvested finding", "private", None).await;
    let stays = write(
        &pool,
        &s,
        alice,
        "harvested note that stays",
        "private",
        None,
    )
    .await;
    let (source, fragment) = harvested(&pool, c).await;
    let (mixed, _) = harvested(&pool, c).await;
    let other = fragment_of(&pool, mixed, stays).await;
    assert!(
        !reads_row(&pool, &s, bob, "harvester_sources", source).await,
        "PREMISE: the teammate cannot read the home group's source"
    );

    share(&pool, &s, alice, &[c], t).await.expect("shared");

    assert_eq!(
        tenancy(&pool, "harvester_fragments", fragment).await,
        group(t)
    );
    assert_eq!(
        tenancy(&pool, "harvester_sources", source).await,
        group(t),
        "every fragment of it is the team's now"
    );
    assert!(reads_row(&pool, &s, bob, "harvester_sources", source).await);
    assert_eq!(
        tenancy(&pool, "harvester_fragments", other).await,
        group(home)
    );
    assert_eq!(
        tenancy(&pool, "harvester_sources", mixed).await,
        group(home),
        "a source whose fragments disagree is left where it is"
    );
    let events = audit(&pool, "claim.shared_with_team").await;
    assert_eq!(events[0]["harvester_sources_moved"], 1, "{events:?}");
    assert_eq!(events[0]["harvester_sources_held"], 1, "{events:?}");
}

/// Publicize: a source whose only fragment went public goes public, and a
/// stranger reads it.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_carries_a_source_whose_fragments_all_went_public(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "casc-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "casc-stranger").await;
    add_member(&pool, t, eve, "admin").await;
    let c = write(&pool, &s, eve, "harvested finding", "team", Some(t)).await;
    let (source, fragment) = harvested(&pool, c).await;
    assert!(!reads_row(&pool, &s, carol, "harvester_sources", source).await);

    publicize(&pool, &s, eve, &[c]).await.expect("publicized");

    assert_eq!(
        tenancy(&pool, "harvester_fragments", fragment).await.0,
        "public"
    );
    assert_eq!(
        tenancy(&pool, "harvester_sources", source).await,
        ("public".to_string(), t),
        "the source takes its fragments' pair (owner kept, as the claim's)"
    );
    assert!(reads_row(&pool, &s, carol, "harvester_sources", source).await);
    let events = audit(&pool, "claim.publicized").await;
    assert_eq!(events[0]["harvester_sources_moved"], 1, "{events:?}");
    assert_eq!(events[0]["harvester_sources_held"], 0, "{events:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// 31285392: the moved claim's belief, cached and scoped
// ─────────────────────────────────────────────────────────────────────────────

/// `(pignistic_prob, belief, plausibility)` as stored on the claim.
type Cache = (Option<f64>, Option<f64>, Option<f64>);

async fn cache(pool: &PgPool, claim: Uuid) -> Cache {
    sqlx::query_as("SELECT pignistic_prob, belief, plausibility FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("cache")
}

/// The cache as `agent` is served it, on its stamped app-role connection.
async fn served_cache(pool: &PgPool, s: &AppRole, agent: Uuid, claim: Uuid) -> Cache {
    let v = viewer(pool, agent).await;
    let mut conn = s.scoped.acquire_as(&v).await.expect("stamped connection");
    sqlx::query_as("SELECT pignistic_prob, belief, plausibility FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("{agent} reads the claim's cache: {e}"))
}

fn same(a: &Cache, b: &Cache) -> bool {
    let eq = |x: Option<f64>, y: Option<f64>| match (x, y) {
        (Some(x), Some(y)) => (x - y).abs() < 1e-9,
        (None, None) => true,
        _ => false,
    };
    eq(a.0, b.0) && eq(a.1, b.1) && eq(a.2, b.2)
}

/// The frame the submit's own BBA sits on, and its hypothesis count.
async fn submit_frame(pool: &PgPool, claim: Uuid) -> (Uuid, i32) {
    sqlx::query_as(
        "SELECT mf.frame_id, array_length(f.hypotheses, 1) \
           FROM mass_functions mf JOIN frames f ON f.id = mf.frame_id \
          WHERE mf.claim_id = $1 ORDER BY mf.created_at LIMIT 1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("PREMISE: the submit wrote a BBA")
}

/// A strongly refuting BBA on `claim`, by `agent`, citing `evidence`, on the
/// frame of the claim's submit BBA (so it folds into the same cache).
async fn refuting_bba(pool: &PgPool, claim: Uuid, agent: Uuid, evidence: Uuid) {
    let (frame, n) = submit_frame(pool, claim).await;
    let all = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let mut masses = serde_json::Map::new();
    masses.insert("1".to_string(), serde_json::json!(0.9));
    masses.insert(all, serde_json::json!(0.1));
    PerspectiveRepository::ensure_evidence_perspective(pool, evidence, Some(agent))
        .await
        .expect("evidence perspective");
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        Some(evidence),
        &serde_json::Value::Object(masses),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        Some(evidence),
    )
    .await
    .expect("store the refuting BBA");
}

/// The claim's cached belief refolded on an app-role transaction stamped as
/// `agent` (the author), committed.
async fn refold(pool: &PgPool, s: &AppRole, agent: Uuid, claim: Uuid) {
    let v = viewer(pool, agent).await;
    let mut tx = s.scoped.begin_as(&v).await.expect("stamped tx");
    recompute_claim_cached_belief(&mut tx, &v, claim)
        .await
        .expect("refold");
    tx.commit().await.expect("commit");
}

/// The two stored scoped folds of `claim`: a global `ds_combined_beliefs` row
/// and a `ds_bayesian_divergence` row, on the claim's submit frame.
async fn scoped_rows(pool: &PgPool, claim: Uuid) {
    let (frame, _) = submit_frame(pool, claim).await;
    sqlx::query(
        "INSERT INTO ds_combined_beliefs (frame_id, claim_id, scope_type, belief, plausibility, \
                                          pignistic_prob) \
         VALUES ($1, $2, 'global', 0.1, 0.2, 0.15)",
    )
    .bind(frame)
    .bind(claim)
    .execute(pool)
    .await
    .expect("seed ds_combined_beliefs");
    sqlx::query(
        "INSERT INTO ds_bayesian_divergence (claim_id, frame_id, pignistic_prob, \
                                             bayesian_posterior, kl_divergence) \
         VALUES ($1, $2, 0.15, 0.8, 0.4)",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed ds_bayesian_divergence");
}

async fn scoped_count(pool: &PgPool, claim: Uuid) -> (i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM ds_combined_beliefs WHERE claim_id = $1), \
                (SELECT count(*) FROM ds_bayesian_divergence WHERE claim_id = $1)",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("scoped counts")
}

/// Publicize: the claim's cache had folded a refuting BBA citing evidence
/// that stays group-only (pinned). After the act every reader is served the
/// value of a control claim that never had that BBA, not the old fold. The
/// claim's stored scoped folds are gone; the control's are kept.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_refolds_the_belief_without_the_bba_on_evidence_left_behind(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "casc-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "casc-stranger").await;
    add_member(&pool, t, eve, "admin").await;
    let c = write(&pool, &s, eve, "a team finding", "team", Some(t)).await;
    let control = write(&pool, &s, eve, "the same finding, public", "public", None).await;
    let hidden = fixture::seed_evidence(&pool, c, "reference").await;
    pin(&pool, hidden, eve).await;
    refuting_bba(&pool, c, eve, hidden).await;
    refold(&pool, &s, eve, c).await;
    refold(&pool, &s, eve, control).await;
    scoped_rows(&pool, c).await;
    scoped_rows(&pool, control).await;
    let stale = cache(&pool, c).await;
    let expected = cache(&pool, control).await;
    assert!(
        expected.0.is_some() && !same(&stale, &expected),
        "PREMISE: the team's fold took in the pinned BBA ({stale:?} vs control {expected:?})"
    );

    publicize(&pool, &s, eve, &[c]).await.expect("publicized");

    assert_eq!(tenancy(&pool, "evidence", hidden).await, group(t), "pinned");
    let served = served_cache(&pool, &s, carol, c).await;
    assert!(
        same(&served, &expected),
        "a stranger is served the fold of what it may read ({served:?}), not the team's \
         fold ({stale:?}); control {expected:?}"
    );
    assert_eq!(scoped_count(&pool, c).await, (0, 0), "stale scoped folds");
    assert_eq!(
        scoped_count(&pool, control).await,
        (1, 1),
        "another claim's"
    );
    let events = audit(&pool, "claim.publicized").await;
    assert_eq!(events[0]["scoped_beliefs_cleared"], 1, "{events:?}");
    assert_eq!(events[0]["divergence_rows_cleared"], 1, "{events:?}");
}

/// Share: the private claim's cache had folded a refuting BBA citing evidence
/// pinned in the home group. After the act the teammate is served the value
/// of a control team claim that never had that BBA.
#[sqlx::test(migrations = "../../migrations")]
async fn share_refolds_the_belief_without_the_bba_on_evidence_left_at_home(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "casc-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "casc-bob").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;
    let c = write(&pool, &s, alice, "a private finding", "private", None).await;
    let control = write(&pool, &s, alice, "the same finding, team", "team", Some(t)).await;
    let hidden = fixture::seed_evidence(&pool, c, "reference").await;
    pin(&pool, hidden, alice).await;
    refuting_bba(&pool, c, alice, hidden).await;
    refold(&pool, &s, alice, c).await;
    refold(&pool, &s, alice, control).await;
    scoped_rows(&pool, c).await;
    let stale = cache(&pool, c).await;
    let expected = cache(&pool, control).await;
    assert!(
        expected.0.is_some() && !same(&stale, &expected),
        "PREMISE: the home fold took in the pinned BBA ({stale:?} vs control {expected:?})"
    );

    share(&pool, &s, alice, &[c], t).await.expect("shared");

    assert_eq!(
        tenancy(&pool, "evidence", hidden).await,
        group(home),
        "pinned"
    );
    let served = served_cache(&pool, &s, bob, c).await;
    assert!(
        same(&served, &expected),
        "the teammate is served the fold of what the team may read ({served:?}), not the \
         home fold ({stale:?}); control {expected:?}"
    );
    assert_eq!(scoped_count(&pool, c).await, (0, 0), "stale scoped folds");
}

/// The refold fails closed. An agent its human operates writes a private
/// claim (into the human's personal group, the agent's home) and shares it
/// into a team the HUMAN writes: 206 admits the target through the operator
/// arm, but the agent's own stamp does not write the team, so the refold
/// could not reach the moved claim. The act is refused and nothing moves.
#[sqlx::test(migrations = "../../migrations")]
async fn an_act_whose_session_cannot_refold_the_moved_claim_is_refused(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "human's team").await;
    let (human, human_home) = fixture::seed_human_operator(&pool, "casc-human").await;
    let (crew, _) = fixture::seed_agent_with_group(&pool, "casc-crew").await;
    add_member(&pool, t, human, "writer").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, crew, human)
            .await
            .expect("live link");
    }
    let c = write(&pool, &s, crew, "crew draft", "private", None).await;
    assert_eq!(tenancy(&pool, "claims", c).await, group(human_home));

    let err = share(&pool, &s, crew, &[c], t)
        .await
        .expect_err("the crew agent's session does not write the team");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_REQUEST, "{err:?}");
    assert!(err.message.contains("does not itself write"), "{err:?}");
    assert_eq!(
        tenancy(&pool, "claims", c).await,
        group(human_home),
        "nothing moved"
    );
    assert!(audit(&pool, "claim.shared_with_team").await.is_empty());
}
