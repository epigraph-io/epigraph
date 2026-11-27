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
//! * backlog 31285392: the moved claim's cached belief is refolded for its new
//!   audience. A claim whose cache folded a BBA citing evidence that stays
//!   behind (pinned) serves, after the act, exactly the value of a control
//!   claim that never had that BBA. Its stored scoped folds
//!   (`ds_combined_beliefs`, `ds_bayesian_divergence`) are deleted as stale,
//!   and another claim's are kept.
//! * backlog 4d8df0cf: the moved claim's `ds_combined_beliefs` rows are then
//!   written afresh at the keys it had, for the new audience (`global` and
//!   `perspective` scopes); a scope with nothing admissible gets no row, and
//!   the divergence row stays deleted.
//! * backlog 31285392, the cache-owner frame: a claim whose `binary_truth`
//!   (the frame that owns its cache) holds only inputs the new audience may
//!   not read, while its `claim_validity` keeps an admissible one, is served
//!   full ignorance after the act, not the old `binary_truth` fold. Pinned for
//!   publicize (a BBA on evidence left behind) and for share (an edge-factor
//!   BBA from a home-private source claim, through an edge the team cannot
//!   read). The widening keeps the recorded owner
//!   (`cache_owner_frame_keeping_recorded`); the claim's NEXT ordinary
//!   recompute applies the admissible-first owner rule (8d720490) and refolds
//!   the cache from `claim_validity`.
//! * backlog ecd842bf (migration 242): an operated agent does not share or
//!   publicize on its own authority, even when it holds the target team's
//!   writer (share) or the owning team's admin (publicize) membership itself,
//!   and even when its human's team is the target; its human makes the same
//!   call and succeeds. (Before 242 the agent's session also failed the
//!   refold check when only its human wrote the team; 242 refuses it first.)
//! * backlog 0d9dfd24: `claims.truth_value`, which `update_with_evidence`
//!   persisted as a copy of a fold that took in a BBA on evidence that stays
//!   behind (pinned), is replaced by the refolded value: the new audience is
//!   served the truth value of a control claim that never had that BBA. The
//!   same holds for a flat workflow claim whose copy `report_workflow_outcome`
//!   wrote, and for a vacated cache (`truth_value` 0.5). A current claim at
//!   the deprecation marker (a step's soft delete) keeps 0.05.
//! * backlog 6e4ff46e: the claim's Beta track (`beta_alpha` / `beta_beta`),
//!   which `update_with_evidence` moved with a BBA on evidence that stays
//!   behind (pinned), is rebuilt from the evidence the new audience may read:
//!   it is served exactly the track of a control claim that only ever had the
//!   readable evidence, and a claim with nothing readable left is back at the
//!   `Beta(1, 1)` prior.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, ScopedPool, SessionGucMode};
use epigraph_engine::edge_factor::{
    auto_wire_ds_for_edge, ensure_binary_frame, recompute_claim_cached_belief,
    resolve_claim_validity_frame, EdgeFactorOutcome,
};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::claims::{submit_claim, update_with_evidence};
use epigraph_mcp::tools::visibility::{publicize_claims, share_claims_with_team};
use epigraph_mcp::tools::workflows::report_workflow_outcome;
use epigraph_mcp::types::{
    PublicizeClaimsParams, ReportWorkflowOutcomeParams, ShareClaimsWithTeamParams, StepExecution,
    SubmitClaimParams, UpdateWithEvidenceParams,
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
        dataset: None,
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
            ..Default::default()
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
            ..Default::default()
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
    MassFunctionRepository::store_for_evidence(
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

/// The `(pignistic_prob, belief, plausibility)` of `claim`'s scoped row at
/// `(scope_type, scope_id)`, as `agent` is served it on its stamped app-role
/// connection; `None` when it reads no row.
async fn served_scoped(
    pool: &PgPool,
    s: &AppRole,
    agent: Uuid,
    claim: Uuid,
    scope_type: &str,
    scope_id: Option<Uuid>,
) -> Option<Cache> {
    let v = viewer(pool, agent).await;
    let mut conn = s.scoped.acquire_as(&v).await.expect("stamped connection");
    sqlx::query_as(
        "SELECT pignistic_prob, belief, plausibility FROM ds_combined_beliefs \
          WHERE claim_id = $1 AND scope_type = $2 AND scope_id IS NOT DISTINCT FROM $3",
    )
    .bind(claim)
    .bind(scope_type)
    .bind(scope_id)
    .fetch_optional(&mut *conn)
    .await
    .unwrap_or_else(|e| panic!("{agent} reads the claim's scoped row: {e}"))
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
    // 4d8df0cf: the global row is written afresh for the new audience, and
    // the divergence row stays deleted (its Beta track moved with the claim).
    assert_eq!(scoped_count(&pool, c).await, (1, 0), "scoped folds afresh");
    let row = served_scoped(&pool, &s, carol, c, "global", None)
        .await
        .expect("a stranger reads the moved claim's global row");
    assert!(
        same(&row, &expected),
        "the global row is the fold of what the stranger may read ({row:?}), not the stale \
         row; control {expected:?}"
    );
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
    // 4d8df0cf: the global row is written afresh for the team; the
    // divergence row stays deleted.
    assert_eq!(scoped_count(&pool, c).await, (1, 0), "scoped folds afresh");
    let row = served_scoped(&pool, &s, bob, c, "global", None)
        .await
        .expect("the teammate reads the moved claim's global row");
    assert!(
        same(&row, &expected),
        "the global row is the fold of what the team may read ({row:?}), not the stale row; \
         control {expected:?}"
    );
}

/// An agent `human` operates through a LIVE link, the human a registered
/// human operator. `(human, human_home, crew)`.
async fn operated(pool: &PgPool, label: &str) -> (Uuid, Uuid, Uuid) {
    let (human, human_home) = fixture::seed_human_operator(pool, &format!("{label}-human")).await;
    let (crew, _) = fixture::seed_agent_with_group(pool, &format!("{label}-crew")).await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, crew, human)
        .await
        .expect("live link");
    (human, human_home, crew)
}

/// Backlog ecd842bf, the shape 215 already refused (through the refold check)
/// and 242 refuses in the definer: the agent shares its private draft into a
/// team only its HUMAN writes. Refused as an operated agent; nothing moves.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_does_not_share_into_its_humans_team(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "human's team").await;
    let (human, human_home, crew) = operated(&pool, "gate-humans-team").await;
    add_member(&pool, t, human, "writer").await;
    let c = write(&pool, &s, crew, "crew draft", "private", None).await;
    assert_eq!(tenancy(&pool, "claims", c).await, group(human_home));

    let err = share(&pool, &s, crew, &[c], t)
        .await
        .expect_err("an operated agent does not share on its own authority");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_REQUEST, "{err:?}");
    assert!(err.message.contains("operated agent"), "{err:?}");
    assert_eq!(
        tenancy(&pool, "claims", c).await,
        group(human_home),
        "nothing moved"
    );
    assert!(audit(&pool, "claim.shared_with_team").await.is_empty());
}

/// Backlog ecd842bf, the hole 215 left open: the operated agent holds its OWN
/// writer membership of the team, so 215 admitted the target (`via = 'own'`)
/// and the refold check passed. 242 refuses it; nothing moves and the
/// teammate reads nothing. The human makes the same call and it succeeds.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_that_writes_the_team_itself_does_not_share_into_it(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (human, human_home, crew) = operated(&pool, "gate-share").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "gate-share-reader").await;
    add_member(&pool, t, crew, "writer").await;
    add_member(&pool, t, human, "writer").await;
    add_member(&pool, t, bob, "reader").await;
    let c = write(&pool, &s, crew, "crew draft", "private", None).await;
    assert_eq!(
        tenancy(&pool, "claims", c).await,
        group(human_home),
        "PREMISE: private to the human's personal group, the agent's home"
    );

    let err = share(&pool, &s, crew, &[c], t)
        .await
        .expect_err("an operated agent does not share on its own authority");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_REQUEST, "{err:?}");
    assert!(err.message.contains("operated agent"), "{err:?}");
    assert_eq!(
        tenancy(&pool, "claims", c).await,
        group(human_home),
        "nothing moved"
    );
    assert!(!reads_row(&pool, &s, bob, "claims", c).await);
    assert!(audit(&pool, "claim.shared_with_team").await.is_empty());

    share(&pool, &s, human, &[c], t)
        .await
        .expect("the human shares its agent's draft");
    assert_eq!(tenancy(&pool, "claims", c).await, group(t));
    assert!(reads_row(&pool, &s, bob, "claims", c).await);
    assert_eq!(audit(&pool, "claim.shared_with_team").await.len(), 1);
}

/// Backlog ecd842bf for publicize: an operated agent that is itself an ADMIN
/// of the owning team (215 admitted it: D-V2 asks only for a live admin), and
/// an agent whose link is RETIRED and that holds the same admin membership,
/// are both refused and nothing is published. The human, an admin of the
/// team, publishes it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_that_admins_the_team_itself_does_not_publicize(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (human, _, crew) = operated(&pool, "gate-pub").await;
    let (retired, _) = fixture::seed_agent_with_group(&pool, "gate-pub-retired").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "gate-pub-stranger").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, retired, human)
            .await
            .expect("retired link");
    }
    add_member(&pool, t, crew, "admin").await;
    add_member(&pool, t, retired, "admin").await;
    add_member(&pool, t, human, "admin").await;
    let c = write(&pool, &s, crew, "crew finding", "team", Some(t)).await;
    assert_eq!(tenancy(&pool, "claims", c).await, group(t), "PREMISE");

    for (who, agent) in [("live-linked", crew), ("retired-linked", retired)] {
        let err = publicize(&pool, &s, agent, &[c])
            .await
            .expect_err("an operated agent does not publicize on its own authority");
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_REQUEST,
            "{who}: {err:?}"
        );
        assert!(err.message.contains("operated agent"), "{who}: {err:?}");
        assert_eq!(
            tenancy(&pool, "claims", c).await,
            group(t),
            "{who}: nothing published"
        );
        assert!(!reads_row(&pool, &s, carol, "claims", c).await, "{who}");
    }
    assert!(audit(&pool, "claim.publicized").await.is_empty());

    publicize(&pool, &s, human, &[c])
        .await
        .expect("the human, an admin of the team, publishes it");
    assert_eq!(tenancy(&pool, "claims", c).await.0, "public");
    assert!(reads_row(&pool, &s, carol, "claims", c).await);
}

// ─────────────────────────────────────────────────────────────────────────────
// 31285392: the cache-owner frame left with no admissible input
// ─────────────────────────────────────────────────────────────────────────────

/// A BBA on `frame` of `claim`, by `agent`, citing `evidence`, with mass `t`
/// on hypothesis 0 and the rest on the whole frame.
async fn bba_on(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, evidence: Uuid, t: f64) {
    let n: i32 = sqlx::query_scalar("SELECT array_length(hypotheses, 1) FROM frames WHERE id = $1")
        .bind(frame)
        .fetch_one(pool)
        .await
        .expect("frame size");
    let all = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let mut masses = serde_json::Map::new();
    masses.insert("0".to_string(), serde_json::json!(t));
    masses.insert(all, serde_json::json!(1.0 - t));
    MassFunctionRepository::store_for_evidence(
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
    .expect("store a BBA");
}

/// A genuine perspective (a viewpoint) owned by `owner`.
async fn lens(pool: &PgPool, name: &str, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(name)
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("a perspective")
}

/// [`bba_on`]'s BBA, filed under the genuine perspective `lens` and citing
/// `evidence` through `evidence_id` (no slot).
async fn bba_under_lens(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    lens: Uuid,
    evidence: Uuid,
    t: f64,
) {
    let n: i32 = sqlx::query_scalar("SELECT array_length(hypotheses, 1) FROM frames WHERE id = $1")
        .bind(frame)
        .fetch_one(pool)
        .await
        .expect("frame size");
    let all = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let mut masses = serde_json::Map::new();
    masses.insert("0".to_string(), serde_json::json!(t));
    masses.insert(all, serde_json::json!(1.0 - t));
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        Some(lens),
        &serde_json::Value::Object(masses),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        Some(evidence),
    )
    .await
    .expect("store a BBA under the perspective");
}

/// `(binary_truth, claim_validity)` frame ids.
async fn frames(pool: &PgPool) -> (Uuid, Uuid) {
    let public = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let binary = ensure_binary_frame(&mut conn, &public)
        .await
        .expect("binary_truth");
    let validity = resolve_claim_validity_frame(&mut conn, &public)
        .await
        .expect("claim_validity");
    (binary, validity)
}

async fn cache_frame(pool: &PgPool, claim: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT belief_frame_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("belief_frame_id")
}

/// Full ignorance on the binary frame: BetP 0.5, Bel 0, Pl 1.
fn vacuous(c: &Cache) -> bool {
    same(c, &(Some(0.5), Some(0.0), Some(1.0)))
}

/// Publicize: the team claim's cache is owned by `binary_truth`, whose only
/// input cites evidence pinned in the team; its `claim_validity` input cites
/// evidence that goes public with it. After the act a stranger is served full
/// ignorance, not the team's `binary_truth` fold of the pinned evidence.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_vacates_a_cache_whose_owner_frame_cites_only_evidence_left_behind(pool: PgPool) {
    let s = app_role(&pool).await;
    let (binary, validity) = frames(&pool).await;
    let t = team(&pool, "team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "owner-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "owner-stranger").await;
    add_member(&pool, t, eve, "admin").await;
    let c = fixture::seed_group_claim(&pool, eve, t, "a team finding, two frames").await;
    let open = fixture::seed_evidence(&pool, c, "observation").await;
    let hidden = fixture::seed_evidence(&pool, c, "reference").await;
    pin(&pool, hidden, eve).await;
    bba_on(&pool, c, validity, eve, open, 0.7).await;
    bba_on(&pool, c, binary, eve, hidden, 0.9).await;
    refold(&pool, &s, eve, c).await;
    let stale = cache(&pool, c).await;
    assert!(
        cache_frame(&pool, c).await == Some(binary) && stale.0.is_some_and(|p| p > 0.6),
        "PREMISE: binary_truth owns the team's fold of the pinned evidence ({stale:?})"
    );
    // `truth_value` as the mirroring writers leave it: a copy of that fold.
    copy_cache_into_truth(&pool, c).await;
    let stale_truth = truth(&pool, c).await.0;
    assert!(
        (stale_truth - 0.5).abs() > 0.1,
        "PREMISE: the copy carries the pinned evidence ({stale_truth})"
    );

    publicize(&pool, &s, eve, &[c]).await.expect("publicized");

    assert_eq!(tenancy(&pool, "evidence", hidden).await, group(t), "pinned");
    assert_eq!(
        tenancy(&pool, "evidence", open).await.0,
        "public",
        "PREMISE: the claim_validity input went public with the claim"
    );
    let served = served_cache(&pool, &s, carol, c).await;
    assert!(
        vacuous(&served),
        "a stranger must be served full ignorance once binary_truth (the cache owner) has no \
         input it may read; it was served {served:?}, the team's fold was {stale:?}"
    );
    assert_eq!(cache_frame(&pool, c).await, Some(binary), "owner unchanged");
    let (served_tv, _) = served_truth(&pool, &s, carol, c).await;
    assert!(
        (served_tv - 0.5).abs() < 1e-9,
        "the vacated cache's value (0.5) must replace the team's copy {stale_truth} in \
         truth_value; a stranger was served {served_tv}"
    );
}

/// Share: the private claim's `binary_truth` holds only an edge-factor BBA
/// carrying a home-private source claim's belief through a home edge; its
/// `claim_validity` input cites the claim's own evidence, which moves with it.
/// After the share the edge is not the team's to read, and the teammate is
/// served full ignorance, not the home fold that carries the source's belief.
#[sqlx::test(migrations = "../../migrations")]
async fn share_vacates_a_cache_whose_owner_frame_holds_only_a_home_edge_factor_bba(pool: PgPool) {
    let s = app_role(&pool).await;
    let (_, validity) = frames(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "owner-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "owner-bob").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;
    let source = fixture::seed_group_claim(&pool, alice, home, "a home-private source").await;
    sqlx::query("UPDATE claims SET belief = 0.9, plausibility = 0.95 WHERE id = $1")
        .bind(source)
        .execute(&pool)
        .await
        .expect("the source's belief");
    let c = fixture::seed_group_claim(&pool, alice, home, "a private finding, two frames").await;
    let own = fixture::seed_evidence(&pool, c, "observation").await;
    bba_on(&pool, c, validity, alice, own, 0.7).await;
    let edge = fixture::seed_edge(&pool, source, c).await;
    let wired = auto_wire_ds_for_edge(
        &mut pool.acquire().await.expect("acquire"),
        &viewer(&pool, alice).await,
        edge,
        alice,
        source,
        c,
        "supports",
    )
    .await
    .expect("wire the edge");
    assert!(
        matches!(wired, EdgeFactorOutcome::Wired),
        "PREMISE: {wired:?}"
    );
    let (binary, _) = frames(&pool).await;
    refold(&pool, &s, alice, c).await;
    let stale = cache(&pool, c).await;
    assert!(
        cache_frame(&pool, c).await == Some(binary) && stale.0.is_some() && !vacuous(&stale),
        "PREMISE: binary_truth owns the home fold of the source's belief ({stale:?})"
    );

    share(&pool, &s, alice, &[c], t).await.expect("shared");

    assert_eq!(
        tenancy(&pool, "claims", c).await,
        group(t),
        "PREMISE: moved"
    );
    assert!(
        !reads_row(&pool, &s, bob, "edges", edge).await,
        "PREMISE: the teammate cannot read the home edge"
    );
    let served = served_cache(&pool, &s, bob, c).await;
    assert!(
        vacuous(&served),
        "the teammate must be served full ignorance once binary_truth (the cache owner) holds \
         only the home edge's BBA; it was served {served:?}, the home fold was {stale:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 0d9dfd24: truth_value follows the refold
// ─────────────────────────────────────────────────────────────────────────────

/// `agent` adds strongly refuting evidence to `claim` through MCP
/// `update_with_evidence`, which stores a BBA citing a new evidence row and
/// persists `truth_value` as a copy of the fold. The new evidence row's id.
async fn refute_through_mcp(pool: &PgPool, s: &AppRole, agent: Uuid, claim: Uuid) -> Uuid {
    let seed = evidence_of(pool, claim).await;
    update_with_evidence(
        &s.server,
        &viewer(pool, agent).await,
        UpdateWithEvidenceParams {
            claim_id: claim.to_string(),
            canonical_name: None,
            step_index: None,
            evidence_data: format!("a refutation of {claim}"),
            evidence_type: "empirical".to_string(),
            supports: false,
            strength: 0.95,
            source_url: None,
            labels: vec![],
        },
        Some(&token(agent)),
    )
    .await
    .unwrap_or_else(|e| panic!("update_with_evidence on {claim}: {e:?}"));
    sqlx::query_scalar("SELECT id FROM evidence WHERE claim_id = $1 AND id <> $2")
        .bind(claim)
        .bind(seed)
        .fetch_one(pool)
        .await
        .expect("the refutation's evidence row")
}

/// `(truth_value, pignistic_prob)` as stored.
async fn truth(pool: &PgPool, claim: Uuid) -> (f64, Option<f64>) {
    sqlx::query_as("SELECT truth_value, pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("truth")
}

/// `(truth_value, pignistic_prob)` as `agent` is served them, on its stamped
/// app-role connection.
async fn served_truth(pool: &PgPool, s: &AppRole, agent: Uuid, claim: Uuid) -> (f64, Option<f64>) {
    let v = viewer(pool, agent).await;
    let mut conn = s.scoped.acquire_as(&v).await.expect("stamped connection");
    sqlx::query_as("SELECT truth_value, pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("{agent} reads the claim's truth value: {e}"))
}

/// The premise both tests share: `update_with_evidence` stored `truth_value`
/// as a copy of its fold, which took in the refuting BBA, so it differs from
/// `expected`, the control's refolded value (which never had that BBA).
fn assert_truth_premise(stale: (f64, Option<f64>), expected: f64) {
    let (t0, p0) = stale;
    assert!(
        p0.is_some_and(|p| (t0 - p).abs() < 1e-12),
        "PREMISE: update_with_evidence persisted truth_value as a copy of its fold \
         ({t0} vs {p0:?})"
    );
    assert!(
        (t0 - expected).abs() > 0.05,
        "PREMISE: the copy carries the refuting BBA ({t0}), so it differs from the control's \
         value ({expected})"
    );
}

/// Share: the private claim's `truth_value` was persisted from a fold that
/// took in a BBA citing evidence pinned at home. After the act the teammate is
/// served the truth value of a control claim that never had that BBA, the
/// refolded cache, and not the home copy.
#[sqlx::test(migrations = "../../migrations")]
async fn share_replaces_a_truth_value_copied_from_a_fold_of_evidence_left_at_home(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "truth-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "truth-bob").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;
    let c = write(
        &pool,
        &s,
        alice,
        "a private finding, refuted at home",
        "private",
        None,
    )
    .await;
    let control = write(&pool, &s, alice, "the same finding, team", "team", Some(t)).await;
    let hidden = refute_through_mcp(&pool, &s, alice, c).await;
    pin(&pool, hidden, alice).await;
    refold(&pool, &s, alice, control).await;
    let expected = cache(&pool, control)
        .await
        .0
        .expect("PREMISE: the control has a cache");
    let stale = truth(&pool, c).await;
    assert_truth_premise(stale, expected);

    share(&pool, &s, alice, &[c], t).await.expect("shared");

    assert_eq!(
        tenancy(&pool, "evidence", hidden).await,
        group(home),
        "pinned"
    );
    let (served, betp) = served_truth(&pool, &s, bob, c).await;
    assert!(
        (served - expected).abs() < 1e-9,
        "the teammate is served truth_value {served}, which must be the team-readable value \
         {expected} (the control's), not the home copy {}",
        stale.0
    );
    assert!(
        betp.is_some_and(|p| (p - served).abs() < 1e-12),
        "truth_value {served} is the refolded cache {betp:?}"
    );
}

/// Publicize: the team claim's `truth_value` was persisted from a fold that
/// took in a BBA citing evidence pinned in the team. After the act a stranger
/// is served the truth value of a public control claim that never had that
/// BBA, not the team's copy.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_replaces_a_truth_value_copied_from_a_fold_of_evidence_left_behind(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "truth-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "truth-stranger").await;
    add_member(&pool, t, eve, "admin").await;
    let c = write(
        &pool,
        &s,
        eve,
        "a team finding, refuted in the team",
        "team",
        Some(t),
    )
    .await;
    let control = write(&pool, &s, eve, "the same finding, public", "public", None).await;
    let hidden = refute_through_mcp(&pool, &s, eve, c).await;
    pin(&pool, hidden, eve).await;
    refold(&pool, &s, eve, control).await;
    let expected = cache(&pool, control)
        .await
        .0
        .expect("PREMISE: the control has a cache");
    let stale = truth(&pool, c).await;
    assert_truth_premise(stale, expected);

    publicize(&pool, &s, eve, &[c]).await.expect("publicized");

    assert_eq!(tenancy(&pool, "evidence", hidden).await, group(t), "pinned");
    let (served, betp) = served_truth(&pool, &s, carol, c).await;
    assert!(
        (served - expected).abs() < 1e-9,
        "a stranger is served truth_value {served}, which must be the public value {expected} \
         (the control's), not the team's copy {}",
        stale.0
    );
    assert!(
        betp.is_some_and(|p| (p - served).abs() < 1e-12),
        "truth_value {served} is the refolded cache {betp:?}"
    );
}

/// Set `truth_value` to the claim's cached BetP, as the mirroring writers
/// (`submit_claim`, `update_with_evidence`) persist it.
async fn copy_cache_into_truth(pool: &PgPool, claim: Uuid) {
    sqlx::query(
        "UPDATE claims SET truth_value = LEAST(GREATEST(pignistic_prob, 0.0), 1.0) \
          WHERE id = $1 AND pignistic_prob IS NOT NULL",
    )
    .bind(claim)
    .execute(pool)
    .await
    .expect("copy the cache into truth_value");
}

/// Make `claim` a legacy flat workflow claim (the `workflow` label, which
/// `report_workflow_outcome`'s flat path and `find_workflow` key on).
async fn label_workflow(pool: &PgPool, claim: Uuid) {
    sqlx::query("UPDATE claims SET labels = array_append(labels, 'workflow') WHERE id = $1")
        .bind(claim)
        .execute(pool)
        .await
        .expect("label the workflow claim");
}

/// Publicize a flat workflow claim: `report_workflow_outcome` persisted its
/// `truth_value` as a copy of a fold that took in a failed run's outcome BBA,
/// whose evidence stays in the team (pinned). After the act a stranger is
/// served the value of a public control workflow that never had that report,
/// not the team's copy, which `find_workflow` would filter and rank on.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_replaces_a_workflow_truth_value_copied_from_an_outcome_left_behind(
    pool: PgPool,
) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "wf-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "wf-stranger").await;
    add_member(&pool, t, eve, "admin").await;
    let c = write(
        &pool,
        &s,
        eve,
        "a team workflow: run the check",
        "team",
        Some(t),
    )
    .await;
    let control = write(&pool, &s, eve, "the same workflow, public", "public", None).await;
    label_workflow(&pool, c).await;
    label_workflow(&pool, control).await;
    let seed = evidence_of(&pool, c).await;
    report_workflow_outcome(
        &s.server,
        &viewer(&pool, eve).await,
        ReportWorkflowOutcomeParams {
            workflow_id: c.to_string(),
            success: false,
            execution_log: vec![StepExecution {
                step_index: 0,
                planned: "run the check".to_string(),
                actual: "the check failed".to_string(),
                deviated: false,
                deviation_reason: None,
            }],
            outcome_details: "a team-internal failure".to_string(),
            quality: Some(0.95),
            goal_text: None,
            idempotency_key: None,
        },
        Some(&token(eve)),
    )
    .await
    .unwrap_or_else(|e| panic!("report_workflow_outcome on {c}: {e:?}"));
    let outcome: Uuid =
        sqlx::query_scalar("SELECT id FROM evidence WHERE claim_id = $1 AND id <> $2")
            .bind(c)
            .bind(seed)
            .fetch_one(&pool)
            .await
            .expect("the outcome's evidence row");
    pin(&pool, outcome, eve).await;
    refold(&pool, &s, eve, control).await;
    let expected = cache(&pool, control)
        .await
        .0
        .expect("PREMISE: the control has a cache");
    let stale = truth(&pool, c).await;
    assert_truth_premise(stale, expected);

    publicize(&pool, &s, eve, &[c]).await.expect("publicized");

    assert_eq!(
        tenancy(&pool, "evidence", outcome).await,
        group(t),
        "pinned"
    );
    let (served, betp) = served_truth(&pool, &s, carol, c).await;
    assert!(
        (served - expected).abs() < 1e-9,
        "a stranger is served the workflow's truth_value {served}, which must be the public \
         value {expected} (the control's), not the team's copy {}",
        stale.0
    );
    assert!(
        betp.is_some_and(|p| (p - served).abs() < 1e-12),
        "truth_value {served} is the refolded cache {betp:?}"
    );
}

/// Publicize a claim at the deprecation marker that is still current, as
/// `delete_step` leaves a soft-deleted step: its cache is refolded, but its
/// `truth_value` stays 0.05, so the act does not revive it.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_keeps_a_current_claim_at_the_deprecation_marker(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "marker-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "marker-stranger").await;
    add_member(&pool, t, eve, "admin").await;
    let c = write(&pool, &s, eve, "a soft-deleted team step", "team", Some(t)).await;
    let hidden = refute_through_mcp(&pool, &s, eve, c).await;
    pin(&pool, hidden, eve).await;
    let stale = cache(&pool, c).await;
    // `delete_step`'s write: the marker, and the claim stays current.
    sqlx::query("UPDATE claims SET truth_value = 0.05 WHERE id = $1")
        .bind(c)
        .execute(&pool)
        .await
        .expect("soft delete");

    publicize(&pool, &s, eve, &[c]).await.expect("publicized");

    let (served, betp) = served_truth(&pool, &s, carol, c).await;
    assert!(
        betp.is_some_and(|p| stale.0.is_some_and(|q| (p - q).abs() > 0.05)),
        "PREMISE: the act refolded the cache ({:?} -> {betp:?})",
        stale.0
    );
    let current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(c)
        .fetch_one(&pool)
        .await
        .expect("is_current");
    assert!(current, "PREMISE: the soft-deleted step is still current");
    assert!(
        (served - 0.05).abs() < 1e-9,
        "the deprecation marker must survive the act; a stranger was served {served}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4d8df0cf: the moved claim's scoped rows, written afresh
// ─────────────────────────────────────────────────────────────────────────────

/// A stale scoped row of `claim` on `frame` (values no fold produces here).
async fn stale_scoped_row(pool: &PgPool, claim: Uuid, frame: Uuid, scope: &str, id: Option<Uuid>) {
    sqlx::query(
        "INSERT INTO ds_combined_beliefs (frame_id, claim_id, scope_type, scope_id, belief, \
                                          plausibility, pignistic_prob) \
         VALUES ($1, $2, $3, $4, 0.1, 0.2, 0.15)",
    )
    .bind(frame)
    .bind(claim)
    .bind(scope)
    .bind(id)
    .execute(pool)
    .await
    .expect("seed a scoped row");
}

/// Publicize: the team claim's `binary_truth` holds a BBA on evidence that
/// goes public with it (under the genuine perspective `open`) and one on
/// evidence pinned in the team (under perspective `hidden`), and the claim has
/// a global row and a row per perspective. (Before migration 267 an evidence
/// BBA was keyed on its evidence id AS a perspective, and this test used those
/// ids as the two lenses; since 267 an evidence id is a slot, never a
/// perspective, so the lenses are real `perspectives` rows citing the
/// evidence through `evidence_id`.) Right after the act a stranger reads the global row and the
/// `open` perspective row folded from the public BBA alone, and no `hidden`
/// row: nothing of it is admissible.
///
/// The oracle is arithmetic: one BBA with mass 0.7 on the claim's hypothesis
/// and 0.3 on the whole frame, read undiscounted, is Bel 0.7, Pl 1, BetP 0.85.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_writes_the_moved_claims_scoped_rows_afresh_for_the_public(pool: PgPool) {
    let s = app_role(&pool).await;
    let (binary, _) = frames(&pool).await;
    let t = team(&pool, "team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "scoped-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "scoped-stranger").await;
    add_member(&pool, t, eve, "admin").await;
    let c = fixture::seed_group_claim(&pool, eve, t, "a team finding, two perspectives").await;
    let open = fixture::seed_evidence(&pool, c, "observation").await;
    let hidden = fixture::seed_evidence(&pool, c, "reference").await;
    pin(&pool, hidden, eve).await;
    let (open_lens, hidden_lens) = (
        lens(&pool, "open", eve).await,
        lens(&pool, "hidden", eve).await,
    );
    bba_under_lens(&pool, c, binary, eve, open_lens, open, 0.7).await;
    bba_under_lens(&pool, c, binary, eve, hidden_lens, hidden, 0.9).await;
    refold(&pool, &s, eve, c).await;
    stale_scoped_row(&pool, c, binary, "global", None).await;
    stale_scoped_row(&pool, c, binary, "perspective", Some(open_lens)).await;
    stale_scoped_row(&pool, c, binary, "perspective", Some(hidden_lens)).await;

    publicize(&pool, &s, eve, &[c]).await.expect("publicized");

    assert_eq!(tenancy(&pool, "evidence", hidden).await, group(t), "pinned");
    let open_only: Cache = (Some(0.85), Some(0.7), Some(1.0));
    let global = served_scoped(&pool, &s, carol, c, "global", None).await;
    assert!(
        global.as_ref().is_some_and(|g| same(g, &open_only)),
        "the stranger reads the global row folded from the public BBA alone {open_only:?}, \
         not nothing and not the team's fold; read {global:?}"
    );
    let persp = served_scoped(&pool, &s, carol, c, "perspective", Some(open_lens)).await;
    assert!(
        persp.as_ref().is_some_and(|p| same(p, &open_only)),
        "the stranger reads the public perspective's row {open_only:?}; read {persp:?}"
    );
    let n_hidden: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ds_combined_beliefs WHERE claim_id = $1 AND scope_id = $2",
    )
    .bind(c)
    .bind(hidden_lens)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        n_hidden, 0,
        "the pinned perspective has nothing admissible: no row"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6e4ff46e: the Beta track follows the act
// ─────────────────────────────────────────────────────────────────────────────

/// `agent` adds evidence to `claim` through MCP `update_with_evidence`, which
/// stores a BBA citing a new evidence row and counts it on the claim's Beta
/// track. The new evidence row's id.
async fn evidence_through_mcp(
    pool: &PgPool,
    s: &AppRole,
    agent: Uuid,
    claim: Uuid,
    supports: bool,
    strength: f64,
) -> Uuid {
    let ids = |pool: &PgPool| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM evidence WHERE claim_id = $1")
                .bind(claim)
                .fetch_all(&pool)
                .await
                .expect("the claim's evidence rows")
        }
    };
    let before = ids(pool).await;
    update_with_evidence(
        &s.server,
        &viewer(pool, agent).await,
        UpdateWithEvidenceParams {
            claim_id: claim.to_string(),
            canonical_name: None,
            step_index: None,
            evidence_data: format!("evidence on {claim}: supports={supports} at {strength}"),
            evidence_type: "empirical".to_string(),
            supports,
            strength,
            source_url: None,
            labels: vec![],
        },
        Some(&token(agent)),
    )
    .await
    .unwrap_or_else(|e| panic!("update_with_evidence on {claim}: {e:?}"));
    ids(pool)
        .await
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("the update's evidence row")
}

/// `(beta_alpha, beta_beta)`, a NULL read as the `Beta(1, 1)` prior.
type Track = (f64, f64);

const PRIOR: Track = (1.0, 1.0);

async fn track(pool: &PgPool, claim: Uuid) -> Track {
    sqlx::query_as(
        "SELECT COALESCE(beta_alpha, 1.0), COALESCE(beta_beta, 1.0) FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("track")
}

/// The Beta track as `agent` is served it, on its stamped app-role
/// connection.
async fn served_track(pool: &PgPool, s: &AppRole, agent: Uuid, claim: Uuid) -> Track {
    let v = viewer(pool, agent).await;
    let mut conn = s.scoped.acquire_as(&v).await.expect("stamped connection");
    sqlx::query_as(
        "SELECT COALESCE(beta_alpha, 1.0), COALESCE(beta_beta, 1.0) FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(&mut *conn)
    .await
    .unwrap_or_else(|e| panic!("{agent} reads the claim's Beta track: {e}"))
}

fn same_track(a: Track, b: Track) -> bool {
    (a.0 - b.0).abs() < 1e-9 && (a.1 - b.1).abs() < 1e-9
}

/// Share: the private claim's Beta track counted a refutation citing evidence
/// pinned at home, beside a support that moves with the claim. After the act
/// the teammate is served the track of a control team claim that only ever
/// had the support, not the home track (whose posterior, and the divergence
/// rows the next evidence write records from it, carry the hidden refutation).
#[sqlx::test(migrations = "../../migrations")]
async fn share_rebuilds_the_beta_track_without_the_evidence_left_at_home(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "beta-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "beta-bob").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;
    let c = write(
        &pool,
        &s,
        alice,
        "a private finding, tracked",
        "private",
        None,
    )
    .await;
    let control = write(&pool, &s, alice, "the same finding, team", "team", Some(t)).await;
    evidence_through_mcp(&pool, &s, alice, c, true, 0.8).await;
    evidence_through_mcp(&pool, &s, alice, control, true, 0.8).await;
    let hidden = evidence_through_mcp(&pool, &s, alice, c, false, 0.95).await;
    pin(&pool, hidden, alice).await;
    let stale = track(&pool, c).await;
    let expected = track(&pool, control).await;
    assert!(
        !same_track(expected, PRIOR) && !same_track(stale, expected),
        "PREMISE: the control's track counted the support ({expected:?}) and the home track \
         also counted the hidden refutation ({stale:?})"
    );

    share(&pool, &s, alice, &[c], t).await.expect("shared");

    assert_eq!(
        tenancy(&pool, "evidence", hidden).await,
        group(home),
        "pinned"
    );
    let served = served_track(&pool, &s, bob, c).await;
    assert!(
        same_track(served, expected),
        "the teammate is served Beta track {served:?}, which must be the team-readable \
         track {expected:?} (the control's), not the home track {stale:?}"
    );
}

/// Publicize: one team claim's track counted a refutation citing evidence
/// pinned in the team beside a support that goes public; another's counted
/// only pinned evidence. After the act a stranger is served, for the first,
/// the track of a public control claim that only ever had the support, and
/// for the second the `Beta(1, 1)` prior.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_rebuilds_the_beta_track_without_the_evidence_left_behind(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "beta-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "beta-stranger").await;
    add_member(&pool, t, eve, "admin").await;
    let c = write(&pool, &s, eve, "a team finding, tracked", "team", Some(t)).await;
    let only_hidden = write(&pool, &s, eve, "a team hunch, tracked", "team", Some(t)).await;
    let control = write(&pool, &s, eve, "the same finding, public", "public", None).await;
    evidence_through_mcp(&pool, &s, eve, c, true, 0.8).await;
    evidence_through_mcp(&pool, &s, eve, control, true, 0.8).await;
    let hidden = evidence_through_mcp(&pool, &s, eve, c, false, 0.95).await;
    pin(&pool, hidden, eve).await;
    let hidden_only = evidence_through_mcp(&pool, &s, eve, only_hidden, false, 0.95).await;
    pin(&pool, hidden_only, eve).await;
    let stale = track(&pool, c).await;
    let expected = track(&pool, control).await;
    assert!(
        !same_track(expected, PRIOR) && !same_track(stale, expected),
        "PREMISE: the control's track counted the support ({expected:?}) and the team track \
         also counted the hidden refutation ({stale:?})"
    );
    let stale_only = track(&pool, only_hidden).await;
    assert!(
        !same_track(stale_only, PRIOR),
        "PREMISE: the second claim's track counted its hidden refutation ({stale_only:?})"
    );

    publicize(&pool, &s, eve, &[c, only_hidden])
        .await
        .expect("publicized");

    assert_eq!(tenancy(&pool, "evidence", hidden).await, group(t), "pinned");
    let served = served_track(&pool, &s, carol, c).await;
    assert!(
        same_track(served, expected),
        "a stranger is served Beta track {served:?}, which must be the public track \
         {expected:?} (the control's), not the team's {stale:?}"
    );
    let served_only = served_track(&pool, &s, carol, only_hidden).await;
    assert!(
        same_track(served_only, PRIOR),
        "a claim with no publicly readable evidence must be back at the Beta(1, 1) prior; a \
         stranger was served {served_only:?} (the team's track was {stale_only:?})"
    );
}

/// `ds_bayesian_divergence` rows of `claim`.
async fn divergence_rows(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM ds_bayesian_divergence WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count divergence rows")
}

/// A claim shared BEFORE the act rebuilt the Beta track (simulated: the stale
/// home track put back after the share, and a divergence row a later evidence
/// write recorded from it) is fixed by the one-off
/// `rebuild_moved_beta_tracks` on a maintenance connection: a dry run writes
/// nothing and reports the rebuilt track; an applying run serves the
/// teammate the team-readable track and deletes the divergence row; and a
/// `moved_before` earlier than the act names no claim.
#[sqlx::test(migrations = "../../migrations")]
async fn the_one_off_rebuild_fixes_a_claim_shared_before_the_act_rebuilt_its_track(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, _) = fixture::seed_agent_with_group(&pool, "backfill-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "backfill-bob").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;
    let c = write(
        &pool,
        &s,
        alice,
        "a private finding, moved early",
        "private",
        None,
    )
    .await;
    let control = write(&pool, &s, alice, "the same finding, team", "team", Some(t)).await;
    evidence_through_mcp(&pool, &s, alice, c, true, 0.8).await;
    evidence_through_mcp(&pool, &s, alice, control, true, 0.8).await;
    let hidden = evidence_through_mcp(&pool, &s, alice, c, false, 0.95).await;
    pin(&pool, hidden, alice).await;
    let stale = track(&pool, c).await;
    let expected = track(&pool, control).await;
    assert!(
        !same_track(stale, expected),
        "PREMISE: the home track ({stale:?}) counted the hidden refutation"
    );
    share(&pool, &s, alice, &[c], t).await.expect("shared");

    // What a claim moved before this deploy looks like: the stale track, and
    // a divergence row recorded from it by a later evidence write.
    sqlx::query("UPDATE claims SET beta_alpha = $2, beta_beta = $3 WHERE id = $1")
        .bind(c)
        .bind(stale.0)
        .bind(stale.1)
        .execute(&pool)
        .await
        .expect("put the stale track back");
    let frame: Uuid =
        sqlx::query_scalar("SELECT frame_id FROM mass_functions WHERE claim_id = $1 LIMIT 1")
            .bind(c)
            .fetch_one(&pool)
            .await
            .expect("a frame of the claim");
    sqlx::query(
        "INSERT INTO ds_bayesian_divergence (claim_id, frame_id, pignistic_prob, \
                                             bayesian_posterior, kl_divergence) \
         VALUES ($1, $2, 0.6, 0.45, 0.1)",
    )
    .bind(c)
    .bind(frame)
    .execute(&pool)
    .await
    .expect("seed a divergence row from the stale track");
    assert!(
        same_track(served_track(&pool, &s, bob, c).await, stale),
        "PREMISE: the teammate is served the stale home track"
    );

    let (scoped, bypass) = fixture::bypass(&pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(epigraph_db::visibility::SystemReason::SchemaContractTest)
        .await
        .expect("maintenance connection");
    let rebuild = epigraph_engine::visibility_act::rebuild_moved_beta_tracks;

    let early = rebuild(
        &mut conn,
        &bypass,
        Some(chrono::Utc::now() - chrono::Duration::days(3650)),
        true,
    )
    .await
    .expect("a run limited to acts ten years ago");
    assert_eq!(early.moved_claims, 0, "moved_before excludes later acts");

    let dry = rebuild(&mut conn, &bypass, None, false)
        .await
        .expect("dry run");
    let row = dry
        .rebuilt
        .iter()
        .find(|r| r.claim_id == c)
        .unwrap_or_else(|| panic!("the dry run names the shared claim: {dry:?}"));
    assert!(
        same_track(row.before, stale) && same_track(row.after, expected),
        "the dry run reports {:?} -> {:?}, wanted {stale:?} -> {expected:?}",
        row.before,
        row.after
    );
    assert_eq!(row.divergence_rows_cleared, 1, "the dry run counts the row");
    assert!(
        same_track(track(&pool, c).await, stale) && divergence_rows(&pool, c).await == 1,
        "a dry run writes nothing"
    );

    let applied = rebuild(&mut conn, &bypass, None, true)
        .await
        .expect("applying run");
    assert!(applied.failed.is_empty(), "no claim failed: {applied:?}");
    let served = served_track(&pool, &s, bob, c).await;
    assert!(
        same_track(served, expected),
        "after the rebuild the teammate is served {served:?}, which must be the team-readable \
         track {expected:?}, not the home track {stale:?}"
    );
    assert_eq!(
        divergence_rows(&pool, c).await,
        0,
        "the divergence row recorded from the stale track is deleted"
    );
}
