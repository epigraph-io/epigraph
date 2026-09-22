//! Integration tests for `DELETE /api/v1/workflows/:id` (deprecate_workflow).
//!
//! Phase B of the flat-workflow consolidation (epigraph-io/epigraph#36):
//! deprecating a workflow MUST set `is_current = false` in addition to
//! lowering `truth_value` to 0.05. Before the fix, callers of
//! `WorkflowRepository::list` with `min_truth = 0.0` (the common default)
//! continued to see deprecated workflows because 0.05 > 0.0; the
//! `is_current` flip is what guarantees they disappear from the list
//! regardless of the truth threshold.
//!
//! # The authorization gate (F-write-authz-reads-unfiltered)
//!
//! The handler used to take no `AuthContext`, check no scope and no owner, and
//! gate on an UNFILTERED `SELECT id FROM claims WHERE id = $1 AND 'workflow' =
//! ANY(labels)`. Any bearer token — `graph:read` included — could deprecate any
//! workflow claim, including one private to a group it is not in. The tests
//! below pin each layer of the replacement gate, in order:
//!
//! 1. `claims:write` (403 without it);
//! 2. the workflow must be READABLE by the caller (404 when it is not — absent,
//!    not forbidden);
//! 3. the caller must own it or hold `claims:admin` (403);
//! 4. the `UPDATE` itself carries `{WRITABLE:c}`, so the caller must be able to
//!    write the group that owns the row (403 when it cannot).
//!
//! Every refusal asserts the ROW as well as the status: a 4xx that still wrote
//! would pass a status-only test.
//!
//! # Fixture shape
//!
//! Workflow claims are declared `(visibility, owner_group_id)` explicitly, on
//! their author's personal group — the shape `POST /api/v1/claims` and the D2
//! legacy backfill both produce. A claim inserted WITHOUT a declaration lands in
//! the seed group through 074's escape hatch, which nobody can write, and would
//! make every success-path test here a test of that hatch instead.

#![cfg(feature = "db")]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

async fn test_pool() -> (String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to test DB");
    (url, pool)
}

/// Seed a `'workflow'`-labelled claim authored by `owner`, declared
/// `(visibility, <owner's personal group>)`. `truth_value = 0.9`,
/// `is_current = true`.
async fn seed_workflow(pool: &PgPool, owner: Uuid, visibility: &str) -> Uuid {
    let group = common::personal_group_of(pool, owner).await;
    let id = Uuid::new_v4();
    // Per-row unique content_hash so repeated runs against a shared test DB do
    // not collide.
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, \
                             is_current, labels, visibility, owner_group_id) \
         VALUES ($1, 'workflow under test', $2, $3, 0.9, true, ARRAY['workflow'], $4, $5)",
    )
    .bind(id)
    .bind(&hash)
    .bind(owner)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed workflow claim");
    id
}

/// `(truth_value, is_current)` for `id`.
async fn row_state(pool: &PgPool, id: Uuid) -> (f64, bool) {
    sqlx::query_as("SELECT truth_value, is_current FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read back workflow claim")
}

fn assert_untouched(state: (f64, bool), what: &str) {
    assert!(
        (state.0 - 0.9).abs() < 1e-9 && state.1,
        "{what} must be untouched (truth 0.9, is_current true), got {state:?}"
    );
}

fn assert_deprecated(state: (f64, bool), what: &str) {
    assert!(
        (state.0 - 0.05).abs() < 1e-9 && !state.1,
        "{what} must be deprecated (truth 0.05, is_current false), got {state:?}"
    );
}

async fn deprecate(
    addr: std::net::SocketAddr,
    token: &str,
    workflow_id: Uuid,
    cascade: bool,
) -> (u16, String) {
    let resp = reqwest::Client::new()
        .delete(format!(
            "http://{addr}/api/v1/workflows/{workflow_id}?reason=test-deprecate&cascade={cascade}"
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("HTTP DELETE succeeds");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

/// Insert `source --supersedes--> target` and force the edge PUBLIC.
///
/// Forced, because migration 070 makes an edge inherit its endpoints'
/// tenancy: an edge touching a private claim is private too, and
/// `find_descendants`' EDGE predicate would then exclude the descendant before
/// the handler's own claims read ever saw it. With the edge public, the only
/// thing that can keep a private descendant out of the cascade is the
/// predicate on `claims` — which is the thing under test.
async fn seed_public_supersedes_edge(pool: &PgPool, source: Uuid, target: Uuid, group: Uuid) {
    let edge = common::insert_edge(pool, source, target, "claim", "claim", "supersedes").await;
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(group)
    .execute(pool)
    .await
    .expect("force the supersedes edge public");
}

/// DELETE /api/v1/workflows/:id should set both `truth_value = 0.05`
/// AND `is_current = false` on the underlying claim row.
#[tokio::test(flavor = "multi_thread")]
async fn deprecate_workflow_sets_is_current_false_and_lowers_truth() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let workflow_id = seed_workflow(&pool, owner, "public").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(owner, &["claims:write"]);
    let (status, body) = deprecate(addr, &token, workflow_id, false).await;
    assert_eq!(status, 200, "DELETE should return 200 OK; body={body}");

    assert_deprecated(row_state(&pool, workflow_id).await, "the workflow");
}

/// A workflow private to a group the caller is not in is ABSENT: 404, and
/// nothing is written.
///
/// Before the fix this returned 200 and deprecated the row: the existence gate
/// was unfiltered and nothing else stood between the caller and the write.
#[tokio::test(flavor = "multi_thread")]
async fn deprecating_a_workflow_the_caller_cannot_read_is_404_and_writes_nothing() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let workflow_id = seed_workflow(&pool, owner, "group").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let stranger = common::test_bearer_token_for_principal(Uuid::new_v4(), &["claims:write"]);
    let (status, body) = deprecate(addr, &stranger, workflow_id, false).await;
    assert_eq!(
        status, 404,
        "a workflow the caller cannot read must be absent (404); body={body}"
    );

    assert_untouched(
        row_state(&pool, workflow_id).await,
        "the unreadable workflow",
    );
}

/// `claims:write` is required. The route used to check no scope at all, so a
/// `graph:read` token could deprecate.
#[tokio::test(flavor = "multi_thread")]
async fn deprecate_without_claims_write_is_403_and_writes_nothing() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let workflow_id = seed_workflow(&pool, owner, "public").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    // The OWNER, so the only thing missing is the scope.
    let token = common::test_bearer_token_for_principal(owner, &["graph:read"]);
    let (status, body) = deprecate(addr, &token, workflow_id, false).await;
    assert_eq!(status, 403, "claims:write is required; body={body}");

    assert_untouched(row_state(&pool, workflow_id).await, "the workflow");
}

/// A readable workflow authored by someone else is 403 for a non-admin.
#[tokio::test(flavor = "multi_thread")]
async fn deprecating_another_principals_workflow_is_403_and_writes_nothing() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let workflow_id = seed_workflow(&pool, owner, "public").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let other = common::test_bearer_token_for_principal(Uuid::new_v4(), &["claims:write"]);
    let (status, body) = deprecate(addr, &other, workflow_id, false).await;
    assert_eq!(
        status, 403,
        "a non-owner without claims:admin must be refused; body={body}"
    );

    assert_untouched(row_state(&pool, workflow_id).await, "the workflow");
}

/// The write predicate is real, not decorative.
///
/// A `claims:admin` token PASSES the owner gate, so on a public workflow owned
/// by another principal's personal group the only thing that can refuse the
/// write is the `{WRITABLE:c}` marker on the `UPDATE` — the admin is in no
/// group that owns the row. Remove the marker and this test goes 200.
#[tokio::test(flavor = "multi_thread")]
async fn claims_admin_outside_the_owning_group_cannot_deprecate() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let workflow_id = seed_workflow(&pool, owner, "public").await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let admin =
        common::test_bearer_token_for_principal(Uuid::new_v4(), &["claims:write", "claims:admin"]);
    let (status, body) = deprecate(addr, &admin, workflow_id, false).await;
    assert_eq!(
        status, 403,
        "the write predicate must refuse a principal that cannot write the owning group; \
         body={body}"
    );

    assert_untouched(row_state(&pool, workflow_id).await, "the workflow");
}

/// A cascade skips a descendant the caller cannot read, and deprecates the
/// root.
///
/// Skip, not refuse: the caller cannot see the descendant, so refusing would
/// disclose that the lineage reaches a private row. This matches the MCP
/// twin's cascade, which also skips an unreadable child.
#[tokio::test(flavor = "multi_thread")]
async fn cascade_skips_a_descendant_the_caller_cannot_read() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let other = common::seed_system_agent(&pool).await;
    let root = seed_workflow(&pool, owner, "public").await;
    let hidden = seed_workflow(&pool, other, "group").await;
    let owner_group = common::personal_group_of(&pool, owner).await;
    seed_public_supersedes_edge(&pool, hidden, root, owner_group).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(owner, &["claims:write"]);
    let (status, body) = deprecate(addr, &token, root, true).await;
    assert_eq!(status, 200, "the owner's cascade must succeed; body={body}");

    let json: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
    assert_eq!(
        json["deprecated_ids"],
        serde_json::json!([root]),
        "only the root may be reported; the unreadable descendant must not appear"
    );
    assert_deprecated(row_state(&pool, root).await, "the root");
    assert_untouched(
        row_state(&pool, hidden).await,
        "the descendant private to another group",
    );
}

/// A cascade that reaches a READABLE workflow owned by someone else is refused
/// as a whole, and writes nothing — including the root.
///
/// Refuse, not skip: the caller can see that descendant, so naming it discloses
/// nothing, and a silently partial cascade would leave a lineage half
/// deprecated with a 200.
#[tokio::test(flavor = "multi_thread")]
async fn cascade_refuses_a_readable_descendant_the_caller_does_not_own() {
    let (url, pool) = test_pool().await;
    let owner = common::seed_system_agent(&pool).await;
    let other = common::seed_system_agent(&pool).await;
    let root = seed_workflow(&pool, owner, "public").await;
    let foreign = seed_workflow(&pool, other, "public").await;
    let owner_group = common::personal_group_of(&pool, owner).await;
    seed_public_supersedes_edge(&pool, foreign, root, owner_group).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_for_principal(owner, &["claims:write"]);
    let (status, body) = deprecate(addr, &token, root, true).await;
    assert_eq!(
        status, 403,
        "a cascade into another principal's workflow must be refused; body={body}"
    );

    assert_untouched(
        row_state(&pool, root).await,
        "the root of the refused cascade",
    );
    assert_untouched(
        row_state(&pool, foreign).await,
        "the descendant owned by another principal",
    );
}
