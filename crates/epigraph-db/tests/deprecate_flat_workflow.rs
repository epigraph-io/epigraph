//! `WorkflowRepository::flat_workflow_author` and
//! `WorkflowRepository::deprecate_flat_workflow`: the read and the write behind
//! `DELETE /api/v1/workflows/:id` (F-write-authz-reads-unfiltered).
//!
//! The route-level tests in `epigraph-api/tests/workflow_deprecate_test.rs`
//! pin the status codes. These pin two properties those tests cannot reach:
//!
//! * the `workflows` MIRROR. Every route fixture is a flat-only workflow with
//!   no `workflows` row, so the mirror CTE runs there but updates nothing;
//! * that a refused claim write mirrors NOTHING. The mirror is gated by the
//!   claim `UPDATE`'s `RETURNING`, not by a second, independent statement.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::WorkflowRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// A `'workflow'`-labelled claim authored by `agent`, declared
/// `(visibility, group)`, with an embedding so the null-on-deprecate half of
/// the embedding policy is observable.
async fn seed_workflow_claim(pool: &PgPool, agent: Uuid, visibility: &str, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    let mut v = vec!["0.0"; 1536];
    v[0] = "0.1";
    let vec_literal = format!("[{}]", v.join(","));
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             labels, visibility, owner_group_id, embedding) \
         VALUES ($1, 'flat workflow', $2, $3, 0.9, true, ARRAY['workflow'], $4, $5, $6::vector)",
    )
    .bind(id)
    .bind(&hash)
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .bind(&vec_literal)
    .execute(pool)
    .await
    .expect("seed workflow claim");
    id
}

/// A hierarchical `workflows` row sharing `id` with the flat claim, which is
/// the shape the mirror exists for. `truth_value` starts at the column
/// default.
async fn seed_workflows_row(pool: &PgPool, id: Uuid) {
    WorkflowRepository::insert_root(
        pool,
        id,
        &format!("deprecate-mirror-{id}"),
        0,
        "goal",
        None,
        serde_json::json!({}),
    )
    .await
    .expect("seed workflows row");
}

/// `(truth_value, is_current, has_embedding)` of the claim, and the mirrored
/// `workflows.truth_value`.
async fn state(pool: &PgPool, id: Uuid) -> ((f64, bool, bool), f64) {
    let claim: (f64, bool, bool) = sqlx::query_as(
        "SELECT truth_value, is_current, embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read claim");
    let mirror: f64 = sqlx::query_scalar("SELECT truth_value FROM workflows WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read workflows row");
    (claim, mirror)
}

async fn viewer_for(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve viewer")
}

/// The owner writes the claim, nulls its embedding, and the `workflows` row
/// with the same id follows it to 0.05.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writable_deprecation_mirrors_onto_the_workflows_row(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "deprecate-owner").await;
    let id = seed_workflow_claim(&pool, owner, "public", group).await;
    seed_workflows_row(&pool, id).await;
    let (_, mirror_before) = state(&pool, id).await;
    assert!(
        (mirror_before - 0.05).abs() > 1e-9,
        "the workflows row must not start at the deprecation sentinel, or the mirror \
         assertion below proves nothing; got {mirror_before}"
    );

    let viewer = viewer_for(&pool, owner).await;
    let written = WorkflowRepository::deprecate_flat_workflow(&pool, &viewer, id)
        .await
        .expect("deprecate");
    assert!(written, "the owner writes its own group's row");

    let ((truth, is_current, has_embedding), mirror) = state(&pool, id).await;
    assert!(
        (truth - 0.05).abs() < 1e-9,
        "claim truth is 0.05, got {truth}"
    );
    assert!(!is_current, "claim is no longer current");
    assert!(
        !has_embedding,
        "an is_current = false claim must carry no embedding (CLAUDE.md embedding policy)"
    );
    assert!(
        (mirror - 0.05).abs() < 1e-9,
        "workflows row mirrored to 0.05, got {mirror}"
    );
}

/// A principal outside the owning group writes NOTHING: not the claim, and not
/// the `workflows` row that shares its id.
///
/// The second half is what the old two-statement shape could not guarantee:
/// `set_truth_value` ran whether or not the claim write had matched a row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_deprecation_mirrors_nothing(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "deprecate-owner").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "deprecate-stranger").await;
    let id = seed_workflow_claim(&pool, owner, "public", group).await;
    seed_workflows_row(&pool, id).await;
    let before = state(&pool, id).await;

    let viewer = viewer_for(&pool, stranger).await;
    let written = WorkflowRepository::deprecate_flat_workflow(&pool, &viewer, id)
        .await
        .expect("deprecate");
    assert!(
        !written,
        "a principal that cannot write the owning group must match no row, even though \
         the row is public and it can read it"
    );
    assert_eq!(
        state(&pool, id).await,
        before,
        "neither the claim nor the workflows row may change"
    );
}

/// The authorization read: `Some(author)` for a reader, `None` for a principal
/// outside the claim's visibility, and `None` for a readable claim that is not
/// a workflow. The last leg keeps the label filter from being dropped.
#[sqlx::test(migrations = "../../migrations")]
async fn the_author_read_is_filtered_by_visibility_and_label(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "author-owner").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "author-stranger").await;
    let private = seed_workflow_claim(&pool, owner, "group", group).await;
    let public = seed_workflow_claim(&pool, owner, "public", group).await;
    sqlx::query("UPDATE claims SET labels = ARRAY['claim'] WHERE id = $1")
        .bind(public)
        .execute(&pool)
        .await
        .expect("strip the workflow label from the public claim");

    let owner_viewer = viewer_for(&pool, owner).await;
    let stranger_viewer = viewer_for(&pool, stranger).await;

    assert_eq!(
        WorkflowRepository::flat_workflow_author(&pool, &owner_viewer, private)
            .await
            .unwrap(),
        Some(owner),
        "the owner reads its own private workflow"
    );
    assert_eq!(
        WorkflowRepository::flat_workflow_author(&pool, &stranger_viewer, private)
            .await
            .unwrap(),
        None,
        "a private workflow is absent to a principal outside its group"
    );
    assert_eq!(
        WorkflowRepository::flat_workflow_author(&pool, &stranger_viewer, public)
            .await
            .unwrap(),
        None,
        "a readable claim without the workflow label is not a workflow"
    );
}
