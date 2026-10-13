//! U033 / I229: hierarchical outcome reports must reach
//! `BehavioralExecutionRepository::behavioral_affinity_lineage`.
//!
//! A hierarchical report writes one `behavioral_executions` row per step with
//! `workflow_id` = a `workflows.id`, never a `claims.id`. The lineage CTE's
//! `live_roots` joined `claims` only, so every hierarchical row dropped out
//! there, embedded or not, and `find_workflow`'s hierarchical leg (keyed on
//! `find_lineage_root(row.id)` = `row.id`, since a `workflows` row has no
//! claim→claim lineage edges) never found an affinity entry.

use chrono::{Duration, Utc};
use epigraph_db::visibility::Viewer;
use epigraph_db::{BehavioralExecutionRepository, BehavioralExecutionRow, WorkflowRepository};
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;

/// A unit vector along axis `axis`, as a pgvector literal.
fn axis_vec(axis: usize) -> String {
    let mut v = vec!["0"; DIM];
    v[axis] = "1";
    format!("[{}]", v.join(","))
}

async fn insert_workflow(pool: &PgPool, canonical_name: &str, truth_value: f64) -> Uuid {
    let id = Uuid::new_v4();
    WorkflowRepository::insert_root(
        pool,
        id,
        canonical_name,
        0,
        "Deploy a service with zero downtime",
        None,
        serde_json::json!({}),
    )
    .await
    .expect("insert workflows row");
    sqlx::query("UPDATE workflows SET truth_value = $1 WHERE id = $2")
        .bind(truth_value)
        .bind(id)
        .execute(pool)
        .await
        .expect("set truth_value");
    id
}

/// One hierarchical outcome report: `steps` rows sharing one `created_at`
/// and one goal embedding, exactly as `do_report_hierarchical_outcome_via_pool`
/// writes them.
async fn insert_report(
    pool: &PgPool,
    workflow_id: Uuid,
    success: bool,
    steps: usize,
    at: chrono::DateTime<Utc>,
    pgvec: &str,
) {
    for i in 0..steps {
        let row = BehavioralExecutionRow {
            id: Uuid::new_v4(),
            workflow_id,
            goal_text: "Deploy a service with zero downtime".to_string(),
            success,
            step_beliefs: serde_json::json!({"deviated": false}),
            tool_pattern: vec![format!("Step {i}")],
            quality: Some(if success { 1.0 } else { 0.0 }),
            deviation_count: 0,
            total_steps: 1,
            created_at: at,
            step_claim_id: None,
            run_label: None,
        };
        BehavioralExecutionRepository::create(pool, row, Some(pgvec))
            .await
            .expect("insert behavioral_executions row");
    }
}

async fn public_viewer(pool: &PgPool) -> Viewer {
    Viewer::resolve(pool, Uuid::nil())
        .await
        .expect("resolve viewer")
}

#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_executions_reach_lineage_affinity(pool: PgPool) {
    let wf = insert_workflow(&pool, "u033-affinity-live", 1.0).await;
    let q = axis_vec(0);
    let t0 = Utc::now();
    // Two successful reports, of 3 steps and 2 steps, plus one failed report.
    insert_report(&pool, wf, true, 3, t0, &q).await;
    insert_report(&pool, wf, true, 2, t0 + Duration::seconds(1), &q).await;
    insert_report(&pool, wf, false, 2, t0 + Duration::seconds(2), &q).await;

    let viewer = public_viewer(&pool).await;
    let hits =
        BehavioralExecutionRepository::behavioral_affinity_lineage(&pool, &viewer, &q, 0.5, 1, 10)
            .await
            .expect("affinity query");

    let hit = hits
        .iter()
        .find(|(id, _, _)| *id == wf)
        .unwrap_or_else(|| panic!("hierarchical workflow {wf} missing from affinity: {hits:?}"));
    assert!(hit.1 > 0.99, "same-goal similarity must be ~1: {hit:?}");
    // The count is per REPORT, not per step row: 2 successful reports, not 5
    // rows. A per-row count would let one many-step report clear any
    // `min_executions` gate on its own, which a flat workflow (one row per
    // report) cannot.
    assert_eq!(
        hit.2, 2,
        "execution_count counts successful reports: {hit:?}"
    );

    // The gate is applied to that per-report count.
    let gated =
        BehavioralExecutionRepository::behavioral_affinity_lineage(&pool, &viewer, &q, 0.5, 3, 10)
            .await
            .expect("affinity query");
    assert!(
        gated.iter().all(|(id, _, _)| *id != wf),
        "2 reports must not clear min_executions = 3: {gated:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn deprecated_hierarchical_workflows_stay_out_of_affinity(pool: PgPool) {
    // Same shape as the live case; only the deprecation differs, so a missing
    // row here is the truth_value filter and nothing else.
    let live = insert_workflow(&pool, "u033-affinity-live-control", 1.0).await;
    let dead = insert_workflow(&pool, "u033-affinity-deprecated", 0.05).await;
    let q = axis_vec(1);
    let t0 = Utc::now();
    insert_report(&pool, live, true, 2, t0, &q).await;
    insert_report(&pool, dead, true, 2, t0, &q).await;

    let viewer = public_viewer(&pool).await;
    let hits =
        BehavioralExecutionRepository::behavioral_affinity_lineage(&pool, &viewer, &q, 0.5, 1, 10)
            .await
            .expect("affinity query");
    assert!(
        hits.iter().any(|(id, _, _)| *id == live),
        "control: the live workflow must appear: {hits:?}"
    );
    assert!(
        hits.iter().all(|(id, _, _)| *id != dead),
        "a deprecated (truth 0.05) workflow must not appear: {hits:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_affinity_respects_the_similarity_floor(pool: PgPool) {
    let wf = insert_workflow(&pool, "u033-affinity-orthogonal", 1.0).await;
    insert_report(&pool, wf, true, 2, Utc::now(), &axis_vec(2)).await;

    let viewer = public_viewer(&pool).await;
    // Orthogonal query: cosine similarity 0, below the 0.5 floor.
    let hits = BehavioralExecutionRepository::behavioral_affinity_lineage(
        &pool,
        &viewer,
        &axis_vec(3),
        0.5,
        1,
        10,
    )
    .await
    .expect("affinity query");
    assert!(
        hits.iter().all(|(id, _, _)| *id != wf),
        "an unrelated goal must not match: {hits:?}"
    );
}

/// Regression guard for the claim arm the UNION sits beside: a FLAT
/// execution (its `workflow_id` is a workflow claim) is still keyed on that
/// claim, still counted once per row, and a hierarchical row in the same
/// query does not displace it.
#[sqlx::test(migrations = "../../migrations")]
async fn flat_claim_executions_still_reach_affinity_beside_hierarchical(pool: PgPool) {
    let agent_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(blake3::hash(b"u033-flat-agent").as_bytes().as_slice())
    .bind("u033-flat-agent")
    .fetch_one(&pool)
    .await
    .unwrap();
    let flat: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind("u033 flat workflow")
    .bind(blake3::hash(b"u033 flat workflow").as_bytes().as_slice())
    .bind(agent_id)
    .bind(0.8_f64)
    .fetch_one(&pool)
    .await
    .unwrap();
    let hier = insert_workflow(&pool, "u033-affinity-beside-flat", 1.0).await;
    let q = axis_vec(4);
    let t0 = Utc::now();
    // Two flat reports (one row each) and one 2-step hierarchical report.
    insert_report(&pool, flat, true, 1, t0, &q).await;
    insert_report(&pool, flat, true, 1, t0 + Duration::seconds(1), &q).await;
    insert_report(&pool, hier, true, 2, t0, &q).await;

    let viewer = public_viewer(&pool).await;
    let hits =
        BehavioralExecutionRepository::behavioral_affinity_lineage(&pool, &viewer, &q, 0.5, 1, 10)
            .await
            .expect("affinity query");
    let flat_hit = hits
        .iter()
        .find(|(id, _, _)| *id == flat)
        .unwrap_or_else(|| panic!("flat workflow claim {flat} missing: {hits:?}"));
    assert_eq!(flat_hit.2, 2, "flat rows count once each: {flat_hit:?}");
    let hier_hit = hits
        .iter()
        .find(|(id, _, _)| *id == hier)
        .unwrap_or_else(|| panic!("hierarchical workflow {hier} missing: {hits:?}"));
    assert_eq!(hier_hit.2, 1, "one hierarchical report: {hier_hit:?}");
}
