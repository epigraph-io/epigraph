//! Integration test for `DELETE /api/v1/workflows/:id` (deprecate_workflow).
//!
//! Phase B of the flat-workflow consolidation (epigraph-io/epigraph#36):
//! deprecating a workflow MUST set `is_current = false` in addition to
//! lowering `truth_value` to 0.05. Before the fix, callers of
//! `WorkflowRepository::list` with `min_truth = 0.0` (the common default)
//! continued to see deprecated workflows because 0.05 > 0.0; the
//! `is_current` flip is what guarantees they disappear from the list
//! regardless of the truth threshold.

#![cfg(feature = "db")]

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

mod common;

/// DELETE /api/v1/workflows/:id should set both `truth_value = 0.05`
/// AND `is_current = false` on the underlying claim row.
#[tokio::test(flavor = "multi_thread")]
async fn deprecate_workflow_sets_is_current_false_and_lowers_truth() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");

    // Build a connection pool we can use to seed and to verify the row
    // post-DELETE. The HTTP server gets its own pool inside `spawn_app`.
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to test DB");

    // ── Seed: agent + workflow claim (is_current=true, truth_value=0.9) ──
    let agent_id = Uuid::new_v4();
    let workflow_id = Uuid::new_v4();
    // Per-test unique public_key + content_hash so concurrent / repeated
    // runs against a shared test DB don't collide on UNIQUE constraints.
    let pk_bytes: Vec<u8> = agent_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    let hash_bytes: Vec<u8> = workflow_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();

    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type) \
         VALUES ($1, $2, 'deprecate-workflow-test', 'service') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .bind(&pk_bytes)
    .execute(&pool)
    .await
    .expect("seed agent");

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, \
                             is_current, labels) \
         VALUES ($1, 'workflow under test', $2, $3, 0.9, true, ARRAY['workflow'])",
    )
    .bind(workflow_id)
    .bind(&hash_bytes)
    .bind(agent_id)
    .execute(&pool)
    .await
    .expect("seed workflow claim");

    // ── Act: DELETE /api/v1/workflows/:id?reason=test ──
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token();
    let resp = reqwest::Client::new()
        .delete(format!(
            "http://{addr}/api/v1/workflows/{workflow_id}?reason=test-deprecate"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("HTTP DELETE succeeds");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "DELETE should return 200 OK, got status={}",
        resp.status()
    );

    // ── Assert: row now has is_current=false AND truth_value=0.05 ──
    let (truth_value, is_current): (f64, bool) =
        sqlx::query_as("SELECT truth_value, is_current FROM claims WHERE id = $1")
            .bind(workflow_id)
            .fetch_one(&pool)
            .await
            .expect("read back deprecated claim");

    assert!(
        (truth_value - 0.05).abs() < 1e-9,
        "deprecate_workflow must set truth_value to 0.05, got {truth_value}"
    );
    assert!(
        !is_current,
        "deprecate_workflow must set is_current=false, got {is_current}"
    );
}
