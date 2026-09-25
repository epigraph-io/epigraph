#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_adds_and_removes(pool: PgPool) {
    let id = seed_claim_with_labels(&pool, "x", &["existing"]).await;
    let viewer = fixture::public_viewer(&pool).await;
    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    epigraph_mcp::tools::claims::update_labels(
        &server,
        &viewer,
        epigraph_mcp::types::UpdateLabelsParams {
            claim_id: id.to_string(),
            add: vec!["new1".into(), "new2".into()],
            remove: vec!["existing".into()],
        },
        None,
    )
    .await
    .unwrap();

    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(labels.contains(&"new1".into()) && labels.contains(&"new2".into()));
    assert!(!labels.contains(&"existing".into()));
}
