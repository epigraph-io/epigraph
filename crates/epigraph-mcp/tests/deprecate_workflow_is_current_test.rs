use sqlx::PgPool;
mod common;
use common::*;

async fn plant_stub_embedding(pool: &PgPool, id: uuid::Uuid) {
    let stub = {
        let mut v = vec!["0.0"; 1536];
        v[0] = "0.1";
        format!("[{}]", v.join(","))
    };
    sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
        .bind(stub.as_str())
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn mcp_deprecate_workflow_sets_is_current_false(pool: PgPool) {
    let id = seed_workflow_claim(&pool, "to-deprecate", &["s1"]).await;
    let server = build_test_server(pool.clone());

    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        epigraph_mcp::types::DeprecateWorkflowParams {
            workflow_id: id.to_string(),
            reason: "obsolete".into(),
            cascade: Some(false),
        },
    )
    .await
    .unwrap();

    let (truth, is_current): (f64, bool) =
        sqlx::query_as("SELECT truth_value, is_current FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        (truth - 0.05).abs() < 1e-9,
        "truth should be 0.05, got {truth}"
    );
    assert!(!is_current, "is_current must be false");
}

/// deprecate_workflow must null the workflow claim's embedding so it drops out
/// of semantic recall.  Regression for the is_current=false → embedding=NULL invariant.
#[sqlx::test(migrations = "../../migrations")]
async fn deprecate_workflow_nulls_embedding(pool: PgPool) {
    let id = seed_workflow_claim(&pool, "to-deprecate-embed", &["s1"]).await;
    plant_stub_embedding(&pool, id).await;

    let server = build_test_server(pool.clone());
    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        epigraph_mcp::types::DeprecateWorkflowParams {
            workflow_id: id.to_string(),
            reason: "embedding test".into(),
            cascade: Some(false),
        },
    )
    .await
    .unwrap();

    let has_embedding: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        !has_embedding,
        "workflow {id} embedding must be NULL after deprecate_workflow"
    );
}

/// Cascade path of deprecate_workflow must also null embeddings on all
/// transitive workflow descendants.
#[sqlx::test(migrations = "../../migrations")]
async fn deprecate_workflow_cascade_nulls_embeddings(pool: PgPool) {
    let root = seed_workflow_claim(&pool, "root-embed", &["s1"]).await;
    let child = seed_workflow_claim(&pool, "child-embed", &["s1"]).await;
    insert_claim_edge(&pool, child, root, "variant_of").await;

    for &id in &[root, child] {
        plant_stub_embedding(&pool, id).await;
    }

    let server = build_test_server(pool.clone());
    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        epigraph_mcp::types::DeprecateWorkflowParams {
            workflow_id: root.to_string(),
            reason: "cascade embed test".into(),
            cascade: Some(true),
        },
    )
    .await
    .unwrap();

    for &id in &[root, child] {
        let has_embedding: bool =
            sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            !has_embedding,
            "claim {id} embedding must be NULL after cascade deprecate_workflow"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn deprecate_workflow_cascade_walks_supersedes_and_variant_of(pool: PgPool) {
    let root = seed_workflow_claim(&pool, "root", &["s1"]).await;
    let child_old = seed_workflow_claim(&pool, "child_old", &["s1"]).await;
    let child_new = seed_workflow_claim(&pool, "child_new", &["s1"]).await;
    insert_claim_edge(&pool, child_old, root, "variant_of").await;
    insert_claim_edge(&pool, child_new, root, "supersedes").await;

    // Negative control: a NON-workflow claim that supersedes the root.
    // It must NOT be touched by the cascade.
    let unrelated = seed_claim(&pool, "non-workflow", 0.5).await;
    insert_claim_edge(&pool, unrelated, root, "supersedes").await;

    let server = build_test_server(pool.clone());
    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        epigraph_mcp::types::DeprecateWorkflowParams {
            workflow_id: root.to_string(),
            reason: "cascade test".into(),
            cascade: Some(true),
        },
    )
    .await
    .unwrap();

    for id in [root, child_old, child_new] {
        let (truth, is_current): (f64, bool) =
            sqlx::query_as("SELECT truth_value, is_current FROM claims WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            (truth - 0.05).abs() < 1e-9,
            "{id} not deprecated, truth={truth}"
        );
        assert!(!is_current, "{id} not is_current=false");
    }

    let (utt_truth, utt_current): (f64, bool) =
        sqlx::query_as("SELECT truth_value, is_current FROM claims WHERE id = $1")
            .bind(unrelated)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        (utt_truth - 0.5).abs() < 1e-9,
        "unrelated non-workflow claim was deprecated, truth={utt_truth}"
    );
    assert!(
        utt_current,
        "unrelated non-workflow claim flipped is_current"
    );
}
