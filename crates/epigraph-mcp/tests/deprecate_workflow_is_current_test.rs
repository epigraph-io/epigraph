#[path = "viewer_fixture.rs"]
mod fixture;

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
    let viewer = fixture::public_viewer(&pool).await;
    let id = seed_workflow_claim(&pool, "to-deprecate", &["s1"]).await;
    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        &viewer,
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
    let viewer = fixture::public_viewer(&pool).await;
    let id = seed_workflow_claim(&pool, "to-deprecate-embed", &["s1"]).await;
    plant_stub_embedding(&pool, id).await;

    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        &viewer,
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
    let viewer = fixture::public_viewer(&pool).await;
    let root = seed_workflow_claim(&pool, "root-embed", &["s1"]).await;
    let child = seed_workflow_claim(&pool, "child-embed", &["s1"]).await;
    insert_claim_edge(&pool, child, root, "variant_of").await;

    for &id in &[root, child] {
        plant_stub_embedding(&pool, id).await;
    }

    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        &viewer,
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
    let viewer = fixture::public_viewer(&pool).await;
    let root = seed_workflow_claim(&pool, "root", &["s1"]).await;
    let child_old = seed_workflow_claim(&pool, "child_old", &["s1"]).await;
    let child_new = seed_workflow_claim(&pool, "child_new", &["s1"]).await;
    insert_claim_edge(&pool, child_old, root, "variant_of").await;
    insert_claim_edge(&pool, child_new, root, "supersedes").await;

    // Negative control: a NON-workflow claim that supersedes the root.
    // It must NOT be touched by the cascade.
    let unrelated = seed_claim(&pool, "non-workflow", 0.5).await;
    insert_claim_edge(&pool, unrelated, root, "supersedes").await;

    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        &viewer,
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

/// A failed cascade read must surface its real cause, not report a success that
/// was silently rolled back.
///
/// `deprecate_workflow` now opens ONE transaction for the whole deprecation. The
/// cascade's `EdgeRepository::get_by_target` was `.unwrap_or_default()`, which was
/// harmless while the tool ran on `&server.pool` — the target's deprecation had
/// already autocommitted and a failed read merely skipped the children. Inside a
/// transaction the same swallow is a poison pill.
///
/// The outcome is worse than the `25P02` one would expect, and it is MEASURED.
/// On the swallowing revision this arm returns:
///
/// ```text
/// {"deprecated_ids": ["dc975b42-…"], "reason": "cascade read failure"}   is_error: false
/// ```
///
/// — success, with nothing written. PostgreSQL accepts `COMMIT` on an aborted
/// transaction and answers with the `ROLLBACK` command tag rather than an error,
/// so `tx.commit()` returns `Ok` and the whole deprecation is discarded while the
/// tool reports it as done. #494 wrapped `create_or_get`'s duplicate-key re-find
/// and `EventRepository::publish_or_log_conn` in SAVEPOINTs for exactly this class.
///
/// # Why this arm is not vacuous under the BYPASSRLS harness
///
/// It does not assert that a write succeeds — an arm shaped that way passes
/// identically on the unconverted tree. It induces a read failure that no role can
/// bypass (the relation is GONE) and asserts that the caller is TOLD. Reverting
/// the `?` to `.unwrap_or_default()` fails this arm on any role, at the
/// `expect_err` — MEASURED, not predicted.
#[sqlx::test(migrations = "../../migrations")]
async fn deprecate_workflow_cascade_read_failure_reports_its_real_cause(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let root = seed_workflow_claim(&pool, "cascade-read-failure", &["s1"]).await;

    // Make the cascade's `get_by_target` fail in a way no privilege level can
    // bypass. Each `#[sqlx::test]` owns its own database, so this is local.
    sqlx::query("DROP TABLE edges CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let err = epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        &viewer,
        epigraph_mcp::types::DeprecateWorkflowParams {
            workflow_id: root.to_string(),
            reason: "cascade read failure".into(),
            cascade: Some(true),
        },
    )
    .await
    .expect_err("a cascade that cannot enumerate its children has not completed");

    let msg = err.message.to_lowercase();
    assert!(
        msg.contains("edges"),
        "the cascade read's real cause must reach the caller; got {:?}. A message \
         mentioning only an aborted transaction (25P02) means the read was swallowed \
         again and the loop kept issuing statements into a dead transaction.",
        err.message
    );
    assert!(
        !msg.contains("25p02") && !msg.contains("current transaction is aborted"),
        "the caller must not receive the SECONDARY failure; got {:?}",
        err.message
    );

    // And nothing landed: the whole deprecation is one transaction, so a cascade
    // that cannot complete must not leave the root flipped.
    let is_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(root)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        is_current,
        "the root must not stay deprecated when the cascade aborted"
    );
}
