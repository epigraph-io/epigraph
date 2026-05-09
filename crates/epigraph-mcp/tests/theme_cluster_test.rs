//! Smoke test for the `theme_cluster` MCP tool.
//!
//! Exercises the skip path: with zero claims carrying embeddings, the engine
//! returns `themes_created=0`, `claims_assigned=0`, `k_used=null`, and a
//! `skipped_reason`. Going through the success path would require seeding
//! pgvector embeddings via the `Vector` type, which is more setup than this
//! smoke needs — the bin's HTTP route already has integration coverage in
//! `crates/epigraph-api/tests/admin_scope_promotions_test.rs`.

#[macro_use]
mod common;

use epigraph_mcp::tools::themes::{theme_cluster, ThemeClusterParams};
use serde_json::Value;

#[tokio::test]
async fn theme_cluster_skip_path_returns_summary() {
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool);

    let params = ThemeClusterParams {
        k: None,
        // k_min defaults to 4; with zero (or near-zero) embedded claims in
        // the pristine test DB, n_claims < k_min triggers the skip branch.
        k_min: None,
        k_max: None,
        min_claims_per_theme: None,
        limit: None,
        label_prefix: None,
        centroid_dim: None,
    };

    let result = theme_cluster(&server, params).await.expect("tool ok");
    let body = common::first_text(&result);

    assert!(
        body.get("themes_created").is_some(),
        "summary must include themes_created: {body}"
    );
    assert!(
        body.get("claims_assigned").is_some(),
        "summary must include claims_assigned: {body}"
    );
    assert!(
        body.get("k_used").is_some(),
        "summary must include k_used: {body}"
    );
    assert!(
        body.get("claims_with_embeddings").is_some(),
        "summary must include claims_with_embeddings: {body}"
    );
    assert!(
        body.get("centroid_dim").is_some(),
        "summary must include centroid_dim: {body}"
    );

    // On the skip path the engine returns themes_created=0 and a non-empty
    // skipped_reason. We allow either branch (a CI DB containing leftover
    // embeddings could take the success branch); only the field shape is
    // load-bearing.
    if body["k_used"] == Value::Null {
        assert_eq!(body["themes_created"], 0);
        assert_eq!(body["claims_assigned"], 0);
        assert!(
            body.get("skipped_reason").is_some(),
            "skip path must include skipped_reason: {body}"
        );
    }
}

#[tokio::test]
async fn theme_cluster_caps_oversized_limit() {
    // Verifies the MCP layer's defensive cap on `limit` (≤500) keeps even
    // misbehaving callers safe from VM OOM. We can't easily observe the cap
    // post-hoc since the engine doesn't echo the effective limit, but we
    // can at least assert the call doesn't fail when an over-limit value is
    // requested.
    let pool = test_pool_or_skip!();
    let server = common::build_test_server(pool);

    let params = ThemeClusterParams {
        k: None,
        k_min: None,
        k_max: None,
        min_claims_per_theme: None,
        limit: Some(10_000),
        label_prefix: None,
        centroid_dim: None,
    };

    let result = theme_cluster(&server, params).await.expect("tool ok");
    let body = common::first_text(&result);
    assert!(body.get("themes_created").is_some());
}
