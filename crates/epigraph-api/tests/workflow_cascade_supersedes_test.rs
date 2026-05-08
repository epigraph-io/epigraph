//! Regression test: API DELETE /api/v1/workflows/:id?cascade=true must walk
//! `supersedes` edges (not just `variant_of`). This catches the bug where
//! `WorkflowRepository::find_descendants` only walked `variant_of`, silently
//! missing all variants created by improve_workflow after PR #99/#100.

#![cfg(feature = "db")]

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

mod common;

/// Regression test: API DELETE /api/v1/workflows/:id?cascade=true must walk
/// `supersedes` edges (not just `variant_of`). This catches the bug where
/// `WorkflowRepository::find_descendants` only walked `variant_of`, silently
/// missing all variants created by improve_workflow after PR #99/#100.
#[tokio::test(flavor = "multi_thread")]
async fn deprecate_workflow_cascade_walks_supersedes_edges() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // Seed: a workflow root + a variant linked via 'supersedes' edge (the
    // post-PR shape produced by improve_workflow). Both labeled 'workflow'.
    let agent = common::seed_system_agent(&pool).await;
    let root = Uuid::new_v4();
    let variant = Uuid::new_v4();
    let root_hash: Vec<u8> = root.as_bytes().iter().copied().cycle().take(32).collect();
    let var_hash: Vec<u8> = variant
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, 'root', $2, 0.5, $3, true, ARRAY['workflow']::text[]), \
                ($4, 'variant', $5, 0.5, $3, true, ARRAY['workflow']::text[])",
    )
    .bind(root)
    .bind(&root_hash)
    .bind(agent)
    .bind(variant)
    .bind(&var_hash)
    .execute(&pool)
    .await
    .unwrap();

    // variant supersedes root (same direction as improve_workflow writes it:
    // source=variant, target=root, relationship='supersedes')
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'supersedes', '{}'::jsonb)",
    )
    .bind(variant)
    .bind(root)
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_with_scopes(&["claims:write"]);

    let resp = reqwest::Client::new()
        .delete(format!(
            "http://{addr}/api/v1/workflows/{root}?cascade=true&reason=regression-test"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "body={:?}", resp.text().await);

    // Both root AND variant must be deprecated (truth=0.05, is_current=false).
    for (label, id) in [("root", root), ("variant", variant)] {
        let (truth, is_current): (f64, bool) =
            sqlx::query_as("SELECT truth_value, is_current FROM claims WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            (truth - 0.05).abs() < 1e-9,
            "{label} not deprecated, truth={truth}"
        );
        assert!(!is_current, "{label} not is_current=false");
    }
}
