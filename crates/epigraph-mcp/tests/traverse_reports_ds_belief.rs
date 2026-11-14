//! Backlog `1574d9b4`: `traverse` reported `belief_score` equal to the authored
//! `truth_value` on its default path, while `recall` reports the computed
//! belief, so one claim showed two beliefs depending on the tool (0.40 against
//! 0.62 in production on 2026-11-04).
//!
//! `traverse` resolved the Dempster-Shafer score only when `min_truth > 0`,
//! because that is the only case in which it can change which nodes are kept.
//! The field it fills is named for the score, not for the gate, so it has to
//! carry the score on every path.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::tools;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_public_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, $2, $3, $4, $5, true)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent)
    .bind(truth)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

fn node<'a>(body: &'a serde_json::Value, claim: Uuid) -> &'a serde_json::Value {
    body["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|n| n["id"] == claim.to_string())
        .unwrap_or_else(|| panic!("claim {claim} is not in the walk: {body}"))
}

async fn walk(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    start: Uuid,
    min_truth: Option<f64>,
) -> serde_json::Value {
    let mut params = serde_json::json!({
        "start_id": start.to_string(),
        "max_depth": 1,
        "limit": 100,
    });
    if let Some(m) = min_truth {
        params["min_truth"] = serde_json::json!(m);
    }
    first_text(
        &tools::graph::traverse(server, viewer, serde_json::from_value(params).unwrap())
            .await
            .expect("traverse"),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn traverse_reports_the_ds_belief_on_the_default_path(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());
    let agent = seed_agent(&pool).await;

    // `wired` was authored at 0.40 and has since been moved to 0.62 by
    // Dempster-Shafer evidence; `plain` has no DS state at all.
    let wired = seed_public_claim(&pool, agent, "ds-wired claim", 0.40).await;
    let plain = seed_public_claim(&pool, agent, "claim with no ds state", 0.70).await;
    sqlx::query(
        "UPDATE claims SET belief = 0.55, plausibility = 0.69, pignistic_prob = 0.62 \
          WHERE id = $1",
    )
    .bind(wired)
    .execute(&pool)
    .await
    .expect("seed the DS cache");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports')",
    )
    .bind(wired)
    .bind(plain)
    .execute(&pool)
    .await
    .expect("edge");

    let default_walk = walk(&server, &viewer, wired, None).await;
    let w = node(&default_walk, wired);
    assert_eq!(
        w["truth_value"],
        serde_json::json!(0.40),
        "the authored value is reported unchanged: {default_walk}"
    );
    assert_eq!(
        w["belief_score"],
        serde_json::json!(0.62),
        "belief_score is the DS pignistic probability on the DEFAULT path too; 0.40 \
         here is the authored truth_value under the wrong name: {default_walk}"
    );
    assert_eq!(
        node(&default_walk, plain)["belief_score"],
        serde_json::json!(0.70),
        "a claim with no DS state falls back to its truth_value: {default_walk}"
    );

    // The gated path already resolved it; the two paths must now agree.
    let gated_walk = walk(&server, &viewer, wired, Some(0.1)).await;
    assert_eq!(
        node(&gated_walk, wired)["belief_score"],
        w["belief_score"],
        "the same claim must report one belief whatever min_truth was: {gated_walk}"
    );
}
