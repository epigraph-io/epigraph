//! `query_claims(max_truth=…)` filters and reports the BELIEF SCORE, the same
//! score `recall`'s `min_truth` gates on (GitHub #395, narrowed; G10).
//!
//! It used to filter `claims.truth_value`, which no Dempster-Shafer write path
//! refreshes, so a claim refuted by epistemic edges (BetP low, stale authored
//! truth high) never entered a `max_truth=0.4` assessment queue — and a
//! vindicated one sat in it forever.
//!
//! Params are JSON so the file compiles against the pre-fix types.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use sqlx::PgPool;
use uuid::Uuid;

async fn seed(pool: &PgPool, content: &str, truth: f64, ds: Option<(f64, f64, f64)>) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, sha256($1::bytea), $2, $3, true) RETURNING id",
    )
    .bind(content)
    .bind(truth)
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap();
    if let Some((bel, pl, betp)) = ds {
        sqlx::query(
            "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4 WHERE id = $1",
        )
        .bind(id)
        .bind(bel)
        .bind(pl)
        .bind(betp)
        .execute(pool)
        .await
        .unwrap();
    }
    id
}

async fn query(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    args: serde_json::Value,
) -> Vec<serde_json::Value> {
    let out = epigraph_mcp::tools::claims::query_claims(
        server,
        viewer,
        serde_json::from_value(args).unwrap(),
    )
    .await
    .unwrap();
    first_text(&out).as_array().expect("array").clone()
}

#[sqlx::test(migrations = "../../migrations")]
async fn max_truth_finds_the_refuted_claim_and_reports_its_belief_score(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let refuted = seed(&pool, "g10 refuted", 0.78, Some((0.10, 0.25, 0.18))).await;
    let vindicated = seed(&pool, "g10 vindicated", 0.30, Some((0.85, 0.95, 0.90))).await;
    let no_ds = seed(&pool, "g10 no ds", 0.35, None).await;

    let low = query(&server, &viewer, serde_json::json!({"max_truth": 0.4})).await;
    let find = |rows: &[serde_json::Value], id: Uuid| {
        rows.iter().find(|r| r["id"] == id.to_string()).cloned()
    };

    let r = find(&low, refuted).unwrap_or_else(|| {
        panic!("refuted claim (BetP 0.18, truth 0.78) not in max_truth=0.4: {low:?}")
    });
    assert_eq!(r["belief_score"], 0.18, "{r}");
    assert_eq!(
        r["truth_value"], 0.78,
        "truth_value is still the authored value: {r}"
    );
    assert!(
        find(&low, vindicated).is_none(),
        "vindicated claim (BetP 0.90, truth 0.30) leaked into max_truth=0.4: {low:?}"
    );
    let n = find(&low, no_ds).expect("a claim with no DS state falls back to truth_value");
    assert_eq!(n["belief_score"], 0.35, "{n}");

    let high = query(&server, &viewer, serde_json::json!({"min_truth": 0.8})).await;
    assert!(find(&high, vindicated).is_some(), "{high:?}");
    assert!(find(&high, refuted).is_none(), "{high:?}");

    // Agreement with recall's gate: the same score, from the same SQL.
    let batch = epigraph_db::ClaimRepository::effective_belief_batch(
        &pool,
        &viewer,
        &[refuted, vindicated, no_ds],
    )
    .await
    .unwrap();
    for row in low.iter().chain(high.iter()) {
        let id: Uuid = row["id"].as_str().unwrap().parse().unwrap();
        if let Some(s) = batch.get(&id) {
            assert_eq!(row["belief_score"].as_f64().unwrap(), *s, "{row}");
        }
    }
}
