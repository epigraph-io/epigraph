//! MCP `get_belief` and `EPIGRAPH_COMPOUND_BELIEF` (atom-level belief
//! program, PR-6; SPEC §7.1): in `legacy` (the default) the response is
//! today's, with no `shadow` key; in `shadow` it carries the claim's
//! atom-level view beside the served values, which do not change.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{FrameRepository, MassFunctionRepository, PgPool};
use epigraph_engine::belief_view::CompoundBeliefMode;
use epigraph_mcp::tools::ds::get_belief_in_mode;
use epigraph_mcp::types::GetBeliefParams;
use serde_json::Value;
use uuid::Uuid;

mod common;
use common::{build_test_server, first_text};

async fn agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("agent")
}

async fn claim(pool: &PgPool, author: Uuid, what: &str) -> Uuid {
    fixture::seed_public_claim(pool, author, &format!("shadow {what} {}", Uuid::new_v4())).await
}

async fn decompose(pool: &PgPool, parent: Uuid, child: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(parent)
    .bind(child)
    .execute(pool)
    .await
    .expect("edge");
}

async fn support(pool: &PgPool, claim: Uuid, t: f64) {
    let viewer = fixture::public_viewer(pool).await;
    let frame = match FrameRepository::get_by_name(pool, &viewer, "binary_truth")
        .await
        .expect("frame lookup")
    {
        Some(f) => f.id,
        None => {
            FrameRepository::create(
                pool,
                "binary_truth",
                None,
                &["TRUE".to_string(), "FALSE".to_string()],
            )
            .await
            .expect("frame")
            .id
        }
    };
    let a = agent(pool).await;
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(a),
        None,
        &serde_json::json!({"0": t, "0,1": 1.0 - t}),
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store BBA");
}

fn params(id: Uuid) -> GetBeliefParams {
    GetBeliefParams {
        claim_id: id.to_string(),
        frame_id: None,
        perspective_id: None,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_belief_carries_a_shadow_view_only_in_shadow_mode(pool: PgPool) {
    let author = agent(&pool).await;
    let k = claim(&pool, author, "K").await;
    let (a1, a2) = (
        claim(&pool, author, "a1").await,
        claim(&pool, author, "a2").await,
    );
    decompose(&pool, k, a1).await;
    decompose(&pool, k, a2).await;
    support(&pool, a1, 0.8).await;
    support(&pool, a2, 0.8).await;
    // The compound's frozen cache: what it is served today.
    sqlx::query(
        "UPDATE claims SET belief = 0.9, plausibility = 0.95, pignistic_prob = 0.925 \
         WHERE id = $1",
    )
    .bind(k)
    .execute(&pool)
    .await
    .expect("cache");

    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let legacy: Value = first_text(
        &get_belief_in_mode(&server, &viewer, params(k), CompoundBeliefMode::Legacy)
            .await
            .expect("legacy get_belief"),
    );
    assert!(
        legacy.get("shadow").is_none(),
        "legacy mode adds no shadow key: {legacy}"
    );

    let mut shadow: Value = first_text(
        &get_belief_in_mode(&server, &viewer, params(k), CompoundBeliefMode::Shadow)
            .await
            .expect("shadow get_belief"),
    );
    let view = shadow
        .as_object_mut()
        .expect("object")
        .remove("shadow")
        .expect("shadow mode carries a shadow view");
    assert_eq!(
        shadow, legacy,
        "apart from the shadow key, the response is the served one"
    );
    assert_eq!(view["basis"], "derived", "{view}");
    let bel = view["bel"].as_f64().expect("bel");
    assert!(
        (bel - 0.64).abs() < 1e-9,
        "the shadow is the conjunction of two .8 leaves, not the cache: {bel}"
    );
    assert!(
        (legacy["belief"].as_f64().unwrap() - 0.9).abs() < 1e-9,
        "the served value is still the cache"
    );
}
