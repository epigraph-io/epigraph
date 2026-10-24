//! MCP `get_belief` and `EPIGRAPH_COMPOUND_BELIEF` (atom-level belief
//! program, PR-6; SPEC §7.1): in `legacy` (the default) the response is
//! today's, with no `shadow` key; in `shadow` it carries the claim's
//! atom-level view beside the served values, which do not change.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_engine::belief_view::CompoundBeliefMode;
use epigraph_mcp::tools::ds::{get_belief, get_belief_in_mode};
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
    store_support(pool, claim, t, None, Some(1.0)).await;
}

async fn binary_frame(pool: &PgPool) -> Uuid {
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
    frame
}

/// A support row at `t`, with the given evidence type and stored strength.
async fn store_support(
    pool: &PgPool,
    claim: Uuid,
    t: f64,
    evidence_type: Option<&str>,
    strength: Option<f64>,
) {
    let frame = binary_frame(pool).await;
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
        strength,
        evidence_type,
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

/// The tool entry point reads the mode from `EPIGRAPH_COMPOUND_BELIEF`; unset,
/// it is `legacy`, so `get_belief` itself carries no `shadow` key.
#[sqlx::test(migrations = "../../migrations")]
async fn get_belief_with_the_switch_unset_carries_no_shadow(pool: PgPool) {
    assert!(
        std::env::var_os(CompoundBeliefMode::ENV).is_none(),
        "precondition: {} is unset in the test environment",
        CompoundBeliefMode::ENV
    );
    let author = agent(&pool).await;
    let k = claim(&pool, author, "K").await;
    let a1 = claim(&pool, author, "a1").await;
    decompose(&pool, k, a1).await;
    support(&pool, a1, 0.8).await;
    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let r: Value = first_text(
        &get_belief(&server, &viewer, params(k))
            .await
            .expect("get_belief"),
    );
    assert!(
        r.get("shadow").is_none(),
        "default mode adds no shadow: {r}"
    );
}

/// The shadow is the global view whatever lens the served read used (it
/// mirrors the top-level fields, which are global; the lensed value stays in
/// `lensed_belief`). Under a lens {empirical: .2} an atom with one empirical
/// item at .8 has `lensed_belief` .16 and a shadow of .8.
#[sqlx::test(migrations = "../../migrations")]
async fn the_shadow_stays_global_beside_a_lensed_belief(pool: PgPool) {
    let author = agent(&pool).await;
    let atom = claim(&pool, author, "lensed atom").await;
    store_support(&pool, atom, 0.8, Some("empirical"), None).await;
    let lens = PerspectiveRepository::create(
        &pool,
        "empirical skeptic",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("perspective");
    PerspectiveRepository::set_source_reliability(
        &pool,
        lens.id,
        &std::collections::HashMap::from([("empirical".to_string(), 0.2)]),
    )
    .await
    .expect("reliability map");
    let frame = binary_frame(&pool).await;

    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let r: Value = first_text(
        &get_belief_in_mode(
            &server,
            &viewer,
            GetBeliefParams {
                claim_id: atom.to_string(),
                frame_id: Some(frame.to_string()),
                perspective_id: Some(lens.id.to_string()),
            },
            CompoundBeliefMode::Shadow,
        )
        .await
        .expect("lensed get_belief"),
    );
    let lensed = r["lensed_belief"]["belief"]
        .as_f64()
        .expect("lensed belief");
    let shadow = r["shadow"]["bel"].as_f64().expect("shadow bel");
    assert!(
        (lensed - 0.16).abs() < 1e-9,
        "lensed .16, got {lensed}: {r}"
    );
    assert!(
        (shadow - 0.8).abs() < 1e-9,
        "the shadow is the global view, .8, got {shadow}: {r}"
    );
}
