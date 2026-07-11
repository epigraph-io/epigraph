//! Cohort-selection test for `recompute_betp` (backlog claim
//! f2521c53-86bb-4b3b-96b4-a5cc963f8015).
//!
//! The cohort is:
//!   (a) claims with >1 BBA on the *same* 2-hypothesis ("binary") frame —
//!       Dempster combination across multiple sources is due for a refresh, and
//!   (b) claims with exactly one BBA on a binary frame whose stored `masses`
//!       JSONB contains a non-simple focal-element key: a lone `"1"` (mass on
//!       the non-supported hypothesis alone, not just `{0}`/`{0,1}`) or `"~"`
//!       (open-world/complement mass) — shapes `effective_source_strength`'s
//!       dynamic derivation (issue #197) never saw when it was originally
//!       written against the raw `source_strength` model.
//!
//! This test asserts `select_cohort` returns exactly the multi-BBA hub claim
//! and the "~"-shape single-BBA claim, and excludes a simple single-BBA claim
//! (masses only on `"0"`/`"0,1"` keys) that needs no recompute.

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::recompute_betp::select_cohort;

/// Seed an agent row (mass_functions/claims both need a valid agent_id FK
/// pattern; mirrors the inline-seed convention used in
/// `tests/reembed_idempotent.rs`). Each call makes a distinct agent so
/// multiple BBAs can land on the same (claim_id, frame_id) without
/// colliding on `mass_functions`' `(claim_id, frame_id, source_agent_id,
/// perspective_id)` unique constraint — real multi-source hub claims have
/// one BBA per contributing agent.
async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'recompute-betp-test', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// Seed a binary (2-hypothesis) frame, matching the `array_length(hypotheses, 1) = 2`
/// scoping `MassFunctionRepository::get_for_claim_binary_frames` uses.
async fn seed_binary_frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, description, hypotheses) \
         VALUES ($1, 'test binary frame', ARRAY['TRUE', 'FALSE']) \
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) \
         RETURNING id",
    )
    .bind(content)
    .bind(agent_id)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

#[allow(clippy::too_many_arguments)]
async fn seed_bba(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Uuid,
    agent_id: Uuid,
    masses_json: serde_json::Value,
) {
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, locality_tag) \
         VALUES ($1, $2, $3, $4, 'unknown')",
    )
    .bind(claim_id)
    .bind(frame_id)
    .bind(agent_id)
    .bind(masses_json)
    .execute(pool)
    .await
    .expect("seed BBA");
}

#[sqlx::test(migrations = "../../migrations")]
async fn select_cohort_includes_multi_bba_hub_and_tilde_shape_excludes_simple(pool: PgPool) {
    let claim_owner = seed_agent(&pool).await;
    let frame_id = seed_binary_frame(&pool, "recompute_betp_test_binary").await;

    // (a) Hub claim: 2 BBAs from 2 distinct source agents on the same binary
    // frame — needs Dempster combination across sources.
    let hub_claim = seed_claim(&pool, claim_owner, "hub claim needs multi-BBA combine").await;
    let source_a = seed_agent(&pool).await;
    let source_b = seed_agent(&pool).await;
    seed_bba(
        &pool,
        hub_claim,
        frame_id,
        source_a,
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    seed_bba(
        &pool,
        hub_claim,
        frame_id,
        source_b,
        serde_json::json!({"0": 0.3, "0,1": 0.7}),
    )
    .await;

    // (b) Single-BBA claim with a non-simple "~" (open-world/complement) key —
    // real shape drawn from crates/epigraph-api/src/routes/belief.rs's
    // submit_evidence_request_with_negative_elements test fixture.
    let tilde_claim = seed_claim(&pool, claim_owner, "single BBA with tilde shape").await;
    let tilde_source = seed_agent(&pool).await;
    seed_bba(
        &pool,
        tilde_claim,
        frame_id,
        tilde_source,
        serde_json::json!({"0": 0.4, "~1": 0.3, "~": 0.3}),
    )
    .await;

    // Excluded: single-BBA claim with only simple positive keys ("0"/"0,1") —
    // no "1" or "~" key present, so no recompute is due.
    let simple_claim = seed_claim(&pool, claim_owner, "single BBA simple shape").await;
    let simple_source = seed_agent(&pool).await;
    seed_bba(
        &pool,
        simple_claim,
        frame_id,
        simple_source,
        serde_json::json!({"0": 0.7, "0,1": 0.3}),
    )
    .await;

    let cohort = select_cohort(&pool).await.expect("select_cohort");

    assert!(
        cohort.contains(&hub_claim),
        "cohort must include the multi-BBA hub claim: {cohort:?}"
    );
    assert!(
        cohort.contains(&tilde_claim),
        "cohort must include the single-BBA '~'-shape claim: {cohort:?}"
    );
    assert!(
        !cohort.contains(&simple_claim),
        "cohort must exclude the simple single-BBA claim: {cohort:?}"
    );
}
