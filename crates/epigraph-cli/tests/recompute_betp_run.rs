//! Dry-run vs. real-write behavior for `recompute_betp` (backlog claim
//! f2521c53-86bb-4b3b-96b4-a5cc963f8015).
//!
//! Empirical finding this test locks in: recomputing a cohort claim's BetP
//! via the current (dynamic `effective_source_strength`, issue #197)
//! pipeline produces a value that DIFFERS from a stale cached
//! `claims.pignistic_prob` — proving real re-derivation, not a no-op. The
//! cached value is deliberately set to a sentinel far from the true combine
//! result so the test cannot pass vacuously (delta = 0 either way).
//!
//! `--dry-run` must not write; a real run must write exactly the recomputed
//! value.

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::recompute_betp::{preview_claim, run_claim};

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'recompute-betp-run-test', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

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

/// Seed a claim with a deliberately-stale cached `pignistic_prob` (0.5,
/// far from what the seeded BBAs actually combine to) so a passing
/// assertion "recomputed != cached" is not vacuous.
async fn seed_claim_with_stale_betp(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, pignistic_prob) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, 0.5) \
         RETURNING id",
    )
    .bind(content)
    .bind(agent_id)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

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

async fn cached_pignistic(pool: &PgPool, claim_id: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read cached pignistic_prob")
}

#[sqlx::test(migrations = "../../migrations")]
async fn dry_run_previews_without_writing_and_differs_from_stale_cache(pool: PgPool) {
    let claim_owner = seed_agent(&pool).await;
    let frame_id = seed_binary_frame(&pool, "recompute_betp_run_test_binary").await;

    // Multi-BBA hub shape: two strongly-supporting sources should combine to
    // a high BetP — far from the seeded stale cache of 0.5.
    let hub_claim = seed_claim_with_stale_betp(&pool, claim_owner, "hub claim, stale cache").await;
    let source_a = seed_agent(&pool).await;
    let source_b = seed_agent(&pool).await;
    seed_bba(
        &pool,
        hub_claim,
        frame_id,
        source_a,
        serde_json::json!({"0": 0.9, "0,1": 0.1}),
    )
    .await;
    seed_bba(
        &pool,
        hub_claim,
        frame_id,
        source_b,
        serde_json::json!({"0": 0.85, "0,1": 0.15}),
    )
    .await;

    let cached_before = cached_pignistic(&pool, hub_claim).await;
    assert_eq!(
        cached_before,
        Some(0.5),
        "sentinel cache is in place pre-run"
    );

    // --- dry-run: preview_claim must compute a value that differs from the
    // stale cache, and must NOT write anything.
    let previews = preview_claim(&pool, hub_claim)
        .await
        .expect("preview_claim");
    assert!(
        !previews.is_empty(),
        "expected at least one (frame, preview) pair for the hub claim"
    );
    let (_, preview) = &previews[0];
    assert!(
        (preview.pignistic_prob - 0.5).abs() > 0.05,
        "recomputed pignistic_prob {} must differ meaningfully from the stale 0.5 cache",
        preview.pignistic_prob
    );

    let cached_after_dry_run = cached_pignistic(&pool, hub_claim).await;
    assert_eq!(
        cached_after_dry_run, cached_before,
        "dry-run must not write to claims.pignistic_prob"
    );

    // --- real run: run_claim must write the same value preview_claim
    // computed.
    let written = run_claim(&pool, hub_claim).await.expect("run_claim");
    assert!(written > 0, "expected at least one frame write");

    let cached_after_write = cached_pignistic(&pool, hub_claim).await;
    assert!(
        cached_after_write.is_some(),
        "claims.pignistic_prob must be populated after a real run"
    );
    let after = cached_after_write.unwrap();
    assert!(
        (after - preview.pignistic_prob).abs() < 1e-9,
        "written value {after} must match the previewed value {}",
        preview.pignistic_prob
    );
    assert_ne!(
        after, 0.5,
        "written value must differ from the original stale cache"
    );
}
