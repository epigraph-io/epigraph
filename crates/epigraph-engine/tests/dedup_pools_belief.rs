//! A dedup pools the duplicate's evidence into the canonical's belief.
//!
//! After `mark_duplicate_with_cascade`, the canonical's cached pignistic
//! probability must be the combine of its own BBAs and the duplicate's pooled
//! ones, computed by the same pipeline (`preview_claim_belief_on_frame`) over a
//! control claim that holds exactly that union. A same-source copy the
//! canonical already counts is NOT in the union: it stays on the duplicate.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{FrameRepository, MassFunctionRepository, PgPool};
use epigraph_engine::edge_factor::preview_claim_belief_on_frame;
use epigraph_engine::retraction_cascade::mark_duplicate_with_cascade;
use uuid::Uuid;

async fn new_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("agent")
}

async fn new_claim(pool: &PgPool, agent: Uuid, tag: &str, frame: Uuid) -> Uuid {
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!("dedup pooling {tag} {}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("claim");
    FrameRepository::assign_claim(pool, claim, frame, Some(0))
        .await
        .expect("assign frame");
    claim
}

async fn store(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Option<Uuid>, m: serde_json::Value) {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        agent,
        None,
        &m,
        None,
        None,
        None,
        Some("empirical"),
        "unknown",
        None,
    )
    .await
    .expect("store bba");
}

/// An assess row as `routes/assess.rs` stores it: no agent, no perspective,
/// `combination_method = "discount"`, untyped.
async fn store_assess(pool: &PgPool, claim: Uuid, frame: Uuid, m: serde_json::Value) {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        None,
        None,
        &m,
        None,
        Some("discount"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("store assess row");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_canonical_belief_after_a_dedup_is_the_combine_of_the_pooled_union(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        None,
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;
    let (a1, a2) = (new_agent(&pool).await, new_agent(&pool).await);
    let canonical = new_claim(&pool, a1, "canonical", frame).await;
    let dup = new_claim(&pool, a1, "duplicate", frame).await;
    let control = new_claim(&pool, a1, "control", frame).await;

    let canon_a1 = serde_json::json!({"0": 0.6, "0,1": 0.4});
    let dup_a2 = serde_json::json!({"0": 0.7, "0,1": 0.3});
    let dup_assess = serde_json::json!({"1": 0.2, "0,1": 0.8});
    // a1's copy on the duplicate collides with the canonical's a1 row and must
    // stay out of the union (it is kept on the duplicate). A move would trip
    // the per-perspective unique key and fail the mark outright.
    let dup_a1 = serde_json::json!({"1": 0.9, "0,1": 0.1});

    store(&pool, canonical, frame, Some(a1), canon_a1.clone()).await;
    store(&pool, dup, frame, Some(a2), dup_a2.clone()).await;
    store_assess(&pool, dup, frame, dup_assess.clone()).await;
    store(&pool, dup, frame, Some(a1), dup_a1).await;
    for (agent, m) in [(Some(a1), canon_a1), (Some(a2), dup_a2)] {
        store(&pool, control, frame, agent, m).await;
    }
    store_assess(&pool, control, frame, dup_assess).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let alone = preview_claim_belief_on_frame(&mut conn, &viewer, canonical, frame)
        .await
        .expect("preview canonical")
        .expect("canonical has BBAs");
    let expected = preview_claim_belief_on_frame(&mut conn, &viewer, control, frame)
        .await
        .expect("preview control")
        .expect("control has BBAs");
    assert!(
        (expected.pignistic_prob - alone.pignistic_prob).abs() > 0.01,
        "calibration: pooling must change the canonical's BetP for this arm to say anything \
         ({} vs {})",
        expected.pignistic_prob,
        alone.pignistic_prob
    );

    let report = mark_duplicate_with_cascade(&mut conn, &viewer, dup, canonical)
        .await
        .expect("dedup with cascade");
    assert!(
        report.errors.is_empty(),
        "cascade errors: {:?}",
        report.errors
    );

    let cached: Option<f64> = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(canonical)
        .fetch_one(&pool)
        .await
        .expect("canonical row");
    let cached = cached.expect("the cascade cached the canonical's BetP");
    assert!(
        (cached - expected.pignistic_prob).abs() < 1e-9,
        "canonical BetP {cached} is not the combine of the pooled union {}",
        expected.pignistic_prob
    );
}
