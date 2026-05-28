//! Round-trip test for `mass_functions.locality_tag` (Phase 1a of issue #197).
//!
//! Asserts that the column persists end-to-end:
//!   * `store_with_perspective("intra")` → row reads back `locality_tag = "intra"`
//!   * Same for `"cross"` and `"unknown"`
//!   * A raw INSERT that omits the column lets the NOT NULL DEFAULT 'unknown'
//!     fire — covers the migration 045 default, which is the legacy/backfill
//!     path that EVERY one of the 279 894 existing BBAs will land on at
//!     deploy time (before Phase 1b backfill SQL rewrites them).
//!
//! Layered against the regression test in `epigraph-engine`: that one
//! verifies the edge_factor path emits `intra` / `cross` correctly through
//! the full write-and-discount pipeline. This one is the tight unit-level
//! round-trip on the repo signature itself, so a future widening of the
//! `MassFunctionRow` struct or the INSERT column list doesn't silently drop
//! the tag and pass only the higher-level integration test by accident.

use epigraph_db::{MassFunctionRepository, MassFunctionRow};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn distinct_hash(tag: u32) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = (tag & 0xff) as u8;
    h[1] = ((tag >> 8) & 0xff) as u8;
    h[2] = ((tag >> 16) & 0xff) as u8;
    h
}

async fn seed_agent(pool: &PgPool, tag: u32) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind(distinct_hash(tag))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, tag: u32) -> Uuid {
    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, $2, $3, $4, 0.5, true)",
    )
    .bind(claim_id)
    .bind(format!("locality-roundtrip-claim-{tag:x}"))
    .bind(distinct_hash(tag))
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    claim_id
}

async fn seed_frame(pool: &PgPool, tag: u32) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, '{\"TRUE\",\"FALSE\"}') RETURNING id",
    )
    .bind(format!("locality-roundtrip-frame-{tag:x}"))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

async fn fetch_row(pool: &PgPool, claim_id: Uuid, frame_id: Uuid) -> MassFunctionRow {
    let rows = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id)
        .await
        .expect("get_for_claim_frame");
    assert_eq!(
        rows.len(),
        1,
        "expected exactly one BBA after a single store call, got {}",
        rows.len()
    );
    rows.into_iter().next().unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn store_with_perspective_roundtrips_intra_tag(pool: PgPool) {
    let agent = seed_agent(&pool, 0xE1_0001).await;
    let claim = seed_claim(&pool, agent, 0xE1_0002).await;
    let frame = seed_frame(&pool, 0xE1_0003).await;
    let masses = json!({"0": 0.6, "0,1": 0.4});

    MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        frame,
        Some(agent),
        None,
        &masses,
        None,
        Some("test"),
        Some(0.21),
        Some("supports"),
        "intra",
    )
    .await
    .expect("store intra");

    let row = fetch_row(&pool, claim, frame).await;
    assert_eq!(row.locality_tag, "intra");
}

#[sqlx::test(migrations = "../../migrations")]
async fn store_with_perspective_roundtrips_cross_tag(pool: PgPool) {
    let agent = seed_agent(&pool, 0xE2_0001).await;
    let claim = seed_claim(&pool, agent, 0xE2_0002).await;
    let frame = seed_frame(&pool, 0xE2_0003).await;
    let masses = json!({"0": 0.6, "0,1": 0.4});

    MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        frame,
        Some(agent),
        None,
        &masses,
        None,
        Some("test"),
        Some(0.7),
        Some("supports"),
        "cross",
    )
    .await
    .expect("store cross");

    let row = fetch_row(&pool, claim, frame).await;
    assert_eq!(row.locality_tag, "cross");
}

#[sqlx::test(migrations = "../../migrations")]
async fn store_with_perspective_roundtrips_unknown_tag(pool: PgPool) {
    let agent = seed_agent(&pool, 0xE3_0001).await;
    let claim = seed_claim(&pool, agent, 0xE3_0002).await;
    let frame = seed_frame(&pool, 0xE3_0003).await;
    let masses = json!({"0": 0.6, "0,1": 0.4});

    MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        frame,
        Some(agent),
        None,
        &masses,
        None,
        Some("test"),
        None,
        None,
        "unknown",
    )
    .await
    .expect("store unknown");

    let row = fetch_row(&pool, claim, frame).await;
    assert_eq!(row.locality_tag, "unknown");
}

/// Verifies migration 045's column default. A raw INSERT that omits
/// `locality_tag` from the column list must let the DEFAULT 'unknown'
/// fire — this is the path every legacy row will take at deploy until the
/// Phase 1b backfill SQL rewrites them.
///
/// Important: this test does NOT route through `store_with_perspective`,
/// because that function explicitly binds `locality_tag` to every INSERT.
/// We need raw SQL to test the column default itself.
#[sqlx::test(migrations = "../../migrations")]
async fn raw_insert_without_locality_tag_defaults_to_unknown(pool: PgPool) {
    let agent = seed_agent(&pool, 0xE4_0001).await;
    let claim = seed_claim(&pool, agent, 0xE4_0002).await;
    let frame = seed_frame(&pool, 0xE4_0003).await;
    let masses = json!({"0": 0.6, "0,1": 0.4});

    // Direct INSERT omitting `locality_tag` from the column list.
    // The NOT NULL constraint must be satisfied by the column DEFAULT
    // 'unknown' set in migration 045.
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(&masses)
    .execute(&pool)
    .await
    .expect("raw INSERT without locality_tag should rely on column DEFAULT");

    let row = fetch_row(&pool, claim, frame).await;
    assert_eq!(
        row.locality_tag, "unknown",
        "column DEFAULT 'unknown' must fire when INSERT omits locality_tag"
    );
}
