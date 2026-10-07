//! The `update_with_evidence` writer must cache the conflict its fold SAW
//! (drain unit U025, backlog 9d4821c1), and agree with the recompute on it.
//!
//! `ds_auto::auto_wire_ds_update` writes `claims.mass_on_empty`. Since U025
//! every `combine_multiple` step is Dempster, which normalises the conflict
//! out of the combined mass, so `combined.mass_of_conflict()` is always 0
//! after a multi-BBA fold. The writer must take the fold's aggregate conflict
//! (`combination::fold_conflict`) instead, exactly as
//! `edge_factor::compute_combined_belief` (the recompute) does. Otherwise
//! every ordinary write caches `mass_on_empty = 0` and the next recompute
//! rewrites it to the real conflict.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::MassFunctionRepository;
use epigraph_engine::edge_factor::recompute_claim_belief_on_frame;
use epigraph_mcp::tools::ds_auto::{auto_wire_ds_update, ensure_binary_frame};

async fn cached_mass_on_empty(pool: &sqlx::PgPool, claim_id: uuid::Uuid) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>("SELECT mass_on_empty FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("query mass_on_empty")
        .expect("mass_on_empty populated by the DS writer")
}

#[sqlx::test(migrations = "../../migrations")]
async fn writer_caches_the_fold_conflict_and_agrees_with_recompute(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, "u025 ds_auto writer conflict", 0.5).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let frame_id = ensure_binary_frame(&mut conn, &viewer)
        .await
        .expect("binary_truth frame");

    // An existing OPPOSING BBA from another writer: m(FALSE) = 0.8.
    // 'empirical' is calibrated at weight 1.0 and locality 'unknown' at 1.0,
    // so neither BBA is discounted and K is exactly 0.8 * 0.8 = 0.64.
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        claim_id,
        frame_id,
        Some(seed_agent(&pool).await),
        None,
        &serde_json::json!({"1": 0.8, "0,1": 0.2}),
        None,
        None,
        None,
        Some("empirical"),
        "unknown",
        None,
    )
    .await
    .expect("store opposing BBA");

    // The writer under test: a SUPPORTING m(TRUE) = 0.8 * 1.0.
    let res = auto_wire_ds_update(
        &mut conn,
        &viewer,
        claim_id,
        seed_agent(&pool).await,
        0.8,
        1.0,
        true,
        Some("empirical"),
        None,
    )
    .await
    .expect("auto_wire_ds_update");
    assert!(res.cache_written, "the writer must write the cache");

    assert!(
        (res.mass_on_conflict - 0.64).abs() < 1e-9,
        "the writer must report the fold's conflict K = 0.64, got {}",
        res.mass_on_conflict
    );
    let written = cached_mass_on_empty(&pool, claim_id).await;
    assert!(
        (written - 0.64).abs() < 1e-9,
        "the writer must cache claims.mass_on_empty = fold conflict 0.64, got {written}"
    );

    // The next recompute folds the same two BBAs (both on binary_truth) and
    // must leave the conflict where the writer put it.
    assert!(
        recompute_claim_belief_on_frame(&mut conn, &viewer, claim_id, frame_id)
            .await
            .expect("recompute"),
        "the recompute wrote the cache"
    );
    drop(conn);
    let recomputed = cached_mass_on_empty(&pool, claim_id).await;
    assert!(
        (recomputed - written).abs() < 1e-12,
        "writer cached mass_on_empty {written}, recompute rewrote it to {recomputed}"
    );
}
