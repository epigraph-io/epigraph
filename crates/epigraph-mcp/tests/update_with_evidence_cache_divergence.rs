//! Backlog 8ff648c9: a supporting `update_with_evidence` must not be a SILENT
//! no-op, and must not silently re-point the claim's cache.
//!
//! `auto_wire_ds_update` folds the claim's BBAs on every two-hypothesis frame,
//! then clamps a supports=true BetP up to the claim's prior (the cached
//! `pignistic_prob`), then writes the cache with `belief_frame_id =
//! binary_truth`. When the claim's cache came from ANOTHER frame (one the fold
//! does not read) and sits above this fold, the clamp pins BetP to the old
//! cached value: `truth_after` equals the prior, `cache_written` is true, and
//! no warning said so (the only warnings were "decreased belief", which a
//! clamp to the prior never trips, and `!cache_written`). The cache's frame
//! was moved to `binary_truth` with no word either.
//!
//! The fixture is the reporter's shape: the cache (BetP 0.9) is recorded on a
//! THREE-hypothesis frame, which the binary fold does not read, and the
//! claim's one binary BBA is a weak pure support, so the fold's plausibility
//! stays 1 and the clamp lifts BetP exactly to the prior (no "decreased
//! belief" warning can fire).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::{FrameRepository, MassFunctionRepository};
use epigraph_mcp::types::UpdateWithEvidenceParams;
use sqlx::PgPool;
use uuid::Uuid;

const PRIOR: f64 = 0.9;

async fn run_update(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
) -> serde_json::Value {
    let result = epigraph_mcp::tools::claims::update_with_evidence(
        server,
        viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: format!("8ff648c9 supporting evidence for {claim_id}"),
            source_url: None,
            supports: true,
            strength: 0.6,
            labels: Vec::new(),
        },
        None,
    )
    .await
    .expect("update_with_evidence ok");
    first_text(&result)
}

async fn recorded_frame(pool: &PgPool, claim: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT belief_frame_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read belief_frame_id")
}

/// A claim whose cache (BetP 0.9) is carried on a ternary frame and whose one
/// binary BBA is a weak support.
async fn seed_other_frame_cache(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> (Uuid, Uuid) {
    let claim = seed_claim_with_belief(pool, 0.85, 0.95, Some(PRIOR)).await;
    let other = FrameRepository::create(
        pool,
        &format!("8ff648c9_ternary_{}", &Uuid::new_v4().to_string()[..8]),
        Some("a cache-owner frame the binary fold does not read"),
        &["A".to_string(), "B".to_string(), "C".to_string()],
    )
    .await
    .expect("create ternary frame")
    .id;
    FrameRepository::assign_claim(pool, claim, other, Some(0))
        .await
        .expect("assign the claim to the ternary frame");
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        other,
        Some(seed_agent(pool).await),
        None,
        &serde_json::json!({"0": 0.9, "0,1,2": 0.1}),
        None,
        None,
        None,
        Some("empirical"),
        "unknown",
        None,
    )
    .await
    .expect("store the ternary BBA the cache came from");
    sqlx::query("UPDATE claims SET belief_frame_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(other)
        .execute(pool)
        .await
        .expect("record the cache on the ternary frame");

    let mut conn = pool.acquire().await.expect("acquire");
    let binary = epigraph_mcp::tools::ds_auto::ensure_binary_frame(&mut conn, viewer)
        .await
        .expect("binary_truth frame");
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        claim,
        binary,
        Some(seed_agent(pool).await),
        None,
        &serde_json::json!({"0": 0.2, "0,1": 0.8}),
        None,
        None,
        None,
        Some("empirical"),
        "unknown",
        None,
    )
    .await
    .expect("store the weak binary support");
    (claim, other)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_clamp_to_the_prior_and_a_repointed_cache_are_reported(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (claim, other) = seed_other_frame_cache(&pool, &viewer).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim).await;
    let after = json["pignistic_prob"].as_f64().expect("pignistic_prob");
    let warning = json["warning"].as_str().unwrap_or_default().to_string();

    // Belief rises, or the response says why it did not. The fixture is
    // built so that it does not rise (the fold's BetP is at most 0.84 and its
    // Pl is 1), so the second arm is the one exercised.
    assert!(
        (after - PRIOR).abs() < 1e-12,
        "fixture premise: the clamp holds BetP at the prior {PRIOR}; got {json}"
    );
    assert_eq!(
        json["cache_written"],
        serde_json::Value::Bool(true),
        "{json}"
    );
    let fold = json["fold_pignistic_prob"].as_f64().unwrap_or_else(|| {
        panic!(
            "a supporting update that left BetP at the prior {PRIOR} must report the fold \
             the clamp overrode (fold_pignistic_prob); got {json}"
        )
    });
    assert!(
        fold < PRIOR,
        "fixture: the binary fold ({fold}) must sit below the other-frame prior: {json}"
    );
    assert!(
        warning.contains("monotonicity clamp fired"),
        "a clamp to the prior must be named in `warning`, not silent: {json}"
    );

    // The cache's frame is not silently re-pointed: either it still records
    // the other frame, or the response names the move.
    let recorded = recorded_frame(&pool, claim).await;
    if recorded != Some(other) {
        assert_eq!(
            json["cache_repointed_from"].as_str(),
            Some(other.to_string().as_str()),
            "the cache moved off {other} to {recorded:?}: the response must name the frame it \
             left; got {json}"
        );
        assert!(
            warning.contains("re-pointed"),
            "a re-pointed cache must be named in `warning`: {json}"
        );
    }
}

/// The third note: a cache written where the owner rule elects no frame.
/// A compound (an in-force `decomposes_to` out-edge) has no cache-owner frame,
/// so the next recompute never keeps this call's write.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cache_written_on_a_claim_with_no_owner_frame_is_reported(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim = seed_claim(&pool, "8ff648c9 compound parent, and more", 0.5).await;
    let child = seed_claim(&pool, "8ff648c9 child", 0.5).await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
         properties) VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
         '{}'::jsonb)",
    )
    .bind(claim)
    .bind(child)
    .execute(&pool)
    .await
    .expect("decomposes_to edge");
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim).await;
    assert_eq!(
        json["cache_written"],
        serde_json::Value::Bool(true),
        "fixture premise: the caller writes the compound's cache: {json}"
    );
    assert_eq!(
        json["cache_owner_frame_id"].as_str(),
        Some("none"),
        "a compound has no cache-owner frame; the response must say so: {json}"
    );
    assert!(
        json["warning"]
            .as_str()
            .is_some_and(|w| w.contains("no cache-owner frame")),
        "{json}"
    );
}
