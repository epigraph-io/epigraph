//! Integration tests for `mcp__epigraph__suggest_alternative_sets`.
//!
//! Two scenarios:
//! 1. Three supporters of T; two of them are linked by `contradicts`. The
//!    tool returns exactly that one pair, scored. The third supporter does
//!    not appear in any candidate.
//! 2. Same shape but with an explicit `alternative_of` edge already in place
//!    — the tool must not re-suggest it.

mod common;

use common::{build_test_server, first_text, insert_claim_edge, seed_claim};
use epigraph_mcp::tools::alternative_sets::{
    suggest_alternative_sets, SuggestAlternativeSetsParams,
};
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn suggest_returns_only_contradicts_pair(pool: PgPool) {
    let target = seed_claim(&pool, "Target", 0.5).await;
    let a1 = seed_claim(&pool, "A1", 0.7).await;
    let a2 = seed_claim(&pool, "A2", 0.6).await;
    let a3 = seed_claim(&pool, "A3", 0.5).await;

    insert_claim_edge(&pool, a1, target, "supports").await;
    insert_claim_edge(&pool, a2, target, "supports").await;
    insert_claim_edge(&pool, a3, target, "supports").await;
    insert_claim_edge(&pool, a1, a2, "contradicts").await;

    let server = build_test_server(pool.clone());
    let result = suggest_alternative_sets(
        &server,
        SuggestAlternativeSetsParams {
            target_claim_id: Some(target.to_string()),
            // `pignistic_prob` is NULL on fresh-seeded claims; SQL coalesces to
            // 0.0, so a 0.0 threshold is the only way the candidate surfaces
            // here without driving a BP recompute first.
            min_pair_strength: 0.0,
        },
    )
    .await
    .expect("tool call ok");

    let payload = first_text(&result);
    let candidates = payload["candidates"]
        .as_array()
        .expect("`candidates` must be a JSON array");
    assert_eq!(
        candidates.len(),
        1,
        "expected exactly 1 candidate, got {candidates:?}"
    );

    let cand = &candidates[0];
    let ids: BTreeSet<Uuid> = [
        Uuid::parse_str(cand["claim_a"].as_str().unwrap()).unwrap(),
        Uuid::parse_str(cand["claim_b"].as_str().unwrap()).unwrap(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        ids,
        BTreeSet::from([a1, a2]),
        "candidate pair must be exactly {{A1, A2}}, got {ids:?}"
    );
    assert!(
        !ids.contains(&a3),
        "A3 must not appear (no contradicts edge), got {ids:?}"
    );

    let target_claim = Uuid::parse_str(cand["target_claim"].as_str().unwrap()).unwrap();
    assert_eq!(
        target_claim, target,
        "target_claim must equal the seeded target"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn suggest_skips_pairs_with_existing_alternative_of(pool: PgPool) {
    let target = seed_claim(&pool, "Target", 0.5).await;
    let a1 = seed_claim(&pool, "A1", 0.7).await;
    let a2 = seed_claim(&pool, "A2", 0.6).await;

    insert_claim_edge(&pool, a1, target, "supports").await;
    insert_claim_edge(&pool, a2, target, "supports").await;
    insert_claim_edge(&pool, a1, a2, "contradicts").await;
    // Already-known alt-set: tool must not re-suggest it.
    insert_claim_edge(&pool, a1, a2, "alternative_of").await;

    let server = build_test_server(pool.clone());
    let result = suggest_alternative_sets(
        &server,
        SuggestAlternativeSetsParams {
            target_claim_id: Some(target.to_string()),
            min_pair_strength: 0.0,
        },
    )
    .await
    .expect("tool call ok");

    let payload = first_text(&result);
    let candidates = payload["candidates"]
        .as_array()
        .expect("`candidates` must be a JSON array");
    assert!(
        candidates.is_empty(),
        "alternative_of pair must not be re-suggested, got {candidates:?}"
    );
}
