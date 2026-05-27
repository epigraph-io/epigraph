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
            // Seeds carry no lifecycle labels — default exclude_settled=true
            // is a no-op for these tests; pin both explicitly so they keep
            // testing pre-lifecycle heuristic semantics.
            exclude_settled: true,
            surface_reconsiderations: false,
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
            exclude_settled: true,
            surface_reconsiderations: false,
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

// ── Lifecycle-label tests (PR feat/alt-set-lifecycle) ────────────────────────
//
// The four tests below cover the two new `SuggestAlternativeSetsParams` fields:
// `exclude_settled` (default true) and `surface_reconsiderations` (default
// false). Together they enforce that:
//   - `alt-chosen` members are dropped by default;
//   - `exclude_settled=false` restores pre-PR behavior;
//   - rejected pairs surface only when `surface_reconsiderations=true` AND the
//     BetP gap to the rival meets `min_pair_strength`.
//
// The SQL filter reads `pignistic_prob`, not `truth_value`, so the BetP-gap
// test pokes `pignistic_prob` directly via raw UPDATE — `seed_claim` leaves
// it NULL (coalesced to 0.0). The settled/exclude tests work fine with the
// default 0.0 BetP because `min_pair_strength = 0.0` clears the score gate.

#[sqlx::test(migrations = "../../migrations")]
async fn exclude_settled_default_drops_chosen_pair(pool: PgPool) {
    let target = seed_claim(&pool, "Target", 0.5).await;
    let a1 = seed_claim(&pool, "A1", 0.7).await;
    let a2 = seed_claim(&pool, "A2", 0.6).await;
    insert_claim_edge(&pool, a1, target, "supports").await;
    insert_claim_edge(&pool, a2, target, "supports").await;
    insert_claim_edge(&pool, a1, a2, "contradicts").await;
    // Mark a1 as alt-chosen — should suppress this pair under default behavior.
    sqlx::query("UPDATE claims SET labels = ARRAY['alt-chosen'] WHERE id = $1")
        .bind(a1)
        .execute(&pool)
        .await
        .expect("set alt-chosen label");

    let server = build_test_server(pool.clone());
    let result = suggest_alternative_sets(
        &server,
        SuggestAlternativeSetsParams {
            target_claim_id: Some(target.to_string()),
            min_pair_strength: 0.0,
            exclude_settled: true,
            surface_reconsiderations: false,
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
        "alt-chosen member must suppress its pair (default exclude_settled=true), got {candidates:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn exclude_settled_false_surfaces_chosen_pair(pool: PgPool) {
    let target = seed_claim(&pool, "Target", 0.5).await;
    let a1 = seed_claim(&pool, "A1", 0.7).await;
    let a2 = seed_claim(&pool, "A2", 0.6).await;
    insert_claim_edge(&pool, a1, target, "supports").await;
    insert_claim_edge(&pool, a2, target, "supports").await;
    insert_claim_edge(&pool, a1, a2, "contradicts").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['alt-chosen'] WHERE id = $1")
        .bind(a1)
        .execute(&pool)
        .await
        .expect("set alt-chosen label");

    let server = build_test_server(pool.clone());
    let result = suggest_alternative_sets(
        &server,
        SuggestAlternativeSetsParams {
            target_claim_id: Some(target.to_string()),
            min_pair_strength: 0.0,
            exclude_settled: false,
            surface_reconsiderations: false,
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
        "exclude_settled=false should return the pair regardless of labels, got {candidates:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn surface_reconsiderations_yields_rejected_with_stronger_rival(pool: PgPool) {
    let target = seed_claim(&pool, "Target", 0.5).await;
    let a1 = seed_claim(&pool, "A1-rejected", 0.3).await;
    let a2 = seed_claim(&pool, "A2-rival", 0.8).await;
    insert_claim_edge(&pool, a1, target, "supports").await;
    insert_claim_edge(&pool, a2, target, "supports").await;
    insert_claim_edge(&pool, a1, a2, "contradicts").await;
    // The SQL filter compares `pignistic_prob`, not `truth_value`. Set it
    // explicitly so the BetP-gap path in scan_candidates fires.
    sqlx::query(
        "UPDATE claims SET labels = ARRAY['alt-rejected'], pignistic_prob = 0.3 WHERE id = $1",
    )
    .bind(a1)
    .execute(&pool)
    .await
    .expect("set alt-rejected + pignistic_prob on a1");
    sqlx::query("UPDATE claims SET pignistic_prob = 0.8 WHERE id = $1")
        .bind(a2)
        .execute(&pool)
        .await
        .expect("set pignistic_prob on a2");

    let server = build_test_server(pool.clone());
    let result = suggest_alternative_sets(
        &server,
        SuggestAlternativeSetsParams {
            target_claim_id: Some(target.to_string()),
            // BetP gap is 0.5; must exceed min_pair_strength.
            min_pair_strength: 0.3,
            exclude_settled: true,
            surface_reconsiderations: true,
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
        "rejected-with-stronger-rival pair should surface, got {candidates:?}"
    );
    let reason = candidates[0]["reason"]
        .as_str()
        .expect("reason is a string");
    assert!(
        reason.starts_with("reconsider"),
        "reconsideration pair must have 'reconsider' reason prefix, got: {reason}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn surface_reconsiderations_skips_when_gap_too_small(pool: PgPool) {
    let target = seed_claim(&pool, "Target", 0.5).await;
    let a1 = seed_claim(&pool, "A1-rejected", 0.6).await;
    let a2 = seed_claim(&pool, "A2-only-slightly-better", 0.7).await;
    insert_claim_edge(&pool, a1, target, "supports").await;
    insert_claim_edge(&pool, a2, target, "supports").await;
    insert_claim_edge(&pool, a1, a2, "contradicts").await;
    sqlx::query(
        "UPDATE claims SET labels = ARRAY['alt-rejected'], pignistic_prob = 0.6 WHERE id = $1",
    )
    .bind(a1)
    .execute(&pool)
    .await
    .expect("set alt-rejected + pignistic_prob on a1");
    sqlx::query("UPDATE claims SET pignistic_prob = 0.7 WHERE id = $1")
        .bind(a2)
        .execute(&pool)
        .await
        .expect("set pignistic_prob on a2");

    let server = build_test_server(pool.clone());
    let result = suggest_alternative_sets(
        &server,
        SuggestAlternativeSetsParams {
            target_claim_id: Some(target.to_string()),
            // BetP gap of 0.1 does NOT exceed this threshold.
            min_pair_strength: 0.5,
            exclude_settled: true,
            surface_reconsiderations: true,
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
        "gap below min_pair_strength must not surface reconsideration, got {candidates:?}"
    );
}
