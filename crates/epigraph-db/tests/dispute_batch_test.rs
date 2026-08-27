//! `ClaimRepository::dispute_batch` — dispute-awareness signal for `recall()`
//! (backlog 34d3400d / design F3).
//!
//! These tests pin the three behaviours that a naive implementation gets
//! wrong, and that the recall-facing contract depends on:
//!
//! 1. Only `contradicts`/`refutes` count — not the rest of the epistemic
//!    allowlist (`in_epistemic_degree_batch` counts all seven; this is a
//!    deliberately narrower sibling).
//! 2. A contester that is no longer `is_current` must NOT count. Superseded
//!    counter-evidence is not live dispute; counting it would permanently
//!    mark a claim contested after its challenger was retracted.
//! 3. `contesting_claim_ids` is capped at the top 3 **ordered by contesting
//!    truth_value DESC** — the cap must drop the weakest contester, not an
//!    arbitrary one.

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-dispute', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, truth: f64, is_current: bool) -> Uuid {
    let content = format!("dispute-fixture-{}", Uuid::new_v4());
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), $2, $3, $4)
         RETURNING id",
    )
    .bind(&content)
    .bind(truth)
    .bind(agent)
    .bind(is_current)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
}

/// Only `contradicts`/`refutes` are disputes. `supports`/`corroborates`/
/// `elaborates` targeting the same claim must not inflate `dispute_count` —
/// otherwise every well-supported claim would report as contested.
#[sqlx::test(migrations = "../../migrations")]
async fn only_contradicts_and_refutes_count_as_disputes(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let target = seed_claim(&pool, agent, 0.8, true).await;

    let contradictor = seed_claim(&pool, agent, 0.7, true).await;
    let refuter = seed_claim(&pool, agent, 0.6, true).await;
    let supporter = seed_claim(&pool, agent, 0.9, true).await;
    let corroborator = seed_claim(&pool, agent, 0.9, true).await;

    seed_edge(&pool, contradictor, target, "contradicts").await;
    seed_edge(&pool, refuter, target, "refutes").await;
    seed_edge(&pool, supporter, target, "supports").await;
    seed_edge(&pool, corroborator, target, "corroborates").await;

    let map = ClaimRepository::dispute_batch(&pool, &[target])
        .await
        .expect("dispute_batch");
    let row = map.get(&target).expect("target present");

    assert_eq!(
        row.dispute_count, 2,
        "only the contradicts + refutes edges count; supports/corroborates must not"
    );
    assert!(row.contesting_claim_ids.contains(&contradictor));
    assert!(row.contesting_claim_ids.contains(&refuter));
    assert!(
        !row.contesting_claim_ids.contains(&supporter),
        "a supporter must never appear as a contester"
    );
}

/// A contradicting claim that has been superseded (`is_current = false`) is
/// not live dispute. Without the `is_current` join a retracted challenger
/// would mark its target contested forever.
#[sqlx::test(migrations = "../../migrations")]
async fn superseded_contester_does_not_count(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let target = seed_claim(&pool, agent, 0.8, true).await;

    let live = seed_claim(&pool, agent, 0.7, true).await;
    let retired = seed_claim(&pool, agent, 0.7, false).await;

    seed_edge(&pool, live, target, "contradicts").await;
    seed_edge(&pool, retired, target, "contradicts").await;

    let map = ClaimRepository::dispute_batch(&pool, &[target])
        .await
        .expect("dispute_batch");
    let row = map.get(&target).expect("target present");

    assert_eq!(
        row.dispute_count, 1,
        "only the is_current contester counts; the superseded one must be excluded"
    );
    assert_eq!(row.contesting_claim_ids, vec![live]);
    assert!(
        !row.contesting_claim_ids.contains(&retired),
        "superseded contester must not be surfaced"
    );
}

/// The `contesting_claim_ids` cap keeps the three STRONGEST contesters.
/// Seeding four and asserting the lowest-truth one is the one dropped pins
/// the ordering, which a `LIMIT 3` without `ORDER BY` would satisfy only by
/// luck.
#[sqlx::test(migrations = "../../migrations")]
async fn contesting_ids_capped_at_top_three_by_truth(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let target = seed_claim(&pool, agent, 0.5, true).await;

    let strongest = seed_claim(&pool, agent, 0.95, true).await;
    let strong = seed_claim(&pool, agent, 0.85, true).await;
    let middling = seed_claim(&pool, agent, 0.75, true).await;
    let weakest = seed_claim(&pool, agent, 0.15, true).await;

    for c in [strongest, strong, middling, weakest] {
        seed_edge(&pool, c, target, "contradicts").await;
    }

    let map = ClaimRepository::dispute_batch(&pool, &[target])
        .await
        .expect("dispute_batch");
    let row = map.get(&target).expect("target present");

    assert_eq!(
        row.dispute_count, 4,
        "dispute_count reports ALL contesters, it is not capped by the id list"
    );
    assert_eq!(
        row.contesting_claim_ids,
        vec![strongest, strong, middling],
        "top-3 by contesting truth_value DESC, in that order"
    );
    assert!(
        !row.contesting_claim_ids.contains(&weakest),
        "the weakest contester is the one dropped by the cap"
    );
}

/// Batching contract: an uncontested claim is ABSENT from the map (callers
/// treat a missing key as 0), mirroring `in_epistemic_degree_batch`. A claim
/// with disputes and one without must be distinguishable in one round-trip.
#[sqlx::test(migrations = "../../migrations")]
async fn uncontested_claims_are_absent_from_the_map(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let contested = seed_claim(&pool, agent, 0.8, true).await;
    let clean = seed_claim(&pool, agent, 0.8, true).await;

    let contester = seed_claim(&pool, agent, 0.7, true).await;
    seed_edge(&pool, contester, contested, "refutes").await;

    let map = ClaimRepository::dispute_batch(&pool, &[contested, clean])
        .await
        .expect("dispute_batch");

    assert!(map.contains_key(&contested), "contested claim present");
    assert!(
        !map.contains_key(&clean),
        "uncontested claim absent (missing key == 0), not present with a zero"
    );
}

/// Empty input must short-circuit without touching the database — the recall
/// path calls this on every page, including pages that returned nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn empty_input_returns_empty_map(pool: PgPool) {
    let map = ClaimRepository::dispute_batch(&pool, &[])
        .await
        .expect("dispute_batch on empty input");
    assert!(map.is_empty());
}

// ---------------------------------------------------------------------------
// Symmetry of `contradicts` on the READ side (backlog 9a0bd3e2).
//
// `link_epistemic` routes `contradicts` through the SYMMETRIC writer, so one
// unordered pair yields exactly ONE row in whichever direction the caller
// asserted it. A read that keys only on `target_id` therefore reports the
// reverse asserter's own claim as uncontested. These pin the fix, and pin the
// two things a blanket symmetrization would get wrong.
// ---------------------------------------------------------------------------

/// The regression itself: `A contradicts B` must mark BOTH A and B disputed.
/// Pre-fix A is absent from the map entirely, because A is never a `target_id`.
#[sqlx::test(migrations = "../../migrations")]
async fn reverse_direction_contradicts_marks_the_source_contested(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, 0.8, true).await;
    let b = seed_claim(&pool, agent, 0.7, true).await;

    seed_edge(&pool, a, b, "contradicts").await;

    let map = ClaimRepository::dispute_batch(&pool, &[a, b])
        .await
        .expect("dispute_batch");

    let row_b = map.get(&b).expect("the asserted target is contested");
    assert_eq!(row_b.dispute_count, 1);
    assert_eq!(row_b.contesting_claim_ids, vec![a]);

    let row_a = map
        .get(&a)
        .expect("the ASSERTER is contested too — `contradicts` is unordered");
    assert_eq!(row_a.dispute_count, 1);
    assert_eq!(row_a.contesting_claim_ids, vec![b]);
}

/// `refutes` is ORDERED — it stays on the directional writer, and `A refutes B`
/// is a claim about B, not a mutual standoff. Mirroring the whole
/// `contradicts`/`refutes` pair would report every refuter as itself disputed.
#[sqlx::test(migrations = "../../migrations")]
async fn reverse_direction_refutes_does_not_mark_the_source_contested(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, 0.8, true).await;
    let b = seed_claim(&pool, agent, 0.7, true).await;

    seed_edge(&pool, a, b, "refutes").await;

    let map = ClaimRepository::dispute_batch(&pool, &[a, b])
        .await
        .expect("dispute_batch");

    assert!(map.contains_key(&b), "the refuted claim is contested");
    assert!(
        !map.contains_key(&a),
        "the refuter must NOT be reported contested — `refutes` is ordered"
    );
}

/// A pair written BEFORE the symmetric writer landed carries both `A->B` and
/// `B->A` rows for one unordered fact. The `UNION` collapses them; `UNION ALL`
/// would score each endpoint 2 and list its single contester twice.
#[sqlx::test(migrations = "../../migrations")]
async fn legacy_duplicate_contradicts_pair_counts_once(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, 0.8, true).await;
    let b = seed_claim(&pool, agent, 0.7, true).await;

    seed_edge(&pool, a, b, "contradicts").await;
    seed_edge(&pool, b, a, "contradicts").await;

    let map = ClaimRepository::dispute_batch(&pool, &[a, b])
        .await
        .expect("dispute_batch");

    let row_a = map.get(&a).expect("a contested");
    let row_b = map.get(&b).expect("b contested");
    assert_eq!(
        row_a.dispute_count, 1,
        "one unordered fact, one contester — not one per legacy row"
    );
    assert_eq!(row_b.dispute_count, 1);
    assert_eq!(row_a.contesting_claim_ids, vec![b]);
    assert_eq!(row_b.contesting_claim_ids, vec![a]);
}

/// `corroborates` is symmetric but is NOT a dispute relation. Mirroring the
/// whole `SYMMETRIC_RELATIONSHIPS` set into this query instead of the
/// `contradicts` leg alone would turn agreement into dispute.
#[sqlx::test(migrations = "../../migrations")]
async fn corroborates_never_counts_as_dispute_in_either_direction(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, 0.8, true).await;
    let b = seed_claim(&pool, agent, 0.7, true).await;

    seed_edge(&pool, a, b, "corroborates").await;

    let map = ClaimRepository::dispute_batch(&pool, &[a, b])
        .await
        .expect("dispute_batch");
    assert!(
        map.is_empty(),
        "corroboration is not dispute, in either direction"
    );
}

/// `in_epistemic_degree_batch` gains the same symmetric leg — and only for the
/// symmetric relations. An ordered `C supports D` must still score D only.
#[sqlx::test(migrations = "../../migrations")]
async fn symmetric_contradicts_lifts_degree_on_both_endpoints(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let a = seed_claim(&pool, agent, 0.8, true).await;
    let b = seed_claim(&pool, agent, 0.7, true).await;
    let c = seed_claim(&pool, agent, 0.8, true).await;
    let d = seed_claim(&pool, agent, 0.7, true).await;

    seed_edge(&pool, a, b, "contradicts").await;
    seed_edge(&pool, c, d, "supports").await;

    let map = ClaimRepository::in_epistemic_degree_batch(&pool, &[a, b, c, d])
        .await
        .expect("in_epistemic_degree_batch");

    assert_eq!(map.get(&a), Some(&1), "symmetric edge counts on the source");
    assert_eq!(map.get(&b), Some(&1), "and on the target");
    assert_eq!(map.get(&d), Some(&1), "ordered edge counts on the target");
    assert_eq!(
        map.get(&c),
        None,
        "an ordered relation must NOT gain a source-side leg"
    );
}
