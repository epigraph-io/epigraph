//! `ClaimRepository::list_by_belief_range` — the `query_claims` range read.
//!
//! Three properties, each pinned by one test:
//!
//! 1. Backlog `5a55a48e`: `query_claims(min_truth=0, max_truth=0.75)` returned
//!    an empty list even though matching claims existed, because the handler
//!    fetched the first `limit` rows and filtered *in Rust, after* the `LIMIT`.
//!    The range is filtered in SQL *before* `LIMIT`.
//! 2. GitHub #395 (G10): the range is on the BELIEF SCORE (DS pignistic when the
//!    claim has DS state, else `truth_value`), not on the stale authored
//!    `truth_value` — so a refuted claim is in a low-range queue and a
//!    vindicated one is not.
//! 3. Deterministic paging: ties on `created_at` are broken by `id`, so `offset`
//!    neither repeats nor skips a row.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

/// Insert a claim with an explicit id, `truth_value` and `created_at`.
async fn seed_claim_with_id(pool: &PgPool, id: Uuid, agent_id: Uuid, truth: f64, created_at: &str) {
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6::timestamptz)",
    )
    .bind(id)
    .bind(format!("test claim {id}"))
    .bind(hash)
    .bind(truth)
    .bind(agent_id)
    .bind(created_at)
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, truth: f64, created_at: &str) -> Uuid {
    let id = Uuid::new_v4();
    seed_claim_with_id(pool, id, agent_id, truth, created_at).await;
    id
}

/// Give a claim a DS cache, as a recompute would write it.
async fn set_ds(pool: &PgPool, id: Uuid, belief: f64, plausibility: f64, betp: f64) {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(belief)
    .bind(plausibility)
    .bind(betp)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn range_filter_finds_matches_outside_recent_window(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // 25 RECENT claims with high truth (0.95) — these crowd out the top-`limit`
    // most-recent rows.
    for i in 0..25 {
        let ts = format!("2026-05-29T12:00:{:02}Z", i);
        seed_claim(&pool, agent, 0.95, &ts).await;
    }
    // One OLD claim with low truth (0.50) — the only one in [0, 0.75], but it
    // is the *oldest* row, so a fetch-recent-then-filter strategy never sees it.
    seed_claim(&pool, agent, 0.50, "2026-01-01T00:00:00Z").await;

    let results = ClaimRepository::list_by_belief_range(&pool, &viewer, 0.0, 0.75, None, 20, 0)
        .await
        .unwrap();

    // The low-truth claim must be returned despite being outside the 20 newest.
    assert_eq!(
        results.len(),
        1,
        "expected exactly the one claim in [0,0.75], got {}",
        results.len()
    );
    let (claim, score) = &results[0];
    assert!(
        (0.0..=0.75).contains(score),
        "returned claim score {score} outside requested range"
    );
    // No DS state: the score IS the authored truth_value.
    assert!((score - claim.truth_value.value()).abs() < 1e-12);

    // And a high-range query still excludes it.
    let high = ClaimRepository::list_by_belief_range(&pool, &viewer, 0.9, 1.0, None, 20, 0)
        .await
        .unwrap();
    assert!(
        high.iter().all(|(_, s)| *s >= 0.9),
        "high-range query leaked a sub-0.9 claim"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_range_is_on_the_belief_score_not_the_stale_truth_value(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // Refuted by epistemic evidence: authored 0.78, BetP 0.18.
    let refuted = seed_claim(&pool, agent, 0.78, "2026-03-01T00:00:00Z").await;
    set_ds(&pool, refuted, 0.10, 0.25, 0.18).await;
    // Vindicated: authored 0.30, BetP 0.90.
    let vindicated = seed_claim(&pool, agent, 0.30, "2026-03-02T00:00:00Z").await;
    set_ds(&pool, vindicated, 0.85, 0.95, 0.90).await;
    // Half-written DS row (belief without plausibility): the guard falls back
    // to truth_value, exactly as `effective_belief_batch` does.
    let half = seed_claim(&pool, agent, 0.35, "2026-03-03T00:00:00Z").await;
    sqlx::query("UPDATE claims SET belief = 0.99, pignistic_prob = 0.99 WHERE id = $1")
        .bind(half)
        .execute(&pool)
        .await
        .unwrap();

    let low: Vec<(Uuid, f64)> =
        ClaimRepository::list_by_belief_range(&pool, &viewer, 0.0, 0.4, None, 20, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|(c, s)| (c.id.as_uuid(), s))
            .collect();
    let low_ids: Vec<Uuid> = low.iter().map(|(id, _)| *id).collect();
    assert!(
        low_ids.contains(&refuted),
        "the refuted claim (BetP 0.18, truth 0.78) is missing from max=0.4: {low:?}"
    );
    assert!(
        !low_ids.contains(&vindicated),
        "the vindicated claim (BetP 0.90, truth 0.30) leaked into max=0.4: {low:?}"
    );
    assert!(
        low_ids.contains(&half),
        "half-written DS row must fall back: {low:?}"
    );
    let refuted_score = low.iter().find(|(id, _)| *id == refuted).unwrap().1;
    assert!(
        (refuted_score - 0.18).abs() < 1e-12,
        "projected {refuted_score}"
    );

    // The SAME score `effective_belief_batch` (recall's min_truth gate) reads.
    let batch =
        ClaimRepository::effective_belief_batch(&pool, &viewer, &[refuted, vindicated, half])
            .await
            .unwrap();
    for (id, s) in &low {
        assert!(
            (batch[id] - s).abs() < 1e-12,
            "{id}: range {s} vs batch {}",
            batch[id]
        );
    }

    let high = ClaimRepository::list_by_belief_range(&pool, &viewer, 0.8, 1.0, None, 20, 0)
        .await
        .unwrap();
    assert!(high.iter().any(|(c, _)| c.id.as_uuid() == vindicated));
    assert!(!high.iter().any(|(c, _)| c.id.as_uuid() == refuted));
}

#[sqlx::test(migrations = "../../migrations")]
async fn paging_breaks_created_at_ties_by_id(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // Three claims sharing one created_at, INSERTED in descending id order so a
    // tie left to physical order comes back high-id first.
    let ts = "2026-04-01T00:00:00Z";
    let mut ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
    ids.sort();
    for id in ids.iter().rev() {
        seed_claim_with_id(&pool, *id, agent, 0.5, ts).await;
    }

    let mut paged = Vec::new();
    for offset in 0..3 {
        let page = ClaimRepository::list_by_belief_range(&pool, &viewer, 0.0, 1.0, None, 1, offset)
            .await
            .unwrap();
        assert_eq!(page.len(), 1, "offset {offset}");
        paged.push(page[0].0.id.as_uuid());
    }
    assert_eq!(
        paged, ids,
        "ties on created_at must page in id order, every row exactly once"
    );
}
