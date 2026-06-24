//! Regression test for backlog bug `5a55a48e`:
//! `query_claims(min_truth=0, max_truth=0.75)` returned an empty list even
//! though matching claims existed. Root cause: the MCP handler fetched the
//! first `limit` rows (ordered `created_at DESC`) via `ClaimRepository::list`
//! and applied the truth-value filter *in Rust, after* the `LIMIT`. A matching
//! claim outside the most-recent `limit` rows was therefore invisible.
//!
//! `list_by_truth_range` filters in SQL *before* `LIMIT`, so a low-truth claim
//! buried under many newer high-truth claims is still returned. This test pins
//! exactly that scenario: it would fail under the old fetch-then-filter path.

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

/// Insert a claim with an explicit `truth_value` and `created_at`.
async fn seed_claim(pool: &PgPool, agent_id: Uuid, truth: f64, created_at: &str) {
    let id = Uuid::new_v4();
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

#[sqlx::test(migrations = "../../migrations")]
async fn truth_range_filter_finds_matches_outside_recent_window(pool: PgPool) {
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

    let results = ClaimRepository::list_by_truth_range(&pool, 0.0, 0.75, 20, 0)
        .await
        .unwrap();

    // The low-truth claim must be returned despite being outside the 20 newest.
    assert_eq!(
        results.len(),
        1,
        "expected exactly the one claim in [0,0.75], got {}",
        results.len()
    );
    let tv = results[0].truth_value.value();
    assert!(
        (0.0..=0.75).contains(&tv),
        "returned claim truth {tv} outside requested range"
    );

    // And a high-truth query still excludes it.
    let high = ClaimRepository::list_by_truth_range(&pool, 0.9, 1.0, 20, 0)
        .await
        .unwrap();
    assert!(
        high.iter().all(|c| c.truth_value.value() >= 0.9),
        "high-range query leaked a sub-0.9 claim"
    );
}
