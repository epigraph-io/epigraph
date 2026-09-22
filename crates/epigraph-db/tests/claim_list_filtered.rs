//! Behaviour pins for [`ClaimRepository::list_filtered`] /
//! [`ClaimRepository::count_filtered`], the SQL push-down pair that replaced
//! `GET /api/v1/claims`'s fetch-10k-then-filter-in-Rust pipeline (backlog
//! `2265a67b`, and the push-down residual of `f1992766`).
//!
//! These are new-surface guards, not before/after regressions: the two methods
//! did not exist at the branch point, so nothing here could have failed
//! against it. The end-to-end regression — a filtered query whose only match
//! lies outside the old 10,000-row window — lives in
//! `epigraph-api/tests/claims_query_pushdown_test.rs`, which drives the real
//! HTTP handler.
//!
//! What IS load-bearing here:
//!
//! * `count_filtered` and `list_filtered` must agree. They are two SQL
//!   statements, and a `total` computed from a different predicate set than
//!   the rows it describes is exactly the defect being fixed. The shared
//!   `FILTER_WHERE` / `bind_filter` pair is what prevents drift; this asserts
//!   the property that construction is supposed to deliver.
//! * `ids: Some(&[])` must select nothing. `None` and `Some(empty)` differ,
//!   and getting it backwards silently inverts a filter into "return
//!   everything" — the loudest possible failure, in the quietest possible way.
//! * Predicates must run before `LIMIT`, the property that makes an old
//!   matching row reachable at all.

mod viewer_fixture;

use chrono::{DateTime, TimeZone, Utc};
use epigraph_db::{ClaimListFilter, ClaimRepository, ClaimSortField, ClaimSortOrder};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn predicates_run_before_limit(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let needle_agent = seed_agent(&pool, "a1").await;
    let noise_agent = seed_agent(&pool, "a2").await;

    // The only row authored by `needle_agent` is the OLDEST in the table.
    let needle = seed_claim(&pool, needle_agent, "needle", 0.4, true, ts(2000, 1, 1)).await;
    for i in 0..30 {
        seed_claim(
            &pool,
            noise_agent,
            &format!("noise {i}"),
            0.9,
            true,
            ts(2026, 1, 1) + chrono::Duration::seconds(i),
        )
        .await;
    }

    // A limit far smaller than the noise population: a fetch-then-filter
    // implementation would only ever inspect the newest 3 rows and return
    // nothing.
    let filter = ClaimListFilter {
        agent_id: Some(needle_agent),
        ..Default::default()
    };
    let rows = ClaimRepository::list_filtered(&pool, &viewer, &filter, 3, 0)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the agent filter must run in SQL before LIMIT so the oldest matching \
         row is still reachable"
    );
    assert_eq!(rows[0].id.as_uuid(), needle);

    // And `total` is a count over the whole table, not over the page.
    assert_eq!(
        ClaimRepository::count_filtered(&pool, &viewer, &filter)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        ClaimRepository::count_filtered(&pool, &viewer, &ClaimListFilter::default())
            .await
            .unwrap(),
        31,
        "an empty filter counts every row"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn count_and_list_agree_across_every_predicate(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let kept = seed_agent(&pool, "b1").await;
    let excluded = seed_agent(&pool, "b2").await;

    // Rows spanning both agents, both retirement states, a truth spread and a
    // date spread, so every predicate below actually discriminates.
    let mut all_marker_ids: Vec<Uuid> = Vec::new();
    let mut matches_other_predicates: Vec<Uuid> = Vec::new();
    for i in 0..12i64 {
        let agent = if i % 3 == 0 { excluded } else { kept };
        let is_current = i % 2 == 0;
        let truth = 0.1 + (i as f64) * 0.07;
        let created = ts(2026, 1, 1) + chrono::Duration::days(i);
        let id = seed_claim(
            &pool,
            agent,
            &format!("agreement MARKER {i}"),
            truth,
            is_current,
            created,
        )
        .await;
        all_marker_ids.push(id);
        if agent == kept
            && is_current
            && (0.2..=0.7).contains(&truth)
            && created >= ts(2026, 1, 2)
            && created <= ts(2026, 1, 11)
        {
            matches_other_predicates.push(id);
        }
    }
    // A row that matches every predicate except the content search.
    seed_claim(&pool, kept, "different text", 0.5, true, ts(2026, 1, 5)).await;

    // Make the id predicate discriminating rather than a restatement of the
    // expectation: allow every seeded row EXCEPT one that all the other
    // predicates accept. If `ids` were silently ignored, `dropped` would come
    // back and the assertion below fails.
    let dropped = *matches_other_predicates
        .first()
        .expect("fixture must produce at least one otherwise-matching row");
    let ids: Vec<Uuid> = all_marker_ids
        .iter()
        .copied()
        .filter(|id| *id != dropped)
        .collect();
    let expected: Vec<Uuid> = matches_other_predicates
        .iter()
        .copied()
        .filter(|id| *id != dropped)
        .collect();

    let filter = ClaimListFilter {
        search: Some("MARKER"),
        truth_min: Some(0.2),
        truth_max: Some(0.7),
        agent_id: Some(kept),
        exclude_agent_id: Some(excluded),
        is_current: Some(true),
        created_after: Some(ts(2026, 1, 2)),
        created_before: Some(ts(2026, 1, 11)),
        ids: Some(&ids),
        sort_by: ClaimSortField::TruthValue,
        sort_order: ClaimSortOrder::Asc,
    };

    let count = ClaimRepository::count_filtered(&pool, &viewer, &filter)
        .await
        .unwrap();
    let rows = ClaimRepository::list_filtered(&pool, &viewer, &filter, 1000, 0)
        .await
        .unwrap();
    assert_eq!(
        count as usize,
        rows.len(),
        "count_filtered and list_filtered must apply the identical WHERE clause"
    );
    assert!(
        !rows.is_empty(),
        "the fixture must leave matching rows or the agreement is vacuous"
    );
    let mut got: Vec<Uuid> = rows.iter().map(|c| c.id.as_uuid()).collect();
    let mut want = expected.clone();
    got.sort();
    want.sort();
    assert_eq!(
        got, want,
        "the SQL predicates must select exactly the rows the fixture predicts"
    );
    assert!(
        !got.contains(&dropped),
        "the `ids` predicate must be applied: {dropped} satisfies every other \
         filter and is excluded only by the id set"
    );

    // Sort key and direction are honoured (ascending truth_value here).
    let truths: Vec<f64> = rows.iter().map(|c| c.truth_value.value()).collect();
    let mut sorted = truths.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    assert_eq!(truths, sorted, "sort_by/sort_order must be applied in SQL");

    // Retirement state is projected, not fabricated.
    assert!(rows.iter().all(|c| c.is_current));
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_id_set_selects_nothing(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool, "c1").await;
    for i in 0..5 {
        seed_claim(&pool, agent, &format!("row {i}"), 0.5, true, ts(2026, 2, 1)).await;
    }

    let empty: [Uuid; 0] = [];
    let filter = ClaimListFilter {
        ids: Some(&empty),
        ..Default::default()
    };
    assert_eq!(
        ClaimRepository::count_filtered(&pool, &viewer, &filter)
            .await
            .unwrap(),
        0,
        "Some(&[]) means 'no claim matches'; treating it as 'no filter' would \
         return all 5 rows"
    );
    assert!(
        ClaimRepository::list_filtered(&pool, &viewer, &filter, 100, 0)
            .await
            .unwrap()
            .is_empty()
    );

    // …and `None` in the same slot really is "no filter".
    let unfiltered = ClaimListFilter::default();
    assert_eq!(
        ClaimRepository::count_filtered(&pool, &viewer, &unfiltered)
            .await
            .unwrap(),
        5
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn is_current_partitions_the_table(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool, "d1").await;
    let live = seed_claim(&pool, agent, "live", 0.5, true, ts(2026, 3, 1)).await;
    let dead = seed_claim(&pool, agent, "dead", 0.5, false, ts(2026, 3, 2)).await;
    // Give the superseded row a real pointer so `supersedes` projection is
    // checked against something other than NULL.
    sqlx::query("UPDATE claims SET supersedes = $1 WHERE id = $2")
        .bind(live)
        .bind(dead)
        .execute(&pool)
        .await
        .unwrap();

    let current_only = ClaimListFilter {
        is_current: Some(true),
        ..Default::default()
    };
    let rows = ClaimRepository::list_filtered(&pool, &viewer, &current_only, 100, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id.as_uuid(), live);

    let superseded_only = ClaimListFilter {
        is_current: Some(false),
        ..Default::default()
    };
    let rows = ClaimRepository::list_filtered(&pool, &viewer, &superseded_only, 100, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id.as_uuid(), dead);
    assert!(
        !rows[0].is_current,
        "is_current must be projected, not defaulted"
    );
    assert_eq!(
        rows[0].supersedes.map(|s| s.as_uuid()),
        Some(live),
        "supersedes must be projected, not defaulted to None"
    );

    // None returns both halves — the two filters partition the table.
    assert_eq!(
        ClaimRepository::count_filtered(&pool, &viewer, &ClaimListFilter::default())
            .await
            .unwrap(),
        2
    );
}

fn ts(y: i32, m: u32, d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
}

async fn seed_agent(pool: &PgPool, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind(tag.repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    content: &str,
    truth: f64,
    is_current: bool,
    created_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(truth)
    .bind(agent_id)
    .bind(is_current)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
