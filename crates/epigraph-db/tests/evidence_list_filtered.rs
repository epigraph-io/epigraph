//! Behaviour pins for [`EvidenceRepository::list_filtered`] /
//! [`EvidenceRepository::count_filtered`], the SQL push-down pair backing the
//! new `GET /api/v1/evidence` read route (backlog `d7aab418`).
//!
//! These are **new-surface guards, not before/after regressions**: neither
//! method existed at the branch point, so nothing in this file could have
//! failed against it. The load-bearing before/after test — `GET
//! /api/v1/evidence` answering 200 instead of axum's 405, with an exact
//! `total` — lives in `epigraph-api/tests/evidence_list_route_test.rs`, which
//! drives the real HTTP handler.
//!
//! What IS load-bearing here:
//!
//! * `count_filtered` and `list_filtered` must agree. They are two SQL
//!   statements, and a `total` computed from a different predicate set than the
//!   rows it describes is the exact defect the route exists to avoid. The
//!   shared `FILTER_WHERE` / `bind_filter` pair is what prevents drift; this
//!   asserts the property that construction is supposed to deliver.
//! * Predicates must run before `LIMIT`, the property that makes an OLD
//!   evidence row reachable in a 123k-row table at all. A fetch-then-filter
//!   implementation returns nothing here.
//! * `content_contains` must not silently match rows with a NULL
//!   `raw_content`. `NULL ILIKE '%x%'` is NULL, not true — the documented
//!   behaviour, pinned so a later rewrite using `COALESCE(raw_content,'')`
//!   cannot change the count without failing a test.
//! * Paging must be stable when every row shares a `created_at`. Bulk
//!   ingestion writes many evidence rows in one transaction with an identical
//!   timestamp; without the `id` tiebreaker, page 2 both duplicates and skips
//!   rows from page 1.

use chrono::{DateTime, TimeZone, Utc};
mod viewer_fixture;

use epigraph_db::{EvidenceListFilter, EvidenceRepository};
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn predicates_run_before_limit(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let needle_claim = seed_claim(&pool, agent).await;
    let noise_claim = seed_claim(&pool, agent).await;

    // The only evidence row on `needle_claim` is the OLDEST in the table.
    let needle = seed_evidence(
        &pool,
        needle_claim,
        "observation",
        Some("needle transcript"),
        ts(2000, 1, 1),
    )
    .await;
    for i in 0..30 {
        seed_evidence(
            &pool,
            noise_claim,
            "document",
            Some(&format!("noise {i}")),
            ts(2026, 1, 1) + chrono::Duration::seconds(i),
        )
        .await;
    }

    // A limit far smaller than the noise population: a fetch-then-filter
    // implementation would only ever inspect the newest 3 rows and return
    // nothing.
    let filter = EvidenceListFilter {
        claim_id: Some(needle_claim),
        ..Default::default()
    };
    let rows = EvidenceRepository::list_filtered(&pool, &viewer, &filter, 3, 0)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the oldest matching row must be reachable under a small LIMIT"
    );
    assert_eq!(rows[0].id, needle);
    assert_eq!(
        EvidenceRepository::count_filtered(&pool, &viewer, &filter)
            .await
            .unwrap(),
        1,
        "count must describe the predicate, not the page"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn count_and_list_agree_across_every_filter_combination(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let claim_a = seed_claim(&pool, agent).await;
    let claim_b = seed_claim(&pool, agent).await;

    // 4 rows on claim_a: two observations (one matching "SECRET"), two
    // documents. 2 rows on claim_b, one an observation matching "SECRET".
    seed_evidence(
        &pool,
        claim_a,
        "observation",
        Some("holds a SECRET name"),
        ts(2026, 1, 1),
    )
    .await;
    seed_evidence(&pool, claim_a, "observation", Some("plain"), ts(2026, 1, 2)).await;
    seed_evidence(
        &pool,
        claim_a,
        "document",
        Some("a SECRET doc"),
        ts(2026, 1, 3),
    )
    .await;
    seed_evidence(
        &pool,
        claim_a,
        "document",
        Some("plain doc"),
        ts(2026, 1, 4),
    )
    .await;
    seed_evidence(
        &pool,
        claim_b,
        "observation",
        Some("another SECRET"),
        ts(2026, 1, 5),
    )
    .await;
    seed_evidence(
        &pool,
        claim_b,
        "reference",
        Some("plain ref"),
        ts(2026, 1, 6),
    )
    .await;

    let cases: Vec<(&str, EvidenceListFilter, i64)> = vec![
        ("no filter", EvidenceListFilter::default(), 6),
        (
            "claim_id only",
            EvidenceListFilter {
                claim_id: Some(claim_a),
                ..Default::default()
            },
            4,
        ),
        (
            "evidence_type only",
            EvidenceListFilter {
                evidence_type: Some("observation"),
                ..Default::default()
            },
            3,
        ),
        (
            "content_contains only (case-insensitive)",
            EvidenceListFilter {
                content_contains: Some("secret"),
                ..Default::default()
            },
            3,
        ),
        (
            "all three compose (AND, not OR)",
            EvidenceListFilter {
                claim_id: Some(claim_a),
                evidence_type: Some("observation"),
                content_contains: Some("SECRET"),
            },
            1,
        ),
        (
            "unsatisfiable combination",
            EvidenceListFilter {
                claim_id: Some(claim_b),
                evidence_type: Some("document"),
                content_contains: None,
            },
            0,
        ),
    ];

    for (label, filter, expected) in cases {
        let count = EvidenceRepository::count_filtered(&pool, &viewer, &filter)
            .await
            .unwrap();
        // A limit comfortably above the fixture so the page IS the full set —
        // which is what makes `rows.len() == count` a real cross-check of the
        // two statements rather than a restatement of the limit.
        let rows = EvidenceRepository::list_filtered(&pool, &viewer, &filter, 100, 0)
            .await
            .unwrap();
        assert_eq!(count, expected, "{label}: unexpected COUNT(*)");
        assert_eq!(
            rows.len() as i64,
            count,
            "{label}: list_filtered returned {} rows but count_filtered said {count} — \
             the two statements have drifted apart",
            rows.len()
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn content_contains_excludes_null_raw_content(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, agent).await;

    seed_evidence(&pool, claim, "document", None, ts(2026, 2, 1)).await;
    let with_text = seed_evidence(&pool, claim, "document", Some("has text"), ts(2026, 2, 2)).await;

    // The unfiltered population is 2 …
    assert_eq!(
        EvidenceRepository::count_filtered(&pool, &viewer, &EvidenceListFilter::default())
            .await
            .unwrap(),
        2
    );

    // … but a `content_contains` predicate that is satisfied by neither row's
    // text still drops the NULL row rather than keeping it. `NULL ILIKE
    // '%zzz%'` is NULL, which is not true.
    let filter = EvidenceListFilter {
        content_contains: Some("zzz"),
        ..Default::default()
    };
    assert_eq!(
        EvidenceRepository::count_filtered(&pool, &viewer, &filter)
            .await
            .unwrap(),
        0,
        "a NULL raw_content must not satisfy a substring predicate"
    );

    // And a matching predicate selects exactly the row that has text.
    let filter = EvidenceListFilter {
        content_contains: Some("has"),
        ..Default::default()
    };
    let rows = EvidenceRepository::list_filtered(&pool, &viewer, &filter, 10, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, with_text);
}

#[sqlx::test(migrations = "../../migrations")]
async fn paging_is_stable_when_every_row_shares_a_timestamp(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, agent).await;

    // The bulk-ingestion shape: 10 evidence rows written with one identical
    // created_at. `ORDER BY created_at DESC` alone leaves the row order
    // unspecified, so pages may overlap and omit.
    let stamp = ts(2026, 3, 3);
    for i in 0..10 {
        seed_evidence(&pool, claim, "document", Some(&format!("row {i}")), stamp).await;
    }

    let filter = EvidenceListFilter::default();
    let mut seen: HashSet<Uuid> = HashSet::new();
    for page in 0..5 {
        let rows = EvidenceRepository::list_filtered(&pool, &viewer, &filter, 2, page * 2)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "page {page} should be full");
        for row in rows {
            assert!(
                seen.insert(row.id),
                "evidence {} appeared on two pages — paging is unstable",
                row.id
            );
        }
    }
    assert_eq!(
        seen.len(),
        10,
        "five pages of 2 must enumerate all 10 rows exactly once"
    );
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn ts(y: i32, m: u32, d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, $3, 0.5, $4)",
    )
    .bind(id)
    .bind(format!("claim {id}"))
    .bind(hash)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// `evidence_type` uses the stored vocabulary pinned by the
/// `evidence_type_valid` CHECK constraint (`document`, `observation`,
/// `testimony`, `computation`, `reference`, `figure`, `conversational`) — NOT
/// the Rust `EvidenceType` variant names.
async fn seed_evidence(
    pool: &PgPool,
    claim_id: Uuid,
    evidence_type: &str,
    raw_content: Option<&str>,
    created_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO evidence (id, content_hash, evidence_type, raw_content, claim_id, \
                               properties, created_at) \
         VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, $6)",
    )
    .bind(id)
    .bind(hash)
    .bind(evidence_type)
    .bind(raw_content)
    .bind(claim_id)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed evidence");
    id
}
