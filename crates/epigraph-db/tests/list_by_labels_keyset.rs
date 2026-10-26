//! Keyset paging for [`ClaimRepository::list_by_labels`] (backlog 6f072833):
//! a [`LabelCursor`] taken from a page's last row resumes the walk strictly
//! after it in `(created_at DESC, id DESC)` order.
//!
//! The two properties offset paging cannot give, and that these tests pin:
//! - rows that share a `created_at` are each visited exactly once (the `id`
//!   tie-break makes the order total, so a boundary inside a tie is exact);
//! - a row inserted between two page reads does not shift the next page
//!   (offset paging re-serves the previous page's last row instead).

#[path = "viewer_fixture.rs"]
mod fixture;

use chrono::{DateTime, Duration, TimeZone, Utc};
use epigraph_db::repos::claim::LabelCursor;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// Upper bound on pages a walk may take; a cursor that does not advance
/// would otherwise loop forever.
const MAX_PAGES: usize = 20;

#[sqlx::test(migrations = "../../migrations")]
async fn keyset_walk_visits_each_row_once_across_created_at_ties(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let t = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();

    // Three rows share `t` exactly; one is newer, one older. A page size of 2
    // puts a page boundary inside the tie.
    let mut seeded: Vec<(DateTime<Utc>, Uuid)> = Vec::new();
    for at in [t + Duration::seconds(1), t, t, t, t - Duration::seconds(1)] {
        seeded.push((at, seed_claim_at(&pool, agent, "keyset-tie", at).await));
    }
    // A claim without the label must never appear.
    seed_claim_at(&pool, agent, "other-label", t).await;

    let mut expected = seeded.clone();
    expected.sort_by(|a, b| b.cmp(a)); // (created_at DESC, id DESC)
    let expected: Vec<Uuid> = expected.into_iter().map(|(_, id)| id).collect();

    let labels = ["keyset-tie".to_string()];
    let mut walked: Vec<Uuid> = Vec::new();
    let mut after: Option<LabelCursor> = None;
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages <= MAX_PAGES, "cursor walk did not terminate");
        let page = ClaimRepository::list_by_labels(
            &pool,
            &viewer,
            epigraph_db::LabelQuery {
                labels: &labels,
                limit: 2,
                after,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        walked.extend(page.iter().map(|(c, _)| c.id.as_uuid()));
        match LabelCursor::next_page(&page, 2) {
            Some(next) => after = Some(next),
            None => break,
        }
        if walked.len() > expected.len() {
            break;
        }
    }

    assert_eq!(
        walked, expected,
        "the cursor walk must visit every labelled row once, newest first, ties by id DESC"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn keyset_page_does_not_shift_when_a_newer_row_arrives(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let t = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();

    // Five rows a second apart; newest first is the reverse of insertion.
    let mut seeded: Vec<Uuid> = Vec::new();
    for i in 0..5 {
        seeded.push(seed_claim_at(&pool, agent, "keyset-drift", t + Duration::seconds(i)).await);
    }
    let expected_desc: Vec<Uuid> = seeded.into_iter().rev().collect();
    let labels = ["keyset-drift".to_string()];

    let page1 = ClaimRepository::list_by_labels(
        &pool,
        &viewer,
        epigraph_db::LabelQuery {
            labels: &labels,
            limit: 2,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let page1_ids: Vec<Uuid> = page1.iter().map(|(c, _)| c.id.as_uuid()).collect();
    assert_eq!(page1_ids, expected_desc[0..2]);
    let cursor = LabelCursor::next_page(&page1, 2).expect("a full page yields a cursor");

    // A writer lands a newer labelled claim between the two reads.
    seed_claim_at(&pool, agent, "keyset-drift", t + Duration::seconds(60)).await;

    let page2 = ClaimRepository::list_by_labels(
        &pool,
        &viewer,
        epigraph_db::LabelQuery {
            labels: &labels,
            limit: 2,
            after: Some(cursor),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let page2_ids: Vec<Uuid> = page2.iter().map(|(c, _)| c.id.as_uuid()).collect();
    assert_eq!(
        page2_ids,
        expected_desc[2..4],
        "page 2 must resume after page 1's last row, unaffected by the newer insert"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_short_page_ends_the_walk_with_no_cursor(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let t = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();
    for i in 0..3 {
        seed_claim_at(&pool, agent, "keyset-short", t + Duration::seconds(i)).await;
    }
    let labels = ["keyset-short".to_string()];
    let full = ClaimRepository::list_by_labels(
        &pool,
        &viewer,
        epigraph_db::LabelQuery {
            labels: &labels,
            limit: 2,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let cursor = LabelCursor::next_page(&full, 2).expect("full page");
    assert_eq!(
        cursor.id,
        full[1].0.id.as_uuid(),
        "cursor names the last row"
    );
    let short = ClaimRepository::list_by_labels(
        &pool,
        &viewer,
        epigraph_db::LabelQuery {
            labels: &labels,
            limit: 2,
            after: Some(cursor),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(short.len(), 1, "one row remains after the first two");
    assert_eq!(LabelCursor::next_page(&short, 2), None);
}

#[test]
fn label_cursor_token_survives_encode_and_refuses_anything_else() {
    let c = LabelCursor {
        // Microsecond precision, as timestamptz stores it.
        created_at: DateTime::from_timestamp_micros(1_790_000_000_123_456).unwrap(),
        id: Uuid::parse_str("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0").unwrap(),
    };
    let token = c.encode();
    assert!(token.starts_with("k1."), "versioned prefix: {token}");
    assert!(
        token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-'),
        "token must be URL-safe without escaping: {token}"
    );
    assert_eq!(LabelCursor::decode(&token), Some(c));

    for bad in [
        "",
        "k1.",
        "k1.123",
        "k2.1790000000123456.0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "1790000000123456.0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "k1.notanumber.0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "k1.1790000000123456.not-a-uuid",
        "k1.99999999999999999999.0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        // Inside chrono's range but before Postgres timestamptz's earliest
        // value (4714-11-24 BC): would decode, then fail at bind time.
        "k1.-230000000000000000.0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "k1.-210866803200000001.0f1e2d3c4b5a69788796a5b4c3d2e1f0",
    ] {
        assert_eq!(LabelCursor::decode(bad), None, "must refuse {bad:?}");
    }
}

/// Postgres timestamptz's earliest value, 4714-11-24 00:00 BC UTC, in Unix
/// microseconds. Written out here, not imported, so the test checks the
/// decoder's bound against the database rather than against itself.
const PG_MIN_MICROS: i64 = -210_866_803_200_000_000;

#[sqlx::test(migrations = "../../migrations")]
async fn every_decodable_cursor_binds_and_the_bound_is_postgres_own(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let id = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

    // The database itself: the bound is accepted, one microsecond earlier is not.
    let at_min = DateTime::from_timestamp_micros(PG_MIN_MICROS).unwrap();
    let below = DateTime::from_timestamp_micros(PG_MIN_MICROS - 1).unwrap();
    sqlx::query("SELECT $1::timestamptz")
        .bind(at_min)
        .execute(&pool)
        .await
        .expect("Postgres accepts its earliest timestamptz");
    assert!(
        sqlx::query("SELECT $1::timestamptz")
            .bind(below)
            .execute(&pool)
            .await
            .is_err(),
        "one microsecond before the bound must be out of Postgres's range"
    );

    // The decoder: exactly the same edge.
    assert!(LabelCursor::decode(&format!("k1.{}.{id}", PG_MIN_MICROS - 1)).is_none());
    // Both ends of what decode accepts reach list_by_labels without a bind
    // error: Postgres's earliest value and chrono's latest (which Postgres's
    // upper bound, 294276 AD, already covers).
    let max_micros = DateTime::<Utc>::MAX_UTC.timestamp_micros();
    for micros in [PG_MIN_MICROS, max_micros] {
        let token = format!("k1.{micros}.{id}");
        let after = LabelCursor::decode(&token).unwrap_or_else(|| panic!("{token} decodes"));
        ClaimRepository::list_by_labels(
            &pool,
            &viewer,
            epigraph_db::LabelQuery {
                labels: &["keyset-bound".to_string()],
                after: Some(after),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("a decodable cursor {token} must bind: {e}"));
    }
}

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

async fn seed_claim_at(pool: &PgPool, agent_id: Uuid, label: &str, at: DateTime<Utc>) -> Uuid {
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
                             labels, is_current, created_at, updated_at) \
         VALUES ($1, $2, $3, 0.5, $4, $5, true, $6, $6)",
    )
    .bind(id)
    .bind(format!("keyset claim {id}"))
    .bind(hash)
    .bind(agent_id)
    .bind(vec![label.to_string()])
    .bind(at)
    .execute(pool)
    .await
    .unwrap();
    id
}
