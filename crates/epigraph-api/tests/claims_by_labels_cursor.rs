//! `GET /api/v1/claims/by-labels` keyset paging over real HTTP (backlog
//! 6f072833, ruling R-9): a full page carries an `X-Next-Cursor` header, the
//! body stays the legacy bare JSON array, and `after=<cursor>` resumes
//! strictly after the previous page's last row in `(created_at DESC, id DESC)`
//! order. The MCP twin is `crates/epigraph-mcp/tests/query_claims_by_label.rs`.
#![cfg(feature = "db")]

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

const NEXT_CURSOR: &str = "x-next-cursor";
/// Bound on pages a walk may take; a cursor that does not advance would
/// otherwise loop forever.
const MAX_PAGES: usize = 20;

#[tokio::test(flavor = "multi_thread")]
async fn by_labels_cursor_walk_visits_each_row_once_over_http() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let agent = seed_agent(&pool).await;
    // A label unique to this run: the database is shared across test binaries.
    let label = format!("cursor-walk-{}", Uuid::new_v4().simple());
    let t = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();
    let mut seeded: Vec<(DateTime<Utc>, Uuid)> = Vec::new();
    // Three rows tie on created_at, so a page of 2 splits the tie.
    for at in [t + Duration::seconds(1), t, t, t, t - Duration::seconds(1)] {
        seeded.push((at, seed_claim_at(&pool, agent, &label, at).await));
    }
    seeded.sort_by(|a, b| b.cmp(a));
    let expected: Vec<String> = seeded.iter().map(|(_, id)| id.to_string()).collect();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());

    let mut walked: Vec<String> = Vec::new();
    let mut after: Option<String> = None;
    let mut pages = 0;
    let mut page_lens: Vec<usize> = Vec::new();
    loop {
        pages += 1;
        assert!(pages <= MAX_PAGES, "cursor walk did not terminate");
        let mut req = format!("http://{addr}/api/v1/claims/by-labels?labels={label}&limit=2");
        if let Some(a) = &after {
            req.push_str(&format!("&after={a}"));
        }
        let resp = client.get(&req).bearer_auth(&token).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200, "{req}");
        let next = resp
            .headers()
            .get(NEXT_CURSOR)
            .map(|v| v.to_str().unwrap().to_string());
        let body: Value = resp.json().await.unwrap();
        let rows = body
            .as_array()
            .expect("the body stays the legacy bare JSON array");
        page_lens.push(rows.len());
        walked.extend(rows.iter().map(|r| r["id"].as_str().unwrap().to_string()));
        match next {
            Some(n) => after = Some(n),
            None => break,
        }
        if walked.len() > expected.len() {
            break;
        }
    }

    assert_eq!(
        walked, expected,
        "following X-Next-Cursor must visit every labelled row once, newest first, ties by id DESC"
    );
    assert_eq!(
        page_lens,
        vec![2, 2, 1],
        "two full pages carry a cursor; the walk ends on the short page, which carries none"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn by_labels_refuses_a_malformed_cursor_and_a_cursor_with_offset() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let agent = seed_agent(&pool).await;
    let label = format!("cursor-refuse-{}", Uuid::new_v4().simple());
    let t = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();
    for i in 0..3 {
        seed_claim_at(&pool, agent, &label, t + Duration::seconds(i)).await;
    }
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let base = format!("http://{addr}/api/v1/claims/by-labels?labels={label}&limit=2");

    let first = client.get(&base).bearer_auth(&token).send().await.unwrap();
    assert_eq!(first.status().as_u16(), 200);
    let cursor = first
        .headers()
        .get(NEXT_CURSOR)
        .expect("a full page carries X-Next-Cursor")
        .to_str()
        .unwrap()
        .to_string();

    for bad in [
        "garbage",
        "k1.1.not-a-uuid",
        "k9.0.00000000000000000000000000000000",
    ] {
        let resp = client
            .get(format!("{base}&after={bad}"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "a malformed cursor {bad:?} must be a 400, not a 500 or a silent first page"
        );
    }

    let both = client
        .get(format!("{base}&after={cursor}&offset=2"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        both.status().as_u16(),
        400,
        "`after` with a non-zero `offset` is ambiguous and must be refused"
    );

    // offset=0 is what existing clients always send; it composes with `after`.
    let ok = client
        .get(format!("{base}&after={cursor}&offset=0"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 200);
    assert!(
        ok.headers().get(NEXT_CURSOR).is_none(),
        "the short last page carries no cursor"
    );
    let body: Value = ok.json().await.unwrap();
    assert_eq!(body.as_array().map(Vec::len), Some(1), "one row remains");
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    // Distinct public_key prefix (EE) from the other by-labels test binary (DD).
    let pk: Vec<u8> = std::iter::repeat_n(0xEE, 16)
        .chain(id.as_bytes().iter().copied())
        .take(32)
        .collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
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
    .bind(format!("cursor claim {id}"))
    .bind(hash)
    .bind(agent_id)
    .bind(vec![label.to_string()])
    .bind(at)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
