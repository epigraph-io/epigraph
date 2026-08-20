//! HTTP integration test for `GET /api/v1/claims/by-labels` (Task 5 of the
//! backlog-retirement plan). Mirrors the MCP integration test in
//! `crates/epigraph-mcp/tests/query_claims_by_label.rs`: seeds three backlog
//! claims (open / resolved / superseded) and exercises the filter
//! cross-product through the public HTTP route.
#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn by_labels_returns_filtered_claims() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = seed_agent(&pool).await;
    let backlog_open = seed_claim(&pool, agent, &["backlog"], true, None).await;
    let _backlog_resolved = seed_claim(&pool, agent, &["backlog", "resolved"], true, None).await;
    let _backlog_superseded =
        seed_claim(&pool, agent, &["backlog"], false, Some(backlog_open)).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();

    // No filters: all 3 claims, with labels/is_current/supersedes populated.
    let resp = client
        .get(format!(
            "http://{addr}/api/v1/claims/by-labels?labels=backlog"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let arr = body.as_array().expect("response is JSON array");
    let ours: Vec<&Value> = arr
        .iter()
        .filter(|c| {
            let id = c["id"].as_str().unwrap();
            id == backlog_open.to_string()
                || id == _backlog_resolved.to_string()
                || id == _backlog_superseded.to_string()
        })
        .collect();
    assert_eq!(
        ours.len(),
        3,
        "expected our 3 seeded backlog claims (filtered): got body={body}"
    );

    let open = ours
        .iter()
        .find(|c| c["id"].as_str().unwrap() == backlog_open.to_string())
        .unwrap();
    assert_eq!(open["labels"], serde_json::json!(["backlog"]));
    assert_eq!(open["is_current"], Value::Bool(true));
    assert!(
        open.get("supersedes").map(|v| v.is_null()).unwrap_or(true),
        "open claim should not supersede anything: {open:?}"
    );

    let superseded = ours
        .iter()
        .find(|c| c["id"].as_str().unwrap() == _backlog_superseded.to_string())
        .unwrap();
    assert_eq!(superseded["is_current"], Value::Bool(false));
    assert_eq!(
        superseded["supersedes"].as_str().unwrap(),
        backlog_open.to_string(),
        "superseded.supersedes should point at backlog_open"
    );

    // exclude_labels=resolved + current_only=true → only the open backlog claim survives.
    let resp = client
        .get(format!(
            "http://{addr}/api/v1/claims/by-labels?labels=backlog&exclude_labels=resolved&current_only=true"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let arr = body.as_array().expect("response is JSON array");
    let ours: Vec<&Value> = arr
        .iter()
        .filter(|c| {
            let id = c["id"].as_str().unwrap();
            id == backlog_open.to_string()
                || id == _backlog_resolved.to_string()
                || id == _backlog_superseded.to_string()
        })
        .collect();
    assert_eq!(
        ours.len(),
        1,
        "exclude_labels=resolved + current_only=true must leave only backlog_open: got {ours:?}"
    );
    assert_eq!(ours[0]["id"].as_str().unwrap(), backlog_open.to_string());

    // Missing labels query parameter → 400.
    let resp = client
        .get(format!("http://{addr}/api/v1/claims/by-labels"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "missing labels query parameter must yield 400"
    );
}

/// The truncation contract (remediation R2). Before this, `GET
/// /api/v1/claims/by-labels` silently clamped `limit` to `MAX_PAGE_LIMIT`
/// (100) and returned a bare array, so a caller asking for 200 got exactly 100
/// rows with no way to tell that apart from "there were exactly 100 matches" —
/// which is how epiclaw-host's backlog router came to believe its
/// `ROUTER_QUERY_LIMIT = 200` was honoured.
///
/// Asserts the three properties a caller needs to detect truncation:
/// 1. `x-page-limit` reports the *effective* limit, so an over-max request is
///    self-diagnosing (ask 500, get told 100).
/// 2. `x-has-more` distinguishes a full page from an exhausted one, and
///    `x-next-offset` says where to resume.
/// 3. The body is never longer than the effective limit — the `limit + 1`
///    probe row must not leak, or `page_claims`-style "short page means done"
///    loops in the Python reconcilers would never terminate.
#[tokio::test(flavor = "multi_thread")]
async fn by_labels_signals_truncation_and_next_page_in_headers() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // Unique label so the counts below are exact regardless of what else is in
    // the shared test database.
    let label = format!("r2-cap-{}", Uuid::new_v4().simple());
    let agent = seed_agent(&pool).await;
    for _ in 0..5 {
        seed_claim(&pool, agent, &[&label], true, None).await;
    }

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();

    let page = |limit: i64, offset: i64| {
        let client = client.clone();
        let label = label.clone();
        async move {
            let resp = client
                .get(format!(
                    "http://{addr}/api/v1/claims/by-labels?labels={label}&limit={limit}&offset={offset}"
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 200);
            let header = |name: &str| {
                resp.headers()
                    .get(name)
                    .map(|v| v.to_str().unwrap().to_string())
            };
            let (page_limit, has_more, next_offset) = (
                header("x-page-limit"),
                header("x-has-more"),
                header("x-next-offset"),
            );
            let body: Value = resp.json().await.unwrap();
            let len = body.as_array().expect("response is JSON array").len();
            (len, page_limit, has_more, next_offset)
        }
    };

    // Mid-stream page: 2 of 5 → more to come, resume at offset 2.
    let (len, page_limit, has_more, next_offset) = page(2, 0).await;
    assert_eq!(
        len, 2,
        "limit=2 must return exactly 2 rows, not the probe row"
    );
    assert_eq!(page_limit.as_deref(), Some("2"));
    assert_eq!(has_more.as_deref(), Some("true"));
    assert_eq!(next_offset.as_deref(), Some("2"));

    // Exact-fit page: 4 rows consumed, 1 left → still more.
    let (len, _, has_more, next_offset) = page(2, 2).await;
    assert_eq!(len, 2);
    assert_eq!(
        has_more.as_deref(),
        Some("true"),
        "a FULL page with rows behind it must report has_more=true — this is the \
         'exactly N' vs 'at least N' distinction the bare array could not express"
    );
    assert_eq!(next_offset.as_deref(), Some("4"));

    // Final page: exhausted, no next offset.
    let (len, _, has_more, next_offset) = page(2, 4).await;
    assert_eq!(len, 1);
    assert_eq!(has_more.as_deref(), Some("false"));
    assert_eq!(
        next_offset, None,
        "x-next-offset must be absent once the result set is exhausted"
    );

    // Over-max request: the clamp is now discoverable instead of silent.
    let (len, page_limit, has_more, _) = page(500, 0).await;
    assert_eq!(
        page_limit.as_deref(),
        Some("100"),
        "limit=500 must report the effective clamped limit (MAX_PAGE_LIMIT=100)"
    );
    assert_eq!(len, 5, "all 5 seeded rows fit inside the clamped page");
    assert_eq!(has_more.as_deref(), Some("false"));
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    // Per-test-binary distinct prefix (DD) so we don't collide with other test
    // binaries' agent public_keys (graph_routes_test uses AA, themes BB,
    // neighborhoods CC, mcp query_claims_by_label uses BB-pattern via `bb`).
    let pk: Vec<u8> = std::iter::repeat_n(0xDD, 16)
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

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    labels: &[&str],
    is_current: bool,
    supersedes: Option<Uuid>,
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
                             labels, is_current, supersedes) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(format!("test claim {}", id))
    .bind(hash)
    .bind(agent_id)
    .bind(labels.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(is_current)
    .bind(supersedes)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
