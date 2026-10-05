#![cfg(feature = "db")]
//! Content summaries must be cut on a CHARACTER boundary.
//!
//! Three handlers shortened claim content with a byte slice:
//!
//! * `political.rs::position_timeline` — `&c.content[..120]`
//! * `political.rs::inflation_index` — `&content[..120]`
//! * `edges.rs::claim_provenance` — `&claim_row.content[..57]`
//!
//! `&s[..n]` panics when byte `n` falls inside a multibyte UTF-8 character, so
//! any claim whose content puts a non-ASCII character across that byte took
//! the handler task down: the caller saw a 500 or a dropped connection instead
//! of the endpoint's answer. Claim content is free text from many sources, so
//! this is ordinary input, not an exotic one.
//!
//! # Why HTTP and not only a unit test of the helper
//!
//! The defect is in the handlers' call sites. A unit test of a truncation
//! helper cannot fail on main (the helper does not exist there) and cannot
//! detect a call site that still slices by byte. These arms drive the real
//! routes through `spawn_app` instead.
//!
//! # The control arm in each test
//!
//! Each test first requests the SAME route for an ASCII claim long enough to be
//! truncated and asserts 200 with a `...` summary. That proves the token, the
//! scope gate and the route are all fine, so a failure on the multibyte arm is
//! the slice and nothing else.
//!
//! These use the ambient `DATABASE_URL`, like `pr07_acceptance_http.rs`:
//! `spawn_app` builds its own pool from a URL, and every request is keyed on a
//! freshly minted agent or claim id, so a shared database cannot make an arm
//! pass or fail spuriously.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// 1 ASCII byte then 200 two-byte `é`: every `é` starts on an ODD byte, so the
/// even byte 120 is the second byte of a character.
fn content_cut_at_120_mid_char() -> String {
    let s = format!("a{}", "é".repeat(200));
    assert!(
        !s.is_char_boundary(120),
        "fixture must put byte 120 inside a character, or it tests nothing"
    );
    s
}

/// 100 two-byte `é`: characters start on EVEN bytes, so the odd byte 57 is
/// the second byte of a character.
fn content_cut_at_57_mid_char() -> String {
    let s = "é".repeat(100);
    assert!(
        !s.is_char_boundary(57),
        "fixture must put byte 57 inside a character, or it tests nothing"
    );
    s
}

async fn pool_and_app() -> (
    sqlx::PgPool,
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool");
    let (addr, shutdown) = common::spawn_app(&url).await;
    (pool, addr, shutdown)
}

/// GET `path` as a stranger with read scopes and return the JSON body,
/// failing with the status (or the transport error a panicking handler
/// produces) otherwise.
async fn get_ok(addr: std::net::SocketAddr, path: &str) -> Value {
    let token = common::mint_token_with_agent(
        &["claims:read", "agents:read", "graph:read", "edges:read"],
        Uuid::new_v4(),
    );
    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("client")
        .get(format!("http://{addr}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {path} produced no response (handler panic?): {e}"));
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "GET {path} must answer 200; got {status}: {body}"
    );
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("GET {path}: {e}: {body}"))
}

/// The one `content_summary` an agent-scoped endpoint returned under `key`.
fn only_summary(body: &Value, key: &str) -> String {
    let rows = body[key]
        .as_array()
        .unwrap_or_else(|| panic!("`{key}` is not an array: {body}"));
    assert_eq!(rows.len(), 1, "one seeded claim, one `{key}` entry: {body}");
    rows[0]["content_summary"]
        .as_str()
        .unwrap_or_else(|| panic!("no string content_summary: {body}"))
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn position_timeline_summarises_multibyte_content_without_panicking() {
    let (pool, addr, _shutdown) = pool_and_app().await;

    // Control: ASCII over 120 characters is truncated to 120 + "...".
    let (ascii_agent, _) = fixture::seed_agent_with_group(&pool, "timeline-ascii").await;
    fixture::seed_public_claim(&pool, ascii_agent, &"x".repeat(130)).await;
    let body = get_ok(
        addr,
        &format!("/api/v1/agents/{ascii_agent}/position-timeline"),
    )
    .await;
    assert_eq!(
        only_summary(&body, "timeline"),
        format!("{}...", "x".repeat(120)),
        "ASCII truncation must be unchanged"
    );

    // Defect arm.
    let content = content_cut_at_120_mid_char();
    let (agent, _) = fixture::seed_agent_with_group(&pool, "timeline-multibyte").await;
    fixture::seed_public_claim(&pool, agent, &content).await;
    let body = get_ok(addr, &format!("/api/v1/agents/{agent}/position-timeline")).await;
    let summary = only_summary(&body, "timeline");
    let expected: String = content.chars().take(120).collect::<String>() + "...";
    assert_eq!(
        summary, expected,
        "a 201-character summary is cut to 120 characters plus an ellipsis"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn inflation_index_summarises_multibyte_content_without_panicking() {
    let (pool, addr, _shutdown) = pool_and_app().await;

    async fn seed_inflation_claim(pool: &sqlx::PgPool, label: &str, content: &str) -> Uuid {
        let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
        let claim = fixture::seed_public_claim(pool, agent, content).await;
        // `get_agent_inflation_claims` selects only claims carrying an
        // `inflation_factor`; without it the list is empty and the summary
        // code never runs.
        sqlx::query(
            "UPDATE claims SET properties = \
             COALESCE(properties, '{}'::jsonb) || '{\"inflation_factor\": 2.0}'::jsonb \
             WHERE id = $1",
        )
        .bind(claim)
        .execute(pool)
        .await
        .expect("mark the claim as an inflation claim");
        agent
    }

    // Control.
    let ascii_agent = seed_inflation_claim(&pool, "inflation-ascii", &"y".repeat(130)).await;
    let body = get_ok(
        addr,
        &format!("/api/v1/agents/{ascii_agent}/inflation-index"),
    )
    .await;
    assert_eq!(
        only_summary(&body, "sample_claims"),
        format!("{}...", "y".repeat(120)),
        "ASCII truncation must be unchanged"
    );

    // Defect arm.
    let content = content_cut_at_120_mid_char();
    let agent = seed_inflation_claim(&pool, "inflation-multibyte", &content).await;
    let body = get_ok(addr, &format!("/api/v1/agents/{agent}/inflation-index")).await;
    let expected: String = content.chars().take(120).collect::<String>() + "...";
    assert_eq!(only_summary(&body, "sample_claims"), expected);
}

/// `claim_provenance` builds its claim label before it looks at any trace, so a
/// claim with no reasoning trace reaches the slice and the response has no
/// chains to carry the label. The assertion is therefore that the route
/// ANSWERS; the 60/57 rule itself is pinned by the helper's unit tests.
#[tokio::test(flavor = "multi_thread")]
async fn claim_provenance_answers_for_multibyte_content() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "provenance-multibyte").await;

    // Control: long ASCII content answers.
    let ascii = fixture::seed_public_claim(&pool, agent, &"z".repeat(100)).await;
    let body = get_ok(addr, &format!("/api/v1/claims/{ascii}/provenance")).await;
    assert_eq!(body["claim_id"], ascii.to_string());

    // Defect arm.
    let claim = fixture::seed_public_claim(&pool, agent, &content_cut_at_57_mid_char()).await;
    let body = get_ok(addr, &format!("/api/v1/claims/{claim}/provenance")).await;
    assert_eq!(body["claim_id"], claim.to_string());
}
