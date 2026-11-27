#![cfg(feature = "db")]
//! Content summaries must be cut on a CHARACTER boundary.
//!
//! `edges.rs::claim_provenance` shortened claim content with a byte slice,
//! `&claim_row.content[..57]`. (Two more call sites, `political.rs`'s
//! `position_timeline` and `inflation_index`, had the same defect and their
//! arms lived here; both handlers were deleted with the political module,
//! backlog bd13e0e0.)
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

/// The provenance label for `claim`, read from the one chain a claim with a
/// reasoning trace and no evidence edges produces: `[claim_step, trace_step]`.
fn provenance_claim_label(body: &Value) -> String {
    let chains = body["chains"]
        .as_array()
        .unwrap_or_else(|| panic!("`chains` is not an array: {body}"));
    assert_eq!(
        chains.len(),
        1,
        "a traced claim with no evidence edges has exactly one chain: {body}"
    );
    let step = &chains[0]["path"][0];
    assert_eq!(step["entity_type"], "claim", "path[0] is the claim: {body}");
    step["label"]
        .as_str()
        .unwrap_or_else(|| panic!("no string claim label: {body}"))
        .to_string()
}

/// `claim_provenance` labels the claim step "over 60 characters -> first 57 +
/// `...`". The label only reaches the response inside a chain, so every claim
/// here gets a reasoning trace (`seed_reasoning_trace` inserts it and sets
/// `claims.trace_id`); with no evidence edges the handler then returns one
/// chain `[claim_step, trace_step]`, and the label is asserted EXACTLY. That
/// pins the (60, 57) arguments at the edges.rs call site, not only the helper:
/// a (60, 60) or (57, 57) call, or no truncation at all, fails an arm below.
#[tokio::test(flavor = "multi_thread")]
async fn claim_provenance_labels_multibyte_content_by_character() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "provenance-multibyte").await;

    async fn traced_claim(pool: &sqlx::PgPool, agent: Uuid, content: &str) -> Uuid {
        let claim = fixture::seed_public_claim(pool, agent, content).await;
        fixture::seed_reasoning_trace(pool, claim, "deductive").await;
        claim
    }

    // Control: 100 ASCII characters -> 57 + "...", byte-identical to main.
    let ascii = traced_claim(&pool, agent, &"z".repeat(100)).await;
    let body = get_ok(addr, &format!("/api/v1/claims/{ascii}/provenance")).await;
    assert_eq!(body["claim_id"], ascii.to_string());
    assert_eq!(
        provenance_claim_label(&body),
        format!("{}...", "z".repeat(57)),
        "ASCII truncation must be unchanged"
    );

    // Defect arm: byte 57 is inside an `é`; main panicked here.
    let claim = traced_claim(&pool, agent, &content_cut_at_57_mid_char()).await;
    let body = get_ok(addr, &format!("/api/v1/claims/{claim}/provenance")).await;
    assert_eq!(body["claim_id"], claim.to_string());
    let label = provenance_claim_label(&body);
    assert_eq!(
        label,
        format!("{}...", "é".repeat(57)),
        "100 characters are cut to 57 characters plus an ellipsis"
    );
    assert_eq!(
        label.chars().count(),
        60,
        "the label never exceeds 60 chars"
    );

    // Threshold arm: 60 `é` is 120 bytes but only 60 characters, so it is NOT
    // over the limit and comes back whole (main byte-counted it as over and
    // panicked on the same mid-character slice).
    let at_limit = "é".repeat(60);
    let claim = traced_claim(&pool, agent, &at_limit).await;
    let body = get_ok(addr, &format!("/api/v1/claims/{claim}/provenance")).await;
    assert_eq!(
        provenance_claim_label(&body),
        at_limit,
        "60 characters is not over 60: returned whole"
    );
}
