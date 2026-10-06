//! The agent-activity page (J5) against a wiremock upstream.
//!
//! What it must do: for each agent in the configured watch list, show its
//! newest claims since a time (`GET /api/v1/claims?agent_id=&created_after=
//! &sort_by=created_at&sort_order=desc&limit=`), marking a list the API
//! counted more rows for than it returned; keep one agent's failure in that
//! agent's section; explain an empty watch list without calling upstream;
//! and fan the per-agent calls out no wider than the per-viewer cap, so a
//! long watch list does not spend its calls' deadlines queueing.
//!
//! The mocks are shaped like the kernel's answer: `ClaimListResponse`
//! (`claims`, a real COUNT in `total`, the applied `limit` and `offset`),
//! with `limit` clamped to 100 upstream. Every claims mock matches the
//! bearer and the full query, so a page that drops `created_after` or the
//! sort asks for something the mock does not answer. An unmatched request
//! gets wiremock's 404, which the page renders as an "unavailable" section
//! with a 200; so every test asserts the rows it expects, never only the
//! status.

mod common;

use axum::http::StatusCode;
use axum::Router;
use common::{spawn, spawn_with, TestApp, BASE};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockBuilder, ResponseTemplate};

/// The watch-list knob (literal, so this file compiles before the config
/// constant exists).
const ENV_WATCH: &str = "EPIGRAPH_EXPLORER_WATCH_AGENTS";
const ENV_SESSION_CONCURRENCY: &str = "EPIGRAPH_EXPLORER_SESSION_CONCURRENCY";
const ENV_UPSTREAM_CONCURRENCY: &str = "EPIGRAPH_EXPLORER_UPSTREAM_CONCURRENCY";
const ENV_TIMEOUT: &str = "EPIGRAPH_EXPLORER_UPSTREAM_TIMEOUT_MS";
const SINCE: &str = "2026-10-01T00:00:00Z";
/// Claims asked for per agent.
const PER_AGENT: &str = "20";
const AGENT_A: &str = "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const AGENT_B: &str = "2c8b6b5f-6054-4d5c-8b63-4a1e2f3d8b21";

/// A synthetic agent id, `n` in its last group.
fn agent_id(n: u64) -> String {
    format!("00000000-0000-4000-a000-{n:012x}")
}

/// A synthetic claim id, `n` in its last group.
fn claim_id(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

/// One `ClaimSummary`, as `GET /api/v1/claims` serialises it.
fn claim(n: u64, agent: &str, content: &str, created_at: &str, is_current: bool) -> Value {
    json!({
        "id": claim_id(n),
        "content": content,
        "statement": content,
        "truth_value": 0.5,
        "agent_id": agent,
        "is_current": is_current,
        "created_at": created_at,
        "updated_at": created_at,
    })
}

/// A `ClaimListResponse` page.
fn claims_page(claims: Vec<Value>, total: usize) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "claims": claims,
        "total": total,
        "limit": 20,
        "offset": 0,
    }))
}

/// `GET /api/v1/claims` for one agent with the bearer and the full query
/// the page must send.
fn agent_claims(agent: &str) -> MockBuilder {
    Mock::given(method("GET"))
        .and(path("/api/v1/claims"))
        .and(header("authorization", "Bearer tok"))
        .and(query_param("agent_id", agent))
        .and(query_param("created_after", SINCE))
        .and(query_param("sort_by", "created_at"))
        .and(query_param("sort_order", "desc"))
        .and(query_param("limit", PER_AGENT))
}

fn activity_url() -> String {
    format!("{BASE}/activity?since={SINCE}")
}

/// The marker an agent's section puts on its claim count.
fn shown(agent: &str, shown: usize, total: usize) -> String {
    format!("data-agent=\"{agent}\" data-claims-shown=\"{shown}\" data-claims-total=\"{total}\"")
}

/// The marker a claim row carries.
fn claim_row(n: u64) -> String {
    format!("data-claim=\"{}\"", claim_id(n))
}

async fn claims_calls(app: &TestApp) -> Vec<wiremock::Request> {
    app.upstream
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == "/api/v1/claims")
        .collect()
}

async fn watching(agents: &[&str]) -> TestApp {
    spawn_with(&[(ENV_WATCH, &agents.join(","))], Router::new()).await
}

/// J5: each watched agent's newest claims since T, in upstream's
/// newest-first order, each linking to the claim reader, under a heading
/// that links the agent's page. A superseded claim says so.
#[tokio::test]
async fn activity_lists_each_watched_agents_claims_since_t() {
    let app = watching(&[AGENT_A, AGENT_B]).await;
    agent_claims(AGENT_A)
        .respond_with(claims_page(
            vec![
                claim(
                    1,
                    AGENT_A,
                    "newer claim of a",
                    "2026-10-02T10:00:00.250000Z",
                    true,
                ),
                claim(
                    2,
                    AGENT_A,
                    "older claim of a",
                    "2026-10-01T09:00:00Z",
                    false,
                ),
            ],
            2,
        ))
        .expect(1)
        .mount(&app.upstream)
        .await;
    agent_claims(AGENT_B)
        .respond_with(claims_page(
            vec![claim(
                3,
                AGENT_B,
                "only claim of b",
                "2026-10-01T12:00:00Z",
                true,
            )],
            1,
        ))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&activity_url(), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains(&shown(AGENT_A, 2, 2)), "{}", res.body);
    assert!(res.body.contains(&shown(AGENT_B, 1, 1)), "{}", res.body);
    for n in [1, 2, 3] {
        assert!(res.body.contains(&claim_row(n)), "claim {n} missing");
        assert!(
            res.body
                .contains(&format!("href=\"/explorer/claim/{}\"", claim_id(n))),
            "claim {n} not linked"
        );
    }
    let (newer, older) = (
        res.body.find(&claim_row(1)).unwrap(),
        res.body.find(&claim_row(2)).unwrap(),
    );
    assert!(newer < older, "upstream's newest-first order is kept");
    // Configured order: a before b.
    assert!(res.body.find(AGENT_A).unwrap() < res.body.find(AGENT_B).unwrap());
    assert!(res
        .body
        .contains(&format!("href=\"/explorer/agent/{AGENT_A}\"")));
    assert!(
        res.body.contains("2026-10-02 10:00:00 UTC"),
        "claim time shown"
    );
    assert!(res.body.contains("superseded"), "claim 2 is not current");
    assert!(
        !res.body.contains("data-activity=\"unavailable\""),
        "{}",
        res.body
    );
    app.upstream.verify().await;
}

/// An API count above the rows it returned is marked capped, with the
/// newest-k-of-total wording; a list it returned whole is not.
#[tokio::test]
async fn activity_marks_an_agents_list_the_api_capped() {
    let app = watching(&[AGENT_A, AGENT_B]).await;
    let many: Vec<Value> = (0..20)
        .map(|n| claim(100 + n, AGENT_A, "busy", "2026-10-02T00:00:00Z", true))
        .collect();
    agent_claims(AGENT_A)
        .respond_with(claims_page(many, 345))
        .expect(1)
        .mount(&app.upstream)
        .await;
    agent_claims(AGENT_B)
        .respond_with(claims_page(vec![], 0))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&activity_url(), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains(&shown(AGENT_A, 20, 345)), "{}", res.body);
    assert!(
        res.body.contains("Showing the newest 20 of 345 claims"),
        "{}",
        res.body
    );
    assert_eq!(
        res.body.matches("data-activity=\"capped\"").count(),
        1,
        "only the capped agent is marked: {}",
        res.body
    );
    assert!(res.body.contains(&shown(AGENT_B, 0, 0)));
    assert!(res.body.contains("No claims since"), "b's empty list");
    app.upstream.verify().await;
}

/// One agent's failed call leaves that agent's section unavailable; the
/// other agent's claims still render.
#[tokio::test]
async fn activity_one_agents_failure_degrades_only_that_agent() {
    let app = watching(&[AGENT_A, AGENT_B]).await;
    agent_claims(AGENT_A)
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&app.upstream)
        .await;
    agent_claims(AGENT_B)
        .respond_with(claims_page(
            vec![claim(
                3,
                AGENT_B,
                "b still renders",
                "2026-10-01T12:00:00Z",
                true,
            )],
            1,
        ))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&activity_url(), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        res.body.contains(&format!(
            "data-agent=\"{AGENT_A}\" data-activity=\"unavailable\""
        )),
        "{}",
        res.body
    );
    assert!(res.body.contains(&shown(AGENT_B, 1, 1)), "{}", res.body);
    assert!(res.body.contains(&claim_row(3)));
    app.upstream.verify().await;
}

/// With no watch list the page says how to configure one, and asks
/// upstream nothing.
#[tokio::test]
async fn activity_without_watch_list_explains_configuration() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&activity_url(), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.body.contains("data-activity=\"no-watch-list\""),
        "{}",
        res.body
    );
    assert!(res.body.contains(ENV_WATCH), "names the variable");
    let calls = app.upstream.received_requests().await.unwrap_or_default();
    assert!(calls.is_empty(), "called upstream: {calls:?}");
}

/// A `since` that is not a time is explained, and upstream is not asked.
#[tokio::test]
async fn activity_rejects_a_bad_since_without_calling_upstream() {
    let app = watching(&[AGENT_A]).await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("{BASE}/activity?since=yesterday"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("is not a time"), "{}", res.body);
    let calls = app.upstream.received_requests().await.unwrap_or_default();
    assert!(calls.is_empty(), "called upstream: {calls:?}");
}

/// The page is for signed-in viewers: anonymous gets the sign-in redirect,
/// and upstream is not asked.
#[tokio::test]
async fn activity_requires_sign_in_and_makes_no_anonymous_call() {
    let app = watching(&[AGENT_A]).await;
    let res = app.get(&activity_url()).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    let calls = app.upstream.received_requests().await.unwrap_or_default();
    assert!(calls.is_empty(), "called upstream: {calls:?}");
}

/// More watched agents than the viewer's in-flight cap: every call still
/// completes. The per-call deadline runs from the moment a call starts,
/// queue wait included, so firing every call at once would leave the last
/// ones waiting out their deadline behind the cap (here: 2 at a time,
/// 300 ms each, a 1 000 ms deadline, so a fourth round would time out).
/// The page starts a call only when a slot is free.
#[tokio::test]
async fn activity_fanout_respects_the_semaphore() {
    let agents: Vec<String> = (1..=7).map(agent_id).collect();
    let refs: Vec<&str> = agents.iter().map(String::as_str).collect();
    let watch = refs.join(",");
    let app = spawn_with(
        &[
            (ENV_WATCH, &watch),
            (ENV_SESSION_CONCURRENCY, "2"),
            (ENV_UPSTREAM_CONCURRENCY, "4"),
            (ENV_TIMEOUT, "1000"),
        ],
        Router::new(),
    )
    .await;
    for (i, a) in refs.iter().enumerate() {
        agent_claims(a)
            .respond_with(
                claims_page(
                    vec![claim(i as u64, a, "fan", "2026-10-02T00:00:00Z", true)],
                    1,
                )
                .set_delay(std::time::Duration::from_millis(300)),
            )
            .expect(1)
            .mount(&app.upstream)
            .await;
    }
    let sid = app.sign_in("tok");
    let res = app.get_as(&activity_url(), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    for (i, a) in refs.iter().enumerate() {
        assert!(
            res.body.contains(&shown(a, 1, 1)),
            "agent {a} did not complete: {}",
            res.body
        );
        assert!(res.body.contains(&claim_row(i as u64)));
    }
    assert!(
        !res.body.contains("data-activity=\"unavailable\""),
        "{}",
        res.body
    );
    assert_eq!(claims_calls(&app).await.len(), refs.len());
    app.upstream.verify().await;
}
