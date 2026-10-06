//! The audit / soak page (J4) against a wiremock upstream.
//!
//! What it must do: count the security events the viewer may read since a
//! time, one row per `event_type` with its failures, pulled from
//! `GET /api/v1/audit/security` in pages of 1 000 walked by an `until`
//! cursor up to a configurable ceiling; mark a window it stopped short of
//! (capped) and one a page failed in (partial) without a 500; and explain a
//! token without `audit:read` instead of calling upstream.
//!
//! The mocks are shaped like the kernel's answer, not like an idealised one:
//! the route filters `created_at >= since AND created_at <= until`, so a page
//! asked for with `until` = the previous page's oldest `created_at` starts
//! with that row again. Every paging mock repeats it, carries sub-second
//! timestamps, and matches the full query (`since`, `limit`, the filters and
//! the exact cursor), so a pager that double-counts the boundary, rounds the
//! cursor, or drops `since` on a later page fails here.
//!
//! An unmatched request gets wiremock's 404, which the page renders as an
//! "unavailable" section with a 200; so every test asserts the counts it
//! expects, never only the status.

mod common;

use axum::http::StatusCode;
use axum::Router;
use chrono::{DateTime, Duration, TimeZone, Utc};
use common::{spawn, spawn_with, TestApp, BASE};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockBuilder, ResponseTemplate};

/// The row-ceiling knob (literal, so this file compiles before the config
/// constant exists).
const ENV_CEILING: &str = "EPIGRAPH_EXPLORER_AUDIT_ROW_CEILING";
const SINCE: &str = "2026-10-01T00:00:00Z";
const AGENT: &str = "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const OTHER_AGENT: &str = "2c8b6b5f-6054-4d5c-8b63-4a1e2f3d8b21";
const NOT_GRANTED: &str = "not granted audit:read";
const OWN_EVENTS: &str = "You see only your own security events";
const BEYOND_OWN: &str = "reads more than its own security events";

fn event_id(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

/// The `n`th event back from a fixed newest time, one second apart, with
/// microseconds, as the kernel serialises `created_at`.
fn ts(n: u64) -> String {
    let newest: DateTime<Utc> =
        Utc.with_ymd_and_hms(2026, 10, 3, 0, 0, 0).unwrap() + Duration::microseconds(123_456);
    (newest - Duration::seconds(n as i64))
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}

/// One `SecurityEventResponse`. Documentation-range address, no
/// identifying details.
fn event(n: u64, event_type: &str, agent: Option<&str>, success: Option<bool>) -> Value {
    event_at(n, event_type, agent, success, &ts(n))
}

fn event_at(
    n: u64,
    event_type: &str,
    agent: Option<&str>,
    success: Option<bool>,
    created_at: &str,
) -> Value {
    json!({
        "id": event_id(n),
        "event_type": event_type,
        "agent_id": agent,
        "success": success,
        "details": {"note": "fixture"},
        "ip_address": "192.0.2.10",
        "correlation_id": format!("corr-{n}"),
        "created_at": created_at,
    })
}

/// `GET /api/v1/audit/security` with the bearer and the parameters every
/// page of a pull must carry.
fn security_page(since: &str) -> MockBuilder {
    Mock::given(method("GET"))
        .and(path("/api/v1/audit/security"))
        .and(header("authorization", "Bearer tok"))
        .and(query_param("since", since))
        .and(query_param("limit", "1000"))
}

/// The first page of an unfiltered pull: no cursor, no filters.
fn first_page() -> MockBuilder {
    security_page(SINCE)
        .and(query_param_is_missing("until"))
        .and(query_param_is_missing("event_type"))
        .and(query_param_is_missing("failures_only"))
}

/// A later page of an unfiltered pull, at the given cursor.
fn page_until(until: &str) -> MockBuilder {
    security_page(SINCE)
        .and(query_param("until", until))
        .and(query_param_is_missing("event_type"))
        .and(query_param_is_missing("failures_only"))
}

fn ok(rows: Vec<Value>) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(Value::Array(rows))
}

fn audit_url(query: &str) -> String {
    format!("{BASE}/audit?since={SINCE}{query}")
}

/// The marker the page puts on one type's row of counts.
fn type_row(event_type: &str, total: u64, failures: u64) -> String {
    format!("data-event-type=\"{event_type}\" data-total=\"{total}\" data-failures=\"{failures}\"")
}

async fn upstream_calls(app: &TestApp) -> Vec<wiremock::Request> {
    app.upstream
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == "/api/v1/audit/security")
        .collect()
}

/// J4: one row per `event_type` with its total and its failures. A failure
/// is `success = false` only (the kernel's own `failures_only` meaning): a
/// NULL outcome is not one. Busiest type first. One short page is the whole
/// window, so there is exactly one request.
#[tokio::test]
async fn audit_groups_by_type_with_failure_counts() {
    let app = spawn().await;
    first_page()
        .respond_with(ok(vec![
            event(0, "auth_attempt", Some(AGENT), Some(true)),
            event(1, "rate_limit_exceeded", Some(AGENT), Some(false)),
            event(2, "auth_attempt", Some(AGENT), Some(false)),
            event(3, "rate_limit_exceeded", Some(AGENT), Some(false)),
            event(4, "auth_attempt", Some(AGENT), None),
        ]))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&audit_url(""), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let auth = res
        .body
        .find(&type_row("auth_attempt", 3, 1))
        .unwrap_or_else(|| panic!("auth_attempt 3 / 1 missing: {}", res.body));
    let rate = res
        .body
        .find(&type_row("rate_limit_exceeded", 2, 2))
        .unwrap_or_else(|| panic!("rate_limit_exceeded 2 / 2 missing: {}", res.body));
    assert!(auth < rate, "busiest type first");
    assert!(res.body.contains("data-events-read=\"5\""), "{}", res.body);
    // A drill-down link per type and the failures-only toggle.
    assert!(res.body.contains("type=auth_attempt"), "{}", res.body);
    assert!(res.body.contains("failures=1"), "{}", res.body);
    // The standing banners: what this trail is not, and whose events.
    assert!(
        res.body.contains("only events you may read"),
        "{}",
        res.body
    );
    assert!(res.body.contains("refresh-token volume and liveness"));
    assert!(res.body.contains(OWN_EVENTS), "{}", res.body);
    for marker in ["capped", "partial", "unavailable"] {
        assert!(
            !res.body.contains(&format!("data-audit=\"{marker}\"")),
            "{marker}: {}",
            res.body
        );
    }
    assert!(!res.body.contains("Not yet available"), "still the stub");
    assert_eq!(upstream_calls(&app).await.len(), 1);
    app.upstream.verify().await;
}

/// J4 / M4: the window is pulled in pages of 1 000, each asking for
/// `until` = the previous page's oldest `created_at` exactly (microseconds
/// kept). The kernel's `until` is inclusive, so each later page starts with
/// the previous page's oldest row again: it is counted once. At the
/// configured ceiling the pull stops and the page says it is capped.
#[tokio::test]
async fn audit_pages_with_until_and_marks_a_capped_window() {
    let app = spawn_with(&[(ENV_CEILING, "2500")], Router::new()).await;
    // The boundary rows (each page's oldest) carry their own type, so a
    // boundary counted twice shows in that type's total.
    let kind = |n: u64| {
        if n == 999 || n == 1998 {
            "token_rotation"
        } else {
            "auth_attempt"
        }
    };
    let rows = |range: std::ops::RangeInclusive<u64>| -> Vec<Value> {
        range
            .map(|n| event(n, kind(n), Some(AGENT), Some(true)))
            .collect()
    };
    // Page 1: rows 0..=999. Page 2: 999 again, then 1000..=1998.
    // Page 3: 1998 again, then 1999..=2997.
    first_page()
        .respond_with(ok(rows(0..=999)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    page_until(&ts(999))
        .respond_with(ok(rows(999..=1998)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    page_until(&ts(1998))
        .respond_with(ok(rows(1998..=2997)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&audit_url(""), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    // The cursor advanced page by page, each page asking for 1 000 rows, and
    // nothing was asked past the ceiling.
    let untils: Vec<Option<String>> = upstream_calls(&app)
        .await
        .iter()
        .map(|r| {
            r.url
                .query_pairs()
                .find(|(k, _)| k == "until")
                .map(|(_, v)| v.into_owned())
        })
        .collect();
    assert_eq!(untils, vec![None, Some(ts(999)), Some(ts(1998))]);
    assert!(
        res.body.contains("data-audit=\"capped\""),
        "no capped banner: {}",
        res.body
    );
    assert!(res.body.contains("Capped at 2,500 events"), "{}", res.body);
    assert!(
        res.body.contains("data-events-read=\"2500\""),
        "{}",
        res.body
    );
    assert!(
        res.body.contains(&type_row("token_rotation", 2, 0)),
        "each boundary row counted once: {}",
        res.body
    );
    assert!(
        res.body.contains(&type_row("auth_attempt", 2498, 0)),
        "{}",
        res.body
    );
    assert!(!res.body.contains("data-audit=\"partial\""), "{}", res.body);

    app.upstream.verify().await;
}

/// J4: a bounded window. The viewer's `until` is the first page's cursor, so
/// upstream is never asked for events after the window's end, and every later
/// page's cursor (the previous page's oldest row) stays inside it. The links
/// that change one filter keep the bound: a drill-down and the failures toggle
/// on a bounded window must not silently widen it to "until now".
#[tokio::test]
async fn audit_window_until_bounds_the_first_page_and_survives_its_links() {
    let app = spawn().await;
    let until = ts(0);
    let rows = |range: std::ops::RangeInclusive<u64>| -> Vec<Value> {
        range
            .map(|n| event(n, "auth_attempt", Some(AGENT), Some(n % 3 == 0)))
            .collect()
    };
    // The first page carries the viewer's own bound, not "no cursor".
    security_page(SINCE)
        .and(query_param("until", until.as_str()))
        .and(query_param_is_missing("event_type"))
        .and(query_param_is_missing("failures_only"))
        .respond_with(ok(rows(0..=999)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    page_until(&ts(999))
        .respond_with(ok(rows(999..=1499)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(&audit_url(&format!("&until={until}")), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let untils: Vec<Option<String>> = upstream_calls(&app)
        .await
        .iter()
        .map(|r| {
            r.url
                .query_pairs()
                .find(|(k, _)| k == "until")
                .map(|(_, v)| v.into_owned())
        })
        .collect();
    assert_eq!(
        untils,
        vec![Some(until.clone()), Some(ts(999))],
        "the window's end is the first cursor"
    );
    assert!(
        res.body.contains("data-events-read=\"1500\""),
        "{}",
        res.body
    );
    assert!(!res.body.contains("data-audit=\"partial\""), "{}", res.body);

    // The bound, as the links carry it.
    let since_q = "since=2026-10-01T00%3A00%3A00Z";
    let until_q = "until=2026-10-03T00%3A00%3A00.123456Z";
    assert!(
        res.body.contains(&format!(
            "href=\"{BASE}/audit?{since_q}&#38;{until_q}&#38;failures=1\""
        )),
        "the failures toggle keeps `until`: {}",
        res.body
    );
    assert!(
        res.body.contains(&format!(
            "href=\"{BASE}/audit?{since_q}&#38;{until_q}&#38;type=auth_attempt\""
        )),
        "the drill-down link keeps `until`: {}",
        res.body
    );
    app.upstream.verify().await;
}

/// J4: a later page the BFF cannot read (here over the 8 MiB body cap) does
/// not fail the page: the counts read so far render, under a banner saying
/// the window is incomplete. Never a 500.
#[tokio::test]
async fn audit_page_over_the_body_cap_shows_partial_not_500() {
    let app = spawn().await;
    first_page()
        .respond_with(ok((0..1000)
            .map(|n| event(n, "auth_attempt", Some(AGENT), Some(false)))
            .collect()))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let pad = "x".repeat(9000);
    let huge: Vec<Value> = (999..1999)
        .map(|n| {
            let mut e = event(n, "auth_attempt", Some(AGENT), Some(false));
            e["details"] = json!({ "pad": pad });
            e
        })
        .collect();
    page_until(&ts(999))
        .respond_with(ok(huge))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&audit_url(""), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.body.contains("data-audit=\"partial\""),
        "no partial banner: {}",
        res.body
    );
    assert!(
        res.body.contains(&type_row("auth_attempt", 1000, 1000)),
        "the first page's counts still render: {}",
        res.body
    );
    assert!(res.body.contains("data-events-read=\"1000\""));
    assert!(!res.body.contains("data-audit=\"capped\""));
    assert_eq!(upstream_calls(&app).await.len(), 2);
    app.upstream.verify().await;
}

/// J4: a token whose granted scope lacks `audit:read` gets an explanation,
/// not an error and not an empty table, and upstream is never asked.
#[tokio::test]
async fn audit_without_scope_explains_and_makes_no_call() {
    let app = spawn().await;
    // Upstream would answer with rows: only the scope check keeps them out.
    Mock::given(method("GET"))
        .and(path("/api/v1/audit/security"))
        .respond_with(ok(vec![event(0, "auth_attempt", Some(AGENT), Some(true))]))
        .expect(0)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    // The token response granted claims:read only.
    app.state
        .sessions
        .set_token_scope(&sid, Some("claims:read".into()), false);

    let res = app.get_as(&audit_url(""), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains(NOT_GRANTED), "{}", res.body);
    assert!(res.body.contains("data-audit=\"not-granted\""));
    assert!(!res.body.contains("data-event-type="), "no table");
    assert!(!res.body.contains("data-audit=\"unavailable\""));
    assert!(upstream_calls(&app).await.is_empty());
    app.upstream.verify().await;

    // `audit:read` among several granted scopes is enough; a scope that
    // merely contains the text is not.
    app.state
        .sessions
        .set_token_scope(&sid, Some("claims:read audit:readonly".into()), false);
    let res = app.get_as(&audit_url(""), &sid).await;
    assert!(res.body.contains(NOT_GRANTED), "{}", res.body);
    assert!(upstream_calls(&app).await.is_empty());
}

/// J4: when the session does not know its token's scope (or upstream
/// disagrees with it), upstream's 403 is the same "not granted" answer.
#[tokio::test]
async fn audit_upstream_403_is_the_not_granted_state() {
    let app = spawn().await;
    first_page()
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "Forbidden", "message": "Missing required scope"
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok"); // scope not reported

    let res = app.get_as(&audit_url(""), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains(NOT_GRANTED), "{}", res.body);
    assert!(!res.body.contains("data-event-type="));
    app.upstream.verify().await;
}

/// J4: a first page that fails leaves nothing to count: the section is
/// unavailable and the page still renders (200), whatever the upstream
/// status, a 404 included (it must not read as "no such page").
#[tokio::test]
async fn audit_first_page_failure_is_unavailable_not_an_error() {
    let app = spawn().await;
    first_page()
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&audit_url(""), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.body.contains("data-audit=\"unavailable\""),
        "{}",
        res.body
    );
    assert!(res
        .body
        .contains("The EpiGraph API is unavailable right now."));
    assert!(!res.body.contains("data-event-type="));
    app.upstream.verify().await;

    // Nothing mounted: wiremock answers 404.
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&audit_url(""), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.body.contains("data-audit=\"unavailable\""),
        "{}",
        res.body
    );
    assert!(!res.body.contains("could not find that page"));
}

/// J4: "failures only" asks upstream for failures (`failures_only=true`) on
/// every page, so each type's total is its failures, and the page offers
/// the way back to all events.
#[tokio::test]
async fn audit_failures_only_asks_upstream_for_failures() {
    let app = spawn().await;
    security_page(SINCE)
        .and(query_param("failures_only", "true"))
        .and(query_param_is_missing("until"))
        .and(query_param_is_missing("event_type"))
        .respond_with(ok(vec![
            event(0, "auth_attempt", Some(AGENT), Some(false)),
            event(1, "auth_attempt", Some(AGENT), Some(false)),
        ]))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&audit_url("&failures=1"), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        res.body.contains(&type_row("auth_attempt", 2, 2)),
        "{}",
        res.body
    );
    assert!(res.body.contains("Showing failures only"), "{}", res.body);
    // The toggle back drops `failures`; the drill link keeps it.
    assert!(
        res.body.contains(&format!(
            "href=\"{BASE}/audit?since=2026-10-01T00%3A00%3A00Z\""
        )),
        "{}",
        res.body
    );
    assert!(
        res.body.contains("type=auth_attempt&#38;failures=1"),
        "{}",
        res.body
    );
    app.upstream.verify().await;
}

/// J4: a filtered window longer than one page carries its filter on EVERY
/// page, not only the first. A pager that dropped `failures_only` on page 2
/// would count successes as failures from there on, and one that dropped
/// `event_type` would mix other types into a drill-down. Each page's mock
/// requires the filter together with its own cursor, so a later page asked
/// without it matches nothing (and the window turns up incomplete).
#[tokio::test]
async fn audit_filters_reach_every_page_of_a_long_window() {
    // Failures only, over two pages.
    let app = spawn().await;
    let failures = |range: std::ops::RangeInclusive<u64>| -> Vec<Value> {
        range
            .map(|n| event(n, "auth_attempt", Some(AGENT), Some(false)))
            .collect()
    };
    security_page(SINCE)
        .and(query_param("failures_only", "true"))
        .and(query_param_is_missing("until"))
        .and(query_param_is_missing("event_type"))
        .respond_with(ok(failures(0..=999)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    security_page(SINCE)
        .and(query_param("failures_only", "true"))
        .and(query_param("until", ts(999).as_str()))
        .and(query_param_is_missing("event_type"))
        .respond_with(ok(failures(999..=1199)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&audit_url("&failures=1"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.body.contains(&type_row("auth_attempt", 1200, 1200)),
        "both pages asked for failures only: {}",
        res.body
    );
    assert!(!res.body.contains("data-audit=\"partial\""), "{}", res.body);
    app.upstream.verify().await;

    // A drill-down to one type, over two pages.
    let app = spawn().await;
    let typed = |range: std::ops::RangeInclusive<u64>| -> Vec<Value> {
        range
            .map(|n| event(n, "token_rotation", Some(AGENT), Some(true)))
            .collect()
    };
    security_page(SINCE)
        .and(query_param("event_type", "token_rotation"))
        .and(query_param_is_missing("until"))
        .and(query_param_is_missing("failures_only"))
        .respond_with(ok(typed(0..=999)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    security_page(SINCE)
        .and(query_param("event_type", "token_rotation"))
        .and(query_param("until", ts(999).as_str()))
        .and(query_param_is_missing("failures_only"))
        .respond_with(ok(typed(999..=1099)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&audit_url("&type=token_rotation"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.body.contains(&type_row("token_rotation", 1100, 0)),
        "both pages asked for the one type: {}",
        res.body
    );
    assert!(!res.body.contains("data-audit=\"partial\""), "{}", res.body);
    app.upstream.verify().await;
}

/// J4: the session can end on a LATER page (its token rejected and the
/// refresh refused). That is a sign-out, exactly as on the first page: a
/// redirect to sign in with the session cookie cleared, never a 200 showing
/// the pages read before it as "incomplete" counts.
#[tokio::test]
async fn audit_session_ending_on_a_later_page_signs_the_viewer_out() {
    let app = spawn().await;
    first_page()
        .respond_with(ok((0..=999)
            .map(|n| event(n, "auth_attempt", Some(AGENT), Some(true)))
            .collect()))
        .expect(1)
        .mount(&app.upstream)
        .await;
    page_until(&ts(999))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized", "message": "token expired"
        })))
        .mount(&app.upstream)
        .await;
    // The refresh after that 401 is refused: the credential is dead.
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant", "error_description": "refresh token revoked"
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&audit_url(""), &sid).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert!(
        res.location().unwrap_or_default().contains("/auth/login"),
        "{:?}",
        res.location()
    );
    assert!(
        res.header_all("set-cookie")
            .iter()
            .any(|c| c.starts_with("epx_session=") && c.contains("Max-Age=0")),
        "the session cookie is cleared: {:?}",
        res.header_all("set-cookie")
    );
    assert!(app.state.sessions.get(&sid).is_none(), "session ended");
    assert_eq!(
        upstream_calls(&app).await.len(),
        2,
        "the first page was read before the second ended the session"
    );
    app.upstream.verify().await;
}

/// J4: `type=` drills down to that type's raw rows (asked of upstream as
/// `event_type=`), newest first, showing the newest 200 of them. Row fields
/// are viewer-readable text and are escaped.
#[tokio::test]
async fn audit_drill_down_lists_one_types_rows() {
    let app = spawn().await;
    let mut rows: Vec<Value> = (0..205)
        .map(|n| event(n, "auth_attempt", Some(AGENT), Some(n % 2 == 0)))
        .collect();
    rows[0]["details"] = json!({ "reason": "<script>alert(1)</script>" });
    security_page(SINCE)
        .and(query_param("event_type", "auth_attempt"))
        .and(query_param_is_missing("until"))
        .and(query_param_is_missing("failures_only"))
        .respond_with(ok(rows))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&audit_url("&type=auth_attempt"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.body.contains(&type_row("auth_attempt", 205, 102)),
        "{}",
        res.body
    );
    assert!(res.body.contains("data-drill-row"), "no rows: {}", res.body);
    assert!(res.body.contains("newest 200 of 205"), "{}", res.body);
    let first = res.body.find("corr-0<").expect("newest row shown");
    let later = res.body.find("corr-199<").expect("200th row shown");
    assert!(first < later, "newest first");
    assert!(!res.body.contains("corr-200<"), "only the newest 200");
    assert!(res.body.contains(&format!("href=\"{BASE}/agent/{AGENT}\"")));
    assert!(res.body.contains("192.0.2.10"));
    assert!(!res.body.contains("<script>alert"), "details escaped");
    assert!(res.body.contains("&#60;script&#62;"), "{}", res.body);
    assert!(res.body.contains("All event types"), "a way back");
    app.upstream.verify().await;
}

/// A `since` or `until` that is not a time, or a window that ends before it
/// starts, is explained on the page and nothing is asked of upstream.
#[tokio::test]
async fn audit_rejects_a_bad_window_without_calling_upstream() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/audit/security"))
        .respond_with(ok(vec![]))
        .expect(0)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    for (uri, why) in [
        (format!("{BASE}/audit?since=yesterday"), "is not a time"),
        (
            format!("{BASE}/audit?since={SINCE}&until=2026-09-30T00:00:00Z"),
            "ends before it starts",
        ),
    ] {
        let res = app.get_as(&uri, &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}");
        assert!(res.body.contains(why), "{uri}: {}", res.body);
        assert!(res.body.contains("notice--warn"), "{uri}");
        assert!(!res.body.contains("data-event-type="), "{uri}");
    }
    assert!(upstream_calls(&app).await.is_empty());
    app.upstream.verify().await;
}

/// Whose events (P4 unmeasured): the page says "your own" unless the rows
/// themselves show more: an event with no agent, or events of two agents,
/// mean this account reads more than its own trail, and the page says so.
#[tokio::test]
async fn audit_scope_note_says_own_events_unless_the_rows_show_more() {
    for (label, rows, beyond) in [
        (
            "one agent",
            vec![
                event(0, "auth_attempt", Some(AGENT), Some(true)),
                event(1, "auth_attempt", Some(AGENT), Some(false)),
            ],
            false,
        ),
        (
            "an unattributed event",
            vec![
                event(0, "auth_attempt", Some(AGENT), Some(true)),
                event(1, "suspicious_activity", None, None),
            ],
            true,
        ),
        (
            "two agents",
            vec![
                event(0, "auth_attempt", Some(AGENT), Some(true)),
                event(1, "auth_attempt", Some(OTHER_AGENT), Some(true)),
            ],
            true,
        ),
    ] {
        let app = spawn().await;
        first_page()
            .respond_with(ok(rows))
            .expect(1)
            .mount(&app.upstream)
            .await;
        let sid = app.sign_in("tok");
        let res = app.get_as(&audit_url(""), &sid).await;
        assert!(
            res.body.contains("data-events-read=\"2\""),
            "{label}: {}",
            res.body
        );
        assert_eq!(
            res.body.contains(BEYOND_OWN),
            beyond,
            "{label}: {}",
            res.body
        );
        assert_eq!(
            res.body.contains(OWN_EVENTS),
            !beyond,
            "{label}: {}",
            res.body
        );
    }
}

/// More than a page of events sharing one timestamp cannot be paged past
/// with an inclusive `until`: the next page is the same rows. The pull stops
/// and says the window is incomplete (narrowing would not help, so it is not
/// "capped").
#[tokio::test]
async fn audit_a_window_it_cannot_page_past_is_partial() {
    let app = spawn().await;
    let same = ts(0);
    let rows: Vec<Value> = (0..1000)
        .map(|n| event_at(n, "auth_attempt", Some(AGENT), Some(true), &same))
        .collect();
    first_page()
        .respond_with(ok(rows.clone()))
        .expect(1)
        .mount(&app.upstream)
        .await;
    page_until(&same)
        .respond_with(ok(rows))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&audit_url(""), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("data-audit=\"partial\""), "{}", res.body);
    assert!(res.body.contains("share one timestamp"), "{}", res.body);
    assert!(res.body.contains(&type_row("auth_attempt", 1000, 0)));
    assert!(!res.body.contains("data-audit=\"capped\""));
    assert_eq!(upstream_calls(&app).await.len(), 2);
    app.upstream.verify().await;
}

/// Signed-in only: an anonymous viewer is sent to sign in and upstream is
/// never asked.
#[tokio::test]
async fn audit_requires_sign_in_and_makes_no_anonymous_call() {
    let app = spawn().await;
    let res = app.get(&audit_url("")).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert!(res.location().unwrap_or_default().contains("/auth/login"));
    assert!(upstream_calls(&app).await.is_empty());
}

/// `/bff/audit` serves what the page renders, as JSON; a bad window is a
/// 400 there, and an anonymous caller gets a JSON 401.
#[tokio::test]
async fn bff_audit_serves_the_counted_window_as_json() {
    let app = spawn().await;
    first_page()
        .respond_with(ok(vec![
            event(0, "auth_attempt", Some(AGENT), Some(false)),
            event(1, "auth_attempt", Some(AGENT), Some(true)),
            event(2, "token_rotation", Some(AGENT), Some(true)),
        ]))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(&format!("{BASE}/bff/audit?since={SINCE}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let v = res.json();
    assert_eq!(v["since"], SINCE);
    assert_eq!(v["failures_only"], false);
    assert_eq!(v["result"]["status"], "counted");
    assert_eq!(v["result"]["events_read"], 3);
    assert_eq!(v["result"]["capped_at"], Value::Null);
    assert_eq!(v["result"]["partial"], Value::Null);
    assert_eq!(v["result"]["reads_beyond_own"], false);
    assert_eq!(
        v["result"]["rows"],
        json!([]),
        "an undrilled window carries no raw rows (addresses, details)"
    );
    assert_eq!(
        v["result"]["types"],
        json!([
            {"event_type": "auth_attempt", "total": 2, "failures": 1},
            {"event_type": "token_rotation", "total": 1, "failures": 0},
        ])
    );
    assert_eq!(res.header("cache-control"), Some("private, no-store"));
    app.upstream.verify().await;

    let res = app
        .get_as(&format!("{BASE}/bff/audit?since=yesterday"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.body);
    assert_eq!(res.json()["error"], "bad_request");

    // Signed-in only, as JSON: no redirect, and upstream is not asked.
    let calls = upstream_calls(&app).await.len();
    let res = app.get(&format!("{BASE}/bff/audit?since={SINCE}")).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json()["error"], "unauthorized");
    assert_eq!(upstream_calls(&app).await.len(), calls);
}
