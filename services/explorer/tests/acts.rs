//! J7: the admin-acts capability probe behind the "Admin acts" nav item.
//!
//! The probe is `GET /api/v1/admin/acts?mine&limit=1` with the viewer's own
//! token, made by signed-in page requests: 2xx (with the `{acts: [...]}`
//! envelope) and 403 mean the route exists, 404/405 mean it does not, and
//! anything else is unknown. Only present/absent are remembered (per
//! process, for a TTL); an unknown answer hides the item for that page and
//! is asked again on the next.
//!
//! `/activity` with no watch list configured is the page used to look at the
//! header: it makes no data call of its own, so every upstream request it
//! causes is the probe.

mod common;

use axum::Router;
use common::{spawn, spawn_with, TestApp, BASE};
use epigraph_explorer::config::{ENV_DEV_BEARER, ENV_PUBLIC_BASE_URL};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const ACTS_PATH: &str = "/api/v1/admin/acts";

/// The nav item, exactly as `templates/base.html` renders it.
const NAV_ITEM: &str = "href=\"/explorer/acts\">Admin acts</a>";

fn header_page() -> String {
    format!("{BASE}/activity")
}

/// The probe: `?mine&limit=1`.
fn probe() -> wiremock::MockBuilder {
    Mock::given(method("GET"))
        .and(path(ACTS_PATH))
        .and(query_param("mine", ""))
        .and(query_param("limit", "1"))
}

async fn probe_answers(app: &TestApp, status: u16, times: u64) {
    let template = if status == 200 {
        ResponseTemplate::new(200).set_body_json(json!({"acts": []}))
    } else {
        ResponseTemplate::new(status).set_body_json(json!({"error": "X", "message": "probe"}))
    };
    probe()
        .respond_with(template)
        .expect(times)
        .named("capability probe")
        .mount(&app.upstream)
        .await;
}

async fn probe_calls(app: &TestApp) -> Vec<wiremock::Request> {
    app.upstream
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == ACTS_PATH && r.url.query() == Some("mine&limit=1"))
        .collect()
}

// ---- the probe and the nav item ------------------------------------------------

/// An API without the route answers the probe 404: the nav item is left out
/// of the HTML, and "absent" is remembered (one probe for two pages).
#[tokio::test]
async fn probe_absent_on_404_hides_the_nav() {
    let app = spawn().await;
    probe_answers(&app, 404, 1).await;
    let sid = app.sign_in("tok");
    for _ in 0..2 {
        let res = app.get_as(&header_page(), &sid).await;
        assert_eq!(res.status, 200, "{}", res.body);
        assert!(res.body.contains("aria-label=\"Sections\""), "section nav");
        assert!(!res.body.contains("Admin acts"), "{}", res.body);
        assert!(!res.body.contains("/explorer/acts"), "{}", res.body);
    }
    app.upstream.verify().await;
}

/// A 401 that reaches the probe says nothing about the route (a session's
/// 401 has already been through refresh-and-retry). It is "unknown": the
/// item is hidden for that page and nothing is remembered, so the next page
/// asks again and, the route answering, shows it. With the dev bearer a 401
/// leaves the viewer signed in, so the second page can show the difference.
#[tokio::test]
async fn probe_unknown_on_401_is_not_cached() {
    let app = spawn_with(
        &[
            (ENV_PUBLIC_BASE_URL, "http://localhost:8096/explorer"),
            (ENV_DEV_BEARER, "dev-token"),
        ],
        Router::new(),
    )
    .await;
    probe()
        .and(header("authorization", "Bearer dev-token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized", "message": "Invalid token: ExpiredSignature"
        })))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&app.upstream)
        .await;
    probe()
        .and(header("authorization", "Bearer dev-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acts": []})))
        .with_priority(2)
        .expect(1)
        .mount(&app.upstream)
        .await;

    let first = app.get(&header_page()).await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert!(
        first.body.contains("aria-label=\"Sections\""),
        "signed in by the dev bearer"
    );
    assert!(!first.body.contains("Admin acts"), "unknown hides the item");

    let second = app.get(&header_page()).await;
    assert!(
        second.body.contains(NAV_ITEM),
        "unknown was not remembered: the second page probed again and saw the route: {}",
        second.body
    );
    app.upstream.verify().await;
}

/// A 5xx is "unknown" too: the item is hidden and the page itself renders.
#[tokio::test]
async fn probe_unknown_on_500_hides_the_nav_and_renders_the_page() {
    let app = spawn().await;
    probe_answers(&app, 500, 1).await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&header_page(), &sid).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert!(
        res.body.contains("data-activity=\"no-watch-list\""),
        "the page rendered: {}",
        res.body
    );
    assert!(!res.body.contains("Admin acts"), "{}", res.body);
    assert!(!res.body.contains("/explorer/acts"), "{}", res.body);
    app.upstream.verify().await;
}

/// A 2xx whose body is not the listing's envelope is not evidence of the
/// route either (a catch-all page, a proxy's own answer): unknown.
#[tokio::test]
async fn probe_200_without_the_listing_shape_hides_the_nav() {
    let app = spawn().await;
    probe()
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .expect(2)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    for _ in 0..2 {
        let res = app.get_as(&header_page(), &sid).await;
        assert_eq!(res.status, 200);
        assert!(!res.body.contains("Admin acts"), "{}", res.body);
    }
    app.upstream.verify().await;
}

/// A 403 means the route exists but this viewer may not use it: the item
/// shows (the page then says so).
#[tokio::test]
async fn probe_403_counts_as_present() {
    let app = spawn().await;
    probe_answers(&app, 403, 1).await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&header_page(), &sid).await;
    assert!(res.body.contains(NAV_ITEM), "{}", res.body);
    app.upstream.verify().await;
}

/// Present is remembered for the TTL: three pages, one probe. The probe is
/// the exact request the kernel's `unregistered_route_status_test` pins,
/// sent with the viewer's own token.
#[tokio::test]
async fn probe_result_is_cached_for_the_ttl() {
    let app = spawn().await;
    probe_answers(&app, 200, 1).await;
    let sid = app.sign_in("tok");
    for _ in 0..3 {
        let res = app.get_as(&header_page(), &sid).await;
        assert_eq!(res.status, 200, "{}", res.body);
        assert!(res.body.contains(NAV_ITEM), "{}", res.body);
    }
    app.upstream.verify().await;

    let calls = probe_calls(&app).await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].url.query(), Some("mine&limit=1"));
    assert_eq!(
        calls[0]
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer tok"),
        "the viewer's own token, never a service token"
    );
}

/// Anonymous pages and `/bff/*` JSON never probe: neither renders the
/// section nav.
#[tokio::test]
async fn only_signed_in_pages_probe() {
    let app = spawn().await;
    probe_answers(&app, 200, 0).await;
    let res = app
        .get(&format!(
            "{BASE}/claim/00000000-0000-4000-8000-0000000000d1"
        ))
        .await;
    assert_eq!(res.status, 200, "anonymous claim card");
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("{BASE}/bff/themes"), &sid).await;
    assert!(
        res.header("content-type")
            .unwrap_or_default()
            .starts_with("application/json"),
        "a bff answer"
    );
    app.upstream.verify().await;
}

/// A probe that refreshed the session's token leaves the page holding the
/// new one: the page's own calls never present the rotated-out token.
#[tokio::test]
async fn a_token_the_probe_refreshed_is_the_one_the_page_sends() {
    let app = spawn().await;
    probe()
        .and(header("authorization", "Bearer old"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized", "message": "Invalid token: ExpiredSignature"
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    probe()
        .and(header("authorization", "Bearer new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acts": []})))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-2",
            "scope": "claims:read audit:read"
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/match_candidates"))
        .and(header("authorization", "Bearer new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&app.upstream)
        .await;

    let sid = app.sign_in("old");
    let res = app.get_as(&format!("{BASE}/candidates"), &sid).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert!(
        res.body.contains("data-candidates=\"empty\""),
        "{}",
        res.body
    );
    assert!(res.body.contains(NAV_ITEM), "{}", res.body);
    let stale = app
        .upstream
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() != ACTS_PATH)
        .filter(|r| {
            r.headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer old")
        })
        .count();
    assert_eq!(stale, 0, "the page presented the rotated-out token");
    app.upstream.verify().await;
}

/// A probe whose 401 ends the session (the refresh is refused) signs the
/// viewer out on that very request, cookie cleared, as the page's own call
/// would have. `/activity` with no watch list makes no call of its own, so
/// only the probe can notice.
#[tokio::test]
async fn a_probe_that_ends_the_session_signs_the_viewer_out() {
    let app = spawn().await;
    probe()
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized", "message": "Invalid token: ExpiredSignature"
        })))
        .mount(&app.upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant", "error_description": "refresh token revoked"
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("stale");
    let res = app.get_as(&header_page(), &sid).await;
    assert_eq!(res.status, 303, "{}", res.body);
    assert_eq!(
        res.location(),
        Some("/explorer/auth/login?return_to=%2Fexplorer%2Factivity")
    );
    assert!(
        res.header_all("set-cookie")
            .iter()
            .any(|c| c.contains("epx_session=") && c.contains("Max-Age=0")),
        "cookie cleared: {:?}",
        res.header_all("set-cookie")
    );
    assert!(app.state.sessions.get(&sid).is_none(), "session ended");
    app.upstream.verify().await;
}
