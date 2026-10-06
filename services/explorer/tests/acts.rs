//! J7: the admin-acts capability probe and the `/acts` link-out page.
//!
//! The listing is the elevation stack's `routes/admin_acts.rs::list_acts`
//! response, `{"acts": [ProposedAct (flattened) + "path"]}`, copied from
//! `feat/mt-c-elevation` at `3387413f` (`admin_acts.rs`,
//! `repos/admin_act_ceremony.rs::ProposedAct` and the `/elevate/act/:id`
//! routes are unchanged through `121d6cca`). Re-check it when that stack
//! gets a PR.
//!
//! The probe is `GET /api/v1/admin/acts?mine&limit=1` with the viewer's own
//! token, made by signed-in page requests: 2xx (with the `{acts: [...]}`
//! envelope) and 403 mean the route exists, 404/405 mean it does not, and
//! anything else is unknown. Present/absent are remembered (per process, for
//! a TTL); an unknown the API itself caused (5xx, 429, timeout, transport) is
//! remembered for a short TTL; any other unknown hides the item for that
//! page and is asked again on the next.
//!
//! `/activity` with no watch list configured is the page used to look at the
//! header: it makes no data call of its own, so every upstream request it
//! causes is the probe.

mod common;

use axum::Router;
use chrono::{Duration, Utc};
use common::{spawn, spawn_with, TestApp, BASE};
use epigraph_explorer::config::{ENV_DEV_BEARER, ENV_OAUTH_BASE_URL, ENV_PUBLIC_BASE_URL};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const ACTS_PATH: &str = "/api/v1/admin/acts";
/// The API's public origin for the link-out: distinct from the mock API
/// (`EPIGRAPH_API_URL`) and from the Explorer's own origin, so a link that
/// pointed at either would not pass by accident.
const API_ORIGIN: &str = "https://api.example.com";

const ACT_PENDING: &str = "00000000-0000-4000-8000-0000000000a1";
const ACT_CONFIRMED: &str = "00000000-0000-4000-8000-0000000000a2";
const ACT_EXECUTED: &str = "00000000-0000-4000-8000-0000000000a3";
const ACT_EXPIRED: &str = "00000000-0000-4000-8000-0000000000a4";
const ACT_REFUSED: &str = "00000000-0000-4000-8000-0000000000a5";
const ACT_OTHER: &str = "00000000-0000-4000-8000-0000000000a6";
const TARGET: &str = "00000000-0000-4000-8000-0000000000b1";
const ELEVATION: &str = "00000000-0000-4000-8000-0000000000c1";

/// The nav item, exactly as `templates/base.html` renders it.
const NAV_ITEM: &str = "href=\"/explorer/acts\">Admin acts</a>";

fn header_page() -> String {
    format!("{BASE}/activity")
}

/// One listed act in the kernel's shape. `when` fields are offsets from now
/// in minutes; `None` leaves the field null.
struct ActSpec<'a> {
    id: &'a str,
    expires_in_min: i64,
    asserted: bool,
    outcome: Option<&'a str>,
    consumed: bool,
    path: Option<String>,
}

impl<'a> ActSpec<'a> {
    fn pending(id: &'a str) -> Self {
        ActSpec {
            id,
            expires_in_min: 30,
            asserted: false,
            outcome: None,
            consumed: false,
            path: None,
        }
    }

    fn json(&self) -> Value {
        let now = Utc::now();
        let at = |min: i64| (now + Duration::minutes(min)).to_rfc3339();
        json!({
            "id": self.id,
            "kind": "role.grant",
            "args": {"agent_id": TARGET, "role": "platform-custodian"},
            "args_digest": "ab".repeat(32),
            "target_type": "agent",
            "target_id": TARGET,
            "reason": format!("reason for {}", self.id),
            "elevation_id": ELEVATION,
            "proposed_at": at(-10),
            "expires_at": at(self.expires_in_min),
            "asserted_at": if self.asserted { Value::String(at(-5)) } else { Value::Null },
            "outcome": self.outcome,
            "refusal": if self.outcome == Some("refused") { json!("credential_revoked") } else { Value::Null },
            "consumed_at": if self.consumed { Value::String(at(-1)) } else { Value::Null },
            "path": self.path.clone().unwrap_or_else(|| format!("/elevate/act/{}", self.id)),
        })
    }
}

/// The probe: `?mine&limit=1`.
fn probe() -> wiremock::MockBuilder {
    Mock::given(method("GET"))
        .and(path(ACTS_PATH))
        .and(query_param("mine", ""))
        .and(query_param("limit", "1"))
}

/// The page's own listing: `?mine&limit=50`.
fn listing() -> wiremock::MockBuilder {
    Mock::given(method("GET"))
        .and(path(ACTS_PATH))
        .and(query_param("mine", ""))
        .and(query_param("limit", "50"))
}

fn acts_body(acts: &[ActSpec<'_>]) -> Value {
    json!({ "acts": acts.iter().map(ActSpec::json).collect::<Vec<_>>() })
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

/// App whose link-out origin is [`API_ORIGIN`].
async fn with_api_origin() -> TestApp {
    spawn_with(&[(ENV_OAUTH_BASE_URL, API_ORIGIN)], Router::new()).await
}

/// The `<li>` of one act, sliced from the page.
fn act_row<'b>(body: &'b str, id: &str) -> &'b str {
    let start = body
        .find(&format!("data-act=\"{id}\""))
        .unwrap_or_else(|| panic!("no row for act {id} in: {body}"));
    let rest = &body[start..];
    let end = rest.find("</li>").expect("row closes");
    &rest[..end]
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

/// An unknown the API itself caused (here a 502) is remembered briefly, so a
/// failing API does not get a probe, and the page a probe deadline, in front
/// of every signed-in page. It still hides the item.
#[tokio::test]
async fn probe_unknown_on_a_server_error_is_remembered_briefly() {
    let app = spawn().await;
    probe_answers(&app, 502, 1).await;
    let sid = app.sign_in("tok");
    for _ in 0..3 {
        let res = app.get_as(&header_page(), &sid).await;
        assert_eq!(res.status, 200, "{}", res.body);
        assert!(!res.body.contains("Admin acts"), "{}", res.body);
    }
    // One probe for three pages.
    app.upstream.verify().await;
    assert_eq!(
        app.state.capabilities.cached_admin_acts(),
        Some(epigraph_explorer::upstream::capabilities::Capability::Unknown)
    );
}

/// The app's capability memory is built with the documented lifetimes: five
/// minutes for a present/absent answer, thirty seconds for an API-side
/// unknown. Pinned as values, so neither a never-expiring cache (an "absent"
/// cached before the elevation stack deploys would hide the item until a
/// restart) nor a change to the constants passes unnoticed.
#[tokio::test]
async fn the_app_remembers_probe_answers_for_the_documented_lifetimes() {
    let app = spawn().await;
    assert_eq!(
        app.state.capabilities.ttl(),
        std::time::Duration::from_secs(5 * 60)
    );
    assert_eq!(
        app.state.capabilities.unknown_ttl(),
        std::time::Duration::from_secs(30)
    );
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

// ---- the /acts page ------------------------------------------------------------

/// Present: the page lists the viewer's acts (decoding `{acts: [...]}`), and
/// a pending act links out to the API's own confirmation page, on the API's
/// public origin, in a new tab, with no referrer. Never the Explorer's
/// origin, never the internal API URL.
#[tokio::test]
async fn probe_present_lists_acts_with_api_origin_links() {
    let app = with_api_origin().await;
    probe_answers(&app, 200, 1).await;
    listing()
        .and(header("authorization", "Bearer tok"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(acts_body(&[ActSpec::pending(ACT_PENDING)])),
        )
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("{BASE}/acts"), &sid).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert!(res.body.contains(NAV_ITEM), "nav item on the page itself");
    assert!(res.body.contains("data-acts=\"listed\""), "{}", res.body);

    let row = act_row(&res.body, ACT_PENDING);
    assert!(row.contains("data-act-status=\"pending\""), "{row}");
    assert!(row.contains("role.grant"), "kind shown: {row}");
    assert!(row.contains(&format!("reason for {ACT_PENDING}")), "{row}");
    let link = format!(
        "<a href=\"{API_ORIGIN}/elevate/act/{ACT_PENDING}\" target=\"_blank\" rel=\"noreferrer noopener\""
    );
    assert!(row.contains(&link), "link to the API origin: {row}");
    assert!(
        !res.body.contains(&app.upstream.uri()),
        "internal API URL leaked"
    );
    assert!(
        !res.body.contains("explorer.example.com/elevate"),
        "the Explorer never serves or proxies the ceremony"
    );
    app.upstream.verify().await;
}

/// Only a pending act (unasserted, unconsumed, unexpired) gets a link:
/// confirmed, refused, executed and expired acts are listed without one.
#[tokio::test]
async fn only_pending_acts_get_a_link() {
    let app = with_api_origin().await;
    probe_answers(&app, 200, 1).await;
    let acts = [
        ActSpec::pending(ACT_PENDING),
        ActSpec {
            asserted: true,
            outcome: Some("confirmed"),
            ..ActSpec::pending(ACT_CONFIRMED)
        },
        ActSpec {
            asserted: true,
            outcome: Some("confirmed"),
            consumed: true,
            ..ActSpec::pending(ACT_EXECUTED)
        },
        ActSpec {
            expires_in_min: -1,
            ..ActSpec::pending(ACT_EXPIRED)
        },
        ActSpec {
            asserted: true,
            outcome: Some("refused"),
            ..ActSpec::pending(ACT_REFUSED)
        },
    ];
    listing()
        .respond_with(ResponseTemplate::new(200).set_body_json(acts_body(&acts)))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("{BASE}/acts"), &sid).await;
    assert_eq!(res.status, 200, "{}", res.body);

    assert!(act_row(&res.body, ACT_PENDING).contains("/elevate/act/"));
    for (id, status) in [
        (ACT_CONFIRMED, "confirmed"),
        (ACT_EXECUTED, "executed"),
        (ACT_EXPIRED, "expired"),
        (ACT_REFUSED, "refused"),
    ] {
        let row = act_row(&res.body, id);
        assert!(
            row.contains(&format!("data-act-status=\"{status}\"")),
            "{id}: {row}"
        );
        assert!(!row.contains("/elevate/act/"), "{id} must not link: {row}");
        assert!(!row.contains("<a "), "{id} must not link: {row}");
    }
    assert_eq!(
        res.body.matches("/elevate/act/").count(),
        1,
        "exactly one link"
    );
}

/// The link is the response's own `path`, used only when it is exactly the
/// act's own confirmation page. Anything else (another origin, another
/// page, another act, a query, a traversal) renders the row with no link.
#[tokio::test]
async fn act_link_with_a_foreign_path_is_not_rendered() {
    let app = with_api_origin().await;
    probe_answers(&app, 200, 1).await;
    let ids = [
        "00000000-0000-4000-8000-0000000000e1",
        "00000000-0000-4000-8000-0000000000e2",
        "00000000-0000-4000-8000-0000000000e3",
        "00000000-0000-4000-8000-0000000000e4",
        "00000000-0000-4000-8000-0000000000e5",
        "00000000-0000-4000-8000-0000000000e6",
        "00000000-0000-4000-8000-0000000000e7",
    ];
    let paths = [
        "//evil.example/x".to_string(),
        "/elsewhere".to_string(),
        format!("/elevate/act/{ACT_OTHER}"),
        format!("/elevate/act/{}?next=//evil.example", ids[3]),
        format!("/elevate/act/../../{}", ids[4]),
        format!("https://evil.example/elevate/act/{}", ids[5]),
        format!("/elevate/act//{}", ids[6]),
    ];
    let acts: Vec<ActSpec<'_>> = ids
        .iter()
        .zip(paths.iter())
        .map(|(id, p)| ActSpec {
            path: Some(p.clone()),
            ..ActSpec::pending(id)
        })
        .collect();
    listing()
        .respond_with(ResponseTemplate::new(200).set_body_json(acts_body(&acts)))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("{BASE}/acts"), &sid).await;
    assert_eq!(res.status, 200, "{}", res.body);
    for id in ids {
        let row = act_row(&res.body, id);
        assert!(row.contains("data-act-status=\"pending\""), "{row}");
        assert!(!row.contains("<a "), "{id}: a foreign path linked: {row}");
    }
    assert!(!res.body.contains("evil.example"), "{}", res.body);
    assert!(!res.body.contains("/elsewhere"), "{}", res.body);
}

/// The page sends `frame-ancestors 'none'` and `no-referrer`, on both mounts
/// and on its sign-in redirect; other pages keep the configured framing.
#[tokio::test]
async fn acts_page_is_not_framable() {
    let app = with_api_origin().await;
    probe_answers(&app, 200, 1).await;
    listing()
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acts": []})))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    for uri in [format!("{BASE}/acts"), "/acts".to_string()] {
        let res = app.get_as(&uri, &sid).await;
        assert_eq!(res.status, 200, "{uri}: {}", res.body);
        let csp = res.header("content-security-policy").unwrap_or_default();
        assert!(csp.ends_with("frame-ancestors 'none'"), "{uri}: {csp}");
        assert_eq!(res.header("referrer-policy"), Some("no-referrer"), "{uri}");
    }
    let anon = app.get(&format!("{BASE}/acts")).await;
    assert_eq!(anon.status, 303);
    let csp = anon.header("content-security-policy").unwrap_or_default();
    assert!(csp.ends_with("frame-ancestors 'none'"), "redirect: {csp}");

    let other = app.get_as(&header_page(), &sid).await;
    let csp = other.header("content-security-policy").unwrap_or_default();
    assert!(!csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(csp.contains("frame-ancestors https://"), "{csp}");
    assert_eq!(other.header("referrer-policy"), Some("same-origin"));
}

/// Visited directly against an API without the route: the page says so,
/// with 200, never 501 or 500, and shows no nav item.
#[tokio::test]
async fn acts_page_without_the_route_says_so() {
    let app = spawn().await;
    probe_answers(&app, 404, 1).await;
    listing()
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "NotFound"})))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("{BASE}/acts"), &sid).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert!(res.body.contains("data-acts=\"absent\""), "{}", res.body);
    assert!(!res.body.contains("Not yet available"));
    assert!(!res.body.contains(NAV_ITEM));
    app.upstream.verify().await;
}

/// 403 from the listing: "no access", not an error page; a 5xx: unavailable.
#[tokio::test]
async fn acts_page_forbidden_and_failed_states() {
    let app = spawn().await;
    probe_answers(&app, 403, 1).await;
    listing()
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": "Forbidden"})))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&app.upstream)
        .await;
    listing()
        .respond_with(ResponseTemplate::new(500))
        .with_priority(2)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("{BASE}/acts"), &sid).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert!(res.body.contains("data-acts=\"forbidden\""), "{}", res.body);
    let res = app.get_as(&format!("{BASE}/acts"), &sid).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert!(
        res.body.contains("data-acts=\"unavailable\""),
        "{}",
        res.body
    );
}

/// An empty listing is a state of its own, not an error.
#[tokio::test]
async fn acts_page_with_no_acts_says_so() {
    let app = spawn().await;
    probe_answers(&app, 200, 1).await;
    listing()
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acts": []})))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("{BASE}/acts"), &sid).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert!(res.body.contains("data-acts=\"empty\""), "{}", res.body);
}

#[tokio::test]
async fn acts_require_sign_in_and_make_no_anonymous_call() {
    let app = spawn().await;
    let res = app.get(&format!("{BASE}/acts")).await;
    assert_eq!(res.status, 303);
    let calls = app.upstream.received_requests().await.unwrap_or_default();
    assert!(calls.is_empty(), "called upstream: {calls:?}");
}
