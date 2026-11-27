//! `/recalls`, the signed-in caller's own recall history, against a wiremock
//! upstream standing in for `GET /api/v1/recall-events` (backlog 39aad446).
//!
//! The upstream body is shaped as the route sends it: `{"items": [...],
//! "next_cursor": ...}`, each item carrying the MCP `get_recall_events`
//! fields, `next_cursor` null on the last page.

mod common;

use axum::http::StatusCode;
use common::{spawn, TestApp};
use serde_json::{json, Value};
use wiremock::matchers::{any, header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, ResponseTemplate};

const ME: &str = "a9e7c1d2-0000-4c4b-9a52-3f0d1e2c7a10";
const C1: &str = "11111111-5f43-4c4b-9a52-3f0d1e2c7a10";
const C2: &str = "22222222-5f43-4c4b-9a52-3f0d1e2c7a10";
const R1: &str = "0b9a5a4e-0001-4c4b-9a52-3f0d1e2c7a10";
const R2: &str = "0b9a5a4e-0002-4c4b-9a52-3f0d1e2c7a10";
const CURSOR: &str = "k1.1790000000000000.0f1e2d3c4b5a69788796a5b4c3d2e1f0";

const HOSTILE: &str = "<script>alert(1)</script>";

fn event(id: &str, query: &str, claims: &[&str], at: &str) -> Value {
    json!({
        "id": id,
        "agent_id": ME,
        "tool": "recall",
        "query_text": query,
        "query_embedding_hash": "ab".repeat(32),
        "params": {"limit": 10},
        "returned_claim_ids": claims,
        "created_at": at
    })
}

/// Fails the test (on `verify`) if anything reaches upstream.
async fn forbid_upstream(app: &TestApp) {
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .named("no upstream call expected")
        .with_priority(u8::MAX)
        .mount(&app.upstream)
        .await;
}

#[tokio::test]
async fn recall_history_requires_sign_in() {
    let app = spawn().await;
    forbid_upstream(&app).await;
    let res = app.get("/explorer/recalls").await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(
        res.location(),
        Some("/explorer/auth/login?return_to=%2Fexplorer%2Frecalls")
    );
    app.upstream.verify().await;
}

/// The first page: the caller's bearer goes upstream with a `limit` and no
/// `after`; each recall shows its query text, its time, its tool and a link
/// to every claim it returned; a `next_cursor` becomes an "Older" link.
#[tokio::test]
async fn the_first_page_lists_recalls_with_links_to_their_claims() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/recall-events"))
        .and(header("authorization", "Bearer tok-me"))
        .and(query_param("limit", "25"))
        .and(query_param_is_missing("after"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                event(R2, "what boils water", &[C1, C2], "2026-11-20T10:30:00+00:00"),
                event(R1, "an older question", &[], "2026-11-19T08:00:00+00:00"),
            ],
            "next_cursor": CURSOR
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok-me");
    let res = app.get_as("/explorer/recalls", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let body = &res.body;
    assert!(body.contains("what boils water"), "{body}");
    assert!(body.contains("an older question"));
    assert!(body.contains("2026-11-20 10:30 UTC"), "{body}");
    assert!(
        body.contains(&format!("href=\"/explorer/claim/{C1}\"")),
        "{body}"
    );
    assert!(body.contains(&format!("href=\"/explorer/claim/{C2}\"")));
    assert!(body.contains("2 claims returned"));
    assert!(
        body.contains(&format!("href=\"/explorer/recalls?after={CURSOR}\"")),
        "an Older link carries next_cursor: {body}"
    );
    assert!(
        !body.contains(">Newest<"),
        "no Newest link on the first page"
    );
    app.upstream.verify().await;
}

/// `?after=` is forwarded unchanged; a null `next_cursor` ends the walk (no
/// "Older" link) and the page offers the way back to the newest recalls.
#[tokio::test]
async fn a_later_page_forwards_the_cursor_and_ends_on_a_null_one() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/recall-events"))
        .and(query_param("after", CURSOR))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [event(R1, "the last one", &[C1], "2026-11-01T00:00:00Z")],
            "next_cursor": null
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/recalls?after={CURSOR}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("the last one"));
    assert!(!res.body.contains("rel=\"next\""), "{}", res.body);
    assert!(
        res.body.contains(">Newest</a>"),
        "a Newest link: {}",
        res.body
    );
    app.upstream.verify().await;
}

/// A cursor outside the route's token alphabet is not forwarded (it could
/// smuggle other query parameters); the page starts from the newest recall.
#[tokio::test]
async fn a_malformed_cursor_is_not_forwarded() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/recall-events"))
        .and(query_param_is_missing("after"))
        .and(query_param_is_missing("agent_id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [], "next_cursor": null
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as("/explorer/recalls?after=x%26agent_id%3Dsomeone", &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("not run a recall"), "{}", res.body);
    app.upstream.verify().await;
}

#[tokio::test]
async fn an_empty_history_says_so() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/recall-events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [], "next_cursor": null
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/recalls", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        res.body.contains("You have not run a recall yet."),
        "{}",
        res.body
    );
    assert!(!res.body.contains("class=\"pager\""));
}

#[tokio::test]
async fn query_text_is_escaped() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/recall-events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [event(R1, HOSTILE, &[C1], "2026-11-01T00:00:00Z")],
            "next_cursor": null
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/recalls", &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        !res.body.contains("<script>alert(1)"),
        "raw script tag leaked"
    );
    assert!(
        res.body.contains("&#60;script&#62;alert(1)"),
        "{}",
        res.body
    );
}

/// An upstream failure degrades the list to a notice; upstream's own error
/// text is never shown.
#[tokio::test]
async fn the_list_degrades_when_the_upstream_call_fails() {
    for failure in [
        ResponseTemplate::new(500).set_body_json(json!({
            "error": "InternalError", "message": "boom"
        })),
        ResponseTemplate::new(403).set_body_json(json!({
            "error": "Forbidden", "message": "missing scope claims:read"
        })),
    ] {
        let app = spawn().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/recall-events"))
            .respond_with(failure)
            .mount(&app.upstream)
            .await;
        let sid = app.sign_in("tok");
        let res = app.get_as("/explorer/recalls", &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.body);
        assert!(res.body.contains("section-unavailable"), "{}", res.body);
        assert!(!res.body.contains("boom"));
        assert!(!res.body.contains("missing scope"));
    }
}

/// Signed-in pages link to the history from the header.
#[tokio::test]
async fn the_header_links_a_signed_in_viewer_to_their_recalls() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/recall-events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [], "next_cursor": null
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/recalls", &sid).await;
    assert!(
        res.body
            .contains("href=\"/explorer/recalls\">My recalls</a>"),
        "{}",
        res.body
    );
}
