//! The backlog page (J3) against a wiremock upstream: open items only
//! (`backlog`, not `resolved`, current versions), newest first as upstream
//! orders them, a one-label sub-filter, offset paging, and an empty list
//! that is told apart from a failed one.
//!
//! Every by-labels mock carries the full query the page must send, and each
//! test asserts the mocked rows (or the empty-state text) actually rendered:
//! a request that matches no mock gets wiremock's 404, which the page
//! degrades to "unavailable" with a 200, so a status check alone would pass
//! with the wrong query.

mod common;

use axum::http::StatusCode;
use axum::Router;
use common::{spawn, spawn_with, BASE};
use serde_json::{json, Value};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockBuilder, ResponseTemplate};

const AGENT: &str = "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
/// Created later than [`OLDER`]; upstream lists it first.
const NEWER: &str = "0c0c0c0c-0000-4000-8000-00000000000c";
const OLDER: &str = "0d0d0d0d-0000-4000-8000-00000000000d";

const EMPTY_TEXT: &str = "No open backlog items";
const UNAVAILABLE_TEXT: &str = "The backlog is unavailable";

fn item(id: &str, content: &str, created_at: &str, labels: &[&str]) -> Value {
    json!({
        "id": id, "content": content, "truth_value": 0.5, "agent_id": AGENT,
        "created_at": created_at, "labels": labels, "is_current": true, "supersedes": null
    })
}

/// `GET /api/v1/claims/by-labels` with every parameter the backlog page
/// must send for one page.
fn by_labels(labels: &str, offset: &str) -> MockBuilder {
    Mock::given(method("GET"))
        .and(path("/api/v1/claims/by-labels"))
        .and(query_param("labels", labels))
        .and(query_param("exclude_labels", "resolved"))
        .and(query_param("current_only", "true"))
        .and(query_param("limit", "20"))
        .and(query_param("offset", offset))
}

/// J3: the list is current claims labelled `backlog` and NOT labelled
/// `resolved`, newest first. Upstream does both the filtering and the
/// ordering (`ORDER BY created_at DESC`); the page must ask for the
/// exclusion and must not re-sort.
#[tokio::test]
async fn backlog_excludes_resolved_items() {
    let app = spawn().await;
    by_labels("backlog", "0")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            item(
                NEWER,
                "Newer open item",
                "2026-03-04T05:06:07+00:00",
                &["backlog", "bug"]
            ),
            item(
                OLDER,
                "Older open item",
                "2026-01-02T03:04:05+00:00",
                &["backlog"]
            ),
        ])))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&format!("{BASE}/backlog"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let newer = res
        .body
        .find(&format!("href=\"{BASE}/claim/{NEWER}\""))
        .unwrap_or_else(|| panic!("newer item not linked: {}", res.body));
    let older = res
        .body
        .find(&format!("href=\"{BASE}/claim/{OLDER}\""))
        .unwrap_or_else(|| panic!("older item not linked: {}", res.body));
    assert!(newer < older, "upstream's newest-first order is kept");
    assert!(res.body.contains("Newer open item") && res.body.contains("Older open item"));
    assert!(res.body.contains("2026-03-04"), "created date shown");
    assert!(!res.body.contains("section-unavailable"), "{}", res.body);
    assert!(!res.body.contains(EMPTY_TEXT));
    assert!(!res.body.contains("Not yet available"), "still the stub");
    app.upstream.verify().await;
}

/// J3: a sub-label narrows the list (a claim must carry `backlog` AND the
/// sub-label), the filter is shown with a way to clear it, and each row's
/// other labels link to the same filter. `backlog` itself, or an empty
/// value, is no filter.
#[tokio::test]
async fn backlog_sub_label_filter_narrows_the_list() {
    let app = spawn().await;
    by_labels("backlog,bug", "0")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([item(
            NEWER,
            "A bug to fix",
            "2026-03-04T05:06:07+00:00",
            &["backlog", "bug", "ui"]
        )])))
        .expect(1)
        .mount(&app.upstream)
        .await;
    by_labels("backlog", "0")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([item(
            OLDER,
            "Unfiltered item",
            "2026-01-02T03:04:05+00:00",
            &["backlog"]
        )])))
        .expect(2)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(&format!("{BASE}/backlog?label=+bug+"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("A bug to fix"), "{}", res.body);
    assert!(!res.body.contains("Unfiltered item"));
    assert!(
        res.body.contains(&format!(
            "href=\"{BASE}/backlog\">Show the whole backlog</a>"
        )),
        "a way back to the whole backlog (not just the header nav link)"
    );
    assert!(
        res.body
            .contains(&format!("href=\"{BASE}/backlog?label=ui\"")),
        "row labels link to their filter: {}",
        res.body
    );
    assert!(
        !res.body
            .contains(&format!("href=\"{BASE}/backlog?label=backlog\"")),
        "backlog itself is not a sub-label"
    );

    for uri in [
        format!("{BASE}/backlog?label="),
        format!("{BASE}/backlog?label=backlog"),
    ] {
        let res = app.get_as(&uri, &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}");
        assert!(res.body.contains("Unfiltered item"), "{uri}: {}", res.body);
    }
    app.upstream.verify().await;
}

/// Upstream ANDs comma-separated labels, so a comma in the sub-label would
/// silently become a narrower filter than the one shown. The page says so
/// and makes no call.
#[tokio::test]
async fn backlog_refuses_a_multi_label_filter_without_calling_upstream() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("{BASE}/backlog?label=bug%2Cui"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("one label at a time"), "{}", res.body);
    let calls = app.upstream.received_requests().await.unwrap_or_default();
    assert!(calls.is_empty(), "called upstream: {calls:?}");
}

/// Offset paging, as label search does: no total exists upstream, so a
/// "next" link appears while a page is full, and page 2 asks for offset 20.
/// The sub-label filter survives paging.
#[tokio::test]
async fn backlog_pages_by_offset_while_pages_are_full() {
    let app = spawn().await;
    let row = |i: usize| {
        item(
            &format!("0000000{}-0000-4000-8000-{:012}", i % 10, i),
            &format!("Backlog item {i}"),
            "2026-01-02T03:04:05+00:00",
            &["backlog", "bug"],
        )
    };
    for (offset, n) in [("0", 20usize), ("20", 3)] {
        by_labels("backlog,bug", offset)
            .respond_with(
                ResponseTemplate::new(200).set_body_json(Value::Array((0..n).map(row).collect())),
            )
            .expect(1)
            .mount(&app.upstream)
            .await;
    }
    let sid = app.sign_in("tok");

    let res = app.get_as(&format!("{BASE}/backlog?label=bug"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("Backlog item 19"));
    assert!(
        res.body.contains(&format!(
            "href=\"{BASE}/backlog?label=bug&#38;page=2\" rel=\"next\""
        )),
        "{}",
        res.body
    );
    assert!(!res.body.contains("rel=\"prev\""));

    let res = app
        .get_as(&format!("{BASE}/backlog?label=bug&page=2"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Backlog item 2"));
    assert!(res.body.contains(&format!(
        "href=\"{BASE}/backlog?label=bug&#38;page=1\" rel=\"prev\""
    )));
    assert!(
        !res.body.contains("rel=\"next\""),
        "a short page is the last"
    );
    app.upstream.verify().await;
}

/// J3: an empty result says "no open backlog items", not an error.
#[tokio::test]
async fn backlog_empty_state_is_not_an_error() {
    let app = spawn().await;
    by_labels("backlog", "0")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&format!("{BASE}/backlog"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains(EMPTY_TEXT), "{}", res.body);
    assert!(!res.body.contains("section-unavailable"), "{}", res.body);
    assert!(!res.body.contains(UNAVAILABLE_TEXT));
    app.upstream.verify().await;
}

/// The twin: a failed list is "unavailable", never the empty state, and
/// the rest of the page still renders.
#[tokio::test]
async fn backlog_upstream_failure_is_unavailable_not_empty() {
    let app = spawn().await;
    by_labels("backlog", "0")
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": "InternalError", "message": "boom"
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as(&format!("{BASE}/backlog"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("section-unavailable"), "{}", res.body);
    assert!(res.body.contains(UNAVAILABLE_TEXT), "{}", res.body);
    assert!(
        !res.body.contains(EMPTY_TEXT),
        "a failure is not an empty backlog"
    );
    assert!(
        res.body.contains("<h1>Backlog</h1>"),
        "the page still renders"
    );
    app.upstream.verify().await;
}

/// Signed-in only, like every MVP page: an anonymous viewer is sent to sign
/// in and nothing is asked of upstream.
#[tokio::test]
async fn backlog_requires_sign_in_and_makes_no_anonymous_call() {
    let app = spawn().await;
    let res = app.get(&format!("{BASE}/backlog")).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    let calls = app.upstream.received_requests().await.unwrap_or_default();
    assert!(calls.is_empty(), "called upstream: {calls:?}");
}

/// J3: each row has an "open in kanban" link only when a kanban base URL is
/// configured (`EPIGRAPH_EXPLORER_KANBAN_URL`), and no kanban link at all
/// otherwise. The board has no per-item address, so the link opens the
/// board; it opens in a new tab and sends no referrer (the board is another
/// origin).
#[tokio::test]
async fn kanban_link_only_when_configured() {
    const KANBAN: &str = "https://kanban.example.com/";
    let link = format!(
        "href=\"{KANBAN}\" target=\"_blank\" rel=\"noreferrer noopener\">Open in kanban</a>"
    );
    for configured in [false, true] {
        let env: &[(&str, &str)] = if configured {
            &[("EPIGRAPH_EXPLORER_KANBAN_URL", KANBAN)]
        } else {
            &[]
        };
        let app = spawn_with(env, Router::new()).await;
        by_labels("backlog", "0")
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                item(
                    NEWER,
                    "Newer open item",
                    "2026-03-04T05:06:07+00:00",
                    &["backlog"]
                ),
                item(
                    OLDER,
                    "Older open item",
                    "2026-01-02T03:04:05+00:00",
                    &["backlog"]
                ),
            ])))
            .expect(1)
            .mount(&app.upstream)
            .await;
        let sid = app.sign_in("tok");

        let res = app.get_as(&format!("{BASE}/backlog"), &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.body);
        assert!(
            res.body.contains("Newer open item") && res.body.contains("Older open item"),
            "{}",
            res.body
        );
        if configured {
            assert_eq!(
                res.body.matches(&link).count(),
                2,
                "one kanban link per row: {}",
                res.body
            );
        } else {
            assert!(!res.body.contains("Open in kanban"), "{}", res.body);
            assert!(!res.body.contains("kanban.example.com"));
        }
        app.upstream.verify().await;
    }
}
