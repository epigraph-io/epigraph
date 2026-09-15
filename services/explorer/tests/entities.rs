//! Entities pages against a wiremock upstream: `/claim/:id/history` and
//! `/claim/:id/provenance`.
//!
//! Upstream JSON is shaped exactly as the mapping reports record it
//! (claims-endpoints §7, plan §2.1), including omitted optional fields, both
//! error-body formats and redaction.

mod common;

use axum::http::StatusCode;
use common::{spawn, TestApp};
use serde_json::{json, Value};
use wiremock::matchers::{any, header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const CLAIM: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const V1: &str = "11111111-5f43-4c4b-9a52-3f0d1e2c7a10";
const V3: &str = "33333333-5f43-4c4b-9a52-3f0d1e2c7a10";
const ANC: &str = "44444444-5f43-4c4b-9a52-3f0d1e2c7a10";
const OLD: &str = "55555555-5f43-4c4b-9a52-3f0d1e2c7a10";
const HIDDEN: &str = "66666666-5f43-4c4b-9a52-3f0d1e2c7a10";
const AGENT: &str = "a9e7c1d2-0000-4c4b-9a52-3f0d1e2c7a10";

const HOSTILE: &str = "<script>alert(1)</script>";
const HOSTILE_ATTR: &str = "\"><img src=x onerror=alert(2)>";

fn json_404(entity: &str, id: &str) -> ResponseTemplate {
    ResponseTemplate::new(404).set_body_json(json!({
        "error": "NotFound",
        "message": format!("{entity} with ID {id} not found"),
        "details": {"entity": entity, "id": id}
    }))
}

fn ok(body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

async fn get_ok(app: &TestApp, route: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ok(body))
        .mount(&app.upstream)
        .await;
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

fn assert_escaped(body: &str) {
    assert!(!body.contains("<script>alert(1)"), "raw script tag leaked");
    assert!(
        body.contains("&#60;script&#62;alert(1)"),
        "escaped text shown"
    );
    assert!(
        !body.contains("<img src=x"),
        "raw attribute breakout leaked"
    );
    assert!(!body.contains("href=\"javascript:"), "javascript: link");
}

fn claim_json(content: &str) -> Value {
    // GET /claims/:id omits `labels` when empty and every privacy field.
    json!({
        "id": CLAIM,
        "content": content,
        "truth_value": 0.8,
        "agent_id": AGENT,
        "trace_id": null,
        "created_at": "2026-01-02T03:04:05Z",
        "updated_at": "2026-01-02T03:04:05Z"
    })
}

// ---- auth and ids --------------------------------------------------------------

/// Every entities route; the claim sub-pages come first.
fn entity_pages(id: &str) -> [String; 5] {
    [
        format!("/explorer/claim/{id}/history"),
        format!("/explorer/claim/{id}/provenance"),
        format!("/explorer/agent/{id}"),
        format!("/explorer/frame/{id}"),
        format!("/explorer/evidence/{id}"),
    ]
}

#[tokio::test]
async fn entity_pages_require_sign_in() {
    let app = spawn().await;
    forbid_upstream(&app).await;
    for uri in entity_pages(CLAIM) {
        let res = app.get(&uri).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{uri}");
        let want = format!("/explorer/auth/login?return_to={}", uri.replace('/', "%2F"));
        assert_eq!(res.location(), Some(want.as_str()), "{uri}");
    }
    app.upstream.verify().await;
}

#[tokio::test]
async fn malformed_ids_are_404_without_an_upstream_call() {
    let app = spawn().await;
    forbid_upstream(&app).await;
    let sid = app.sign_in("tok");
    let whats = ["claim", "claim"];
    for bad in ["not-a-uuid", "0b9a5a4e-5f43-4c4b-9a52", "%3Cscript%3E"] {
        for (uri, what) in entity_pages(bad).iter().zip(whats) {
            let res = app.get_as(uri, &sid).await;
            assert_eq!(res.status, StatusCode::NOT_FOUND, "{uri}");
            assert!(
                res.body
                    .contains(&format!("We could not find that {what}.")),
                "{uri}"
            );
            assert!(!res.body.contains("<script>"), "{uri}");
        }
    }
    app.upstream.verify().await;
}

#[tokio::test]
async fn entity_routes_answer_with_and_without_the_base_path() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    get_ok(&app, &format!("/api/v1/claims/{CLAIM}"), claim_json("c")).await;
    get_ok(
        &app,
        &format!("/api/v1/claims/{CLAIM}/history"),
        history_json(),
    )
    .await;
    get_ok(
        &app,
        &format!("/api/v1/claims/{CLAIM}/provenance-chain"),
        chain_json(false),
    )
    .await;

    for uri in entity_pages(CLAIM).iter().take(2) {
        for u in [uri.clone(), uri.trim_start_matches("/explorer").to_string()] {
            let res = app.get_as(&u, &sid).await;
            assert_eq!(res.status, StatusCode::OK, "{u}");
            assert!(res.header("content-type").unwrap().starts_with("text/html"));
            assert!(res.body.contains("/explorer/static/entities.css?v="), "{u}");
            assert!(!res.body.contains("not built yet"), "{u}");
            assert!(
                !res.body.contains("style="),
                "CSP forbids inline styles: {u}"
            );
            assert!(
                !res.body.contains("<script"),
                "CSP forbids inline scripts: {u}"
            );
        }
    }
}

#[tokio::test]
async fn entities_stylesheet_is_served() {
    let app = spawn().await;
    let res = app.get("/explorer/static/entities.css").await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.header("content-type").unwrap().starts_with("text/css"));
    assert!(res.body.contains(".version-list"));
}

// ---- /claim/:id/history --------------------------------------------------------

/// v1 superseded by the requested claim (current), then V3 — a duplicate
/// of the requested claim reached through `mark_duplicate`.
fn history_json() -> Value {
    json!({
        "claim_id": CLAIM,
        "versions": [
            {"claim_id": V1, "content": "Water boils at 99 °C.", "truth_value": 0.3,
             "version": 1, "is_current": false, "created_at": "2025-12-01T00:00:00Z",
             "superseded_by": CLAIM},
            {"claim_id": CLAIM, "content": "Water boils at 100 °C at sea level.",
             "truth_value": 0.8, "version": 2, "is_current": true,
             "created_at": "2026-01-02T03:04:05Z", "superseded_by": V3},
            {"claim_id": V3, "content": "Water boils at 100 degrees at sea level.",
             "truth_value": 0.8, "version": 3, "is_current": false,
             "created_at": "2026-02-02T03:04:05Z", "superseded_by": null}
        ],
        "total_versions": 3,
        "current_version": 2
    })
}

#[tokio::test]
async fn history_lists_versions_marking_current_superseded_and_duplicates() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}")))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(claim_json("Water boils at 100 °C at sea level.")))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/history")))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(history_json()))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/history"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = &res.body;
    for v in [V1, CLAIM, V3] {
        assert!(b.contains(&format!("href=\"/explorer/claim/{v}\"")), "{v}");
    }
    assert!(b.contains("Version 1") && b.contains("Version 2") && b.contains("Version 3"));
    assert_eq!(
        b.matches("badge--current").count(),
        1,
        "one current version"
    );
    assert!(b.contains("version--current version--requested"));
    assert!(b.contains("You are here"));
    assert_eq!(
        b.matches("badge--superseded").count(),
        1,
        "only v1 was superseded"
    );
    assert!(
        b.contains(&format!(
            "Duplicate of <a href=\"/explorer/claim/{CLAIM}\">version 2</a>"
        )),
        "{b}"
    );
    assert!(b.contains("folded into the"), "duplicate explanation");
    assert!(b.contains("2025-12-01 00:00 UTC"));
    // Not the political-propagation `/genealogy` route.
    assert!(app
        .upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|r| !r.url.path().ends_with("/genealogy")));
    app.upstream.verify().await;
}

#[tokio::test]
async fn history_escapes_hostile_content() {
    let app = spawn().await;
    get_ok(
        &app,
        &format!("/api/v1/claims/{CLAIM}"),
        claim_json(&format!("{HOSTILE}{HOSTILE_ATTR}")),
    )
    .await;
    get_ok(
        &app,
        &format!("/api/v1/claims/{CLAIM}/history"),
        json!({
            "claim_id": CLAIM,
            "versions": [{"claim_id": CLAIM, "content": HOSTILE, "truth_value": 0.5,
                          "version": 1, "is_current": true,
                          "created_at": HOSTILE_ATTR, "superseded_by": null}],
            "total_versions": 1, "current_version": 1
        }),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/history"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_escaped(&res.body);
}

#[tokio::test]
async fn history_of_a_redacted_claim_makes_no_content_bearing_call() {
    let app = spawn().await;
    get_ok(
        &app,
        &format!("/api/v1/claims/{CLAIM}"),
        claim_json("[REDACTED]"),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/history")))
        .respond_with(ok(history_json()))
        .expect(0)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/history"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("claim-text--redacted"));
    assert!(res.body.contains("version history is not shown"));
    assert!(!res.body.contains("[REDACTED]"));
    assert!(!res.body.contains("Water boils"));
    app.upstream.verify().await;
}

#[tokio::test]
async fn history_404s_when_the_claim_is_missing() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}")))
        .respond_with(json_404("Claim", CLAIM))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/history"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("We could not find that claim."));
}

#[tokio::test]
async fn history_section_degrades_when_the_history_call_fails() {
    for failure in [
        ResponseTemplate::new(500).set_body_json(json!({
            "error": "InternalError", "message": "boom"
        })),
        // axum's text/plain rejection body.
        ResponseTemplate::new(400)
            .insert_header("content-type", "text/plain; charset=utf-8")
            .set_body_string("Invalid URL: UUID parsing failed"),
    ] {
        let app = spawn().await;
        get_ok(&app, &format!("/api/v1/claims/{CLAIM}"), claim_json("c")).await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/claims/{CLAIM}/history")))
            .respond_with(failure)
            .mount(&app.upstream)
            .await;
        let sid = app.sign_in("tok");
        let res = app
            .get_as(&format!("/explorer/claim/{CLAIM}/history"), &sid)
            .await;
        assert_eq!(res.status, StatusCode::OK);
        assert!(res.body.contains("section-unavailable"));
        assert!(!res.body.contains("boom"), "upstream detail is never shown");
        assert!(
            !res.body.contains("UUID parsing"),
            "upstream detail is never shown"
        );
    }
}

// ---- /claim/:id/provenance -----------------------------------------------------

/// Root ← ANC (supports), root → OLD (supersedes; OLD not current),
/// ANC ← HIDDEN (redacted, depth 2), and a HIDDEN ↔ ANC cycle. Evidence
/// first, root last, as the repo's Kahn sort emits them.
fn chain_json(truncated: bool) -> Value {
    json!({
        "root": CLAIM,
        "nodes": [
            {"id": HIDDEN, "content": "[REDACTED]", "truth_value": 0.9, "labels": [],
             "is_current": true, "depth": 2, "redacted": true},
            {"id": ANC, "content": "Boiling point depends on pressure.", "truth_value": 0.7,
             "labels": ["physics"], "is_current": true, "depth": 1, "redacted": false},
            {"id": OLD, "content": "Water boils at 99 °C.", "truth_value": 0.3,
             "labels": [], "is_current": false, "depth": 1, "redacted": false},
            {"id": CLAIM, "content": "Water boils at 100 °C at sea level.", "truth_value": 0.8,
             "labels": [], "is_current": true, "depth": 0, "redacted": false}
        ],
        "edges": [
            {"source": ANC, "target": CLAIM, "relationship": "supports"},
            {"source": CLAIM, "target": OLD, "relationship": "supersedes"},
            {"source": HIDDEN, "target": ANC, "relationship": "corroborates"},
            {"source": ANC, "target": HIDDEN, "relationship": "elaborates"}
        ],
        "truncated": truncated,
        "cycles": [[ANC, HIDDEN]]
    })
}

#[tokio::test]
async fn provenance_renders_levels_edges_cycles_and_redaction() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/provenance-chain")))
        .and(query_param("max_depth", "3"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(chain_json(true)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(
            &format!("/explorer/claim/{CLAIM}/provenance?max_depth=3"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = &res.body;
    assert!(
        b.contains("Water boils at 100 °C at sea level."),
        "root heading"
    );
    assert!(b.contains("This claim"));
    assert!(b.contains("Direct sources · depth 1"));
    assert!(b.contains("Depth 2"));
    for id in [ANC, OLD, HIDDEN] {
        assert!(
            b.contains(&format!("href=\"/explorer/claim/{id}\"")),
            "{id}"
        );
    }
    // Edges are phrased from their upstream end.
    assert!(b.contains("<span class=\"rel\">supports</span>"));
    assert!(b.contains("<span class=\"rel\">superseded by</span>"));
    assert!(b.contains("<span class=\"rel\">corroborates</span>"));
    // The superseded ancestor is flagged; the redacted one is hidden.
    assert!(b.contains("chain-node--superseded"));
    assert!(b.contains("badge--superseded"));
    assert!(b.contains("badge--hidden"));
    assert!(b.contains("Hidden claim 66666666"));
    assert!(!b.contains("[REDACTED]"));
    // Cycles are listed.
    assert!(b.contains("id=\"cycles-title\""));
    assert!(b.contains("badge--cycle"));
    // Truncation is worded as a possibility, with a deeper walk offered.
    assert!(b.contains("may have more"));
    assert!(b.contains("ancestors that are not shown"));
    assert!(b.contains(&format!(
        "href=\"/explorer/claim/{CLAIM}/provenance?max_depth=5\""
    )));
    assert!(b.contains("<option value=\"3\" selected>"));
    assert!(b.contains("3 ancestors within 3 steps."));
    app.upstream.verify().await;
}

#[tokio::test]
async fn provenance_without_truncation_makes_no_completeness_claim() {
    let app = spawn().await;
    get_ok(
        &app,
        &format!("/api/v1/claims/{CLAIM}/provenance-chain"),
        chain_json(false),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/provenance"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(!res.body.contains("may have more"));
    assert!(!res.body.contains("notice--warn"));
    assert!(res.body.contains("3 ancestors within 4 steps."));
    assert!(
        res.body.contains("<option value=\"4\" selected>"),
        "default depth 4"
    );
}

#[tokio::test]
async fn provenance_depth_is_clamped_before_it_reaches_upstream() {
    for (asked, sent) in [("300", "8"), ("-2", "1"), ("abc", "4"), ("8", "8")] {
        let app = spawn().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/claims/{CLAIM}/provenance-chain")))
            .and(query_param("max_depth", sent))
            .respond_with(ok(chain_json(true)))
            .expect(1)
            .mount(&app.upstream)
            .await;
        let sid = app.sign_in("tok");
        let res = app
            .get_as(
                &format!("/explorer/claim/{CLAIM}/provenance?max_depth={asked}"),
                &sid,
            )
            .await;
        assert_eq!(res.status, StatusCode::OK, "{asked}");
        assert!(
            res.body
                .contains(&format!("<option value=\"{sent}\" selected>")),
            "{asked}"
        );
        if sent == "8" {
            assert!(res.body.contains("deepest walk"), "{asked}");
            assert!(!res.body.contains("max_depth=10"), "{asked}");
        }
        app.upstream.verify().await;
    }
}

#[tokio::test]
async fn provenance_with_no_ancestors_says_so() {
    let app = spawn().await;
    // Minimal node: optional fields omitted.
    get_ok(
        &app,
        &format!("/api/v1/claims/{CLAIM}/provenance-chain"),
        json!({"root": CLAIM, "nodes": [{"id": CLAIM, "content": "Lonely claim", "depth": 0}],
               "edges": [], "truncated": false, "cycles": []}),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/provenance"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Lonely claim"));
    assert!(res
        .body
        .contains("No claims were found that this claim derives from."));
    assert!(!res.body.contains("id=\"cycles-title\""));
}

#[tokio::test]
async fn provenance_404_and_upstream_failure() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/provenance-chain")))
        .respond_with(json_404("claim", CLAIM))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/provenance"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("We could not find that claim."));

    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/provenance-chain")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": "DatabaseError", "message": "pool timed out"
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/provenance"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::BAD_GATEWAY);
    assert!(!res.body.contains("pool timed out"));
}

#[tokio::test]
async fn provenance_escapes_hostile_content() {
    let app = spawn().await;
    get_ok(
        &app,
        &format!("/api/v1/claims/{CLAIM}/provenance-chain"),
        json!({
            "root": CLAIM,
            "nodes": [
                {"id": ANC, "content": HOSTILE_ATTR, "truth_value": 0.5,
                 "labels": [HOSTILE], "is_current": true, "depth": 1, "redacted": false},
                {"id": CLAIM, "content": HOSTILE, "truth_value": 0.5, "labels": [],
                 "is_current": true, "depth": 0, "redacted": false}
            ],
            "edges": [{"source": ANC, "target": CLAIM, "relationship": HOSTILE}],
            "truncated": false,
            "cycles": []
        }),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/provenance"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_escaped(&res.body);
}
