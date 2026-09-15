//! Entities pages against a wiremock upstream: `/claim/:id/history`,
//! `/claim/:id/provenance`, `/agent/:id`, `/frame/:id`, `/evidence/:id`.
//!
//! Upstream JSON is shaped exactly as the mapping reports record it
//! (claims-endpoints §7, graph-entity-endpoints §4-§9, plan §2.1), including
//! omitted optional fields, both error-body formats and redaction.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use axum::Router;
use common::{spawn, spawn_with, TestApp};
use epigraph_explorer::config::ENV_UPSTREAM_TIMEOUT_MS;
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
const FRAME: &str = "f4a3e2d1-0000-4c4b-9a52-3f0d1e2c7a10";
const PARENT_FRAME: &str = "f4a3e2d1-1111-4c4b-9a52-3f0d1e2c7a10";
const EVIDENCE: &str = "e1d2c3b4-0000-4c4b-9a52-3f0d1e2c7a10";

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
    let whats = ["claim", "claim", "agent", "frame", "evidence"];
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
    get_ok(&app, &format!("/api/v1/agents/{CLAIM}"), agent_json(CLAIM)).await;
    get_ok(
        &app,
        &format!("/api/v1/agents/{CLAIM}/claims"),
        json!({"items": [], "total": 0, "limit": 20, "offset": 0}),
    )
    .await;
    get_ok(
        &app,
        &format!("/api/v1/agents/{CLAIM}/epistemic-profile"),
        profile_json(CLAIM),
    )
    .await;
    get_ok(&app, &format!("/api/v1/frames/{CLAIM}"), frame_json(CLAIM)).await;
    get_ok(&app, &format!("/api/v1/frames/{CLAIM}/claims"), json!([])).await;
    get_ok(
        &app,
        &format!("/api/v1/evidence/{CLAIM}"),
        minimal_evidence_json(CLAIM),
    )
    .await;

    for uri in entity_pages(CLAIM) {
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

// ---- /agent/:id ----------------------------------------------------------------

fn agent_json(id: &str) -> Value {
    json!({
        "id": id,
        "display_name": "Ada Lovelace",
        "public_key": "ab".repeat(32),
        "created_at": "2026-01-02T03:04:05Z",
        "labels": ["author"],
        "orcid": "0000-0002-1825-0097",
        "ror_id": null
    })
}

fn attributed_json(n: usize, total: i64, offset: i64) -> Value {
    let items: Vec<Value> = (0..n)
        .map(|i| {
            json!({
                "id": format!("c0000000-0000-4000-8000-{:012}", offset as usize + i),
                "content": format!("Attributed claim number {}", offset as usize + i),
                "truth_value": 0.6,
                "agent_id": AGENT,
                "trace_id": null,
                "created_at": "2026-01-02T03:04:05Z",
                "updated_at": "2026-01-02T03:04:05Z",
                "attribution": {"position": i}
            })
        })
        .collect();
    json!({"items": items, "total": total, "limit": 20, "offset": offset})
}

fn profile_json(id: &str) -> Value {
    let topics: Vec<String> = (0..45).map(|i| format!("topic-{i}")).collect();
    json!({
        "agent_id": id,
        "display_name": "Ada Lovelace",
        "claim_count": 57,
        "evidence_distribution": {"document": 0.25, "observation": 0.75},
        "epistemic_status_distribution": {"active": 0.9, "refuted": 0.1},
        "mean_truth_value": 0.64,
        "refutation_rate": 0.1,
        "topics": topics,
        "time_range": {"first": "2025-01-01T00:00:00Z", "last": "2026-01-01T00:00:00Z"}
    })
}

#[tokio::test]
async fn agent_page_renders_profile_attributed_claims_and_epistemic_profile() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{AGENT}")))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(agent_json(AGENT)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{AGENT}/claims")))
        .and(query_param("limit", "20"))
        .and(query_param("offset", "0"))
        .respond_with(ok(attributed_json(20, 45, 0)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    get_ok(
        &app,
        &format!("/api/v1/agents/{AGENT}/epistemic-profile"),
        profile_json(AGENT),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/agent/{AGENT}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = &res.body;
    assert!(b.contains("<h1>Ada Lovelace</h1>"));
    assert!(b.contains("href=\"https://orcid.org/0000-0002-1825-0097\""));
    assert!(b.contains("Attributed claims"));
    assert!(!b.contains("Authored claims"));
    assert!(b.contains("Attributed claim number 0"));
    assert!(b.contains("href=\"/explorer/claim/c0000000-0000-4000-8000-000000000019\""));
    assert!(b.contains("Showing 1–20 of 45."));
    assert!(b.contains(&format!(
        "href=\"/explorer/agent/{AGENT}?page=2\" rel=\"next\""
    )));
    assert!(!b.contains("rel=\"prev\""));
    // Profile.
    assert!(b.contains("Epistemic profile"));
    assert!(b.contains(">57<"));
    assert!(b.contains("0.64"));
    assert!(b.contains("<meter min=\"0\" max=\"1\" value=\"0.750\">75%</meter>"));
    assert!(b.contains(">Observation<"), "evidence types are normalised");
    assert!(
        b.contains("topic-39") && !b.contains("topic-40"),
        "topics are capped"
    );
    assert!(b.contains("and 5 more"));
    app.upstream.verify().await;
}

#[tokio::test]
async fn agent_attributed_claims_page_through_offsets() {
    let app = spawn().await;
    get_ok(&app, &format!("/api/v1/agents/{AGENT}"), agent_json(AGENT)).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{AGENT}/claims")))
        .and(query_param("offset", "40"))
        .respond_with(ok(attributed_json(5, 45, 40)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    get_ok(
        &app,
        &format!("/api/v1/agents/{AGENT}/epistemic-profile"),
        profile_json(AGENT),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/agent/{AGENT}?page=3&page=3"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Showing 41–45 of 45."));
    assert!(res.body.contains(&format!(
        "href=\"/explorer/agent/{AGENT}?page=2\" rel=\"prev\""
    )));
    assert!(!res.body.contains("rel=\"next\""));
    app.upstream.verify().await;
}

#[tokio::test]
async fn agent_epistemic_profile_timeout_degrades_only_that_section() {
    let app = spawn_with(&[(ENV_UPSTREAM_TIMEOUT_MS, "400")], Router::new()).await;
    get_ok(&app, &format!("/api/v1/agents/{AGENT}"), agent_json(AGENT)).await;
    get_ok(
        &app,
        &format!("/api/v1/agents/{AGENT}/claims"),
        attributed_json(2, 2, 0),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{AGENT}/epistemic-profile")))
        .respond_with(ok(profile_json(AGENT)).set_delay(Duration::from_secs(3)))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/agent/{AGENT}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Attributed claim number 1"));
    assert!(res.body.contains(
        "<p class=\"section-unavailable\">The EpiGraph API took too long to answer.</p>"
    ));
    assert!(!res.body.contains("topic-0"));
}

#[tokio::test]
async fn agent_attributed_claims_text_plain_400_degrades() {
    let app = spawn().await;
    get_ok(&app, &format!("/api/v1/agents/{AGENT}"), agent_json(AGENT)).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{AGENT}/claims")))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "text/plain; charset=utf-8")
                .set_body_string("Failed to deserialize query string: invalid digit"),
        )
        .mount(&app.upstream)
        .await;
    get_ok(
        &app,
        &format!("/api/v1/agents/{AGENT}/epistemic-profile"),
        profile_json(AGENT),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/agent/{AGENT}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res
        .body
        .contains("<p class=\"section-unavailable\">The EpiGraph API rejected this request.</p>"));
    assert!(!res.body.contains("invalid digit"));
    assert!(res.body.contains("topic-0"), "the profile still renders");
}

#[tokio::test]
async fn agent_404_and_omitted_optionals() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{AGENT}")))
        .respond_with(json_404("Agent", AGENT))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{AGENT}/claims")))
        .respond_with(json_404("Agent", AGENT))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{AGENT}/epistemic-profile")))
        .respond_with(json_404("Agent", AGENT))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/agent/{AGENT}"), &sid).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("We could not find that agent."));

    // No display name, key, labels or ids; empty claims; null time range.
    let app = spawn().await;
    get_ok(
        &app,
        &format!("/api/v1/agents/{AGENT}"),
        json!({"id": AGENT}),
    )
    .await;
    get_ok(
        &app,
        &format!("/api/v1/agents/{AGENT}/claims"),
        json!({"items": [], "total": 0, "limit": 20, "offset": 0}),
    )
    .await;
    get_ok(
        &app,
        &format!("/api/v1/agents/{AGENT}/epistemic-profile"),
        json!({"agent_id": AGENT, "claim_count": 0, "evidence_distribution": {},
               "epistemic_status_distribution": {}, "mean_truth_value": 0.0,
               "refutation_rate": 0.0, "topics": [], "time_range": null}),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/agent/{AGENT}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("Agent a9e7c1d2"));
    assert!(res.body.contains("No claims are attributed to this agent."));
    assert!(res.body.contains("No evidence recorded."));
}

#[tokio::test]
async fn agent_escapes_hostile_content_and_refuses_unsafe_links() {
    let app = spawn().await;
    get_ok(
        &app,
        &format!("/api/v1/agents/{AGENT}"),
        json!({"id": AGENT, "display_name": HOSTILE, "public_key": HOSTILE_ATTR,
               "created_at": "2026-01-02T03:04:05Z", "labels": [HOSTILE_ATTR],
               "orcid": "javascript:alert(1)", "ror_id": HOSTILE_ATTR}),
    )
    .await;
    let mut claims = attributed_json(1, 2, 0);
    claims["items"][0]["content"] = json!(HOSTILE);
    claims["items"].as_array_mut().unwrap().push(
        json!({"id": CLAIM, "content": "[REDACTED]", "truth_value": 0.1,
                     "agent_id": AGENT, "trace_id": null,
                     "created_at": "2026-01-02T03:04:05Z",
                     "updated_at": "2026-01-02T03:04:05Z", "attribution": {}}),
    );
    get_ok(&app, &format!("/api/v1/agents/{AGENT}/claims"), claims).await;
    let mut profile = profile_json(AGENT);
    profile["topics"] = json!([HOSTILE_ATTR]);
    profile["evidence_distribution"] = json!({ HOSTILE: 1.0 });
    get_ok(
        &app,
        &format!("/api/v1/agents/{AGENT}/epistemic-profile"),
        profile,
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/agent/{AGENT}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_escaped(&res.body);
    assert!(res.body.contains("javascript:alert(1)"), "shown as text");
    assert!(
        !res.body.contains("https://ror.org/"),
        "an invalid ROR id is not linked"
    );
    assert!(
        res.body.contains("Content hidden."),
        "redacted attributed claim"
    );
    assert!(!res.body.contains("[REDACTED]"));
}

#[tokio::test]
async fn session_expiry_on_an_entity_page_sends_the_viewer_to_sign_in() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized", "message": "token expired",
            "details": {"reason": "expired"}
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("stale");
    let res = app.get_as(&format!("/explorer/agent/{AGENT}"), &sid).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(
        res.location(),
        Some(format!("/explorer/auth/login?return_to=%2Fexplorer%2Fagent%2F{AGENT}").as_str())
    );
    assert!(res
        .header_all("set-cookie")
        .iter()
        .any(|c| c.starts_with("epx_session=") && c.contains("Max-Age=0")));
    assert!(app.state.sessions.get(&sid).is_none(), "session ended");
}

// ---- /frame/:id ----------------------------------------------------------------

fn frame_json(id: &str) -> Value {
    json!({
        "frame": {"id": id, "name": "Boiling point", "description": "Where water boils.",
                  "hypotheses": ["below 100 °C", "at 100 °C", "above 100 °C"],
                  "parent_frame_id": PARENT_FRAME, "is_refinable": true, "version": 3,
                  "created_at": "2026-01-02T03:04:05+00:00"},
        "claim_count": 60,
        "claims": [{"claim_id": CLAIM, "hypothesis_index": 1},
                   {"claim_id": V1, "hypothesis_index": null}]
    })
}

fn frame_rows(n: usize, offset: usize) -> Value {
    let rows: Vec<Value> = (0..n)
        .map(|i| {
            let k = offset + i;
            if k == 1 {
                json!({"claim_id": format!("d0000000-0000-4000-8000-{k:012}"),
                       "content": "[REDACTED]", "hypothesis_index": null,
                       "belief": null, "plausibility": null, "ignorance": null,
                       "mass_on_missing": null})
            } else {
                json!({"claim_id": format!("d0000000-0000-4000-8000-{k:012}"),
                       "content": format!("Frame claim {k}"), "hypothesis_index": 1,
                       "belief": 0.5, "plausibility": 0.75, "ignorance": 0.25,
                       "mass_on_missing": 0.0})
            }
        })
        .collect();
    Value::Array(rows)
}

#[tokio::test]
async fn frame_page_renders_definition_and_a_page_of_claims() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/frames/{FRAME}")))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(frame_json(FRAME)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/frames/{FRAME}/claims")))
        .and(query_param("sort_by", "belief"))
        .and(query_param("order", "desc"))
        .and(query_param("limit", "26"))
        .and(query_param("offset", "0"))
        .respond_with(ok(frame_rows(26, 0)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/frame/{FRAME}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = &res.body;
    assert!(b.contains("<h1>Boiling point</h1>"));
    assert!(b.contains("Where water boils."));
    assert!(b.contains(&format!("href=\"/explorer/frame/{PARENT_FRAME}\"")));
    assert!(b.contains("<li value=\"2\">above 100 °C</li>"));
    assert!(b.contains(">60<"), "claim count");
    assert!(b.contains("Frame claim 24"));
    assert!(!b.contains("Frame claim 25"), "the probe row is not shown");
    assert!(b.contains("Showing 1–25 (more follow)."));
    assert!(b.contains(&format!(
        "href=\"/explorer/frame/{FRAME}?page=2\" rel=\"next\""
    )));
    assert!(b.contains("Hypothesis: at 100 °C"));
    assert!(b.contains("plausibility <span class=\"num\">0.75</span>"));
    assert!(b.contains("Content hidden."));
    assert!(!b.contains("[REDACTED]"));
    app.upstream.verify().await;
}

#[tokio::test]
async fn frame_sort_order_and_page_are_validated_and_forwarded() {
    let app = spawn().await;
    get_ok(&app, &format!("/api/v1/frames/{FRAME}"), frame_json(FRAME)).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/frames/{FRAME}/claims")))
        .and(query_param("sort_by", "plausibility"))
        .and(query_param("order", "asc"))
        .and(query_param("offset", "25"))
        .respond_with(ok(frame_rows(3, 25)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/frames/{FRAME}/claims")))
        .and(query_param("sort_by", "belief"))
        .and(query_param("order", "desc"))
        .respond_with(ok(frame_rows(0, 0)))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(
            &format!("/explorer/frame/{FRAME}?sort=plausibility&order=asc&page=2"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Showing 26–28."));
    assert!(res.body.contains(&format!(
        "href=\"/explorer/frame/{FRAME}?sort=plausibility&#38;order=asc\" rel=\"prev\""
    )));
    assert!(res
        .body
        .contains("<option value=\"plausibility\" selected>"));
    assert!(res.body.contains("<option value=\"asc\" selected>"));

    // Unknown values fall back to the defaults instead of an upstream 400.
    let res = app
        .get_as(
            &format!("/explorer/frame/{FRAME}?sort=drop%20table&order=sideways"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("No claims are in this frame."));
    app.upstream.verify().await;
}

#[tokio::test]
async fn frame_definition_degrades_when_only_the_claims_load() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/frames/{FRAME}")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": "DatabaseError", "message": "statement timeout"
        })))
        .mount(&app.upstream)
        .await;
    get_ok(
        &app,
        &format!("/api/v1/frames/{FRAME}/claims"),
        frame_rows(2, 0),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/frame/{FRAME}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("<h1>Frame f4a3e2d1</h1>"));
    assert!(res.body.contains("section-unavailable"));
    assert!(res.body.contains("Frame claim 0"));
    assert!(
        res.body.contains("Hypothesis: #1"),
        "no names without the definition"
    );
    assert!(!res.body.contains("statement timeout"));
}

#[tokio::test]
async fn frame_404_and_total_failure() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/frames/{FRAME}")))
        .respond_with(json_404("frame", FRAME))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/frames/{FRAME}/claims")))
        .respond_with(json_404("frame", FRAME))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/frame/{FRAME}"), &sid).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("We could not find that frame."));

    let app = spawn().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/frame/{FRAME}"), &sid).await;
    assert_eq!(res.status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn frame_escapes_hostile_content() {
    let app = spawn().await;
    let mut f = frame_json(FRAME);
    f["frame"]["name"] = json!(HOSTILE);
    f["frame"]["description"] = json!(HOSTILE_ATTR);
    f["frame"]["hypotheses"] = json!([HOSTILE, HOSTILE_ATTR]);
    get_ok(&app, &format!("/api/v1/frames/{FRAME}"), f).await;
    let mut rows = frame_rows(1, 0);
    rows[0]["content"] = json!(HOSTILE);
    get_ok(&app, &format!("/api/v1/frames/{FRAME}/claims"), rows).await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/frame/{FRAME}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_escaped(&res.body);
}

// ---- /evidence/:id -------------------------------------------------------------

/// Only the always-present fields; every skip-if-None field omitted.
fn minimal_evidence_json(id: &str) -> Value {
    json!({
        "id": id, "claim_id": null, "agent_id": null, "evidence_type": "unknown",
        "content": null, "content_hash": "00ff", "source_url": null,
        "created_at": "2026-01-02T03:04:05+00:00"
    })
}

#[tokio::test]
async fn evidence_page_normalises_type_links_doi_and_linked_claim() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/evidence/{EVIDENCE}")))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(json!({
            "id": EVIDENCE, "claim_id": CLAIM, "agent_id": AGENT,
            "evidence_type": "empirical",
            "content": "Measured at 101.3 kPa.\nSecond line.",
            "content_hash": "9f86d081884c7d65",
            "source_url": "10.1000/xyz#frag",
            "caption": "Figure 2: boiling curve", "figure_id": "fig-2", "page": 7,
            "doi": "10.1000/XYZ#frag",
            "created_at": "2026-01-02T03:04:05+00:00"
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}")))
        .respond_with(ok(claim_json("Water boils at 100 °C at sea level.")))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/evidence/{EVIDENCE}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = &res.body;
    assert!(b.contains("<h1>Observation evidence</h1>"));
    assert!(b.contains("Recorded as “empirical”."));
    assert!(b.contains("href=\"https://doi.org/10.1000/xyz%23frag\""));
    assert_eq!(
        b.matches("href=\"https://doi.org/").count(),
        1,
        "one DOI link"
    );
    assert!(b.contains("Measured at 101.3 kPa.\nSecond line."));
    assert!(b.contains("Water boils at 100 °C at sea level."));
    assert!(b.contains(&format!("href=\"/explorer/claim/{CLAIM}\"")));
    assert!(b.contains(&format!("href=\"/explorer/agent/{AGENT}\"")));
    assert!(b.contains("Figure 2: boiling curve"));
    assert!(b.contains("<dd>7</dd>"));
    assert!(b.contains("2026-01-02 03:04 UTC"));
    app.upstream.verify().await;
}

#[tokio::test]
async fn evidence_with_only_required_fields_renders() {
    let app = spawn().await;
    get_ok(
        &app,
        &format!("/api/v1/evidence/{EVIDENCE}"),
        minimal_evidence_json(EVIDENCE),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/evidence/{EVIDENCE}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("<h1>Unspecified evidence</h1>"));
    assert!(res.body.contains("No content was recorded"));
    assert!(res.body.contains("No source was recorded."));
    assert!(res.body.contains("No claim is linked"));
}

#[tokio::test]
async fn evidence_escapes_hostile_content_and_never_links_unsafe_urls() {
    let app = spawn().await;
    get_ok(
        &app,
        &format!("/api/v1/evidence/{EVIDENCE}"),
        json!({
            "id": EVIDENCE, "claim_id": null, "agent_id": null,
            "evidence_type": HOSTILE, "content": HOSTILE,
            "content_hash": HOSTILE_ATTR, "source_url": "javascript:alert(1)",
            "caption": HOSTILE_ATTR, "doi": HOSTILE_ATTR,
            "created_at": "2026-01-02T03:04:05+00:00"
        }),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/evidence/{EVIDENCE}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_escaped(&res.body);
    assert!(res
        .body
        .contains("<span class=\"mono\">javascript:alert(1)</span>"));
}

#[tokio::test]
async fn redacted_evidence_makes_no_claim_call() {
    let app = spawn().await;
    get_ok(
        &app,
        &format!("/api/v1/evidence/{EVIDENCE}"),
        json!({
            "id": EVIDENCE, "claim_id": CLAIM, "agent_id": AGENT,
            "evidence_type": "document", "content": "[REDACTED]",
            "content_hash": "00ff", "source_url": null,
            "created_at": "2026-01-02T03:04:05+00:00"
        }),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}")))
        .respond_with(ok(claim_json("secret")))
        .expect(0)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/evidence/{EVIDENCE}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("Content hidden."));
    assert!(!res.body.contains("[REDACTED]"));
    assert!(!res.body.contains("secret"));
    app.upstream.verify().await;
}

#[tokio::test]
async fn evidence_404_and_degraded_linked_claim() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/evidence/{EVIDENCE}")))
        .respond_with(json_404("evidence", EVIDENCE))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/evidence/{EVIDENCE}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("We could not find that evidence."));

    let app = spawn().await;
    get_ok(
        &app,
        &format!("/api/v1/evidence/{EVIDENCE}"),
        json!({
            "id": EVIDENCE, "claim_id": CLAIM, "agent_id": null,
            "evidence_type": "figure", "content": "a figure",
            "content_hash": "00ff", "source_url": "https://api.example.com/fig.png",
            "created_at": "2026-01-02T03:04:05+00:00"
        }),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/evidence/{EVIDENCE}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res
        .body
        .contains("href=\"https://api.example.com/fig.png\""));
    assert!(res.body.contains("Claim 0b9a5a4e"));
    assert!(res.body.contains("section-unavailable"));
}
