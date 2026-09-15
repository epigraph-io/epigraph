//! Graph area: `/bff/graph/ego/:id`, `/bff/themes`, `/bff/communities` and
//! `/bff/neighborhood/:id`, against a wiremock upstream shaped like plan
//! §2.2 and `graph-entity-endpoints.md` §1-3 (text/plain errors included).

mod common;

use axum::http::StatusCode;
use common::{spawn, TestApp};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const CLAIM: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const SECRET: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a11";
const OTHER: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a12";
const AGENT: &str = "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const PAPER: &str = "5b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const THEME: &str = "2c9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const NBH: &str = "3d9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const NBH2: &str = "3d9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a11";
const CLUSTER: &str = "4e9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const FRAME: &str = "6f9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const EDGE1: &str = "7a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const EDGE2: &str = "7a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a11";
const EDGE3: &str = "7a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a12";
const EDGE4: &str = "7a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a13";

const HOSTILE: &str = "\"><script>alert(1)</script>";

/// `GET /api/v1/claims/:id/ego` as plan §2.2 specifies it: a redacted
/// neighbour, a paper (no page), an agent, and optional fields omitted.
fn ego_json(center_label: &str) -> Value {
    json!({
        "center": {"id": CLAIM, "entity_type": "claim", "label": center_label,
                   "content": center_label, "truth_value": 0.7, "pignistic_prob": 0.8,
                   "labels": ["physics"], "is_current": true, "redacted": false},
        "nodes": [
            {"id": SECRET, "entity_type": "claim", "label": "[REDACTED]",
             "content": "[REDACTED]", "truth_value": 0.1, "labels": ["private-label"],
             "is_current": true, "redacted": true},
            {"id": OTHER, "entity_type": "claim", "label": HOSTILE, "content": HOSTILE,
             "truth_value": 0.4, "labels": [], "is_current": false, "redacted": false},
            {"id": PAPER, "entity_type": "paper", "label": "paper", "redacted": false},
            {"id": AGENT, "entity_type": "agent", "label": "Ada Lovelace", "redacted": false}
        ],
        "edges": [
            {"id": EDGE1, "source_id": CLAIM, "target_id": SECRET, "source_type": "claim",
             "target_type": "claim", "relationship": "SUPPORTS", "direction": "out"},
            {"id": EDGE2, "source_id": OTHER, "target_id": CLAIM, "source_type": "claim",
             "target_type": "claim", "relationship": "contradicts", "direction": "in"},
            {"id": EDGE3, "source_id": PAPER, "target_id": CLAIM, "source_type": "paper",
             "target_type": "claim", "relationship": "asserts", "direction": "in"},
            {"id": EDGE4, "source_id": CLAIM, "target_id": AGENT, "source_type": "claim",
             "target_type": "agent", "relationship": "attributed_to", "direction": "out"}
        ],
        "total_edges": 212,
        "truncated": true
    })
}

async fn mount_ego(app: &TestApp, degree: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/ego")))
        .and(query_param("max_degree", degree))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(&app.upstream)
        .await;
}

fn text_plain(status: u16, body: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_raw(body.as_bytes().to_vec(), "text/plain; charset=utf-8")
}

fn node<'v>(body: &'v Value, id: &str) -> &'v Value {
    body["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == id)
        .unwrap_or_else(|| panic!("node {id} missing from {body}"))
}

// ---- /bff/graph/ego/:id ---------------------------------------------------------

#[tokio::test]
async fn ego_bff_clamps_degree_and_returns_the_canvas_shape() {
    let app = spawn().await;
    mount_ego(&app, "80", ego_json("Water boils at 100 °C.")).await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(
            &format!("/explorer/bff/graph/ego/{CLAIM}?max_degree=500"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.header("cache-control"), Some("private, no-store"));
    let body = res.json();
    assert_eq!(body["center"], CLAIM);
    assert_eq!(body["max_degree"], 80, "clamped in the BFF");
    assert_eq!(body["total_edges"], 212);
    assert_eq!(body["truncated"], true);
    assert_eq!(body["hidden_nodes"], 0);
    assert_eq!(body["nodes"].as_array().unwrap().len(), 5);
    assert_eq!(body["nodes"][0]["id"], CLAIM, "the centre comes first");

    let centre = node(&body, CLAIM);
    assert_eq!(centre["is_center"], true);
    assert_eq!(centre["href"], format!("/explorer/claim/{CLAIM}"));
    assert_eq!(
        centre["expand_href"],
        format!("/explorer/bff/graph/ego/{CLAIM}")
    );
    assert_eq!(
        centre["graph_href"],
        format!("/explorer/claim/{CLAIM}/graph")
    );
    assert_eq!(centre["pignistic_prob"], 0.8);
    assert_eq!(centre["labels"], json!(["physics"]));

    let agent = node(&body, AGENT);
    assert_eq!(agent["href"], format!("/explorer/agent/{AGENT}"));
    assert_eq!(agent["expand_href"], Value::Null, "only claims have an ego");
    let paper = node(&body, PAPER);
    assert_eq!(paper["href"], Value::Null, "papers have no page");

    let hidden = node(&body, SECRET);
    assert_eq!(hidden["redacted"], true);
    assert_eq!(hidden["label"], "Hidden claim");
    assert_eq!(hidden["content"], Value::Null);
    assert_eq!(hidden["labels"], json!([]));
    assert_eq!(hidden["truth_value"], Value::Null);
    assert_eq!(hidden["expand_href"], Value::Null);
    assert!(
        !res.body.contains("private-label"),
        "redacted labels never leave"
    );
    assert!(!res.body.contains("[REDACTED]"));

    let edges = body["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 4);
    let fam = |id: &str| {
        edges
            .iter()
            .find(|e| e["id"] == id)
            .map(|e| {
                (
                    e["family"].clone(),
                    e["source"].clone(),
                    e["target"].clone(),
                )
            })
            .unwrap()
    };
    assert_eq!(fam(EDGE1), (json!("support"), json!(CLAIM), json!(SECRET)));
    assert_eq!(fam(EDGE2), (json!("refute"), json!(OTHER), json!(CLAIM)));
    assert_eq!(fam(EDGE4).0, json!("structural"));
    assert!(edges.iter().all(|e| e["directed"] == true));
}

#[tokio::test]
async fn ego_bff_defaults_and_floors_the_degree() {
    let app = spawn().await;
    mount_ego(&app, "40", ego_json("c")).await;
    mount_ego(&app, "1", ego_json("c")).await;
    let sid = app.sign_in("tok");

    for (uri, expect) in [
        (format!("/explorer/bff/graph/ego/{CLAIM}"), 40),
        (format!("/explorer/bff/graph/ego/{CLAIM}?max_degree=0"), 1),
    ] {
        let res = app.get_as(&uri, &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}: {}", res.body);
        assert_eq!(res.json()["max_degree"], expect, "{uri}");
    }
}

#[tokio::test]
async fn ego_bff_maps_404_and_bad_ids_to_json_not_found() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/ego")))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "NotFound", "message": format!("Claim with ID {CLAIM} not found"),
            "details": {"entity": "Claim", "id": CLAIM}
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(&format!("/explorer/bff/graph/ego/{CLAIM}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res
        .header("content-type")
        .unwrap()
        .starts_with("application/json"));
    assert_eq!(
        res.json(),
        json!({"error": "not_found", "message": "We could not find that claim."})
    );

    // A malformed id never reaches upstream (the mock above expects 1 call).
    let res = app.get_as("/explorer/bff/graph/ego/not-a-uuid", &sid).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json()["error"], "not_found");
}

#[tokio::test]
async fn graph_bff_routes_require_sign_in() {
    let app = spawn().await;
    for uri in [
        format!("/explorer/bff/graph/ego/{CLAIM}"),
        "/explorer/bff/themes".to_string(),
        "/explorer/bff/communities".to_string(),
        format!("/explorer/bff/neighborhood/{NBH}"),
    ] {
        let res = app.get(&uri).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(res.json()["error"], "unauthorized", "{uri}");
    }
    assert!(app.upstream.received_requests().await.unwrap().is_empty());
}

// ---- /bff/themes, /bff/communities ------------------------------------------------

async fn mount_themes_for(app: &TestApp, token: &str, label: &str) {
    Mock::given(method("GET"))
        .and(path("/api/v1/graph/themes/overview"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "themes": [{"id": THEME, "label": label, "claim_count": 42}]
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
}

#[tokio::test]
async fn themes_overview_is_cached_per_viewer() {
    let app = spawn().await;
    mount_themes_for(&app, "tok-a", "Theme seen by A").await;
    mount_themes_for(&app, "tok-b", "Theme seen by B").await;
    let a = app.sign_in("tok-a");
    let b = app.sign_in("tok-b");

    let first = app.get_as("/explorer/bff/themes", &a).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let body = first.json();
    assert_eq!(body["themes"][0]["label"], "Theme seen by A");
    assert_eq!(body["themes"][0]["claim_count"], 42);
    assert_eq!(
        body["themes"][0]["href"],
        format!("/explorer/theme/{THEME}")
    );
    assert_eq!(body["total"], 1);
    assert_eq!(body["truncated"], false);

    // Same viewer within 60 s: served from the cache, identical body.
    let again = app.get_as("/explorer/bff/themes", &a).await;
    assert_eq!(again.json(), body);

    // Another viewer never sees A's cached body: their own upstream call.
    let other = app.get_as("/explorer/bff/themes", &b).await;
    assert_eq!(other.status, StatusCode::OK);
    assert_eq!(other.json()["themes"][0]["label"], "Theme seen by B");

    let calls = app.upstream.received_requests().await.unwrap();
    assert_eq!(
        calls.len(),
        2,
        "one upstream call per viewer, not per request"
    );
    app.upstream.verify().await;
}

#[tokio::test]
async fn communities_overview_is_cached_and_linked() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/graph/communities/overview"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "run_id": "8a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
            "generated_at": "2026-09-01T12:00:00Z",
            "degraded": false,
            "supernodes": [
                {"cluster_id": CLUSTER, "label": "cluster-1", "size": 40, "mean_betp": 0.66,
                 "dominant_type": null, "dominant_frame_id": FRAME},
                {"cluster_id": NBH2, "label": "cluster-2", "size": 3}
            ],
            "cluster_edges": [{"a": CLUSTER, "b": NBH2, "weight": 7}]
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as("/explorer/bff/communities", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let body = res.json();
    assert_eq!(
        body["status"],
        Value::Null,
        "omitted upstream once a run exists"
    );
    assert_eq!(
        body["supernodes"][0]["href"],
        format!("/explorer/community/{CLUSTER}")
    );
    assert_eq!(
        body["supernodes"][0]["frame_href"],
        format!("/explorer/frame/{FRAME}")
    );
    assert_eq!(body["supernodes"][1]["mean_betp"], Value::Null);
    assert_eq!(body["cluster_edges"][0]["weight"], 7.0);

    let again = app.get_as("/explorer/bff/communities", &sid).await;
    assert_eq!(again.json(), body);
    app.upstream.verify().await;
}

#[tokio::test]
async fn overview_failures_are_json_and_not_cached() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/graph/communities/overview"))
        .respond_with(text_plain(
            500,
            "error returned from database: relation missing",
        ))
        .expect(2)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    for _ in 0..2 {
        let res = app.get_as("/explorer/bff/communities", &sid).await;
        assert_eq!(res.status, StatusCode::BAD_GATEWAY);
        assert_eq!(res.json()["error"], "upstream_unavailable");
        assert!(
            !res.body.contains("relation missing"),
            "upstream detail stays in logs"
        );
    }
    app.upstream.verify().await;
}

#[tokio::test]
async fn overview_401_ends_the_session() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/graph/themes/overview"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized", "message": "Invalid token", "details": {"reason": "expired"}
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/bff/themes", &sid).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json()["error"], "session_expired");
    assert!(app.state.sessions.get(&sid).is_none());
}

// ---- /bff/neighborhood/:id --------------------------------------------------------

fn compound_json() -> Value {
    json!({
        "neighborhood_id": NBH, "truncated": false,
        "nodes": [
            {"id": CLAIM, "label": "Compound claim", "kind": "compound", "atom_count": 4,
             "pignistic_prob": 0.9, "frame_id": FRAME},
            {"id": OTHER, "label": "Standalone claim", "kind": "standalone", "atom_count": 0,
             "pignistic_prob": null, "frame_id": null}
        ],
        "induced_edges": [{"source": CLAIM, "target": OTHER, "relationship": "supports",
                           "strength": 0.5, "atom_edge_count": 2}],
        "direct_edges": [{"source": CLAIM, "target": OTHER, "relationship": "supports"},
                         {"source": OTHER, "target": CLAIM, "relationship": "decomposes_to"}],
        "structural_edges": [{"source": CLAIM, "target": OTHER, "kind": "shared_atom",
                              "atom_count": 1}]
    })
}

fn atomic_json() -> Value {
    json!({
        "neighborhood_id": NBH, "truncated": false,
        "nodes": [{"id": OTHER, "label": "An atom", "compound_id": CLAIM,
                   "pignistic_prob": 0.3, "frame_id": null}],
        "edges": [],
        "compound_groups": [{"compound_id": CLAIM, "label": "Parent claim",
                             "member_atom_ids": [OTHER]}]
    })
}

async fn mount_neighborhood(app: &TestApp, mode: &str, body: Value, times: u64) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/neighborhoods/{NBH}/expand")))
        .and(query_param("mode", mode))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(times)
        .mount(&app.upstream)
        .await;
}

#[tokio::test]
async fn neighborhood_bff_passes_the_mode_through() {
    let app = spawn().await;
    // No mode and an unknown mode both mean compound, sent explicitly.
    mount_neighborhood(&app, "compound", compound_json(), 2).await;
    mount_neighborhood(&app, "atomic", atomic_json(), 1).await;
    let sid = app.sign_in("tok");

    for uri in [
        format!("/explorer/bff/neighborhood/{NBH}"),
        format!("/explorer/bff/neighborhood/{NBH}?mode=bogus"),
    ] {
        let res = app.get_as(&uri, &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}: {}", res.body);
        let body = res.json();
        assert_eq!(body["mode"], "compound", "{uri}");
        assert_eq!(body["neighborhood_id"], NBH);
        assert_eq!(body["center"], Value::Null);
        assert_eq!(node(&body, CLAIM)["atom_count"], 4);
        assert_eq!(node(&body, CLAIM)["frame_id"], FRAME);
        assert_eq!(
            node(&body, CLAIM)["expand_href"],
            format!("/explorer/bff/graph/ego/{CLAIM}")
        );
        // induced + direct `supports` collapse; decomposes_to and shared_atom stay.
        assert_eq!(body["edges"].as_array().unwrap().len(), 3, "{uri}");
        assert_eq!(body["total_edges"], 3);
        let shared = body["edges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["relationship"] == "shared_atom")
            .unwrap();
        assert_eq!(shared["directed"], false);
        assert_eq!(body["compound_groups"], json!([]));
    }

    let res = app
        .get_as(
            &format!("/explorer/bff/neighborhood/{NBH}?mode=ATOMIC"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let body = res.json();
    assert_eq!(body["mode"], "atomic");
    assert_eq!(node(&body, OTHER)["kind"], "atom");
    assert_eq!(body["compound_groups"][0]["label"], "Parent claim");
    assert_eq!(body["compound_groups"][0]["member_count"], 1);
    assert_eq!(
        body["compound_groups"][0]["href"],
        format!("/explorer/claim/{CLAIM}")
    );
    app.upstream.verify().await;
}

#[tokio::test]
async fn neighborhood_bff_404_is_json() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/neighborhoods/{NBH}/expand")))
        .respond_with(text_plain(404, "neighborhood not found in latest run"))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/bff/neighborhood/{NBH}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json()["error"], "not_found");
}
