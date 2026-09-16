//! Graph area: `/bff/graph/ego/:id`, `/bff/themes`, `/bff/communities`,
//! `/bff/neighborhood/:id`, and the `/claim/:id/graph`, `/theme/:id`,
//! `/community/:id`, `/neighborhood/:id` pages, against a wiremock upstream
//! shaped like plan §2.2 and `graph-entity-endpoints.md` §1-3 (text/plain
//! errors included).

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

// ---- /theme/:id -------------------------------------------------------------------

#[tokio::test]
async fn theme_synthetic_entry_renders_view_expired() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/themes/{THEME}/expand")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "theme_id": THEME, "truncated": false,
            "neighborhoods": [{"id": THEME, "label": "synthetic", "size": 0,
                               "mean_betp": null, "dominant_frame_id": null}],
            "neighborhood_edges": []
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/theme/{THEME}?claim={CLAIM}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("View expired — clustering has re-run"));
    assert!(res
        .body
        .contains(&format!("href=\"/explorer/claim/{CLAIM}\"")));
    assert!(
        !res.body
            .contains(&format!("/explorer/neighborhood/{THEME}")),
        "the synthetic id is the theme id; linking it would 404"
    );
}

#[tokio::test]
async fn theme_404_renders_view_expired() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/themes/{THEME}/expand")))
        .respond_with(text_plain(404, "theme not found"))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/theme/{THEME}"), &sid).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.header("content-type").unwrap().starts_with("text/html"));
    assert!(res.body.contains("View expired — clustering has re-run"));
    assert!(
        res.body.contains("href=\"/explorer/\""),
        "inside the layout"
    );
    assert!(
        !res.body.contains("theme not found"),
        "upstream text is not shown"
    );
}

#[tokio::test]
async fn theme_renders_neighbourhoods_weighted_edges_and_share() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/themes/{THEME}/expand")))
        .and(query_param("budget", "150"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "theme_id": THEME, "truncated": false,
            "neighborhoods": [
                {"id": NBH, "label": FRAME, "size": 12, "mean_betp": 0.756,
                 "dominant_frame_id": FRAME},
                {"id": NBH2, "label": "neighborhood-2", "size": 3}
            ],
            "neighborhood_edges": [{"a": NBH, "b": NBH2, "weight": 0.25}]
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(
            &format!("/explorer/theme/{THEME}?budget=9999&claim={CLAIM}"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = &res.body;
    assert!(b.contains("not a permalink"));
    assert!(b.contains(&format!(
        "data-share-url=\"https://explorer.example.com/explorer/claim/{CLAIM}\""
    )));
    assert!(b.contains(&format!(
        "href=\"/explorer/neighborhood/{NBH}?claim={CLAIM}\""
    )));
    assert!(b.contains("Frame 6f9a5a4e"), "frame-UUID labels are named");
    assert!(b.contains("neighborhood-2"));
    assert!(b.contains("0.76"), "mean belief to two places");
    assert!(b.contains("0.25"), "edge weight");
    assert!(b.contains(&format!("href=\"/explorer/frame/{FRAME}\"")));
    assert!(!b.contains("View expired"));
    app.upstream.verify().await;
}

#[tokio::test]
async fn theme_without_a_known_claim_has_no_share_button() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/themes/{THEME}/expand")))
        .and(query_param("budget", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "theme_id": THEME,
            "neighborhoods": [{"id": NBH, "label": "neighborhood-1", "size": 2}]
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    // A malformed ?claim= is ignored rather than failing the page.
    let res = app
        .get_as(&format!("/explorer/theme/{THEME}?claim=nope"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("not a permalink"));
    assert!(!res.body.contains("data-share-url"));
    assert!(res
        .body
        .contains(&format!("href=\"/explorer/neighborhood/{NBH}\"")));
}

#[tokio::test]
async fn theme_upstream_failure_is_the_error_page() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/themes/{THEME}/expand")))
        .respond_with(text_plain(500, "error returned from database"))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as(&format!("/explorer/theme/{THEME}"), &sid).await;
    assert_eq!(res.status, StatusCode::BAD_GATEWAY);
    assert!(res.body.contains("EpiGraph is unavailable"));
    assert!(!res.body.contains("database"));
}

// ---- /community/:id ---------------------------------------------------------------

#[tokio::test]
async fn community_clamps_budget_and_hides_redacted_labels() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/communities/{CLUSTER}/expand")))
        .and(query_param("budget", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cluster_id": CLUSTER, "truncated": true, "total_size": 900,
            "nodes": [
                {"id": CLAIM, "label": "Visible claim text", "entity_type": "claim",
                 "pignistic_prob": 0.42, "frame_id": null, "cluster_id": CLUSTER,
                 "conflict_k": null},
                {"id": SECRET, "label": "[REDACTED]", "entity_type": "claim",
                 "pignistic_prob": 0.9, "frame_id": FRAME, "cluster_id": CLUSTER,
                 "conflict_k": null}
            ],
            "edges": [{"source": SECRET, "target": CLAIM, "relationship": "SUPPORTS"}],
            "filtered_edge_count": 5
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/community/{CLUSTER}?budget=-4"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = &res.body;
    assert!(b.contains("Visible claim text"));
    assert!(b.contains("belief 0.42"));
    assert!(b.contains("Hidden claim"));
    assert!(!b.contains("[REDACTED]"));
    assert!(
        !b.contains("0.90"),
        "a hidden claim's numbers are not shown"
    );
    assert!(b.contains("2 of 900"));
    assert!(b.contains("SUPPORTS"));
    assert!(b.contains("graph-row--support"));
    assert!(b.contains("5 connections of other kinds"));
    assert!(b.contains("not a permalink"));
    app.upstream.verify().await;
}

#[tokio::test]
async fn community_404_renders_view_expired() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/communities/{CLUSTER}/expand")))
        .and(query_param("budget", "100"))
        .respond_with(text_plain(404, "cluster not in latest run"))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/community/{CLUSTER}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("View expired — clustering has re-run"));
}

// ---- /neighborhood/:id ------------------------------------------------------------

#[tokio::test]
async fn neighborhood_page_toggles_modes_and_seeds_the_canvas() {
    let app = spawn().await;
    mount_neighborhood(&app, "atomic", atomic_json(), 1).await;
    mount_neighborhood(&app, "compound", compound_json(), 1).await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(
            &format!("/explorer/neighborhood/{NBH}?mode=atomic&claim={CLAIM}"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = &res.body;
    assert!(b.contains(&format!(
        "data-graph-source=\"/explorer/bff/neighborhood/{NBH}?mode=atomic\""
    )));
    assert!(b.contains(&format!(
        "href=\"/explorer/neighborhood/{NBH}?mode=atomic&#38;claim={CLAIM}\" aria-current=\"page\""
    )));
    assert!(b.contains(&format!(
        "href=\"/explorer/neighborhood/{NBH}?mode=compound&#38;claim={CLAIM}\">"
    )));
    assert!(
        b.contains("Parent claim"),
        "compound groups listed in atomic mode"
    );
    assert!(b.contains("An atom"));

    let res = app
        .get_as(&format!("/explorer/neighborhood/{NBH}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains(&format!(
        "data-graph-source=\"/explorer/bff/neighborhood/{NBH}?mode=compound\""
    )));
    assert!(res.body.contains("Compound claim"));
    assert!(res.body.contains("decomposes_to"));
    app.upstream.verify().await;
}

#[tokio::test]
async fn neighborhood_404_renders_view_expired() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/neighborhoods/{NBH}/expand")))
        .respond_with(text_plain(404, "neighborhood not found in latest run"))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/neighborhood/{NBH}?claim={CLAIM}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("View expired — clustering has re-run"));
    assert!(res
        .body
        .contains(&format!("href=\"/explorer/claim/{CLAIM}\"")));
    assert!(
        !res.body.contains("data-graph-source"),
        "no canvas for a dead id"
    );
}

// ---- /claim/:id/graph -------------------------------------------------------------

async fn mount_placement(app: &TestApp) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/placement")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "claim_id": CLAIM, "theme_id": THEME,
            "cluster_run_id": "8a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
            "cluster_id": CLUSTER, "neighborhood_id": null,
            "run_completed_at": "2026-09-01T12:00:00Z"
        })))
        .mount(&app.upstream)
        .await;
}

#[tokio::test]
async fn claim_graph_page_escapes_data_and_uses_no_inline_script() {
    let app = spawn().await;
    mount_ego(&app, "40", ego_json(HOSTILE)).await;
    mount_placement(&app).await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/graph"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = &res.body;
    assert!(b.contains(&format!(
        "data-graph-source=\"/explorer/bff/graph/ego/{CLAIM}\""
    )));
    assert!(b.contains(&format!("data-graph-center=\"{CLAIM}\"")));
    assert!(b.contains("data-node-cap=\"150\""));
    assert!(b.contains("/explorer/static/graph.js?v="));
    assert!(b.contains("/explorer/static/graph.css?v="));
    assert!(!b.contains("<script>alert"), "claim text is escaped");
    assert!(b.contains("&#34;&#62;&#60;script&#62;alert(1)&#60;/script&#62;"));
    for tag in b.split("<script").skip(1) {
        let open = tag.split('>').next().unwrap();
        assert!(
            open.contains(" src=\""),
            "every script is external: <script{open}>"
        );
    }
    assert!(!b.contains("style="), "CSP forbids inline styles");
    assert!(!b.contains("[REDACTED]"));

    // The <noscript> list: every edge, relationship and direction.
    assert!(b.contains("<noscript>"));
    assert!(b.contains("SUPPORTS →"));
    assert!(b.contains("← contradicts"));
    assert!(b.contains(&format!("href=\"/explorer/agent/{AGENT}\"")));
    assert!(b.contains("Hidden claim"));
    assert!(b.contains("212 connections"), "degree-cap notice");

    // Placement links carry the claim so their share buttons work.
    assert!(b.contains(&format!("href=\"/explorer/theme/{THEME}?claim={CLAIM}\"")));
    assert!(b.contains(&format!(
        "href=\"/explorer/community/{CLUSTER}?claim={CLAIM}\""
    )));
    assert!(
        !b.contains("Its neighbourhood"),
        "null neighborhood_id → no link"
    );
}

#[tokio::test]
async fn claim_graph_max_degree_is_clamped_into_the_canvas_source() {
    let app = spawn().await;
    mount_ego(&app, "80", ego_json("c")).await;
    mount_placement(&app).await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(
            &format!("/explorer/claim/{CLAIM}/graph?max_degree=999"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains(&format!(
        "data-graph-source=\"/explorer/bff/graph/ego/{CLAIM}?max_degree=80\""
    )));
}

#[tokio::test]
async fn claim_graph_redacted_centre_shows_no_text() {
    let app = spawn().await;
    mount_ego(
        &app,
        "40",
        json!({
            "center": {"id": CLAIM, "entity_type": "claim", "label": "[REDACTED]",
                       "content": "[REDACTED]", "labels": ["secret-label"], "redacted": true},
            "nodes": [], "edges": [], "total_edges": 0, "truncated": false
        }),
    )
    .await;
    mount_placement(&app).await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/graph"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("<title>Hidden claim · Graph"));
    assert!(res.body.contains("You do not have access to this claim"));
    assert!(!res.body.contains("[REDACTED]"));
    assert!(!res.body.contains("secret-label"));
}

#[tokio::test]
async fn claim_graph_404_and_degraded_placement() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/ego")))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "NotFound", "message": "Claim not found"
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/graph"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(res.body.contains("We could not find that claim."));

    // Ego works, placement fails: the page renders with that section degraded.
    let app = spawn().await;
    mount_ego(&app, "40", ego_json("c")).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/placement")))
        .respond_with(text_plain(500, "boom"))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/claim/{CLAIM}/graph"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("class=\"section-unavailable\""));
    assert!(res.body.contains("data-graph-source"));
}

#[tokio::test]
async fn graph_pages_redirect_anonymous_viewers() {
    let app = spawn().await;
    let res = app
        .get(&format!("/explorer/theme/{THEME}?claim={CLAIM}"))
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(
        res.location().unwrap(),
        format!("/explorer/auth/login?return_to=%2Fexplorer%2Ftheme%2F{THEME}%3Fclaim%3D{CLAIM}")
    );
}

#[tokio::test]
async fn every_graph_route_is_built_at_both_mounts() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{CLAIM}/ego")))
        .respond_with(ResponseTemplate::new(200).set_body_json(ego_json("c")))
        .mount(&app.upstream)
        .await;
    mount_placement(&app).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/themes/{THEME}/expand")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "theme_id": THEME, "neighborhoods": [{"id": NBH, "label": "n", "size": 1}]
        })))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/communities/{CLUSTER}/expand")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cluster_id": CLUSTER, "total_size": 0
        })))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/graph/neighborhoods/{NBH}/expand")))
        .respond_with(ResponseTemplate::new(200).set_body_json(compound_json()))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/graph/themes/overview"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"themes": []})))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/graph/communities/overview"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "run_id": null, "generated_at": null, "degraded": false,
            "status": "no_clusters_computed", "supernodes": [], "cluster_edges": []
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    for base in ["/explorer", ""] {
        for route in [
            format!("/claim/{CLAIM}/graph"),
            format!("/theme/{THEME}"),
            format!("/community/{CLUSTER}"),
            format!("/neighborhood/{NBH}?mode=compound"),
        ] {
            let uri = format!("{base}{route}");
            let res = app.get_as(&uri, &sid).await;
            assert_eq!(res.status, StatusCode::OK, "{uri}: {}", res.body);
            assert!(res.header("content-type").unwrap().starts_with("text/html"));
            assert!(!res.body.contains("not built yet"), "{uri}");
            assert!(
                res.body.contains("href=\"/explorer/\""),
                "{uri}: base-path links"
            );
        }
        for route in [
            format!("/bff/graph/ego/{CLAIM}"),
            "/bff/themes".to_string(),
            "/bff/communities".to_string(),
            format!("/bff/neighborhood/{NBH}"),
        ] {
            let uri = format!("{base}{route}");
            let res = app.get_as(&uri, &sid).await;
            assert_eq!(res.status, StatusCode::OK, "{uri}: {}", res.body);
            assert!(res
                .header("content-type")
                .unwrap()
                .starts_with("application/json"));
        }
    }
    // Links are base-path aware even when the proxy stripped the prefix.
    let res = app.get_as("/bff/themes", &sid).await;
    assert_eq!(res.json()["themes"], json!([]));
    let res = app.get_as("/bff/communities", &sid).await;
    assert_eq!(res.json()["status"], "no_clusters_computed");
}

// ---- static assets ----------------------------------------------------------------

#[tokio::test]
async fn graph_assets_are_served_with_their_content_types() {
    let app = spawn().await;
    for (name, ct) in [
        ("graph.js", "text/javascript; charset=utf-8"),
        ("graph.css", "text/css; charset=utf-8"),
    ] {
        let res = app.get(&format!("/explorer/static/{name}")).await;
        assert_eq!(res.status, StatusCode::OK, "{name}");
        assert_eq!(res.header("content-type"), Some(ct), "{name}");
        assert_eq!(res.header("x-content-type-options"), Some("nosniff"));
        assert!(!res.body.is_empty());
    }
}

/// Pins graph.js's safety rules (no eval, no HTML parsing of data) so a
/// later edit cannot quietly break them; the browser behaviour itself is
/// exercised by hand.
#[test]
fn graph_js_never_parses_strings_as_code_or_html() {
    let js = include_str!("../static/graph.js");
    for banned in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "setAttribute('style'",
        ".style.",
    ] {
        assert!(!js.contains(banned), "graph.js must not use {banned}");
    }
    assert!(js.contains("'use strict'"));
    assert!(
        js.contains("function localPath("),
        "URLs from data are checked"
    );
}

// ---- canvas palette and status routing -------------------------------------
//
// There is no JS runtime in this tree, so these read the shipped assets: the
// palette test recomputes the WCAG contrast arithmetic a browser would apply
// to the `hsl()` fills graph.js writes, and the two status tests pin the
// structure that makes the guards unskippable.

/// The numbers in a `const NAME = [1, 2];` declaration.
fn js_numbers(js: &str, name: &str) -> Vec<f64> {
    let needle = format!("const {name} = [");
    let start = js
        .find(&needle)
        .unwrap_or_else(|| panic!("graph.js declares {name}"))
        + needle.len();
    let end = start + js[start..].find(']').expect("a closed array");
    js[start..end]
        .split(',')
        .map(|p| p.trim().parse::<f64>().expect("a plain number"))
        .collect()
}

/// The body of the `{ … }` block opened by `header` (which must end in `{`).
fn block<'a>(src: &'a str, header: &str) -> &'a str {
    let start = src
        .find(header)
        .unwrap_or_else(|| panic!("{header} is present"))
        + header.len();
    let mut depth = 1usize;
    for (i, c) in src[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[start..start + i];
                }
            }
            _ => {}
        }
    }
    panic!("{header} is never closed");
}

/// A `--token: value;` from app.css, in the light or the dark theme.
fn css_token(css: &str, name: &str, dark: bool) -> String {
    let split = css
        .find("@media (prefers-color-scheme: dark)")
        .expect("app.css has a dark block");
    let region = if dark { &css[split..] } else { &css[..split] };
    let needle = format!("{name}:");
    let start = region
        .find(&needle)
        .unwrap_or_else(|| panic!("{name} is defined"))
        + needle.len();
    let end = start + region[start..].find(';').expect("a closed declaration");
    region[start..end].trim().to_string()
}

fn srgb_from_hex(hex: &str) -> [f64; 3] {
    let h = hex.trim_start_matches('#');
    assert_eq!(h.len(), 6, "{hex} is #rrggbb");
    [0usize, 2, 4]
        .map(|i| f64::from(u8::from_str_radix(&h[i..i + 2], 16).expect("hex digits")) / 255.0)
}

/// CSS `hsl(h, s%, l%)` → sRGB in 0..=1 (CSS Color 4 §7.1).
fn srgb_from_hsl(hue: f64, sat_pct: f64, light_pct: f64) -> [f64; 3] {
    let (s, l) = (sat_pct / 100.0, light_pct / 100.0);
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let hp = hue / 60.0;
    let x = c * (1.0 - (hp % 2.0 - 1.0).abs());
    let (r, g, b) = match hp as u8 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = l - c / 2.0;
    [r + m, g + m, b + m]
}

/// WCAG 2.1 relative luminance of an sRGB colour.
fn luminance(rgb: [f64; 3]) -> f64 {
    let lin = |c: f64| {
        if c <= 0.039_28 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * lin(rgb[0]) + 0.7152 * lin(rgb[1]) + 0.0722 * lin(rgb[2])
}

/// WCAG 2.1 contrast ratio, `(lighter + 0.05) / (darker + 0.05)`.
fn contrast(a: [f64; 3], b: [f64; 3]) -> f64 {
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

/// The belief ramp used to run to 90% lightness on a `--surface: #ffffff`
/// stage while `.gnode circle` stroked with `--surface` itself, so a
/// low-belief node was a white disc outlined in white: 1.18:1 for the palest
/// hue. Recomputes every extreme from the constants the assets ship.
#[test]
fn every_node_stays_visible_against_the_stage_in_both_themes() {
    let js = include_str!("../static/graph.js");
    let css = include_str!("../static/graph.css");
    let tokens = include_str!("../static/app.css");

    let hues = js_numbers(js, "HUES");
    let sat = js_numbers(js, "RAMP_SATURATION");
    let neutral = js_numbers(js, "NEUTRAL_LIGHTNESS");
    assert_eq!(sat.len(), 2, "the saturation ramp has two ends");
    assert_eq!(neutral.len(), 2, "one neutral grey per theme");

    // The outline is what actually clears 3:1 for every node, whatever the
    // ramp does to the fill; --surface would be the stage's own colour.
    let circle = block(css, ".gnode circle {");
    assert!(
        circle.contains("stroke: var(--text-muted)"),
        ".gnode circle must stroke with a colour that contrasts with the stage, got: {circle}"
    );

    for (i, dark) in [false, true].into_iter().enumerate() {
        let theme = if dark { "dark" } else { "light" };
        let ramp = js_numbers(
            js,
            if dark {
                "RAMP_LIGHTNESS_DARK"
            } else {
                "RAMP_LIGHTNESS_LIGHT"
            },
        );
        assert_eq!(ramp.len(), 2, "the {theme} ramp has two ends");
        let stage = srgb_from_hex(&css_token(tokens, "--surface", dark));
        let stroke = srgb_from_hex(&css_token(tokens, "--text-muted", dark));

        let outline = contrast(stroke, stage);
        assert!(
            outline >= 3.0,
            "the node outline is {outline:.2}:1 against the {theme} stage, want >= 3"
        );

        // Still a belief scale: the ends stay far apart in lightness.
        assert!(
            (ramp[0] - ramp[1]).abs() >= 30.0,
            "the {theme} ramp spans only {} lightness points",
            (ramp[0] - ramp[1]).abs()
        );

        for &hue in &hues {
            let pale = srgb_from_hsl(hue, sat[0], ramp[0]);
            let ratio = contrast(pale, stage);
            assert!(
                ratio >= 1.5,
                "a no-belief node hsl({hue}, {}%, {}%) is {ratio:.2}:1 against the {theme} stage",
                sat[0],
                ramp[0]
            );
            let strong = srgb_from_hsl(hue, sat[1], ramp[1]);
            let scale = contrast(strong, pale);
            assert!(
                scale >= 1.6,
                "hue {hue}: high and low belief are only {scale:.2}:1 apart in {theme}"
            );
        }

        let grey = srgb_from_hsl(210.0, 6.0, neutral[i]);
        let ratio = contrast(grey, stage);
        assert!(
            ratio >= 1.5,
            "a redacted node is {ratio:.2}:1 against the {theme} stage"
        );
        assert!(
            (neutral[i] - ramp[0]).abs() <= 10.0,
            "the {theme} neutral grey drifted away from the ramp's low end"
        );

        // The legend swatch claims to show this ramp; keep it honest.
        let gradient = format!(
            "hsl(212, {}%, {}%), hsl(212, {}%, {}%)",
            sat[0] as i64, ramp[0] as i64, sat[1] as i64, ramp[1] as i64
        );
        assert!(
            css.contains(&gradient),
            ".graph__ramp must paint the {theme} ramp: {gradient}"
        );
    }
}

/// `load` used to write "Loading neighbours…" / "Added N nodes." into the side
/// panel whatever node was selected when the fetch landed, so selecting
/// another node mid-fetch showed it a status about the first one.
#[test]
fn expansion_status_is_addressed_to_the_node_that_asked_for_it() {
    let js = include_str!("../static/graph.js");

    let setter = block(js, "setPanelStatus(anchor, text) {");
    assert!(
        setter.contains("this.selected !== anchor"),
        "setPanelStatus must drop messages for a node that is no longer selected: {setter}"
    );

    // Every panel-status message goes through that guard. `select` clears the
    // element through its own alias when the selection really did change.
    assert_eq!(
        js.matches("panel.status.textContent").count(),
        1,
        "only setPanelStatus may write the panel status"
    );
    assert!(
        !js.contains("forPanel"),
        "the unguarded panel branch of setStatus is gone"
    );

    let load = block(js, "async load(url, anchor) {");
    assert!(
        !load.contains("status.textContent"),
        "load must not touch a status element directly: {load}"
    );
    assert_eq!(
        load.matches("this.setPanelStatus(anchor,").count(),
        2,
        "load's progress and outcome messages are anchored"
    );
    assert_eq!(
        load.matches("this.reportLoadError(anchor,").count(),
        2,
        "load's two failure paths are anchored"
    );

    let report = block(js, "reportLoadError(anchor, message) {");
    assert!(
        report.contains("this.setPanelStatus(anchor, message)"),
        "an expansion's failure goes through the guard too: {report}"
    );

    let expand = block(js, "async expand(n) {");
    assert_eq!(
        expand.matches("this.setPanelStatus(n,").count(),
        2,
        "expand's own refusals are anchored to the node they are about"
    );
}
