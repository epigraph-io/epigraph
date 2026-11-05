//! The Atlas (Topics view, phase P3a): `/atlas` and the six `/bff/atlas/*`
//! routes, against a wiremock upstream shaped like the U1-U5 contracts
//! (batch-get, claim context, theme layout, graph links, theme-pinned
//! search). Every request test checks the viewer's own bearer reached
//! upstream; the tenancy test (T25) runs two viewers side by side.

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::Router;
use common::{spawn, spawn_with, TestApp, TestResponse};
use epigraph_explorer::auth::flow::validate_return_to;
use epigraph_explorer::config::ENV_UPSTREAM_TIMEOUT_MS;
use epigraph_explorer::links::Links;
use epigraph_explorer::pages::atlas::VENDOR_SCRIPTS;
use epigraph_explorer::pages::core::relationships::heading;
use epigraph_explorer::upstream::EdgeDirection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wiremock::matchers::{
    body_json, body_partial_json, header, method, path, query_param, query_param_is_missing,
};
use wiremock::{Match, Mock, Request, ResponseTemplate};

const T: &str = "2c9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const T2: &str = "2c9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a11";
const T3: &str = "2c9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a12";
/// A theme only viewer A can see.
const H: &str = "2c9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a1f";
const R: &str = "3d9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const R2: &str = "3d9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a11";
/// A region no response carries.
const R9: &str = "3d9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a19";
const RUN: &str = "8a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const RUN2: &str = "8a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a11";
const C1: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a11";
const C2: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a12";
const C3: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a13";
const C4: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a14";
const C5: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a15";
/// A private claim only viewer A can read.
const P: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a99";
/// A claim id that never existed.
const N: &str = "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a98";
const PAPER: &str = "5b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const AGENT: &str = "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const E1: &str = "7a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const E2: &str = "7a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a11";
const E3: &str = "7a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a12";
const E4: &str = "7a9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a13";

const LAYOUT: &str = "/api/v1/graph/themes/layout";
const SEARCH: &str = "/api/v1/search/semantic";
const BATCH: &str = "/api/v1/claims/batch-get";
const OVERVIEW: &str = "/api/v1/graph/themes/overview";
const LINKS: &str = "/api/v1/graph/links";

// ---- helpers ----------------------------------------------------------------------

fn simple(id: &str) -> String {
    id.replace('-', "")
}

fn bearer(tok: &str) -> String {
    format!("Bearer {tok}")
}

/// Matches a JSON body that lacks `key` entirely (not even `null`).
struct NoKey(&'static str);

impl Match for NoKey {
    fn matches(&self, r: &Request) -> bool {
        r.body_json::<Value>()
            .map(|v| v.get(self.0).is_none())
            .unwrap_or(false)
    }
}

fn text_plain(status: u16, body: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_raw(body.as_bytes().to_vec(), "text/plain; charset=utf-8")
}

fn not_found(entity: &str, id: &str) -> ResponseTemplate {
    ResponseTemplate::new(404).set_body_json(json!({
        "error": "NotFound",
        "message": format!("{entity} with ID {id} not found"),
        "details": {"entity": entity, "id": id}
    }))
}

fn forbidden() -> ResponseTemplate {
    ResponseTemplate::new(403).set_body_json(json!({
        "error": "Forbidden", "message": "not a member of that group"
    }))
}

async fn requests(app: &TestApp, p: &str) -> Vec<Request> {
    app.upstream
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == p)
        .collect()
}

async fn count_as(app: &TestApp, tok: &str) -> usize {
    let want = bearer(tok);
    app.upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| {
            r.headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(want.as_str())
        })
        .count()
}

async fn total_calls(app: &TestApp) -> usize {
    app.upstream.received_requests().await.unwrap().len()
}

fn query_of(r: &Request) -> BTreeMap<String, String> {
    r.url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn walk<'v>(v: &'v Value, f: &mut dyn FnMut(Option<&'v str>, &'v Value)) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                f(Some(k), x);
                walk(x, f);
            }
        }
        Value::Array(a) => {
            for x in a {
                f(None, x);
                walk(x, f);
            }
        }
        _ => {}
    }
}

fn assert_no_belief_keys(v: &Value) {
    walk(v, &mut |k, _| {
        if let Some(k) = k {
            assert!(
                ![
                    "belief",
                    "plausibility",
                    "pignistic_prob",
                    "epistemic",
                    "mean_betp"
                ]
                .contains(&k),
                "a body carries `{k}`"
            );
        }
    });
}

fn max_array_len(v: &Value) -> usize {
    let mut max = 0;
    if let Value::Array(a) = v {
        max = a.len();
    }
    walk(v, &mut |_, x| {
        if let Value::Array(a) = x {
            max = max.max(a.len());
        }
    });
    max
}

/// Every `href`-like string (not the external DOI link).
fn hrefs(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    walk(v, &mut |k, x| {
        if let (Some(k), Value::String(s)) = (k, x) {
            if k.ends_with("href") && k != "doi_href" {
                out.push(s.clone());
            }
        }
    });
    out
}

fn assert_private(res: &TestResponse, what: &str) {
    assert_eq!(
        res.header("cache-control"),
        Some("private, no-store"),
        "{what}: per-viewer JSON must not be stored"
    );
    assert!(res.header("etag").is_none(), "{what}: no ETag");
}

async fn mount_dir(app: &TestApp, tok: &str, themes: Value) {
    Mock::given(method("GET"))
        .and(path(OVERVIEW))
        .and(header("authorization", bearer(tok).as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "themes": themes })))
        .mount(&app.upstream)
        .await;
}

fn dir_default() -> Value {
    json!([
        {"id": T, "label": "Theme one", "claim_count": 42},
        {"id": T2, "label": "Theme two", "claim_count": 7}
    ])
}

fn run_json(stale: bool) -> Value {
    json!({"run_id": RUN, "completed_at": "2026-11-01T00:00:00Z", "algo": "pca2-ward-v1",
           "cluster_run_id": RUN2, "stale": stale, "extent": 1000.0})
}

fn top_json(member: i64) -> Value {
    json!({
        "run": run_json(false), "status": null,
        "relationships": ["supports", "contradicts", "cites"],
        "regions": [
            {"id": R, "label": "Region one", "x": -412.3, "y": 88.1, "r": 151.0,
             "theme_ids": [T, T2], "theme_count": 2, "member_count": member},
            {"id": R2, "label": "Region two", "x": 300.0, "y": -50.0, "r": 90.0,
             "theme_ids": [T3], "theme_count": 1, "member_count": member}
        ],
        "links": [{"kind": "region", "a": R, "b": R2,
                   "counts": {"SUPPORTS": 30, "supports": 10, "contradicts": 6}, "total": 46}],
        "unplaced_theme_count": 1,
        "next": {"themes": null, "links": null}
    })
}

fn region_json(member: i64) -> Value {
    json!({
        "run": run_json(false), "status": null, "relationships": ["supports"],
        "region": {"id": R, "label": "Region one", "x": -412.3, "y": 88.1, "r": 151.0,
                   "theme_count": 2, "member_count": member},
        "themes": [
            {"id": T, "label": "Theme one", "region_id": R, "placement": "shared",
             "x": -398.0, "y": 120.5, "member_count": member},
            {"id": T2, "label": "Theme two", "region_id": R, "placement": "viewer",
             "x": null, "y": null, "member_count": member}
        ],
        "links": [
            {"kind": "theme", "a": T, "b": T2, "counts": {"supports": 5}, "total": 5},
            {"kind": "theme_region", "a": T, "b": R2, "counts": {"cites": 2}, "total": 2}
        ],
        "next": {"themes": "lt2.3.abc", "links": null}
    })
}

fn no_run_json(status: &str) -> Value {
    json!({"run": null, "status": status, "regions": [], "links": [],
           "unplaced_theme_count": 0, "next": {"themes": null, "links": null}})
}

/// Top level: no `region_id`. Region level: `region_id` as given.
async fn mount_layout(app: &TestApp, region: Option<&str>, body: Value) {
    let m = Mock::given(method("GET")).and(path(LAYOUT));
    let m = match region {
        Some(r) => m.and(query_param("region_id", r)),
        None => m.and(query_param_is_missing("region_id")),
    };
    m.respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&app.upstream)
        .await;
}

fn hit(id: &str, statement: &str, truth: f64) -> Value {
    json!({"claim_id": id, "statement": statement, "similarity": 0.8,
           "epistemic": {"belief": 0.42, "plausibility": 0.9, "ignorance": 0.48, "truth_value": truth},
           "agent_id": AGENT, "created_at": "2026-11-01T00:00:00Z"})
}

fn search_body(hits: Vec<Value>, scope: Option<(&str, i64)>, next: Option<&str>) -> Value {
    let mut v = json!({"total": hits.len(), "query_time_ms": 3, "results": hits});
    if let Some((t, m)) = scope {
        v["theme_scope"] = json!({"theme_id": t, "member_count": m, "rank_by": "theme_core"});
    }
    if let Some(n) = next {
        v["next_cursor"] = json!(n);
    }
    v
}

fn batch_claim(id: &str, content: &str, truth: f64, current: bool) -> Value {
    json!({"id": id, "content": content, "truth_value": truth, "agent_id": AGENT,
           "trace_id": null, "created_at": "2026-11-01T00:00:00Z",
           "updated_at": "2026-11-01T00:00:00Z", "is_current": current})
}

async fn mount_theme_search(app: &TestApp, hits: Vec<Value>, member: i64) {
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .and(body_partial_json(
            json!({"theme_id": T, "rank_by": "theme_core"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(search_body(
            hits,
            Some((T, member)),
            None,
        )))
        .mount(&app.upstream)
        .await;
}

fn three_hits() -> Vec<Value> {
    vec![
        hit(C1, "First claim", 0.1),
        hit(C2, "Second claim", 0.2),
        hit(C3, "Third claim", 0.3),
    ]
}

fn node(id: &str, content: &str, theme: Option<&str>) -> Value {
    json!({"id": id, "content": content, "content_truncated": false, "truth_value": 0.4,
           "is_current": true, "theme_id": theme})
}

fn context_json() -> Value {
    json!({
        "claim": {"id": C1, "content": "The centre claim.", "content_truncated": false,
                  "truth_value": 0.72, "is_current": true, "level": 2, "theme_id": T},
        "paper": {"id": PAPER, "doi": "10.1234/abc(1)", "title": "A paper", "truncated": false},
        "papers": {"items": [{"id": PAPER, "doi": "10.1234/abc(1)", "title": "A paper",
                              "truncated": false}], "total": 1, "next_cursor": null},
        "section": node(C5, "Methods", None),
        "parents": {"items": [node(C5, "Methods", None)], "total": 1, "next_cursor": null},
        "parts": {"items": [node(C2, "A part", Some(T))], "total": 50, "next_cursor": "k1.1.ab"},
        "siblings": {"parent_id": C5, "items": [node(C4, "A sibling", Some(T))], "total": 12,
                     "next_cursor": null},
        "edges": {
            "items": [
                {"edge_id": E1, "relationship": "CONTRADICTS", "direction": "incoming",
                 "strength": 0.9, "neighbor": node(C3, "Across themes", Some(T2))},
                {"edge_id": E2, "relationship": "refutes", "direction": "incoming",
                 "neighbor": node(C4, "A refuter", Some(T))},
                {"edge_id": E3, "relationship": "cites", "direction": "outgoing",
                 "neighbor": node(C2, "Cited", Some(T))}
            ],
            "total": 3,
            "by_relationship": [
                {"relationship": "contradicts", "direction": "incoming", "count": 1},
                {"relationship": "refutes", "direction": "incoming", "count": 1},
                {"relationship": "cites", "direction": "outgoing", "count": 1}
            ],
            "next_cursor": null
        }
    })
}

fn placement_json(id: &str, theme: Option<&str>, layout: Value) -> Value {
    json!({"claim_id": id, "theme_id": theme, "cluster_run_id": null, "cluster_id": null,
           "layout": layout, "neighborhood_id": null, "run_completed_at": null})
}

fn shared_layout() -> Value {
    json!({"run_id": RUN, "region_id": R, "placement": "shared", "x": -398.0, "y": 120.5})
}

fn link_item(edge: &str, rel: &str, src: &str, tgt: &str) -> Value {
    json!({"edge_id": edge, "relationship": rel, "strength": 0.5, "direction": "from_to",
           "created_at": "2026-11-01T00:00:00Z",
           "source": {"id": src, "label": "source claim", "truth_value": 0.7, "theme_id": T},
           "target": {"id": tgt, "label": "target claim", "truth_value": 0.2, "theme_id": T2}})
}

async fn mount_get(app: &TestApp, p: &str, resp: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(resp)
        .mount(&app.upstream)
        .await;
}

fn ok(body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

// ---- the page ---------------------------------------------------------------------

#[tokio::test]
async fn atlas_page_anonymous_is_a_signin_shell_with_no_upstream_call() {
    let app = spawn().await;
    let res = app.get("/explorer/atlas").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.body
            .contains(r#"<meta property="og:title" content="The EpiGraph Atlas">"#),
        "{}",
        res.body
    );
    assert!(res.body.contains(
        r#"<meta property="og:url" content="https://explorer.example.com/explorer/atlas">"#
    ));
    assert!(res.body.contains(r#"data-role="atlas-signin""#));
    assert!(res.body.contains(r#"data-atlas-mode="anon""#));
    assert!(res
        .body
        .contains("/explorer/auth/login?return_to=%2Fexplorer%2Fatlas"));
    assert!(
        !res.body.contains("vendor/d3"),
        "the sign-in shell loads atlas.js only"
    );
    assert_eq!(res.header("cache-control"), Some("private, no-store"));
    assert!(app.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn atlas_page_signed_in_is_a_shell_without_inline_script_or_style() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/atlas", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let body = &res.body;

    let mut last = 0;
    for name in VENDOR_SCRIPTS.iter().copied().chain(["atlas.js"]) {
        let needle = format!("src=\"/explorer/static/{name}");
        let at = body
            .find(&needle)
            .unwrap_or_else(|| panic!("{name} is loaded: {body}"));
        assert!(at > last, "{name} loads after the module before it");
        last = at;
        let rest = &body[at + needle.len()..];
        if epigraph_explorer::assets::find(name).is_some() {
            assert!(rest.starts_with("?v="), "{name} is content-hashed");
        }
    }
    assert!(
        epigraph_explorer::assets::find("atlas.js").is_some()
            && epigraph_explorer::assets::find("atlas.css").is_some()
    );
    for (i, _) in body.match_indices("<script") {
        let tag = &body[i..i + body[i..].find('>').unwrap()];
        assert!(tag.contains(" src=\""), "inline script: {tag}");
        assert!(tag.contains(" defer"), "{tag}");
    }
    assert!(!body.contains("style="), "no inline style anywhere");
    assert!(
        !body.contains("class=\"search-form\""),
        "the Atlas replaces the header search with its own"
    );
    assert!(body.contains(r#"data-atlas-mode="signed-in""#));
    assert!(body.contains(r#"data-layout-url="/explorer/bff/atlas/layout""#));
    assert!(body.contains(r#"data-resolve-prefix="/explorer/bff/atlas/resolve/""#));
    assert!(body.contains(r#"data-themes-url="/explorer/bff/themes""#));
    assert!(res
        .header("content-security-policy")
        .unwrap()
        .contains("script-src 'self'"));
    assert_eq!(res.header("cache-control"), Some("private, no-store"));
    assert!(app.upstream.received_requests().await.unwrap().is_empty());

    // Every other page keeps the header search byte for byte.
    let other = app.get_as("/explorer/no-such-page", &sid).await;
    assert!(other.body.contains("class=\"search-form\""));
}

#[tokio::test]
async fn every_atlas_route_is_built_at_both_mounts() {
    let app = spawn().await;
    mount_layout(&app, None, top_json(10)).await;
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .respond_with(ok(search_body(
            vec![hit(C1, "A claim", 0.5)],
            Some((T, 10)),
            None,
        )))
        .mount(&app.upstream)
        .await;
    Mock::given(method("POST"))
        .and(path(BATCH))
        .respond_with(ok(
            json!({"claims": [batch_claim(C1, "A claim", 0.5, true)],
                                "not_found": [], "remaining": []}),
        ))
        .mount(&app.upstream)
        .await;
    mount_get(&app, OVERVIEW, ok(json!({"themes": dir_default()}))).await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/context"),
        ok(context_json()),
    )
    .await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/placement"),
        ok(placement_json(C1, Some(T), Value::Null)),
    )
    .await;
    mount_get(
        &app,
        LINKS,
        ok(json!({"counts": {"supports": 1}, "total": 1,
                  "items": [link_item(E1, "supports", C1, C2)], "next": null})),
    )
    .await;
    let sid = app.sign_in("tok");

    for base in ["/explorer", ""] {
        let page = app.get_as(&format!("{base}/atlas"), &sid).await;
        assert_eq!(page.status, StatusCode::OK, "{base}/atlas");
        assert!(page
            .header("content-type")
            .unwrap()
            .starts_with("text/html"));
        assert!(page
            .body
            .contains("data-layout-url=\"/explorer/bff/atlas/layout\""));
        for route in [
            "/bff/atlas/layout".to_string(),
            format!("/bff/atlas/theme/{T}/claims"),
            format!("/bff/atlas/claim/{C1}"),
            format!("/bff/atlas/links?from={T}&to={T2}"),
            "/bff/atlas/search?q=water".to_string(),
            format!("/bff/atlas/resolve/c-{}", simple(C1)),
        ] {
            let uri = format!("{base}{route}");
            let res = app.get_as(&uri, &sid).await;
            assert_eq!(res.status, StatusCode::OK, "{uri}: {}", res.body);
            assert!(res
                .header("content-type")
                .unwrap()
                .starts_with("application/json"));
            assert_private(&res, &uri);
            for h in hrefs(&res.json()) {
                assert!(h.starts_with("/explorer/"), "{uri}: {h} is base-path aware");
            }
        }
    }
    for r in app.upstream.received_requests().await.unwrap() {
        assert_eq!(
            r.headers.get("authorization").unwrap(),
            "Bearer tok",
            "the viewer's own bearer, never a service token"
        );
    }
}

#[tokio::test]
async fn atlas_bff_routes_require_sign_in() {
    let app = spawn().await;
    for uri in [
        "/explorer/bff/atlas/layout".to_string(),
        format!("/explorer/bff/atlas/theme/{T}/claims"),
        format!("/explorer/bff/atlas/claim/{C1}"),
        format!("/explorer/bff/atlas/links?from={T}&to={T2}"),
        "/explorer/bff/atlas/search?q=x".to_string(),
        format!("/explorer/bff/atlas/resolve/c-{}", simple(C1)),
    ] {
        let res = app.get(&uri).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(res.json()["error"], "unauthorized", "{uri}");
    }
    assert!(app.upstream.received_requests().await.unwrap().is_empty());
}

// ---- layout -----------------------------------------------------------------------

#[tokio::test]
async fn layout_top_level_maps_params_and_drops_theme_ids() {
    let app = spawn().await;
    mount_layout(&app, None, top_json(10)).await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(
            "/explorer/bff/atlas/layout?rel=Supports,cites&structure=1&limit=999",
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_private(&res, "layout");

    let reqs = requests(&app, LAYOUT).await;
    assert_eq!(reqs.len(), 1);
    let q = query_of(&reqs[0]);
    assert_eq!(q.get("rel").map(String::as_str), Some("supports,cites"));
    assert_eq!(q.get("include_structure").map(String::as_str), Some("true"));
    assert_eq!(q.get("limit").map(String::as_str), Some("200"));
    assert!(!q.contains_key("region_id") && !q.contains_key("run_id"));
    assert_eq!(reqs[0].headers.get("authorization").unwrap(), "Bearer tok");

    let b = res.json();
    assert_eq!(b["mode"], "layout");
    assert_eq!(b["run"]["run_id"], RUN);
    assert!(!res.body.contains("theme_ids"), "{}", res.body);
    assert!(!res.body.contains("cluster_run_id"));
    assert_eq!(b["regions"].as_array().unwrap().len(), 2);
    assert_eq!(b["regions"][0]["theme_count"], 2);
    assert_eq!(
        b["links"][0]["counts"],
        json!({"supports": 40, "contradicts": 6}),
        "spellings fold and merge"
    );
    assert_eq!(b["links"][0]["total"], 46);
    let share = b["links"][0]["refute_share"].as_f64().unwrap();
    assert!((share - 0.1304).abs() < 1e-9, "{share}");
    assert_eq!(b["unplaced_theme_count"], 1);
    assert_eq!(b["notice"], Value::Null);
}

#[tokio::test]
async fn layout_rejects_bad_params_before_any_upstream_call() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    for q in [
        "region=nope".to_string(),
        "structure=maybe".to_string(),
        "limit=abc".to_string(),
        "themes_after=x".to_string(),
        format!("region={R}&themes_after=a&links_after=b"),
        "rel=a%3Bb".to_string(),
        "links_after=a%24b".to_string(),
        "after=p.7".to_string(),
        "run=nope".to_string(),
    ] {
        let res = app
            .get_as(&format!("/explorer/bff/atlas/layout?{q}"), &sid)
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{q}: {}", res.body);
        assert_eq!(res.json()["error"], "bad_request", "{q}");
    }
    assert!(app.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn layout_region_level_and_unplaced() {
    let app = spawn().await;
    mount_layout(&app, Some(R), region_json(10)).await;
    mount_layout(
        &app,
        Some("unplaced"),
        json!({"run": run_json(false), "status": null, "relationships": [], "region": null,
               "themes": [{"id": T3, "label": "Loose theme", "region_id": null, "placement": null,
                           "x": null, "y": null, "member_count": 3}],
               "links": [], "next": {"themes": null, "links": null}}),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(LAYOUT))
        .and(query_param("region_id", R9))
        .respond_with(not_found("Region", R9))
        .mount(&app.upstream)
        .await;
    mount_layout(&app, None, top_json(10)).await;
    mount_dir(&app, "tok", dir_default()).await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(&format!("/explorer/bff/atlas/layout?region={R}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = res.json();
    assert_eq!(b["region"]["id"], R);
    assert_eq!(b["themes"][0]["placement"], "shared");
    assert_eq!(b["themes"][0]["x"], -398.0);
    assert_eq!(b["themes"][1]["placement"], "viewer");
    assert_eq!(b["themes"][1]["x"], Value::Null);
    assert_eq!(b["links"].as_array().unwrap().len(), 2);
    assert_eq!(b["next"]["themes"], "lt2.3.abc");
    let region_calls: Vec<_> = requests(&app, LAYOUT)
        .await
        .into_iter()
        .filter(|r| query_of(r).get("region_id").map(String::as_str) == Some(R))
        .collect();
    assert_eq!(region_calls.len(), 1);

    let res = app
        .get_as("/explorer/bff/atlas/layout?region=unplaced", &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = res.json();
    assert_eq!(b["region"], Value::Null);
    assert_eq!(b["themes"][0]["x"], Value::Null);
    assert_eq!(b["themes"][0]["region_id"], Value::Null);

    let res = app
        .get_as(&format!("/explorer/bff/atlas/layout?region={R9}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json()["message"], "We could not find that region.");
    let res = app
        .get_as(
            &format!("/explorer/bff/atlas/layout?region={R9}&run={RUN}"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json()["message"], "We could not find that map version.");
}

fn many_themes(n: u128) -> Value {
    Value::Array(
        (0..n)
            .map(|i| {
                json!({"id": Uuid::from_u128(0x1000 + i), "label": format!("Theme {i}"),
                       "claim_count": 1000 - i as i64})
            })
            .collect(),
    )
}

#[tokio::test]
async fn layout_without_a_run_falls_back_to_packed_themes() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(LAYOUT))
        .respond_with(ok(no_run_json("no_layout_run")))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(OVERVIEW))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(json!({"themes": many_themes(250)})))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app.get_as("/explorer/bff/atlas/layout", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_private(&res, "packed");
    let b = res.json();
    assert_eq!(b["mode"], "packed");
    assert_eq!(b["status"], "no_layout_run");
    assert_eq!(b["run"], Value::Null);
    assert_eq!(b["themes"].as_array().unwrap().len(), 200);
    assert_eq!(
        b["themes"][0]["member_count"], 1000,
        "U1's live claim_count"
    );
    assert_eq!(b["next"], "p.200");
    assert_eq!(b["total"], 250);
    assert_eq!(b["truncated"], false);
    assert!(b["notice"].as_str().unwrap().contains("no layout run"));

    let res = app
        .get_as("/explorer/bff/atlas/layout?after=p.200", &sid)
        .await;
    let b = res.json();
    assert_eq!(b["themes"].as_array().unwrap().len(), 50);
    assert_eq!(b["next"], Value::Null);
    let res = app
        .get_as("/explorer/bff/atlas/layout?after=p.400", &sid)
        .await;
    let b = res.json();
    assert_eq!(b["themes"], json!([]));
    assert_eq!(b["next"], Value::Null);
    // Both decodes were cached: one layout call and one U1 walk in all.
    app.upstream.verify().await;

    let app = spawn().await;
    mount_get(&app, LAYOUT, ok(no_run_json("layout_invalidated"))).await;
    mount_get(&app, OVERVIEW, ok(json!({"themes": many_themes(3)}))).await;
    let sid = app.sign_in("tok");
    let b = app.get_as("/explorer/bff/atlas/layout", &sid).await.json();
    assert_eq!(b["mode"], "packed");
    assert_eq!(b["status"], "layout_invalidated");
    assert_eq!(b["themes"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn layout_is_cached_per_viewer_only_for_default_shapes() {
    let app = spawn().await;
    for (tok, m) in [("tok-a", 11), ("tok-b", 10)] {
        Mock::given(method("GET"))
            .and(path(LAYOUT))
            .and(header("authorization", bearer(tok).as_str()))
            .respond_with(ok(top_json(m)))
            .mount(&app.upstream)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(LAYOUT))
        .and(header("authorization", "Bearer tok-c"))
        .respond_with(text_plain(500, "relation atlas_layout_runs does not exist"))
        .mount(&app.upstream)
        .await;
    let a = app.sign_in("tok-a");
    let b = app.sign_in("tok-b");
    let c = app.sign_in("tok-c");

    let first = app.get_as("/explorer/bff/atlas/layout", &a).await;
    assert_eq!(first.json()["regions"][0]["member_count"], 11);
    let again = app.get_as("/explorer/bff/atlas/layout", &a).await;
    assert_eq!(again.body, first.body);
    assert_eq!(
        count_as(&app, "tok-a").await,
        1,
        "a repeat default request is cached"
    );

    let other = app.get_as("/explorer/bff/atlas/layout", &b).await;
    assert_eq!(
        other.json()["regions"][0]["member_count"],
        10,
        "B's own body"
    );
    assert_eq!(count_as(&app, "tok-b").await, 1);

    let mut expected = 1;
    for extra in ["rel=supports", "links_after=x", "limit=50"] {
        for _ in 0..2 {
            let res = app
                .get_as(&format!("/explorer/bff/atlas/layout?{extra}"), &a)
                .await;
            assert_eq!(res.status, StatusCode::OK, "{extra}");
            expected += 1;
        }
        assert_eq!(
            count_as(&app, "tok-a").await,
            expected,
            "{extra}: not a default shape, so never cached"
        );
    }

    for _ in 0..2 {
        let res = app.get_as("/explorer/bff/atlas/layout", &c).await;
        assert_eq!(res.status, StatusCode::BAD_GATEWAY);
        assert_eq!(res.json()["error"], "upstream_unavailable");
        assert!(!res.body.contains("atlas_layout_runs"));
    }
    assert_eq!(count_as(&app, "tok-c").await, 2, "a failure is not cached");
}

#[tokio::test]
async fn layout_falls_back_to_packed_when_the_layout_route_is_missing() {
    for status in [404u16, 405] {
        let app = spawn().await;
        mount_get(&app, LAYOUT, ResponseTemplate::new(status)).await;
        mount_get(&app, OVERVIEW, ok(json!({"themes": many_themes(2)}))).await;
        let sid = app.sign_in("tok");
        let res = app.get_as("/explorer/bff/atlas/layout", &sid).await;
        assert_eq!(res.status, StatusCode::OK, "{status}: {}", res.body);
        let b = res.json();
        assert_eq!(b["mode"], "packed", "{status}");
        assert_eq!(b["status"], "no_layout_run");
        assert_eq!(b["themes"].as_array().unwrap().len(), 2);
    }
    let app = spawn().await;
    mount_get(&app, LAYOUT, not_found("Layout run", RUN)).await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/bff/atlas/layout?run={RUN}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.body);
    assert_eq!(res.json()["message"], "We could not find that map version.");
}

#[tokio::test]
async fn layout_drops_links_to_ids_the_body_does_not_carry() {
    let app = spawn().await;
    let mut top = top_json(10);
    top["links"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind": "region", "a": R, "b": R9, "counts": {"supports": 9}, "total": 9}));
    mount_layout(&app, None, top).await;
    let mut region = region_json(10);
    let links = region["links"].as_array_mut().unwrap();
    links.push(json!({"kind": "theme", "a": T, "b": H, "counts": {"supports": 4}, "total": 4}));
    links
        .push(json!({"kind": "theme_region", "a": T, "b": R9, "counts": {"cites": 1}, "total": 1}));
    mount_layout(&app, Some(R), region).await;
    mount_dir(&app, "tok", dir_default()).await;
    let sid = app.sign_in("tok");

    let res = app.get_as("/explorer/bff/atlas/layout", &sid).await;
    let b = res.json();
    assert_eq!(b["links"].as_array().unwrap().len(), 1, "{}", res.body);
    assert!(!res.body.contains(R9));

    let res = app
        .get_as(&format!("/explorer/bff/atlas/layout?region={R}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(
        res.json()["links"].as_array().unwrap().len(),
        2,
        "{}",
        res.body
    );
    assert!(
        !res.body.contains(H),
        "the hidden theme's id appears nowhere"
    );
    assert!(!res.body.contains(R9));

    // The viewer's top level cannot be read: every theme_region link goes.
    let app = spawn().await;
    mount_layout(&app, Some(R), region_json(10)).await;
    Mock::given(method("GET"))
        .and(path(LAYOUT))
        .and(query_param_is_missing("region_id"))
        .respond_with(text_plain(500, "boom"))
        .mount(&app.upstream)
        .await;
    mount_dir(&app, "tok", dir_default()).await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/bff/atlas/layout?region={R}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let links = res.json()["links"].clone();
    assert_eq!(links.as_array().unwrap().len(), 1);
    assert_eq!(links[0]["kind"], "theme");
}

// ---- theme claims -----------------------------------------------------------------

#[tokio::test]
async fn theme_claims_run_theme_core_search_then_batch_get() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .and(header("authorization", "Bearer tok"))
        .and(body_partial_json(json!({
            "theme_id": T, "rank_by": "theme_core", "limit": 60, "cursor": "o:0"
        })))
        .and(NoKey("query"))
        .respond_with(ok(search_body(three_hits(), Some((T, 412)), Some("o:60"))))
        .expect(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("POST"))
        .and(path(BATCH))
        .and(header("authorization", "Bearer tok"))
        .and(body_json(json!({"ids": [C1, C2, C3]})))
        .respond_with(ok(json!({
            "claims": [batch_claim(C3, "Third claim", 0.93, false),
                       batch_claim(C1, "First claim", 0.91, true),
                       batch_claim(C2, "Second claim", 0.92, true)],
            "not_found": [], "remaining": []
        })))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(&format!("/explorer/bff/atlas/theme/{T}/claims"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_private(&res, "theme claims");
    let b = res.json();
    assert_eq!(b["theme"], json!({"id": T, "label": "Theme one"}));
    assert_eq!(b["member_count"], 412);
    assert_eq!(b["next"], "o:60");
    assert_eq!(b["truncated"], false);
    let claims = b["claims"].as_array().unwrap();
    let ids: Vec<&str> = claims.iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!(ids, [C1, C2, C3], "search order, not batch-get order");
    let ranks: Vec<i64> = claims.iter().map(|c| c["rank"].as_i64().unwrap()).collect();
    assert_eq!(ranks, [0, 1, 2]);
    let truths: Vec<f64> = claims
        .iter()
        .map(|c| c["truth_value"].as_f64().unwrap())
        .collect();
    assert_eq!(
        truths,
        [0.91, 0.92, 0.93],
        "truth values come from batch-get"
    );
    assert_eq!(claims[2]["is_current"], false);
    assert_eq!(claims[0]["key"], format!("c-{}", simple(C1)));
    assert_eq!(claims[0]["href"], format!("/explorer/claim/{C1}"));
    assert_eq!(claims[0]["label"], "First claim");
    assert_no_belief_keys(&b);
    app.upstream.verify().await;
}

#[tokio::test]
async fn theme_claims_drop_not_found_and_keep_rank_gaps() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    mount_theme_search(&app, three_hits(), 3).await;
    Mock::given(method("POST"))
        .and(path(BATCH))
        .respond_with(ok(json!({
            "claims": [batch_claim(C1, "First claim", 0.5, true),
                       batch_claim(C3, "Third claim", 0.5, true)],
            "not_found": [C2], "remaining": []
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    for (after, start) in [("", 0), ("?after=o:40", 40)] {
        let res = app
            .get_as(
                &format!("/explorer/bff/atlas/theme/{T}/claims{after}"),
                &sid,
            )
            .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.body);
        let b = res.json();
        let claims = b["claims"].as_array().unwrap();
        let ids: Vec<&str> = claims.iter().map(|c| c["id"].as_str().unwrap()).collect();
        assert_eq!(ids, [C1, C3], "the vanished claim is dropped");
        let ranks: Vec<i64> = claims.iter().map(|c| c["rank"].as_i64().unwrap()).collect();
        assert_eq!(ranks, [start, start + 2], "ranks keep the gap");
        assert!(!res.body.contains(C2));
    }
}

#[tokio::test]
async fn theme_claims_resubmit_remaining_at_most_three_times() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    mount_theme_search(&app, three_hits(), 3).await;
    for (ids, claims, remaining) in [
        (
            json!([C1, C2, C3]),
            json!([batch_claim(C1, "First claim", 0.61, true)]),
            json!([C2, C3]),
        ),
        (
            json!([C2, C3]),
            json!([batch_claim(C2, "Second claim", 0.62, true)]),
            json!([C3]),
        ),
        (json!([C3]), json!([]), json!([C3])),
    ] {
        Mock::given(method("POST"))
            .and(path(BATCH))
            .and(body_json(json!({ "ids": ids })))
            .respond_with(ok(
                json!({"claims": claims, "not_found": [], "remaining": remaining}),
            ))
            .expect(1)
            .mount(&app.upstream)
            .await;
    }
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/bff/atlas/theme/{T}/claims"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(requests(&app, BATCH).await.len(), 3);
    let b = res.json();
    let c = &b["claims"];
    assert_eq!(c[0]["truth_value"], 0.61);
    assert_eq!(c[1]["truth_value"], 0.62);
    assert_eq!(c[2]["id"], C3);
    assert_eq!(c[2]["is_current"], Value::Null, "left over: hit data only");
    assert_eq!(c[2]["truth_value"], 0.3);
    app.upstream.verify().await;
}

#[tokio::test]
async fn theme_claims_clamp_and_validate() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    mount_theme_search(&app, Vec::new(), 0).await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(
            &format!("/explorer/bff/atlas/theme/{T}/claims?limit=500"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let res = app
        .get_as(
            &format!("/explorer/bff/atlas/theme/{T}/claims?after=o:40"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let bodies: Vec<Value> = requests(&app, SEARCH)
        .await
        .iter()
        .map(|r| r.body_json().unwrap())
        .collect();
    assert_eq!(bodies[0]["limit"], 100, "clamped to the U2 maximum");
    assert_eq!(bodies[0]["cursor"], "o:0");
    assert_eq!(bodies[1]["cursor"], "o:40");
    assert_eq!(bodies[1]["limit"], 60);
    assert!(
        requests(&app, BATCH).await.is_empty(),
        "no ids, no batch-get"
    );

    let before = total_calls(&app).await;
    for bad in ["x%20y", "o:1000", "o:abc"] {
        let res = app
            .get_as(
                &format!("/explorer/bff/atlas/theme/{T}/claims?after={bad}"),
                &sid,
            )
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let res = app
        .get_as("/explorer/bff/atlas/theme/nope/claims", &sid)
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(res.json()["message"], "We could not find that theme.");
    assert_eq!(total_calls(&app).await, before);
}

#[tokio::test]
async fn theme_claims_404_is_identical_for_absent_unreadable_and_forbidden_themes() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    let (absent, empty, closed) = (T, T2, T3);
    for (id, resp) in [
        (absent, not_found("Theme", absent)),
        (empty, not_found("Theme", empty)),
        (closed, forbidden()),
    ] {
        Mock::given(method("POST"))
            .and(path(SEARCH))
            .and(body_partial_json(json!({"theme_id": id})))
            .respond_with(resp)
            .mount(&app.upstream)
            .await;
    }
    let sid = app.sign_in("tok");
    let mut seen = Vec::new();
    for id in [absent, empty, closed] {
        let res = app
            .get_as(&format!("/explorer/bff/atlas/theme/{id}/claims"), &sid)
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{id}");
        for any in [absent, empty, closed] {
            assert!(!res.body.contains(any), "no id in the body");
        }
        seen.push(res.body);
    }
    assert_eq!(seen[0], seen[1]);
    assert_eq!(seen[1], seen[2], "403 answers exactly as 404");
}

#[tokio::test]
async fn theme_search_rejects_an_upstream_that_ignored_theme_id() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .respond_with(ok(search_body(
            vec![hit(C4, "A global statement from everywhere", 0.5)],
            None,
            None,
        )))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    for uri in [
        format!("/explorer/bff/atlas/theme/{T}/claims"),
        format!("/explorer/bff/atlas/search?q=x&theme={T}"),
    ] {
        let res = app.get_as(&uri, &sid).await;
        assert_eq!(res.status, StatusCode::BAD_GATEWAY, "{uri}: {}", res.body);
        assert!(!res.body.contains(C4) && !res.body.contains("global statement"));
    }
    assert!(requests(&app, BATCH).await.is_empty());

    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "error": "UnprocessableEntity", "message": "missing field `query`"
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/bff/atlas/theme/{T}/claims"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::BAD_GATEWAY, "{}", res.body);
}

#[tokio::test]
async fn theme_claims_stop_batch_rounds_at_the_route_budget() {
    let app = spawn_with(&[(ENV_UPSTREAM_TIMEOUT_MS, "400")], Router::new()).await;
    mount_dir(&app, "tok", dir_default()).await;
    mount_theme_search(&app, three_hits(), 3).await;
    Mock::given(method("POST"))
        .and(path(BATCH))
        .respond_with(
            ok(json!({"claims": [], "not_found": [], "remaining": [C1, C2, C3]}))
                .set_delay(Duration::from_millis(300)),
        )
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let start = Instant::now();
    let res = app
        .get_as(&format!("/explorer/bff/atlas/theme/{T}/claims"), &sid)
        .await;
    let took = start.elapsed();
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        took < Duration::from_millis(1200),
        "the route budget (1.5 × 400 ms) bounds the rounds, took {took:?}"
    );
    assert!(
        requests(&app, BATCH).await.len() <= 2,
        "the third round never starts"
    );
    let b = res.json();
    let claims = b["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 3);
    assert!(claims.iter().all(|c| c["is_current"].is_null()));
}

#[tokio::test]
async fn batch_get_missing_route_degrades_to_hit_data() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    mount_theme_search(&app, three_hits(), 3).await;
    Mock::given(method("POST"))
        .and(path(BATCH))
        .respond_with(ResponseTemplate::new(404))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/bff/atlas/theme/{T}/claims"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = res.json();
    let claims = b["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 3);
    assert!(claims.iter().all(|c| c["is_current"].is_null()));
    assert_eq!(claims[1]["truth_value"], 0.2, "the hit's own truth value");
}

// ---- claim panel ------------------------------------------------------------------

#[tokio::test]
async fn claim_panel_composes_context_placement_and_directory() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{C1}/context")))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(context_json()))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{C1}/placement")))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(placement_json(C1, Some(T), shared_layout())))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(&format!("/explorer/bff/atlas/claim/{C1}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_private(&res, "claim panel");
    let b = res.json();
    let c = &b["claim"];
    assert_eq!(c["key"], format!("c-{}", simple(C1)));
    assert_eq!(c["content"], "The centre claim.");
    assert_eq!(c["truth_value"], 0.72);
    assert_eq!(c["theme"], json!({"id": T, "label": "Theme one"}));
    assert_eq!(
        c["embed_url"],
        format!(
            "https://explorer.example.com/explorer/atlas#c-{}",
            simple(C1)
        )
    );
    assert_eq!(c["history_href"], format!("/explorer/claim/{C1}/history"));
    assert_eq!(c["graph_href"], format!("/explorer/claim/{C1}/graph"));
    assert_eq!(
        b["contested"],
        json!({"status": "ok", "data": {"contested": true, "incoming": 2}})
    );
    assert_eq!(b["placement"]["status"], "ok");
    assert_eq!(b["placement"]["data"]["region_id"], R);
    assert_eq!(b["placement"]["data"]["x"], -398.0);

    assert_eq!(b["ring"]["status"], "ok");
    let ring = &b["ring"]["data"];
    let doi = ring["paper"]["doi_href"].as_str().unwrap();
    assert!(doi.starts_with("https://doi.org/"), "{doi}");
    assert_eq!(doi, "https://doi.org/10.1234/abc(1)");
    assert_eq!(ring["section"]["id"], C5);
    assert_eq!(ring["section"]["theme"], Value::Null);
    assert_eq!(
        ring["parts"]["items"][0]["key"],
        format!("c-{}", simple(C2))
    );
    assert_eq!(ring["parts"]["total"], 50);
    assert_eq!(ring["parts"]["next"], "k1.1.ab");
    assert_eq!(ring["siblings"]["parent_id"], C5);
    let edges = ring["edges"]["items"].as_array().unwrap();
    assert_eq!(edges[0]["neighbor"]["id"], C3);
    assert_eq!(edges[0]["neighbor"]["cross_theme"], true);
    assert_eq!(
        edges[0]["neighbor"]["theme"],
        json!({"id": T2, "label": "Theme two"})
    );
    assert_eq!(edges[0]["relationship"], "contradicts");
    assert_eq!(edges[0]["direction"], "incoming");
    assert_eq!(edges[0]["family"], "refute");
    assert_eq!(edges[0]["words"], heading("contradicts", EdgeDirection::In));
    assert_eq!(edges[2]["words"], heading("cites", EdgeDirection::Out));
    assert_eq!(edges[2]["neighbor"]["cross_theme"], false);
    assert_eq!(
        ring["edges"]["by_relationship"][0]["words"],
        heading("contradicts", EdgeDirection::In)
    );
    assert_no_belief_keys(&b);
}

#[tokio::test]
async fn claim_panel_falls_back_to_get_claim_when_context_fails() {
    let claim = json!({"id": C1, "content": "Full text from the claim route.", "truth_value": 0.6,
                       "agent_id": AGENT, "trace_id": null, "created_at": "2026-11-01T00:00:00Z"});
    // A context 500.
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/context"),
        text_plain(500, "boom"),
    )
    .await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/placement"),
        ok(placement_json(C1, Some(T), Value::Null)),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{C1}")))
        .respond_with(ok(claim.clone()))
        .expect(1)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/bff/atlas/claim/{C1}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = res.json();
    assert_eq!(b["claim"]["content"], "Full text from the claim route.");
    assert_eq!(b["claim"]["is_current"], Value::Null);
    assert_eq!(
        b["claim"]["theme"]["id"], T,
        "the theme comes from placement"
    );
    assert_eq!(b["ring"]["status"], "unavailable");
    assert_eq!(b["contested"]["status"], "unavailable");
    app.upstream.verify().await;

    // A context timeout behaves the same.
    let app = spawn_with(&[(ENV_UPSTREAM_TIMEOUT_MS, "400")], Router::new()).await;
    mount_dir(&app, "tok", dir_default()).await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/context"),
        ok(context_json()).set_delay(Duration::from_millis(1000)),
    )
    .await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/placement"),
        ok(placement_json(C1, Some(T), Value::Null)),
    )
    .await;
    mount_get(&app, &format!("/api/v1/claims/{C1}"), ok(claim.clone())).await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/bff/atlas/claim/{C1}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(
        res.json()["claim"]["content"],
        "Full text from the claim route."
    );

    // A 401 whose refresh is refused ends the session: no fallback call.
    let app = spawn().await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/context"),
        ResponseTemplate::new(401)
            .set_body_json(json!({"error": "Unauthorized", "message": "expired"})),
    )
    .await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/placement"),
        ok(placement_json(C1, Some(T), Value::Null)),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/claims/{C1}")))
        .respond_with(ok(claim))
        .expect(0)
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(&format!("/explorer/bff/atlas/claim/{C1}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.body);
    assert_eq!(res.json()["error"], "session_expired");
    app.upstream.verify().await;
}

#[tokio::test]
async fn claim_panel_404_is_identical_for_absent_unreadable_and_forbidden_claims() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    for id in [P, N] {
        for suffix in ["/context", "", "/placement"] {
            mount_get(
                &app,
                &format!("/api/v1/claims/{id}{suffix}"),
                not_found("Claim", id),
            )
            .await;
        }
    }
    mount_get(&app, &format!("/api/v1/claims/{C5}/context"), forbidden()).await;
    mount_get(&app, &format!("/api/v1/claims/{C5}/placement"), forbidden()).await;
    let sid = app.sign_in("tok");
    let mut seen = Vec::new();
    for id in [P, N, C5] {
        let res = app
            .get_as(&format!("/explorer/bff/atlas/claim/{id}"), &sid)
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{id}: {}", res.body);
        for any in [P, N, C5] {
            assert!(!res.body.contains(any) && !res.body.contains(&simple(any)));
        }
        seen.push(res.body);
    }
    assert_eq!(seen[0], seen[1]);
    assert_eq!(seen[1], seen[2]);
    assert!(
        requests(&app, &format!("/api/v1/claims/{C5}"))
            .await
            .is_empty(),
        "a 403 never falls back"
    );
}

#[tokio::test]
async fn claim_panel_page_mode() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/context"),
        ok(json!({
            "claim": {"id": C1, "content": "c", "content_truncated": false, "truth_value": 0.5,
                      "is_current": true, "theme_id": T},
            "parts": {"items": [node(C2, "A part", Some(T)), node(C2, "A duplicate", Some(T))],
                      "total": 160, "next_cursor": "k1.2.cd"}
        })),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app
        .get_as(
            &format!("/explorer/bff/atlas/claim/{C1}?list=parts&after=k1.1.ab&limit=999"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = res.json();
    assert_eq!(b["list"], "parts");
    assert_eq!(
        b["items"].as_array().unwrap().len(),
        1,
        "de-duplicated by id"
    );
    assert_eq!(b["items"][0]["id"], C2);
    assert_eq!(b["total"], 160);
    assert_eq!(b["next"], "k1.2.cd");
    let reqs = requests(&app, &format!("/api/v1/claims/{C1}/context")).await;
    let q = query_of(&reqs[0]);
    assert_eq!(q.get("list").map(String::as_str), Some("parts"));
    assert_eq!(q.get("after").map(String::as_str), Some("k1.1.ab"));
    assert_eq!(q.get("limit").map(String::as_str), Some("200"));

    let before = total_calls(&app).await;
    for bad in ["list=papers", "list=bogus", "after=k1.1.ab", "limit=5"] {
        let res = app
            .get_as(&format!("/explorer/bff/atlas/claim/{C1}?{bad}"), &sid)
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(total_calls(&app).await, before);
}

// ---- links ------------------------------------------------------------------------

#[tokio::test]
async fn links_group_by_relationship_strongest_first() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    Mock::given(method("GET"))
        .and(path(LINKS))
        .and(query_param("from", T))
        .and(query_param("to", T2))
        .and(query_param("after", "gl2.s.x"))
        .respond_with(ok(
            json!({"items": [link_item(E4, "supports", C2, C3)], "next": null}),
        ))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(LINKS))
        .and(query_param("from", T))
        .and(query_param("to", T2))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(json!({
            "from": {"id": T, "kind": "theme"}, "to": {"id": T2, "kind": "theme"},
            "run_id": null, "relationships": ["supports", "contradicts"],
            "counts": {"supports": 1, "CONTRADICTS": 3}, "total": 4,
            "items": [link_item(E1, "supports", C1, C2), link_item(E2, "contradicts", C3, C4),
                      link_item(E3, "Contradicts", C1, C4), link_item(E2, "contradicts", C3, C4)],
            "next": "gl2.s.x"
        })))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(LINKS))
        .and(query_param("to", T3))
        .respond_with(ok(json!({"status": "layout_invalidated"})))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(LINKS))
        .and(query_param("to", R9))
        .respond_with(not_found("Theme or region", R9))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(LINKS))
        .and(query_param("to", R2))
        .respond_with(forbidden())
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(LINKS))
        .and(query_param("to", R))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "BadRequest", "message": "the two sides overlap"
        })))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let base = "/explorer/bff/atlas/links";

    let res = app.get_as(&format!("{base}?from={T}&to={T2}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_private(&res, "links");
    let b = res.json();
    assert_eq!(b["from"], json!({"id": T, "kind": "theme"}));
    assert_eq!(b["to"], json!({"id": T2, "kind": "theme"}));
    assert_eq!(b["total"], 4);
    assert_eq!(b["next"], "gl2.s.x");
    let groups = b["groups"].as_array().unwrap();
    assert_eq!(groups[0]["relationship"], "contradicts");
    assert_eq!(groups[0]["count"], 3);
    assert_eq!(groups[0]["family"], "refute");
    let items: Vec<&str> = groups[0]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["edge_id"].as_str().unwrap())
        .collect();
    assert_eq!(items, [E2, E3], "upstream order, duplicates dropped");
    assert_eq!(groups[1]["relationship"], "supports");
    assert_eq!(groups[1]["count"], 1);
    let src = &groups[0]["items"][0]["source"];
    assert_eq!(src["cross_theme"], false);
    assert_eq!(src["theme"]["label"], "Theme one");
    assert_eq!(src["is_current"], Value::Null);
    assert_no_belief_keys(&b);

    let res = app
        .get_as(&format!("{base}?from={T}&to={T2}&after=gl2.s.x"), &sid)
        .await;
    let b = res.json();
    assert_eq!(
        b["total"],
        Value::Null,
        "U5 sends total on the first page only"
    );
    assert_eq!(
        b["groups"][0]["count"],
        Value::Null,
        "counts are first-page only"
    );
    assert_eq!(b["from"]["id"], T, "the BFF echoes its own parameters");
    assert_eq!(b["from"]["kind"], Value::Null);

    let before = total_calls(&app).await;
    let res = app.get_as(&format!("{base}?from={T}&to={T}"), &sid).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    let res = app.get_as(&format!("{base}?from={T}"), &sid).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(total_calls(&app).await, before);

    let res = app.get_as(&format!("{base}?from={T}&to={T3}"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = res.json();
    assert_eq!(b["status"], "layout_invalidated");
    assert_eq!(b["groups"], json!([]));
    assert_eq!(b["total"], Value::Null);
    assert_eq!(b["to"]["id"], T3);

    let absent = app.get_as(&format!("{base}?from={T}&to={R9}"), &sid).await;
    let closed = app.get_as(&format!("{base}?from={T}&to={R2}"), &sid).await;
    assert_eq!(absent.status, StatusCode::NOT_FOUND);
    assert_eq!(absent.json()["message"], "We could not find that link.");
    assert_eq!(absent.body, closed.body, "403 answers exactly as 404");

    let res = app.get_as(&format!("{base}?from={T}&to={R}"), &sid).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.json()["message"].as_str().unwrap().contains("overlap"));

    // A 400 on a later page is U5 refusing the cursor, not an overlap.
    let res = app
        .get_as(&format!("{base}?from={T}&to={R}&after=gl2.s.old"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    let msg = res.json()["message"].as_str().unwrap().to_owned();
    assert!(!msg.contains("overlap"), "{msg}");
    assert!(msg.contains("no longer valid"), "{msg}");
}

// ---- search -----------------------------------------------------------------------

#[tokio::test]
async fn search_semantic_and_label_modes() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    let long = "𝄞".repeat(400);
    let mut pinned = hit(C2, "In the theme", 0.4);
    pinned["theme_id"] = json!(T);
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .and(body_partial_json(
            json!({"theme_id": T, "query": "stern layer"}),
        ))
        .respond_with(ok(search_body(vec![pinned], Some((T, 412)), None)))
        .with_priority(1)
        .mount(&app.upstream)
        .await;
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .and(header("authorization", "Bearer tok"))
        .and(body_partial_json(json!({
            "query": "stern layer", "cursor": "o:0", "rank_by": "query", "limit": 20
        })))
        .and(NoKey("theme_id"))
        .respond_with(ok(search_body(
            vec![hit(C1, &long, 0.6)],
            None,
            Some("o:20"),
        )))
        .mount(&app.upstream)
        .await;
    let label_hit = |id: &str| {
        json!({"id": id, "content": "A labelled claim", "truth_value": 0.3, "agent_id": AGENT,
               "created_at": "2026-11-01T00:00:00+00:00", "labels": ["physics"],
               "is_current": true})
    };
    Mock::given(method("GET"))
        .and(path("/api/v1/claims/by-labels"))
        .and(query_param("labels", "doi:10.1/x,physics"))
        .and(query_param("offset", "0"))
        .and(query_param("limit", "2"))
        .respond_with(ok(json!([label_hit(C2), label_hit(C3)])))
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/claims/by-labels"))
        .and(query_param("offset", "2"))
        .respond_with(ok(json!([label_hit(C4)])))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let base = "/explorer/bff/atlas/search";

    let res = app.get_as(&format!("{base}?q=stern%20layer"), &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_private(&res, "search");
    let b = res.json();
    assert_eq!(b["mode"], "semantic");
    assert_eq!(b["q"], "stern layer");
    assert_eq!(b["theme"], Value::Null);
    assert_eq!(b["next"], "o:20");
    let r0 = &b["results"][0];
    let label = r0["label"].as_str().unwrap();
    assert!(label.chars().count() <= 160, "{}", label.chars().count());
    assert!(label.ends_with('…'));
    assert_eq!(r0["truth_value"], 0.6);
    assert_eq!(r0["similarity"], 0.8);
    assert_eq!(r0["theme_id"], Value::Null);
    assert_eq!(r0["key"], format!("c-{}", simple(C1)));
    assert_no_belief_keys(&b);

    let res = app
        .get_as(&format!("{base}?q=stern%20layer&theme={T}"), &sid)
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = res.json();
    assert_eq!(
        b["theme"],
        json!({"id": T, "label": "Theme one", "member_count": 412})
    );
    assert_eq!(b["results"][0]["theme_id"], T);

    let res = app
        .get_as(
            &format!("{base}?q=doi:10.1/x,physics&mode=label&limit=2"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let b = res.json();
    assert_eq!(b["mode"], "label");
    assert_eq!(b["results"].as_array().unwrap().len(), 2);
    assert_eq!(b["next"], "l.2");
    let res = app
        .get_as(
            &format!("{base}?q=doi:10.1/x,physics&mode=label&limit=2&after=l.2"),
            &sid,
        )
        .await;
    let b = res.json();
    assert_eq!(b["results"][0]["claim_id"], C4);
    assert_eq!(b["next"], Value::Null, "a short page ends the walk");

    let before = total_calls(&app).await;
    for bad in [
        format!("q=x&mode=label&theme={T}"),
        "q=%20".to_string(),
        format!("q={}", "a".repeat(1001)),
        "q=x&mode=bogus".to_string(),
        "q=x&after=l.2".to_string(),
        "q=x&mode=label&after=o:2".to_string(),
    ] {
        let res = app.get_as(&format!("{base}?{bad}"), &sid).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(total_calls(&app).await, before);
}

// ---- resolve ----------------------------------------------------------------------

#[tokio::test]
async fn resolve_claim_keys_only() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/placement"),
        ok(placement_json(C1, Some(T), shared_layout())),
    )
    .await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C2}/placement"),
        ok(placement_json(C2, Some(T2), Value::Null)),
    )
    .await;
    let sid = app.sign_in("tok");
    let base = "/explorer/bff/atlas/resolve";

    let simple_key = app.get_as(&format!("{base}/c-{}", simple(C1)), &sid).await;
    assert_eq!(simple_key.status, StatusCode::OK, "{}", simple_key.body);
    assert_private(&simple_key, "resolve");
    let b = simple_key.json();
    assert_eq!(b["key"], format!("c-{}", simple(C1)));
    assert_eq!(b["kind"], "claim");
    assert_eq!(b["claim_id"], C1);
    assert_eq!(b["theme"], json!({"id": T, "label": "Theme one"}));
    assert_eq!(b["region_id"], R);
    assert_eq!(b["placement"], "shared");
    assert_eq!(b["x"], -398.0);
    assert_eq!(b["run_id"], RUN);
    let hyphenated = app.get_as(&format!("{base}/c-{C1}"), &sid).await;
    assert_eq!(hyphenated.body, simple_key.body);

    let b = app
        .get_as(&format!("{base}/c-{}", simple(C2)), &sid)
        .await
        .json();
    assert_eq!(b["theme"]["id"], T2);
    assert_eq!(b["region_id"], Value::Null);
    assert_eq!(b["placement"], Value::Null);
    assert_eq!(b["run_id"], Value::Null);

    let before = total_calls(&app).await;
    let res = app.get_as(&format!("{base}/c-1234abcd"), &sid).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.json()["message"]
        .as_str()
        .unwrap()
        .contains("shortened"));
    for bad in [
        format!("t-{}", simple(T)),
        "t-1234abcd".to_string(),
        "x-1234abcd".to_string(),
        "garbage".to_string(),
        format!("c-{}", simple(C1).to_uppercase()),
    ] {
        let res = app.get_as(&format!("{base}/{bad}"), &sid).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{bad}");
        assert_eq!(res.json()["message"], "We could not find that link.");
    }
    assert_eq!(
        total_calls(&app).await,
        before,
        "syntax alone decides these"
    );
}

#[tokio::test]
async fn resolve_404_is_identical_for_absent_unreadable_and_forbidden_claims() {
    let app = spawn().await;
    mount_dir(&app, "tok", dir_default()).await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{P}/placement"),
        not_found("Claim", P),
    )
    .await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{N}/placement"),
        ResponseTemplate::new(404),
    )
    .await;
    mount_get(&app, &format!("/api/v1/claims/{C5}/placement"), forbidden()).await;
    let sid = app.sign_in("tok");
    let mut seen = Vec::new();
    for id in [P, N, C5] {
        let res = app
            .get_as(
                &format!("/explorer/bff/atlas/resolve/c-{}", simple(id)),
                &sid,
            )
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{id}");
        assert!(!res.body.contains(id) && !res.body.contains(&simple(id)));
        seen.push(res.body);
    }
    assert_eq!(seen[0], seen[1]);
    assert_eq!(seen[1], seen[2]);
}

#[tokio::test]
async fn bff_atlas_session_expiry_is_json_401() {
    let app = spawn().await;
    mount_get(
        &app,
        LAYOUT,
        ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized", "message": "Invalid token", "details": {"reason": "expired"}
        })),
    )
    .await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/bff/atlas/layout", &sid).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.body);
    assert_eq!(res.json()["error"], "session_expired");
    assert!(
        !res.header_all("set-cookie").is_empty(),
        "the cookie is cleared"
    );
    assert!(app.state.sessions.get(&sid).is_none());
}

// ---- caps ---------------------------------------------------------------------------

fn uuid_n(n: u128) -> String {
    Uuid::from_u128(0xabc0_0000 + n).to_string()
}

#[tokio::test]
async fn atlas_bodies_stay_under_caps() {
    let big = |n: usize| "𝄞".repeat(n);
    let app = spawn().await;
    let sid = app.sign_in("tok");

    // 250 regions and 250 links at top level.
    let regions: Vec<Value> = (0..250)
        .map(|i| {
            json!({"id": uuid_n(i), "label": big(400), "x": 1.0, "y": 2.0, "r": 3.0,
                   "theme_ids": (0..200).map(|j| uuid_n(10_000 + j)).collect::<Vec<_>>(),
                   "theme_count": 200, "member_count": 9})
        })
        .collect();
    let links: Vec<Value> = (0..250)
        .map(|i| {
            json!({"kind": "region", "a": uuid_n(i % 200), "b": uuid_n((i + 1) % 200),
                         "counts": {"supports": 1, "contradicts": 1}, "total": 2})
        })
        .collect();
    mount_layout(
        &app,
        None,
        json!({"run": run_json(false), "status": null, "relationships": ["supports"],
               "regions": regions, "links": links, "unplaced_theme_count": 0,
               "next": {"themes": null, "links": "ll1.x"}}),
    )
    .await;
    // A region page with 250 themes and 250 theme links.
    let themes: Vec<Value> = (0..250)
        .map(|i| {
            json!({"id": uuid_n(20_000 + i), "label": big(400), "region_id": R,
                   "placement": "shared", "x": 1.0, "y": 1.0, "member_count": 5})
        })
        .collect();
    let theme_links: Vec<Value> = (0..250)
        .map(|i| json!({"kind": "theme", "a": uuid_n(20_000 + i % 200), "b": uuid_n(20_000 + (i + 1) % 200),
                         "counts": {"supports": 1}, "total": 1}))
        .collect();
    mount_layout(
        &app,
        Some(R),
        json!({"run": run_json(false), "status": null, "relationships": [],
               "region": {"id": R, "label": big(400), "x": 1.0, "y": 1.0, "r": 1.0,
                          "theme_count": 250, "member_count": 9},
               "themes": themes, "links": theme_links, "next": {"themes": "lt2.x", "links": null}}),
    )
    .await;
    mount_dir(&app, "tok", dir_default()).await;
    // 100 hits with long statements; batch-get returns nothing.
    let hits: Vec<Value> = (0..100)
        .map(|i| hit(&uuid_n(30_000 + i), &big(2000), 0.5))
        .collect();
    Mock::given(method("POST"))
        .and(path(SEARCH))
        .respond_with(ok(search_body(hits, Some((T, 100)), Some("o:100"))))
        .mount(&app.upstream)
        .await;
    Mock::given(method("POST"))
        .and(path(BATCH))
        .respond_with(ok(json!({"claims": [], "not_found": [], "remaining": []})))
        .mount(&app.upstream)
        .await;
    // U4 full mode at its maximum: 195 nodes of 1,500 four-byte chars.
    let nodes = |base: u128, n: u128| -> Vec<Value> {
        (0..n)
            .map(|i| {
                json!({"id": uuid_n(base + i), "content": big(1500), "content_truncated": true,
                       "truth_value": 0.5, "is_current": true, "theme_id": T2})
            })
            .collect()
    };
    let edges: Vec<Value> = nodes(40_000, 80)
        .into_iter()
        .enumerate()
        .map(|(i, n)| {
            json!({"edge_id": uuid_n(50_000 + i as u128), "relationship": "supports",
                              "direction": "outgoing", "strength": 0.5, "neighbor": n})
        })
        .collect();
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/context"),
        ok(json!({
            "claim": {"id": C1, "content": big(1500), "content_truncated": true,
                      "truth_value": 0.5, "is_current": true, "theme_id": T},
            "paper": {"id": PAPER, "doi": format!("10.1/{}", "x".repeat(250)),
                      "title": big(300), "truncated": true},
            "section": nodes(60_000, 1).remove(0),
            "parents": {"items": nodes(61_000, 10), "total": 10, "next_cursor": null},
            "parts": {"items": nodes(62_000, 50), "total": 500, "next_cursor": "k1.x"},
            "siblings": {"parent_id": C2, "items": nodes(63_000, 50), "total": 500,
                         "next_cursor": "k1.y"},
            "edges": {"items": edges, "total": 900, "next_cursor": "k1.z",
                      "by_relationship": [{"relationship": "supports", "direction": "outgoing",
                                           "count": 900}]}
        })),
    )
    .await;
    mount_get(
        &app,
        &format!("/api/v1/claims/{C1}/placement"),
        ok(placement_json(C1, Some(T), shared_layout())),
    )
    .await;
    // 200 link items with 160-char labels.
    let items: Vec<Value> = (0..250)
        .map(|i| {
            let mut it = link_item(&uuid_n(70_000 + i), "supports", C1, C2);
            it["source"]["label"] = json!(big(160));
            it["target"]["label"] = json!(big(160));
            it
        })
        .collect();
    mount_get(
        &app,
        LINKS,
        ok(json!({"counts": {"supports": 250}, "total": 250, "items": items, "next": "gl2.x"})),
    )
    .await;

    for uri in [
        "/explorer/bff/atlas/layout".to_string(),
        format!("/explorer/bff/atlas/layout?region={R}"),
        format!("/explorer/bff/atlas/theme/{T}/claims?limit=100"),
        format!("/explorer/bff/atlas/claim/{C1}"),
        format!("/explorer/bff/atlas/links?from={T}&to={T2}&limit=200"),
        "/explorer/bff/atlas/search?q=x&limit=50".to_string(),
    ] {
        let res = app.get_as(&uri, &sid).await;
        assert_eq!(
            res.status,
            StatusCode::OK,
            "{uri}: {}",
            &res.body[..res.body.len().min(300)]
        );
        assert!(
            res.body.len() < 2_000_000,
            "{uri}: {} bytes",
            res.body.len()
        );
        let v = res.json();
        assert!(max_array_len(&v) <= 200, "{uri}: an array over 200");
        walk(&v, &mut |k, x| {
            if let (Some("label"), Value::String(s)) = (k, x) {
                assert!(s.chars().count() <= 160, "{uri}: a label over 160 chars");
            }
        });
    }
}

// ---- tenancy ------------------------------------------------------------------------

/// Private claim P (text `SECRET-P-91f3`, theme T) and private theme H are
/// visible to viewer A only. Viewer B's stubs are what the kernel returns to
/// a non-member, except that B's region page still carries a T–H link (a
/// simulated upstream mis-filter). Nothing of P or H, and none of A's
/// counts, may reach B, whatever A warmed first.
#[tokio::test]
async fn hidden_claim_text_id_and_count_never_reach_another_viewer() {
    const SECRET: &str = "SECRET-P-91f3";
    const LAB: &str = "A's lab notes";
    let app = spawn().await;
    let a = app.sign_in("tok-a");
    let b = app.sign_in("tok-b");

    mount_dir(
        &app,
        "tok-a",
        json!([{"id": T, "label": "Theme one", "claim_count": 11},
               {"id": H, "label": LAB, "claim_count": 11},
               {"id": T2, "label": "Theme two", "claim_count": 11}]),
    )
    .await;
    mount_dir(
        &app,
        "tok-b",
        json!([{"id": T, "label": "Theme one", "claim_count": 10},
               {"id": T2, "label": "Theme two", "claim_count": 10}]),
    )
    .await;

    for (tok, m) in [("tok-a", 11i64), ("tok-b", 10)] {
        let auth = bearer(tok);
        let top = json!({
            "run": run_json(false), "status": null, "relationships": ["supports"],
            "regions": [
                {"id": R, "label": "Region one", "x": 0.0, "y": 0.0, "r": 100.0,
                 "theme_ids": if m == 11 { json!([T, H]) } else { json!([T]) },
                 "theme_count": 1, "member_count": m},
                {"id": R2, "label": "Region two", "x": 300.0, "y": 0.0, "r": 90.0,
                 "theme_ids": [T2], "theme_count": 1, "member_count": m}
            ],
            "links": [{"kind": "region", "a": R, "b": R2, "counts": {"supports": 10}, "total": 10}],
            "unplaced_theme_count": 1, "next": {"themes": null, "links": null}
        });
        Mock::given(method("GET"))
            .and(path(LAYOUT))
            .and(header("authorization", auth.as_str()))
            .and(query_param_is_missing("region_id"))
            .and(query_param_is_missing("include_structure"))
            .respond_with(ok(top))
            .mount(&app.upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(LAYOUT))
            .and(header("authorization", auth.as_str()))
            .and(query_param_is_missing("region_id"))
            .and(query_param("include_structure", "true"))
            .respond_with(ok(no_run_json("no_layout_run")))
            .mount(&app.upstream)
            .await;
        let mut themes = vec![json!({"id": T, "label": "Theme one", "region_id": R,
                                     "placement": "shared", "x": 1.0, "y": 1.0, "member_count": m})];
        if m == 11 {
            themes.push(
                json!({"id": H, "label": LAB, "region_id": R, "placement": "viewer",
                               "x": null, "y": null, "member_count": m}),
            );
        }
        Mock::given(method("GET"))
            .and(path(LAYOUT))
            .and(header("authorization", auth.as_str()))
            .and(query_param("region_id", R))
            .respond_with(ok(json!({
                "run": run_json(false), "status": null, "relationships": ["supports"],
                "region": {"id": R, "label": "Region one", "x": 0.0, "y": 0.0, "r": 100.0,
                           "theme_count": 1, "member_count": m},
                "themes": themes,
                "links": [
                    // B's copy is the mis-filter: H is not B's to see.
                    {"kind": "theme", "a": T, "b": H, "counts": {"supports": 10}, "total": 10},
                    {"kind": "theme_region", "a": T, "b": R2, "counts": {"supports": 10}, "total": 10}
                ],
                "next": {"themes": null, "links": null}
            })))
            .mount(&app.upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(LAYOUT))
            .and(header("authorization", auth.as_str()))
            .and(query_param("region_id", "unplaced"))
            .respond_with(ok(json!({
                "run": run_json(false), "status": null, "relationships": [], "region": null,
                "themes": [{"id": T3, "label": "Loose", "region_id": null, "placement": null,
                            "x": null, "y": null, "member_count": m}],
                "links": [], "next": {"themes": null, "links": null}
            })))
            .mount(&app.upstream)
            .await;
    }

    // A's reads include P everywhere it can appear.
    let a_auth = bearer("tok-a");
    let b_auth = bearer("tok-b");
    let mount_as = |auth: &str, verb: &str, p: String, resp: ResponseTemplate| {
        Mock::given(method(verb))
            .and(path(p))
            .and(header("authorization", auth))
            .respond_with(resp)
    };
    for m in [
        mount_as(
            &a_auth,
            "POST",
            SEARCH.into(),
            ok(search_body(
                vec![hit(C1, "A public claim", 0.5), hit(P, SECRET, 0.5)],
                Some((T, 11)),
                None,
            )),
        ),
        mount_as(
            &a_auth,
            "POST",
            BATCH.into(),
            ok(json!({
            "claims": [batch_claim(C1, "A public claim", 0.5, true), batch_claim(P, SECRET, 0.5, true)],
            "not_found": [], "remaining": []})),
        ),
        mount_as(
            &a_auth,
            "GET",
            format!("/api/v1/claims/{C1}/context"),
            ok(json!({
            "claim": {"id": C1, "content": "A public claim", "content_truncated": false,
                      "truth_value": 0.5, "is_current": true, "theme_id": T},
            "parts": {"items": [node(P, SECRET, Some(T))], "total": 11, "next_cursor": null},
            "edges": {"items": [{"edge_id": E1, "relationship": "supports", "direction": "incoming",
                                 "neighbor": node(P, SECRET, Some(H))}], "total": 11,
                      "by_relationship": [{"relationship": "supports", "direction": "incoming", "count": 11}],
                      "next_cursor": null}})),
        ),
        mount_as(
            &a_auth,
            "GET",
            format!("/api/v1/claims/{P}/context"),
            ok(json!({
            "claim": {"id": P, "content": SECRET, "content_truncated": false, "truth_value": 0.5,
                      "is_current": true, "theme_id": H},
            "parts": {"items": [], "total": 11, "next_cursor": null}})),
        ),
        mount_as(
            &a_auth,
            "GET",
            format!("/api/v1/claims/{P}/placement"),
            ok(placement_json(P, Some(H), Value::Null)),
        ),
        mount_as(
            &a_auth,
            "GET",
            format!("/api/v1/claims/{C1}/placement"),
            ok(placement_json(C1, Some(T), shared_layout())),
        ),
        mount_as(
            &a_auth,
            "GET",
            LINKS.into(),
            ok(json!({
            "counts": {"supports": 11}, "total": 11,
            "items": [link_item(E1, "supports", P, C2)], "next": null})),
        ),
        mount_as(
            &a_auth,
            "GET",
            "/api/v1/claims/by-labels".into(),
            ok(json!([{
            "id": P, "content": SECRET, "truth_value": 0.5, "created_at": "2026-11-01T00:00:00+00:00",
            "labels": ["secret"]}])),
        ),
        // B: what the kernel returns to a non-member.
        mount_as(
            &b_auth,
            "POST",
            SEARCH.into(),
            ok(json!({
            "results": [hit(C1, "A public claim", 0.5)], "total": 1, "query_time_ms": 1,
            "theme_scope": {"theme_id": T, "member_count": 10, "rank_by": "theme_core"}})),
        ),
        mount_as(
            &b_auth,
            "POST",
            BATCH.into(),
            ok(json!({
            "claims": [batch_claim(C1, "A public claim", 0.5, true)], "not_found": [], "remaining": []})),
        ),
        mount_as(
            &b_auth,
            "GET",
            format!("/api/v1/claims/{C1}/context"),
            ok(json!({
            "claim": {"id": C1, "content": "A public claim", "content_truncated": false,
                      "truth_value": 0.5, "is_current": true, "theme_id": T},
            "parents": {"items": [], "total": 10, "next_cursor": null},
            "parts": {"items": [node(C2, "Another public claim", Some(T))], "total": 10, "next_cursor": null},
            "siblings": {"parent_id": null, "items": [], "total": 10, "next_cursor": null},
            "edges": {"items": [], "total": 10, "by_relationship": [], "next_cursor": null}})),
        ),
        mount_as(
            &b_auth,
            "GET",
            format!("/api/v1/claims/{C1}/placement"),
            ok(placement_json(C1, Some(T), shared_layout())),
        ),
        mount_as(
            &b_auth,
            "GET",
            LINKS.into(),
            ok(json!({
            "counts": {"supports": 10}, "total": 10,
            "items": [link_item(E2, "supports", C1, C2)], "next": null})),
        ),
        mount_as(
            &b_auth,
            "GET",
            "/api/v1/claims/by-labels".into(),
            ok(json!([])),
        ),
    ] {
        m.mount(&app.upstream).await;
    }
    // Absent for B, and never existing for anyone: one body each, naming
    // the id the way the kernel does.
    for id in [P, N] {
        for suffix in ["/context", "", "/placement"] {
            Mock::given(method("GET"))
                .and(path(format!("/api/v1/claims/{id}{suffix}")))
                .respond_with(not_found("Claim", id))
                .mount(&app.upstream)
                .await;
        }
    }

    let routes: Vec<String> = vec![
        "/explorer/atlas".into(),
        "/explorer/bff/atlas/layout".into(),
        format!("/explorer/bff/atlas/layout?region={R}"),
        "/explorer/bff/atlas/layout?region=unplaced".into(),
        "/explorer/bff/atlas/layout?structure=1".into(),
        format!("/explorer/bff/atlas/theme/{T}/claims"),
        format!("/explorer/bff/atlas/claim/{C1}"),
        format!("/explorer/bff/atlas/claim/{C1}?list=parts"),
        format!("/explorer/bff/atlas/claim/{C1}?list=edges"),
        format!("/explorer/bff/atlas/claim/{P}"),
        format!("/explorer/bff/atlas/claim/{N}"),
        format!("/explorer/bff/atlas/claim/{P}?list=parts"),
        format!("/explorer/bff/atlas/claim/{N}?list=parts"),
        format!("/explorer/bff/atlas/links?from={T}&to={T2}"),
        format!("/explorer/bff/atlas/links?from={T}&to={T2}&limit=200"),
        "/explorer/bff/atlas/search?q=secret".into(),
        "/explorer/bff/atlas/search?q=secret&mode=label".into(),
        format!("/explorer/bff/atlas/resolve/c-{}", simple(P)),
        format!("/explorer/bff/atlas/resolve/c-{}", simple(N)),
    ];

    // 1. A warms every cache.
    let mut a_saw_secret = false;
    for r in &routes {
        let res = app.get_as(r, &a).await;
        a_saw_secret |= res.body.contains(SECRET);
    }
    assert!(a_saw_secret, "the stubs do show P to A");

    // 2. B reads every route.
    let a_calls = count_as(&app, "tok-a").await;
    let mut bodies: BTreeMap<String, TestResponse> = BTreeMap::new();
    for r in &routes {
        let before = count_as(&app, "tok-b").await;
        let res = app.get_as(r, &b).await;
        if r != "/explorer/atlas" {
            assert!(
                count_as(&app, "tok-b").await > before,
                "{r}: B's answer came from B's own upstream call"
            );
        }
        bodies.insert(r.clone(), res);
    }
    assert_eq!(
        count_as(&app, "tok-a").await,
        a_calls,
        "B never spends A's token"
    );

    // 3. Nothing of P, H or A's counts in any B body.
    for (r, res) in &bodies {
        for leak in [SECRET, P, &simple(P), H, &simple(H), LAB] {
            assert!(!res.body.contains(leak), "{r} leaks {leak}: {}", res.body);
        }
        assert!(res.header("etag").is_none(), "{r}: no ETag");
        let cc = res.header("cache-control").unwrap_or("");
        if res.status == StatusCode::OK {
            assert_eq!(cc, "private, no-store", "{r}");
        } else {
            assert!(cc.contains("no-store"), "{r}: {cc}");
        }
        if r == "/explorer/atlas" {
            continue;
        }
        let v: Value = serde_json::from_str(&res.body).unwrap();
        let packed = v["mode"] == "packed";
        walk(&v, &mut |k, x| match (k, x.as_i64()) {
            (Some("member_count"), Some(n)) => assert_eq!(n, 10, "{r}: member_count"),
            (Some("total"), Some(n)) => {
                let want = if packed { 2 } else { 10 };
                assert_eq!(n, want, "{r}: total");
            }
            _ => {}
        });
    }
    let pair = |x: &str, y: &str| {
        let (p, n) = (&bodies[x], &bodies[y]);
        assert_eq!(p.status, n.status, "{x} vs {y}");
        assert_eq!(p.body, n.body, "{x} vs {y}");
    };
    pair(
        &format!("/explorer/bff/atlas/claim/{P}"),
        &format!("/explorer/bff/atlas/claim/{N}"),
    );
    pair(
        &format!("/explorer/bff/atlas/claim/{P}?list=parts"),
        &format!("/explorer/bff/atlas/claim/{N}?list=parts"),
    );
    pair(
        &format!("/explorer/bff/atlas/resolve/c-{}", simple(P)),
        &format!("/explorer/bff/atlas/resolve/c-{}", simple(N)),
    );
    let region = &bodies[&format!("/explorer/bff/atlas/layout?region={R}")];
    assert_eq!(region.status, StatusCode::OK, "{}", region.body);
    let links = region.json()["links"].clone();
    assert_eq!(
        links.as_array().unwrap().len(),
        1,
        "the mis-filtered T–H link is dropped"
    );
    assert_eq!(links[0]["kind"], "theme_region");
}

// ---- static assets --------------------------------------------------------------------

/// Pins atlas.js's safety rules (no eval, no HTML parsing of data, checked
/// URLs) so a later edit cannot quietly break them.
#[test]
fn atlas_js_never_parses_strings_as_code_or_html() {
    let js = include_str!("../static/atlas.js");
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
        assert!(!js.contains(banned), "atlas.js must not use {banned}");
    }
    for needed in [
        "'use strict'",
        "function localPath(",
        "function doiHref(",
        "credentials: 'same-origin'",
        "prefers-reduced-motion",
        "d3.interpolateZoom",
    ] {
        assert!(js.contains(needed), "atlas.js must contain {needed}");
    }
    assert!(js.contains("rel=\"noopener noreferrer\"") || js.contains("'noopener noreferrer'"));
    let mut calls = 0;
    for (i, _) in js.match_indices("replaceState(") {
        let end = js[i..].find(';').map_or(js.len(), |e| i + e);
        assert!(
            !js[i..end].contains("#t-"),
            "a t- hash is never written: {}",
            &js[i..end]
        );
        calls += 1;
    }
    assert!(calls > 0, "selection writes the hash with replaceState");
    assert!(!include_str!("../static/atlas.css").trim().is_empty());
}

/// A `--token: #rrggbb;` from a stylesheet, in the light or the dark theme.
fn css_hex(css: &str, name: &str, dark: bool) -> [f64; 3] {
    let split = css
        .find("@media (prefers-color-scheme: dark)")
        .expect("a dark block");
    let region = if dark { &css[split..] } else { &css[..split] };
    let needle = format!("{name}:");
    let start = region.find(&needle).unwrap_or_else(|| {
        panic!(
            "{name} is defined ({})",
            if dark { "dark" } else { "light" }
        )
    }) + needle.len();
    let end = start + region[start..].find(';').unwrap();
    let hex = region[start..end].trim().trim_start_matches('#');
    assert_eq!(hex.len(), 6, "{name} is #rrggbb");
    [0usize, 2, 4].map(|i| f64::from(u8::from_str_radix(&hex[i..i + 2], 16).unwrap()) / 255.0)
}

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

fn contrast(a: [f64; 3], b: [f64; 3]) -> f64 {
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

#[test]
fn atlas_belief_ramp_is_monotonic_and_visible_in_both_themes() {
    let css = include_str!("../static/atlas.css");
    let app = include_str!("../static/app.css");
    for dark in [false, true] {
        let theme = if dark { "dark" } else { "light" };
        let stage = css_hex(css, "--atlas-stage", dark);
        let steps: Vec<[f64; 3]> = (0..7)
            .map(|i| css_hex(css, &format!("--atlas-belief-{i}"), dark))
            .collect();
        let lum: Vec<f64> = steps.iter().map(|c| luminance(*c)).collect();
        let rising = lum.windows(2).all(|w| w[1] > w[0]);
        let falling = lum.windows(2).all(|w| w[1] < w[0]);
        assert!(
            rising || falling,
            "{theme}: the ramp is not monotonic: {lum:?}"
        );
        let none = css_hex(css, "--atlas-belief-none", dark);
        for (what, c) in [("step 0", steps[0]), ("none", none)] {
            let r = contrast(c, stage);
            assert!(r >= 1.5, "{theme}: {what} is {r:.2}:1 against the stage");
        }
        let span = contrast(steps[6], steps[0]);
        assert!(span >= 3.0, "{theme}: step 6 vs step 0 is {span:.2}:1");
        let refute = css_hex(app, "--refute", dark);
        let r = contrast(refute, stage);
        assert!(r >= 3.0, "{theme}: --refute is {r:.2}:1 against the stage");
    }
    assert!(css.contains("--atlas-critical: var(--refute)"));
    let js = include_str!("../static/atlas.js");
    assert!(!js.contains("pignistic"), "colour never comes from BetP");
    assert!(!js.contains(".belief"), "no belief figure is read");
}

/// sha256 of each vendored file, recorded when vendoring and cross-checked
/// against the npm registry's `integrity`.
const VENDOR_PINS: &[(&str, &str, &str)] = &[
    (
        "d3-color",
        "3.1.0",
        "a12639010163230b8c130fbeb92a3a49bb5f6989a566d3664d759522db458489",
    ),
    (
        "d3-interpolate",
        "3.0.1",
        "bfc321e4c3f3b3aadc88cfe15ccb5e443abfeadef8b75c65b41c33a4d78a98ae",
    ),
    (
        "d3-ease",
        "3.0.1",
        "e60a1ed750a1ad138dd18e8d3f463238113cfbf7d89685a13d19bd4e048dc3ce",
    ),
    (
        "d3-hierarchy",
        "3.1.2",
        "a8771380454be89ec5ffe9a6396ba7c247081e348ae740dc9cb9629abd4c0e43",
    ),
    (
        "d3-dispatch",
        "3.0.1",
        "94b3bbdb6b98dc1325a15762b051013e8253999b0e0436b27d1da17b952ba0af",
    ),
    (
        "d3-timer",
        "3.0.1",
        "911ceda305f014b6b53ca68d5c896a9a387da120cfd56a421a2c60cca2fc9b36",
    ),
    (
        "d3-quadtree",
        "3.0.1",
        "57e2ad12824ed82893ba447523f2a2fb9beeb9222aafb2c778a9f5b313348b0e",
    ),
    (
        "d3-force",
        "3.0.0",
        "1e07b473241328795d5ea9ad479a7bbabd765012fa2ef95633c83b69868dff6b",
    ),
];

#[tokio::test]
async fn vendored_d3_is_pinned_and_licensed() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("static/vendor");
    assert_eq!(VENDOR_PINS.len(), VENDOR_SCRIPTS.len());
    let licence = std::fs::read_to_string(dir.join("LICENSE-d3.txt")).expect("LICENSE-d3.txt");
    assert!(licence.contains("ISC"));
    let app = spawn().await;
    for ((module, version, want), script) in VENDOR_PINS.iter().zip(VENDOR_SCRIPTS) {
        assert_eq!(
            *script,
            format!("vendor/{module}.min.js"),
            "same order as the page"
        );
        let bytes = std::fs::read(dir.join(format!("{module}.min.js"))).expect("vendored file");
        let got: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(&got, want, "{module} changed");
        assert!(
            licence.contains(module) && licence.contains(version),
            "LICENSE-d3.txt names {module} {version}"
        );
        let res = app.get(&format!("/explorer/static/{script}")).await;
        assert_eq!(res.status, StatusCode::OK, "{script}");
        assert_eq!(
            res.header("content-type"),
            Some("text/javascript; charset=utf-8")
        );
    }
}

#[test]
fn anon_shell_signin_link_round_trips_a_hash() {
    let links = Links::new("https://explorer.example.com", "/explorer");
    let back = format!("/explorer/atlas#c-{}", simple(C1));
    assert_eq!(
        validate_return_to(&links, &back).as_deref(),
        Some(back.as_str())
    );
    let js = include_str!("../static/atlas.js");
    assert!(
        js.contains("/^#[ct]-[0-9a-f-]{8,36}$/"),
        "the rewrite is guarded"
    );
    assert!(js.contains("searchParams.set('return_to'"));
}
