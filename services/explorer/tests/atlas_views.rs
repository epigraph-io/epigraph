//! The Atlas Sources and Timeline views (phases P3b and P3c):
//! `/bff/atlas/sources` and `/bff/atlas/timeline`, against a wiremock
//! upstream shaped like the kernel's `GET /sources/overview` and
//! `GET /claims?theme_id=&include_links=true` bodies. Every request test
//! checks the viewer's own bearer reached upstream.

mod common;

use std::collections::BTreeMap;

use axum::http::StatusCode;
use common::{spawn, TestApp, TestResponse};
use epigraph_explorer::bff::atlas_sources::{SOURCES_NARROW, SOURCES_UNSUPPORTED};
use serde_json::{json, Value};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, Request, ResponseTemplate};

const T: &str = "2c9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const PAPER: &str = "5b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const AGENT: &str = "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10";
const AUTHOR: &str = "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a11";

const SOURCES: &str = "/api/v1/sources/overview";
const OVERVIEW: &str = "/api/v1/graph/themes/overview";

// ---- helpers ----------------------------------------------------------------------

fn ok(body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
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

fn query_of(r: &Request) -> BTreeMap<String, String> {
    r.url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn assert_private(res: &TestResponse, what: &str) {
    assert_eq!(
        res.header("cache-control"),
        Some("private, no-store"),
        "{what}: per-viewer JSON must not be stored"
    );
    assert!(res.header("etag").is_none(), "{what}: no ETag");
}

fn walk_keys(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                out.push(k.clone());
                walk_keys(x, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| walk_keys(x, out)),
        _ => {}
    }
}

fn assert_no_belief_keys(v: &Value) {
    let mut keys = Vec::new();
    walk_keys(v, &mut keys);
    for k in keys {
        assert!(
            !common::atlas_contract::BELIEF_KEYS.contains(&k.as_str()),
            "a body carries `{k}`"
        );
    }
}

async fn mount_dir(app: &TestApp) {
    Mock::given(method("GET"))
        .and(path(OVERVIEW))
        .respond_with(ok(json!({"themes": [
            {"id": T, "label": "Theme one", "claim_count": 42}
        ]})))
        .mount(&app.upstream)
        .await;
}

fn sources_body() -> Value {
    json!({
        "sources": [
            {"kind": "paper", "id": PAPER, "doi": " 10.1234/abc ", "title": "A\n  paper",
             "authors": [{"id": AUTHOR, "display_name": "Ada  Lovelace", "pending_countersign": true}],
             "authors_truncated": false, "claim_count": 12},
            {"kind": "paper", "id": AUTHOR, "doi": "not a doi", "title": null,
             "authors": [], "authors_truncated": true, "claim_count": 3},
            {"kind": "agent", "id": AGENT, "display_name": null, "claim_count": 4},
            {"kind": "web", "domain": "Example.org", "claim_count": 2},
            {"kind": "web", "domain": "javascript:alert(1)", "claim_count": 1},
            {"kind": "dataset", "id": PAPER, "claim_count": 9}
        ],
        "next_cursor": "so1.web.2.6578616d706c652e6f7267"
    })
}

// ---- /bff/atlas/sources -----------------------------------------------------------

#[tokio::test]
async fn sources_pass_each_kind_through_with_the_viewer_bearer() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(SOURCES))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ok(sources_body()))
        .mount(&app.upstream)
        .await;
    mount_dir(&app).await;
    let sid = app.sign_in("tok");

    let res = app
        .get_as(
            &format!("/explorer/bff/atlas/sources?theme_id={T}&kind=Paper&after=so1.paper.3.ab&limit=999"),
            &sid,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_private(&res, "sources");
    let q = query_of(&requests(&app, SOURCES).await[0]);
    assert_eq!(q.get("theme_id").map(String::as_str), Some(T));
    assert_eq!(q.get("kind").map(String::as_str), Some("paper"));
    assert_eq!(q.get("after").map(String::as_str), Some("so1.paper.3.ab"));
    assert_eq!(q.get("limit").map(String::as_str), Some("200"), "clamped");

    let v = res.json();
    assert_no_belief_keys(&v);
    assert_eq!(v["theme"], json!({"id": T, "label": "Theme one"}));
    assert_eq!(v["kind"], "paper");
    assert_eq!(v["next"], "so1.web.2.6578616d706c652e6f7267");
    let s = v["sources"].as_array().unwrap();
    // The unknown kind and the domain that is not a host name are dropped.
    assert_eq!(s.len(), 4, "{v}");
    assert_eq!(
        s[0],
        json!({"kind": "paper", "id": PAPER, "doi": "10.1234/abc",
               "doi_href": "https://doi.org/10.1234/abc", "title": "A paper",
               "authors": [{"id": AUTHOR, "name": "Ada Lovelace", "pending_countersign": true}],
               "authors_truncated": false, "claim_count": 12})
    );
    assert_eq!(s[1]["doi_href"], Value::Null, "only a real DOI is linked");
    assert_eq!(s[1]["authors_truncated"], true);
    assert_eq!(
        s[2],
        json!({"kind": "agent", "id": AGENT, "name": null,
               "href": format!("/explorer/agent/{AGENT}"), "claim_count": 4})
    );
    assert_eq!(
        s[3],
        json!({"kind": "web", "domain": "example.org", "claim_count": 2})
    );
    for r in app.upstream.received_requests().await.unwrap() {
        assert_eq!(r.headers.get("authorization").unwrap(), "Bearer tok");
    }
}

#[tokio::test]
async fn sources_without_a_theme_ask_the_whole_corpus_and_no_directory() {
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(SOURCES))
        .respond_with(ok(json!({"sources": [], "next_cursor": null})))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/bff/atlas/sources", &sid).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let q = query_of(&requests(&app, SOURCES).await[0]);
    assert_eq!(
        q,
        BTreeMap::from([("limit".to_string(), "50".to_string())]),
        "default page, nothing else"
    );
    assert!(requests(&app, OVERVIEW).await.is_empty());
    assert_eq!(
        res.json(),
        json!({"theme": null, "kind": null, "sources": [], "next": null})
    );
}

#[tokio::test]
async fn sources_cap_a_page_at_two_hundred_items() {
    let app = spawn().await;
    let many: Vec<Value> = (0..250)
        .map(|i| json!({"kind": "web", "domain": format!("d{i}.example.org"), "claim_count": 1}))
        .collect();
    Mock::given(method("GET"))
        .and(path(SOURCES))
        .respond_with(ok(json!({"sources": many, "next_cursor": null})))
        .mount(&app.upstream)
        .await;
    let sid = app.sign_in("tok");
    let res = app.get_as("/explorer/bff/atlas/sources", &sid).await;
    assert_eq!(res.json()["sources"].as_array().unwrap().len(), 200);
}

#[tokio::test]
async fn sources_reject_bad_params_before_any_upstream_call() {
    let app = spawn().await;
    let sid = app.sign_in("tok");
    for q in ["theme_id=nope", "kind=dataset", "after=a%20b", "limit=many"] {
        let res = app
            .get_as(&format!("/explorer/bff/atlas/sources?{q}"), &sid)
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{q}");
    }
    assert!(app.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn sources_degrade_without_the_route_or_on_a_timed_out_page() {
    let sid_for = |app: &TestApp| app.sign_in("tok");

    // An API from before the overview: no route.
    let app = spawn().await;
    let res = app
        .get_as("/explorer/bff/atlas/sources", &sid_for(&app))
        .await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE, "{}", res.body);
    assert_eq!(res.json()["message"], SOURCES_UNSUPPORTED);

    // The API timed a corpus-wide page out.
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(SOURCES))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": "ServiceUnavailable", "message": "narrow the read with theme_id"
        })))
        .mount(&app.upstream)
        .await;
    let res = app
        .get_as("/explorer/bff/atlas/sources", &sid_for(&app))
        .await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(res.json()["message"], SOURCES_NARROW);

    // A cursor the API no longer takes is a stale link, not a bad gateway.
    let app = spawn().await;
    Mock::given(method("GET"))
        .and(path(SOURCES))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "ValidationError", "message": "after: not a valid cursor"
        })))
        .mount(&app.upstream)
        .await;
    let res = app
        .get_as(
            "/explorer/bff/atlas/sources?after=so1.paper.1.00",
            &sid_for(&app),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.json()["message"]
        .as_str()
        .unwrap()
        .contains("no longer valid"));
}

#[tokio::test]
async fn the_view_routes_require_sign_in() {
    let app = spawn().await;
    for uri in ["/explorer/bff/atlas/sources", "/bff/atlas/sources"] {
        let res = app.get(uri).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{uri}");
    }
    assert!(app.upstream.received_requests().await.unwrap().is_empty());
}
