#![cfg(feature = "db")]
//! The unversioned legacy routes and their `/api/v1` twins (backlog f2938a03).
//!
//! `GET /agents/:id/reputation`, `GET /agents/:id/perspectives` and
//! `GET /lineage/:claim_id` were registered only unversioned. Each now has an
//! `/api/v1` twin on the same handler and router tier, and every unversioned
//! alias answers as before with two more headers: `Deprecation: true` and
//! `Link: </api/v1<path>>; rel="successor-version"`.
//!
//! * each twin answers the same body as its alias, for the same token, on
//!   seeded data that makes the body non-trivial (calibrated below);
//! * each alias carries the two headers, and no twin carries `Deprecation`;
//! * the twin sits on the alias's tier: no token is 401 on both;
//! * `GET /claims` keeps its own handler and envelope (`items`, `total`,
//!   `limit`, `offset`), not `GET /api/v1/claims`'s (`claims`, ...): only its
//!   headers changed.

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

struct Answer {
    status: StatusCode,
    deprecation: Option<String>,
    link: Option<String>,
    body: Value,
}

async fn get(app: &axum::Router, uri: &str, token: Option<&str>) -> Answer {
    call(app, Method::GET, uri, token).await
}

/// A GET with no body, or a POST with the JSON body `{}`.
async fn call(app: &axum::Router, method: Method, uri: &str, token: Option<&str>) -> Answer {
    let mut req = Request::builder().method(method.clone()).uri(uri);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let body = if method == Method::POST {
        req = req.header(header::CONTENT_TYPE, "application/json");
        Body::from("{}")
    } else {
        Body::empty()
    };
    let resp = app
        .clone()
        .oneshot(req.body(body).expect("request"))
        .await
        .expect("response");
    let status = resp.status();
    let h = |name: &str| {
        resp.headers()
            .get(name)
            .map(|v| v.to_str().expect("ascii header").to_string())
    };
    let (deprecation, link) = (h("deprecation"), h("link"));
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Answer {
        status,
        deprecation,
        link,
        body,
    }
}

/// `claim_age_days_avg` is computed from the request's clock, so two calls a
/// moment apart differ in its last digits: compare it approximately and the
/// rest of the body exactly.
fn without_clock(mut v: Value) -> (Value, Option<f64>) {
    let age = v
        .as_object_mut()
        .and_then(|o| o.remove("claim_age_days_avg"))
        .and_then(|a| a.as_f64());
    (v, age)
}

fn assert_alias_headers(a: &Answer, alias: &str) {
    assert_eq!(
        a.deprecation.as_deref(),
        Some("true"),
        "{alias}: the alias must say it is deprecated"
    );
    assert_eq!(
        a.link.as_deref(),
        Some(
            format!(
                "</api/v1{}>; rel=\"successor-version\"",
                alias.split('?').next().unwrap()
            )
            .as_str()
        ),
        "{alias}: the alias must link its /api/v1 successor"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn each_orphan_route_has_an_api_v1_twin_and_its_alias_is_marked_deprecated() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("pool");
    common::assert_test_db_at_head(&url).await;

    // An agent with two claims, one deriving from the other (`supports`,
    // ancestor -> claim), and a perspective it owns.
    let agent = Uuid::new_v4();
    let tag = Uuid::new_v4().simple().to_string();
    let parent = common::seed_claim_with_agent(&pool, &format!("twin parent {tag}"), agent).await;
    let child = common::seed_claim_with_agent(&pool, &format!("twin child {tag}"), agent).await;
    common::insert_edge(&pool, parent, child, "claim", "claim", "supports").await;
    sqlx::query("INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2)")
        .bind(format!("twin lens {tag}"))
        .bind(agent)
        .execute(&pool)
        .await
        .expect("seed perspective");

    let app = epigraph_api::build_app_for_tests(&url)
        .await
        .expect("app builds");
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());

    for alias in [
        format!("/agents/{agent}/reputation"),
        format!("/agents/{agent}/perspectives"),
        format!("/lineage/{child}"),
    ] {
        let twin = format!("/api/v1{alias}");
        let a = get(&app, &alias, Some(&token)).await;
        let t = get(&app, &twin, Some(&token)).await;
        assert_eq!(a.status, StatusCode::OK, "{alias}: {}", a.body);
        assert_eq!(
            t.status,
            StatusCode::OK,
            "{twin} must be registered: {}",
            t.body
        );

        let (a_body, a_age) = without_clock(a.body.clone());
        let (t_body, t_age) = without_clock(t.body.clone());
        assert_eq!(t_body, a_body, "{twin} must answer what {alias} answers");
        match (a_age, t_age) {
            (Some(x), Some(y)) => assert!((x - y).abs() < 1e-3, "{alias}: {x} vs {y}"),
            (None, None) => {}
            other => panic!("{alias}: claim_age_days_avg present on one side only: {other:?}"),
        }
        assert_alias_headers(&a, &alias);
        assert_eq!(t.deprecation, None, "{twin} is the current route");
        assert_eq!(t.link, None, "{twin} names no successor");

        // Same tier: neither answers an anonymous caller.
        assert_eq!(
            get(&app, &alias, None).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get(&app, &twin, None).await.status,
            StatusCode::UNAUTHORIZED
        );
    }

    // CALIBRATION: the bodies compared above are not empty.
    let rep = get(
        &app,
        &format!("/api/v1/agents/{agent}/reputation"),
        Some(&token),
    )
    .await;
    assert_eq!(rep.body["total_claims"], 2, "{}", rep.body);
    let lenses = get(
        &app,
        &format!("/api/v1/agents/{agent}/perspectives"),
        Some(&token),
    )
    .await;
    assert_eq!(
        lenses.body.as_array().map(Vec::len),
        Some(1),
        "{}",
        lenses.body
    );
    let lineage = get(&app, &format!("/api/v1/lineage/{child}"), Some(&token)).await;
    let lineage_text = lineage.body.to_string();
    assert!(
        lineage_text.contains(&parent.to_string()),
        "the lineage names the parent: {lineage_text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_other_unversioned_aliases_are_marked_deprecated_and_get_claims_keeps_its_body() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("pool");
    common::assert_test_db_at_head(&url).await;

    let agent = Uuid::new_v4();
    let tag = Uuid::new_v4().simple().to_string();
    let claim = common::seed_claim_with_agent(&pool, &format!("legacy list {tag}"), agent).await;

    let app = epigraph_api::build_app_for_tests(&url)
        .await
        .expect("app builds");
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());

    for alias in [
        format!("/claims/{claim}"),
        "/agents?limit=1".to_string(),
        format!("/agents/{agent}"),
    ] {
        let a = get(&app, &alias, Some(&token)).await;
        assert_eq!(a.status, StatusCode::OK, "{alias}: {}", a.body);
        assert_alias_headers(&a, &alias);
        let t = get(&app, &format!("/api/v1{alias}"), Some(&token)).await;
        assert_eq!(t.deprecation, None, "/api/v1{alias} is the current route");
    }

    // GET /claims: deprecated, linked to /api/v1/claims, and still the legacy
    // handler's envelope with the seeded claim in it.
    let legacy = get(&app, &format!("/claims?search={tag}"), Some(&token)).await;
    assert_eq!(legacy.status, StatusCode::OK, "{}", legacy.body);
    assert_alias_headers(&legacy, "/claims");
    let keys: Vec<&str> = legacy
        .body
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 4, "{}", legacy.body);
    for k in ["items", "total", "limit", "offset"] {
        assert!(
            keys.contains(&k),
            "GET /claims keeps `{k}`: {}",
            legacy.body
        );
    }
    assert_eq!(legacy.body["total"], 1, "{}", legacy.body);
    assert_eq!(
        legacy.body["items"][0]["id"],
        claim.to_string(),
        "{}",
        legacy.body
    );

    let v1 = get(&app, "/api/v1/claims?limit=1", Some(&token)).await;
    assert!(
        v1.body.get("claims").is_some() && v1.body.get("items").is_none(),
        "CALIBRATION: /api/v1/claims is the other envelope: {}",
        v1.body
    );
    assert_eq!(v1.deprecation, None);
}

/// The POST aliases (`/claims`, `/agents`) carry the headers too. The request
/// is refused (a `claims:read` token, an empty body), and the refusal comes
/// from the handler's own extractors, inside the alias's layer, so it still
/// says where the successor is. CALIBRATION: the route matched (not 404) and
/// the token authenticated (not 401); the `/api/v1` twin carries no header.
#[tokio::test(flavor = "multi_thread")]
async fn the_post_aliases_are_marked_deprecated() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    common::assert_test_db_at_head(&url).await;
    let app = epigraph_api::build_app_for_tests(&url)
        .await
        .expect("app builds");
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());

    for alias in ["/claims", "/agents"] {
        let a = call(&app, Method::POST, alias, Some(&token)).await;
        assert!(
            a.status != StatusCode::NOT_FOUND && a.status != StatusCode::UNAUTHORIZED,
            "POST {alias}: {} {}",
            a.status,
            a.body
        );
        assert_alias_headers(&a, alias);
        let t = call(&app, Method::POST, &format!("/api/v1{alias}"), Some(&token)).await;
        assert_eq!(t.status, a.status, "POST /api/v1{alias}: same handler");
        assert_eq!(
            t.deprecation, None,
            "POST /api/v1{alias} is the current route"
        );
    }
}
