#![cfg(feature = "db")]
//! `GET /api/v1/claims/:id/provenance-chain` (plan §2.1).
//!
//! Hermetic: every test gets a fresh migrated database from `#[sqlx::test]`,
//! so the exact-shape and count assertions below cannot be perturbed by other
//! rows in a shared test database.
//!
//! `AppState` is built with `with_scoped_pool`: every other constructor leaves
//! `scoped: None` and `read_as` refuses rather than falling back to the raw
//! pool. Every request carries a bearer, because `ViewerExtractor` has no
//! anonymous shape.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

async fn router(pool: &PgPool) -> Router {
    create_router(AppState::with_scoped_pool(
        fixture::scoped_pool(pool).await,
        ApiConfig::default(),
    ))
}

/// A token for a principal with no group memberships: it reads exactly the
/// public corpus.
fn reader() -> String {
    common::mint_token_with_agent(&["claims:read"], Uuid::new_v4())
}

async fn raw(router: &Router, path: &str, bearer: Option<&str>) -> (StatusCode, String, String) {
    let mut req = Request::builder().method(Method::GET).uri(path);
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, content_type, String::from_utf8_lossy(&bytes).into())
}

async fn get(router: &Router, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let (status, _, text) = raw(router, path, bearer).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// `supports` is written ancestor→descendant, so this makes `ancestor` a
/// parent of `descendant` in the provenance walk.
async fn supports(pool: &PgPool, ancestor: Uuid, descendant: Uuid) {
    common::insert_edge(pool, ancestor, descendant, "claim", "claim", "supports").await;
}

fn node(body: &Value, id: Uuid) -> &Value {
    body["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .find(|n| n["id"] == id.to_string())
        .unwrap_or_else(|| panic!("node {id} missing from {body}"))
}

fn node_ids(body: &Value) -> Vec<String> {
    body["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .map(|n| n["id"].as_str().expect("id string").to_string())
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn happy_path_returns_the_documented_shape(pool: PgPool) {
    let root = common::seed_claim(&pool, "root conclusion").await;
    let ancestor = common::seed_claim(&pool, "supporting premise").await;
    supports(&pool, ancestor, root).await;
    let app = router(&pool).await;

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{root}/provenance-chain"),
        Some(&reader()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(body["root"], root.to_string());
    assert_eq!(body["truncated"], Value::Bool(false));
    assert_eq!(body["cycles"], serde_json::json!([]));

    let ids = node_ids(&body);
    assert_eq!(ids.len(), 2, "root + one ancestor, got {body}");
    assert!(ids.contains(&root.to_string()));
    assert!(ids.contains(&ancestor.to_string()));

    // Exact per-node field set, so a rename breaks this test rather than the BFF.
    let root_node = node(&body, root);
    let keys: Vec<&str> = root_node
        .as_object()
        .expect("node object")
        .keys()
        .map(String::as_str)
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec![
            "content",
            "depth",
            "id",
            "is_current",
            "labels",
            "truth_value",
        ]
    );
    assert_eq!(root_node["content"], "root conclusion");
    assert_eq!(root_node["depth"], 0);
    assert_eq!(root_node["is_current"], Value::Bool(true));
    assert_eq!(root_node["truth_value"], 0.5);
    assert_eq!(root_node["labels"], serde_json::json!([]));
    assert_eq!(node(&body, ancestor)["depth"], 1);

    let edges = body["edges"].as_array().expect("edges array");
    assert_eq!(edges.len(), 1, "one seeded edge, got {body}");
    assert_eq!(
        edges[0],
        serde_json::json!({
            "source": ancestor.to_string(),
            "target": root.to_string(),
            "relationship": "supports",
        }),
        "edges are reported exactly as stored (ancestor -> descendant)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_root_is_404_not_an_empty_chain(pool: PgPool) {
    let app = router(&pool).await;
    let missing = Uuid::new_v4();

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{missing}/provenance-chain"),
        Some(&reader()),
    )
    .await;
    // The repo answers a nonexistent root with an empty success; the route
    // must not pass that through as "this claim derives from nothing".
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["error"], "NotFound");
}

#[sqlx::test(migrations = "../../migrations")]
async fn max_depth_is_clamped_to_1_and_8(pool: PgPool) {
    // a3 -> a2 -> a1 -> root, all `supports`.
    let root = common::seed_claim(&pool, "depth-0").await;
    let a1 = common::seed_claim(&pool, "depth-1").await;
    let a2 = common::seed_claim(&pool, "depth-2").await;
    let a3 = common::seed_claim(&pool, "depth-3").await;
    supports(&pool, a1, root).await;
    supports(&pool, a2, a1).await;
    supports(&pool, a3, a2).await;
    let app = router(&pool).await;

    // 0 clamps UP to 1: the root plus exactly one hop.
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{root}/provenance-chain?max_depth=0"),
        Some(&reader()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ids = node_ids(&body);
    assert_eq!(ids.len(), 2, "max_depth=0 clamps to 1, got {body}");
    assert!(ids.contains(&a1.to_string()));
    assert!(!ids.contains(&a2.to_string()));

    // Far above the range clamps DOWN to 8 and is answered, not rejected —
    // the reason the query field is u32 and not u8.
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{root}/provenance-chain?max_depth=9999"),
        Some(&reader()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body).len(), 4, "whole 3-hop chain, got {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn empty_relationships_param_means_the_default_set(pool: PgPool) {
    let root = common::seed_claim(&pool, "root").await;
    let ancestor = common::seed_claim(&pool, "premise").await;
    supports(&pool, ancestor, root).await;
    let app = router(&pool).await;

    // An empty value must NOT filter the walk down to nothing.
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{root}/provenance-chain?relationships="),
        Some(&reader()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body).len(), 2, "default set, got {body}");

    // A non-empty filter that excludes `supports` does isolate the root.
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{root}/provenance-chain?relationships=supersedes"),
        Some(&reader()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body), vec![root.to_string()]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_ancestor_and_its_edge_are_absent_for_everyone_but_its_owner(pool: PgPool) {
    let owner = Uuid::new_v4();
    let root = common::seed_claim(&pool, "public conclusion").await;
    let secret = common::seed_claim_with_agent(&pool, "classified premise", owner).await;
    common::insert_edge(&pool, secret, root, "claim", "claim", "supports").await;
    common::seed_private_ownership(&pool, secret, owner).await;

    // Force the derivation edge PUBLIC. Migration 070 derives an edge's
    // tenancy from its endpoints, so a trigger-stamped edge would be excluded
    // by the recursive term's EDGE predicate alone and this arm would stay
    // green with the hydration predicate — and with the dangling-edge retain —
    // both deleted. Forced public, the edge survives the walk and the CLAIMS
    // filter is the only thing that can withhold the node.
    sqlx::query(
        "UPDATE edges SET visibility = 'public', co_owner_group_id = NULL \
         WHERE source_id = $1 AND target_id = $2",
    )
    .bind(secret)
    .bind(root)
    .execute(&pool)
    .await
    .expect("force the derivation edge public");

    let app = router(&pool).await;
    let path = format!("/api/v1/claims/{root}/provenance-chain");

    // No credential: 401. There is no anonymous read of claim content left.
    let (status, _, _) = raw(&app, &path, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A signed-in stranger: the ancestor is ABSENT, not blanked — and so is the
    // edge naming it. This is the regression test for the dangling-edge fix in
    // `ProvenanceChainRepository::chain`: before it, `edges` was retained
    // against the WALK (edge-filtered) rather than against the HYDRATED node
    // set (claim-filtered), so this edge came back carrying `secret`'s uuid and
    // the relationship it stands in. A uuid plus "supports" is a disclosure
    // with no content attached, which is still a disclosure.
    let stranger = reader();
    let (status, body) = get(&app, &path, Some(&stranger)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body), vec![root.to_string()]);
    assert_eq!(
        body["edges"],
        serde_json::json!([]),
        "an edge naming an invisible claim must not survive hydration, got {body}"
    );
    assert_eq!(node(&body, root)["content"], "public conclusion");
    assert!(
        !body.to_string().contains(&secret.to_string()),
        "the invisible claim's uuid must not appear anywhere in the response, got {body}"
    );

    // A spoofed `agent_id` must not buy access: the route has no such parameter
    // and visibility comes from the token's principal.
    let (status, body) = get(&app, &format!("{path}?agent_id={owner}"), Some(&stranger)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body), vec![root.to_string()]);

    // CALIBRATION: the owner sees both nodes and the edge, so the assertions
    // above are about tenancy rather than about a walk that returns nothing.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let (status, body) = get(&app, &path, Some(&owner_token)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node(&body, secret)["content"], "classified premise");
    assert_eq!(body["edges"].as_array().expect("edges").len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_root_is_the_same_404_as_a_root_that_does_not_exist(pool: PgPool) {
    let owner = Uuid::new_v4();
    let root = common::seed_claim_with_agent(&pool, "classified conclusion", owner).await;
    common::seed_private_ownership(&pool, root, owner).await;
    let app = router(&pool).await;

    let stranger = reader();
    let (private_status, private_ct, private_body) = raw(
        &app,
        &format!("/api/v1/claims/{root}/provenance-chain"),
        Some(&stranger),
    )
    .await;
    assert_eq!(private_status, StatusCode::NOT_FOUND, "{private_body}");

    let absent = Uuid::new_v4();
    let (absent_status, absent_ct, absent_body) = raw(
        &app,
        &format!("/api/v1/claims/{absent}/provenance-chain"),
        Some(&stranger),
    )
    .await;
    assert_eq!(private_status, absent_status);
    assert_eq!(private_ct, absent_ct);
    assert_eq!(
        private_body.replace(&root.to_string(), "<ID>"),
        absent_body.replace(&absent.to_string(), "<ID>"),
        "a private root and a nonexistent one are one answer"
    );

    // CALIBRATION.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{root}/provenance-chain"),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body), vec![root.to_string()]);
}
