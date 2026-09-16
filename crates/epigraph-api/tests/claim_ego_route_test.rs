#![cfg(feature = "db")]
//! `GET /api/v1/claims/:id/ego` (plan §2.2).
//!
//! Hermetic `#[sqlx::test]`: the degree-cap, balance and `total_edges`
//! assertions count rows, so they only mean anything on a database that holds
//! nothing but this test's fixtures.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn router(pool: PgPool) -> Router {
    create_router(AppState::with_db(pool, ApiConfig::default()))
}

async fn get(router: &Router, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
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
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn node_ids(body: &Value) -> Vec<String> {
    body["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .map(|n| n["id"].as_str().expect("id string").to_string())
        .collect()
}

fn node(body: &Value, id: Uuid) -> &Value {
    body["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .find(|n| n["id"] == id.to_string())
        .unwrap_or_else(|| panic!("node {id} missing from {body}"))
}

fn directions(body: &Value) -> (usize, usize) {
    let edges = body["edges"].as_array().expect("edges array");
    let out = edges.iter().filter(|e| e["direction"] == "out").count();
    let inb = edges.iter().filter(|e| e["direction"] == "in").count();
    (out, inb)
}

async fn seed_agent_named(pool: &PgPool, display_name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, display_name) \
         VALUES ($1, $2, 'system', $3)",
    )
    .bind(id)
    .bind(&pk)
    .bind(display_name)
    .execute(pool)
    .await
    .expect("seed named agent");
    id
}

async fn seed_trace(pool: &PgPool, claim_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO reasoning_traces (id, claim_id, reasoning_type, confidence, explanation) \
         VALUES ($1, $2, 'deductive', 0.75, 'because')",
    )
    .bind(id)
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("seed reasoning trace");
    id
}

async fn seed_paper(pool: &PgPool, title: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("10.1234/{id}"))
        .bind(title)
        .execute(pool)
        .await
        .expect("seed paper");
    id
}

async fn seed_activity(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO activities (id, activity_type, started_at) VALUES ($1, 'test', now())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed activity");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn happy_path_returns_the_documented_shape(pool: PgPool) {
    let center = common::seed_claim(&pool, "the centre claim").await;
    let out_neighbour = common::seed_claim(&pool, "a claim the centre supports").await;
    let in_neighbour = common::seed_claim(&pool, "a claim supporting the centre").await;
    let out_edge =
        common::insert_edge(&pool, center, out_neighbour, "claim", "claim", "supports").await;
    let in_edge =
        common::insert_edge(&pool, in_neighbour, center, "claim", "claim", "supports").await;
    let app = router(pool);

    let (status, body) = get(&app, &format!("/api/v1/claims/{center}/ego"), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    assert_eq!(body["total_edges"], 2);
    assert_eq!(body["truncated"], Value::Bool(false));

    // Exact top-level key set: the BFF is written against this shape.
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["center", "edges", "nodes", "total_edges", "truncated"]
    );

    let mut center_keys: Vec<&str> = body["center"]
        .as_object()
        .expect("center object")
        .keys()
        .map(String::as_str)
        .collect();
    center_keys.sort_unstable();
    assert_eq!(
        center_keys,
        vec![
            "content",
            "entity_type",
            "id",
            "is_current",
            "label",
            "labels",
            "redacted",
            "truth_value",
        ],
        "pignistic_prob is omitted, not null, when the claim has none"
    );
    assert_eq!(body["center"]["id"], center.to_string());
    assert_eq!(body["center"]["entity_type"], "claim");
    assert_eq!(body["center"]["label"], "the centre claim");
    assert_eq!(body["center"]["content"], "the centre claim");
    assert_eq!(body["center"]["truth_value"], 0.5);
    assert_eq!(body["center"]["is_current"], Value::Bool(true));
    assert_eq!(body["center"]["redacted"], Value::Bool(false));

    let ids = node_ids(&body);
    assert_eq!(ids.len(), 2, "both neighbours hydrated, got {body}");
    assert_eq!(
        node(&body, out_neighbour)["label"],
        "a claim the centre supports",
        "neighbours arrive hydrated — no second call per link"
    );

    let edges = body["edges"].as_array().expect("edges array");
    assert_eq!(edges.len(), 2);
    let out = edges
        .iter()
        .find(|e| e["id"] == out_edge.to_string())
        .expect("outbound edge");
    assert_eq!(
        *out,
        serde_json::json!({
            "id": out_edge.to_string(),
            "source_id": center.to_string(),
            "target_id": out_neighbour.to_string(),
            "source_type": "claim",
            "target_type": "claim",
            "relationship": "supports",
            "direction": "out",
        })
    );
    let inbound = edges
        .iter()
        .find(|e| e["id"] == in_edge.to_string())
        .expect("inbound edge");
    assert_eq!(inbound["direction"], "in");
    assert_eq!(inbound["source_id"], in_neighbour.to_string());
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_claim_is_404(pool: PgPool) {
    let app = router(pool);
    let missing = Uuid::new_v4();
    let (status, body) = get(&app, &format!("/api/v1/claims/{missing}/ego"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["error"], "NotFound");
}

#[sqlx::test(migrations = "../../migrations")]
async fn both_directions_get_half_the_budget(pool: PgPool) {
    let center = common::seed_claim(&pool, "centre").await;
    for i in 0..5 {
        let out = common::seed_claim(&pool, &format!("out {i}")).await;
        common::insert_edge(&pool, center, out, "claim", "claim", "supports").await;
        let inb = common::seed_claim(&pool, &format!("in {i}")).await;
        common::insert_edge(&pool, inb, center, "claim", "claim", "supports").await;
    }
    let app = router(pool);

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?max_degree=4"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // The bug this route exists to avoid: `claim_neighborhood` collects
    // outgoing rows first and cuts the tail, so backlinks vanish entirely.
    assert_eq!(
        directions(&body),
        (2, 2),
        "budget 4 splits evenly, got {body}"
    );
    assert_eq!(body["total_edges"], 10);
    assert_eq!(body["truncated"], Value::Bool(true));
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unused_half_goes_to_the_other_direction(pool: PgPool) {
    let center = common::seed_claim(&pool, "centre").await;
    for i in 0..10 {
        let out = common::seed_claim(&pool, &format!("out {i}")).await;
        common::insert_edge(&pool, center, out, "claim", "claim", "supports").await;
    }
    let inb = common::seed_claim(&pool, "the only backlink").await;
    common::insert_edge(&pool, inb, center, "claim", "claim", "supports").await;
    let app = router(pool);

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?max_degree=6"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        directions(&body),
        (5, 1),
        "inbound's unspent budget goes to outbound, got {body}"
    );
    assert_eq!(body["edges"].as_array().expect("edges").len(), 6);
    assert_eq!(body["total_edges"], 11);
    assert_eq!(body["truncated"], Value::Bool(true));
}

#[sqlx::test(migrations = "../../migrations")]
async fn max_degree_is_clamped_and_below_the_cap_nothing_is_truncated(pool: PgPool) {
    let center = common::seed_claim(&pool, "centre").await;
    let a = common::seed_claim(&pool, "a").await;
    let b = common::seed_claim(&pool, "b").await;
    common::insert_edge(&pool, center, a, "claim", "claim", "supports").await;
    common::insert_edge(&pool, b, center, "claim", "claim", "supports").await;
    let app = router(pool);

    // 0 clamps up to 1: one edge, and `truncated` says so.
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?max_degree=0"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["edges"].as_array().expect("edges").len(), 1);
    assert_eq!(body["total_edges"], 2);
    assert_eq!(body["truncated"], Value::Bool(true));

    // Far above the range clamps down to 200 and is answered, not rejected.
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?max_degree=99999"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["edges"].as_array().expect("edges").len(), 2);
    assert_eq!(body["truncated"], Value::Bool(false));
}

#[sqlx::test(migrations = "../../migrations")]
async fn retracted_edges_are_excluded(pool: PgPool) {
    let center = common::seed_claim(&pool, "centre").await;
    let live = common::seed_claim(&pool, "still linked").await;
    let gone = common::seed_claim(&pool, "link was retracted").await;
    common::insert_edge(&pool, center, live, "claim", "claim", "supports").await;
    let retracted = common::insert_edge(&pool, center, gone, "claim", "claim", "supports").await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1")
        .bind(retracted)
        .execute(&pool)
        .await
        .expect("retract edge");
    let app = router(pool);

    let (status, body) = get(&app, &format!("/api/v1/claims/{center}/ego"), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["edges"].as_array().expect("edges").len(), 1);
    assert_eq!(
        body["total_edges"], 1,
        "a retracted edge is not part of the degree either, got {body}"
    );
    assert_eq!(node_ids(&body), vec![live.to_string()]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn non_claim_neighbours_are_hydrated_and_unknown_types_fall_back(pool: PgPool) {
    let center = common::seed_claim(&pool, "centre").await;

    let agent = seed_agent_named(&pool, "Dr. Ada Lovelace").await;
    common::insert_edge(&pool, center, agent, "claim", "agent", "attributed_to").await;

    let trace = seed_trace(&pool, center).await;
    common::insert_edge(&pool, center, trace, "claim", "trace", "derived_from").await;

    let paper = seed_paper(&pool, "A Paper With A Title").await;
    common::insert_edge(&pool, center, paper, "claim", "paper", "asserts").await;

    // `activity` is a legal edge-endpoint type that this route does not
    // hydrate; the neighbour must still be rendered, as a bare typed node.
    let activity = seed_activity(&pool).await;
    common::insert_edge(&pool, center, activity, "claim", "activity", "produced").await;

    let app = router(pool);

    let (status, body) = get(&app, &format!("/api/v1/claims/{center}/ego"), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body).len(), 4, "body: {body}");

    assert_eq!(node(&body, agent)["entity_type"], "agent");
    assert_eq!(node(&body, agent)["label"], "Dr. Ada Lovelace");
    assert_eq!(
        node(&body, agent).get("content"),
        None,
        "claim-only fields are omitted for other entity types"
    );
    assert_eq!(node(&body, agent).get("truth_value"), None);

    assert_eq!(node(&body, trace)["entity_type"], "trace");
    assert_eq!(node(&body, trace)["label"], "deductive (0.75)");

    assert_eq!(node(&body, paper)["entity_type"], "paper");
    assert_eq!(node(&body, paper)["label"], "A Paper With A Title");

    assert_eq!(node(&body, activity)["entity_type"], "activity");
    assert_eq!(
        node(&body, activity)["label"],
        "activity",
        "an unhydrated neighbour keeps its declared type as its label"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn relationship_filter_is_case_insensitive(pool: PgPool) {
    let center = common::seed_claim(&pool, "centre").await;
    let supported = common::seed_claim(&pool, "supported").await;
    let refuted = common::seed_claim(&pool, "refuted").await;
    // The corpus holds both spellings of the same relationship.
    common::insert_edge(&pool, center, supported, "claim", "claim", "SUPPORTS").await;
    common::insert_edge(&pool, center, refuted, "claim", "claim", "refutes").await;
    let app = router(pool);

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?relationships=supports"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body), vec![supported.to_string()]);
    assert_eq!(
        body["total_edges"], 1,
        "the filter applies to the degree count too, got {body}"
    );

    // Empty means no filter.
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?relationships="),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["total_edges"], 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_neighbour_and_its_edges_are_dropped_for_everyone_but_its_owner(pool: PgPool) {
    let owner = Uuid::new_v4();
    let center = common::seed_claim(&pool, "public centre").await;
    let public_neighbour = common::seed_claim(&pool, "public neighbour").await;
    let secret = common::seed_claim_with_agent(&pool, "classified neighbour", owner).await;
    common::insert_edge(
        &pool,
        center,
        public_neighbour,
        "claim",
        "claim",
        "supports",
    )
    .await;
    common::insert_edge(&pool, secret, center, "claim", "claim", "supports").await;
    common::seed_private_ownership(&pool, secret, owner).await;
    let app = router(pool);

    let path = format!("/api/v1/claims/{center}/ego");

    // Anonymous: the neighbour and the edge to it are gone, not redacted —
    // a bare claim id plus a relationship already says too much.
    let (status, body) = get(&app, &path, None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body), vec![public_neighbour.to_string()]);
    assert_eq!(body["edges"].as_array().expect("edges").len(), 1);
    assert_eq!(body["center"]["content"], "public centre");

    // A spoofed query parameter buys nothing.
    let (status, body) = get(&app, &format!("{path}?agent_id={owner}"), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body), vec![public_neighbour.to_string()]);

    // A stranger's token.
    let stranger = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let (status, body) = get(&app, &path, Some(&stranger)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body), vec![public_neighbour.to_string()]);

    // The owner sees both, with content.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let (status, body) = get(&app, &path, Some(&owner_token)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let mut ids = node_ids(&body);
    ids.sort();
    let mut want = vec![public_neighbour.to_string(), secret.to_string()];
    want.sort();
    assert_eq!(ids, want);
    assert_eq!(node(&body, secret)["content"], "classified neighbour");
    assert_eq!(node(&body, secret)["redacted"], Value::Bool(false));
    assert_eq!(body["edges"].as_array().expect("edges").len(), 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_centre_returns_itself_redacted_and_nothing_else(pool: PgPool) {
    let owner = Uuid::new_v4();
    let center = common::seed_claim_with_agent(&pool, "classified centre", owner).await;
    let neighbour = common::seed_claim(&pool, "public neighbour").await;
    common::insert_edge(&pool, center, neighbour, "claim", "claim", "supports").await;
    common::seed_private_ownership(&pool, center, owner).await;
    let app = router(pool);

    let path = format!("/api/v1/claims/{center}/ego");

    let (status, body) = get(&app, &path, None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["center"]["id"], center.to_string());
    assert_eq!(body["center"]["content"], "[REDACTED]");
    assert_eq!(body["center"]["label"], "[REDACTED]");
    assert_eq!(body["center"]["redacted"], Value::Bool(true));
    assert_eq!(body["nodes"], serde_json::json!([]));
    assert_eq!(body["edges"], serde_json::json!([]));
    assert_eq!(
        body["total_edges"], 0,
        "the degree of an unreadable claim is itself withheld, got {body}"
    );

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let (status, body) = get(&app, &path, Some(&owner_token)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["center"]["content"], "classified centre");
    assert_eq!(body["center"]["redacted"], Value::Bool(false));
    assert_eq!(node_ids(&body), vec![neighbour.to_string()]);
    assert_eq!(body["total_edges"], 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn long_labels_are_cut_on_a_char_boundary(pool: PgPool) {
    // 200 two-byte characters: 400 bytes, 200 chars. A byte slice at 157 would
    // land inside a character and panic the handler.
    let content = "é".repeat(200);
    let center = common::seed_claim(&pool, &content).await;
    let app = router(pool);

    let (status, body) = get(&app, &format!("/api/v1/claims/{center}/ego"), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let label = body["center"]["label"].as_str().expect("label");
    assert_eq!(label.chars().count(), 160);
    assert!(label.ends_with("..."));
    assert_eq!(
        body["center"]["content"], content,
        "`content` is never truncated; only `label` is"
    );
}
