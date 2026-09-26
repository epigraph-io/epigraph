#![cfg(feature = "db")]
//! `GET /api/v1/claims/:id/ego` (plan §2.2).
//!
//! Hermetic `#[sqlx::test]`: the degree-cap, balance and `total_edges`
//! assertions count rows, so they only mean anything on a database that holds
//! nothing but this test's fixtures.
//!
//! # Two fixture rules this file depends on
//!
//! `AppState` is built with `with_scoped_pool`, not `with_db`. Every other
//! constructor leaves `scoped: None`, and `read_as` REFUSES in that case rather
//! than falling back to the raw pool, so a converted handler 500s and every
//! assertion below reads the error body.
//!
//! Every request carries a bearer. `ViewerExtractor` has no anonymous shape:
//! the tenancy series moved 105 registrations from the public router to the
//! protected one and the anonymous allowlist is two routes, neither of them
//! this one. The arms that used to send no credential now assert 401.

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
/// public corpus, which is the default position of any signed-in stranger.
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
    let app = router(&pool).await;

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego"),
        Some(&reader()),
    )
    .await;
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
    let app = router(&pool).await;
    let missing = Uuid::new_v4();
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{missing}/ego"),
        Some(&reader()),
    )
    .await;
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
    let app = router(&pool).await;

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?max_degree=4"),
        Some(&reader()),
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
    let app = router(&pool).await;

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?max_degree=6"),
        Some(&reader()),
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
    let app = router(&pool).await;

    // 0 clamps up to 1: one edge, and `truncated` says so.
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?max_degree=0"),
        Some(&reader()),
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
        Some(&reader()),
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
    let app = router(&pool).await;

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego"),
        Some(&reader()),
    )
    .await;
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

    let app = router(&pool).await;

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego"),
        Some(&reader()),
    )
    .await;
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
    let app = router(&pool).await;

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?relationships=supports"),
        Some(&reader()),
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
        Some(&reader()),
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
    let secret_edge =
        common::insert_edge(&pool, secret, center, "claim", "claim", "supports").await;
    common::seed_private_ownership(&pool, secret, owner).await;

    // THE TRAP THIS LINE EXISTS TO DISARM. Migration 070 makes an edge inherit
    // its endpoints' tenancy, so an edge stamped by the trigger AFTER the
    // neighbour went private would be excluded by the EDGE predicate alone and
    // this test would stay green with the far-endpoint `claims` predicate
    // deleted. Forcing the edge public leaves that predicate as the only thing
    // that can withhold the node.
    sqlx::query("UPDATE edges SET visibility = 'public', co_owner_group_id = NULL WHERE id = $1")
        .bind(secret_edge)
        .execute(&pool)
        .await
        .expect("force the connecting edge public");

    let app = router(&pool).await;
    let path = format!("/api/v1/claims/{center}/ego");

    // No credential at all: 401, because there is no anonymous read of claim
    // content left anywhere on this router.
    let (status, _, _) = raw(&app, &path, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A signed-in stranger: the neighbour and the edge to it are GONE, not
    // blanked — a bare claim id plus a relationship already says too much.
    let stranger = reader();
    let (status, body) = get(&app, &path, Some(&stranger)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body), vec![public_neighbour.to_string()]);
    assert_eq!(body["edges"].as_array().expect("edges").len(), 1);
    assert_eq!(body["center"]["content"], "public centre");

    // A spoofed query parameter buys nothing: visibility comes from the token's
    // principal and never from the wire.
    let (status, body) = get(&app, &format!("{path}?agent_id={owner}"), Some(&stranger)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(node_ids(&body), vec![public_neighbour.to_string()]);

    // The owner sees both, with content. CALIBRATION: without this arm the
    // stranger assertions would pass just as well against a handler that
    // returned nothing at all.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let (status, body) = get(&app, &path, Some(&owner_token)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let mut ids = node_ids(&body);
    ids.sort();
    let mut want = vec![public_neighbour.to_string(), secret.to_string()];
    want.sort();
    assert_eq!(ids, want);
    assert_eq!(node(&body, secret)["content"], "classified neighbour");
    assert_eq!(body["edges"].as_array().expect("edges").len(), 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_centre_is_the_same_404_as_a_claim_that_does_not_exist(pool: PgPool) {
    let owner = Uuid::new_v4();
    let center = common::seed_claim_with_agent(&pool, "classified centre", owner).await;
    let neighbour = common::seed_claim(&pool, "public neighbour").await;
    common::insert_edge(&pool, center, neighbour, "claim", "claim", "supports").await;
    common::seed_private_ownership(&pool, center, owner).await;
    let app = router(&pool).await;

    let path = format!("/api/v1/claims/{center}/ego");
    let stranger = reader();

    // Byte-identical to the answer for a uuid that names nothing, modulo the
    // echoed id. A status-code-only assertion would pass while the oracle
    // stood: the old shape here was a 200 carrying the centre with a zeroed
    // degree, which confirmed the claim existed.
    let (private_status, private_ct, private_body) = raw(&app, &path, Some(&stranger)).await;
    assert_eq!(private_status, StatusCode::NOT_FOUND, "{private_body}");

    let absent = Uuid::new_v4();
    let (absent_status, absent_ct, absent_body) = raw(
        &app,
        &format!("/api/v1/claims/{absent}/ego"),
        Some(&stranger),
    )
    .await;
    assert_eq!(
        private_status, absent_status,
        "status must not discriminate"
    );
    assert_eq!(private_ct, absent_ct, "content-type must not discriminate");
    assert_eq!(
        private_body.replace(&center.to_string(), "<ID>"),
        absent_body.replace(&absent.to_string(), "<ID>"),
        "the body must not discriminate either: a private claim and a \
         nonexistent one are one answer"
    );

    // CALIBRATION: the owner still gets the whole ego view, so the assertions
    // above are about tenancy and not about a route that 404s unconditionally.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let (status, body) = get(&app, &path, Some(&owner_token)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["center"]["content"], "classified centre");
    assert_eq!(node_ids(&body), vec![neighbour.to_string()]);
    assert_eq!(body["total_edges"], 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn long_labels_are_cut_on_a_char_boundary(pool: PgPool) {
    // 200 two-byte characters: 400 bytes, 200 chars. A byte slice at 157 would
    // land inside a character and panic the handler.
    let content = "é".repeat(200);
    let center = common::seed_claim(&pool, &content).await;
    let app = router(&pool).await;

    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego"),
        Some(&reader()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let label = body["center"]["label"].as_str().expect("label");
    assert_eq!(label.chars().count(), 160);
    assert!(label.ends_with("..."));
    assert_eq!(
        body["center"]["content"], content,
        "`content` is never truncated; only `label` is"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn total_edges_excludes_edges_the_viewer_cannot_see(pool: PgPool) {
    // Two private neighbours and one public one. Serialising the database
    // degree would tell a stranger that exactly two neighbours are being
    // withheld — the same metadata leak as returning them, dressed as a count.
    let owner = Uuid::new_v4();
    let center = common::seed_claim(&pool, "public centre").await;
    let public_neighbour = common::seed_claim(&pool, "public neighbour").await;
    let secret_a = common::seed_claim_with_agent(&pool, "classified A", owner).await;
    let secret_b = common::seed_claim_with_agent(&pool, "classified B", owner).await;
    common::insert_edge(
        &pool,
        center,
        public_neighbour,
        "claim",
        "claim",
        "supports",
    )
    .await;
    let edge_a = common::insert_edge(&pool, center, secret_a, "claim", "claim", "supports").await;
    let edge_b = common::insert_edge(&pool, secret_b, center, "claim", "claim", "supports").await;
    common::seed_private_ownership(&pool, secret_a, owner).await;
    common::seed_private_ownership(&pool, secret_b, owner).await;
    // Force both connecting edges PUBLIC. Migration 070's edge-inherits-
    // endpoint-tenancy would otherwise satisfy this assertion through the EDGE
    // predicate alone, and the test would stay green with the far-endpoint
    // `claims` predicate — the thing it exists to test — deleted.
    sqlx::query(
        "UPDATE edges SET visibility = 'public', co_owner_group_id = NULL WHERE id = ANY($1)",
    )
    .bind(vec![edge_a, edge_b])
    .execute(&pool)
    .await
    .expect("force the connecting edges public");
    let app = router(&pool).await;

    let path = format!("/api/v1/claims/{center}/ego");

    // A stranger: one visible edge, and `total_edges` says one — not three.
    let (status, body) = get(&app, &path, Some(&reader())).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["edges"].as_array().expect("edges").len(), 1);
    assert_eq!(
        body["total_edges"], 1,
        "`total_edges` must not count edges whose far endpoint is invisible, got {body}"
    );
    assert_eq!(
        body["truncated"],
        Value::Bool(false),
        "invisibility is not cap-truncation, got {body}"
    );

    // The owner sees the whole degree, so this cannot pass by always reporting
    // `edges.len()` of a shrunken set.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let (status, body) = get(&app, &path, Some(&owner_token)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["edges"].as_array().expect("edges").len(), 3);
    assert_eq!(body["total_edges"], 3);
    assert_eq!(body["truncated"], Value::Bool(false));
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_degree_cap_and_invisibility_subtract_independently(pool: PgPool) {
    // Four public neighbours and one private one, capped at 2. `truncated`
    // must stay true (the cap really did cut the list) while `total_edges`
    // drops to the four edges this caller is allowed to know about.
    let owner = Uuid::new_v4();
    let center = common::seed_claim(&pool, "public centre").await;
    for i in 0..4 {
        let n = common::seed_claim(&pool, &format!("public neighbour {i}")).await;
        common::insert_edge(&pool, center, n, "claim", "claim", "supports").await;
    }
    let secret = common::seed_claim_with_agent(&pool, "classified", owner).await;
    let secret_edge =
        common::insert_edge(&pool, secret, center, "claim", "claim", "supports").await;
    common::seed_private_ownership(&pool, secret, owner).await;
    sqlx::query("UPDATE edges SET visibility = 'public', co_owner_group_id = NULL WHERE id = $1")
        .bind(secret_edge)
        .execute(&pool)
        .await
        .expect("force the connecting edge public");
    let app = router(&pool).await;

    // max_degree=2 with 4 outbound and 1 inbound: the inbound side of the
    // balanced split now has nothing visible to offer, so both slots go to
    // outbound rather than one of them being spent on a node that is dropped.
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?max_degree=2"),
        Some(&reader()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["edges"].as_array().expect("edges").len(),
        2,
        "the cap is spent entirely on edges this caller can see, got {body}"
    );
    assert_eq!(
        body["truncated"],
        Value::Bool(true),
        "the cap did cut the list, so `truncated` stays true, got {body}"
    );
    assert_eq!(
        body["total_edges"], 4,
        "five edges exist but only four are this caller's to count, got {body}"
    );

    // The owner: same cap, nothing hidden, full degree reported.
    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let (status, body) = get(
        &app,
        &format!("/api/v1/claims/{center}/ego?max_degree=2"),
        Some(&owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["edges"].as_array().expect("edges").len(), 2);
    assert_eq!(body["truncated"], Value::Bool(true));
    assert_eq!(body["total_edges"], 5);
}
