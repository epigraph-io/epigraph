//! Plan 2.5 — Server-side ingestion idempotency (TDD)
//!
//! These tests drive durable, cross-process idempotency for agent
//! registration and `POST /api/v1/submit/packet` claim insertion, so the
//! per-PR-process commit ingester can find-or-create repo/PR/commit nodes and
//! author/orchestrator agents without 500s on run 2+.
//!
//! # Running
//!
//! ```bash
//! DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
//!   cargo test -p epigraph-api --test idempotency_2p5_tests
//! ```

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use epigraph_api::middleware::SignatureVerificationState;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_core::Agent;
use epigraph_db::{AgentRepository, PgPool};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

/// Create an agent with a fixed (deterministic) 32-byte public key so two
/// calls collide on `agents_public_key_unique`.
fn fixed_agent(seed: u8, display_name: &str) -> Agent {
    let key = [seed; 32];
    Agent::new(key, Some(display_name.to_string()))
}

/// `create_or_get` is idempotent on `public_key`: the first call creates the
/// agent, the second returns the same row without inserting a duplicate.
#[sqlx::test(migrations = "../../migrations")]
async fn agent_create_or_get_is_idempotent_on_public_key(pool: PgPool) {
    let agent = fixed_agent(7, "idem-agent");

    let (first, created_first) = AgentRepository::create_or_get(&pool, &agent)
        .await
        .expect("first create_or_get should succeed");
    assert!(created_first, "first call must report a fresh creation");

    let (second, created_second) = AgentRepository::create_or_get(&pool, &agent)
        .await
        .expect("second create_or_get should succeed");
    assert!(!created_second, "second call must report find (not create)");

    assert_eq!(
        first.id, second.id,
        "both calls must resolve to the same agent id"
    );

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(agent.public_key.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count query should succeed");
    assert_eq!(count, 1, "exactly one agents row for the fixed public key");
}

// =============================================================================
// HTTP test harness (each integration file is its own `[[test]]` crate, so
// `create_test_router` from `submit_persistence_tests.rs` is not importable;
// replicate the minimal pieces here).
// =============================================================================

/// Build a router on `pool` with signature verification bypassed, mirroring
/// `submit_persistence_tests::create_test_router`.
fn create_test_router(pool: PgPool) -> Router {
    let config = ApiConfig {
        require_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
    };
    let signature_state = SignatureVerificationState::with_bypass_routes(vec!["/".to_string()]);
    let state = AppState::with_db_and_signature_state(pool, config, signature_state);
    create_router(state)
}

/// Mint a Bearer token carrying `agents:write` so it clears the `create_agent`
/// scope gate (the generic `submit` token lacks `agents:write` → 403). The
/// secret matches `default_jwt_config()`'s fallback so no env setup is needed.
fn agents_write_bearer_token() -> String {
    use epigraph_api::oauth::JwtConfig;
    let jwt_config = JwtConfig::from_secret(b"epigraph-dev-secret-change-in-production!!");
    let (token, _) = jwt_config
        .issue_access_token(
            uuid::Uuid::new_v4(),
            vec!["agents:write".to_string(), "agents:read".to_string()],
            "service",
            None,
            None,
            chrono::Duration::seconds(300),
        )
        .expect("issue_access_token must succeed for tests");
    token
}

/// POST a JSON body to `uri` through `router`, returning (status, body string).
async fn post_json(router: &Router, uri: &str, body: serde_json::Value) -> (StatusCode, String) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", agents_write_bearer_token()),
        )
        .body(Body::from(body.to_string()))
        .expect("Failed to build request");

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes();
    let body_string = String::from_utf8(body_bytes.to_vec()).expect("Body is not valid UTF-8");
    (status, body_string)
}

/// `POST /api/v1/agents` is find-or-create on `public_key`: re-POSTing the same
/// key returns the same agent id with a success status (not 400), and leaves
/// exactly one `agents` row. Before the fix the second POST hit
/// `agents_public_key_unique` → `DbError::DuplicateKey` → 400.
#[sqlx::test(migrations = "../../migrations")]
async fn create_agent_is_idempotent_on_public_key(pool: PgPool) {
    let router = create_test_router(pool.clone());
    // 64 hex chars == 32-byte Ed25519 public key, fixed so both POSTs collide.
    let public_key_hex = "ab".repeat(32);
    let request_body = serde_json::json!({
        "public_key": public_key_hex,
        "display_name": "idem-http-agent",
    });

    let (status_1, body_1) = post_json(&router, "/api/v1/agents", request_body.clone()).await;
    assert!(
        status_1.is_success(),
        "first POST /api/v1/agents should succeed, got {status_1}: {body_1}"
    );
    let json_1: serde_json::Value =
        serde_json::from_str(&body_1).expect("first response should be JSON");
    let id_1 = json_1["id"].as_str().expect("first response must carry id");

    let (status_2, body_2) = post_json(&router, "/api/v1/agents", request_body).await;
    assert!(
        status_2.is_success(),
        "second POST with the same public_key must succeed (not 400), got {status_2}: {body_2}"
    );
    let json_2: serde_json::Value =
        serde_json::from_str(&body_2).expect("second response should be JSON");
    let id_2 = json_2["id"]
        .as_str()
        .expect("second response must carry id");

    assert_eq!(
        id_1, id_2,
        "both POSTs must resolve to the same agent id (find-or-create)"
    );

    let key_bytes = hex::decode(&public_key_hex).expect("public key hex should decode");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(key_bytes.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count query should succeed");
    assert_eq!(count, 1, "exactly one agents row for the fixed public key");
}

// =============================================================================
// submit/packet harness (Task 3): a submit-scoped Bearer token + JSON POST.
// =============================================================================

/// Mint a Bearer token carrying `epigraph:write` so it clears the
/// `submit/packet` scope gate (mirrors `submit_persistence_tests::test_bearer_token`).
fn submit_bearer_token() -> String {
    use epigraph_api::oauth::JwtConfig;
    let jwt_config = JwtConfig::from_secret(b"epigraph-dev-secret-change-in-production!!");
    let (token, _) = jwt_config
        .issue_access_token(
            Uuid::new_v4(),
            vec!["epigraph:write".to_string(), "epigraph:read".to_string()],
            "service",
            None,
            None,
            chrono::Duration::seconds(300),
        )
        .expect("issue_access_token must succeed for tests");
    token
}

/// POST a packet to `/api/v1/submit/packet` with an `epigraph:write` token,
/// returning (status, body string).
async fn post_packet(router: &Router, packet: serde_json::Value) -> (StatusCode, String) {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", submit_bearer_token()),
        )
        .body(Body::from(packet.to_string()))
        .expect("Failed to build request");

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to collect body")
        .to_bytes();
    let body_string = String::from_utf8(body_bytes.to_vec()).expect("Body is not valid UTF-8");
    (status, body_string)
}

/// **Task 3 driver — durable cross-process idempotency.**
///
/// Submitting the same packet twice through two *independent* routers (each
/// with its own in-memory idempotency cache, simulating a restarted process)
/// must converge on a single claim row keyed on `(content_hash, agent_id)`:
/// both responses 201, the same `claim_id`, exactly one `claims` row, no
/// duplicate evidence, and the create path persists `properties`.
///
/// Before the fix the second submit reached the bare `INSERT INTO claims` and
/// hit `uq_claims_content_hash_agent` → 500.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_durable_idempotency_across_processes(pool: PgPool) {
    // Seed the author agent (FK on claims.agent_id).
    let agent = fixed_agent(42, "idem-submit-agent");
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();

    // Evidence content + its real BLAKE3 hash (the route validates hash↔content).
    let evidence_content = "Empirical data supporting the idempotent claim";
    let evidence_hash = epigraph_crypto::ContentHasher::to_hex(
        &epigraph_crypto::ContentHasher::hash(evidence_content.as_bytes()),
    );
    let claim_content = "The idempotent claim is supported by evidence";

    // Packet carries an idempotency_key, one evidence item, and non-empty
    // properties (B1 — properties must be ported to the create path).
    let packet = serde_json::json!({
        "claim": {
            "content": claim_content,
            "initial_truth": 0.5,
            "agent_id": agent_uuid,
            "idempotency_key": "idem-task3-key",
            "properties": { "files_changed": 3, "commit_sha": "deadbeef" }
        },
        "evidence": [{
            "content_hash": evidence_hash,
            "evidence_type": { "type": "document", "source_url": null, "mime_type": "text/plain" },
            "raw_content": evidence_content,
            "signature": null
        }],
        "reasoning_trace": {
            "methodology": "inductive",
            "inputs": [{ "type": "evidence", "index": 0 }],
            "confidence": 0.8,
            "explanation": "Based on the provided evidence, this conclusion follows.",
            "signature": null
        },
        "signature": "0".repeat(128)
    });

    // First "process": fresh router on the pool.
    let router_a = create_test_router(pool.clone());
    let (status_1, body_1) = post_packet(&router_a, packet.clone()).await;
    assert_eq!(
        status_1,
        StatusCode::CREATED,
        "first submit should be 201, got {status_1}: {body_1}"
    );
    let json_1: serde_json::Value =
        serde_json::from_str(&body_1).expect("first response should be JSON");
    let claim_id_1 = json_1["claim_id"]
        .as_str()
        .expect("first response must carry claim_id");

    // Second "process": a *new* router on the same pool — its in-memory
    // idempotency cache is empty, so the request reaches persist_packet.
    let router_b = create_test_router(pool.clone());
    let (status_2, body_2) = post_packet(&router_b, packet.clone()).await;
    assert_eq!(
        status_2,
        StatusCode::CREATED,
        "second submit (fresh process) must be 201, not 500, got {status_2}: {body_2}"
    );
    let json_2: serde_json::Value =
        serde_json::from_str(&body_2).expect("second response should be JSON");
    let claim_id_2 = json_2["claim_id"]
        .as_str()
        .expect("second response must carry claim_id");

    assert_eq!(
        claim_id_1, claim_id_2,
        "both submits must resolve to the same canonical claim id"
    );

    // Exactly one claim row for (content_hash, agent_id).
    let content_hash = epigraph_crypto::ContentHasher::hash(claim_content.as_bytes());
    let claim_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(content_hash.as_slice())
            .bind(agent_uuid)
            .fetch_one(&pool)
            .await
            .expect("claim count query should succeed");
    assert_eq!(
        claim_count, 1,
        "exactly one claims row for the (content_hash, agent_id) key"
    );

    // No duplicate evidence: the dependent inserts are short-circuited on dedup.
    let canonical_claim_uuid = Uuid::parse_str(claim_id_1).expect("claim_id should parse as uuid");
    let evidence_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
            .bind(canonical_claim_uuid)
            .fetch_one(&pool)
            .await
            .expect("evidence count query should succeed");
    assert_eq!(
        evidence_count, 1,
        "evidence must not be duplicated on the second (dedup) submit"
    );

    // The create path persisted properties (B1).
    let files_changed: Option<String> =
        sqlx::query_scalar("SELECT properties->>'files_changed' FROM claims WHERE id = $1")
            .bind(canonical_claim_uuid)
            .fetch_one(&pool)
            .await
            .expect("properties query should succeed");
    assert_eq!(
        files_changed.as_deref(),
        Some("3"),
        "properties from the create path must be persisted"
    );
}
