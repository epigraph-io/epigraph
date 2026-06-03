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
use epigraph_core::{Agent, ClaimId, TruthValue};
use epigraph_db::{AgentRepository, ClaimRepository, PgPool};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use http_body_util::BodyExt;
use std::sync::Arc;
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

// =============================================================================
// Task 4: dead-node guard (B3) + correct dedup return data (B2).
// =============================================================================

/// Build a submit packet with one document-evidence item and the given
/// `agent_uuid`/`claim_content`. No `idempotency_key`: the in-memory cache
/// (submit.rs:1361) short-circuits before `persist_packet` when a key is
/// present, which would mask the duplicate path under test. Without a key
/// every submit reaches `persist_packet`.
fn evidence_packet(agent_uuid: Uuid, claim_content: &str) -> serde_json::Value {
    let evidence_content = "Empirical data backing the claim under dedup test";
    let evidence_hash = epigraph_crypto::ContentHasher::to_hex(
        &epigraph_crypto::ContentHasher::hash(evidence_content.as_bytes()),
    );
    serde_json::json!({
        "claim": {
            "content": claim_content,
            "initial_truth": 0.5,
            "agent_id": agent_uuid,
            "properties": { "kind": "dedup-test" }
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
    })
}

/// **Task 4 driver — dead-node guard (B3).**
///
/// If the claim for `(content_hash, agent_id)` exists but is no longer current
/// (superseded / marked duplicate), resubmitting the same content must be
/// rejected with **409 Conflict** rather than silently attaching dependent
/// rows to a tombstone or returning the dead node as if it were live.
///
/// `find_by_content_hash_and_agent` (and therefore `create_or_get`) has no
/// `is_current` predicate, so without the guard the duplicate branch returns
/// the tombstone as if current. We supersede with *different* content so the
/// original `(content_hash, agent_id)` row flips to `is_current = false` while
/// its content hash is unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_rejects_tombstone_duplicate_with_409(pool: PgPool) {
    let agent = fixed_agent(43, "tombstone-agent");
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();

    let claim_content = "Claim destined to be superseded then resubmitted";
    let packet = evidence_packet(agent_uuid, claim_content);

    // Create claim C.
    let router = create_test_router(pool.clone());
    let (status_1, body_1) = post_packet(&router, packet.clone()).await;
    assert_eq!(
        status_1,
        StatusCode::CREATED,
        "first submit should be 201, got {status_1}: {body_1}"
    );
    let json_1: serde_json::Value =
        serde_json::from_str(&body_1).expect("first response should be JSON");
    let claim_id_1 = Uuid::parse_str(json_1["claim_id"].as_str().expect("claim_id present"))
        .expect("claim_id should parse as uuid");

    // Supersede C with *different* content → C.is_current = false, content_hash
    // unchanged, so resubmitting the original content re-finds the tombstone.
    ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(claim_id_1),
        "A corrected, different claim that replaces the original",
        TruthValue::new(0.6).expect("valid truth value"),
        "test: retire the original to create a tombstone",
    )
    .await
    .expect("supersede should succeed");

    // Resubmit the original packet → must be 409 (refusing the tombstone).
    let (status_2, body_2) = post_packet(&router, packet).await;
    assert_eq!(
        status_2,
        StatusCode::CONFLICT,
        "resubmitting content whose (content_hash, agent_id) row is a tombstone \
         must be 409, got {status_2}: {body_2}"
    );
    // Pin the 409 to the dead-node guard specifically, not any future 409 on
    // this path: the body must carry the `DuplicateNotCurrent` error code.
    let json_2: serde_json::Value =
        serde_json::from_str(&body_2).expect("409 response should be JSON");
    assert_eq!(
        json_2["error"], "DuplicateNotCurrent",
        "tombstone rejection must carry the DuplicateNotCurrent error code, got {body_2}"
    );
}

/// **Task 4 driver — correct dedup return data (B2).**
///
/// A *normal* dedup (the existing claim is still current) returns 201 with
/// `was_duplicate = true`, the **same canonical `claim_id`**, and an **empty
/// `evidence_ids`** list — the server must not echo phantom evidence ids the
/// caller would then try to embed against non-existent evidence rows.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_dedup_returns_canonical_id_and_empty_evidence(pool: PgPool) {
    let agent = fixed_agent(44, "normal-dedup-agent");
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();

    let claim_content = "Claim submitted twice while remaining current";
    let packet = evidence_packet(agent_uuid, claim_content);

    let router = create_test_router(pool.clone());

    // First submit → create path.
    let (status_1, body_1) = post_packet(&router, packet.clone()).await;
    assert_eq!(
        status_1,
        StatusCode::CREATED,
        "first submit should be 201, got {status_1}: {body_1}"
    );
    let json_1: serde_json::Value =
        serde_json::from_str(&body_1).expect("first response should be JSON");
    assert_eq!(
        json_1["was_duplicate"], false,
        "create path must report was_duplicate=false"
    );
    let claim_id_1 = json_1["claim_id"]
        .as_str()
        .expect("first response must carry claim_id")
        .to_string();
    // The create path inserted a reasoning trace, so the first response carries
    // a concrete trace id we expect the dedup to echo verbatim.
    let trace_id_1 = json_1["trace_id"]
        .as_str()
        .expect("create response must carry a trace_id")
        .to_string();

    // Second submit (same router, no idempotency_key) → reaches persist_packet,
    // finds the still-current claim → dedup path.
    let (status_2, body_2) = post_packet(&router, packet).await;
    assert_eq!(
        status_2,
        StatusCode::CREATED,
        "dedup submit should be 201, got {status_2}: {body_2}"
    );
    let json_2: serde_json::Value =
        serde_json::from_str(&body_2).expect("second response should be JSON");
    assert_eq!(
        json_2["was_duplicate"], true,
        "dedup path must report was_duplicate=true"
    );
    assert_eq!(
        json_2["claim_id"].as_str(),
        Some(claim_id_1.as_str()),
        "dedup must return the same canonical claim id"
    );
    let evidence_ids = json_2["evidence_ids"]
        .as_array()
        .expect("evidence_ids must be an array");
    assert!(
        evidence_ids.is_empty(),
        "dedup must return empty evidence_ids (no phantom ids), got {evidence_ids:?}"
    );
    // B2 (trace dimension): the dedup response's trace_id must equal the
    // existing claim's *actual* trace — never the fresh, never-persisted
    // pre-generated trace id of the second submit. Since the existing claim was
    // created via submit/packet it carries the trace from the first response.
    assert_eq!(
        json_2["trace_id"].as_str(),
        Some(trace_id_1.as_str()),
        "dedup must echo the existing claim's trace, not a phantom id, got {body_2}"
    );
}

/// **B2 regression — dedup onto a NULL-trace claim returns `trace_id: null`,
/// never a phantom id.**
///
/// `submit/packet`'s own create path always inserts a reasoning trace, so the
/// existing dedup test can only exercise the `Some(trace)` branch. But several
/// repo insert paths create claims with `trace_id IS NULL` that share the
/// `(content_hash, agent_id)` key (e.g. `create_with_id_if_absent`, used by
/// workflow-ingest). A same-agent cross-path collision (a NULL-trace claim
/// later resubmitted via submit/packet) drives the dedup branch with
/// `existing.trace_id == None`.
///
/// Before the fix the caller fell back to the pre-generated `trace_id` (a fresh
/// UUID never inserted into `reasoning_traces`), advertising a phantom trace the
/// CLI would then try to operate on. The response's `trace_id` must instead be
/// `null` — faithfully reflecting that the canonical claim has no trace.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_dedup_onto_null_trace_claim_returns_null_trace(pool: PgPool) {
    use epigraph_core::Claim;

    let agent = fixed_agent(45, "null-trace-dedup-agent");
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();
    let agent_id = created_agent.id;

    // Content the packet will carry; the pre-seeded claim must share its
    // `(content_hash, agent_id)` so the submit collapses onto it.
    let claim_content = "A claim first ingested with no reasoning trace";

    // Seed a *current* claim with trace_id = None directly via the repo,
    // mimicking a NULL-trace cross-path insert (e.g. workflow ingest). The
    // content hash is computed inside `create_strict` from the content, so it
    // matches the packet's content hash for the same agent.
    let content_hash = epigraph_crypto::ContentHasher::hash(claim_content.as_bytes());
    let seeded = Claim::with_id(
        ClaimId::new(),
        claim_content.to_string(),
        agent_id,
        [0u8; 32],
        content_hash,
        None, // trace_id IS NULL — the branch under test
        None,
        TruthValue::new(0.5).expect("valid truth value"),
        chrono::Utc::now(),
        chrono::Utc::now(),
    );
    let mut conn = pool.acquire().await.expect("acquire conn");
    let (persisted, created) = ClaimRepository::create_or_get(&mut conn, &seeded)
        .await
        .expect("seeding the null-trace claim should succeed");
    assert!(created, "seed must be a fresh create");
    assert!(
        persisted.trace_id.is_none(),
        "seeded claim must have a NULL trace_id"
    );
    drop(conn);
    let seeded_id = persisted.id.as_uuid().to_string();

    // Resubmit the same content via submit/packet → dedup branch with
    // existing.trace_id == None.
    let router = create_test_router(pool.clone());
    let packet = evidence_packet(agent_uuid, claim_content);
    let (status, body) = post_packet(&router, packet).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "dedup onto a current null-trace claim should be 201, got {status}: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("response should be JSON");
    assert_eq!(
        json["was_duplicate"], true,
        "must report was_duplicate=true (collapsed onto the seeded claim)"
    );
    assert_eq!(
        json["claim_id"].as_str(),
        Some(seeded_id.as_str()),
        "dedup must return the seeded claim's canonical id"
    );
    // The whole point: no phantom trace. The seeded claim has no trace, so the
    // response must report `trace_id: null`, not the second submit's fresh,
    // never-persisted pre-generated trace id.
    assert!(
        json["trace_id"].is_null(),
        "dedup onto a NULL-trace claim must return trace_id: null (no phantom), got {body}"
    );
}

// =============================================================================
// Task 5: caller rewiring — was_duplicate, propagation skip, embedding guards.
// =============================================================================

/// Build a router on `pool` with signature verification bypassed AND a
/// deterministic `MockProvider` embedding service attached. Test (a) below
/// requires a *configured* embedding service: without one the claim-embed
/// block in `submit_packet` short-circuits at `if let Some(ref
/// embedding_service)` and any "did it re-embed?" assertion would pass
/// vacuously — even unfixed.
fn create_test_router_with_embedder(pool: PgPool) -> Router {
    let config = ApiConfig {
        require_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
    };
    let signature_state = SignatureVerificationState::with_bypass_routes(vec!["/".to_string()]);
    let service: Arc<dyn EmbeddingService> =
        Arc::new(MockProvider::new(EmbeddingConfig::local(1536)));
    let state = AppState::with_db_and_signature_state(pool, config, signature_state)
        .with_embedding_service(service);
    create_router(state)
}

/// **Task 5 driver (a) — no re-embed on dedup (B5 / §5 embedding guard).**
///
/// A duplicate submit must NOT re-run the `UPDATE claims SET embedding` for the
/// existing claim: re-embedding a deduped claim is a wasted (paid) embedding
/// call and churns the canonical row for no reason.
///
/// The discriminator is a NULL sentinel, not a value comparison: `MockProvider`
/// is deterministic, so a stray re-embed on the dedup path writes back the
/// *same* vector the create path wrote — "embedding unchanged" would be a false
/// green. Instead we (1) submit (create → embedded), (2) NULL the embedding
/// directly, (3) resubmit (dedup). If the dedup path re-embeds, the column goes
/// non-null again (RED); if it is correctly guarded by `if !was_duplicate`, the
/// column stays NULL (GREEN).
#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_dedup_does_not_re_embed(pool: PgPool) {
    let agent = fixed_agent(46, "no-reembed-agent");
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();

    let claim_content = "A claim that should be embedded once and never re-embedded on dedup";
    let packet = evidence_packet(agent_uuid, claim_content);

    let router = create_test_router_with_embedder(pool.clone());

    // 1. Create path → claim is embedded.
    let (status_1, body_1) = post_packet(&router, packet.clone()).await;
    assert_eq!(
        status_1,
        StatusCode::CREATED,
        "first submit should be 201, got {status_1}: {body_1}"
    );
    let json_1: serde_json::Value =
        serde_json::from_str(&body_1).expect("first response should be JSON");
    let canonical_id = Uuid::parse_str(json_1["claim_id"].as_str().expect("claim_id present"))
        .expect("claim_id should parse as uuid");

    // Proves the embedding service is actually wired (guards the vacuous-pass:
    // if no service were attached this would already be NULL).
    let embedded_after_create: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(canonical_id)
            .fetch_one(&pool)
            .await
            .expect("embedding presence query should succeed");
    assert!(
        embedded_after_create,
        "the create path must embed the claim (else the dedup test is vacuous)"
    );

    // 2. NULL the embedding so a dedup re-embed is detectable as non-null.
    sqlx::query("UPDATE claims SET embedding = NULL WHERE id = $1")
        .bind(canonical_id)
        .execute(&pool)
        .await
        .expect("nulling the embedding should succeed");

    // 3. Dedup path (same router, no idempotency_key) → must NOT re-embed.
    let (status_2, body_2) = post_packet(&router, packet).await;
    assert_eq!(
        status_2,
        StatusCode::CREATED,
        "dedup submit should be 201, got {status_2}: {body_2}"
    );

    let embedded_after_dedup: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(canonical_id)
            .fetch_one(&pool)
            .await
            .expect("embedding presence query should succeed");
    assert!(
        !embedded_after_dedup,
        "the dedup path must NOT re-embed the existing claim — embedding column \
         was NULLed and must stay NULL (was_duplicate embedding guard)"
    );
}

/// **Task 5 driver (b) — response `was_duplicate` reflects create vs dedup.**
///
/// Regression guard: the create response must carry `was_duplicate=false` and
/// the dedup response `was_duplicate=true`. (Wired in Task 3/4; this pins it.)
#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_response_was_duplicate_flag(pool: PgPool) {
    let agent = fixed_agent(47, "was-dup-flag-agent");
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();

    let claim_content = "A claim used to verify the was_duplicate response flag";
    let packet = evidence_packet(agent_uuid, claim_content);

    let router = create_test_router(pool.clone());

    let (status_1, body_1) = post_packet(&router, packet.clone()).await;
    assert_eq!(
        status_1,
        StatusCode::CREATED,
        "first submit should be 201: {body_1}"
    );
    let json_1: serde_json::Value =
        serde_json::from_str(&body_1).expect("first response should be JSON");
    assert_eq!(
        json_1["was_duplicate"], false,
        "create path must report was_duplicate=false"
    );

    let (status_2, body_2) = post_packet(&router, packet).await;
    assert_eq!(
        status_2,
        StatusCode::CREATED,
        "dedup submit should be 201: {body_2}"
    );
    let json_2: serde_json::Value =
        serde_json::from_str(&body_2).expect("second response should be JSON");
    assert_eq!(
        json_2["was_duplicate"], true,
        "dedup path must report was_duplicate=true"
    );
}

/// **Task 5 driver (c) — idempotency cache keys on the canonical id.**
///
/// After a dedup, a *third* same-process submit carrying the same
/// `idempotency_key` must return the canonical claim id from the in-memory
/// cache — proving the cache write (submit.rs:1850) stores the canonical id,
/// not a stale pre-generated one.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_idempotency_cache_holds_canonical_id(pool: PgPool) {
    let agent = fixed_agent(48, "cache-canonical-agent");
    let created_agent = AgentRepository::create(&pool, &agent)
        .await
        .expect("agent creation should succeed");
    let agent_uuid: Uuid = created_agent.id.into();

    // Carry an idempotency_key so the in-memory cache participates.
    let claim_content = "A claim used to verify the idempotency cache canonical id";
    let mut packet = evidence_packet(agent_uuid, claim_content);
    packet["claim"]["idempotency_key"] = serde_json::json!("idem-task5-cache-key");

    // Use a *fresh* router for the create submit and a *second fresh* router for
    // the dedup submit (each with an empty cache, so both reach persist_packet),
    // then a third submit on the second router (cache now warm) to exercise the
    // cache-hit path that must return the canonical id.
    let router_a = create_test_router(pool.clone());
    let (status_1, body_1) = post_packet(&router_a, packet.clone()).await;
    assert_eq!(
        status_1,
        StatusCode::CREATED,
        "first submit should be 201: {body_1}"
    );
    let json_1: serde_json::Value =
        serde_json::from_str(&body_1).expect("first response should be JSON");
    let canonical_id = json_1["claim_id"]
        .as_str()
        .expect("first response must carry claim_id")
        .to_string();

    let router_b = create_test_router(pool.clone());
    let (status_2, body_2) = post_packet(&router_b, packet.clone()).await;
    assert_eq!(
        status_2,
        StatusCode::CREATED,
        "dedup submit should be 201: {body_2}"
    );
    let json_2: serde_json::Value =
        serde_json::from_str(&body_2).expect("second response should be JSON");
    assert_eq!(
        json_2["claim_id"].as_str(),
        Some(canonical_id.as_str()),
        "dedup must resolve to the canonical claim id"
    );

    // Third submit on router_b: now served from its in-memory cache (cache-hit
    // path). It must echo the canonical id stored on the previous (dedup) write.
    let (status_3, body_3) = post_packet(&router_b, packet).await;
    assert_eq!(
        status_3,
        StatusCode::CREATED,
        "cache-hit submit should be 201: {body_3}"
    );
    let json_3: serde_json::Value =
        serde_json::from_str(&body_3).expect("third response should be JSON");
    assert_eq!(
        json_3["claim_id"].as_str(),
        Some(canonical_id.as_str()),
        "the idempotency cache must hold the canonical claim id"
    );
    assert_eq!(
        json_3["was_duplicate"], true,
        "a cache-hit must report was_duplicate=true"
    );
}
