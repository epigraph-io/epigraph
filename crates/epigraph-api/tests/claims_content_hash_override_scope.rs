#![cfg(feature = "db")]
//! SCOPE GUARD on `claims.canonical_hash` for the client-supplied
//! `content_hash` override (`POST /api/v1/claims`). Backlog e09986c2.
//!
//! `canonical_hash` (migration 061) is the canonicalization-tolerant TWIN of
//! `content_hash`: it exists so a resubmission that renders identically finds
//! the stored row through `create_or_get`'s stage-2 lookup. That relationship
//! only holds while `content_hash` IS the plain BLAKE3 of `content`.
//!
//! `POST /api/v1/claims` lets a caller REPLACE the digest
//! (`UPDATE claims SET content_hash = COALESCE($1, content_hash)`), which is
//! how a row takes a foreign or namespaced identity — the ingest spine's
//! document-scoped hash, or a `fully_private` claim whose stored `content` is
//! the literal placeholder `"[private]"` and whose real digest is supplied by
//! the client. Leaving `canonical_hash` set to the digest of the *stored* text
//! drags every such row back into the plain-text lookup dimension it
//! deliberately left: the override changes the row's identity, so the twin
//! computed from the old identity must go.
//!
//! Before the canonical column existed, an overridden row was reachable only by
//! its overridden `content_hash`. This pins that back.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::{create_router, state::AppState, ApiConfig};
use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_crypto::ContentHasher;
use epigraph_db::ClaimRepository;
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Bearer token valid against the dev JWT secret used by `default_jwt_config()`
/// when `EPIGRAPH_JWT_SECRET` is unset — same pattern as
/// `integration/embed_on_create_claim.rs`.
fn test_bearer_token() -> String {
    use epigraph_api::oauth::JwtConfig;
    let jwt_config = JwtConfig::from_secret(b"epigraph-dev-secret-change-in-production!!");
    let (token, _) = jwt_config
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:write".to_string(), "epigraph:write".to_string()],
            "service",
            None,
            None,
            chrono::Duration::seconds(300),
        )
        .expect("issue_access_token must succeed for tests");
    token
}

fn test_app(pool: &PgPool) -> axum::Router {
    let provider = MockProvider::new(EmbeddingConfig::local(1536));
    let service: Arc<dyn EmbeddingService> = Arc::new(provider);
    let state =
        AppState::with_db(pool.clone(), ApiConfig::default()).with_embedding_service(service);
    create_router(state)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind(Uuid::new_v4().as_bytes().repeat(2).as_slice())
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

async fn post_claim(app: &axum::Router, body: serde_json::Value) -> (StatusCode, String) {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/claims")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", test_bearer_token()),
        )
        .body(Body::from(body.to_string()))
        .expect("build request");
    let response = app.clone().oneshot(request).await.expect("execute request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect body");
    (
        status,
        String::from_utf8(bytes.to_vec()).expect("utf8 body"),
    )
}

/// REGRESSION. A claim created with a `content_hash` OVERRIDE must not keep a
/// `canonical_hash` derived from its stored text.
///
/// The override is what gives the row an identity other than "the plain digest
/// of this text". A `canonical_hash` over the text alone contradicts that and
/// makes the row reachable by plain text through `create_or_get`'s stage 2 —
/// which is exactly the lookup the override opted out of.
#[sqlx::test(migrations = "../../migrations")]
async fn content_hash_override_clears_the_canonical_twin(pool: PgPool) {
    let app = test_app(&pool);
    let agent_id = seed_agent(&pool).await;

    let content = "Overridden-digest claim whose text must not be a lookup key";
    // A digest that is NOT blake3(content) — stands in for any namespaced or
    // client-computed identity (ingest spine seed, encrypted-payload digest).
    let foreign_hash = ContentHasher::hash(b"some other identity entirely");
    let foreign_hex = ContentHasher::to_hex(&foreign_hash);

    let (status, body) = post_claim(
        &app,
        json!({
            "agent_id": agent_id,
            "content": content,
            "privacy_tier": "public",
            "initial_truth": 0.5,
            "content_hash": foreign_hex,
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "create with content_hash override should succeed; got {status}: {body}"
    );
    let claim_id = Uuid::parse_str(
        serde_json::from_str::<serde_json::Value>(&body).expect("json")["id"]
            .as_str()
            .expect("id present in response"),
    )
    .expect("id parses as uuid");

    let (stored_hash, canonical): (Vec<u8>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT content_hash, canonical_hash FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("read digests back");

    assert_eq!(
        stored_hash,
        foreign_hash.to_vec(),
        "fixture: the override must actually have taken effect"
    );
    assert_eq!(
        canonical, None,
        "a row whose content_hash was overridden away from the plain digest of \
         its text must not advertise a canonical_hash over that text"
    );

    // The consequence that matters: a plain submission of the same text must
    // start its own row rather than being resolved onto the overridden one.
    let mut conn = pool.acquire().await.expect("acquire");
    let plain = Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    );
    let (found, created) = ClaimRepository::create_or_get(&mut conn, &plain)
        .await
        .expect("create_or_get plain");
    assert!(
        created,
        "a plain submission must not be resolved onto a row that overrode its \
         digest — it resolved onto {}",
        Uuid::from(found.id)
    );
    assert_ne!(Uuid::from(found.id), claim_id);
}

/// The complement: WITHOUT an override the canonical twin must still be
/// written. The guard narrows the overridden case only; it must not switch the
/// dedup feature off for the ordinary create path.
#[sqlx::test(migrations = "../../migrations")]
async fn create_without_override_still_writes_the_canonical_twin(pool: PgPool) {
    let app = test_app(&pool);
    let agent_id = seed_agent(&pool).await;

    // Non-canonical text so the two digests are provably different.
    let content = "Ordinary  claim with a doubled space.\n";
    let (status, body) = post_claim(
        &app,
        json!({
            "agent_id": agent_id,
            "content": content,
            "privacy_tier": "public",
            "initial_truth": 0.5,
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "ordinary create should succeed; got {status}: {body}"
    );
    let claim_id = Uuid::parse_str(
        serde_json::from_str::<serde_json::Value>(&body).expect("json")["id"]
            .as_str()
            .expect("id present in response"),
    )
    .expect("id parses as uuid");

    let (stored_hash, canonical): (Vec<u8>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT content_hash, canonical_hash FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("read digests back");

    assert_eq!(
        stored_hash,
        ContentHasher::hash(content.as_bytes()).to_vec(),
        "content_hash must stay raw BLAKE3 over the submitted bytes"
    );
    assert_eq!(
        canonical,
        Some(ContentHasher::hash_canonical_text(content).to_vec()),
        "the ordinary create path must still write the canonical twin"
    );
}
