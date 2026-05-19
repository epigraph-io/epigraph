//! POST /api/v1/submit/packet must NOT embed claims whose
//! `properties.event` marks them as host-provenance telemetry from
//! `epiclaw-host`. Embedding sentence-shaped operational events like
//! "Container X exited code 0 after Yms" has no semantic value and costs an
//! OpenAI call per event; the host signs them only for tamper-evidence on
//! container lifecycle.
//!
//! Regression guard: removing the skip-check in `submit.rs` would resume
//! ~thousands of wasted embedding calls per day from the epiclaw orchestrator.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::{create_router, state::AppState, ApiConfig};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

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
        .expect("issue_access_token");
    token
}

async fn submit_packet_with_properties(
    pool: PgPool,
    content: &str,
    properties: Option<serde_json::Value>,
) -> Uuid {
    let provider = MockProvider::new(EmbeddingConfig::local(1536));
    let service: Arc<dyn EmbeddingService> = Arc::new(provider);
    let state = AppState::with_db(pool.clone(), ApiConfig::default())
        .with_embedding_service(service.clone());
    let app = create_router(state);

    let agent_id = Uuid::new_v4();
    // Public key must be unique across agents — derive from the UUID so each
    // call to this helper inserts a distinct row.
    let mut public_key = [0u8; 32];
    public_key[..16].copy_from_slice(agent_id.as_bytes());
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind(public_key.as_slice())
        .execute(&pool)
        .await
        .unwrap();

    let evidence_content = "host observation";
    let evidence_hash = epigraph_crypto::ContentHasher::to_hex(
        &epigraph_crypto::ContentHasher::hash(evidence_content.as_bytes()),
    );

    let mut claim = json!({
        "content": content,
        "initial_truth": 0.99,
        "agent_id": agent_id,
    });
    if let Some(p) = properties {
        claim["properties"] = p;
    }

    let body = json!({
        "claim": claim,
        "evidence": [{
            "content_hash": evidence_hash,
            "evidence_type": {
                "type": "observation",
                "observed_at": chrono::Utc::now(),
                "method": "test",
                "location": null
            },
            "raw_content": evidence_content,
            "signature": null
        }],
        "reasoning_trace": {
            "methodology": "deductive",
            "inputs": [{"type": "evidence", "index": 0}],
            "confidence": 0.99,
            "explanation": "test",
            "signature": null
        },
        "signature": "0".repeat(128)
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/submit/packet")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", test_bearer_token()),
        )
        .body(Body::from(body.to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "submit_packet should succeed; body: {}",
        String::from_utf8_lossy(&bytes)
    );

    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["claim_id"].as_str().unwrap().parse().unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_skips_embedding_for_container_exited(pool: PgPool) {
    let claim_id = submit_packet_with_properties(
        pool.clone(),
        "Container epiclaw-sched-foo exited code 0 after 12345ms",
        Some(json!({
            "event": "container_exited",
            "exit_code": 0,
            "duration_ms": 12345_i64
        })),
    )
    .await;

    let has_embedding: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        !has_embedding,
        "claim {claim_id} is host-provenance telemetry (event=container_exited); \
         embedding should be SKIPPED but column is populated"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_skips_embedding_for_all_known_telemetry_events(pool: PgPool) {
    for event in [
        "container_spawned",
        "container_exited",
        "agent_output",
        "task_scheduled",
        "task_executed",
        "message_received",
        "message_sent",
    ] {
        let claim_id = submit_packet_with_properties(
            pool.clone(),
            &format!("telemetry: {event}"),
            Some(json!({"event": event})),
        )
        .await;

        let has_embedding: bool =
            sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
                .bind(claim_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert!(
            !has_embedding,
            "claim with properties.event = {event:?} should not be embedded \
             (host-telemetry skip)"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_still_embeds_non_telemetry_claims(pool: PgPool) {
    // No properties.event → embed as normal. This guards against an overly
    // broad skip rule that would silently drop embeddings for ordinary claims.
    let claim_id = submit_packet_with_properties(
        pool.clone(),
        "An ordinary knowledge claim that should be embedded",
        None,
    )
    .await;

    let has_embedding: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(
        has_embedding,
        "ordinary claim {claim_id} (no properties.event) should be embedded"
    );

    // Unknown event values should NOT trigger the skip — keeps the filter
    // tight to the known epiclaw-host emitters.
    let claim_id_unknown = submit_packet_with_properties(
        pool.clone(),
        "Claim with unknown event marker",
        Some(json!({"event": "something_else_entirely"})),
    )
    .await;

    let has_embedding_unknown: bool = sqlx::query_scalar(
        "SELECT embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(claim_id_unknown)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(
        has_embedding_unknown,
        "claim with unknown properties.event value should still be embedded"
    );
}
