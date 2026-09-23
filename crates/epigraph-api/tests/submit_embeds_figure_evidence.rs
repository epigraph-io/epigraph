#![cfg(feature = "db")]
//! POST /api/v1/submit/packet embeds FIGURE evidence inline, best-effort.
//!
//! The claim half of `submit_packet`'s write-on-create embedding already has
//! a witness (`integration/skip_embed_host_telemetry.rs::submit_packet_still_embeds_non_telemetry_claims`).
//! The figure-evidence half had none. It moved from an inline
//! `UPDATE evidence SET embedding` onto `EvidenceRepository::store_embedding_vec`
//! (deferred-commitment key `embed-on-write-helper`), and a move with no test
//! behind it is the kind that silently stops embedding. The non-figure
//! evidence row in the same packet is the negative control: only figures are
//! embedded on this path.

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

fn bearer_token(principal: Uuid) -> String {
    use epigraph_api::oauth::JwtConfig;
    let jwt_config = JwtConfig::from_secret(b"epigraph-dev-secret-change-in-production!!");
    let (token, _) = jwt_config
        .issue_access_token(
            principal,
            vec!["claims:write".to_string(), "epigraph:write".to_string()],
            "service",
            Some(principal),
            Some(principal),
            chrono::Duration::seconds(300),
        )
        .expect("issue_access_token");
    token
}

fn hex_hash(s: &str) -> String {
    epigraph_crypto::ContentHasher::to_hex(&epigraph_crypto::ContentHasher::hash(s.as_bytes()))
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_embeds_figure_evidence_and_only_figure_evidence(pool: PgPool) {
    let provider = MockProvider::new(EmbeddingConfig::local(1536));
    let service: Arc<dyn EmbeddingService> = Arc::new(provider);
    let state =
        AppState::with_db(pool.clone(), ApiConfig::default()).with_embedding_service(service);
    let app = create_router(state);

    let agent_id = Uuid::new_v4();
    let mut public_key = [0u8; 32];
    public_key[..16].copy_from_slice(agent_id.as_bytes());
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind(public_key.as_slice())
        .execute(&pool)
        .await
        .unwrap();

    let figure_body = "figure 3: dose-response curve";
    let observation_body = "bench observation";
    let body = json!({
        "claim": {
            "content": "a claim supported by a figure and an observation",
            "initial_truth": 0.9,
            "agent_id": agent_id,
        },
        "evidence": [
            {
                "content_hash": hex_hash(figure_body),
                "evidence_type": {
                    "type": "figure",
                    "doi": "10.1000/figure-embed-test",
                    "figure_id": "3",
                    "caption": "dose-response curve",
                    "mime_type": "image/png",
                    "page": null
                },
                "raw_content": figure_body,
                "signature": null
            },
            {
                "content_hash": hex_hash(observation_body),
                "evidence_type": {
                    "type": "observation",
                    "observed_at": chrono::Utc::now(),
                    "method": "test",
                    "location": null
                },
                "raw_content": observation_body,
                "signature": null
            }
        ],
        "reasoning_trace": {
            "methodology": "deductive",
            "inputs": [{"type": "evidence", "index": 0}, {"type": "evidence", "index": 1}],
            "confidence": 0.9,
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
            format!("Bearer {}", bearer_token(agent_id)),
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
    let claim_id: Uuid = v["claim_id"].as_str().unwrap().parse().unwrap();

    let rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT evidence_type, embedding IS NOT NULL FROM evidence \
          WHERE claim_id = $1 ORDER BY evidence_type",
    )
    .bind(claim_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(
        rows.len(),
        2,
        "the packet's two evidence rows must both exist: {rows:?}"
    );
    for (evidence_type, embedded) in &rows {
        if evidence_type == "figure" {
            assert!(
                *embedded,
                "figure evidence must be embedded on submit (caption fallback \
                 with a text-only provider): {rows:?}"
            );
        } else {
            assert!(
                !*embedded,
                "only figure evidence is embedded on this path; a \
                 {evidence_type} row got a vector: {rows:?}"
            );
        }
    }
    assert!(
        rows.iter().any(|(t, _)| t == "figure"),
        "the figure row must be stored as evidence_type 'figure' for this test \
         to mean anything: {rows:?}"
    );
}
