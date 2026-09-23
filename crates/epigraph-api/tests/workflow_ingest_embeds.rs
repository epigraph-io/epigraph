#![cfg(feature = "db")]
//! POST /api/v1/workflows/ingest embeds every claim the executor inserted.
//!
//! CLAUDE.md lists this route as a write path that must embed on insert. Its
//! embedding loop moved from an inline `UPDATE claims SET embedding` onto
//! `ClaimRepository::store_embedding_vec` (deferred-commitment key
//! `embed-on-write-helper`). Until now the route had an ingest test that
//! checked the response and nothing about the vectors. This test pins the
//! write-on-create property itself, with a non-emptiness check so that it
//! cannot pass over an ingest that inserted nothing.

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::{create_router, state::AppState, ApiConfig};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn bearer_token(principal: Uuid) -> String {
    use epigraph_api::oauth::JwtConfig;
    let jwt_config = JwtConfig::from_secret(b"epigraph-dev-secret-change-in-production!!");
    let (token, _) = jwt_config
        .issue_access_token(
            principal,
            vec![
                "claims:read".to_string(),
                "claims:write".to_string(),
                "edges:write".to_string(),
                "workflows:read".to_string(),
                "workflows:write".to_string(),
            ],
            "service",
            Some(principal),
            Some(principal),
            chrono::Duration::seconds(300),
        )
        .expect("issue_access_token");
    token
}

async fn claim_ids(pool: &PgPool) -> HashSet<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM claims")
        .fetch_all(pool)
        .await
        .expect("list claim ids")
        .into_iter()
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn workflow_ingest_embeds_every_inserted_claim(pool: PgPool) {
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

    let before = claim_ids(&pool).await;

    let body = serde_json::json!({
        "source": {
            "canonical_name": "embed-on-write-helper-ingest",
            "goal": "Ingest a workflow and embed each claim it creates",
            "generation": 0,
            "authors": []
        },
        "thesis": "Every claim a workflow ingest inserts carries a vector",
        "thesis_derivation": "TopDown",
        "phases": [{
            "title": "Phase One",
            "summary": "Single test phase",
            "steps": [{
                "compound": "Run the workflow ingest route",
                "rationale": "Exercise the write-on-create embed loop",
                "operations": ["POST /api/v1/workflows/ingest"],
                "generality": [1],
                "confidence": 0.85
            }]
        }],
        "relationships": []
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/workflows/ingest")
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
        StatusCode::OK,
        "workflow ingest should succeed; body: {}",
        String::from_utf8_lossy(&bytes)
    );

    let inserted: Vec<Uuid> = claim_ids(&pool)
        .await
        .difference(&before)
        .copied()
        .collect();
    assert!(
        inserted.len() >= 3,
        "the ingest must have inserted the thesis, phase and step claims at \
         least; found {} new claims",
        inserted.len()
    );

    let missing: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM claims WHERE id = ANY($1) AND is_current AND embedding IS NULL",
    )
    .bind(&inserted)
    .fetch_all(&pool)
    .await
    .expect("read inserted claims' vectors");
    assert!(
        missing.is_empty(),
        "{} of {} claims inserted by workflow ingest have no embedding: {missing:?}",
        missing.len(),
        inserted.len()
    );
}
