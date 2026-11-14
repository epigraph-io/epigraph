//! `POST /api/v1/voids/detect` (`routes/voids.rs::detect_voids`): F-PR29-A1
//! (backlog efe82380).
//!
//! * an oversized request is `400` before anything runs;
//! * the footprint probe below records the scoped pool's state at each
//!   embedder call, and the handler's result must still be served from the
//!   stamped connection (the viewer's own group-private claim covers its
//!   concept).
#![cfg(feature = "db")]

mod search_fixture;
mod viewer_fixture;

use async_trait::async_trait;
use axum::extract::State;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::voids::{detect_voids, DetectVoidsRequest, MAX_VOID_CONCEPTS};
use epigraph_embeddings::{EmbeddingError, EmbeddingService, MockProvider, TokenUsage};
use search_fixture::*;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use viewer_fixture::{seed_agent_with_group, seed_group_claim};

/// The shared mock, plus the footprint probe's record.
struct OccupancyProbe {
    inner: Arc<MockProvider>,
    pool: PgPool,
    in_use_at_embed: Mutex<Vec<u32>>,
}

impl OccupancyProbe {
    fn record(&self) {
        let in_use = self.pool.size() - u32::try_from(self.pool.num_idle()).unwrap_or(u32::MAX);
        self.in_use_at_embed.lock().unwrap().push(in_use);
    }
}

#[async_trait]
impl EmbeddingService for OccupancyProbe {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.record();
        self.inner.generate(text).await
    }
    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        self.record();
        self.inner.batch_generate(texts).await
    }
    fn dimension(&self) -> usize {
        self.inner.dimension()
    }
    fn token_usage(&self) -> TokenUsage {
        self.inner.token_usage()
    }
    fn reset_token_usage(&self) {
        self.inner.reset_token_usage();
    }
    async fn health_check(&self) -> Result<(), EmbeddingError> {
        self.inner.health_check().await
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_oversized_request_is_refused_before_anything_runs(pool: PgPool) {
    let (agent, _) = seed_agent_with_group(&pool, "efe8-cap").await;
    // No embedding service at all: a handler that reached it would answer 500,
    // so a 400 here proves the cap is checked first.
    let state = split_state(&pool).await;
    let res = detect_voids(
        ViewerExtractor(viewer_for(&pool, agent).await),
        State(state),
        axum::Json(DetectVoidsRequest {
            concepts: vec!["c".to_string(); MAX_VOID_CONCEPTS + 1],
            threshold: None,
        }),
    )
    .await;
    match res {
        Err(ApiError::ValidationError { field, .. }) => assert_eq!(field, "concepts"),
        other => panic!("over the cap must be 400 on `concepts`, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn detect_voids_meets_the_f_pr29_a1_footprint(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "efe8-hold").await;
    let embedder = mock_embedder();
    let concepts = [
        "efe8 first concept",
        "efe8 second concept",
        "efe8 third concept",
    ];
    let vec = probe(&embedder, concepts[0]).await;
    let mine = seed_group_claim(&pool, agent, group, "efe8: my claim").await;
    set_embedding(&pool, mine, &vec).await;

    let state = split_state(&pool).await;
    let scoped_inner = state.scoped.as_ref().expect("scoped").inner().clone();
    let probe_svc = Arc::new(OccupancyProbe {
        inner: embedder,
        pool: scoped_inner,
        in_use_at_embed: Mutex::new(Vec::new()),
    });
    let state = state.with_embedding_service(probe_svc.clone());

    let out = detect_voids(
        ViewerExtractor(viewer_for(&pool, agent).await),
        State(state),
        axum::Json(DetectVoidsRequest {
            concepts: concepts.iter().map(|c| (*c).to_string()).collect(),
            threshold: None,
        }),
    )
    .await
    .expect("detect_voids serves")
    .0;

    let seen = probe_svc.in_use_at_embed.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        concepts.len(),
        "CALIBRATION: every concept was embedded through the probe: {seen:?}"
    );
    assert!(
        seen.iter().all(|n| *n == 0),
        "F-PR29-A1 footprint probe: {seen:?}"
    );
    let first_covered = out["covered_concepts"]
        .as_array()
        .expect("covered_concepts is an array")
        .iter()
        .any(|c| c["concept"] == concepts[0] && c["nearest_claim"] == "efe8: my claim");
    assert!(
        first_covered,
        "the reads still run on the stamped connection: the viewer's own \
         group-private claim covers the first concept; got {out}"
    );
}
