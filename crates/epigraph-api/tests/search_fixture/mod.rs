//! Shared fixture for the `POST /api/v1/search/semantic` handler tests.
//!
//! These helpers lived file-local in `search_voids_methods_scoped_read.rs`.
//! `search_theme_filter.rs` needs the same instrument, and a second hand-kept
//! copy is the drift `F-PR28-viewer-fixture-duplication` warns about, so they
//! live here once. The directory form (`search_fixture/mod.rs`) keeps cargo
//! from compiling this file as a test crate of its own.
//!
//! A test file declares both modules and imports this one:
//!
//! ```ignore
//! mod viewer_fixture;
//! mod search_fixture;
//! use search_fixture::*;
//! ```
//!
//! See `search_voids_methods_scoped_read.rs`'s module docs for why
//! [`split_state`] is built the way it is (the authority trap).

#![allow(dead_code)]

use crate::viewer_fixture::{downgraded_pool, scoped_pool};
use axum::extract::State;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::search::{
    semantic_search, SemanticSearchRequest, SemanticSearchResponse,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

/// The dimension every seeded vector and every mock embedding uses.
///
/// It must equal `routes/search.rs::EMBEDDING_DIM` and the `claims.embedding`
/// column width, or `generate_query_embedding` silently discards the configured
/// service and falls back to its private deterministic mock — which the test
/// cannot call, so every seeded vector would be uncorrelated with the probe and
/// the arms would pass or fail for reasons unrelated to tenancy.
pub const DIM: usize = 1536;

// ── The instrument ──

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped.
///
/// The asymmetry is the instrument: a converted site reads through `scoped` and
/// works; the same site reverted to `&state.db_pool` reads through a session the
/// RLS policies filter, with no `epigraph.group_ids` to admit the viewer's own
/// group, and loses the rows.
pub async fn split_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let scoped = scoped_pool(pool).await;

    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);

    // CALIBRATION: the two arms must really be different sessions, or every
    // assertion below is about one pool wearing two names.
    assert!(
        state.scoped.is_some(),
        "CALIBRATION: AppState.scoped must be populated, or read_as refuses and \
         the handler cannot serve at all"
    );
    let raw_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&state.db_pool)
        .await
        .expect("current_user on the raw pool");
    assert_eq!(
        raw_user, "epigraph_app",
        "CALIBRATION: AppState.db_pool must be DOWNGRADED, or reverting a converted \
         site to it is invisible and the mutation proof is vacuous"
    );
    let scoped_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(state.scoped.as_ref().expect("scoped").inner())
        .await
        .expect("current_user on the scoped pool");
    assert_ne!(
        scoped_user, raw_user,
        "CALIBRATION: the scoped and raw arms must not be the same session — that \
         sameness is exactly what makes with_scoped_pool useless as a conversion fixture"
    );

    state
}

/// A deterministic 1536d embedding service, and the same provider the test can
/// query itself.
///
/// Both `voids.rs` handlers return `InternalError` at
/// `state.embedding_service()` BEFORE any SQL runs, so without this they are
/// untestable. `search.rs` does not require one, but gets it anyway: with a
/// service whose `dimension()` matches the target dim, `generate_query_embedding`
/// takes the service branch, so the test can compute the EXACT probe vector the
/// handler will use and seed a claim at cosine similarity ~1.0.
///
/// `MockProvider` does not override `EmbeddingService::generate_query`, whose
/// default delegates to `generate`, so the vector this returns for a string is
/// the one both handlers compute for it.
pub fn mock_embedder() -> Arc<MockProvider> {
    Arc::new(MockProvider::new(EmbeddingConfig::openai(DIM)))
}

pub async fn split_state_with_embedder(pool: &PgPool, embedder: Arc<MockProvider>) -> AppState {
    split_state(pool).await.with_embedding_service(embedder)
}

pub fn pgvec(v: &[f32]) -> String {
    format!(
        "[{}]",
        v.iter().map(f32::to_string).collect::<Vec<_>>().join(",")
    )
}

/// The exact vector the handlers will compute for `text`.
pub async fn probe(embedder: &Arc<MockProvider>, text: &str) -> String {
    pgvec(&embedder.generate(text).await.expect("mock embed"))
}

// ── Seeding ──

/// Give a seeded claim an `embedding`, so the vector-ranked reads can find it.
pub async fn set_embedding(pool: &PgPool, claim: Uuid, vec: &str) {
    crate::viewer_fixture::set_claim_embedding(pool, claim, vec).await;
}

/// A `claim_themes` row with a 1536d centroid, and the claims attached to it.
pub async fn seed_theme(pool: &PgPool, label: &str, centroid: &str) -> Uuid {
    let theme: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, $2) RETURNING id",
    )
    .bind(label)
    .bind("PR-29 scoped-read fixture theme")
    .fetch_one(pool)
    .await
    .expect("insert theme");

    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(theme)
        .bind(centroid)
        .execute(pool)
        .await
        .expect("set centroid");
    theme
}

pub async fn attach_theme(pool: &PgPool, claim: Uuid, theme: Uuid) {
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("attach theme");
}

/// Resolved on the SUPERUSER pool, never the downgraded one: `Viewer::resolve`
/// reads `group_memberships`, and on a filtered unstamped session it resolves to
/// an EMPTY group set — which would satisfy every "a stranger is absent"
/// assertion for entirely the wrong reason.
pub async fn viewer_for(pool: &PgPool, agent: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
}

pub fn search_request(query: &str, diverse: bool) -> SemanticSearchRequest {
    SemanticSearchRequest {
        query: query.to_string(),
        limit: Some(20),
        min_similarity: None,
        claim_type: None,
        created_after: None,
        created_before: None,
        agent_id: None,
        diverse: Some(diverse),
        max_themes: Some(5),
        diversity_weight: Some(0.5),
        centroid_dim: None,
        candidate_pool: None,
        theme_id: None,
        rank_by: None,
        cursor: None,
    }
}

pub async fn search(
    pool: &PgPool,
    state: AppState,
    agent: Uuid,
    request: SemanticSearchRequest,
) -> Result<SemanticSearchResponse, ApiError> {
    let viewer = viewer_for(pool, agent).await;
    semantic_search(ViewerExtractor(viewer), State(state), axum::Json(request))
        .await
        .map(|j| j.0)
}

pub fn hit_ids(r: &SemanticSearchResponse) -> Vec<Uuid> {
    r.results.iter().map(|h| h.claim_id).collect()
}
