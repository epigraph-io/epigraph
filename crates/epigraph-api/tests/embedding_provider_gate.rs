#![cfg(feature = "db")]
//! Only the provider that owns `claims.embedding` may store vectors from a
//! request-serving write path (backlog 211bd623).
//!
//! `embedding_service_from_env` falls through OpenAI, Jina and a mock and
//! returns which one it selected, so that a writer can refuse a provider whose
//! vectors do not belong in the stored column. Only the `embedding_generation`
//! job handler was told. `bin/server.rs` discarded the kind, so an API process
//! with no `OPENAI_API_KEY` wrote mock (or Jina-space) vectors into
//! `claims.embedding` from every inline write path.
//!
//! The rule now lives on `AppState`: a write path asks
//! `storing_embedding_service`, and `store_claim_embedding_as` refuses as a
//! backstop. A state with NO declared provider (every test-built state, and an
//! embedder that wires its own service) behaves as before.

use epigraph_api::embedding_restore::EmbeddingProviderKind;
use epigraph_api::{ApiConfig, AppState};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use std::sync::Arc;

fn with_mock_service(pool: sqlx::PgPool) -> AppState {
    let service: Arc<dyn EmbeddingService> =
        Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    AppState::with_db(pool, ApiConfig::default()).with_embedding_service(service)
}

/// A state over a pool that is never connected to: the accessors under test
/// read fields only.
fn state() -> AppState {
    with_mock_service(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool construction does not connect"),
    )
}

#[tokio::test]
async fn an_undeclared_provider_stores_as_before() {
    let state = state();
    assert!(state.may_store_embeddings());
    assert!(state.storing_embedding_service().is_some());
}

#[tokio::test]
async fn the_owning_provider_stores() {
    let state = state().with_embedding_provider(EmbeddingProviderKind::OpenAi);
    assert!(state.may_store_embeddings());
    assert!(state.storing_embedding_service().is_some());
}

/// Mock and Jina both keep serving QUERY embedding and both stop STORING:
/// "is not a mock" is not the rule, "owns the column" is.
#[tokio::test]
async fn a_non_owning_provider_serves_queries_and_stores_nothing() {
    for provider in [EmbeddingProviderKind::Mock, EmbeddingProviderKind::Jina] {
        let state = state().with_embedding_provider(provider);
        assert!(
            state.embedding_service().is_some(),
            "{provider:?}: query embedding must stay available"
        );
        assert!(
            !state.may_store_embeddings(),
            "{provider:?} does not own claims.embedding"
        );
        assert!(
            state.storing_embedding_service().is_none(),
            "{provider:?}: a write path must be given no embedder, so it neither generates \
             nor stores a vector"
        );
    }
}

/// The backstop behind the accessor: a store helper refuses a non-owning
/// provider's vector whatever its caller generated it with, and leaves the row
/// untouched.
#[sqlx::test(migrations = "../../migrations")]
async fn the_store_helper_refuses_a_non_owning_providers_vector(pool: sqlx::PgPool) {
    let agent: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) \
         VALUES (sha256('provider-gate'::bytea), 'provider-gate') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("agent");
    let claim: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, is_current) \
         VALUES ('provider gate claim', sha256('provider gate claim'::bytea), $1, 0.5, true) \
         RETURNING id",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("claim");
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
        .await
        .expect("public viewer");
    let pgvec = format!("[{}]", vec!["0.01"; 1536].join(","));

    let state =
        with_mock_service(pool.clone()).with_embedding_provider(EmbeddingProviderKind::Mock);
    let refused = state
        .store_claim_embedding_as(&viewer, claim, &pgvec, "test")
        .await
        .expect_err("a mock provider's vector must not be stored");
    assert!(
        refused.contains("does not own the stored vector columns"),
        "{refused}"
    );
    let has_embedding: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("claim row");
    assert!(!has_embedding, "the refused store wrote nothing");
}
