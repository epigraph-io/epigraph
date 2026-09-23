//! `reembed` must never select or write a retired claim (`is_current = false`).
//!
//! # Why this is worth a test of its own
//!
//! Before the `is_current` predicate existed the selection was
//! `embedding_3072 IS NULL AND NOT sealed`, and every retirement path nulls the
//! vector columns, so every superseded, duplicate, deprecated and consolidated
//! claim matched. A run wrote a 3072-d vector onto each of them, and recall and
//! theme k-means at `centroid_dim = 3072` then surfaced them as live. Migration
//! 101 now forbids that state with a CHECK, so without the predicate the run is
//! not merely leaky: it aborts on the first retired row it reaches.
//!
//! # The mid-run case is the one a selection filter cannot cover
//!
//! The provider call sits between `fetch_batch` and the per-row UPDATE, and it
//! is the slow part of every batch. A claim retired inside that window was
//! current when it was selected. The second test retires one from inside the
//! provider call, which puts the interleaving at a deterministic point instead
//! of racing two connections, and requires the run to skip the row and succeed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::reembed::{run, ReembedConfig, ReembedTarget};
use epigraph_embeddings::{
    EmbeddingConfig, EmbeddingError, EmbeddingService, MockProvider, SimilarClaim, TokenUsage,
};

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'reembed-retired-test', 'system', \
                 ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A claim with both vector columns NULL, current or retired. A retired claim
/// has no vectors by construction: every retirement path nulls them, and that
/// is exactly the shape the old selection matched.
async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, is_current: bool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             embedding, embedding_3072) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, $3, NULL, NULL) \
         RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(is_current)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn has_vector(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding_3072 IS NOT NULL FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read embedding_3072")
}

fn config(provider: Arc<dyn EmbeddingService>) -> ReembedConfig {
    ReembedConfig {
        target: ReembedTarget::Claims,
        batch_size: 16,
        embedding_provider: provider,
        checkpoint_path: None,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reembed_run_writes_no_vector_onto_a_retired_claim(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let live = seed_claim(&pool, agent, "reembed-retired-test live claim", true).await;
    let retired = seed_claim(&pool, agent, "reembed-retired-test retired claim", false).await;

    let summary = run(
        &pool,
        config(Arc::new(MockProvider::new(EmbeddingConfig::openai(3072)))),
    )
    .await
    .expect("a corpus containing a retired claim must not fail the run");

    // POSITIVE ARM FIRST: an exclusion that selected nothing would satisfy the
    // negative assertion below.
    assert!(
        has_vector(&pool, live).await,
        "a current claim must still be re-embedded"
    );
    assert!(
        !has_vector(&pool, retired).await,
        "a retired claim must not be given a 3072-d vector"
    );
    assert_eq!(summary.rows_written, 1, "only the current claim is written");
}

/// Wraps `MockProvider` and, on the first batch call, retires one claim the
/// way `ClaimRepository::supersede` does before returning the embeddings.
struct RetiringProvider {
    inner: MockProvider,
    pool: PgPool,
    victim: Uuid,
    fired: AtomicBool,
}

#[async_trait]
impl EmbeddingService for RetiringProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.inner.generate(text).await
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if !self.fired.swap(true, Ordering::SeqCst) {
            sqlx::query(
                "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
                  WHERE id = $1",
            )
            .bind(self.victim)
            .execute(&self.pool)
            .await
            .expect("retire the claim between selection and write");
        }
        self.inner.batch_generate(texts).await
    }

    async fn store(&self, claim_id: Uuid, embedding: &[f32]) -> Result<(), EmbeddingError> {
        self.inner.store(claim_id, embedding).await
    }

    async fn get(&self, claim_id: Uuid) -> Result<Vec<f32>, EmbeddingError> {
        self.inner.get(claim_id).await
    }

    async fn similar(
        &self,
        embedding: &[f32],
        k: usize,
        min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        self.inner.similar(embedding, k, min_similarity).await
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
async fn a_claim_retired_mid_run_is_skipped_and_the_run_succeeds(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let survivor = seed_claim(&pool, agent, "reembed-retired-test survivor", true).await;
    let victim = seed_claim(&pool, agent, "reembed-retired-test retired mid-run", true).await;

    let provider = Arc::new(RetiringProvider {
        inner: MockProvider::new(EmbeddingConfig::openai(3072)),
        pool: pool.clone(),
        victim,
        fired: AtomicBool::new(false),
    });

    let summary = run(&pool, config(provider.clone()))
        .await
        .expect("a claim retired mid-run must be skipped, not fail the run");

    assert!(
        provider.fired.load(Ordering::SeqCst),
        "precondition: the provider retired the victim inside the batch"
    );
    assert!(
        has_vector(&pool, survivor).await,
        "the claim that stayed current must still be written"
    );
    assert!(
        !has_vector(&pool, victim).await,
        "a claim retired after selection must not be given a 3072-d vector"
    );
    assert_eq!(
        summary.rows_written, 1,
        "rows_written counts rows that landed, not rows that were selected"
    );
}
