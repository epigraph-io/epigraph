//! Verifies the reembed CLI is idempotent: re-running over already-populated
//! rows is a no-op (zero embedding-provider calls beyond the first run).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::reembed::{run, ReembedConfig, ReembedTarget};
use epigraph_embeddings::{
    EmbeddingConfig, EmbeddingError, EmbeddingService, MockProvider, SimilarClaim, TokenUsage,
};

/// Wrapper around `MockProvider` that exposes an externally observable call
/// counter. The upstream `MockProvider::call_count` is private, and we want
/// to assert "no extra batch_generate calls on the second run".
struct CountingProvider {
    inner: MockProvider,
    batch_calls: AtomicUsize,
}

impl CountingProvider {
    fn new_3072() -> Self {
        let config = EmbeddingConfig::openai(3072);
        Self {
            inner: MockProvider::new(config),
            batch_calls: AtomicUsize::new(0),
        }
    }

    fn batch_call_count(&self) -> usize {
        self.batch_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl EmbeddingService for CountingProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.inner.generate(text).await
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        self.batch_calls.fetch_add(1, Ordering::SeqCst);
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

/// Insert `n` claims with a non-null 1536d embedding and NULL embedding_3072.
async fn seed_claims_with_1536_embeddings(pool: &PgPool, n: usize) -> Vec<Uuid> {
    // Inline agent seed (no epigraph_test_support helper). Pattern mirrors
    // tests in crates/epigraph-db/src/repos/claim.rs.
    let agent_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'reembed-test', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent");

    // Build a length-1536 zero-ish vector as a pgvector literal.
    let inner: Vec<String> = (0..1536).map(|i| format!("{}", (i as f32) * 0.0001)).collect();
    let pgvec = format!("[{}]", inner.join(","));

    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let content = format!("reembed-test-{}-{}", i, Uuid::new_v4());
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, embedding_3072) \
             VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector, NULL) \
             RETURNING id",
        )
        .bind(&content)
        .bind(agent_id)
        .bind(&pgvec)
        .fetch_one(pool)
        .await
        .expect("seed claim");
        ids.push(id);
    }
    ids
}

#[sqlx::test(migrations = "../../migrations")]
async fn reembed_is_idempotent(pool: PgPool) {
    let _seeded = seed_claims_with_1536_embeddings(&pool, 3).await;

    let provider = Arc::new(CountingProvider::new_3072());
    let summary1 = run(
        &pool,
        ReembedConfig {
            target: ReembedTarget::Claims,
            batch_size: 2,
            embedding_provider: provider.clone(),
            checkpoint_path: None,
        },
    )
    .await
    .expect("first run");
    assert_eq!(summary1.rows_written, 3, "first run writes 3 rows");

    let calls_after_first = provider.batch_call_count();
    assert!(calls_after_first >= 1, "first run made at least one batch call");

    let summary2 = run(
        &pool,
        ReembedConfig {
            target: ReembedTarget::Claims,
            batch_size: 2,
            embedding_provider: provider.clone(),
            checkpoint_path: None,
        },
    )
    .await
    .expect("second run");
    assert_eq!(summary2.rows_written, 0, "second run is a no-op");
    assert_eq!(
        provider.batch_call_count(),
        calls_after_first,
        "no extra embedding calls on second run",
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims WHERE embedding_3072 IS NOT NULL AND content LIKE 'reembed-test-%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 3, "all 3 seeded claims have embedding_3072 populated");
}
