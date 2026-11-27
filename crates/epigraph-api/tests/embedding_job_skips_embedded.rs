//! The `embedding_generation` job leaves a claim's existing vector alone
//! (backlog 1b83b2a1).
//!
//! The job is enqueued when a vector is wanted (an unseal's restore, a
//! submission whose inline embed did not land), but by the time the drain
//! runs it the claim may already carry one: the inline path wrote it, or an
//! earlier attempt of the same job did. Two things follow, and each is pinned
//! here against the production `ClaimEmbeddingJobService`, driven through
//! `ConfigurableEmbeddingHandler` as the drain does:
//!
//! * a claim that already has `claims.embedding` costs NO provider call and
//!   keeps its vector bit for bit (the job completes as a skip);
//! * a vector written while the job was calling the provider (between its read
//!   and its store) is not overwritten by the job's vector.
//!
//! The provider is a counting wrapper around the deterministic
//! `MockProvider`, so "the provider was not called" is a measured count, not
//! an inference from the vector. The seeded and inline vectors are constants
//! that differ from anything the mock returns, so "unchanged" is not vacuous.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use epigraph_api::embedding_restore::ClaimEmbeddingJobService;
use epigraph_embeddings::{
    EmbeddingConfig, EmbeddingError, EmbeddingService, MockProvider, TokenUsage,
};
use epigraph_jobs::{ConfigurableEmbeddingHandler, EpiGraphJob, Job, JobHandler};
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;

/// A 1536-d pgvector literal with every component equal to `x`. The mock
/// provider returns a hash-derived unit vector, never a constant one, so a
/// constant vector is distinguishable from the job's own write.
fn constant_vector(x: f32) -> String {
    let parts: Vec<String> = std::iter::repeat_n(x.to_string(), DIM).collect();
    format!("[{}]", parts.join(","))
}

/// A real `EmbeddingService` over `MockProvider` that counts `generate` calls
/// and, when `inline` is set, writes that vector onto `claim` through `pool`
/// before returning: an inline write landing while the job waits on the
/// provider.
struct CountingProvider {
    inner: MockProvider,
    calls: AtomicUsize,
    inline: Option<(PgPool, Uuid, String)>,
}

impl CountingProvider {
    fn new(inline: Option<(PgPool, Uuid, String)>) -> Self {
        Self {
            inner: MockProvider::new(EmbeddingConfig::openai(DIM)),
            calls: AtomicUsize::new(0),
            inline,
        }
    }
}

#[epigraph_jobs::async_trait]
impl EmbeddingService for CountingProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some((pool, claim, vec)) = &self.inline {
            viewer_fixture::set_claim_embedding(pool, *claim, vec).await;
        }
        self.inner.generate(text).await
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        let mut out = Vec::with_capacity(texts.len());
        for t in texts {
            out.push(self.generate(t).await?);
        }
        Ok(out)
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

async fn embedding_text(pool: &PgPool, claim: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT embedding::text FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read claims.embedding")
}

fn embedding_job(claim_id: Uuid) -> Job {
    Job::new(
        "embedding_generation",
        serde_json::to_value(EpiGraphJob::EmbeddingGeneration { claim_id }).unwrap(),
    )
}

/// Seed one public, current, unsealed claim with no vector.
async fn seed(pool: &PgPool, content: &str) -> Uuid {
    let (agent, _group) = viewer_fixture::seed_agent_with_group(pool, "embed-job").await;
    viewer_fixture::grant_app_privileges(pool, "epigraph_app").await;
    let claim = viewer_fixture::seed_public_claim(pool, agent, content).await;
    assert_eq!(
        embedding_text(pool, claim).await,
        None,
        "CALIBRATION: the seeded claim must start without a vector"
    );
    claim
}

/// Run the handler over the production service with `provider`.
async fn run_job(
    pool: &PgPool,
    claim: Uuid,
    provider: Arc<CountingProvider>,
) -> Result<epigraph_jobs::JobResult, epigraph_jobs::JobError> {
    let scoped = Arc::new(viewer_fixture::scoped_pool(pool).await);
    let handler = ConfigurableEmbeddingHandler::new(Arc::new(ClaimEmbeddingJobService::new(
        scoped, provider,
    )));
    handler.handle(&embedding_job(claim)).await
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_already_embedded_claim_costs_no_provider_call_and_keeps_its_vector(pool: PgPool) {
    let claim = seed(&pool, "a claim whose vector was written inline").await;
    viewer_fixture::set_claim_embedding(&pool, claim, &constant_vector(0.25)).await;
    let before = embedding_text(&pool, claim).await;
    assert!(
        before.is_some(),
        "CALIBRATION: the claim must start embedded"
    );

    let provider = Arc::new(CountingProvider::new(None));
    let result = run_job(&pool, claim, Arc::clone(&provider))
        .await
        .expect("the job for an already-embedded claim must complete, not fail");

    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        0,
        "the job called the embedding provider for a claim that already has a vector"
    );
    assert_eq!(
        embedding_text(&pool, claim).await,
        before,
        "the job overwrote a claim's existing vector"
    );
    assert_eq!(
        result.output["skipped"], "already_embedded",
        "the job must report the skip, got {}",
        result.output
    );
    assert_eq!(result.output["claim_id"], claim.to_string());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_without_a_vector_gets_one(pool: PgPool) {
    let claim = seed(&pool, "a claim the job must embed").await;

    let provider = Arc::new(CountingProvider::new(None));
    let result = run_job(&pool, claim, Arc::clone(&provider))
        .await
        .expect("the job for a NULL-embedding claim must succeed");

    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert!(
        embedding_text(&pool, claim).await.is_some(),
        "the job left a NULL-embedding claim without a vector"
    );
    assert_eq!(result.output["embedding_dimension"], DIM);
    assert!(
        result.output.get("skipped").is_none(),
        "a claim the job embedded must not be reported as skipped: {}",
        result.output
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_vector_written_during_the_provider_call_is_not_overwritten(pool: PgPool) {
    let claim = seed(&pool, "a claim embedded inline while the job waits").await;
    let inline = constant_vector(0.5);

    let provider = Arc::new(CountingProvider::new(Some((
        pool.clone(),
        claim,
        inline.clone(),
    ))));
    let result = run_job(&pool, claim, Arc::clone(&provider))
        .await
        .expect("a job that lost the race to an inline write must complete, not fail");

    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        1,
        "CALIBRATION: the claim had no vector when the job read it, so the provider is called"
    );
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT embedding::text FROM claims WHERE id = $1 AND embedding = $2::vector",
    )
    .bind(claim)
    .bind(&inline)
    .fetch_optional(&pool)
    .await
    .expect("compare the stored vector");
    assert!(
        stored.is_some(),
        "the job's store overwrote the vector written inline during its provider call"
    );
    assert_eq!(
        result.output["skipped"], "already_embedded",
        "the job must report the skip, got {}",
        result.output
    );
}
