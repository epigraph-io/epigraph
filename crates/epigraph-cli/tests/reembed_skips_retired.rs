//! `reembed --target claims` must never write a 3072-d vector onto a RETIRED
//! (`is_current = false`) claim.
//!
//! # Why this is worth a test of its own
//!
//! Every retirement write path (`ClaimRepository::supersede_act_conn`,
//! `evolve_step_conn`, `deprecate_claim`, `consolidate_act_conn`,
//! `mark_duplicate_act`) nulls BOTH `embedding` and `embedding_3072` in the
//! statement that flips `is_current`, so a retired claim leaves the ANN
//! surface. `reembed` selects rows by `embedding_3072 IS NULL` — which is
//! exactly the shape a retirement leaves behind — so without an `is_current`
//! clause a run re-populates every retired claim it meets. Two costs:
//!
//! 1. Recall at `centroid_dim = 3072`
//!    (`ClaimRepository::search_by_embedding_since`) has no `is_current`
//!    filter, so the retired claim becomes retrievable again.
//! 2. `chk_deprecated_no_embedding` covers `embedding_3072` (migration 144),
//!    so the first retired row in a batch makes the UPDATE raise 23514 and
//!    the whole run aborts.
//!
//! The assertion is therefore on persisted column state, with a CURRENT claim
//! beside the retired one as calibration: an exclusion that selected nothing
//! would pass every negative assertion while breaking the tool.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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

/// A claim with BOTH vector columns NULL — the state every retirement path
/// leaves behind, and the state `reembed` selects on.
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

#[sqlx::test(migrations = "../../migrations")]
async fn reembed_never_writes_a_vector_onto_a_retired_claim(pool: PgPool) {
    const LIVE: &str = "reembed-retired-test live claim";
    const RETIRED: &str = "reembed-retired-test retired claim";
    let agent = seed_agent(&pool).await;
    let live = seed_claim(&pool, agent, LIVE, true).await;
    let retired = seed_claim(&pool, agent, RETIRED, false).await;

    let provider = Arc::new(ProbeProvider::recording(pool.clone()));
    let summary = run(
        &pool,
        ReembedConfig {
            target: ReembedTarget::Claims,
            batch_size: 10,
            embedding_provider: provider.clone(),
            checkpoint_path: None,
        },
    )
    .await
    .expect("reembed run over a corpus holding a retired claim must succeed");

    // POSITIVE ARM FIRST: the current claim IS selected, sent and re-embedded,
    // so the exclusion is not simply "select nothing".
    let sent = provider.sent_texts();
    assert!(
        sent.iter().any(|t| t == LIVE),
        "calibration: the current claim's content must be sent to the provider; sent = {sent:?}"
    );
    assert!(
        has_vector(&pool, live).await,
        "calibration: a current claim must still be re-embedded"
    );
    // SELECTION GUARD (`fetch_batch`'s eligibility clause): the retired claim's
    // content never reaches the provider. The write-time re-check alone would
    // still leave the column NULL, so only this assertion pins the selection —
    // without it every fresh run pays to embed the whole retired corpus.
    assert!(
        !sent.iter().any(|t| t == RETIRED),
        "a retired claim must never be selected and sent to the embedding provider; sent = {sent:?}"
    );
    assert!(
        !has_vector(&pool, retired).await,
        "a retired claim must never get a 3072 vector (recall at 3072 has no is_current filter)"
    );
    assert_eq!(
        summary.rows_written, 1,
        "exactly the one current claim is written; the retired one is never written"
    );
}

/// A wrapper around `MockProvider` that records every text sent to
/// `batch_generate` and, optionally, RETIRES one claim the first time it is
/// asked for vectors, i.e. inside the window between `fetch_batch` selecting
/// the row and the UPDATE writing its vector. That window is the provider
/// round trip on every batch, so a concurrent supersede / deprecate /
/// mark_duplicate landing in it is the ordinary case, not a contrived one. The
/// retirement is the statement the repo layer runs: `is_current = false` with
/// BOTH vectors nulled.
struct ProbeProvider {
    inner: MockProvider,
    pool: PgPool,
    victim: Option<Uuid>,
    fired: AtomicBool,
    sent: Mutex<Vec<String>>,
}

impl ProbeProvider {
    fn recording(pool: PgPool) -> Self {
        Self {
            inner: MockProvider::new(EmbeddingConfig::openai(3072)),
            pool,
            victim: None,
            fired: AtomicBool::new(false),
            sent: Mutex::new(Vec::new()),
        }
    }

    fn retiring(pool: PgPool, victim: Uuid) -> Self {
        Self {
            victim: Some(victim),
            ..Self::recording(pool)
        }
    }

    fn sent_texts(&self) -> Vec<String> {
        self.sent.lock().expect("sent lock").clone()
    }
}

#[async_trait]
impl EmbeddingService for ProbeProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.inner.generate(text).await
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        self.sent
            .lock()
            .expect("sent lock")
            .extend(texts.iter().map(|t| (*t).to_string()));
        if let Some(victim) = self
            .victim
            .filter(|_| !self.fired.swap(true, Ordering::SeqCst))
        {
            sqlx::query(
                "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
                  WHERE id = $1",
            )
            .bind(victim)
            .execute(&self.pool)
            .await
            .expect("retire the victim mid-batch");
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

/// A claim retired AFTER `fetch_batch` selected it must neither get a vector
/// nor abort the run. Under `chk_deprecated_no_embedding` (migration 144) an
/// unconditional `UPDATE ... SET embedding_3072 = $1 WHERE id = $2` raises
/// 23514 on it and `run` returns Err, stopping the whole corpus pass; before
/// 144 the same UPDATE silently resurrected the retired claim in recall.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_retired_mid_batch_is_skipped_not_fatal(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let live = seed_claim(&pool, agent, "reembed-race-test live claim", true).await;
    let victim = seed_claim(&pool, agent, "reembed-race-test retired mid-batch", true).await;

    let provider = Arc::new(ProbeProvider::retiring(pool.clone(), victim));

    let summary = run(
        &pool,
        ReembedConfig {
            target: ReembedTarget::Claims,
            batch_size: 10,
            embedding_provider: provider.clone(),
            checkpoint_path: None,
        },
    )
    .await
    .expect("a claim retired between fetch and update must not abort the run");

    assert!(
        provider.fired.load(Ordering::SeqCst),
        "calibration: the retirement really ran inside the batch window"
    );
    assert!(
        has_vector(&pool, live).await,
        "calibration: the claim still current at update time is re-embedded"
    );
    assert!(
        !has_vector(&pool, victim).await,
        "a claim retired mid-batch must not be given a 3072 vector"
    );
    assert_eq!(
        summary.rows_written, 1,
        "rows_written counts rows actually written, not rows fetched"
    );
}
