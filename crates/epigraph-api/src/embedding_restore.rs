//! The runner-side half of `embedding_generation`.
//!
//! # What was missing, and what was not
//!
//! `epigraph-jobs` has carried a complete `embedding_generation` handler —
//! [`epigraph_jobs::ConfigurableEmbeddingHandler`] — since before the
//! privatization work, together with the [`epigraph_jobs::EmbeddingJobService`]
//! trait it is generic over. What the workspace never had was an
//! implementation of that trait, so the handler was unconstructible and the
//! runner registered nothing for the job type that `unseal-commit` enqueues.
//! The enqueued row was therefore a marker, not a restoration.
//!
//! This module is that implementation. It is deliberately small: the parsing,
//! the retry budget and the backoff all already exist in the handler.
//!
//! # It lives in the library, not in `bin/server.rs`
//!
//! A type defined in a `[[bin]]` target exports nothing, so no test could
//! construct it and the acceptance for this fix is a test that drives a real
//! claim's vector from `NULL` to non-`NULL`. It is also outside
//! `src/routes/`, which is the scan root for the handler-side bypass ban — a
//! background job holding a maintenance lease is the point of that mechanism,
//! and the ban's own documentation says jobs are deliberately not scanned.
//!
//! # Two refusals, and the difference between them
//!
//! 1. **A mock embedder must not be registered at all.** See
//!    [`EmbeddingProviderKind`]. This is a boot-time decision.
//! 2. **A sealed claim must not be embedded.** See
//!    [`ClaimEmbeddingJobService`]. This is a per-job decision, and it is
//!    enforced in the repository layer at BOTH ends — the read that supplies
//!    the text and the write that stores the vector.

/// Which provider `create_embedding_service` actually selected.
///
/// # Why the caller must be told, rather than inferring it
///
/// The provider chain falls through OpenAI → Jina → a mock, and the fallthrough
/// is silent by design: a mock embedder is the right answer for local
/// development, where nothing durable is written from it. The moment a
/// *background job* starts writing embeddings, that stops being true — the
/// first drain on a box with no API key would fill `claims.embedding` with mock
/// vectors, and `claims.embedding` is the live ANN column semantic recall
/// ranks on. Nothing downstream can tell a mock vector from a real one, so the
/// distinction has to be carried from the one place that knows it.
///
/// `epigraph_embeddings::EmbeddingService` exposes no provider identity, which
/// is why this is a separate value rather than a method on the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbeddingProviderKind {
    /// `text-embedding-3-small`, the model `claims.embedding` already holds.
    OpenAi,
    /// Jina v4. Usable for queries, but it embeds into a DIFFERENT vector
    /// space, so persisting its output beside OpenAI vectors would make cosine
    /// similarity across the column meaningless.
    Jina,
    /// The development fallback. Generates deterministic nonsense.
    Mock,
}

impl EmbeddingProviderKind {
    /// Whether this provider may write `claims.embedding`.
    ///
    /// Only OpenAI may. This is deliberately stricter than "is not a mock":
    /// Jina works, and its vectors are good vectors — they are simply not in
    /// the space the stored corpus occupies, and a column holding two spaces
    /// degrades recall in a way no error surfaces. `bin/server.rs`'s own
    /// comment on the Jina fallback already says query vectors from it "may not
    /// match OpenAI-embedded claims"; writing them makes that permanent.
    ///
    /// The same condition guards the MCP server's backfill tool, which refuses
    /// up front rather than reporting a batch of failures.
    #[must_use]
    pub const fn may_restore_claim_embeddings(self) -> bool {
        matches!(self, Self::OpenAi)
    }

    /// A short name for the boot log.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Jina => "jina",
            Self::Mock => "mock",
        }
    }
}

/// Render a vector as a pgvector literal.
///
/// # A duplication, named rather than refactored away
///
/// Six private copies of this three-line function already exist across the
/// workspace (`epigraph-mcp`, `epigraph-engine`, `epigraph-embeddings` and two
/// `epigraph-cli` binaries). Consolidating them is a worthwhile change and is
/// not this one: it would touch five crates for no behavioural gain, in a
/// change whose subject is a job registration.
#[cfg(feature = "db")]
fn format_pgvector(vec: &[f32]) -> String {
    let body = vec
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

/// The production [`epigraph_jobs::EmbeddingJobService`].
///
/// # The seal is the whole difficulty
///
/// A privatization seal nulls a claim's vector columns and replaces its
/// `content` with a stub; `unseal-commit` restores the plaintext and enqueues
/// one of these jobs per restored claim. Between that enqueue and the drain the
/// claim can be sealed again — plans overlap, and the queue has a retry budget
/// measured in hours. Writing a plaintext-derived vector onto a sealed row is
/// not a degraded restoration, it is a confidentiality violation: CLAUDE.md's
/// audit treats a sealed claim carrying a vector as a page-the-on-call
/// condition, separately from the ordinary embedding gap.
///
/// So the check is made twice, in the statement each time and never in this
/// file's control flow:
///
/// * [`ClaimRepository::claim_text_for_embedding`] refuses to hand over text
///   for a sealed claim, so the provider is never called on one;
/// * [`ClaimRepository::store_embedding_if_unsealed`] locks the row and then
///   re-checks in the `WHERE` of the `UPDATE`, so a claim sealed during the
///   provider round trip is not written. The lock is load-bearing and its own
///   doc says why: a lone single-statement `WHERE` does not see a seal that
///   commits while the `UPDATE` is blocked on the row.
///
/// [`ClaimRepository::claim_text_for_embedding`]: epigraph_db::ClaimRepository::claim_text_for_embedding
/// [`ClaimRepository::store_embedding_if_unsealed`]: epigraph_db::ClaimRepository::store_embedding_if_unsealed
///
/// # What a refusal looks like from the queue
///
/// The trait returns `Option<String>`, so "sealed" and "no such claim" reach
/// the handler as the same `None` and it fails the job. That is the intended
/// direction: the job retries, and if the claim is still sealed when the budget
/// runs out it lands in `failed`, where an operator can see it. The alternative
/// — treating a sealed claim as success — would drop the restoration silently
/// for the one population where silence is least acceptable.
///
/// There is a THIRD `None`, and for it `failed` is a correct decline rather
/// than a missing restoration: a claim the corpus deliberately does not embed.
/// `claim_text_for_embedding` applies the enumerator's population rules — the
/// `telemetry` label, the `properties->>'event'` marker, `is_current` — and
/// `unseal-commit` enqueues one job per restored claim without consulting them,
/// so a claim of that population inside a seal plan reaches `failed` after the
/// retry budget. Nothing is owed on such a row; the job row is a report, not a
/// defect. Narrowing the enqueue to the embeddable population would remove the
/// noise and is a larger change than a registration.
#[cfg(feature = "db")]
pub struct ClaimEmbeddingJobService {
    scoped: std::sync::Arc<epigraph_db::ScopedPool>,
    embedder: std::sync::Arc<dyn epigraph_embeddings::EmbeddingService>,
}

#[cfg(feature = "db")]
impl ClaimEmbeddingJobService {
    /// Build the service over the runner's own pool.
    ///
    /// Takes a `ScopedPool` rather than a `PgPool` for the same reason the
    /// privatization handlers do: it is the only mint of the `MaintenanceLease`
    /// that a bypass viewer requires, and a job has no principal whose tenancy
    /// could stand in for one.
    #[must_use]
    pub const fn new(
        scoped: std::sync::Arc<epigraph_db::ScopedPool>,
        embedder: std::sync::Arc<dyn epigraph_embeddings::EmbeddingService>,
    ) -> Self {
        Self { scoped, embedder }
    }
}

#[cfg(feature = "db")]
#[async_trait::async_trait]
impl epigraph_jobs::EmbeddingJobService for ClaimEmbeddingJobService {
    async fn get_claim_text(&self, claim_id: uuid::Uuid) -> Option<String> {
        let (mut conn, lease) = self
            .scoped
            .unscoped_for_maintenance(epigraph_db::visibility::SystemReason::EmbeddingBackfill)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, %claim_id, "embedding restore: no maintenance connection");
            })
            .ok()?;
        let bypass = epigraph_db::visibility::Viewer::system(
            &lease,
            epigraph_db::visibility::SystemReason::EmbeddingBackfill,
        );
        match epigraph_db::ClaimRepository::claim_text_for_embedding(&mut *conn, &bypass, claim_id)
            .await
        {
            Ok(text) => text,
            Err(e) => {
                tracing::error!(error = %e, %claim_id, "embedding restore: text read failed");
                None
            }
        }
    }

    async fn generate_and_store(
        &self,
        claim_id: uuid::Uuid,
        text: &str,
    ) -> Result<Vec<f32>, epigraph_jobs::EmbeddingJobError> {
        let vector = self.embedder.generate(text).await.map_err(|e| {
            epigraph_jobs::EmbeddingJobError::ApiError {
                message: e.to_string(),
            }
        })?;

        let (mut conn, lease) = self
            .scoped
            .unscoped_for_maintenance(epigraph_db::visibility::SystemReason::EmbeddingBackfill)
            .await
            .map_err(|e| epigraph_jobs::EmbeddingJobError::ApiError {
                message: format!("no maintenance connection: {e}"),
            })?;
        let bypass = epigraph_db::visibility::Viewer::system(
            &lease,
            epigraph_db::visibility::SystemReason::EmbeddingBackfill,
        );
        let stored = epigraph_db::ClaimRepository::store_embedding_if_unsealed(
            &mut conn,
            &bypass,
            claim_id,
            &format_pgvector(&vector),
        )
        .await
        .map_err(|e| epigraph_jobs::EmbeddingJobError::ApiError {
            message: e.to_string(),
        })?;

        // NOT `Ok(())`. A zero-row UPDATE here means the claim was sealed while
        // the provider was being called, or removed. Reporting success would
        // mark the job done and leave the vector missing with nothing recording
        // why.
        if !stored {
            return Err(epigraph_jobs::EmbeddingJobError::NotFound { claim_id });
        }
        Ok(vector)
    }

    fn dimension(&self) -> usize {
        self.embedder.dimension()
    }

    fn token_usage(&self) -> epigraph_jobs::EmbeddingTokenUsage {
        // CUMULATIVE FOR THE PROCESS, NOT FOR THIS JOB. The embedder is the
        // same `Arc` the query path holds — deliberately, so the job writes
        // vectors from the provider queries are ranked against — and its
        // counter therefore includes every semantic search since boot. An
        // operator reading `tokens_used` on a job row is reading that total.
        // Reporting a delta instead is not a fix: drains can overlap, and two
        // jobs sharing one counter would attribute each other's tokens.
        // `reset_token_usage()` is worse still — it would zero the counter the
        // query path shares. Per-job attribution needs a per-call figure from
        // the provider, which `EmbeddingService` does not expose.
        let usage = self.embedder.token_usage();
        epigraph_jobs::EmbeddingTokenUsage {
            total_tokens: usage.total_tokens,
            prompt_tokens: usage.prompt_tokens,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EmbeddingProviderKind;

    /// The gate is on the provider that owns the column, not on "is not mock".
    ///
    /// Jina is the case that matters: it is a real provider that really
    /// embeds, so a condition written as `!= Mock` would admit it, compile,
    /// pass every test that only checks a vector appeared, and quietly fill
    /// one ANN column with two incompatible vector spaces.
    #[test]
    fn only_openai_may_write_the_claim_embedding_column() {
        assert!(EmbeddingProviderKind::OpenAi.may_restore_claim_embeddings());
        assert!(!EmbeddingProviderKind::Jina.may_restore_claim_embeddings());
        assert!(!EmbeddingProviderKind::Mock.may_restore_claim_embeddings());
    }
}
