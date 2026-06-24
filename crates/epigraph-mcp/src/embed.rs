use async_trait::async_trait;
use epigraph_embeddings::{
    service::{SimilarClaim, TokenUsage},
    EmbeddingError, EmbeddingService,
};
use sqlx::PgPool;

/// Per-leg candidate pool size before RRF fusion in hybrid recall.
pub const HYBRID_CANDIDATE_POOL: i64 = 50;
/// Reciprocal Rank Fusion constant `k` (canonical default 60).
pub const HYBRID_RRF_K: i64 = 60;

pub struct McpEmbedder {
    api_key: Option<String>,
    pool: PgPool,
    http: reqwest::Client,
}

/// Whether an OpenAI API key string is unusable for embedding generation:
/// absent, empty, or the literal `"mock"`. Mirrors the disabled-condition that
/// `generate`/`generate_at_dim` apply inline (`.filter(|k| !k.is_empty() && *k
/// != "mock")`); `embeddings_disabled` delegates here so the backfill guard and
/// the generate path agree. Kept free-standing so it is unit-testable without a
/// `PgPool`.
fn key_disabled(key: Option<&str>) -> bool {
    !matches!(key, Some(k) if !k.is_empty() && k != "mock")
}

/// Map a centroid dimension to the OpenAI model that produces it.
/// Returns None for unsupported dims (caller treats as InvalidParams).
#[must_use]
pub const fn model_for_dim(dim: u32) -> Option<&'static str> {
    match dim {
        1536 => Some("text-embedding-3-small"),
        3072 => Some("text-embedding-3-large"),
        _ => None,
    }
}

impl McpEmbedder {
    #[must_use]
    pub fn new(pool: PgPool, api_key: Option<String>) -> Self {
        Self {
            api_key,
            pool,
            http: reqwest::Client::new(),
        }
    }

    #[must_use]
    pub const fn is_mock(&self) -> bool {
        self.api_key.is_none()
    }

    /// True when no usable API key is configured, so `generate`/`generate_at_dim`
    /// will reject every call. Mirrors their disabled-condition exactly — a
    /// `None`, empty, or literal `"mock"` key — so batch callers (e.g.
    /// `backfill_embeddings`) can fail loudly up front instead of churning a
    /// whole batch into all-failed. Stricter than [`is_mock`](Self::is_mock),
    /// which only catches the `None` case.
    #[must_use]
    pub fn embeddings_disabled(&self) -> bool {
        key_disabled(self.api_key.as_deref())
    }

    /// Generate an embedding vector without storing it.
    ///
    /// Returns the raw `Vec<f32>` from OpenAI. Callers can format it
    /// with `format_pgvector()` for SQL queries.
    pub async fn generate(&self, text: &str) -> Result<Vec<f32>, String> {
        let api_key = self
            .api_key
            .as_deref()
            .filter(|k| !k.is_empty() && *k != "mock")
            .ok_or_else(|| "embeddings disabled (no API key)".to_string())?;

        // Truncate the EMBEDDING INPUT only to the OpenAI model's 8191-token limit;
        // the stored claim content stays full verbatim. Verbatim_v2 paragraph
        // nodes can carry whole sections that exceed the embedding context — an
        // over-limit request 400s, so clip here rather than drop the embedding.
        let truncated = truncate_embedding_input(text);
        generate_openai_embedding_with_model(
            &self.http,
            api_key,
            &truncated,
            "text-embedding-3-small",
        )
        .await
    }

    /// Generate an embedding at the requested dimension by selecting the right
    /// OpenAI model. Returns the raw `Vec<f32>`; caller formats with format_pgvector.
    pub async fn generate_at_dim(&self, text: &str, dim: u32) -> Result<Vec<f32>, String> {
        let api_key = self
            .api_key
            .as_deref()
            .filter(|k| !k.is_empty() && *k != "mock")
            .ok_or_else(|| "embeddings disabled (no API key)".to_string())?;

        let model = model_for_dim(dim)
            .ok_or_else(|| format!("unsupported centroid_dim: {dim} (must be 1536 or 3072)"))?;

        // Truncate the embedding input to the model token limit (stored content
        // is untouched); see `generate` for the verbatim-spine rationale.
        let truncated = truncate_embedding_input(text);
        generate_openai_embedding_with_model(&self.http, api_key, &truncated, model).await
    }

    /// Generate embedding and store it for a claim. Returns true if embedding succeeded.
    pub async fn embed_and_store(&self, claim_id: uuid::Uuid, text: &str) -> bool {
        let embedding = match self.generate(text).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("embedding failed (claim still stored): {e}");
                return false;
            }
        };

        let pgvec = format_pgvector(&embedding);
        match epigraph_db::ClaimRepository::store_embedding(&self.pool, claim_id, &pgvec).await {
            Ok(true) => true,
            Ok(false) => {
                tracing::warn!(
                    claim_id = %claim_id,
                    "embedding store affected 0 rows (claim missing?)"
                );
                false
            }
            Err(e) => {
                tracing::warn!("embedding store failed: {e}");
                false
            }
        }
    }

    /// Search current claims by embedding similarity. Returns
    /// (claim_id, similarity) pairs. Unscoped convenience wrapper over
    /// [`search_scoped`](Self::search_scoped).
    ///
    /// Searches `claims.embedding` (where memorize/submit/ingest write claim
    /// vectors). This previously called `EvidenceRepository::search_by_embedding`
    /// = `evidence.embedding`, which is unpopulated, so the `recall` tool's
    /// semantic path always returned empty.
    pub async fn search(&self, query: &str, limit: i64) -> Result<Vec<(uuid::Uuid, f64)>, String> {
        self.search_scoped(query, limit, None, None).await
    }

    /// Embedding search over current claims with optional scope pushed into
    /// the query (see `ClaimRepository::search_by_embedding_scoped`): `tags`
    /// requires label containment, `agent_id` requires authorship, `None` does
    /// not restrict.
    pub async fn search_scoped(
        &self,
        query: &str,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<uuid::Uuid>,
    ) -> Result<Vec<(uuid::Uuid, f64)>, String> {
        let embedding = self.generate(query).await?;

        let pgvec = format_pgvector(&embedding);
        let results = epigraph_db::ClaimRepository::search_by_embedding_scoped(
            &self.pool, &pgvec, limit, tags, agent_id,
        )
        .await
        .map_err(|e| e.to_string())?;

        Ok(results
            .into_iter()
            .map(|r| (r.claim_id, r.similarity))
            .collect())
    }

    /// Hybrid retrieval: embed the query (1536d), then RRF-fuse the dense and
    /// lexical legs via [`ClaimRepository::search_hybrid_scoped`]. Returns the
    /// fused hits; the caller (`recall`) degrades to lexical-only on `Err`.
    pub async fn search_hybrid_scoped(
        &self,
        query: &str,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<uuid::Uuid>,
    ) -> Result<Vec<epigraph_db::HybridHit>, String> {
        let embedding = self.generate(query).await?;
        let pgvec = format_pgvector(&embedding);
        epigraph_db::ClaimRepository::search_hybrid_scoped(
            &self.pool,
            &pgvec,
            query,
            HYBRID_CANDIDATE_POOL,
            HYBRID_RRF_K,
            limit,
            tags,
            agent_id,
        )
        .await
        .map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// EmbeddingService implementation
// ---------------------------------------------------------------------------
//
// `McpEmbedder` uses the OpenAI API directly (text-embedding-3-small, 1536d).
// This impl exposes it through the canonical trait so callers — including the
// library `recall` function in `epigraph-engine` — only need `&dyn EmbeddingService`.
//
// Methods that have no natural delegation in `McpEmbedder` (token tracking,
// in-memory retrieval) return honest no-op / not-found values rather than
// `unimplemented!()` panics.  None of these are on the hot path for `recall`.

#[async_trait]
impl EmbeddingService for McpEmbedder {
    /// Delegate to the inherent `McpEmbedder::generate`, mapping `String`
    /// errors to `EmbeddingError::ApiError`.
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        McpEmbedder::generate(self, text)
            .await
            .map_err(|msg| EmbeddingError::ApiError {
                message: msg,
                status_code: None,
            })
    }

    /// Sequential batch: loop over `generate` for each text.
    ///
    /// `McpEmbedder` has no batch OpenAI endpoint; sequential is correct here.
    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        let mut results = Vec::with_capacity(texts.len());
        for text in texts {
            // Call the inherent method and map String → EmbeddingError.
            let embedding = McpEmbedder::generate(self, text).await.map_err(|msg| {
                EmbeddingError::ApiError {
                    message: msg,
                    status_code: None,
                }
            })?;
            results.push(embedding);
        }
        Ok(results)
    }

    /// Store an embedding on `claims.embedding` via `ClaimRepository::store_embedding`.
    ///
    /// Per the embedding-policy contract in CLAUDE.md, the canonical storage
    /// site for claim embeddings is `claims.embedding`. An earlier impl wrote
    /// to `evidence.embedding` keyed by `claim_id`, which silently no-op'd
    /// because evidence rows have their own ids.
    async fn store(&self, claim_id: uuid::Uuid, embedding: &[f32]) -> Result<(), EmbeddingError> {
        let pgvec = format_pgvector(embedding);
        epigraph_db::ClaimRepository::store_embedding(&self.pool, claim_id, &pgvec)
            .await
            .map(|_| ())
            .map_err(|e| EmbeddingError::DatabaseError(e.to_string()))
    }

    /// `McpEmbedder` does not expose a point-query for stored embeddings.
    ///
    /// Returns `EmbeddingError::NotFound` unconditionally.  Nothing in the
    /// `recall` path calls `get`, so this is an honest gap, not a silent lie.
    async fn get(&self, claim_id: uuid::Uuid) -> Result<Vec<f32>, EmbeddingError> {
        Err(EmbeddingError::NotFound { claim_id })
    }

    /// Find similar claims via `EvidenceRepository::search_by_embedding`.
    ///
    /// Converts `f64` similarity from the DB row to `f32` for `SimilarClaim`.
    async fn similar(
        &self,
        embedding: &[f32],
        k: usize,
        min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        let pgvec = format_pgvector(embedding);
        let rows =
            epigraph_db::EvidenceRepository::search_by_embedding(&self.pool, &pgvec, k as i64)
                .await
                .map_err(|e| EmbeddingError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| SimilarClaim::new(r.claim_id, r.similarity as f32))
            .filter(|s| s.similarity >= min_similarity)
            .collect())
    }

    /// `text-embedding-3-small` outputs 1536-dimensional vectors.
    fn dimension(&self) -> usize {
        1536
    }

    /// `McpEmbedder` does not track token usage.
    fn token_usage(&self) -> TokenUsage {
        TokenUsage::default()
    }

    /// No-op: `McpEmbedder` does not track token usage.
    fn reset_token_usage(&self) {}

    /// Healthy when an API key is configured; unavailable in mock mode.
    async fn health_check(&self) -> Result<(), EmbeddingError> {
        if self.is_mock() {
            Err(EmbeddingError::ProviderUnavailable {
                provider: "McpEmbedder (no API key)".to_string(),
            })
        } else {
            Ok(())
        }
    }
}

/// Clip text to the OpenAI embedding model's 8191-token context window before
/// it is sent as an embedding input. Returns the original string unchanged when
/// it is already within the limit. This truncates ONLY the embedding input — the
/// caller-supplied claim content is stored full-length elsewhere; this function
/// never sees or mutates stored content. Uses the embeddings crate's
/// [`Tokenizer`](epigraph_embeddings::Tokenizer) (tiktoken when the `openai`
/// feature is on, char-estimate fallback otherwise).
fn truncate_embedding_input(text: &str) -> String {
    epigraph_embeddings::Tokenizer::new(epigraph_embeddings::config::DEFAULT_MAX_TOKENS)
        .truncate(text)
}

/// Format a vector as a pgvector string literal: `"[0.1,0.2,...]"`.
///
/// Public so callers can format a cached `Vec<f32>` for direct SQL use
/// without going through the embedder.
pub fn format_pgvector(vec: &[f32]) -> String {
    let inner: Vec<String> = vec.iter().map(|v| format!("{v}")).collect();
    format!("[{}]", inner.join(","))
}

async fn generate_openai_embedding_with_model(
    http: &reqwest::Client,
    api_key: &str,
    text: &str,
    model: &str,
) -> Result<Vec<f32>, String> {
    let resp = http
        .post("https://api.openai.com/v1/embeddings")
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&serde_json::json!({
            "model": model,
            "input": text,
        }))
        .send()
        .await
        .map_err(|e| format!("OpenAI request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("OpenAI API error {status}: {body}"));
    }

    let json: serde_json::Value = resp.json().await.map_err(|e| format!("parse error: {e}"))?;
    let embedding = json["data"][0]["embedding"]
        .as_array()
        .ok_or("missing embedding in response")?
        .iter()
        .map(|v| v.as_f64().unwrap_or(0.0) as f32)
        .collect();
    Ok(embedding)
}

#[cfg(test)]
mod tests {
    use super::model_for_dim;

    #[test]
    fn model_for_dim_picks_small_at_1536() {
        assert_eq!(model_for_dim(1536), Some("text-embedding-3-small"));
    }

    #[test]
    fn model_for_dim_picks_large_at_3072() {
        assert_eq!(model_for_dim(3072), Some("text-embedding-3-large"));
    }

    #[test]
    fn model_for_dim_rejects_unknown_dim() {
        assert!(model_for_dim(1024).is_none());
        assert!(model_for_dim(0).is_none());
    }

    // `key_disabled` is the shared disabled-condition behind both `generate`
    // and `embeddings_disabled`; pinning it keeps the backfill fail-loud guard
    // from being bypassed by an empty or "mock" key.
    #[test]
    fn key_disabled_catches_none_empty_and_mock() {
        assert!(super::key_disabled(None), "no key => disabled");
        assert!(super::key_disabled(Some("")), "empty key => disabled");
        assert!(
            super::key_disabled(Some("mock")),
            "literal mock => disabled"
        );
    }

    #[test]
    fn key_disabled_allows_a_real_key() {
        assert!(
            !super::key_disabled(Some("sk-real-key")),
            "a real key => enabled"
        );
    }

    // An over-limit input (a verbatim_v2 paragraph can be a whole section) must
    // be clipped to <= the OpenAI 8191-token window before it is sent, so the
    // embedding request never 400s on length. We measure with the SAME tokenizer
    // the truncator uses, so the assertion holds regardless of whether tiktoken
    // (openai feature) or the char-estimate fallback is active. No network.
    #[test]
    fn truncate_embedding_input_clips_over_limit_text() {
        let limit = epigraph_embeddings::config::DEFAULT_MAX_TOKENS;
        let tokenizer = epigraph_embeddings::Tokenizer::new(limit);
        // Build a string comfortably over the token limit (~5 chars/word).
        let huge = "word ".repeat(limit * 2);
        assert!(
            tokenizer.count_tokens(&huge) > limit,
            "fixture must exceed the token limit to exercise truncation"
        );

        let clipped = super::truncate_embedding_input(&huge);
        assert!(
            tokenizer.count_tokens(&clipped) <= limit,
            "truncated input must fit the model's token window"
        );
        assert!(
            clipped.len() < huge.len(),
            "over-limit input must actually be shortened"
        );
    }

    // Short inputs (the common case) must pass through byte-for-byte: truncation
    // must not silently alter content that already fits.
    #[test]
    fn truncate_embedding_input_passes_through_short_text() {
        let text = "The Earth orbits the Sun.";
        assert_eq!(super::truncate_embedding_input(text), text);
    }
}
