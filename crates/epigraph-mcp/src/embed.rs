use async_trait::async_trait;
use epigraph_embeddings::{
    service::{SimilarClaim, TokenUsage},
    EmbeddingError, EmbeddingService,
};
use sqlx::PgPool;
use std::sync::Arc;

/// Per-leg candidate pool size before RRF fusion in hybrid recall.
pub const HYBRID_CANDIDATE_POOL: i64 = 50;
/// Reciprocal Rank Fusion constant `k` (canonical default 60).
pub const HYBRID_RRF_K: i64 = 60;

/// Dimension of `claims.embedding`, the column [`McpEmbedder::generate`]
/// serves (`text-embedding-3-small`).
const CLAIM_EMBEDDING_DIM: u32 = 1536;

pub struct McpEmbedder {
    api_key: Option<String>,
    pool: PgPool,
    http: reqwest::Client,
    /// An injected embedding source that replaces the OpenAI endpoint.
    ///
    /// `None` in every deploy build: the only constructor that sets it,
    /// [`with_provider`](Self::with_provider), exists only under
    /// `cfg(test)` or the `test-support` feature (which this crate enables
    /// for its own integration tests through a dev-dependency on itself).
    /// Production writes to `claims.embedding` therefore stay with the one
    /// provider that owns that column's vector space.
    provider: Option<Arc<dyn EmbeddingService>>,
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
            provider: None,
        }
    }

    /// An embedder that generates through `provider` instead of the OpenAI
    /// endpoint. **Test and development only** — compiled only under
    /// `cfg(test)` or the `test-support` feature, never in a deploy build.
    ///
    /// Exists so the MCP write paths that act on an embedding (the novelty
    /// gate's `ReturnExisting` / `near-duplicate` / pending-vector glue in
    /// `submit_claim` and `memorize`, and every inline embed-on-insert) can be
    /// driven end-to-end through a real `EpiGraphMcpFull` without a live API
    /// key. Everything that reaches the embedder — the inherent
    /// [`generate`](Self::generate) / [`generate_at_dim`](Self::generate_at_dim),
    /// [`embed_and_store`](Self::embed_and_store), the search helpers, and the
    /// [`EmbeddingService`] impl the novelty gate and `recall` consume — goes
    /// through the injected provider.
    ///
    /// Gated rather than public because `claims.embedding` is one ANN column
    /// with one owning vector space: a deploy wired to a different provider
    /// would write vectors from a second space into it and degrade recall with
    /// no error (the same invariant `epigraph-api`'s `bin/server.rs` enforces
    /// for the embedding job handler). The dimension checks in
    /// `generate`/`generate_at_dim` refuse a provider of the wrong width, but
    /// a width match does not prove a space match.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_provider(pool: PgPool, provider: Arc<dyn EmbeddingService>) -> Self {
        Self {
            api_key: None,
            pool,
            http: reqwest::Client::new(),
            provider: Some(provider),
        }
    }

    /// True when this embedder has no embedding source at all: no API key and
    /// no injected provider. Callers use it to skip an embedding path that
    /// would only fail (e.g. `find_workflow_hierarchical` falls straight to
    /// its ILIKE path). Only catches a `None` key; see
    /// [`embeddings_disabled`](Self::embeddings_disabled) for the strict form.
    #[must_use]
    pub const fn is_mock(&self) -> bool {
        self.api_key.is_none() && self.provider.is_none()
    }

    /// True when `generate`/`generate_at_dim` will reject every call: no
    /// injected provider and no usable API key. Mirrors their disabled-condition
    /// exactly — a `None`, empty, or literal `"mock"` key — so batch callers
    /// (e.g. `backfill_embeddings`) can fail loudly up front instead of
    /// churning a whole batch into all-failed. Stricter than
    /// [`is_mock`](Self::is_mock), which only catches the `None` case.
    #[must_use]
    pub fn embeddings_disabled(&self) -> bool {
        self.provider.is_none() && key_disabled(self.api_key.as_deref())
    }

    /// Generate an embedding vector without storing it.
    ///
    /// Returns the raw `Vec<f32>` from OpenAI. Callers can format it
    /// with `format_pgvector()` for SQL queries.
    pub async fn generate(&self, text: &str) -> Result<Vec<f32>, String> {
        if let Some(provider) = &self.provider {
            return provider_generate(provider.as_ref(), text, CLAIM_EMBEDDING_DIM).await;
        }
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
        if let Some(provider) = &self.provider {
            model_for_dim(dim)
                .ok_or_else(|| format!("unsupported centroid_dim: {dim} (must be 1536 or 3072)"))?;
            return provider_generate(provider.as_ref(), text, dim).await;
        }
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
    pub async fn search(
        &self,
        viewer: &epigraph_db::visibility::Viewer,
        query: &str,
        limit: i64,
    ) -> Result<Vec<(uuid::Uuid, f64)>, String> {
        self.search_scoped(viewer, query, limit, None, None).await
    }

    /// Embedding search over current claims with optional scope pushed into
    /// the query (see `ClaimRepository::search_by_embedding_scoped`): `tags`
    /// requires label containment, `agent_id` requires authorship, `None` does
    /// not restrict.
    pub async fn search_scoped(
        &self,
        viewer: &epigraph_db::visibility::Viewer,
        query: &str,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<uuid::Uuid>,
    ) -> Result<Vec<(uuid::Uuid, f64)>, String> {
        let embedding = self.generate(query).await?;

        let pgvec = format_pgvector(&embedding);
        let results = epigraph_db::ClaimRepository::search_by_embedding_scoped(
            &self.pool, viewer, &pgvec, limit, tags, agent_id,
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
        viewer: &epigraph_db::visibility::Viewer,
        query: &str,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<uuid::Uuid>,
    ) -> Result<Vec<epigraph_db::HybridHit>, String> {
        let embedding = self.generate(query).await?;
        let pgvec = format_pgvector(&embedding);
        epigraph_db::ClaimRepository::search_hybrid_scoped(
            &self.pool,
            viewer,
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

    /// **Unimplemented as of PR-06, deliberately.**
    ///
    /// `EmbeddingService` lives in `epigraph-interfaces`, which does not depend
    /// on `epigraph-db` and therefore cannot name a `Viewer`. PR-06 makes
    /// `EvidenceRepository::search_by_embedding` require one, so this method has
    /// no way to be tenancy-correct through this trait, and returning unfiltered
    /// rows through a trait object would be the exact fail-open the PR exists to
    /// close. It has no production caller — the MCP novelty and recall paths go
    /// through [`McpEmbedder::search_scoped`] and
    /// [`McpEmbedder::search_hybrid_scoped`], both of which take a viewer.
    ///
    /// Widening the trait is PR-09's call, when `mcp_viewer` gives every tool a
    /// viewer to hand down.
    async fn similar(
        &self,
        _embedding: &[f32],
        _k: usize,
        _min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        Err(EmbeddingError::DatabaseError(
            "McpEmbedder::similar is not tenancy-aware: EmbeddingService cannot carry a \
             Viewer. Use McpEmbedder::search_scoped or ::search_hybrid_scoped."
                .to_string(),
        ))
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

    /// Healthy when an API key is configured or a provider is injected;
    /// unavailable in mock mode.
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

/// Generate through an injected provider, refusing any vector that is not
/// `dim`-dimensional.
///
/// Checked twice — the provider's declared width before the call, the
/// returned vector's length after — because the caller is about to store or
/// compare it against a fixed-width column: a 1536-d vector answered to a
/// 3072-d request (`recall_with_context` at `centroid_dim=3072`) would be
/// compared against `embedding_3072` and fail, or worse, be written into the
/// wrong column. The input is clipped exactly as the OpenAI path clips it, so
/// the provider sees what the production endpoint would.
async fn provider_generate(
    provider: &dyn EmbeddingService,
    text: &str,
    dim: u32,
) -> Result<Vec<f32>, String> {
    let want = dim as usize;
    if provider.dimension() != want {
        return Err(format!(
            "injected embedding provider produces {}-d vectors; cannot serve a {dim}-d request",
            provider.dimension()
        ));
    }
    let truncated = truncate_embedding_input(text);
    let vector = provider
        .generate(&truncated)
        .await
        .map_err(|e| e.to_string())?;
    if vector.len() != want {
        return Err(format!(
            "injected embedding provider returned a {}-d vector for a {dim}-d request",
            vector.len()
        ));
    }
    Ok(vector)
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

    // ── injected provider (`with_provider`) ──
    //
    // None of these touch the database: the pool is lazy and never connects,
    // because `generate`/`generate_at_dim` and the two guards read no rows.

    use super::McpEmbedder;
    use epigraph_embeddings::{config::EmbeddingConfig, EmbeddingService, MockProvider};
    use std::sync::Arc;

    fn lazy_pool() -> sqlx::PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .expect("a lazy pool never connects at construction")
    }

    fn mock(dim: usize) -> Arc<dyn EmbeddingService> {
        Arc::new(MockProvider::new(EmbeddingConfig::openai(dim)))
    }

    // The two guards callers consult before an embedding path must agree with
    // what `generate` will actually do. Before the provider existed both keyed
    // on the API key alone; with a provider injected, `generate` succeeds, so
    // reporting "disabled" would make `backfill_embeddings` refuse to run and
    // `find_workflow_hierarchical` skip its embedding leg for no reason.
    #[tokio::test]
    async fn an_injected_provider_clears_both_disabled_guards() {
        let keyless = McpEmbedder::new(lazy_pool(), None);
        assert!(keyless.is_mock(), "no key, no provider => mock");
        assert!(
            keyless.embeddings_disabled(),
            "no key, no provider => disabled"
        );

        let injected = McpEmbedder::with_provider(lazy_pool(), mock(1536));
        assert!(!injected.is_mock(), "a provider is an embedding source");
        assert!(
            !injected.embeddings_disabled(),
            "a provider makes generate succeed, so embeddings are not disabled"
        );
        assert!(
            EmbeddingService::health_check(&injected).await.is_ok(),
            "health_check follows is_mock"
        );
    }

    // Every path into the embedder must reach the provider: the inherent
    // `generate` (embed_and_store, search) AND the `EmbeddingService` impl
    // (the novelty gate and `recall` consume `&dyn EmbeddingService`).
    #[tokio::test]
    async fn generate_and_the_trait_impl_both_delegate_to_the_provider() {
        let provider = mock(1536);
        let embedder = McpEmbedder::with_provider(lazy_pool(), Arc::clone(&provider));
        let text = "The Earth orbits the Sun.";
        let expected = provider.generate(text).await.expect("mock generate");

        let inherent = embedder.generate(text).await.expect("inherent generate");
        assert_eq!(
            inherent, expected,
            "inherent generate must use the provider"
        );

        let via_trait = EmbeddingService::generate(&embedder, text)
            .await
            .expect("trait generate");
        assert_eq!(via_trait, expected, "the trait impl must use the provider");
    }

    // A 1536-d provider must not answer a 3072-d request: `recall_with_context`
    // at centroid_dim=3072 compares the result against `embedding_3072`.
    #[tokio::test]
    async fn generate_at_dim_refuses_a_width_the_provider_does_not_produce() {
        let embedder = McpEmbedder::with_provider(lazy_pool(), mock(1536));

        let ok = embedder
            .generate_at_dim("some query", 1536)
            .await
            .expect("matching width is served");
        assert_eq!(ok.len(), 1536);

        let err = embedder
            .generate_at_dim("some query", 3072)
            .await
            .expect_err("a 1536-d provider must refuse a 3072-d request");
        assert!(
            err.contains("1536-d"),
            "error names the provider width: {err}"
        );

        let err = embedder
            .generate_at_dim("some query", 1024)
            .await
            .expect_err("an unsupported dim stays unsupported with a provider");
        assert!(err.contains("unsupported centroid_dim"), "got: {err}");
    }

    // `generate` serves the 1536-d `claims.embedding` column, so a provider of
    // any other width is refused rather than handed to `store_embedding`.
    #[tokio::test]
    async fn generate_refuses_a_provider_whose_width_is_not_the_claim_column() {
        let embedder = McpEmbedder::with_provider(lazy_pool(), mock(64));
        let err = embedder
            .generate("some claim")
            .await
            .expect_err("a 64-d provider cannot feed claims.embedding");
        assert!(
            err.contains("64-d"),
            "error names the provider width: {err}"
        );
    }
}
