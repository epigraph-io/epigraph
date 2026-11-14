use async_trait::async_trait;
use epigraph_embeddings::{service::TokenUsage, EmbeddingError, EmbeddingService};
use sqlx::PgPool;

/// Per-leg candidate pool size before RRF fusion in hybrid recall.
pub const HYBRID_CANDIDATE_POOL: i64 = 50;
/// Reciprocal Rank Fusion constant `k` (canonical default 60).
pub const HYBRID_RRF_K: i64 = 60;

/// How this embedder is allowed to run its `UPDATE claims SET embedding`.
///
/// # Why the store path is a declared property and not a pool
///
/// `store_embedding(&self.pool, …)` was the release gate this type carried into
/// every one of its nine callers. `claims_tenancy`'s
/// `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))` refuses that
/// UPDATE on an unstamped application session, the refusal is swallowed by design
/// (embedding is best-effort), and the tool still reports success — so on a
/// cleanly-migrated schema `store_workflow`, `ingest_workflow`,
/// `improve_workflow_hierarchy`, `add_step`, `consolidate_claims` and both
/// `ingest_document` paths would land `embedding = NULL` with **no error
/// anywhere**, visible only as CLAUDE.md's `live_missing` climbing.
///
/// Fixing that at the six call sites would have left the type itself still able
/// to do the wrong thing, and PR #494 had already shown what happens then: it
/// converted `submit_claim` and `memorize` and the other seven callers kept the
/// defect. So the capability is declared once, here, and the variant that can
/// silently write unstamped does not exist.
///
/// [`Undeclared`](Self::Undeclared) is the DEFAULT, and it REFUSES rather than
/// falling back — hard constraint #5 of the write-path brief: a refusal must stay
/// loud, because a fallback to the unstamped pool is how a `42501` becomes a
/// silent orphan.
///
/// # MEASURED, end to end, with the real binary as `epigraph_app`
///
/// `store_workflow` (4 executor-authored claims) + `add_step` (1), on the
/// prod-faithful schema configuration:
///
/// | binary | outcome |
/// |---|---|
/// | this code | `all_claims=5 all_embedded=5`, no warning in the log |
/// | one hunk reverted — `main` builds the embedder WITHOUT `with_scoped_pool` | `all_claims=5 all_embedded=0`, five `tenancy.scoped_write` ERRORs |
/// | restored | `all_claims=5 all_embedded=5` again |
///
/// The mutation is the proof that the declaration is what stores the vectors, and
/// it is run on the PROD-FAITHFUL configuration deliberately. On the clean
/// configuration these tools never reach the embed at all — the executor's own
/// unstamped `claims` INSERT is refused first (the D5 residual registered in
/// `tests/residual_unstamped_writes.rs`), so a clean-schema arm would report
/// `all_claims=0` and discriminate nothing. This is therefore the one
/// configuration in which the seven executor-path callers' embed is observable,
/// and the arm that makes it non-vacuous is the reverted hunk rather than the
/// policies.
pub enum StorePath {
    /// No store capability was declared. Every store attempt is refused with a
    /// named cause. This is what `McpEmbedder::new` yields, so a new construction
    /// site cannot acquire an unstamped writer by omission.
    Undeclared,
    /// Stamp a connection from the CLAIM's author and store there. The
    /// production arm: `main` attaches the same [`epigraph_db::ScopedPool`] the
    /// write path uses.
    AuthorStamped(epigraph_db::ScopedPool),
    /// `self.pool` is already privileged — a `MaintenancePool`, whose role
    /// bypasses RLS — so there is no stamp to take and none is needed. Carries
    /// the caller's reason so the exemption is auditable rather than implicit;
    /// `epigraph-cli/src/bin/ingest_document.rs` is the one production user, and
    /// its own comment records that its whole ingest deliberately runs on the
    /// maintenance pool.
    PrivilegedPool(&'static str),
}

/// A replacement for the embedding provider behind [`McpEmbedder::generate`]:
/// given the caller's input text, the vector to store. See
/// [`McpEmbedder::with_generator`].
pub type EmbeddingGenerator =
    std::sync::Arc<dyn Fn(&str) -> Result<Vec<f32>, String> + Send + Sync>;

/// Generation for [`McpEmbedder`] is `epigraph_embeddings::OpenAiProvider`, the
/// same client the HTTP API embeds with, so a claim gets the same truncation,
/// bounded retry and normalization whichever surface wrote it (backlog
/// ef32cdeb: the hand-rolled POST this replaced clipped long input while the
/// API refused it, so one long claim was embedded on MCP and NULL over HTTP).
/// One provider per model, built only when a usable key is configured; no mock
/// fallback, so a keyless embedder still refuses every `generate`.
struct OpenAiModels {
    small_1536: epigraph_embeddings::OpenAiProvider,
    large_3072: epigraph_embeddings::OpenAiProvider,
}

impl OpenAiModels {
    fn new(api_key: &str) -> Result<Self, EmbeddingError> {
        Ok(Self {
            small_1536: openai_provider(api_key, 1536)?,
            large_3072: openai_provider(api_key, 3072)?,
        })
    }

    fn at_dim(&self, dim: u32) -> Option<&epigraph_embeddings::OpenAiProvider> {
        match dim {
            1536 => Some(&self.small_1536),
            3072 => Some(&self.large_3072),
            _ => None,
        }
    }
}

/// An `OpenAiProvider` for the model [`model_for_dim`] names at `dim`.
///
/// The response cache is OFF: the provider's default keeps up to 10 000
/// vectors (about 60 MB at 1536 dims) per instance, and this server ran
/// without one before. Rate limiting and retry are the provider's defaults.
fn openai_provider(
    api_key: &str,
    dim: u32,
) -> Result<epigraph_embeddings::OpenAiProvider, EmbeddingError> {
    let model = model_for_dim(dim)
        .ok_or_else(|| EmbeddingError::ConfigError(format!("no OpenAI model for dim {dim}")))?;
    let mut config = epigraph_embeddings::EmbeddingConfig::openai(dim as usize).with_cache(false);
    config.provider = epigraph_embeddings::config::ProviderConfig::OpenAi {
        model: model.to_string(),
        api_base_url: None,
    };
    epigraph_embeddings::OpenAiProvider::new(config, api_key.to_string())
}

pub struct McpEmbedder {
    api_key: Option<String>,
    pool: PgPool,
    store_path: StorePath,
    models: Option<OpenAiModels>,
    generator: Option<EmbeddingGenerator>,
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
    /// Build an embedder with **no store capability** ([`StorePath::Undeclared`]).
    ///
    /// Generation and search work; every store is refused with a named cause
    /// until one of [`with_scoped_pool`](Self::with_scoped_pool) or
    /// [`on_a_privileged_pool`](Self::on_a_privileged_pool) is called. That
    /// default is deliberate — see [`StorePath`] — and it is why the ~25 test
    /// fixtures that call `new(pool, None)` needed no edit: a mock embedder has
    /// no API key, so `generate` refuses before any store is attempted.
    #[must_use]
    pub fn new(pool: PgPool, api_key: Option<String>) -> Self {
        let models = api_key
            .as_deref()
            .filter(|k| !key_disabled(Some(k)))
            .and_then(|k| match OpenAiModels::new(k) {
                Ok(m) => Some(m),
                Err(e) => {
                    tracing::error!(error = %e, "OpenAI embedding provider init failed; embeddings disabled");
                    None
                }
            });
        Self {
            api_key,
            pool,
            store_path: StorePath::Undeclared,
            models,
            generator: None,
        }
    }

    /// Replace the embedding provider behind [`generate`](Self::generate) with
    /// `generator`, whatever the API key: no request leaves the process.
    ///
    /// The seam an integration test needs to observe a tool's embedding calls
    /// (how many, on which text) and to store real vectors without a provider.
    /// Without it a keyless test embedder refuses every `generate`, so "this
    /// call sent no text to the provider" and "this call embedded every claim"
    /// are indistinguishable. Public rather than `#[cfg(test)]` because the
    /// callers are `tests/` integration tests of this and other crates; no
    /// production construction site calls it. [`generate_at_dim`](Self::generate_at_dim)
    /// is not affected.
    #[must_use]
    pub fn with_generator(mut self, generator: EmbeddingGenerator) -> Self {
        self.generator = Some(generator);
        self
    }

    /// Declare that stores run on a connection stamped from the claim's author,
    /// drawn from `scoped`.
    ///
    /// The production wiring: `main` passes the same `ScopedPool` it gives
    /// `EpiGraphMcpFull::with_scoped_pool`, so the embedder and the write path
    /// stamp through one pool. The two are attached at the same places on purpose
    /// — `crates/epigraph-mcp/tests/residual_unstamped_writes.rs::
    /// every_scoped_server_construction_also_scopes_its_embedder` is the ratchet
    /// that keeps them from drifting, because a server with a `ScopedPool` and an
    /// embedder without one would write claims correctly and embed none of them.
    #[must_use]
    pub fn with_scoped_pool(mut self, scoped: epigraph_db::ScopedPool) -> Self {
        self.store_path = StorePath::AuthorStamped(scoped);
        self
    }

    /// Declare that `self.pool` is already privileged, so stores may run on it
    /// directly. `reason` is recorded in the refusal-free path's log line.
    ///
    /// The only sanctioned use is an embedder over a `MaintenancePool`, whose
    /// role holds `BYPASSRLS`: there `epigraph_bypass()` is true, the tier-A
    /// `WITH CHECK` admits the UPDATE, and a stamp would be meaningless. Calling
    /// this over an ORDINARY application pool re-creates exactly the defect
    /// [`StorePath`] documents, silently — do not.
    #[must_use]
    pub fn on_a_privileged_pool(mut self, reason: &'static str) -> Self {
        self.store_path = StorePath::PrivilegedPool(reason);
        self
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
        self.generator.is_none() && key_disabled(self.api_key.as_deref())
    }

    /// Generate an embedding vector without storing it.
    ///
    /// `text-embedding-3-small` through `OpenAiProvider`: an input over the
    /// model's token limit is clipped (the stored claim content stays full
    /// verbatim; only the embedding input is cut), and a 429 / 5xx is retried
    /// within a bounded budget. Callers can format the vector with
    /// `epigraph_db::pgvector_literal()` for SQL.
    pub async fn generate(&self, text: &str) -> Result<Vec<f32>, String> {
        if let Some(generator) = &self.generator {
            return generator(text);
        }
        self.generate_with(text, 1536).await
    }

    /// Generate an embedding at the requested dimension by selecting the right
    /// OpenAI model. Returns the raw `Vec<f32>`; caller formats with `epigraph_db::pgvector_literal`.
    pub async fn generate_at_dim(&self, text: &str, dim: u32) -> Result<Vec<f32>, String> {
        self.generate_with(text, dim).await
    }

    async fn generate_with(&self, text: &str, dim: u32) -> Result<Vec<f32>, String> {
        let models = self
            .models
            .as_ref()
            .ok_or_else(|| "embeddings disabled (no API key)".to_string())?;
        let provider = models
            .at_dim(dim)
            .ok_or_else(|| format!("unsupported centroid_dim: {dim} (must be 1536 or 3072)"))?;
        EmbeddingService::generate(provider, text)
            .await
            .map_err(|e| format!("OpenAI embedding failed: {e}"))
    }

    /// Store an already-formatted pgvector on `claims.embedding`, through this
    /// embedder's declared [`StorePath`].
    ///
    /// The single store mechanism behind every caller of this type — nine of them
    /// at the time of writing — and the reason the conversion is a type change
    /// rather than six call-site edits.
    ///
    /// # The author is read from the ROW, not supplied by the caller
    ///
    /// `claims_tenancy`'s `WITH CHECK` asks about the row's `owner_group_id`, and
    /// `ClaimRepository::default_decl_for_author` sets that from the CLAIM
    /// AUTHOR's personal group. The author is therefore the only viewer whose
    /// writable set can satisfy the check, and it is NOT `server.agent_id()` for
    /// most of this type's callers: `epigraph_ingest_executor`'s
    /// `execute_workflow_ingest_plan`, `add_step` and `improve_workflow_hierarchy`
    /// all author as the workflow-ingest system agent
    /// (`get_or_create_system_agent`). A signature that took the
    /// author from the caller would have let `store_workflow` pass the MCP
    /// server's agent, produce a session stamped with the WRONG writable group,
    /// and be refused exactly as before — silently, because the embed is
    /// best-effort. That is a worse outcome than the current defect, because it
    /// looks converted.
    ///
    /// The lookup is `ClaimRepository::get_agent_id` under a viewer resolved over
    /// the NIL principal, i.e. the public corpus. That read WORKS on an unstamped
    /// application session, and the reason is specific rather than lucky:
    /// migration 077's tier-A USING clause is
    /// `bypass OR definer_bypass OR visibility = 'public' OR owner_group_id = ANY(session_groups)`,
    /// and every claim these paths write is `visibility = 'public'` by
    /// `default_decl_for_author`. (Contrast `groups_tenancy`, whose USING has no
    /// public arm — which is why hard constraint #3 forbids read-then-mint helpers
    /// on this connection.) A group-private claim therefore yields `None` here and
    /// the store is REFUSED with a named cause rather than attempted with a viewer
    /// that cannot satisfy the check.
    ///
    /// So this path is for a PUBLIC claim of unknown author. A caller that knows
    /// the author of a team or private claim stores through
    /// `claim_helper::store_embedding_author_stamped` (or its `_with_grant`
    /// form) instead: `submit_claim`, `memorize`, workflow ingest, both document
    /// walks and `consolidate_claims` do.
    ///
    /// # Errors
    /// `Err` when no vector could be stored and the cause is not "the row did not
    /// match": an undeclared store path, an unresolvable author, a failed stamp,
    /// or a database error. `Ok(false)` means the statement ran and matched no row
    /// (claim missing, sealed, superseded, or not writable by its author).
    pub async fn store_vector(&self, claim_id: uuid::Uuid, pgvec: &str) -> Result<bool, String> {
        match &self.store_path {
            StorePath::Undeclared => {
                tracing::error!(
                    target: "tenancy.scoped_write",
                    claim_id = %claim_id,
                    "embedding store refused: this McpEmbedder declared no StorePath, so there \
                     is no connection it may run `UPDATE claims SET embedding` on. Refusing \
                     rather than using the plain pool, where migration 077's claims_tenancy \
                     WITH CHECK refuses the UPDATE and the swallowed failure leaves the claim \
                     invisible to semantic recall with no error anywhere. Construct the embedder \
                     with McpEmbedder::with_scoped_pool."
                );
                Err("McpEmbedder has no declared StorePath; nothing was stored".to_string())
            }
            StorePath::PrivilegedPool(reason) => {
                tracing::debug!(
                    claim_id = %claim_id,
                    reason = reason,
                    "storing the embedding directly on a privileged pool"
                );
                epigraph_db::ClaimRepository::store_embedding(&self.pool, claim_id, pgvec)
                    .await
                    .map_err(|e| e.to_string())
            }
            StorePath::AuthorStamped(scoped) => {
                let public =
                    epigraph_db::visibility::Viewer::resolve(&self.pool, uuid::Uuid::nil())
                        .await
                        .map_err(|e| {
                            format!("could not resolve a public viewer to read the author: {e}")
                        })?;
                let author =
                    epigraph_db::ClaimRepository::get_agent_id(&self.pool, &public, claim_id)
                        .await
                        .map_err(|e| format!("could not read claim {claim_id}'s author: {e}"))?
                        .ok_or_else(|| {
                            format!(
                        "claim {claim_id} is not readable as public, so its author — the only \
                         viewer whose writable set can satisfy claims_tenancy's WITH CHECK on \
                         this row — cannot be resolved. Nothing was stored."
                    )
                        })?;
                crate::claim_helper::store_embedding_author_stamped(
                    Some(scoped),
                    &self.pool,
                    author,
                    claim_id,
                    pgvec,
                    "embedder",
                )
                .await
            }
        }
    }

    /// Generate embedding and store it for a claim. Returns true if embedding succeeded.
    ///
    /// Best-effort by contract (CLAUDE.md's embedding policy): every failure is
    /// warned and reported as `false`, never returned, because the claim is
    /// already committed. The store half goes through
    /// [`store_vector`](Self::store_vector), so this function can no longer reach
    /// the unstamped pool.
    pub async fn embed_and_store(&self, claim_id: uuid::Uuid, text: &str) -> bool {
        let embedding = match self.generate(text).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("embedding failed (claim still stored): {e}");
                return false;
            }
        };

        let pgvec = epigraph_db::pgvector_literal(&embedding);
        match self.store_vector(claim_id, &pgvec).await {
            Ok(true) => true,
            Ok(false) => {
                tracing::warn!(
                    claim_id = %claim_id,
                    "embedding store affected 0 rows (claim missing, sealed, superseded, or not \
                     writable by its author's viewer)"
                );
                false
            }
            Err(e) => {
                tracing::warn!(claim_id = %claim_id, "embedding store failed: {e}");
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

    /// The connection a search runs on, taken AFTER the embedding round trip:
    /// a read stamped with `viewer` on the declared [`StorePath::AuthorStamped`]
    /// pool (the server's own `ScopedPool`), so row security agrees with the
    /// search's in-query predicate and a member finds its own group-private
    /// claims. On an unstamped application session that policy admits public
    /// rows only. A [`StorePath::PrivilegedPool`] embedder reads its own pool,
    /// which bypasses row security by declaration. An undeclared embedder
    /// REFUSES, as its stores do, rather than reading unstamped.
    async fn search_conn(
        &self,
        viewer: &epigraph_db::visibility::Viewer,
    ) -> Result<SearchConn<'_>, String> {
        match &self.store_path {
            StorePath::AuthorStamped(scoped) => scoped
                .read_as(viewer)
                .await
                .map(SearchConn::Stamped)
                .map_err(|e| format!("search: could not acquire a viewer-stamped connection: {e}")),
            StorePath::PrivilegedPool(_) => self
                .pool
                .acquire()
                .await
                .map(SearchConn::Privileged)
                .map_err(|e| format!("search: could not acquire a connection: {e}")),
            StorePath::Undeclared => Err("search refused: this embedder was built without a \
                 ScopedPool (McpEmbedder::with_scoped_pool), so the search cannot be stamped \
                 with the caller's tenancy context and would see public rows only"
                .to_string()),
        }
    }

    /// Embedding search over current claims with optional scope pushed into
    /// the query (see `ClaimRepository::search_by_embedding_scoped`): `tags`
    /// requires label containment, `agent_id` requires authorship, `None` does
    /// not restrict. Reads as `viewer` (see `search_conn`).
    pub async fn search_scoped(
        &self,
        viewer: &epigraph_db::visibility::Viewer,
        query: &str,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<uuid::Uuid>,
    ) -> Result<Vec<(uuid::Uuid, f64)>, String> {
        let embedding = self.generate(query).await?;

        let pgvec = epigraph_db::pgvector_literal(&embedding);
        let mut conn = self.search_conn(viewer).await?;
        let results = epigraph_db::ClaimRepository::search_by_embedding_scoped(
            &mut *conn, viewer, &pgvec, limit, tags, agent_id,
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
    /// Reads as `viewer` (see `search_conn`).
    pub async fn search_hybrid_scoped(
        &self,
        viewer: &epigraph_db::visibility::Viewer,
        query: &str,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<uuid::Uuid>,
    ) -> Result<Vec<epigraph_db::HybridHit>, String> {
        let embedding = self.generate(query).await?;
        let pgvec = epigraph_db::pgvector_literal(&embedding);
        let mut conn = self.search_conn(viewer).await?;
        epigraph_db::ClaimRepository::search_hybrid_scoped_since_in_theme_conn(
            &mut conn,
            viewer,
            &pgvec,
            query,
            HYBRID_CANDIDATE_POOL,
            HYBRID_RRF_K,
            limit,
            0,
            tags,
            agent_id,
            None,
            None,
        )
        .await
        .map_err(|e| e.to_string())
    }
}

/// The connection [`McpEmbedder::search_conn`] hands a search.
enum SearchConn<'a> {
    Stamped(epigraph_db::ScopedRead<'a>),
    Privileged(sqlx::pool::PoolConnection<sqlx::Postgres>),
}

impl std::ops::Deref for SearchConn<'_> {
    type Target = sqlx::PgConnection;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Stamped(r) => r,
            Self::Privileged(c) => c,
        }
    }
}

impl std::ops::DerefMut for SearchConn<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Stamped(r) => r,
            Self::Privileged(c) => c,
        }
    }
}

// ---------------------------------------------------------------------------
// EmbeddingService implementation
// ---------------------------------------------------------------------------
//
// `McpEmbedder` generates through `epigraph_embeddings::OpenAiProvider`
// (text-embedding-3-small, 1536d, unless a test generator replaces it).
// This impl exposes it through the canonical trait so callers — including the
// library `recall` function in `epigraph-engine` — only need `&dyn EmbeddingService`.
//
// Token tracking has no natural delegation in `McpEmbedder` and returns honest
// no-op values rather than `unimplemented!()` panics. Storing goes through the
// inherent `store_vector` / `embed_and_store` (the trait has no store method).

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

    // Truncation and retry are `OpenAiProvider`'s now, and are measured against
    // an HTTP fixture in `epigraph-embeddings/tests/openai_provider_http.rs`.
    // What is left here is the routing: which provider each dim reaches.
    #[test]
    fn each_supported_dim_reaches_a_provider_of_that_dim() {
        use epigraph_embeddings::EmbeddingService as _;
        let models = super::OpenAiModels::new("sk-test-not-sent").expect("providers build");
        assert_eq!(models.at_dim(1536).map(|p| p.dimension()), Some(1536));
        assert_eq!(models.at_dim(3072).map(|p| p.dimension()), Some(3072));
        assert!(models.at_dim(1024).is_none());
    }

    // No mock fallback: a keyless embedder refuses at both dims, before any
    // request, with the message `embeddings_disabled` callers grep for.
    #[tokio::test]
    async fn a_keyless_embedder_refuses_instead_of_falling_back() {
        let pool =
            sqlx::PgPool::connect_lazy("postgres://unused@127.0.0.1:1/unused").expect("lazy pool");
        for key in [None, Some(String::new()), Some("mock".to_string())] {
            let embedder = super::McpEmbedder::new(pool.clone(), key.clone());
            assert!(embedder.embeddings_disabled(), "{key:?} must disable");
            for dim in [1536, 3072] {
                let err = embedder
                    .generate_at_dim("text", dim)
                    .await
                    .expect_err("a keyless embedder must refuse");
                assert!(err.contains("embeddings disabled"), "{key:?}@{dim}: {err}");
            }
        }
    }
}
