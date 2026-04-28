use async_trait::async_trait;
use epigraph_embeddings::{
    service::{SimilarClaim, TokenUsage},
    EmbeddingError, EmbeddingService,
};
use sqlx::PgPool;

pub struct McpEmbedder {
    api_key: Option<String>,
    pool: PgPool,
    http: reqwest::Client,
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

        generate_openai_embedding(&self.http, api_key, text).await
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
        match epigraph_db::EvidenceRepository::store_embedding(&self.pool, claim_id.into(), &pgvec)
            .await
        {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!("embedding store failed: {e}");
                false
            }
        }
    }

    /// Search by embedding similarity. Returns (claim_id, similarity) pairs.
    pub async fn search(&self, query: &str, limit: i64) -> Result<Vec<(uuid::Uuid, f64)>, String> {
        let embedding = self.generate(query).await?;

        let pgvec = format_pgvector(&embedding);
        let results =
            epigraph_db::EvidenceRepository::search_by_embedding(&self.pool, &pgvec, limit)
                .await
                .map_err(|e| e.to_string())?;

        Ok(results
            .into_iter()
            .map(|r| (r.claim_id, r.similarity))
            .collect())
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

    /// Store an embedding for a claim via `EvidenceRepository::store_embedding`.
    ///
    /// `McpEmbedder` stores embeddings against *evidence* rows (keyed by claim).
    /// Here we delegate to that path: format the vector, then call the DB method.
    async fn store(&self, claim_id: uuid::Uuid, embedding: &[f32]) -> Result<(), EmbeddingError> {
        let pgvec = format_pgvector(embedding);
        epigraph_db::EvidenceRepository::store_embedding(&self.pool, claim_id.into(), &pgvec)
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

/// Format a vector as a pgvector string literal: `"[0.1,0.2,...]"`.
///
/// Public so callers can format a cached `Vec<f32>` for direct SQL use
/// without going through the embedder.
pub fn format_pgvector(vec: &[f32]) -> String {
    let inner: Vec<String> = vec.iter().map(|v| format!("{v}")).collect();
    format!("[{}]", inner.join(","))
}

async fn generate_openai_embedding(
    http: &reqwest::Client,
    api_key: &str,
    text: &str,
) -> Result<Vec<f32>, String> {
    let resp = http
        .post("https://api.openai.com/v1/embeddings")
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&serde_json::json!({
            "model": "text-embedding-3-small",
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
