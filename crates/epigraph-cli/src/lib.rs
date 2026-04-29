pub mod enrichment;

#[cfg(feature = "db")]
use sqlx::PgPool;
use std::sync::Arc;

/// Connect to postgres via DATABASE_URL environment variable.
#[cfg(feature = "db")]
pub async fn db_connect() -> Result<PgPool, Box<dyn std::error::Error>> {
    let url = std::env::var("DATABASE_URL").map_err(|_| {
        "DATABASE_URL not set — set it to postgresql://epigraph:epigraph@127.0.0.1:5432/epigraph"
    })?;
    Ok(PgPool::connect(&url).await?)
}

/// Create embedding service from OPENAI_API_KEY.
/// Returns None if key is not set (embeddings will be skipped).
pub fn embedding_service() -> Option<Arc<dyn epigraph_embeddings::EmbeddingService>> {
    let api_key = std::env::var("OPENAI_API_KEY").ok()?;
    let config = epigraph_embeddings::EmbeddingConfig::openai(1536);
    let provider = epigraph_embeddings::OpenAiProvider::new(config, api_key).ok()?;
    Some(Arc::new(provider) as Arc<dyn epigraph_embeddings::EmbeddingService>)
}
