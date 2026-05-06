//! Error type for the rerank library.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RerankError {
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("LLM client: {0}")]
    Llm(String),
    #[error("config: {0}")]
    Config(String),
    #[error("other: {0}")]
    Other(String),
}
