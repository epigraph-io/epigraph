// Embeddings crate: allow pedantic/nursery lints that are non-critical in this crate.
// - missing_errors_doc: doc coverage will be improved in a follow-up
// - significant_drop_tightening: lock usage patterns are intentional
// - cast_possible_truncation/wrap: embedding dimension sizes are always small
// - cast_precision_loss: acceptable for embedding arithmetic
#![allow(
    clippy::missing_errors_doc,
    clippy::significant_drop_tightening,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
//! `EpiGraph` Embeddings: Vector Embedding Service for Semantic Similarity
//!
//! This crate provides vector embedding generation and storage for enabling
//! semantic similarity search across claims in the epistemic knowledge graph.
//!
//! # Design Philosophy
//!
//! Embeddings bridge the gap between symbolic reasoning (claims, evidence) and
//! semantic understanding. By representing claims as dense vectors, we enable:
//! - Finding semantically similar claims regardless of exact wording
//! - Clustering related concepts in the knowledge graph
//! - Detecting potential contradictions through vector opposition
//!
//! # Architecture
//!
//! The embedding service is designed with:
//! - **Provider abstraction**: Support for `OpenAI`, local models, or custom backends
//! - **Caching**: Prevent duplicate API calls for identical text
//! - **Rate limiting**: Respect API rate limits to prevent throttling
//! - **Fallback**: Graceful degradation to local models when API fails
//! - **Normalization**: All embeddings are unit vectors for consistent similarity
//!
//! # Core Types
//!
//! - [`EmbeddingService`]: Main trait for embedding generation and storage
//! - [`EmbeddingConfig`]: Configuration for embedding dimensions and providers
//! - [`SimilarClaim`]: Result type for similarity searches
//! - [`EmbeddingError`]: Error types for embedding operations
//!
//! # Example
//!
//! ```rust,ignore
//! use epigraph_embeddings::{EmbeddingService, EmbeddingConfig, OpenAiProvider};
//!
//! let config = EmbeddingConfig::openai(1536);
//! let service = OpenAiProvider::new(config, api_key)?;
//!
//! // Generate embedding for a claim
//! let embedding = service.generate("The Earth orbits the Sun").await?;
//!
//! // Find similar claims
//! let similar = service.similar(&embedding, 10, 0.8).await?;
//! ```

pub mod cache;
pub mod config;
pub mod errors;
pub mod normalizer;
pub mod providers;
pub mod rate_limiter;
#[cfg(feature = "db")]
pub mod repository;
pub mod service;
pub mod tokenizer;

// Re-export primary types at crate root
pub use config::EmbeddingConfig;
pub use errors::EmbeddingError;
pub use service::{
    EmbeddingService, MultimodalEmbeddingService, MultimodalInput, SimilarClaim, TokenUsage,
};

// Re-export provider implementations
pub use providers::{
    JinaProvider, LocalProvider, MockMultimodalProvider, MockProvider, OpenAiProvider,
};

// Re-export utility types
pub use cache::EmbeddingCache;
pub use normalizer::Normalizer;
pub use rate_limiter::RateLimiter;
#[cfg(feature = "db")]
pub use repository::EmbeddingRepository;
pub use tokenizer::Tokenizer;
