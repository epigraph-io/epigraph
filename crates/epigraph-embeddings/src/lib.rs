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
//! This crate provides vector embedding generation for semantic similarity
//! search across claims in the epistemic knowledge graph. Vectors are stored and
//! searched through `epigraph-db`, which applies the seal, `is_current` and
//! tenancy rules this crate cannot see.
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
//! - **Provider abstraction**: `OpenAI` and Jina backends, plus a deterministic
//!   `MockProvider` for tests and keyless development (there is no local model)
//! - **Caching**: Prevent duplicate API calls for identical text
//! - **Rate limiting**: Respect API rate limits to prevent throttling
//! - **Normalization**: All embeddings are unit vectors for consistent similarity
//!
//! # Core Types
//!
//! - [`EmbeddingService`]: Main trait for embedding generation
//! - [`EmbeddingConfig`]: Configuration for embedding dimensions and providers
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
//! ```

pub mod cache;
pub mod config;
pub mod errors;
pub mod normalizer;
pub mod providers;
pub mod rate_limiter;
pub mod service;
pub mod tokenizer;

// Re-export primary types at crate root
pub use config::EmbeddingConfig;
pub use errors::EmbeddingError;
pub use service::{EmbeddingService, MultimodalEmbeddingService, MultimodalInput, TokenUsage};

// Re-export provider implementations
pub use providers::{
    JinaProvider, MockMultimodalProvider, MockProvider, OpenAiProvider, RetryPolicy,
};

// Re-export utility types
pub use cache::EmbeddingCache;
pub use normalizer::Normalizer;
pub use rate_limiter::RateLimiter;
pub use tokenizer::Tokenizer;
