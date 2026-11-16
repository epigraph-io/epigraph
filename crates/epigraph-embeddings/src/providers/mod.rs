//! Embedding provider implementations
//!
//! This module contains various embedding provider backends:
//! - `MockProvider`: For testing
//! - `OpenAiProvider`: `OpenAI` API (requires `openai` feature)
//! - `JinaProvider`: Jina multimodal API (requires `jina` feature)

mod jina;
mod mock;
mod openai;

pub use jina::JinaProvider;
pub use mock::MockMultimodalProvider;
pub use mock::MockProvider;
pub use mock::MockProviderWithFallback;
pub use openai::{OpenAiProvider, RetryPolicy};
