//! Embedding provider implementations
//!
//! This module contains various embedding provider backends:
//! - `MockProvider`: For testing
//! - `OpenAiProvider`: `OpenAI` API (requires `openai` feature)
//! - `LocalProvider`: Local model inference (requires `local` feature)

mod jina;
mod local;
mod mock;
mod openai;

pub use jina::JinaProvider;
pub use local::LocalProvider;
pub use mock::MockMultimodalProvider;
pub use mock::MockProvider;
pub use mock::MockProviderWithFallback;
pub use openai::OpenAiProvider;
