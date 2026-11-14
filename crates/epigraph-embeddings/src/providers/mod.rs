//! Embedding provider implementations
//!
//! This module contains various embedding provider backends:
//! - `MockProvider`: For testing
//! - `OpenAiProvider`: `OpenAI` API (requires `openai` feature)
//! - `LocalProvider`: a deterministic hash stub, NOT model inference. It is
//!   compiled unconditionally (no feature gates it) and its vectors carry no
//!   semantic meaning, so nothing should store them in the `embedding` column.

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
