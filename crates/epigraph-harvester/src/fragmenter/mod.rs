//! Document fragmentation for processing
//!
//! This module provides tools to split large documents into manageable fragments
//! for processing by the harvester. Each fragment is:
//! - Small enough to fit in LLM context windows (~1000-2000 tokens)
//! - Semantically coherent (respects paragraph/sentence boundaries)
//! - Content-addressed via BLAKE3 hash
//! - Includes overlap to preserve context across boundaries

pub mod text;

pub use text::TextFragmenter;

use async_trait::async_trait;

/// A fragment of a document ready for processing
#[derive(Debug, Clone)]
pub struct Fragment {
    /// The fragment content
    pub content: String,

    /// BLAKE3 content hash (32 bytes)
    pub content_hash: [u8; 32],

    /// Character offset where fragment starts in original document
    pub start_offset: usize,

    /// Character offset where fragment ends in original document
    pub end_offset: usize,

    /// Sequence number (0-indexed)
    pub sequence_number: u32,
}

/// Trait for document fragmenters
///
/// Different fragmenters can handle different input types (text, PDF, etc.)
#[async_trait]
pub trait Fragmenter {
    /// Error type for this fragmenter
    type Error;

    /// Split content into fragments
    ///
    /// # Errors
    /// Returns error if fragmentation fails
    async fn fragment(&self, content: &str) -> Result<Vec<Fragment>, Self::Error>;
}
