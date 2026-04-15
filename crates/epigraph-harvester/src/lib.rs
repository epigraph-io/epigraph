// Allow result_large_err: HarvesterError contains tonic::Status (176 bytes)
// which is a third-party type we cannot control. Boxing would break #[from] ergonomics.
#![allow(clippy::result_large_err)]
//! `EpiGraph` Harvester Client
//!
//! This crate provides Rust bindings for the Harvester intelligence worker,
//! which extracts epistemic claims from documents using LLMs.
//!
//! # Architecture
//!
//! The harvester is a Python service that runs the extraction pipeline:
//! 1. **Extractor**: LLM-based claim extraction with Council of Critics
//! 2. **Skeptic**: Validates claims against source text (anti-hallucination)
//! 3. **Logician**: Checks for contradictions and fallacies
//! 4. **Variance Probe**: Ensures extraction stability across runs
//!
//! This crate provides:
//! - [`HarvesterClient`]: gRPC client for communication
//! - [`TextFragmenter`]: Splits large documents into processable fragments
//! - [`convert`]: Converts proto types to domain types
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use epigraph_harvester::{HarvesterClient, TextFragmenter, Fragmenter};
//! use epigraph_crypto::ContentHasher;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect to harvester service
//! let mut client = HarvesterClient::new("http://localhost:50051").await?;
//!
//! // Check service health
//! let health = client.health_check().await?;
//! println!("Harvester is healthy: {}", health.healthy);
//!
//! // Fragment a document
//! let fragmenter = TextFragmenter::default();
//! let fragments = fragmenter.fragment("Your document text here...").await?;
//!
//! // Process each fragment
//! for fragment in fragments {
//!     let graph = client.process_fragment(
//!         &fragment.content,
//!         fragment.content_hash,
//!         None,
//!     ).await?;
//!
//!     println!("Extracted {} claims", graph.claims.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Protocol Details
//!
//! The harvester uses Protocol Buffers (see `proto/harvester.proto`) for:
//! - Structured claim representation
//! - Audit trail tracking
//! - Token usage metrics
//! - Quality assurance reports

pub mod client;
pub mod commit;
pub mod convert;
pub mod errors;
pub mod fragmenter;
pub mod proto;

// Re-export main types at crate root
pub use client::HarvesterClient;
pub use commit::{
    ClaimStore, CommitHandler, CommitResult, EvidenceStore, TraceStore, TransactionManager,
};
pub use convert::{
    methodology_from_proto, methodology_to_proto, proto_claim_to_domain, proto_graph_to_claims,
    Citation, PartialClaim,
};
pub use errors::HarvesterError;
pub use fragmenter::{Fragment, Fragmenter, TextFragmenter};

// Re-export common proto types for convenience
pub use proto::{
    BatchResponse, ExtractionConfig, ExtractionStatus, FragmentMetadata, HealthResponse,
    Methodology as ProtoMethodology, VerifiedGraph,
};
