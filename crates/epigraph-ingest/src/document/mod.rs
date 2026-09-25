//! Document-specific (paper / textbook / report / …) extraction and ingest.

pub mod axis;
pub mod builder;
pub mod byline;
pub mod schema;
pub mod structure;

pub use builder::{build_ingest_plan, stored_content_hash_is_seed_scoped, DOCUMENT_SOURCE_TYPES};
pub use schema::*;
