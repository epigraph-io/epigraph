//! Document-specific (paper / textbook / report / …) extraction and ingest.

pub mod axis;
pub mod builder;
pub mod byline;
pub mod schema;
pub mod structure;

pub use builder::{
    adopt_recorded_ids, build_ingest_plan, build_ingest_plan_scoped,
    stored_content_hash_is_canonical_name_scoped, stored_content_hash_is_seed_scoped,
    DOCUMENT_SOURCE_TYPES,
};
pub use schema::*;
