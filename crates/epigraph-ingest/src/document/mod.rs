//! Document-specific (paper / textbook / report / …) extraction and ingest.

pub mod builder;
pub mod byline;
pub mod schema;
pub mod structure;

pub use builder::build_ingest_plan;
pub use schema::*;
