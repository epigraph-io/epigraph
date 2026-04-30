//! Document-specific (paper / textbook / report / …) extraction and ingest.

pub mod builder;
pub mod schema;

pub use builder::build_ingest_plan;
pub use schema::*;
