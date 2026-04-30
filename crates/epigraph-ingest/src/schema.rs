//! Back-compat shim. Document schema lives in `document::schema` now; workflow
//! schema lives in `workflow::schema`. Re-exports here keep existing
//! `epigraph_ingest::DocumentExtraction` etc. callers compiling.

pub use crate::common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation};
pub use crate::document::schema::{
    default_confidence, DocumentExtraction, DocumentSource, Paragraph, Section, SourceType,
};
