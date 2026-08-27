//! Export-time serialization of the epistemic graph into external
//! provenance/interchange vocabularies.
//!
//! The vocabulary MAPPING is additive at serialization time only: internal edge
//! relationship strings (`derived_from`, `supersedes`, etc.) are never
//! rewritten in the `edges` table. See `prov` for the PROV-O mapping.
//!
//! # This module is no longer read-only
//!
//! It was, until manifests landed. `prov::export_provenance_prov_o` now anchors
//! a signed Merkle manifest over exactly the rows it emitted, and anchoring
//! writes a `manifests` row plus one `manifest_entries` row per committed row.
//! There is deliberately no flag to turn that off: an unanchored export is one
//! whose recipient must simply trust that nothing was dropped, and that is the
//! failure this feature exists to remove. An anchored export is a RECORDED
//! export. Operators scripting the exporter in a loop should expect a
//! `manifests` row per invocation.
//!
//! Nothing here rewrites an existing row; the only writes are inserts into the
//! two manifest tables.

pub mod manifest;
pub mod prov;
