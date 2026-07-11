//! Export-time serialization of the epistemic graph into external
//! provenance/interchange vocabularies.
//!
//! Everything in this module is **read-only against the DB and additive at
//! serialization time only**: internal edge relationship strings
//! (`derived_from`, `supersedes`, etc.) are never rewritten in the `edges`
//! table. See `prov` for the PROV-O mapping.

pub mod prov;
