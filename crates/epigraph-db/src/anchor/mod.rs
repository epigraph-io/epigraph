//! External anchoring: publishing a Merkle root to a party OTHER than the
//! operator (backlog 94e62824, `migrations/072_anchors.sql`).
//!
//! `manifests` (migration 071) proves a set of rows was committed to as a
//! unit, signed by an agent whose key this instance holds. `provenance_log` is
//! append-only against SQL but not against whoever runs the database. Neither
//! establishes WHEN something existed to anyone who does not already trust the
//! operator. An anchor does: a third party attests that these 32 bytes were
//! published before block N.
//!
//! # Orchestration here, SQL in `crate::repos::anchor`
//!
//! Two modules share the name `anchor` in this crate. THIS one is
//! orchestration — [`AnchorService`], the backends, the root-source seam — and
//! issues no SQL of its own. [`crate::repos::anchor`] holds every statement,
//! per CLAUDE.md. Resolving the collision by moving the SQL up here would
//! violate that rule, so the collision stays and is documented instead.
//!
//! # THE MOCK IS NOT A TRUST BOUNDARY
//!
//! The kernel default [`MockAnchorBackend`] is a real append-only ledger, and
//! it lives in the same Postgres as the anchors it attests to. It proves the
//! MECHANISM — commitment computed, published, read back, compared byte for
//! byte across two stores — and it does NOT remove the operator from the trust
//! base. Every report says which is which via `trust_basis`:
//! `"operator-held"` for the mock, `"third-party"` otherwise. A green
//! `verify_anchor` against the mock is not an audit result.
//!
//! # No enable flag
//!
//! Anchoring on manifest seal is unconditional. `EPIGRAPH_ANCHOR_BACKEND`
//! chooses which backend and defaults to `mock`, so the default configuration
//! — the one every test and dev machine runs — anchors for real.

pub mod cardano;
pub mod mock;
pub mod root_source;
pub mod service;

pub use cardano::{CardanoBlockfrostBackend, METADATUM_LABEL, PROJECT_ID_ENV};
pub use mock::{MockAnchorBackend, MOCK_METADATUM_LABEL};
pub use root_source::{AnchorRootSource, ManifestRootSource, SealedRoot};
pub use service::{
    anchor_manifest_best_effort, parse_backend_name, AnchorService, AnchorServiceError,
    AnchorVerdict, AnchorVerification, BackendKind, BACKEND_ENV, TRUST_OPERATOR_HELD,
    TRUST_THIRD_PARTY,
};
