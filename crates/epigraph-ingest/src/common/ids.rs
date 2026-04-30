//! Deterministic ID derivation for hierarchical artifact ingest.
//!
//! Atoms (level 3) use a global namespace so that identical text across
//! different documents AND different workflows converges on the same claim
//! node. Compound nodes (thesis, section/phase, paragraph/step) are scoped by
//! a per-artifact seed (the document title, or the workflow's canonical_name)
//! so they do NOT converge across artifacts even when their text matches.

use uuid::Uuid;

/// EpiGraph atom content namespace for deterministic UUIDv5 generation.
/// Atoms with identical text across different documents and workflows
/// intentionally get the same UUID — this is how cross-source matching works.
pub const ATOM_NAMESPACE: Uuid = Uuid::from_bytes([
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x47, 0x89, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
]);

/// Namespace for compound claims (thesis, section/phase, paragraph/step).
/// Compound claims are scoped by their host artifact (document title or
/// workflow canonical_name) so the same summary text in two different
/// papers gets two different UUIDs.
pub const COMPOUND_NAMESPACE: Uuid = Uuid::from_bytes([
    0xc0, 0x4d, 0x90, 0xd1, 0xe2, 0xf3, 0x44, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0xa5,
]);

/// Namespace for workflow root nodes. Used by `workflow::builder` to derive
/// `workflows.id` from `(canonical_name, generation)`.
pub const WORKFLOW_NAMESPACE: Uuid = Uuid::from_bytes([
    0xf1, 0x0e, 0x55, 0xa5, 0x37, 0x42, 0x4b, 0xc0, 0x9d, 0x21, 0x8e, 0xa6, 0xf3, 0x12, 0x6c, 0x88,
]);

/// BLAKE3-32 of `content` as a fixed-size array.
#[must_use]
pub fn content_hash(content: &str) -> [u8; 32] {
    *blake3::hash(content.as_bytes()).as_bytes()
}

/// Generate a deterministic UUID for a compound claim (thesis/section/phase/
/// paragraph/step) scoped to its host artifact. Same content + same artifact
/// seed → same UUID.
#[must_use]
pub fn compound_claim_id(content_hash: &[u8; 32], artifact_seed: &str) -> Uuid {
    let mut material = Vec::with_capacity(32 + artifact_seed.len());
    material.extend_from_slice(content_hash);
    material.extend_from_slice(artifact_seed.as_bytes());
    Uuid::new_v5(&COMPOUND_NAMESPACE, &material)
}

/// Generate a deterministic UUID for an atomic claim (level 3) from its
/// content hash. Globally unique to the text — converges across artifacts.
#[must_use]
pub fn atom_id(content_hash: &[u8; 32]) -> Uuid {
    Uuid::new_v5(&ATOM_NAMESPACE, content_hash)
}

/// Generate a deterministic UUID for a workflow root node from canonical_name
/// and generation. Variants share `canonical_name`; their root IDs differ by
/// the appended generation tag.
#[must_use]
pub fn workflow_root_id(canonical_name: &str, generation: u32) -> Uuid {
    let material = format!("{canonical_name}:{generation}");
    let hash = blake3::hash(material.as_bytes());
    Uuid::new_v5(&WORKFLOW_NAMESPACE, hash.as_bytes())
}
