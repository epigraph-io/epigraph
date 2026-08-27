//! Merkle manifests: a commitment over a **set** of graph rows.
//!
//! `claims.signature` / `edges.signature` prove each row's authorship but say
//! nothing about the completeness or the boundary of a SET. An exporter can drop
//! inconvenient rows from a subgraph export and every surviving row still
//! verifies on its own. This module builds the missing piece: a single 32-byte
//! root that changes if any committed row is dropped, added, or substituted.
//!
//! Pure — nothing here touches a database, a clock, or the filesystem.
//!
//! # Tree shape: RFC 6962, not Bitcoin
//!
//! ```text
//! leaf(d)          = BLAKE3(0x00 || d)
//! node(left,right) = BLAKE3(0x01 || left || right)
//! root(D[0..1])    = leaf hash itself
//! root(D[0..n])    = node(root(D[0..k]), root(D[k..n]))
//!                    where k is the largest power of two STRICTLY below n
//! ```
//!
//! The two decisions that matter:
//!
//! * **Distinct `0x00` / `0x01` domain tags.** Without them a 32-byte interior
//!   digest could be replayed as a leaf preimage (the classic second-preimage
//!   attack on naive Merkle trees).
//! * **The RFC 6962 split, not Bitcoin's duplicate-the-last-node promotion.**
//!   Bitcoin's shape admits CVE-2012-2459: an `n`-leaf tree and a crafted
//!   `(n+1)`-leaf tree can fold to the same root, so a root proves nothing about
//!   how many leaves went into it. The split rule above is collision-free on
//!   leaf count.
//!
//! An empty set is [`MerkleError::Empty`], never a sentinel root: a manifest
//! over zero rows proves nothing and would be a footgun for every consumer that
//! checked `root == expected` without also checking the count.
//!
//! # Leaf preimages: fixed width per kind, domain-separated
//!
//! ```text
//! 0x00 || b"epigraph.manifest.v1" || kind_tag || row_id(16) || created_at_micros_be(8) || payload
//!
//! claim payload = content_hash(32) || agent_id(16)          -> 94-byte preimage
//! edge  payload = BLAKE3(relationship)(32)                  -> 78-byte preimage
//! ```
//!
//! `MANIFEST_DOMAIN` separates these digests from every other BLAKE3 use in the
//! workspace (`ContentHasher::hash` over claim content, `did_key`'s seeds,
//! `recall_events.query_embedding_hash`). Hashing the relationship *string*
//! rather than embedding it keeps every preimage fixed-width, so no length
//! prefix is needed and no cross-field ambiguity is possible.
//!
//! # What a leaf does and does not bind
//!
//! Each leaf commits only to the **write-once** subset of its row, because a
//! commitment over whole rows would break on ordinary maintenance — label
//! patches, supersession, theme reassignment, Dempster-Shafer recomputes. In
//! particular an edge leaf binds `(id, relationship, created_at)` and
//! **deliberately not its endpoints**: `edges.source_id` / `target_id` are
//! legitimately rewritten by dedup re-sourcing and by the retraction cascade. So
//! an edge leaf proves "an edge with THIS id and THIS relationship, created at
//! THIS instant, was in the set" — omission and substitution of edges are
//! caught, silent re-pointing of a surviving edge is not, and must not be.

use crate::HASH_SIZE;

/// Domain separator for every manifest leaf preimage. Exactly 20 ASCII bytes.
pub const MANIFEST_DOMAIN: &[u8; 20] = b"epigraph.manifest.v1";

/// RFC 6962 leaf-node prefix.
const LEAF_TAG: u8 = 0x00;

/// RFC 6962 interior-node prefix.
const NODE_TAG: u8 = 0x01;

/// Which graph table a manifest leaf covers.
///
/// The tag byte goes into the leaf preimage, so a claim and an edge that
/// happened to share a UUID and a creation instant still hash differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManifestRowKind {
    /// A row of `claims`.
    Claim,
    /// A row of `edges`.
    Edge,
}

impl ManifestRowKind {
    /// The domain-separating byte written into the leaf preimage.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Claim => 0x01,
            Self::Edge => 0x02,
        }
    }

    /// The `manifest_entries.row_kind` string for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Edge => "edge",
        }
    }

    /// Parse a `manifest_entries.row_kind` string.
    ///
    /// Returns `None` for anything the `manifest_entries_kind_known` CHECK
    /// would already have rejected.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "claim" => Some(Self::Claim),
            "edge" => Some(Self::Edge),
            _ => None,
        }
    }
}

impl std::fmt::Display for ManifestRowKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The kind-specific tail of a leaf preimage. Fixed width in both arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafPayload {
    /// `content_hash(32) || agent_id(16)`.
    Claim {
        content_hash: [u8; HASH_SIZE],
        agent_id: [u8; 16],
    },
    /// `BLAKE3(relationship)(32)`.
    Edge { relationship_hash: [u8; HASH_SIZE] },
}

/// One committed row, reduced to exactly the material that gets hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestLeaf {
    kind: ManifestRowKind,
    row_id: [u8; 16],
    created_at_micros: i64,
    payload: LeafPayload,
}

impl ManifestLeaf {
    /// Which table this leaf covers.
    #[must_use]
    pub const fn kind(&self) -> ManifestRowKind {
        self.kind
    }

    /// The committed row's id, as raw UUID bytes.
    #[must_use]
    pub const fn row_id(&self) -> [u8; 16] {
        self.row_id
    }

    /// The committed row's `created_at`, in microseconds since the Unix epoch.
    ///
    /// Microseconds, not nanoseconds: Postgres `timestamptz` is
    /// microsecond-resolution, so this round-trips losslessly.
    #[must_use]
    pub const fn created_at_micros(&self) -> i64 {
        self.created_at_micros
    }

    /// The exact bytes fed to BLAKE3 for this leaf.
    #[must_use]
    pub fn preimage(&self) -> Vec<u8> {
        // 1 tag + 20 domain + 1 kind + 16 id + 8 timestamp = 46, plus payload.
        let mut buf = Vec::with_capacity(46 + HASH_SIZE + 16);
        buf.push(LEAF_TAG);
        buf.extend_from_slice(MANIFEST_DOMAIN);
        buf.push(self.kind.tag());
        buf.extend_from_slice(&self.row_id);
        buf.extend_from_slice(&self.created_at_micros.to_be_bytes());
        match &self.payload {
            LeafPayload::Claim {
                content_hash,
                agent_id,
            } => {
                buf.extend_from_slice(content_hash);
                buf.extend_from_slice(agent_id);
            }
            LeafPayload::Edge { relationship_hash } => {
                buf.extend_from_slice(relationship_hash);
            }
        }
        buf
    }

    /// This leaf's 32-byte hash.
    #[must_use]
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        blake3::hash(&self.preimage()).into()
    }

    /// The canonical ordering key: `(kind tag, row id bytes)`.
    ///
    /// Sorting by this — rather than by the exporter's enumeration order —
    /// makes the root a function of the SET alone, so two honest exports of the
    /// same rows produce the same root and set-equality becomes provable.
    #[must_use]
    pub const fn sort_key(&self) -> (u8, [u8; 16]) {
        (self.kind.tag(), self.row_id)
    }
}

/// Build the leaf for a `claims` row from its write-once subset.
#[must_use]
pub fn claim_leaf(
    row_id: [u8; 16],
    content_hash: &[u8; HASH_SIZE],
    agent_id: &[u8; 16],
    created_at_micros: i64,
) -> ManifestLeaf {
    ManifestLeaf {
        kind: ManifestRowKind::Claim,
        row_id,
        created_at_micros,
        payload: LeafPayload::Claim {
            content_hash: *content_hash,
            agent_id: *agent_id,
        },
    }
}

/// Build the leaf for an `edges` row from its write-once subset.
///
/// The endpoints are deliberately absent — see the module docs.
#[must_use]
pub fn edge_leaf(row_id: [u8; 16], relationship: &str, created_at_micros: i64) -> ManifestLeaf {
    ManifestLeaf {
        kind: ManifestRowKind::Edge,
        row_id,
        created_at_micros,
        payload: LeafPayload::Edge {
            relationship_hash: blake3::hash(relationship.as_bytes()).into(),
        },
    }
}

/// A single sibling on an inclusion path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    /// The sibling subtree's root hash.
    pub sibling: [u8; HASH_SIZE],
    /// `true` when the sibling sits to the RIGHT of the accumulated hash, i.e.
    /// the fold is `node(acc, sibling)`; `false` means `node(sibling, acc)`.
    pub sibling_is_right: bool,
}

/// Failures that are structural rather than cryptographic.
///
/// A dedicated enum rather than new [`crate::CryptoError`] variants: nothing
/// here is a key or serialization failure, and widening `CryptoError` would
/// touch every exhaustive match in the workspace.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MerkleError {
    /// A manifest over zero rows. Rejected rather than given a sentinel root.
    #[error("a manifest must commit to at least one row")]
    Empty,

    /// The same `(kind, row id)` appeared twice in one manifest.
    #[error("duplicate {kind} entry in manifest: {}", uuid_hex(.id))]
    DuplicateEntry {
        /// Which table the repeated row belongs to.
        kind: ManifestRowKind,
        /// The repeated row id, as raw UUID bytes.
        id: [u8; 16],
    },

    /// An inclusion proof was requested for a position that does not exist.
    #[error("leaf index {index} out of range for a {len}-leaf tree")]
    IndexOutOfRange {
        /// The requested position.
        index: usize,
        /// The number of leaves actually present.
        len: usize,
    },
}

/// Render raw UUID bytes as a hyphenated UUID string, for error messages only.
fn uuid_hex(id: &[u8; 16]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(36);
    for (i, b) in id.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Sort leaves into canonical order and reject a repeated `(kind, row id)`.
///
/// Duplicates are an error rather than a silent dedup at this layer: the crypto
/// layer cannot tell an honest repeat from a caller that lost track of its set,
/// and folding a leaf twice would inflate `entry_count` against the same set.
/// Callers that legitimately hold a multiset (an exporter enumerating the same
/// id from two directions) dedup their id slices before building leaves.
///
/// # Errors
/// [`MerkleError::DuplicateEntry`] if two leaves share a kind and row id.
pub fn canonical_order(mut leaves: Vec<ManifestLeaf>) -> Result<Vec<ManifestLeaf>, MerkleError> {
    leaves.sort_unstable_by_key(ManifestLeaf::sort_key);
    for pair in leaves.windows(2) {
        if pair[0].sort_key() == pair[1].sort_key() {
            return Err(MerkleError::DuplicateEntry {
                kind: pair[0].kind,
                id: pair[0].row_id,
            });
        }
    }
    Ok(leaves)
}

/// The largest power of two strictly below `n`. Requires `n >= 2`.
const fn split_point(n: usize) -> usize {
    // The highest power of two <= n-1 is exactly the largest power of two < n.
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Hash an interior node under the `0x01` domain tag.
#[must_use]
fn node_hash(left: &[u8; HASH_SIZE], right: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut buf = [0u8; 1 + 2 * HASH_SIZE];
    buf[0] = NODE_TAG;
    buf[1..=HASH_SIZE].copy_from_slice(left);
    buf[1 + HASH_SIZE..].copy_from_slice(right);
    blake3::hash(&buf).into()
}

/// Fold a non-empty slice of leaf hashes into its root. Callers guarantee
/// non-emptiness; [`merkle_root`] is the checked entry point.
fn fold(leaf_hashes: &[[u8; HASH_SIZE]]) -> [u8; HASH_SIZE] {
    debug_assert!(!leaf_hashes.is_empty());
    if leaf_hashes.len() == 1 {
        return leaf_hashes[0];
    }
    let k = split_point(leaf_hashes.len());
    node_hash(&fold(&leaf_hashes[..k]), &fold(&leaf_hashes[k..]))
}

/// Fold leaf hashes (already in canonical order) into the Merkle root.
///
/// A single leaf's root is that leaf's own hash, per RFC 6962's `MTH({d0})`.
///
/// # Errors
/// [`MerkleError::Empty`] if `leaf_hashes` is empty.
pub fn merkle_root(leaf_hashes: &[[u8; HASH_SIZE]]) -> Result<[u8; HASH_SIZE], MerkleError> {
    if leaf_hashes.is_empty() {
        return Err(MerkleError::Empty);
    }
    Ok(fold(leaf_hashes))
}

/// The `sibling_is_right` sequence an honest proof for `(index, n)` must have,
/// ordered leaf-first. Shared by proof construction and verification so the two
/// cannot drift.
fn path_shape(index: usize, n: usize) -> Vec<bool> {
    let mut shape = Vec::new();
    let (mut lo, mut hi, mut m) = (0usize, n, index);
    while hi - lo > 1 {
        let k = split_point(hi - lo);
        if m < k {
            shape.push(true);
            hi = lo + k;
        } else {
            shape.push(false);
            m -= k;
            lo += k;
        }
    }
    shape.reverse();
    shape
}

/// Build the RFC 6962 audit path proving that leaf `index` is in the tree.
///
/// The returned steps are ordered leaf-first: fold the leaf with step 0, then
/// that result with step 1, and so on up to the root.
///
/// # Errors
/// - [`MerkleError::Empty`] if there are no leaves.
/// - [`MerkleError::IndexOutOfRange`] if `index` is past the last leaf.
pub fn inclusion_proof(
    leaf_hashes: &[[u8; HASH_SIZE]],
    index: usize,
) -> Result<Vec<ProofStep>, MerkleError> {
    let n = leaf_hashes.len();
    if n == 0 {
        return Err(MerkleError::Empty);
    }
    if index >= n {
        return Err(MerkleError::IndexOutOfRange { index, len: n });
    }

    let mut proof = Vec::new();
    let (mut lo, mut hi, mut m) = (0usize, n, index);
    while hi - lo > 1 {
        let k = split_point(hi - lo);
        if m < k {
            proof.push(ProofStep {
                sibling: fold(&leaf_hashes[lo + k..hi]),
                sibling_is_right: true,
            });
            hi = lo + k;
        } else {
            proof.push(ProofStep {
                sibling: fold(&leaf_hashes[lo..lo + k]),
                sibling_is_right: false,
            });
            m -= k;
            lo += k;
        }
    }
    // The descent emits the outermost sibling first; the fold wants the
    // leaf-closest sibling first.
    proof.reverse();
    Ok(proof)
}

/// Verify that `leaf` sits at `index` of an `n`-leaf tree whose root is `root`.
///
/// The proof's `sibling_is_right` flags are checked against the shape `(index,
/// n)` implies before folding, so the proof binds the position and the leaf
/// count rather than just happening to reach the root.
#[must_use]
pub fn verify_inclusion(
    leaf: [u8; HASH_SIZE],
    index: usize,
    n: usize,
    proof: &[ProofStep],
    root: [u8; HASH_SIZE],
) -> bool {
    if n == 0 || index >= n {
        return false;
    }
    let shape = path_shape(index, n);
    if shape.len() != proof.len() {
        return false;
    }
    let mut acc = leaf;
    for (step, expect_right) in proof.iter().zip(shape) {
        if step.sibling_is_right != expect_right {
            return false;
        }
        acc = if expect_right {
            node_hash(&acc, &step.sibling)
        } else {
            node_hash(&step.sibling, &acc)
        };
    }
    acc == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_bytes(n: u8) -> [u8; HASH_SIZE] {
        [n; HASH_SIZE]
    }

    fn leaves(n: u8) -> Vec<[u8; HASH_SIZE]> {
        (0..n).map(leaf_bytes).collect()
    }

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        // RFC 6962 MTH({d0}) = the leaf hash itself, with no interior node.
        let only = leaf_bytes(7);
        assert_eq!(merkle_root(&[only]).unwrap(), only);
    }

    #[test]
    fn rfc6962_split_is_largest_power_of_two_below_n() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);

        // Hand-computed roots for the same n, folded straight from the rule.
        let d = leaves(9);
        let n = node_hash;

        // n = 2 -> node(d0, d1)
        assert_eq!(merkle_root(&d[..2]).unwrap(), n(&d[0], &d[1]));
        // n = 3 -> k=2 -> node(node(d0,d1), d2)
        assert_eq!(
            merkle_root(&d[..3]).unwrap(),
            n(&n(&d[0], &d[1]), &d[2]),
            "3 leaves must split 2|1, not 1|2"
        );
        // n = 4 -> k=2 -> node(node(d0,d1), node(d2,d3))
        assert_eq!(
            merkle_root(&d[..4]).unwrap(),
            n(&n(&d[0], &d[1]), &n(&d[2], &d[3]))
        );
        // n = 5 -> k=4 -> node(root(d0..4), d4)
        assert_eq!(
            merkle_root(&d[..5]).unwrap(),
            n(&n(&n(&d[0], &d[1]), &n(&d[2], &d[3])), &d[4]),
            "5 leaves must split 4|1"
        );
        // n = 8 -> k=4, a perfect tree
        let left8 = n(&n(&d[0], &d[1]), &n(&d[2], &d[3]));
        let right8 = n(&n(&d[4], &d[5]), &n(&d[6], &d[7]));
        assert_eq!(merkle_root(&d[..8]).unwrap(), n(&left8, &right8));
        // n = 9 -> k=8 -> node(root(d0..8), d8)
        assert_eq!(
            merkle_root(&d[..9]).unwrap(),
            n(&n(&left8, &right8), &d[8]),
            "9 leaves must split 8|1"
        );
    }

    #[test]
    fn leaf_and_interior_domains_do_not_collide() {
        // The same 64 bytes under the leaf tag and under the interior tag must
        // hash differently — otherwise a 32-byte interior digest could be
        // replayed as a leaf preimage (second preimage).
        let a = leaf_bytes(1);
        let b = leaf_bytes(2);

        let mut as_leaf = Vec::with_capacity(65);
        as_leaf.push(LEAF_TAG);
        as_leaf.extend_from_slice(&a);
        as_leaf.extend_from_slice(&b);
        let leaf_digest: [u8; HASH_SIZE] = blake3::hash(&as_leaf).into();

        assert_ne!(
            leaf_digest,
            node_hash(&a, &b),
            "0x00 and 0x01 domain tags must separate leaf and interior hashing"
        );
    }

    #[test]
    fn duplicate_last_node_attack_does_not_collide() {
        // CVE-2012-2459: Bitcoin's tree duplicates the final node to pad an odd
        // level, so [a,b,c] and [a,b,c,c] fold to the SAME root and a root
        // proves nothing about the leaf count. The RFC 6962 split must not.
        let d = leaves(3);
        let padded = vec![d[0], d[1], d[2], d[2]];
        assert_ne!(
            merkle_root(&d).unwrap(),
            merkle_root(&padded).unwrap(),
            "3-leaf and duplicate-padded 4-leaf trees must not collide"
        );
    }

    #[test]
    fn claim_and_edge_leaves_never_collide() {
        // Same row id, same instant, both kinds — the kind tag must separate
        // them even before the payloads differ.
        let row = id(9);
        let claim = claim_leaf(row, &[0xAB; HASH_SIZE], &id(3), 1_700_000_000_000_000);
        let edge = edge_leaf(row, "derived_from", 1_700_000_000_000_000);
        assert_ne!(claim.hash(), edge.hash());
        assert_ne!(claim.sort_key().0, edge.sort_key().0);
    }

    #[test]
    fn leaf_preimages_are_fixed_width_per_kind() {
        // 1 tag + 20 domain + 1 kind + 16 id + 8 micros = 46, plus payload.
        let claim = claim_leaf(id(1), &[0u8; HASH_SIZE], &id(2), 0);
        assert_eq!(
            claim.preimage().len(),
            46 + 32 + 16,
            "claim preimage is 94 B"
        );

        let short = edge_leaf(id(1), "a", 0);
        let long = edge_leaf(id(1), "a_very_long_relationship_name", 0);
        assert_eq!(short.preimage().len(), 46 + 32, "edge preimage is 78 B");
        assert_eq!(
            long.preimage().len(),
            short.preimage().len(),
            "hashing the relationship keeps the preimage width independent of it"
        );
        assert_ne!(short.hash(), long.hash());
    }

    #[test]
    fn canonical_order_is_input_order_independent() {
        let a = claim_leaf(id(3), &[1u8; HASH_SIZE], &id(1), 10);
        let b = claim_leaf(id(1), &[2u8; HASH_SIZE], &id(1), 20);
        let c = edge_leaf(id(2), "derived_from", 30);

        let one = canonical_order(vec![a, b, c]).unwrap();
        let two = canonical_order(vec![c, a, b]).unwrap();
        let three = canonical_order(vec![b, c, a]).unwrap();

        let root_of = |ls: &[ManifestLeaf]| {
            merkle_root(&ls.iter().map(ManifestLeaf::hash).collect::<Vec<_>>()).unwrap()
        };
        assert_eq!(root_of(&one), root_of(&two));
        assert_eq!(root_of(&one), root_of(&three));

        // Claims (tag 0x01) sort ahead of edges (tag 0x02), then by id bytes.
        assert_eq!(one[0].row_id(), id(1));
        assert_eq!(one[1].row_id(), id(3));
        assert_eq!(one[2].kind(), ManifestRowKind::Edge);
    }

    #[test]
    fn canonical_order_rejects_duplicate_kind_and_id() {
        // Same id, DIFFERENT payload — still one row, so still a duplicate.
        let a = claim_leaf(id(4), &[1u8; HASH_SIZE], &id(1), 10);
        let b = claim_leaf(id(4), &[9u8; HASH_SIZE], &id(2), 99);
        let err = canonical_order(vec![a, b]).unwrap_err();
        assert_eq!(
            err,
            MerkleError::DuplicateEntry {
                kind: ManifestRowKind::Claim,
                id: id(4)
            }
        );

        // Same id under different kinds is NOT a duplicate.
        let claim = claim_leaf(id(4), &[1u8; HASH_SIZE], &id(1), 10);
        let edge = edge_leaf(id(4), "derived_from", 10);
        assert_eq!(canonical_order(vec![claim, edge]).unwrap().len(), 2);
    }

    #[test]
    fn merkle_root_rejects_empty() {
        assert_eq!(merkle_root(&[]).unwrap_err(), MerkleError::Empty);
        assert_eq!(inclusion_proof(&[], 0).unwrap_err(), MerkleError::Empty);
    }

    #[test]
    fn inclusion_proof_roundtrips_for_every_index() {
        // 1..=17 covers n=1 (empty proof), both parities, and the powers-of-two
        // boundaries at 2, 4, 8, 16 where the split rule changes shape.
        for n in 1u8..=17 {
            let d = leaves(n);
            let root = merkle_root(&d).unwrap();
            for index in 0..usize::from(n) {
                let proof = inclusion_proof(&d, index).unwrap();
                assert!(
                    verify_inclusion(d[index], index, d.len(), &proof, root),
                    "n={n} index={index} must verify"
                );
                // A correct proof must not verify at the wrong position.
                if index + 1 < d.len() {
                    assert!(
                        !verify_inclusion(d[index], index + 1, d.len(), &proof, root),
                        "n={n} index={index} must not verify at index+1"
                    );
                }
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_index_past_the_end() {
        let d = leaves(3);
        assert_eq!(
            inclusion_proof(&d, 3).unwrap_err(),
            MerkleError::IndexOutOfRange { index: 3, len: 3 }
        );
    }

    #[test]
    fn verify_inclusion_rejects_a_flipped_sibling_bit() {
        let d = leaves(5);
        let root = merkle_root(&d).unwrap();
        let proof = inclusion_proof(&d, 2).unwrap();
        assert!(verify_inclusion(d[2], 2, 5, &proof, root));

        // Flip one bit of one sibling.
        let mut tampered = proof.clone();
        tampered[0].sibling[0] ^= 0x01;
        assert!(!verify_inclusion(d[2], 2, 5, &tampered, root));

        // Flip a direction flag instead.
        let mut swapped = proof.clone();
        swapped[0].sibling_is_right = !swapped[0].sibling_is_right;
        assert!(!verify_inclusion(d[2], 2, 5, &swapped, root));

        // Truncate the path.
        assert!(!verify_inclusion(d[2], 2, 5, &proof[..1], root));
    }

    #[test]
    fn row_kind_strings_round_trip() {
        for kind in [ManifestRowKind::Claim, ManifestRowKind::Edge] {
            assert_eq!(ManifestRowKind::from_str_opt(kind.as_str()), Some(kind));
        }
        assert_eq!(ManifestRowKind::from_str_opt("paper"), None);
    }

    #[test]
    fn duplicate_error_renders_a_readable_uuid() {
        let err = MerkleError::DuplicateEntry {
            kind: ManifestRowKind::Edge,
            id: [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 1, 2, 3, 4, 5, 6, 7,
            ],
        };
        assert!(
            err.to_string()
                .contains("01234567-89ab-cdef-0001-020304050607"),
            "got: {err}"
        );
    }
}
