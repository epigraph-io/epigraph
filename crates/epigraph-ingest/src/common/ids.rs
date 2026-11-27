//! Deterministic ID derivation for hierarchical artifact ingest.
//!
//! Atoms (level 3) use a global namespace so that identical text across
//! different documents AND different workflows converges on the same claim
//! node. Compound nodes (thesis, section/phase, paragraph/step) are scoped by
//! a per-artifact seed (the document title, or the workflow's canonical_name)
//! so they do NOT converge across artifacts even when their text matches.
//!
//! # Scope-derived ids (non-public document ingest)
//!
//! The paragraph above is the rule for a PUBLIC ingest only. A document
//! ingested as `private` or `team` mixes the group that owns its rows (the
//! ingest's `owner_group_id`) into every id and stored hash it derives:
//!
//! | node | public ingest (`scope = None`) | non-public ingest (`scope = Some(g)`) |
//! |---|---|---|
//! | atom id | `uuid_v5(ATOM, blake3(text))` | `uuid_v5(ATOM, blake3(text) \|\| g.as_bytes())` |
//! | atom stored hash | `blake3(text)` | `blake3(blake3(text) \|\| g.as_bytes())` |
//! | compound id | `uuid_v5(COMPOUND, blake3(text) \|\| seed)` | the same, with `seed + ":" + g` |
//! | compound stored hash | `blake3(blake3(text) \|\| seed)` | the same, with `seed + ":" + g` |
//!
//! `g.as_bytes()` is the group id's 16 raw bytes; `":" + g` is its lowercase
//! hyphenated text form. `seed` is the per-node seed the builder already uses
//! (`"{title}\u{1f}{path}"` for a document). Use [`scoped_atom_id`],
//! [`scoped_atom_content_hash`] and [`scoped_seed`] rather than re-spelling
//! these; with `scope = None` each returns exactly the public value, byte for
//! byte, so a public ingest's ids are unchanged.
//!
//! What follows from it, for a client that recomputes ids locally and for the
//! cross-source matcher:
//!
//! * The same text ingested by two groups is two claims, one per group. Before
//!   this, a group's private ingest of a document another group had already
//!   ingested resolved every node to the other group's rows: on the
//!   application role (row security enforced) the ingest then failed outright,
//!   and on a path that bypasses row security it converged onto, and reported
//!   the ids of, the other group's rows.
//! * A non-public ingest never looks a claim up by its text outside its own
//!   group: its atoms are written by id, so they converge only on the same
//!   group's ingest of the same text, or on what the document's earlier
//!   ingest by that group recorded. The one text lookup it makes is confined,
//!   in its SQL, to the group's own non-public rows (the last bullet).
//! * A scope-derived id is NOT a function of the text alone. A client must
//!   know the owning group (returned as the ingest's `owner_group_id`) to
//!   recompute it, and must recompute nothing for a row whose `properties`
//!   carry [`ID_SCOPE_KEY`] `=` [`ID_SCOPE_OWNER_GROUP`] from the text alone.
//! * Publicizing a scoped claim later keeps its scoped id; it does not merge
//!   into the public twin that shares its text. The two are linked by
//!   cross-source matching (the matcher's embedding neighbourhood: identical
//!   text embeds identically), never by id convergence. The matcher's
//!   content-hash blocker does not pair them, because the stored hash is
//!   scope-derived too.
//! * `verify_claim` re-derives a scoped atom's stored hash from its body and
//!   the row's current owning group: an unchanged row reports `match`. A row
//!   whose owner moved since it was written (shared with a team) reports
//!   `not_applicable`, as does one whose body changed, so a body change on a
//!   shared scoped atom is not detected by the hash check.
//! * A re-ingest by the same group of a document it ingested before these ids
//!   existed keeps the global ids that ingest wrote, claim by claim, so the
//!   re-run writes no duplicate of them. The walk re-uses, in this order, the
//!   ids the group's in-scope `papers` row already asserts; the group's own
//!   non-public rows that hold one of the document's global ids or global
//!   stored hashes; and, when the document key's PUBLIC `papers` row asserts
//!   one of the group's own non-public rows, the group's and the public rows
//!   that public row asserts. The last two cover an ingest from before the
//!   `papers` tenancy migration (246): a document then had one paper row,
//!   which that migration made public, so the group's own paper row is new
//!   and asserts nothing, and an atom that ingest converged onto an existing
//!   public row is recorded only on the public row. Never re-used: another
//!   group's non-public row. A node the earlier ingest resolved to one gets
//!   the group's own scoped claim.
//!
//! The workflow-side adopter of the same scheme is tracked as backlog
//! eb8ea9e5; workflow ingest still derives global ids.
//!
//! ```
//! use epigraph_ingest::common::ids::{
//!     atom_id, compound_claim_id, content_hash, scoped_atom_id, scoped_seed,
//! };
//! use uuid::Uuid;
//!
//! let h = content_hash("Water boils at 100 C at sea level.");
//! let group = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
//!
//! // Public: exactly the global id.
//! assert_eq!(scoped_atom_id(&h, None), atom_id(&h));
//! // Non-public: the owning group is part of the id.
//! let scoped = scoped_atom_id(&h, Some(group));
//! assert_ne!(scoped, atom_id(&h));
//! let mut material = h.to_vec();
//! material.extend_from_slice(group.as_bytes());
//! assert_eq!(scoped, Uuid::new_v5(&epigraph_ingest::common::ids::ATOM_NAMESPACE, &material));
//!
//! // Compound seeds gain ":" + the group id.
//! let seed = "My Paper\u{1f}sections[0]";
//! assert_eq!(scoped_seed(seed, None), seed);
//! assert_eq!(
//!     scoped_seed(seed, Some(group)),
//!     "My Paper\u{1f}sections[0]:01234567-89ab-cdef-0123-456789abcdef"
//! );
//! assert_ne!(
//!     compound_claim_id(&h, &scoped_seed(seed, Some(group))),
//!     compound_claim_id(&h, seed)
//! );
//! ```

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

/// Storage content hash for a compound (document-scoped) claim.
///
/// A compound node's identity is `(artifact seed, text)`, not text alone —
/// that is exactly what [`compound_claim_id`] encodes. `claims.content_hash`
/// must agree with that identity, because migration 013 puts
/// `UNIQUE (content_hash, agent_id)` on `claims` and every structural node of
/// every document is written by the same server agent. Hashing text alone
/// would make paper A's "Introduction" and paper B's "Introduction"
/// indistinguishable to that constraint, so the second insert would fail even
/// though the two rows carry different (correct) ids.
///
/// Derived over the same material as [`compound_claim_id`], so the row's
/// uniqueness key and its primary key are functions of the same inputs.
/// Atoms keep the plain [`content_hash`] — global convergence is their point.
#[must_use]
pub fn compound_content_hash(content_hash: &[u8; 32], artifact_seed: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(32 + artifact_seed.len());
    material.extend_from_slice(content_hash);
    material.extend_from_slice(artifact_seed.as_bytes());
    *blake3::hash(&material).as_bytes()
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

/// `properties` key a scope-derived claim carries (see the module doc,
/// "Scope-derived ids"), with value [`ID_SCOPE_OWNER_GROUP`]. It says the row's
/// id and stored hash fold in its owning group, so neither is recomputable
/// from the text alone.
pub const ID_SCOPE_KEY: &str = "id_scope";

/// The [`ID_SCOPE_KEY`] value: the scope is the ingest's `owner_group_id`.
pub const ID_SCOPE_OWNER_GROUP: &str = "owner_group";

/// [`atom_id`] for an ingest whose rows are owned by `scope`: `None` (a public
/// ingest) is exactly [`atom_id`]; `Some(group)` is
/// `uuid_v5(ATOM_NAMESPACE, content_hash || group.as_bytes())`, so the same
/// text in two groups' non-public ingests gives two ids. The 48-byte name can
/// never equal a 32-byte global name, so a scoped id never collides with a
/// global one.
#[must_use]
pub fn scoped_atom_id(content_hash: &[u8; 32], scope: Option<Uuid>) -> Uuid {
    match scope {
        None => atom_id(content_hash),
        Some(group) => {
            let mut material = Vec::with_capacity(32 + 16);
            material.extend_from_slice(content_hash);
            material.extend_from_slice(group.as_bytes());
            Uuid::new_v5(&ATOM_NAMESPACE, &material)
        }
    }
}

/// The stored `claims.content_hash` of an atom written under `scope`: `None`
/// is the plain `content_hash` (global convergence, unchanged); `Some(group)`
/// is `blake3(content_hash || group.as_bytes())`, the same material as
/// [`scoped_atom_id`]. Scoped for the reason [`compound_content_hash`] is: a
/// writer that converges by stored hash (`ClaimRepository::create_conn`'s
/// content-hash lookup, by any agent, in any scope) must never find a group's
/// non-public atom from another tenant's ingest of the same text.
#[must_use]
pub fn scoped_atom_content_hash(content_hash: &[u8; 32], scope: Option<Uuid>) -> [u8; 32] {
    match scope {
        None => *content_hash,
        Some(group) => {
            let mut material = Vec::with_capacity(32 + 16);
            material.extend_from_slice(content_hash);
            material.extend_from_slice(group.as_bytes());
            *blake3::hash(&material).as_bytes()
        }
    }
}

/// A compound node's artifact seed for an ingest whose rows are owned by
/// `scope`: `None` is `seed` unchanged; `Some(group)` appends `':'` and the
/// group id's lowercase hyphenated text. Feed the result to
/// [`compound_claim_id`] and [`compound_content_hash`].
///
/// A document seed is `"{title}\u{1f}{path}"` and its `path` is
/// builder-made (`thesis`, `sections[i]`, `sections[i].paragraphs[j]`), so it
/// never ends in `":" + uuid`: no scoped seed equals any public seed.
#[must_use]
pub fn scoped_seed(seed: &str, scope: Option<Uuid>) -> String {
    match scope {
        None => seed.to_string(),
        Some(group) => format!("{seed}:{group}"),
    }
}
