//! Client-side content sealing for `EpiGraph`.
//!
//! # Where this runs
//!
//! On the client. The server never holds a group key, so it can neither seal
//! nor unseal; it stores ciphertext and enforces who may fetch the row that
//! holds it. Everything in this crate is pure: keys and bytes in, keys and
//! bytes out. There is no database access, no key custody, and no ambient
//! state.
//!
//! # The two axes, kept apart
//!
//! * **Visibility** — `visibility` / `owner_group_id` on the row — answers *who
//!   may read this*. It is enforced in the database and is not this crate's
//!   concern.
//! * **Confidentiality** — [`Confidentiality`] — answers *are the bytes
//!   ciphertext*. That is this crate's concern, and it is never consulted for
//!   authorization.
//!
//! Sealing a row does not restrict it and restricting a row does not seal it.
//!
//! # What binds a ciphertext
//!
//! Every ciphertext is authenticated against
//! `entity_id || epoch || field_tag`, so it cannot be moved between entities,
//! replayed across a key rotation, or transplanted between two fields of the
//! same entity. See [`encryptor`] for the encoding, which is pinned by a
//! known-byte-vector test because the two ends of a seal are written by
//! different programs.
//!
//! # Padding
//!
//! Ciphertext length leaks plaintext length. [`encryptor::encrypt_content`]
//! still takes already-padded bytes and returns them unchanged on decrypt — the
//! encryptor is deliberately ignorant of the scheme. **PR-19's module doc said
//! this crate "neither pads nor unpads"; PR-21 adds [`padding`], and the
//! separation it described is preserved rather than dropped**: padding is a
//! sibling module the caller composes, not a step the encryptor performs, so a
//! caller with its own scheme still passes bytes straight through.

pub mod encryptor;
pub mod errors;
pub mod group;
pub mod padding;
pub mod rewrap;
pub mod tier;

pub use padding::{pad, stored_len, unpad, PAD_BUCKETS, PAYLOAD_OVERHEAD};

pub use encryptor::{
    decrypt_claim_content, decrypt_content, decrypt_edge_properties, decrypt_evidence_content,
    decrypt_version_content, decrypt_with_base_key, encrypt_claim_content, encrypt_content,
    encrypt_edge_properties, encrypt_evidence_content, encrypt_version_content,
    encrypt_with_base_key, FieldTag,
};
pub use errors::PrivacyError;
pub use group::GroupRole;
pub use rewrap::{rewrap_for_recipient, ShareBinding};
pub use tier::Confidentiality;
