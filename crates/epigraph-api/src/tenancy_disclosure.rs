//! One canonical copy of the sentence FINAL-PLAN §6.7 requires the system to
//! say about itself, out loud, in three places.
//!
//! # Why a constant and not three string literals
//!
//! §6.7 requires the sentence **verbatim, not paraphrased**, in
//! `docs/tenancy.md`, in the `POST /api/v1/groups/:id/rotate` response body,
//! and in the D4 privatization preview's `side_effects.revocation`. Three
//! independently-typed copies of a sentence drift on the first copy-edit, and
//! the one that drifts is the one nobody reads again. The two machine-readable
//! copies are this constant by construction; the prose copy in `docs/tenancy.md`
//! is asserted byte-equal against it by
//! `crates/epigraph-api/tests/group_rotation.rs`, which is the positive twin of
//! `crates/epigraph-api/tests/no_redaction_sentinel.rs` — that file asserts a
//! spelling must never appear, this one asserts a spelling must always appear.
//!
//! # Why this is a disclosure and not a vulnerability report
//!
//! It states a DESIGN PROPERTY with a named owner, already published in
//! `docs/tenancy/FINAL-PLAN.md` in this repository: rotation is forward-only by
//! construction, because the server holds no group key (§6.5.6) and
//! `claim_encryption` rows stay bound to the epoch they were sealed under. The
//! sentence exists so that "we rotated the key" is never mistaken for "we
//! revoked their access". It says what the guarantee IS; it says nothing about
//! how to exercise a retained share, and nothing further belongs here.
//!
//! Not feature-gated. It is a `&str` and nothing else, and both readers are
//! behind `#[cfg(feature = "db")]` already.

/// The §6.7 sentence, in the one plain-text form all three copies carry.
///
/// The plan's own copy is marked up (`**…**`, `*future*`); markdown emphasis
/// cannot survive into a JSON string field, so the canonical form is the
/// unmarked one and `docs/tenancy.md` quotes it unmarked too. Changing a byte
/// of this constant reddens the three-copy test until every copy is changed
/// with it — which is the point.
pub const ROTATION_DOES_NOT_REVOKE_PAST_ACCESS: &str = "A member removed at epoch N who kept their share can decrypt every claim sealed before the rotation, forever. Rotation gates only future ciphertext.";
