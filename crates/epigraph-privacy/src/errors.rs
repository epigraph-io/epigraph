//! Privacy subsystem error types.
//!
//! Three variants of the ported enum are deliberately absent, and their absence
//! is load-bearing rather than tidying:
//!
//! * a `#[from] sqlx::Error` arm — it was this crate's only contact with a
//!   database driver, and carrying it would make "DB-free" false in the
//!   manifest even with no query in the crate;
//! * an arm naming multi-party computation parameters — that subsystem is
//!   permanently out of scope, and porting its error vocabulary ports the
//!   vocabulary of the thing that was excluded;
//! * an arm naming re-encryption key expiry — it referred to a repository with
//!   no callers, which this workspace does not carry.
//!
//! What remains is smaller than what the ported enum carried, and — stated
//! plainly rather than left to be discovered — larger than what this crate
//! constructs today. Only [`PrivacyError::Crypto`] has a construction site
//! here, because every function in this crate takes keys and bytes and has no
//! group state to disagree with. The membership and epoch variants are the
//! vocabulary for the callers that DO hold that state: the rotation and seal
//! slices, which decide a role or resolve an active epoch before they reach an
//! encryptor. They are declared here so those callers share one spelling
//! instead of minting a second, not because anything raises them yet.

use thiserror::Error;

/// Errors raised by client-side sealing.
#[derive(Error, Debug)]
pub enum PrivacyError {
    /// No such group.
    #[error("Group not found: {group_id}")]
    GroupNotFound { group_id: uuid::Uuid },

    /// The agent is not a live member of the group.
    #[error("Not a group member: agent {agent_id} in group {group_id}")]
    NotMember {
        agent_id: uuid::Uuid,
        group_id: uuid::Uuid,
    },

    /// The agent's role does not permit the operation.
    #[error("Insufficient role: need {required}, have {actual}")]
    InsufficientRole { required: String, actual: String },

    /// The group has no active key epoch, so nothing can be sealed for it.
    #[error("No active key epoch for group {group_id}")]
    NoActiveEpoch { group_id: uuid::Uuid },

    /// The claim has no ciphertext to decrypt.
    #[error("Claim not encrypted: {claim_id}")]
    NotEncrypted { claim_id: uuid::Uuid },

    /// An underlying cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(#[from] epigraph_crypto::CryptoError),
}
