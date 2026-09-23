//! Confidentiality: are an entity's bytes ciphertext on disk?

use serde::{Deserialize, Serialize};

/// Whether an entity's content is stored as ciphertext.
///
/// # This is not an authorization axis
///
/// Confidentiality and visibility are permanently separate. `visibility` /
/// `owner_group_id` answer *who may read a row*; this type answers *what the
/// bytes in that row are*. Nothing consults `Confidentiality` to decide access,
/// and `Sealed` is not a stronger `private` — a sealed row is still returned to
/// whoever the visibility predicate admits, ciphertext and all.
///
/// This is why there is no `Public` variant. The ported three-tier enum had
/// one, alongside `EncryptedContent` and `FullyPrivate`; "public" is a
/// *visibility*, not a storage encoding, and the other two collapse into a
/// single question with a yes and a no. The pair below is that question.
///
/// # Derived, never stored
///
/// The state lives in whether a `claim_encryption` (or `evidence_encryption`,
/// or `claim_version_encryption`) row exists for the entity — see
/// [`Confidentiality::from_encryption_row`]. There is deliberately no
/// `as_db_str` / `from_db_str` pair: this value is never written to a column,
/// never round-tripped through one, and never compared against the
/// `privacy_tier` vocabulary those tables carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidentiality {
    /// The content bytes are readable as stored.
    Plaintext,
    /// The content bytes are AES-256-GCM ciphertext under a group epoch key.
    Sealed,
}

impl Confidentiality {
    /// Derive the confidentiality of an entity from whether it has an
    /// encryption row.
    ///
    /// This is the only constructor that means anything: presence of the row
    /// *is* the state, so there is no way for the VALUE and the state to
    /// disagree.
    ///
    /// The caller is where they can. `bool` has no third state, so a caller
    /// that collapses a failed lookup into `false` — `.unwrap_or(None)
    /// .is_some()` and its relatives — gets `Plaintext` for an entity it could
    /// not read the row for. Pass `false` only for a query that SUCCEEDED and
    /// returned nothing; propagate the error otherwise. The safe reading of an
    /// indeterminate result is `Sealed`, and this signature cannot express it.
    #[must_use]
    pub const fn from_encryption_row(row_present: bool) -> Self {
        if row_present {
            Self::Sealed
        } else {
            Self::Plaintext
        }
    }

    /// True when the stored bytes require a group key to read.
    #[must_use]
    pub const fn is_sealed(self) -> bool {
        matches!(self, Self::Sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_of_an_encryption_row_is_the_whole_state() {
        assert_eq!(
            Confidentiality::from_encryption_row(true),
            Confidentiality::Sealed
        );
        assert_eq!(
            Confidentiality::from_encryption_row(false),
            Confidentiality::Plaintext
        );
        assert!(Confidentiality::from_encryption_row(true).is_sealed());
        assert!(!Confidentiality::from_encryption_row(false).is_sealed());
    }

    #[test]
    fn the_serialized_forms_are_the_two_this_type_admits() {
        // Pinned because the value crosses a wire in the seal ceremony. If a
        // third state is ever wanted, it needs an argument against the
        // orthogonality rule above, not a new arm here.
        assert_eq!(
            serde_json::to_string(&Confidentiality::Plaintext).unwrap(),
            "\"plaintext\""
        );
        assert_eq!(
            serde_json::to_string(&Confidentiality::Sealed).unwrap(),
            "\"sealed\""
        );
    }
}
