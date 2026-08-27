//! `CardanoBlockfrostBackend` — a STUB that refuses to submit.
//!
//! It compiles, it is selectable through `EPIGRAPH_ANCHOR_BACKEND=cardano`,
//! and it publishes nothing. There is no HTTP client, no wallet, no key
//! material, and no network call anywhere in this file — so nothing in this
//! track needs funding or credentials to build or test.
//!
//! # Why ship a stub at all
//!
//! To pin two things that are expensive to get wrong later: the metadatum
//! label (40961, per the OpenWater proof of concept) and the shape of "not
//! configured" versus "not implemented". An operator who sets
//! `EPIGRAPH_ANCHOR_BACKEND=cardano` today gets a `failed` anchor row whose
//! `failure_reason` names the missing configuration, on a manifest seal that
//! still succeeded — which is the behaviour a real outage will produce too.
//!
//! # Chain choice is deferred on purpose
//!
//! See `docs/superpowers/specs/2026-08-27-external-anchoring-design.md`: run
//! mock-only for a month, read the volume off `SELECT count(*) FROM anchors`,
//! then price Cardano label 40961 against Sigstore/Rekor and a signed git tag.
//! [`AnchorBackend`] admits all three unchanged.

use async_trait::async_trait;
use epigraph_interfaces::anchor::{
    AnchorBackend, AnchorCommitment, AnchorError, AnchorReceipt, PublishedAnchor,
};

/// Environment variable holding a Blockfrost project id.
pub const PROJECT_ID_ENV: &str = "BLOCKFROST_PROJECT_ID";

/// Cardano transaction-metadata label reserved for EpiGraph anchors, per the
/// OpenWater proof of concept.
///
/// A label is the top-level key of a transaction's metadata map, so it is what
/// lets a verifier find our commitments among everything else on chain.
pub const METADATUM_LABEL: u64 = 40961;

/// Selectable, unimplemented Cardano backend.
pub struct CardanoBlockfrostBackend {
    project_id: Option<String>,
    network: &'static str,
}

impl CardanoBlockfrostBackend {
    /// Same label as [`METADATUM_LABEL`], reachable as an associated constant
    /// so callers can name it without importing the free constant.
    pub const METADATUM_LABEL: u64 = METADATUM_LABEL;

    /// Build from the environment, reading [`PROJECT_ID_ENV`].
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            project_id: std::env::var(PROJECT_ID_ENV)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            network: "preprod",
        }
    }

    /// Build with an explicit project id, for tests that need to reach the
    /// `Unimplemented` arm without touching process-wide environment.
    #[must_use]
    pub fn with_project_id(project_id: Option<String>) -> Self {
        Self {
            project_id,
            network: "preprod",
        }
    }

    /// `NotConfigured` unless a project id is present.
    fn require_configured(&self) -> Result<(), AnchorError> {
        if self.project_id.is_some() {
            return Ok(());
        }
        Err(AnchorError::NotConfigured {
            backend: "cardano",
            detail: format!(
                "{PROJECT_ID_ENV} is unset; a Cardano anchor also needs a funded wallet and key \
                 custody, neither of which this build provides"
            ),
        })
    }
}

#[async_trait]
impl AnchorBackend for CardanoBlockfrostBackend {
    fn name(&self) -> &'static str {
        "cardano"
    }

    fn network(&self) -> &'static str {
        self.network
    }

    async fn submit(&self, _commitment: &AnchorCommitment) -> Result<AnchorReceipt, AnchorError> {
        self.require_configured()?;
        Err(AnchorError::Unimplemented {
            backend: "cardano",
            operation: "submit",
        })
    }

    async fn fetch(&self, _tx_id: &str) -> Result<Option<PublishedAnchor>, AnchorError> {
        self.require_configured()?;
        Err(AnchorError::Unimplemented {
            backend: "cardano",
            operation: "fetch",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfigured_is_not_configured_and_configured_is_unimplemented() {
        let commitment = AnchorCommitment::new("manifest", [0u8; 16], [0u8; 32], 1, 0);

        let bare = CardanoBlockfrostBackend::with_project_id(None);
        let err = bare.submit(&commitment).await.expect_err("must refuse");
        assert!(
            matches!(err, AnchorError::NotConfigured { .. }),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains(PROJECT_ID_ENV),
            "the reason must name the missing variable: {err}"
        );

        // With a project id the answer changes shape: the operator's
        // configuration is fine, the build simply cannot do it.
        let configured = CardanoBlockfrostBackend::with_project_id(Some("proj".into()));
        let err = configured
            .submit(&commitment)
            .await
            .expect_err("still unimplemented");
        assert!(
            matches!(err, AnchorError::Unimplemented { .. }),
            "got {err:?}"
        );
        let err = configured
            .fetch("tx")
            .await
            .expect_err("still unimplemented");
        assert!(
            matches!(err, AnchorError::Unimplemented { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn metadatum_label_is_pinned() {
        assert_eq!(CardanoBlockfrostBackend::METADATUM_LABEL, 40961);
        assert_eq!(METADATUM_LABEL, 40961);
    }
}
