//! `MockAnchorBackend` — the kernel default, and a REAL ledger.
//!
//! # It is not an in-memory fake
//!
//! Submitting writes the exact published bytes to `anchor_mock_chain`, a
//! separate table whose BEFORE UPDATE / BEFORE DELETE triggers refuse every
//! mutation. Verification then reads the commitment back OUT of that table and
//! compares it byte-for-byte against `anchors.commitment_bytes`. Two stores
//! must agree, and one of them cannot be edited at all — that is what makes an
//! end-to-end check here mean something, and it is why the kernel default is
//! this rather than a no-op that returns `Ok(())` and publishes nothing.
//!
//! # What it still does NOT prove — read this before quoting a green verify
//!
//! The mock lives in the same Postgres it is meant to police. Whoever can
//! `DROP TRIGGER` can rewrite it. So a green `verify_anchor` against
//! `backend = "mock"` proves the MECHANISM — the commitment was computed,
//! published, and read back intact — and NOT the trust property. The operator
//! remains inside the trust base until a real backend is configured. Every
//! verification report carries `trust_basis: "operator-held"` for exactly this
//! reason; a mock verification is not an audit result.

use async_trait::async_trait;
use epigraph_crypto::ContentHasher;
use epigraph_interfaces::anchor::{
    AnchorBackend, AnchorCommitment, AnchorError, AnchorReceipt, PublishedAnchor,
};
use sqlx::PgPool;

use crate::repos::anchor::MockChainRepository;

/// Metadata label the mock publishes under, mirroring
/// [`CardanoBlockfrostBackend::METADATUM_LABEL`](crate::anchor::cardano::CardanoBlockfrostBackend)
/// so the two backends' ledger rows are shaped alike.
pub const MOCK_METADATUM_LABEL: i64 = 40961;

/// A ledger in the same Postgres. See the module docs for the honest bounds.
pub struct MockAnchorBackend {
    pool: PgPool,
}

impl MockAnchorBackend {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// `hex(BLAKE3(commitment_bytes || block_height_be))`.
    ///
    /// 64 lowercase hex characters — the exact shape of a Cardano transaction
    /// hash, so nothing downstream learns to depend on the mock's id format.
    /// Folding the height in keeps ids distinct when the same commitment is
    /// republished after a failed attempt, which a hash of the payload alone
    /// would collide on.
    #[must_use]
    pub fn derive_tx_id(commitment_bytes: &[u8], block_height: i64) -> String {
        let mut hasher = ContentHasher::incremental();
        hasher.update(commitment_bytes);
        hasher.update(&block_height.to_be_bytes());
        ContentHasher::to_hex(hasher.finalize().as_bytes())
    }
}

#[async_trait]
impl AnchorBackend for MockAnchorBackend {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn network(&self) -> &'static str {
        "mock"
    }

    async fn submit(&self, commitment: &AnchorCommitment) -> Result<AnchorReceipt, AnchorError> {
        let bytes = commitment.to_cbor()?;

        let block_height = MockChainRepository::next_block_height(&self.pool)
            .await
            .map_err(|e| AnchorError::Transport(format!("mock ledger height: {e}")))?;
        let tx_id = Self::derive_tx_id(&bytes, block_height);

        let row = MockChainRepository::publish(
            &self.pool,
            &tx_id,
            MOCK_METADATUM_LABEL,
            &bytes,
            block_height,
        )
        .await
        .map_err(|e| AnchorError::Transport(format!("mock ledger publish: {e}")))?;

        Ok(AnchorReceipt {
            tx_id: row.tx_id,
            block_height: Some(row.block_height),
            block_time_unix: Some(row.block_time.timestamp()),
        })
    }

    async fn fetch(&self, tx_id: &str) -> Result<Option<PublishedAnchor>, AnchorError> {
        let Some(row) = MockChainRepository::fetch(&self.pool, tx_id)
            .await
            .map_err(|e| AnchorError::Transport(format!("mock ledger fetch: {e}")))?
        else {
            return Ok(None);
        };

        // Depth relative to the ledger tip, so a caller that demands N
        // confirmations behaves identically against mock and real chains.
        let tip = MockChainRepository::tip_height(&self.pool)
            .await
            .map_err(|e| AnchorError::Transport(format!("mock ledger tip: {e}")))?
            .unwrap_or(row.block_height);
        let confirmations = u32::try_from((tip - row.block_height).max(0)).unwrap_or(u32::MAX);

        Ok(Some(PublishedAnchor {
            metadata_cbor: row.metadata_cbor,
            block_height: row.block_height,
            block_time_unix: row.block_time.timestamp(),
            confirmations,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_id_is_64_hex_chars_and_height_sensitive() {
        let bytes = b"a commitment payload";
        let a = MockAnchorBackend::derive_tx_id(bytes, 1);
        let b = MockAnchorBackend::derive_tx_id(bytes, 2);

        assert_eq!(a.len(), 64, "must be shaped like a Cardano tx hash");
        assert!(a
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        assert_ne!(
            a, b,
            "republishing identical bytes at a new height must not collide"
        );
        assert_eq!(
            a,
            MockAnchorBackend::derive_tx_id(bytes, 1),
            "derivation must be deterministic"
        );
    }
}
