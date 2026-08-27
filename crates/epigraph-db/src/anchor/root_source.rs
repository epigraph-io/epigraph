//! Where a root comes from, and how to re-derive it today.
//!
//! # THE ONLY FILE COUPLED TO THE MANIFEST TRACK
//!
//! Verification is generic over [`AnchorRootSource`], so drift and tamper
//! mechanics are testable against a fixture source while
//! [`ManifestRootSource`] carries the production coupling. If migration 071's
//! repository ever changes shape, this file is the only one that follows it.
//!
//! # `sealed` vs `live_root`
//!
//! [`AnchorRootSource::sealed`] reads what was committed to at seal time — the
//! stored `manifests.root`. [`AnchorRootSource::live_root`] RE-DERIVES the
//! root from the rows as they stand now. Comparing the two is what surfaces
//! drift; whether a given drift is benign (a legitimately deleted claim) or
//! malicious is the manifest track's semantic, so this layer reports both
//! hashes and judges neither.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use epigraph_crypto::{claim_leaf, edge_leaf, merkle_root, ManifestRowKind, HASH_SIZE};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::anchor::ROOT_TYPE_MANIFEST;
use crate::repos::manifest::ManifestRepository;

/// A root as it was sealed: exactly what the commitment will carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRoot {
    pub root_id: Uuid,
    pub root_hash: [u8; HASH_SIZE],
    /// Leaves the root covers. Published in the commitment so a verifier can
    /// detect a root re-derived over a different-sized set.
    pub leaf_count: u64,
    /// Seal time as CLAIMED by the sealer.
    pub sealed_at: DateTime<Utc>,
}

/// A kind of root this instance knows how to anchor and re-derive.
#[async_trait]
pub trait AnchorRootSource: Send + Sync {
    /// The `anchors.root_type` this source handles.
    fn kind(&self) -> &'static str;

    /// The sealed root, or `None` if `root_id` names nothing.
    ///
    /// # Errors
    /// Propagates the underlying query failure.
    async fn sealed(&self, pool: &PgPool, root_id: Uuid) -> Result<Option<SealedRoot>, DbError>;

    /// Re-derive the root from the rows as they stand NOW.
    ///
    /// `None` means the root can no longer be derived at all — every covered
    /// row is gone, or the sealed record itself has been removed. That is
    /// reported as `RootUnresolvable`, distinct from a root that derives to a
    /// different value (`Drift`).
    ///
    /// # Errors
    /// Propagates the underlying query failure.
    async fn live_root(
        &self,
        pool: &PgPool,
        root_id: Uuid,
    ) -> Result<Option<[u8; HASH_SIZE]>, DbError>;
}

/// [`AnchorRootSource`] over migration 071's `manifests`.
///
/// A thin delegation to `ManifestRepository` plus the same leaf/fold
/// arithmetic `epigraph_engine::export::manifest::verify_manifest` performs.
/// It is repeated rather than called because `epigraph-engine` depends on
/// `epigraph-db`, not the reverse — and both sides fold with the shared
/// primitives in `epigraph-crypto`, so there is no second definition of the
/// hash.
pub struct ManifestRootSource;

#[async_trait]
impl AnchorRootSource for ManifestRootSource {
    fn kind(&self) -> &'static str {
        ROOT_TYPE_MANIFEST
    }

    async fn sealed(&self, pool: &PgPool, root_id: Uuid) -> Result<Option<SealedRoot>, DbError> {
        let Some(manifest) = ManifestRepository::get(pool, root_id).await? else {
            return Ok(None);
        };
        let root_hash = <[u8; HASH_SIZE]>::try_from(manifest.root.as_slice()).map_err(|_| {
            DbError::InvalidData {
                reason: format!(
                    "manifests.root for {root_id} is {} bytes, expected {HASH_SIZE}",
                    manifest.root.len()
                ),
            }
        })?;
        Ok(Some(SealedRoot {
            root_id,
            root_hash,
            leaf_count: u64::try_from(manifest.entry_count).unwrap_or(0),
            // The manifest is sealed at creation — the row is written whole in
            // one transaction and every commitment-bearing column is inside the
            // signed header — so `created_at` IS the seal time.
            sealed_at: manifest.created_at,
        }))
    }

    async fn live_root(
        &self,
        pool: &PgPool,
        root_id: Uuid,
    ) -> Result<Option<[u8; HASH_SIZE]>, DbError> {
        let entries = ManifestRepository::entries(pool, root_id).await?;
        if entries.is_empty() {
            return Ok(None);
        }

        let claim_ids: Vec<Uuid> = entries
            .iter()
            .filter(|e| e.row_kind == ManifestRowKind::Claim.as_str())
            .map(|e| e.row_id)
            .collect();
        let edge_ids: Vec<Uuid> = entries
            .iter()
            .filter(|e| e.row_kind == ManifestRowKind::Edge.as_str())
            .map(|e| e.row_id)
            .collect();

        let live_claims = ManifestRepository::load_claim_leaf_inputs(pool, &claim_ids).await?;
        let live_edges = ManifestRepository::load_edge_leaf_inputs(pool, &edge_ids).await?;

        let mut live_leaf: std::collections::HashMap<(&str, Uuid), [u8; HASH_SIZE]> =
            std::collections::HashMap::new();
        for row in &live_claims {
            // A malformed content_hash cannot reproduce any leaf; leaving it
            // out shortens the live list, which can never fold to the sealed
            // root — the honest outcome.
            let Ok(content_hash) = <[u8; HASH_SIZE]>::try_from(row.content_hash.as_slice()) else {
                continue;
            };
            live_leaf.insert(
                (ManifestRowKind::Claim.as_str(), row.id),
                claim_leaf(
                    *row.id.as_bytes(),
                    &content_hash,
                    row.agent_id.as_bytes(),
                    row.created_at.timestamp_micros(),
                )
                .hash(),
            );
        }
        for row in &live_edges {
            live_leaf.insert(
                (ManifestRowKind::Edge.as_str(), row.id),
                edge_leaf(
                    *row.id.as_bytes(),
                    &row.relationship,
                    row.created_at.timestamp_micros(),
                )
                .hash(),
            );
        }

        // Stored order IS canonical order (the manifest writes leaves sorted by
        // (kind tag, row id)), so the live leaves are folded in the positions
        // the sealed root used.
        let leaves: Vec<[u8; HASH_SIZE]> = entries
            .iter()
            .filter_map(|e| {
                let kind = if e.row_kind == ManifestRowKind::Claim.as_str() {
                    ManifestRowKind::Claim.as_str()
                } else {
                    ManifestRowKind::Edge.as_str()
                };
                live_leaf.get(&(kind, e.row_id)).copied()
            })
            .collect();

        Ok(merkle_root(&leaves).ok())
    }
}
