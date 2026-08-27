//! Repository for external anchors and the mock ledger
//! (backlog 94e62824, `migrations/072_anchors.sql`).
//!
//! Per CLAUDE.md every statement this feature issues lives here. The
//! orchestration in [`crate::anchor`] — the service, the two backends, the
//! root-source seam — calls these functions and writes no SQL of its own.
//!
//! # Two modules named `anchor`
//!
//! `crate::repos::anchor` (this file) is the SQL. `crate::anchor` is the
//! orchestration: `AnchorService`, `MockAnchorBackend`, `AnchorRootSource`.
//! The split is deliberate and matches every other feature in this crate; the
//! name collision is merely unfortunate. Moving the SQL up into
//! `crate::anchor` to resolve it would violate CLAUDE.md.
//!
//! # Why `insert_pending` re-selects
//!
//! `ON CONFLICT ... DO NOTHING` returns no row when it conflicts, and the
//! conflict is the *normal* case for a re-anchor. Returning the row that is
//! already there — rather than an error or a `None` the caller must interpret
//! — is what makes `AnchorService::anchor` idempotent without a read-then-write
//! race window.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

/// `anchors.root_type` for a `manifests` row. The only kind implemented.
pub const ROOT_TYPE_MANIFEST: &str = "manifest";

/// One stored `anchors` row.
#[derive(Debug, Clone)]
pub struct AnchorRow {
    pub id: Uuid,
    /// `"manifest"` today; `"checkpoint"` is reserved by the schema.
    pub root_type: String,
    pub root_id: Uuid,
    /// 32-byte Merkle root (`anchors_root_hash_len`).
    pub root_hash: Vec<u8>,
    pub commitment_version: i16,
    /// `BLAKE3(commitment_bytes)`, so a rewritten payload is caught without
    /// re-decoding it.
    pub commitment_hash: Vec<u8>,
    /// The EXACT bytes handed to the backend.
    pub commitment_bytes: Vec<u8>,
    pub backend: String,
    pub network: String,
    /// `pending` | `submitted` | `confirmed` | `failed`.
    pub status: String,
    pub tx_id: Option<String>,
    pub block_height: Option<i64>,
    pub block_time: Option<DateTime<Utc>>,
    /// Seal time CLAIMED by the root; the ledger block is the proven bound.
    pub sealed_at: DateTime<Utc>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub failure_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Everything one `anchors` INSERT needs.
#[derive(Debug, Clone)]
pub struct NewAnchor {
    pub root_type: String,
    pub root_id: Uuid,
    pub root_hash: Vec<u8>,
    pub commitment_version: i16,
    pub commitment_hash: Vec<u8>,
    pub commitment_bytes: Vec<u8>,
    pub backend: String,
    pub network: String,
    pub sealed_at: DateTime<Utc>,
}

/// One row of the mock ledger.
#[derive(Debug, Clone)]
pub struct MockChainRow {
    pub tx_id: String,
    pub metadata_label: i64,
    pub metadata_cbor: Vec<u8>,
    pub block_height: i64,
    pub block_time: DateTime<Utc>,
}

pub struct AnchorRepository;

impl AnchorRepository {
    /// Record a new `pending` anchor, or return the live one that already
    /// exists for `(root_type, root_id, backend, network)`.
    ///
    /// The `ON CONFLICT` predicate matches `uq_anchors_live_root` exactly, so
    /// Postgres infers the partial index. `failed` rows are outside that index:
    /// a retry after `NotConfigured` or a transport failure gets a fresh row,
    /// while a successful anchor can never be duplicated — two live
    /// commitments over one root would let an operator present whichever one
    /// suited them at verification time.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the insert or the re-select fails.
    #[instrument(skip(pool, anchor), fields(root_id = %anchor.root_id, backend = %anchor.backend))]
    pub async fn insert_pending(pool: &PgPool, anchor: &NewAnchor) -> Result<AnchorRow, DbError> {
        sqlx::query!(
            r#"
            INSERT INTO anchors (root_type, root_id, root_hash, commitment_version,
                                 commitment_hash, commitment_bytes, backend, network,
                                 status, sealed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9)
            ON CONFLICT (root_type, root_id, backend, network) WHERE status <> 'failed'
            DO NOTHING
            "#,
            anchor.root_type,
            anchor.root_id,
            anchor.root_hash,
            anchor.commitment_version,
            anchor.commitment_hash,
            anchor.commitment_bytes,
            anchor.backend,
            anchor.network,
            anchor.sealed_at,
        )
        .execute(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        Self::get_live(
            pool,
            &anchor.root_type,
            anchor.root_id,
            &anchor.backend,
            &anchor.network,
        )
        .await?
        .ok_or_else(|| DbError::NotFound {
            entity: "anchor".to_string(),
            id: anchor.root_id,
        })
    }

    /// Advance `pending` -> `submitted` and record the ledger transaction id.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the update fails.
    #[instrument(skip(pool))]
    pub async fn mark_submitted(pool: &PgPool, id: Uuid, tx_id: &str) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE anchors
            SET status = 'submitted', tx_id = $2, submitted_at = NOW(), failure_reason = NULL
            WHERE id = $1
            "#,
            id,
            tx_id,
        )
        .execute(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(())
    }

    /// Advance to `confirmed` with the block the commitment landed in.
    ///
    /// `tx_id` is written again rather than assumed, so `poll_pending` can
    /// confirm a row whose submit response was lost.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the update fails — including the
    /// `anchors_confirmed_has_tx` CHECK, which refuses a confirmation with no
    /// transaction to point at.
    #[instrument(skip(pool))]
    pub async fn mark_confirmed(
        pool: &PgPool,
        id: Uuid,
        tx_id: &str,
        block_height: i64,
        block_time: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE anchors
            SET status = 'confirmed', tx_id = $2, block_height = $3, block_time = $4,
                confirmed_at = NOW(), failure_reason = NULL
            WHERE id = $1
            "#,
            id,
            tx_id,
            block_height,
            block_time,
        )
        .execute(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(())
    }

    /// Record a failed attempt, freeing the root for a later retry.
    ///
    /// The row is kept rather than deleted: an accumulating pile of `failed`
    /// rows under `idx_anchors_open` is the only signal a silent backend
    /// outage produces, since anchoring never blocks the write it follows.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the update fails.
    #[instrument(skip(pool, reason))]
    pub async fn mark_failed(pool: &PgPool, id: Uuid, reason: &str) -> Result<(), DbError> {
        sqlx::query!(
            r#"UPDATE anchors SET status = 'failed', failure_reason = $2 WHERE id = $1"#,
            id,
            reason,
        )
        .execute(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(())
    }

    /// The live (non-`failed`) anchor for one root on one backend/network.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn get_live(
        pool: &PgPool,
        root_type: &str,
        root_id: Uuid,
        backend: &str,
        network: &str,
    ) -> Result<Option<AnchorRow>, DbError> {
        let row = sqlx::query_as!(
            AnchorRow,
            r#"
            SELECT id, root_type, root_id, root_hash, commitment_version,
                   commitment_hash, commitment_bytes, backend, network, status,
                   tx_id, block_height, block_time, sealed_at, submitted_at,
                   confirmed_at, failure_reason, created_at
            FROM anchors
            WHERE root_type = $1 AND root_id = $2 AND backend = $3 AND network = $4
              AND status <> 'failed'
            "#,
            root_type,
            root_id,
            backend,
            network,
        )
        .fetch_optional(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(row)
    }

    /// Fetch one anchor by id.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<AnchorRow>, DbError> {
        let row = sqlx::query_as!(
            AnchorRow,
            r#"
            SELECT id, root_type, root_id, root_hash, commitment_version,
                   commitment_hash, commitment_bytes, backend, network, status,
                   tx_id, block_height, block_time, sealed_at, submitted_at,
                   confirmed_at, failure_reason, created_at
            FROM anchors
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(row)
    }

    /// Anchors still awaiting confirmation, oldest first — the `idx_anchors_open`
    /// read path, driven by `AnchorService::poll_pending`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn list_open(pool: &PgPool, limit: i64) -> Result<Vec<AnchorRow>, DbError> {
        let rows = sqlx::query_as!(
            AnchorRow,
            r#"
            SELECT id, root_type, root_id, root_hash, commitment_version,
                   commitment_hash, commitment_bytes, backend, network, status,
                   tx_id, block_height, block_time, sealed_at, submitted_at,
                   confirmed_at, failure_reason, created_at
            FROM anchors
            WHERE status IN ('pending', 'submitted')
            ORDER BY created_at
            LIMIT $1
            "#,
            limit,
        )
        .fetch_all(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(rows)
    }

    /// Every anchor, newest first — what `anchor_verify --all` sweeps.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn list_all(pool: &PgPool, limit: i64) -> Result<Vec<AnchorRow>, DbError> {
        let rows = sqlx::query_as!(
            AnchorRow,
            r#"
            SELECT id, root_type, root_id, root_hash, commitment_version,
                   commitment_hash, commitment_bytes, backend, network, status,
                   tx_id, block_height, block_time, sealed_at, submitted_at,
                   confirmed_at, failure_reason, created_at
            FROM anchors
            ORDER BY created_at DESC
            LIMIT $1
            "#,
            limit,
        )
        .fetch_all(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(rows)
    }
}

/// SQL for the mock ledger. Called ONLY by
/// [`MockAnchorBackend`](crate::anchor::MockAnchorBackend).
///
/// `anchor_mock_chain` is append-only at the trigger level and deliberately
/// separate from `anchors`, so verification compares two stores that a
/// tamperer would have to edit consistently — and cannot, because the mock
/// chain refuses UPDATE and DELETE outright.
pub struct MockChainRepository;

impl MockChainRepository {
    /// Take the next block height from `anchor_mock_chain_height_seq`.
    ///
    /// Separate from [`publish`](Self::publish) because the transaction id is
    /// derived from the height: `hex(BLAKE3(commitment_bytes || height_be))`.
    /// A sequence rather than `MAX(block_height) + 1` so concurrent publishers
    /// cannot collide, and heights are never reused even after a failed
    /// attempt.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn next_block_height(pool: &PgPool) -> Result<i64, DbError> {
        let height =
            sqlx::query_scalar!(r#"SELECT nextval('anchor_mock_chain_height_seq') AS "height!""#)
                .fetch_one(pool)
                .await
                .map_err(|source| DbError::QueryFailed { source })?;
        Ok(height)
    }

    /// Append one published commitment to the mock ledger.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the insert fails, including on a
    /// duplicate `tx_id` — republishing identical bytes at the same height is
    /// a caller bug, not something to paper over.
    #[instrument(skip(pool, metadata_cbor), fields(bytes = metadata_cbor.len()))]
    pub async fn publish(
        pool: &PgPool,
        tx_id: &str,
        metadata_label: i64,
        metadata_cbor: &[u8],
        block_height: i64,
    ) -> Result<MockChainRow, DbError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO anchor_mock_chain (tx_id, metadata_label, metadata_cbor, block_height)
            VALUES ($1, $2, $3, $4)
            RETURNING tx_id, metadata_label, metadata_cbor, block_height, block_time
            "#,
            tx_id,
            metadata_label,
            metadata_cbor,
            block_height,
        )
        .fetch_one(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        Ok(MockChainRow {
            tx_id: row.tx_id,
            metadata_label: row.metadata_label,
            metadata_cbor: row.metadata_cbor,
            block_height: row.block_height,
            block_time: row.block_time,
        })
    }

    /// Read a published commitment back out of the ledger.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn fetch(pool: &PgPool, tx_id: &str) -> Result<Option<MockChainRow>, DbError> {
        let row = sqlx::query_as!(
            MockChainRow,
            r#"
            SELECT tx_id, metadata_label, metadata_cbor, block_height, block_time
            FROM anchor_mock_chain
            WHERE tx_id = $1
            "#,
            tx_id,
        )
        .fetch_optional(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(row)
    }

    /// The ledger's current tip, or `None` when nothing has been published.
    ///
    /// Used only to report depth: `tip - block_height` is the mock's
    /// confirmation count, so a caller that demands N confirmations behaves
    /// the same against the mock as against a real chain.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn tip_height(pool: &PgPool) -> Result<Option<i64>, DbError> {
        let tip = sqlx::query_scalar!(r#"SELECT MAX(block_height) FROM anchor_mock_chain"#)
            .fetch_one(pool)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        Ok(tip)
    }
}
