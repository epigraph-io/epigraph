//! Merkle manifests: signed commitments over a SET of graph rows
//! (backlog 6e2364b8, `migrations/071_manifests.sql`).
//!
//! Per CLAUDE.md every statement this feature issues lives here — the engine's
//! `export::manifest` and the two MCP tools call these functions and never write
//! manifest SQL of their own.
//!
//! # Only the write-once columns are read
//!
//! [`load_claim_leaf_inputs`](ManifestRepository::load_claim_leaf_inputs) and
//! [`load_edge_leaf_inputs`](ManifestRepository::load_edge_leaf_inputs) select a
//! deliberately narrow projection — `(id, content_hash, agent_id, created_at)`
//! for claims, `(id, relationship, created_at)` for edges. Those are the columns
//! with no production UPDATE path, and they are precisely what the leaf commits
//! to. Selecting more would invite a future edit to fold a mutable column into
//! the hash and quietly break every historical root the first time a label was
//! patched or a belief recomputed.
//!
//! `claim_from_row` is untouched: these are new SELECTs over new shapes, not a
//! widening of its signature.
//!
//! # `idx_manifest_entries_row` has no reader
//!
//! That index (`migrations/071_manifests.sql:133`) supports the reverse lookup
//! "which manifests commit to this row?". The `list_for_row` helper that used it
//! never acquired a production caller and was deleted; its only consumer had been
//! a test, which is what made a dead helper look live. The index is KEPT on
//! purpose: dropping it is schema churn on an already-applied migration,
//! `manifest_entries` is append-only so it costs one index write per leaf insert,
//! and it is precisely what a future discovery tool would want.
//!
//! If that tool ever arrives it MUST be scoped. `manifests` / `manifest_entries`
//! carry no ownership or visibility columns, so an unscoped
//! row-id -> manifest-metadata read turns an attacker-chosen row id into the
//! signer's DID and public key plus the `subject` JSON, which itself embeds
//! `root_claim_id`. Every manifest tool shipped today is capability-shaped:
//! `export_subgraph_manifest` and `anchor_manifest` write under the caller's own
//! identity, and `verify_manifest` is keyed by a manifest_id the caller already
//! holds. A row-keyed lookup is the only one that would manufacture a handle from
//! an identifier the caller was never given.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

/// The only `manifests.algo` value this version writes or accepts.
pub const MANIFEST_ALGO: &str = "blake3-merkle-v1";

/// The write-once subset of a `claims` row that a manifest leaf commits to.
#[derive(Debug, Clone)]
pub struct ClaimLeafInput {
    pub id: Uuid,
    /// Exactly 32 bytes (`claims_content_hash_length`).
    pub content_hash: Vec<u8>,
    pub agent_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// The write-once subset of an `edges` row that a manifest leaf commits to.
///
/// `source_id` / `target_id` are absent on purpose: dedup re-sourcing and the
/// retraction cascade legitimately rewrite them, so a leaf that bound the
/// endpoints would break on ordinary maintenance.
#[derive(Debug, Clone)]
pub struct EdgeLeafInput {
    pub id: Uuid,
    pub relationship: String,
    pub created_at: DateTime<Utc>,
}

/// One stored `manifests` row.
#[derive(Debug, Clone)]
pub struct ManifestRow {
    pub id: Uuid,
    pub algo: String,
    /// 32-byte Merkle root.
    pub root: Vec<u8>,
    pub entry_count: i32,
    pub subject: serde_json::Value,
    /// The exact canonical-JSON bytes that were signed.
    pub signed_header: Vec<u8>,
    /// 64-byte Ed25519 signature over `signed_header`.
    pub signature: Vec<u8>,
    /// `None` once the signing agent's row has been deleted (ON DELETE SET
    /// NULL). Verification still works — see `signer_public_key`.
    pub signer_id: Option<Uuid>,
    /// 32-byte Ed25519 public key snapshotted at signing time. THIS, not
    /// `agents.public_key`, is the verification authority.
    pub signer_public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// One stored `manifest_entries` row: a leaf, in canonical position.
#[derive(Debug, Clone)]
pub struct ManifestEntryRow {
    pub manifest_id: Uuid,
    pub position: i32,
    /// `"claim"` or `"edge"` (`manifest_entries_kind_known`).
    pub row_kind: String,
    pub row_id: Uuid,
    /// 32-byte leaf hash.
    pub leaf_hash: Vec<u8>,
}

/// A leaf to persist alongside its manifest, already in canonical order.
#[derive(Debug, Clone)]
pub struct NewManifestEntry {
    pub position: i32,
    pub row_kind: String,
    pub row_id: Uuid,
    pub leaf_hash: Vec<u8>,
}

/// Everything one `INSERT` of a manifest needs.
///
/// `id` and `created_at` are caller-supplied rather than defaulted by Postgres:
/// both are inside the signed header, so letting `DEFAULT gen_random_uuid()` /
/// `DEFAULT NOW()` supply them would guarantee the header and the columns
/// disagree and `header_consistent` would fail on every manifest ever written.
#[derive(Debug, Clone)]
pub struct NewManifest {
    pub id: Uuid,
    pub root: Vec<u8>,
    pub entry_count: i32,
    pub subject: serde_json::Value,
    pub signed_header: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_id: Option<Uuid>,
    pub signer_public_key: Vec<u8>,
    /// Must be microsecond-truncated by the caller, to match what Postgres
    /// stores and what the signed header says.
    pub created_at: DateTime<Utc>,
    pub entries: Vec<NewManifestEntry>,
}

pub struct ManifestRepository;

impl ManifestRepository {
    /// Load the write-once subset of every requested claim.
    ///
    /// Rows that do not exist are simply absent from the result — the caller
    /// (`anchor_manifest`) compares lengths and fails closed, because signing a
    /// commitment to a row you could not read is exactly the silent-omission
    /// bug this feature exists to kill.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool, ids), fields(count = ids.len()))]
    pub async fn load_claim_leaf_inputs(
        pool: &PgPool,
        ids: &[Uuid],
    ) -> Result<Vec<ClaimLeafInput>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query!(
            r#"
            SELECT id, content_hash, agent_id, created_at
            FROM claims
            WHERE id = ANY($1)
            "#,
            ids
        )
        .fetch_all(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        Ok(rows
            .into_iter()
            .map(|r| ClaimLeafInput {
                id: r.id,
                content_hash: r.content_hash,
                agent_id: r.agent_id,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Load the write-once subset of every requested edge.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool, ids), fields(count = ids.len()))]
    pub async fn load_edge_leaf_inputs(
        pool: &PgPool,
        ids: &[Uuid],
    ) -> Result<Vec<EdgeLeafInput>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query!(
            r#"
            SELECT id, relationship, created_at
            FROM edges
            WHERE id = ANY($1)
            "#,
            ids
        )
        .fetch_all(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        Ok(rows
            .into_iter()
            .map(|r| EdgeLeafInput {
                id: r.id,
                relationship: r.relationship,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Write the manifest and all of its leaves in ONE transaction.
    ///
    /// Atomic on purpose: a `manifests` row whose entries only partially landed
    /// would present a signed root over a leaf list that cannot reproduce it —
    /// indistinguishable from tampering at verification time.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if either insert or the commit fails.
    #[instrument(skip(pool, manifest), fields(manifest_id = %manifest.id, entries = manifest.entries.len()))]
    pub async fn insert(pool: &PgPool, manifest: &NewManifest) -> Result<Uuid, DbError> {
        let mut tx = pool
            .begin()
            .await
            .map_err(|source| DbError::QueryFailed { source })?;

        sqlx::query!(
            r#"
            INSERT INTO manifests (id, algo, root, entry_count, subject,
                                   signed_header, signature, signer_id,
                                   signer_public_key, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            manifest.id,
            MANIFEST_ALGO,
            manifest.root,
            manifest.entry_count,
            manifest.subject,
            manifest.signed_header,
            manifest.signature,
            manifest.signer_id,
            manifest.signer_public_key,
            manifest.created_at,
        )
        .execute(&mut *tx)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        // UNNEST rather than a per-row loop: one round trip regardless of set
        // size, and the whole leaf list lands or none of it does.
        let positions: Vec<i32> = manifest.entries.iter().map(|e| e.position).collect();
        let kinds: Vec<String> = manifest
            .entries
            .iter()
            .map(|e| e.row_kind.clone())
            .collect();
        let row_ids: Vec<Uuid> = manifest.entries.iter().map(|e| e.row_id).collect();
        let leaves: Vec<Vec<u8>> = manifest
            .entries
            .iter()
            .map(|e| e.leaf_hash.clone())
            .collect();

        sqlx::query!(
            r#"
            INSERT INTO manifest_entries (manifest_id, position, row_kind, row_id, leaf_hash)
            SELECT $1, p, k, r, l
            FROM UNNEST($2::int[], $3::text[], $4::uuid[], $5::bytea[]) AS t(p, k, r, l)
            "#,
            manifest.id,
            &positions,
            &kinds,
            &row_ids,
            &leaves,
        )
        .execute(&mut *tx)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;

        tx.commit()
            .await
            .map_err(|source| DbError::QueryFailed { source })?;

        Ok(manifest.id)
    }

    /// Fetch one manifest by id.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<ManifestRow>, DbError> {
        let row = sqlx::query_as!(
            ManifestRow,
            r#"
            SELECT id, algo, root, entry_count, subject, signed_header,
                   signature, signer_id, signer_public_key, created_at
            FROM manifests
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(row)
    }

    /// Fetch a manifest's leaves in canonical (stored) order.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn entries(pool: &PgPool, id: Uuid) -> Result<Vec<ManifestEntryRow>, DbError> {
        let rows = sqlx::query_as!(
            ManifestEntryRow,
            r#"
            SELECT manifest_id, position, row_kind, row_id, leaf_hash
            FROM manifest_entries
            WHERE manifest_id = $1
            ORDER BY position
            "#,
            id
        )
        .fetch_all(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(rows)
    }

    /// Count a manifest's leaves.
    ///
    /// Separate from [`entries`](Self::entries) because verification compares
    /// this against the *signed* `entry_count`: a deleted `manifest_entries`
    /// row is caught here even though the surviving leaves still fold to
    /// something.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn count_entries(pool: &PgPool, id: Uuid) -> Result<i64, DbError> {
        let count = sqlx::query_scalar!(
            r#"SELECT COUNT(*) AS "count!" FROM manifest_entries WHERE manifest_id = $1"#,
            id
        )
        .fetch_one(pool)
        .await
        .map_err(|source| DbError::QueryFailed { source })?;
        Ok(count)
    }
}
