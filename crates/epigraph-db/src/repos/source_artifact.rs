//! Repository for `source_artifacts` — the per-rendition node of essence
//! binding (backlog 7c909c49).
//!
//! # What a rendition is
//!
//! A `papers` row models a DOCUMENT IDENTITY: `papers.doi` is UNIQUE and its
//! only writer is [`PaperRepository::get_or_create`](crate::PaperRepository),
//! so a preprint and the published PDF of the same work are one row. A
//! *rendition* is the other thing — one exact byte payload that some ingest
//! run actually consumed. One document has many renditions over its life; a
//! scalar `papers.essence_digest` would be silently overwritten by the next
//! re-ingest and would take every previously-asserted claim's binding with it.
//!
//! So the rendition is its own node, keyed by content, joined to its document
//! by a `paper -has_essence-> source_artifact` edge. `source_artifacts` has
//! existed since migration 001 with an unused `content_hash BYTEA`, is a
//! registered entity type since 054, and resolves on `validate_edge_reference`'s
//! fast path since 055 — it needed no new table, only the uniqueness migration
//! 074 adds.
//!
//! # The key is GLOBAL, not per-paper
//!
//! `uq_source_artifacts_essence_hash` (migration 074) is
//! `UNIQUE (content_hash) WHERE artifact_type = 'essence'`, mirroring the
//! `blobs` model: two papers over byte-identical essence converge on ONE
//! rendition row carrying TWO `has_essence` edges. Per-paper uniqueness is not
//! expressible on this table at all, because the paper linkage is an edge and
//! not a column.

use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

/// Verb on the `paper -has_essence-> source_artifact` edge.
///
/// Deliberately NOT added to `GRAPH_VIEW_RELATIONSHIPS`: essence edges are
/// integrity infrastructure, not GUI node expansion.
pub const HAS_ESSENCE_RELATIONSHIP: &str = "has_essence";

pub struct SourceArtifactRepository;

impl SourceArtifactRepository {
    /// Get-or-create the rendition row for `digest`.
    ///
    /// Returns `(id, was_created)`. `was_created = false` means these exact
    /// bytes were already recorded — by an earlier ingest of this document, or
    /// by a different document that happens to have identical essence — and the
    /// existing row is returned untouched.
    ///
    /// `ON CONFLICT DO NOTHING` + re-SELECT rather than `DO UPDATE`, matching
    /// [`BlobRepository::store`](crate::BlobRepository::store): the row records
    /// who first observed these bytes, so a later observer must not rewrite its
    /// `name`, `agent_id` or `properties`.
    ///
    /// # Errors
    /// - [`DbError::QueryFailed`] on a database error.
    /// - [`DbError::InvalidData`] in the (concurrent-DELETE only) case where
    ///   the insert conflicted but the conflicting row was gone by the
    ///   re-SELECT.
    #[instrument(skip(pool, properties))]
    pub async fn upsert_essence_rendition(
        pool: &PgPool,
        agent_id: Uuid,
        name: &str,
        digest: &[u8; 32],
        properties: &serde_json::Value,
    ) -> Result<(Uuid, bool), DbError> {
        let inserted = sqlx::query_scalar!(
            r#"
            INSERT INTO source_artifacts (agent_id, name, artifact_type, content_hash, properties)
            VALUES ($1, $2, 'essence', $3, $4)
            ON CONFLICT (content_hash) WHERE artifact_type = 'essence' AND content_hash IS NOT NULL
            DO NOTHING
            RETURNING id
            "#,
            agent_id,
            name,
            &digest[..],
            properties,
        )
        .fetch_optional(pool)
        .await?;

        if let Some(id) = inserted {
            return Ok((id, true));
        }

        let existing = sqlx::query_scalar!(
            r#"
            SELECT id
            FROM source_artifacts
            WHERE artifact_type = 'essence' AND content_hash = $1
            "#,
            &digest[..],
        )
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| DbError::InvalidData {
            reason: "essence rendition insert conflicted but the conflicting row vanished"
                .to_string(),
        })?;
        Ok((existing, false))
    }
}
