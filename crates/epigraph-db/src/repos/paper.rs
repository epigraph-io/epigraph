//! Paper entity repository.
//!
//! Papers are first-class graph nodes (entity_type = "paper") used by
//! hierarchical document ingestion. The `papers` table has a UNIQUE
//! constraint on `doi`, so re-ingestion of the same DOI returns the
//! existing paper id (get-or-create semantics) rather than creating a
//! second row. Re-ingestion is gated separately via the `processed_by`
//! edge with a `pipeline` property.

use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

#[derive(Debug, Clone)]
pub struct PaperRow {
    pub id: Uuid,
    pub doi: String,
    pub title: Option<String>,
    pub journal: Option<String>,
}

pub struct PaperRepository;

impl PaperRepository {
    /// Insert a paper, or return the existing id if the DOI already exists.
    ///
    /// On conflict (UNIQUE doi), updates `title` and `journal` to the
    /// provided values when non-null. Idempotent for repeat ingestion.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_or_create(
        pool: &PgPool,
        doi: &str,
        title: Option<&str>,
        journal: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO papers (doi, title, journal)
            VALUES ($1, $2, $3)
            ON CONFLICT (doi) DO UPDATE SET
                title = COALESCE(EXCLUDED.title, papers.title),
                journal = COALESCE(EXCLUDED.journal, papers.journal)
            RETURNING id
            "#,
            doi,
            title,
            journal,
        )
        .fetch_one(pool)
        .await?;
        Ok(row.id)
    }

    /// Find a paper by DOI. Returns `None` if no paper has this DOI.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn find_by_doi(pool: &PgPool, doi: &str) -> Result<Option<PaperRow>, DbError> {
        // Use `as "title?"` to override sqlx introspection: the migration
        // declares `title` nullable; the dev DB has historical NOT NULL drift.
        let row = sqlx::query!(
            r#"
            SELECT id, doi, title as "title?", journal
            FROM papers
            WHERE doi = $1
            "#,
            doi
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|r| PaperRow {
            id: r.id,
            doi: r.doi,
            title: r.title,
            journal: r.journal,
        }))
    }

    /// Returns true if the paper has any outgoing `processed_by` edge whose
    /// `properties.pipeline` matches `pipeline_version`. Used as the
    /// re-ingestion version gate by hierarchical ingestion.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn has_processed_by_edge(
        pool: &PgPool,
        paper_id: Uuid,
        pipeline_version: &str,
    ) -> Result<bool, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT 1 AS exists_marker
            FROM edges
            WHERE source_id = $1
              AND source_type = 'paper'
              AND relationship = 'processed_by'
              AND properties ->> 'pipeline' = $2
            LIMIT 1
            "#,
            paper_id,
            pipeline_version,
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.is_some())
    }

    /// Count the claims this paper asserts (`paper -asserts-> claim` edges).
    ///
    /// This alone under-counts a partially-ingested paper: `do_ingest_document`
    /// / `do_ingest_document_spine` label every claim `doi:<doi>` *before*
    /// writing that claim's `asserts` edge (evidence + reasoning-trace writes
    /// sit in between), so a crash or error mid-loop can leave claims with the
    /// doi label but no edge yet. Callers that need an accurate "has this DOI
    /// landed in the graph at all?" probe must combine this with
    /// [`Self::count_claims_by_doi_label`] (see `query_paper`) — trusting this
    /// alone as a duplicate-ingestion gate is the write-order race behind
    /// backlog 7c6ce1b3-b372-4727-a510-43e63001bf18 (the specific claims that
    /// prompted that report predate the `doi:<doi>` label entirely and were
    /// resolved separately by a full re-ingestion; this closes the gap for
    /// future partial ingestions under the current write order).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count_asserted_claims(pool: &PgPool, paper_id: Uuid) -> Result<i64, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "count!"
            FROM edges
            WHERE source_id = $1
              AND source_type = 'paper'
              AND target_type = 'claim'
              AND relationship = 'asserts'
            "#,
            paper_id,
        )
        .fetch_one(pool)
        .await?;
        Ok(row.count)
    }

    /// Count current claims labelled `doi:<doi>`, independent of whether a
    /// `paper -asserts-> claim` edge exists yet for them.
    ///
    /// Every claim written by `do_ingest_document` / `do_ingest_document_spine`
    /// picks up this label as soon as the claim row itself is created — ahead
    /// of the `asserts` edge, which lands only after evidence + reasoning-trace
    /// writes succeed. This makes the label a more direct "does this DOI have
    /// node presence in the graph?" signal than the edge-based count, and is
    /// what `query_paper` uses to avoid mis-reporting `claim_count=0` for a
    /// paper that was partially ingested.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count_claims_by_doi_label(pool: &PgPool, doi: &str) -> Result<i64, DbError> {
        let label = format!("doi:{doi}");
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "count!"
            FROM claims
            WHERE is_current
              AND labels @> ARRAY[$1]::text[]
            "#,
            label,
        )
        .fetch_one(pool)
        .await?;
        Ok(row.count)
    }

    /// List the authors of a paper as `(agent_id, display_name)` pairs,
    /// resolved via `agent -authored-> paper` edges.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_authors(
        pool: &PgPool,
        paper_id: Uuid,
    ) -> Result<Vec<(Uuid, Option<String>)>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT a.id AS "id!", a.display_name
            FROM edges e
            JOIN agents a ON a.id = e.source_id
            WHERE e.target_id = $1
              AND e.target_type = 'paper'
              AND e.source_type = 'agent'
              AND e.relationship = 'authored'
            ORDER BY a.display_name NULLS LAST, a.id
            "#,
            paper_id,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.id, r.display_name)).collect())
    }

    /// List claim summaries asserted by this paper, up to `limit` rows,
    /// reached via `paper -asserts-> claim` edges. Ordered by claim
    /// `created_at` ascending (ingest order) for stable pagination.
    ///
    /// Returns `(id, content, truth_value, agent_id, content_hash, created_at)`
    /// per claim — the shape `query_paper` needs for `ClaimResponse`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_asserted_claims(
        pool: &PgPool,
        paper_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AssertedClaimRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                c.id          AS "id!",
                c.content     AS "content!",
                c.truth_value AS "truth_value!",
                c.agent_id    AS "agent_id!",
                c.content_hash AS "content_hash!",
                c.created_at  AS "created_at!"
            FROM edges e
            JOIN claims c ON c.id = e.target_id
            WHERE e.source_id = $1
              AND e.source_type = 'paper'
              AND e.target_type = 'claim'
              AND e.relationship = 'asserts'
            ORDER BY c.created_at ASC, c.id
            LIMIT $2
            "#,
            paper_id,
            limit,
        )
        .fetch_all(pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                let content_hash: [u8; 32] =
                    r.content_hash
                        .as_slice()
                        .try_into()
                        .map_err(|_| DbError::InvalidData {
                            reason: format!(
                                "claim {} has content_hash of length {} (expected 32)",
                                r.id,
                                r.content_hash.len()
                            ),
                        })?;
                Ok(AssertedClaimRow {
                    id: r.id,
                    content: r.content,
                    truth_value: r.truth_value,
                    agent_id: r.agent_id,
                    content_hash,
                    created_at: r.created_at,
                })
            })
            .collect()
    }
}

/// Minimal claim shape returned by [`PaperRepository::list_asserted_claims`].
#[derive(Debug, Clone)]
pub struct AssertedClaimRow {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub agent_id: Uuid,
    pub content_hash: [u8; 32],
    pub created_at: chrono::DateTime<chrono::Utc>,
}
