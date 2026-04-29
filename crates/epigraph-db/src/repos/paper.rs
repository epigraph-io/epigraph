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
}
