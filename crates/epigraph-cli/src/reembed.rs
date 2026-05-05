//! Idempotent, resumable batch re-embedding from `text-embedding-3-small`
//! (1536d) to `text-embedding-3-large` (3072d).
//!
//! Operates on `claims` and `evidence` tables. Pulls rows whose 3072d column
//! is NULL, generates embeddings via the supplied `EmbeddingService`, and
//! UPDATEs the `embedding_3072` column. Optional checkpoint file (last `id`
//! written, as a UUID string) lets a crashed run resume cheaply.
//!
//! Idempotent: re-running over already-populated rows fetches zero rows
//! (filter is `WHERE embedding_3072 IS NULL`). Resumable: filter
//! `id > $last_id ORDER BY id` continues from the checkpoint UUID.

use std::path::PathBuf;
use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_embeddings::{EmbeddingError, EmbeddingService};

/// Config for a single reembed run.
pub struct ReembedConfig {
    pub target: ReembedTarget,
    pub batch_size: usize,
    pub embedding_provider: Arc<dyn EmbeddingService>,
    pub checkpoint_path: Option<PathBuf>,
}

/// Which table to reembed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReembedTarget {
    Claims,
    Evidence,
}

impl ReembedTarget {
    /// Table name in SQL.
    fn table(self) -> &'static str {
        match self {
            Self::Claims => "claims",
            Self::Evidence => "evidence",
        }
    }

    /// Column holding the source text for embedding.
    fn content_column(self) -> &'static str {
        match self {
            // claims.content is the canonical text column.
            Self::Claims => "content",
            // evidence.raw_content is the text column (see migration 001).
            Self::Evidence => "raw_content",
        }
    }
}

/// Summary of a completed reembed run.
#[derive(Debug, Clone)]
pub struct ReembedSummary {
    pub rows_written: usize,
    pub batches: usize,
}

#[derive(thiserror::Error, Debug)]
pub enum ReembedError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("embedding provider error: {0}")]
    Provider(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid checkpoint contents: {0}")]
    InvalidCheckpoint(String),
}

impl From<EmbeddingError> for ReembedError {
    fn from(e: EmbeddingError) -> Self {
        Self::Provider(e.to_string())
    }
}

/// Run the reembed loop until no rows remain.
///
/// # Errors
/// Returns an error if the database, embedding provider, or checkpoint I/O fails.
pub async fn run(pool: &PgPool, config: ReembedConfig) -> Result<ReembedSummary, ReembedError> {
    let mut last_id = read_checkpoint(config.checkpoint_path.as_ref())?;
    let mut rows_written = 0_usize;
    let mut batches = 0_usize;

    loop {
        let rows = fetch_batch(pool, config.target, last_id, config.batch_size).await?;
        if rows.is_empty() {
            break;
        }

        let texts: Vec<&str> = rows.iter().map(|(_, c)| c.as_str()).collect();
        let embeddings = config.embedding_provider.batch_generate(&texts).await?;
        if embeddings.len() != rows.len() {
            return Err(ReembedError::Provider(format!(
                "provider returned {} embeddings for {} inputs",
                embeddings.len(),
                rows.len()
            )));
        }

        for ((row_id, _), embedding) in rows.iter().zip(embeddings.iter()) {
            let pgvec = format_pgvector(embedding);
            update_embedding_3072(pool, config.target, *row_id, &pgvec).await?;
            rows_written += 1;
        }

        // Advance checkpoint to last id of this batch.
        if let Some(last) = rows.last() {
            last_id = Some(last.0);
            write_checkpoint(config.checkpoint_path.as_ref(), last.0)?;
        }
        batches += 1;

        if rows.len() < config.batch_size {
            // Last partial batch; next loop would return zero anyway.
            break;
        }
    }

    Ok(ReembedSummary {
        rows_written,
        batches,
    })
}

/// Fetch a batch of rows whose `embedding_3072` is NULL, ordered by id.
async fn fetch_batch(
    pool: &PgPool,
    target: ReembedTarget,
    last_id: Option<Uuid>,
    batch_size: usize,
) -> Result<Vec<(Uuid, String)>, ReembedError> {
    let table = target.table();
    let content_col = target.content_column();

    let sql = format!(
        "SELECT id, {content_col} AS content \
         FROM {table} \
         WHERE embedding_3072 IS NULL \
           AND ($1::uuid IS NULL OR id > $1) \
           AND {content_col} IS NOT NULL \
           AND length({content_col}) > 0 \
         ORDER BY id \
         LIMIT $2"
    );

    let rows: Vec<(Uuid, String)> = sqlx::query_as(&sql)
        .bind(last_id)
        .bind(i64::try_from(batch_size).unwrap_or(i64::MAX))
        .fetch_all(pool)
        .await?;

    Ok(rows)
}

/// UPDATE one row's `embedding_3072` column.
async fn update_embedding_3072(
    pool: &PgPool,
    target: ReembedTarget,
    id: Uuid,
    pgvec: &str,
) -> Result<(), ReembedError> {
    let table = target.table();
    let sql = format!("UPDATE {table} SET embedding_3072 = $1::vector WHERE id = $2");
    sqlx::query(&sql).bind(pgvec).bind(id).execute(pool).await?;
    Ok(())
}

/// Format a `&[f32]` as pgvector literal `[a,b,c,...]`.
fn format_pgvector(vec: &[f32]) -> String {
    let inner: Vec<String> = vec.iter().map(|v| format!("{v}")).collect();
    format!("[{}]", inner.join(","))
}

fn read_checkpoint(path: Option<&PathBuf>) -> Result<Option<Uuid>, ReembedError> {
    let Some(path) = path else { return Ok(None) };
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let id = Uuid::parse_str(trimmed).map_err(|e| {
        ReembedError::InvalidCheckpoint(format!("expected UUID, got {trimmed}: {e}"))
    })?;
    Ok(Some(id))
}

fn write_checkpoint(path: Option<&PathBuf>, id: Uuid) -> Result<(), ReembedError> {
    let Some(path) = path else { return Ok(()) };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, id.to_string())?;
    Ok(())
}
