//! Handler for `EpiGraphJob::ThemeClusterRebuild`.
//!
//! Sibling to `cluster_graph::ClusterGraphHandler`. Runs the same shared
//! k-means helper used by `POST /api/v1/themes/build-from-corpus` (so the
//! cron and the route stay in lock-step) but with `wipe_first = true` and
//! a higher `limit`, suitable for an unattended overnight rebuild.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;

use crate::{EpiGraphJob, Job, JobError, JobHandler, JobResult, JobResultMetadata};

/// Job handler for the scheduled theme rebuild.
pub struct ThemeClusterRebuildHandler {
    pool: Arc<PgPool>,
}

/// Summary returned by [`ThemeClusterRebuildHandler::handle_direct`].
#[derive(Debug, Clone)]
pub struct HandleSummary {
    /// `true` when the skip-check (corpus unchanged since last theme
    /// update) short-circuited the rebuild.
    pub skipped: bool,
    /// Number of themes the rebuild created (0 on the skip path).
    pub themes_created: usize,
    /// Total claims assigned across all created themes.
    pub claims_assigned: usize,
}

impl ThemeClusterRebuildHandler {
    /// Construct a handler bound to a connection pool.
    #[must_use]
    pub const fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Direct-call entry point for tests and library callers that don't
    /// want to construct a `Job` envelope.
    ///
    /// # Errors
    /// Returns `JobError::ProcessingFailed` if the skip-check or k-means
    /// rebuild fails.
    pub async fn handle_direct(
        pool: &PgPool,
        max_themes: u32,
        min_claims_per_theme: u32,
        skip_if_unchanged: bool,
    ) -> Result<HandleSummary, JobError> {
        if skip_if_unchanged
            && is_corpus_unchanged(pool)
                .await
                .map_err(|e| JobError::ProcessingFailed {
                    message: format!("skip-check: {e}"),
                })?
        {
            tracing::info!("theme_cluster_rebuild: corpus unchanged; skipping");
            return Ok(HandleSummary {
                skipped: true,
                themes_created: 0,
                claims_assigned: 0,
            });
        }

        let config = epigraph_engine::theme_kmeans::RunThemeKmeansConfig {
            k: None,
            k_min: 4,
            k_max: max_themes,
            min_claims_per_theme,
            // 5000 is a reasonable upper bound for the cron rebuild — large
            // enough to cover the wrhq-scale corpus, small enough that
            // linfa k-means stays well under the 2 GB VM RAM ceiling.
            limit: 5000,
            label_prefix: "auto".to_string(),
            // Scheduled rebuild replaces existing themes wholesale; the
            // skip-check above ensures we only do this when the corpus
            // has actually changed.
            wipe_first: true,
            // Start with 1536d; a separate cron at 3072d can be added once
            // `claims.embedding_3072` is populated cluster-wide.
            centroid_dim: 1536,
        };
        let summary = epigraph_engine::theme_kmeans::run_theme_kmeans(pool, &config)
            .await
            .map_err(|e| JobError::ProcessingFailed {
                message: format!("theme rebuild: {e}"),
            })?;

        Ok(HandleSummary {
            skipped: false,
            themes_created: summary.themes_created,
            claims_assigned: summary.claims_assigned,
        })
    }
}

#[async_trait]
impl JobHandler for ThemeClusterRebuildHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        let epigraph_job: EpiGraphJob =
            serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
                message: format!("Failed to deserialize ThemeClusterRebuild payload: {e}"),
            })?;
        let EpiGraphJob::ThemeClusterRebuild {
            max_themes,
            min_claims_per_theme,
            skip_if_unchanged,
        } = epigraph_job
        else {
            return Err(JobError::PayloadError {
                message: format!(
                    "Expected ThemeClusterRebuild job, got: {}",
                    epigraph_job.job_type()
                ),
            });
        };

        let started = std::time::Instant::now();
        let summary = Self::handle_direct(
            &self.pool,
            max_themes,
            min_claims_per_theme,
            skip_if_unchanged,
        )
        .await?;

        Ok(JobResult {
            output: serde_json::json!({
                "skipped": summary.skipped,
                "themes_created": summary.themes_created,
                "claims_assigned": summary.claims_assigned,
            }),
            execution_duration: started.elapsed(),
            metadata: JobResultMetadata {
                worker_id: Some("theme-cluster-rebuild".into()),
                items_processed: Some(summary.themes_created as u64),
                extra: std::collections::HashMap::default(),
            },
        })
    }

    fn job_type(&self) -> &'static str {
        "theme_cluster_rebuild"
    }

    // OOM/timeout: leave the previous theme set intact, fail loudly.
    fn max_retries(&self) -> u32 {
        1
    }
}

/// Returns `true` when the most recent theme update is at-or-after the
/// most recent change in the claim corpus, i.e. the rebuild has nothing
/// to do.
///
/// We use plain `sqlx::query` (not the macro) so this compiles even when
/// `DATABASE_URL` is unreachable and the offline `.sqlx/` cache hasn't
/// been refreshed for these new queries.
async fn is_corpus_unchanged(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let theme_update_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT MAX(updated_at) FROM claim_themes")
            .fetch_one(pool)
            .await?;
    let corpus_change_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT GREATEST(MAX(created_at), MAX(updated_at)) FROM claims")
            .fetch_one(pool)
            .await?;

    Ok(theme_update_at.is_some()
        && corpus_change_at.is_some()
        && theme_update_at >= corpus_change_at)
}
