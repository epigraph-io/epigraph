//! Handler for `EpiGraphJob::ThemeClusterRebuild`.
//!
//! Sibling to `cluster_graph::ClusterGraphHandler`. Runs the same shared
//! k-means helper used by `POST /api/v1/themes/build-from-corpus` (so the
//! cron and the route stay in lock-step) but with `wipe_first = true` and
//! a higher `limit`, suitable for an unattended overnight rebuild.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use epigraph_db::ClaimThemeRepository;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    run_serialized, EpiGraphJob, Job, JobError, JobHandler, JobQueue, JobResult, JobResultMetadata,
    THEME_REBUILD_LOCK_KEY,
};

/// Job handler for the scheduled theme rebuild.
pub struct ThemeClusterRebuildHandler {
    pool: Arc<PgPool>,
    /// Optional queue used to enqueue a follow-up `ClusterGraph` job after
    /// a non-skipped rebuild.  `wipe_first` cascades into
    /// `graph_neighborhoods.theme_id` (ON DELETE CASCADE), so we re-run
    /// `ClusterGraph` immediately to refill the table rather than wait up
    /// to 24 h for the next scheduled run.  `None` in tests (the test
    /// path uses [`Self::handle_direct`] which bypasses the queue).
    followup_queue: Option<Arc<dyn JobQueue>>,
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
    /// Construct a handler bound to a connection pool.  No follow-up
    /// `ClusterGraph` enqueue happens in this configuration (used by
    /// tests and library callers that don't care about
    /// `graph_neighborhoods` self-healing).
    #[must_use]
    pub const fn new(pool: Arc<PgPool>) -> Self {
        Self {
            pool,
            followup_queue: None,
        }
    }

    /// Construct a handler that re-enqueues a `ClusterGraph` job after
    /// every non-skipped rebuild.  Used by the API server so a daily
    /// `theme_cluster_rebuild` cron immediately repopulates
    /// `graph_neighborhoods` (which `wipe_first` cascades through) rather
    /// than waiting up to 24 h for the next ClusterGraph cron tick.
    #[must_use]
    pub const fn with_followup_queue(pool: Arc<PgPool>, queue: Arc<dyn JobQueue>) -> Self {
        Self {
            pool,
            followup_queue: Some(queue),
        }
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
            // 2000 claims for centroid computation only; the assign-all
            // phase assigns the remaining corpus via pgvector ANN.
            limit: 2000,
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

        // Phase 2: Assign every remaining unthemed claim to its nearest centroid.
        // The k-means sample (limit=2000) assigned ~2000 claims; the corpus has
        // 400K+. Loop assign_unthemed_batch until exhausted.
        let mut assign_all_total: i64 = 0;
        let mut assign_batch_num: u32 = 0;
        loop {
            let batch = ClaimThemeRepository::assign_unthemed_batch(pool, 2000)
                .await
                .map_err(|e| JobError::ProcessingFailed {
                    message: format!("assign-all batch {assign_batch_num}: {e}"),
                })?;
            if batch == 0 {
                break;
            }
            assign_all_total += batch;
            assign_batch_num += 1;
            tracing::info!(
                batch = assign_batch_num,
                batch_assigned = batch,
                total_assigned = assign_all_total,
                "theme_cluster_rebuild: assign-all progress"
            );
        }
        tracing::info!(
            total_assigned = assign_all_total,
            batches = assign_batch_num,
            "theme_cluster_rebuild: assign-all complete"
        );

        // Phase 3: Recompute centroids from the full assignment set.
        // k-means centroids were computed from a 2000-claim sample;
        // after assign-all they should reflect the true cluster geometry.
        ClaimThemeRepository::recompute_all_centroids(pool)
            .await
            .map_err(|e| JobError::ProcessingFailed {
                message: format!("recompute_all_centroids: {e}"),
            })?;
        tracing::info!("theme_cluster_rebuild: centroids recomputed from full assignment");

        Ok(HandleSummary {
            skipped: false,
            themes_created: summary.themes_created,
            claims_assigned: summary.claims_assigned + assign_all_total as usize,
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

        // Serialize: at most one theme rebuild runs at a time across workers
        // AND processes. `wipe_first` makes a concurrent second run especially
        // destructive, so a contended run is a cheap no-op.
        let pool_for_body = Arc::clone(&self.pool);
        let outcome = run_serialized(self.pool.as_ref(), THEME_REBUILD_LOCK_KEY, async move {
            Self::handle_direct(
                pool_for_body.as_ref(),
                max_themes,
                min_claims_per_theme,
                skip_if_unchanged,
            )
            .await
        })
        .await?;

        let Some(summary) = outcome else {
            tracing::info!("theme_cluster_rebuild: another run holds the advisory lock; skipping");
            return Ok(JobResult {
                output: serde_json::json!({ "skipped_locked": true }),
                execution_duration: started.elapsed(),
                metadata: JobResultMetadata {
                    worker_id: Some("theme-cluster-rebuild".into()),
                    items_processed: Some(0),
                    extra: std::collections::HashMap::default(),
                },
            });
        };

        // Self-heal `graph_neighborhoods` after a `wipe_first` cascade.
        // The skip path leaves the row set intact, so we only need to
        // re-run ClusterGraph when the rebuild actually wiped rows.
        if !summary.skipped {
            if let Some(queue) = self.followup_queue.as_ref() {
                match (EpiGraphJob::ClusterGraph {
                    resolution: 1.0,
                    retain_runs: 3,
                })
                .into_job()
                {
                    Ok(followup) => match queue.enqueue_unique_pending(followup).await {
                        Ok(Some(_)) => tracing::info!(
                            "theme_cluster_rebuild: enqueued follow-up ClusterGraph to refill graph_neighborhoods"
                        ),
                        Ok(None) => tracing::info!(
                            "theme_cluster_rebuild: follow-up ClusterGraph already pending; not re-enqueued"
                        ),
                        Err(e) => tracing::error!(
                            error = %e,
                            "theme_cluster_rebuild: failed to enqueue follow-up ClusterGraph job"
                        ),
                    },
                    Err(e) => tracing::error!(
                        error = %e,
                        "theme_cluster_rebuild: failed to serialize follow-up ClusterGraph job"
                    ),
                }
            } else {
                tracing::debug!(
                    "theme_cluster_rebuild: no follow-up queue registered; \
                     graph_neighborhoods will be repopulated on next ClusterGraph cron"
                );
            }
        }

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
