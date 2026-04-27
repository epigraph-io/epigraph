use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;

use super::runner::{run_clustering, RunConfig};
use crate::{EpiGraphJob, Job, JobError, JobHandler, JobResult, JobResultMetadata};

pub struct ClusterGraphHandler {
    pool: Arc<PgPool>,
}

impl ClusterGraphHandler {
    #[must_use]
    pub const fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl JobHandler for ClusterGraphHandler {
    async fn handle(&self, job: &Job) -> Result<JobResult, JobError> {
        let epigraph_job: EpiGraphJob =
            serde_json::from_value(job.payload.clone()).map_err(|e| JobError::PayloadError {
                message: format!("Failed to deserialize ClusterGraph payload: {e}"),
            })?;
        let EpiGraphJob::ClusterGraph {
            resolution,
            retain_runs,
        } = epigraph_job
        else {
            return Err(JobError::PayloadError {
                message: format!(
                    "Expected ClusterGraph job, got: {}",
                    epigraph_job.job_type()
                ),
            });
        };

        let started = std::time::Instant::now();
        let summary = run_clustering(
            &self.pool,
            &RunConfig {
                resolution,
                retain_runs,
            },
        )
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: e.to_string(),
        })?;

        let mut extra = std::collections::HashMap::new();
        extra.insert("run_id".into(), serde_json::json!(summary.run_id));
        extra.insert(
            "cluster_count".into(),
            serde_json::json!(summary.cluster_count),
        );
        extra.insert("degraded".into(), serde_json::json!(summary.degraded));

        Ok(JobResult {
            output: serde_json::json!({
                "run_id": summary.run_id,
                "cluster_count": summary.cluster_count,
                "degraded": summary.degraded,
            }),
            execution_duration: started.elapsed(),
            metadata: JobResultMetadata {
                worker_id: Some("cluster-graph".into()),
                items_processed: Some(summary.cluster_count as u64),
                extra,
            },
        })
    }

    fn job_type(&self) -> &'static str {
        "cluster_graph"
    }

    // OOM/timeout: leave the previous run intact, fail loudly.
    fn max_retries(&self) -> u32 {
        1
    }
}
