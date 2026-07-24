//! Repository for behavioral execution persistence.
//!
//! A behavioral execution records a single run of a workflow against a specific
//! goal, capturing success/failure, step beliefs, tool pattern, and optionally
//! a goal embedding. This data supports task-conditional scoring: the agent can
//! find which workflow works best for goals semantically similar to a new one.
//!
//! Distinct from `workflow_executions` (migration 080) which tracks orchestrator
//! state (task counts, lifecycle). This table focuses on behavioral signal.
//!
//! Uses runtime sqlx queries (not compile-time macros) for SQLX_OFFLINE compatibility.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// A database row from the `behavioral_executions` table.
///
/// `goal_embedding` is stored as a `vector(1536)` column in PostgreSQL but is
/// not directly queryable through `sqlx::FromRow` without the pgvector crate.
/// Callers that need the raw embedding should use a custom projection query.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BehavioralExecutionRow {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub goal_text: String,
    // goal_embedding is omitted: vector(1536) has no sqlx::Decode impl in this crate
    pub success: bool,
    pub step_beliefs: serde_json::Value,
    pub tool_pattern: Vec<String>,
    pub quality: Option<f64>,
    pub deviation_count: i32,
    pub total_steps: i32,
    pub created_at: DateTime<Utc>,
    pub step_claim_id: Option<uuid::Uuid>,
    /// Optional run/variant label distinguishing rows of a parameter sweep.
    pub run_label: Option<String>,
}

/// Repository for `behavioral_executions` table operations.
///
/// All methods are static async and take a `&PgPool`. The goal embedding is
/// passed as a pgvector-formatted string (`"[0.1,0.2,...]"`) to avoid a
/// dependency on the pgvector crate in this crate; the cast `$N::vector` is
/// handled in-query.
pub struct BehavioralExecutionRepository;

impl BehavioralExecutionRepository {
    /// Insert a new behavioral execution row, returning the persisted row
    /// (without the `goal_embedding` column which cannot be decoded here).
    ///
    /// `goal_embedding_pgvec` is an optional pgvector string literal such as
    /// `"[0.1,0.2,...]"`. Pass `None` when no embedding is available.
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` if an execution with the same ID exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool, row, goal_embedding_pgvec))]
    pub async fn create(
        pool: &PgPool,
        row: BehavioralExecutionRow,
        goal_embedding_pgvec: Option<&str>,
    ) -> Result<BehavioralExecutionRow, DbError> {
        let result: BehavioralExecutionRow = if let Some(emb) = goal_embedding_pgvec {
            sqlx::query_as(
                r#"
                INSERT INTO behavioral_executions (
                    id, workflow_id, goal_text, goal_embedding,
                    success, step_beliefs, tool_pattern,
                    quality, deviation_count, total_steps, created_at,
                    step_claim_id, run_label
                )
                VALUES (
                    $1, $2, $3, $4::vector,
                    $5, $6, $7,
                    $8, $9, $10, $11,
                    $12, $13
                )
                RETURNING id, workflow_id, goal_text,
                          success, step_beliefs, tool_pattern,
                          quality, deviation_count, total_steps, created_at,
                          step_claim_id, run_label
                "#,
            )
            .bind(row.id)
            .bind(row.workflow_id)
            .bind(&row.goal_text)
            .bind(emb)
            .bind(row.success)
            .bind(&row.step_beliefs)
            .bind(&row.tool_pattern)
            .bind(row.quality)
            .bind(row.deviation_count)
            .bind(row.total_steps)
            .bind(row.created_at)
            .bind(row.step_claim_id)
            .bind(&row.run_label)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_as(
                r#"
                INSERT INTO behavioral_executions (
                    id, workflow_id, goal_text,
                    success, step_beliefs, tool_pattern,
                    quality, deviation_count, total_steps, created_at,
                    step_claim_id, run_label
                )
                VALUES (
                    $1, $2, $3,
                    $4, $5, $6,
                    $7, $8, $9, $10,
                    $11, $12
                )
                RETURNING id, workflow_id, goal_text,
                          success, step_beliefs, tool_pattern,
                          quality, deviation_count, total_steps, created_at,
                          step_claim_id, run_label
                "#,
            )
            .bind(row.id)
            .bind(row.workflow_id)
            .bind(&row.goal_text)
            .bind(row.success)
            .bind(&row.step_beliefs)
            .bind(&row.tool_pattern)
            .bind(row.quality)
            .bind(row.deviation_count)
            .bind(row.total_steps)
            .bind(row.created_at)
            .bind(row.step_claim_id)
            .bind(&row.run_label)
            .fetch_one(pool)
            .await
        }
        .map_err(|err| {
            if let sqlx::Error::Database(ref db_err) = err {
                if db_err.is_unique_violation() {
                    return DbError::DuplicateKey {
                        entity: "BehavioralExecution".to_string(),
                    };
                }
            }
            DbError::from(err)
        })?;

        Ok(result)
    }

    /// Compute the rolling success rate for a workflow over its last `window`
    /// executions.
    ///
    /// Returns the fraction of successful runs in `[0.0, 1.0]`, or `0.0` if
    /// there are no executions in the window.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn rolling_success_rate(
        pool: &PgPool,
        workflow_id: Uuid,
        window: i64,
    ) -> Result<f64, DbError> {
        // Subquery selects the last `window` rows; outer query aggregates.
        let rate: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(success::int)::float8
            FROM (
                SELECT success
                FROM behavioral_executions
                WHERE workflow_id = $1
                ORDER BY created_at DESC
                LIMIT $2
            ) AS recent
            "#,
        )
        .bind(workflow_id)
        .bind(window)
        .fetch_one(pool)
        .await?;

        Ok(rate.unwrap_or(0.0))
    }

    /// Fetch the most recent `limit` behavioral executions for a workflow,
    /// newest first (by `created_at`).
    ///
    /// Projects every column EXCEPT `goal_embedding` (which has no
    /// `sqlx::Decode` in this crate), matching [`BehavioralExecutionRow`]. This
    /// is the raw-row getter the workflow-evolution (GEPA) proposer reads to
    /// reflect on a workflow's recent runs — `step_beliefs` (per-step
    /// `deviation_reason`), `tool_pattern`, `quality`, `success` — before
    /// proposing a variant. The aggregate methods (`rolling_success_rate`,
    /// `behavioral_affinity`) summarise; this returns the rows themselves.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn recent_executions(
        pool: &PgPool,
        workflow_id: Uuid,
        limit: i64,
    ) -> Result<Vec<BehavioralExecutionRow>, DbError> {
        let rows = sqlx::query_as::<_, BehavioralExecutionRow>(
            r#"
            SELECT id, workflow_id, goal_text,
                   success, step_beliefs, tool_pattern,
                   quality, deviation_count, total_steps, created_at,
                   step_claim_id, run_label
            FROM behavioral_executions
            WHERE workflow_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(workflow_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Count `(successes, total)` over a workflow's last `window` executions.
    ///
    /// Unlike `rolling_success_rate` (which returns only the rate), this keeps
    /// the denominator — the Wilson promotion gate needs both the success count
    /// and the sample size to compute a lower bound.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn success_stats(
        pool: &PgPool,
        workflow_id: Uuid,
        window: i64,
    ) -> Result<(i64, i64), DbError> {
        let row: (i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE success)::bigint AS successes,
                COUNT(*)::bigint AS total
            FROM (
                SELECT success
                FROM behavioral_executions
                WHERE workflow_id = $1
                ORDER BY created_at DESC
                LIMIT $2
            ) AS recent
            "#,
        )
        .bind(workflow_id)
        .bind(window)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// Find workflows with high behavioral success for goals similar to the
    /// supplied embedding.
    ///
    /// Returns up to `limit` rows of `(workflow_id, avg_similarity, execution_count)`,
    /// filtered to workflows that have at least `min_executions` executions and
    /// whose average cosine similarity to `goal_embedding_pgvec` meets or exceeds
    /// `min_similarity`.
    ///
    /// `goal_embedding_pgvec` is a pgvector string literal like `"[0.1,0.2,...]"`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, goal_embedding_pgvec))]
    pub async fn behavioral_affinity(
        pool: &PgPool,
        goal_embedding_pgvec: &str,
        min_similarity: f64,
        min_executions: i64,
        limit: i64,
    ) -> Result<Vec<(Uuid, f64, i64)>, DbError> {
        // Affinity query:
        //   For each workflow, compute average cosine similarity between stored
        //   goal embeddings and the query vector, then filter and rank.
        //   Only successful executions contribute to affinity scoring.
        #[derive(sqlx::FromRow)]
        struct AffinityRow {
            workflow_id: Uuid,
            avg_similarity: f64,
            execution_count: i64,
        }

        let rows: Vec<AffinityRow> = sqlx::query_as(
            r#"
            WITH query_vec AS (SELECT $1::vector AS vec)
            SELECT
                be.workflow_id,
                AVG(1.0 - (be.goal_embedding <=> q.vec))::float8 AS avg_similarity,
                COUNT(*)::bigint                                   AS execution_count
            FROM behavioral_executions be, query_vec q
            WHERE be.success = TRUE
              AND be.goal_embedding IS NOT NULL
            GROUP BY be.workflow_id
            HAVING AVG(1.0 - (be.goal_embedding <=> q.vec)) >= $2
               AND COUNT(*) >= $3
            ORDER BY avg_similarity DESC
            LIMIT $4
            "#,
        )
        .bind(goal_embedding_pgvec)
        .bind(min_similarity)
        .bind(min_executions)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.workflow_id, r.avg_similarity, r.execution_count))
            .collect())
    }

    /// Find workflows with high behavioral success for goals similar to the
    /// supplied embedding, aggregating across workflow lineages.
    ///
    /// Unlike `behavioral_affinity` which groups by individual `workflow_id`,
    /// this method walks `variant_of` edges to find each execution's lineage
    /// root and groups by root. This means a workflow variant inherits goal
    /// affinity from its parent/ancestors (but NOT success rate — that's
    /// per-workflow via `rolling_success_rate`).
    ///
    /// Deprecated workflows (truth_value <= 0.1) are excluded from lineage
    /// aggregation.
    ///
    /// Returns `(lineage_root, avg_similarity, execution_count)`.
    #[instrument(skip(pool, goal_embedding_pgvec))]
    pub async fn behavioral_affinity_lineage(
        pool: &PgPool,
        goal_embedding_pgvec: &str,
        min_similarity: f64,
        min_executions: i64,
        limit: i64,
    ) -> Result<Vec<(Uuid, f64, i64)>, DbError> {
        #[derive(sqlx::FromRow)]
        struct AffinityRow {
            workflow_id: Uuid,
            avg_similarity: f64,
            execution_count: i64,
        }

        let rows: Vec<AffinityRow> = sqlx::query_as(
            r#"
            WITH RECURSIVE lineage AS (
                -- Base: every successful execution with an embedding
                SELECT be.id AS exec_id, be.workflow_id AS root_id
                FROM behavioral_executions be
                WHERE be.success = TRUE
                  AND be.goal_embedding IS NOT NULL
                UNION ALL
                -- Walk up: if current root has a variant_of or supersedes parent, adopt the parent
                SELECT l.exec_id, e.target_id AS root_id
                FROM lineage l
                JOIN edges e ON e.source_id = l.root_id
                    AND e.relationship IN ('variant_of', 'supersedes')
                    AND e.source_type = 'claim' AND e.target_type = 'claim'
            ),
            -- The true root per execution: the ancestor with no outgoing variant_of or supersedes
            roots AS (
                SELECT l.exec_id, l.root_id
                FROM lineage l
                WHERE NOT EXISTS (
                    SELECT 1 FROM edges e
                    WHERE e.source_id = l.root_id
                      AND e.relationship IN ('variant_of', 'supersedes')
                      AND e.source_type = 'claim' AND e.target_type = 'claim'
                )
            ),
            -- Filter out deprecated lineage roots
            live_roots AS (
                SELECT r.exec_id, r.root_id
                FROM roots r
                JOIN claims c ON c.id = r.root_id
                WHERE c.truth_value > 0.1
            ),
            query_vec AS (SELECT $1::vector AS vec)
            SELECT
                lr.root_id                                             AS workflow_id,
                AVG(1.0 - (be.goal_embedding <=> q.vec))::float8      AS avg_similarity,
                COUNT(*)::bigint                                       AS execution_count
            FROM live_roots lr
            JOIN behavioral_executions be ON be.id = lr.exec_id
            CROSS JOIN query_vec q
            GROUP BY lr.root_id
            HAVING AVG(1.0 - (be.goal_embedding <=> q.vec)) >= $2
               AND COUNT(*) >= $3
            ORDER BY avg_similarity DESC
            LIMIT $4
            "#,
        )
        .bind(goal_embedding_pgvec)
        .bind(min_similarity)
        .bind(min_executions)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.workflow_id, r.avg_similarity, r.execution_count))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_behavioral_execution_placeholder(_pool: sqlx::PgPool) {
        // Integration tests need workflow claim fixtures
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn behavioral_execution_persists_step_claim_id(pool: sqlx::PgPool) {
        // Seed an agent and a claim to reference.
        let agent_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
        )
        .bind(blake3::hash(b"test-agent").as_bytes().as_slice())
        .bind("test-agent")
        .fetch_one(&pool)
        .await
        .unwrap();

        let claim_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind("test claim")
        .bind(blake3::hash(b"test claim").as_bytes().as_slice())
        .bind(agent_id)
        .bind(0.5_f64)
        .fetch_one(&pool)
        .await
        .unwrap();

        let workflow_root_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind("workflow root")
        .bind(blake3::hash(b"workflow root").as_bytes().as_slice())
        .bind(agent_id)
        .bind(0.5_f64)
        .fetch_one(&pool)
        .await
        .unwrap();

        let row = BehavioralExecutionRow {
            id: uuid::Uuid::new_v4(),
            workflow_id: workflow_root_id,
            goal_text: "test".into(),
            success: true,
            step_beliefs: serde_json::json!({}),
            tool_pattern: vec!["t1".into()],
            quality: Some(0.9),
            deviation_count: 0,
            total_steps: 1,
            created_at: chrono::Utc::now(),
            step_claim_id: Some(claim_id),
            run_label: None,
        };
        BehavioralExecutionRepository::create(&pool, row, None)
            .await
            .unwrap();

        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM behavioral_executions WHERE step_claim_id IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(count >= 1);
    }

    /// `recent_executions` returns a workflow's rows newest-first, honours the
    /// limit, and is scoped to the requested workflow_id (the GEPA proposer
    /// reads exactly this to reflect on a workflow's recent runs).
    #[sqlx::test(migrations = "../../migrations")]
    async fn recent_executions_newest_first_scoped_and_limited(pool: sqlx::PgPool) {
        let agent_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
        )
        .bind(blake3::hash(b"re-agent").as_bytes().as_slice())
        .bind("re-agent")
        .fetch_one(&pool)
        .await
        .unwrap();

        let mk_wf = |content: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, uuid::Uuid>(
                    "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
                     VALUES ($1, $2, $3, 0.5) RETURNING id",
                )
                .bind(content)
                .bind(blake3::hash(content.as_bytes()).as_bytes().as_slice())
                .bind(agent_id)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let wf = mk_wf("wf-target").await;
        let other = mk_wf("wf-other").await;

        let base = chrono::Utc::now();
        let mk_row = |wfid: uuid::Uuid, secs: i64, goal: &str| BehavioralExecutionRow {
            id: uuid::Uuid::new_v4(),
            workflow_id: wfid,
            goal_text: goal.to_string(),
            success: true,
            step_beliefs: serde_json::json!({}),
            tool_pattern: vec![],
            quality: None,
            deviation_count: 0,
            total_steps: 1,
            created_at: base + chrono::Duration::seconds(secs),
            step_claim_id: None,
            run_label: None,
        };
        for (wfid, secs, goal) in [
            (wf, 0, "oldest"),
            (wf, 1, "mid"),
            (wf, 2, "newest"),
            (other, 5, "other-wf"),
        ] {
            BehavioralExecutionRepository::create(&pool, mk_row(wfid, secs, goal), None)
                .await
                .unwrap();
        }

        // Limit < count: newest two of the target workflow, DESC by created_at.
        let recent = BehavioralExecutionRepository::recent_executions(&pool, wf, 2)
            .await
            .unwrap();
        assert_eq!(recent.len(), 2, "limit honoured");
        assert_eq!(recent[0].goal_text, "newest", "newest first");
        assert_eq!(recent[1].goal_text, "mid");
        assert!(
            recent.iter().all(|r| r.workflow_id == wf),
            "scoped to the requested workflow"
        );

        // Limit > count: all three target rows, never the other workflow's row.
        let all = BehavioralExecutionRepository::recent_executions(&pool, wf, 100)
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|r| r.workflow_id == wf));
    }

    /// `success_stats` returns (successes, total) over the last `window`
    /// executions of one workflow — the raw counts the Wilson promotion gate
    /// needs (rolling_success_rate alone drops the denominator).
    #[sqlx::test(migrations = "../../migrations")]
    async fn success_stats_counts_successes_and_total_over_window(pool: sqlx::PgPool) {
        let agent_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
        )
        .bind(blake3::hash(b"ss-agent").as_bytes().as_slice())
        .bind("ss-agent")
        .fetch_one(&pool)
        .await
        .unwrap();
        let wf: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
             VALUES ('ss-wf', sha256('ss-wf'::bytea), $1, 0.5) RETURNING id",
        )
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let base = chrono::Utc::now();
        // 3 successes + 2 failures, staggered so the window cut is deterministic.
        for (i, succ) in [false, false, true, true, true].iter().enumerate() {
            BehavioralExecutionRepository::create(
                &pool,
                BehavioralExecutionRow {
                    id: uuid::Uuid::new_v4(),
                    workflow_id: wf,
                    goal_text: "g".into(),
                    success: *succ,
                    step_beliefs: serde_json::json!({}),
                    tool_pattern: vec![],
                    quality: None,
                    deviation_count: 0,
                    total_steps: 1,
                    created_at: base + chrono::Duration::seconds(i as i64),
                    step_claim_id: None,
                    run_label: None,
                },
                None,
            )
            .await
            .unwrap();
        }

        // Whole history: 3 successes of 5.
        let (succ, total) = BehavioralExecutionRepository::success_stats(&pool, wf, 100)
            .await
            .unwrap();
        assert_eq!((succ, total), (3, 5));

        // Window of the newest 3 (all successes): 3 of 3.
        let (succ3, total3) = BehavioralExecutionRepository::success_stats(&pool, wf, 3)
            .await
            .unwrap();
        assert_eq!((succ3, total3), (3, 3), "window restricts to newest N");

        // Unknown workflow: empty.
        let (z_s, z_t) =
            BehavioralExecutionRepository::success_stats(&pool, uuid::Uuid::new_v4(), 100)
                .await
                .unwrap();
        assert_eq!((z_s, z_t), (0, 0));
    }
}
