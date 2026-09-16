//! Corpus counts — how much is actually in the graph.
//!
//! This is the SQL that used to sit inline in MCP `system_stats`
//! (`epigraph-mcp/src/tools/batch.rs`). Both that tool and
//! `GET /api/v1/stats` read it from here, so the landing page and the agent
//! surface can never disagree about the size of the corpus.
//!
//! Not to be confused with `GET /api/v1/admin/stats`, which reports process
//! diagnostics (uptime, pool state), not corpus size.

use sqlx::PgPool;

use crate::errors::DbError;

/// The counts every caller wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct CorpusCounts {
    pub claims: i64,
    pub evidence: i64,
    pub edges: i64,
    pub agents: i64,
    pub frames: i64,
}

/// The counts only a detailed report wants. Split from [`CorpusCounts`]
/// because MCP `system_stats` runs them only when `detailed` is set, and
/// `embedding IS NOT NULL` is a scan over the whole claims table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct DetailedCorpusCounts {
    pub workflows: i64,
    pub challenges: i64,
    pub embeddings: i64,
}

pub struct StatsRepository;

impl StatsRepository {
    /// Claim, evidence, edge, agent and frame counts, in one round trip.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn corpus_counts(pool: &PgPool) -> Result<CorpusCounts, DbError> {
        let counts = sqlx::query_as::<_, CorpusCounts>(
            "SELECT (SELECT COUNT(*) FROM claims)   AS claims,
                    (SELECT COUNT(*) FROM evidence) AS evidence,
                    (SELECT COUNT(*) FROM edges)    AS edges,
                    (SELECT COUNT(*) FROM agents)   AS agents,
                    (SELECT COUNT(*) FROM frames)   AS frames",
        )
        .fetch_one(pool)
        .await?;
        Ok(counts)
    }

    /// Workflow, challenge and embedding counts, in one round trip.
    ///
    /// A workflow is a claim carrying the `workflow` label, not a row in
    /// `workflows`: that is the definition MCP `system_stats` has always
    /// reported, kept so the two surfaces agree.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn detailed_counts(pool: &PgPool) -> Result<DetailedCorpusCounts, DbError> {
        let counts = sqlx::query_as::<_, DetailedCorpusCounts>(
            "SELECT (SELECT COUNT(*) FROM claims WHERE 'workflow' = ANY(labels)) AS workflows,
                    (SELECT COUNT(*) FROM challenges)                            AS challenges,
                    (SELECT COUNT(*) FROM claims WHERE embedding IS NOT NULL)    AS embeddings",
        )
        .fetch_one(pool)
        .await?;
        Ok(counts)
    }
}
