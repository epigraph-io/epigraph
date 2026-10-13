//! Error type for the ingest executor.

use thiserror::Error;

/// Errors that can be raised while executing a workflow ingest plan.
///
/// Callers (MCP and API handlers) map this into their own error type
/// (`McpError`, `ApiError`, etc.) at the wrapper boundary.
#[derive(Error, Debug)]
pub enum IngestExecutorError {
    /// Raw `sqlx` error from inline queries (UPDATE / SELECT COUNT(*)).
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Repository-layer error from `epigraph_db`.
    #[error("repository error: {0}")]
    Repository(#[from] epigraph_db::DbError),

    /// Failed to look up or create an agent (system or author).
    #[error("agent creation failed: {0}")]
    AgentCreation(String),

    /// The system role has no row in migration 148's `system_agents` and the
    /// database is ARMED (migration 122), so the resolver refuses rather than
    /// derive the identity from its public-constant key: once armed, the
    /// system agent is exactly the registered one. Raised before anything is
    /// written.
    #[error(
        "the {role} system agent is not registered in system_agents and this database is armed \
         (migration 122): workflow ingest is refused until a maintenance session registers it \
         (epigraph-operator register-system-agent --role {role} --agent <id> --reason <text> \
         --apply). Nothing was written"
    )]
    SystemAgentUnregistered { role: &'static str },

    /// Failed to insert the workflow row.
    #[error("workflow row insert failed: {0}")]
    WorkflowInsert(String),

    /// Plan structure violated an executor invariant.
    #[error("plan inconsistency: {0}")]
    PlanInconsistency(String),

    /// A planned claim has blank content, which would violate the DB
    /// `claims_content_not_empty` constraint. The embedded `path` names the
    /// extraction field responsible (e.g. `"phases[2].summary"`).
    #[error("blank claim content at {path}: claim content must not be empty or whitespace-only")]
    InvalidContent { path: String },

    /// The plan would write a content-less workflow generation: it plans no
    /// claims at all (any generation), or it is a NEW generation (> 0) that
    /// plans no level-2 step claims. Raised before anything is written.
    ///
    /// Generation 0 with a thesis and no steps stays legal: that is the
    /// `store_workflow` / `POST /workflows` `steps: []` scaffold that
    /// `add_step` fills in place.
    #[error(
        "empty workflow generation: {canonical_name} generation {generation} plans {level2} \
         step claims and {claims} claims in total; a workflow generation above 0 needs at least \
         one step, and every ingest needs at least one claim (steps under an unrecognised key \
         are ignored). Nothing was written; retrying the same payload will be refused again"
    )]
    EmptyGeneration {
        canonical_name: String,
        generation: i32,
        level2: usize,
        claims: usize,
    },
}
