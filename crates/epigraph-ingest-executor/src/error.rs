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

    /// A declared-tenancy ingest names a group the CALLING agent itself does
    /// not write: it holds no live `writer` / `admin` membership of it. The
    /// caller's human writing the group does not count (an agent writes only
    /// where it is itself a member). Raised before anything is written.
    #[error(
        "the calling agent {caller} holds no live writer or admin membership of group {group}, \
         so it may not declare that group as the tenancy of a workflow ingest (its own \
         membership is required; its operator's does not count). Nothing was written"
    )]
    CallerNotGroupWriter {
        caller: uuid::Uuid,
        group: uuid::Uuid,
    },

    /// A declared-tenancy ingest names a group the workflow-ingest system
    /// agent does not write, so its stamp could not satisfy the row-security
    /// `WITH CHECK` on the claims and edges it would create. Raised on the
    /// stamped transaction before anything is written.
    #[error(
        "the workflow-ingest system agent {system_agent} holds no live writer or admin \
         membership of group {group}, so no claim of this ingest could be owned by it: a \
         maintenance session must grant that agent a writer row in the group first. Nothing \
         was written"
    )]
    DeclaredGroupNotWritable {
        group: uuid::Uuid,
        system_agent: uuid::Uuid,
    },

    /// A declared-tenancy ingest's plan names a claim that already exists and
    /// that is private to a group the CALLING agent does not write (or that the
    /// ingest's own stamp cannot read at all). The ingest would write
    /// `executes` / `decomposes_to` edges to it, which row security assigns to
    /// that group, on the system agent's stamp: a write into a group the caller
    /// holds no membership of. Raised on the stamped transaction before any
    /// edge is written, so the whole ingest rolls back. The message names the
    /// claim (its id is derived from the plan's own text) and never its group.
    #[error(
        "the plan reuses claim {claim_id}, which already exists and is private to a group the \
         calling agent does not write, so a declared-tenancy ingest may not link it. Nothing \
         was written"
    )]
    ReusedClaimOutsideCallerGroups { claim_id: uuid::Uuid },

    /// Failed to insert the workflow row.
    #[error("workflow row insert failed: {0}")]
    WorkflowInsert(String),

    /// The plan's `(canonical_name, generation)` is already held by a
    /// `workflows` row this ingest's stamp cannot read (migration 183: the row
    /// carries its plan's tenancy). Writing this plan's claims and `executes`
    /// edges under that row would extend a plan the ingest has no view of, so
    /// nothing is written. Raised before any claim or edge; the message never
    /// names the row's id or group. A caller's payload conflict, not a fault:
    /// retrying the same payload is refused again.
    #[error(
        "workflow {canonical_name:?} generation {generation} already exists and is not readable \
         by this ingest. Nothing was written"
    )]
    WorkflowOutsideView {
        canonical_name: String,
        generation: i32,
    },

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

impl IngestExecutorError {
    /// Whether this is one of the declared-tenancy refusals
    /// ([`Self::CallerNotGroupWriter`], [`Self::DeclaredGroupNotWritable`],
    /// [`Self::ReusedClaimOutsideCallerGroups`]): a denial the caller can act
    /// on (403 / `INVALID_REQUEST`), not a fault.
    #[must_use]
    pub const fn is_declared_tenancy_refusal(&self) -> bool {
        matches!(
            self,
            Self::CallerNotGroupWriter { .. }
                | Self::DeclaredGroupNotWritable { .. }
                | Self::ReusedClaimOutsideCallerGroups { .. }
        )
    }
}
