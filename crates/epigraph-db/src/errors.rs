//! Database error types

use thiserror::Error;
use uuid::Uuid;

/// SQLSTATE 23514, `check_violation`.
///
/// Spelled once, here, because it is also the ERRCODE the tenancy trigger arms
/// in `migrations/070_tenancy_triggers.sql` and `migrations/072_edge_co_ownership.sql`
/// raise deliberately, and a second literal would be a place for the two to
/// drift.
const CHECK_VIOLATION: &str = "23514";

/// SQLSTATE `RVK01`: `epigraph_ensure_personal_group` refused because the agent
/// holds only REVOKED membership rows of its personal group (migration 105).
///
/// A custom class on purpose: `RV` is outside the standard's reserved `0-4` /
/// `A-H` classes and outside every class PostgreSQL itself raises, so no
/// server-side error can be mistaken for this refusal. Spelled once, here, for
/// the same reason [`CHECK_VIOLATION`] is.
pub const PERSONAL_MEMBERSHIP_REVOKED: &str = "RVK01";

/// SQLSTATE `RVK02`: `epigraph_ensure_personal_group` refused because the group
/// under the agent's canonical personal did_key is not the agent's own — not
/// `kind = 'personal'`, or created by another agent (a squat). Migration 105.
/// Same class as [`PERSONAL_MEMBERSHIP_REVOKED`], for the same reason.
pub const PERSONAL_GROUP_NOT_OWNED: &str = "RVK02";

/// SQLSTATE `OPL01`: a claim write named an author that is not bound to a human
/// operator (migration 122). Raised by `epigraph_require_bound_author`, which the
/// `claims_require_tenancy_then_operator_binding` trigger and
/// `ClaimRepository::default_decl_for_author` both call, once the database is
/// armed. Same custom-class reasoning as [`PERSONAL_MEMBERSHIP_REVOKED`].
pub const OPERATOR_LINK_REQUIRED: &str = "OPL01";

/// SQLSTATE `OPL02`: a live-linked agent was named on a row owned by a group its
/// OPERATOR holds no writer/admin membership in, or given a writer/admin row in
/// such a group (migration 122 section 1b). Every agent writes only where its
/// own human writes; admin access is the only thing that crosses groups.
pub const OPERATOR_SCOPE_REFUSED: &str = "OPL02";

/// The remedy every surface prints with an [`DbError::OperatorLinkRequired`].
/// One string, so the HTTP body, the MCP message and the CLI text cannot drift.
pub const OPERATOR_LINK_FIX: &str = "an operator records a live link for the agent on a \
     maintenance DSN: `epigraph-operator link --agent <agent id> --operator <human operator \
     agent id> --apply` (docs/tenancy.md, \"Operator binding\")";

/// Database operation errors
#[derive(Error, Debug)]
pub enum DbError {
    /// Failed to connect to the database
    #[error("Failed to connect to database: {source}")]
    ConnectionFailed {
        #[source]
        source: sqlx::Error,
    },

    /// Query execution failed
    #[error("Query failed: {source}")]
    QueryFailed {
        #[source]
        source: sqlx::Error,
    },

    /// Entity not found
    #[error("{entity} with ID {id} not found")]
    NotFound { entity: String, id: Uuid },

    /// Duplicate key constraint violation
    #[error("Duplicate {entity} already exists")]
    DuplicateKey { entity: String },

    /// Foreign-key constraint violation (SQLSTATE 23503).
    ///
    /// A referencing row named a parent row that does not exist. Distinguished
    /// from `QueryFailed` because it is a CLIENT error, not a server fault:
    /// `groups.created_by_agent_id` FKs to `agents`, so a token whose
    /// `agent_id` claim names a deleted (or never-created) agent must surface
    /// as 403, not 500. `constraint` is the PostgreSQL constraint name when the
    /// driver reports one.
    #[error("Foreign key constraint {constraint} violated")]
    ForeignKeyViolation { constraint: String },

    /// CHECK constraint violation (SQLSTATE 23514).
    ///
    /// A CLIENT error for the same reason `ForeignKeyViolation` is: the row the
    /// caller asked for is not a row this schema can hold. Without this arm it
    /// falls through to [`Self::QueryFailed`] and the caller gets a bare 500
    /// reading "A database error occurred".
    ///
    /// PR-13 added it for the tenancy CHECKs on `edges` and `claims` —
    /// `edges_co_owner_shape` (migration 072), `edges_group_needs_real_group`
    /// and `claims_visibility_check` (062). Note what it is NOT, because a
    /// stale comment here would be worse than none: migration 070's arm (b)
    /// raised 23514 for "edge spans groups % and %; writer is not a member of
    /// both", and **migration 072 removes that RAISE** — a cross-group edge is
    /// now expressible and is stamped, not rejected. So 23514 on the edge write
    /// path now means malformed tenancy, not an authorization refusal.
    /// Write-side *authorization* is PR-16's, and will not arrive as 23514.
    ///
    /// It is ALSO raised by `migrations/071_ownership_compat_shim.sql`, and
    /// that source is why `message` below is not optional. 071's shim refuses
    /// to transcribe an `ownership` row into `(group, G)` when G has no live
    /// members — *"that group has no live members and the row would be
    /// unreadable by everyone, including its owner"* — via
    /// `RAISE ... USING ERRCODE = '23514'`. That is server state a client
    /// cannot know, on the `ownership` write path, and it reports NO constraint
    /// name. Classifying it by SQLSTATE is right; discarding its text is not.
    ///
    /// `constraint` is the PostgreSQL constraint name when the driver reports
    /// one. A `RAISE ... USING ERRCODE = '23514'` from plpgsql reports none,
    /// so `<unnamed>` is a normal value here, not a bug — and it is exactly why
    /// `message` exists.
    ///
    /// `message` is the driver's primary message, carried verbatim, and it is
    /// in `Display` deliberately: `epigraph-mcp/src/errors.rs::internal_error`
    /// renders a `DbError` with `to_string()`, so without this field an
    /// operator calling `assign_ownership` would see `Check constraint
    /// <unnamed> violated` and nothing else where 071's message used to be.
    /// The HTTP layer makes its own disclosure decision and deliberately does
    /// NOT put `message` in the response body — see `epigraph-api/src/errors.rs`.
    #[error("Check constraint {constraint} violated: {message}")]
    CheckViolation { constraint: String, message: String },

    /// Invalid data provided
    #[error("Invalid data: {reason}")]
    InvalidData { reason: String },

    /// The request is well-formed but conflicts with the state of the graph,
    /// and no automatic resolution is safe. Maps to HTTP **409**.
    ///
    /// Distinct from [`Self::InvalidData`] (422 — the caller sent something
    /// unusable) and from [`Self::CheckViolation`] (the schema rejected the
    /// row). This one is a REFUSAL BY POLICY: the statement would have
    /// succeeded, and we decline because the outcome would be wrong.
    ///
    /// PR-16 introduces it for `ClaimRepository::consolidate`'s cross-group
    /// case (plan §4.6): merging claims owned by two different groups into one
    /// row discloses each group's content to the other, and neither authorized
    /// it. Picking a winner and picking the world group are both disclosures;
    /// refusing is the only answer that is not.
    #[error("Conflict: {reason}")]
    Conflict { reason: String },

    /// A write that row security let the session SEE but not CHANGE: the
    /// statement matched fewer rows than the session can read, so a row it had
    /// to change was left as it was. Maps to HTTP **403**.
    ///
    /// Migrations 115 and 117 made DELETE (every tier-A table) and UPDATE
    /// (`edges` and the registries) owner-scoped with RESTRICTIVE USING
    /// clauses. Under row security a USING clause that refuses a row does not
    /// raise: the statement matches zero rows and reports success. A caller
    /// that must change a row compares what it could see with what it changed
    /// and raises this instead of reporting a write that did not happen.
    #[error("{action} of {entity} {id} was refused: this session may read it but not {action} it; nothing was changed")]
    WriteRefused {
        entity: String,
        id: Uuid,
        action: String,
    },

    /// The agent's personal-group membership is REVOKED, and the provisioning
    /// function refused to restore it (SQLSTATE [`PERSONAL_MEMBERSHIP_REVOKED`],
    /// migration 105).
    ///
    /// Migration 077's `epigraph_ensure_personal_group` revived a revoked row as
    /// `admin` on every call; 105 makes that call refuse instead, and this is the
    /// named form of the refusal. It is a DENIAL, not a server fault: an operator
    /// revoked the membership, and reversing that is an operator action. The
    /// HTTP layer maps it to 403 and the MCP layer to `INVALID_REQUEST`.
    ///
    /// `message` is the function's own text (it names the agent and the group),
    /// carried because a plpgsql `RAISE` has no constraint name to report.
    #[error("Personal-group membership revoked: {message}")]
    MembershipRevoked { message: String },

    /// The group carrying the agent's canonical personal did_key is not the
    /// agent's personal group (SQLSTATE [`PERSONAL_GROUP_NOT_OWNED`], migration
    /// 105): somebody else created it under that name. The provisioning
    /// function refuses to join it rather than seat the agent beside the
    /// squatter. A DENIAL like [`Self::MembershipRevoked`], mapped the same way
    /// (HTTP 403, MCP `INVALID_REQUEST`); clearing it is an operator action.
    #[error("Personal group not owned by the agent: {message}")]
    PersonalGroupNotOwned { message: String },

    /// The claim's author is not bound to a human operator (SQLSTATE
    /// [`OPERATOR_LINK_REQUIRED`], migration 122): it is neither a human
    /// operator nor the holder of a live operator link, and the database is
    /// armed. A DENIAL like [`Self::MembershipRevoked`] (HTTP 403, MCP
    /// `INVALID_REQUEST`), and fixed only by an operator action, which the
    /// rendered text names ([`OPERATOR_LINK_FIX`]).
    #[error("OPL01 operator link required: {message}. Fix: {}", OPERATOR_LINK_FIX)]
    OperatorLinkRequired { message: String },

    /// A live-linked agent wrote (or was enrolled to write) into a group its
    /// operator does not write (SQLSTATE [`OPERATOR_SCOPE_REFUSED`], migration
    /// 122 section 1b). A DENIAL (HTTP 403, MCP `INVALID_REQUEST`).
    #[error("OPL02 outside the operator's groups: {message}")]
    OperatorScopeRefused { message: String },

    /// A WRITE was asked of an ELEVATED viewer (elevation plan EL-6). An
    /// elevation widens one human's READS for at most 15 minutes and writes
    /// nothing: `ScopedPool::begin_as` refuses to open a transaction for it.
    /// A DENIAL (HTTP 403, MCP `INVALID_REQUEST`), fixed by the caller: write
    /// with an unelevated token, or end the elevation first.
    #[error(
        "ELEVATED READ-ONLY: this request is elevated, and an elevated session writes nothing; \
         write with an unelevated token, or end the elevation first"
    )]
    ElevatedReadOnly,

    /// Migration failed
    #[error("Migration failed: {source}")]
    MigrationFailed {
        #[source]
        source: sqlx::Error,
    },

    /// JSON serialization/deserialization error
    #[error("JSON error: {source}")]
    JsonError {
        #[source]
        source: serde_json::Error,
    },

    /// Core domain error
    #[error("Domain error: {source}")]
    CoreError {
        #[source]
        source: epigraph_core::CoreError,
    },
}

impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            // Check for unique constraint violations
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => Self::DuplicateKey {
                entity: "entity".to_string(),
            },
            // 23503. Kept alongside the unique-violation arm so every repo gets
            // the classification for free; without it a bad FK is a 500.
            sqlx::Error::Database(db_err) if db_err.is_foreign_key_violation() => {
                Self::ForeignKeyViolation {
                    constraint: db_err.constraint().unwrap_or("<unnamed>").to_string(),
                }
            }
            // 23514. `sqlx` has no `is_check_violation()` helper, so the code
            // is read off the driver directly. Matched AFTER the two helpers
            // above so their classification is unchanged.
            sqlx::Error::Database(db_err) if db_err.code().as_deref() == Some(CHECK_VIOLATION) => {
                Self::CheckViolation {
                    constraint: db_err.constraint().unwrap_or("<unnamed>").to_string(),
                    // Captured HERE, at construction. `QueryFailed` keeps the
                    // driver error as `#[source]` and gets the message for
                    // free; a struct variant with no `source` discards it
                    // permanently unless it is copied out now.
                    message: db_err.message().to_string(),
                }
            }
            // RVK01, migration 105's refusal to revive a revoked personal
            // membership. Named so no caller has to string-match a message.
            sqlx::Error::Database(db_err)
                if db_err.code().as_deref() == Some(PERSONAL_MEMBERSHIP_REVOKED) =>
            {
                Self::MembershipRevoked {
                    message: db_err.message().to_string(),
                }
            }
            // RVK02, migration 105's refusal to join a squatted personal group.
            sqlx::Error::Database(db_err)
                if db_err.code().as_deref() == Some(PERSONAL_GROUP_NOT_OWNED) =>
            {
                Self::PersonalGroupNotOwned {
                    message: db_err.message().to_string(),
                }
            }
            // OPL01, migration 122's refusal of an author not bound to a human
            // operator.
            sqlx::Error::Database(db_err)
                if db_err.code().as_deref() == Some(OPERATOR_LINK_REQUIRED) =>
            {
                Self::OperatorLinkRequired {
                    message: db_err.message().to_string(),
                }
            }
            // OPL02, migration 122 section 1b: outside the operator's groups.
            sqlx::Error::Database(db_err)
                if db_err.code().as_deref() == Some(OPERATOR_SCOPE_REFUSED) =>
            {
                Self::OperatorScopeRefused {
                    message: db_err.message().to_string(),
                }
            }
            // All other database errors become QueryFailed
            other => Self::QueryFailed { source: other },
        }
    }
}

impl DbError {
    /// `true` for migration 105's two refusals of a personal-group provisioning
    /// call ([`Self::MembershipRevoked`], [`Self::PersonalGroupNotOwned`]): a
    /// denial the caller cannot fix, never a server fault. Every surface that
    /// maps a `DbError` to a status asks this one question, so a third refusal
    /// added later is classified in one place.
    #[must_use]
    pub fn is_personal_group_refusal(&self) -> bool {
        matches!(
            self,
            Self::MembershipRevoked { .. } | Self::PersonalGroupNotOwned { .. }
        )
    }

    /// `true` for every refusal of the WRITER's authority that the caller
    /// cannot fix by changing a parameter and that is never a server fault:
    /// migration 105's two personal-group refusals
    /// ([`Self::is_personal_group_refusal`]) and migration 122's
    /// [`Self::OperatorLinkRequired`] and [`Self::OperatorScopeRefused`], and
    /// the elevated viewer's [`Self::ElevatedReadOnly`]. The write surfaces map
    /// exactly this set to a denial (HTTP 403, MCP `INVALID_REQUEST`).
    #[must_use]
    pub fn is_write_authority_refusal(&self) -> bool {
        self.is_personal_group_refusal()
            || matches!(
                self,
                Self::OperatorLinkRequired { .. }
                    | Self::OperatorScopeRefused { .. }
                    | Self::ElevatedReadOnly
            )
    }
}

impl From<serde_json::Error> for DbError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError { source: err }
    }
}

impl From<epigraph_core::CoreError> for DbError {
    fn from(err: epigraph_core::CoreError) -> Self {
        Self::CoreError { source: err }
    }
}
