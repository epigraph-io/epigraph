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

// The custom-SQLSTATE codes this file's typed variants name live in the
// refusal-code registry, with every other code; re-exported so their paths
// stay `epigraph_db::errors::*` and `epigraph_db::*`.
use crate::refusal_codes::{self, Answer};
pub use crate::refusal_codes::{
    OPERATOR_LINK_REQUIRED, OPERATOR_SCOPE_REFUSED, PERSONAL_GROUP_NOT_OWNED,
    PERSONAL_MEMBERSHIP_REVOKED, ROLE_HOLDER_REQUIRED,
};

/// The message prefix of migration 184's RT07 refusal (SQLSTATE 42501): a
/// write to the key of a RETRACTED mass function (operator ruling R-103).
pub const RETRACTED_BBA_REWRITE_PREFIX: &str = "RT07: ";

/// The caller-facing text of an RT07 refusal, naming the row when the
/// database reported its id.
#[must_use]
pub fn retracted_bba_rewrite_message(id: Option<Uuid>) -> String {
    let row = id.map_or_else(
        || "a mass function".to_string(),
        |id| format!("mass function {id}"),
    );
    format!(
        "{RETRACTED_BBA_REWRITE_PREFIX}{row} is retracted, and a retracted BBA holds its key \
         (claim, frame, source agent, perspective): a write to that key is refused until the BBA \
         is un-retracted (MCP `unretract_bba`, or POST /api/v1/mass-functions/<id>/unretract, \
         with a reason; audited); nothing was written"
    )
}

/// The remedy every surface prints with an [`DbError::OperatorLinkRequired`].
/// One string, so the HTTP body, the MCP message and the CLI text cannot drift.
///
/// The second remedy (migration 149) is for an HTTP OAuth client, which a link
/// would make stdio-only: the operator allowlists its agent instead.
pub const OPERATOR_LINK_FIX: &str = "an operator records a live link for the agent on a \
     maintenance DSN: `epigraph-operator link --agent <agent id> --operator <human operator \
     agent id> --apply` (docs/tenancy.md, \"Operator binding\"); for an HTTP OAuth client \
     (which a link would make stdio-only), allowlist it instead: `epigraph-operator \
     allow-author-binding-client --client <oauth client id> --operator <human operator agent \
     id> --reason <text> --apply`";

/// What a repo-authored refusal ([`DbError::Refused`]) refuses, which decides
/// the answer a transport gives it (operator ruling R-55).
///
/// A refusal whose answer must not reveal that its target exists is not a
/// `Refused` of any kind: such a site returns [`DbError::NotFound`], exactly as
/// it would for a missing row, so it stays indistinguishable from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// The request itself is malformed or out of bounds, whatever the state
    /// of the graph (an empty merge, too many ids, a claim deduped onto
    /// itself). HTTP 400.
    Input,
    /// The caller may not do this to a target it can see (it may read the
    /// target but not write it). HTTP 403.
    Authority,
    /// The request is well formed and permitted, but the target's current
    /// state does not admit it (already superseded, not current, not a
    /// duplicate). HTTP 409.
    State,
}

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

    /// A refusal the repo layer AUTHORED: literal text and ids it wrote
    /// itself, naming why the request is not carried out and, usually, that
    /// nothing was written ("mark_duplicate: canonical ... is not current",
    /// "consolidate: duplicate source ids", "FA07: ...").
    ///
    /// Its own variant so that a surface can send `message` to the caller as
    /// written WITHOUT trusting a shape that other errors also take. These
    /// refusals used to be built as `QueryFailed { source: sqlx::Error::Protocol
    /// (msg) }`, and `From<sqlx::Error>` wraps ANY `Protocol` error into that
    /// same shape (sqlx's own protocol errors, an engine stringification of
    /// another error), so the MCP layer could not tell a designed refusal
    /// from a server fault (backlog e0f0cb68). Never construct it from an
    /// error's `Display`.
    ///
    /// `kind` says what is refused ([`RefusalKind`]); every construction site
    /// names it, with no default, so a new refusal cannot skip the choice.
    ///
    /// The MCP layer sends `message` as written (`errors::designed_refusal`).
    /// The HTTP layer answers by `kind` (input 400, authority 403, state 409,
    /// operator ruling R-55) with `message` as the body's reason, and logs it.
    #[error("{message}")]
    Refused { kind: RefusalKind, message: String },

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

    /// An agent attached to a role wrote (or was named as the author) while no
    /// human holds the role, or while its linked human is not the holder
    /// (SQLSTATE [`ROLE_HOLDER_REQUIRED`], migration 166). A DENIAL (HTTP 403,
    /// MCP `INVALID_REQUEST`), fixed only by an operator: grant the role to the
    /// agent's human, or detach the agent and attach an identity linked to the
    /// holder (a link never moves to another human).
    #[error("ROL01 the agent's role has no live holder it belongs to: {message}")]
    RoleHolderRequired { message: String },

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

    /// An elevated request could not be RECORDED in the per-access log
    /// (elevation plan EL-8, migration 127): the viewer is not elevated, the
    /// pool does not declare the recorder, or the recorder refused or failed.
    /// The serving process WITHHOLDS the response (HTTP 500, MCP internal
    /// error): an elevated read that is not recorded is never sent.
    #[error("ELEVATED ACCESS NOT RECORDED: {reason}; the response is withheld")]
    ElevatedAccessUnrecorded { reason: String },

    /// A maintenance connection was asked of a `ScopedPool` with NO
    /// maintenance pool attached (`ScopedPool::unscoped_for_maintenance` /
    /// `maintenance_session`, backlog e27ad9b6).
    ///
    /// The pool used to fall back to its application pool, where row security
    /// filters a bypass viewer to zero rows: maintenance work silently read
    /// and wrote nothing. Now it refuses. A server fault, never the caller's
    /// (HTTP 500, MCP internal error): a request-serving process holds no
    /// maintenance DSN, and a maintenance binary attaches its vetted pool with
    /// `ScopedPool::with_maintenance_pool`. `reason` is the `SystemReason`
    /// the connection was asked for.
    #[error(
        "MAINTENANCE POOL NOT ATTACHED: a maintenance connection ({reason}) was refused because \
         no maintenance pool is attached to this ScopedPool; it is never drawn from the \
         application pool, where row security filters a bypass viewer to zero rows"
    )]
    MaintenancePoolNotAttached { reason: &'static str },

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
            // 23505 on migration 358's `shifted_to` pair index: a designed
            // refusal of the graph's STATE (the pair already holds an in-force
            // succession), answered with its own text on every surface (HTTP
            // 409, the MCP tool error) instead of an opaque duplicate. Matched
            // by constraint name BEFORE the generic arm below, so every other
            // unique violation keeps its classification.
            sqlx::Error::Database(db_err)
                if db_err.is_unique_violation()
                    && db_err.constraint() == Some(crate::repos::edge::SHIFTED_TO_PAIR_INDEX) =>
            {
                Self::Refused {
                    kind: RefusalKind::State,
                    message: crate::repos::edge::SHIFTED_TO_PAIR_REFUSAL.to_string(),
                }
            }
            // Check for unique constraint violations
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => Self::DuplicateKey {
                entity: "entity".to_string(),
            },
            // 23503. Kept alongside the unique-violation arm so every repo gets
            // the classification for free; without it a bad FK is a 500.
            //
            // A DESIGNED 23503 refusal whose message opens with a listed
            // caller-refusal code (migration 359's TEN04: a derived row whose
            // claim_id names no claim) is the caller's input refusal (HTTP
            // 400, the MCP tool error) carrying its reviewed message; the
            // SQLSTATE stays in the foreign-key class. An uncoded 23503 (a
            // real FK constraint, or an arm left uncoded because its text
            // would tell a missing row from a hidden one) stays
            // `ForeignKeyViolation`, which routes match on.
            sqlx::Error::Database(db_err) if db_err.is_foreign_key_violation() => {
                if crate::refusal_codes::caller_refusal_code(db_err.message()).is_some() {
                    // DETAIL is what the reply withholds (TEN04 moved the
                    // claim id there), and `Refused` carries only the
                    // message, so the server log keeps it here.
                    let db_detail = db_err
                        .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
                        .and_then(sqlx::postgres::PgDatabaseError::detail);
                    tracing::warn!(
                        detail = %db_err.message(),
                        db_detail = ?db_detail,
                        "the database refused the request (a coded 23503)"
                    );
                    Self::Refused {
                        kind: RefusalKind::Input,
                        message: db_err.message().to_string(),
                    }
                } else {
                    Self::ForeignKeyViolation {
                        constraint: db_err.constraint().unwrap_or("<unnamed>").to_string(),
                    }
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
            // A coded refusal the registry answers for every caller: migration
            // 105's RVK01/RVK02, 122's OPL01/OPL02, 166's ROL01 (each a typed
            // DENIAL, so no caller has to string-match a message), and 184's
            // RT07 (operator ruling R-103): a write to the key of a retracted
            // BBA, a designed refusal of the target's STATE (the remedy is
            // the explicit un-retract), so every surface answers it as one
            // (HTTP 409, the MCP tool error) rather than as a redacted fault.
            // RT07's text is built here; only the row id is taken from the
            // database, from DETAIL, parsed as a uuid. Every other code
            // (a repo's own, a route's, a disclosed one) stays QueryFailed.
            sqlx::Error::Database(db_err) => {
                let message = || db_err.message().to_string();
                match refusal_codes::lookup(&*db_err).map(|c| c.answer) {
                    Some(Answer::MembershipRevoked) => {
                        Self::MembershipRevoked { message: message() }
                    }
                    Some(Answer::PersonalGroupNotOwned) => {
                        Self::PersonalGroupNotOwned { message: message() }
                    }
                    Some(Answer::OperatorLinkRequired) => {
                        Self::OperatorLinkRequired { message: message() }
                    }
                    Some(Answer::OperatorScopeRefused) => {
                        Self::OperatorScopeRefused { message: message() }
                    }
                    Some(Answer::RoleHolderRequired) => {
                        Self::RoleHolderRequired { message: message() }
                    }
                    Some(Answer::RetractedBbaRewrite) => {
                        let id = db_err
                            .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
                            .and_then(sqlx::postgres::PgDatabaseError::detail)
                            .and_then(|d| Uuid::parse_str(d.trim()).ok());
                        Self::Refused {
                            kind: RefusalKind::State,
                            message: retracted_bba_rewrite_message(id),
                        }
                    }
                    _ => Self::QueryFailed {
                        source: sqlx::Error::Database(db_err),
                    },
                }
            }
            // All other errors become QueryFailed
            other => Self::QueryFailed { source: other },
        }
    }
}

impl DbError {
    /// The answer to an error from a definer of `family`, whose coded
    /// refusals the caller answers: a code of that family the registry
    /// answers as a site refusal ([`Answer::Refused`]) becomes
    /// [`Self::Refused`] of its kind with the database's text; anything else
    /// is the ordinary conversion. Only a repo that calls a coded definer
    /// converts this way, so the same code reached through any other
    /// statement stays a database error.
    #[must_use]
    pub(crate) fn from_definer(e: sqlx::Error, family: refusal_codes::Family) -> Self {
        if let sqlx::Error::Database(db) = &e {
            if let Some(Answer::Refused(kind)) =
                refusal_codes::lookup_in(&**db, family).map(|c| c.answer)
            {
                return Self::Refused {
                    kind,
                    message: db.message().to_string(),
                };
            }
        }
        Self::from(e)
    }

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
    /// [`Self::OperatorLinkRequired`] and [`Self::OperatorScopeRefused`],
    /// migration 166's [`Self::RoleHolderRequired`], and the elevated viewer's
    /// [`Self::ElevatedReadOnly`]. The write surfaces map
    /// exactly this set to a denial (HTTP 403, MCP `INVALID_REQUEST`).
    #[must_use]
    pub fn is_write_authority_refusal(&self) -> bool {
        self.is_personal_group_refusal()
            || matches!(
                self,
                Self::OperatorLinkRequired { .. }
                    | Self::OperatorScopeRefused { .. }
                    | Self::RoleHolderRequired { .. }
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

/// A driver error built in memory, for the unit tests that pin how a coded
/// database refusal becomes a [`DbError`] (no database needed).
#[cfg(test)]
pub(crate) mod fake_db {
    use super::DbError;
    use std::borrow::Cow;

    #[derive(Debug)]
    struct FakeDbError {
        code: &'static str,
        message: String,
    }
    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.message)
        }
    }
    impl std::error::Error for FakeDbError {}
    impl sqlx::error::DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            &self.message
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.code))
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    /// A database error with SQLSTATE `code` and message `message`.
    pub(crate) fn error(code: &'static str, message: &str) -> sqlx::Error {
        sqlx::Error::Database(Box::new(FakeDbError {
            code,
            message: message.to_string(),
        }))
    }

    /// The variant `e` is, with the kind of a `Refused` and the text of a
    /// message-carrying variant: what a transport answers from.
    pub(crate) fn shape(e: &DbError) -> String {
        match e {
            DbError::Refused { kind, message } => format!("Refused({kind:?}): {message}"),
            DbError::QueryFailed { .. } => "QueryFailed".to_string(),
            DbError::NotFound { entity, id } => format!("NotFound({entity} {id})"),
            DbError::MembershipRevoked { message } => format!("MembershipRevoked: {message}"),
            DbError::PersonalGroupNotOwned { message } => {
                format!("PersonalGroupNotOwned: {message}")
            }
            DbError::OperatorLinkRequired { message } => {
                format!("OperatorLinkRequired: {message}")
            }
            DbError::OperatorScopeRefused { message } => {
                format!("OperatorScopeRefused: {message}")
            }
            DbError::RoleHolderRequired { message } => format!("RoleHolderRequired: {message}"),
            other => format!("other: {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake_db::{error, shape};
    use super::*;

    /// Every coded refusal `From<sqlx::Error>` answers for all callers, and
    /// the site-answered codes it must leave alone (a repo that calls the
    /// family's definer converts those, never the central mapping).
    #[test]
    fn the_central_conversion_answers_exactly_its_coded_refusals() {
        let rt07 = retracted_bba_rewrite_message(None);
        for (code, message, want) in [
            (
                "RVK01",
                "RVK01: x",
                "MembershipRevoked: RVK01: x".to_string(),
            ),
            (
                "RVK02",
                "RVK02: x",
                "PersonalGroupNotOwned: RVK02: x".to_string(),
            ),
            (
                "OPL01",
                "OPL01: x",
                "OperatorLinkRequired: OPL01: x".to_string(),
            ),
            (
                "OPL02",
                "OPL02: x",
                "OperatorScopeRefused: OPL02: x".to_string(),
            ),
            (
                "ROL01",
                "ROL01: x",
                "RoleHolderRequired: ROL01: x".to_string(),
            ),
            // RT07 is 42501 plus the prefix; the text is rebuilt here (no
            // DETAIL on an in-memory error, so no row id).
            (
                "42501",
                "RT07: mass function 1 is retracted",
                format!("Refused(State): {rt07}"),
            ),
            // RT07 under another SQLSTATE, or without ": ", is not RT07.
            (
                "P0001",
                "RT07: mass function 1 is retracted",
                "QueryFailed".to_string(),
            ),
            (
                "42501",
                "RT07 mass function 1 is retracted",
                "QueryFailed".to_string(),
            ),
            // A site-answered code stays a database error centrally.
            ("P0001", "VIS01: x", "QueryFailed".to_string()),
            ("P0001", "PVS01: x", "QueryFailed".to_string()),
            ("42501", "CSG01: x", "QueryFailed".to_string()),
            ("P0001", "BUG01: x", "QueryFailed".to_string()),
            ("TGP01", "TGP01: x", "QueryFailed".to_string()),
            ("TGP08", "TGP08: x", "QueryFailed".to_string()),
            ("ELV04", "ELV04: x", "QueryFailed".to_string()),
            ("CUS04", "CUS04: x", "QueryFailed".to_string()),
            // A reviewed 176 code is disclosed by the HTTP layer, not here.
            ("42501", "GRM05: x", "QueryFailed".to_string()),
            ("55000", "SR09: x", "QueryFailed".to_string()),
            // A custom SQLSTATE no one maps.
            ("ELV05", "ELV05: x", "QueryFailed".to_string()),
        ] {
            assert_eq!(
                shape(&DbError::from(error(code, message))),
                want,
                "{code} {message:?}"
            );
        }
    }
}
