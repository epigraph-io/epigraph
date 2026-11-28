#![allow(clippy::wildcard_imports)]

use std::borrow::Cow;

use rmcp::model::*;

pub type McpError = ErrorData;

pub fn invalid_params(msg: impl Into<String>) -> McpError {
    McpError {
        code: ErrorCode::INVALID_PARAMS,
        message: Cow::from(msg.into()),
        data: None,
    }
}

/// The message every redacted [`internal_error`] carries in place of the
/// error it was given.
pub const INTERNAL_ERROR_MESSAGE: &str = "internal error; the detail is in the server log";

/// A server fault whose detail stays on the server.
///
/// `e` is logged (`tracing::error!`, target `mcp.internal_error`) and the
/// JSON-RPC message is [`INTERNAL_ERROR_MESSAGE`]: call sites hand this a
/// driver, upstream or provider error (`.map_err(internal_error)`), whose
/// text can name SQL, internal hosts or another tenant's rows, so it never
/// reaches the caller. A site with context to add uses
/// [`internal_error_logged`] instead: `internal_error(format!("ctx: {e}"))`
/// would discard the context too (tests/internal_error_format_ratchet.rs
/// refuses new ones). The MCP
/// twin of the HTTP layer's `ApiError::InternalError` redaction (PR #667).
///
/// One exception: a refusal the codebase itself authored
/// ([`designed_refusal`]) is sent as it was written, because it is the
/// caller's remedy, and logged at `warn` ([`log_designed_refusal`]) the way
/// the HTTP mapper logs it. It is recognised from the error's type, never from the
/// rendered `Display` of `e`, so it only applies where `e` reaches this call
/// unwrapped (`.map_err(internal_error)`): a coded refusal formatted into a
/// `String` first (`internal_error(format!("ctx: {e}"))`) is redacted.
///
/// Text the CALLER must read (an operator remedy, "Nothing was written") is
/// [`internal_error_text`], or [`internal_error_logged`] when there is also an
/// error to keep server-side.
pub fn internal_error<E: std::fmt::Display + 'static>(e: E) -> McpError {
    if let Some(text) = designed_refusal(&e) {
        log_designed_refusal(&e, &text);
        return internal_error_text(text);
    }
    tracing::error!(target: "mcp.internal_error", detail = %e, "internal error");
    McpError {
        code: ErrorCode::INTERNAL_ERROR,
        message: Cow::Borrowed(INTERNAL_ERROR_MESSAGE),
        data: None,
    }
}

/// The caller's answer when a federated `tools/call` fails (backlog 7ea4bd74).
///
/// `extension` is the configured extension name and `tool` the name the
/// caller used (the gateway's, prefix included).
///
/// - The downstream ANSWERED with a JSON-RPC error: that error is returned
///   unchanged, code and message. It is the extension's own tool error (an
///   invalid-params refusal, say) and the federation spec's "surfaced as a
///   normal MCP tool error"; redacting it left the caller unable to correct
///   the call.
/// - Except an INTERNAL error (`-32603`): a downstream's internal error is
///   where its own driver and provider text lands when it does not redact
///   (the reference extension's `internal_error` formats `e` into the
///   message), and this server keeps that text from every caller
///   ([`internal_error`]). The caller is told which extension failed; the
///   downstream's message goes to the server log ([`internal_error_logged`]).
///   The operator ruled redaction over pass-through on 2026-11-16.
/// - The extension could not be reached, or did not answer in time: a designed
///   message naming the extension and what happened, so "the tool is down"
///   is told apart from "the gateway is broken".
/// - Anything else on the session: named as a failed request to that
///   extension.
///
/// The transport detail (the dialled URI, the driver's error text) is
/// deployment topology and stays in the server log, as for
/// [`internal_error`].
pub fn federated_call_error(
    extension: &str,
    tool: &str,
    e: crate::federation::client::FederationError,
) -> McpError {
    use crate::federation::client::FederationError as F;
    let message = match e {
        F::Downstream(downstream) if downstream.code == ErrorCode::INTERNAL_ERROR => {
            return internal_error_logged(
                format!(
                    "`{tool}` failed with an internal error in extension `{extension}`; the \
                     detail is in the server log"
                ),
                format_args!(
                    "federated extension `{extension}` answered `{tool}` with an internal \
                     error: {}",
                    downstream.message
                ),
            );
        }
        F::Downstream(downstream) => {
            tracing::info!(
                target: "mcp.federation",
                extension,
                tool,
                code = downstream.code.0,
                "federated call refused by the extension"
            );
            return downstream;
        }
        F::CallTimeout { timeout, .. } => {
            tracing::warn!(target: "mcp.federation", extension, tool, ?timeout, "federated call timed out");
            format!(
                "extension `{extension}` did not answer `{tool}` within {}s; the gateway \
                 abandoned the call. It may still have run in the extension, so check before \
                 retrying a write.",
                timeout.as_secs()
            )
        }
        ref unreachable @ (F::Timeout(..) | F::Connect { .. }) => {
            tracing::warn!(target: "mcp.federation", extension, tool, detail = %unreachable, "federated call could not reach the extension");
            format!(
                "extension `{extension}` is unavailable; `{tool}` was not run. The gateway \
                 re-dials it on a timer and its tools return when it answers."
            )
        }
        F::Exchange(ref detail) => {
            tracing::warn!(target: "mcp.federation", extension, tool, detail = %detail, "federated call refused: no extension token");
            format!(
                "the gateway could not obtain a token for extension `{extension}` ({detail}); \
                 `{tool}` was not run"
            )
        }
        F::Request(ref detail) => {
            tracing::error!(target: "mcp.federation", extension, tool, detail = %detail, "federated call failed");
            format!(
                "the request to extension `{extension}` for `{tool}` failed; the detail is in \
                 the server log"
            )
        }
    };
    McpError {
        code: ErrorCode::INTERNAL_ERROR,
        message: Cow::from(message),
        data: None,
    }
}

/// The caller-facing text of a refusal the codebase authored, or `None`.
///
/// Two shapes qualify:
///
/// * a `sqlx::Error::Database` (bare or inside `DbError::QueryFailed`) whose
///   own message opens with a schema refusal code ([`coded`]: `FA07: ...`,
///   `CX02: ...`), the convention the migrations' `RAISE EXCEPTION` refusals
///   follow. This arm reads the database's MESSAGE (not the driver's
///   wrapping of it), and only that message is returned.
/// * `DbError::Refused { message, .. }`, the variant the repo layer builds for
///   its own refusals (`mark_duplicate: canonical ... is not current`); every
///   such site in `epigraph-db` writes literal text and ids, no error. A
///   `sqlx::Error::Protocol`, bare or `?`-converted into
///   `DbError::QueryFailed`, does not qualify: `epigraph-engine` stringifies
///   other errors into that variant and sqlx raises its own protocol errors
///   through it (backlog e0f0cb68).
///
/// A designed refusal without a code (a `RAISE` that names no code) is
/// redacted like any other error: that fails closed.
fn designed_refusal(e: &dyn std::any::Any) -> Option<String> {
    let database = |s: &sqlx::Error| match s {
        sqlx::Error::Database(d) if coded(d.message()) => Some(d.message().to_string()),
        _ => None,
    };
    if let Some(db) = e.downcast_ref::<epigraph_db::DbError>() {
        return match db {
            epigraph_db::DbError::Refused { message, .. } => Some(message.clone()),
            epigraph_db::DbError::QueryFailed { source } => database(source),
            _ => None,
        };
    }
    e.downcast_ref::<sqlx::Error>().and_then(database)
}

/// Log a designed refusal [`internal_error`] is about to send as written
/// (backlog 365e0749): `warn`, target `mcp.internal_error`, with the fields
/// and message the HTTP mapper (`From<DbError> for ApiError`) logs for the
/// same refusal, so an operator finds it in the MCP journal too.
///
/// * a coded database refusal: `detail` (its message) and `db_detail`, the
///   database's DETAIL, which the reply withholds (migration 176 moved
///   disclosure-sensitive text there), so the log is the only place it is
///   kept;
/// * a repo-authored `DbError::Refused`: `?kind` and `detail`.
fn log_designed_refusal(e: &dyn std::any::Any, text: &str) {
    let source = match e.downcast_ref::<epigraph_db::DbError>() {
        Some(epigraph_db::DbError::Refused { kind, .. }) => {
            tracing::warn!(
                target: "mcp.internal_error",
                ?kind,
                detail = %text,
                "the repository refused the request"
            );
            return;
        }
        Some(epigraph_db::DbError::QueryFailed { source }) => Some(source),
        Some(_) => None,
        None => e.downcast_ref::<sqlx::Error>(),
    };
    let db_detail = source
        .and_then(sqlx::Error::as_database_error)
        .and_then(|d| d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>())
        .and_then(sqlx::postgres::PgDatabaseError::detail);
    tracing::warn!(
        target: "mcp.internal_error",
        detail = %text,
        db_detail = ?db_detail,
        "the database refused the request"
    );
}

/// Whether a database message opens with a schema refusal code: two to five
/// ASCII capitals, two digits, a colon (`FA07: ...`), at the very start. The
/// grammar is [`epigraph_auth::claim_act::is_coded_refusal`], the one the
/// claim-act refusal kinds are classified by, so a code reads as a code on
/// every path.
pub(crate) fn coded(message: &str) -> bool {
    epigraph_auth::claim_act::is_coded_refusal(message)
}

/// A server fault whose message is DESIGNED, caller-facing text, sent
/// verbatim.
///
/// Never interpolate an error's `Display` (a driver, upstream or provider
/// error) into `message`: that is what [`internal_error`] and
/// [`internal_error_logged`] exist to keep out of a response. Identifiers the
/// caller already holds (its tool name, its agent id) are fine.
pub fn internal_error_text(message: impl Into<String>) -> McpError {
    McpError {
        code: ErrorCode::INTERNAL_ERROR,
        message: Cow::from(message.into()),
        data: None,
    }
}

/// [`internal_error_text`] for a site that also holds the error that caused
/// it: `message` (designed text, no error interpolated) goes to the caller,
/// `cause` to the server log (target `mcp.internal_error`).
pub fn internal_error_logged(
    message: impl Into<String>,
    cause: impl std::fmt::Display,
) -> McpError {
    let message = message.into();
    tracing::error!(
        target: "mcp.internal_error",
        reply = %message,
        detail = %cause,
        "internal error"
    );
    internal_error_text(message)
}

/// The explicit refusal for a patch, retract or delete of an edge the caller
/// can READ but may not write (migrations 115/117/120; operator decision D8).
///
/// Caller-error class (`INVALID_REQUEST`): a denial of authority, not a server
/// fault and not something a parameter change fixes. The message names the
/// rule ("owned by another writer", or "an administrative (world-owned) edge;
/// admin-only"), and `data` carries it for machines:
/// `{"error": "not_owner", "rule": "owned_by_another_writer" |
/// "administrative_edge", "edge_id": "<id>"}`. An edge the caller cannot read
/// keeps the not-found answer instead (no existence oracle).
pub fn edge_not_owner(
    refusal: epigraph_db::EdgeRefusal,
    edge_id: uuid::Uuid,
    action: &str,
) -> McpError {
    McpError {
        code: ErrorCode::INVALID_REQUEST,
        message: Cow::from(refusal.message(edge_id, action)),
        data: Some(serde_json::json!({
            "error": "not_owner",
            "rule": refusal.rule(),
            "edge_id": edge_id,
            "retryable": false,
        })),
    }
}

/// The explicit refusal for a claim act (`supersede_claim`, `mark_duplicate`)
/// on a claim the caller can READ but may not retire (batch OA1, operator
/// decision D1; the rule is `epigraph_auth::claim_act`).
///
/// `INVALID_REQUEST`, like [`edge_not_owner`]: a denial of authority. `data`
/// carries `{"error": "not_owner", "rule": "not_claim_writer", "claim_id":
/// "<id>", "retryable": false}`, the HTTP route's body keys. A claim the caller
/// cannot read keeps the not-found answer instead (no existence oracle).
pub fn claim_not_writer(claim_id: uuid::Uuid, action: &str) -> McpError {
    McpError {
        code: ErrorCode::INVALID_REQUEST,
        message: Cow::from(epigraph_auth::claim_act::not_claim_writer_message(
            claim_id, action,
        )),
        data: Some(serde_json::json!({
            "error": "not_owner",
            "rule": epigraph_auth::claim_act::NOT_CLAIM_WRITER_RULE,
            "claim_id": claim_id,
            "retryable": false,
        })),
    }
}

pub fn parse_uuid(s: &str) -> Result<uuid::Uuid, McpError> {
    uuid::Uuid::parse_str(s).map_err(|e| invalid_params(format!("invalid UUID: {e}")))
}

/// Map a repository error onto the right JSON-RPC code, keeping
/// `DbError::InvalidData` on the CALLER's side of the line.
///
/// `internal_error` is wrong for `InvalidData`: it reports a rejection the
/// caller caused (e.g. a label carrying unexpanded shell syntax, refused by
/// `epigraph_db::reject_unexpanded_labels`) as a server fault, which tells an
/// agent to retry a request that can never succeed. Mirrors the HTTP layer,
/// where `From<DbError> for ApiError` maps `InvalidData` to a 400
/// `ValidationError`, and `map_edge_err` in `crate::tools::edge_mutation`,
/// which does the same for `NotFound`.
///
/// `DbError::MembershipRevoked` (migration 105's refusal to restore a revoked
/// personal-group membership) and its sibling `DbError::PersonalGroupNotOwned`
/// (105's refusal to join a group squatting the agent's personal did_key) are
/// `INVALID_REQUEST`: a denial of authority, not
/// a server fault, and not something the caller can fix by changing a
/// parameter either — the same classification `tools::viewer::request_viewer`
/// uses for a missing principal.
///
/// Every other `DbError` variant stays `INTERNAL_ERROR` — a connection fault or
/// a failed query is not the caller's fault and must not read as one.
pub fn db_caller_error(e: epigraph_db::DbError) -> McpError {
    match e {
        epigraph_db::DbError::InvalidData { reason } => invalid_params(reason),
        epigraph_db::DbError::MembershipRevoked { message }
        | epigraph_db::DbError::PersonalGroupNotOwned { message } => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(message),
            data: None,
        },
        // Migration 122's OPL01 names only the unbound agent (the caller's own
        // write identity or the author it named), never a human: forwarded as
        // the database words it, code and fix included.
        e @ epigraph_db::DbError::OperatorLinkRequired { .. } => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(e.to_string()),
            data: None,
        },
        // OPL02 carries the database's own words, which name the agent's human
        // operator ("... belongs to human operator <id>"): a human's id is a
        // disclosure the human-identity rule keeps to readers it admits (spec
        // 2026-11-24, row I3; finding L8). Mapped to the fixed text the REST
        // surface already answers (`epigraph-api/src/errors.rs`); the ids stay
        // in the server log.
        epigraph_db::DbError::OperatorScopeRefused { message } => {
            tracing::warn!(detail = %message, "linked agent outside its operator's groups");
            McpError {
                code: ErrorCode::INVALID_REQUEST,
                message: Cow::from(
                    "OPL02: the write is outside the groups its human operator holds \
                     writer/admin membership in, or names an author that belongs to another \
                     human than the caller's; an agent writes only where its own operator \
                     writes, and only in its own human's name. Nothing was written.",
                ),
                data: None,
            }
        }
        // Migration 166's ROL01 (a role's agent without its live holder): the
        // same class of denial; its rendering carries the code and the fix.
        e @ epigraph_db::DbError::RoleHolderRequired { .. } => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(e.to_string()),
            data: None,
        },
        // Row security let the caller read the row but not change it
        // (migrations 115/117): the same class of denial.
        e @ epigraph_db::DbError::WriteRefused { .. } => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(e.to_string()),
            data: None,
        },
        // An elevated request asked to write (elevation plan EL-6).
        e @ epigraph_db::DbError::ElevatedReadOnly => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(e.to_string()),
            data: None,
        },
        // A supersede-architecture refusal (SPEC section 7.2; migration 194's
        // SR09): the database's coded MESSAGE, reviewed for the caller (row ids
        // are in DETAIL), as a caller error. `internal_error` would send the
        // same text as -32603.
        epigraph_db::DbError::QueryFailed {
            source: sqlx::Error::Database(db),
        } if epigraph_db::supersede_refusal_code(db.message()).is_some() => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(db.message().to_string()),
            data: None,
        },
        other => internal_error(other),
    }
}

/// Map an ingest-executor error for the caller: migration 105's two
/// personal-group refusals (`DbError::is_personal_group_refusal`), carried as
/// `IngestExecutorError::Repository`, take [`db_caller_error`]'s
/// `INVALID_REQUEST`, as they do on every other tool. Everything else stays
/// `INTERNAL_ERROR`, prefixed with `context`.
///
/// The executor reaches the definer through `default_decl_for_author` (the
/// workflow ingest's one undeclared owner, `add_step`'s step claim): for a
/// caller-authored write, the caller's own default declaration (`OPL01` /
/// `OPL02` and migration 105's refusals are all the caller's to act on).
pub fn executor_caller_error(
    context: &str,
    e: epigraph_ingest_executor::IngestExecutorError,
) -> McpError {
    match e {
        epigraph_ingest_executor::IngestExecutorError::Repository(db)
            if db.is_write_authority_refusal() =>
        {
            db_caller_error(db)
        }
        // U032: the caller's payload plans a content-less generation. A caller
        // error, so an agent stops retrying (the retry loop minted the stubs).
        e @ epigraph_ingest_executor::IngestExecutorError::EmptyGeneration { .. } => {
            invalid_params(format!("{context}: {e}"))
        }
        // The pre-flight refused blank claim content (a blank thesis, phase,
        // step or operation): the caller's payload error, naming the field.
        e @ epigraph_ingest_executor::IngestExecutorError::InvalidContent { .. } => {
            invalid_params(format!("{context}: {e}"))
        }
        // A generation-0 payload naming a parent it could never link
        // (backlog 26a436c6): the caller's payload error.
        e @ epigraph_ingest_executor::IngestExecutorError::GenerationZeroNamesParent { .. } => {
            invalid_params(format!("{context}: {e}"))
        }
        // A tenancy refusal (the caller does not write the declared or
        // inherited group, or names no principal): a denial, as OPL02 is.
        e if e.is_declared_tenancy_refusal() => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(format!("{context}: {e}")),
            data: None,
        },
        // The plan's (canonical_name, generation) is held by a `workflows` row
        // the ingest cannot read (migration 183), or the lineage it writes has
        // generations the caller cannot read (migration 202): a caller
        // conflict, so an agent reads the reason instead of a logged internal
        // error.
        //
        // A walk stopped at an existing row it was not admitted over
        // (`ExistingWorkflowNeedsAuthority`): an entry point checks its
        // authority and retries, so it reaches here only unhandled. Its text
        // names the workflow by name and generation, never by id.
        e @ (epigraph_ingest_executor::IngestExecutorError::WorkflowOutsideView { .. }
        | epigraph_ingest_executor::IngestExecutorError::LineageOutsideView { .. }
        | epigraph_ingest_executor::IngestExecutorError::ExistingWorkflowNeedsAuthority {
            ..
        }) => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(format!("{context}: {e}")),
            data: None,
        },
        // Migration 148's armed-and-unregistered refusal: its text is the
        // operator's remedy (no driver error in it), so the caller reads it.
        e @ epigraph_ingest_executor::IngestExecutorError::SystemAgentUnregistered { .. } => {
            internal_error_text(format!("{context}: {e}"))
        }
        other => internal_error_logged(format!("{context}: {INTERNAL_ERROR_MESSAGE}"), other),
    }
}

/// How an HTTP twin of a tool answers one of its errors (`epigraph-api`'s
/// `routes::mcp_twins`, backlog fff61b9e). Defined in the service crate
/// (`epigraph_service::errors`), so a front end that is not this server can
/// classify a service error without depending on it; re-exported here for the
/// callers that classify an [`McpError`].
pub use epigraph_service::errors::{HttpClass, ServiceError};

/// The [`ServiceError`] an [`McpError`] is, decided by the JSON-RPC code alone:
/// `INVALID_PARAMS` is [`ServiceError::InvalidParams`], `INVALID_REQUEST` (this
/// codebase's class for a denial of authority: [`edge_not_owner`],
/// [`claim_not_writer`], a missing principal) is [`ServiceError::Denied`], and
/// every other code, `INTERNAL_ERROR` included, is [`ServiceError::Internal`].
/// The message is kept; `data` is not (a service error carries none).
#[must_use]
pub fn to_service(e: &McpError) -> ServiceError {
    let message = e.message.to_string();
    if e.code == ErrorCode::INVALID_PARAMS {
        ServiceError::InvalidParams(message)
    } else if e.code == ErrorCode::INVALID_REQUEST {
        ServiceError::Denied(message)
    } else {
        ServiceError::Internal(message)
    }
}

/// The [`McpError`] a [`ServiceError`] is answered with.
///
/// * [`ServiceError::InvalidParams`], [`ServiceError::Denied`] and
///   [`ServiceError::Internal`] carry designed, caller-facing text (the service
///   crate's contract), sent as written: [`invalid_params`], an
///   `INVALID_REQUEST` with no `data`, or [`internal_error_text`]. These three
///   are the inverse of [`to_service`].
/// * [`ServiceError::InternalLogged`]: [`internal_error_logged`], its message
///   to the caller and its cause to the server log.
/// * [`ServiceError::Repository`]: classified from the repository error's type
///   by [`crate::claim_helper::visibility_caller_error`] (a repository refusal
///   keeps its text and class, a row the caller cannot see answers as missing,
///   and everything else takes [`db_caller_error`]).
/// * [`ServiceError::Fault`]: [`internal_error`] on the typed cause, so a coded
///   refusal is forwarded as written and anything else is redacted, exactly
///   as when the call site mapped the error itself.
///
/// A free function rather than a `From` impl: both types are foreign to this
/// crate (`McpError` is rmcp's `ErrorData`), so the orphan rule allows no impl
/// between them here, and the service crate does not depend on rmcp.
#[must_use]
pub fn from_service(e: ServiceError) -> McpError {
    match e {
        ServiceError::InvalidParams(m) => invalid_params(m),
        ServiceError::Denied(m) => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(m),
            data: None,
        },
        ServiceError::Internal(m) => internal_error_text(m),
        ServiceError::InternalLogged { message, cause } => internal_error_logged(message, cause),
        ServiceError::Repository(e) => crate::claim_helper::visibility_caller_error(e),
        ServiceError::Fault(epigraph_service::errors::Fault::Db(e)) => internal_error(e),
        ServiceError::Fault(epigraph_service::errors::Fault::Sqlx(e)) => internal_error(e),
    }
}

/// The [`HttpClass`] of `e`: the class of the [`ServiceError`] it is
/// ([`to_service`]), so the two surfaces classify a refusal the same way.
#[must_use]
pub fn http_class(e: &McpError) -> HttpClass {
    to_service(e).http_class()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boundaries of the refusal-code grammar (two to five ASCII capitals,
    /// exactly two digits, a colon, at the very start) that `internal_error`
    /// relays a database refusal by and the supersede mapper splits `42501`
    /// on (one predicate since backlog 86a26e69; the mapper had a private
    /// byte-for-byte copy).
    #[test]
    fn coded_admits_exactly_the_code_grammar() {
        for msg in [
            "CX03: the act",
            "OPL01: unbound",
            "ABCDE12: five capitals",
            "AB12:",
        ] {
            assert!(coded(msg), "{msg:?} is coded");
        }
        for msg in [
            "A12: one capital",
            "ABCDEF12: six capitals",
            "FA4: one digit",
            "FA123: three digits",
            "FA04 no colon",
            "FA04",
            " CX03: leading space",
            "cx03: lower case",
            "new row violates row-level security policy for table \"claims\"",
            "permission denied for function epigraph_record_cascade_deferral",
            "",
        ] {
            assert!(!coded(msg), "{msg:?} is not coded");
        }
    }

    /// A caller-caused rejection must be INVALID_PARAMS and must carry the
    /// repo's reason text through, and everything else must stay
    /// INTERNAL_ERROR. Both directions matter: collapsing the second arm into
    /// INVALID_PARAMS would tell an agent a transient DB fault is its fault
    /// and stop it retrying.
    #[test]
    fn invalid_data_is_invalid_params_other_variants_are_internal() {
        let caller = db_caller_error(epigraph_db::DbError::InvalidData {
            reason: "label \"group:$EPICLAW_GROUP_ID\" contains an unexpanded shell variable"
                .to_string(),
        });
        assert_eq!(caller.code, ErrorCode::INVALID_PARAMS);
        assert!(
            caller.message.contains("group:$EPICLAW_GROUP_ID"),
            "the offending value must survive the mapping, got: {}",
            caller.message
        );

        let server = db_caller_error(epigraph_db::DbError::NotFound {
            entity: "Claim".to_string(),
            id: uuid::Uuid::nil(),
        });
        assert_eq!(server.code, ErrorCode::INTERNAL_ERROR);

        let revoked = db_caller_error(epigraph_db::DbError::MembershipRevoked {
            message: "agent a holds only REVOKED membership(s) of its personal group g".to_string(),
        });
        assert_eq!(
            revoked.code,
            ErrorCode::INVALID_REQUEST,
            "a revoked membership is a denial, not a server fault"
        );
        assert!(revoked.message.contains("REVOKED"));

        let squatted = db_caller_error(epigraph_db::DbError::PersonalGroupNotOwned {
            message: "group g carries agent a's personal did_key but is not its personal group"
                .to_string(),
        });
        assert_eq!(
            squatted.code,
            ErrorCode::INVALID_REQUEST,
            "a squatted personal group is a denial, not a server fault"
        );

        let unbound = db_caller_error(epigraph_db::DbError::OperatorLinkRequired {
            message: "OPL01: agent a is not bound to a human operator".to_string(),
        });
        assert_eq!(
            unbound.code,
            ErrorCode::INVALID_REQUEST,
            "an unbound author is a denial, not a server fault"
        );
        assert!(
            unbound.message.contains("OPL01") && unbound.message.contains("epigraph-operator link"),
            "the denial must carry the code and name the fix: {}",
            unbound.message
        );
        let human = "5d1b1f2e-0000-4000-8000-00000000abcd";
        let scope = db_caller_error(epigraph_db::DbError::OperatorScopeRefused {
            message: format!(
                "OPL02: agent a writes a claim attributed to b, which belongs to human \
                 operator {human}"
            ),
        });
        assert_eq!(scope.code, ErrorCode::INVALID_REQUEST);
        assert!(scope.message.starts_with("OPL02"), "{}", scope.message);
        assert!(
            !scope.message.contains(human),
            "the human's id must stay in the log (spec I3): {}",
            scope.message
        );

        let role = db_caller_error(epigraph_db::DbError::RoleHolderRequired {
            message: "ROL01: agent a is attached to role r".to_string(),
        });
        assert_eq!(
            role.code,
            ErrorCode::INVALID_REQUEST,
            "a role's agent without its holder is a denial, not a server fault"
        );
        assert!(role.message.contains("ROL01"), "{}", role.message);

        // An elevated request asking to write (EL-6): a denial, not a fault.
        let elevated = db_caller_error(epigraph_db::DbError::ElevatedReadOnly);
        assert_eq!(elevated.code, ErrorCode::INVALID_REQUEST);
        assert!(
            elevated.message.contains("ELEVATED READ-ONLY"),
            "{}",
            elevated.message
        );
    }

    /// U032: a step-less new generation (or an empty plan) is the CALLER's
    /// payload error. As INTERNAL_ERROR it invited the very retry loop that
    /// minted 7 empty generations in ~90 s; it must be INVALID_PARAMS and keep
    /// the executor's reason text.
    #[test]
    fn an_empty_generation_is_invalid_params() {
        let e = executor_caller_error(
            "workflow ingest",
            epigraph_ingest_executor::IngestExecutorError::EmptyGeneration {
                canonical_name: "weekly-capability-audit".to_string(),
                generation: 3,
                level2: 0,
                claims: 1,
            },
        );
        assert_eq!(e.code, ErrorCode::INVALID_PARAMS);
        assert!(
            e.message.contains("empty workflow generation")
                && e.message.contains("weekly-capability-audit")
                && e.message.contains("Nothing was written"),
            "{}",
            e.message
        );
    }

    /// Backlog 26a436c6: a generation-0 payload naming a parent is the
    /// caller's error, INVALID_PARAMS with the executor's text.
    #[test]
    fn a_generation_zero_parent_is_invalid_params() {
        let e = executor_caller_error(
            "workflow ingest",
            epigraph_ingest_executor::IngestExecutorError::GenerationZeroNamesParent {
                canonical_name: "weekly-capability-audit-fork".to_string(),
                parent_canonical_name: "weekly-capability-audit".to_string(),
            },
        );
        assert_eq!(e.code, ErrorCode::INVALID_PARAMS);
        assert!(
            e.message.contains("generation 0 starts a lineage")
                && e.message.contains("Nothing was written"),
            "{}",
            e.message
        );
    }

    /// The executor's pre-flight refusal of blank claim content (a blank
    /// thesis, phase, step or operation in the caller's payload) is the
    /// caller's error: INVALID_PARAMS with the executor's text, which names the
    /// field. As INTERNAL_ERROR it told an agent to retry a payload that can
    /// never succeed.
    #[test]
    fn blank_claim_content_is_invalid_params() {
        let e = executor_caller_error(
            "workflow ingest",
            epigraph_ingest_executor::IngestExecutorError::InvalidContent {
                path: "phases[0].steps[1]".to_string(),
            },
        );
        assert_eq!(e.code, ErrorCode::INVALID_PARAMS);
        assert!(
            e.message.starts_with("workflow ingest: ")
                && e.message
                    .contains("blank claim content at phases[0].steps[1]"),
            "{}",
            e.message
        );
    }

    /// The executor wraps the refusal in `IngestExecutorError::Repository`; the
    /// workflow-ingest and add_step tools must still surface it as the denial,
    /// and must keep every other executor failure a server fault.
    #[test]
    fn executor_errors_surface_the_personal_group_refusal_as_a_denial() {
        use epigraph_ingest_executor::IngestExecutorError as X;
        let refused = executor_caller_error(
            "workflow ingest",
            X::Repository(epigraph_db::DbError::MembershipRevoked {
                message: "agent a holds only REVOKED membership(s) of its personal group g"
                    .to_string(),
            }),
        );
        assert_eq!(refused.code, ErrorCode::INVALID_REQUEST);
        assert!(refused.message.contains("REVOKED"));

        let other = executor_caller_error(
            "workflow ingest",
            X::Repository(epigraph_db::DbError::NotFound {
                entity: "Claim".to_string(),
                id: uuid::Uuid::nil(),
            }),
        );
        assert_eq!(other.code, ErrorCode::INTERNAL_ERROR);
        assert!(other.message.starts_with("workflow ingest: "));

        let preflight = executor_caller_error("store_workflow", X::AgentCreation("x".into()));
        assert_eq!(
            preflight.code,
            ErrorCode::INTERNAL_ERROR,
            "#498's system-agent preflight refusal keeps its classification"
        );
    }
    /// A driver or upstream error handed to `internal_error` stays on the
    /// server: the JSON-RPC message the caller reads does not carry its text,
    /// and the server log does (backlog 49863d2c).
    #[test]
    #[tracing_test::traced_test]
    fn internal_error_withholds_the_error_text_and_logs_it() {
        const MARKER: &str = "relation \"secret_table_7f3a\" does not exist at db-host-7f3a";
        let e = internal_error(format!("could not read: {MARKER}"));
        assert_eq!(e.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(
            e.message, INTERNAL_ERROR_MESSAGE,
            "the fixed message is sent"
        );
        assert!(
            !e.message.contains("secret_table_7f3a") && !e.message.contains("db-host-7f3a"),
            "the error text reached the caller: {}",
            e.message
        );
        assert!(e.data.is_none(), "no detail in data either: {:?}", e.data);
        assert!(
            logs_contain("secret_table_7f3a"),
            "the withheld detail must reach the server log"
        );
    }
    /// Designed caller-facing text survives verbatim, and the cause handed to
    /// `internal_error_logged` stays on the server.
    #[test]
    #[tracing_test::traced_test]
    fn designed_internal_error_text_reaches_the_caller_and_its_cause_does_not() {
        let text = internal_error_text("tool_x: nothing was written; register the agent first");
        assert_eq!(text.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(
            text.message, "tool_x: nothing was written; register the agent first",
            "designed text must reach the caller unchanged"
        );

        let logged = internal_error_logged(
            "tool_x: could not commit. Nothing was written.",
            "connection to db-host-91c2 refused",
        );
        assert_eq!(logged.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(
            logged.message,
            "tool_x: could not commit. Nothing was written."
        );
        assert!(
            !logged.message.contains("db-host-91c2"),
            "{}",
            logged.message
        );
        assert!(
            logs_contain("db-host-91c2"),
            "the withheld cause must reach the server log"
        );
    }

    /// The executor's fall-through arm keeps its context prefix and withholds
    /// the executor error; migration 148's unregistered-system-agent refusal is
    /// the operator's remedy and is kept verbatim.
    #[test]
    fn executor_fall_through_withholds_the_error_and_keeps_the_remedy() {
        use epigraph_ingest_executor::IngestExecutorError as X;
        let other = executor_caller_error(
            "workflow ingest",
            X::AgentCreation("create: duplicate key value violates \"agents_pkey_7d1e\"".into()),
        );
        assert_eq!(other.code, ErrorCode::INTERNAL_ERROR);
        assert!(
            other.message.starts_with("workflow ingest: "),
            "{}",
            other.message
        );
        assert!(
            !other.message.contains("agents_pkey_7d1e"),
            "{}",
            other.message
        );

        let unregistered = executor_caller_error(
            "workflow ingest",
            X::SystemAgentUnregistered {
                role: "workflow-ingest",
            },
        );
        assert_eq!(unregistered.code, ErrorCode::INTERNAL_ERROR);
        assert!(
            unregistered.message.contains("register-system-agent"),
            "the operator remedy must reach the caller: {}",
            unregistered.message
        );
    }

    /// A `Protocol` error that `?` converted into `DbError::QueryFailed` is
    /// NOT a designed refusal (backlog e0f0cb68 (1)): `From<sqlx::Error> for
    /// DbError` wraps sqlx's own protocol errors and an engine
    /// stringification of any other error into exactly this shape, so its
    /// text is the server's to read. Only `DbError::Refused`, the variant
    /// the repo layer builds for its own refusals, is sent as written.
    #[test]
    fn a_protocol_error_converted_into_query_failed_is_redacted() {
        let converted = internal_error(epigraph_db::DbError::from(sqlx::Error::Protocol(
            "louvain: worker at db-host-5d2e panicked".to_string(),
        )));
        assert_eq!(converted.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(
            converted.message, INTERNAL_ERROR_MESSAGE,
            "a converted protocol error reached the caller: {}",
            converted.message
        );
    }

    /// A refusal the repo layer authored (`DbError::Refused`) is the caller's
    /// remedy and is sent as written; a bare `sqlx::Error::Protocol` handed
    /// over unconverted (engine code stringifies other errors into it) is
    /// not, and neither is its `?`-converted form (the test above).
    #[test]
    fn a_repo_authored_refusal_passes_and_a_bare_protocol_error_does_not() {
        // Every kind passes as written (operator ruling R-55 keeps the #686
        // passthrough for a refusal of any kind; the kind is not appended).
        for (kind, message) in [
            (
                epigraph_db::RefusalKind::Input,
                "mark_duplicate: dup == canonical",
            ),
            (
                epigraph_db::RefusalKind::Authority,
                "FA04: canonical c is not public and this session cannot write it",
            ),
            (
                epigraph_db::RefusalKind::State,
                "mark_duplicate: canonical c is not current; refusing",
            ),
        ] {
            let designed = internal_error(epigraph_db::DbError::Refused {
                kind,
                message: message.to_string(),
            });
            assert_eq!(designed.code, ErrorCode::INTERNAL_ERROR, "{kind:?}");
            assert_eq!(designed.message, message, "{kind:?}");
        }

        let bare = internal_error(sqlx::Error::Protocol(
            "Check constraint chk_secret_7a1 violated".to_string(),
        ));
        assert_eq!(bare.message, INTERNAL_ERROR_MESSAGE, "{}", bare.message);

        let other = internal_error(epigraph_db::DbError::CheckViolation {
            constraint: "chk_secret_7a1".to_string(),
            message: "violated".to_string(),
        });
        assert_eq!(other.message, INTERNAL_ERROR_MESSAGE, "{}", other.message);
    }

    /// A designed refusal is sent as written AND logged (backlog 365e0749):
    /// before, `internal_error` returned it before its log line, so the MCP
    /// journal never showed it while the HTTP mapper logs the same refusal at
    /// `warn`. The fields match the HTTP `Refused` arm (`?kind`, `detail`).
    /// The uncoded path keeps its own `internal error` line (calibration).
    #[test]
    #[tracing_test::traced_test]
    fn a_designed_refusal_reaches_the_caller_as_written_and_is_logged() {
        const MESSAGE: &str = "mark_duplicate: canonical c-5b17 is not current; refusing";
        let designed = internal_error(epigraph_db::DbError::Refused {
            kind: epigraph_db::RefusalKind::State,
            message: MESSAGE.to_string(),
        });
        assert_eq!(designed.message, MESSAGE, "the caller's text is unchanged");
        assert!(
            logs_contain("the repository refused the request"),
            "a repo-authored refusal leaves a log line"
        );
        assert!(
            logs_contain("c-5b17"),
            "the line carries the refusal's text"
        );
        assert!(logs_contain("State"), "the line carries the refusal's kind");
        assert!(
            logs_contain("WARN"),
            "logged at warn, the HTTP mapper's level"
        );
        // By field NAME, on the refusal's own line, under the MCP target.
        logs_assert(|lines: &[&str]| {
            let line = lines
                .iter()
                .find(|l| l.contains("the repository refused the request"))
                .ok_or("no repository-refusal line")?;
            for field in [
                "WARN",
                "mcp.internal_error",
                "kind=State",
                "detail=mark_duplicate: canonical c-5b17",
            ] {
                if !line.contains(field) {
                    return Err(format!("the refusal's line lacks `{field}`: {line}"));
                }
            }
            Ok(())
        });

        let uncoded = internal_error(epigraph_db::DbError::from(sqlx::Error::Protocol(
            "worker at db-host-a91e failed".to_string(),
        )));
        assert_eq!(uncoded.message, INTERNAL_ERROR_MESSAGE);
        logs_assert(|lines: &[&str]| {
            lines
                .iter()
                .any(|l| {
                    l.contains("db-host-a91e")
                        && l.contains("mcp.internal_error")
                        && l.contains("ERROR")
                })
                .then_some(())
                .ok_or_else(|| {
                    "calibration: the redacted path logs its detail at error under \
                     mcp.internal_error, on one line"
                        .to_string()
                })
        });
    }

    /// The schema-code gate decides which database text reaches the caller,
    /// so both of its edges are pinned: two to five capitals, exactly two
    /// digits, a colon, at the start of the message.
    #[test]
    fn a_schema_refusal_code_is_recognised_only_in_its_exact_shape() {
        for accepted in [
            "FA07: writer-owned attach refused",
            "CX02: x",
            "ABCDE12: five capitals",
        ] {
            assert!(coded(accepted), "{accepted:?} must be recognised");
        }
        for rejected in [
            "A07: one capital",
            "ABCDEF07: six capitals",
            "FA7: one digit",
            "FA071: three digits",
            "fa07: lowercase",
            "x FA07: not at the start",
            "FA07 no colon",
            "duplicate key value violates unique constraint \"agents_pkey\"",
            "",
        ] {
            assert!(!coded(rejected), "{rejected:?} must not be recognised");
        }
    }

    /// Each code an HTTP twin can see maps to its own class, and an unknown
    /// code is a server fault, never a caller error.
    #[test]
    fn http_class_follows_the_json_rpc_code() {
        assert_eq!(http_class(&invalid_params("bad")), HttpClass::BadRequest);
        assert_eq!(
            http_class(&claim_not_writer(uuid::Uuid::nil(), "supersede")),
            HttpClass::Forbidden
        );
        assert_eq!(http_class(&internal_error_text("x")), HttpClass::Internal);
        assert_eq!(
            http_class(&McpError {
                code: ErrorCode::METHOD_NOT_FOUND,
                message: Cow::Borrowed("no such method"),
                data: None,
            }),
            HttpClass::Internal
        );
    }

    /// Every service error survives the trip into an `McpError` and back with
    /// its class and message, and its MCP code classifies to the same
    /// [`HttpClass`] the service crate gives it.
    #[test]
    fn service_errors_round_trip_through_mcp_errors() {
        let designed = || {
            [
                ServiceError::InvalidParams("bad input".into()),
                ServiceError::Denied("not yours".into()),
                ServiceError::Internal("designed fault text".into()),
            ]
        };
        for (e, again) in designed().into_iter().zip(designed()) {
            let class = e.http_class();
            let mcp = from_service(e);
            assert_eq!(http_class(&mcp), class, "{again:?}");
            assert_eq!(mcp.data, None, "{again:?}");
            let back = to_service(&mcp);
            assert_eq!(back.http_class(), class, "{again:?}");
            assert_eq!(back.message(), again.message());
        }
        assert_eq!(
            from_service(ServiceError::InvalidParams("x".into())).code,
            ErrorCode::INVALID_PARAMS
        );
        assert_eq!(
            from_service(ServiceError::Denied("x".into())).code,
            ErrorCode::INVALID_REQUEST
        );
        assert_eq!(
            from_service(ServiceError::Internal("x".into())).code,
            ErrorCode::INTERNAL_ERROR
        );
    }

    /// The typed variants are answered as the call sites that used to map the
    /// error themselves answered it: a logged fault sends its designed message
    /// and keeps the cause out of the reply, a driver fault is redacted, and a
    /// repository error is classified from its type, so the MCP class and the
    /// service crate's HTTP class agree.
    #[test]
    fn typed_service_errors_keep_their_mcp_answer() {
        use epigraph_db::errors::RefusalKind;
        use epigraph_db::DbError;
        use epigraph_service::errors::Fault;

        let logged = from_service(ServiceError::InternalLogged {
            message: "tool: could not acquire a viewer-stamped connection".into(),
            cause: "secret driver text".into(),
        });
        assert_eq!(logged.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(
            logged.message,
            "tool: could not acquire a viewer-stamped connection"
        );

        let fault = from_service(ServiceError::Fault(Fault::Sqlx(sqlx::Error::PoolTimedOut)));
        assert_eq!(fault.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(fault.message, INTERNAL_ERROR_MESSAGE);
        let fault = from_service(ServiceError::Fault(Fault::Db(DbError::QueryFailed {
            source: sqlx::Error::PoolTimedOut,
        })));
        assert_eq!(fault.message, INTERNAL_ERROR_MESSAGE);

        let samples = || {
            vec![
                DbError::ElevatedReadOnly,
                DbError::Refused {
                    kind: RefusalKind::Input,
                    message: "malformed".into(),
                },
                DbError::Refused {
                    kind: RefusalKind::Authority,
                    message: "not yours".into(),
                },
                DbError::Refused {
                    kind: RefusalKind::State,
                    message: "already superseded".into(),
                },
                DbError::NotFound {
                    entity: "group".into(),
                    id: uuid::Uuid::nil(),
                },
                DbError::InvalidData {
                    reason: "bad label".into(),
                },
                DbError::QueryFailed {
                    source: sqlx::Error::PoolTimedOut,
                },
            ]
        };
        for (e, again) in samples().into_iter().zip(samples()) {
            let service_class = ServiceError::Repository(e).http_class();
            let mcp = from_service(ServiceError::Repository(again));
            assert_eq!(http_class(&mcp), service_class, "{mcp:?}");
        }
        assert_eq!(
            from_service(ServiceError::Repository(DbError::ElevatedReadOnly)).message,
            DbError::ElevatedReadOnly.to_string()
        );
    }
}
