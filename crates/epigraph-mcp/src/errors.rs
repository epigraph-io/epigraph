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
/// driver, upstream or provider error (`.map_err(internal_error)`,
/// `internal_error(format!("...: {e}"))`), whose text can name SQL, internal
/// hosts or another tenant's rows, so it never reaches the caller. The MCP
/// twin of the HTTP layer's `ApiError::InternalError` redaction (PR #667).
///
/// One exception: a refusal the codebase itself authored
/// ([`designed_refusal`]) is sent as it was written, because it is the
/// caller's remedy. It is recognised from the error's type, never from the
/// rendered `Display` of `e`, so it only applies where `e` reaches this call
/// unwrapped (`.map_err(internal_error)`): a coded refusal formatted into a
/// `String` first (`internal_error(format!("ctx: {e}"))`) is redacted.
///
/// Text the CALLER must read (an operator remedy, "Nothing was written") is
/// [`internal_error_text`], or [`internal_error_logged`] when there is also an
/// error to keep server-side.
pub fn internal_error<E: std::fmt::Display + 'static>(e: E) -> McpError {
    if let Some(text) = designed_refusal(&e) {
        return internal_error_text(text);
    }
    tracing::error!(target: "mcp.internal_error", detail = %e, "internal error");
    McpError {
        code: ErrorCode::INTERNAL_ERROR,
        message: Cow::Borrowed(INTERNAL_ERROR_MESSAGE),
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
/// * `DbError::QueryFailed { source: sqlx::Error::Protocol(msg) }`, the shape
///   the repo layer builds for its own refusals (`mark_duplicate: canonical
///   ... is not current`); every such site in `epigraph-db` writes literal
///   text and ids, no error. A bare `sqlx::Error::Protocol` does not qualify,
///   because `epigraph-engine` stringifies other errors into that variant.
///   RESIDUAL: `From<sqlx::Error> for DbError` wraps ANY `Protocol` error into
///   this same shape once it is `?`-converted, including sqlx's own protocol
///   errors and an engine stringification that went through `DbError`, and
///   that text is then sent as written. A dedicated `DbError` variant for
///   repo-authored refusals would close it.
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
            epigraph_db::DbError::QueryFailed {
                source: sqlx::Error::Protocol(msg),
            } => Some(msg.clone()),
            epigraph_db::DbError::QueryFailed { source } => database(source),
            _ => None,
        };
    }
    e.downcast_ref::<sqlx::Error>().and_then(database)
}

/// Whether a database message opens with a schema refusal code: two to five
/// ASCII capitals, two digits, a colon (`FA07: ...`), at the very start.
fn coded(message: &str) -> bool {
    let b = message.as_bytes();
    let caps = b.iter().take_while(|c| c.is_ascii_uppercase()).count();
    (2..=5).contains(&caps)
        && b.len() > caps + 2
        && b[caps].is_ascii_digit()
        && b[caps + 1].is_ascii_digit()
        && b[caps + 2] == b':'
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
        // Migration 122's OPL01: the author is not bound to a human operator.
        // The same class of denial; its rendering carries the code and the fix.
        // Migration 166's ROL01 (a role's agent without its live holder) is
        // the same class.
        e @ (epigraph_db::DbError::OperatorLinkRequired { .. }
        | epigraph_db::DbError::OperatorScopeRefused { .. }
        | epigraph_db::DbError::RoleHolderRequired { .. }) => McpError {
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
/// workflow ingest's one declaration, `add_step`'s step claim). On the stamped
/// paths `system_agent_write_authority` refuses a revoked system agent first,
/// with its own `AgentCreation` error (#498's INTERNAL_ERROR, unchanged), so
/// this arm is what a revocation racing the preflight, or the unstamped
/// `do_ingest_workflow_via_pool` path, would surface.
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
        // A declared-tenancy refusal (the caller, or the system agent, does not
        // write the declared group): a denial, as OPL02 is.
        e if e.is_declared_tenancy_refusal() => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(format!("{context}: {e}")),
            data: None,
        },
        // The plan's (canonical_name, generation) is held by a `workflows` row
        // the ingest cannot read (migration 183): a caller conflict, so an
        // agent reads the reason instead of a logged internal error.
        e @ epigraph_ingest_executor::IngestExecutorError::WorkflowOutsideView { .. } => McpError {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let scope = db_caller_error(epigraph_db::DbError::OperatorScopeRefused {
            message: "OPL02: agent a is linked to operator o".to_string(),
        });
        assert_eq!(scope.code, ErrorCode::INVALID_REQUEST);
        assert!(scope.message.contains("OPL02"), "{}", scope.message);

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

    /// A refusal the repo layer authored (`QueryFailed { Protocol }`) is the
    /// caller's remedy and is sent as written; a bare `sqlx::Error::Protocol`
    /// handed over unconverted (engine code stringifies other errors into it)
    /// is not. Once `?` converts such an error into `DbError` it takes the
    /// first shape: see [`designed_refusal`]'s RESIDUAL.
    #[test]
    fn a_repo_authored_refusal_passes_and_a_bare_protocol_error_does_not() {
        let designed = internal_error(epigraph_db::DbError::QueryFailed {
            source: sqlx::Error::Protocol(
                "mark_duplicate: canonical c is not current; refusing".to_string(),
            ),
        });
        assert_eq!(designed.code, ErrorCode::INTERNAL_ERROR);
        assert_eq!(
            designed.message,
            "mark_duplicate: canonical c is not current; refusing"
        );

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
}
