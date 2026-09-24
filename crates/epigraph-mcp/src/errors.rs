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

pub fn internal_error(e: impl std::fmt::Display) -> McpError {
    McpError {
        code: ErrorCode::INTERNAL_ERROR,
        message: Cow::from(e.to_string()),
        data: None,
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
            if db.is_personal_group_refusal() =>
        {
            db_caller_error(db)
        }
        other => internal_error(format!("{context}: {other}")),
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
}
