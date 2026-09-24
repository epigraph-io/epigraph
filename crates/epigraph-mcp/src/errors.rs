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
/// personal-group membership) is `INVALID_REQUEST`: a denial of authority, not
/// a server fault, and not something the caller can fix by changing a
/// parameter either — the same classification `tools::viewer::request_viewer`
/// uses for a missing principal.
///
/// Every other `DbError` variant stays `INTERNAL_ERROR` — a connection fault or
/// a failed query is not the caller's fault and must not read as one.
pub fn db_caller_error(e: epigraph_db::DbError) -> McpError {
    match e {
        epigraph_db::DbError::InvalidData { reason } => invalid_params(reason),
        epigraph_db::DbError::MembershipRevoked { message } => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(message),
            data: None,
        },
        other => internal_error(other),
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
    }
}
