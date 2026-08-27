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

/// Map a repository error onto the right JSON-RPC error class.
///
/// `DbError::InvalidData` is a caller mistake (e.g. a label carrying
/// unexpanded shell syntax), so it must surface as `INVALID_PARAMS` — an agent
/// that gets `INTERNAL_ERROR` retries the same bad payload. Every other
/// variant keeps the pre-existing `internal_error` behaviour, including
/// `NotFound`, so this is not a wider behaviour change.
pub fn map_db_error(e: epigraph_db::DbError) -> McpError {
    match e {
        epigraph_db::DbError::InvalidData { reason } => invalid_params(reason),
        other => internal_error(other),
    }
}

pub fn parse_uuid(s: &str) -> Result<uuid::Uuid, McpError> {
    uuid::Uuid::parse_str(s).map_err(|e| invalid_params(format!("invalid UUID: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_db_error_maps_invalid_data_to_invalid_params() {
        let err = map_db_error(epigraph_db::DbError::InvalidData {
            reason: "label \"$FOO\" contains `$NAME` variable reference".to_string(),
        });
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
        assert!(err.message.contains("$FOO"), "message was: {}", err.message);
    }

    /// Pins that the mapping change is additive: variants other than
    /// `InvalidData` keep their pre-existing `INTERNAL_ERROR` classification.
    #[test]
    fn map_db_error_leaves_other_variants_as_internal_error() {
        let err = map_db_error(epigraph_db::DbError::NotFound {
            entity: "Claim".to_string(),
            id: uuid::Uuid::nil(),
        });
        assert_eq!(err.code, ErrorCode::INTERNAL_ERROR);
    }
}
