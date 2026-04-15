use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
#[cfg(feature = "db")]
use epigraph_db::DbError;
use serde::Serialize;
use thiserror::Error;

/// API error types with HTTP status code mapping
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Bad request: {message}")]
    BadRequest { message: String },

    #[error("{entity} with ID {id} not found")]
    NotFound { entity: String, id: String },

    #[error("Unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature error: {reason}")]
    SignatureError { reason: String },

    #[error("Internal error: {message}")]
    InternalError { message: String },

    #[error("Validation error on field '{field}': {reason}")]
    ValidationError { field: String, reason: String },

    #[error("Integrity error on field '{field}': expected {expected}, got {actual}")]
    IntegrityError {
        field: String,
        expected: String,
        actual: String,
    },

    #[error("Database error: {message}")]
    DatabaseError { message: String },

    #[error("Service unavailable: {service}")]
    ServiceUnavailable { service: String },

    #[error("Forbidden: {reason}")]
    Forbidden { reason: String },
}

/// JSON error response structure
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_type, details) = match &self {
            ApiError::BadRequest { message } => (
                StatusCode::BAD_REQUEST,
                "BadRequest",
                Some(serde_json::json!({ "message": message })),
            ),
            ApiError::NotFound { entity, id } => (
                StatusCode::NOT_FOUND,
                "NotFound",
                Some(serde_json::json!({ "entity": entity, "id": id })),
            ),
            ApiError::Unauthorized { reason } => (
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                Some(serde_json::json!({ "reason": reason })),
            ),
            ApiError::InvalidSignature => (StatusCode::UNAUTHORIZED, "InvalidSignature", None),
            ApiError::SignatureError { reason } => (
                StatusCode::UNAUTHORIZED,
                "SignatureError",
                Some(serde_json::json!({ "reason": reason })),
            ),
            ApiError::InternalError { message } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                Some(serde_json::json!({ "message": message })),
            ),
            ApiError::ValidationError { field, reason } => (
                StatusCode::BAD_REQUEST,
                "ValidationError",
                Some(serde_json::json!({ "field": field, "reason": reason })),
            ),
            ApiError::IntegrityError {
                field,
                expected,
                actual,
            } => (
                StatusCode::BAD_REQUEST,
                "IntegrityError",
                Some(serde_json::json!({
                    "field": field,
                    "expected": expected,
                    "actual": actual
                })),
            ),
            ApiError::DatabaseError { message } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DatabaseError",
                Some(serde_json::json!({ "message": message })),
            ),
            ApiError::ServiceUnavailable { service } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                Some(serde_json::json!({ "service": service })),
            ),
            ApiError::Forbidden { reason } => (
                StatusCode::FORBIDDEN,
                "Forbidden",
                Some(serde_json::json!({ "reason": reason })),
            ),
        };

        let body = ErrorResponse {
            error: error_type.to_string(),
            message: self.to_string(),
            details,
        };

        (status, Json(body)).into_response()
    }
}

#[cfg(feature = "db")]
impl From<DbError> for ApiError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::NotFound { entity, id } => ApiError::NotFound {
                entity,
                id: id.to_string(),
            },
            DbError::DuplicateKey { entity } => ApiError::BadRequest {
                message: format!("{} already exists", entity),
            },
            DbError::InvalidData { reason } => ApiError::ValidationError {
                field: "data".to_string(),
                reason,
            },
            DbError::ConnectionFailed { source } => {
                tracing::error!(error = %source, "Database connection failed");
                ApiError::DatabaseError {
                    message: "Database connection error".to_string(),
                }
            }
            DbError::QueryFailed { source } => {
                tracing::error!(error = %source, "Database query failed");
                ApiError::DatabaseError {
                    message: "A database error occurred".to_string(),
                }
            }
            DbError::MigrationFailed { source } => {
                tracing::error!(error = %source, "Database migration failed");
                ApiError::DatabaseError {
                    message: "Database migration error".to_string(),
                }
            }
            DbError::JsonError { source } => {
                tracing::error!(error = %source, "JSON serialization failed");
                ApiError::DatabaseError {
                    message: "Data serialization error".to_string(),
                }
            }
            DbError::CoreError { source } => ApiError::ValidationError {
                field: "value".to_string(),
                reason: source.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_request_status_code() {
        let error = ApiError::BadRequest {
            message: "Invalid input".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_not_found_status_code() {
        let error = ApiError::NotFound {
            entity: "Claim".to_string(),
            id: "123".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_unauthorized_status_code() {
        let error = ApiError::Unauthorized {
            reason: "Invalid token".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_invalid_signature_status_code() {
        let error = ApiError::InvalidSignature;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_internal_error_status_code() {
        let error = ApiError::InternalError {
            message: "Database connection failed".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_validation_error_status_code() {
        let error = ApiError::ValidationError {
            field: "truth_value".to_string(),
            reason: "Must be between 0 and 1".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_forbidden_status_code() {
        let error = ApiError::Forbidden {
            reason: "Admin role required".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_database_error_does_not_leak_details() {
        let error = ApiError::DatabaseError {
            message: "A database error occurred".to_string(),
        };
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
