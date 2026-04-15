//! Security audit log query endpoint
//!
//! Provides HTTP access to the persisted `security_events` table for admin
//! forensic analysis.  All access requires `audit:read` scope via OAuth2 bearer.

use axum::{
    extract::{Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{errors::ApiError, state::AppState};

// =============================================================================
// REQUEST TYPES
// =============================================================================

/// Query parameters for `GET /api/v1/audit/security`
#[derive(Deserialize, Debug)]
pub struct SecurityEventQuery {
    /// Filter by agent UUID
    pub agent_id: Option<Uuid>,
    /// Filter by event_type discriminator (e.g. "auth_attempt")
    pub event_type: Option<String>,
    /// Return events created on or after this timestamp (RFC 3339)
    pub since: Option<DateTime<Utc>>,
    /// Return events created on or before this timestamp (RFC 3339)
    pub until: Option<DateTime<Utc>>,
    /// When true, only return rows where success = false
    pub failures_only: Option<bool>,
    /// Maximum number of rows to return (default 100, max 10 000)
    pub limit: Option<i64>,
}

// =============================================================================
// RESPONSE TYPES
// =============================================================================

/// HTTP response for a single security event row
#[derive(Serialize, Debug)]
pub struct SecurityEventResponse {
    pub id: Uuid,
    pub event_type: String,
    pub agent_id: Option<Uuid>,
    pub success: Option<bool>,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub correlation_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

// =============================================================================
// HANDLER (db feature)
// =============================================================================

/// Query security events
///
/// GET /api/v1/audit/security
///
/// Returns a list of security events filtered by the provided query parameters,
/// ordered by `created_at DESC`.  Requires `audit:read` OAuth2 scope.
#[cfg(feature = "db")]
pub async fn query_security_events(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Query(params): Query<SecurityEventQuery>,
) -> Result<Json<Vec<SecurityEventResponse>>, ApiError> {
    // Admin scope gate — any authenticated caller must carry audit:read
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["audit:read"])?;
    }

    use epigraph_db::repos::security_event::{SecurityEventFilter, SecurityEventRepository};

    let filter = SecurityEventFilter {
        agent_id: params.agent_id,
        event_type: params.event_type,
        from: params.since,
        until: params.until,
        failures_only: params.failures_only.unwrap_or(false),
        limit: Some(params.limit.unwrap_or(100).clamp(1, 10_000)),
    };

    let rows = SecurityEventRepository::query(&state.db_pool, filter).await?;

    let response: Vec<SecurityEventResponse> = rows
        .into_iter()
        .map(|r| SecurityEventResponse {
            id: r.id,
            event_type: r.event_type,
            agent_id: r.agent_id,
            success: r.success,
            details: r.details,
            ip_address: r.ip_address,
            correlation_id: r.correlation_id,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(response))
}

/// Placeholder when database feature is disabled
///
/// GET /api/v1/audit/security
#[cfg(not(feature = "db"))]
pub async fn query_security_events(
    State(_state): State<AppState>,
    Query(_params): Query<SecurityEventQuery>,
) -> Result<Json<Vec<SecurityEventResponse>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Security event query requires database".to_string(),
    })
}
