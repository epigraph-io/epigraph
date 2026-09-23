//! Security audit log query endpoint
//!
//! Provides HTTP access to the persisted `security_events` table for admin
//! forensic analysis.  All access requires `audit:read` scope via OAuth2 bearer.
//! A caller reads its own principal's events; a live instance administrator
//! reads every principal's. See [`query_security_events`].

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
///
/// # Whose events: the caller's own, or everyone's for an instance admin
///
/// `audit:read` is a member of `canonical_scopes::READ_SCOPES`, which every
/// role carries. It is not an admin scope, so it cannot decide whose events a
/// caller reads. That is decided the way migration 083's `security_events_read`
/// decides it: a caller reads the rows attributed to its own principal, and a
/// live instance administrator reads every row, including the unattributed
/// (`agent_id IS NULL`) rows that pre-authentication paths write.
///
/// The rule is applied TWICE, by two filters that do not depend on each other:
///
/// * the read runs on a connection stamped with the caller's viewer, from
///   [`AppState::read_as`], so the policy admits the caller's rows once plan
///   §9.2 step 11d makes `epigraph_app` the connecting role. On an unstamped
///   `state.db_pool` there, `epigraph_principal_id()` would be NULL and every
///   caller, instance admins included, would get an empty 200;
/// * `SecurityEventRepository::query_for_principal_conn` states the same rule
///   in its own `WHERE`, bound to the caller's principal. RLS does not filter
///   a superuser or `BYPASSRLS` session, and on one the in-query conjunct is
///   what narrows. The repo doc says why the policy's bypass arms are left out.
///
/// `?agent_id=` naming ANOTHER principal is refused with 403 unless the caller
/// is an instance admin. Silently returning nothing would read to operator
/// tooling as "that agent has no events". The 403 says only that the CALLER
/// lacks the authority. It is the same whether or not the named agent exists or
/// has events, so it tells the caller nothing about the target.
///
/// # Refusals
///
/// * `401` from `ViewerExtractor` when the token names no `agents.id`: there
///   is no principal to scope the read to.
/// * `403` without `audit:read`, or for a foreign `?agent_id=` from a
///   non-admin.
/// * `500` when this `AppState` was not built from a `ScopedPool`. `read_as`
///   refuses rather than fall back to the raw pool, and so does this handler.
///
/// This discharges `F-PR18a-B1` (`docs/tenancy/progress.json`,
/// `closed_findings`). Its detail had been redacted and never recorded, so it
/// was re-derived from this code before it was closed.
#[cfg(feature = "db")]
pub async fn query_security_events(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Query(params): Query<SecurityEventQuery>,
) -> Result<Json<Vec<SecurityEventResponse>>, ApiError> {
    // Admin scope gate — any authenticated caller must carry audit:read.
    //
    // An ABSENT auth context is a refusal, not a pass. This route is registered
    // on the `protected` chain, which layers a mandatory `bearer_auth_middleware`
    // (PR-03), and `locked_decisions.rs` asserts no route moves between the
    // `public` and `protected` chains — so the extension is always present today
    // and this branch is unreachable. It is written as a refusal anyway because
    // the previous `if let Some(..)` with no `else` made the handler's
    // correctness depend on which router chain it happened to be registered on,
    // and it is the caller-facing end of a read policy 083 widens.
    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["audit:read"])?;

    use epigraph_db::repos::instance_admin::InstanceAdminRepository;
    use epigraph_db::repos::security_event::{SecurityEventFilter, SecurityEventRepository};

    // `ViewerExtractor` only ever yields a `Scoped` viewer, and `read_as`
    // refuses a bypass one anyway. Refuse here too rather than invent a
    // principal.
    let Some(principal) = viewer.principal() else {
        return Err(ApiError::Forbidden {
            reason: "the security-event log is read as a principal".to_string(),
        });
    };

    // Same error shape as `routes/voids.rs`: `read_as`'s refusal reason is
    // internal prose, and `ApiError::InternalError` serialises its message into
    // the body, so the reason is logged in full and the caller gets an opaque
    // message.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "query_security_events",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // A filter on another principal needs the authority to read that
    // principal's rows. It is asked on the stamped connection and about the
    // caller's own principal, the only subject 083's function answers for there.
    if params.agent_id.is_some_and(|a| a != principal)
        && !InstanceAdminRepository::is_active_conn(&mut read, principal).await?
    {
        return Err(ApiError::Forbidden {
            reason: "reading another principal's security events requires instance-admin \
                     authority"
                .to_string(),
        });
    }

    let filter = SecurityEventFilter {
        agent_id: params.agent_id,
        event_type: params.event_type,
        from: params.since,
        until: params.until,
        failures_only: params.failures_only.unwrap_or(false),
        limit: Some(params.limit.unwrap_or(100).clamp(1, 10_000)),
    };

    let rows =
        SecurityEventRepository::query_for_principal_conn(&mut read, principal, filter).await?;
    read.commit().await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "query_security_events",
            "could not finish the viewer-stamped read"
        );
        ApiError::InternalError {
            message: "Failed to finish a scoped read".to_string(),
        }
    })?;

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
///
/// Takes the same `ViewerExtractor` as the `db` arm, so both builds refuse an
/// unauthenticated or principal-less caller with the same 401 before anything
/// else.
#[cfg(not(feature = "db"))]
pub async fn query_security_events(
    crate::middleware::bearer::ViewerExtractor(_viewer): crate::middleware::bearer::ViewerExtractor,
    State(_state): State<AppState>,
    Query(_params): Query<SecurityEventQuery>,
) -> Result<Json<Vec<SecurityEventResponse>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Security event query requires database".to_string(),
    })
}
