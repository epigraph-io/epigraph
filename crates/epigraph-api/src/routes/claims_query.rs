//! Advanced claim listing and filtering endpoint
//!
//! Provides a `GET /api/v1/claims` endpoint with support for truth value range
//! filtering, agent filtering, date range filtering, content search, pagination,
//! and sorting.
//!
//! When the `db` feature is enabled, queries PostgreSQL directly.
//! Otherwise, reads from the in-memory `AppState.claim_store`.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;

#[cfg(feature = "db")]
use epigraph_db::ClaimRepository;

#[cfg(feature = "db")]
use std::collections::HashSet;

// ============================================================================
// Constants
// ============================================================================

/// Default page size when no limit is specified
const DEFAULT_LIMIT: u32 = 20;

/// Maximum page size to prevent excessive memory usage in responses
const MAX_LIMIT: u32 = 100;

/// Maximum length for the content_contains search string (DoS prevention)
const MAX_CONTENT_SEARCH_LENGTH: usize = 1024;

/// Valid reasoning methodology values (mirrors DB CHECK constraint on reasoning_traces)
const VALID_METHODOLOGIES: &[&str] = &[
    "deductive",
    "inductive",
    "abductive",
    "analogical",
    "statistical",
];

/// Valid evidence type values (mirrors DB CHECK constraint on evidence + later migrations)
const VALID_EVIDENCE_TYPES: &[&str] = &[
    "document",
    "observation",
    "testimony",
    "computation",
    "reference",
    "figure",
    "conversational",
];

// ============================================================================
// Request / Response DTOs
// ============================================================================

/// Query parameters for the claim listing endpoint
///
/// All parameters are optional. When omitted, sensible defaults are applied.
/// Multiple filters combine with AND semantics.
#[derive(Debug, Deserialize)]
pub struct ClaimQueryParams {
    /// Maximum number of results to return (default: 20, max: 100)
    pub limit: Option<u32>,

    /// Pagination offset (default: 0)
    pub offset: Option<u32>,

    /// Minimum truth value filter (inclusive)
    pub truth_min: Option<f64>,

    /// Maximum truth value filter (inclusive)
    pub truth_max: Option<f64>,

    /// Filter by the agent who created the claim
    pub agent_id: Option<Uuid>,

    /// Exclude claims created by this agent. Composes with `agent_id`
    /// (if both are set, `agent_id` filters in and `exclude_agent_id`
    /// filters out — useful for "all claims except those from the host").
    pub exclude_agent_id: Option<Uuid>,

    /// Filter by current/superseded status
    pub is_current: Option<bool>,

    /// Only return claims created after this timestamp
    pub created_after: Option<DateTime<Utc>>,

    /// Only return claims created before this timestamp
    pub created_before: Option<DateTime<Utc>>,

    /// Sort field: "truth_value" or "created_at" (default: "created_at")
    pub sort_by: Option<String>,

    /// Sort direction: "asc" or "desc" (default: "desc")
    pub sort_order: Option<String>,

    /// Case-insensitive substring search on claim content
    #[serde(alias = "search")]
    pub content_contains: Option<String>,

    /// Filter by reasoning methodology (requires claim to have a reasoning trace).
    /// Values: deductive, inductive, abductive, analogical, statistical
    pub methodology: Option<String>,

    /// Filter by evidence type (requires claim to have evidence of this type).
    /// Values: document, observation, testimony, computation, reference, figure, conversational
    pub evidence_type: Option<String>,
}

/// Summary representation of a claim for list responses
///
/// Excludes cryptographic fields (signatures, hashes, public keys) that are
/// not needed for browsing and would bloat the response payload.
///
/// Includes both `content` and `statement` fields for backward compatibility
/// with UI components that reference either name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSummary {
    /// Unique identifier for this claim
    pub id: Uuid,

    /// The claim statement text
    pub content: String,

    /// Alias for `content` — used by the UI graph/search components
    pub statement: String,

    /// The truth value of this claim [0.0, 1.0]
    pub truth_value: f64,

    /// The agent who made this claim
    pub agent_id: Uuid,

    /// Whether this claim is the current (latest) version
    pub is_current: bool,

    /// When this claim was created
    pub created_at: DateTime<Utc>,

    /// When this claim was last updated
    pub updated_at: DateTime<Utc>,
}

/// Paginated response for claim listings
///
/// Includes the total count of matching claims (before pagination)
/// so clients can implement pagination UI (e.g., "page 2 of 5").
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimListResponse {
    /// The claims matching the query (after pagination)
    pub claims: Vec<ClaimSummary>,

    /// Total number of claims matching the filters (before pagination)
    pub total: usize,

    /// The page size that was applied
    pub limit: u32,

    /// The offset that was applied
    pub offset: u32,
}

// ============================================================================
// Handler
// ============================================================================

/// List and filter claims from PostgreSQL
///
/// `GET /api/v1/claims`
///
/// Queries the claims table with filtering, sorting, and pagination.
#[cfg(feature = "db")]
pub async fn list_claims_query(
    State(state): State<AppState>,
    Query(params): Query<ClaimQueryParams>,
) -> Result<Json<ClaimListResponse>, ApiError> {
    // ---- Validate and normalize pagination ----
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);

    // ---- Validate truth value bounds ----
    if let Some(truth_min) = params.truth_min {
        if !(0.0..=1.0).contains(&truth_min) {
            return Err(ApiError::ValidationError {
                field: "truth_min".to_string(),
                reason: "truth_min must be between 0.0 and 1.0".to_string(),
            });
        }
    }
    if let Some(truth_max) = params.truth_max {
        if !(0.0..=1.0).contains(&truth_max) {
            return Err(ApiError::ValidationError {
                field: "truth_max".to_string(),
                reason: "truth_max must be between 0.0 and 1.0".to_string(),
            });
        }
    }

    // ---- Validate sort_by ----
    let sort_by = params.sort_by.unwrap_or_else(|| "created_at".to_string());
    if sort_by != "truth_value" && sort_by != "created_at" {
        return Err(ApiError::ValidationError {
            field: "sort_by".to_string(),
            reason: format!(
                "Invalid sort_by '{}'. Must be 'truth_value' or 'created_at'",
                sort_by
            ),
        });
    }

    // ---- Validate sort_order ----
    let sort_order = params.sort_order.unwrap_or_else(|| "desc".to_string());
    if sort_order != "asc" && sort_order != "desc" {
        return Err(ApiError::ValidationError {
            field: "sort_order".to_string(),
            reason: format!(
                "Invalid sort_order '{}'. Must be 'asc' or 'desc'",
                sort_order
            ),
        });
    }

    // ---- Validate content_contains length ----
    if let Some(ref search) = params.content_contains {
        if search.len() > MAX_CONTENT_SEARCH_LENGTH {
            return Err(ApiError::ValidationError {
                field: "content_contains".to_string(),
                reason: format!(
                    "Search string too long: {} bytes, maximum is {} bytes",
                    search.len(),
                    MAX_CONTENT_SEARCH_LENGTH
                ),
            });
        }
    }

    // ---- Validate methodology ----
    if let Some(ref m) = params.methodology {
        if !VALID_METHODOLOGIES.contains(&m.as_str()) {
            return Err(ApiError::ValidationError {
                field: "methodology".to_string(),
                reason: format!(
                    "Invalid methodology '{}'. Must be one of: {}",
                    m,
                    VALID_METHODOLOGIES.join(", ")
                ),
            });
        }
    }

    // ---- Validate evidence_type ----
    if let Some(ref et) = params.evidence_type {
        if !VALID_EVIDENCE_TYPES.contains(&et.as_str()) {
            return Err(ApiError::ValidationError {
                field: "evidence_type".to_string(),
                reason: format!(
                    "Invalid evidence_type '{}'. Must be one of: {}",
                    et,
                    VALID_EVIDENCE_TYPES.join(", ")
                ),
            });
        }
    }

    // ---- Pre-fetch methodology / evidence_type claim ID sets ----
    let methodology_ids: Option<HashSet<uuid::Uuid>> = match params.methodology {
        Some(ref m) => {
            let ids = ClaimRepository::claim_ids_by_methodology(&state.db_pool, m)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Methodology filter query failed: {}", e),
                })?;
            Some(ids.into_iter().collect())
        }
        None => None,
    };

    let evidence_type_ids: Option<HashSet<uuid::Uuid>> = match params.evidence_type {
        Some(ref et) => {
            let ids = ClaimRepository::claim_ids_by_evidence_type(&state.db_pool, et)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Evidence type filter query failed: {}", e),
                })?;
            Some(ids.into_iter().collect())
        }
        None => None,
    };

    // ---- Fast path: no post-fetch filters, default sort ----
    // The legacy in-memory pipeline below caps the working set at 10_000 rows
    // and reports `total` as the slice length, which understates the true table
    // count on large databases. When the request needs no truth/agent/date/
    // methodology/evidence-type filtering and uses the default sort, we can let
    // PostgreSQL do COUNT(*) + LIMIT/OFFSET directly.
    let needs_in_memory_filters = params.truth_min.is_some()
        || params.truth_max.is_some()
        || params.agent_id.is_some()
        || params.exclude_agent_id.is_some()
        || params.is_current.is_some()
        || params.created_after.is_some()
        || params.created_before.is_some()
        || methodology_ids.is_some()
        || evidence_type_ids.is_some()
        || sort_by != "created_at"
        || sort_order != "desc";

    if !needs_in_memory_filters {
        let total = ClaimRepository::count(&state.db_pool, params.content_contains.as_deref())
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Database count failed: {}", e),
            })? as usize;

        let rows = ClaimRepository::list(
            &state.db_pool,
            limit as i64,
            offset as i64,
            params.content_contains.as_deref(),
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Database query failed: {}", e),
        })?;

        let paginated: Vec<ClaimSummary> = rows
            .into_iter()
            .map(|c| ClaimSummary {
                id: c.id.as_uuid(),
                statement: c.content.clone(),
                content: c.content.clone(),
                truth_value: c.truth_value.value(),
                agent_id: c.agent_id.as_uuid(),
                is_current: c.is_current,
                created_at: c.created_at,
                updated_at: c.updated_at,
            })
            .collect();

        return Ok(Json(ClaimListResponse {
            claims: paginated,
            total,
            limit,
            offset,
        }));
    }

    // ---- Slow path: filters/sort require fetching a working set into memory ----
    // Capped at 10_000 rows; the reported `total` reflects the filtered slice.
    let all_claims = ClaimRepository::list(
        &state.db_pool,
        10_000,
        0,
        params.content_contains.as_deref(),
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Database query failed: {}", e),
    })?;

    let mut claims: Vec<_> = all_claims.iter().collect();

    // ---- Apply filters ----
    if let Some(truth_min) = params.truth_min {
        claims.retain(|c| c.truth_value.value() >= truth_min);
    }
    if let Some(truth_max) = params.truth_max {
        claims.retain(|c| c.truth_value.value() <= truth_max);
    }
    if let Some(agent_id) = params.agent_id {
        claims.retain(|c| c.agent_id.as_uuid() == agent_id);
    }
    // Filter out a specific agent (composes with agent_id above)
    if let Some(exclude_agent_id) = params.exclude_agent_id {
        claims.retain(|c| c.agent_id.as_uuid() != exclude_agent_id);
    }
    if let Some(is_current) = params.is_current {
        claims.retain(|c| c.is_current == is_current);
    }
    if let Some(created_after) = params.created_after {
        claims.retain(|c| c.created_at >= created_after);
    }
    if let Some(created_before) = params.created_before {
        claims.retain(|c| c.created_at <= created_before);
    }
    if let Some(ref search) = params.content_contains {
        let search_lower = search.to_lowercase();
        claims.retain(|c| c.content.to_lowercase().contains(&search_lower));
    }
    if let Some(ref ids) = methodology_ids {
        claims.retain(|c| ids.contains(&c.id.as_uuid()));
    }
    if let Some(ref ids) = evidence_type_ids {
        claims.retain(|c| ids.contains(&c.id.as_uuid()));
    }

    // ---- Sort ----
    let ascending = sort_order == "asc";
    match sort_by.as_str() {
        "truth_value" => {
            claims.sort_by(|a, b| {
                let cmp = a
                    .truth_value
                    .value()
                    .partial_cmp(&b.truth_value.value())
                    .unwrap_or(std::cmp::Ordering::Equal);
                if ascending {
                    cmp
                } else {
                    cmp.reverse()
                }
            });
        }
        _ => {
            claims.sort_by(|a, b| {
                let cmp = a.created_at.cmp(&b.created_at);
                if ascending {
                    cmp
                } else {
                    cmp.reverse()
                }
            });
        }
    }

    let total = claims.len();

    let paginated: Vec<ClaimSummary> = claims
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(|c| ClaimSummary {
            id: c.id.as_uuid(),
            statement: c.content.clone(),
            content: c.content.clone(),
            truth_value: c.truth_value.value(),
            agent_id: c.agent_id.as_uuid(),
            is_current: c.is_current,
            created_at: c.created_at,
            updated_at: c.updated_at,
        })
        .collect();

    Ok(Json(ClaimListResponse {
        claims: paginated,
        total,
        limit,
        offset,
    }))
}

/// List and filter claims from the in-memory claim store (no database)
///
/// `GET /api/v1/claims`
#[cfg(not(feature = "db"))]
pub async fn list_claims_query(
    State(state): State<AppState>,
    Query(params): Query<ClaimQueryParams>,
) -> Result<Json<ClaimListResponse>, ApiError> {
    // ---- Validate and normalize pagination ----
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);

    // ---- Validate truth value bounds ----
    if let Some(truth_min) = params.truth_min {
        if !(0.0..=1.0).contains(&truth_min) {
            return Err(ApiError::ValidationError {
                field: "truth_min".to_string(),
                reason: "truth_min must be between 0.0 and 1.0".to_string(),
            });
        }
    }
    if let Some(truth_max) = params.truth_max {
        if !(0.0..=1.0).contains(&truth_max) {
            return Err(ApiError::ValidationError {
                field: "truth_max".to_string(),
                reason: "truth_max must be between 0.0 and 1.0".to_string(),
            });
        }
    }

    // ---- Validate sort_by ----
    let sort_by = params.sort_by.unwrap_or_else(|| "created_at".to_string());
    if sort_by != "truth_value" && sort_by != "created_at" {
        return Err(ApiError::ValidationError {
            field: "sort_by".to_string(),
            reason: format!(
                "Invalid sort_by '{}'. Must be 'truth_value' or 'created_at'",
                sort_by
            ),
        });
    }

    // ---- Validate sort_order ----
    let sort_order = params.sort_order.unwrap_or_else(|| "desc".to_string());
    if sort_order != "asc" && sort_order != "desc" {
        return Err(ApiError::ValidationError {
            field: "sort_order".to_string(),
            reason: format!(
                "Invalid sort_order '{}'. Must be 'asc' or 'desc'",
                sort_order
            ),
        });
    }

    // ---- Validate content_contains length ----
    if let Some(ref search) = params.content_contains {
        if search.len() > MAX_CONTENT_SEARCH_LENGTH {
            return Err(ApiError::ValidationError {
                field: "content_contains".to_string(),
                reason: format!(
                    "Search string too long: {} bytes, maximum is {} bytes",
                    search.len(),
                    MAX_CONTENT_SEARCH_LENGTH
                ),
            });
        }
    }

    // ---- Validate methodology ----
    if let Some(ref m) = params.methodology {
        if !VALID_METHODOLOGIES.contains(&m.as_str()) {
            return Err(ApiError::ValidationError {
                field: "methodology".to_string(),
                reason: format!(
                    "Invalid methodology '{}'. Must be one of: {}",
                    m,
                    VALID_METHODOLOGIES.join(", ")
                ),
            });
        }
    }

    // ---- Validate evidence_type ----
    if let Some(ref et) = params.evidence_type {
        if !VALID_EVIDENCE_TYPES.contains(&et.as_str()) {
            return Err(ApiError::ValidationError {
                field: "evidence_type".to_string(),
                reason: format!(
                    "Invalid evidence_type '{}'. Must be one of: {}",
                    et,
                    VALID_EVIDENCE_TYPES.join(", ")
                ),
            });
        }
    }

    // methodology and evidence_type filters require database JOINs with
    // reasoning_traces / evidence tables. In-memory mode has no such data,
    // so if either filter is specified the result set is always empty.
    if params.methodology.is_some() || params.evidence_type.is_some() {
        return Ok(Json(ClaimListResponse {
            claims: vec![],
            total: 0,
            limit,
            offset,
        }));
    }

    // ---- Read claims from the in-memory store ----
    let store = state.claim_store.read().await;
    let mut claims: Vec<_> = store.values().collect();

    // ---- Apply filters ----

    // Filter by truth_min
    if let Some(truth_min) = params.truth_min {
        claims.retain(|c| c.truth_value.value() >= truth_min);
    }

    // Filter by truth_max
    if let Some(truth_max) = params.truth_max {
        claims.retain(|c| c.truth_value.value() <= truth_max);
    }

    // Filter by agent_id
    if let Some(agent_id) = params.agent_id {
        claims.retain(|c| c.agent_id.as_uuid() == agent_id);
    }

    // Filter out a specific agent (composes with agent_id above)
    if let Some(exclude_agent_id) = params.exclude_agent_id {
        claims.retain(|c| c.agent_id.as_uuid() != exclude_agent_id);
    }

    // Filter by is_current
    if let Some(is_current) = params.is_current {
        claims.retain(|c| c.is_current == is_current);
    }

    // Filter by created_after
    if let Some(created_after) = params.created_after {
        claims.retain(|c| c.created_at >= created_after);
    }

    // Filter by created_before
    if let Some(created_before) = params.created_before {
        claims.retain(|c| c.created_at <= created_before);
    }

    // Filter by content_contains (case-insensitive substring search)
    if let Some(ref search) = params.content_contains {
        let search_lower = search.to_lowercase();
        claims.retain(|c| c.content.to_lowercase().contains(&search_lower));
    }

    // ---- Sort ----
    let ascending = sort_order == "asc";
    match sort_by.as_str() {
        "truth_value" => {
            claims.sort_by(|a, b| {
                let cmp = a
                    .truth_value
                    .value()
                    .partial_cmp(&b.truth_value.value())
                    .unwrap_or(std::cmp::Ordering::Equal);
                if ascending {
                    cmp
                } else {
                    cmp.reverse()
                }
            });
        }
        // Default: "created_at"
        _ => {
            claims.sort_by(|a, b| {
                let cmp = a.created_at.cmp(&b.created_at);
                if ascending {
                    cmp
                } else {
                    cmp.reverse()
                }
            });
        }
    }

    // ---- Capture total count before pagination ----
    let total = claims.len();

    // ---- Apply pagination ----
    let offset_usize = offset as usize;
    let limit_usize = limit as usize;
    let paginated: Vec<ClaimSummary> = claims
        .into_iter()
        .skip(offset_usize)
        .take(limit_usize)
        .map(|c| ClaimSummary {
            id: c.id.as_uuid(),
            statement: c.content.clone(),
            content: c.content.clone(),
            truth_value: c.truth_value.value(),
            agent_id: c.agent_id.as_uuid(),
            is_current: c.is_current,
            created_at: c.created_at,
            updated_at: c.updated_at,
        })
        .collect();

    Ok(Json(ClaimListResponse {
        claims: paginated,
        total,
        limit,
        offset,
    }))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, not(feature = "db")))]
mod tests {
    use super::*;
    use crate::state::ApiConfig;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use chrono::{Duration, Utc};
    use epigraph_core::{AgentId, Claim, TruthValue};
    use tower::ServiceExt;

    /// Create a test router with the claims query endpoint
    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/claims", get(list_claims_query))
            .with_state(state)
    }

    /// Insert a test claim into the in-memory claim store.
    ///
    /// Creates a claim with the given content and truth value using a default
    /// agent. Returns the claim for further inspection if needed.
    fn insert_test_claim(state: &AppState, content: &str, truth: f64) -> Claim {
        let agent_id = AgentId::new();
        insert_test_claim_with_agent(state, content, truth, agent_id)
    }

    /// Insert a test claim with a specific agent_id.
    fn insert_test_claim_with_agent(
        state: &AppState,
        content: &str,
        truth: f64,
        agent_id: AgentId,
    ) -> Claim {
        let truth_value = TruthValue::new(truth).expect("valid truth value");
        let claim = Claim::new(content.to_string(), agent_id, [0u8; 32], truth_value);
        let claim_clone = claim.clone();
        // Use try_write to get synchronous access in tests
        // (We know nothing else holds the lock in test setup)
        let mut store = state.claim_store.try_write().expect("lock not held");
        store.insert(claim.id.as_uuid(), claim);
        claim_clone
    }

    /// Insert a test claim with a specific created_at timestamp.
    fn insert_test_claim_with_timestamp(
        state: &AppState,
        content: &str,
        truth: f64,
        created_at: DateTime<Utc>,
    ) -> Claim {
        let agent_id = AgentId::new();
        let truth_value = TruthValue::new(truth).expect("valid truth value");
        let mut claim = Claim::new(content.to_string(), agent_id, [0u8; 32], truth_value);
        claim.created_at = created_at;
        claim.updated_at = created_at;
        let claim_clone = claim.clone();
        let mut store = state.claim_store.try_write().expect("lock not held");
        store.insert(claim.id.as_uuid(), claim);
        claim_clone
    }

    /// Insert a superseded (non-current) claim.
    fn insert_superseded_claim(state: &AppState, content: &str, truth: f64) -> Claim {
        let agent_id = AgentId::new();
        let truth_value = TruthValue::new(truth).expect("valid truth value");
        let mut claim = Claim::new(content.to_string(), agent_id, [0u8; 32], truth_value);
        claim.is_current = false;
        let claim_clone = claim.clone();
        let mut store = state.claim_store.try_write().expect("lock not held");
        store.insert(claim.id.as_uuid(), claim);
        claim_clone
    }

    /// Helper to parse the JSON response body into a ClaimListResponse
    async fn parse_response(response: axum::http::Response<Body>) -> ClaimListResponse {
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    // ---- Test 1: Empty store returns empty list with total=0 ----

    #[tokio::test]
    async fn test_empty_store_returns_empty_list() {
        let state = AppState::new(ApiConfig::default());
        let router = test_router(state);

        let request = Request::builder()
            .uri("/api/v1/claims")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp = parse_response(response).await;
        assert_eq!(resp.claims.len(), 0);
        assert_eq!(resp.total, 0);
        assert_eq!(resp.limit, DEFAULT_LIMIT);
        assert_eq!(resp.offset, 0);
    }

    // ---- Test 2: Default pagination (limit=20, offset=0) ----

    #[tokio::test]
    async fn test_default_pagination() {
        let state = AppState::new(ApiConfig::default());

        // Insert 25 claims
        for i in 0..25 {
            insert_test_claim(&state, &format!("Claim {}", i), 0.5);
        }

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp = parse_response(response).await;
        assert_eq!(resp.claims.len(), 20, "Default limit should be 20");
        assert_eq!(resp.total, 25, "Total should reflect all matching claims");
        assert_eq!(resp.limit, 20);
        assert_eq!(resp.offset, 0);
    }

    // ---- Test 3: Custom limit/offset pagination ----

    #[tokio::test]
    async fn test_custom_pagination() {
        let state = AppState::new(ApiConfig::default());

        // Insert 10 claims
        for i in 0..10 {
            insert_test_claim(&state, &format!("Claim {}", i), 0.5);
        }

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?limit=3&offset=2")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp = parse_response(response).await;
        assert_eq!(resp.claims.len(), 3, "Should return exactly 3 claims");
        assert_eq!(
            resp.total, 10,
            "Total should be 10 regardless of pagination"
        );
        assert_eq!(resp.limit, 3);
        assert_eq!(resp.offset, 2);
    }

    // ---- Test 4: Filter by truth_min ----

    #[tokio::test]
    async fn test_filter_truth_min() {
        let state = AppState::new(ApiConfig::default());

        insert_test_claim(&state, "Low truth", 0.2);
        insert_test_claim(&state, "Medium truth", 0.5);
        insert_test_claim(&state, "High truth", 0.9);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?truth_min=0.5")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(resp.total, 2, "Only claims with truth >= 0.5 should match");
        for claim in &resp.claims {
            assert!(
                claim.truth_value >= 0.5,
                "All returned claims should have truth >= 0.5, got {}",
                claim.truth_value
            );
        }
    }

    // ---- Test 5: Filter by truth_max ----

    #[tokio::test]
    async fn test_filter_truth_max() {
        let state = AppState::new(ApiConfig::default());

        insert_test_claim(&state, "Low truth", 0.2);
        insert_test_claim(&state, "Medium truth", 0.5);
        insert_test_claim(&state, "High truth", 0.9);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?truth_max=0.5")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(resp.total, 2, "Only claims with truth <= 0.5 should match");
        for claim in &resp.claims {
            assert!(
                claim.truth_value <= 0.5,
                "All returned claims should have truth <= 0.5, got {}",
                claim.truth_value
            );
        }
    }

    // ---- Test 6: Filter by truth_min AND truth_max (range) ----

    #[tokio::test]
    async fn test_filter_truth_range() {
        let state = AppState::new(ApiConfig::default());

        insert_test_claim(&state, "Very low", 0.1);
        insert_test_claim(&state, "Low", 0.3);
        insert_test_claim(&state, "Medium", 0.5);
        insert_test_claim(&state, "High", 0.7);
        insert_test_claim(&state, "Very high", 0.95);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?truth_min=0.3&truth_max=0.7")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(
            resp.total, 3,
            "Only claims with 0.3 <= truth <= 0.7 should match"
        );
        for claim in &resp.claims {
            assert!(
                claim.truth_value >= 0.3 && claim.truth_value <= 0.7,
                "Claim truth {} outside range [0.3, 0.7]",
                claim.truth_value
            );
        }
    }

    // ---- Test 7: Filter by is_current=true ----

    #[tokio::test]
    async fn test_filter_is_current() {
        let state = AppState::new(ApiConfig::default());

        insert_test_claim(&state, "Current claim", 0.5);
        insert_superseded_claim(&state, "Superseded claim", 0.5);
        insert_test_claim(&state, "Another current", 0.7);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?is_current=true")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(resp.total, 2, "Only current claims should be returned");
        for claim in &resp.claims {
            assert!(claim.is_current, "All returned claims should be current");
        }
    }

    // ---- Test 8: Filter by agent_id ----

    #[tokio::test]
    async fn test_filter_agent_id() {
        let state = AppState::new(ApiConfig::default());

        let target_agent = AgentId::new();
        insert_test_claim_with_agent(&state, "Agent A claim 1", 0.5, target_agent);
        insert_test_claim_with_agent(&state, "Agent A claim 2", 0.7, target_agent);
        insert_test_claim(&state, "Other agent claim", 0.6);

        let router = test_router(state);
        let request = Request::builder()
            .uri(format!(
                "/api/v1/claims?agent_id={}",
                target_agent.as_uuid()
            ))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(
            resp.total, 2,
            "Only claims from the target agent should match"
        );
        for claim in &resp.claims {
            assert_eq!(
                claim.agent_id,
                target_agent.as_uuid(),
                "All returned claims should belong to the target agent"
            );
        }
    }

    // ---- Test 8b: Filter out claims by agent_id (exclude_agent_id) ----

    #[tokio::test]
    async fn list_claims_excludes_agent_id() {
        let state = AppState::new(ApiConfig::default());
        let agent_a = AgentId::new();
        let agent_b = AgentId::new();
        insert_test_claim_with_agent(&state, "from agent A", 0.5, agent_a);
        insert_test_claim_with_agent(&state, "from agent B", 0.5, agent_b);

        let router = test_router(state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri(&format!(
                        "/api/v1/claims?exclude_agent_id={}",
                        agent_a.as_uuid()
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp = parse_response(response).await;
        assert_eq!(resp.claims.len(), 1);
        assert_eq!(resp.claims[0].content, "from agent B");
    }

    // ---- Test 9: Sort by truth_value ascending ----

    #[tokio::test]
    async fn test_sort_by_truth_value_ascending() {
        let state = AppState::new(ApiConfig::default());

        insert_test_claim(&state, "High", 0.9);
        insert_test_claim(&state, "Low", 0.1);
        insert_test_claim(&state, "Medium", 0.5);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?sort_by=truth_value&sort_order=asc")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(resp.claims.len(), 3);
        assert!(
            resp.claims[0].truth_value <= resp.claims[1].truth_value
                && resp.claims[1].truth_value <= resp.claims[2].truth_value,
            "Claims should be sorted by truth_value ascending: [{}, {}, {}]",
            resp.claims[0].truth_value,
            resp.claims[1].truth_value,
            resp.claims[2].truth_value,
        );
    }

    // ---- Test 10: Sort by created_at descending (default) ----

    #[tokio::test]
    async fn test_sort_by_created_at_descending_default() {
        let state = AppState::new(ApiConfig::default());

        let now = Utc::now();
        let old = now - Duration::hours(2);
        let older = now - Duration::hours(4);

        insert_test_claim_with_timestamp(&state, "Oldest", 0.5, older);
        insert_test_claim_with_timestamp(&state, "Middle", 0.5, old);
        insert_test_claim_with_timestamp(&state, "Newest", 0.5, now);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(resp.claims.len(), 3);
        // Default sort is created_at desc (newest first)
        assert!(
            resp.claims[0].created_at >= resp.claims[1].created_at
                && resp.claims[1].created_at >= resp.claims[2].created_at,
            "Claims should be sorted by created_at descending (newest first)"
        );
        assert_eq!(resp.claims[0].content, "Newest");
        assert_eq!(resp.claims[2].content, "Oldest");
    }

    // ---- Test 11: Content substring search (case-insensitive) ----

    #[tokio::test]
    async fn test_content_contains_case_insensitive() {
        let state = AppState::new(ApiConfig::default());

        insert_test_claim(&state, "The Earth is ROUND", 0.9);
        insert_test_claim(&state, "Water is wet", 0.8);
        insert_test_claim(&state, "The earth rotates around the sun", 0.95);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?content_contains=earth")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(
            resp.total, 2,
            "Case-insensitive search for 'earth' should match 2 claims"
        );
        for claim in &resp.claims {
            assert!(
                claim.content.to_lowercase().contains("earth"),
                "Claim '{}' should contain 'earth'",
                claim.content
            );
        }
    }

    // ---- Test 12: Combined filters (truth range + is_current) ----

    #[tokio::test]
    async fn test_combined_filters() {
        let state = AppState::new(ApiConfig::default());

        // Current claims with varying truth
        insert_test_claim(&state, "Current low", 0.2);
        insert_test_claim(&state, "Current high", 0.8);
        insert_test_claim(&state, "Current very high", 0.95);

        // Superseded claims
        insert_superseded_claim(&state, "Superseded high", 0.85);
        insert_superseded_claim(&state, "Superseded low", 0.1);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?truth_min=0.7&is_current=true")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(
            resp.total, 2,
            "Only current claims with truth >= 0.7 should match"
        );
        for claim in &resp.claims {
            assert!(claim.is_current, "Should be current");
            assert!(
                claim.truth_value >= 0.7,
                "Truth should be >= 0.7, got {}",
                claim.truth_value
            );
        }
    }

    // ---- Additional validation tests ----

    #[tokio::test]
    async fn test_invalid_truth_min_returns_400() {
        let state = AppState::new(ApiConfig::default());
        let router = test_router(state);

        let request = Request::builder()
            .uri("/api/v1/claims?truth_min=1.5")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invalid_truth_max_returns_400() {
        let state = AppState::new(ApiConfig::default());
        let router = test_router(state);

        let request = Request::builder()
            .uri("/api/v1/claims?truth_max=-0.1")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invalid_sort_by_returns_400() {
        let state = AppState::new(ApiConfig::default());
        let router = test_router(state);

        let request = Request::builder()
            .uri("/api/v1/claims?sort_by=invalid_field")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invalid_sort_order_returns_400() {
        let state = AppState::new(ApiConfig::default());
        let router = test_router(state);

        let request = Request::builder()
            .uri("/api/v1/claims?sort_order=sideways")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_limit_capped_at_max() {
        let state = AppState::new(ApiConfig::default());

        for i in 0..5 {
            insert_test_claim(&state, &format!("Claim {}", i), 0.5);
        }

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?limit=200")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(
            resp.limit, MAX_LIMIT,
            "Limit should be capped at MAX_LIMIT ({})",
            MAX_LIMIT
        );
    }

    #[tokio::test]
    async fn test_offset_beyond_total_returns_empty() {
        let state = AppState::new(ApiConfig::default());

        insert_test_claim(&state, "Only claim", 0.5);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?offset=100")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        assert_eq!(
            resp.claims.len(),
            0,
            "Offset beyond total should return no claims"
        );
        assert_eq!(resp.total, 1, "Total should still reflect matching claims");
    }

    #[tokio::test]
    async fn test_date_range_filter() {
        let state = AppState::new(ApiConfig::default());

        let now = Utc::now();
        let one_hour_ago = now - Duration::hours(1);
        let two_hours_ago = now - Duration::hours(2);
        let three_hours_ago = now - Duration::hours(3);

        insert_test_claim_with_timestamp(&state, "Old", 0.5, three_hours_ago);
        insert_test_claim_with_timestamp(&state, "Middle", 0.5, two_hours_ago);
        insert_test_claim_with_timestamp(&state, "Recent", 0.5, one_hour_ago);
        insert_test_claim_with_timestamp(&state, "Now", 0.5, now);

        let router = test_router(state);
        // Filter: created_after two_hours_ago (should get Middle, Recent, Now)
        // Use RFC 3339 format with manual percent-encoding of '+' and ':'
        let after_str = two_hours_ago
            .to_rfc3339()
            .replace('+', "%2B")
            .replace(':', "%3A");
        let request = Request::builder()
            .uri(format!("/api/v1/claims?created_after={}", after_str))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let resp = parse_response(response).await;

        // two_hours_ago is inclusive (>=), so "Middle" at exactly two_hours_ago should match
        assert_eq!(
            resp.total, 3,
            "Claims at or after two_hours_ago should match (Middle, Recent, Now)"
        );
    }

    // ---- Test: Invalid methodology returns 400 ----

    #[tokio::test]
    async fn test_invalid_methodology_returns_400() {
        let state = AppState::new(ApiConfig::default());
        let router = test_router(state);

        let request = Request::builder()
            .uri("/api/v1/claims?methodology=phrenology")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ---- Test: Invalid evidence_type returns 400 ----

    #[tokio::test]
    async fn test_invalid_evidence_type_returns_400() {
        let state = AppState::new(ApiConfig::default());
        let router = test_router(state);

        let request = Request::builder()
            .uri("/api/v1/claims?evidence_type=vibes")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ---- Test: Valid methodology accepted (returns empty in non-db mode) ----

    #[tokio::test]
    async fn test_valid_methodology_accepted() {
        let state = AppState::new(ApiConfig::default());

        insert_test_claim(&state, "Some claim", 0.5);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?methodology=deductive")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp = parse_response(response).await;
        // In non-db mode, methodology filter always returns empty
        assert_eq!(resp.total, 0);
    }

    // ---- Test: Valid evidence_type accepted (returns empty in non-db mode) ----

    #[tokio::test]
    async fn test_valid_evidence_type_accepted() {
        let state = AppState::new(ApiConfig::default());

        insert_test_claim(&state, "Some claim", 0.5);

        let router = test_router(state);
        let request = Request::builder()
            .uri("/api/v1/claims?evidence_type=testimony")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp = parse_response(response).await;
        // In non-db mode, evidence_type filter always returns empty
        assert_eq!(resp.total, 0);
    }

    // ---- Test: Compound filter methodology + evidence_type + agent_id ----

    #[tokio::test]
    async fn test_compound_filter_methodology_evidence_type_agent() {
        let state = AppState::new(ApiConfig::default());
        let agent = AgentId::new();

        insert_test_claim_with_agent(&state, "Claim by agent", 0.8, agent);

        let router = test_router(state);
        let request = Request::builder()
            .uri(format!(
                "/api/v1/claims?methodology=statistical&evidence_type=document&agent_id={}",
                agent.as_uuid()
            ))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let resp = parse_response(response).await;
        // In non-db mode, methodology/evidence_type filter returns empty
        assert_eq!(resp.total, 0);
    }

    // ---- Test: All valid methodology values accepted ----

    #[tokio::test]
    async fn test_all_valid_methodology_values() {
        for methodology in &[
            "deductive",
            "inductive",
            "abductive",
            "analogical",
            "statistical",
        ] {
            let state = AppState::new(ApiConfig::default());
            let router = test_router(state);

            let request = Request::builder()
                .uri(format!("/api/v1/claims?methodology={}", methodology))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Methodology '{}' should be accepted",
                methodology
            );
        }
    }

    // ---- Test: All valid evidence_type values accepted ----

    #[tokio::test]
    async fn test_all_valid_evidence_type_values() {
        for evidence_type in &[
            "document",
            "observation",
            "testimony",
            "computation",
            "reference",
            "figure",
            "conversational",
        ] {
            let state = AppState::new(ApiConfig::default());
            let router = test_router(state);

            let request = Request::builder()
                .uri(format!("/api/v1/claims?evidence_type={}", evidence_type))
                .body(Body::empty())
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Evidence type '{}' should be accepted",
                evidence_type
            );
        }
    }
}
