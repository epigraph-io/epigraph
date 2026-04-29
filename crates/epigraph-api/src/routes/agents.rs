use axum::{
    extract::{Path, Query, State},
    Json,
};
use epigraph_core::{Agent, AgentId};
#[cfg(feature = "db")]
use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, OAuthClientRepository};
#[cfg(feature = "db")]
use epigraph_engine::reputation::{ClaimOutcome, ReputationCalculator};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routes::claims::{ClaimResponse, PaginatedResponse};
use crate::services::ValidationService;
use crate::{errors::ApiError, state::AppState};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Truth value below which a claim is considered refuted by strong counter-evidence.
/// Used when converting claims to `ClaimOutcome` for reputation calculation.
const REFUTATION_THRESHOLD: f64 = 0.2;

// =============================================================================
// PUBLIC KEY CONSTANTS
// =============================================================================

/// Length of a hex-encoded Ed25519 public key (32 bytes = 64 hex characters)
#[cfg(test)]
const ED25519_PUBLIC_KEY_HEX_LENGTH: usize = 64;

/// Length of an Ed25519 public key in bytes
const ED25519_PUBLIC_KEY_BYTE_LENGTH: usize = 32;

/// Request to create a new agent
#[derive(Deserialize)]
pub struct CreateAgentRequest {
    /// Ed25519 public key (hex-encoded, 64 chars for 32 bytes)
    pub public_key: String,
    /// Optional display name
    pub display_name: Option<String>,
    /// PROV-O labels (e.g., "person", "organization", "software_agent")
    #[serde(default)]
    pub labels: Option<Vec<String>>,
    /// ORCID identifier for person-type agents
    #[serde(default)]
    pub orcid: Option<String>,
    /// ROR identifier for organization-type agents
    #[serde(default)]
    pub ror_id: Option<String>,
    /// Arbitrary JSONB properties (methodology, affiliation metadata, etc.)
    #[serde(default)]
    pub properties: Option<serde_json::Value>,
}

/// Agent response structure
#[derive(Serialize, Debug)]
pub struct AgentResponse {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub public_key: String, // hex-encoded Ed25519 public key
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub labels: Vec<String>,
    pub orcid: Option<String>,
    pub ror_id: Option<String>,
}

/// Agent reputation response
#[derive(Serialize, Debug)]
pub struct AgentReputationResponse {
    pub agent_id: Uuid,
    pub display_name: Option<String>,
    pub reputation_score: f64,
    pub total_claims: usize,
    pub verified_claims: usize,
    pub claim_age_days_avg: f64,
}

impl From<Agent> for AgentResponse {
    fn from(agent: Agent) -> Self {
        Self {
            id: agent.id.into(),
            display_name: agent.display_name,
            public_key: hex::encode(agent.public_key),
            created_at: agent.created_at,
            labels: agent.labels,
            orcid: agent.orcid,
            ror_id: agent.ror_id,
        }
    }
}

/// Query parameters for agent listing with optional label filter
#[derive(Deserialize, Debug)]
pub struct AgentListParams {
    #[serde(default = "default_agent_list_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Filter agents by PROV-O label (person, organization, software_agent, instrument)
    pub label: Option<String>,
}

fn default_agent_list_limit() -> i64 {
    20
}

/// Parse and validate a hex-encoded Ed25519 public key.
///
/// Delegates to `ValidationService::parse_public_key` for centralized validation.
///
/// # Arguments
/// * `hex_key` - The hex-encoded public key string (must be 64 characters)
///
/// # Returns
/// * `Ok([u8; 32])` - The decoded 32-byte public key
/// * `Err(ApiError::ValidationError)` - If the key is invalid
///
/// # Example
/// ```rust,ignore
/// let key = parse_public_key("0".repeat(64).as_str())?;
/// assert_eq!(key.len(), 32);
/// ```
fn parse_public_key(hex_key: &str) -> Result<[u8; ED25519_PUBLIC_KEY_BYTE_LENGTH], ApiError> {
    ValidationService::parse_public_key(hex_key)
}

/// Standard harvester-level scopes for auto-provisioned agent OAuth clients.
/// These allow the agent to read/write claims, edges, and evidence.
#[cfg(feature = "db")]
const AGENT_DEFAULT_SCOPES: &[&str] = &[
    "claims:read",
    "claims:write",
    "edges:read",
    "edges:write",
    "evidence:read",
    "evidence:write",
    "agents:read",
];

/// Create a new agent
///
/// POST /agents
///
/// Creates a new agent with the given public key and optional display name.
/// When called by an authenticated user (OAuth2 bearer token), also auto-provisions
/// an `oauth_clients` row so the new agent can authenticate via client_credentials.
#[cfg(feature = "db")]
pub async fn create_agent(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<CreateAgentRequest>,
) -> Result<Json<AgentResponse>, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = &auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["agents:write"])?;
    }

    let public_key = parse_public_key(&request.public_key)?;

    let mut agent = Agent::new(public_key, request.display_name);
    if let Some(labels) = request.labels {
        agent.labels = labels;
    }
    if let Some(orcid) = request.orcid {
        agent.orcid = Some(orcid);
    }
    if let Some(ror_id) = request.ror_id {
        agent.ror_id = Some(ror_id);
    }
    // Note: properties stored via AgentRepository if column exists; currently
    // the Agent struct doesn't carry a properties field, so we rely on the
    // update path or direct DB write for properties. The field is accepted
    // here for forward-compatibility but not persisted until core model is extended.
    let _ = request.properties; // acknowledged but unused until core model supports it
    let created_agent = AgentRepository::create(&state.db_pool, &agent).await?;
    let new_agent_id = Uuid::from(created_agent.id);

    // Auto-provision an OAuth client for the new agent when caller is authenticated
    if let Some(axum::Extension(auth)) = &auth_ctx {
        let client_id_str = hex::encode(public_key);
        let client_name = created_agent.display_name.as_deref().unwrap_or("Agent");
        let scopes: Vec<String> = AGENT_DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect();

        if let Err(e) = OAuthClientRepository::create(
            &state.db_pool,
            &client_id_str,
            None, // no client_secret_hash for agent clients
            client_name,
            "agent",
            &scopes, // allowed_scopes
            &scopes, // granted_scopes (auto-approved for agents)
            "active",
            Some(new_agent_id),   // agent_id
            Some(auth.client_id), // owner_id = the creating user/service
            None,                 // legal_entity_name
            None,                 // legal_contact_email
        )
        .await
        {
            // Log but don't fail agent creation — the agent row already exists
            tracing::warn!(
                agent_id = %new_agent_id,
                error = %e,
                "Failed to auto-provision OAuth client for new agent"
            );
        }
    }

    Ok(Json(created_agent.into()))
}

/// Create a new agent (placeholder - no database)
///
/// POST /agents
///
/// Returns a placeholder response when DB is not enabled.
#[cfg(not(feature = "db"))]
pub async fn create_agent(
    State(_state): State<AppState>,
    Json(request): Json<CreateAgentRequest>,
) -> Result<Json<AgentResponse>, ApiError> {
    let public_key = parse_public_key(&request.public_key)?;

    let response = AgentResponse {
        id: Uuid::new_v4(),
        display_name: request.display_name,
        public_key: hex::encode(public_key),
        created_at: chrono::Utc::now(),
        labels: vec![],
        orcid: None,
        ror_id: None,
    };

    Ok(Json(response))
}

/// Get an agent by ID
///
/// GET /agents/:id
///
/// Returns agent information including their public key.
#[cfg(feature = "db")]
pub async fn get_agent(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentResponse>, ApiError> {
    let agent_id = AgentId::from_uuid(id);

    let agent = AgentRepository::get_by_id(&state.db_pool, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    Ok(Json(agent.into()))
}

/// Get an agent by ID (placeholder - no database)
///
/// GET /agents/:id
///
/// Returns placeholder data until DB integration is complete.
#[cfg(not(feature = "db"))]
pub async fn get_agent(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentResponse>, ApiError> {
    let response = AgentResponse {
        id,
        display_name: Some("Placeholder Agent".to_string()),
        public_key: "0".repeat(64), // Placeholder hex-encoded key
        created_at: chrono::Utc::now(),
        labels: vec![],
        orcid: None,
        ror_id: None,
    };

    Ok(Json(response))
}

/// List agents with pagination and optional label filter
///
/// GET /agents?limit=20&offset=0&label=person
///
/// Returns a paginated list of agents ordered by creation date (newest first).
/// When `label` is provided, only agents with that PROV-O label are returned.
#[cfg(feature = "db")]
pub async fn list_agents(
    State(state): State<AppState>,
    Query(params): Query<AgentListParams>,
) -> Result<Json<PaginatedResponse<AgentResponse>>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let (agents, total) = if let Some(ref label) = params.label {
        let agents = AgentRepository::list_by_label(&state.db_pool, label, limit, offset).await?;
        let total = AgentRepository::count_by_label(&state.db_pool, label).await?;
        (agents, total)
    } else {
        let agents = AgentRepository::list(&state.db_pool, limit, offset).await?;
        let total = AgentRepository::count(&state.db_pool).await?;
        (agents, total)
    };

    let items: Vec<AgentResponse> = agents.into_iter().map(Into::into).collect();

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// List agents with pagination (placeholder - no database)
///
/// GET /agents?limit=20&offset=0
///
/// Returns an empty list when DB is not enabled.
#[cfg(not(feature = "db"))]
pub async fn list_agents(
    State(_state): State<AppState>,
    Query(params): Query<AgentListParams>,
) -> Result<Json<PaginatedResponse<AgentResponse>>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    Ok(Json(PaginatedResponse {
        items: vec![],
        total: 0,
        limit,
        offset,
    }))
}

/// Get an agent's reputation score
///
/// GET /agents/:id/reputation
///
/// Computes a reputation score from the agent's claim history.
/// Reputation is derived FROM claim outcomes, never used AS INPUT to truth calculation.
/// This prevents the "Appeal to Authority" fallacy.
#[cfg(feature = "db")]
pub async fn get_agent_reputation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentReputationResponse>, ApiError> {
    let agent_id = AgentId::from_uuid(id);

    // 1. Look up the agent (404 if not found)
    let agent = AgentRepository::get_by_id(&state.db_pool, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    // 2. Fetch all claims by this agent
    let claims = ClaimRepository::get_by_agent(&state.db_pool, agent_id).await?;

    // 3. Convert claims into ClaimOutcome structs
    let now = chrono::Utc::now();
    let outcomes: Vec<ClaimOutcome> = claims
        .iter()
        .map(|claim| {
            let age = now.signed_duration_since(claim.created_at);
            #[allow(clippy::cast_precision_loss)]
            let age_days = (age.num_hours() as f64 / 24.0).max(0.0);
            ClaimOutcome {
                truth_value: claim.truth_value.value(),
                age_days,
                was_refuted: claim.truth_value.value() < REFUTATION_THRESHOLD,
            }
        })
        .collect();

    // 4. Calculate reputation score
    let calculator = ReputationCalculator::new();
    let reputation_score =
        calculator
            .calculate(&outcomes)
            .map_err(|e| ApiError::InternalError {
                message: format!("Reputation calculation failed: {}", e),
            })?;

    // 5. Compute response statistics
    let total_claims = claims.len();
    let verified_claims = claims
        .iter()
        .filter(|c| c.truth_value.is_verified_true())
        .count();
    let claim_age_days_avg = if outcomes.is_empty() {
        0.0
    } else {
        outcomes.iter().map(|o| o.age_days).sum::<f64>() / outcomes.len() as f64
    };

    Ok(Json(AgentReputationResponse {
        agent_id: id,
        display_name: agent.display_name,
        reputation_score,
        total_claims,
        verified_claims,
        claim_age_days_avg,
    }))
}

/// Get an agent's reputation score (placeholder - no database)
///
/// GET /agents/:id/reputation
///
/// Returns a placeholder response with initial reputation when DB is not enabled.
#[cfg(not(feature = "db"))]
pub async fn get_agent_reputation(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentReputationResponse>, ApiError> {
    let calculator = ReputationCalculator::new();
    let reputation_score = calculator
        .calculate(&[])
        .map_err(|e| ApiError::InternalError {
            message: format!("Reputation calculation failed: {}", e),
        })?;

    Ok(Json(AgentReputationResponse {
        agent_id: id,
        display_name: Some("Placeholder Agent".to_string()),
        reputation_score,
        total_claims: 0,
        verified_claims: 0,
        claim_age_days_avg: 0.0,
    }))
}

// =============================================================================
// AGENT CLAIMS (via ATTRIBUTED_TO edges)
// =============================================================================

/// Query parameters for the agent claims endpoint
#[derive(Deserialize, Debug)]
pub struct AgentClaimsParams {
    /// Maximum number of items to return (default: 20, max: 100)
    #[serde(default = "default_agent_claims_limit")]
    pub limit: i64,
    /// Number of items to skip (default: 0)
    #[serde(default)]
    pub offset: i64,
    /// Minimum truth value filter (default: 0.0)
    #[serde(default)]
    pub min_truth: f64,
}

fn default_agent_claims_limit() -> i64 {
    20
}

/// Response for agent claims endpoint, includes attribution metadata
#[derive(Serialize, Debug)]
pub struct AttributedClaimResponse {
    #[serde(flatten)]
    pub claim: ClaimResponse,
    /// PROV-O edge properties (role, position, contributions)
    pub attribution: serde_json::Value,
}

/// List claims attributed to an agent via ATTRIBUTED_TO edges
///
/// GET /api/v1/agents/:id/claims?limit=50&offset=0&min_truth=0.0
///
/// Traverses `prov:wasAttributedTo` edges to return all claims attributed to
/// the given agent. Works for both human author agents and digital ingestion agents.
///
/// Returns claims linked via ATTRIBUTED_TO edges (claim → agent), with pagination
/// and optional minimum truth value filtering.
#[cfg(feature = "db")]
pub async fn agent_claims(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<AgentClaimsParams>,
) -> Result<Json<PaginatedResponse<AttributedClaimResponse>>, ApiError> {
    let agent_id = AgentId::from_uuid(id);

    // Verify agent exists
    AgentRepository::get_by_id(&state.db_pool, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    // Clamp pagination
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let min_truth = params.min_truth.clamp(0.0, 1.0);

    // Query claims via ATTRIBUTED_TO edges
    let rows =
        EdgeRepository::get_claims_attributed_to(&state.db_pool, id, min_truth, limit, offset)
            .await?;

    let total = EdgeRepository::count_claims_attributed_to(&state.db_pool, id, min_truth).await?;

    let items: Vec<AttributedClaimResponse> = rows
        .into_iter()
        .map(|row| {
            let claim = ClaimResponse {
                id: row.id,
                content: row.content,
                truth_value: row.truth_value,
                agent_id: row.agent_id,
                trace_id: row.trace_id,
                created_at: row.created_at,
                updated_at: row.updated_at,
                privacy_tier: None,
                encrypted_content: None,
                encryption_epoch: None,
                group_id: None,
                labels: Vec::new(),
                was_created: false,
            };
            AttributedClaimResponse {
                claim,
                attribution: row.edge_properties,
            }
        })
        .collect();

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// List claims attributed to an agent (placeholder - no database)
///
/// GET /api/v1/agents/:id/claims
#[cfg(not(feature = "db"))]
pub async fn agent_claims(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Query(params): Query<AgentClaimsParams>,
) -> Result<Json<PaginatedResponse<AttributedClaimResponse>>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    Ok(Json(PaginatedResponse {
        items: vec![],
        total: 0,
        limit,
        offset,
    }))
}

// =============================================================================
// UPDATE AGENT
// =============================================================================

/// Request to update an existing agent
#[derive(Deserialize)]
pub struct UpdateAgentRequest {
    pub display_name: Option<String>,
    pub labels: Option<Vec<String>>,
    pub orcid: Option<String>,
    pub ror_id: Option<String>,
    /// Reserved for future use
    pub properties: Option<serde_json::Value>,
}

/// Update an existing agent
///
/// PUT /api/v1/agents/:id
///
/// Updates mutable fields on an agent. The public key is immutable.
#[cfg(feature = "db")]
pub async fn update_agent(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateAgentRequest>,
) -> Result<Json<AgentResponse>, ApiError> {
    // Enforce scope when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        crate::middleware::scopes::check_scopes(auth, &["agents:write"])?;
    }

    let agent_id = AgentId::from_uuid(id);

    // Fetch existing agent (404 if not found)
    let mut agent = AgentRepository::get_by_id(&state.db_pool, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    // Apply partial updates
    if let Some(display_name) = request.display_name {
        agent.display_name = Some(display_name);
    }
    if let Some(labels) = request.labels {
        agent.labels = labels;
    }
    if let Some(orcid) = request.orcid {
        agent.orcid = Some(orcid);
    }
    if let Some(ror_id) = request.ror_id {
        agent.ror_id = Some(ror_id);
    }

    let updated = AgentRepository::update(&state.db_pool, &agent).await?;

    // Record provenance when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let content_hash = blake3::hash(id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "agent",
            id,
            "update",
            content_hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(agent_id = %id, error = %e, "Failed to record agent update provenance");
        }
    }

    Ok(Json(updated.into()))
}

/// Update an existing agent (placeholder - no database)
#[cfg(not(feature = "db"))]
pub async fn update_agent(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Json(_request): Json<UpdateAgentRequest>,
) -> Result<Json<AgentResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Agent updates require database".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_response_from_agent() {
        let public_key = [42u8; ED25519_PUBLIC_KEY_BYTE_LENGTH];
        let agent = Agent::new(public_key, Some("Alice".to_string()));

        // Consume agent directly - no need to clone since we don't use it after
        let response: AgentResponse = agent.into();

        assert_eq!(response.display_name, Some("Alice".to_string()));
        assert_eq!(response.public_key.len(), ED25519_PUBLIC_KEY_HEX_LENGTH);
        assert!(response.public_key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_parse_public_key_valid() {
        let valid_hex = "0".repeat(ED25519_PUBLIC_KEY_HEX_LENGTH);
        let result = parse_public_key(&valid_hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0u8; ED25519_PUBLIC_KEY_BYTE_LENGTH]);
    }

    #[test]
    fn test_parse_public_key_invalid_length() {
        let short_hex = "0".repeat(ED25519_PUBLIC_KEY_BYTE_LENGTH); // Half the required length
        let result = parse_public_key(&short_hex);
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::ValidationError { field, .. } => {
                assert_eq!(field, "public_key");
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_parse_public_key_invalid_hex() {
        let invalid_hex = "g".repeat(ED25519_PUBLIC_KEY_HEX_LENGTH);
        let result = parse_public_key(&invalid_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_reputation_response_serialization() {
        let response = AgentReputationResponse {
            agent_id: Uuid::nil(),
            display_name: Some("Test Agent".to_string()),
            reputation_score: 0.75,
            total_claims: 10,
            verified_claims: 7,
            claim_age_days_avg: 15.5,
        };

        let json = serde_json::to_value(&response).unwrap();

        assert_eq!(json["agent_id"], Uuid::nil().to_string());
        assert_eq!(json["display_name"], "Test Agent");
        assert_eq!(json["reputation_score"], 0.75);
        assert_eq!(json["total_claims"], 10);
        assert_eq!(json["verified_claims"], 7);
        assert_eq!(json["claim_age_days_avg"], 15.5);
    }

    #[test]
    fn test_new_agent_no_claims_gets_initial_reputation() {
        let calculator = ReputationCalculator::new();
        let reputation = calculator.calculate(&[]).unwrap();

        // New agents with no claims should get initial reputation of 0.5
        assert!(
            (reputation - 0.5).abs() < f64::EPSILON,
            "Expected initial reputation 0.5, got {}",
            reputation
        );
    }

    #[test]
    fn test_agent_response_includes_labels() {
        let mut agent = Agent::new([42u8; 32], Some("Dr. Smith".to_string()));
        agent.labels = vec!["person".to_string()];
        agent.orcid = Some("0000-0001-2345-6789".to_string());

        let response: AgentResponse = agent.into();
        assert_eq!(response.labels, vec!["person"]);
        assert_eq!(response.orcid, Some("0000-0001-2345-6789".to_string()));
        assert!(response.ror_id.is_none());
    }

    #[test]
    fn test_agent_list_params_defaults() {
        let json = "{}";
        let params: AgentListParams = serde_json::from_str(json).unwrap();

        assert_eq!(params.limit, 20);
        assert_eq!(params.offset, 0);
        assert!(params.label.is_none());
    }

    #[test]
    fn test_agent_claims_params_defaults() {
        let json = "{}";
        let params: AgentClaimsParams = serde_json::from_str(json).unwrap();

        assert_eq!(params.limit, 20);
        assert_eq!(params.offset, 0);
        assert!((params.min_truth - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_agent_claims_params_custom() {
        let json = r#"{"limit": 50, "offset": 10, "min_truth": 0.7}"#;
        let params: AgentClaimsParams = serde_json::from_str(json).unwrap();

        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 10);
        assert!((params.min_truth - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_attributed_claim_response_serialization() {
        let now = chrono::Utc::now();
        let response = AttributedClaimResponse {
            claim: ClaimResponse {
                id: Uuid::nil(),
                content: "Test claim".to_string(),
                truth_value: 0.85,
                agent_id: Uuid::nil(),
                trace_id: None,
                created_at: now,
                updated_at: now,
                privacy_tier: None,
                encrypted_content: None,
                encryption_epoch: None,
                group_id: None,
                labels: Vec::new(),
            },
            attribution: serde_json::json!({
                "prov": "wasAttributedTo",
                "role": "author",
                "position": 0
            }),
        };

        let json = serde_json::to_value(&response).unwrap();

        // #[serde(flatten)] means claim fields are at top level
        assert_eq!(json["content"], "Test claim");
        assert_eq!(json["truth_value"], 0.85);
        assert_eq!(json["attribution"]["prov"], "wasAttributedTo");
        assert_eq!(json["attribution"]["role"], "author");
        assert_eq!(json["attribution"]["position"], 0);
    }
}
