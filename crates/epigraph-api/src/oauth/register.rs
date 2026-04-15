//! POST /oauth/register — Dynamic client registration (RFC 7591).

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub client_name: String,
    pub client_type: String,
    /// For agents: hex-encoded Ed25519 public key (used as client_id).
    /// Omit for human/service (auto-generated).
    pub client_id: Option<String>,
    /// Required for authorization_code flow
    pub redirect_uris: Option<Vec<String>>,
    /// Requested scopes
    pub scope: Option<String>,
    /// Required for 'service' type
    pub legal_entity_name: Option<String>,
    pub legal_entity_id: Option<String>,
    pub legal_contact_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_name: String,
    pub client_type: String,
    pub status: String,
    pub allowed_scopes: Vec<String>,
    pub message: String,
}

/// Default read-only scopes for pending service clients.
const PENDING_SERVICE_SCOPES: &[&str] = &[
    "claims:read",
    "evidence:read",
    "edges:read",
    "agents:read",
    "groups:read",
    "analysis:belief",
    "analysis:propagation",
    "analysis:reasoning",
    "analysis:gaps",
    "analysis:structural",
    "analysis:hypothesis",
    "analysis:political",
];

#[cfg(feature = "db")]
pub async fn register_endpoint(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    // Validate client_type
    if !["human", "service", "agent"].contains(&req.client_type.as_str()) {
        return Err(ApiError::BadRequest {
            message: "client_type must be 'human', 'service', or 'agent'".to_string(),
        });
    }

    // Validate legal entity for services
    if req.client_type == "service"
        && (req.legal_entity_name.is_none() || req.legal_contact_email.is_none())
    {
        return Err(ApiError::BadRequest {
            message: "Services require legal_entity_name and legal_contact_email".to_string(),
        });
    }

    // Agents must provide their own client_id (hex-encoded Ed25519 public key)
    if req.client_type == "agent" && req.client_id.is_none() {
        return Err(ApiError::BadRequest {
            message: "Agents must provide client_id (hex-encoded Ed25519 public key)".to_string(),
        });
    }

    // Generate or use provided client_id and secret
    let (client_id, client_secret, secret_hash_bytes) = if req.client_type == "agent" {
        // Agent: client_id is the hex pubkey, no secret needed (Ed25519 assertion auth)
        (req.client_id.clone().unwrap(), None, None)
    } else {
        // Human/service: auto-generate client_id + secret
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let cid = format!("epigraph_{}", hex::encode(rng.gen::<[u8; 16]>()));
        let secret_bytes: [u8; 32] = rng.gen();
        let cs = hex::encode(secret_bytes);
        let hash = blake3::hash(&secret_bytes);
        (cid, Some(cs), Some(hash))
    };

    // Check for existing client (idempotent for agents)
    {
        use epigraph_db::repos::oauth_client::OAuthClientRepository;
        if let Ok(Some(_)) =
            OAuthClientRepository::get_by_client_id(&state.db_pool, &client_id).await
        {
            return Ok((
                StatusCode::OK,
                Json(RegisterResponse {
                    client_id,
                    client_secret: None,
                    client_name: req.client_name,
                    client_type: req.client_type,
                    status: "active".to_string(),
                    allowed_scopes: vec![],
                    message: "Client already registered.".to_string(),
                }),
            ));
        }
    }

    // Determine initial scopes and status
    let (status, allowed_scopes, granted_scopes) = match req.client_type.as_str() {
        "agent" => {
            // Agents are auto-activated with full write scopes
            let scopes = vec![
                "claims:read".to_string(),
                "claims:write".to_string(),
                "evidence:read".to_string(),
                "evidence:write".to_string(),
                "edges:read".to_string(),
                "edges:write".to_string(),
                "agents:read".to_string(),
                "agents:write".to_string(),
                "analysis:belief".to_string(),
                "analysis:propagation".to_string(),
                "ingest:write".to_string(),
            ];
            ("active", scopes.clone(), scopes)
        }
        "service" => (
            "pending",
            PENDING_SERVICE_SCOPES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            vec![],
        ),
        "human" => ("pending", vec![], vec![]),
        _ => unreachable!(),
    };

    // For agents, find the owner (first active human client)
    let owner_id: Option<uuid::Uuid> = if req.client_type == "agent" {
        let row: Option<(uuid::Uuid,)> = sqlx::query_as(
            "SELECT id FROM oauth_clients WHERE client_type = 'human' AND status = 'active' ORDER BY created_at LIMIT 1"
        )
        .fetch_optional(&state.db_pool)
        .await
        .unwrap_or(None);
        row.map(|(id,)| id)
    } else {
        None
    };

    {
        use epigraph_db::repos::oauth_client::OAuthClientRepository;
        OAuthClientRepository::create(
            &state.db_pool,
            &client_id,
            secret_hash_bytes
                .as_ref()
                .map(|h: &blake3::Hash| h.as_bytes() as &[u8]),
            &req.client_name,
            &req.client_type,
            &allowed_scopes,
            &granted_scopes,
            status,
            None, // agent_id linked later via ensure_agent_by_content
            owner_id,
            req.legal_entity_name.as_deref(),
            req.legal_contact_email.as_deref(),
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?;
    }

    let message = match status {
        "pending" => {
            "Registration received. An admin must approve before write scopes are granted."
                .to_string()
        }
        "active" => "Agent registered and activated.".to_string(),
        _ => "Client registered successfully.".to_string(),
    };

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            client_id,
            client_secret,
            client_name: req.client_name,
            client_type: req.client_type,
            status: status.to_string(),
            allowed_scopes,
            message,
        }),
    ))
}

#[cfg(not(feature = "db"))]
pub async fn register_endpoint(
    State(_state): State<AppState>,
    Json(_req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database required for OAuth2".to_string(),
    })
}
