//! POST /oauth/register — Dynamic client registration (RFC 7591).

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub client_name: String,
    /// EpiGraph-native client class. Optional so RFC 7591 DCR clients (claude.ai)
    /// that send only redirect_uris + response_types=["code"] are accepted as a
    /// public authorization_code 'human' client.
    #[serde(default)]
    pub client_type: Option<String>,
    /// For agents: hex-encoded Ed25519 public key (used as client_id).
    /// Omit for human/service (auto-generated).
    pub client_id: Option<String>,
    /// Required for authorization_code flow
    pub redirect_uris: Option<Vec<String>>,
    /// Requested scopes
    pub scope: Option<String>,
    /// RFC 7591: defaults to ["code"] when omitted.
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    /// RFC 7591: e.g. ["authorization_code","refresh_token"].
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    /// RFC 7591: "none" (public + PKCE) or "client_secret_post".
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
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
    /// RFC 7591: the locked redirect URIs, echoed back for DCR clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
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
    // RFC 7591 DCR detection: a request with NO client_type is an OAuth-native
    // dynamic registration (claude.ai sends redirect_uris + response_types=["code"]).
    // It becomes a PUBLIC authorization_code 'human' client. Requests that DO carry
    // client_type keep the legacy EpiGraph human/service/agent semantics unchanged.
    let is_dcr = req.client_type.is_none();

    // Enforce the redirect-host allowlist FIRST, before any client_id generation or
    // DB access, so an abusive registration is rejected DB-free (and so the negative
    // test needs no database). This closes the open-redirect / open-registration gap
    // flagged in recon: any redirect_uri whose host is not claude.ai/claude.com is
    // refused regardless of client_type.
    if let Some(uris) = req.redirect_uris.as_deref() {
        for u in uris {
            let host_ok =
                u.starts_with("https://claude.ai/") || u.starts_with("https://claude.com/");
            if !host_ok {
                return Err(ApiError::BadRequest {
                    message: "redirect_uri host must be claude.ai or claude.com".to_string(),
                });
            }
        }
    }

    // A DCR (no client_type) for the authorization_code flow MUST carry redirect_uris;
    // a typeless body without one is not a valid registration.
    if is_dcr && req.redirect_uris.as_ref().map(|u| u.is_empty()).unwrap_or(true) {
        return Err(ApiError::BadRequest {
            message: "redirect_uris is required for dynamic client registration".to_string(),
        });
    }

    // Resolve the effective EpiGraph client_type. DCR maps to a 'human' client.
    let client_type: &str = match req.client_type.as_deref() {
        None => "human",
        Some(t) if ["human", "service", "agent"].contains(&t) => t,
        Some(_) => {
            return Err(ApiError::BadRequest {
                message: "client_type must be 'human', 'service', or 'agent'".to_string(),
            });
        }
    };

    // Validate legal entity for services
    if client_type == "service"
        && (req.legal_entity_name.is_none() || req.legal_contact_email.is_none())
    {
        return Err(ApiError::BadRequest {
            message: "Services require legal_entity_name and legal_contact_email".to_string(),
        });
    }

    // Agents must provide their own client_id (hex-encoded Ed25519 public key)
    if client_type == "agent" && req.client_id.is_none() {
        return Err(ApiError::BadRequest {
            message: "Agents must provide client_id (hex-encoded Ed25519 public key)".to_string(),
        });
    }

    // Generate or use provided client_id and secret.
    let (client_id, client_secret, secret_hash_bytes) = if client_type == "agent" {
        // Agent: client_id is the hex pubkey, no secret needed (Ed25519 assertion auth)
        (req.client_id.clone().unwrap(), None, None)
    } else if is_dcr {
        // DCR public client: PKCE-only (token_endpoint_auth_method "none"), so issue NO
        // client_secret — claude.ai authenticates the code exchange with the PKCE
        // verifier, and a secret on a public client would be a credential to leak.
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let cid = format!("epigraph_{}", hex::encode(rng.gen::<[u8; 16]>()));
        (cid, None, None)
    } else {
        // Legacy human/service: auto-generate client_id + secret
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let cid = format!("epigraph_{}", hex::encode(rng.gen::<[u8; 16]>()));
        let secret_bytes: [u8; 32] = rng.gen();
        let cs = hex::encode(secret_bytes);
        let hash = blake3::hash(&secret_bytes);
        (cid, Some(cs), Some(hash))
    };

    let redirect_uris = req.redirect_uris.clone();

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
                    client_type: client_type.to_string(),
                    status: "active".to_string(),
                    allowed_scopes: vec![],
                    redirect_uris,
                    message: "Client already registered.".to_string(),
                }),
            ));
        }
    }

    // Determine initial scopes and status.
    let dcr_scopes = || {
        PENDING_SERVICE_SCOPES
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    };
    let (status, allowed_scopes, granted_scopes) = if is_dcr {
        // Active public client for the authorization_code flow: BOTH allowed and
        // granted are the safe read/analysis default set, because the token is minted
        // from granted_scopes (an empty granted set would yield empty tokens). Write
        // scopes still require an explicit admin grant later.
        ("active", dcr_scopes(), dcr_scopes())
    } else {
        match client_type {
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
            "service" => ("pending", dcr_scopes(), vec![]),
            "human" => ("pending", vec![], vec![]),
            _ => unreachable!(),
        }
    };

    // For agents, find the owner (first active human client)
    let owner_id: Option<uuid::Uuid> = if client_type == "agent" {
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
            client_type,
            &allowed_scopes,
            &granted_scopes,
            status,
            None, // agent_id linked later via ensure_agent_by_content
            owner_id,
            req.legal_entity_name.as_deref(),
            req.legal_contact_email.as_deref(),
            redirect_uris.as_deref(),
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?;
    }

    let message = if is_dcr {
        "Client registered. Use the authorization_code flow with PKCE.".to_string()
    } else {
        match status {
            "pending" => {
                "Registration received. An admin must approve before write scopes are granted."
                    .to_string()
            }
            "active" => "Agent registered and activated.".to_string(),
            _ => "Client registered successfully.".to_string(),
        }
    };

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            client_id,
            client_secret,
            client_name: req.client_name,
            client_type: client_type.to_string(),
            status: status.to_string(),
            allowed_scopes,
            redirect_uris,
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
