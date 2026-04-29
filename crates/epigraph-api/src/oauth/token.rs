//! POST /oauth/token — OAuth2 token issuance.
//!
//! Supports:
//! - client_credentials with Ed25519 proof (agents) or client_secret (services)
//! - refresh_token (all client types)
//! - external provider grant types (registered via providers.toml; e.g. google_id_token, cloudflare_access_jwt)

use axum::{extract::State, http::StatusCode, Json};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    /// Public client identifier (hex-encoded public key for agents)
    pub client_id: Option<String>,
    /// For services: client secret
    pub client_secret: Option<String>,
    /// For agents: "urn:epigraph:ed25519"
    pub client_assertion_type: Option<String>,
    /// For agents: base64(timestamp || nonce || signature)
    pub client_assertion: Option<String>,
    /// For refresh: the refresh token
    pub refresh_token: Option<String>,
    /// Requested scopes (space-separated)
    pub scope: Option<String>,
    /// For google_id_token grant: the Google ID token JWT
    pub id_token: Option<String>,
    /// Generic external-provider assertion (preferred over id_token for non-Google).
    pub assertion: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: String,
}

/// POST /oauth/token
#[cfg(feature = "db")]
pub async fn token_endpoint(
    State(state): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> Result<(StatusCode, Json<TokenResponse>), ApiError> {
    match req.grant_type.as_str() {
        "client_credentials" => handle_client_credentials(&state, &req).await,
        "refresh_token" => handle_refresh_token(&state, &req).await,
        other => {
            // Look up an external provider by grant_type.
            if let Some(provider) = state.providers.by_grant_type(other) {
                handle_external_grant(&state, provider, &req).await
            } else {
                Err(ApiError::BadRequest {
                    message: format!("Unsupported grant_type: {other}"),
                })
            }
        }
    }
}

#[cfg(not(feature = "db"))]
pub async fn token_endpoint(
    State(_state): State<AppState>,
    Json(_req): Json<TokenRequest>,
) -> Result<(StatusCode, Json<TokenResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "database required for OAuth2".to_string(),
    })
}

#[cfg(feature = "db")]
async fn handle_external_grant(
    state: &AppState,
    provider: std::sync::Arc<dyn crate::oauth::providers::ExternalIdentityProvider>,
    req: &TokenRequest,
) -> Result<(StatusCode, Json<TokenResponse>), ApiError> {
    use crate::oauth::providers::{provision_external_user, ProviderError};

    let assertion =
        req.assertion
            .as_deref()
            .or(req.id_token.as_deref())
            .ok_or(ApiError::BadRequest {
                message: "assertion required".into(),
            })?;

    let identity = match provider.validate(assertion).await {
        Ok(id) => id,
        Err(e) => {
            crate::oauth::providers::provision::emit_oauth_audit(
                &state.db_pool,
                "oauth_assertion_rejected",
                false,
                serde_json::json!({
                    "provider": provider.name(),
                    "grant_type": req.grant_type,
                    "reason": format!("{e}"),
                }),
            );
            return Err(match e {
                ProviderError::InvalidAssertion(msg) => ApiError::Unauthorized { reason: msg },
                ProviderError::JwksFetch(msg) => ApiError::ServiceUnavailable {
                    service: format!("JWKS unavailable: {msg}"),
                },
                ProviderError::Upstream(msg) => ApiError::BadGateway { reason: msg },
                ProviderError::Config(msg) => ApiError::InternalError { message: msg },
            });
        }
    };

    provision_external_user(state, provider.as_ref(), &identity, req.scope.as_deref()).await
}

// ── Agent assertion verification ─────────────────────────────────────────

/// Maximum age of an assertion timestamp (past). Assertions older than this are rejected.
const ASSERTION_MAX_AGE_SECS: u64 = 300; // 5 minutes
/// Maximum clock skew into the future. Assertions timestamped further ahead are rejected.
const ASSERTION_MAX_FUTURE_SECS: u64 = 30;

/// Verify an Ed25519 agent assertion for the client_credentials grant.
///
/// Assertion format: `timestamp(8B big-endian) || nonce(16B) || Ed25519_signature(64B)`
/// The signature covers `timestamp || nonce` (24 bytes).
///
/// Security properties:
/// - Real Ed25519 verification via `verify_strict` (rejects small-subgroup attacks)
/// - Timestamp freshness: max 5 minutes old, max 30 seconds into the future
/// - No nonce tracking (stateless). Replay within the window yields a duplicate
///   short-lived token (15min). Note: replay can also acquire a 24h refresh token,
///   so transport security (TLS in production) is the primary replay defense.
fn verify_agent_assertion(
    assertion_bytes: &[u8],
    pub_key_bytes: &[u8],
    client_id_str: &str,
) -> Result<(), ApiError> {
    if assertion_bytes.len() != 88 {
        return Err(ApiError::BadRequest {
            message: format!(
                "client_assertion must be exactly 88 bytes (got {})",
                assertion_bytes.len()
            ),
        });
    }

    let pub_key: [u8; 32] = pub_key_bytes.try_into().map_err(|_| ApiError::BadRequest {
        message: "agent public key must be exactly 32 bytes".to_string(),
    })?;

    // Check timestamp freshness (asymmetric: 30s future, 5min past)
    let timestamp_bytes: [u8; 8] = assertion_bytes[..8]
        .try_into()
        .expect("slice is exactly 8 bytes");
    let assertion_ts = u64::from_be_bytes(timestamp_bytes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if assertion_ts > now + ASSERTION_MAX_FUTURE_SECS {
        tracing::warn!(
            client_id = %client_id_str,
            "Agent assertion rejected: timestamp {assertion_ts} is too far in the future (now={now})"
        );
        return Err(ApiError::Unauthorized {
            reason: "client_assertion timestamp is in the future".to_string(),
        });
    }
    if now.saturating_sub(assertion_ts) > ASSERTION_MAX_AGE_SECS {
        tracing::warn!(
            client_id = %client_id_str,
            "Agent assertion rejected: timestamp {assertion_ts} is too old (now={now})"
        );
        return Err(ApiError::Unauthorized {
            reason: format!(
                "client_assertion timestamp too old ({}s), max {}s",
                now - assertion_ts,
                ASSERTION_MAX_AGE_SECS
            ),
        });
    }

    // Verify Ed25519 signature over timestamp+nonce
    let message = &assertion_bytes[..24]; // timestamp(8) + nonce(16)
    let sig_bytes: [u8; 64] = assertion_bytes[24..88]
        .try_into()
        .expect("slice is exactly 64 bytes");

    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&pub_key).map_err(|e| ApiError::BadRequest {
            message: format!("Invalid Ed25519 public key: {e}"),
        })?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    if verifying_key.verify_strict(message, &signature).is_err() {
        tracing::warn!(
            client_id = %client_id_str,
            "Agent assertion rejected: Ed25519 signature verification failed"
        );
        return Err(ApiError::Unauthorized {
            reason: "Ed25519 signature verification failed".to_string(),
        });
    }

    Ok(())
}

#[cfg(feature = "db")]
async fn handle_client_credentials(
    state: &AppState,
    req: &TokenRequest,
) -> Result<(StatusCode, Json<TokenResponse>), ApiError> {
    use epigraph_db::repos::oauth_client::OAuthClientRepository;

    let client_id_str = req.client_id.as_deref().ok_or(ApiError::BadRequest {
        message: "client_id required for client_credentials grant".to_string(),
    })?;

    let client = OAuthClientRepository::get_by_client_id(&state.db_pool, client_id_str)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::Unauthorized {
            reason: "Unknown client_id".to_string(),
        })?;

    if client.status != "active" {
        return Err(ApiError::Forbidden {
            reason: format!("Client status is '{}', must be 'active'", client.status),
        });
    }

    // Credential verification based on client type
    match client.client_type.as_str() {
        "agent" => {
            let assertion_type =
                req.client_assertion_type
                    .as_deref()
                    .ok_or(ApiError::BadRequest {
                        message: "client_assertion_type required for agents".to_string(),
                    })?;
            if assertion_type != "urn:epigraph:ed25519" {
                return Err(ApiError::BadRequest {
                    message: "Agents must use urn:epigraph:ed25519 assertion type".to_string(),
                });
            }
            let assertion = req
                .client_assertion
                .as_deref()
                .ok_or(ApiError::BadRequest {
                    message: "client_assertion required for agents".to_string(),
                })?;
            let assertion_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, assertion)
                    .map_err(|_| ApiError::BadRequest {
                        message: "Invalid base64 in client_assertion".to_string(),
                    })?;
            let pub_key_bytes = hex::decode(client_id_str).map_err(|_| ApiError::BadRequest {
                message: "client_id must be hex-encoded public key for agents".to_string(),
            })?;
            verify_agent_assertion(&assertion_bytes, &pub_key_bytes, client_id_str)?;
        }
        "service" => {
            let secret = req.client_secret.as_deref().ok_or(ApiError::BadRequest {
                message: "client_secret required for service clients".to_string(),
            })?;
            let secret_bytes = hex::decode(secret).map_err(|_| ApiError::BadRequest {
                message: "client_secret must be hex-encoded".to_string(),
            })?;
            let hash = blake3::hash(&secret_bytes);
            let stored_hash =
                client
                    .client_secret_hash
                    .as_deref()
                    .ok_or(ApiError::InternalError {
                        message: "Service client has no stored secret hash".to_string(),
                    })?;
            let ct_eq: bool =
                subtle::ConstantTimeEq::ct_eq(hash.as_bytes().as_slice(), stored_hash).into();
            if !ct_eq {
                return Err(ApiError::Unauthorized {
                    reason: "Invalid client_secret".to_string(),
                });
            }
        }
        _ => {
            return Err(ApiError::BadRequest {
                message: "client_credentials grant not supported for this client type".to_string(),
            });
        }
    }

    let ttl = match client.client_type.as_str() {
        "agent" => Duration::minutes(15),
        "human" => Duration::hours(1),
        "service" => Duration::hours(1),
        _ => Duration::minutes(15),
    };

    // Effective scopes = intersection of requested and granted
    let effective_scopes = {
        let granted = &client.granted_scopes;
        match &req.scope {
            Some(requested) => {
                let requested: Vec<String> = requested.split(' ').map(|s| s.to_string()).collect();
                requested
                    .into_iter()
                    .filter(|s| granted.contains(s))
                    .collect::<Vec<_>>()
            }
            None => granted.clone(),
        }
    };

    let (access_token, _jti) = state
        .jwt_config
        .issue_access_token(
            client.id,
            effective_scopes.clone(),
            &client.client_type,
            client.owner_id,
            client.agent_id,
            ttl,
        )
        .map_err(|e| ApiError::InternalError {
            message: format!("JWT signing failed: {e}"),
        })?;

    // Generate refresh token
    let refresh_token = {
        use rand::Rng;
        let raw: [u8; 32] = rand::thread_rng().gen();
        let token_str = hex::encode(raw);
        let hash = blake3::hash(&raw);
        let refresh_ttl = match client.client_type.as_str() {
            "agent" => Duration::hours(24),
            "human" => Duration::days(30),
            "service" => Duration::days(90),
            _ => Duration::hours(24),
        };
        epigraph_db::repos::refresh_token::RefreshTokenRepository::create(
            &state.db_pool,
            hash.as_bytes(),
            client.id,
            &effective_scopes,
            Utc::now() + refresh_ttl,
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?;
        token_str
    };

    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: ttl.num_seconds(),
            refresh_token: Some(refresh_token),
            scope: effective_scopes.join(" "),
        }),
    ))
}

#[cfg(feature = "db")]
async fn handle_refresh_token(
    state: &AppState,
    req: &TokenRequest,
) -> Result<(StatusCode, Json<TokenResponse>), ApiError> {
    use epigraph_db::repos::oauth_client::OAuthClientRepository;
    use epigraph_db::repos::refresh_token::RefreshTokenRepository;

    let refresh_token_str = req.refresh_token.as_deref().ok_or(ApiError::BadRequest {
        message: "refresh_token required".to_string(),
    })?;

    let raw = hex::decode(refresh_token_str).map_err(|_| ApiError::BadRequest {
        message: "Invalid refresh token format".to_string(),
    })?;
    let hash = blake3::hash(&raw);

    let stored = RefreshTokenRepository::get_valid(&state.db_pool, hash.as_bytes())
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::Unauthorized {
            reason: "Invalid or expired refresh token".to_string(),
        })?;

    // Revoke old token (rotation)
    RefreshTokenRepository::revoke(&state.db_pool, stored.id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?;

    let client = OAuthClientRepository::get_by_id(&state.db_pool, stored.client_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::InternalError {
            message: "Client not found for refresh token".to_string(),
        })?;

    if client.status != "active" {
        return Err(ApiError::Forbidden {
            reason: "Client has been suspended or revoked".to_string(),
        });
    }

    let ttl = match client.client_type.as_str() {
        "agent" => Duration::minutes(15),
        "human" => Duration::hours(1),
        "service" => Duration::hours(1),
        _ => Duration::minutes(15),
    };

    // Use client's current granted_scopes (may have been updated since refresh token was issued)
    let effective_scopes = client.granted_scopes.clone();

    let (access_token, _jti) = state
        .jwt_config
        .issue_access_token(
            client.id,
            effective_scopes.clone(),
            &client.client_type,
            client.owner_id,
            client.agent_id,
            ttl,
        )
        .map_err(|e| ApiError::InternalError {
            message: format!("JWT signing failed: {e}"),
        })?;

    // New refresh token
    let new_refresh = {
        use rand::Rng;
        let raw: [u8; 32] = rand::thread_rng().gen();
        let token_str = hex::encode(raw);
        let hash = blake3::hash(&raw);
        let refresh_ttl = match client.client_type.as_str() {
            "agent" => Duration::hours(24),
            "human" => Duration::days(30),
            "service" => Duration::days(90),
            _ => Duration::hours(24),
        };
        RefreshTokenRepository::create(
            &state.db_pool,
            hash.as_bytes(),
            client.id,
            &effective_scopes,
            Utc::now() + refresh_ttl,
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?;
        token_str
    };

    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: ttl.num_seconds(),
            refresh_token: Some(new_refresh),
            scope: effective_scopes.join(" "),
        }),
    ))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod assertion_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a valid agent assertion: timestamp(8B) || nonce(16B) || sig(64B)
    fn build_assertion(signing_key: &SigningKey, timestamp_secs: u64) -> Vec<u8> {
        let timestamp = timestamp_secs.to_be_bytes();
        let nonce: [u8; 16] = rand::random();
        let message = [&timestamp[..], &nonce[..]].concat();
        let signature = signing_key.sign(&message);
        [&timestamp[..], &nonce[..], signature.to_bytes().as_slice()].concat()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn valid_assertion_passes() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();
        let assertion = build_assertion(&sk, now_secs());
        let client_id = hex::encode(pk);

        assert!(verify_agent_assertion(&assertion, &pk, &client_id).is_ok());
    }

    #[test]
    fn wrong_key_rejected() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let wrong_sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let wrong_pk = wrong_sk.verifying_key().to_bytes();
        let assertion = build_assertion(&sk, now_secs());
        let client_id = hex::encode(wrong_pk);

        let err = verify_agent_assertion(&assertion, &wrong_pk, &client_id).unwrap_err();
        match err {
            ApiError::Unauthorized { reason } => {
                assert!(reason.contains("signature verification failed"), "{reason}");
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn tampered_nonce_rejected() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();
        let mut assertion = build_assertion(&sk, now_secs());
        let client_id = hex::encode(pk);

        // Flip a bit in the nonce region
        assertion[12] ^= 0xFF;

        let err = verify_agent_assertion(&assertion, &pk, &client_id).unwrap_err();
        match err {
            ApiError::Unauthorized { reason } => {
                assert!(reason.contains("signature verification failed"), "{reason}");
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn stale_timestamp_rejected() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();
        // 10 minutes ago
        let assertion = build_assertion(&sk, now_secs() - 600);
        let client_id = hex::encode(pk);

        let err = verify_agent_assertion(&assertion, &pk, &client_id).unwrap_err();
        match err {
            ApiError::Unauthorized { reason } => {
                assert!(reason.contains("too old"), "{reason}");
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn future_timestamp_rejected() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();
        // 5 minutes in the future
        let assertion = build_assertion(&sk, now_secs() + 300);
        let client_id = hex::encode(pk);

        let err = verify_agent_assertion(&assertion, &pk, &client_id).unwrap_err();
        match err {
            ApiError::Unauthorized { reason } => {
                assert!(reason.contains("future"), "{reason}");
            }
            other => panic!("Expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn wrong_length_rejected() {
        let pk = [0u8; 32];
        let short = vec![0u8; 50];
        let client_id = hex::encode(pk);

        let err = verify_agent_assertion(&short, &pk, &client_id).unwrap_err();
        match err {
            ApiError::BadRequest { message } => {
                assert!(message.contains("exactly 88 bytes"), "{message}");
            }
            other => panic!("Expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn slight_clock_skew_allowed() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();
        // 20 seconds in the future — within 30s tolerance
        let assertion = build_assertion(&sk, now_secs() + 20);
        let client_id = hex::encode(pk);

        assert!(verify_agent_assertion(&assertion, &pk, &client_id).is_ok());
    }
}
