//! POST /oauth/token — OAuth2 token issuance.
//!
//! Supports:
//! - client_credentials with Ed25519 proof (agents) or client_secret (services)
//! - refresh_token (all client types)
//! - external provider grant types (registered via providers.toml; e.g. google_id_token, cloudflare_access_jwt)

use axum::{
    body::Bytes,
    extract::State,
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::errors::ApiError;
use crate::state::AppState;

/// Parse a token request from either `application/x-www-form-urlencoded` — the OAuth 2.0
/// standard body for the token endpoint (RFC 6749 §4.1.3), sent by claude.ai and other
/// RFC 6749 / remote-MCP clients — or `application/json`, used by EpiGraph's own agents.
/// Defaults to form-encoded when the Content-Type is absent, per the spec.
#[cfg(feature = "db")]
fn parse_token_request(headers: &HeaderMap, body: &[u8]) -> Result<TokenRequest, ApiError> {
    let ct = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ct.starts_with("application/json") {
        serde_json::from_slice(body).map_err(|e| ApiError::BadRequest {
            message: format!("invalid JSON token request: {e}"),
        })
    } else {
        serde_urlencoded::from_bytes(body).map_err(|e| ApiError::BadRequest {
            message: format!("invalid form-encoded token request: {e}"),
        })
    }
}

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
    /// For authorization_code grant: the code returned to the client.
    pub code: Option<String>,
    /// For authorization_code grant: PKCE verifier.
    pub code_verifier: Option<String>,
    /// For authorization_code grant: must equal the redirect_uri used at /authorize.
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: String,
}

/// Pure allowlist decision for the `refresh_token` grant — re-evaluates the
/// provider's email allowlist against the persisted identity at refresh time.
///
/// This closes the revocation hole: the provision gate
/// ([`crate::oauth::providers::provision::provision_external_user_client`]) only
/// runs on a full ID-token / authorization grant, but `handle_refresh_token`
/// rotates a fresh 30-day refresh token on every call keyed solely on possession
/// of a valid refresh token. Without re-checking here, an identity removed from
/// the allowlist would keep renewing access indefinitely (status flip is the only
/// other stop). Re-running the SAME `email_is_allowed` predicate makes the gate
/// comment's "removed identities stop authenticating" guarantee true for refresh.
///
/// Returns `true` (issue tokens normally — SKIP the gate) when:
/// * `client_id` has no `':'` (not a `{provider}:{subject}` external client —
///   agent client_ids are hex pubkeys, service / DCR are `epigraph_{hex}`; gating
///   these would lock agents/services out of refresh), OR
/// * the prefix resolves to no registered provider via [`ProviderRegistry::by_name`]
///   (unknown / removed provider — there is no allowlist left to consult here; whole-
///   provider de-authorization is an operational `status='suspended'` action), OR
/// * the resolved provider configures no allowlist (both lists empty — allow-all,
///   backward compatible with [`crate::oauth::providers::config::email_is_allowed`]).
///
/// Returns `false` (DENY) only when an external client's provider HAS a configured
/// allowlist and `persisted_email` (from `oauth_clients.legal_contact_email`, `""`
/// when NULL) is not on it. `email_verified` is deliberately NOT consulted: it lives
/// only on the original assertion (not on `OAuthClientRow`), verification was already
/// enforced at provision time and does not lapse, and defaulting a missing flag to
/// `false` would lock out every external client on rotation.
///
/// Gated on `feature = "db"` to match its only production caller
/// (`handle_refresh_token` / `handle_authorization_code`); without the gate it is
/// dead code under `--no-default-features` and trips `clippy -D warnings`.
#[cfg(feature = "db")]
fn refresh_allowed(
    registry: &crate::oauth::providers::ProviderRegistry,
    client_id: &str,
    persisted_email: &str,
) -> bool {
    // Provider names are validated to `[a-z0-9-]+` (cannot contain ':'), so the
    // FIRST ':' is the correct prefix splitter even when a subject embeds colons.
    let Some((prefix, _)) = client_id.split_once(':') else {
        return true; // non-external client (agent / service / DCR) — skip the gate.
    };
    let Some(provider) = registry.by_name(prefix) else {
        return true; // unknown / removed provider — no allowlist to consult.
    };
    let allowed_emails = provider.allowed_emails();
    let allowed_domains = provider.allowed_domains();
    if allowed_emails.is_empty() && allowed_domains.is_empty() {
        return true; // provider configures no allowlist — allow-all.
    }
    crate::oauth::providers::config::email_is_allowed(
        persisted_email,
        allowed_emails,
        allowed_domains,
    )
}

/// POST /oauth/token
#[cfg(feature = "db")]
pub async fn token_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<TokenResponse>), ApiError> {
    let req = parse_token_request(&headers, &body)?;
    match req.grant_type.as_str() {
        "client_credentials" => handle_client_credentials(&state, &req).await,
        "refresh_token" => handle_refresh_token(&state, &req).await,
        "authorization_code" => handle_authorization_code(&state, &req).await,
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
    _headers: HeaderMap,
    _body: Bytes,
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

    // Re-run the provider email allowlist for external (`{provider}:{subject}`)
    // clients BEFORE minting. The provision gate only fires on a full ID-token /
    // authorization grant; refresh rotation re-issues a fresh 30d refresh on every
    // call, so without this an identity removed from the allowlist keeps renewing
    // access indefinitely. The old token was already revoked above (rotation), so a
    // denied refresh correctly burns it — a deauthorized identity keeps no reusable
    // token. SKIP (issue normally) for non-external clients and unconfigured
    // allowlists; see [`refresh_allowed`].
    if !refresh_allowed(
        &state.providers,
        &client.client_id,
        client.legal_contact_email.as_deref().unwrap_or(""),
    ) {
        tracing::warn!(
            client_id = %client.client_id,
            "Denied token refresh: identity no longer in provider email allowlist"
        );
        crate::oauth::providers::provision::emit_oauth_audit(
            &state.db_pool,
            "oauth_refresh_denied",
            false,
            serde_json::json!({
                "client_id": client.client_id,
                "email": client.legal_contact_email,
                "reason": "email_not_in_allowlist",
            }),
        );
        return Err(ApiError::Forbidden {
            reason: "email no longer authorized for this provider".into(),
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

#[cfg(feature = "db")]
async fn handle_authorization_code(
    state: &AppState,
    req: &TokenRequest,
) -> Result<(StatusCode, Json<TokenResponse>), ApiError> {
    use base64::Engine;
    use epigraph_db::repos::authorization_code::AuthorizationCodeRepository;
    use epigraph_db::repos::oauth_client::OAuthClientRepository;
    use sha2::Digest;

    let code = req.code.as_deref().ok_or(ApiError::BadRequest {
        message: "missing code".into(),
    })?;
    let verifier = req.code_verifier.as_deref().ok_or(ApiError::BadRequest {
        message: "missing code_verifier".into(),
    })?;
    let redirect_uri = req.redirect_uri.as_deref().ok_or(ApiError::BadRequest {
        message: "missing redirect_uri".into(),
    })?;
    // RFC 9700 §4.1.3 / OAuth 2.1: client_id validation in the authorization_code
    // grant is a MUST. Extract presence here, alongside the other required-param
    // checks and BEFORE consume(), so an omitted client_id is rejected without
    // burning the single-use code. The value-vs-row binding check is below (needs
    // the consumed row). Making this unconditional closes the binding-bypass where
    // a captured/replayed code could be redeemed by any caller that simply leaves
    // client_id out of the token request.
    let req_client_id = req.client_id.as_deref().ok_or(ApiError::BadRequest {
        message: "missing client_id".into(),
    })?;

    // Single-use consume (atomic; rejects used/expired).
    let raw = code.as_bytes();
    let code_hash = blake3::hash(raw);
    let row = AuthorizationCodeRepository::consume(&state.db_pool, code_hash.as_bytes())
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::BadRequest {
            message: "invalid_grant: code invalid, used, or expired".into(),
        })?;

    // PKCE S256: base64url(SHA256(verifier)) == stored challenge.
    // We assume S256 (we never compute the "plain" transform). That assumption is
    // safe by construction: oauth_authorization_codes.code_challenge_method defaults
    // to 'S256' (migration 049), AuthorizationCodeRepository::create never sets a
    // different value, and Task 7's /authorize will reject any method != "S256"
    // before a code is ever minted. consume() therefore omits the method column
    // rather than carrying an always-'S256' field through this hot path.
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    if computed != row.code_challenge {
        return Err(ApiError::BadRequest {
            message: "invalid_grant: PKCE mismatch".into(),
        });
    }
    // Binding checks.
    if redirect_uri != row.redirect_uri {
        return Err(ApiError::BadRequest {
            message: "invalid_grant: redirect_uri mismatch".into(),
        });
    }
    if req_client_id != row.client_id {
        return Err(ApiError::BadRequest {
            message: "invalid_grant: client mismatch".into(),
        });
    }

    // Load the per-user client to populate token claims (type/owner/agent).
    let client = OAuthClientRepository::get_by_id(&state.db_pool, row.oauth_client_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::BadRequest {
            message: "invalid_grant: unknown user".into(),
        })?;

    // get_by_id returns suspended/revoked clients, so gate on status here — same as
    // handle_client_credentials and handle_refresh_token. Without this, a user whose
    // client was suspended/revoked could still redeem a valid code for a fresh 1h
    // access token + 30d refresh token (a 30-day blast radius).
    if client.status != "active" {
        return Err(ApiError::Forbidden {
            reason: format!("Client status is '{}', must be 'active'", client.status),
        });
    }

    // Re-run the provider email allowlist before issuing tokens, mirroring
    // handle_refresh_token, so the SAME invariant holds on every token-issuance
    // path: an identity de-listed between consent (when the provision gate ran and
    // minted this code) and code exchange is refused here rather than handed a 1h
    // access token + 30d refresh. The single-use code was already consumed above,
    // so a denied exchange burns it. SKIP for non-external clients / unconfigured
    // allowlists; see [`refresh_allowed`].
    if !refresh_allowed(
        &state.providers,
        &client.client_id,
        client.legal_contact_email.as_deref().unwrap_or(""),
    ) {
        tracing::warn!(
            client_id = %client.client_id,
            "Denied authorization_code exchange: identity no longer in provider email allowlist"
        );
        crate::oauth::providers::provision::emit_oauth_audit(
            &state.db_pool,
            "oauth_authcode_denied",
            false,
            serde_json::json!({
                "client_id": client.client_id,
                "email": client.legal_contact_email,
                "reason": "email_not_in_allowlist",
            }),
        );
        return Err(ApiError::Forbidden {
            reason: "email no longer authorized for this provider".into(),
        });
    }

    // TTLs by client type, matching the sibling grant handlers' tables. Per-user
    // clients are always client_type="human" (1h access / 30d refresh); keying off
    // client_type keeps the values coupled to type rather than hardcoded.
    let ttl = match client.client_type.as_str() {
        "agent" => Duration::minutes(15),
        "human" => Duration::hours(1),
        "service" => Duration::hours(1),
        _ => Duration::minutes(15),
    };
    let effective_scopes = row.scopes.clone();
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

    // Refresh token (reuse the existing rotation pattern).
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

/// Unit tests for the pure `refresh_allowed` decision. DB-free: they build an
/// in-memory `ProviderRegistry` with a stub provider whose allowlist is
/// configurable, mirroring the `email_is_allowed` and registry tests. These cover
/// the four branches the refresh re-gate must get right WITHOUT touching the DB.
#[cfg(all(test, feature = "db"))]
mod refresh_gate_tests {
    use super::refresh_allowed;
    use crate::oauth::providers::{
        ExternalIdentity, ExternalIdentityProvider, ProviderError, ProviderRegistry,
    };
    use async_trait::async_trait;
    use std::sync::Arc;

    /// A provider whose allowlist is supplied by the test, so we can exercise both
    /// the configured-allowlist (deny/allow) and the empty-allowlist (allow-all)
    /// branches — the default trait impls only give the allow-all path.
    struct AllowlistProvider {
        name: String,
        grant: String,
        allowed_emails: Vec<String>,
        allowed_domains: Vec<String>,
    }

    #[async_trait]
    impl ExternalIdentityProvider for AllowlistProvider {
        fn name(&self) -> &str {
            &self.name
        }
        fn grant_type(&self) -> &str {
            &self.grant
        }
        async fn validate(&self, _: &str) -> Result<ExternalIdentity, ProviderError> {
            unimplemented!("not exercised by the pure refresh_allowed decision")
        }
        fn auto_provision(&self) -> bool {
            true
        }
        fn default_scopes(&self) -> &[String] {
            &[]
        }
        fn allowed_emails(&self) -> &[String] {
            &self.allowed_emails
        }
        fn allowed_domains(&self) -> &[String] {
            &self.allowed_domains
        }
    }

    fn registry_with(
        name: &str,
        grant: &str,
        allowed_emails: Vec<String>,
        allowed_domains: Vec<String>,
    ) -> ProviderRegistry {
        let mut r = ProviderRegistry::empty();
        r.register(
            Arc::new(AllowlistProvider {
                name: name.into(),
                grant: grant.into(),
                allowed_emails,
                allowed_domains,
            }) as Arc<dyn ExternalIdentityProvider>,
            None,
        )
        .unwrap();
        r
    }

    #[test]
    fn allowlisted_external_client_is_allowed() {
        // (a) External client whose persisted email IS on the provider allowlist.
        let r = registry_with(
            "google",
            "google_id_token",
            vec!["jeremy.barton@gmail.com".into()],
            vec![],
        );
        assert!(refresh_allowed(
            &r,
            "google:107485523387294236292",
            "jeremy.barton@gmail.com"
        ));
    }

    #[test]
    fn delisted_external_client_is_denied() {
        // (b) External client whose persisted email is NOT on the allowlist (the
        // revocation case): an identity removed from the allowlist must be denied.
        let r = registry_with(
            "google",
            "google_id_token",
            vec!["jeremy.barton@gmail.com".into()],
            vec![],
        );
        assert!(!refresh_allowed(
            &r,
            "google:999999999999999999999",
            "evil@attacker.com"
        ));
    }

    #[test]
    fn non_external_client_skips_gate() {
        // (c) Non-external clients must NOT be affected by the gate. Agent client_ids
        // are hex pubkeys and service/DCR are `epigraph_{hex}` — neither contains a
        // ':' — so the gate skips (returns allowed) regardless of registry contents.
        let r = registry_with(
            "google",
            "google_id_token",
            vec!["jeremy.barton@gmail.com".into()],
            vec![],
        );
        // hex pubkey (agent): no ':' → skip.
        assert!(refresh_allowed(
            &r,
            "a1b2c3d4e5f6071829aabbccddeeff00112233445566778899aabbccddeeff00",
            ""
        ));
        // service / DCR: no ':' → skip.
        assert!(refresh_allowed(&r, "epigraph_deadbeefcafef00d", ""));
        // unrecognized provider prefix (e.g. legacy underscore `google_<sub>` has no
        // ':'; a colon-bearing id for an UNregistered provider also skips).
        assert!(refresh_allowed(
            &r,
            "google_107485523387294236292",
            "evil@attacker.com"
        ));
        assert!(refresh_allowed(
            &r,
            "removed-provider:subject",
            "evil@attacker.com"
        ));
    }

    #[test]
    fn empty_allowlist_provider_allows_all() {
        // (d) A registered provider that configures NO allowlist (both lists empty)
        // is allow-all (backward compatible) — even an empty persisted email passes.
        let r = registry_with("google", "google_id_token", vec![], vec![]);
        assert!(refresh_allowed(
            &r,
            "google:any-subject",
            "anyone@example.com"
        ));
        assert!(refresh_allowed(&r, "google:any-subject", ""));
    }

    #[test]
    fn domain_allowlist_external_client() {
        // Belt-and-braces: the domain branch of the allowlist also gates refresh.
        let r = registry_with(
            "google",
            "google_id_token",
            vec![],
            vec!["baros.associates".into()],
        );
        assert!(refresh_allowed(&r, "google:sub", "anyone@baros.associates"));
        assert!(!refresh_allowed(&r, "google:sub", "anyone@gmail.com"));
    }
}
