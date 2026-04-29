//! Provider-agnostic provisioning: synthesize client_id, find-or-create, issue tokens.

use axum::{http::StatusCode, Json};
use chrono::{Duration, Utc};

use super::traits::{ExternalIdentity, ExternalIdentityProvider};
use crate::errors::ApiError;
use crate::oauth::token::TokenResponse;
use crate::state::AppState;

#[cfg(feature = "db")]
pub async fn provision_external_user(
    state: &AppState,
    provider: &dyn ExternalIdentityProvider,
    identity: &ExternalIdentity,
    requested_scope: Option<&str>,
) -> Result<(StatusCode, Json<TokenResponse>), ApiError> {
    use epigraph_db::repos::oauth_client::OAuthClientRepository;
    use epigraph_db::repos::refresh_token::RefreshTokenRepository;

    let email = identity.email.clone().unwrap_or_default();
    let name = identity.name.clone().unwrap_or_else(|| email.clone());

    let oauth_client_id = format!("{}:{}", provider.name(), identity.subject);

    let client =
        match OAuthClientRepository::get_by_client_id(&state.db_pool, &oauth_client_id).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                if !provider.auto_provision() {
                    return Err(ApiError::Forbidden {
                        reason: "user not provisioned and auto_provision disabled".into(),
                    });
                }
                let scopes = provider.default_scopes().to_vec();
                let id = OAuthClientRepository::create(
                    &state.db_pool,
                    &oauth_client_id,
                    None,
                    &name,
                    "human",
                    &scopes,
                    &scopes,
                    "active",
                    None,
                    None,
                    None,
                    Some(&email),
                )
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Failed to create human client: {e}"),
                })?;
                tracing::info!(
                    provider = provider.name(),
                    client_id = %oauth_client_id,
                    email = %email,
                    "Auto-provisioned human OAuth client"
                );
                emit_oauth_audit(
                    &state.db_pool,
                    "oauth_human_provisioned",
                    true,
                    serde_json::json!({
                        "provider": provider.name(),
                        "client_id": oauth_client_id,
                        "email": email,
                    }),
                );
                OAuthClientRepository::get_by_id(&state.db_pool, id)
                    .await
                    .map_err(|e| ApiError::InternalError {
                        message: e.to_string(),
                    })?
                    .ok_or(ApiError::InternalError {
                        message: "Failed to read newly created client".into(),
                    })?
            }
            Err(e) => {
                return Err(ApiError::InternalError {
                    message: e.to_string(),
                })
            }
        };

    let ttl = Duration::hours(1);
    let effective_scopes = match requested_scope {
        Some(req) => req
            .split(' ')
            .map(|s| s.to_string())
            .filter(|s| client.granted_scopes.contains(s))
            .collect::<Vec<_>>(),
        None => client.granted_scopes.clone(),
    };

    let (access_token, _jti) = state
        .jwt_config
        .issue_access_token(
            client.id,
            effective_scopes.clone(),
            "human",
            None,
            None,
            ttl,
        )
        .map_err(|e| ApiError::InternalError {
            message: format!("JWT signing failed: {e}"),
        })?;

    let refresh_token = {
        use rand::Rng;
        let raw: [u8; 32] = rand::thread_rng().gen();
        let token_str = hex::encode(raw);
        let hash = blake3::hash(&raw);
        let refresh_ttl = Duration::days(30);
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
            token_type: "Bearer".into(),
            expires_in: ttl.num_seconds(),
            refresh_token: Some(refresh_token),
            scope: effective_scopes.join(" "),
        }),
    ))
}

/// Fire-and-forget audit row emit. Failure to write is logged at warn level only.
#[cfg(feature = "db")]
pub fn emit_oauth_audit(
    pool: &sqlx::PgPool,
    event_type: &str,
    success: bool,
    details: serde_json::Value,
) {
    use epigraph_db::repos::security_event::{SecurityEventRepository, SecurityEventRow};
    let pool = pool.clone();
    let row = SecurityEventRow {
        id: uuid::Uuid::new_v4(),
        event_type: event_type.to_string(),
        agent_id: None,
        success: Some(success),
        details,
        ip_address: None,
        user_agent: None,
        correlation_id: None,
        created_at: chrono::Utc::now(),
    };
    tokio::spawn(async move {
        if let Err(e) = SecurityEventRepository::log(&pool, row).await {
            tracing::warn!("Failed to persist OAuth audit event: {e}");
        }
    });
}
