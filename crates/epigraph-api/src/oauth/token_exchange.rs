//! `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693):
//! exchange a KERNEL access token for a short-lived token whose audience is a
//! mounted federation extension (backlog c9b82fae).
//!
//! The MCP federation gateway calls this once per federated `tools/call` and
//! forwards ONLY the token it gets back, never the caller's own bearer, so an
//! extension never holds a token the kernel would admit (the confused-deputy
//! "token passthrough" the MCP authorization spec forbids; design
//! `docs/superpowers/specs/2026-09-26-episcience-operator-authority-design.md`
//! section 2).
//!
//! What is minted ([`epigraph_auth::JwtConfig::exchange_token`]): the same
//! principal as the subject (`sub`, `agent_id`, `owner_id`, `client_type`),
//! `aud` = the extension, scopes no wider than the subject's (a `scope`
//! parameter may narrow them), at most
//! [`epigraph_auth::EXCHANGED_TOKEN_MAX_SECS`] and never past the subject's
//! own `exp`, no refresh token, no `fam`/`elv`/`dlg`. The kernel's validator
//! refuses it on every kernel route (its `aud` is not the kernel's).
//!
//! Refused, besides what that function refuses (an audience that is not a
//! configured extension, a subject that is not a plain live kernel token, a
//! wider scope): a subject whose `jti` is on the revocation denylist, and a
//! subject whose OAuth client is no longer `active`. Those two are why this
//! runs at the token endpoint rather than in the gateway: a suspended client
//! gets no extension token, and its last one lapses within five minutes.
//!
//! The configured extensions are [`TokenExchangeAudiences`], read once at
//! boot from [`TOKEN_EXCHANGE_AUDIENCES_ENV`]. Empty (the default) refuses
//! every exchange with `invalid_target`.
//!
//! The grant does not authenticate a client: the subject token IS the
//! credential, and what it yields is a narrower, shorter-lived token for the
//! same principal that no kernel route admits. RFC 8693 `actor_token` / `act`
//! is not implemented.

// UNSCOPED-POOL-EXEMPT: Pre-authentication, as `oauth/token.rs`: the grant mints a token from a
// bearer the request carries, so no Viewer precedes it; its reads are the revocation denylist and
// the subject's client row.

/// The environment variable naming the federation extensions (by the name
/// the gateway mounts them under in `EPIGRAPH_MCP_EXTENSIONS`) a token may be
/// exchanged for.
pub const TOKEN_EXCHANGE_AUDIENCES_ENV: &str = "EPIGRAPH_TOKEN_EXCHANGE_AUDIENCES";

/// The audiences the token-exchange grant may mint for. EMPTY in every
/// constructor and when the variable is unset or blank, and an empty list
/// refuses every exchange.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenExchangeAudiences(Vec<String>);

impl TokenExchangeAudiences {
    /// Parse a comma- or whitespace-separated list. Entries are trimmed;
    /// blanks, repeats and the kernel's own audience
    /// ([`epigraph_auth::KERNEL_AUDIENCE`]) are dropped.
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        let mut out: Vec<String> = Vec::new();
        for entry in raw
            .unwrap_or_default()
            .split(|c: char| c == ',' || c.is_whitespace())
        {
            let entry = entry.trim();
            if !entry.is_empty()
                && entry != epigraph_auth::KERNEL_AUDIENCE
                && !out.iter().any(|a| a == entry)
            {
                out.push(entry.to_string());
            }
        }
        Self(out)
    }

    /// [`Self::parse`] of [`TOKEN_EXCHANGE_AUDIENCES_ENV`]. For a binary's boot only.
    #[must_use]
    pub fn from_env() -> Self {
        Self::parse(std::env::var(TOKEN_EXCHANGE_AUDIENCES_ENV).ok().as_deref())
    }

    /// The configured audiences, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

#[cfg(feature = "db")]
fn grant_error(error: &'static str, description: impl Into<String>) -> crate::errors::ApiError {
    crate::errors::ApiError::OAuthGrantError {
        error,
        description: description.into(),
    }
}

/// `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`. See the module doc.
///
/// # Errors
/// `OAuthGrantError` (`invalid_request`, `invalid_target`, `invalid_grant`,
/// `invalid_scope`); `InternalError` / `ServiceUnavailable` when a liveness
/// read cannot answer (no token is issued then).
#[cfg(feature = "db")]
pub(crate) async fn handle_token_exchange_grant(
    state: &crate::state::AppState,
    req: &crate::oauth::token::TokenRequest,
) -> Result<
    (
        axum::http::StatusCode,
        axum::Json<crate::oauth::token::TokenResponse>,
    ),
    crate::errors::ApiError,
> {
    use crate::errors::ApiError;
    use epigraph_auth::ACCESS_TOKEN_TYPE;
    use epigraph_db::repos::oauth_client::OAuthClientRepository;

    let subject_token = req
        .subject_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| grant_error("invalid_request", "subject_token is required"))?;
    match req.subject_token_type.as_deref() {
        Some(ACCESS_TOKEN_TYPE) => {}
        Some(other) => {
            return Err(grant_error(
                "invalid_request",
                format!("subject_token_type `{other}` is not supported; use {ACCESS_TOKEN_TYPE}"),
            ))
        }
        None => {
            return Err(grant_error(
                "invalid_request",
                "subject_token_type is required",
            ))
        }
    }
    if let Some(other) = req
        .requested_token_type
        .as_deref()
        .filter(|t| *t != ACCESS_TOKEN_TYPE)
    {
        return Err(grant_error(
            "invalid_request",
            format!("requested_token_type `{other}` is not supported; only {ACCESS_TOKEN_TYPE}"),
        ));
    }
    let audience = req.audience.as_deref().unwrap_or_default();
    let requested: Option<Vec<String>> = req
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect());

    let exchanged = state
        .jwt_config
        .exchange_token(
            subject_token,
            audience,
            state.token_exchange_audiences.as_slice(),
            requested.as_deref(),
        )
        .map_err(|refusal| {
            tracing::info!(
                audience,
                error = refusal.oauth_error(),
                reason = refusal.description(),
                "token exchange refused"
            );
            grant_error(refusal.oauth_error(), refusal.description())
        })?;

    // Liveness of the SUBJECT, read before the minted token leaves this
    // function. A revoked subject is refused like an invalid one; an
    // unanswerable lookup refuses too (fail closed).
    match crate::middleware::bearer::access_token_is_revoked(state, exchanged.subject.jti).await {
        Ok(false) => {}
        Ok(true) => {
            tracing::info!(audience, jti = %exchanged.subject.jti, "token exchange refused: subject revoked");
            return Err(grant_error(
                "invalid_grant",
                "subject_token is not a valid, unexpired kernel access token",
            ));
        }
        Err(e) => {
            tracing::error!(error = %e, "token exchange refused: the revocation lookup failed");
            return Err(ApiError::ServiceUnavailable {
                service: "token revocation status".to_string(),
            });
        }
    }
    let client = OAuthClientRepository::get_by_id(&state.db_pool, exchanged.subject.sub)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("token exchange: client lookup failed: {e}"),
        })?;
    if !client.is_some_and(|c| c.status == "active") {
        tracing::info!(
            audience,
            client = %exchanged.subject.sub,
            "token exchange refused: the subject's client is not active"
        );
        return Err(grant_error(
            "invalid_grant",
            "the subject token's client is not active",
        ));
    }

    let now = chrono::Utc::now().timestamp();
    tracing::info!(
        audience,
        client = %exchanged.subject.sub,
        agent = ?exchanged.claims.agent_id,
        subject_jti = %exchanged.subject.jti,
        jti = %exchanged.claims.jti,
        "token exchanged for a federation extension"
    );
    Ok((
        axum::http::StatusCode::OK,
        axum::Json(crate::oauth::token::TokenResponse {
            access_token: exchanged.token,
            token_type: "Bearer".to_string(),
            expires_in: (exchanged.claims.exp - now).max(0),
            refresh_token: None,
            scope: exchanged.claims.scopes.join(" "),
            issued_token_type: Some(ACCESS_TOKEN_TYPE.to_string()),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's own audience can never be configured as an exchange
    /// target, and blanks/repeats are dropped. Mutation: the kernel-audience
    /// filter removed -> `epigraph-api` survives the parse.
    #[test]
    fn the_audience_list_never_holds_the_kernel_audience() {
        let parsed =
            TokenExchangeAudiences::parse(Some(" episcience, epigraph-api ,,episcience other "));
        assert_eq!(parsed.as_slice(), ["episcience", "other"]);
        assert!(TokenExchangeAudiences::parse(None).as_slice().is_empty());
        assert!(TokenExchangeAudiences::parse(Some("  "))
            .as_slice()
            .is_empty());
    }
}
