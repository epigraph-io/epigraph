//! `grant_type=urn:epigraph:grant:run-token`: a short-lived DELEGATED run
//! token for an operated LLM agent, minted for a host delegator client.
//!
//! The delegator is an active `service` client on migration 149's allowlist
//! for a human operator, whose agent holds a writer membership of that
//! operator's group. It names the principal by its IDENTITY PUBLIC KEY (the
//! key a host computes for the agent it is about to run; the server cannot
//! derive a host-keyed identity itself). The token it gets is an `agent`
//! token FOR THAT PRINCIPAL: `agent_id` = the principal, `sub` = the
//! delegator client, `dlg` = the delegator's agent, at most
//! [`RUN_TOKEN_MAX_SECS`], no refresh token (the host mints again), scopes
//! inside `epigraph_auth::DELEGATED_SCOPE_CEILING`.
//!
//! What the token may READ and WRITE is never in the request. Every request
//! that carries it is admitted only while
//! `AgentRepository::delegated_principal_pool` answers (EG-D1), and its
//! viewer is the principal's own live memberships, resolved by the server on
//! that request. A request field naming a group, or asking for a scope
//! outside the ceiling, changes nothing.
//!
//! The mint asks the same liveness question first, so a token is never
//! issued for a delegation that would be refused on its first request.
//!
//! Every mint and every refusal (once the grant is on) writes one
//! `security_events` row ([`MINTED_EVENT`] / [`REFUSED_EVENT`]). A mint whose
//! row cannot be written returns no token.
//!
//! See `docs/tenancy.md` ("Delegated run tokens").

// UNSCOPED-POOL-EXEMPT: Pre-authentication, as `oauth/token.rs`: the grant mints the principal's
// token, so no Viewer can precede it; its reads are the delegator client row and three definers.

/// The grant type this module serves.
pub const RUN_TOKEN_GRANT_TYPE: &str = "urn:epigraph:grant:run-token";

/// The longest a run token lives (15 minutes; the host re-mints before it
/// lapses).
pub const RUN_TOKEN_MAX_SECS: i64 = 900;

/// The longest `run_label` (free text naming the schedule or run, audit only).
pub const RUN_LABEL_MAX_CHARS: usize = 64;

/// The audit row of a successful mint (`security_events.event_type`).
pub const MINTED_EVENT: &str = "oauth_run_token_minted";

/// The audit row of a refused mint.
pub const REFUSED_EVENT: &str = "oauth_run_token_refused";

/// The environment variable naming the LLM models a run token may be minted
/// for, read ONCE at boot ([`RunTokenModels::from_env`]).
pub const RUN_TOKEN_MODELS_ENV: &str = "EPIGRAPH_RUN_TOKEN_MODELS";

/// The LLM models (`agents.properties ->> 'llm_model'`) a run token may be
/// minted for. EMPTY in every constructor and when the variable is unset or
/// blank, and an empty list refuses EVERY mint: an operator who arms the
/// grant names the models it serves.
///
/// The list narrows which operator-linked identities a stolen delegator
/// secret could mint for (an operator's own local tooling identity, say). It
/// is not the authority check: that is the delegation's liveness
/// (`AgentRepository::delegated_principal_pool`), re-read on every request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunTokenModels(Vec<String>);

impl RunTokenModels {
    /// Parse a comma- or whitespace-separated list. Entries are trimmed;
    /// blanks and repeats are dropped; case is kept (model ids are external
    /// identifiers).
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        let mut out: Vec<String> = Vec::new();
        for entry in raw
            .unwrap_or_default()
            .split(|c: char| c == ',' || c.is_whitespace())
        {
            let entry = entry.trim();
            if !entry.is_empty() && !out.iter().any(|m| m == entry) {
                out.push(entry.to_string());
            }
        }
        Self(out)
    }

    /// [`Self::parse`] of [`RUN_TOKEN_MODELS_ENV`]. For a binary's boot only.
    #[must_use]
    pub fn from_env() -> Self {
        Self::parse(std::env::var(RUN_TOKEN_MODELS_ENV).ok().as_deref())
    }

    /// Whether `model` (trimmed) is listed.
    #[must_use]
    pub fn contains(&self, model: &str) -> bool {
        let model = model.trim();
        self.0.iter().any(|m| m == model)
    }

    /// Whether no model is listed (every mint is refused).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The listed models, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

/// A refused mint: the RFC 6749 §5.2 error, its description, and a short
/// machine reason for the audit row.
#[cfg(feature = "db")]
struct Refusal {
    error: &'static str,
    description: String,
    reason: &'static str,
}

#[cfg(feature = "db")]
fn refusal(error: &'static str, reason: &'static str, description: impl Into<String>) -> Refusal {
    Refusal {
        error,
        description: description.into(),
        reason,
    }
}

/// What the audit row of a mint or a refusal names, as far as the request got.
#[cfg(feature = "db")]
#[derive(Default)]
struct Seen {
    delegator_client: Option<uuid::Uuid>,
    delegator: Option<uuid::Uuid>,
    principal: Option<uuid::Uuid>,
}

/// `grant_type=urn:epigraph:grant:run-token`. See the module doc.
///
/// # Errors
/// `OAuthGrantError` (`unsupported_grant_type` while `EPIGRAPH_RUN_TOKENS` is
/// off; `invalid_request`, `invalid_client`, `invalid_grant`, `invalid_scope`
/// otherwise), and `InternalError` when a read fails or the mint's audit row
/// cannot be written (no token is returned then).
#[cfg(feature = "db")]
pub(crate) async fn handle_run_token_grant(
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

    // Dormant: the grant does not exist on a process that did not arm it, and
    // a dormant grant writes nothing.
    if state.run_tokens != epigraph_db::RunTokens::On {
        return Err(ApiError::OAuthGrantError {
            error: "unsupported_grant_type",
            description: format!(
                "{RUN_TOKEN_GRANT_TYPE} is not enabled on this server (EPIGRAPH_RUN_TOKENS)"
            ),
        });
    }
    let pool = &state.db_pool;
    let run_label = req.run_label.as_deref().map(str::trim).unwrap_or_default();
    let mut seen = Seen::default();
    match decide(state, pool, req, run_label, &mut seen).await? {
        Ok(minted) => {
            let row = audit_row(
                MINTED_EVENT,
                &seen,
                true,
                serde_json::json!({
                    "delegator": seen.delegator,
                    "delegator_client": seen.delegator_client,
                    "operator": minted.operator,
                    "operator_group": minted.operator_group,
                    "jti": minted.jti,
                    "exp": minted.exp,
                    "scopes": minted.scopes,
                    "run_label": run_label,
                }),
            );
            // No token without its audit row.
            epigraph_db::SecurityEventRepository::log(pool, row)
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("could not record the run-token mint; no token issued: {e}"),
                })?;
            tracing::info!(
                principal = ?seen.principal,
                delegator = ?seen.delegator,
                jti = %minted.jti,
                run_label,
                "run token minted"
            );
            Ok((
                axum::http::StatusCode::OK,
                axum::Json(crate::oauth::token::TokenResponse {
                    access_token: minted.access_token,
                    token_type: "Bearer".to_string(),
                    expires_in: RUN_TOKEN_MAX_SECS,
                    refresh_token: None,
                    scope: minted.scopes.join(" "),
                }),
            ))
        }
        Err(r) => {
            let row = audit_row(
                REFUSED_EVENT,
                &seen,
                false,
                serde_json::json!({
                    "reason": r.reason,
                    "delegator": seen.delegator,
                    "delegator_client": seen.delegator_client,
                    "principal": seen.principal,
                    "run_label": run_label.chars().take(RUN_LABEL_MAX_CHARS).collect::<String>(),
                }),
            );
            // The refusal stands whether or not its row lands.
            if let Err(e) = epigraph_db::SecurityEventRepository::log(pool, row).await {
                tracing::warn!(error = %e, reason = r.reason, "could not record a run-token refusal");
            }
            tracing::warn!(
                reason = r.reason,
                principal = ?seen.principal,
                delegator = ?seen.delegator,
                "run token refused"
            );
            Err(ApiError::OAuthGrantError {
                error: r.error,
                description: r.description,
            })
        }
    }
}

#[cfg(feature = "db")]
fn audit_row(
    event_type: &str,
    seen: &Seen,
    success: bool,
    details: serde_json::Value,
) -> epigraph_db::SecurityEventRow {
    epigraph_db::SecurityEventRow {
        id: uuid::Uuid::new_v4(),
        event_type: event_type.to_string(),
        agent_id: seen.principal,
        success: Some(success),
        details,
        ip_address: None,
        user_agent: None,
        correlation_id: None,
        created_at: chrono::Utc::now(),
    }
}

#[cfg(feature = "db")]
struct Minted {
    access_token: String,
    jti: uuid::Uuid,
    exp: i64,
    scopes: Vec<String>,
    operator: uuid::Uuid,
    operator_group: uuid::Uuid,
}

/// The grant's decision, in order: request shape, delegator client, the
/// principal, the model list, the delegation's liveness, the scopes, the
/// token. `Ok(Err(_))` is a refusal; `Err(_)` a failure to answer.
#[cfg(feature = "db")]
async fn decide(
    state: &crate::state::AppState,
    pool: &sqlx::PgPool,
    req: &crate::oauth::token::TokenRequest,
    run_label: &str,
    seen: &mut Seen,
) -> Result<Result<Minted, Refusal>, crate::errors::ApiError> {
    use crate::errors::ApiError;
    use epigraph_db::repos::oauth_client::OAuthClientRepository;
    use epigraph_db::AgentRepository;

    const CLIENT: &str = "the delegator must be an active service client presenting its secret";

    if run_label.chars().count() > RUN_LABEL_MAX_CHARS {
        return Ok(Err(refusal(
            "invalid_request",
            "run_label_too_long",
            format!("run_label is at most {RUN_LABEL_MAX_CHARS} characters"),
        )));
    }
    let (Some(client_id), Some(secret)) = (req.client_id.as_deref(), req.client_secret.as_deref())
    else {
        return Ok(Err(refusal(
            "invalid_request",
            "client_credentials_missing",
            "client_id and client_secret are required",
        )));
    };
    let Some(key) = req.agent_public_key.as_deref().and_then(parse_key) else {
        return Ok(Err(refusal(
            "invalid_request",
            "agent_public_key_invalid",
            "agent_public_key must be the principal's identity public key: 64 hex characters",
        )));
    };

    // The delegator client: exactly the service arm of client_credentials.
    let client = OAuthClientRepository::get_by_client_id(pool, client_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?;
    let Some(client) = client else {
        return Ok(Err(refusal("invalid_client", "unknown_client", CLIENT)));
    };
    seen.delegator_client = Some(client.id);
    seen.delegator = client.agent_id;
    if client.status != "active" || client.client_type != "service" {
        return Ok(Err(refusal(
            "invalid_client",
            "client_not_active_service",
            CLIENT,
        )));
    }
    let secret_ok = match (hex::decode(secret), client.client_secret_hash.as_deref()) {
        (Ok(bytes), Some(stored)) => {
            let hash = blake3::hash(&bytes);
            bool::from(subtle::ConstantTimeEq::ct_eq(
                hash.as_bytes().as_slice(),
                stored,
            ))
        }
        _ => false,
    };
    if !secret_ok {
        return Ok(Err(refusal("invalid_client", "bad_secret", CLIENT)));
    }
    // The delegator's EXISTING agent; this grant never materialises one.
    let Some(delegator) = client.agent_id else {
        return Ok(Err(refusal(
            "invalid_grant",
            "delegator_has_no_agent",
            "the delegator client has no agent yet; it is not on the author-binding allowlist",
        )));
    };

    // The principal, by its identity key. Never created here.
    let principal = AgentRepository::run_token_principal_pool(pool, &key)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("could not look up the run token's principal: {e}"),
        })?;
    let Some((principal, model)) = principal else {
        return Ok(Err(refusal(
            "invalid_grant",
            "unknown_identity",
            "no agent has this identity key: the host registers an identity before it runs it, \
             and links it to its operator (epigraph-operator link)",
        )));
    };
    seen.principal = Some(principal);

    if state.run_token_models.is_empty() {
        return Ok(Err(refusal(
            "invalid_grant",
            "no_model_allowed",
            format!("{RUN_TOKEN_MODELS_ENV} lists no model on this server"),
        )));
    }
    if !model
        .as_deref()
        .is_some_and(|m| state.run_token_models.contains(m))
    {
        return Ok(Err(refusal(
            "invalid_grant",
            "model_not_allowed",
            format!("the agent's model is not in {RUN_TOKEN_MODELS_ENV}"),
        )));
    }

    // THE authority check, the one every request will repeat.
    let live =
        AgentRepository::delegated_principal_pool(pool, state.run_tokens, delegator, principal)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("could not check the delegation: {e}"),
            })?;
    let Some(live) = live else {
        return Ok(Err(refusal(
            "invalid_grant",
            "delegation_not_live",
            "the delegation is not live: the delegator must be allowlisted for the agent's \
             operator and hold a writer membership of the operator's group, and the agent must \
             hold an acting (not retired) link to that operator",
        )));
    };

    // Scopes: asked-for (or all granted) ∩ granted ∩ the delegated ceiling,
    // then the mint chokepoint. The ceiling holds no admin-only scope, so the
    // chokepoint's would-strip recorder never sees one.
    let asked: Vec<String> = match req.scope.as_deref() {
        Some(s) => s.split_whitespace().map(str::to_string).collect(),
        None => client.granted_scopes.clone(),
    };
    let mut scopes: Vec<String> = Vec::new();
    for s in asked {
        if client.granted_scopes.contains(&s)
            && epigraph_auth::DELEGATED_SCOPE_CEILING.contains(&s.as_str())
            && !scopes.contains(&s)
        {
            scopes.push(s);
        }
    }
    let scopes = crate::oauth::scopes::grantable(
        state,
        client.id,
        scopes,
        crate::oauth::scopes::MintGrant::ClientCredentials,
    )
    .await;
    if scopes.is_empty() {
        return Ok(Err(refusal(
            "invalid_scope",
            "no_scope",
            "no requested scope is both granted to the delegator and inside the delegated ceiling",
        )));
    }

    let ttl = chrono::Duration::seconds(RUN_TOKEN_MAX_SECS);
    // No owner: the token speaks for the principal, never for whoever owns
    // the delegator client (the shape the admission sites were proved
    // against).
    let owner: Option<uuid::Uuid> = None;
    let (access_token, jti) = state
        .jwt_config
        .issue_access_token(
            client.id,
            scopes.clone(),
            "agent",
            owner,
            Some(principal),
            ttl,
            epigraph_auth::AccessTokenBinding {
                delegated_by: Some(delegator),
                ..epigraph_auth::AccessTokenBinding::NONE
            },
        )
        .map_err(|e| ApiError::InternalError {
            message: format!("JWT signing failed: {e}"),
        })?;
    // The audit row names the token's own expiry, read back from it.
    let exp = state
        .jwt_config
        .validate_token(&access_token)
        .map_err(|e| ApiError::InternalError {
            message: format!("the minted run token does not verify: {e}"),
        })?
        .exp;
    Ok(Ok(Minted {
        access_token,
        jti,
        exp,
        scopes,
        operator: live.operator_id,
        operator_group: live.operator_group_id,
    }))
}

/// 64 hex characters (either case) as 32 bytes.
#[cfg(feature = "db")]
fn parse_key(raw: &str) -> Option<[u8; 32]> {
    let raw = raw.trim();
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(raw, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::RunTokenModels;

    #[test]
    fn unset_or_blank_lists_no_model() {
        for raw in [None, Some(""), Some("  "), Some(" , ,")] {
            let m = RunTokenModels::parse(raw);
            assert!(m.is_empty(), "{raw:?}");
            assert!(!m.contains("claude-sonnet-5"), "{raw:?}");
        }
    }

    #[test]
    fn entries_are_trimmed_deduplicated_and_case_kept() {
        let m = RunTokenModels::parse(Some(" model-a, model-b  model-a\tModel-C "));
        assert_eq!(m.as_slice(), ["model-a", "model-b", "Model-C"]);
        assert!(m.contains(" model-b "));
        assert!(!m.contains("model-c"), "case is significant");
        assert!(!m.contains("model"), "no prefix match");
    }
}
