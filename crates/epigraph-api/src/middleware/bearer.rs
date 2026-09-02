//! Bearer token extraction and JWT validation middleware.
//!
//! Extracts JWT from `Authorization: Bearer <token>` header,
//! validates it, checks revocation, and injects AuthContext
//! into request extensions.

use axum::{extract::State, http::Request, middleware::Next, response::Response};

use crate::errors::ApiError;
use crate::state::AppState;

pub use epigraph_auth::{AuthContext, ClientType};

/// Middleware: extract Bearer token, validate JWT, inject AuthContext.
///
/// Requests without a valid Bearer token are rejected with 401 Unauthorized.
pub async fn bearer_auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match auth_header.as_deref() {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];

            // Check revocation set
            if state.is_token_revoked(token) {
                return Err(ApiError::Unauthorized {
                    reason: "Token has been revoked".to_string(),
                });
            }

            // Validate JWT
            let claims =
                state
                    .jwt_config
                    .validate_token(token)
                    .map_err(|e| ApiError::Unauthorized {
                        reason: format!("Invalid token: {e}"),
                    })?;

            // Build AuthContext
            let auth_ctx: AuthContext = claims.into();

            request.extensions_mut().insert(auth_ctx);
            Ok(next.run(request).await)
        }
        _ => Err(ApiError::Unauthorized {
            reason: "Missing Authorization header".to_string(),
        }),
    }
}

/// Middleware: extract Bearer token if present, validate, inject AuthContext.
///
/// Unlike [`bearer_auth_middleware`], a request WITHOUT an Authorization header
/// is allowed through with no `AuthContext` and no 401. A request WITH a
/// `Bearer` token that is revoked, malformed, or expired is rejected 401.
///
/// Since PR-03 this layers on the **anonymous allowlist router only** — the two
/// routes (`/health`, `/api/v1/openapi.json`) that are legitimately reachable
/// without a credential, plus the OAuth/discovery router which must precede
/// authentication by construction. Every route that returns claim content,
/// claim-derived structure, ACLs, embeddings or aggregates now sits behind
/// [`bearer_auth_middleware`] instead.
///
/// It is still `optional` rather than absent because an allowlisted route may
/// legitimately want to know *who* is calling when a token happens to be
/// present, and because a present-but-invalid token should 401 even on an
/// allowlisted route rather than being silently ignored.
pub async fn optional_bearer_auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match auth_header.as_deref() {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];

            // Present token must be valid: revoked → 401.
            if state.is_token_revoked(token) {
                return Err(ApiError::Unauthorized {
                    reason: "Token has been revoked".to_string(),
                });
            }

            // Present token must validate: invalid/expired → 401.
            let claims =
                state
                    .jwt_config
                    .validate_token(token)
                    .map_err(|e| ApiError::Unauthorized {
                        reason: format!("Invalid token: {e}"),
                    })?;

            let auth_ctx: AuthContext = claims.into();
            request.extensions_mut().insert(auth_ctx);
            Ok(next.run(request).await)
        }
        // No Authorization header (or a non-Bearer scheme) → anonymous pass-through.
        _ => Ok(next.run(request).await),
    }
}

/// Scope-aware `FromRequestParts` extractors.
///
/// These run BEFORE any `FromRequest` body-consuming extractor (e.g., `Json`),
/// so a wrong-scope request is rejected with 403 *before* the body is parsed.
/// This prevents the 422-instead-of-403 bug described in issue #128.
///
/// In axum, all `FromRequestParts` extractors run before any `FromRequest`
/// extractor regardless of their order in the handler signature. So a handler
/// that uses one of these extractors gets the scope check enforced at extractor
/// time, ahead of `Json<...>` parsing the body.
macro_rules! require_scope_extractor {
    ($name:ident, $scope:expr) => {
        /// Extracts `AuthContext` from request extensions and verifies the
        /// caller has the required scope. Returns 401 if no `AuthContext` is
        /// present (i.e., bearer middleware did not run / inject one), 403 if
        /// the context is present but lacks the scope.
        pub struct $name(pub AuthContext);

        #[axum::async_trait]
        impl<S: Send + Sync> axum::extract::FromRequestParts<S> for $name {
            type Rejection = ApiError;

            async fn from_request_parts(
                parts: &mut axum::http::request::Parts,
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                let auth = parts.extensions.get::<AuthContext>().cloned().ok_or(
                    ApiError::Unauthorized {
                        reason: "authentication required".into(),
                    },
                )?;
                if !auth.has_scope($scope) {
                    return Err(ApiError::Forbidden {
                        reason: format!("Missing required scope: {}", $scope),
                    });
                }
                Ok(Self(auth))
            }
        }
    };
}

require_scope_extractor!(RequireScopeAdmin, "claims:admin");
require_scope_extractor!(RequireScopeWrite, "claims:write");
require_scope_extractor!(RequireScopeWebhooksWrite, "webhooks:write");
// Group management. `groups:write` creates a group (the creator becomes its sole
// admin); `groups:admin` manages an EXISTING group's membership and is checked
// alongside a live `role='admin'` membership in that group
// (`middleware::group_authz::require_group_admin`) — scope AND membership.
// Using the extractor rather than `check_scopes` inside the handler matters
// here: these routes take a `Json` body, and an extractor rejection runs before
// body parsing, so a scope failure is 403 rather than 422 (issue #128).
require_scope_extractor!(RequireScopeGroupsWrite, "groups:write");
require_scope_extractor!(RequireScopeGroupsAdmin, "groups:admin");

/// The ONLY way an HTTP handler obtains a [`Viewer`](epigraph_db::Viewer).
///
/// Handlers take `ViewerExtractor(viewer): ViewerExtractor`, never
/// `Option<ViewerExtractor>` — an optional viewer reintroduces exactly the
/// fail-open idiom (`if let Some(auth) = auth_ctx { check() }`) that PR-03
/// exists to remove.
///
/// # When it 401s (RFC 6750 `invalid_token`)
///
/// * **No `AuthContext` in extensions** — no credential reached the handler.
///   On the protected router this should be unreachable, because
///   [`bearer_auth_middleware`] rejects first; it stays here so that a handler
///   accidentally registered on the allowlist router still fails closed.
/// * **`AuthContext.agent_id` is `None`** — a credential with no principal.
///   `Viewer::resolve` needs an `agents.id`; there is no defensible reading
///   authority to synthesise without one, and D3 removes the anonymous shape
///   that would otherwise absorb this case.
///
/// The second case is **401, not 403**. A 403 would say "you are known and the
/// answer is no", inviting the client to retry with different parameters
/// forever. The token is structurally deficient: the remedy is to re-mint it,
/// which is precisely what `invalid_token` tells the client. (An OAuth client
/// registered before PR-02 populated `oauth_clients.agent_id` mints exactly
/// this token, and re-minting after PR-02 is the fix.)
///
/// # Ordering
///
/// `FromRequestParts` runs before any `FromRequest` body extractor regardless
/// of parameter order in the handler signature (see the note on
/// [`require_scope_extractor`] above), so the 401 lands before body parse —
/// no 422-instead-of-401.
///
/// # Cost
///
/// One indexed round trip per request (`Viewer::resolve` →
/// `GroupMembershipRepository::list_live_for_agent`, served index-only by
/// `idx_group_memberships_agent_live`). PR-03 defined the extractor; PR-06 and
/// PR-07 wired it to the read paths.
#[cfg(feature = "db")]
pub struct ViewerExtractor(pub epigraph_db::Viewer);

#[cfg(feature = "db")]
#[axum::async_trait]
impl axum::extract::FromRequestParts<AppState> for ViewerExtractor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // `visibility.viewer.rejected{reason, route}` is emitted as a
        // structured tracing event rather than a Prometheus counter:
        // `metrics::Metrics` is a fixed struct of unlabeled counter handles
        // reached through an `Extension` that only `bin/server.rs` installs, so
        // a labeled counter family here would be both a new metrics-shape
        // change and unavailable in every test router.
        let route = parts.uri.path().to_string();

        let Some(auth) = parts.extensions.get::<AuthContext>().cloned() else {
            tracing::warn!(
                target: "visibility.viewer.rejected",
                reason = "no_auth_context",
                route = %route,
                "viewer rejected: request carried no AuthContext"
            );
            return Err(ApiError::Unauthorized {
                reason: "authentication required".into(),
            });
        };

        let Some(principal) = auth.agent_id else {
            tracing::warn!(
                target: "visibility.viewer.rejected",
                reason = "no_agent_id",
                route = %route,
                client_id = %auth.client_id,
                "viewer rejected: token carries no agent_id; re-mint the token"
            );
            return Err(ApiError::Unauthorized {
                reason: "token carries no agent_id; re-authenticate to obtain \
                         a token bound to a principal"
                    .into(),
            });
        };

        let viewer = epigraph_db::Viewer::resolve(&state.db_pool, principal)
            .await
            .map_err(|e| {
                tracing::error!(
                    route = %route,
                    principal = %principal,
                    error = %e,
                    "failed to resolve viewer group membership"
                );
                ApiError::from(e)
            })?;

        Ok(Self(viewer))
    }
}

/// The `not(feature = "db")` stand-in for [`Viewer`](epigraph_db::Viewer).
///
/// Without the `db` feature there is no `epigraph_db`, hence no `Viewer`, no
/// pool to resolve group membership against, and no corpus to filter — the
/// in-memory services that back the `not(db)` router hold no tenancy state at
/// all. This type exists so that the *shape* of a read handler is identical in
/// both configurations: one `ViewerExtractor` parameter, one authentication
/// precondition, no `#[cfg]` fork in the signature.
///
/// It deliberately carries no authority and exposes no accessor. Anything that
/// would consume a real `Viewer` is inside a `#[cfg(feature = "db")]` block by
/// construction, because the repo layer it would call only exists there.
#[cfg(not(feature = "db"))]
#[derive(Debug, Clone, Copy)]
pub struct NoDbViewer;

/// The ONLY way an HTTP handler obtains a viewer under `not(feature = "db")`.
///
/// See the `db` variant above for the full contract. This one enforces the
/// **same two 401 branches in the same order** — no `AuthContext`, then
/// `agent_id == None` — and emits the same `visibility.viewer.rejected`
/// tracing events, so a handler fails closed identically in both builds. The
/// only step it omits is `Viewer::resolve`, which has no meaning without a
/// pool.
///
/// Keeping the authentication precondition here rather than degrading to an
/// infallible extractor is the point: if the two builds disagreed about when a
/// read is refused, the `not(db)` configuration would be a strictly weaker
/// second implementation of the same route table, and CI checks it
/// (`.github/workflows/ci.yml`, `cargo check -p epigraph-api
/// --no-default-features --locked`).
#[cfg(not(feature = "db"))]
pub struct ViewerExtractor(pub NoDbViewer);

#[cfg(not(feature = "db"))]
#[axum::async_trait]
impl axum::extract::FromRequestParts<AppState> for ViewerExtractor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let route = parts.uri.path().to_string();

        let Some(auth) = parts.extensions.get::<AuthContext>().cloned() else {
            tracing::warn!(
                target: "visibility.viewer.rejected",
                reason = "no_auth_context",
                route = %route,
                "viewer rejected: request carried no AuthContext"
            );
            return Err(ApiError::Unauthorized {
                reason: "authentication required".into(),
            });
        };

        if auth.agent_id.is_none() {
            tracing::warn!(
                target: "visibility.viewer.rejected",
                reason = "no_agent_id",
                route = %route,
                client_id = %auth.client_id,
                "viewer rejected: token carries no agent_id; re-mint the token"
            );
            return Err(ApiError::Unauthorized {
                reason: "token carries no agent_id; re-authenticate to obtain \
                         a token bound to a principal"
                    .into(),
            });
        }

        Ok(Self(NoDbViewer))
    }
}

#[cfg(test)]
mod require_scope_tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use axum::http::Request;

    fn parts_with_scopes(scopes: &[&str]) -> axum::http::request::Parts {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        parts.extensions.insert(AuthContext {
            client_id: uuid::Uuid::nil(),
            agent_id: None,
            owner_id: None,
            client_type: ClientType::Service,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: uuid::Uuid::nil(),
        });
        parts
    }

    #[tokio::test]
    async fn require_scope_admin_missing_context_returns_401() {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        let r: Result<RequireScopeAdmin, _> =
            RequireScopeAdmin::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Unauthorized { .. })));
    }

    #[tokio::test]
    async fn require_scope_admin_wrong_scope_returns_403() {
        let mut parts = parts_with_scopes(&["claims:read"]);
        let r: Result<RequireScopeAdmin, _> =
            RequireScopeAdmin::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Forbidden { .. })));
    }

    #[tokio::test]
    async fn require_scope_admin_with_scope_succeeds() {
        let mut parts = parts_with_scopes(&["claims:admin"]);
        let r = RequireScopeAdmin::from_request_parts(&mut parts, &())
            .await
            .expect("should succeed");
        assert!(r.0.has_scope("claims:admin"));
    }

    #[tokio::test]
    async fn require_scope_write_wrong_scope_returns_403() {
        let mut parts = parts_with_scopes(&["claims:read"]);
        let r: Result<RequireScopeWrite, _> =
            RequireScopeWrite::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Forbidden { .. })));
    }

    #[tokio::test]
    async fn require_scope_webhooks_write_wrong_scope_returns_403() {
        let mut parts = parts_with_scopes(&["claims:read"]);
        let r: Result<RequireScopeWebhooksWrite, _> =
            RequireScopeWebhooksWrite::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Forbidden { .. })));
    }
}

/// `ViewerExtractor`'s two rejection paths.
///
/// Both are reached before `Viewer::resolve` is called, so neither test needs a
/// database. The success path (`agent_id: Some(_)` → a `Scoped` viewer) does
/// need one and lives in `crates/epigraph-api/tests/` alongside the other
/// pool-backed tests; asserting it here would mean standing up a pool inside a
/// `--lib` unit test, which nothing else in this crate does.
///
/// These two tests are, in PR-03, the ONLY thing that exercises
/// `ViewerExtractor` at all — it is defined here and attached to no handler
/// until PR-07.
#[cfg(all(test, feature = "db"))]
mod viewer_extractor_tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use axum::http::Request;
    use axum::response::IntoResponse;
    use uuid::Uuid;

    fn parts_with_auth(auth: Option<AuthContext>) -> axum::http::request::Parts {
        let req = Request::builder()
            .uri("/api/v1/claims/00000000-0000-0000-0000-000000000000")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        if let Some(auth) = auth {
            parts.extensions.insert(auth);
        }
        parts
    }

    fn auth_ctx(agent_id: Option<Uuid>) -> AuthContext {
        AuthContext {
            client_id: Uuid::new_v4(),
            agent_id,
            owner_id: None,
            client_type: ClientType::Service,
            scopes: vec!["claims:read".to_string()],
            jti: Uuid::new_v4(),
        }
    }

    /// A pool that is never connected to. Both rejection paths return before
    /// `Viewer::resolve` touches it, so lazy connection is never triggered.
    fn unconnected_state() -> AppState {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool construction does not connect");
        AppState::with_db(pool, crate::state::ApiConfig::default())
    }

    #[tokio::test]
    async fn missing_auth_context_is_401() {
        let state = unconnected_state();
        let mut parts = parts_with_auth(None);
        let r: Result<ViewerExtractor, _> =
            ViewerExtractor::from_request_parts(&mut parts, &state).await;
        assert!(
            matches!(r, Err(ApiError::Unauthorized { .. })),
            "no credential must be 401, never a viewer"
        );
    }

    #[tokio::test]
    async fn auth_context_without_agent_id_is_401_invalid_token() {
        let state = unconnected_state();
        let mut parts = parts_with_auth(Some(auth_ctx(None)));
        let r: Result<ViewerExtractor, _> =
            ViewerExtractor::from_request_parts(&mut parts, &state).await;

        let err = match r {
            Err(e) => e,
            Ok(_) => panic!("a token with no agent_id must not yield a Viewer"),
        };
        assert!(
            matches!(err, ApiError::Unauthorized { .. }),
            "a principal-less token is 401 (re-mint), not 403 (you are known \
             and the answer is no)"
        );

        // The client has to be able to *tell* that re-minting is the fix, which
        // is what the RFC 6750 challenge says.
        let response = err.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let challenge = response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .expect("401 carries a WWW-Authenticate challenge")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            challenge.contains(r#"error="invalid_token""#),
            "got: {challenge}"
        );
    }
}
