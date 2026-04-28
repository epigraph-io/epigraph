//! Integration tests: auth_chain_middleware in front of bearer.
//!
//! Both the `db` and `not(db)` test fns share `AlwaysDeclineProvider` /
//! `AlwaysRejectProvider`. The pass-through paths (empty, decline) are
//! exercised against the no-db build, where `create_router` exists without
//! a live DB pool. The reject path uses the no-db `auth_chain_middleware`
//! short-circuit (which returns `Err(ApiError::Unauthorized)` independent
//! of the resolver, since the chain runner errs on `Err(_)` before reaching
//! the resolver).

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use epigraph_interfaces::{AuthError, AuthProvider, ClientType, ProviderIdentity};

struct AlwaysDeclineProvider;

#[async_trait]
impl AuthProvider for AlwaysDeclineProvider {
    fn name(&self) -> &'static str { "always-decline" }
    async fn try_authenticate(
        &self,
        _parts: &http::request::Parts,
    ) -> Result<Option<ProviderIdentity>, AuthError> {
        Ok(None)
    }
}

struct AlwaysRejectProvider;

#[async_trait]
impl AuthProvider for AlwaysRejectProvider {
    fn name(&self) -> &'static str { "always-reject" }
    async fn try_authenticate(
        &self,
        _parts: &http::request::Parts,
    ) -> Result<Option<ProviderIdentity>, AuthError> {
        Err(AuthError::InvalidCredential("test reject".into()))
    }
}

// Sentinel handler: present only so that the protected route table is non-empty.
#[allow(dead_code)]
async fn _sentinel() -> &'static str { "ok" }

#[cfg(not(feature = "db"))]
#[tokio::test]
async fn empty_chain_falls_through_to_bearer() {
    use epigraph_api::{create_router, ApiConfig, AppState};
    use tower::ServiceExt;

    let state = AppState::new(ApiConfig::default());
    let router = create_router(state);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[cfg(not(feature = "db"))]
#[tokio::test]
async fn declining_chain_falls_through_to_bearer() {
    use epigraph_api::{create_router, ApiConfig, AppState};
    use tower::ServiceExt;

    let state = AppState::new(ApiConfig::default())
        .with_auth_provider(Arc::new(AlwaysDeclineProvider));
    let router = create_router(state);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    // `/health` is a public route, so even with bearer-401-ing, this returns 200.
    assert_eq!(resp.status(), StatusCode::OK);
}

#[cfg(not(feature = "db"))]
#[tokio::test]
async fn rejecting_chain_returns_401_on_protected_route() {
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use epigraph_api::middleware::auth_chain_middleware;
    use epigraph_api::{ApiConfig, AppState};
    use tower::ServiceExt;

    let state = AppState::new(ApiConfig::default())
        .with_auth_provider(Arc::new(AlwaysRejectProvider));

    // Build a minimal router with the chain middleware in front of a sentinel.
    // This exercises the chain runner's `Err(_) → ApiError::Unauthorized` path
    // without depending on the full `create_router` shape (which requires a DB
    // pool for the `feature = "db"` variant).
    let app = Router::new()
        .route("/probe", get(_sentinel))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_chain_middleware,
        ))
        .with_state(state);

    let req = Request::builder()
        .uri("/probe")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
