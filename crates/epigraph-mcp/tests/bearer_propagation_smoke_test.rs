//! Smoke test: verify that axum's `request.extensions_mut().insert(_)` flows
//! through into the http::request::Parts that downstream code can read.
//!
//! This pattern is what rmcp's StreamableHttpService relies on to deliver
//! AuthContext into RequestContext for the scope guard in Task 3. If this
//! test fails, the whole Bearer-auth design is wrong and Tasks 2/3 need to
//! be revisited before any further work.

use std::sync::Arc;

use axum::{middleware, Router};
use epigraph_auth::{AuthContext, ClientType};
use uuid::Uuid;

#[derive(Clone)]
struct Probe(Arc<std::sync::Mutex<Option<AuthContext>>>);

async fn inject_dummy_auth(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let auth = AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: None,
        owner_id: None,
        client_type: ClientType::Service,
        scopes: vec!["claims:read".into()],
        jti: Uuid::new_v4(),
    };
    req.extensions_mut().insert(auth);
    next.run(req).await
}

#[tokio::test]
async fn axum_middleware_extension_reaches_handler_via_parts() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let probe = Probe(Arc::new(std::sync::Mutex::new(None)));
    let probe_for_handler = probe.clone();

    let router: Router = Router::new()
        .route(
            "/mcp",
            axum::routing::post(move |req: Request<Body>| {
                let probe = probe_for_handler.clone();
                async move {
                    let (parts, _body) = req.into_parts();
                    let auth = parts.extensions.get::<AuthContext>().cloned();
                    *probe.0.lock().unwrap() = auth;
                    StatusCode::OK
                }
            }),
        )
        .layer(middleware::from_fn(inject_dummy_auth));

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let captured = probe.0.lock().unwrap().clone().expect(
        "AuthContext inserted by axum middleware should appear in the downstream handler's Parts.extensions",
    );
    assert!(captured.has_scope("claims:read"));
}
