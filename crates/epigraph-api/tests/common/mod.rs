use std::net::SocketAddr;
use tokio::sync::oneshot;

pub async fn spawn_app(database_url: &str) -> (SocketAddr, oneshot::Sender<()>) {
    let app = epigraph_api::build_app_for_tests(database_url).await
        .expect("app builds for tests");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async { let _ = rx.await; })
            .await
            .unwrap();
    });
    (addr, tx)
}

/// Returns a real signed JWT that the production bearer_auth_middleware will accept.
/// Uses the same secret-fallback logic as `AppState::default_jwt_config`.
pub fn test_bearer_token() -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _jti) = cfg
        .issue_access_token(
            uuid::Uuid::new_v4(),
            vec!["graph:read".into()],
            "service",
            None,
            None,
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    token
}
