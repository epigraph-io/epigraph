use axum::Json;
use serde::Serialize;

/// Health check response structure
#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Health check endpoint
///
/// Returns the service status, version, and current timestamp.
/// This endpoint is useful for monitoring and load balancer health checks.
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert_eq!(response.0.status, "healthy");
        assert_eq!(response.0.version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn test_health_check_timestamp() {
        let before = chrono::Utc::now();
        let response = health_check().await;
        let after = chrono::Utc::now();

        assert!(response.0.timestamp >= before);
        assert!(response.0.timestamp <= after);
    }
}
