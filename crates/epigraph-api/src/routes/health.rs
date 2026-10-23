use axum::Json;
use serde::Serialize;

/// Health check response structure
#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The belief modes this process read from its environment at startup
    /// (SPEC §10.2): `atom_fold`, `compound_belief`, `compound_write_guard`,
    /// `compound_source_edges`, `atom_cache_mode`, `inference`, `bp_apply`.
    /// A reported mode is not necessarily acted on by this build; see
    /// `epigraph_engine::belief_modes` for which ones are.
    /// The pre-flip mode check (SPEC §10.4) compares this report across every
    /// live process, and a CLI wave
    /// bin refuses a writing run when its own modes differ from it.
    #[schema(value_type = Object)]
    pub belief_modes: epigraph_engine::belief_modes::BeliefModes,
}

/// Health check endpoint
///
/// Returns the service status, version, current timestamp and the belief
/// modes this process runs under.
/// This endpoint is useful for monitoring and load balancer health checks.
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now(),
        belief_modes: *epigraph_engine::belief_modes::current(),
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
