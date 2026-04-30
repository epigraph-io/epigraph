//! /api/v1/policies/* — labeled-claim view over network access policies.
//!
//! All policies are stored as ordinary claims with `policy:active` and
//! `policy:network` labels and `host`/`port`/`protocol`/`decay_exempt`
//! fields in `properties`. Challenges are claims with `policy:challenge`
//! and a `status` field in `properties`.
//!
//! Reference implementation: `epigraph-nano/src/persistence.rs:7332-7530`.

#[cfg(feature = "db")]
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
#[cfg(feature = "db")]
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::{errors::ApiError, AppState};

#[derive(Debug, Deserialize)]
pub struct ListPoliciesQuery {
    #[serde(default = "default_min_truth")]
    pub min_truth: f64,
}
const fn default_min_truth() -> f64 {
    0.5
}

#[derive(Debug, Deserialize)]
pub struct OutcomeRequest {
    pub supports: bool,
    pub strength: f64,
}

#[derive(Debug, Deserialize)]
pub struct CreateChallengeRequest {
    pub host: String,
    pub port: i64,
    pub protocol: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveChallengeRequest {
    pub approved: bool,
}

/// GET /api/v1/policies/network — list active network-access policies.
#[cfg(feature = "db")]
pub async fn list_network_policies(
    State(state): State<AppState>,
    Query(params): Query<ListPoliciesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let min_truth = params.min_truth.clamp(0.0, 1.0);
    let rows: Vec<(Uuid, f64, serde_json::Value)> = sqlx::query_as(
        "SELECT id, truth_value, properties \
         FROM claims \
         WHERE 'policy:active' = ANY(labels) \
           AND 'policy:network' = ANY(labels) \
           AND truth_value >= $1 \
         ORDER BY truth_value DESC",
    )
    .bind(min_truth)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to list policies: {e}"),
    })?;

    let policies: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, truth_value, properties)| {
            serde_json::json!({
                "claim_id": id,
                "host": properties.get("host"),
                "port": properties.get("port"),
                "protocol": properties.get("protocol"),
                "truth_value": truth_value,
                "decay_exempt": properties.get("decay_exempt").and_then(|v| v.as_bool()).unwrap_or(false),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "policies": policies })))
}

/// POST /api/v1/policies/:claim_id/outcome — Bayesian-style nudge.
///
/// `supports = true` increases truth toward 1.0; `false` decreases.
/// `strength` is the magnitude in (0, 1]; clamped server-side.
#[cfg(feature = "db")]
pub async fn record_outcome(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Json(req): Json<OutcomeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let strength = req.strength.clamp(0.0, 1.0);
    let signed = if req.supports { strength } else { -strength };

    // Same closed-form update as epigraph-nano/src/persistence.rs:7430.
    let row: Option<(f64,)> = sqlx::query_as(
        "UPDATE claims SET \
            truth_value = LEAST(0.99, GREATEST(0.01, \
                truth_value + $1 * (1.0 - truth_value) * \
                CASE WHEN $1 > 0 THEN 1.0 ELSE truth_value END)), \
            updated_at = NOW() \
         WHERE id = $2 AND 'policy:active' = ANY(labels) \
         RETURNING truth_value",
    )
    .bind(signed)
    .bind(claim_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to update policy outcome: {e}"),
    })?;

    let new_truth = row
        .ok_or(ApiError::NotFound {
            entity: "policy".to_string(),
            id: claim_id.to_string(),
        })?
        .0;

    Ok(Json(serde_json::json!({
        "claim_id": claim_id,
        "truth_value": new_truth,
    })))
}

/// POST /api/v1/policies/decay-sweep — pull stale active policies toward 0.5.
///
/// Skips claims with `properties->>'decay_exempt' = 'true'`. Returns the
/// number of rows updated.
#[cfg(feature = "db")]
pub async fn decay_sweep(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = sqlx::query(
        "UPDATE claims SET \
            truth_value = truth_value + 0.1 * (0.5 - truth_value), \
            updated_at = NOW() \
         WHERE 'policy:active' = ANY(labels) \
           AND COALESCE((properties->>'decay_exempt')::boolean, false) IS NOT TRUE \
           AND updated_at < NOW() - INTERVAL '90 days'",
    )
    .execute(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Decay sweep failed: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "rows_affected": result.rows_affected(),
    })))
}

#[cfg(all(test, feature = "db"))]
mod tests {
    use super::*;
    use crate::state::{ApiConfig, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use axum::Router;
    use http_body_util::BodyExt;
    use sqlx::PgPool;
    use tower::ServiceExt;
    use uuid::Uuid;

    // ── Test scaffolding ──

    /// Build a minimal AppState backed by the given pool.
    fn test_state(pool: PgPool) -> AppState {
        AppState::with_db(pool, ApiConfig::default())
    }

    /// Build a router exposing the policy routes under test.
    fn policy_router(state: AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/policies/network",
                get(list_network_policies),
            )
            .route(
                "/api/v1/policies/:claim_id/outcome",
                post(record_outcome),
            )
            .route(
                "/api/v1/policies/decay-sweep",
                post(decay_sweep),
            )
            .with_state(state)
    }

    /// Insert a system agent (mirrors `get_or_create_system_agent` but without
    /// going through the public API) and return its id.
    async fn ensure_system_agent(pool: &PgPool) -> Uuid {
        let pub_key = vec![0u8; 32];
        if let Some(id) = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM agents WHERE public_key = $1",
        )
        .bind(&pub_key)
        .fetch_optional(pool)
        .await
        .unwrap()
        {
            return id;
        }
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
        )
        .bind(&pub_key)
        .bind("api-system-test")
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Insert a claim labeled `policy:active` + `policy:network` with the
    /// given network attributes in `properties`.
    async fn seed_policy(
        pool: &PgPool,
        host: &str,
        port: i64,
        protocol: &str,
        truth: f64,
        decay_exempt: bool,
    ) -> Uuid {
        let agent_id = ensure_system_agent(pool).await;
        let content = format!("policy:network {host}:{port}/{protocol}");
        let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
             VALUES ($1, $2, $3, $4, ARRAY['policy:active','policy:network'], $5) RETURNING id",
        )
        .bind(&content)
        .bind(content_hash.as_slice())
        .bind(agent_id)
        .bind(truth)
        .bind(serde_json::json!({
            "host": host,
            "port": port,
            "protocol": protocol,
            "decay_exempt": decay_exempt,
        }))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Like `seed_policy` but additionally backdates `updated_at` to simulate
    /// a stale or fresh policy. Used by the decay sweep test.
    ///
    /// The `claims_updated_at` trigger normally forces `updated_at = NOW()`
    /// on every UPDATE, so we temporarily disable user triggers around the
    /// backdating UPDATE.
    async fn seed_policy_with_age(
        pool: &PgPool,
        host: &str,
        port: i64,
        protocol: &str,
        truth: f64,
        decay_exempt: bool,
        days_old: i64,
    ) -> Uuid {
        let id = seed_policy(pool, host, port, protocol, truth, decay_exempt).await;
        sqlx::query("ALTER TABLE claims DISABLE TRIGGER claims_updated_at")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE claims SET updated_at = NOW() - ($2 || ' days')::interval WHERE id = $1")
            .bind(id)
            .bind(days_old.to_string())
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE claims ENABLE TRIGGER claims_updated_at")
            .execute(pool)
            .await
            .unwrap();
        id
    }

    async fn parse_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ── Tests ──

    #[sqlx::test(migrations = "../../migrations")]
    async fn list_network_policies_returns_active_policies_above_min_truth(pool: PgPool) {
        seed_policy(&pool, "example.com", 443, "https", 0.92, false).await;
        seed_policy(&pool, "blocked.com", 443, "https", 0.10, false).await;
        let state = test_state(pool.clone());

        let router = policy_router(state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/policies/network?min_truth=0.5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = parse_body(response).await;
        let policies = body["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0]["host"], "example.com");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn outcome_supports_true_increases_truth_value(pool: PgPool) {
        let claim_id = seed_policy(&pool, "example.com", 443, "https", 0.5, false).await;
        let state = test_state(pool.clone());

        let router = policy_router(state.clone());
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/v1/policies/{claim_id}/outcome"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"supports": true, "strength": 0.05}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let new_truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(new_truth > 0.5, "expected truth to increase, got {new_truth}");
        assert!(new_truth <= 0.99);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn decay_sweep_pulls_stale_truth_toward_one_half(pool: PgPool) {
        let stale_id = seed_policy_with_age(&pool, "stale.com", 443, "https", 0.9, false, 100).await;
        let fresh_id = seed_policy_with_age(&pool, "fresh.com", 443, "https", 0.9, false, 1).await;
        let exempt_id = seed_policy_with_age(&pool, "exempt.com", 443, "https", 0.9, true, 100).await;
        let state = test_state(pool.clone());

        let router = policy_router(state);
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/policies/decay-sweep")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = parse_body(response).await;
        assert_eq!(body["rows_affected"], 1);

        let stale_truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
            .bind(stale_id)
            .fetch_one(&pool).await.unwrap();
        assert!(stale_truth < 0.9 && stale_truth > 0.5,
            "stale should have decayed toward 0.5; got {stale_truth}");

        let fresh_truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
            .bind(fresh_id).fetch_one(&pool).await.unwrap();
        assert_eq!(fresh_truth, 0.9, "fresh policy must not decay");

        let exempt_truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
            .bind(exempt_id).fetch_one(&pool).await.unwrap();
        assert_eq!(exempt_truth, 0.9, "decay_exempt policy must not decay");
    }
}
