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
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(claim_id): Path<Uuid>,
    Json(req): Json<OutcomeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "record_outcome requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;
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

/// POST /api/v1/policy-challenges — create a pending challenge claim.
#[cfg(feature = "db")]
pub async fn create_challenge(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(req): Json<CreateChallengeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "create_challenge requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:write"])?;
    let sys_agent_id = crate::routes::workflows::get_or_create_system_agent(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to resolve system agent: {e}"),
        })?;

    let content = format!(
        "Network access challenge: {}:{} ({})",
        req.host,
        req.port,
        req.protocol.as_deref().unwrap_or("any")
    );
    let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
         VALUES ($1, $2, $3, 0.5, ARRAY['policy','policy:challenge'], $4) \
         RETURNING id",
    )
    .bind(&content)
    .bind(content_hash.as_slice())
    .bind(sys_agent_id)
    .bind(serde_json::json!({
        "host": req.host,
        "port": req.port,
        "protocol": req.protocol,
        "status": "pending",
    }))
    .fetch_one(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create challenge: {e}"),
    })?;

    Ok(Json(serde_json::json!({ "id": id })))
}

/// GET /api/v1/policy-challenges/:id — fetch a challenge by ID.
#[cfg(feature = "db")]
pub async fn get_challenge(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row: Option<(Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT id, properties FROM claims \
         WHERE id = $1 AND 'policy:challenge' = ANY(labels)",
    )
    .bind(id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to fetch challenge: {e}"),
    })?;

    let (id, properties) = row.ok_or(ApiError::NotFound {
        entity: "policy-challenge".to_string(),
        id: id.to_string(),
    })?;

    Ok(Json(serde_json::json!({
        "id": id,
        "host": properties.get("host"),
        "port": properties.get("port"),
        "protocol": properties.get("protocol"),
        "status": properties.get("status"),
    })))
}

/// POST /api/v1/policy-challenges/:id/resolve — approve or deny.
///
/// On `approved=false`, also strengthens the default-deny policy claim
/// by +0.03 (capped at 0.99). Default-deny is identified by host='*' in properties.
#[cfg(feature = "db")]
pub async fn resolve_challenge(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(req): Json<ResolveChallengeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "resolve_challenge requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;
    let new_status = if req.approved { "approved" } else { "denied" };

    let updated: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE claims SET \
            properties = jsonb_set(properties, '{status}', to_jsonb($2::text), true), \
            updated_at = NOW() \
         WHERE id = $1 AND 'policy:challenge' = ANY(labels) \
         RETURNING id",
    )
    .bind(id)
    .bind(new_status)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to resolve challenge: {e}"),
    })?;

    if updated.is_none() {
        return Err(ApiError::NotFound {
            entity: "policy-challenge".to_string(),
            id: id.to_string(),
        });
    }

    if !req.approved {
        sqlx::query(
            "UPDATE claims SET \
                truth_value = LEAST(0.99, truth_value + 0.03), \
                updated_at = NOW() \
             WHERE 'policy:active' = ANY(labels) \
               AND properties->>'host' = '*'",
        )
        .execute(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to strengthen default-deny: {e}"),
        })?;
    }

    Ok(Json(serde_json::json!({
        "id": id,
        "status": new_status,
    })))
}

/// POST /api/v1/policies/decay-sweep — pull stale active policies toward 0.5.
///
/// Skips claims with `properties->>'decay_exempt' = 'true'`. Returns the
/// number of rows updated.
#[cfg(feature = "db")]
pub async fn decay_sweep(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "decay_sweep requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;
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
            .route("/api/v1/policies/network", get(list_network_policies))
            .route("/api/v1/policies/:claim_id/outcome", post(record_outcome))
            .route("/api/v1/policies/decay-sweep", post(decay_sweep))
            .route("/api/v1/policy-challenges", post(create_challenge))
            .route("/api/v1/policy-challenges/:id", get(get_challenge))
            .route(
                "/api/v1/policy-challenges/:id/resolve",
                post(resolve_challenge),
            )
            .with_state(state)
    }

    /// Insert a system agent (mirrors `get_or_create_system_agent` but without
    /// going through the public API) and return its id.
    async fn ensure_system_agent(pool: &PgPool) -> Uuid {
        let pub_key = vec![0u8; 32];
        if let Some(id) =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM agents WHERE public_key = $1")
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

    async fn parse_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Insert a plain claim with no labels — used to verify that the
    /// challenge GET handler returns 404 for non-challenge claims.
    async fn seed_plain_claim(pool: &PgPool, content: &str) -> Uuid {
        let agent_id = ensure_system_agent(pool).await;
        let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
             VALUES ($1, $2, $3, 0.5, ARRAY[]::text[], '{}'::jsonb) RETURNING id",
        )
        .bind(content)
        .bind(content_hash.as_slice())
        .bind(agent_id)
        .fetch_one(pool)
        .await
        .unwrap()
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
    async fn get_challenge_returns_404_when_not_a_challenge(pool: PgPool) {
        let claim_id = seed_plain_claim(&pool, "not a challenge").await;
        let state = test_state(pool.clone());
        let router = policy_router(state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/policy-challenges/{claim_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
