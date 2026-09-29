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
    _scope: crate::middleware::bearer::RequireScopeAdmin,
    Path(claim_id): Path<Uuid>,
    Json(req): Json<OutcomeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Scope already verified by extractor: caller has `claims:admin`.
    // See `RequireScopeAdmin` in `middleware::bearer`.
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
///
/// Idempotent on `(host, port, protocol)`: a repeat request answers `200`
/// with the id of the challenge the first one created, whatever that
/// challenge's status is now, and writes nothing.
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

    // Tenancy declaration (PR-16). A policy challenge is authored by the SYSTEM
    // agent (resolved above) and is instance-wide by construction -- the
    // approval surface that reads it back is not scoped to the requester's
    // group -- so the declaration is the system agent's own group, publicly
    // visible. The caller's `AuthContext` is spent on the `claims:write` scope
    // check above, which is what it is for here.
    let decl =
        epigraph_db::ClaimRepository::default_decl_for_author_pool(&state.db_pool, sys_agent_id)
            .await?;

    // Idempotent on (host, port, protocol). `content` is a pure function of
    // those three fields and the author is the one system agent, so a repeat
    // request names the same (content_hash, agent_id) pair as the first. It
    // must answer with the challenge that pair already names rather than
    // insert a second one.
    //
    // The existing row is FOUND, not inferred from a unique violation.
    // `uq_claims_content_hash_agent` (migration 013) is absent on the
    // long-lived production database (migrations/README.md, "Known schema
    // drift"), so a handler that relied on the constraint firing would 500 on
    // a fresh database and silently mint a duplicate pending challenge on
    // production. The lookup works with or without the constraint.
    //
    // The transaction-scoped advisory lock serializes concurrent creates of
    // the same challenge, so two first requests racing each other cannot both
    // miss the lookup and both insert -- which, again, nothing else prevents
    // where the constraint is absent. The two-key form keeps this lock space
    // disjoint from the single-key `hashtext('epigraph.*')` locks elsewhere.
    //
    // The lookup projects `id` only, and the repeat answers `{ "id" }`, the
    // same shape as a first create; the challenge's state is
    // `GET /api/v1/policy-challenges/:id`'s to serve.
    let mut tx = state
        .db_pool
        .begin()
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to create challenge: {e}"),
        })?;

    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtext('epigraph.policy_challenge'), hashtext($1))",
    )
    .bind(&content)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to create challenge: {e}"),
    })?;

    // Taken AFTER the lock, as its own statement, so under READ COMMITTED it
    // reads a snapshot that includes a racing request's committed insert.
    // Ordered because production already holds duplicates from before this
    // lookup existed; the oldest is the one every repeat keeps answering with.
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM claims \
         WHERE content_hash = $1 AND agent_id = $2 \
           AND 'policy:challenge' = ANY(labels) \
         ORDER BY created_at, id \
         LIMIT 1",
    )
    .bind(content_hash.as_slice())
    .bind(sys_agent_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to look up existing challenge: {e}"),
    })?;

    let id = match existing {
        Some(id) => id,
        None => sqlx::query_scalar(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties, \
                                 visibility, owner_group_id) \
             VALUES ($1, $2, $3, 0.5, ARRAY['policy','policy:challenge'], $4, $5, $6) \
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
        .bind(decl.visibility_bind())
        .bind(decl.owner_group_bind())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to create challenge: {e}"),
        })?,
    };

    tx.commit().await.map_err(|e| ApiError::InternalError {
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

    // ── create_challenge idempotency ──

    /// A `claims:write` caller, injected the way the bearer middleware would.
    /// Without it `create_challenge` answers 401 before reaching the insert,
    /// and every assertion below would be about the auth gate instead.
    fn challenge_router(state: AppState) -> Router {
        let principal = Uuid::new_v4();
        Router::new()
            .route("/api/v1/policy-challenges", post(create_challenge))
            .layer(axum::Extension(crate::middleware::bearer::AuthContext {
                client_id: principal,
                agent_id: Some(principal),
                owner_id: Some(principal),
                client_type: crate::middleware::bearer::ClientType::Service,
                scopes: vec!["claims:write".to_string()],
                jti: Uuid::new_v4(),
            }))
            .with_state(state)
    }

    /// POST one challenge and return (status, body-as-text).
    async fn post_challenge(state: AppState, body: &serde_json::Value) -> (StatusCode, String) {
        let response = challenge_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/policy-challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// POST and require a 200 carrying an id; return the id.
    async fn create_ok(state: AppState, body: &serde_json::Value, which: &str) -> Uuid {
        let (status, text) = post_challenge(state, body).await;
        assert_eq!(status, StatusCode::OK, "{which} create: body={text}");
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or_else(|| panic!("{which} create: no id in body={text}"))
    }

    /// Rows that are the challenge for `body` — counted on the SUPERUSER pool,
    /// so RLS cannot hide a duplicate from the count.
    async fn challenge_rows(pool: &PgPool, body: &serde_json::Value) -> i64 {
        let text = format!(
            "Network access challenge: {}:{} ({})",
            body["host"].as_str().unwrap(),
            body["port"].as_i64().unwrap(),
            body["protocol"].as_str().unwrap_or("any")
        );
        // Keyed on the hash, not the text: selecting on the content column
        // would charge this test helper to `viewer_route_table_lint.rs`'s
        // inline-content-read register, which it is not.
        let hash = epigraph_crypto::ContentHasher::hash(text.as_bytes());
        sqlx::query_scalar(
            "SELECT count(*) FROM claims \
             WHERE content_hash = $1 AND 'policy:challenge' = ANY(labels)",
        )
        .bind(hash.as_slice())
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// The fresh-database shape: `uq_claims_content_hash_agent` is present, so
    /// a second identical insert is a unique violation. Before the lookup the
    /// repeat answered 500 `Failed to create challenge: ... duplicate key`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_challenge_repeat_returns_the_existing_challenge(pool: PgPool) {
        let body = serde_json::json!({ "host": "idem.example", "port": 8443, "protocol": "https" });

        let first = create_ok(test_state(pool.clone()), &body, "first").await;
        let second = create_ok(test_state(pool.clone()), &body, "repeat").await;

        assert_eq!(
            second, first,
            "a repeat must answer the existing challenge's id"
        );
        assert_eq!(
            challenge_rows(&pool, &body).await,
            1,
            "a repeat must write nothing"
        );

        // A different tuple is a different challenge — the lookup is keyed on
        // the tuple, not on "any challenge exists".
        let other = serde_json::json!({ "host": "idem.example", "port": 8443, "protocol": "http" });
        let third = create_ok(test_state(pool.clone()), &other, "other-protocol").await;
        assert_ne!(
            third, first,
            "a different (host, port, protocol) is a new challenge"
        );
    }

    /// The PRODUCTION shape: `migrations/README.md` records that the
    /// long-lived database has no `uq_claims_content_hash_agent`. There the
    /// repeat never errored — it silently inserted a second pending challenge.
    /// A fix that only caught the unique violation would still do that.
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_challenge_repeat_is_idempotent_without_the_unique_constraint(pool: PgPool) {
        sqlx::query("ALTER TABLE claims DROP CONSTRAINT uq_claims_content_hash_agent")
            .execute(&pool)
            .await
            .unwrap();
        let body = serde_json::json!({ "host": "drift.example", "port": 443, "protocol": "https" });

        let first = create_ok(test_state(pool.clone()), &body, "first").await;
        let second = create_ok(test_state(pool.clone()), &body, "repeat").await;

        assert_eq!(
            second, first,
            "a repeat must answer the existing challenge's id"
        );
        assert_eq!(
            challenge_rows(&pool, &body).await,
            1,
            "with the constraint absent, a repeat must still not mint a duplicate"
        );
    }

    /// Concurrent first requests for one tuple, constraint absent: the
    /// advisory lock is the only thing that keeps them from all missing the
    /// lookup and all inserting.
    ///
    /// A race is probabilistic, so the arm runs several rounds. Measured with
    /// the lock deleted, a single 8-racer round minted duplicates in 7 of 9
    /// runs; six independent rounds make a lock-less handler pass this arm
    /// with probability well under 1 in 1000. With the lock the outcome is not
    /// probabilistic at all: the racers are serialized.
    #[sqlx::test(migrations = "../../migrations")]
    async fn concurrent_first_creates_yield_one_challenge_without_the_unique_constraint(
        pool: PgPool,
    ) {
        sqlx::query("ALTER TABLE claims DROP CONSTRAINT uq_claims_content_hash_agent")
            .execute(&pool)
            .await
            .unwrap();
        // Resolve the system agent and its group once, so the racers contend
        // on the challenge insert and not on agent provisioning.
        let seed = serde_json::json!({ "host": "seed.example", "port": 1, "protocol": "tcp" });
        create_ok(test_state(pool.clone()), &seed, "seed").await;

        for round in 0..6 {
            let body = serde_json::json!({ "host": "race.example", "port": 9000 + round, "protocol": "tcp" });
            let mut handles = Vec::new();
            for _ in 0..8 {
                let state = test_state(pool.clone());
                let body = body.clone();
                handles.push(tokio::spawn(async move {
                    create_ok(state, &body, "racer").await
                }));
            }
            let mut ids = std::collections::BTreeSet::new();
            for h in handles {
                ids.insert(h.await.unwrap());
            }
            assert_eq!(
                ids.len(),
                1,
                "round {round}: every racer must answer the same challenge: {ids:?}"
            );
            assert_eq!(
                challenge_rows(&pool, &body).await,
                1,
                "round {round}: racers must insert once"
            );
        }
    }

    /// The repeat path on a NON-BYPASSING role. `#[sqlx::test]` connects as
    /// `epigraph` — superuser, BYPASSRLS — so no policy filters the arms
    /// above. Here the repeat runs on a pool whose every connection is
    /// `SET SESSION AUTHORIZATION epigraph_app`, unstamped, which is what the
    /// handler's `db_pool` is once the DSN is repointed at the app role.
    ///
    /// An unstamped `epigraph_app` session has no writable groups, so any
    /// INSERT into `claims` fails `claims_tenancy`'s WITH CHECK (42501) —
    /// before the unique index is consulted. A repeat that still attempted the
    /// insert (main's handler, and a catch-the-23505 fix alike) answers 500
    /// here. The lookup reads the challenge, which is `visibility = 'public'`
    /// (`default_decl_for_author_pool`), and never reaches the insert.
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_challenge_repeat_is_idempotent_on_the_app_role(pool: PgPool) {
        let body =
            serde_json::json!({ "host": "app-role.example", "port": 5000, "protocol": "https" });

        // First create as the superuser, so the agent, its group and the row
        // are exactly what the handler writes rather than a hand-built copy.
        let first = create_ok(test_state(pool.clone()), &body, "first").await;

        let opts = (*pool.connect_options()).clone();
        let app_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::Executor::execute(conn, "SET SESSION AUTHORIZATION epigraph_app").await?;
                    Ok(())
                })
            })
            .connect_with(opts)
            .await
            .unwrap();
        let (user, privileged): (String, bool) = sqlx::query_as(
            "SELECT current_user::text, rolsuper OR rolbypassrls \
             FROM pg_roles WHERE rolname = current_user",
        )
        .fetch_one(&app_pool)
        .await
        .unwrap();
        assert_eq!(
            user, "epigraph_app",
            "CALIBRATION: the repeat must run as the app role"
        );
        assert!(
            !privileged,
            "CALIBRATION: the app role must be subject to RLS, or this arm proves nothing"
        );

        let second = create_ok(test_state(app_pool), &body, "repeat on epigraph_app").await;

        assert_eq!(
            second, first,
            "the app-role repeat must answer the existing challenge"
        );
        assert_eq!(
            challenge_rows(&pool, &body).await,
            1,
            "a repeat must write nothing"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn get_challenge_returns_404_when_not_a_challenge(pool: PgPool) {
        let claim_id = seed_plain_claim(&pool, "not a challenge").await;
        let state = test_state(pool.clone());
        let router = policy_router(state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/policy-challenges/{claim_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
