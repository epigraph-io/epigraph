//! Operator decision D9 (batch W12a): the corpus-wide embedding worklist is a
//! MAINTENANCE route, and a request-serving `server` holds no maintenance
//! connection, so it answers 501 MOVED naming the operator CLI.
//!
//! The gate is `AppState::maintenance_viewer`'s. Without it, `ScopedPool`'s
//! fallback leases from the APPLICATION pool when no maintenance pool is
//! attached: on a privileged application DSN (any deployment before its
//! app-role move) the route kept serving a surface D9 removed, and on the application role it
//! would spend a bypass viewer on a filtered connection (an empty 200). The
//! arms below run on a PRIVILEGED application DSN (the superuser test pool),
//! so the refusal cannot be the second shape.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::RequireScopeAdmin;
use epigraph_api::routes::claims::{find_claims_needing_embeddings, NeedingEmbeddingsQuery};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_auth::{AuthContext, ClientType};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;

fn admin() -> RequireScopeAdmin {
    RequireScopeAdmin(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: None,
        owner_id: None,
        client_type: ClientType::Service,
        scopes: vec!["claims:admin".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_embedding_worklist_answers_moved_on_a_privileged_dsn_without_a_maintenance_pool(
    pool: PgPool,
) {
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "d9-embed").await;
    viewer_fixture::seed_public_claim(&pool, agent, "an unembedded claim").await;

    let state = AppState::with_scoped_pool(
        viewer_fixture::scoped_pool(&pool).await,
        ApiConfig::default(),
    );
    let privileged: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(&state.db_pool)
        .await
        .expect("probe");
    assert!(
        privileged,
        "CALIBRATION: the application DSN is privileged, so a 501 is the D9 gate"
    );

    let err = find_claims_needing_embeddings(
        State(state),
        admin(),
        Query(NeedingEmbeddingsQuery { limit: None }),
    )
    .await
    .expect_err("the worklist was served by a unit with no maintenance pool");
    assert!(
        matches!(
            &err,
            ApiError::MaintenanceSurfaceNotServed { surface, runs_on_kind, runs_on_name }
                if surface == "find_claims_needing_embeddings"
                    && *runs_on_kind == "cli"
                    && runs_on_name == "embed_backfill"
        ),
        "{err:?}"
    );
    let resp = err.into_response();
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "MOVED is 501: not 503 (transient, invites retries), not 403 (authority is fine)"
    );
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(
        (
            json["error"].clone(),
            json["runs_on"].clone(),
            json["retryable"].clone(),
            json["decision"].clone()
        ),
        (
            serde_json::json!("maintenance_surface_not_served"),
            serde_json::json!({"kind": "cli", "name": "embed_backfill"}),
            serde_json::json!(false),
            serde_json::json!("D9"),
        ),
        "{json}"
    );
}

/// The control: the same route on a state that HAS a maintenance pool (a test
/// harness; `bin/server.rs` never attaches one) is served, and finds the
/// unembedded claim. So the 501 above is the missing pool, not a broken route.
#[sqlx::test(migrations = "../../migrations")]
async fn with_a_maintenance_pool_the_same_route_is_served(pool: PgPool) {
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "d9-embed-ok").await;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "an unembedded claim").await;
    let state = AppState::with_scoped_pool(
        viewer_fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
        ApiConfig::default(),
    );
    assert!(state.serves_maintenance_surface());
    let axum::Json(json) = find_claims_needing_embeddings(
        State(state),
        admin(),
        Query(NeedingEmbeddingsQuery { limit: None }),
    )
    .await
    .expect("served");
    let ids: Vec<String> = json["claims"]
        .as_array()
        .expect("claims")
        .iter()
        .map(|c| c["id"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(ids.contains(&claim.to_string()), "{json}");
}
