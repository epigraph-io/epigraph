//! `POST /api/v1/bp/propagate` bounds its caller-supplied run parameters
//! (backlog 69f52e3f).
//!
//! The BP loops stop only at `max_change < convergence_threshold` or at
//! `max_iterations`, so those two (and a `damping` at which no message moves)
//! are caller-controlled run time. Out-of-range values are `400` before
//! anything is loaded; the boundary values themselves are admitted.
//!
//! The database is migrated and EMPTY, so an admitted request takes the
//! empty-factor early return and answers `200` at once. That is what makes the
//! refusals observable: a handler that did not validate would answer `200`
//! here too, not hang.
#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::State;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::computation::{propagate_beliefs, PropagateRequest, BP_MAX_ITERATIONS};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use viewer_fixture::{scoped_pool, seed_agent_with_group};

async fn run(pool: &PgPool, body: serde_json::Value) -> Result<serde_json::Value, ApiError> {
    let (agent, _) =
        seed_agent_with_group(pool, &format!("69f5-bp-bounds-{}", uuid::Uuid::new_v4())).await;
    let state = AppState::with_scoped_pool(scoped_pool(pool).await, ApiConfig::default());
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let request: PropagateRequest = serde_json::from_value(body).expect("request");
    propagate_beliefs(ViewerExtractor(viewer), State(state), Json(request))
        .await
        .map(|Json(v)| v)
}

fn refused_on(res: Result<serde_json::Value, ApiError>, field: &str, what: &str) {
    match res {
        Err(ApiError::ValidationError { field: f, .. }) => {
            assert_eq!(f, field, "{what}: refused on the wrong field")
        }
        other => panic!("{what}: must be a 400 on `{field}`, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn out_of_range_run_parameters_are_refused(pool: PgPool) {
    refused_on(
        run(
            &pool,
            serde_json::json!({ "max_iterations": BP_MAX_ITERATIONS + 1 }),
        )
        .await,
        "max_iterations",
        "one iteration over the cap",
    );
    refused_on(
        run(
            &pool,
            serde_json::json!({ "max_iterations": 1_000_000_000u64 }),
        )
        .await,
        "max_iterations",
        "an effectively unbounded run",
    );
    for t in [0.0, -0.5] {
        refused_on(
            run(&pool, serde_json::json!({ "convergence_threshold": t })).await,
            "convergence_threshold",
            &format!("threshold {t}"),
        );
    }
    for d in [1.0, 1.5, -0.1] {
        refused_on(
            run(&pool, serde_json::json!({ "damping": d })).await,
            "damping",
            &format!("damping {d}"),
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn defaults_and_boundary_run_parameters_are_admitted(pool: PgPool) {
    let out = run(&pool, serde_json::json!({}))
        .await
        .expect("the defaults are admitted");
    assert_eq!(out["factors_count"], 0, "CALIBRATION: the graph is empty");
    run(
        &pool,
        serde_json::json!({
            "max_iterations": BP_MAX_ITERATIONS,
            "convergence_threshold": 1e-9,
            "damping": 0.0,
        }),
    )
    .await
    .expect("the boundary values are admitted");
}
