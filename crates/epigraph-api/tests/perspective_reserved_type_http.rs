#![cfg(feature = "db")]
//! `POST /api/v1/perspectives` refuses the two `perspective_type` values that
//! named the internal BBA keys (`edge`, `evidence`) with a 400 that names the
//! field, and writes nothing (backlog 1777638e).
//!
//! Migration 267's `perspectives_not_bba_slot` CHECK refuses such a row in the
//! database anyway, and the API maps that to a generic 400 ("request violates
//! a database constraint (constraint perspectives_not_bba_slot)"), so neither
//! the status nor the absence of a row separates the two. What the handler's
//! check adds is a validation error that names the field and says the type is
//! reserved; this test pins that, with the status and the absence of a row.
//! The control (`analytical`) is written through the same request, so a
//! refusal is not the harness failing.
//! Mutation: deleting the `reserved_perspective_type` check in
//! `routes/perspective.rs::create_perspective` fails the body assertion (the
//! constraint message names neither `perspective_type` nor "reserved").

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

async fn router(pool: &PgPool) -> axum::Router {
    let state = epigraph_api::state::AppState::with_db(
        pool.clone(),
        epigraph_api::state::ApiConfig::default(),
    );
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    epigraph_api::routes::create_router(state)
}

async fn create(
    app: &axum::Router,
    agent: Uuid,
    name: &str,
    perspective_type: &str,
) -> (StatusCode, String) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/perspectives")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "name": name, "perspective_type": perspective_type }).to_string(),
        ))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("router");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn rows_named(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM perspectives WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("count perspectives")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reserved_perspective_type_is_a_400_and_writes_nothing(pool: PgPool) {
    let app = router(&pool).await;
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "m267-rest-type").await;

    let control = format!("m267 control lens {}", Uuid::new_v4());
    let (status, body) = create(&app, agent, &control, "analytical").await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "CONTROL: an ordinary type is created: {body}"
    );
    assert_eq!(rows_named(&pool, &control).await, 1, "CONTROL: one row");

    for reserved in ["edge", "evidence"] {
        let name = format!("m267 {reserved} lens {}", Uuid::new_v4());
        let (status, body) = create(&app, agent, &name, reserved).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "perspective_type `{reserved}` is a 400: {body}"
        );
        assert!(
            body.contains("perspective_type") && body.contains("reserved"),
            "the error names the field and why: {body}"
        );
        assert_eq!(
            rows_named(&pool, &name).await,
            0,
            "nothing written for `{reserved}`"
        );
    }
}
