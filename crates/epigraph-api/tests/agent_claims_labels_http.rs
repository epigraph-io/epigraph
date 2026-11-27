#![cfg(feature = "db")]
//! `GET /api/v1/agents/:id/claims` returns each attributed claim's stored
//! labels (backlog a8b785a7).
//!
//! The handler used to build every item with `labels: Vec::new()`, so a
//! labelled claim read back through this route looked unlabelled. Driven
//! through the full router (bearer middleware, scope check, viewer extractor,
//! the stamped read) with both pools of the `AppState` on the APPLICATION ROLE,
//! so the labels read is subject to the same row security as the page itself.
//! All names are invented.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool};

async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(scoped.inner())
        .await
        .expect("epigraph_bypass on the scoped pool");
    assert!(
        !bypass,
        "CALIBRATION: the scoped pool must not be privileged"
    );
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

/// A public `claim -ATTRIBUTED_TO-> agent` edge, world-owned.
async fn attribute(pool: &PgPool, claim: Uuid, agent: Uuid) {
    let world = viewer_fixture::world_group(pool).await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'agent', 'ATTRIBUTED_TO')",
    )
    .bind(id)
    .bind(claim)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed the attribution edge");
    sqlx::query(
        "UPDATE edges SET visibility = 'public', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .bind(world)
    .execute(pool)
    .await
    .expect("declare the attribution edge's tenancy");
}

async fn set_labels(pool: &PgPool, claim: Uuid, labels: &[&str]) {
    sqlx::query("UPDATE claims SET labels = $2 WHERE id = $1")
        .bind(claim)
        .bind(labels)
        .execute(pool)
        .await
        .expect("set the claim's labels");
}

/// Two attributed claims with DIFFERENT labels and one with none: each item
/// carries exactly its own stored labels, so a handler that dropped them, or
/// assigned one claim's labels to another, fails.
#[sqlx::test(migrations = "../../migrations")]
async fn agent_claims_returns_each_claims_stored_labels(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (author, _) = viewer_fixture::seed_agent_with_group(&pool, "acl-author").await;
    let (reader, _) = viewer_fixture::seed_agent_with_group(&pool, "acl-reader").await;

    let alpha = viewer_fixture::seed_public_claim(&pool, author, "acl: the alpha claim").await;
    let beta = viewer_fixture::seed_public_claim(&pool, author, "acl: the beta claim").await;
    let bare = viewer_fixture::seed_public_claim(&pool, author, "acl: an unlabelled claim").await;
    set_labels(&pool, alpha, &["topic:alpha", "src:notes.md"]).await;
    set_labels(&pool, beta, &["topic:beta"]).await;
    for claim in [alpha, beta, bare] {
        attribute(&pool, claim, author).await;
    }

    let token = common::mint_token_with_agent(&["claims:read"], reader);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/agents/{author}/claims"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = create_router(state).oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(status, StatusCode::OK, "attributed claims: {body}");

    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 3, "all three attributions are listed: {body}");
    let labels_of = |claim: Uuid| -> Vec<String> {
        let item = items
            .iter()
            .find(|i| i["id"].as_str() == Some(claim.to_string().as_str()))
            .unwrap_or_else(|| panic!("{claim} is listed: {body}"));
        // `ClaimResponse` omits an empty `labels` from the JSON.
        match &item["labels"] {
            Value::Null => Vec::new(),
            labels => serde_json::from_value(labels.clone()).expect("labels is a string array"),
        }
    };
    assert_eq!(
        labels_of(alpha),
        ["topic:alpha", "src:notes.md"],
        "the alpha claim's stored labels: {body}"
    );
    assert_eq!(
        labels_of(beta),
        ["topic:beta"],
        "the beta claim's stored labels: {body}"
    );
    assert!(
        labels_of(bare).is_empty(),
        "an unlabelled claim lists no labels: {body}"
    );
}
