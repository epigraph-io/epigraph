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

/// A public `claim -<relationship>-> agent` attribution edge, world-owned.
async fn attribute(pool: &PgPool, claim: Uuid, agent: Uuid, relationship: &str) {
    let world = viewer_fixture::world_group(pool).await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'agent', $4)",
    )
    .bind(id)
    .bind(claim)
    .bind(agent)
    .bind(relationship)
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
/// assigned one claim's labels to another, fails. The alpha claim has a
/// SECOND attribution edge (the lowercase spelling the page query also
/// matches), so it is listed twice; both copies must carry its labels, so a
/// handler that consumed the label map on first use fails.
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
        attribute(&pool, claim, author, "ATTRIBUTED_TO").await;
    }
    attribute(&pool, alpha, author, "attributed_to").await;

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
    assert_eq!(items.len(), 4, "all four attributions are listed: {body}");
    // Every listed copy of `claim`, as its labels.
    let labels_of = |claim: Uuid| -> Vec<Vec<String>> {
        let copies: Vec<Vec<String>> = items
            .iter()
            .filter(|i| i["id"].as_str() == Some(claim.to_string().as_str()))
            // `ClaimResponse` omits an empty `labels` from the JSON.
            .map(|item| match &item["labels"] {
                Value::Null => Vec::new(),
                labels => serde_json::from_value(labels.clone()).expect("labels is a string array"),
            })
            .collect();
        assert!(!copies.is_empty(), "{claim} is listed: {body}");
        copies
    };
    assert_eq!(
        labels_of(alpha),
        [
            ["topic:alpha", "src:notes.md"],
            ["topic:alpha", "src:notes.md"]
        ],
        "both attributions of the alpha claim carry its stored labels: {body}"
    );
    assert_eq!(
        labels_of(beta),
        [["topic:beta"]],
        "the beta claim's stored labels: {body}"
    );
    assert_eq!(
        labels_of(bare),
        [Vec::<String>::new()],
        "an unlabelled claim lists no labels: {body}"
    );
}
