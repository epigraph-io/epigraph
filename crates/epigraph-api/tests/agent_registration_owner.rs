#![cfg(feature = "db")]
//! `POST /oauth/register` names no owner for a self-registered agent
//! (backlog be024524, migration 312).
//!
//! The agent arm used to stamp `owner_id` with the OLDEST ACTIVE HUMAN client
//! (an inline lookup whose error it swallowed). The request is
//! unauthenticated, so nothing about it names that human; yet suspending that
//! human (`OAuthClientRepository::suspend_by_owner`) suspended every approved
//! self-registered agent, and the agent's token carried that human as its
//! owner. Now the registration writes no owner, and the operator names one at
//! approval (312's four-argument `epigraph_oauth_client_approve`).
//!
//! Fails on the old registration: the row's owner is the oldest human, the
//! three-argument approval activates it with that owner, and with no active
//! human at all the registration is a 500 (001's CHECK on a NULL owner).

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::repos::oauth_client::OAuthClientRepository;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

async fn register_agent(pool: &PgPool, seed: &str) -> (StatusCode, Value, String) {
    let client_id = hex::encode(blake3::hash(seed.as_bytes()).as_bytes());
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "client_name": seed,
                "client_type": "agent",
                "client_id": client_id,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = create_router(AppState::with_db(pool.clone(), ApiConfig::default()))
        .oneshot(req)
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        client_id,
    )
}

/// An active human client, created `age_days` ago.
async fn human(pool: &PgPool, age_days: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, created_at) \
         VALUES ($1, 'human', 'human', '{}', '{}', 'active', now() - make_interval(days => $2)) \
         RETURNING id",
    )
    .bind(format!("h_{}", Uuid::new_v4().simple()))
    .bind(age_days)
    .fetch_one(pool)
    .await
    .expect("seed human client")
}

/// `(id, status, owner_id)` of the client registered as `client_id`.
async fn row(pool: &PgPool, client_id: &str) -> (Uuid, String, Option<Uuid>) {
    sqlx::query_as("SELECT id, status::text, owner_id FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .fetch_one(pool)
        .await
        .expect("the registered row")
}

/// The registration writes no owner, so nothing an operator did not name can
/// own the agent: the three-argument approval cannot activate it, the
/// approval that names an owner does, and suspending the oldest human leaves
/// it active.
#[sqlx::test(migrations = "../../migrations")]
async fn a_self_registered_agent_has_no_owner_until_its_approval_names_one(pool: PgPool) {
    let oldest_human = human(&pool, 30).await;
    let named = human(&pool, 1).await;

    let (status, body, client_id) = register_agent(&pool, "be024524-agent").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (id, st, owner) = row(&pool, &client_id).await;
    assert_eq!(st, "pending");
    assert_eq!(
        owner, None,
        "an unauthenticated registration must not be given an owner (the old arm \
         picked the oldest active human, {oldest_human})"
    );

    // 118's approval, which names no owner, cannot activate it.
    let r = sqlx::query_scalar::<_, bool>(
        "SELECT public.epigraph_oauth_client_approve($1, ARRAY['claims:read'], NULL)",
    )
    .bind(id)
    .fetch_one(&pool)
    .await;
    let code = r
        .expect_err("activating an agent no one was named to own")
        .as_database_error()
        .and_then(|d| d.code().map(|c| c.to_string()));
    assert_eq!(code.as_deref(), Some("23514"));
    assert_eq!(row(&pool, &client_id).await.1, "pending");

    // The operator names the owner at approval.
    OAuthClientRepository::approve(&pool, id, &["claims:read".into()], named, Some(named))
        .await
        .expect("approve naming the owner");
    assert_eq!(
        row(&pool, &client_id).await,
        (id, "active".to_string(), Some(named))
    );

    let n = OAuthClientRepository::suspend_by_owner(&pool, oldest_human)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert_eq!(
        row(&pool, &client_id).await.1,
        "active",
        "suspending the oldest human must not suspend an agent it was never named to own"
    );
}

/// With no active human client at all the registration still succeeds: the
/// old arm's lookup found none, its error-swallowing `unwrap_or(None)` passed
/// NULL on, and 001's CHECK turned every agent registration into a 500.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_registers_when_no_human_client_is_active(pool: PgPool) {
    let (status, body, client_id) = register_agent(&pool, "be024524-alone").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["status"], "pending", "{body}");
    let (_, st, owner) = row(&pool, &client_id).await;
    assert_eq!((st.as_str(), owner), ("pending", None));
}
