#![cfg(feature = "db")]
//! `POST /api/v1/agents` registers an identity; it does not mint a login
//! (backlog 2f87eb08).
//!
//! It used to give every newly created agent an ACTIVE `agent` OAuth client
//! with `claims:write` granted whenever the caller held `agents:write`, so any
//! `agents:write` holder (a bulk ingester registering one agent per author)
//! minted a live login for every key it registered. Now a client exists only
//! on an explicit `login: true`, and it is ACTIVE only for a `claims:admin`
//! caller; any other caller's client is PENDING with nothing granted, the
//! shape `/oauth/register`'s agent arm writes.
//!
//! Through the real router and bearer middleware, with a token whose `sub` is
//! a real `oauth_clients` row (the provisioned client's `owner_id` references
//! it). CALIBRATION: an admin's explicit login request still yields an active
//! client with the provision scopes, so "no active client" below is the rule
//! and not a fixture that could never provision one.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chrono::Duration;
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_auth::AccessTokenBinding;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// The caller: an agent row and an ACTIVE human client for it. Returns the
/// client's row id (the token's `sub`) and the agent id.
async fn caller(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(blake3::hash(name.as_bytes()).as_bytes().as_slice())
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("caller agent");
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id) \
         VALUES ($1, $1, 'human', ARRAY['agents:write'], ARRAY['agents:write'], 'active', $2) \
         RETURNING id",
    )
    .bind(format!("caller-{name}"))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("caller client");
    (client, agent)
}

fn token(state: &AppState, client: Uuid, agent: Uuid, scopes: &[&str]) -> String {
    state
        .jwt_config
        .issue_access_token(
            client,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "human",
            None,
            Some(agent),
            Duration::minutes(15),
            AccessTokenBinding::NONE,
        )
        .expect("mint")
        .0
}

/// `POST /api/v1/agents` for a fresh key; returns the status, the body and the
/// key's hex (which is the client_id a provisioned client would carry).
async fn register(
    state: &AppState,
    access: &str,
    key: u8,
    login: Option<bool>,
) -> (StatusCode, Value, String) {
    let key_hex = hex::encode([key; 32]);
    let mut body = json!({ "public_key": key_hex, "display_name": format!("registered-{key}") });
    if let Some(login) = login {
        body["login"] = json!(login);
    }
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/agents")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        key_hex,
    )
}

/// Every client row for `client_id`: `(status, granted_scopes, agent_id)`.
async fn clients_for(pool: &PgPool, client_id: &str) -> Vec<(String, Vec<String>, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT status, granted_scopes, agent_id FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_all(pool)
    .await
    .expect("clients")
}

#[sqlx::test(migrations = "../../migrations")]
async fn registering_an_agent_mints_no_login_without_an_admin_login_request(pool: PgPool) {
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    let (writer_client, writer_agent) = caller(&pool, "bulk-ingester").await;
    let writer = token(&state, writer_client, writer_agent, &["agents:write"]);
    let (admin_client, admin_agent) = caller(&pool, "admin").await;
    let admin = token(
        &state,
        admin_client,
        admin_agent,
        &["agents:write", "claims:admin"],
    );

    // CALIBRATION: an admin who asks for a login gets an ACTIVE client, linked
    // to the new agent, holding exactly the provision scopes.
    let (status, body, key) = register(&state, &admin, 0x31, Some(true)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = clients_for(&pool, &key).await;
    assert_eq!(
        rows.len(),
        1,
        "CALIBRATION: one client provisioned: {rows:?}"
    );
    let (st, granted, agent) = &rows[0];
    assert_eq!(st, "active", "CALIBRATION: {rows:?}");
    let mut granted = granted.clone();
    granted.sort();
    let mut want: Vec<String> = epigraph_core::canonical_scopes::AGENT_PROVISION_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    want.sort();
    assert_eq!(granted, want, "CALIBRATION: the provision scopes, granted");
    assert_eq!(
        agent.map(|a| a.to_string()),
        body["id"].as_str().map(String::from)
    );

    // 1. A plain `agents:write` registration (the bulk-ingest shape): the
    //    agent exists and NO client does, active or otherwise.
    let (status, body, key) = register(&state, &writer, 0x32, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["id"].is_string(), "the agent is registered: {body}");
    assert_eq!(
        clients_for(&pool, &key).await,
        vec![],
        "an agents:write registration provisioned a client"
    );

    // 2. `login: false` said explicitly: the same.
    let (status, body, key) = register(&state, &writer, 0x33, Some(false)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(clients_for(&pool, &key).await, vec![]);

    // 3. A login request WITHOUT claims:admin: a PENDING client, nothing
    //    granted. It cannot mint until an admin approves it.
    let (status, body, key) = register(&state, &writer, 0x34, Some(true)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = clients_for(&pool, &key).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].0, "pending",
        "a non-admin login request is not approved: {rows:?}"
    );
    assert!(
        rows[0].1.is_empty(),
        "nothing granted before approval: {rows:?}"
    );

    // 4. An admin who does not ask for a login: no client either. Admin is the
    //    approval of a REQUEST, not a reason to provision one.
    let (status, body, key) = register(&state, &admin, 0x35, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(clients_for(&pool, &key).await, vec![]);

    // Nothing anywhere is active but the calibration's client and the callers'.
    let active_agent_clients: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_clients WHERE client_type = 'agent' AND status = 'active'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        active_agent_clients, 1,
        "only the admin's explicit login is active"
    );
}
