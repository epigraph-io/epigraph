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

mod viewer_fixture;

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

/// `POST /api/v1/agents` with an EXISTING agent's key is a find-hit that
/// returns that agent's row. It must not read back a private ORCID / ROR id
/// (backlog 761c2b05): `GET /api/v1/agents` serves every agent's
/// `public_key`, and `agents:write` is in every read-write token, so posting
/// the key back would undo the profile-visibility rule in two requests.
/// Positive controls: the agent itself and a `claims:admin` caller still read
/// them, and a fresh registration echoes what its caller supplied.
#[sqlx::test(migrations = "../../migrations")]
async fn re_registering_an_existing_key_does_not_read_back_its_private_profile(pool: PgPool) {
    // A find-hit's NAME is decided on a viewer-stamped connection (migration
    // 309's disclosure, `create_agent`), so the state carries a ScopedPool as
    // the server's does; `AppState::read_as` refuses without one.
    let scoped = epigraph_db::ScopedPool::connect(
        &viewer_fixture::database_url_for(&pool).await,
        epigraph_db::SessionGucMode::Session,
    )
    .await
    .expect("ScopedPool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
    let (writer_client, writer_agent) = caller(&pool, "outsider-writer").await;
    let writer = token(&state, writer_client, writer_agent, &["agents:write"]);
    let (admin_client, admin_agent) = caller(&pool, "admin").await;
    let admin = token(
        &state,
        admin_client,
        admin_agent,
        &["agents:write", "claims:admin"],
    );
    // The profiled agent holds its own client, so it can post its own key.
    let (own_client, profiled) = caller(&pool, "private-profile").await;
    let own = token(&state, own_client, profiled, &["agents:write"]);
    sqlx::query(
        "UPDATE agents SET orcid = '0000-0002-1825-0097', ror_id = '03yrm5c26', \
                profile_visibility = 'group' WHERE id = $1",
    )
    .bind(profiled)
    .execute(&pool)
    .await
    .expect("private profile");
    let key_hex = hex::encode(blake3::hash(b"private-profile").as_bytes());

    let post = |access: String, body: Value| {
        let state = state.clone();
        async move {
            let resp = create_router(state)
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
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };

    // The outsider posts the private agent's key: the SAME row comes back
    // (a find-hit, not a new agent), with no profile detail.
    let (status, body) = post(writer.clone(), json!({ "public_key": key_hex })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["id"],
        profiled.to_string(),
        "CALIBRATION: a find-hit returns the existing agent: {body}"
    );
    assert!(
        body["orcid"].is_null() && body["ror_id"].is_null(),
        "re-registering an existing key read back its private ORCID / ROR id: {body}"
    );

    // Positive controls: the agent itself, and an admin, read both.
    for (who, access) in [("self", own), ("admin", admin)] {
        let (status, body) = post(access, json!({ "public_key": key_hex })).await;
        assert_eq!(status, StatusCode::OK, "{who}: {body}");
        assert_eq!(body["id"], profiled.to_string(), "{who}: {body}");
        assert_eq!(body["orcid"], "0000-0002-1825-0097", "{who}: {body}");
        assert_eq!(body["ror_id"], "03yrm5c26", "{who}: {body}");
    }

    // A fresh registration echoes the ORCID its caller supplied.
    let (status, body) = post(
        writer,
        json!({ "public_key": hex::encode([0x51u8; 32]), "orcid": "0000-0001-5109-3700" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["id"], profiled.to_string(), "{body}");
    assert_eq!(body["orcid"], "0000-0001-5109-3700", "{body}");
}
