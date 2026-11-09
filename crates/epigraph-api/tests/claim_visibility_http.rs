//! The HTTP half of the claim visibility controls
//! (docs/tenancy/claim-visibility-controls.md, migration 206) on the
//! APPLICATION ROLE: `POST /api/v1/claims` (plain tier),
//! `POST /api/v1/claims/publicize` and `PUT /api/v1/agents/me/default-group`,
//! each on a transaction stamped from the caller as `epigraph_app`
//! (`connect_downgraded_for_tests`). The raw `db_pool` is the harness
//! superuser, used only to seed and to read state back.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

async fn spawn_app(pool: &PgPool) -> (SocketAddr, oneshot::Sender<()>) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    let app = epigraph_api::routes::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (addr, tx)
}

async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

async fn send(
    addr: SocketAddr,
    method: reqwest::Method,
    path: &str,
    agent: Uuid,
    body: Value,
) -> (u16, Value) {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .request(method, format!("http://{addr}{path}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn tenancy(pool: &PgPool, id: Uuid) -> (String, Uuid) {
    sqlx::query_as("SELECT visibility::text, owner_group_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("tenancy")
}

fn claim_body(agent: Uuid, content: &str, extra: Value) -> Value {
    let mut b = json!({"content": content, "agent_id": agent, "if_not_exists": true});
    if let (Some(o), Some(e)) = (b.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    b
}

/// `POST /api/v1/claims` with no visibility lands in the caller's team; a
/// reader of the team naming it is refused 403 with nothing written; a group
/// beside `public` is a 400; `private` is the home group.
#[sqlx::test(migrations = "../../migrations")]
async fn post_claims_defaults_to_the_team_and_refuses_a_reader(pool: PgPool) {
    let (addr, _stop) = spawn_app(&pool).await;
    let t = team(&pool, "http-team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "http-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "http-bob").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        alice,
        claim_body(alice, "http team default", json!({})),
    )
    .await;
    assert!(status == 200 || status == 201, "{status} {body}");
    assert_eq!(body["visibility"], "team", "{body}");
    assert_eq!(body["owner_group_id"], t.to_string(), "{body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(tenancy(&pool, id).await, ("group".to_string(), t));

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        bob,
        claim_body(bob, "http reader write", json!({"group_id": t})),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = 'http reader write'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(n, 0, "nothing written");

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        alice,
        claim_body(
            alice,
            "http contradiction",
            json!({"visibility": "public", "group_id": t}),
        ),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        alice,
        claim_body(alice, "http private", json!({"visibility": "private"})),
    )
    .await;
    assert!(status == 200 || status == 201, "{status} {body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(tenancy(&pool, id).await, ("group".to_string(), home));
}

/// `POST /api/v1/claims/publicize`: a writer is refused 403, a non-member gets
/// 404, a team admin publishes (and the audit row names the admin).
/// `PUT /api/v1/agents/me/default-group` refuses a group the caller does not
/// write.
#[sqlx::test(migrations = "../../migrations")]
async fn publicize_over_http_is_for_team_admins(pool: PgPool) {
    let (addr, _stop) = spawn_app(&pool).await;
    let t = team(&pool, "http-team").await;
    let other = team(&pool, "http-other").await;
    let (alice, _) = fixture::seed_agent_with_group(&pool, "http-writer").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "http-admin").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "http-stranger").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, eve, "admin").await;

    let (_, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims",
        alice,
        claim_body(alice, "http finding", json!({})),
    )
    .await;
    let c: Uuid = body["id"].as_str().expect("id").parse().unwrap();
    let req = json!({"claim_ids": [c], "reason": "publish"});

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims/publicize",
        alice,
        req.clone(),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims/publicize",
        carol,
        req.clone(),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(tenancy(&pool, c).await, ("group".to_string(), t));

    let (status, body) = send(
        addr,
        reqwest::Method::POST,
        "/api/v1/claims/publicize",
        eve,
        req,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["results"][0]["outcome"], "publicized", "{body}");
    assert_eq!(tenancy(&pool, c).await, ("public".to_string(), t));
    let who: Option<Uuid> = sqlx::query_scalar(
        "SELECT agent_id FROM security_events WHERE event_type = 'claim.publicized'",
    )
    .fetch_one(&pool)
    .await
    .expect("audit row");
    assert_eq!(who, Some(eve));

    let (status, body) = send(
        addr,
        reqwest::Method::PUT,
        "/api/v1/agents/me/default-group",
        alice,
        json!({"group_id": other}),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let (status, body) = send(
        addr,
        reqwest::Method::PUT,
        "/api/v1/agents/me/default-group",
        alice,
        json!({"group_id": t}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["default_group_id"], t.to_string(), "{body}");
}
