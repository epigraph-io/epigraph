//! The REST half of person-facing keyless team groups and consented
//! invitations (migration 263, backlog ee9e05b4), on the APPLICATION ROLE:
//! `POST /api/v1/groups/team`, `GET /api/v1/groups/mine`,
//! `POST /api/v1/groups/:id/invitations` and
//! `POST /api/v1/group-invitations/:id/{accept,decline}`, each on a
//! transaction stamped from the caller as `epigraph_app`
//! (`connect_downgraded_for_tests`). The raw pool is the harness superuser,
//! used only to seed and to read state back.
//!
//! Pinned: a Person creates a group and invites another Person, and the
//! membership goes live only when the invitee accepts; each designed refusal
//! answers by its kind (403 authority, 400 input, 409 state, 404 for a group
//! or invitation the caller may not see) with its `TGPnn` code in the body
//! and nothing written; a token without `groups:write` writes nothing.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

const RW: &[&str] = &["groups:read", "groups:write"];

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
    // Built as `bin/server.rs` builds it, so `db_pool` is the application
    // role too.
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
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

async fn send_with(
    addr: SocketAddr,
    method: reqwest::Method,
    path: &str,
    agent: Uuid,
    scopes: &[&str],
    body: Option<Value>,
) -> (u16, Value) {
    let token = common::mint_token_with_agent(scopes, agent);
    let mut req = reqwest::Client::new()
        .request(method, format!("http://{addr}{path}"))
        .bearer_auth(&token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn post(addr: SocketAddr, path: &str, agent: Uuid, body: Value) -> (u16, Value) {
    send_with(addr, reqwest::Method::POST, path, agent, RW, Some(body)).await
}

async fn mine(addr: SocketAddr, agent: Uuid) -> Value {
    let (status, body) = send_with(
        addr,
        reqwest::Method::GET,
        "/api/v1/groups/mine",
        agent,
        RW,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    body
}

async fn human(pool: &PgPool, label: &str) -> Uuid {
    fixture::seed_human_operator(pool, label).await.0
}

async fn operated(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent");
    agent
}

async fn live_rows(pool: &PgPool, group: Uuid, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("count")
}

fn id_of(body: &Value, field: &str) -> Uuid {
    body[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} in {body}"))
        .parse()
        .expect("uuid")
}

/// The refusal's code, read from the body's text whatever its field name.
fn code_in(body: &Value) -> Option<String> {
    let text = body.to_string();
    let at = text.find("TGP0")?;
    Some(text[at..at + 5].to_string())
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_person_creates_invites_and_the_membership_goes_live_on_accept(pool: PgPool) {
    let (addr, _stop) = spawn_app(&pool).await;
    let a = human(&pool, "http-a").await;
    let b = human(&pool, "http-b").await;

    let (status, body) = post(
        addr,
        "/api/v1/groups/team",
        a,
        json!({"name": "Synthetic HTTP Team", "reason": "working group"}),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let group = id_of(&body, "group_id");
    assert_eq!(body["role"], "admin");
    assert_eq!(body["did_key"], format!("did:epigraph:group:{group}"));
    assert_eq!(live_rows(&pool, group, a).await, 1);

    let (status, body) = post(
        addr,
        &format!("/api/v1/groups/{group}/invitations"),
        a,
        json!({"agent_id": b, "role": "writer", "reason": "join us"}),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["status"], "pending");
    let invitation = id_of(&body, "invitation_id");
    assert_eq!(
        live_rows(&pool, group, b).await,
        0,
        "no membership before consent"
    );

    let b_mine = mine(addr, b).await;
    assert!(
        !b_mine["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["group_id"] == group.to_string()),
        "{b_mine}"
    );
    let invs = b_mine["invitations"].as_array().unwrap();
    assert_eq!(invs.len(), 1, "{b_mine}");
    assert_eq!(invs[0]["invitation_id"], invitation.to_string());
    assert_eq!(invs[0]["invited_by"], a.to_string());
    assert_eq!(invs[0]["display_name"], "Synthetic HTTP Team");
    assert_eq!(invs[0]["reason"], "join us");

    let (status, body) = post(
        addr,
        &format!("/api/v1/group-invitations/{invitation}/accept"),
        b,
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["role"], "writer");
    assert_eq!(body["group_id"], group.to_string());
    assert_eq!(live_rows(&pool, group, b).await, 1, "live once accepted");
    let b_mine = mine(addr, b).await;
    assert!(
        b_mine["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["group_id"] == group.to_string() && g["role"] == "writer"),
        "{b_mine}"
    );
    assert!(b_mine["invitations"].as_array().unwrap().is_empty());
    // GET /groups/:id still answers a member: the static `/groups/mine` and
    // `/groups/team` segments did not shadow it.
    let (status, body) = send_with(
        addr,
        reqwest::Method::GET,
        &format!("/api/v1/groups/{group}"),
        b,
        RW,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // A second invitee declines: nothing is joined.
    let c = human(&pool, "http-c").await;
    let (_, body) = post(
        addr,
        &format!("/api/v1/groups/{group}/invitations"),
        a,
        json!({"agent_id": c}),
    )
    .await;
    let inv_c = id_of(&body, "invitation_id");
    assert_eq!(body["role"], "reader", "the default role");
    let (status, body) = post(
        addr,
        &format!("/api/v1/group-invitations/{inv_c}/decline"),
        c,
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "declined");
    assert_eq!(live_rows(&pool, group, c).await, 0);
}

/// Input is normalised exactly as the MCP twin normalises it: the role is
/// trimmed (`" writer "` is `writer`, not a 400), and the echoed
/// `display_name` is what was stored (SQL `btrim` strips spaces only, so a
/// trailing tab stays).
#[sqlx::test(migrations = "../../migrations")]
async fn input_is_normalised_as_the_mcp_twin_normalises_it(pool: PgPool) {
    let (addr, _stop) = spawn_app(&pool).await;
    let a = human(&pool, "http-parity-a").await;
    let b = human(&pool, "http-parity-b").await;

    let (status, body) = post(
        addr,
        "/api/v1/groups/team",
        a,
        json!({"name": "  Synthetic Parity Team\t "}),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let group = id_of(&body, "group_id");
    let stored: String = sqlx::query_scalar("SELECT display_name::text FROM groups WHERE id = $1")
        .bind(group)
        .fetch_one(&pool)
        .await
        .expect("stored name");
    assert_eq!(
        stored, "Synthetic Parity Team\t",
        "PREMISE: btrim strips spaces only"
    );
    assert_eq!(body["display_name"], stored, "the echo is the stored name");

    let (status, body) = post(
        addr,
        &format!("/api/v1/groups/{group}/invitations"),
        a,
        json!({"agent_id": b, "role": " writer "}),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["role"], "writer");
    let role: String =
        sqlx::query_scalar("SELECT role FROM group_invitations WHERE invitee_agent_id = $1")
            .bind(b)
            .fetch_one(&pool)
            .await
            .expect("invitation row");
    assert_eq!(role, "writer");
}

/// Each designed refusal answers by its kind, carries its code, and writes
/// nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn each_refusal_answers_by_its_kind_with_nothing_written(pool: PgPool) {
    let (addr, _stop) = spawn_app(&pool).await;
    let a = human(&pool, "ref-a").await;
    let b = human(&pool, "ref-b").await;
    let outsider = human(&pool, "ref-out").await;
    let agent = operated(&pool, b, "ref-agent").await;
    let (_, body) = post(
        addr,
        "/api/v1/groups/team",
        a,
        json!({"name": "Synthetic Ref"}),
    )
    .await;
    let group = id_of(&body, "group_id");
    let (_, body) = post(
        addr,
        &format!("/api/v1/groups/{group}/invitations"),
        a,
        json!({"agent_id": b, "role": "writer"}),
    )
    .await;
    let invitation = id_of(&body, "invitation_id");
    let invitations: i64 = sqlx::query_scalar("SELECT count(*) FROM group_invitations")
        .fetch_one(&pool)
        .await
        .unwrap();
    let groups: i64 = sqlx::query_scalar("SELECT count(*) FROM groups")
        .fetch_one(&pool)
        .await
        .unwrap();

    let invite = format!("/api/v1/groups/{group}/invitations");
    let accept = format!("/api/v1/group-invitations/{invitation}/accept");
    let decline = format!("/api/v1/group-invitations/{invitation}/decline");
    let cases: Vec<(&str, String, Uuid, Value, u16, Option<&str>)> = vec![
        // (case, path, caller, body, status, code)
        (
            "duplicate name",
            "/api/v1/groups/team".into(),
            a,
            json!({"name": "synthetic ref"}),
            409,
            Some("TGP06"),
        ),
        (
            "blank name",
            "/api/v1/groups/team".into(),
            a,
            json!({"name": "  "}),
            400,
            Some("TGP09"),
        ),
        (
            "a non-member",
            invite.clone(),
            outsider,
            json!({"agent_id": b}),
            404,
            None,
        ),
        (
            "invitee not a Person",
            invite.clone(),
            a,
            json!({"agent_id": agent}),
            400,
            Some("TGP03"),
        ),
        (
            "already invited",
            invite.clone(),
            a,
            json!({"agent_id": b}),
            409,
            Some("TGP04"),
        ),
        (
            "bad role",
            invite.clone(),
            a,
            json!({"agent_id": outsider, "role": "owner"}),
            400,
            Some("TGP09"),
        ),
        (
            "missing group",
            format!("/api/v1/groups/{}/invitations", Uuid::new_v4()),
            a,
            json!({"agent_id": b}),
            404,
            None,
        ),
        (
            "accept as the inviter",
            accept.clone(),
            a,
            json!({}),
            404,
            None,
        ),
        (
            "decline as another",
            decline.clone(),
            outsider,
            json!({}),
            404,
            None,
        ),
    ];
    for (case, path, caller, body, want, code) in cases {
        let (status, got) = post(addr, &path, caller, body).await;
        assert_eq!(status, want, "{case}: {got}");
        if let Some(code) = code {
            assert_eq!(code_in(&got).as_deref(), Some(code), "{case}: {got}");
        }
    }
    let after_i: i64 = sqlx::query_scalar("SELECT count(*) FROM group_invitations")
        .fetch_one(&pool)
        .await
        .unwrap();
    let after_g: i64 = sqlx::query_scalar("SELECT count(*) FROM groups")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        (after_i, after_g),
        (invitations, groups),
        "no refusal wrote"
    );
    assert_eq!(live_rows(&pool, group, b).await, 0);

    // A writer is not an admin (403, authority).
    let (status, _) = post(addr, &accept, b, json!({})).await;
    assert_eq!(status, 200, "POSITIVE CONTROL: the invitee accepts");
    let (status, got) = post(addr, &invite, b, json!({"agent_id": outsider})).await;
    assert_eq!(status, 403, "{got}");
    assert_eq!(code_in(&got).as_deref(), Some("TGP02"), "{got}");
    // Answered once (409, state).
    let (status, got) = post(addr, &accept, b, json!({})).await;
    assert_eq!(status, 409, "{got}");
    assert_eq!(code_in(&got).as_deref(), Some("TGP05"), "{got}");

    // A token without groups:write writes nothing.
    let (status, got) = send_with(
        addr,
        reqwest::Method::POST,
        "/api/v1/groups/team",
        outsider,
        &["groups:read"],
        Some(json!({"name": "Synthetic Unscoped"})),
    )
    .await;
    assert_eq!(status, 403, "{got}");
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM groups WHERE display_name = 'Synthetic Unscoped'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(n, 0);
}

/// An agent its human operates is refused (403) on every write: creating,
/// and accepting an invitation addressed to its human.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_cannot_act_for_its_human(pool: PgPool) {
    let (addr, _stop) = spawn_app(&pool).await;
    let a = human(&pool, "op-a").await;
    let b = human(&pool, "op-b").await;
    let b_agent = operated(&pool, b, "op-b-agent").await;
    let (status, got) = post(
        addr,
        "/api/v1/groups/team",
        b_agent,
        json!({"name": "Synthetic Op"}),
    )
    .await;
    assert_eq!(status, 403, "{got}");
    let (_, body) = post(
        addr,
        "/api/v1/groups/team",
        a,
        json!({"name": "Synthetic Op"}),
    )
    .await;
    let group = id_of(&body, "group_id");
    let (_, body) = post(
        addr,
        &format!("/api/v1/groups/{group}/invitations"),
        a,
        json!({"agent_id": b}),
    )
    .await;
    let invitation = id_of(&body, "invitation_id");
    let (status, got) = post(
        addr,
        &format!("/api/v1/group-invitations/{invitation}/accept"),
        b_agent,
        json!({}),
    )
    .await;
    assert!(
        status == 403 || status == 404,
        "the human's agent does not consent for them: {status} {got}"
    );
    assert_eq!(live_rows(&pool, group, b).await, 0);
    assert_eq!(live_rows(&pool, group, b_agent).await, 0);
}
