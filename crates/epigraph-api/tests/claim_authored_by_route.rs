#![cfg(feature = "db")]
//! `GET /api/v1/claims/:id` carries `authored_by` (backlog 48421526): the
//! agent that filed the claim, the human it acts for, and the prompt snapshot
//! it was running, each under the caller's viewer.
//!
//! Every request goes through the full router with a real bearer, on an
//! `AppState` whose pools are both the APPLICATION ROLE: on the superuser pool
//! `epigraph_bypass()` is true, so every caller would pass the snapshot gate
//! and every edge would be readable, and "a stranger does not see it" could
//! not fail.
//!
//! The snapshot's audience is the ONE constant
//! `epigraph_db::PROMPT_SNAPSHOT_AUDIENCE`. These tests read it and assert
//! whichever setting is live, so the owner's ruling is that one line; the
//! repo-level tests (`epigraph-db/tests/claim_authored_by.rs`) drive both
//! settings explicitly.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{
    AgentIdentityRepository, AgentRepository, IdentityRegistration, PromptFile,
    PromptSnapshotAudience, ScopedPool, SessionGucMode, PROMPT_SNAPSHOT_AUDIENCE,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{as_role, database_url_for, downgraded_pool};

async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

async fn named(pool: &PgPool, agent: Uuid, name: &str) {
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(agent)
        .bind(name)
        .execute(pool)
        .await
        .expect("name the agent");
}

/// A registered human with its personal group (so its viewer reads).
async fn human(pool: &PgPool, name: &str) -> Uuid {
    let (id, _) = viewer_fixture::seed_agent_with_group(pool, name).await;
    viewer_fixture::make_human_operator(pool, id).await;
    named(pool, id, name).await;
    id
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("the maintenance role links the agent");
    assert!(out.link_live, "CALIBRATION: the manual link is live");
}

/// A registered EpiClaw identity linked to `operator`: `(agent, snapshot)`.
async fn registered_agent(pool: &PgPool, operator: Uuid) -> (Uuid, Uuid) {
    let pubkey = random32();
    let reg = IdentityRegistration {
        identity_pubkey: pubkey,
        parent_agent_id: None,
        model: "test-model-7".to_string(),
        prompt_hash: blake3::hash(&pubkey).to_hex().to_string(),
        group_folder: "g-authored".to_string(),
        signing_pubkey: Some(random32()),
        identity_md: PromptFile::Absent,
        global_claude_md: PromptFile::Absent,
        group_claude_md: PromptFile::Stored(b"group rules\n".to_vec()),
        learned_md: PromptFile::Absent,
        in_prompt: json!({"global_claude_md": false, "group_claude_md": true, "learned_md": false}),
        runner_version: Some("runner-test".to_string()),
        host_sha: None,
    };
    let out = as_role(pool, "epigraph_identity_attestor", |mut conn| async move {
        let r = AgentIdentityRepository::register(&mut conn, &reg).await;
        (conn, r)
    })
    .await
    .expect("the attestor registers");
    link(pool, out.agent_id, operator).await;
    named(pool, out.agent_id, "fixture-agent-7").await;
    (out.agent_id, out.snapshot_id)
}

async fn get_claim(state: &AppState, caller: Uuid, claim: Uuid) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/v1/claims/{claim}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

async fn authored_by(state: &AppState, caller: Uuid, claim: Uuid) -> Value {
    let (status, body) = get_claim(state, caller, claim).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["authored_by"].clone()
}

/// The agent's human sees the whole block; an admin sees the snapshot; a
/// stranger sees the agent and (through the public link edge) the human, and
/// the snapshot only when the audience setting is every claim reader.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_read_names_the_agent_the_human_and_the_snapshot_by_audience(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let operator = human(&pool, "Operator Fixture").await;
    let custodian = human(&pool, "Custodian Fixture").await;
    viewer_fixture::make_custodian(&pool, custodian).await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (agent, snapshot) = registered_agent(&pool, operator).await;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "authored-by fixture claim").await;

    let mine = authored_by(&state, operator, claim).await;
    assert_eq!(
        mine["agent"],
        json!({"id": agent, "display_name": "fixture-agent-7"}),
        "{mine}"
    );
    assert_eq!(
        mine["human"],
        json!({"id": operator, "display_name": "Operator Fixture"}),
        "{mine}"
    );
    let snap = &mine["prompt_snapshot"];
    assert_eq!(snap["snapshot_id"], json!(snapshot), "{mine}");
    assert_eq!(snap["model"], json!("test-model-7"), "{mine}");
    assert_eq!(
        snap["prompt_hash"].as_str().map(str::len),
        Some(64),
        "{mine}"
    );
    assert!(snap["started_at"].is_string(), "{mine}");
    assert!(snap.get("text").is_none(), "no prompt text: {mine}");

    let admin = authored_by(&state, custodian, claim).await;
    assert_eq!(
        &admin["prompt_snapshot"], snap,
        "an admin sees the snapshot"
    );

    let theirs = authored_by(&state, stranger, claim).await;
    assert_eq!(theirs["agent"], mine["agent"]);
    assert_eq!(theirs["human"], mine["human"], "the link edge is public");
    match PROMPT_SNAPSHOT_AUDIENCE {
        PromptSnapshotAudience::OperatorAndAdmins => assert_eq!(
            theirs["prompt_snapshot"],
            Value::Null,
            "gated: a stranger does not see the snapshot: {theirs}"
        ),
        PromptSnapshotAudience::ClaimReaders => assert_eq!(
            &theirs["prompt_snapshot"], snap,
            "open: every reader of the claim sees the snapshot"
        ),
    }
    assert!(
        theirs.as_object().is_some_and(|o| o.len() == 3),
        "exactly agent, human, prompt_snapshot: {theirs}"
    );
}

/// A link the caller cannot read (its edge private to a group the caller is
/// not in) reads, on the wire, exactly like an agent bound to no human; a
/// claim the caller cannot read is the 404 a missing id gets, with no block.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_link_and_a_hidden_claim_leak_nothing_on_the_wire(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let operator = human(&pool, "Operator Fixture").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = viewer_fixture::seed_agent_with_group(&pool, "member").await;
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "agent").await;
    link(&pool, agent, operator).await;
    let (unbound, _) = viewer_fixture::seed_agent_with_group(&pool, "unbound").await;
    let moved = sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $3, co_owner_group_id = NULL \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'OPERATED_BY'",
    )
    .bind(agent)
    .bind(operator)
    .bind(group)
    .execute(&pool)
    .await
    .expect("make the link edge group-private")
    .rows_affected();
    assert_eq!(moved, 1, "CALIBRATION: one OPERATED_BY edge");
    let linked_claim = viewer_fixture::seed_public_claim(&pool, agent, "hidden link claim").await;
    let unbound_claim = viewer_fixture::seed_public_claim(&pool, unbound, "unbound claim").await;

    assert_eq!(
        authored_by(&state, member, linked_claim).await["human"]["id"],
        json!(operator),
        "CONTROL: a member of the edge's group sees the human"
    );
    let mut hidden = authored_by(&state, stranger, linked_claim).await;
    let mut none = authored_by(&state, stranger, unbound_claim).await;
    hidden["agent"] = Value::Null;
    none["agent"] = Value::Null;
    assert_eq!(hidden, none, "a hidden link reads as no human");

    let private = viewer_fixture::seed_group_claim(&pool, agent, group, "private claim").await;
    let (status, body) = get_claim(&state, member, private).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CONTROL: the member reads it: {body}"
    );
    let (status, hidden_body) = get_claim(&state, stranger, private).await;
    let (missing_status, missing_body) = get_claim(&state, stranger, Uuid::new_v4()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert!(hidden_body.get("authored_by").is_none(), "{hidden_body}");
    let strip = |mut v: Value| {
        if let Some(o) = v.as_object_mut() {
            o.retain(|k, _| k != "details" && k != "message");
        }
        v
    };
    assert_eq!(
        strip(hidden_body),
        strip(missing_body),
        "the same 404 shape"
    );
}
