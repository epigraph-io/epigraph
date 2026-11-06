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
/// stranger sees the agent and its human (the binding is shown to every
/// reader), and the snapshot only when the audience setting is every claim
/// reader.
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
    assert_eq!(
        theirs["human"], mine["human"],
        "every reader sees the human"
    );
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
    assert_eq!(theirs["source"], json!("agent"), "{theirs}");
    assert!(
        theirs.as_object().is_some_and(|o| o.len() == 4),
        "exactly source, agent, human, prompt_snapshot: {theirs}"
    );
}

/// `caller` writes an `OPERATED_BY` edge `agent -> target` through
/// `POST /api/v1/edges`, as any edges:write caller may.
async fn forge_over_http(state: &AppState, caller: Uuid, agent: Uuid, target: Uuid) {
    let token = common::mint_token_with_agent(&["edges:write"], caller);
    let body = json!({
        "source_id": agent, "source_type": "agent",
        "target_id": target, "target_type": "agent",
        "relationship": "OPERATED_BY",
    });
    let resp = create_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/edges")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    assert!(
        status.is_success(),
        "CALIBRATION: the route writes the forged edge: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
}

/// On the wire the human is the agent's binding, for every reader: a stranger
/// sees the human of a link no edge records, and edges the stranger forges
/// through `POST /api/v1/edges`, to a wrong guess and to the right human,
/// leave the block byte for byte as it was. A claim the caller cannot read is
/// the 404 a missing id gets, with no block.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_edge_changes_nothing_and_a_hidden_claim_leaks_nothing(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (operator, operator_group) = viewer_fixture::seed_agent_with_group(&pool, "op").await;
    viewer_fixture::make_human_operator(&pool, operator).await;
    named(&pool, operator, "Operator Fixture").await;
    let decoy = human(&pool, "Decoy Fixture").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = viewer_fixture::seed_agent_with_group(&pool, "member").await;
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "agent").await;
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) VALUES ($1, $2, $3)",
    )
    .bind(agent)
    .bind(operator)
    .bind(operator_group)
    .execute(&pool)
    .await
    .expect("a link row with no edge");
    let edges = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'OPERATED_BY'",
        )
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("count")
    };
    assert_eq!(edges().await, 0, "CALIBRATION: no edge records the link");
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "edgeless link claim").await;

    let before = authored_by(&state, stranger, claim).await;
    assert_eq!(
        before["human"],
        json!({"id": operator, "display_name": "Operator Fixture"}),
        "a stranger sees the binding: {before}"
    );
    forge_over_http(&state, stranger, agent, decoy).await;
    forge_over_http(&state, stranger, agent, operator).await;
    assert_eq!(edges().await, 2, "CALIBRATION: both forged edges landed");
    assert_eq!(
        authored_by(&state, stranger, claim).await,
        before,
        "forged edges change nothing on the wire"
    );

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

/// A claim a document asserts, on the wire: `source: "literature"`, the
/// document and its authors first (by position, with role and affiliations),
/// and the agent that filed the claim, with its human, apart as
/// `ingested_by`. A reader who cannot see the document's `asserts` edge gets
/// the agent block instead.
#[sqlx::test(migrations = "../../migrations")]
async fn a_literature_claim_names_the_document_authors_and_the_ingester_apart(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let operator = human(&pool, "Operator Fixture").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "stranger").await;
    let (member, group) = viewer_fixture::seed_agent_with_group(&pool, "member").await;
    let (ingester, _) = viewer_fixture::seed_agent_with_group(&pool, "ingester").await;
    named(&pool, ingester, "ingest-fixture").await;
    link(&pool, ingester, operator).await;
    let claim = viewer_fixture::seed_public_claim(&pool, ingester, "wire literature claim").await;
    let doc: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.0000/fixture.wire', 'Wire Paper') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("paper");
    let edge = |src: Uuid,
                st: &'static str,
                tgt: Uuid,
                tt: &'static str,
                rel: &'static str,
                props: Value| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                    properties) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            )
            .bind(src)
            .bind(st)
            .bind(tgt)
            .bind(tt)
            .bind(rel)
            .bind(props)
            .fetch_one(&pool)
            .await
            .expect("edge")
        }
    };
    let asserts = edge(doc, "paper", claim, "claim", "asserts", json!({})).await;
    let (second, _) = viewer_fixture::seed_agent_with_group(&pool, "second").await;
    named(&pool, second, "Second Author").await;
    let (first, _) = viewer_fixture::seed_agent_with_group(&pool, "first").await;
    named(&pool, first, "First Author").await;
    edge(
        second,
        "agent",
        doc,
        "paper",
        "authored",
        json!({"position": 1, "role": "author", "affiliations": []}),
    )
    .await;
    edge(
        first,
        "agent",
        doc,
        "paper",
        "authored",
        json!({"position": 0, "role": "corresponding", "affiliations": ["Fixture Institute"]}),
    )
    .await;

    let block = authored_by(&state, stranger, claim).await;
    assert_eq!(block["source"], json!("literature"), "{block}");
    assert!(block.get("agent").is_none(), "{block}");
    assert_eq!(block["papers_truncated"], json!(false));
    let p = &block["papers"][0];
    assert_eq!(
        p["paper"],
        json!({"id": doc, "doi": "10.0000/fixture.wire", "title": "Wire Paper"})
    );
    assert_eq!(
        p["authors"],
        json!([
            {"id": first, "display_name": "First Author", "position": 0,
             "role": "corresponding", "affiliations": ["Fixture Institute"]},
            {"id": second, "display_name": "Second Author", "position": 1,
             "role": "author", "affiliations": []},
        ]),
        "{block}"
    );
    assert_eq!(p["authors_truncated"], json!(false));
    assert_eq!(
        block["ingested_by"]["agent"],
        json!({"id": ingester, "display_name": "ingest-fixture"})
    );
    assert_eq!(
        block["ingested_by"]["human"],
        json!({"id": operator, "display_name": "Operator Fixture"})
    );
    assert_eq!(block["ingested_by"]["prompt_snapshot"], Value::Null);

    // The document's asserts edge private to the member's group: the member
    // still sees the literature block, a stranger the plain agent block.
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(asserts)
    .bind(group)
    .execute(&pool)
    .await
    .expect("make the asserts edge group-private");
    assert_eq!(
        authored_by(&state, member, claim).await["source"],
        json!("literature")
    );
    let plain = authored_by(&state, stranger, claim).await;
    assert_eq!(plain["source"], json!("agent"), "{plain}");
    assert_eq!(plain["agent"]["id"], json!(ingester));
    assert_eq!(plain["human"]["id"], json!(operator));
}
