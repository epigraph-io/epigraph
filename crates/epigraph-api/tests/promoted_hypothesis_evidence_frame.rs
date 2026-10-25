//! `POST /api/v1/frames/:id/evidence` naming `hypothesis_assessment` for a
//! PROMOTED hypothesis files the BBA on `research_validity` (operator ruling
//! R-8: evidence submitted against a hypothesis after its promotion goes to the
//! frame its readers read, on every transport that writes hypothesis evidence).
//!
//! A promotion MOVES the hypothesis's evidence onto `research_validity`, and
//! every reader of a promoted hypothesis (`GET /hypothesis/:id/status`, the CLI
//! `hypothesis status`) reads that frame (`promotion::status_belief_frame`). A
//! BBA filed on `hypothesis_assessment` afterwards is read by none of them. The
//! MCP twin is `epigraph-mcp/tests/ds_evidence_promoted_hypothesis.rs`.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

async fn spawn_app(conn_opts: &PgConnectOptions) -> (SocketAddr, oneshot::Sender<()>) {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let db = conn_opts.get_database().expect("test database name");
    let prefix = base
        .split_once('?')
        .map_or(base.as_str(), |(a, _)| a)
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0
        .to_string();
    let scoped = epigraph_db::ScopedPool::connect(
        &format!("{prefix}/{db}"),
        epigraph_db::SessionGucMode::Session,
    )
    .await
    .expect("ScopedPool::connect");
    let state =
        epigraph_api::AppState::with_scoped_pool(scoped, epigraph_api::ApiConfig::default());
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

async fn ensure_frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['supported','unsupported']::text[]) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {name} frame: {e}"))
}

/// A public hypothesis owned by `group`, with `hypothesis_status` = `status`.
async fn hypothesis(pool: &PgPool, agent: Uuid, group: Uuid, status: &str) -> Uuid {
    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, \
                             properties, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, ARRAY['hypothesis'], $5, 'public', $6)",
    )
    .bind(claim)
    .bind(format!("r8 {status} hypothesis {claim}"))
    .bind(hash)
    .bind(agent)
    .bind(serde_json::json!({ "hypothesis_status": status }))
    .bind(group)
    .execute(pool)
    .await
    .expect("seed hypothesis");
    claim
}

async fn frames_with_bbas(pool: &PgPool, claim: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT frame_id FROM mass_functions WHERE claim_id = $1 ORDER BY created_at, id",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read BBAs")
}

async fn post(addr: SocketAddr, token: &str, frame: Uuid, claim: Uuid) -> Value {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/frames/{frame}/evidence"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "claim_id": claim,
            "masses": {"1": 0.7, "0,1": 0.3},
        }))
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    assert_eq!(status, 201, "POST evidence must be 201: {text}");
    serde_json::from_str(&text).expect("json body")
}

#[sqlx::test(migrations = "../../migrations")]
async fn evidence_named_on_hypothesis_assessment_for_a_promoted_hypothesis_lands_on_research_validity(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (agent, group) = fixture::seed_agent_with_group(&pool, "r8-rest").await;
    let hyp_frame = ensure_frame(&pool, "hypothesis_assessment").await;
    let rv_frame = ensure_frame(&pool, "research_validity").await;
    let promoted = hypothesis(&pool, agent, group, "promoted").await;
    let active = hypothesis(&pool, agent, group, "active").await;
    let (addr, _shutdown) = spawn_app(&conn_opts).await;
    let token = common::mint_token_with_agent(&["claims:write"], agent);

    // CALIBRATION: the route files a not-yet-promoted hypothesis's evidence
    // where it was named, so what follows is about the promotion only.
    post(addr, &token, hyp_frame, active).await;
    assert_eq!(frames_with_bbas(&pool, active).await, vec![hyp_frame]);

    let out = post(addr, &token, hyp_frame, promoted).await;
    assert_eq!(
        frames_with_bbas(&pool, promoted).await,
        vec![rv_frame],
        "a promoted hypothesis's evidence is filed on research_validity, where its readers \
         look: {out}"
    );
    let warned = out["warnings"].as_array().is_some_and(|w| {
        w.iter().any(|s| {
            s.as_str()
                .is_some_and(|s| s.contains("research_validity") && s.contains("promoted"))
        })
    });
    assert!(warned, "the response says where the evidence went: {out}");
}
