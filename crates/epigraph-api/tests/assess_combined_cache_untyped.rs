//! `POST /api/v1/claims/:id/assess` must never leave a typed row
//! (backlog bc06ec6f). Its one stored row is the request's own input BBA, and
//! it stays untyped: `build_bba_directed` already sized its masses with the
//! request's type weight, so a typed row would be discounted a second time on
//! any later fold.
//!
//! Until U027 the handler also stored a "combined result" row on the input's
//! `(claim, frame, NULL agent, NULL perspective)` key, which replaced the input
//! in the same request (main later skipped that store while an input held the
//! slot, backlog b5cb3efb). Each call now stores its input in its OWNER's one
//! assessment slot (ruling Q-U027F-2: key (claim, frame, owner, the owner's
//! slot perspective)) and no combined row at all, so the row that survives IS
//! the `discount` input row.
//!
//! Driven over HTTP with a real bearer agent, so it also pins that the slot is
//! that agent's own (an unlinked agent is its own owner) and that the slot
//! perspective records it as `owner_agent_id` (`TenancyDecl::instance_wide`).
#![cfg(feature = "db")]

mod common;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
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

#[sqlx::test(migrations = "../../migrations")]
async fn assess_leaves_only_its_untyped_input_row(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent)
        .bind(&pk)
        .execute(&pool)
        .await
        .expect("seed agent");
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!("bc06ec6f assess typing {}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("seed claim");

    let (addr, _shutdown) = spawn_app(&conn_opts).await;
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim}/assess"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "evidence_type": "Observation",
            "methodology": "instrumental",
            "confidence": 0.8,
            "supports": true,
        }))
        .send()
        .await
        .expect("assess request");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(status.is_success(), "assess: {status} {body}");
    let mf_id: Uuid = body["mass_function_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("mass_function_id in {body}"));

    // One call stores exactly one row: its own input BBA, in its owner's
    // assessment slot. No combined row is stored beside or over it.
    let rows: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, combination_method, evidence_type FROM mass_functions WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_all(&pool)
    .await
    .expect("BBAs");
    assert_eq!(rows.len(), 1, "one call stores exactly one row: {rows:?}");
    assert_eq!(
        rows[0].0, mf_id,
        "the surviving row is the call's input row: {rows:?}"
    );
    assert_eq!(
        rows[0].1.as_deref(),
        Some("discount"),
        "the surviving row is the discount input, not a combined cache: {rows:?}"
    );
    assert_eq!(rows[0].2, None, "the input BBA must stay untyped: {rows:?}");

    // Ruling Q-U027F-2: the row is the caller's OWNER's one assessment slot,
    // keyed (claim, frame, owner, the owner's assessment perspective); an
    // unlinked agent is its own owner, and the slot perspective records it.
    let (source, slot_owner): (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT m.source_agent_id, p.owner_agent_id FROM mass_functions m \
           JOIN perspectives p ON p.id = m.perspective_id WHERE m.id = $1",
    )
    .bind(mf_id)
    .fetch_one(&pool)
    .await
    .expect("the input row and its slot perspective");
    assert_eq!(
        (source, slot_owner),
        (Some(agent), Some(agent)),
        "the input row must sit in the calling agent's own assessment slot"
    );
}
