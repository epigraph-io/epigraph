//! `POST /api/v1/claims/:id/assess` must never leave a typed row (backlog
//! bc06ec6f). Its input BBA and its combined cache share one `mass_functions`
//! key, so the handler does not store the cache over the input (backlog
//! b5cb3efb). The row that survives is the input. It must stay untyped,
//! because its masses were already sized with the request's type weight.
//!
//! Its own binary because the handler reads `calibration.toml` relative to the
//! working directory, so this test moves the process to the workspace root.
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
async fn assess_leaves_only_its_untyped_input(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    // The handler loads `calibration.toml` from the working directory.
    std::env::set_current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .expect("cd to the workspace root");

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

    // The handler stores its input BBA with no agent and no perspective. The
    // combined result's key is the SAME (claim, frame, NULL, NULL; unique NULLS
    // NOT DISTINCT, migration 034), so storing it would overwrite the input, and
    // the combine-input readers would then drop that input as a cached row.
    // The handler therefore skips the cache while an input holds the slot
    // (backlog b5cb3efb). What survives is the untyped input.
    let rows: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, combination_method, evidence_type FROM mass_functions WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_all(&pool)
    .await
    .expect("BBAs");
    assert_eq!(
        rows.len(),
        1,
        "one row on the shared key: the input, with no cache beside it: {rows:?}"
    );
    assert_eq!(
        rows[0].0, mf_id,
        "the surviving row is the input the handler stored: {rows:?}"
    );
    assert_eq!(
        rows[0].1.as_deref(),
        Some("discount"),
        "the input row survives; no combined cache was stored over it: {rows:?}"
    );
    assert_eq!(rows[0].2, None, "the input must stay untyped: {rows:?}");
}
