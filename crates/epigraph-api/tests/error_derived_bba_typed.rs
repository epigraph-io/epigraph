//! `POST /api/v1/experiments/:eid/results/:rid/analyze` writes an
//! `error_derived` BBA through `MassFunctionRepository::store`, which had no
//! `evidence_type` parameter (backlog bc06ec6f). Its type now comes from the
//! result's `data_source`: `instrument` is a direct measurement
//! (`empirical`); `literature` does not say what kind of support the cited
//! value is, so it stays NULL.
#![cfg(feature = "db")]

mod common;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

/// The app on the per-test database (not `DATABASE_URL`'s), so the routes
/// read the rows this test seeds.
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

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, owner: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!("{content} {}", Uuid::new_v4()))
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// (source_agent_id, combination_method, evidence_type) of every BBA on the pair.
async fn bbas(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
) -> Vec<(Option<Uuid>, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT source_agent_id, combination_method, evidence_type FROM mass_functions \
         WHERE claim_id = $1 AND frame_id = $2 ORDER BY source_agent_id NULLS FIRST",
    )
    .bind(claim)
    .bind(frame)
    .fetch_all(pool)
    .await
    .expect("read BBAs")
}

/// Seed hypothesis claim + `hypothesis_assessment` frame + experiment + result
/// with `data_source`, then call the analyze route; return the hypothesis id
/// and the frame id.
async fn analyze_with_data_source(
    pool: &PgPool,
    conn_opts: &PgConnectOptions,
    data_source: &str,
) -> (Uuid, Uuid) {
    let agent = seed_agent(pool).await;
    let hypothesis = seed_claim(pool, agent, "bc06ec6f error_derived hypothesis").await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ('hypothesis_assessment', \
         ARRAY['true','false']::text[]) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed hypothesis_assessment frame");
    let experiment: Uuid = sqlx::query_scalar(
        "INSERT INTO experiments (hypothesis_id, created_by, status) \
         VALUES ($1, $2, 'collecting') RETURNING id",
    )
    .bind(hypothesis)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed experiment");
    let result: Uuid = sqlx::query_scalar(
        "INSERT INTO experiment_results (experiment_id, data_source, raw_measurements, measurement_count) \
         VALUES ($1, $2, $3, 2) RETURNING id",
    )
    .bind(experiment)
    .bind(data_source)
    .bind(serde_json::json!([
        {"value": 1.2, "random_error": 0.05, "systematic_error": 0.02},
        {"value": 1.1, "random_error": 0.05, "systematic_error": 0.02}
    ]))
    .fetch_one(pool)
    .await
    .expect("seed result");

    let (addr, _shutdown) = spawn_app(conn_opts).await;
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/experiments/{experiment}/results/{result}/analyze"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "agent_id": agent,
            "direction": "supports",
            "scope_limitations": [],
            "expected_value": 0.0,
        }))
        .send()
        .await
        .expect("analyze request");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(
        status.is_success(),
        "analyze ({data_source}): {status} {body}"
    );
    (hypothesis, frame)
}

async fn error_derived_type(pool: &PgPool, claim: Uuid, frame: Uuid) -> Option<String> {
    let rows = bbas(pool, claim, frame).await;
    let derived: Vec<_> = rows
        .iter()
        .filter(|(_, m, _)| m.as_deref() == Some("error_derived"))
        .collect();
    assert_eq!(derived.len(), 1, "one error_derived BBA: {rows:?}");
    derived[0].2.clone()
}

#[sqlx::test(migrations = "../../migrations")]
async fn analyze_types_an_instrument_result_empirical(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let (claim, frame) = analyze_with_data_source(&pool, &conn_opts, "instrument").await;
    assert_eq!(
        error_derived_type(&pool, claim, frame).await.as_deref(),
        Some("empirical")
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn analyze_leaves_a_literature_result_untyped(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let (claim, frame) = analyze_with_data_source(&pool, &conn_opts, "literature").await;
    assert_eq!(error_derived_type(&pool, claim, frame).await, None);
}
