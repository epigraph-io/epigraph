//! `POST /api/v1/frames/:id/evidence` and `GET /api/v1/claims/:id/pignistic`
//! must report the conflict their fold SAW (drain unit U025, backlog
//! 9d4821c1).
//!
//! Since U025 `combine_multiple` folds with Dempster at every step, so the
//! combined BBA's residual empty-set mass (`combined.mass_of_empty()`) is
//! always 0 after a fold. Both handlers used to read that residual as
//! "mass on conflict": `submit_evidence` cached it in `claims.mass_on_empty`
//! and echoed it as `mass_on_conflict`, `get_pignistic` returned it. Read that
//! way, two BBAs in head-on conflict would report 0 here while the recompute
//! (`edge_factor::compute_combined_belief`, see
//! `epigraph-engine/tests/recompute_reports_fold_conflict.rs`) caches the
//! fold's K = 0.64 for the same claim: the writer and the recompute would
//! disagree on the cached conflict. Both handlers now read
//! `combination::fold_conflict`.
//!
//! Two distinct source agents are required: `mass_functions` upserts on
//! `(claim_id, frame_id, source_agent_id, perspective_id)`, so a second BBA
//! from the same agent would REPLACE the first and fold nothing.
#![cfg(feature = "db")]

mod common;

use serde_json::Value;
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

/// `POST /api/v1/frames/:id/evidence` as `agent`, asserting 201; the body.
async fn submit(
    client: &reqwest::Client,
    addr: SocketAddr,
    frame: Uuid,
    claim: Uuid,
    agent: Uuid,
    masses: Value,
) -> Value {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = client
        .post(format!("http://{addr}/api/v1/frames/{frame}/evidence"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "claim_id": claim,
            "agent_id": agent,
            "masses": masses,
            "reliability": 1.0,
            "assume_independent": true,
        }))
        .send()
        .await
        .expect("evidence request");
    let status = resp.status();
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(status, 201, "POST evidence as {agent}: {body}");
    body
}

fn approx(v: &Value, expected: f64) -> bool {
    v.as_f64().is_some_and(|x| (x - expected).abs() < 1e-9)
}

/// m(TRUE) = 0.8 vs m(FALSE) = 0.8, each from its own agent, undiscounted:
/// K = 0.8 * 0.8 = 0.64. The writer's echo, its cache column and the
/// compute-on-read pignistic route must all report 0.64.
#[sqlx::test(migrations = "../../migrations")]
async fn head_on_conflict_is_reported_by_the_writer_and_the_pignistic_read(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let owner = seed_agent(&pool).await;
    let (pro, con) = (seed_agent(&pool).await, seed_agent(&pool).await);
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!(
        "u025 submit_evidence head-on conflict {}",
        Uuid::new_v4()
    ))
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("seed claim");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['TRUE','FALSE']::text[]) \
         RETURNING id",
    )
    .bind(format!("u025-fold-conflict-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");

    let (addr, _shutdown) = spawn_app(&conn_opts).await;
    let client = reqwest::Client::new();

    // (1) One BBA: no fold, nothing to conflict with.
    let first = submit(
        &client,
        addr,
        frame,
        claim,
        pro,
        serde_json::json!({"0": 0.8, "0,1": 0.2}),
    )
    .await;
    assert!(
        approx(&first["mass_on_conflict"], 0.0),
        "a single BBA has no conflict: {first}"
    );

    // (2) The opposing BBA from a second agent. Non-vacuity: the handler must
    // actually have folded two BBAs, or a 0 below would prove nothing.
    let second = submit(
        &client,
        addr,
        frame,
        claim,
        con,
        serde_json::json!({"1": 0.8, "0,1": 0.2}),
    )
    .await;
    // (`total_sources` is no probe: it counts every `mass_functions` row for
    // the pair, including rows the handler derives itself.)
    let steps = second["combination_reports"]
        .as_array()
        .unwrap_or_else(|| panic!("combination_reports is an array: {second}"));
    assert_eq!(
        steps.len(),
        1,
        "two BBAs fold in exactly one step: {second}"
    );
    assert!(
        approx(&steps[0]["conflict_k"], 0.64),
        "the one step is the head-on pair, K = 0.64: {second}"
    );
    assert!(
        approx(&second["mass_on_conflict"], 0.64),
        "submit_evidence must echo the fold's conflict K = 0.64: {second}"
    );

    let cached: f64 = sqlx::query_scalar("SELECT mass_on_empty FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("read cache");
    assert!(
        (cached - 0.64).abs() < 1e-9,
        "submit_evidence must cache the fold's conflict in claims.mass_on_empty, got {cached}"
    );

    // (3) The compute-on-read route folds the same two BBAs.
    let token = common::mint_token_with_agent(&["claims:read"], owner);
    let resp = client
        .get(format!(
            "http://{addr}/api/v1/claims/{claim}/pignistic?frame_id={frame}"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("pignistic request");
    let status = resp.status();
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(status, 200, "GET pignistic: {body}");
    assert!(
        approx(&body["mass_on_conflict"], 0.64),
        "get_pignistic must report the fold's conflict K = 0.64, as the cache does: {body}"
    );
}
