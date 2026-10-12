//! `POST /api/v1/frames/:id/evidence` must store the canonical evidence type
//! it is given, and never type the combined system row (backlog bc06ec6f).
//!
//! The caller's `evidence_type` is resolved through `calibration.toml
//! [evidence_type_aliases]`. The combined row the handler caches beside the
//! inputs (`source_agent_id IS NULL`) aggregates every input, so it has no
//! single type and stays NULL.
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

#[sqlx::test(migrations = "../../migrations")]
async fn submit_evidence_stores_the_canonical_type_and_leaves_the_combined_row_untyped(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let owner = seed_agent(&pool).await;
    let (a, b) = (seed_agent(&pool).await, seed_agent(&pool).await);
    let claim = seed_claim(&pool, owner, "bc06ec6f REST evidence typing").await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['TRUE','FALSE']::text[]) \
         RETURNING id",
    )
    .bind(format!("bc06ec6f-rest-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");

    let (addr, _shutdown) = spawn_app(&conn_opts).await;
    let client = reqwest::Client::new();
    for (agent, et) in [(a, "Observation"), (b, "testimony")] {
        let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
        let resp = client
            .post(format!("http://{addr}/api/v1/frames/{frame}/evidence"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "claim_id": claim,
                "agent_id": agent,
                "masses": {"0": 0.6, "0,1": 0.4},
                "reliability": 1.0,
                "evidence_type": et,
                "assume_independent": true,
            }))
            .send()
            .await
            .expect("evidence request");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("json body");
        assert_eq!(status, 201, "POST evidence ({et}): {body}");
    }

    let rows = bbas(&pool, claim, frame).await;
    let typed: Vec<_> = rows
        .iter()
        .filter(|(agent, _, _)| agent.is_some())
        .map(|(agent, _, et)| (agent.unwrap(), et.clone()))
        .collect();
    assert!(
        typed.contains(&(a, Some("empirical".to_string()))),
        "the `Observation` input must be stored as `empirical`: {rows:?}"
    );
    assert!(
        typed.contains(&(b, Some("testimonial".to_string()))),
        "the `testimony` input must be stored as `testimonial`: {rows:?}"
    );

    // Non-vacuity: the combined system row exists, and it carries no type.
    let combined: Vec<_> = rows
        .iter()
        .filter(|(agent, _, _)| agent.is_none())
        .collect();
    assert_eq!(combined.len(), 1, "one combined system row: {rows:?}");
    assert_eq!(
        combined[0].2, None,
        "the combined row must stay untyped: {rows:?}"
    );
}
