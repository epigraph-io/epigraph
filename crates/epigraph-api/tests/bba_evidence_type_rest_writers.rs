//! `POST /api/v1/frames/:id/evidence` must store the canonical evidence type
//! it is given (backlog bc06ec6f), and store nothing beside the inputs.
//!
//! The caller's `evidence_type` is resolved through `calibration.toml
//! [evidence_type_aliases]`. An input sent without `evidence_type` stays
//! NULL: its masses are already discounted by `reliability`, and a type the
//! writer invented would discount them again.
//!
//! The handler used to cache a NULL-agent "combined" row beside the inputs,
//! which this file pinned as untyped. Since U024 (backlogs 2bffdfdc,
//! 82dcff9d) the handler delegates to the shared recompute and stores no
//! derived row at all, so the pins below say that instead.
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

/// POST one input BBA as `agent`, with `evidence_type` only when given.
async fn post_evidence(addr: &SocketAddr, frame: Uuid, claim: Uuid, agent: Uuid, et: Option<&str>) {
    let mut body = serde_json::json!({
        "claim_id": claim,
        "agent_id": agent,
        "masses": {"0": 0.6, "0,1": 0.4},
        "reliability": 1.0,
        "assume_independent": true,
    });
    if let Some(et) = et {
        body["evidence_type"] = serde_json::json!(et);
    }
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/frames/{frame}/evidence"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("evidence request");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(status, 201, "POST evidence ({et:?}): {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_evidence_stores_the_canonical_type_and_no_combined_row(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let owner = seed_agent(&pool).await;
    let (a, b, c) = (
        seed_agent(&pool).await,
        seed_agent(&pool).await,
        seed_agent(&pool).await,
    );
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
    for (agent, et) in [(a, Some("Observation")), (b, Some("testimony")), (c, None)] {
        post_evidence(&addr, frame, claim, agent, et).await;
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
    assert!(
        typed.contains(&(c, None)),
        "an input sent with no `evidence_type` must stay untyped: {rows:?}"
    );

    // Exactly the three inputs: no NULL-agent combined row beside them.
    assert_eq!(
        rows.len(),
        3,
        "one BBA per input, nothing derived: {rows:?}"
    );
    assert!(
        rows.iter().all(|(agent, _, _)| agent.is_some()),
        "no combined system row may be stored: {rows:?}"
    );
}

/// A single input is stored typed, and it is the only row: the handler used
/// to fold it into a NULL-agent, NULL-method combined row beside it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_single_input_is_stored_typed_and_alone(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let owner = seed_agent(&pool).await;
    let a = seed_agent(&pool).await;
    let claim = seed_claim(&pool, owner, "bc06ec6f REST single-input fold").await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['TRUE','FALSE']::text[]) \
         RETURNING id",
    )
    .bind(format!("bc06ec6f-rest-single-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");

    let (addr, _shutdown) = spawn_app(&conn_opts).await;
    post_evidence(&addr, frame, claim, a, Some("observation")).await;

    let rows = bbas(&pool, claim, frame).await;
    assert!(
        rows.contains(&(
            Some(a),
            Some("discount".to_string()),
            Some("empirical".to_string())
        )),
        "the input is stored typed: {rows:?}"
    );
    assert_eq!(rows.len(), 1, "the input is the only row: {rows:?}");
}
