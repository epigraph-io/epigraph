//! `POST /api/v1/evidence` with dataset evidence (backlog c8beb101).
//!
//! The route deserialises `evidence_type` straight into
//! `epigraph_core::EvidenceType`, so a `{"type": "dataset", ...}` body was
//! refused as an unknown variant before the Dataset variant existed, and with
//! the variant but no validation a malformed manifest digest would be stored
//! for no reader to verify against. Bodies are raw JSON on purpose, so the
//! same request runs against the old code and fails on its assertions.
//!
//! `#[sqlx::test]` (a database migrated from empty, 229 included), served
//! through the real router.
#![cfg(feature = "db")]

mod common;

use serde_json::{json, Value};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

const B3_HEX: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
const ROOT: &str = "https://data.example.org/c8beb101/run-7/";

fn dataset_body(agent: Uuid, claim: Uuid, manifest_hash: &str) -> Value {
    json!({
        "agent_id": agent,
        "claim_id": claim,
        "raw_content": format!("run 7 output, manifest {manifest_hash}"),
        "evidence_type": {
            "type": "dataset",
            "root_uri": ROOT,
            "manifest_uri": null,
            "manifest_blob_id": "blob-manifest-7",
            "manifest_hash": manifest_hash,
            "hash_algorithm": "blake3",
            "file_count": 40,
            "total_bytes": 123_456_789,
            "sample_id": null
        }
    })
}

/// A dataset body lands as a `dataset` row with every field intact and its
/// root in `evidence.source_url`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dataset_body_is_stored_as_dataset_evidence(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts.connect_with(conn_opts.clone()).await.unwrap();
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, agent, "c8beb101: http dataset claim").await;
    let (addr, _shutdown) = spawn_app(pool.clone(), &conn_opts).await;
    let token = common::mint_token_with_agent(&["evidence:write"], agent);

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/evidence"))
        .bearer_auth(&token)
        .json(&dataset_body(agent, claim, &format!("blake3:{B3_HEX}")))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["evidence_type"], "dataset", "{body}");

    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    let (stored_type, source_url, properties): (String, Option<String>, Value) =
        sqlx::query_as("SELECT evidence_type, source_url, properties FROM evidence WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_type, "dataset");
    assert_eq!(source_url.as_deref(), Some(ROOT));
    assert_eq!(
        properties,
        json!({
            "type": "dataset",
            "root_uri": ROOT,
            "manifest_uri": null,
            "manifest_blob_id": "blob-manifest-7",
            "manifest_hash": format!("blake3:{B3_HEX}"),
            "hash_algorithm": "blake3",
            "file_count": 40,
            "total_bytes": 123_456_789,
            "sample_id": null,
            "blob_ids": []
        })
    );
}

/// A digest no reader could compare against (here a sha256-length digest
/// declared blake3 but truncated) is refused as a validation error naming the
/// field, and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_malformed_manifest_digest_is_refused_and_nothing_is_written(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = pool_opts.connect_with(conn_opts.clone()).await.unwrap();
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, agent, "c8beb101: http bad dataset").await;
    let (addr, _shutdown) = spawn_app(pool.clone(), &conn_opts).await;
    let token = common::mint_token_with_agent(&["evidence:write"], agent);

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/evidence"))
        .bearer_auth(&token)
        .json(&dataset_body(
            agent,
            claim,
            &format!("blake3:{}", &B3_HEX[..40]),
        ))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["details"]["field"], "evidence_type.manifest_hash",
        "{body}"
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

async fn spawn_app(
    pool: PgPool,
    conn_opts: &PgConnectOptions,
) -> (SocketAddr, oneshot::Sender<()>) {
    let _ = &pool;
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

async fn seed_claim(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, $3, 0.5, $4)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
