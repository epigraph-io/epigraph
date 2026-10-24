//! `POST /api/v1/frames/:id/evidence` says what its write did to the caller's
//! BBA slot (backlog 6f82db4f), as its MCP twin `submit_ds_evidence` does
//! since #675 (backlog bcbe34b2).
//!
//! # What was wrong, measured at origin/main before this file
//!
//! The BBA is upserted on `(claim, frame, source agent, perspective)`, and the
//! route answered an identical resubmission exactly like a first submission
//! (201, the same `mass_function_id`) and a resubmission with different masses
//! the same way, though it silently REPLACED the earlier BBA under that id. A
//! caller could not tell a real update from a no-op.
//!
//! Now the response carries `write_outcome` (`inserted` | `unchanged` |
//! `replaced`) and `deduplicated` (true iff `unchanged`), decided by the same
//! probe the MCP tool uses (`epigraph_db::bba_write_outcome`), against what
//! this route STORES: the masses after the reliability discount,
//! `combination_method = 'discount'`, `source_strength = 1.0`, the canonical
//! evidence type. Assertions read JSON keys, so this file compiles against the
//! pre-fix response type and fails on the assertions.
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

/// The app on the per-test database, built from a `ScopedPool` so the
/// handler's stamped write transaction is available.
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

struct World {
    pool: PgPool,
    addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
    claim: Uuid,
    frame: Uuid,
}

async fn world(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
    owner: Uuid,
    group: Uuid,
) -> World {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, visibility, \
                             owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, 'public', $5)",
    )
    .bind(claim)
    .bind(format!("6f82db4f write outcome claim {claim}"))
    .bind(hash)
    .bind(owner)
    .bind(group)
    .execute(&pool)
    .await
    .expect("seed claim");
    let frame = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) VALUES ($1, $2, ARRAY['h0','h1']::text[])",
    )
    .bind(frame)
    .bind(format!("6f82db4f-frame-{frame}"))
    .execute(&pool)
    .await
    .expect("seed frame");
    let (addr, shutdown) = spawn_app(&conn_opts).await;
    World {
        pool,
        addr,
        _shutdown: shutdown,
        claim,
        frame,
    }
}

/// POST the evidence and insist on 201, printing the body otherwise.
async fn post(w: &World, token: &str, body: Value) -> Value {
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/api/v1/frames/{}/evidence",
            w.addr, w.frame
        ))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("body");
    assert_eq!(status, 201, "POST evidence must be 201: {text}");
    serde_json::from_str(&text).expect("json body")
}

fn warnings(out: &Value) -> Vec<String> {
    out.get("warnings")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|w| w.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

async fn stored(pool: &PgPool, id: &Value) -> (Value, Option<String>) {
    sqlx::query_as("SELECT masses, evidence_type FROM mass_functions WHERE id = $1::uuid")
        .bind(id.as_str().expect("mass_function_id"))
        .fetch_one(pool)
        .await
        .expect("read the stored BBA")
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_rest_write_reports_whether_it_inserted_deduplicated_or_replaced(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let seed = pool_opts
        .clone()
        .connect_with(conn_opts.clone())
        .await
        .expect("seed pool");
    let (a, group_a) = fixture::seed_agent_with_group(&seed, "6f82db4f-a").await;
    let (b, _) = fixture::seed_agent_with_group(&seed, "6f82db4f-b").await;
    let w = world(pool_opts, conn_opts, a, group_a).await;
    let token_a = common::mint_token_with_agent(&["claims:write"], a);
    let token_b = common::mint_token_with_agent(&["claims:write"], b);
    // Reliability below 1: the route stores DISCOUNTED masses, so the probe
    // must compare against those, not against the raw request.
    let body = serde_json::json!({
        "claim_id": w.claim, "reliability": 0.8, "evidence_type": "statistical",
        "masses": {"0": 0.7, "0,1": 0.3},
    });

    let first = post(&w, &token_a, body.clone()).await;
    assert_eq!(first["write_outcome"], "inserted", "{first}");
    assert_eq!(first["deduplicated"], false, "{first}");
    assert!(
        first.get("warnings").is_none(),
        "a first submission carries no warning (the field is omitted): {first}"
    );
    let first_row = stored(&w.pool, &first["mass_function_id"]).await;

    // The identical request: one row, untouched, and the caller is told.
    let again = post(&w, &token_a, body.clone()).await;
    assert_eq!(again["write_outcome"], "unchanged", "{again}");
    assert_eq!(again["deduplicated"], true, "{again}");
    assert_eq!(again["mass_function_id"], first["mass_function_id"]);
    assert!(
        warnings(&again).iter().any(|x| x.contains("identical")),
        "an unchanged write says so: {again}"
    );
    assert_eq!(stored(&w.pool, &again["mass_function_id"]).await, first_row);

    // The same raw masses at another reliability store other masses: a
    // replacement under the same id, never "unchanged".
    let mut rediscounted = body.clone();
    rediscounted["reliability"] = serde_json::json!(0.5);
    let replaced = post(&w, &token_a, rediscounted).await;
    assert_eq!(replaced["write_outcome"], "replaced", "{replaced}");
    assert_eq!(replaced["deduplicated"], false, "{replaced}");
    assert_eq!(replaced["mass_function_id"], first["mass_function_id"]);
    assert!(
        warnings(&replaced).iter().any(|x| x.contains("REPLACED")),
        "a replacement says so: {replaced}"
    );
    assert_ne!(
        stored(&w.pool, &replaced["mass_function_id"]).await.0,
        first_row.0,
        "CALIBRATION: the replacement did change the stored masses"
    );

    // Same masses, another evidence type: a column the upsert writes changed.
    let mut retyped = body.clone();
    retyped["reliability"] = serde_json::json!(0.5);
    retyped["evidence_type"] = serde_json::json!("testimonial");
    let retyped = post(&w, &token_a, retyped).await;
    assert_eq!(retyped["write_outcome"], "replaced", "{retyped}");

    // Another agent's identical BBA is its own slot.
    let other = post(&w, &token_b, body).await;
    assert_eq!(other["write_outcome"], "inserted", "{other}");
    assert_ne!(other["mass_function_id"], first["mass_function_id"]);
}
