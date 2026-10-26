//! A claim's cached combination result must never be folded back in as
//! evidence (backlog b5cb3efb).
//!
//! `POST /api/v1/frames/:id/evidence` (`routes::belief::submit_evidence`)
//! used to store each input BBA (`combination_method = "discount"`, its agent)
//! AND, at its step 14, the combined result of folding them, as an agent-less
//! row on the SAME (claim, frame). Its own fold kept only `"discount"` rows,
//! but the recompute (`edge_factor::compute_combined_belief`, behind
//! `recompute_beliefs` and the deferred R.4 recompute) and the framed read
//! (`belief_query::get_belief`) loaded every row of the pair through
//! `MassFunctionRepository::get_for_claim_frame`, so they folded the claim's
//! previous answer in as if it were an independent source: BetP inflated past
//! what the evidence supports and kept climbing as evidence arrived.
//!
//! No live writer stores that row any more. Since U024 `/evidence` delegates
//! to the shared recompute and stores nothing beside its input (pinned below:
//! no agent-less row after the submissions), and `/assess` always holds the
//! pair's agent-less slot with its own input, so its guarded cache store never
//! fires. The rows already on prod remain (~15.5k measured, by b5cb3efb), and
//! the combine-input readers must keep excluding them. So the inputs are
//! submitted through the real writer, and each legacy cached row is planted in
//! its prod shape (no agent, no perspective), one test per label: a fold's
//! `"Dempster"` report, and `cached_unfolded`, the label b5cb3efb gave the
//! cached copy of a lone BBA (whose label had been NULL).
//!
//! Masses are submitted at reliability 1.0 by agents with no competence scopes,
//! so the stored inputs are the submitted masses and every expected value is
//! hand-computable on the binary frame {TRUE, FALSE}:
//! * A = m({TRUE}) 0.6, m(Θ) 0.4               → BetP(TRUE) = 0.6 + 0.4/2 = 0.8
//! * A ⊕ B, B = m({TRUE}) 0.5, m(Θ) 0.5        → m({TRUE}) = 1 − 0.4·0.5 = 0.8,
//!   m(Θ) = 0.2                                 → BetP(TRUE) = 0.9
//!
//! On origin/main 3d0ccfd4 the recompute folded the cached row in as one more
//! source (at the fallback reliability 0.5, since it carries no
//! `source_strength`). The red values: BetP 0.86 for A alone (expected 0.8),
//! and 0.94 for A and B (expected 0.9). The planted rows carry exactly the
//! masses the writer cached (A, and A ⊕ B), so those red values still apply.
#![cfg(feature = "db")]

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

use epigraph_engine::belief_query;
use epigraph_engine::edge_factor::{
    preview_claim_belief_on_frame, recompute_claim_belief_on_frame,
};

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

/// Plant a legacy cached combination row on the pair in its prod shape: no
/// source agent, no perspective, no type, `label` as its combination method.
async fn plant_cached_row(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    masses: &Value,
    conflict_k: Option<f64>,
    label: &str,
) {
    epigraph_db::MassFunctionRepository::store(
        pool,
        claim,
        frame,
        None, // the writers cached their result with no agent
        masses,
        conflict_k,
        Some(label),
        None,
        "unknown",
        None,
    )
    .await
    .expect("plant the legacy cached combination row");
}

/// Rows on the pair with no source agent: the cached combination.
/// Non-vacuity probe — without one, a green run proves nothing.
async fn agentless_rows(pool: &PgPool, claim: Uuid, frame: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions \
         WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id IS NULL",
    )
    .bind(claim)
    .bind(frame)
    .fetch_one(pool)
    .await
    .expect("count agent-less rows")
}

/// Every fold reader's BetP(TRUE) for the pair, labelled, after a full
/// recompute that writes the claim cache: the write-free preview, the
/// recompute's cached `claims.pignistic_prob`, and the framed read.
async fn fold_readers(pool: &PgPool, claim: Uuid, frame: Uuid) -> Vec<(&'static str, f64)> {
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let preview = preview_claim_belief_on_frame(&mut conn, &viewer, claim, frame)
        .await
        .expect("preview")
        .expect("the pair has BBAs");
    assert!(
        recompute_claim_belief_on_frame(&mut conn, &viewer, claim, frame)
            .await
            .expect("recompute"),
        "the recompute found BBAs"
    );
    drop(conn);
    let cached: f64 = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read cache");
    let framed = belief_query::get_belief(pool, &viewer, claim, Some(frame))
        .await
        .expect("framed get_belief");
    vec![
        ("preview_claim_belief_on_frame", preview.pignistic_prob),
        ("recompute -> claims.pignistic_prob", cached),
        ("belief_query::get_belief", framed.pignistic_prob),
    ]
}

fn assert_all(readers: &[(&'static str, f64)], expected: f64, when: &str) {
    for (who, got) in readers {
        assert!(
            (got - expected).abs() < 1e-9,
            "{when}: {who} BetP(TRUE) = {got}, expected {expected} — the cached \
             combination row was folded back in as evidence"
        );
    }
}

/// A claim with a binary {TRUE, FALSE} frame, two input agents, and a running
/// app on this test's database.
struct World {
    pool: PgPool,
    claim: Uuid,
    frame: Uuid,
    a: Uuid,
    b: Uuid,
    addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
    client: reqwest::Client,
}

async fn world(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) -> World {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let owner = seed_agent(&pool).await;
    let (a, b) = (seed_agent(&pool).await, seed_agent(&pool).await);
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!("b5cb3efb cached combination {}", Uuid::new_v4()))
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("seed claim");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['TRUE','FALSE']::text[]) \
         RETURNING id",
    )
    .bind(format!("b5cb3efb-binary-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let (addr, shutdown) = spawn_app(&conn_opts).await;
    World {
        pool,
        claim,
        frame,
        a,
        b,
        addr,
        _shutdown: shutdown,
        client: reqwest::Client::new(),
    }
}

/// A = m({TRUE}) 0.6, m(Θ) 0.4.
fn masses_a() -> Value {
    serde_json::json!({"0": 0.6, "0,1": 0.4})
}

/// B = m({TRUE}) 0.5, m(Θ) 0.5.
fn masses_b() -> Value {
    serde_json::json!({"0": 0.5, "0,1": 0.5})
}

/// The unfolded shape: a lone BBA beside the cached copy of itself, labelled
/// `cached_unfolded` (the label b5cb3efb's writers gave it; before that it
/// was NULL, an ambiguous shape the readers keep).
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_does_not_refold_the_cached_copy_of_a_lone_bba(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;

    let first = submit(&w.client, w.addr, w.frame, w.claim, w.a, masses_a()).await;
    assert!(
        first["pignistic_prob"]
            .as_f64()
            .is_some_and(|p| (p - 0.8).abs() < 1e-9),
        "fixture: the writer's own fold of A alone is BetP 0.8: {first}"
    );
    assert_eq!(
        agentless_rows(&w.pool, w.claim, w.frame).await,
        0,
        "the writer stores nothing beside its input (U024)"
    );
    plant_cached_row(
        &w.pool,
        w.claim,
        w.frame,
        &masses_a(),
        None,
        epigraph_db::CACHED_COMBINATION_UNFOLDED,
    )
    .await;
    assert_eq!(
        agentless_rows(&w.pool, w.claim, w.frame).await,
        1,
        "non-vacuity: the legacy cached copy sits beside the input"
    );
    let readers = fold_readers(&w.pool, w.claim, w.frame).await;
    assert_all(&readers, 0.8, "one BBA");

    // Idempotent: recomputing again changes nothing.
    let again = fold_readers(&w.pool, w.claim, w.frame).await;
    assert_all(&again, 0.8, "one BBA, recomputed a second time");
}

/// The folded shape: two inputs beside their cached combination, labelled
/// "Dempster". This is the shape of the ~15,566 cached rows measured on prod.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_does_not_refold_the_dempster_labelled_cached_combination(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;

    submit(&w.client, w.addr, w.frame, w.claim, w.a, masses_a()).await;
    let second = submit(&w.client, w.addr, w.frame, w.claim, w.b, masses_b()).await;
    assert!(
        second["pignistic_prob"]
            .as_f64()
            .is_some_and(|p| (p - 0.9).abs() < 1e-9),
        "fixture: the writer's own fold of A and B is BetP 0.9: {second}"
    );
    assert_eq!(
        agentless_rows(&w.pool, w.claim, w.frame).await,
        0,
        "the writer stores nothing beside its inputs (U024)"
    );
    // A ⊕ B, exactly what the writer used to cache: m({TRUE}) 0.8, m(Θ) 0.2.
    plant_cached_row(
        &w.pool,
        w.claim,
        w.frame,
        &serde_json::json!({"0": 0.8, "0,1": 0.2}),
        Some(0.0),
        "Dempster",
    )
    .await;
    let label: Option<String> = sqlx::query_scalar(
        "SELECT combination_method FROM mass_functions \
         WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id IS NULL",
    )
    .bind(w.claim)
    .bind(w.frame)
    .fetch_one(&w.pool)
    .await
    .expect("non-vacuity: one cached combination row beside the inputs");
    assert_eq!(
        label.as_deref(),
        Some("Dempster"),
        "non-vacuity: the cached row carries the Dempster fold's label"
    );
    let readers = fold_readers(&w.pool, w.claim, w.frame).await;
    assert_all(&readers, 0.9, "two BBAs");

    // Idempotent: recomputing again changes nothing.
    let again = fold_readers(&w.pool, w.claim, w.frame).await;
    assert_all(&again, 0.9, "two BBAs, recomputed a second time");
}
