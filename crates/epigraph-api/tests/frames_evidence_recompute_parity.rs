//! `POST /api/v1/frames/:id/evidence` must leave the claim where the shared
//! belief pipeline would put it (backlogs 2bffdfdc / I075 and 82dcff9d / I228,
//! REST twins of the MCP fixes in #317 and #513).
//!
//! The MCP `submit_ds_evidence` delegates its combine and cache write to
//! `epigraph_engine::edge_factor::recompute_claim_belief_on_frame`, the same
//! function `recompute_beliefs` and the framed `get_belief` use, so on MCP a
//! submit and a later recompute agree by construction. The REST handler used to
//! run its own combine (only `'discount'` rows, independence analysis, the
//! caller's threshold), wrote the cache unattributed (`belief_frame_id` NULL),
//! stored its pre-discounted masses with `source_strength = reliability` (which
//! the shared pipeline discounts AGAIN), and then stored the combined result
//! back as a NULL-agent "system" BBA, which every later recompute folds in as
//! one more independent source.
//!
//! Every test here asserts STORED state (rows, the claims cache after a
//! no-new-evidence recompute) or a hand-computed Dempster value, never the
//! response against a function the response was itself computed from.
//!
//! `#[sqlx::test]` gives each test an ephemeral database.
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

const EPS: f64 = 1e-9;

/// The app on the per-test database (not `DATABASE_URL`'s), built from a
/// `ScopedPool` so the handler's stamped write transaction is available.
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
    /// The claim's author, owning the claim through its personal group.
    agent_a: Uuid,
    token_a: String,
    claim: Uuid,
    frame: Uuid,
}

async fn world(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) -> World {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");
    let (agent_a, group_a) = fixture::seed_agent_with_group(&pool, "u024-a").await;

    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, visibility, \
                             owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, 'public', $5)",
    )
    .bind(claim)
    .bind(format!("u024 parity claim {claim}"))
    .bind(hash)
    .bind(agent_a)
    .bind(group_a)
    .execute(&pool)
    .await
    .expect("seed claim");

    let frame = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) VALUES ($1, $2, ARRAY['h0','h1']::text[])",
    )
    .bind(frame)
    .bind(format!("u024-parity-frame-{frame}"))
    .execute(&pool)
    .await
    .expect("seed frame");

    let (addr, shutdown) = spawn_app(&conn_opts).await;
    let token_a = common::mint_token_with_agent(&["claims:write"], agent_a);
    World {
        pool,
        addr,
        _shutdown: shutdown,
        agent_a,
        token_a,
        claim,
        frame,
    }
}

/// POST the evidence and insist on 201, printing the body otherwise so a 401
/// or 500 can never pose as the behaviour under test.
async fn post_evidence(w: &World, token: &str, body: Value) -> Value {
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
    let status = resp.status();
    let text = resp.text().await.expect("body");
    assert_eq!(status, 201, "POST evidence must be 201: {text}");
    serde_json::from_str(&text).expect("json body")
}

async fn bba_rows(w: &World) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2")
        .bind(w.claim)
        .bind(w.frame)
        .fetch_one(&w.pool)
        .await
        .expect("count BBAs")
}

async fn cached(w: &World) -> (Option<f64>, Option<Uuid>) {
    sqlx::query_as("SELECT belief, belief_frame_id FROM claims WHERE id = $1")
        .bind(w.claim)
        .fetch_one(&w.pool)
        .await
        .expect("read the cache")
}

/// Recompute the claim on the frame with no new evidence, the maintenance way
/// (`recompute_beliefs`), and return the cached belief it leaves.
async fn recompute(w: &World) -> f64 {
    let (_scoped, viewer) = fixture::bypass(&w.pool).await;
    let mut conn = w.pool.acquire().await.expect("acquire");
    let wrote = epigraph_engine::edge_factor::recompute_claim_belief_on_frame(
        &mut conn, &viewer, w.claim, w.frame,
    )
    .await
    .expect("recompute");
    assert!(
        wrote,
        "the claim has BBAs on the frame, so recompute writes"
    );
    drop(conn);
    cached(w).await.0.expect("belief after recompute")
}

/// I075's literal symptom: a submit's belief must already be the shared
/// pipeline's fixpoint. Before the fix the handler stored a second, NULL-agent
/// "combined" row (2 rows), left `belief_frame_id` NULL, and a recompute with
/// no new evidence moved the belief from 0.60 to 0.72.
#[sqlx::test(migrations = "../../migrations")]
async fn rest_evidence_leaves_the_claim_at_the_shared_pipelines_fixpoint(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let resp = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim,
            "agent_id": w.agent_a,
            "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }),
    )
    .await;

    assert_eq!(
        bba_rows(&w).await,
        1,
        "one submission is one BBA; no derived combined row may be stored beside it"
    );
    let (b1, frame_of_cache) = cached(&w).await;
    let b1 = b1.expect("the submit wrote the claim's cache");
    assert_eq!(
        frame_of_cache,
        Some(w.frame),
        "the cache must record the frame whose combination it holds"
    );
    let b2 = recompute(&w).await;
    assert!(
        (b2 - b1).abs() < EPS,
        "a recompute with no new evidence must not move the belief: submit left {b1}, \
         recompute gives {b2}"
    );
    assert!(
        (b2 - 0.6).abs() < EPS,
        "one fully reliable BBA with m({{0}}) = 0.6 has Bel = 0.6; got {b2}"
    );
    let reported = resp["updated_belief"].as_f64().expect("updated_belief");
    assert!(
        (reported - b2).abs() < EPS,
        "the response must report the belief the store holds: {reported} vs {b2}"
    );
}

/// Two independent agents, Dempster with K = 0: Bel = 1 - 0.4 * 0.5 = 0.80,
/// both in the second response and after a recompute. Before the fix the
/// response was 0.80 but the recompute moved it to ~0.88 (the stored combined
/// row folded back in at the 0.5 unknown-source discount).
#[sqlx::test(migrations = "../../migrations")]
async fn two_agents_combine_to_the_hand_computed_belief(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let (agent_b, _) = fixture::seed_agent_with_group(&w.pool, "u024-b").await;
    let token_b = common::mint_token_with_agent(&["claims:write"], agent_b);

    post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }),
    )
    .await;
    let resp = post_evidence(
        &w,
        &token_b,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": agent_b, "reliability": 1.0,
            "masses": {"0": 0.5, "0,1": 0.5},
        }),
    )
    .await;

    let reported = resp["updated_belief"].as_f64().expect("updated_belief");
    assert!(
        (reported - 0.8).abs() < EPS,
        "Dempster of m1({{0}})=0.6 and m2({{0}})=0.5 is 0.80; response said {reported}"
    );
    assert_eq!(
        resp["total_sources"], 2,
        "two submissions, two BBAs: {resp}"
    );
    let after = recompute(&w).await;
    assert!(
        (after - 0.8).abs() < EPS,
        "recompute over the same two BBAs must stay at 0.80; got {after}"
    );
}

/// `reliability` is applied exactly once. The stored masses are the
/// discounted ones, and the shared pipeline must not discount them again.
/// Before the fix the row carried `source_strength = 0.8`, so a recompute
/// discounted 0.8 a second time (0.64) and folded in the combined row (~0.784).
#[sqlx::test(migrations = "../../migrations")]
async fn reliability_is_applied_once(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) {
    let w = world(pool_opts, conn_opts).await;
    let resp = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 0.8,
            "masses": {"0": 1.0},
        }),
    )
    .await;

    let stored: f64 = sqlx::query_scalar(
        "SELECT (masses->>'0')::float8 FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id = $3",
    )
    .bind(w.claim)
    .bind(w.frame)
    .bind(w.agent_a)
    .fetch_one(&w.pool)
    .await
    .expect("the caller's BBA");
    assert!(
        (stored - 0.8).abs() < EPS,
        "the stored BBA is the reliability-discounted one: m({{0}}) = 0.8, got {stored}"
    );
    let reported = resp["updated_belief"].as_f64().expect("updated_belief");
    assert!(
        (reported - 0.8).abs() < EPS,
        "response belief must be 0.80, got {reported}"
    );
    let after = recompute(&w).await;
    assert!(
        (after - 0.8).abs() < EPS,
        "a recompute must not apply the reliability a second time: expected 0.80, got {after}"
    );
}

/// I228's REST twin: `combination_method`, `gamma` and `assume_independent`
/// are accepted but do not change the belief, and the caller is told so.
#[sqlx::test(migrations = "../../migrations")]
async fn deprecated_combination_parameters_are_reported(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    let resp = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
            "combination_method": "yager_open",
            "gamma": 0.5,
            "assume_independent": true,
        }),
    )
    .await;

    let warnings: Vec<String> = resp["warnings"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("`warnings` must be present when deprecated fields are sent: {resp}")
        })
        .iter()
        .map(|v| v.as_str().expect("warning string").to_string())
        .collect();
    let names = |needle: &str| {
        warnings
            .iter()
            .any(|m| m.contains(needle) && m.contains("deprecated"))
    };
    assert!(
        names("combination_method=yager_open"),
        "combination_method: {warnings:?}"
    );
    assert!(names("gamma=0.5"), "gamma: {warnings:?}");
    assert!(
        names("assume_independent"),
        "assume_independent: {warnings:?}"
    );

    // And a plain submission earns no warning at all (the field is omitted).
    let plain = post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }),
    )
    .await;
    assert!(
        plain.get("warnings").is_none(),
        "no deprecated field, no warnings: {plain}"
    );
}

/// A submission with no `agent_id` (as `scripts/lib/nli_stance.py` sends)
/// shares the unique key `(claim, frame, NULL agent, NULL perspective)` with
/// the old combined row, which then overwrote the caller's BBA with the
/// combination of every source.
#[sqlx::test(migrations = "../../migrations")]
async fn anonymous_submission_is_not_overwritten_by_a_combined_row(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let w = world(pool_opts, conn_opts).await;
    post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "agent_id": w.agent_a, "reliability": 1.0,
            "masses": {"0": 0.6, "0,1": 0.4},
        }),
    )
    .await;
    post_evidence(
        &w,
        &w.token_a,
        serde_json::json!({
            "claim_id": w.claim, "reliability": 1.0,
            "masses": {"0": 0.5, "0,1": 0.5},
        }),
    )
    .await;

    let anon: f64 = sqlx::query_scalar(
        "SELECT (masses->>'0')::float8 FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id IS NULL",
    )
    .bind(w.claim)
    .bind(w.frame)
    .fetch_one(&w.pool)
    .await
    .expect("exactly one anonymous BBA");
    assert!(
        (anon - 0.5).abs() < EPS,
        "the anonymous caller's BBA must hold what it submitted (m({{0}}) = 0.5), not a \
         combination; got {anon}"
    );
    assert_eq!(
        bba_rows(&w).await,
        2,
        "one BBA per submitter, nothing derived"
    );
}
