//! Regression tests for backlog `36bfc07d` (and its duplicate `4a1912c9`): the
//! silence alarm counted claim-to-claim contradictions as zero by construction.
//!
//! `GET /api/v1/conflicts/scan`, `GET /api/v1/conflicts/silence-check` and the
//! `19c` step of `POST /api/v1/frames/:id/evidence` each counted
//!
//! ```sql
//! SELECT COUNT(*) FROM edges e
//! JOIN mass_functions mf1 ON mf1.claim_id = e.source_id AND mf1.frame_id = f.id
//! WHERE e.relationship = 'CONTRADICTS'
//! ```
//!
//! `edges.relationship` is a case-sensitive varchar, and claim-to-claim
//! contradictions are written lower-case (`contradicts` / `refutes`) by
//! `link_epistemic`, `semantic_link` and the cross-source matcher. The
//! upper-case writers use a mass-function id as the source, never a claim. So
//! the count was ~0 on every frame and every frame with >= 20 claims and >= 2
//! sources alarmed, whatever its real dissent. The JOIN also counted once per
//! BBA row of the source claim, counted A->B plus B->A twice, ignored
//! `valid_to` and the endpoint types, and tested only the source for frame
//! membership.
//!
//! The first test is the discriminating pair at the HTTP surface of both
//! routes: the frame alarms with no contradiction, and stops alarming once one
//! lower-case claim->claim `contradicts` edge exists. The rest pin each
//! counting rule on `ConflictDensityRepository::for_frames`, which all three
//! call sites now share. Each case is built so the previous query gets a
//! different number for its own reason (noted per test).
//!
//! `#[sqlx::test]` gives each test an ephemeral database, so the frame set the
//! scan sees is small and every count is exact.
#![cfg(feature = "db")]

mod common;

use epigraph_db::ConflictDensityRepository;
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

/// The app on the per-test database (not `DATABASE_URL`'s), so the routes
/// read the rows these tests seed.
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

async fn seed_claim(pool: &PgPool, agent_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, $3, 0.5, $4)",
    )
    .bind(id)
    .bind(format!("silence-check claim {id}"))
    .bind(hash)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn seed_frame(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) VALUES ($1, $2, ARRAY['h0','h1']::text[])",
    )
    .bind(id)
    .bind(format!("silence-check-frame-{id}"))
    .execute(pool)
    .await
    .expect("seed frame");
    id
}

/// One BBA for `claim_id` in `frame_id` from `source_agent`.
async fn seed_bba(pool: &PgPool, claim_id: Uuid, frame_id: Uuid, source_agent: Uuid) {
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"0\": 0.6, \"0,1\": 0.4}'::jsonb)",
    )
    .bind(claim_id)
    .bind(frame_id)
    .bind(source_agent)
    .execute(pool)
    .await
    .expect("seed bba");
}

/// A frame of `n` claims, one BBA each, alternating between two source agents
/// (so `distinct_sources = 2`).
struct SeededFrame {
    frame: Uuid,
    claims: Vec<Uuid>,
    agents: [Uuid; 2],
}

async fn seed_frame_with_claims(pool: &PgPool, n: usize) -> SeededFrame {
    let agents = [seed_agent(pool).await, seed_agent(pool).await];
    let frame = seed_frame(pool).await;
    let mut claims = Vec::with_capacity(n);
    for i in 0..n {
        let claim = seed_claim(pool, agents[0]).await;
        seed_bba(pool, claim, frame, agents[i % 2]).await;
        claims.push(claim);
    }
    SeededFrame {
        frame,
        claims,
        agents,
    }
}

async fn insert_edge_at(
    pool: &PgPool,
    (source_id, source_type): (Uuid, &str),
    (target_id, target_type): (Uuid, &str),
    relationship: &str,
    retracted: bool,
) {
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship, valid_to) \
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $6 THEN now() - interval '1 day' END)",
    )
    .bind(source_id)
    .bind(target_id)
    .bind(source_type)
    .bind(target_type)
    .bind(relationship)
    .bind(retracted)
    .execute(pool)
    .await
    .expect("insert edge");
}

async fn claim_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    insert_edge_at(
        pool,
        (source, "claim"),
        (target, "claim"),
        relationship,
        false,
    )
    .await;
}

/// The frame's `(total_claims, contradicts_edges)` from the shared repo fn.
async fn density(pool: &PgPool, frame: Uuid) -> (i64, i64) {
    let rows = ConflictDensityRepository::for_frames(pool, &[frame])
        .await
        .expect("for_frames");
    assert_eq!(rows.len(), 1, "exactly the requested frame: {rows:?}");
    assert_eq!(rows[0].frame_id, frame);
    (rows[0].total_claims, rows[0].contradicts_edges)
}

async fn connect(pool_opts: PgPoolOptions, conn_opts: &PgConnectOptions) -> PgPool {
    pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool")
}

async fn get_json(client: &reqwest::Client, addr: SocketAddr, token: &str, path: &str) -> Value {
    let resp = client
        .get(format!("http://{addr}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .expect("request");
    let status = resp.status();
    let body: Value = resp.json().await.expect("json body");
    assert_eq!(status, 200, "GET {path}: {body}");
    body
}

/// The alarm entries for `frame` in `body[key]`.
fn alarms_for(body: &Value, key: &str, frame: Uuid) -> Vec<Value> {
    body[key]
        .as_array()
        .unwrap_or_else(|| panic!("`{key}` is an array: {body}"))
        .iter()
        .filter(|a| a["frame_id"] == Value::String(frame.to_string()))
        .cloned()
        .collect()
}

/// The discriminating pair, on both HTTP routes. Previous query: the
/// lower-case edge is never matched, so the frame still alarms after step 3.
#[sqlx::test(migrations = "../../migrations")]
async fn silence_check_clears_once_a_lowercase_claim_contradiction_exists(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = connect(pool_opts, &conn_opts).await;
    let seeded = seed_frame_with_claims(&pool, 20).await;
    let frame = seeded.frame;

    let (addr, _shutdown) = spawn_app(&conn_opts).await;
    let client = reqwest::Client::new();
    let token = common::mint_token_with_agent(&["claims:read"], seeded.agents[0]);

    // (1) No contradiction yet: 0 / 20 < 2%, so both routes alarm on the frame.
    // This half proves the frame is in the scanned set, so (2) cannot pass
    // vacuously.
    let silence = get_json(&client, addr, &token, "/api/v1/conflicts/silence-check").await;
    let before = alarms_for(&silence, "alarms", frame);
    assert_eq!(before.len(), 1, "silent frame must alarm: {silence}");
    assert_eq!(before[0]["contradicts_edges"], 0);
    assert_eq!(before[0]["total_claims"], 20);
    assert_eq!(before[0]["distinct_sources"], 2);

    let scan = get_json(&client, addr, &token, "/api/v1/conflicts/scan").await;
    let before = alarms_for(&scan, "silence_alarms", frame);
    assert_eq!(before.len(), 1, "silent frame must alarm in scan: {scan}");
    assert_eq!(before[0]["contradicts_edges"], 0);

    // (2) One claim->claim contradiction, in the spelling every MCP / matcher
    // writer uses: 1 / 20 = 5% >= 2%, so neither route may alarm on the frame.
    common::insert_edge(
        &pool,
        seeded.claims[0],
        seeded.claims[1],
        "claim",
        "claim",
        "contradicts",
    )
    .await;

    let silence = get_json(&client, addr, &token, "/api/v1/conflicts/silence-check").await;
    assert_eq!(
        alarms_for(&silence, "alarms", frame),
        Vec::<Value>::new(),
        "a frame with a live claim->claim `contradicts` edge is not silent: {silence}"
    );
    let scan = get_json(&client, addr, &token, "/api/v1/conflicts/scan").await;
    assert_eq!(
        alarms_for(&scan, "silence_alarms", frame),
        Vec::<Value>::new(),
        "scan must agree with silence-check: {scan}"
    );
}

/// One edge whose source claim carries 3 BBAs in the frame is one
/// contradiction. Previous query: 3 (one per BBA row of the source).
#[sqlx::test(migrations = "../../migrations")]
async fn a_contradiction_counts_once_however_many_bbas_its_source_has(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = connect(pool_opts, &conn_opts).await;
    let seeded = seed_frame_with_claims(&pool, 2).await;
    let third = seed_agent(&pool).await;
    // claims[0] already has a BBA from agents[0]; add agents[1] and a third.
    seed_bba(&pool, seeded.claims[0], seeded.frame, seeded.agents[1]).await;
    seed_bba(&pool, seeded.claims[0], seeded.frame, third).await;
    claim_edge(&pool, seeded.claims[0], seeded.claims[1], "CONTRADICTS").await;

    assert_eq!(density(&pool, seeded.frame).await, (2, 1));
}

/// A->B plus B->A is one disagreeing pair. Previous query: 2.
#[sqlx::test(migrations = "../../migrations")]
async fn a_symmetric_pair_counts_once(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) {
    let pool = connect(pool_opts, &conn_opts).await;
    let seeded = seed_frame_with_claims(&pool, 2).await;
    let (a, b) = (seeded.claims[0], seeded.claims[1]);
    claim_edge(&pool, a, b, "CONTRADICTS").await;
    claim_edge(&pool, b, a, "CONTRADICTS").await;

    assert_eq!(density(&pool, seeded.frame).await, (2, 1));
}

/// Both spellings of `contradicts` and `refutes` count, once per unordered
/// pair. Previous query: 1 (only the upper-case `CONTRADICTS` row).
#[sqlx::test(migrations = "../../migrations")]
async fn every_spelling_of_contradicts_and_refutes_counts_once_per_pair(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = connect(pool_opts, &conn_opts).await;
    let seeded = seed_frame_with_claims(&pool, 6).await;
    let c = &seeded.claims;
    // Pair (0,1) in both spellings: one pair.
    claim_edge(&pool, c[0], c[1], "contradicts").await;
    claim_edge(&pool, c[0], c[1], "CONTRADICTS").await;
    // Pair (2,3) lower-case `refutes`, pair (4,5) upper-case `REFUTES`.
    claim_edge(&pool, c[2], c[3], "refutes").await;
    claim_edge(&pool, c[5], c[4], "REFUTES").await;

    assert_eq!(density(&pool, seeded.frame).await, (6, 3));
}

/// A retracted edge (`valid_to` in the past) is not a live contradiction.
/// Previous query (scan / silence-check): 1, it had no `valid_to` filter.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_contradiction_does_not_count(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = connect(pool_opts, &conn_opts).await;
    let seeded = seed_frame_with_claims(&pool, 2).await;
    insert_edge_at(
        &pool,
        (seeded.claims[0], "claim"),
        (seeded.claims[1], "claim"),
        "CONTRADICTS",
        true,
    )
    .await;

    assert_eq!(density(&pool, seeded.frame).await, (2, 0));
}

/// A `CONTRADICTS` edge from an in-frame claim to a non-claim node is not a
/// claim contradiction. Previous query: 1, it never checked endpoint types.
#[sqlx::test(migrations = "../../migrations")]
async fn a_contradiction_with_a_non_claim_endpoint_does_not_count(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = connect(pool_opts, &conn_opts).await;
    let seeded = seed_frame_with_claims(&pool, 2).await;
    insert_edge_at(
        &pool,
        (seeded.claims[0], "claim"),
        (seeded.agents[1], "agent"),
        "CONTRADICTS",
        false,
    )
    .await;

    assert_eq!(density(&pool, seeded.frame).await, (2, 0));
}

/// `contradicts` is symmetric and its stored orientation is arbitrary, so a
/// contradiction counts for a frame when EITHER endpoint holds a BBA there
/// (default decision; the stricter alternative is "both endpoints").
/// Previous query: 0, it only tested the source for frame membership.
#[sqlx::test(migrations = "../../migrations")]
async fn a_contradiction_counts_when_only_its_target_is_in_the_frame(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    let pool = connect(pool_opts, &conn_opts).await;
    let seeded = seed_frame_with_claims(&pool, 2).await;
    // An outside claim with a BBA in a different frame only.
    let other_frame = seed_frame(&pool).await;
    let outsider = seed_claim(&pool, seeded.agents[0]).await;
    seed_bba(&pool, outsider, other_frame, seeded.agents[0]).await;
    claim_edge(&pool, outsider, seeded.claims[0], "CONTRADICTS").await;

    assert_eq!(density(&pool, seeded.frame).await, (2, 1));
    assert_eq!(
        density(&pool, other_frame).await,
        (1, 1),
        "the source's frame counts the same pair"
    );
}
