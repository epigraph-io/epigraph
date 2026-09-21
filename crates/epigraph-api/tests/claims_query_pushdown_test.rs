//! Regression test for backlog bug `2265a67b` (and the SQL push-down residual
//! of `f1992766`): `GET /api/v1/claims` diverted any filtered request to an
//! in-memory pipeline over `ClaimRepository::list(pool, 10_000, 0, …)` —
//! `ORDER BY created_at DESC LIMIT 10000` — then `retain`ed in Rust and
//! reported `claims.len()` as `total`.
//!
//! Two wrong answers came out of that, and this test pins both:
//!
//! 1. **`total` was the filtered slice length, not a count.** With more than
//!    10,000 rows in the table, an unfiltered-but-`is_current`-filtered query
//!    reported at most 10,000 however many claims actually matched.
//! 2. **The result was unrepresentative, not merely truncated.** The working
//!    set was always the *most recent* 10,000 rows, so a filter matching only
//!    older claims returned an empty set with HTTP 200 — indistinguishable
//!    from a true zero.
//!
//! The fixture is deliberately expensive: it needs > 10,000 rows for the cap
//! to bite at all, which is precisely why the defect survived every
//! small-fixture test in this crate. `#[sqlx::test]` gives each run its own
//! ephemeral database, so the bulk insert neither sees nor pollutes any shared
//! test data.
#![cfg(feature = "db")]

use serde_json::Value;
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

/// The cap the old in-memory slow path applied to its working set.
const OLD_WORKING_SET_CAP: i64 = 10_000;

#[sqlx::test(migrations = "../../migrations")]
async fn filtered_queries_count_and_reach_past_the_old_10k_window(pool: PgPool) {
    let needle_agent = seed_agent(&pool, 0xE1).await;
    let filler_agent = seed_agent(&pool, 0xE2).await;

    // The needle: authored by `needle_agent`, and the OLDEST row in the table.
    let needle = seed_claim(
        &pool,
        needle_agent,
        "needle",
        true,
        None,
        "2000-01-01T00:00:00Z",
    )
    .await;

    // `OLD_WORKING_SET_CAP + 1` newer rows from a different agent, so the
    // needle sits strictly outside the window the old path could see. One of
    // them is superseded, so the two `is_current` populations are both
    // non-trivial.
    let filler_total = OLD_WORKING_SET_CAP + 1;
    bulk_seed(&pool, filler_agent, filler_total).await;
    let superseded_filler = seed_claim(
        &pool,
        filler_agent,
        "superseded filler",
        false,
        Some(needle),
        "2026-01-02T00:00:00Z",
    )
    .await;

    let total_rows = filler_total + 2; // fillers + needle + superseded filler

    let (addr, _shutdown) = spawn_app(pool.clone()).await;
    let client = reqwest::Client::new();

    // ---- (1) The needle is reachable through a filter, not buried ----
    let body = get(
        &client,
        addr,
        &format!("/api/v1/claims?agent_id={needle_agent}&limit=50"),
    )
    .await;
    let rows = body["claims"].as_array().expect("claims array");
    assert_eq!(
        rows.len(),
        1,
        "?agent_id must find the oldest matching claim even though \
         {filler_total} newer rows exist — an empty result here is the \
         2265a67b out-of-window false zero: {body}"
    );
    assert_eq!(rows[0]["id"].as_str().unwrap(), needle.to_string());
    assert_eq!(
        body["total"],
        Value::from(1),
        "total must be a real COUNT(*) over the filter"
    );

    // ---- (2) `total` on a filtered query is a count, not a capped slice ----
    let body = get(&client, addr, "/api/v1/claims?is_current=true&limit=5").await;
    let expected_current = total_rows - 1; // everything but the superseded filler
    assert_eq!(
        body["total"],
        Value::from(expected_current),
        "?is_current=true must report the real matching count; \
         {OLD_WORKING_SET_CAP} here is the capped-slice length of 2265a67b"
    );
    assert_eq!(
        body["claims"].as_array().unwrap().len(),
        5,
        "pagination still applies: total counts, limit pages"
    );

    // ---- (3) The complement partitions the table exactly ----
    let body = get(&client, addr, "/api/v1/claims?is_current=false&limit=50").await;
    assert_eq!(body["total"], Value::from(1));
    let rows = body["claims"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["id"].as_str().unwrap(),
        superseded_filler.to_string()
    );

    // ---- (4) A sort that used to divert to the in-memory path still sorts
    //          over the whole table, not over the newest 10,000 rows ----
    let body = get(
        &client,
        addr,
        "/api/v1/claims?sort_by=created_at&sort_order=asc&limit=1",
    )
    .await;
    assert_eq!(
        body["claims"][0]["id"].as_str().unwrap(),
        needle.to_string(),
        "ascending created_at must surface the table's oldest row; the old \
         path sorted only the 10,000 NEWEST rows, so it could never return it"
    );
    assert_eq!(body["total"], Value::from(total_rows));

    // ---- (5) An unfiltered query still reports the whole table ----
    let body = get(&client, addr, "/api/v1/claims?limit=1").await;
    assert_eq!(body["total"], Value::from(total_rows));
}

/// Filters that resolve to an id set must keep "matched nothing" distinct from
/// "no filter". `methodology` resolves through `claim_ids_by_methodology`; with
/// no reasoning traces seeded it matches zero claims, so the endpoint must
/// return zero — NOT the whole table, which is what collapsing an empty id set
/// to "unfiltered" would produce.
#[sqlx::test(migrations = "../../migrations")]
async fn a_filter_that_matches_nothing_returns_nothing(pool: PgPool) {
    let agent = seed_agent(&pool, 0xE3).await;
    for i in 0..3 {
        seed_claim(
            &pool,
            agent,
            &format!("empty-set-{i}"),
            true,
            None,
            "2026-03-01T00:00:00Z",
        )
        .await;
    }

    let (addr, _shutdown) = spawn_app(pool.clone()).await;
    let client = reqwest::Client::new();

    let body = get(
        &client,
        addr,
        "/api/v1/claims?methodology=deductive&limit=50",
    )
    .await;
    assert_eq!(
        body["total"],
        Value::from(0),
        "a methodology matching no claim must select nothing, not everything: {body}"
    );
    assert!(body["claims"].as_array().unwrap().is_empty());
}

async fn get(client: &reqwest::Client, addr: SocketAddr, path: &str) -> Value {
    client
        .get(format!("http://{addr}{path}"))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json body")
}

/// Same wiring as `epigraph_api::build_app_for_tests`, but from an existing
/// pool so the ephemeral `#[sqlx::test]` database is the one under test.
async fn spawn_app(pool: PgPool) -> (SocketAddr, oneshot::Sender<()>) {
    let state = epigraph_api::AppState::with_db(pool, epigraph_api::ApiConfig::default());
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

async fn seed_agent(pool: &PgPool, tag: u8) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = std::iter::repeat_n(tag, 16)
        .chain(id.as_bytes().iter().copied())
        .take(32)
        .collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    content: &str,
    is_current: bool,
    supersedes: Option<Uuid>,
    created_at: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, supersedes, created_at) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, $7::timestamptz)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent_id)
    .bind(is_current)
    .bind(supersedes)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// Insert `n` current claims in one round-trip, all newer than the needle.
async fn bulk_seed(pool: &PgPool, agent_id: Uuid, n: i64) {
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, created_at) \
         SELECT gen_random_uuid(), 'filler ' || g, \
                sha256(g::text::bytea), 0.5, $1, true, \
                TIMESTAMPTZ '2026-01-01 00:00:00Z' + (g * INTERVAL '1 second') \
           FROM generate_series(1, $2) AS g",
    )
    .bind(agent_id)
    .bind(n)
    .execute(pool)
    .await
    .expect("bulk seed fillers");
}
