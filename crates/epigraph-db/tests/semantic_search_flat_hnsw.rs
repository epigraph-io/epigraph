//! `ClaimRepository::semantic_search_flat` is served by the HNSW index and
//! still fills its `limit` past `hnsw.ef_search`.
//!
//! The statement used to `ORDER BY similarity DESC` (`1 - distance`), a form
//! pgvector's HNSW index cannot serve, so every call scanned and sorted every
//! embedded claim; on prod that ran past 30 s and timed out every Explorer
//! search. Ordering by the raw distance puts it on the index, where a scan
//! yields at most `hnsw.ef_search` (default 40) rows unless the call widens it.
//!
//! Small tables are always cheaper to seq-scan, so these tests pin the plan
//! prod actually runs: ONE connection (the `SET`s are session-scoped and a pool
//! may hand the next statement another backend), with seq scans, bitmap scans
//! and explicit sorts disabled. Disabling a node only penalises it: a statement
//! the index cannot serve still plans as a sort over a seq scan, which is what
//! the plan test catches. `hnsw.ef_search` is left at its default: the tests
//! must not set the knob the implementation sets.
//!
//! Schema notes (mirrors claim_search_hybrid.rs): seed an `agents` row first
//! (FK + edge-validation trigger); `content_hash bytea NOT NULL` and
//! `(content_hash, agent_id)` UNIQUE → use distinct hashes.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// Rows seeded per test: twice the default `hnsw.ef_search` window.
const ROWS: usize = 80;

/// A unit vector at `deg` degrees in the dim-0/dim-1 plane. The query is
/// `vec_angle(0.0)`, so a row's cosine distance to it grows strictly with its
/// angle and every row has its own distance.
///
/// The rows lie on one arc rather than on spokes of their own dims: with
/// spokes, HNSW's neighbour-pruning heuristic leaves most of the graph with no
/// inbound edge, so the index cannot reach them at any `ef_search`. An arc is
/// a well-formed graph, which [`hnsw_graph_reaches_every_row`] checks.
fn vec_angle(deg: f64) -> String {
    let (s, c) = deg.to_radians().sin_cos();
    let mut v: Vec<String> = vec!["0.0".to_string(); 1536];
    v[0] = format!("{c:.6}");
    v[1] = format!("{s:.6}");
    format!("[{}]", v.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

/// Seed `ROWS` current, embedded claims at 0°, 0.5°, … and return their ids in
/// ascending distance from `vec_angle(0.0)`.
async fn seed_arc(pool: &PgPool) -> Vec<Uuid> {
    let agent = seed_agent(pool).await;
    let mut ids = Vec::with_capacity(ROWS);
    for i in 0..ROWS {
        let id = Uuid::new_v4();
        let mut hash = vec![0u8; 32];
        hash[0] = i as u8;
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, embedding) \
             VALUES ($1, $2, $3, $4, 0.8, true, $5::vector)",
        )
        .bind(id)
        .bind(format!("arc row number {i}"))
        .bind(hash)
        .bind(agent)
        .bind(vec_angle(0.5 * i as f64))
        .execute(pool)
        .await
        .expect("insert claim");
        ids.push(id);
    }
    ids
}

/// Disable the plans a small table would otherwise get, on `conn` only.
async fn force_index_plans(conn: &mut sqlx::PgConnection) {
    for s in [
        "SET enable_seqscan = off",
        "SET enable_bitmapscan = off",
        "SET enable_sort = off",
    ] {
        sqlx::query(s).execute(&mut *conn).await.expect(s);
    }
}

/// Calibration: with a search list larger than the table (`ef_search = 1000`,
/// in a rolled-back transaction so nothing leaks into the call under test),
/// the HNSW plan reaches all `ROWS` embedded rows. Without this a badly
/// connected test graph would fail the fill test for a reason that has
/// nothing to do with `ef_search` truncation.
async fn hnsw_graph_reaches_every_row(conn: &mut sqlx::PgConnection) {
    let q = vec_angle(0.0);
    sqlx::query("BEGIN")
        .execute(&mut *conn)
        .await
        .expect("BEGIN");
    sqlx::query("SET LOCAL hnsw.ef_search = 1000")
        .execute(&mut *conn)
        .await
        .expect("SET LOCAL ef_search");
    let reached: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM (SELECT c.id FROM claims c \
         WHERE c.embedding IS NOT NULL \
         ORDER BY c.embedding <=> '{q}'::vector LIMIT 1000) s"
    ))
    .fetch_one(&mut *conn)
    .await
    .expect("graph reach probe");
    sqlx::query("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("ROLLBACK");
    assert_eq!(
        reached, ROWS as i64,
        "calibration: HNSW graph reaches only {reached} of {ROWS} rows"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn flat_search_statement_is_served_by_the_hnsw_index(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    seed_arc(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    force_index_plans(&mut conn).await;

    let explain = format!(
        "EXPLAIN (COSTS OFF) {}",
        ClaimRepository::semantic_search_flat_sql(&viewer)
    );
    let mut q = sqlx::query_scalar::<_, String>(&explain)
        .bind(vec_angle(0.0))
        .bind(-1.0_f64)
        .bind(None::<String>)
        .bind(None::<chrono::DateTime<chrono::Utc>>)
        .bind(None::<chrono::DateTime<chrono::Utc>>)
        .bind(None::<Uuid>)
        .bind(50_i64);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    let plan = q.fetch_all(&mut *conn).await.expect("EXPLAIN").join("\n");

    assert!(
        plan.contains("Index Scan using idx_claims_embedding_hnsw"),
        "semantic_search_flat must be served by the HNSW index, not a scan and sort of every \
         embedded claim:\n{plan}"
    );
    assert!(
        !plan.contains("Sort"),
        "the HNSW index already yields distance order; a Sort node means the ORDER BY no \
         longer matches it:\n{plan}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn flat_search_on_the_index_fills_a_limit_beyond_ef_search(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let ids = seed_arc(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    force_index_plans(&mut conn).await;
    hnsw_graph_reaches_every_row(&mut conn).await;

    let limit = 60_usize; // above pgvector's default ef_search of 40
    let hits = ClaimRepository::semantic_search_flat(
        &mut *conn,
        &viewer,
        &vec_angle(0.0),
        -1.0,
        None,
        None,
        None,
        None,
        limit as i64,
    )
    .await
    .expect("semantic_search_flat");

    let got: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert_eq!(
        got.len(),
        limit,
        "an index scan capped at hnsw.ef_search returns 40 rows; the call must widen it to \
         fill LIMIT {limit}"
    );
    assert_eq!(
        got,
        ids[..limit].to_vec(),
        "hits must be the {limit} nearest rows, nearest first"
    );

    // The widened settings are SET LOCAL inside a transaction the call rolls
    // back. On a caller's own transaction that transaction is a savepoint, and
    // releasing it instead would carry the settings into the caller's later
    // HNSW reads, so call it inside one and read them back before it ends.
    // `begin()`, not a raw `BEGIN`: sqlx only opens a savepoint for the
    // call's own `begin()` when it knows the connection is in a transaction.
    use sqlx::Connection;
    let mut outer = conn.begin().await.expect("BEGIN");
    let in_tx = ClaimRepository::semantic_search_flat(
        &mut *outer,
        &viewer,
        &vec_angle(0.0),
        -1.0,
        None,
        None,
        None,
        None,
        limit as i64,
    )
    .await
    .expect("semantic_search_flat inside the caller's transaction");
    assert_eq!(in_tx.len(), limit, "the savepoint path must fill LIMIT too");
    let ef: String = sqlx::query_scalar("SHOW hnsw.ef_search")
        .fetch_one(&mut *outer)
        .await
        .expect("SHOW hnsw.ef_search");
    let iterative: String = sqlx::query_scalar("SHOW hnsw.iterative_scan")
        .fetch_one(&mut *outer)
        .await
        .expect("SHOW hnsw.iterative_scan");
    outer.rollback().await.expect("ROLLBACK");
    assert_eq!(
        (ef.as_str(), iterative.as_str()),
        ("40", "off"),
        "semantic_search_flat leaked its HNSW settings into the caller's transaction"
    );
}
