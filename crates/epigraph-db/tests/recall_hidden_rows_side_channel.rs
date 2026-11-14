//! Recall ranking as a side channel (backlog a507966d): can rows a viewer
//! cannot read change the COUNT, ORDER or SCORES of the rows it can?
//!
//! Embeddings carry no share table of their own (migration 060 deliberately
//! did not create `embedding_shares`); a vector is protected only by its
//! row's tenancy. Every recall leg reads on a viewer-scoped statement, so a
//! hidden row is never RETURNED. What this file pins is the subtler property:
//! a hidden row must not be able to displace, reorder or rescore a visible
//! one either.
//!
//! The leak shape is HNSW truncation. An HNSW index scan yields at most
//! `hnsw.ef_search` rows (pgvector default 40) and the visibility predicate is
//! applied AFTER the index, so a foreign group that plants 40+ vectors nearer
//! a query than a viewer's own rows empties that viewer's page — and how much
//! it empties tells the viewer how many hidden rows sit near the query. The
//! fix is pgvector's iterative scan (`hnsw.iterative_scan = strict_order`),
//! which keeps scanning until `LIMIT` visible rows are found (bounded by
//! `hnsw.max_scan_tuples`, default 20,000).
//!
//! Scope: the three legs pinned below, which serve `recall`,
//! `recall_with_context`'s flat seeds and the library `recall`. Other HNSW
//! reads still scan without it and are NOT covered here, among them the
//! diverse pipeline's theme coverage and candidate queries
//! (`claim_theme.rs`), the workflows leg (`search_by_goal_embedding_since`)
//! and the write-side novelty gate (`nearest_by_embedding`).
//!
//! Each test measures the viewer's page BEFORE and AFTER seeding the hidden
//! rows, on one connection forced onto the HNSW plan (seq scans and explicit
//! sorts disabled, as prod runs on a corpus too large to seq-scan), and
//! asserts the pages are identical: same ids, same order, same scores, full
//! `limit`. Two calibrations keep a green honest: the HNSW graph reaches every
//! row (a short page is truncation, not a disconnected graph), and the index
//! was actually scanned (a seq scan would pass for the wrong reason).
//!
//! The lexical leg's `ts_rank_cd` is a per-document score with no corpus
//! statistics, so hidden rows cannot rescore it; the hybrid test pins that
//! too, with hidden rows that out-rank every visible row lexically.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, EmbeddingSeedScope};
use sqlx::PgPool;
use uuid::Uuid;

/// Visible rows: more than the page `LIMIT`, so "full count" is checkable.
const VISIBLE: usize = 12;
/// Hidden rows: twice the default `ef_search` window, all nearer the query.
const HIDDEN: usize = 80;
const LIMIT: i64 = 10;

/// A unit vector at `deg` degrees in the dim-0/dim-1 plane. Rows on one arc
/// give a well-connected HNSW graph (see `semantic_search_flat_hnsw.rs`).
fn vec_angle(deg: f64) -> String {
    let (s, c) = deg.to_radians().sin_cos();
    let mut v: Vec<String> = vec!["0.0".to_string(); 1536];
    v[0] = format!("{c:.6}");
    v[1] = format!("{s:.6}");
    format!("[{}]", v.join(","))
}

struct World {
    viewer: Viewer,
    foreign_agent: Uuid,
    foreign_group: Uuid,
}

/// A viewer that is a member of its own group A (so the group-bind arm of the
/// visibility predicate is exercised, not only the public arm), plus a
/// foreign agent with its own group B, whose rows the viewer cannot read.
async fn world(pool: &PgPool) -> (World, Vec<Uuid>) {
    let (agent, group) = fixture::seed_agent_with_group(pool, "side-channel-viewer").await;
    let (foreign_agent, foreign_group) =
        fixture::seed_agent_with_group(pool, "side-channel-foreign").await;
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve viewer");

    // The viewer's own rows, at 30°..35.5°: every hidden row below is nearer.
    // Visible row i carries the lexical term `VISIBLE - i` times, so the
    // lexical ranks are distinct (no tie order for a hidden row to perturb by
    // accident) and agree with the dense ranks; every hidden row carries it
    // more often than any visible row, so it out-ranks them lexically too.
    let mut visible = Vec::with_capacity(VISIBLE);
    for i in 0..VISIBLE {
        let id = fixture::seed_group_claim(
            pool,
            agent,
            group,
            &format!(
                "side channel visible claim {i} about the {} habitat",
                "quokka ".repeat(VISIBLE - i).trim_end()
            ),
        )
        .await;
        fixture::set_claim_embedding(pool, id, &vec_angle(30.0 + 0.5 * i as f64)).await;
        visible.push(id);
    }
    (
        World {
            viewer,
            foreign_agent,
            foreign_group,
        },
        visible,
    )
}

/// The foreign group's near-duplicates: nearer the query than every visible
/// row (0°..19.75°) and lexically stronger (the term more often than any).
async fn seed_hidden(pool: &PgPool, w: &World) {
    for i in 0..HIDDEN {
        let id = fixture::seed_group_claim(
            pool,
            w.foreign_agent,
            w.foreign_group,
            &format!(
                "side channel hidden claim {i} {} habitat",
                "quokka ".repeat(VISIBLE + 8).trim_end()
            ),
        )
        .await;
        fixture::set_claim_embedding(pool, id, &vec_angle(0.25 * i as f64)).await;
    }
}

async fn force_index_plans(conn: &mut sqlx::PgConnection) {
    for s in [
        "SET enable_seqscan = off",
        "SET enable_bitmapscan = off",
        "SET enable_sort = off",
    ] {
        sqlx::query(s).execute(&mut *conn).await.expect(s);
    }
}

/// Calibration: with `ef_search` above the table size the HNSW plan reaches
/// every embedded row, so a short page can only be `ef_search` truncation.
async fn hnsw_graph_reaches_every_row(conn: &mut sqlx::PgConnection, n: i64) {
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
        reached, n,
        "calibration: HNSW graph reaches only {reached} of {n} rows"
    );
}

/// Calibration: the test connection's HNSW knobs are pgvector's defaults, so
/// a green cannot come from a role- or database-level setting the code under
/// test did not make. Needs the `vector` library loaded on `conn`.
async fn assert_hnsw_knobs_at_default(conn: &mut sqlx::PgConnection) {
    let (iterative, ef): (String, String) = sqlx::query_as(
        "SELECT current_setting('hnsw.iterative_scan'), current_setting('hnsw.ef_search')",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("read hnsw settings");
    assert_eq!(
        (iterative.as_str(), ef.as_str()),
        ("off", "40"),
        "calibration: hnsw knobs not at pgvector defaults on the test connection"
    );
}

/// Index scans this transaction has made on `idx_claims_embedding_hnsw`.
async fn hnsw_scans(conn: &mut sqlx::PgConnection) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE(sum(pg_stat_get_xact_numscans(i.indexrelid)), 0)::bigint \
         FROM pg_index i JOIN pg_class ix ON ix.oid = i.indexrelid \
         WHERE i.indrelid = 'claims'::regclass \
           AND ix.relname = 'idx_claims_embedding_hnsw'",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("pg_stat_get_xact_numscans")
}

/// A connection forced onto the HNSW plan, with both calibrations run.
async fn hnsw_conn(pool: &PgPool, n_rows: i64) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let mut conn = pool.acquire().await.expect("acquire");
    force_index_plans(&mut conn).await;
    hnsw_graph_reaches_every_row(&mut conn, n_rows).await;
    assert_hnsw_knobs_at_default(&mut conn).await;
    conn
}

/// Evaluate `$body` with `$conn: &mut PgConnection` on a forced-HNSW
/// connection, inside an outer transaction so `pg_stat_get_xact_numscans` sees
/// the call's index scans; yields `(body, hnsw_index_was_scanned)`.
macro_rules! on_hnsw {
    ($pool:expr, $n:expr, |$conn:ident| $body:expr) => {{
        use sqlx::Connection;
        let mut pooled = hnsw_conn($pool, $n).await;
        let mut tx = pooled.begin().await.expect("BEGIN");
        let before = hnsw_scans(&mut tx).await;
        let out = {
            let $conn: &mut sqlx::PgConnection = &mut tx;
            $body
        };
        let after = hnsw_scans(&mut tx).await;
        tx.rollback().await.expect("ROLLBACK");
        (out, after > before)
    }};
}

fn assert_identical_pages<T: PartialEq + std::fmt::Debug>(
    leg: &str,
    before: &[T],
    after: &[T],
    own_rows_in_baseline: usize,
) {
    assert_eq!(
        before.len(),
        LIMIT as usize,
        "{leg}: calibration: the baseline page is not full ({} of {LIMIT})",
        before.len()
    );
    assert_eq!(
        own_rows_in_baseline, LIMIT as usize,
        "{leg}: calibration: the baseline must be the viewer's own rows only"
    );
    assert_eq!(
        after,
        before,
        "{leg}: {HIDDEN} rows the viewer cannot read changed its page (count {} -> {}). \
         Hidden rows nearer the query exhausted the HNSW ef_search window before the \
         visibility predicate ran, so the page's size, order or scores now encode how \
         many foreign rows sit near the query",
        before.len(),
        after.len()
    );
}

async fn scoped_page(conn: &mut sqlx::PgConnection, viewer: &Viewer) -> Vec<(Uuid, f64)> {
    ClaimRepository::search_by_embedding_scoped(
        &mut *conn,
        viewer,
        &vec_angle(0.0),
        LIMIT,
        None,
        None,
    )
    .await
    .expect("search_by_embedding_scoped")
    .into_iter()
    .map(|h| (h.claim_id, h.similarity))
    .collect()
}

async fn seed_page(conn: &mut sqlx::PgConnection, viewer: &Viewer) -> Vec<(Uuid, f64)> {
    ClaimRepository::search_by_embedding_since_conn(
        conn,
        viewer,
        &vec_angle(0.0),
        1536,
        LIMIT,
        None,
        None,
        EmbeddingSeedScope::AllClaims,
    )
    .await
    .expect("search_by_embedding_since_conn")
    .into_iter()
    .map(|h| (h.claim_id, h.similarity))
    .collect()
}

type HybridRow = (Uuid, f64, Option<f64>, bool);

async fn hybrid_page(conn: &mut sqlx::PgConnection, viewer: &Viewer) -> Vec<HybridRow> {
    ClaimRepository::search_hybrid_scoped_since_in_theme_conn(
        conn,
        viewer,
        &vec_angle(0.0),
        "quokka",
        50,
        60,
        LIMIT,
        0,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("search_hybrid_scoped_since_in_theme_conn")
    .into_iter()
    .map(|h| (h.claim_id, h.rrf_score, h.dense_similarity, h.in_lexical))
    .collect()
}

/// The `search_by_embedding_current` / `search_by_embedding_scoped` leg —
/// what the library `recall` (`epigraph-engine::recall`), `find_workflow` and
/// `McpEmbedder::search_scoped` read. This is the leg that FAILED the audit:
/// it ran a plain HNSW scan, so a foreign group's 40 nearest rows emptied the
/// viewer's page.
#[sqlx::test(migrations = "../../migrations")]
async fn hidden_rows_do_not_change_the_scoped_embedding_page(pool: PgPool) {
    let (w, visible) = world(&pool).await;

    let (before, _) = on_hnsw!(&pool, VISIBLE as i64, |conn| scoped_page(conn, &w.viewer)
        .await);
    let own = before.iter().filter(|(id, _)| visible.contains(id)).count();
    seed_hidden(&pool, &w).await;
    let (after, used_index) = on_hnsw!(&pool, (VISIBLE + HIDDEN) as i64, |conn| scoped_page(
        conn, &w.viewer
    )
    .await);

    assert!(
        used_index,
        "calibration: the scoped kNN was not served by idx_claims_embedding_hnsw"
    );
    assert_identical_pages("search_by_embedding_scoped", &before, &after, own);
}

/// The `search_by_embedding_since_conn` leg in the whole-corpus scope — what
/// MCP `recall_with_context` seeds on. Already iterative; pinned here so a
/// change that drops the setting reopens the channel loudly.
#[sqlx::test(migrations = "../../migrations")]
async fn hidden_rows_do_not_change_the_recall_with_context_seed_page(pool: PgPool) {
    let (w, visible) = world(&pool).await;

    let (before, _) = on_hnsw!(&pool, VISIBLE as i64, |conn| seed_page(conn, &w.viewer)
        .await);
    let own = before.iter().filter(|(id, _)| visible.contains(id)).count();
    seed_hidden(&pool, &w).await;
    let (after, used_index) = on_hnsw!(&pool, (VISIBLE + HIDDEN) as i64, |conn| seed_page(
        conn, &w.viewer
    )
    .await);

    assert!(
        used_index,
        "calibration: the whole-corpus kNN was not served by idx_claims_embedding_hnsw"
    );
    assert_identical_pages("search_by_embedding_since_conn", &before, &after, own);
}

/// The hybrid (dense + lexical, RRF-fused) leg — what MCP `recall` reads. The
/// hidden rows beat every visible row on BOTH legs: nearer vectors and the
/// query term more often. The fused page — ids, order, `rrf_score`,
/// `dense_similarity`, `in_lexical` — must not move.
#[sqlx::test(migrations = "../../migrations")]
async fn hidden_rows_do_not_change_the_hybrid_page(pool: PgPool) {
    let (w, visible) = world(&pool).await;

    let (before, _) = on_hnsw!(&pool, VISIBLE as i64, |conn| hybrid_page(conn, &w.viewer)
        .await);
    let own = before
        .iter()
        .filter(|(id, ..)| visible.contains(id))
        .count();
    assert!(
        before
            .iter()
            .all(|(_, _, dense, lex)| dense.is_some() && *lex),
        "calibration: every baseline hit must come from both legs: {before:?}"
    );
    seed_hidden(&pool, &w).await;
    let (after, used_index) = on_hnsw!(&pool, (VISIBLE + HIDDEN) as i64, |conn| hybrid_page(
        conn, &w.viewer
    )
    .await);

    assert!(
        used_index,
        "calibration: the hybrid dense leg was not served by idx_claims_embedding_hnsw"
    );
    assert_identical_pages("search_hybrid_scoped", &before, &after, own);
}
