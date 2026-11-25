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
//! `hnsw.max_scan_tuples`, default 20,000), plus an exact retry of a pass that
//! comes back short, which covers that bound (backlog 28b79b1e; the
//! `*_past_max_scan_tuples` tests at the end of this file).
//!
//! Scope: the five legs pinned below, which serve `recall`,
//! `recall_with_context`'s flat seeds, the library `recall`, and the diverse
//! pipeline's theme-coverage probe and theme candidate query (MCP
//! `recall_with_context diverse=true` and REST `search/semantic?diverse=true`);
//! the write-side novelty gate (`nearest_by_embedding`, backlog b00aa40e); and,
//! at the end of this file, the opt-in workflows leg of `recall`
//! (`search_by_goal_embedding_since`), which an IVFFlat index serves, so its
//! truncation is the `ivfflat.probes` window rather than `hnsw.ef_search`.
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
use epigraph_db::{
    ClaimRepository, ClaimThemeRepository, EmbeddingSeedScope, NeighbourhoodThemeCoverage,
};
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
    /// The viewer's own agent: every visible row is authored by it.
    agent: Uuid,
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
            agent,
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

/// The write-side novelty gate's neighbours (`nearest_by_embedding`, what
/// `submit_claim` and `memorize` read before deciding whether to insert).
async fn novelty_page(conn: &mut sqlx::PgConnection, viewer: &Viewer) -> Vec<(Uuid, f64)> {
    ClaimRepository::nearest_by_embedding(&mut *conn, viewer, &vec_angle(0.0), LIMIT)
        .await
        .expect("nearest_by_embedding")
        .into_iter()
        .map(|h| (h.claim_id, h.distance))
        .collect()
}

/// The novelty gate's neighbour read (backlog b00aa40e). It ran a plain HNSW
/// scan, so a foreign group's 40 nearest rows emptied the caller's
/// neighbours: its own near-duplicate went unseen (a second copy was
/// inserted), and whether the gate fired told the caller whether foreign rows
/// sit near its text.
#[sqlx::test(migrations = "../../migrations")]
async fn hidden_rows_do_not_change_the_novelty_gate_neighbours(pool: PgPool) {
    let (w, visible) = world(&pool).await;

    let (before, _) = on_hnsw!(&pool, VISIBLE as i64, |conn| novelty_page(conn, &w.viewer)
        .await);
    let own = before.iter().filter(|(id, _)| visible.contains(id)).count();
    seed_hidden(&pool, &w).await;
    let (after, used_index) = on_hnsw!(&pool, (VISIBLE + HIDDEN) as i64, |conn| novelty_page(
        conn, &w.viewer
    )
    .await);

    assert!(
        used_index,
        "calibration: the novelty gate's kNN was not served by idx_claims_embedding_hnsw"
    );
    assert_identical_pages("nearest_by_embedding", &before, &after, own);
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

/// One theme holding every embedded claim seeded so far, visible and hidden
/// alike, so the theme restriction cannot be what keeps a hidden row out.
/// Re-run after [`seed_hidden`] to enrol the hidden rows too.
async fn theme_holding_every_claim(pool: &PgPool, theme: Option<Uuid>) -> Uuid {
    let theme = match theme {
        Some(t) => t,
        None => sqlx::query_scalar(
            "INSERT INTO claim_themes (label) VALUES ('side channel theme') RETURNING id",
        )
        .fetch_one(pool)
        .await
        .expect("seed theme"),
    };
    sqlx::query("UPDATE claims SET theme_id = $1 WHERE embedding IS NOT NULL")
        .bind(theme)
        .execute(pool)
        .await
        .expect("assign theme");
    theme
}

async fn theme_candidates_page(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    theme: Uuid,
) -> Vec<(Uuid, f64)> {
    ClaimThemeRepository::claims_in_themes_at_dim_since(
        &mut *conn,
        viewer,
        &[theme],
        &vec_angle(0.0),
        LIMIT as i32,
        1536,
        false,
        None,
    )
    .await
    .expect("claims_in_themes_at_dim_since")
    .into_iter()
    .map(|(id, _, sim)| (id, sim))
    .collect()
}

async fn coverage_probe(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    theme: Uuid,
) -> NeighbourhoodThemeCoverage {
    ClaimThemeRepository::nearest_theme_coverage_since(
        &mut *conn,
        viewer,
        &vec_angle(0.0),
        1536,
        &[theme],
        1536,
        // `THEME_COVERAGE_PROBE_K` in epigraph-engine, which this crate
        // cannot depend on; the K both diverse pipelines probe with.
        40,
        false,
        None,
    )
    .await
    .expect("nearest_theme_coverage_since")
}

/// The diverse pipeline's candidate query (`claims_in_themes_at_dim_since`)
/// — what `recall_with_context diverse=true` and the REST diverse route draw
/// their candidates from. The hidden rows sit in the SAME theme, nearer the
/// query, so only the scan depth stands between them and the viewer's page.
#[sqlx::test(migrations = "../../migrations")]
async fn hidden_rows_do_not_change_the_diverse_theme_candidates(pool: PgPool) {
    let (w, visible) = world(&pool).await;
    let theme = theme_holding_every_claim(&pool, None).await;

    let (before, _) = on_hnsw!(&pool, VISIBLE as i64, |conn| theme_candidates_page(
        conn, &w.viewer, theme
    )
    .await);
    let own = before.iter().filter(|(id, _)| visible.contains(id)).count();
    seed_hidden(&pool, &w).await;
    theme_holding_every_claim(&pool, Some(theme)).await;
    let (after, used_index) = on_hnsw!(&pool, (VISIBLE + HIDDEN) as i64, |conn| {
        theme_candidates_page(conn, &w.viewer, theme).await
    });

    assert!(
        used_index,
        "calibration: the theme candidate kNN was not served by idx_claims_embedding_hnsw"
    );
    assert_identical_pages("claims_in_themes_at_dim_since", &before, &after, own);
}

/// The diverse pipeline's theme-coverage probe
/// (`nearest_theme_coverage_since`), whose count decides between the diverse
/// selection and the flat fallback. If hidden rows could shrink `probed` or
/// skew `reachable / probed`, rows the viewer cannot read would choose which
/// algorithm serves its page.
#[sqlx::test(migrations = "../../migrations")]
async fn hidden_rows_do_not_change_the_theme_coverage_probe(pool: PgPool) {
    let (w, _) = world(&pool).await;
    let theme = theme_holding_every_claim(&pool, None).await;

    let (before, _) = on_hnsw!(&pool, VISIBLE as i64, |conn| coverage_probe(
        conn, &w.viewer, theme
    )
    .await);
    assert_eq!(
        before,
        NeighbourhoodThemeCoverage {
            probed: VISIBLE as i64,
            reachable: VISIBLE as i64,
        },
        "calibration: the baseline probe must see every visible row, all reachable"
    );
    seed_hidden(&pool, &w).await;
    theme_holding_every_claim(&pool, Some(theme)).await;
    let (after, used_index) = on_hnsw!(&pool, (VISIBLE + HIDDEN) as i64, |conn| {
        coverage_probe(conn, &w.viewer, theme).await
    });

    assert!(
        used_index,
        "calibration: the coverage probe was not served by idx_claims_embedding_hnsw"
    );
    assert_eq!(
        after, before,
        "nearest_theme_coverage_since: {HIDDEN} rows the viewer cannot read changed the \
         coverage probe, so they now decide whether the viewer gets diverse or flat recall"
    );
}

// ---------------------------------------------------------------------------
// Past `hnsw.max_scan_tuples` (backlog 28b79b1e)
// ---------------------------------------------------------------------------
//
// The iterative scan above keeps scanning until `LIMIT` visible rows are
// found, but only up to `hnsw.max_scan_tuples` (pgvector default 20,000).
// A viewer with more hidden rows than that nearer the query than its own got
// a short page. These tests are the scaled-down equivalent: the bound is set
// to `SCALED_MAX_SCAN_TUPLES` on the test connection (the code under test
// never sets it) and `HIDDEN_PAST_BOUND` hidden rows, five times the bound,
// sit nearer the query than every visible row. A calibration proves the
// bound really cuts the iterative scan short on that connection, so a full
// page can only come from the read's own fallback.

/// Stand-in for pgvector's default `hnsw.max_scan_tuples` of 20,000.
const SCALED_MAX_SCAN_TUPLES: i64 = 60;
/// Hidden rows nearer the query than every visible row: well past the bound.
const HIDDEN_PAST_BOUND: usize = 300;

/// `n` foreign rows, all nearer the query (0°..29°) than every visible row
/// (30°..35.5°) and lexically stronger, as in [`seed_hidden`]. With a
/// `theme`, each row joins it BEFORE it gets its embedding: assigning the
/// theme afterwards would be a second, non-HOT update of an embedded row,
/// which leaves a dead entry in the HNSW graph for every row and (measured)
/// can disconnect a live one, failing the reach calibration.
async fn seed_hidden_n(pool: &PgPool, w: &World, n: usize, theme: Option<Uuid>) {
    for i in 0..n {
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
        if let Some(t) = theme {
            sqlx::query("UPDATE claims SET theme_id = $1 WHERE id = $2")
                .bind(t)
                .bind(id)
                .execute(pool)
                .await
                .expect("assign hidden row to theme");
        }
        fixture::set_claim_embedding(pool, id, &vec_angle(29.0 * i as f64 / n as f64)).await;
    }
}

/// `VACUUM claims`, so the HNSW graph drops (and repairs around) the dead
/// node each embedded row leaves behind when the theme assignment above
/// rewrites it (a non-HOT update: `theme_id` is indexed). Measured without
/// it: with the 300 hidden rows inserted around those dead nodes, the reach
/// calibration failed for exactly the 12 rewritten visible rows. A REINDEX is
/// no substitute: a bulk build of this arc left the visible rows unreachable
/// in every non-theme case.
async fn vacuum_claims(pool: &PgPool) {
    sqlx::query("VACUUM claims")
        .execute(pool)
        .await
        .expect("VACUUM claims");
}

/// [`hnsw_conn`] plus `hnsw.max_scan_tuples = SCALED_MAX_SCAN_TUPLES` at
/// session level, set after the calibrations have loaded the `vector`
/// library (a value set before the library loads can be discarded), and
/// read back.
async fn bounded_hnsw_conn(
    pool: &PgPool,
    n_rows: i64,
) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let mut conn = hnsw_conn(pool, n_rows).await;
    sqlx::query(&format!(
        "SET hnsw.max_scan_tuples = {SCALED_MAX_SCAN_TUPLES}"
    ))
    .execute(&mut *conn)
    .await
    .expect("SET hnsw.max_scan_tuples");
    let bound: String = sqlx::query_scalar("SELECT current_setting('hnsw.max_scan_tuples')")
        .fetch_one(&mut *conn)
        .await
        .expect("read hnsw.max_scan_tuples");
    assert_eq!(
        bound,
        SCALED_MAX_SCAN_TUPLES.to_string(),
        "calibration: hnsw.max_scan_tuples did not take on the test connection"
    );
    conn
}

/// Calibration: on `conn`, an iterative HNSW scan restricted to the viewer's
/// own rows (the visible set, by author) under the scaled bound returns FEWER
/// than `LIMIT` rows. Without this, pgvector handing back its leftover
/// candidates at the bound could let a read pass with no fallback at all.
async fn assert_bound_cuts_the_iterative_scan(conn: &mut sqlx::PgConnection, viewer_agent: Uuid) {
    use sqlx::Connection;
    let mut tx = conn.begin().await.expect("BEGIN");
    sqlx::query(
        "SELECT set_config('hnsw.iterative_scan', 'strict_order', true), \
                set_config('hnsw.ef_search', '40', true)",
    )
    .execute(&mut *tx)
    .await
    .expect("iterative scan settings");
    let reached: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM (SELECT c.id FROM claims c \
         WHERE c.embedding IS NOT NULL AND c.agent_id = $1 \
         ORDER BY c.embedding <=> '{}'::vector LIMIT {LIMIT}) s",
        vec_angle(0.0)
    ))
    .bind(viewer_agent)
    .fetch_one(&mut *tx)
    .await
    .expect("bounded iterative probe");
    tx.rollback().await.expect("ROLLBACK");
    assert!(
        reached < LIMIT,
        "calibration: hnsw.max_scan_tuples = {SCALED_MAX_SCAN_TUPLES} did not cut the \
         iterative scan short ({reached} of {LIMIT} visible rows reached), so this test \
         cannot tell a fallback from no fallback"
    );
}

/// As `on_hnsw!`, on a [`bounded_hnsw_conn`]. With `Some(agent)`, the bound
/// is first proven to cut the iterative scan short for that agent's rows (the
/// hidden rows must be seeded by then; the baseline passes `None`).
macro_rules! on_bounded_hnsw {
    ($pool:expr, $n:expr, $calibrate_for:expr, |$conn:ident| $body:expr) => {{
        use sqlx::Connection;
        let mut pooled = bounded_hnsw_conn($pool, $n).await;
        if let Some(agent) = $calibrate_for {
            assert_bound_cuts_the_iterative_scan(&mut pooled, agent).await;
        }
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

fn assert_full_page_past_the_bound<T: PartialEq + std::fmt::Debug>(
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
        "{leg}: {HIDDEN_PAST_BOUND} hidden rows nearer the query than the viewer's own, more \
         than hnsw.max_scan_tuples ({SCALED_MAX_SCAN_TUPLES} here, 20,000 by default), changed \
         its page (count {} -> {}). The iterative scan stopped at the bound and the read did \
         not fall back to an exact scan",
        before.len(),
        after.len()
    );
}

async fn flat_page(conn: &mut sqlx::PgConnection, viewer: &Viewer) -> Vec<(Uuid, f64)> {
    ClaimRepository::semantic_search_flat(
        &mut *conn,
        viewer,
        epigraph_db::FlatRanking::Query(&vec_angle(0.0)),
        -1.0,
        None,
        None,
        None,
        None,
        LIMIT,
        None,
        0,
    )
    .await
    .expect("semantic_search_flat")
    .into_iter()
    .map(|h| (h.claim_id, h.similarity))
    .collect()
}

/// Runs `$page` before and after seeding [`HIDDEN_PAST_BOUND`] hidden rows,
/// on bounded connections, and asserts the page did not move.
macro_rules! past_bound_case {
    ($pool:expr, $leg:expr, $theme:expr, |$conn:ident, $w:ident, $t:ident| $page:expr) => {{
        let pool: &PgPool = $pool;
        let ($w, visible) = world(pool).await;
        let viewer_agent = $w.agent;
        let $t: Option<Uuid> = if $theme {
            Some(theme_holding_every_claim(pool, None).await)
        } else {
            None
        };
        if $theme {
            vacuum_claims(pool).await;
        }
        let (before, _) = on_bounded_hnsw!(pool, VISIBLE as i64, None::<Uuid>, |$conn| $page);
        seed_hidden_n(pool, &$w, HIDDEN_PAST_BOUND, $t).await;
        let (after, used_index) = on_bounded_hnsw!(
            pool,
            (VISIBLE + HIDDEN_PAST_BOUND) as i64,
            Some(viewer_agent),
            |$conn| $page
        );
        assert!(
            used_index,
            "{}: calibration: the first pass was not served by idx_claims_embedding_hnsw",
            $leg
        );
        (before, after, visible)
    }};
}

#[sqlx::test(migrations = "../../migrations")]
async fn scoped_embedding_page_fills_past_max_scan_tuples(pool: PgPool) {
    let (before, after, visible) =
        past_bound_case!(&pool, "search_by_embedding_scoped", false, |conn, w, _t| {
            scoped_page(conn, &w.viewer).await
        });
    let own = before.iter().filter(|(id, _)| visible.contains(id)).count();
    assert_full_page_past_the_bound("search_by_embedding_scoped", &before, &after, own);
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_seed_page_fills_past_max_scan_tuples(pool: PgPool) {
    let (before, after, visible) = past_bound_case!(
        &pool,
        "search_by_embedding_since_conn",
        false,
        |conn, w, _t| seed_page(conn, &w.viewer).await
    );
    let own = before.iter().filter(|(id, _)| visible.contains(id)).count();
    assert_full_page_past_the_bound("search_by_embedding_since_conn", &before, &after, own);
}

#[sqlx::test(migrations = "../../migrations")]
async fn hybrid_page_fills_past_max_scan_tuples(pool: PgPool) {
    let (before, after, visible) =
        past_bound_case!(&pool, "search_hybrid_scoped", false, |conn, w, _t| {
            hybrid_page(conn, &w.viewer).await
        });
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
    assert_full_page_past_the_bound("search_hybrid_scoped", &before, &after, own);
}

#[sqlx::test(migrations = "../../migrations")]
async fn flat_semantic_page_fills_past_max_scan_tuples(pool: PgPool) {
    let (before, after, visible) =
        past_bound_case!(&pool, "semantic_search_flat", false, |conn, w, _t| {
            flat_page(conn, &w.viewer).await
        });
    let own = before.iter().filter(|(id, _)| visible.contains(id)).count();
    assert_full_page_past_the_bound("semantic_search_flat", &before, &after, own);
}

#[sqlx::test(migrations = "../../migrations")]
async fn diverse_theme_candidates_fill_past_max_scan_tuples(pool: PgPool) {
    let (before, after, visible) = past_bound_case!(
        &pool,
        "claims_in_themes_at_dim_since",
        true,
        |conn, w, t| theme_candidates_page(conn, &w.viewer, t.expect("theme")).await
    );
    let own = before.iter().filter(|(id, _)| visible.contains(id)).count();
    assert_full_page_past_the_bound("claims_in_themes_at_dim_since", &before, &after, own);
}

#[sqlx::test(migrations = "../../migrations")]
async fn theme_coverage_probe_counts_past_max_scan_tuples(pool: PgPool) {
    let (before, after, _visible) =
        past_bound_case!(&pool, "nearest_theme_coverage_since", true, |conn, w, t| {
            coverage_probe(conn, &w.viewer, t.expect("theme")).await
        });
    assert_eq!(
        before,
        NeighbourhoodThemeCoverage {
            probed: VISIBLE as i64,
            reachable: VISIBLE as i64,
        },
        "calibration: the baseline probe must see every visible row, all reachable"
    );
    assert_eq!(
        after, before,
        "nearest_theme_coverage_since: {HIDDEN_PAST_BOUND} hidden rows past \
         hnsw.max_scan_tuples ({SCALED_MAX_SCAN_TUPLES} here) shrank the coverage probe; \
         the probe did not fall back to an exact scan"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn novelty_gate_neighbours_fill_past_max_scan_tuples(pool: PgPool) {
    let (before, after, visible) =
        past_bound_case!(&pool, "nearest_by_embedding", false, |conn, w, _t| {
            novelty_page(conn, &w.viewer).await
        });
    let own = before.iter().filter(|(id, _)| visible.contains(id)).count();
    assert_full_page_past_the_bound("nearest_by_embedding", &before, &after, own);
}

// ---------------------------------------------------------------------------
// The workflows leg: `search_by_goal_embedding_since` (backlog b00aa40e)
// ---------------------------------------------------------------------------
//
// `workflows.goal_embedding` is served by an IVFFlat index (migration 040,
// `lists = 10`), not HNSW. A plain IVFFlat scan reads only the
// `ivfflat.probes` lists (pgvector default 1) whose centroids lie nearest
// the query, and the visibility predicate runs after it, so a viewer whose
// workflows sit in other lists than the foreign rows nearest the query got a
// short page, or none. These tests rebuild the index over the seeded rows (so
// its lists are k-means clusters of them, as on a populated table), force the
// index plan, and prove on the test connection that a scan at the default
// probes really falls short for the viewer's own rows.

/// The viewer's own workflows: far from the query (150°..155.5°), so the
/// lists nearest the query hold only foreign rows.
const WORKFLOWS_VISIBLE: usize = 12;
/// Foreign workflows, all nearer the query (0°..19.75°).
const WORKFLOWS_HIDDEN: usize = 80;

/// One `visibility = 'group'` workflow owned by `group`, its goal embedded at
/// `deg` degrees.
async fn seed_goal_workflow(pool: &PgPool, group: Uuid, name: &str, deg: f64) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, visibility, owner_group_id, \
                                goal_embedding) \
         VALUES ($1, $2, $3, 'group', $4, $5::vector)",
    )
    .bind(id)
    .bind(format!("{name}-{id}"))
    .bind(format!("goal of {name}"))
    .bind(group)
    .bind(vec_angle(deg))
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

/// The viewer and its own workflows (nearest first), then the foreign
/// group's, and the index rebuilt over all of them.
async fn workflow_world(pool: &PgPool) -> (Viewer, Uuid, Vec<Uuid>) {
    let (agent, group) = fixture::seed_agent_with_group(pool, "goal-viewer").await;
    let (_, foreign_group) = fixture::seed_agent_with_group(pool, "goal-foreign").await;
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let mut visible = Vec::with_capacity(WORKFLOWS_VISIBLE);
    for i in 0..WORKFLOWS_VISIBLE {
        visible.push(
            seed_goal_workflow(pool, group, &format!("own-{i}"), 150.0 + 0.5 * i as f64).await,
        );
    }
    for i in 0..WORKFLOWS_HIDDEN {
        seed_goal_workflow(
            pool,
            foreign_group,
            &format!("foreign-{i}"),
            0.25 * i as f64,
        )
        .await;
    }
    sqlx::query("REINDEX INDEX idx_workflows_goal_embedding")
        .execute(pool)
        .await
        .expect("rebuild the goal index over the seeded rows");
    (viewer, group, visible)
}

/// Index scans this transaction has made on `idx_workflows_goal_embedding`.
async fn goal_index_scans(conn: &mut sqlx::PgConnection) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE(sum(pg_stat_get_xact_numscans(i.indexrelid)), 0)::bigint \
         FROM pg_index i JOIN pg_class ix ON ix.oid = i.indexrelid \
         WHERE i.indrelid = 'workflows'::regclass \
           AND ix.relname = 'idx_workflows_goal_embedding'",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("pg_stat_get_xact_numscans")
}

/// Calibrations on the forced-index connection: a plain scan at the default
/// `ivfflat.probes`, restricted to the viewer's own group, returns FEWER than
/// `LIMIT` rows (so a full page below can only come from the read itself),
/// and the IVFFlat knobs are pgvector's defaults (so a green cannot come from
/// a role- or database-level setting the code under test did not make).
async fn assert_probes_cut_a_plain_goal_scan(conn: &mut sqlx::PgConnection, group: Uuid) {
    let reached: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM (SELECT w.id FROM workflows w \
         WHERE w.goal_embedding IS NOT NULL AND w.owner_group_id = $1 \
         ORDER BY w.goal_embedding <=> '{}'::vector LIMIT {LIMIT}) s",
        vec_angle(0.0)
    ))
    .bind(group)
    .fetch_one(&mut *conn)
    .await
    .expect("plain goal probe");
    let (probes, iterative): (String, String) = sqlx::query_as(
        "SELECT current_setting('ivfflat.probes'), current_setting('ivfflat.iterative_scan')",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("read ivfflat settings");
    assert_eq!(
        (probes.as_str(), iterative.as_str()),
        ("1", "off"),
        "calibration: ivfflat knobs not at pgvector defaults on the test connection"
    );
    assert!(
        reached < LIMIT,
        "calibration: a plain IVFFlat scan at probes = 1 reached {reached} of the viewer's \
         {WORKFLOWS_VISIBLE} workflows, so this test cannot tell a filled page from the plain \
         scan"
    );
}

/// A viewer whose workflows lie in other IVFFlat lists than the foreign rows
/// nearest the query (a rare scope) still fills its page with its own
/// workflows, nearest first. Before the fix the read was a plain scan of the
/// one nearest list, all foreign, and returned nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn rare_scope_viewer_fills_its_workflow_goal_page(pool: PgPool) {
    use sqlx::Connection;
    let (viewer, group, visible) = workflow_world(&pool).await;
    let mut pooled = pool.acquire().await.expect("acquire");
    force_index_plans(&mut pooled).await;
    assert_probes_cut_a_plain_goal_scan(&mut pooled, group).await;

    let mut tx = pooled.begin().await.expect("BEGIN");
    let before = goal_index_scans(&mut tx).await;
    let hits = epigraph_db::WorkflowRepository::search_by_goal_embedding_since(
        &mut tx,
        &viewer,
        &vec_angle(0.0),
        LIMIT,
        None,
    )
    .await
    .expect("search_by_goal_embedding_since");
    let after = goal_index_scans(&mut tx).await;
    // The call's settings are transaction-local to a savepoint it rolls back.
    let (probes, iterative): (String, String) = sqlx::query_as(
        "SELECT current_setting('ivfflat.probes'), current_setting('ivfflat.iterative_scan')",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read ivfflat settings after the call");
    tx.rollback().await.expect("ROLLBACK");

    assert!(
        after > before,
        "calibration: the goal kNN was not served by idx_workflows_goal_embedding"
    );
    assert_eq!(
        (probes.as_str(), iterative.as_str()),
        ("1", "off"),
        "the read's IVFFlat settings leaked into the caller's transaction"
    );
    let got: Vec<Uuid> = hits.iter().map(|h| h.workflow_id).collect();
    assert_eq!(
        got,
        visible[..LIMIT as usize].to_vec(),
        "a viewer whose workflows sit in other IVFFlat lists than the {WORKFLOWS_HIDDEN} \
         foreign rows nearest the query must get its own {LIMIT} nearest workflows, in \
         distance order; it got {} rows",
        got.len()
    );
    assert!(
        hits.windows(2).all(|p| p[0].similarity >= p[1].similarity),
        "the page is in distance order: {:?}",
        hits.iter().map(|h| h.similarity).collect::<Vec<_>>()
    );
}

/// The iterative IVFFlat scan stops at `ivfflat.max_probes` lists. With that
/// bound set to 1 on the session (so the iterative pass reads only the one
/// list nearest the query, all foreign, and comes back empty), the read still
/// fills the viewer's page, nearest first: its exact retry (`vector_scan`
/// module doc) is what serves a viewer for whom the bound cut the scan.
#[sqlx::test(migrations = "../../migrations")]
async fn workflow_goal_page_fills_past_ivfflat_max_probes(pool: PgPool) {
    let (viewer, group, visible) = workflow_world(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    force_index_plans(&mut conn).await;
    sqlx::query("SET ivfflat.max_probes = 1")
        .execute(&mut *conn)
        .await
        .expect("bound the iterative IVFFlat scan");

    // Calibration: an iterative scan under that bound, restricted to the
    // viewer's own group, really falls short.
    let reached: i64 = {
        use sqlx::Connection;
        let mut tx = conn.begin().await.expect("BEGIN");
        sqlx::query("SET LOCAL ivfflat.iterative_scan = relaxed_order")
            .execute(&mut *tx)
            .await
            .expect("iterative scan");
        let n = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM (SELECT w.id FROM workflows w \
             WHERE w.goal_embedding IS NOT NULL AND w.owner_group_id = $1 \
             ORDER BY w.goal_embedding <=> '{}'::vector LIMIT {LIMIT}) s",
            vec_angle(0.0)
        ))
        .bind(group)
        .fetch_one(&mut *tx)
        .await
        .expect("bounded iterative goal probe");
        tx.rollback().await.expect("ROLLBACK");
        n
    };
    assert!(
        reached < LIMIT,
        "calibration: an iterative IVFFlat scan at max_probes = 1 reached {reached} of the \
         viewer's {WORKFLOWS_VISIBLE} workflows, so this test cannot tell the exact retry \
         from the iterative pass"
    );

    let hits = epigraph_db::WorkflowRepository::search_by_goal_embedding_since(
        &mut conn,
        &viewer,
        &vec_angle(0.0),
        LIMIT,
        None,
    )
    .await
    .expect("search_by_goal_embedding_since");
    let got: Vec<Uuid> = hits.iter().map(|h| h.workflow_id).collect();
    assert_eq!(
        got,
        visible[..LIMIT as usize].to_vec(),
        "with the iterative scan bounded short of the viewer's lists, the read must still \
         return its own {LIMIT} nearest workflows, in distance order (the exact retry); it \
         got {} rows",
        got.len()
    );
}

/// The query of the hierarchical goal reads as `&[f32]`: `vec_angle(0.0)`.
fn goal_query() -> Vec<f32> {
    let mut v = vec![0.0f32; 1536];
    v[0] = 1.0;
    v
}

/// MCP `find_workflow`'s hierarchical leg and the store-time workflow match
/// (`search_hierarchical_by_embedding_scored`) read the same IVFFlat index
/// with the visibility splice after it (backlog b00aa40e). A rare-scope
/// viewer still fills its page with its own workflows, nearest first. Before
/// the fix the read was a plain scan of the one nearest list, all foreign, and
/// returned nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn rare_scope_viewer_fills_its_scored_hierarchical_workflow_page(pool: PgPool) {
    use sqlx::Connection;
    let (viewer, group, visible) = workflow_world(&pool).await;
    let mut pooled = pool.acquire().await.expect("acquire");
    force_index_plans(&mut pooled).await;
    assert_probes_cut_a_plain_goal_scan(&mut pooled, group).await;

    let mut tx = pooled.begin().await.expect("BEGIN");
    let before = goal_index_scans(&mut tx).await;
    let hits = epigraph_db::WorkflowRepository::search_hierarchical_by_embedding_scored(
        &mut tx,
        &viewer,
        &vec_angle(0.0),
        0.0,
        LIMIT,
    )
    .await
    .expect("search_hierarchical_by_embedding_scored");
    let after = goal_index_scans(&mut tx).await;
    let (probes, iterative): (String, String) = sqlx::query_as(
        "SELECT current_setting('ivfflat.probes'), current_setting('ivfflat.iterative_scan')",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read ivfflat settings after the call");
    tx.rollback().await.expect("ROLLBACK");

    assert!(
        after > before,
        "calibration: the scored goal kNN was not served by idx_workflows_goal_embedding"
    );
    assert_eq!(
        (probes.as_str(), iterative.as_str()),
        ("1", "off"),
        "the read's IVFFlat settings leaked into the caller's transaction"
    );
    let got: Vec<Uuid> = hits.iter().map(|h| h.id).collect();
    assert_eq!(
        got,
        visible[..LIMIT as usize].to_vec(),
        "a viewer whose workflows sit in other IVFFlat lists than the {WORKFLOWS_HIDDEN} \
         foreign rows nearest the query must get its own {LIMIT} nearest workflows from the \
         scored hierarchical read, in distance order; it got {} rows",
        got.len()
    );
}

/// `find_hierarchical_by_embedding` (MCP and REST `find_workflow_hierarchical`)
/// takes no viewer: row security on the caller's stamped read scopes it, and
/// row security, like the splice, filters after a vector index scan. It is
/// safe only because its ORDER BY (distance plus tiebreak columns) keeps the
/// IVFFlat index from serving it (backlog b00aa40e; the function's doc). This
/// pins both halves on an application-role read stamped as a rare-scope
/// member, in both result shapes: the statement makes no scan of
/// `idx_workflows_goal_embedding` even with sequential scans and sorts
/// penalised, and the member gets its own nearest workflows in distance
/// order. Dropping the tiebreaks (so the index serves the statement) fails
/// both assertions.
#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_embedding_search_stays_exact_and_fills_a_rare_scope_page(pool: PgPool) {
    let (viewer, group, visible) = workflow_world(&pool).await;
    let url = fixture::database_url_for(&pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");

    for resolve_to_latest in [false, true] {
        let mut read = scoped.read_as(&viewer).await.expect("stamped read");
        force_index_plans(&mut read).await;
        assert_probes_cut_a_plain_goal_scan(&mut read, group).await;
        // In a transaction: the per-transaction scan counter resets at every
        // autocommit statement.
        let mut tx = sqlx::Connection::begin(&mut *read).await.expect("BEGIN");
        // Calibration: on this connection a distance-only ORDER BY IS served
        // by the goal index, so a zero below is the statement's own plan.
        let probe_before = goal_index_scans(&mut tx).await;
        sqlx::query(&format!(
            "SELECT w.id FROM workflows w WHERE w.goal_embedding IS NOT NULL \
             ORDER BY w.goal_embedding <=> '{}'::vector LIMIT {LIMIT}",
            vec_angle(0.0)
        ))
        .fetch_all(&mut *tx)
        .await
        .expect("distance-only probe");
        let probe_after = goal_index_scans(&mut tx).await;
        let before = goal_index_scans(&mut tx).await;
        let rows = epigraph_db::WorkflowRepository::find_hierarchical_by_embedding(
            &mut *tx,
            &goal_query(),
            -1.0,
            0.0,
            LIMIT,
            resolve_to_latest,
        )
        .await
        .expect("find_hierarchical_by_embedding");
        let after = goal_index_scans(&mut tx).await;
        // Calibration: the stamped session reads none of the foreign rows.
        let foreign_seen: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM workflows WHERE owner_group_id <> $1")
                .bind(group)
                .fetch_one(&mut *tx)
                .await
                .expect("count foreign rows on the stamped read");
        tx.rollback().await.expect("ROLLBACK");
        for s in [
            "RESET enable_seqscan",
            "RESET enable_bitmapscan",
            "RESET enable_sort",
        ] {
            sqlx::query(s).execute(&mut *read).await.expect(s);
        }
        read.commit().await.expect("close read");

        assert_eq!(
            foreign_seen, 0,
            "calibration: row security must hide the foreign group's workflows"
        );
        assert!(
            probe_after > probe_before,
            "calibration: a distance-only goal kNN on this connection must use \
             idx_workflows_goal_embedding"
        );
        assert_eq!(
            after, before,
            "resolve_to_latest = {resolve_to_latest}: the statement was served by \
             idx_workflows_goal_embedding, so row security now filters after a capped IVFFlat \
             scan; give it the iterative scan and exact retry of search_by_goal_embedding_since"
        );
        let got: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        assert_eq!(
            got,
            visible[..LIMIT as usize].to_vec(),
            "resolve_to_latest = {resolve_to_latest}: a member whose workflows sit in other \
             IVFFlat lists than the {WORKFLOWS_HIDDEN} foreign rows nearest the query must get \
             its own {LIMIT} nearest workflows, in distance order; it got {} rows",
            got.len()
        );
    }
}
