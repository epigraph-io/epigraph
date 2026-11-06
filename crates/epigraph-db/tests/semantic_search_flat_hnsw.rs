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
//! the index cannot serve still plans as a sort over a seq scan, so the plan
//! test counts this transaction's scans of the HNSW index around the call. `hnsw.ef_search` is left at its default: the tests
//! must not set the knob the implementation sets.
//!
//! Schema notes (mirrors claim_search_hybrid.rs): seed an `agents` row first
//! (FK + edge-validation trigger); `content_hash bytea NOT NULL` and
//! `(content_hash, agent_id)` UNIQUE → use distinct hashes.
//!
//! # The theme pin, paging and the theme core
//!
//! The second half of this file covers what `POST /api/v1/search/semantic`'s
//! `theme_id`, `cursor` and `rank_by=theme_core` added to the same function:
//! the unpinned paged form must stay on the index; the pinned form must be
//! exact (it fills its limit however far the theme is from the query, and it
//! makes no HNSW scan even when index plans are forced); pages must be
//! disjoint; and the theme core must be the mean of the PUBLIC members, never
//! the stored `claim_themes.centroid`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ClaimRepository, ClaimThemeRepository, FlatRanking};
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
async fn flat_search_is_served_by_the_hnsw_index(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    seed_arc(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    force_index_plans(&mut conn).await;

    // Run the real call inside an outer transaction, then read this
    // transaction's own scan counter for the index: pg_stat_get_xact_numscans
    // counts every scan made so far in the current transaction, including one
    // inside the call's rolled-back savepoint.
    use sqlx::Connection;
    let mut outer = conn.begin().await.expect("BEGIN");
    let before: i64 = hnsw_scans(&mut outer).await;
    let hits = ClaimRepository::semantic_search_flat(
        &mut *outer,
        &viewer,
        epigraph_db::FlatRanking::Query(&vec_angle(0.0)),
        -1.0,
        None,
        None,
        None,
        None,
        10,
        None,
        0,
    )
    .await
    .expect("semantic_search_flat");
    let after: i64 = hnsw_scans(&mut outer).await;
    outer.rollback().await.expect("ROLLBACK");

    assert_eq!(hits.len(), 10);
    assert!(
        after > before,
        "semantic_search_flat must be served by the HNSW index; an ORDER BY the index \
         cannot match (e.g. the derived similarity) scans and sorts every embedded claim"
    );
}

/// Index scans this transaction has made on the claims HNSW index(es).
async fn hnsw_scans(conn: &mut sqlx::PgConnection) -> i64 {
    sqlx::query_scalar(
        "SELECT COALESCE(sum(pg_stat_get_xact_numscans(i.indexrelid)), 0)::bigint \
         FROM pg_index i JOIN pg_class ix ON ix.oid = i.indexrelid \
         WHERE i.indrelid = 'claims'::regclass \
           AND ix.relname LIKE 'idx_claims_embedding_hnsw%'",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("pg_stat_get_xact_numscans")
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
        epigraph_db::FlatRanking::Query(&vec_angle(0.0)),
        -1.0,
        None,
        None,
        None,
        None,
        limit as i64,
        None,
        0,
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
        epigraph_db::FlatRanking::Query(&vec_angle(0.0)),
        -1.0,
        None,
        None,
        None,
        None,
        limit as i64,
        None,
        0,
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

// ── The theme pin, paging and the theme core ──

/// A `claim_themes` row. `claim_themes` carries no tenancy, so a bare INSERT
/// is the production shape.
async fn seed_theme(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, 'flat-hnsw fixture') \
         RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("insert theme")
}

/// One current, embedded claim at `deg` degrees, optionally in `theme`. The
/// row is public, the shape [`seed_arc`] writes.
async fn seed_row(pool: &PgPool, agent: Uuid, deg: f64, theme: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             embedding, theme_id) \
         VALUES ($1, $2, $3, $4, 0.8, true, $5::vector, $6)",
    )
    .bind(id)
    .bind(format!("flat-hnsw row at {deg} degrees ({id})"))
    .bind(hash)
    .bind(agent)
    .bind(vec_angle(deg))
    .bind(theme)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

async fn set_created_at(pool: &PgPool, id: Uuid, at: &str) {
    sqlx::query("UPDATE claims SET created_at = $2::timestamptz WHERE id = $1")
        .bind(id)
        .bind(at)
        .execute(pool)
        .await
        .expect("set created_at");
}

async fn attach(pool: &PgPool, claim: Uuid, theme: Uuid, deg: f64) {
    sqlx::query("UPDATE claims SET theme_id = $2, embedding = $3::vector WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .bind(vec_angle(deg))
        .execute(pool)
        .await
        .expect("attach theme and embedding");
}

/// `semantic_search_flat` ids for one page, on the pool, no other filter.
async fn page(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    ranking: FlatRanking<'_>,
    limit: i64,
    theme: Option<Uuid>,
    offset: i64,
) -> Vec<Uuid> {
    ClaimRepository::semantic_search_flat(
        pool, viewer, ranking, -1.0, None, None, None, None, limit, theme, offset,
    )
    .await
    .expect("semantic_search_flat")
    .into_iter()
    .map(|h| h.claim_id)
    .collect()
}

/// The exact top-`limit` of `theme` by distance to `vec`, ties by id, in an
/// ORDER BY no index can serve (adding zero hides the operator from the
/// planner).
async fn brute_force_in_theme(pool: &PgPool, theme: Uuid, vec: &str, limit: i64) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT c.id FROM claims c \
         WHERE c.theme_id = $1 AND c.embedding IS NOT NULL \
         ORDER BY (c.embedding <=> $2::vector) + 0::float8, c.id \
         LIMIT $3",
    )
    .bind(theme)
    .bind(vec)
    .bind(limit)
    .fetch_all(pool)
    .await
    .expect("brute force")
}

/// The public-member mean of `theme`, as pgvector text.
async fn public_mean(pool: &PgPool, theme: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT AVG(embedding)::text FROM claims \
         WHERE theme_id = $1 AND embedding IS NOT NULL AND visibility = 'public'",
    )
    .bind(theme)
    .fetch_one(pool)
    .await
    .expect("public mean")
}

/// Test 1: an `offset` page on the unpinned form is still an HNSW scan.
#[sqlx::test(migrations = "../../migrations")]
async fn unpinned_offset_window_still_uses_the_hnsw_index(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let ids = seed_arc(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    force_index_plans(&mut conn).await;
    hnsw_graph_reaches_every_row(&mut conn).await;

    use sqlx::Connection;
    let mut outer = conn.begin().await.expect("BEGIN");
    let before: i64 = hnsw_scans(&mut outer).await;
    let hits = ClaimRepository::semantic_search_flat(
        &mut *outer,
        &viewer,
        FlatRanking::Query(&vec_angle(0.0)),
        -1.0,
        None,
        None,
        None,
        None,
        20,
        None,
        40,
    )
    .await
    .expect("semantic_search_flat at offset 40");
    let after: i64 = hnsw_scans(&mut outer).await;
    outer.rollback().await.expect("ROLLBACK");

    let got: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert_eq!(got.len(), 20, "an offset page must still fill its limit");
    assert_eq!(
        got,
        ids[40..60].to_vec(),
        "offset 40, limit 20 must be ranks 40..60, nearest first"
    );
    assert!(
        after > before,
        "the unpinned paged form must still be served by the HNSW index"
    );
}

/// Test 2: the pin sits above the cut, so a theme far from the query fills.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_theme_fills_its_limit_when_members_are_far_from_the_query(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    // 80 unthemed rows nearest the probe, from seed_arc (0 to 39.5 degrees).
    let arc = seed_arc(&pool).await;
    // The arc's own agent: `seed_agent` uses a fixed public key, so a second
    // call in one database collides on `agents_public_key_unique`.
    let agent: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(arc[0])
        .fetch_one(&pool)
        .await
        .expect("arc agent");
    let theme = seed_theme(&pool, "far-theme").await;
    let mut members = Vec::new();
    for i in 0..20 {
        members.push(seed_row(&pool, agent, 100.0 + i as f64, Some(theme)).await);
    }

    let got = page(
        &pool,
        &viewer,
        FlatRanking::Query(&vec_angle(0.0)),
        20,
        Some(theme),
        0,
    )
    .await;
    assert_eq!(
        got, members,
        "a pinned call must return all 20 theme members in ascending distance, \
         however many unthemed rows are nearer the query"
    );
}

/// Test 3: every pinned hit is a member of the pinned theme.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_theme_returns_only_members(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let t = seed_theme(&pool, "only-t").await;
    let u = seed_theme(&pool, "only-u").await;
    for i in 0..30 {
        let theme = if i % 2 == 0 { t } else { u };
        seed_row(&pool, agent, i as f64, Some(theme)).await;
    }
    for i in 0..10 {
        seed_row(&pool, agent, 0.25 + i as f64, None).await;
    }

    let got = page(
        &pool,
        &viewer,
        FlatRanking::Query(&vec_angle(0.0)),
        100,
        Some(t),
        0,
    )
    .await;
    assert_eq!(got.len(), 15, "all 15 members of T, no more");
    let themes: Vec<Option<Uuid>> =
        sqlx::query_scalar("SELECT theme_id FROM claims WHERE id = ANY($1)")
            .bind(&got)
            .fetch_all(&pool)
            .await
            .expect("theme ids");
    assert!(
        themes.iter().all(|x| *x == Some(t)),
        "every pinned hit must be in T; got {themes:?}"
    );
}

/// Pages at 0, 10 and 20 are pairwise disjoint and their concatenation is the
/// `limit = 30` result.
fn assert_pages_cover_the_prefix(pages: &[Vec<Uuid>], whole: &[Uuid], arm: &str) {
    for (i, a) in pages.iter().enumerate() {
        for b in &pages[i + 1..] {
            assert!(
                a.iter().all(|x| !b.contains(x)),
                "{arm}: pages must be disjoint; {a:?} and {b:?} overlap"
            );
        }
    }
    let joined: Vec<Uuid> = pages.iter().flatten().copied().collect();
    assert_eq!(
        joined, whole,
        "{arm}: the pages, in order, must equal the limit-30 result"
    );
}

/// Test 4, pinned arm: four IDENTICAL embeddings at ranks 9-12 straddle the
/// offset-10 boundary, so only the `id` tiebreak keeps the pages disjoint.
#[sqlx::test(migrations = "../../migrations")]
async fn offset_pages_are_disjoint_and_cover_the_prefix_pinned(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let theme = seed_theme(&pool, "paged-pinned").await;
    for rank in 1..=40 {
        // Ranks 9..=12 share the angle of rank 9.
        let deg = if (9..=12).contains(&rank) {
            9.0
        } else {
            rank as f64
        };
        seed_row(&pool, agent, deg, Some(theme)).await;
    }

    let q = vec_angle(0.0);
    let mut pages = Vec::new();
    for offset in [0, 10, 20] {
        let p = page(
            &pool,
            &viewer,
            FlatRanking::Query(&q),
            10,
            Some(theme),
            offset,
        )
        .await;
        assert_eq!(p.len(), 10);
        pages.push(p);
    }
    let whole = page(&pool, &viewer, FlatRanking::Query(&q), 30, Some(theme), 0).await;
    assert_eq!(whole.len(), 30);
    assert_pages_cover_the_prefix(&pages, &whole, "pinned");
}

/// Test 4, unpinned arm: the tie group sits at ranks 12-15, strictly inside
/// page 2 and on one side of every inner cut (10, 20, 30). A tie group across
/// an inner cut is the documented residual and is not asserted.
#[sqlx::test(migrations = "../../migrations")]
async fn offset_pages_are_disjoint_and_cover_the_prefix_unpinned(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    for rank in 1..=40 {
        let deg = if (12..=15).contains(&rank) {
            12.0
        } else {
            rank as f64
        };
        seed_row(&pool, agent, deg, None).await;
    }

    let q = vec_angle(0.0);
    let mut pages = Vec::new();
    for offset in [0, 10, 20] {
        let p = page(&pool, &viewer, FlatRanking::Query(&q), 10, None, offset).await;
        assert_eq!(p.len(), 10);
        pages.push(p);
    }
    let whole = page(&pool, &viewer, FlatRanking::Query(&q), 30, None, 0).await;
    assert_eq!(whole.len(), 30);
    assert_pages_cover_the_prefix(&pages, &whole, "unpinned");
}

/// Test 5: the created window and the similarity floor apply inside the
/// member set, and the limit fills from the rows that qualify.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_theme_composes_with_created_window_and_min_similarity(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let theme = seed_theme(&pool, "window-theme").await;
    let mut rows = Vec::new();
    for i in 0..20 {
        let id = seed_row(&pool, agent, i as f64, Some(theme)).await;
        let at = match i {
            0..=4 => "2020-01-01T00:00:00Z",
            15..=19 => "2026-06-01T00:00:00Z",
            _ => "2024-01-01T00:00:00Z",
        };
        set_created_at(&pool, id, at).await;
        rows.push(id);
    }
    let after = chrono::DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let before = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    // Midway between 12 and 13 degrees: rows 0..=12 clear it, 13.. do not.
    let floor = 12.5_f64.to_radians().cos();
    let q = vec_angle(0.0);

    let mut got = Vec::new();
    for limit in [100_i64, 5] {
        let ids: Vec<Uuid> = ClaimRepository::semantic_search_flat(
            &pool,
            &viewer,
            FlatRanking::Query(&q),
            floor,
            None,
            Some(after),
            Some(before),
            None,
            limit,
            Some(theme),
            0,
        )
        .await
        .expect("pinned windowed call")
        .into_iter()
        .map(|h| h.claim_id)
        .collect();
        got.push(ids);
    }

    assert_eq!(
        got[0],
        rows[5..=12].to_vec(),
        "only in-window rows above the floor qualify (rows 5..=12)"
    );
    assert_eq!(
        got[1],
        rows[5..10].to_vec(),
        "the limit fills from qualifying rows, nearest first"
    );
}

/// Test 6: the pinned reads are exact and make no HNSW scan even with every
/// other plan disabled.
#[sqlx::test(migrations = "../../migrations")]
async fn pinned_reads_make_no_hnsw_scan_even_when_index_plans_are_forced(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let ids = seed_arc(&pool).await;
    let theme = seed_theme(&pool, "forced-plans").await;
    // Every third arc row joins the theme.
    let members: Vec<Uuid> = ids.iter().step_by(3).copied().collect();
    sqlx::query("UPDATE claims SET theme_id = $1 WHERE id = ANY($2)")
        .bind(theme)
        .bind(&members)
        .execute(&pool)
        .await
        .expect("attach theme");

    // Brute force, on another connection, before the counting window.
    let q = vec_angle(0.0);
    let expect_query = brute_force_in_theme(&pool, theme, &q, 10).await;
    let core = public_mean(&pool, theme).await;
    let expect_core = brute_force_in_theme(&pool, theme, &core, 10).await;
    assert_eq!(
        expect_query.len(),
        10,
        "calibration: the theme has 27 members"
    );

    let mut conn = pool.acquire().await.expect("acquire");
    force_index_plans(&mut conn).await;
    use sqlx::Connection;
    let mut outer = conn.begin().await.expect("BEGIN");
    let before: i64 = hnsw_scans(&mut outer).await;

    let by_query: Vec<Uuid> = ClaimRepository::semantic_search_flat(
        &mut *outer,
        &viewer,
        FlatRanking::Query(&q),
        -1.0,
        None,
        None,
        None,
        None,
        10,
        Some(theme),
        0,
    )
    .await
    .expect("pinned Query")
    .into_iter()
    .map(|h| h.claim_id)
    .collect();
    let by_core: Vec<Uuid> = ClaimRepository::semantic_search_flat(
        &mut *outer,
        &viewer,
        FlatRanking::ThemeCore,
        -1.0,
        None,
        None,
        None,
        None,
        10,
        Some(theme),
        0,
    )
    .await
    .expect("pinned ThemeCore")
    .into_iter()
    .map(|h| h.claim_id)
    .collect();
    let exact: Vec<Uuid> = ClaimThemeRepository::claims_in_theme_exact_at_dim(
        &mut *outer,
        &viewer,
        theme,
        &q,
        10,
        1536,
        None,
        -1.0,
    )
    .await
    .expect("claims_in_theme_exact_at_dim")
    .into_iter()
    .map(|(id, _, _)| id)
    .collect();

    let after: i64 = hnsw_scans(&mut outer).await;
    outer.rollback().await.expect("ROLLBACK");

    assert_eq!(
        after, before,
        "a pinned read must make no HNSW scan, even with seq scans, bitmap scans \
         and sorts disabled"
    );
    assert_eq!(
        by_query, expect_query,
        "pinned Query must be the exact top 10"
    );
    assert_eq!(
        by_core, expect_core,
        "pinned ThemeCore must be the exact top 10"
    );
    assert_eq!(
        exact, expect_query,
        "claims_in_theme_exact_at_dim must be the exact top 10"
    );
}

/// Run `ThemeCore` on `theme` for `viewer`, every member (limit 100).
async fn theme_core_hits(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    theme: Uuid,
) -> Vec<(Uuid, f64)> {
    ClaimRepository::semantic_search_flat(
        pool,
        viewer,
        FlatRanking::ThemeCore,
        -1.0,
        None,
        None,
        None,
        None,
        100,
        Some(theme),
        0,
    )
    .await
    .expect("theme core")
    .into_iter()
    .map(|h| (h.claim_id, h.similarity))
    .collect()
}

fn sim_of(hits: &[(Uuid, f64)], id: Uuid) -> f64 {
    hits.iter()
        .find(|(c, _)| *c == id)
        .map(|(_, s)| *s)
        .unwrap_or_else(|| panic!("{id} absent from {hits:?}"))
}

/// Test 7: the theme core is the PUBLIC mean, not the stored centroid and not
/// a mean over private members, so a stranger and a group member rank the
/// public members identically.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_core_ranks_by_the_public_mean_not_the_stored_centroid(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "core-public").await;
    let theme = seed_theme(&pool, "core-public").await;
    // The stored centroid points at the private member's direction.
    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(theme)
        .bind(vec_angle(90.0))
        .execute(&pool)
        .await
        .expect("set stored centroid");
    let p1 = fixture::seed_public_claim(&pool, agent, "core-public P1").await;
    let p2 = fixture::seed_public_claim(&pool, agent, "core-public P2").await;
    let x = fixture::seed_group_claim(&pool, agent, group, "core-public X").await;
    attach(&pool, p1, theme, 10.0).await;
    attach(&pool, p2, theme, 20.0).await;
    attach(&pool, x, theme, 90.0).await;

    let expected_p1: f64 = sqlx::query_scalar(
        "SELECT (1 - (p.embedding <=> \
                 (SELECT AVG(embedding) FROM claims WHERE id = ANY($2))))::float8 \
         FROM claims p WHERE p.id = $1",
    )
    .bind(p1)
    .bind(vec![p1, p2])
    .fetch_one(&pool)
    .await
    .expect("expected similarity");
    assert!(
        (expected_p1 - 5.0_f64.to_radians().cos()).abs() < 1e-4,
        "calibration: P1 is 5 degrees from the public mean; got {expected_p1}"
    );

    let member = epigraph_db::Viewer::resolve(&pool, agent)
        .await
        .expect("resolve member");
    let stranger = fixture::public_viewer(&pool).await;

    let mine = theme_core_hits(&pool, &member, theme).await;
    let ids: Vec<Uuid> = mine.iter().map(|(c, _)| *c).collect();
    assert_eq!(ids.len(), 3, "the member sees all three; got {ids:?}");
    assert_eq!(ids[2], x, "P1 and P2 rank above X; got {ids:?}");
    assert!(
        (sim_of(&mine, p1) - expected_p1).abs() < 1e-6,
        "similarity(P1) must be to the public mean: got {}, want {expected_p1}",
        sim_of(&mine, p1)
    );

    let theirs = theme_core_hits(&pool, &stranger, theme).await;
    assert!(
        !theirs.iter().any(|(c, _)| *c == x),
        "a stranger must not see X; got {theirs:?}"
    );
    assert_eq!(
        theirs.len(),
        2,
        "the stranger sees P1 and P2; got {theirs:?}"
    );
    for p in [p1, p2] {
        assert!(
            (sim_of(&theirs, p) - sim_of(&mine, p)).abs() < 1e-9,
            "a stranger and a member must rank public members against the same core"
        );
    }
}

/// Test 8: with no public member the core falls back to the mean of what
/// the viewer can read, and a stranger reads nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn theme_core_falls_back_to_visible_members_when_no_member_is_public(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "core-fallback").await;
    let theme = seed_theme(&pool, "core-fallback").await;
    let x1 = fixture::seed_group_claim(&pool, agent, group, "core-fallback X1").await;
    let x2 = fixture::seed_group_claim(&pool, agent, group, "core-fallback X2").await;
    attach(&pool, x1, theme, 10.0).await;
    attach(&pool, x2, theme, 30.0).await;

    let member = epigraph_db::Viewer::resolve(&pool, agent)
        .await
        .expect("resolve member");
    let hits = theme_core_hits(&pool, &member, theme).await;
    assert_eq!(hits.len(), 2, "the member sees both private members");
    let want = 10.0_f64.to_radians().cos();
    for (_, s) in &hits {
        assert!(
            (s - want).abs() < 1e-4,
            "each is 10 degrees from mean(X1, X2); got {s}"
        );
    }

    let stranger = fixture::public_viewer(&pool).await;
    let none = theme_core_hits(&pool, &stranger, theme).await;
    assert!(
        none.is_empty(),
        "a stranger must get zero rows; got {none:?}"
    );
}

/// Test 9: a retired member (not current, both embeddings NULL, as
/// `chk_deprecated_no_embedding` requires) is neither counted nor returned.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_theme_member_is_neither_counted_nor_returned(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let theme = seed_theme(&pool, "retired-member").await;
    let l1 = seed_row(&pool, agent, 1.0, Some(theme)).await;
    let l2 = seed_row(&pool, agent, 2.0, Some(theme)).await;
    let retired = seed_row(&pool, agent, 0.0, Some(theme)).await;
    sqlx::query(
        "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
         WHERE id = $1",
    )
    .bind(retired)
    .execute(&pool)
    .await
    .expect("retire the member");

    let q = vec_angle(0.0);
    for ranking in [FlatRanking::Query(&q), FlatRanking::ThemeCore] {
        let got = page(&pool, &viewer, ranking, 100, Some(theme), 0).await;
        assert!(
            !got.contains(&retired),
            "a retired member must not be returned"
        );
        assert_eq!(got.len(), 2);
        assert!(got.contains(&l1) && got.contains(&l2));
    }
    let summary = ClaimThemeRepository::get_summary(&pool, &viewer, theme)
        .await
        .expect("get_summary")
        .expect("theme exists");
    assert_eq!(
        summary.member_count, 2,
        "member_count must exclude the retired member"
    );
}
