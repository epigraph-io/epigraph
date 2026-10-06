//! Integration tests for `ClaimRepository::search_hybrid_scoped` (RRF fusion of
//! the dense `claims.embedding` leg and the lexical `content_tsv` leg).
//!
//! Schema notes (mirrors claim_search_by_embedding.rs): seed an `agents` row
//! first (FK + edge-validation trigger); `content_hash bytea NOT NULL` and
//! `(content_hash, agent_id)` UNIQUE → use distinct hashes. `content_tsv` is a
//! GENERATED column (migration 050), so inserting `content` auto-populates it.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// 1536-d unit-ish vector with the "hot" dimension at `idx` set to 0.99.
fn vec_hot(idx: usize) -> String {
    let mut v = vec!["0.0"; 1536];
    v[idx] = "0.99";
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

fn distinct_hash(tag: u8) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = tag;
    h
}

#[allow(clippy::too_many_arguments)]
async fn insert_claim(
    pool: &PgPool,
    id: Uuid,
    agent: Uuid,
    tag: u8,
    content: &str,
    embedding_pgvec: &str,
    is_current: bool,
    labels: &[&str],
) {
    let labels_arr: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
    // Invariant chk_deprecated_no_embedding (migration 052): is_current=false rows
    // MUST have embedding=NULL. The "non-current" fixtures exercise the is_current
    // filter; a retired row carries no embedding, matching production.
    let embedding_pgvec = if is_current {
        Some(embedding_pgvec)
    } else {
        None
    };
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, labels, embedding) \
         VALUES ($1, $2, $3, $4, 0.8, $5, $6, $7::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(distinct_hash(tag))
    .bind(agent)
    .bind(is_current)
    .bind(&labels_arr)
    .bind(embedding_pgvec)
    .execute(pool)
    .await
    .expect("insert claim");
}

#[sqlx::test(migrations = "../../migrations")]
async fn hybrid_fuses_both_legs_ranking_the_overlap_first(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let query = vec_hot(0); // dense query points at dim 0

    // DENSE: closest vector, no lexical overlap with the query text.
    let dense = Uuid::new_v4();
    insert_claim(
        &pool,
        dense,
        agent,
        1,
        "orthogonal filler prose about weather",
        &vec_hot(0),
        true,
        &[],
    )
    .await;
    // BOTH: 2nd-closest vector AND contains the rare lexical term.
    let both = Uuid::new_v4();
    insert_claim(
        &pool,
        both,
        agent,
        2,
        "discussion of quasinormal mechanosynthesis tooling",
        &vec_hot(1),
        true,
        &[],
    )
    .await;
    // LEX: far vector, contains the rare lexical term.
    let lex = Uuid::new_v4();
    insert_claim(
        &pool,
        lex,
        agent,
        3,
        "quasinormal mechanosynthesis appears here too",
        &vec_hot(900),
        true,
        &[],
    )
    .await;

    let hits = ClaimRepository::search_hybrid_scoped(
        &pool,
        &viewer,
        &query,
        "quasinormal mechanosynthesis",
        50,
        60,
        10,
        None,
        None,
    )
    .await
    .expect("hybrid search");

    let order: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert!(order.contains(&both) && order.contains(&dense) && order.contains(&lex));
    // `both` is in BOTH legs → its RRF sum beats any single-leg claim.
    assert_eq!(
        order[0], both,
        "overlap claim must rank first; got {order:?}"
    );

    let both_hit = hits.iter().find(|h| h.claim_id == both).unwrap();
    assert!(
        both_hit.dense_similarity.is_some() && both_hit.in_lexical,
        "both legs"
    );
    let dense_hit = hits.iter().find(|h| h.claim_id == dense).unwrap();
    assert!(
        dense_hit.dense_similarity.is_some() && !dense_hit.in_lexical,
        "dense only"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn hybrid_surfaces_lexical_only_hit_outside_dense_pool(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let query = vec_hot(0);

    let dense = Uuid::new_v4();
    insert_claim(
        &pool,
        dense,
        agent,
        1,
        "no overlap filler",
        &vec_hot(0),
        true,
        &[],
    )
    .await;
    let lex = Uuid::new_v4();
    insert_claim(
        &pool,
        lex,
        agent,
        2,
        "rare token zubuzonium present",
        &vec_hot(900),
        true,
        &[],
    )
    .await;

    // candidate_pool=1 → dense leg yields only `dense`; `lex` can only enter via
    // the lexical leg, so dense_similarity must be NULL there.
    let hits = ClaimRepository::search_hybrid_scoped(
        &pool,
        &viewer,
        &query,
        "zubuzonium",
        1,
        60,
        10,
        None,
        None,
    )
    .await
    .expect("hybrid search");

    let lex_hit = hits
        .iter()
        .find(|h| h.claim_id == lex)
        .expect("lexical-only hit present");
    assert!(
        lex_hit.dense_similarity.is_none(),
        "lexical-only ⇒ no dense similarity"
    );
    assert!(lex_hit.in_lexical);
}

#[sqlx::test(migrations = "../../migrations")]
async fn hybrid_excludes_non_current_and_honors_tag_scope(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let query = vec_hot(0);

    // Non-current claim that would otherwise match both legs.
    let stale = Uuid::new_v4();
    insert_claim(
        &pool,
        stale,
        agent,
        1,
        "zubuzonium stale",
        &vec_hot(0),
        false,
        &["keep"],
    )
    .await;
    // Current, in-scope (label "keep").
    let keep = Uuid::new_v4();
    insert_claim(
        &pool,
        keep,
        agent,
        2,
        "zubuzonium keep",
        &vec_hot(0),
        true,
        &["keep"],
    )
    .await;
    // Current, out-of-scope (no "keep" label).
    let drop = Uuid::new_v4();
    insert_claim(
        &pool,
        drop,
        agent,
        3,
        "zubuzonium drop",
        &vec_hot(0),
        true,
        &["other"],
    )
    .await;

    let tags = vec!["keep".to_string()];
    let hits = ClaimRepository::search_hybrid_scoped(
        &pool,
        &viewer,
        &query,
        "zubuzonium",
        50,
        60,
        10,
        Some(&tags),
        None,
    )
    .await
    .expect("hybrid search");

    let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert!(ids.contains(&keep), "in-scope current claim present");
    assert!(!ids.contains(&stale), "non-current excluded");
    assert!(
        !ids.contains(&drop),
        "out-of-scope (tag) excluded on both legs"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn lexical_scoped_ranks_matches_and_honors_scope(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    let hit = Uuid::new_v4();
    insert_claim(
        &pool,
        hit,
        agent,
        1,
        "zubuzonium reactor design",
        &vec_hot(0),
        true,
        &["keep"],
    )
    .await;
    let miss = Uuid::new_v4();
    insert_claim(
        &pool,
        miss,
        agent,
        2,
        "unrelated weather prose",
        &vec_hot(0),
        true,
        &["keep"],
    )
    .await;
    let stale = Uuid::new_v4();
    insert_claim(
        &pool,
        stale,
        agent,
        3,
        "zubuzonium stale",
        &vec_hot(0),
        false,
        &["keep"],
    )
    .await;
    let oos = Uuid::new_v4();
    insert_claim(
        &pool,
        oos,
        agent,
        4,
        "zubuzonium other",
        &vec_hot(0),
        true,
        &["other"],
    )
    .await;

    let tags = vec!["keep".to_string()];
    let hits = ClaimRepository::search_lexical_scoped(
        &pool,
        &viewer,
        "zubuzonium",
        60,
        10,
        Some(&tags),
        None,
    )
    .await
    .expect("lexical search");

    let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
    assert!(ids.contains(&hit), "lexical match in scope present");
    assert!(!ids.contains(&miss), "non-matching content excluded");
    assert!(!ids.contains(&stale), "non-current excluded");
    assert!(!ids.contains(&oos), "out-of-scope tag excluded");

    let h = hits.iter().find(|h| h.claim_id == hit).unwrap();
    assert!(
        h.dense_similarity.is_none() && h.in_lexical,
        "lexical-only shape"
    );
    assert!(h.rrf_score > 0.0);
}

// ── Dense-leg truncation under an HNSW index plan (backlog fdd8e494) ────────
//
// pgvector's HNSW index scan yields at most `hnsw.ef_search` (default 40)
// candidates unless iterative scanning is on, and every scope predicate in the
// dense CTE (`labels @>`, `agent_id`, `since`, `theme_id`, the visibility
// splice) is applied AFTER that scan. So a scope that is rare among the ~40
// nearest neighbours silently returns 0–2 dense rows, and even the unscoped
// dense leg cannot fill a candidate pool larger than 40.
//
// Small tables are always cheaper to seq-scan, so these tests pin the plan
// prod actually runs: ONE connection (the `SET`s are session-scoped and a pool
// may hand the next statement another backend), with seq scans, bitmap scans
// (GIN serves only bitmap scans) and explicit sorts disabled. A calibration
// step EXPLAINs the dense CTE shape and aborts — never passes — if the planner
// did not choose `idx_claims_embedding_hnsw`. `hnsw.ef_search` is left at its
// default: the tests must not set the knob the implementation sets.

/// A unit vector at `deg` degrees in the dim-0/dim-1 plane. The query is
/// `vec_hot(0)` (angle 0; cosine is scale-free), so a row's cosine distance to
/// it grows strictly with its angle and every row has its own distance.
///
/// The rows lie on one arc rather than as `e0 + eps_i * e_i` spokes on their
/// own dims: with spokes, HNSW's neighbour-pruning heuristic keeps only the
/// smallest-`eps` rows as neighbours and leaves most of the graph with no
/// inbound edge, so the index cannot reach them at ANY `ef_search` (measured:
/// 33 of 85 rows reachable at ef_search = 200). An arc is a well-formed graph,
/// which [`hnsw_graph_reaches_every_row`] checks.
fn vec_angle(deg: f64) -> String {
    let (s, c) = deg.to_radians().sin_cos();
    let mut v: Vec<String> = vec!["0.0".to_string(); 1536];
    v[0] = format!("{c:.6}");
    v[1] = format!("{s:.6}");
    format!("[{}]", v.join(","))
}

/// Calibration: with a search list larger than the table (`ef_search = 1000`,
/// no iterative scan, in a rolled-back transaction so nothing leaks into the
/// call under test), the HNSW plan reaches all `n` embedded rows. Without this
/// a badly-connected test graph would fail the tests for a reason that has
/// nothing to do with `ef_search` truncation.
async fn hnsw_graph_reaches_every_row(conn: &mut sqlx::PgConnection, n: i64) {
    let q = vec_hot(0);
    sqlx::query("BEGIN")
        .execute(&mut *conn)
        .await
        .expect("BEGIN");
    sqlx::query("SET LOCAL hnsw.ef_search = 1000")
        .execute(&mut *conn)
        .await
        .expect("SET LOCAL ef_search");
    let probe = format!(
        "SELECT COUNT(*) FROM (SELECT c.id FROM claims c \
         WHERE c.embedding IS NOT NULL AND c.is_current \
         ORDER BY c.embedding <=> '{q}'::vector LIMIT 1000) s"
    );
    // The probe only measures the graph if it actually walks the index: on a
    // seq-scan plan it would count every row and calibrate nothing.
    let plan = sqlx::query_scalar::<_, String>(&format!("EXPLAIN (COSTS OFF) {probe}"))
        .fetch_all(&mut *conn)
        .await
        .expect("EXPLAIN graph reach probe")
        .join("\n");
    assert!(
        plan.contains("idx_claims_embedding_hnsw"),
        "calibration: graph reach probe not on HNSW plan:\n{plan}"
    );
    let reached: i64 = sqlx::query_scalar(&probe)
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

/// Calibration: the HNSW knobs on `conn` are at pgvector's defaults
/// (`ef_search = 40`, no iterative scan) right before the act step. Both red
/// results on origin/main (40 of 50 unscoped rows, 0 of 5 tagged rows) depend
/// on the scan being truncated at 40; a different image default or a
/// role/database-level setting would make the tests pass without the fix, so
/// abort instead. Also proves the reach probe's `SET LOCAL` did not leak.
/// Needs the `vector` library loaded on `conn` (any prior `::vector` cast):
/// before that, the `hnsw.*` names are unrecognized.
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
        "calibration: hnsw.iterative_scan/ef_search not at pgvector defaults on the test connection"
    );
}

/// Force the dense CTE onto the HNSW index on `conn` and prove it did, plus
/// prove the test database's pgvector has iterative index scans (>= 0.8.0).
async fn force_hnsw_plan(conn: &mut sqlx::PgConnection, tags: Option<&str>) {
    let ext: String =
        sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
            .fetch_one(&mut *conn)
            .await
            .expect("pgvector extension version");
    let mut parts = ext.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let (major, minor) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    assert!(
        (major, minor) >= (0, 8),
        "calibration: pgvector {ext} < 0.8 on the test DB (no hnsw.iterative_scan)"
    );

    for s in [
        "SET enable_seqscan = off",
        "SET enable_bitmapscan = off",
        "SET enable_sort = off",
    ] {
        sqlx::query(s).execute(&mut *conn).await.expect(s);
    }

    let tag_pred = match tags {
        Some(t) => format!("AND c.labels @> ARRAY['{t}']::text[]"),
        None => String::new(),
    };
    let q = vec_hot(0);
    let plan = sqlx::query_scalar::<_, String>(&format!(
        "EXPLAIN (COSTS OFF) \
         SELECT c.id, row_number() OVER (ORDER BY c.embedding <=> '{q}'::vector) AS rank \
         FROM claims c \
         WHERE c.embedding IS NOT NULL AND c.is_current {tag_pred} \
         ORDER BY c.embedding <=> '{q}'::vector \
         LIMIT 50"
    ))
    .fetch_all(&mut *conn)
    .await
    .expect("EXPLAIN dense CTE")
    .join("\n");
    assert!(
        plan.contains("idx_claims_embedding_hnsw"),
        "calibration: dense leg not on HNSW plan:\n{plan}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn tag_scoped_dense_leg_returns_every_matching_row_beyond_ef_search(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // 80 UNTAGGED rows at 0°..39.5°, all nearer the query than any tagged
    // row: they fill the default ef_search=40 window twice over.
    for i in 0..80usize {
        insert_claim(
            &pool,
            Uuid::new_v4(),
            agent,
            10 + i as u8,
            &format!("untagged filler row number {i}"),
            &vec_angle(0.5 * i as f64),
            true,
            &[],
        )
        .await;
    }
    // 5 TAGGED rows at 50°..58°, farther from the query than every untagged
    // row, with no lexical overlap with the query text — the dense leg is the
    // only way they can be returned.
    let mut tagged = Vec::new();
    for j in 0..5usize {
        let id = Uuid::new_v4();
        insert_claim(
            &pool,
            id,
            agent,
            200 + j as u8,
            &format!("scoped backlog filler item {j}"),
            &vec_angle(50.0 + 2.0 * j as f64),
            true,
            &["backlog"],
        )
        .await;
        tagged.push(id);
    }

    let truth: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims \
         WHERE labels @> '{backlog}' AND embedding IS NOT NULL AND is_current",
    )
    .fetch_one(&pool)
    .await
    .expect("ground truth");
    assert_eq!(truth, 5, "calibration: 5 embedded current backlog rows");

    let mut conn = pool.acquire().await.expect("acquire");
    force_hnsw_plan(&mut conn, Some("backlog")).await;
    hnsw_graph_reaches_every_row(&mut conn, 85).await;
    assert_hnsw_knobs_at_default(&mut conn).await;

    let tags = vec!["backlog".to_string()];
    let hits = ClaimRepository::search_hybrid_scoped_since_in_theme(
        &mut *conn,
        &viewer,
        &vec_hot(0),
        "zzqxnomatch",
        50,
        60,
        10,
        0,
        Some(&tags),
        None,
        None,
        None,
    )
    .await
    .expect("hybrid search");

    let dense: Vec<Uuid> = hits
        .iter()
        .filter(|h| h.dense_similarity.is_some())
        .map(|h| h.claim_id)
        .collect();
    assert_eq!(
        dense.len(),
        5,
        "tag-scoped dense leg must return min(pool, matching embedded rows); \
         got {} dense rows of 5 tagged",
        dense.len()
    );
    for id in &tagged {
        assert!(dense.contains(id), "tagged row {id} missing from dense leg");
    }
    assert!(
        hits.iter().all(|h| !h.in_lexical),
        "query text matches nothing, so no row may come from the lexical leg"
    );
    // Rank stability under the iterative scan: with no lexical leg the fused
    // order is the dense `row_number()` order, which must be the true distance
    // order — the 50°, 52°, ..., 58° insertion order, with strictly falling
    // cosine similarity.
    assert_eq!(
        dense, tagged,
        "dense hits must come back in distance (angle) order"
    );
    assert_dense_similarity_strictly_falls(&hits);
}

/// Every hit is dense-only and `dense_similarity` strictly decreases in hit
/// (i.e. `rrf_score`) order: the dense ranks agree with the actual distances.
fn assert_dense_similarity_strictly_falls(hits: &[epigraph_db::HybridHit]) {
    let sims: Vec<f64> = hits
        .iter()
        .map(|h| h.dense_similarity.expect("dense-only fixture"))
        .collect();
    for (r, w) in sims.windows(2).enumerate() {
        assert!(
            w[0] > w[1],
            "dense rank {} has similarity {} not above rank {}'s {}",
            r + 1,
            w[0],
            r + 2,
            w[1]
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn unscoped_dense_leg_fills_the_candidate_pool(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // 60 rows > candidate_pool 50 > default ef_search 40. `ids[i]` is the row
    // at 0.5 * i degrees, i.e. the i-th nearest to the query.
    let mut ids = Vec::new();
    for i in 0..60usize {
        let id = Uuid::new_v4();
        ids.push(id);
        insert_claim(
            &pool,
            id,
            agent,
            10 + i as u8,
            &format!("unscoped filler row number {i}"),
            &vec_angle(0.5 * i as f64),
            true,
            &[],
        )
        .await;
    }

    let mut conn = pool.acquire().await.expect("acquire");
    force_hnsw_plan(&mut conn, None).await;
    hnsw_graph_reaches_every_row(&mut conn, 60).await;
    assert_hnsw_knobs_at_default(&mut conn).await;

    // limit 100 (the fused `LIMIT $5`) so the outer cut cannot mask the pool.
    let hits = ClaimRepository::search_hybrid_scoped_since_in_theme(
        &mut *conn,
        &viewer,
        &vec_hot(0),
        "zzqxnomatch",
        50,
        60,
        100,
        0,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("hybrid search");

    let dense: Vec<Uuid> = hits
        .iter()
        .filter(|h| h.dense_similarity.is_some())
        .map(|h| h.claim_id)
        .collect();
    assert_eq!(
        dense.len(),
        50,
        "unscoped dense leg must fill candidate_pool (50) when 60 rows are \
         embedded; got {}",
        dense.len()
    );
    // Not just any 50: exactly the 50 nearest rows (0°..24.5°), in distance
    // order.
    assert_eq!(
        dense,
        ids[..50].to_vec(),
        "dense leg must be the 50 nearest rows in distance order"
    );
    assert_dense_similarity_strictly_falls(&hits);
}
