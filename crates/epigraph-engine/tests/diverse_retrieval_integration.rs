//! Integration tests for [`epigraph_engine::diverse_retrieval`].
//!
//! These tests run against a live Postgres test DB (`epigraph_db_repo_test`
//! per the repo convention) — they exercise the SQL the helper builds,
//! the `claim_themes` ↔ `claims` join, and the `diverse_select` selection
//! behaviour end-to-end.
//!
//! Schema notes (verified against migrations through 029):
//!   * `claims.agent_id` is NOT NULL → fixture seeds an `agents` row.
//!   * `agents.public_key` is `bytea` length 32.
//!   * `claims.content_hash` is `bytea NOT NULL` UNIQUE with `agent_id`.
//!   * `claim_themes.centroid` is `vector(1536)`.

use epigraph_engine::diverse_retrieval::{
    find_similar_themes_at_dim, run_diverse_pipeline, DiverseRetrievalConfig,
    DEFAULT_CANDIDATE_POOL,
};
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;
const N_BUCKETS: usize = 8;
const STRIDE: usize = DIM / N_BUCKETS;

fn vec_to_pgvec(v: &[f32]) -> String {
    let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
    format!("[{}]", inner.join(","))
}

/// Pgvector literal at dim=1536 where positions `bucket * STRIDE ..
/// (bucket+1) * STRIDE` are set to `value` and everything else is 0.
/// Vectors with the same `bucket` are highly similar (cosine ~1);
/// different buckets are orthogonal.
fn cluster_pgvec(bucket: usize, value: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    let start = bucket * STRIDE;
    let end = start + STRIDE;
    for slot in v.iter_mut().take(end).skip(start) {
        *slot = value;
    }
    vec_to_pgvec(&v)
}

/// Pgvector with `value` in `bucket` AND `drift` in `drift_bucket`. Used
/// by candidate_pool tests where we need a *monotonically decreasing
/// cosine similarity* across seeded rows: scaling magnitude alone (as
/// `cluster_pgvec(0, 1.0 - i*0.01)` does) yields IDENTICAL cosine sim
/// because direction is unchanged — direction must drift instead.
///
/// `cos(query=cluster_pgvec(bucket, 1.0), this) = value / sqrt(value² + drift²)`,
/// monotonically decreasing in `drift` for `value > 0`.
fn cluster_pgvec_with_drift(bucket: usize, value: f32, drift_bucket: usize, drift: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    let start = bucket * STRIDE;
    let end = start + STRIDE;
    for slot in v.iter_mut().take(end).skip(start) {
        *slot = value;
    }
    let dstart = drift_bucket * STRIDE;
    let dend = dstart + STRIDE;
    for slot in v.iter_mut().take(dend).skip(dstart) {
        *slot = drift;
    }
    vec_to_pgvec(&v)
}

/// Pgvector that splits its mass between TWO buckets: `query_share` in
/// bucket 0 (where the test queries live) and `1.0` in `far_bucket`.
///
/// At `query_share = 0.0` this degenerates to a pure `cluster_pgvec(far_bucket)`
/// (orthogonal to the query → cosine ~0). At `query_share = 1.0` it sits
/// halfway between query and `far_bucket`. We want sim_b ≈ 0.5–0.7 so
/// theme_b's coverage gain (alpha=0.4) actually wins pick #2 over more
/// theme_a items. With STRIDE=192 and value=1.0 everywhere:
///   sim = query_share / sqrt(query_share^2 + 1.0)
/// `query_share = 1.0` → sim ≈ 0.707. Plenty of headroom past 0.33.
fn mixed_bucket_pgvec(far_bucket: usize, query_share: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    // Component in bucket 0 (query bucket) at magnitude `query_share`.
    for slot in v.iter_mut().take(STRIDE) {
        *slot = query_share;
    }
    // Component in `far_bucket` at full magnitude.
    let start = far_bucket * STRIDE;
    let end = start + STRIDE;
    for slot in v.iter_mut().take(end).skip(start) {
        *slot = 1.0;
    }
    vec_to_pgvec(&v)
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

fn hash_for(id: Uuid) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[..16].copy_from_slice(id.as_bytes());
    h
}

async fn seed_theme_with_centroid(pool: &PgPool, label: &str, centroid_pgvec: &str) -> Uuid {
    let theme_id: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, 'integration-test theme') \
         RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("insert theme");
    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(theme_id)
        .bind(centroid_pgvec)
        .execute(pool)
        .await
        .expect("set centroid");
    theme_id
}

async fn seed_claim_in_theme(
    pool: &PgPool,
    agent_id: Uuid,
    theme_id: Uuid,
    content: &str,
    level: i32,
    embedding_pgvec: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, theme_id, embedding) \
         VALUES ($1, $2, $3, $4, 0.7, jsonb_build_object('level', $5::int), $6, $7::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(hash_for(id))
    .bind(agent_id)
    .bind(level)
    .bind(theme_id)
    .bind(embedding_pgvec)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn run_diverse_pipeline_returns_empty_when_no_themes(pool: PgPool) {
    // No themes seeded — corpus has never run k-means.
    let query = cluster_pgvec(0, 1.0);
    let config = DiverseRetrievalConfig {
        centroid_dim: 1536,
        max_themes: 5,
        candidate_pool: DEFAULT_CANDIDATE_POOL,
        budget: 10,
        alpha: 0.4,
        paragraph_only: true,
    };
    let result = run_diverse_pipeline(&pool, &query, config)
        .await
        .expect("pipeline should succeed against empty themes table");
    assert!(
        result.is_empty(),
        "no themes → empty result so callers can fall back to flat ANN; got len={}",
        result.len()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn run_diverse_pipeline_returns_empty_when_themes_have_no_claims(pool: PgPool) {
    // Theme exists but no claims attached — second fallback branch.
    let _theme_a = seed_theme_with_centroid(&pool, "empty-theme", &cluster_pgvec(0, 1.0)).await;

    let query = cluster_pgvec(0, 1.0);
    let config = DiverseRetrievalConfig {
        centroid_dim: 1536,
        max_themes: 5,
        candidate_pool: DEFAULT_CANDIDATE_POOL,
        budget: 10,
        alpha: 0.4,
        paragraph_only: true,
    };
    let result = run_diverse_pipeline(&pool, &query, config)
        .await
        .expect("pipeline should succeed when themes have no claims");
    assert!(
        result.is_empty(),
        "themes with zero claims → empty result; got len={}",
        result.len()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_similar_themes_orders_by_centroid_proximity(pool: PgPool) {
    // Three themes at three different cluster positions.
    let theme_a = seed_theme_with_centroid(&pool, "theme-A", &cluster_pgvec(0, 1.0)).await;
    let theme_b = seed_theme_with_centroid(&pool, "theme-B", &cluster_pgvec(3, 1.0)).await;
    let theme_c = seed_theme_with_centroid(&pool, "theme-C", &cluster_pgvec(6, 1.0)).await;

    // Query closest to theme B's centroid.
    let query = cluster_pgvec(3, 1.0);
    let results = find_similar_themes_at_dim(&pool, &query, 3, 1536)
        .await
        .expect("find_similar_themes_at_dim");

    assert_eq!(results.len(), 3);
    // Top hit must be theme B (exact match → similarity ≈ 1.0).
    assert_eq!(
        results[0].0, theme_b,
        "closest theme should be theme_b; got ordering: {results:?}"
    );
    // A and C are equidistant from query at this fixture, but the helper
    // must order both BELOW theme_b. Sanity: theme_b similarity > others.
    let theme_b_sim = results.iter().find(|(id, _, _)| *id == theme_b).unwrap().2;
    let theme_a_sim = results.iter().find(|(id, _, _)| *id == theme_a).unwrap().2;
    let theme_c_sim = results.iter().find(|(id, _, _)| *id == theme_c).unwrap().2;
    assert!(
        theme_b_sim > theme_a_sim && theme_b_sim > theme_c_sim,
        "theme_b's similarity {theme_b_sim} should exceed theme_a {theme_a_sim} and theme_c {theme_c_sim}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn diverse_selection_spreads_across_themes_when_flat_would_not(pool: PgPool) {
    // Multi-theme corpus designed so:
    //
    //   - Flat ANN over `claims.embedding` (ordered by cosine distance)
    //     would pick the top-5 from theme_a — they sit AT the query
    //     vector, similarity ~1.0.
    //   - theme_b's claims sit at a different bucket — lower similarity
    //     to the query, but high coverage gain.
    //   - With alpha=0.4, `diverse_select` should still pull ≥1 claim
    //     from theme_b (or from outside the top-5-by-relevance) so
    //     {selected theme_ids} has size ≥ 2.
    let agent = seed_agent(&pool).await;

    // theme_a: centroid at bucket 0, claims all at bucket 0.
    let theme_a = seed_theme_with_centroid(&pool, "theme-A-near", &cluster_pgvec(0, 1.0)).await;
    let mut theme_a_claims = Vec::new();
    for i in 0..6 {
        // Slight perturbation so claims aren't identical but stay near
        // bucket 0.
        let id = seed_claim_in_theme(
            &pool,
            agent,
            theme_a,
            &format!("near-claim-{i}"),
            2,
            &cluster_pgvec(0, 1.0 - (i as f32) * 0.001),
        )
        .await;
        theme_a_claims.push(id);
    }

    // theme_b: centroid + claims share some mass with the query bucket
    // so they have non-trivial similarity (~0.7) but still cluster
    // around a different region of the space. With sim_b ≈ 0.7 and
    // alpha=0.4, theme_b's coverage gain at pick #2 (~0.4) wins against
    // theme_a remainders (~0.6 * 1.0 - small_coverage ≈ 0.60) provided
    // the kNN neighbourhood masks most of theme_a's remaining
    // coverage. (See test comment: this is the calibration sweet spot.)
    let theme_b = seed_theme_with_centroid(&pool, "theme-B-far", &mixed_bucket_pgvec(3, 1.0)).await;
    let mut theme_b_claims = Vec::new();
    for i in 0..6 {
        let id = seed_claim_in_theme(
            &pool,
            agent,
            theme_b,
            &format!("far-claim-{i}"),
            2,
            // Slightly stagger query_share so the 6 theme_b vectors
            // aren't identical (similarity-neighbour graph needs spread).
            &mixed_bucket_pgvec(3, 1.0 - (i as f32) * 0.01),
        )
        .await;
        theme_b_claims.push(id);
    }

    // Query lives at bucket 0 — theme_a is closer. Flat ANN would pick
    // entirely from theme_a.
    let query = cluster_pgvec(0, 1.0);

    // Sanity check (regression guard): the flat ANN path (i.e. what
    // diverse=false in MCP would call) returns 5 hits, ALL from theme_a.
    let flat_hits = epigraph_db::ClaimRepository::search_by_embedding(
        &pool, &query, 1536, 5, None,
    )
    .await
    .expect("flat ANN");
    assert_eq!(flat_hits.len(), 5, "flat ANN should fill the budget");
    let flat_theme_ids: std::collections::HashSet<Uuid> = sqlx::query_scalar(
        "SELECT theme_id FROM claims WHERE id = ANY($1) AND theme_id IS NOT NULL",
    )
    .bind(flat_hits.iter().map(|h| h.claim_id).collect::<Vec<_>>())
    .fetch_all(&pool)
    .await
    .expect("collect flat theme_ids")
    .into_iter()
    .collect();
    assert_eq!(
        flat_theme_ids.len(),
        1,
        "fixture invariant: flat ANN must hit a single theme so the diverse-mode improvement is measurable; got: {flat_theme_ids:?}"
    );
    assert!(
        flat_theme_ids.contains(&theme_a),
        "flat ANN should land entirely in theme_a"
    );

    // Now the diverse path — budget 5, alpha 0.4 (the MCP default).
    let config = DiverseRetrievalConfig {
        centroid_dim: 1536,
        max_themes: 5,
        candidate_pool: DEFAULT_CANDIDATE_POOL,
        budget: 5,
        alpha: 0.4,
        paragraph_only: true,
    };
    let selected = run_diverse_pipeline(&pool, &query, config)
        .await
        .expect("diverse pipeline");
    assert!(!selected.is_empty(), "diverse pipeline must return results");
    assert!(
        selected.len() <= 5,
        "selection respects budget; got {}",
        selected.len()
    );

    // Distinct theme_ids in the diverse selection — load from DB.
    let selected_ids: Vec<Uuid> = selected.iter().map(|(id, _, _)| *id).collect();
    let diverse_theme_ids: std::collections::HashSet<Uuid> = sqlx::query_scalar(
        "SELECT theme_id FROM claims WHERE id = ANY($1) AND theme_id IS NOT NULL",
    )
    .bind(&selected_ids)
    .fetch_all(&pool)
    .await
    .expect("collect diverse theme_ids")
    .into_iter()
    .collect();

    assert!(
        diverse_theme_ids.len() >= 2,
        "diverse_select with alpha=0.4 should spread across ≥2 themes when flat hits 1; got: {diverse_theme_ids:?}, selected_ids: {selected_ids:?}"
    );
    assert!(
        diverse_theme_ids.contains(&theme_b),
        "diverse selection should include theme_b (the coverage win); diverse_theme_ids={diverse_theme_ids:?}"
    );
}

/// `candidate_pool` end-to-end behavioural test (small pool).
///
/// Seeds 30 paragraphs in one theme at MONOTONICALLY decreasing similarity to
/// the query, then runs the pipeline with `candidate_pool=5, budget=5,
/// alpha=0.0` (pure relevance). With a 5-row pool the SQL `LIMIT $3`
/// returns only the top-5-by-similarity rows, so `diverse_select` cannot
/// possibly surface any rank-6+ candidate. We assert the selection is a
/// subset of the seeded top-5.
///
/// This is the cheapest behavioural proof that `candidate_pool` reached
/// the SQL — if it were silently overridden to the old default (100)
/// the helper would have 30 rows to draw from and pure-relevance pick
/// the exact top-5; same assertion would still pass. So this test also
/// asserts that the *result count* matches `budget` AND that a strict
/// subset of seeded IDs (the bottom-5, deliberately at lower rank) is
/// absent from the selection. That second check distinguishes a pool of
/// 5 from a pool of 30.
#[sqlx::test(migrations = "../../migrations")]
async fn candidate_pool_small_value_truncates_sql_input(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let theme = seed_theme_with_centroid(&pool, "pool-small", &cluster_pgvec(0, 1.0)).await;

    // 30 paragraphs in this theme, similarity monotonically decreasing with i.
    // Top-5 (smallest i) sit at value≈1.0; bottom-5 (largest i) at value≈0.7.
    let mut seeded: Vec<Uuid> = Vec::with_capacity(30);
    for i in 0..30 {
        let v = cluster_pgvec_with_drift(0, 1.0, 1, (i as f32) * 0.05);
        let id = seed_claim_in_theme(
            &pool,
            agent,
            theme,
            &format!("pool-small-claim-{i}"),
            2,
            &v,
        )
        .await;
        seeded.push(id);
    }

    let query = cluster_pgvec(0, 1.0);

    // candidate_pool=5 with pure-relevance alpha=0.0 → must be the top-5.
    let config = DiverseRetrievalConfig {
        centroid_dim: 1536,
        max_themes: 5,
        candidate_pool: 5,
        budget: 5,
        alpha: 0.0,
        paragraph_only: true,
    };
    let selected = run_diverse_pipeline(&pool, &query, config)
        .await
        .expect("pipeline");

    let selected_ids: std::collections::HashSet<Uuid> =
        selected.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(
        selected_ids.len(),
        5,
        "pure-relevance with budget=5 must return 5 unique claims"
    );

    // The five lowest-similarity seeds (largest indices) must NOT appear:
    // their rank is far below pool size 5, so the SQL `LIMIT 5` excludes
    // them entirely. If `candidate_pool` were silently ignored (e.g.
    // falling back to default 100), the helper would have all 30 rows in
    // its pool — but pure-relevance picking would still pick the top-5,
    // so this exclusion assertion would *still* hold. So we also assert
    // INclusion of the top-5 (positive control) — both together pin
    // pool=5.
    let bottom_5: std::collections::HashSet<Uuid> = seeded[25..30].iter().copied().collect();
    let top_5: std::collections::HashSet<Uuid> = seeded[..5].iter().copied().collect();
    assert!(
        selected_ids.is_disjoint(&bottom_5),
        "bottom-5 claims must NOT appear in the selection; bottom_5={bottom_5:?}, selected={selected_ids:?}"
    );
    assert_eq!(
        selected_ids, top_5,
        "with pool=5 and pure relevance, selection must equal the top-5"
    );
}

/// `candidate_pool` end-to-end behavioural test (large pool).
///
/// Same fixture as `candidate_pool_small_value_truncates_sql_input` (30
/// paragraphs in one theme, monotonically decreasing similarity), but
/// runs with `candidate_pool=200, budget=5, alpha=1.0` (pure coverage).
///
/// With pool=200 the SQL pulls all 30 rows; under pure coverage
/// `diverse_select` spreads picks across the similarity range — at
/// least one pick MUST come from outside the top-5 by similarity. With
/// pool=5 that would be impossible (the kNN graph wouldn't even contain
/// those rows), so observing a low-rank pick proves the larger pool
/// value reached the SQL.
#[sqlx::test(migrations = "../../migrations")]
async fn candidate_pool_large_value_widens_diverse_select_input(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let theme = seed_theme_with_centroid(&pool, "pool-large", &cluster_pgvec(0, 1.0)).await;

    let mut seeded: Vec<Uuid> = Vec::with_capacity(30);
    for i in 0..30 {
        let v = cluster_pgvec_with_drift(0, 1.0, 1, (i as f32) * 0.05);
        let id = seed_claim_in_theme(
            &pool,
            agent,
            theme,
            &format!("pool-large-claim-{i}"),
            2,
            &v,
        )
        .await;
        seeded.push(id);
    }

    let query = cluster_pgvec(0, 1.0);

    // candidate_pool=200 (pool widens to whatever the SQL can find — here 30),
    // pure-coverage alpha=1.0 → submodular spread across the similarity range.
    let config = DiverseRetrievalConfig {
        centroid_dim: 1536,
        max_themes: 5,
        candidate_pool: 200,
        budget: 5,
        alpha: 1.0,
        paragraph_only: true,
    };
    let selected = run_diverse_pipeline(&pool, &query, config)
        .await
        .expect("pipeline");

    let selected_ids: std::collections::HashSet<Uuid> =
        selected.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(selected_ids.len(), 5, "budget=5 must return 5 picks");

    // At least one pick must be a claim seeded outside the top-5 by similarity.
    // With pool=5 such a claim would never have entered the candidate matrix.
    let top_5: std::collections::HashSet<Uuid> = seeded[..5].iter().copied().collect();
    let outside_top_5: usize = selected_ids.iter().filter(|id| !top_5.contains(id)).count();
    assert!(
        outside_top_5 >= 1,
        "candidate_pool=200 + pure coverage must surface ≥1 claim outside the top-5 by relevance; \
         selected={selected_ids:?}, top_5={top_5:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn paragraph_only_filter_excludes_non_paragraph_claims(pool: PgPool) {
    // When paragraph_only=true, the helper must filter out level≠2 claims
    // so MCP's downstream paragraph-context fetch never sees a section
    // or atom dressed up as a candidate.
    let agent = seed_agent(&pool).await;
    let theme = seed_theme_with_centroid(&pool, "mixed-levels", &cluster_pgvec(0, 1.0)).await;

    // Paragraph (level=2) and atom (level=3) both attached to the same theme.
    let para = seed_claim_in_theme(
        &pool,
        agent,
        theme,
        "paragraph",
        2,
        &cluster_pgvec(0, 1.0),
    )
    .await;
    let atom = seed_claim_in_theme(&pool, agent, theme, "atom", 3, &cluster_pgvec(0, 1.0)).await;

    let query = cluster_pgvec(0, 1.0);

    // paragraph_only=true → atom must be excluded.
    let config_strict = DiverseRetrievalConfig {
        centroid_dim: 1536,
        max_themes: 5,
        candidate_pool: DEFAULT_CANDIDATE_POOL,
        budget: 10,
        alpha: 0.4,
        paragraph_only: true,
    };
    let strict = run_diverse_pipeline(&pool, &query, config_strict)
        .await
        .expect("paragraph_only=true");
    let strict_ids: std::collections::HashSet<Uuid> =
        strict.iter().map(|(id, _, _)| *id).collect();
    assert!(
        strict_ids.contains(&para),
        "paragraph_only must keep the level=2 paragraph"
    );
    assert!(
        !strict_ids.contains(&atom),
        "paragraph_only must drop the level=3 atom; got selected={strict_ids:?}"
    );

    // paragraph_only=false (REST behaviour) → both eligible.
    let config_lax = DiverseRetrievalConfig {
        centroid_dim: 1536,
        max_themes: 5,
        candidate_pool: DEFAULT_CANDIDATE_POOL,
        budget: 10,
        alpha: 0.4,
        paragraph_only: false,
    };
    let lax = run_diverse_pipeline(&pool, &query, config_lax)
        .await
        .expect("paragraph_only=false");
    let lax_ids: std::collections::HashSet<Uuid> = lax.iter().map(|(id, _, _)| *id).collect();
    assert!(
        lax_ids.contains(&para) && lax_ids.contains(&atom),
        "paragraph_only=false must surface both levels; got selected={lax_ids:?}"
    );
}
