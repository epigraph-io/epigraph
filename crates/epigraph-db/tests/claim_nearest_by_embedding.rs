//! Regression for `ClaimRepository::nearest_by_embedding` — the ANN lookup
//! backing the write-side semantic novelty gate (backlog `1bcaed94`,
//! Task 6.4). `submit_claim`/`memorize` call this to find the nearest
//! `is_current` claims to a freshly-generated embedding BEFORE deciding
//! whether to insert.
//!
//! Uses `<=>` (cosine distance), matching the HNSW index
//! (`idx_claims_embedding_hnsw ... vector_cosine_ops`) and every other ANN
//! query in this repo (`search_by_embedding_scoped`, `search_hybrid_scoped`,
//! `pairwise_cosine_distance`). The backlog plan's literal SQL sketch uses
//! `<->` (L2), but L2 is neither index-accelerated here nor consistent with
//! the 0.05/0.15 thresholds, which are calibrated as cosine distances.

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// Build a pgvector literal that is all-zero except index 0, so cosine
/// distance between two vectors built this way is controllable via the
/// value placed at index 0..N.
fn unit_vec(nonzero_idx: usize, value: f32) -> String {
    let mut v = vec![0.0_f32; 1536];
    v[nonzero_idx] = value;
    format!(
        "[{}]",
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("bb".repeat(32))
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

async fn seed_claim_with_embedding(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    tag: u8,
    pgvec: &str,
    is_current: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, embedding, is_current) \
         VALUES ($1, $2, $3, $4, 0.5, $5::vector, $6)",
    )
    .bind(id)
    .bind(content)
    .bind(distinct_hash(tag))
    .bind(agent)
    .bind(pgvec)
    .bind(is_current)
    .execute(pool)
    .await
    .expect("seed claim with embedding");
    id
}

/// An exact-match vector (distance ~0) against an `is_current` claim must be
/// returned as the nearest hit, ordered before a more-distant claim.
#[sqlx::test(migrations = "../../migrations")]
async fn nearest_by_embedding_orders_closest_first(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    let close_vec = unit_vec(0, 1.0);
    let far_vec = unit_vec(1, 1.0); // orthogonal to close_vec => cosine distance 1.0

    let close_id =
        seed_claim_with_embedding(&pool, agent, "close claim", 1, &close_vec, true).await;
    let far_id = seed_claim_with_embedding(&pool, agent, "far claim", 2, &far_vec, true).await;

    let hits = ClaimRepository::nearest_by_embedding(&pool, &close_vec, 5)
        .await
        .expect("nearest_by_embedding");

    assert!(!hits.is_empty(), "expected at least one hit");
    assert_eq!(hits[0].claim_id, close_id, "closest vector must rank first");
    assert!(
        hits[0].distance < 0.01,
        "identical vector should have ~0 cosine distance, got {}",
        hits[0].distance
    );

    let far_hit = hits.iter().find(|h| h.claim_id == far_id);
    if let Some(far_hit) = far_hit {
        assert!(
            far_hit.distance > hits[0].distance,
            "orthogonal claim must be farther than the identical one"
        );
    }
}

/// `is_current = false` claims must never surface as ANN neighbors — the
/// gate would otherwise suppress inserts against claims that are no longer
/// live (e.g. already superseded).
///
/// Note: `chk_deprecated_no_embedding` (migration 052) already makes
/// `is_current = false AND embedding IS NOT NULL` impossible at the DB
/// level, so a stale claim is seeded WITHOUT an embedding (the only state
/// the schema allows) and this test pins that `nearest_by_embedding`'s own
/// `is_current` predicate is redundant-but-correct defense in depth, not
/// the only thing standing between stale claims and the gate.
#[sqlx::test(migrations = "../../migrations")]
async fn nearest_by_embedding_excludes_non_current(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let v = unit_vec(0, 1.0);

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, $2, $3, $4, 0.5, false)",
    )
    .bind(id)
    .bind("stale claim")
    .bind(distinct_hash(1))
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed stale claim");

    let hits = ClaimRepository::nearest_by_embedding(&pool, &v, 5)
        .await
        .expect("nearest_by_embedding");

    assert!(
        hits.is_empty(),
        "non-current claim must not be returned as an ANN neighbor, got {hits:?}"
    );
}

/// Claims with no embedding must never surface (would crash/garbage the
/// distance ordering, and semantically a NULL vector has no defined distance).
#[sqlx::test(migrations = "../../migrations")]
async fn nearest_by_embedding_excludes_null_embedding(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, $2, $3, $4, 0.5, true)",
    )
    .bind(id)
    .bind("no embedding claim")
    .bind(distinct_hash(9))
    .bind(agent)
    .execute(&pool)
    .await
    .expect("seed claim without embedding");

    let v = unit_vec(0, 1.0);
    let hits = ClaimRepository::nearest_by_embedding(&pool, &v, 5)
        .await
        .expect("nearest_by_embedding");

    assert!(
        hits.is_empty(),
        "claim with NULL embedding must not be returned, got {hits:?}"
    );
}

/// `limit` must be honored: with more `is_current` neighbors than `limit`,
/// only the closest `limit` are returned.
#[sqlx::test(migrations = "../../migrations")]
async fn nearest_by_embedding_respects_limit(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let query_vec = unit_vec(0, 1.0);

    for i in 0..7u8 {
        // Slightly perturb each vector's second component so all seven are
        // distinct-but-close neighbors of query_vec.
        let mut v = vec![0.0_f32; 1536];
        v[0] = 1.0;
        v[1] = f32::from(i) * 0.01;
        let pgvec = format!(
            "[{}]",
            v.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        seed_claim_with_embedding(&pool, agent, &format!("neighbor {i}"), i + 10, &pgvec, true)
            .await;
    }

    let hits = ClaimRepository::nearest_by_embedding(&pool, &query_vec, 3)
        .await
        .expect("nearest_by_embedding");

    assert_eq!(hits.len(), 3, "limit must cap the returned hit count");
}
