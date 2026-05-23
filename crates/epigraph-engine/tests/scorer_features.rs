//! Integration tests for the scorer module (Tasks 11 + 12).
//!
//! Each test is independent: all seed data uses `Uuid::new_v4()` for isolation.

use epigraph_engine::matching::scorer::{score_pair, Weights};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.expect("test DB migrations failed — likely a description/version mismatch with existing _sqlx_migrations; use a fresh DB");
    Some(pool)
}

macro_rules! test_pool_or_skip {
    () => {
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set");
                return;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("insert agent");
    id
}

/// Insert a plain claim (no embedding, no properties).
async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

/// Insert a claim with a fixed 1536-dimensional unit embedding (all 0.1).
/// The vector literal is passed as text and cast with `::vector` in SQL.
async fn insert_claim_with_embedding(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    let vec_literal = format!("[{}]", vec!["0.1"; 1536].join(","));
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, embedding)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, $4::vector)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .bind(vec_literal)
    .execute(pool)
    .await
    .expect("insert claim with embedding");
    id
}

/// Insert a claim with a JSONB property `method_id`.
async fn insert_claim_with_method(pool: &PgPool, agent: Uuid, method_id: &str) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    let props = serde_json::json!({"method_id": method_id});
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, properties)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, $4)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .bind(props)
    .execute(pool)
    .await
    .expect("insert claim with method");
    id
}

async fn insert_entity(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO entities (id, canonical_name, type_top)
         VALUES ($1, $2, 'Concept')",
    )
    .bind(id)
    .bind(format!("entity-{}", id))
    .execute(pool)
    .await
    .expect("insert entity");
    id
}

async fn insert_triple(pool: &PgPool, claim_id: Uuid, subject_id: Uuid, predicate: &str) {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO triples (id, claim_id, subject_id, predicate, object_literal, confidence, extractor)
         VALUES ($1, $2, $3, $4, 'lit', 0.9, 'test')",
    )
    .bind(id)
    .bind(claim_id)
    .bind(subject_id)
    .bind(predicate)
    .execute(pool)
    .await
    .expect("insert triple");
}

async fn insert_cluster_row(pool: &PgPool, claim_id: Uuid, cluster_id: i32, run_id: Uuid) {
    // Public schema has NOT NULL on centroid_distance / second_centroid_dist /
    // boundary_ratio / silhouette_score; fill with sentinel zeros (the test
    // doesn't read these — only cluster_id matters for nbhd_overlap).
    sqlx::query(
        "INSERT INTO claim_clusters (claim_id, cluster_id, cluster_run_id,
                                     centroid_distance, second_centroid_dist,
                                     boundary_ratio, silhouette_score)
         VALUES ($1, $2, $3, 0.0, 0.0, 0.0, 0.0)",
    )
    .bind(claim_id)
    .bind(cluster_id)
    .bind(run_id)
    .execute(pool)
    .await
    .expect("insert claim_clusters");
}

/// Insert a `cites` edge from `source_id` to `target_id`.
async fn insert_cites_edge(pool: &PgPool, source_id: Uuid, target_id: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, target_id, source_type, target_type, relationship)
         VALUES (gen_random_uuid(), $1, $2, 'claim', 'claim', 'cites')",
    )
    .bind(source_id)
    .bind(target_id)
    .execute(pool)
    .await
    .expect("insert cites edge");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Two claims with identical embeddings → embed_cosine ≈ 1.0.
#[sqlx::test(migrations = "../../migrations")]
async fn embed_cosine_identical_vectors(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim_with_embedding(&pool, agent).await;
    let b = insert_claim_with_embedding(&pool, agent).await;

    let features = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert!(
        features.embed_cosine > 0.99,
        "expected embed_cosine > 0.99, got {}",
        features.embed_cosine
    );
}

/// Two claims sharing all (subject_id, predicate) triples → triple_overlap ≈ 1.0.
#[sqlx::test(migrations = "../../migrations")]
async fn triple_overlap_full_match(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;

    let subj = insert_entity(&pool).await;
    insert_triple(&pool, a, subj, "has_property").await;
    insert_triple(&pool, b, subj, "has_property").await;

    let features = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert!(
        features.triple_overlap > 0.99,
        "expected triple_overlap > 0.99, got {}",
        features.triple_overlap
    );
}

/// Both claims have the same non-null method_id → method_match == true.
#[sqlx::test(migrations = "../../migrations")]
async fn method_match_true_when_equal(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim_with_method(&pool, agent, "rct-parallel").await;
    let b = insert_claim_with_method(&pool, agent, "rct-parallel").await;

    let features = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert!(features.method_match, "expected method_match = true");
}

/// Both claims in the same cluster → nbhd_overlap ≈ 1.0.
#[sqlx::test(migrations = "../../migrations")]
async fn nbhd_overlap_same_cluster(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;

    let run_id = Uuid::new_v4();
    insert_cluster_row(&pool, a, 7, run_id).await;
    insert_cluster_row(&pool, b, 7, run_id).await;

    let features = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert!(
        features.nbhd_overlap > 0.99,
        "expected nbhd_overlap > 0.99, got {}",
        features.nbhd_overlap
    );
}

/// Both claims cite the same third claim → citation_overlap > 0.0.
#[sqlx::test(migrations = "../../migrations")]
async fn citation_overlap_one_shared(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let cited = insert_claim(&pool, agent).await;

    insert_cites_edge(&pool, a, cited).await;
    insert_cites_edge(&pool, b, cited).await;

    let features = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert!(
        features.citation_overlap > 0.0,
        "expected citation_overlap > 0.0, got {}",
        features.citation_overlap
    );
}

/// Two claims share a non-self graph neighbor → graph_overlap > 0.0
/// (Adamic-Adar over any claim↔claim edge, not just `cites`).
#[sqlx::test(migrations = "../../migrations")]
async fn graph_overlap_via_shared_neighbor(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let shared = insert_claim(&pool, agent).await;
    // Use an arbitrary non-`cites` relationship to verify AA isn't just
    // citation_overlap — `supports` is also a real claim-claim edge.
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', 'supports')",
    )
    .bind(a)
    .bind(shared)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', 'supports')",
    )
    .bind(b)
    .bind(shared)
    .execute(&pool)
    .await
    .unwrap();

    let features = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert!(
        features.graph_overlap > 0.0,
        "expected graph_overlap > 0.0 for two claims sharing a neighbor, got {}",
        features.graph_overlap
    );
    // tanh-normalized: a single shared neighbor of degree 2 contributes
    // ~1/ln(2)≈1.44 raw, tanh(1.44)≈0.89.
    assert!(
        features.graph_overlap < 1.0,
        "graph_overlap should be < 1.0 (tanh-bounded), got {}",
        features.graph_overlap
    );
}

/// Two claims with no shared neighbors → graph_overlap == 0.0 (sanity check
/// that AA doesn't false-positive on disjoint neighborhoods).
#[sqlx::test(migrations = "../../migrations")]
async fn graph_overlap_zero_when_neighborhoods_disjoint(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let only_a = insert_claim(&pool, agent).await;
    let only_b = insert_claim(&pool, agent).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', 'supports'),
                ($3, 'claim', $4, 'claim', 'supports')",
    )
    .bind(a)
    .bind(only_a)
    .bind(b)
    .bind(only_b)
    .execute(&pool)
    .await
    .unwrap();

    let features = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");
    assert_eq!(
        features.graph_overlap, 0.0,
        "expected graph_overlap = 0.0 with disjoint neighborhoods, got {}",
        features.graph_overlap
    );
}

/// Both claims have aligned beliefs (both ~supported) →
/// belief_alignment > 0.9. Mismatched beliefs (one supported, one not) →
/// belief_alignment near 0.
#[sqlx::test(migrations = "../../migrations")]
async fn belief_alignment_reflects_betp_distance(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let c = insert_claim(&pool, agent).await;

    // sqlx::test runs migrations into a fresh DB without the seed frame
    // rows that production deploys carry. Insert the binary frame
    // explicitly so the mass_functions FK is satisfied.
    let frame_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses)
         VALUES ('binary', ARRAY['supported', 'unsupported'])
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("insert binary frame");

    // a, b: both strongly supported. m({0}) = 0.8, m({0,1}) = 0.2 → BetP = 0.9.
    for &claim in &[a, b] {
        sqlx::query(
            "INSERT INTO mass_functions (claim_id, frame_id, masses)
             VALUES ($1, $2, '{\"0\": 0.8, \"0,1\": 0.2}')",
        )
        .bind(claim)
        .bind(frame_id)
        .execute(&pool)
        .await
        .unwrap();
    }
    // c: strongly unsupported. m({1}) = 0.8, m({0,1}) = 0.2 → BetP = 0.1.
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, masses)
         VALUES ($1, $2, '{\"1\": 0.8, \"0,1\": 0.2}')",
    )
    .bind(c)
    .bind(frame_id)
    .execute(&pool)
    .await
    .unwrap();

    let aligned = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score a,b");
    let opposed = score_pair(&pool, a, c, &Weights::default())
        .await
        .expect("score a,c");

    assert!(
        aligned.belief_alignment > 0.9,
        "expected aligned beliefs to score > 0.9, got {}",
        aligned.belief_alignment
    );
    assert!(
        opposed.belief_alignment < 0.1,
        "expected opposed beliefs to score < 0.1, got {}",
        opposed.belief_alignment
    );
}

/// No mass function on either claim → belief_alignment = 0.5 (genuinely
/// neutral: doesn't lift the score, doesn't depress it).
#[sqlx::test(migrations = "../../migrations")]
async fn belief_alignment_neutral_when_no_mass_function(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let features = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");
    assert!(
        (features.belief_alignment - 0.5).abs() < 1e-6,
        "expected belief_alignment = 0.5 (neutral) with no mass functions, got {}",
        features.belief_alignment
    );
}

/// Claims matching across all features → score in (0.55, 1.0].
#[sqlx::test(migrations = "../../migrations")]
async fn combined_score_in_unit_interval(pool: PgPool) {
    let agent = insert_agent(&pool).await;

    // Identical embeddings
    let a = insert_claim_with_embedding(&pool, agent).await;
    let b = insert_claim_with_embedding(&pool, agent).await;

    // Force method_id onto both claims
    sqlx::query("UPDATE claims SET properties = $1 WHERE id = $2")
        .bind(serde_json::json!({"method_id": "rct-v1"}))
        .bind(a)
        .execute(&pool)
        .await
        .expect("update a props");
    sqlx::query("UPDATE claims SET properties = $1 WHERE id = $2")
        .bind(serde_json::json!({"method_id": "rct-v1"}))
        .bind(b)
        .execute(&pool)
        .await
        .expect("update b props");

    // Shared triple
    let subj = insert_entity(&pool).await;
    insert_triple(&pool, a, subj, "is_related_to").await;
    insert_triple(&pool, b, subj, "is_related_to").await;

    // Same cluster
    let run_id = Uuid::new_v4();
    insert_cluster_row(&pool, a, 99, run_id).await;
    insert_cluster_row(&pool, b, 99, run_id).await;

    // Shared citation
    let cited = insert_claim(&pool, agent).await;
    insert_cites_edge(&pool, a, cited).await;
    insert_cites_edge(&pool, b, cited).await;

    let features = score_pair(&pool, a, b, &Weights::default())
        .await
        .expect("score_pair");

    assert!(
        features.score > 0.55,
        "expected score > 0.55, got {}",
        features.score
    );
    assert!(
        features.score <= 1.0,
        "expected score <= 1.0, got {}",
        features.score
    );
}
