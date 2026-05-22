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
