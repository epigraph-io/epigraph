//! Integration tests for `ClaimRepository::search_by_embedding`.
//!
//! Schema notes (verified against `epigraph_db_repo_test`, migrations through 029):
//!   * `claims.agent_id` is NOT NULL and the canonical `validate_edge_reference`
//!     trigger requires the FK target to exist for any incoming edge — so
//!     fixtures must seed an `agents` row before inserting claims.
//!   * `claims.content_hash bytea NOT NULL` and `(content_hash, agent_id)` is
//!     UNIQUE; we generate distinct 32-byte hashes per claim to avoid
//!     collisions.
//!   * `edges.source_type` / `target_type` are NOT NULL with a CHECK against
//!     the entity-type allowlist; for paper→claim assertions we use
//!     `'paper'` / `'claim'`.
//!   * `'asserts'` is the relationship name expected by the
//!     `recall_with_context` design (spec §3.6); `relationship` is
//!     `varchar(100)` so the value is just a string literal.

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

fn build_query_vec() -> String {
    let mut v = vec!["0.0"; 1536];
    v[0] = "0.99";
    format!("[{}]", v.join(","))
}

/// Insert an `agents` row whose UUID we control so that downstream claims can
/// reference it. `public_key` is a deterministic 32-byte tag.
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

/// Build a 32-byte hash with the high byte set to `tag` so each claim gets a
/// distinct content_hash without depending on pgcrypto.
fn distinct_hash(tag: u8) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = tag;
    h
}

#[sqlx::test(migrations = "../../migrations")]
async fn search_by_embedding_returns_only_level_2(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    let p1 = Uuid::new_v4();
    let p2 = Uuid::new_v4();
    let a1 = Uuid::new_v4();

    let pgvec = build_query_vec();

    for (idx, (id, level)) in [(p1, 2), (p2, 2), (a1, 3)].iter().enumerate() {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
             VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', $5::int), $6::vector)",
        )
        .bind(id)
        .bind(format!("c-{id}"))
        .bind(distinct_hash(idx as u8 + 1))
        .bind(agent)
        .bind(level)
        .bind(&pgvec)
        .execute(&pool)
        .await
        .expect("insert claim");
    }

    let results = ClaimRepository::search_by_embedding(&pool, &pgvec, 1536, 5, None)
        .await
        .expect("search_by_embedding");

    let ids: Vec<Uuid> = results.iter().map(|r| r.claim_id).collect();
    assert!(ids.contains(&p1), "expected p1 (level=2) in results");
    assert!(ids.contains(&p2), "expected p2 (level=2) in results");
    assert!(!ids.contains(&a1), "atom (level=3) must be filtered out");
}

#[sqlx::test(migrations = "../../migrations")]
async fn search_by_embedding_filters_by_paper_doi(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    let paper_a = Uuid::new_v4();
    let paper_b = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO papers (id, doi, title) \
         VALUES ($1, '10.1/A', 'Paper A'), ($2, '10.2/B', 'Paper B')",
    )
    .bind(paper_a)
    .bind(paper_b)
    .execute(&pool)
    .await
    .expect("seed papers");

    let pa = Uuid::new_v4();
    let pb = Uuid::new_v4();
    let pgvec = build_query_vec();

    for (idx, (id, paper)) in [(pa, paper_a), (pb, paper_b)].iter().enumerate() {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
             VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', 2), $5::vector)",
        )
        .bind(id)
        .bind(format!("c-{id}"))
        .bind(distinct_hash(idx as u8 + 10))
        .bind(agent)
        .bind(&pgvec)
        .execute(&pool)
        .await
        .expect("insert claim");

        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
             VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
        )
        .bind(paper)
        .bind(id)
        .execute(&pool)
        .await
        .expect("insert asserts edge");
    }

    let results = ClaimRepository::search_by_embedding(&pool, &pgvec, 1536, 5, Some("10.1/A"))
        .await
        .expect("search_by_embedding with doi filter");

    let ids: Vec<Uuid> = results.iter().map(|r| r.claim_id).collect();
    assert!(ids.contains(&pa), "expected pa from paper A");
    assert!(!ids.contains(&pb), "pb from paper B must be filtered out");
}

#[sqlx::test(migrations = "../../migrations")]
async fn search_by_embedding_rejects_unsupported_dim(pool: PgPool) {
    let pgvec = build_query_vec();
    let result = ClaimRepository::search_by_embedding(&pool, &pgvec, 2048, 5, None).await;
    assert!(
        matches!(result, Err(epigraph_db::DbError::InvalidData { .. })),
        "expected InvalidData for unsupported dim, got {:?}",
        result
    );
}
