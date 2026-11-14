//! Integration tests for `derive_source_key`.
//!
//! Requires a live PostgreSQL database reachable via `DATABASE_URL`.
//! Tests skip automatically when the database is unavailable.

use epigraph_engine::matching::source_key::derive_source_key;
use sqlx::PgPool;
use uuid::Uuid;

// --- seed helpers ---

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

async fn insert_claim_with_properties(
    pool: &PgPool,
    agent_id: Uuid,
    properties: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, properties)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, $4)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent_id)
    .bind(properties)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

async fn insert_claim(pool: &PgPool, agent_id: Uuid) -> Uuid {
    insert_claim_with_properties(pool, agent_id, serde_json::json!({})).await
}

async fn insert_paper(pool: &PgPool, doi: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(doi)
        .bind(format!("paper {}", id))
        .execute(pool)
        .await
        .expect("insert paper");
    id
}

async fn insert_asserts_edge(pool: &PgPool, paper_id: Uuid, claim_id: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper_id)
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("insert asserts edge");
}

async fn insert_derived_from(pool: &PgPool, child: Uuid, parent: Uuid) {
    // source_type and target_type are NOT NULL; both are 'claim' here.
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', 'derived_from')",
    )
    .bind(child)
    .bind(parent)
    .execute(pool)
    .await
    .expect("insert derived_from edge");
}

// --- tests ---

#[sqlx::test(migrations = "../../migrations")]
async fn derive_extracts_paper_doi_from_asserts_edge(pool: PgPool) {
    // Canonical paper provenance is relational: the DOI lives on the papers
    // row and is reached via a paper -asserts-> claim edge, NOT in
    // properties->>'paper_doi' (which no write path ever populates).
    let agent_id = insert_agent(&pool).await;
    let claim_id = insert_claim(&pool, agent_id).await;
    let paper_id = insert_paper(&pool, "10.1/regression").await;
    insert_asserts_edge(&pool, paper_id, claim_id).await;

    let key = derive_source_key(&pool, claim_id).await.expect("derive");
    assert_eq!(key.paper_dois, vec!["10.1/regression".to_string()]);
    assert_eq!(key.agent_id, agent_id);
    assert_eq!(key.derivation_root, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn derive_chases_derivation_root(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let root = insert_claim(&pool, agent_id).await;
    let mid = insert_claim(&pool, agent_id).await;
    let leaf = insert_claim(&pool, agent_id).await;
    insert_derived_from(&pool, mid, root).await;
    insert_derived_from(&pool, leaf, mid).await;
    let key = derive_source_key(&pool, leaf).await.expect("derive");
    assert_eq!(key.derivation_root, Some(root));
}

/// 50b19b4e: a claim asserted by TWO papers keeps both DOIs, so a claim that
/// shares only the second paper is still detected as same-source. The DOIs are
/// chosen so the non-shared one sorts first: the former
/// `ORDER BY depth, doi LIMIT 1` kept exactly that one and let the pair pass
/// the filter as cross-source.
#[sqlx::test(migrations = "../../migrations")]
async fn derive_keeps_every_asserting_paper_doi(pool: PgPool) {
    use epigraph_engine::matching::source_key::{is_same_source, SourceFilterConfig};

    let agent_a = insert_agent(&pool).await;
    let agent_b = insert_agent(&pool).await;
    let claim_a = insert_claim(&pool, agent_a).await;
    let claim_b = insert_claim(&pool, agent_b).await;
    let p_only_a = insert_paper(&pool, "10.1/only-a").await;
    let p_shared = insert_paper(&pool, "10.2/shared").await;
    insert_asserts_edge(&pool, p_only_a, claim_a).await;
    insert_asserts_edge(&pool, p_shared, claim_a).await;
    insert_asserts_edge(&pool, p_shared, claim_b).await;

    let ka = derive_source_key(&pool, claim_a).await.expect("derive a");
    let kb = derive_source_key(&pool, claim_b).await.expect("derive b");
    assert_eq!(
        ka.paper_dois,
        vec!["10.1/only-a".to_string(), "10.2/shared".to_string()],
        "every asserting paper, sorted"
    );
    assert_eq!(kb.paper_dois, vec!["10.2/shared".to_string()]);
    assert!(
        is_same_source(&ka, &kb, SourceFilterConfig::default()),
        "claims sharing paper 10.2/shared must be same-source, got {ka:?} vs {kb:?}"
    );
}
