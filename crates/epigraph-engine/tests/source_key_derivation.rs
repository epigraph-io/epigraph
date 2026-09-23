//! Integration tests for `derive_source_key`.
//!
//! Requires a live PostgreSQL database reachable via `DATABASE_URL`.
//! Tests skip automatically when the database is unavailable.

use std::collections::BTreeSet;

use epigraph_db::repos::derivation::MAX_DERIVATION_DEPTH;
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

async fn insert_edge(
    pool: &PgPool,
    source_id: Uuid,
    source_type: &str,
    target_id: Uuid,
    target_type: &str,
    relationship: &str,
) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(source_id)
    .bind(source_type)
    .bind(target_id)
    .bind(target_type)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("insert edge");
}

/// `child --derived_from--> parent`: the source is the DERIVED claim, the
/// target what it was derived from. That is the direction of the migration-011
/// paraphrase -> atom rows and of the privatization closure invariant; see
/// `epigraph_db::repos::derivation` for the full argument.
async fn insert_derived_from(pool: &PgPool, child: Uuid, parent: Uuid) {
    insert_edge(pool, child, "claim", parent, "claim", "derived_from").await;
}

/// An `evidence` row owned by `owner` (`claim_id` and `evidence_type` are NOT
/// NULL).
async fn insert_evidence(pool: &PgPool, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO evidence (id, raw_content, content_hash, evidence_type, claim_id)
         VALUES ($1, 'ev', $2, 'document', $3)",
    )
    .bind(id)
    .bind(&hash)
    .bind(owner)
    .execute(pool)
    .await
    .expect("insert evidence");
    id
}

fn set(ids: &[Uuid]) -> BTreeSet<Uuid> {
    ids.iter().copied().collect()
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
    assert_eq!(key.paper_doi.as_deref(), Some("10.1/regression"));
    assert_eq!(key.agent_id, agent_id);
    // No derivation edges: the lineage is the claim alone, so it can overlap
    // only with the claim's own descendants.
    assert_eq!(key.derivation_lineage, set(&[claim_id]));
}

#[sqlx::test(migrations = "../../migrations")]
async fn derive_collects_the_whole_derivation_chain(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let root = insert_claim(&pool, agent_id).await;
    let mid = insert_claim(&pool, agent_id).await;
    let leaf = insert_claim(&pool, agent_id).await;
    insert_derived_from(&pool, mid, root).await;
    insert_derived_from(&pool, leaf, mid).await;

    let key = derive_source_key(&pool, leaf).await.expect("derive");
    assert_eq!(key.derivation_lineage, set(&[leaf, mid, root]));
    // The root is its own lineage, so it overlaps with every descendant.
    let root_key = derive_source_key(&pool, root).await.expect("derive root");
    assert_eq!(root_key.derivation_lineage, set(&[root]));
}

/// Every spelling of the relationship is followed. Migration 011 documents
/// 36,791 claim-to-claim `DERIVED_FROM` (uppercase) rows, and `derives_from`
/// is the older spelling `export::prov` and `SemanticLinkType` still accept.
/// The pre-fix walk matched the literal `'derived_from'` only.
#[sqlx::test(migrations = "../../migrations")]
async fn derive_follows_every_spelling_of_derived_from(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let upper = insert_claim(&pool, agent_id).await;
    let legacy = insert_claim(&pool, agent_id).await;
    let grand = insert_claim(&pool, agent_id).await;
    let child = insert_claim(&pool, agent_id).await;
    insert_edge(&pool, child, "claim", upper, "claim", "DERIVED_FROM").await;
    insert_edge(&pool, child, "claim", legacy, "claim", "derives_from").await;
    insert_edge(&pool, upper, "claim", grand, "claim", "Derived_From").await;

    let key = derive_source_key(&pool, child).await.expect("derive");
    assert_eq!(key.derivation_lineage, set(&[child, upper, legacy, grand]));
}

/// Every parent is followed, not `LIMIT 1` of them.
#[sqlx::test(migrations = "../../migrations")]
async fn derive_collects_every_parent_of_a_multi_parent_claim(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let p1 = insert_claim(&pool, agent_id).await;
    let p2 = insert_claim(&pool, agent_id).await;
    let child = insert_claim(&pool, agent_id).await;
    insert_derived_from(&pool, child, p1).await;
    insert_derived_from(&pool, child, p2).await;

    let key = derive_source_key(&pool, child).await.expect("derive");
    assert_eq!(key.derivation_lineage, set(&[child, p1, p2]));
}

/// The walk never leaves the claim graph. Both claim -> evidence shapes are
/// present: UPPERCASE `DERIVED_FROM` (what every `submit_claim` /
/// `create_claim` / crud write emits — only safe to case-fold because of the
/// `target_type = 'claim'` restriction) and lowercase `derived_from` (what the
/// caller-less `ClaimRepository::inherit_evidence` left in legacy rows, and
/// what the pre-fix walk stepped onto as a "root").
#[sqlx::test(migrations = "../../migrations")]
async fn derive_never_walks_onto_evidence(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let parent = insert_claim(&pool, agent_id).await;
    let child = insert_claim(&pool, agent_id).await;
    let ev_upper = insert_evidence(&pool, child).await;
    let ev_lower = insert_evidence(&pool, parent).await;
    insert_edge(&pool, child, "claim", ev_upper, "evidence", "DERIVED_FROM").await;
    insert_edge(&pool, child, "claim", ev_lower, "evidence", "derived_from").await;
    insert_derived_from(&pool, child, parent).await;

    let key = derive_source_key(&pool, child).await.expect("derive");
    assert_eq!(key.derivation_lineage, set(&[child, parent]));
}

/// A derivation cycle terminates, and every claim on it is in the lineage.
#[sqlx::test(migrations = "../../migrations")]
async fn derive_terminates_on_a_derivation_cycle(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent_id).await;
    let b = insert_claim(&pool, agent_id).await;
    insert_derived_from(&pool, a, b).await;
    insert_derived_from(&pool, b, a).await;

    let key = derive_source_key(&pool, a).await.expect("derive");
    assert_eq!(key.derivation_lineage, set(&[a, b]));
}

/// The walk stops after `MAX_DERIVATION_DEPTH` hops: a chain one hop longer
/// than the cap leaves its far end out.
#[sqlx::test(migrations = "../../migrations")]
async fn derive_caps_the_walk_at_max_derivation_depth(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let hops = usize::try_from(MAX_DERIVATION_DEPTH).expect("positive cap");
    let mut chain = Vec::with_capacity(hops + 2);
    for _ in 0..hops + 2 {
        chain.push(insert_claim(&pool, agent_id).await);
    }
    for i in 1..chain.len() {
        insert_derived_from(&pool, chain[i], chain[i - 1]).await;
    }

    let leaf = *chain.last().expect("non-empty chain");
    let key = derive_source_key(&pool, leaf).await.expect("derive");
    assert_eq!(key.derivation_lineage, set(&chain[1..]));
    assert!(!key.derivation_lineage.contains(&chain[0]));
}
