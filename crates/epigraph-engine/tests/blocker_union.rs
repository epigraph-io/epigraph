//! Integration test for union_block with source-filter.

use epigraph_engine::matching::blocker::{
    content_hash_prefix::ContentHashBlocker, embedding_ann::EmbeddingAnnBlocker, union_block,
    Blocker,
};
use epigraph_engine::matching::calibration::EligibilityConfig;
use epigraph_engine::matching::source_key::SourceFilterConfig;
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

async fn insert_claim_with_props_and_hash(
    pool: &PgPool,
    agent: Uuid,
    props: serde_json::Value,
    hash: &[u8; 32],
) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, properties)
         VALUES ($1, $2, $3, 0.5, $4, $5)",
    )
    .bind(id)
    .bind(&content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(props)
    .execute(pool)
    .await
    .expect("claim");
    id
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

/// Regression for the silent-no-op cross-source filter (promoted CORROBORATES
/// pair 530d00be): two claims asserted by the SAME paper via the relational
/// `paper -asserts-> claim` edge must be filtered out as same-source. On the
/// pre-fix code, `derive_source_key` read `properties->>'paper_doi'` (never
/// written), so both keys had `paper_doi = None`, `both_eq(None,None)=false`,
/// and the pair slipped through as cross-source — this test would fail.
///
/// Load-bearing design: the two claims share an IDENTICAL `content_hash` so
/// `ContentHashBlocker` EMITS the candidate (defeating the empty-candidate
/// tautology), but use DISTINCT agents so agent-blocking is not the cause and
/// the `(content_hash, agent_id)` UNIQUE constraint holds. The shared paper,
/// reachable only via the asserts edge, is the ONLY same-source signal present.
#[sqlx::test(migrations = "../../migrations")]
async fn same_paper_via_asserts_edge_is_filtered_out(pool: PgPool) {
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    let hash = [42u8; 32];
    // No paper_doi in properties, no derived_from edges: the ONLY provenance
    // link is the relational asserts edge to a shared paper.
    let seed = insert_claim_with_props_and_hash(&pool, a1, serde_json::json!({}), &hash).await;
    let peer = insert_claim_with_props_and_hash(&pool, a2, serde_json::json!({}), &hash).await;

    let paper_id = insert_paper(&pool, "10.1/regression").await;
    insert_asserts_edge(&pool, paper_id, seed).await;
    insert_asserts_edge(&pool, paper_id, peer).await;

    let blockers: Vec<Box<dyn Blocker>> = vec![
        Box::new(ContentHashBlocker),
        Box::new(EmbeddingAnnBlocker::new(10)),
    ];
    let pairs = union_block(
        &pool,
        &blockers,
        &[seed],
        SourceFilterConfig::default(),
        &EligibilityConfig::default(),
    )
    .await
    .expect("union_block");

    assert!(
        pairs.is_empty(),
        "same-paper pair resolved via asserts edge must be filtered out, got {:?}",
        pairs
    );
}

/// Positive control for the relational paper resolution: two claims asserted
/// by DIFFERENT papers (distinct DOIs), each via its own `asserts` edge, must
/// SURVIVE `union_block` as a genuine cross-source pair. This closes the loop
/// on `same_paper_via_asserts_edge_is_filtered_out` — that test proves the
/// filter FIRES on a shared paper, this one proves it DISCRIMINATES by DOI and
/// doesn't over-match (e.g. collapse any two paper-asserted claims to
/// same-source, or drop the `p.doi` predicate). Shares a `content_hash` so
/// `ContentHashBlocker` emits the candidate; distinct agents so agent-blocking
/// is not involved. The shared-vs-distinct paper is the ONLY difference from
/// the filtered-out case.
#[sqlx::test(migrations = "../../migrations")]
async fn different_papers_via_asserts_edges_survive_as_cross_source(pool: PgPool) {
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    let hash = [43u8; 32];
    let seed = insert_claim_with_props_and_hash(&pool, a1, serde_json::json!({}), &hash).await;
    let peer = insert_claim_with_props_and_hash(&pool, a2, serde_json::json!({}), &hash).await;

    // Two DISTINCT papers with different DOIs — a genuine cross-source pair.
    let paper_a = insert_paper(&pool, "10.1/cross-A").await;
    let paper_b = insert_paper(&pool, "10.1/cross-B").await;
    insert_asserts_edge(&pool, paper_a, seed).await;
    insert_asserts_edge(&pool, paper_b, peer).await;

    let blockers: Vec<Box<dyn Blocker>> = vec![Box::new(ContentHashBlocker)];
    let pairs = union_block(
        &pool,
        &blockers,
        &[seed],
        SourceFilterConfig::default(),
        &EligibilityConfig::default(),
    )
    .await
    .expect("union_block");

    assert_eq!(
        pairs.len(),
        1,
        "claims from DIFFERENT papers must survive as a cross-source pair, got {:?}",
        pairs
    );
}

async fn insert_claim_labeled(
    pool: &PgPool,
    agent: Uuid,
    props: serde_json::Value,
    hash: &[u8; 32],
    labels: &[&str],
) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    let labels: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, properties, labels)
         VALUES ($1, $2, $3, 0.5, $4, $5, $6)",
    )
    .bind(id)
    .bind(&content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(props)
    .bind(&labels)
    .execute(pool)
    .await
    .expect("claim");
    id
}

/// Candidate hygiene: a cross-source pair touching a `workflow_step` claim
/// (e.g. content "Body") must be dropped before scoring, while a substantive
/// cross-source pair survives. Both halves are load-bearing — the positive
/// control proves the filter discriminates rather than dropping everything.
#[sqlx::test(migrations = "../../migrations")]
async fn workflow_step_claims_are_excluded_by_hygiene(pool: PgPool) {
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    // No asserts edges are inserted, so post-fix both claims resolve
    // paper_doi = None and the source-key filter does NOT drop them (None does
    // not match None); the hygiene filter is the only thing that can. (The
    // props below are inert — properties->>'paper_doi' is no longer read.)
    let props_a = serde_json::json!({"paper_doi": "10.1/HYGI-A"});
    let props_b = serde_json::json!({"paper_doi": "10.1/HYGI-B"});
    let blockers: Vec<Box<dyn Blocker>> = vec![Box::new(ContentHashBlocker)];
    let elig = EligibilityConfig::default(); // exclude_labels = [workflow_step, telemetry]

    // Positive control: substantive cross-source pair (no excluded labels),
    // sharing a content_hash so ContentHashBlocker pairs them → survives.
    let sub_hash = [11u8; 32];
    let sub_seed = insert_claim_labeled(&pool, a1, props_a.clone(), &sub_hash, &[]).await;
    let _sub_peer = insert_claim_labeled(&pool, a2, props_b.clone(), &sub_hash, &[]).await;
    let pairs = union_block(
        &pool,
        &blockers,
        &[sub_seed],
        SourceFilterConfig::default(),
        &elig,
    )
    .await
    .expect("union_block");
    assert_eq!(
        pairs.len(),
        1,
        "substantive cross-source pair must survive hygiene, got {:?}",
        pairs
    );

    // The bug class: a `workflow_step` pair would also be generated, but must
    // be EXCLUDED by candidate hygiene.
    let ws_hash = [12u8; 32];
    let ws_seed = insert_claim_labeled(&pool, a1, props_a, &ws_hash, &["workflow_step"]).await;
    let _ws_peer = insert_claim_labeled(&pool, a2, props_b, &ws_hash, &["workflow_step"]).await;
    let ws_pairs = union_block(
        &pool,
        &blockers,
        &[ws_seed],
        SourceFilterConfig::default(),
        &elig,
    )
    .await
    .expect("union_block");
    assert!(
        ws_pairs.is_empty(),
        "workflow_step pair must be excluded by candidate hygiene, got {:?}",
        ws_pairs
    );
}
