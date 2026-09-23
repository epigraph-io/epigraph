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

// --- derivation-lineage same-source filtering ---
//
// Every test below pairs its two claims of interest through a shared
// `content_hash` (so `ContentHashBlocker` EMITS the candidate, defeating the
// empty-candidate tautology) and gives them DISTINCT agents (so agent-blocking
// is not the cause, and the `(content_hash, agent_id)` UNIQUE holds). No
// `asserts` edges are inserted, so `paper_doi` is `None` on both sides and the
// derivation edges are the ONLY same-source signal present.

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

/// An `evidence` row owned by `owner` (both `claim_id` and `evidence_type` are
/// NOT NULL).
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

async fn content_hash_pairs(pool: &PgPool, seed: Uuid) -> Vec<(Uuid, Uuid)> {
    let blockers: Vec<Box<dyn Blocker>> = vec![Box::new(ContentHashBlocker)];
    union_block(
        pool,
        &blockers,
        &[seed],
        SourceFilterConfig::default(),
        &EligibilityConfig::default(),
    )
    .await
    .expect("union_block")
}

/// A claim and the claim it was derived from are the same source.
///
/// On the pre-fix walk the PARENT's `derivation_root` was `None` (a claim with
/// no outgoing `derived_from` edge returned `None` at depth 0) while the
/// child's was `Some(parent)`, so `both_eq(None, Some(_))` was false and the
/// pair leaked as cross-source. Only siblings under a common root were caught.
#[sqlx::test(migrations = "../../migrations")]
async fn parent_and_child_in_one_derivation_chain_are_filtered_out(pool: PgPool) {
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    let hash = [51u8; 32];
    let parent = insert_claim_with_props_and_hash(&pool, a1, serde_json::json!({}), &hash).await;
    let child = insert_claim_with_props_and_hash(&pool, a2, serde_json::json!({}), &hash).await;
    insert_edge(&pool, child, "claim", parent, "claim", "derived_from").await;

    let pairs = content_hash_pairs(&pool, child).await;
    assert!(
        pairs.is_empty(),
        "a claim and its own derivation parent must be filtered out as same-source, got {pairs:?}"
    );
}

/// Two paraphrases of the same source atom are the same source.
///
/// Migration 011 documents 36,791 claim-to-claim `DERIVED_FROM` (UPPERCASE)
/// edges written by `paraphrase_full_sweep.py`, pointing paraphrase -> source
/// atom. The pre-fix walk compared `relationship = 'derived_from'`
/// case-sensitively, so it never followed one of them and every paraphrase
/// pair of a shared atom leaked as cross-source.
#[sqlx::test(migrations = "../../migrations")]
async fn paraphrase_siblings_under_uppercase_derived_from_are_filtered_out(pool: PgPool) {
    let a0 = insert_agent(&pool).await;
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    let atom =
        insert_claim_with_props_and_hash(&pool, a0, serde_json::json!({}), &[60u8; 32]).await;
    let hash = [61u8; 32];
    let p1 = insert_claim_with_props_and_hash(&pool, a1, serde_json::json!({}), &hash).await;
    let p2 = insert_claim_with_props_and_hash(&pool, a2, serde_json::json!({}), &hash).await;
    insert_edge(&pool, p1, "claim", atom, "claim", "DERIVED_FROM").await;
    insert_edge(&pool, p2, "claim", atom, "claim", "DERIVED_FROM").await;

    let pairs = content_hash_pairs(&pool, p1).await;
    assert!(
        pairs.is_empty(),
        "two paraphrases of one atom (uppercase DERIVED_FROM) must be filtered out, got {pairs:?}"
    );
}

/// A claim derived from TWO parents is the same source as a sibling that
/// shares only the second parent.
///
/// The pre-fix walk followed `LIMIT 1` parent per hop, so a multi-parent claim
/// resolved to whichever parent the plan returned first and the other parent's
/// descendants leaked. The parents are ordered so `first` is returned first by
/// every plan the old query could take (heap order, TID order within an
/// `idx_edges_source` key, or `target_id` order via `idx_edges_source_target`),
/// which makes the pre-fix failure deterministic rather than a coin flip.
#[sqlx::test(migrations = "../../migrations")]
async fn sibling_through_a_second_parent_is_filtered_out(pool: PgPool) {
    let a0 = insert_agent(&pool).await;
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    let x = insert_claim_with_props_and_hash(&pool, a0, serde_json::json!({}), &[70u8; 32]).await;
    let y = insert_claim_with_props_and_hash(&pool, a0, serde_json::json!({}), &[71u8; 32]).await;
    let (first, second) = if x < y { (x, y) } else { (y, x) };

    let hash = [72u8; 32];
    let multi = insert_claim_with_props_and_hash(&pool, a1, serde_json::json!({}), &hash).await;
    let sibling = insert_claim_with_props_and_hash(&pool, a2, serde_json::json!({}), &hash).await;
    insert_edge(&pool, multi, "claim", first, "claim", "derived_from").await;
    insert_edge(&pool, multi, "claim", second, "claim", "derived_from").await;
    insert_edge(&pool, sibling, "claim", second, "claim", "derived_from").await;

    let pairs = content_hash_pairs(&pool, multi).await;
    assert!(
        pairs.is_empty(),
        "claims sharing ANY derivation ancestor must be filtered out, got {pairs:?}"
    );
}

/// Positive control for the three tests above: two claims in UNRELATED
/// derivation chains survive as a genuine cross-source pair. Proves the
/// derivation filter discriminates by shared lineage rather than firing on any
/// claim that has a derivation edge at all.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_in_unrelated_derivation_chains_survive_as_cross_source(pool: PgPool) {
    let a0 = insert_agent(&pool).await;
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    let root_x =
        insert_claim_with_props_and_hash(&pool, a0, serde_json::json!({}), &[90u8; 32]).await;
    let root_y =
        insert_claim_with_props_and_hash(&pool, a0, serde_json::json!({}), &[91u8; 32]).await;
    let hash = [92u8; 32];
    let x = insert_claim_with_props_and_hash(&pool, a1, serde_json::json!({}), &hash).await;
    let y = insert_claim_with_props_and_hash(&pool, a2, serde_json::json!({}), &hash).await;
    insert_edge(&pool, x, "claim", root_x, "claim", "derived_from").await;
    insert_edge(&pool, y, "claim", root_y, "claim", "DERIVED_FROM").await;

    let pairs = content_hash_pairs(&pool, x).await;
    assert_eq!(
        pairs.len(),
        1,
        "claims in unrelated derivation chains must survive as cross-source, got {pairs:?}"
    );
}

/// Claim-to-EVIDENCE `derived_from` edges are not derivation lineage.
///
/// Two shapes are covered, both pointing two otherwise-unrelated claims at the
/// same evidence row:
///
/// * lowercase `derived_from` claim -> evidence, the shape
///   `ClaimRepository::inherit_evidence` writes. That function has no callers
///   today, so this half guards LEGACY rows already in the table. The pre-fix
///   walk had no `target_type` filter, stepped onto the evidence id, and
///   reported it as both claims' `derivation_root` — this test fails there.
/// * UPPERCASE `DERIVED_FROM` claim -> evidence, the shape every MCP
///   `submit_claim` / HTTP `create_claim` / crud write emits. The pre-fix walk
///   never matched it (case-sensitive literal), so this half guards the fix
///   itself: case-folding the relationship WITHOUT the `target_type = 'claim'`
///   filter would walk onto evidence ids.
///
/// Evidence inheritance copies SUPPORT links; it does not derive one claim's
/// content from another's, so it is not a derivation-lineage signal.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_sharing_inherited_evidence_survive_as_cross_source(pool: PgPool) {
    let a0 = insert_agent(&pool).await;
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    let owner =
        insert_claim_with_props_and_hash(&pool, a0, serde_json::json!({}), &[80u8; 32]).await;
    let ev_lower = insert_evidence(&pool, owner).await;
    let ev_upper = insert_evidence(&pool, owner).await;

    let hash = [81u8; 32];
    let a = insert_claim_with_props_and_hash(&pool, a1, serde_json::json!({}), &hash).await;
    let b = insert_claim_with_props_and_hash(&pool, a2, serde_json::json!({}), &hash).await;
    for claim in [a, b] {
        insert_edge(&pool, claim, "claim", ev_lower, "evidence", "derived_from").await;
        insert_edge(&pool, claim, "claim", ev_upper, "evidence", "DERIVED_FROM").await;
    }

    let pairs = content_hash_pairs(&pool, a).await;
    assert_eq!(
        pairs.len(),
        1,
        "claims sharing only an evidence row must survive as cross-source, got {pairs:?}"
    );
}
