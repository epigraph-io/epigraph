//! Integration test for union_block with source-filter.

use epigraph_engine::matching::blocker::{canonical, CandidatePair};
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

/// R-12 (backlog c618e4fc): two NON-paper claims (no `paper -asserts->` edge on
/// either side, no run id, no derivation chain) written by the SAME agent are
/// same-source and must be dropped by `union_block` under the default config.
/// Before the fix, `is_same_source` had no usable component for such a pair,
/// so a same-agent restatement passed as a cross-source candidate.
///
/// Shape: same-agent DUPLICATE content (a shared `content_hash`), emitted by
/// the real `ContentHashBlocker`. Migration 150 dropped the
/// `(content_hash, agent_id)` UNIQUE constraint, so two rows by one agent with
/// one hash are legal and exist in long-lived databases.
///
/// Positive control in the same run: an otherwise identical shared-hash
/// non-paper pair by two DIFFERENT agents survives, so an empty result cannot
/// come from the blocker emitting nothing or the filter dropping everything.
#[sqlx::test(migrations = "../../migrations")]
async fn non_paper_same_agent_pair_is_filtered_out(pool: PgPool) {
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    let same_hash = [51u8; 32];
    let cross_hash = [53u8; 32];
    let same_l =
        insert_claim_with_props_and_hash(&pool, a1, serde_json::json!({}), &same_hash).await;
    let same_r =
        insert_claim_with_props_and_hash(&pool, a1, serde_json::json!({}), &same_hash).await;
    let cross_l =
        insert_claim_with_props_and_hash(&pool, a1, serde_json::json!({}), &cross_hash).await;
    let cross_r =
        insert_claim_with_props_and_hash(&pool, a2, serde_json::json!({}), &cross_hash).await;
    let cross = canonical(cross_l, cross_r).unwrap();

    // Both pairs are emitted by the blocker; only the source filter can tell
    // them apart.
    let emitted = ContentHashBlocker
        .candidates(&pool, &[same_l, cross_l])
        .await
        .expect("content-hash candidates");
    assert_eq!(
        emitted.len(),
        2,
        "ContentHashBlocker must emit both shared-hash pairs, got {:?}",
        emitted
    );
    assert!(emitted.contains(&canonical(same_l, same_r).unwrap()));

    let blockers: Vec<Box<dyn Blocker>> = vec![Box::new(ContentHashBlocker)];
    let pairs = union_block(
        &pool,
        &blockers,
        &[same_l, cross_l],
        SourceFilterConfig::default(),
        &EligibilityConfig::default(),
    )
    .await
    .expect("union_block");

    assert_eq!(
        pairs,
        vec![cross],
        "same-agent non-paper pair must be dropped and the different-agent \
         non-paper pair kept; got {:?}",
        pairs
    );
}

/// R-12 keeps today's rule for paper claims: two claims by the SAME agent with
/// the same content, each asserted by a DIFFERENT paper, survive `union_block`
/// as cross-source under the default config (same agent alone is not enough
/// for paper claims). Emitted by the real `ContentHashBlocker`.
#[sqlx::test(migrations = "../../migrations")]
async fn paper_claims_same_agent_different_papers_survive(pool: PgPool) {
    let a = insert_agent(&pool).await;
    let hash = [61u8; 32];
    let l = insert_claim_with_props_and_hash(&pool, a, serde_json::json!({}), &hash).await;
    let r = insert_claim_with_props_and_hash(&pool, a, serde_json::json!({}), &hash).await;
    let paper_a = insert_paper(&pool, "10.1/r12-A").await;
    let paper_b = insert_paper(&pool, "10.1/r12-B").await;
    insert_asserts_edge(&pool, paper_a, l).await;
    insert_asserts_edge(&pool, paper_b, r).await;
    let pair = canonical(l, r).unwrap();

    let blockers: Vec<Box<dyn Blocker>> = vec![Box::new(ContentHashBlocker)];
    let pairs = union_block(
        &pool,
        &blockers,
        &[l],
        SourceFilterConfig::default(),
        &EligibilityConfig::default(),
    )
    .await
    .expect("union_block");

    assert_eq!(
        pairs,
        vec![pair],
        "same-agent claims from different papers must stay cross-source, got {:?}",
        pairs
    );
}

/// `parent -decomposes_to-> atom`, the edge `decompose_claims` writes
/// (`epigraph-cli` `persist_decomposition`). The atom itself gets NO
/// `paper -asserts->` edge and inherits the parent's `agent_id`.
async fn insert_decomposes_edge(pool: &PgPool, parent: Uuid, atom: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(parent)
    .bind(atom)
    .execute(pool)
    .await
    .expect("insert decomposes_to edge");
}

/// Test blocker that emits exactly the pairs it was built with. Two atoms of
/// DIFFERENT papers by one agent have different text: identical atom text by
/// one agent collapses to a single row on the canonical create path
/// (`if_not_exists` under the `(content_hash, agent_id)` advisory lock), so in
/// production such a pair comes from the embedding blocker, which needs stored
/// embeddings this test does not have. Candidate generation is all this
/// replaces; key derivation and the filter run for real on the rows below.
struct FixedPairs(Vec<CandidatePair>);

#[async_trait::async_trait]
impl Blocker for FixedPairs {
    async fn candidates(
        &self,
        _pool: &PgPool,
        _seeds: &[Uuid],
    ) -> Result<Vec<CandidatePair>, sqlx::Error> {
        Ok(self.0.clone())
    }
}

/// R-12 "paper claims keep today's rule" covers atoms that `decompose_claims`
/// splits out of paper-asserted compounds. Shape of its output: each atom has
/// the parent's `agent_id`, a `parent -decomposes_to-> atom` edge, and no
/// `asserts` edge of its own. Two such atoms from DIFFERENT papers, ingested
/// by the SAME agent, are a cross-paper corroboration and must survive. If the
/// atoms resolved no paper, they would look like same-agent non-paper claims
/// and be dropped.
#[sqlx::test(migrations = "../../migrations")]
async fn decompose_atoms_of_different_papers_by_one_agent_survive(pool: PgPool) {
    let a = insert_agent(&pool).await;
    let parent_a =
        insert_claim_with_props_and_hash(&pool, a, serde_json::json!({}), &[71u8; 32]).await;
    let parent_b =
        insert_claim_with_props_and_hash(&pool, a, serde_json::json!({}), &[72u8; 32]).await;
    let paper_a = insert_paper(&pool, "10.1/atoms-A").await;
    let paper_b = insert_paper(&pool, "10.1/atoms-B").await;
    insert_asserts_edge(&pool, paper_a, parent_a).await;
    insert_asserts_edge(&pool, paper_b, parent_b).await;

    let atom_a =
        insert_claim_with_props_and_hash(&pool, a, serde_json::json!({}), &[73u8; 32]).await;
    let atom_b =
        insert_claim_with_props_and_hash(&pool, a, serde_json::json!({}), &[74u8; 32]).await;
    insert_decomposes_edge(&pool, parent_a, atom_a).await;
    insert_decomposes_edge(&pool, parent_b, atom_b).await;
    let pair = canonical(atom_a, atom_b).unwrap();

    let blockers: Vec<Box<dyn Blocker>> = vec![Box::new(FixedPairs(vec![pair]))];
    let pairs = union_block(
        &pool,
        &blockers,
        &[atom_a],
        SourceFilterConfig::default(),
        &EligibilityConfig::default(),
    )
    .await
    .expect("union_block");

    assert_eq!(
        pairs,
        vec![pair],
        "atoms of different papers by one agent must stay cross-source, got {:?}",
        pairs
    );
}

/// The other half of the paper rule for atoms: two atoms of the SAME paper are
/// same-source, even when their parents were written by DIFFERENT agents (so
/// the agent rule cannot be what drops them). One atom hangs two
/// `decomposes_to` levels below the asserted compound, so the paper is
/// resolved through the whole decomposition chain, not just one hop.
///
/// Positive control in the same run: an identically shaped pair whose
/// parents are asserted by DIFFERENT papers survives, so the drop comes from
/// the shared DOI and not from the filter dropping every atom pair. Both pairs
/// share a content_hash and are emitted by the real `ContentHashBlocker`.
#[sqlx::test(migrations = "../../migrations")]
async fn decompose_atoms_of_one_paper_are_filtered_out(pool: PgPool) {
    let a1 = insert_agent(&pool).await;
    let a2 = insert_agent(&pool).await;
    let json = || serde_json::json!({});

    // Same paper P: parent1 (a1) and parent2 (a2) both asserted by P;
    // parent2 -> mid -> atom2 (depth 2), parent1 -> atom1 (depth 1).
    let paper_p = insert_paper(&pool, "10.1/atoms-P").await;
    let parent1 = insert_claim_with_props_and_hash(&pool, a1, json(), &[81u8; 32]).await;
    let parent2 = insert_claim_with_props_and_hash(&pool, a2, json(), &[82u8; 32]).await;
    insert_asserts_edge(&pool, paper_p, parent1).await;
    insert_asserts_edge(&pool, paper_p, parent2).await;
    let mid = insert_claim_with_props_and_hash(&pool, a2, json(), &[83u8; 32]).await;
    insert_decomposes_edge(&pool, parent2, mid).await;
    let same_hash = [84u8; 32];
    let atom1 = insert_claim_with_props_and_hash(&pool, a1, json(), &same_hash).await;
    let atom2 = insert_claim_with_props_and_hash(&pool, a2, json(), &same_hash).await;
    insert_decomposes_edge(&pool, parent1, atom1).await;
    insert_decomposes_edge(&pool, mid, atom2).await;

    // Control: same shape, parents asserted by two DIFFERENT papers.
    let paper_x = insert_paper(&pool, "10.1/atoms-X").await;
    let paper_y = insert_paper(&pool, "10.1/atoms-Y").await;
    let parent_x = insert_claim_with_props_and_hash(&pool, a1, json(), &[85u8; 32]).await;
    let parent_y = insert_claim_with_props_and_hash(&pool, a2, json(), &[86u8; 32]).await;
    insert_asserts_edge(&pool, paper_x, parent_x).await;
    insert_asserts_edge(&pool, paper_y, parent_y).await;
    let cross_hash = [87u8; 32];
    let atom_x = insert_claim_with_props_and_hash(&pool, a1, json(), &cross_hash).await;
    let atom_y = insert_claim_with_props_and_hash(&pool, a2, json(), &cross_hash).await;
    insert_decomposes_edge(&pool, parent_x, atom_x).await;
    insert_decomposes_edge(&pool, parent_y, atom_y).await;
    let cross = canonical(atom_x, atom_y).unwrap();

    let emitted = ContentHashBlocker
        .candidates(&pool, &[atom1, atom_x])
        .await
        .expect("content-hash candidates");
    assert!(
        emitted.contains(&canonical(atom1, atom2).unwrap()) && emitted.contains(&cross),
        "ContentHashBlocker must emit both atom pairs, got {:?}",
        emitted
    );

    let blockers: Vec<Box<dyn Blocker>> = vec![Box::new(ContentHashBlocker)];
    let pairs = union_block(
        &pool,
        &blockers,
        &[atom1, atom_x],
        SourceFilterConfig::default(),
        &EligibilityConfig::default(),
    )
    .await
    .expect("union_block");

    assert_eq!(
        pairs,
        vec![cross],
        "same-paper atoms must be dropped and different-paper atoms kept; got {:?}",
        pairs
    );
}
