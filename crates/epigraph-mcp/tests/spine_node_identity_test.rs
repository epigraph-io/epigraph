//! Spine-node identity: structural (compound) claims are DOCUMENT-SCOPED.
//!
//! `epigraph_ingest::common::ids` states the contract verbatim: compound nodes
//! (thesis L0, section L1, paragraph L2) are seeded with the host artifact so
//! they "do NOT converge across artifacts even when their text matches", while
//! atoms (L3) use a global namespace and converge by design.
//!
//! The document write path used to discard that: it handed the planner's id to
//! `ClaimRepository::create`, which re-resolves by `content_hash` alone, so the
//! second paper with a section titled "Introduction" was remapped onto the
//! first paper's node. Every planned structural edge was then remapped through
//! that id, fusing unrelated papers' spines into one subgraph.
//!
//! These tests assert on persisted rows and edges, never on the returned
//! counters, and deliberately do NOT use `tests/common` — that helper DROPs
//! `uq_claims_content_hash_agent`, and keeping the constraint in force is part
//! of what is under test (all structural claims are written by one server
//! agent, so two rows with the same `content_hash` would violate it).

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{do_ingest_document, do_ingest_document_spine};
use sqlx::PgPool;
use uuid::Uuid;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

/// Text shared by an atom in BOTH papers. Level 3 → must converge to one node.
const SHARED_ATOM: &str = "Widget throughput scales linearly with actuator count.";

/// Boilerplate paragraph (level 2) with byte-identical text in both papers.
const SHARED_PARAGRAPH: &str = "This work was supported by an institutional grant.";

/// Section heading (level 1) shared by both papers — the fusion vector.
const SHARED_SECTION: &str = "Introduction";

/// Two DIFFERENT documents (different titles → different artifact seeds) that
/// share a section heading, a boilerplate paragraph, and one atom sentence.
fn paper(title: &str, doi: &str, intro_text: &str) -> DocumentExtraction {
    let json = serde_json::json!({
        "source": {
            "title": title,
            "doi": doi,
            "source_type": "Paper",
            "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("{title} advances the state of the art."),
        "thesis_derivation": "TopDown",
        "sections": [
            {
                "title": SHARED_SECTION,
                "paragraphs": [
                    {
                        "text": intro_text,
                        "atoms": [SHARED_ATOM],
                        "generality": [1],
                        "confidence": 0.9
                    }
                ]
            },
            {
                "title": "Acknowledgements",
                "paragraphs": [
                    {
                        "text": SHARED_PARAGRAPH,
                        "atoms": [],
                        "generality": [],
                        "confidence": 0.8
                    }
                ]
            }
        ],
        "relationships": []
    });
    serde_json::from_value(json).expect("fixture parses")
}

fn alpha() -> DocumentExtraction {
    paper(
        "Alpha Study of Widget Actuation",
        "10.9999/spine-identity-alpha",
        "The alpha study opens by framing actuator scaling.",
    )
}

fn beta() -> DocumentExtraction {
    paper(
        "Beta Study of Gadget Actuation",
        "10.9999/spine-identity-beta",
        "The beta study opens by framing a different question.",
    )
}

async fn claims_with_content(pool: &PgPool, content: &str) -> Vec<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM claims WHERE content = $1 ORDER BY id")
        .bind(content)
        .fetch_all(pool)
        .await
        .expect("claim lookup")
}

/// Papers that `asserts` the given claim id.
async fn asserting_papers(pool: &PgPool, claim_id: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT DISTINCT source_id FROM edges \
         WHERE target_id = $1 AND relationship = 'asserts' AND source_type = 'paper' \
         ORDER BY source_id",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .expect("asserts lookup")
}

/// THE BUG. Two distinct documents sharing a section heading (level 1) and a
/// boilerplate paragraph (level 2) must each get their OWN structural node.
///
/// Pre-fix this fails with `1` row for "Introduction" — the second paper's
/// planned id is discarded by `ClaimRepository::create`'s content-hash resolve
/// and both papers `asserts` the single fused node.
#[sqlx::test(migrations = "../../migrations")]
async fn two_documents_sharing_a_section_heading_get_distinct_spine_nodes(pool: PgPool) {
    let server = make_server(pool.clone());

    do_ingest_document(&server, &alpha())
        .await
        .expect("alpha ingests");
    do_ingest_document(&server, &beta())
        .await
        .expect("beta ingests");

    // Level 1: the shared section heading.
    let section_nodes = claims_with_content(&pool, SHARED_SECTION).await;
    assert_eq!(
        section_nodes.len(),
        2,
        "two papers with a section titled {SHARED_SECTION:?} must own two \
         distinct section nodes, got {section_nodes:?}"
    );

    // Each node belongs to exactly one paper, and the two papers differ.
    let owners_a = asserting_papers(&pool, section_nodes[0]).await;
    let owners_b = asserting_papers(&pool, section_nodes[1]).await;
    assert_eq!(
        owners_a.len(),
        1,
        "section node {} must be asserted by exactly one paper, got {owners_a:?}",
        section_nodes[0]
    );
    assert_eq!(
        owners_b.len(),
        1,
        "section node {} must be asserted by exactly one paper, got {owners_b:?}",
        section_nodes[1]
    );
    assert_ne!(
        owners_a[0], owners_b[0],
        "the two section nodes must belong to different papers"
    );

    // Level 2: byte-identical boilerplate paragraph is also document-scoped.
    let para_nodes = claims_with_content(&pool, SHARED_PARAGRAPH).await;
    assert_eq!(
        para_nodes.len(),
        2,
        "an identically-worded paragraph in two papers must not fuse, got {para_nodes:?}"
    );
}

/// The fix must not over-correct: level-3 atoms converge across papers by
/// design (that is how cross-source corroboration works).
#[sqlx::test(migrations = "../../migrations")]
async fn shared_atom_text_still_converges_to_a_single_node(pool: PgPool) {
    let server = make_server(pool.clone());

    do_ingest_document(&server, &alpha())
        .await
        .expect("alpha ingests");
    do_ingest_document(&server, &beta())
        .await
        .expect("beta ingests");

    let atom_nodes = claims_with_content(&pool, SHARED_ATOM).await;
    assert_eq!(
        atom_nodes.len(),
        1,
        "identical atom text must converge to ONE claim, got {atom_nodes:?}"
    );

    // ...and that single atom is asserted by both papers.
    let owners = asserting_papers(&pool, atom_nodes[0]).await;
    assert_eq!(
        owners.len(),
        2,
        "the converged atom must be asserted by both papers, got {owners:?}"
    );

    // The atom's id is the global content-addressed one, unchanged by the fix.
    let expected = uuid::Uuid::new_v5(
        &epigraph_ingest::common::ids::ATOM_NAMESPACE,
        blake3::hash(SHARED_ATOM.as_bytes()).as_bytes(),
    );
    assert_eq!(
        atom_nodes[0], expected,
        "atom id must stay uuid_v5(ATOM_NAMESPACE, blake3(text))"
    );
}

/// Idempotency: re-ingesting the SAME document must reuse its structural nodes,
/// not mint a second set. The compound id is a pure function of
/// (artifact seed, content), so the second run collides on `id` and
/// `create_with_id_if_absent`'s `ON CONFLICT (id) DO NOTHING` short-circuits.
#[sqlx::test(migrations = "../../migrations")]
async fn reingesting_the_same_document_reuses_its_spine_nodes(pool: PgPool) {
    let server = make_server(pool.clone());

    do_ingest_document(&server, &alpha())
        .await
        .expect("first ingest");
    let count_after_first: i64 = sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(&pool)
        .await
        .expect("count");
    let section_first = claims_with_content(&pool, SHARED_SECTION).await;

    do_ingest_document(&server, &alpha())
        .await
        .expect("second ingest");
    let count_after_second: i64 = sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(&pool)
        .await
        .expect("count");
    let section_second = claims_with_content(&pool, SHARED_SECTION).await;

    assert_eq!(
        count_after_first, count_after_second,
        "re-ingesting an identical document must not create any new claim rows"
    );
    assert_eq!(
        section_first, section_second,
        "the section node must keep the same id across re-ingestion"
    );
    assert_eq!(
        section_first.len(),
        1,
        "exactly one section node for one paper"
    );
}

/// The spine tool (phase 1 of the two-phase flow) writes levels 0–2 through the
/// same code shape and must be fixed in lockstep.
#[sqlx::test(migrations = "../../migrations")]
async fn spine_path_also_scopes_structural_nodes_per_document(pool: PgPool) {
    let server = make_server(pool.clone());

    do_ingest_document_spine(&server, &alpha())
        .await
        .expect("alpha spine ingests");
    do_ingest_document_spine(&server, &beta())
        .await
        .expect("beta spine ingests");

    let section_nodes = claims_with_content(&pool, SHARED_SECTION).await;
    assert_eq!(
        section_nodes.len(),
        2,
        "ingest_document_spine must also give each paper its own section node, \
         got {section_nodes:?}"
    );

    let owners_a = asserting_papers(&pool, section_nodes[0]).await;
    let owners_b = asserting_papers(&pool, section_nodes[1]).await;
    assert_eq!(owners_a.len(), 1, "one owner per spine section node");
    assert_eq!(owners_b.len(), 1, "one owner per spine section node");
    assert_ne!(owners_a[0], owners_b[0], "different papers own them");

    // Spine mode skips atoms entirely.
    assert!(
        claims_with_content(&pool, SHARED_ATOM).await.is_empty(),
        "spine phase must not write level-3 atoms"
    );
}

/// The same document-scoping contract, asserted in the LOOKUP dimension.
///
/// Distinct `content_hash` values keep the two "Introduction" nodes distinct as
/// ROWS. `claims.canonical_hash` (migration 061) is a second, lookup-only
/// digest that `ClaimRepository::create_or_get` consults when the exact hash
/// misses — and deriving it from the node's text alone would hand both papers
/// one key, re-fusing them exactly where the namespacing was meant to keep them
/// apart, and letting an ordinary claim submission land on a spine node.
///
/// So a document-scoped node must carry NO canonical_hash. Asserted here
/// against the REAL ids module rather than a reconstruction of it, because the
/// property depends on `compound_content_hash` genuinely differing from the
/// plain digest — the write path's eligibility check is exactly that
/// comparison.
#[sqlx::test(migrations = "../../migrations")]
async fn spine_nodes_carry_no_canonical_hash(pool: PgPool) {
    let server = make_server(pool.clone());

    do_ingest_document(&server, &alpha())
        .await
        .expect("alpha ingests");
    do_ingest_document(&server, &beta())
        .await
        .expect("beta ingests");

    let section_nodes = claims_with_content(&pool, SHARED_SECTION).await;
    assert_eq!(
        section_nodes.len(),
        2,
        "fixture: both papers must own a section node, got {section_nodes:?}"
    );

    let rows: Vec<(Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT content_hash, canonical_hash FROM claims WHERE id = ANY($1) ORDER BY id",
    )
    .bind(&section_nodes)
    .fetch_all(&pool)
    .await
    .expect("read digests");

    let plain = blake3::hash(SHARED_SECTION.as_bytes()).as_bytes().to_vec();
    for (content_hash, canonical_hash) in &rows {
        assert_ne!(
            content_hash, &plain,
            "fixture: a spine node's content_hash must be NAMESPACED, not the \
             plain digest of its text (see ids::compound_content_hash)"
        );
        assert_eq!(
            canonical_hash, &None,
            "a document-scoped spine node must not carry a canonical_hash — a \
             digest of {SHARED_SECTION:?} alone is a lookup key both papers \
             would share"
        );
    }

    // The consequence: an ordinary claim whose text happens to match a section
    // heading must get its own row, not one of the papers' spine nodes.
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent)
        .bind([9u8; 32].as_slice())
        .execute(&pool)
        .await
        .expect("seed agent");

    let mut conn = pool.acquire().await.expect("acquire");
    let claim = epigraph_core::Claim::new(
        SHARED_SECTION.to_string(),
        epigraph_core::AgentId::from_uuid(agent),
        [0u8; 32],
        epigraph_core::TruthValue::new(0.5).expect("truth"),
    );
    let (found, created) = epigraph_db::ClaimRepository::create_or_get(&mut conn, &claim)
        .await
        .expect("create_or_get");
    assert!(
        created,
        "a plain claim must not be resolved onto a document-scoped spine node \
         — it resolved onto {}",
        Uuid::from(found.id)
    );
    assert!(!section_nodes.contains(&Uuid::from(found.id)));
}
