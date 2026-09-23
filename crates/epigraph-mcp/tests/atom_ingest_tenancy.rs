//! Level-3 atoms converge across papers — but only onto rows the ingesting
//! viewer can read.
//!
//! An atom's id is `uuid_v5(ATOM_NAMESPACE, blake3(text))`, a GLOBAL id, so the
//! same sentence in two papers resolves to one claim; that is how cross-source
//! corroboration finds agreement. The document ingest wrote atoms through the
//! legacy `ClaimRepository::create`, which re-resolved by `content_hash` ALONE:
//! whichever row carried the text, in whatever tenant, came back. The ingest
//! then added its paper label to that row, `asserts`-linked it, and remapped
//! the paragraph's `decomposes_to` edge onto it — a cross-tenant write with no
//! ownership check.
//!
//! These arms seed the colliding row with its REAL BLAKE3 content hash (the
//! shared fixture seeders write a stand-in) so the legacy dedup could see it;
//! otherwise they would pass on the broken tree.
//!
//! Like `spine_node_identity_test.rs`, this file deliberately does NOT use
//! `tests/common`, which DROPs `uq_claims_content_hash_agent`: the constraint
//! stays in force here.
//!
//! Deferred-commitment screen key `legacy-claim-create-callers`
//! (s3a-followup #7).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::do_ingest_document;
use sqlx::PgPool;
use uuid::Uuid;

/// The atom sentence every arm collides on.
const ATOM: &str = "Actuator latency falls below one millisecond at 40 kelvin.";

fn make_server(pool: PgPool, signer: AgentSigner) -> EpiGraphMcpFull {
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn paper(title: &str, doi: &str) -> DocumentExtraction {
    let json = serde_json::json!({
        "source": {
            "title": title,
            "doi": doi,
            "source_type": "Paper",
            "authors": [{"name": "Ada Author", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("{title} reports a cryogenic actuator result."),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Results",
            "paragraphs": [{
                "text": format!("{title}: the measured latency is reported here."),
                "atoms": [ATOM],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        "relationships": []
    });
    serde_json::from_value(json).expect("fixture parses")
}

fn atom_id() -> Uuid {
    Uuid::new_v5(
        &epigraph_ingest::common::ids::ATOM_NAMESPACE,
        blake3::hash(ATOM.as_bytes()).as_bytes(),
    )
}

/// Insert a claim carrying [`ATOM`]'s text and REAL hash, at `id`, owned by
/// `group` with `visibility`.
async fn seed_atom_text_claim(pool: &PgPool, id: Uuid, agent: Uuid, group: Uuid, visibility: &str) {
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, $5, $6)",
    )
    .bind(id)
    .bind(ATOM)
    .bind(blake3::hash(ATOM.as_bytes()).as_bytes().as_slice())
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed atom-text claim");
}

async fn labels_of(pool: &PgPool, id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("labels")
}

async fn edges_touching(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM edges WHERE source_id = $1 OR target_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("edge count")
}

async fn asserting_papers(pool: &PgPool, claim_id: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT DISTINCT source_id FROM edges \
         WHERE target_id = $1 AND relationship = 'asserts' AND source_type = 'paper' \
         ORDER BY source_id",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .expect("asserts lookup")
}

async fn rows_with_atom_text(pool: &PgPool) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT id FROM claims WHERE content = $1 ORDER BY id")
        .bind(ATOM)
        .fetch_all(pool)
        .await
        .expect("rows")
}

/// Agent A holds the atom's text in a group-private claim under an unrelated
/// id. Ingesting a paper that asserts the sentence must give the atom its own
/// row, and must neither label nor link A's claim.
///
/// Pre-fix: the content-hash dedup returned A's row, so A's claim picked up the
/// paper's `doi:` label and the paper's `asserts` / `decomposes_to` edges.
#[sqlx::test(migrations = "../../migrations")]
async fn an_atom_matching_another_tenants_private_text_gets_its_own_row(pool: PgPool) {
    let (other_agent, other_group) = fixture::seed_agent_with_group(&pool, "atom-other").await;
    let theirs = Uuid::new_v4();
    seed_atom_text_claim(&pool, theirs, other_agent, other_group, "group").await;

    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone(), AgentSigner::generate());
    do_ingest_document(
        &server,
        &viewer,
        &paper("Cryo Alpha", "10.9999/atom-tenancy-a"),
    )
    .await
    .expect("ingest succeeds: the collision is by text, not by atom id");

    assert!(
        labels_of(&pool, theirs).await.is_empty(),
        "the other tenant's private claim must not be labelled by this ingest"
    );
    assert_eq!(
        edges_touching(&pool, theirs).await,
        0,
        "no edge may be written to or from the other tenant's private claim"
    );

    let rows = rows_with_atom_text(&pool).await;
    assert!(
        rows.contains(&atom_id()),
        "the atom must be written at its own content-addressed id, got {rows:?}"
    );
    assert_eq!(
        asserting_papers(&pool, atom_id()).await.len(),
        1,
        "the paper asserts its OWN atom row"
    );
}

/// Agent A's group-private claim holds the atom's GLOBAL id itself (A ingested
/// the sentence and its row was later made private). The id is taken by a row
/// this viewer cannot read, so the ingest must FAIL CLOSED rather than
/// converge onto it.
///
/// Pre-fix (measured): the ingest succeeded with `claims_skipped_dedup: 0` —
/// A's row came back at the planner's own id with no `trace_id`, so it was
/// treated as NEW, and the ingest wrote its label, edges, evidence, reasoning
/// trace and properties onto A's private claim.
#[sqlx::test(migrations = "../../migrations")]
async fn an_atom_id_held_by_an_unreadable_claim_fails_the_ingest_closed(pool: PgPool) {
    let (other_agent, other_group) = fixture::seed_agent_with_group(&pool, "atom-owner").await;
    seed_atom_text_claim(&pool, atom_id(), other_agent, other_group, "group").await;

    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone(), AgentSigner::generate());
    let err = do_ingest_document(
        &server,
        &viewer,
        &paper("Cryo Beta", "10.9999/atom-tenancy-b"),
    )
    .await
    .expect_err("converging onto an unreadable claim must be refused");
    assert!(
        err.message.contains("cannot read"),
        "the refusal must say why, got: {err:?}"
    );

    assert!(
        labels_of(&pool, atom_id()).await.is_empty(),
        "the unreadable claim must not be labelled"
    );
    assert_eq!(
        edges_touching(&pool, atom_id()).await,
        0,
        "no edge may be written to or from the unreadable claim"
    );
}

/// The fix must keep cross-AGENT convergence where the row IS readable: two
/// different ingesting agents asserting the same sentence share one public atom.
/// (`spine_node_identity_test.rs` covers the same-agent case, which step 1 of
/// `persist_atom` answers; this one reaches the id-conflict re-read.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_readable_atom_still_converges_across_ingesting_agents(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let first = make_server(pool.clone(), AgentSigner::generate());
    let second = make_server(pool.clone(), AgentSigner::generate());

    do_ingest_document(
        &first,
        &viewer,
        &paper("Cryo Gamma", "10.9999/atom-tenancy-g"),
    )
    .await
    .expect("first agent ingests");
    do_ingest_document(
        &second,
        &viewer,
        &paper("Cryo Delta", "10.9999/atom-tenancy-d"),
    )
    .await
    .expect("second agent converges");

    assert_eq!(
        rows_with_atom_text(&pool).await,
        vec![atom_id()],
        "one atom row for one sentence"
    );
    assert_eq!(
        asserting_papers(&pool, atom_id()).await.len(),
        2,
        "both papers assert the converged atom"
    );
}

/// The ingesting agent ALREADY holds the sentence under another id (e.g. from
/// `submit_claim`). That row is the noun-claim `(content_hash, agent_id)` match
/// and is reused; a second row for the same author and text would violate
/// `uq_claims_content_hash_agent` where it exists and duplicate where it does
/// not.
#[sqlx::test(migrations = "../../migrations")]
async fn the_authors_own_row_with_the_atom_text_is_reused(pool: PgPool) {
    let signer = AgentSigner::generate();
    let agent = epigraph_core::Agent::new(signer.public_key(), Some("atom-own-author".to_string()));
    let agent_id: Uuid = epigraph_db::AgentRepository::create(&pool, &agent)
        .await
        .expect("author agent")
        .id
        .into();
    let group = epigraph_db::ClaimRepository::personal_group_of_pool(&pool, agent_id)
        .await
        .expect("author's personal group");
    let own = Uuid::new_v4();
    seed_atom_text_claim(&pool, own, agent_id, group, "public").await;

    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone(), signer);
    do_ingest_document(
        &server,
        &viewer,
        &paper("Cryo Epsilon", "10.9999/atom-tenancy-e"),
    )
    .await
    .expect("ingest reuses the author's row");

    assert_eq!(
        rows_with_atom_text(&pool).await,
        vec![own],
        "the author's existing row is the atom; no second row"
    );
    assert_eq!(asserting_papers(&pool, own).await.len(), 1);
}
