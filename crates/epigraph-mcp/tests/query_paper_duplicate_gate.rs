//! Regression test for backlog 7c6ce1b3-b372-4727-a510-43e63001bf18:
//! `query_paper(doi)` used the `paper -asserts-> claim` edge count alone as
//! its "has this DOI landed in the graph?" probe. Ingestion labels a claim
//! `doi:<doi>` *before* it links that edge (evidence + reasoning-trace writes
//! sit in between), so a crash mid-ingestion can leave claim nodes that carry
//! the label but no edge yet. The edge-only count reported `claim_count=0`
//! for such a paper, which is exactly the shape EpiClaw's nightly monitor
//! reads as "not yet ingested" — causing it to re-run extraction on an
//! already (partially) ingested paper.

use epigraph_core::{Agent, AgentId, Claim, TruthValue};
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_db::{AgentRepository, ClaimRepository, PaperRepository};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::paper_queries::query_paper;
use epigraph_mcp::types::QueryPaperParams;
use sqlx::PgPool;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .expect("query_paper result has text content")
        .text
        .clone();
    serde_json::from_str(&text).expect("query_paper result is valid JSON")
}

#[sqlx::test(migrations = "../../migrations")]
async fn query_paper_surfaces_labeled_claims_missing_asserts_edge(pool: PgPool) {
    let server = make_server(pool.clone());
    let doi = "10.48550/arXiv.2504.18085";

    // Simulate a crashed partial ingestion: the paper row and one claim exist,
    // the claim already carries the `doi:<doi>` label that
    // `do_ingest_document_spine` attaches immediately after creating the claim
    // row, but the `paper -asserts-> claim` edge — written later in the same
    // loop iteration — was never created.
    PaperRepository::get_or_create(&pool, doi, Some("Random-Set Large Language Models"), None)
        .await
        .expect("create paper");

    let agent = Agent::new([9u8; 32], Some("test-extractor".to_string()));
    let agent_row = AgentRepository::create(&pool, &agent)
        .await
        .expect("create agent");

    let content = "Random-Set Large Language Models introduces an epistemic decoding layer";
    let mut claim = Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_row.id.into()),
        [0u8; 32],
        TruthValue::new(0.7).unwrap(),
    );
    claim.content_hash = ContentHasher::hash(content.as_bytes());
    let persisted = ClaimRepository::create(&pool, &claim)
        .await
        .expect("create claim");
    let persisted_id: uuid::Uuid = persisted.id.into();
    ClaimRepository::update_labels(&pool, persisted_id, &[format!("doi:{doi}")], &[])
        .await
        .expect("label claim");

    // No `paper -asserts-> claim` edge is created for this claim — that is
    // the partial-ingestion state under test.

    let result = query_paper(
        &server,
        QueryPaperParams {
            doi: doi.to_string(),
        },
        None,
    )
    .await
    .expect("query_paper succeeds");

    let json = result_json(&result);
    assert_eq!(
        json["claim_count"].as_i64(),
        Some(1),
        "an orphaned doi-labeled claim must surface in claim_count even \
         without an asserts edge, or a duplicate-ingestion gate reading \
         claim_count reports this DOI as unstarted: {json}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn query_paper_reports_zero_for_unknown_doi(pool: PgPool) {
    let server = make_server(pool.clone());

    let result = query_paper(
        &server,
        QueryPaperParams {
            doi: "10.9999/never-ingested".to_string(),
        },
        None,
    )
    .await
    .expect("query_paper succeeds");

    let json = result_json(&result);
    assert_eq!(json["claim_count"].as_i64(), Some(0));
    assert_eq!(json["claims"].as_array().map(Vec::len), Some(0));
}
