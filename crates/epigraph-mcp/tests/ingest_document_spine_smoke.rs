//! Smoke tests for `do_ingest_document_spine` — the phase-1 tool of the
//! two-phase ingest flow.
//!
//! The key invariants being verified:
//! 1. Fresh spine returns all paragraphs in `new_paragraph_paths`, in document order.
//! 2. Spine after an abstract-only ingest: shared paragraphs land in `paragraphs_deduped`,
//!    new body paragraphs in `new_paragraph_paths`.
//! 3. Full re-spine of an already-ingested document: `already_ingested: true`, zero new paths.

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::do_ingest_document_spine;
use sqlx::PgPool;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

/// Two-section paper, 3 paragraphs total, no atoms (spine mode).
const SPINE_FIXTURE: &str = r#"{
  "source": {
    "title": "Spine Smoke Test Paper",
    "doi": "10.1234/spine-smoke",
    "source_type": "Paper",
    "authors": [
      {"name": "Alice Author", "affiliations": [], "roles": ["author"]}
    ]
  },
  "thesis": "Spine ingest captures document structure without atoms",
  "thesis_derivation": "TopDown",
  "sections": [
    {
      "title": "Introduction",
      "paragraphs": [
        {"text": "Paragraph one of the introduction.", "atoms": [], "generality": [], "confidence": 0.9},
        {"text": "Paragraph two of the introduction.", "atoms": [], "generality": [], "confidence": 0.9}
      ]
    },
    {
      "title": "Methods",
      "paragraphs": [
        {"text": "The only paragraph in the methods section.", "atoms": [], "generality": [], "confidence": 0.8}
      ]
    }
  ],
  "relationships": []
}"#;

/// Abstract-only extraction: the first section (2 paragraphs) from SPINE_FIXTURE.
const ABSTRACT_FIXTURE: &str = r#"{
  "source": {
    "title": "Spine Smoke Test Paper",
    "doi": "10.1234/spine-smoke",
    "source_type": "Paper",
    "authors": [
      {"name": "Alice Author", "affiliations": [], "roles": ["author"]}
    ]
  },
  "thesis": "Spine ingest captures document structure without atoms",
  "thesis_derivation": "TopDown",
  "sections": [
    {
      "title": "Introduction",
      "paragraphs": [
        {"text": "Paragraph one of the introduction.", "atoms": [], "generality": [], "confidence": 0.9},
        {"text": "Paragraph two of the introduction.", "atoms": [], "generality": [], "confidence": 0.9}
      ]
    }
  ],
  "relationships": []
}"#;

fn result_text(result: &rmcp::model::CallToolResult) -> String {
    let content = result.content.first().expect("at least one content block");
    content.as_text().expect("text content").text.clone()
}

/// A fresh spine returns all paragraphs as new, in document order.
#[sqlx::test(migrations = "../../migrations")]
async fn spine_fresh_paper_returns_new_paragraph_paths(pool: PgPool) {
    let server = make_server(pool);
    let extraction: DocumentExtraction =
        serde_json::from_str(SPINE_FIXTURE).expect("fixture parses");

    let result = do_ingest_document_spine(&server, &extraction)
        .await
        .expect("spine ingest succeeds");

    let json: serde_json::Value =
        serde_json::from_str(&result_text(&result)).expect("response JSON");

    assert_eq!(json["already_ingested"], serde_json::json!(false));
    assert_eq!(
        json["paragraphs_new"].as_u64().unwrap(),
        3,
        "3 paragraphs across 2 sections are all new"
    );
    assert_eq!(json["paragraphs_deduped"].as_u64().unwrap(), 0);

    let paths = json["new_paragraph_paths"]
        .as_array()
        .expect("new_paragraph_paths is an array");
    assert_eq!(paths.len(), 3);
    // Document order: sections[0].paragraphs[0], [1], then sections[1].paragraphs[0].
    assert_eq!(paths[0], "sections[0].paragraphs[0]");
    assert_eq!(paths[1], "sections[0].paragraphs[1]");
    assert_eq!(paths[2], "sections[1].paragraphs[0]");
}

/// Abstract-first → full-paper: the shared abstract paragraphs are deduped and
/// the new body paragraphs appear in `new_paragraph_paths`.
#[sqlx::test(migrations = "../../migrations")]
async fn abstract_then_full_paper_abstract_paras_deduped(pool: PgPool) {
    let server = make_server(pool);
    let abstract_extraction: DocumentExtraction =
        serde_json::from_str(ABSTRACT_FIXTURE).expect("abstract fixture parses");
    let full_extraction: DocumentExtraction =
        serde_json::from_str(SPINE_FIXTURE).expect("full fixture parses");

    // Phase 1: ingest the abstract.
    let first = do_ingest_document_spine(&server, &abstract_extraction)
        .await
        .expect("abstract spine ingest succeeds");
    let first_json: serde_json::Value =
        serde_json::from_str(&result_text(&first)).expect("response JSON");
    assert_eq!(first_json["paragraphs_new"].as_u64().unwrap(), 2);
    assert_eq!(first_json["paragraphs_deduped"].as_u64().unwrap(), 0);

    // Phase 2: ingest the full paper — abstract paragraphs are deduped,
    // the Methods paragraph is genuinely new.
    let second = do_ingest_document_spine(&server, &full_extraction)
        .await
        .expect("full spine ingest succeeds");
    let json: serde_json::Value =
        serde_json::from_str(&result_text(&second)).expect("response JSON");

    assert_eq!(json["already_ingested"], serde_json::json!(false));
    assert_eq!(
        json["paragraphs_deduped"].as_u64().unwrap(),
        2,
        "both abstract paragraphs are already in the DB"
    );
    assert_eq!(
        json["paragraphs_new"].as_u64().unwrap(),
        1,
        "only the methods paragraph is new"
    );

    let paths = json["new_paragraph_paths"]
        .as_array()
        .expect("new_paragraph_paths is an array");
    assert_eq!(paths.len(), 1);
    assert_eq!(
        paths[0], "sections[1].paragraphs[0]",
        "the new paragraph is sections[1].paragraphs[0] in the full-paper extraction"
    );
}

/// Re-running spine on an already-fully-ingested paper returns `already_ingested: true`
/// with no new paragraph paths.
#[sqlx::test(migrations = "../../migrations")]
async fn full_reingest_returns_already_ingested(pool: PgPool) {
    let server = make_server(pool);
    let extraction: DocumentExtraction =
        serde_json::from_str(SPINE_FIXTURE).expect("fixture parses");

    let _first = do_ingest_document_spine(&server, &extraction)
        .await
        .expect("first spine ingest");
    let second = do_ingest_document_spine(&server, &extraction)
        .await
        .expect("second spine ingest");

    let json: serde_json::Value =
        serde_json::from_str(&result_text(&second)).expect("response JSON");

    assert_eq!(json["already_ingested"], serde_json::json!(true));
    assert_eq!(json["paragraphs_new"].as_u64().unwrap(), 0);
    assert_eq!(
        json["paragraphs_deduped"].as_u64().unwrap(),
        3,
        "all 3 paragraphs are already in the DB"
    );
    let paths = json["new_paragraph_paths"]
        .as_array()
        .expect("new_paragraph_paths is an array");
    assert!(paths.is_empty(), "no new paragraph paths on full re-ingest");
}
