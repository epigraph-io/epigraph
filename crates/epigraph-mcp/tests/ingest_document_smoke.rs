//! End-to-end smoke test for the hierarchical `ingest_document` tool.
//!
//! Drives a tiny synthetic `DocumentExtraction` through `do_ingest_document`
//! and asserts the expected paper/claim/edge graph shape lands in Postgres.

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::do_ingest_document;
use sqlx::PgPool;

const FIXTURE: &str = r#"{
  "source": {
    "title": "Test Hierarchical Paper",
    "doi": "10.1234/hierarchy-smoke",
    "source_type": "Paper",
    "authors": [
      {"name": "Alice Author", "affiliations": [], "roles": ["author"]}
    ]
  },
  "thesis": "Hierarchies converge through layered claims",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Intro",
    "summary": "Background section connecting prior work to this thesis",
    "paragraphs": [{
      "compound": "Atomization aids cross-source matching, and explicit decomposition is necessary",
      "supporting_text": "We argue both points throughout the paper.",
      "atoms": [
        "Atomization aids cross-source matching",
        "Explicit decomposition is necessary for hierarchical reasoning"
      ],
      "generality": [3, 3],
      "confidence": 0.8
    }]
  }],
  "relationships": [
    {
      "source_path": "sections/0/paragraphs/0/atoms/0",
      "target_path": "sections/0/paragraphs/0/atoms/1",
      "relationship": "supports"
    }
  ]
}"#;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

#[sqlx::test(migrations = "../../migrations")]
async fn happy_path_ingests_full_hierarchy(pool: PgPool) {
    let server = make_server(pool.clone());
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    let result = do_ingest_document(&server, &extraction)
        .await
        .expect("ingest_document succeeds");

    // Pull the paper_id out of the structured response.
    let payload = result_text(&result);
    let json: serde_json::Value = serde_json::from_str(&payload).expect("response JSON");
    assert_eq!(json["already_ingested"], serde_json::json!(false));
    assert_eq!(json["doi"], "10.1234/hierarchy-smoke");
    assert_eq!(
        json["claims_ingested"].as_u64().unwrap(),
        5,
        "thesis + section + paragraph + 2 atoms; all newly inserted, no dedup"
    );
    assert_eq!(json["claims_skipped_dedup"].as_u64().unwrap(), 0);
    assert!(json["relationships_created"].as_u64().unwrap() >= 5);

    let paper_id = uuid::Uuid::parse_str(json["paper_id"].as_str().unwrap()).unwrap();

    // 1. Paper row exists with correct DOI.
    let row = sqlx::query!("SELECT doi, title FROM papers WHERE id = $1", paper_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.doi, "10.1234/hierarchy-smoke");

    // 2. Each level is represented as a claim node.
    let claim_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM claims
        WHERE content IN (
            'Hierarchies converge through layered claims',
            'Background section connecting prior work to this thesis',
            'Atomization aids cross-source matching, and explicit decomposition is necessary',
            'Atomization aids cross-source matching',
            'Explicit decomposition is necessary for hierarchical reasoning'
        )
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        claim_count.0, 5,
        "all 5 hierarchy levels persisted as claims"
    );

    // 3. Paper -> claim asserts edges exist for every claim.
    let assert_edges: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges
        WHERE source_id = $1 AND source_type = 'paper'
          AND target_type = 'claim' AND relationship = 'asserts'
        "#,
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(assert_edges.0, 5, "paper asserts every claim level");

    // 4. agent -authored-> paper edge exists.
    let authored: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE target_id = $1 AND relationship = 'authored'",
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(authored.0, 1);

    // 5. supports edge between the two atoms exists.
    let supports: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE relationship = 'supports' AND source_type = 'claim' AND target_type = 'claim'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(supports.0, 1, "atom -supports-> atom edge persisted");

    // 6. paper -processed_by-> agent edge marks the version gate.
    let processed: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges
        WHERE source_id = $1 AND source_type = 'paper'
          AND target_type = 'agent' AND relationship = 'processed_by'
          AND properties ->> 'pipeline' = 'hierarchical_extraction_v1'
        "#,
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(processed.0, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn re_ingest_hits_version_gate(pool: PgPool) {
    let server = make_server(pool.clone());
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");

    let _first = do_ingest_document(&server, &extraction)
        .await
        .expect("first ingest");
    let second = do_ingest_document(&server, &extraction)
        .await
        .expect("second ingest");

    let payload = result_text(&second);
    let json: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(json["already_ingested"], serde_json::json!(true));
    assert_eq!(json["claims_ingested"], serde_json::json!(0));
    assert_eq!(json["relationships_created"], serde_json::json!(0));
}

/// A second fixture sharing one atom and the same author with the primary
/// fixture. Validates cross-paper atom convergence and author dedup.
const FIXTURE_OVERLAP: &str = r#"{
  "source": {
    "title": "Second Hierarchical Paper",
    "doi": "10.1234/hierarchy-second",
    "source_type": "Paper",
    "authors": [
      {"name": "Alice Author", "affiliations": [], "roles": ["author"]}
    ]
  },
  "thesis": "Different thesis but shared atom",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Other Intro",
    "summary": "An entirely different section summary that should not collide",
    "paragraphs": [{
      "compound": "A different compound claim that overlaps via one shared atom",
      "supporting_text": "Different supporting passage.",
      "atoms": [
        "Atomization aids cross-source matching",
        "A genuinely new atom that has never been ingested before"
      ],
      "generality": [3, 3],
      "confidence": 0.7
    }]
  }],
  "relationships": []
}"#;

#[sqlx::test(migrations = "../../migrations")]
async fn cross_paper_atom_and_author_converge(pool: PgPool) {
    let server = make_server(pool.clone());
    let first: DocumentExtraction = serde_json::from_str(FIXTURE).expect("fixture parses");
    let second: DocumentExtraction = serde_json::from_str(FIXTURE_OVERLAP).expect("fixture parses");

    let _ = do_ingest_document(&server, &first)
        .await
        .expect("first ingest");
    let res = do_ingest_document(&server, &second)
        .await
        .expect("second ingest");

    let payload = result_text(&res);
    let json: serde_json::Value = serde_json::from_str(&payload).unwrap();

    // The shared atom hits cross-paper dedup; the new atom + thesis +
    // section + paragraph are fresh → 4 newly inserted, 1 deduped.
    assert_eq!(json["claims_skipped_dedup"].as_u64().unwrap(), 1);
    assert_eq!(json["claims_ingested"].as_u64().unwrap(), 4);

    // Same shared atom → exactly one atom claim row for that content.
    let shared_atom_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM claims WHERE content = 'Atomization aids cross-source matching'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        shared_atom_count.0, 1,
        "shared atom must converge to one row"
    );

    // The shared atom is asserted by BOTH papers.
    let asserts_into_shared: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges e
        JOIN claims c ON c.id = e.target_id
        WHERE e.relationship = 'asserts'
          AND e.source_type = 'paper'
          AND e.target_type = 'claim'
          AND c.content = 'Atomization aids cross-source matching'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        asserts_into_shared.0, 2,
        "both papers assert the shared atom"
    );

    // Same author across both papers → exactly one author agent row.
    let alice_agents: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM agents WHERE display_name = 'Alice Author'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(alice_agents.0, 1, "author dedup via deterministic key");

    // ...and Alice authored both papers.
    let authored_edges: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE relationship = 'authored' AND source_type = 'agent'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(authored_edges.0, 2, "alice authored both papers");
}

fn result_text(result: &rmcp::model::CallToolResult) -> String {
    let content = result.content.first().expect("at least one content block");
    content.as_text().expect("text content").text.clone()
}
