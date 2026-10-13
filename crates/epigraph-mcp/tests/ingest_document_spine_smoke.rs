//! Smoke tests for `do_ingest_document_spine` — the phase-1 tool of the
//! two-phase ingest flow.
//!
//! The key invariants being verified:
//! 1. Fresh spine returns all paragraphs in `new_paragraph_paths`, in document order.
//! 2. Spine after an abstract-only ingest: shared paragraphs land in `paragraphs_deduped`,
//!    new body paragraphs in `new_paragraph_paths`.
//! 3. Full re-spine of an already-ingested document: `already_ingested: true`, zero new paths.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::do_ingest_document_spine;
use sqlx::PgPool;

/// Built FROM A `ScopedPool`: the document ingest walk now runs in one
/// transaction stamped from the ingesting agent and refuses (nothing written) on
/// a server that cannot stamp one. `#[sqlx::test]` connects as a BYPASSRLS
/// superuser, so the stamp is inert here — what this buys is that the fixture
/// drives the PRODUCTION code path (`begin_author_stamped_tx`) rather than the
/// refusal.
async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
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
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction =
        serde_json::from_str(SPINE_FIXTURE).expect("fixture parses");

    let result = do_ingest_document_spine(
        &server,
        &fixture::public_viewer(&pool).await,
        &extraction,
        None,
    )
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
    let server = make_server(pool.clone()).await;
    let abstract_extraction: DocumentExtraction =
        serde_json::from_str(ABSTRACT_FIXTURE).expect("abstract fixture parses");
    let full_extraction: DocumentExtraction =
        serde_json::from_str(SPINE_FIXTURE).expect("full fixture parses");

    // Phase 1: ingest the abstract.
    let first = do_ingest_document_spine(
        &server,
        &fixture::public_viewer(&pool).await,
        &abstract_extraction,
        None,
    )
    .await
    .expect("abstract spine ingest succeeds");
    let first_json: serde_json::Value =
        serde_json::from_str(&result_text(&first)).expect("response JSON");
    assert_eq!(first_json["paragraphs_new"].as_u64().unwrap(), 2);
    assert_eq!(first_json["paragraphs_deduped"].as_u64().unwrap(), 0);

    // Phase 2: ingest the full paper — abstract paragraphs are deduped,
    // the Methods paragraph is genuinely new.
    let second = do_ingest_document_spine(
        &server,
        &fixture::public_viewer(&pool).await,
        &full_extraction,
        None,
    )
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
    let server = make_server(pool.clone()).await;
    let extraction: DocumentExtraction =
        serde_json::from_str(SPINE_FIXTURE).expect("fixture parses");

    let _first = do_ingest_document_spine(
        &server,
        &fixture::public_viewer(&pool).await,
        &extraction,
        None,
    )
    .await
    .expect("first spine ingest");
    let second = do_ingest_document_spine(
        &server,
        &fixture::public_viewer(&pool).await,
        &extraction,
        None,
    )
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

/// Backlog a55aac45 / U039: the spine walk has its OWN copy of the author loop
/// and byline gate, so it needs its own guard. A placeholder ahead of a real
/// author must mint no agent, and the real author must keep her per-claim
/// `asserts` edges (planner and walk skip the same original index).
#[sqlx::test(migrations = "../../migrations")]
async fn spine_rejects_placeholder_author(pool: PgPool) {
    let server = make_server(pool.clone()).await;
    let mut v: serde_json::Value = serde_json::from_str(SPINE_FIXTURE).expect("fixture parses");
    v["source"]["doi"] = serde_json::json!("10.1234/spine-placeholder-author");
    v["source"]["authors"] = serde_json::json!([
        {"name": "Authors Not Specified", "affiliations": [], "roles": ["author"]},
        {"name": "Alice Author", "affiliations": [], "roles": ["author"]}
    ]);
    let extraction: DocumentExtraction = serde_json::from_value(v).expect("fixture parses");

    let result = do_ingest_document_spine(
        &server,
        &fixture::public_viewer(&pool).await,
        &extraction,
        None,
    )
    .await
    .expect("spine ingest succeeds — a bad author name is dropped, not fatal");
    let json: serde_json::Value =
        serde_json::from_str(&result_text(&result)).expect("response JSON");
    let paper_id =
        uuid::Uuid::parse_str(json["paper_id"].as_str().expect("paper_id")).expect("uuid");

    let placeholder_agents: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM agents WHERE display_name = 'Authors Not Specified'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        placeholder_agents.0, 0,
        "a placeholder author name must not mint an agent on the spine path"
    );

    let authored: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges e JOIN agents a ON a.id = e.source_id
        WHERE e.target_id = $1 AND e.relationship = 'authored'
          AND a.display_name = 'Alice Author'
        "#,
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let authored_total: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE target_id = $1 AND relationship = 'authored'",
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(authored.0, 1, "the real author authors the paper");
    assert_eq!(authored_total.0, 1, "and nobody else does");

    // thesis + 2 sections + 3 paragraphs = 6 spine claims (levels 0–2).
    let alice_asserts: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges e JOIN agents a ON a.id = e.source_id
        WHERE e.source_type = 'agent' AND e.target_type = 'claim'
          AND e.relationship = 'asserts' AND a.display_name = 'Alice Author'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        alice_asserts.0, 6,
        "the real author asserts every spine claim despite the placeholder ahead of her"
    );
}

/// The spine walk's byline gate is its own copy too: an all-placeholder
/// structured list counts as "no real author", so the body byline is recovered
/// (it was gated on an EMPTY list only). Byline authors get `authored → paper`
/// and no per-claim `asserts` (the planner emitted none for the placeholder).
#[sqlx::test(migrations = "../../migrations")]
async fn spine_placeholder_only_authors_fall_back_to_body_byline(pool: PgPool) {
    let server = make_server(pool.clone()).await;
    let byline_text =
        "Spine Smoke Test Paper\n\nGrace Byline, Ada Byline\n\nAbstract\nSpine body text.\n";
    assert_eq!(
        epigraph_ingest::document::byline::parse_byline_authors(byline_text).len(),
        2,
        "CALIBRATION: the body byline parses to two authors"
    );
    let mut v: serde_json::Value = serde_json::from_str(SPINE_FIXTURE).expect("fixture parses");
    v["source"]["doi"] = serde_json::json!("10.1234/spine-placeholder-byline");
    v["source"]["authors"] = serde_json::json!([
        {"name": "Unknown", "affiliations": [], "roles": ["author"]}
    ]);
    v["source_text"] = serde_json::json!(byline_text);
    let extraction: DocumentExtraction = serde_json::from_value(v).expect("fixture parses");

    let result = do_ingest_document_spine(
        &server,
        &fixture::public_viewer(&pool).await,
        &extraction,
        None,
    )
    .await
    .expect("spine ingest succeeds");
    let json: serde_json::Value =
        serde_json::from_str(&result_text(&result)).expect("response JSON");
    let paper_id =
        uuid::Uuid::parse_str(json["paper_id"].as_str().expect("paper_id")).expect("uuid");

    let authored_names: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT a.display_name FROM edges e JOIN agents a ON a.id = e.source_id
        WHERE e.target_id = $1 AND e.relationship = 'authored'
        ORDER BY a.display_name
        "#,
    )
    .bind(paper_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let authored_names: Vec<&str> = authored_names.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        authored_names,
        vec!["Ada Byline", "Grace Byline"],
        "exactly the two byline authors author the paper; no 'Unknown'"
    );

    let byline_asserts: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM edges e JOIN agents a ON a.id = e.source_id
        WHERE e.source_type = 'agent' AND e.target_type = 'claim'
          AND e.relationship = 'asserts'
          AND a.display_name IN ('Ada Byline', 'Grace Byline', 'Unknown')
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        byline_asserts.0, 0,
        "byline-recovered authors get authored→paper only, never per-claim asserts"
    );
}

/// Spine twin of `existing_placeholder_agent_is_not_reused`: prod already holds
/// the placeholder-derived agent (c12bddb2 "Authors Not Specified"), and the
/// spine walk's author loop is its own copy. Its skip must come BEFORE the
/// lookup by key, or the existing fake agent is reused on every new paper.
#[sqlx::test(migrations = "../../migrations")]
async fn spine_existing_placeholder_agent_is_not_reused(pool: PgPool) {
    let server = make_server(pool.clone()).await;
    let key = epigraph_crypto::did_key::did_key_for_author(None, "Authors Not Specified").1;
    let fake: uuid::Uuid = epigraph_db::AgentRepository::create(
        &pool,
        &epigraph_core::Agent::new(key, Some("Authors Not Specified".to_string())),
    )
    .await
    .expect("seed the name-derived agent")
    .id
    .into();
    let mut v: serde_json::Value = serde_json::from_str(SPINE_FIXTURE).expect("fixture parses");
    v["source"]["doi"] = serde_json::json!("10.1234/spine-placeholder-existing-agent");
    v["source"]["authors"] = serde_json::json!([
        {"name": "Authors Not Specified", "affiliations": [], "roles": ["author"]},
        {"name": "Alice Author", "affiliations": [], "roles": ["author"]}
    ]);
    let extraction: DocumentExtraction = serde_json::from_value(v).expect("fixture parses");

    let result = do_ingest_document_spine(
        &server,
        &fixture::public_viewer(&pool).await,
        &extraction,
        None,
    )
    .await
    .expect("spine ingest succeeds");
    let json: serde_json::Value =
        serde_json::from_str(&result_text(&result)).expect("response JSON");
    let paper_id =
        uuid::Uuid::parse_str(json["paper_id"].as_str().expect("paper_id")).expect("uuid");

    let fake_edges: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM edges WHERE source_id = $1 AND source_type = 'agent'")
            .bind(fake)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        fake_edges.0, 0,
        "the pre-existing placeholder agent must gain no edge of any kind"
    );
    let key_holders: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        key_holders.0, 1,
        "no second agent minted for the placeholder key"
    );

    // The walk did run over the structured list: the real author landed.
    let authored_names: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT a.display_name FROM edges e JOIN agents a ON a.id = e.source_id
        WHERE e.target_id = $1 AND e.relationship = 'authored'
        "#,
    )
    .bind(paper_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let authored_names: Vec<&str> = authored_names.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(authored_names, vec!["Alice Author"]);
}
