//! End-to-end acceptance test for the verbatim spine (no live LLM — Approach C).
//!
//! Drives the two-step agent flow with CANNED atoms:
//!   1. `structure_source` deterministically slices raw markdown into a verbatim
//!      `DocumentExtraction` (sections + paragraphs as byte-exact source slices,
//!      `source_text` + spans populated, `atoms` empty).
//!   2. We inject canned atoms (standing in for the LLM atomizer) and resubmit
//!      via `ingest_document_inline`; the writer re-verifies the threaded
//!      `source_text` + spans.
//!
//! It then asserts the §2 Tier-1 invariant end to end: the persisted paragraph
//! node `content` is BYTE-EQUAL to the source paragraph (NOT an atom/paraphrase —
//! note the trailing period), the tier stamp is `verbatim_v2`, and the
//! deterministic spine carries the `section_follows` edge between the two
//! sections.

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{ingest_document_inline, structure_source};
use epigraph_mcp::types::{IngestDocumentInlineParams, StructureSourceParams};
use sqlx::PgPool;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn result_text(result: &rmcp::model::CallToolResult) -> String {
    let content = result.content.first().expect("at least one content block");
    content.as_text().expect("text content").text.clone()
}

#[sqlx::test(migrations = "../../migrations")]
async fn structure_then_ingest_yields_verbatim_spine(pool: PgPool) {
    let server = make_server(pool.clone());
    let src = "# Intro\n\nAlpha is a fact.\n\n## Body\n\nBeta follows alpha.";

    // 1) structure — deterministic, verbatim, atoms empty.
    let sp = StructureSourceParams {
        text: src.to_string(),
        source: serde_json::from_value(serde_json::json!({ "title": "E2E", "doi": "10.1/e2e" }))
            .unwrap(),
        format: "markdown".to_string(),
        segmentation: None,
    };
    let structured = structure_source(&server, sp).await.unwrap();
    let mut extraction: DocumentExtraction =
        serde_json::from_str(&result_text(&structured)).unwrap();

    // The structurer must have recovered exactly two sections (one per heading),
    // each with one paragraph, so the canned-atom injection indices line up.
    assert_eq!(extraction.sections.len(), 2, "two headings -> two sections");
    assert_eq!(extraction.sections[0].paragraphs.len(), 1);
    assert_eq!(extraction.sections[1].paragraphs.len(), 1);

    // 2) inject canned atoms (stands in for the LLM atomizer — Approach C). The
    // atoms intentionally DROP the trailing period so 4a can prove the
    // paragraph node is the verbatim source, not an atom/paraphrase.
    extraction.sections[0].paragraphs[0].atoms = vec!["Alpha is a fact".to_string()];
    extraction.sections[1].paragraphs[0].atoms = vec!["Beta follows alpha".to_string()];

    // 3) ingest inline; the writer re-verifies the threaded source_text + spans.
    //    ingest_document_inline is fire-and-forget: it spawns the write as a
    //    detached Tokio task and returns {"status":"queued"} immediately.
    let result = ingest_document_inline(&server, IngestDocumentInlineParams { extraction })
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&result_text(&result)).unwrap();
    assert_eq!(json["status"], "queued");

    // Give the background task time to finish its DB writes.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Resolve paper_id by DOI now that the background write has landed.
    let paper_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM papers WHERE doi = '10.1/e2e'")
        .fetch_one(&pool)
        .await
        .expect("paper row must exist after background task completes");

    // 4a) the paragraph node content is BYTE-EQUAL to the source paragraph.
    //
    // Scoped to THIS paper via its `asserts` edge (there is no `paper_id`
    // column on `claims`), and ordered by content so the alphabetically-first
    // level-2 node ("Alpha is a fact." < "Beta follows alpha.") is decisive.
    // The trailing period is load-bearing: the injected atom is "Alpha is a
    // fact" (no period, level 3), so only the verbatim level-2 node carries it.
    let para: String = sqlx::query_scalar(
        r#"
        SELECT c.content FROM claims c
        JOIN edges e ON e.target_id = c.id
        WHERE e.source_id = $1
          AND e.source_type = 'paper'
          AND e.target_type = 'claim'
          AND e.relationship = 'asserts'
          AND c.properties->>'level' = '2'
        ORDER BY c.content
        LIMIT 1
        "#,
    )
    .bind(paper_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        para, "Alpha is a fact.",
        "paragraph node must be the verbatim source (incl. the period), NOT an atom/paraphrase"
    );

    // 4b) tier stamp: source_text present => Tier 1 verbatim_v2.
    let kind: Option<String> = sqlx::query_scalar(
        "SELECT properties->>'spine_text_kind' FROM claims WHERE properties->>'level' = '2' LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kind.as_deref(), Some("verbatim_v2"));

    // 4c) deterministic spine: exactly one section_follows edge (two sections).
    let follows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM edges WHERE relationship = 'section_follows'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        follows, 1,
        "two sections -> exactly one section_follows edge"
    );
}
