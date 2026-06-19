//! Smoke test for the `structure_source` MCP tool.
//!
//! Drives raw markdown through `structure_source` and asserts the deterministic
//! structurer yields a verbatim `DocumentExtraction`: heading → section title,
//! blocks → byte-exact paragraph `text`, `atoms` left EMPTY for the agent, and
//! the original bytes carried in `source_text`.

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::structure_source;
use epigraph_mcp::types::StructureSourceParams;
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
async fn structures_markdown_into_verbatim_extraction(pool: PgPool) {
    let server = make_server(pool);
    let params = StructureSourceParams {
        text: "# Intro\n\nAlpha para.\n\nBeta para.".to_string(),
        source: serde_json::from_value(serde_json::json!({ "title": "Doc", "doi": "10.1/x" }))
            .unwrap(),
        format: "markdown".to_string(),
        segmentation: None,
    };
    let result = structure_source(&server, params).await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&result_text(&result)).unwrap();
    assert_eq!(json["sections"][0]["title"], "Intro");
    assert_eq!(json["sections"][0]["paragraphs"][0]["text"], "Alpha para.");
    assert!(json["sections"][0]["paragraphs"][0]["atoms"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(json["source_text"], "# Intro\n\nAlpha para.\n\nBeta para.");
}
