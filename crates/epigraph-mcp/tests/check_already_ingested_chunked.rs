//! `check_already_ingested`'s default must match the stamp the ingest tools
//! actually write (backlog 02653c4a, G8).
//!
//! A chunked ingest (`source.metadata.chapter_index = n`) stamps its
//! `processed_by` edge `hierarchical_extraction_v2:ch{n}`, but the pre-flight
//! defaulted to the bare `hierarchical_extraction_v2`, so a textbook ingested
//! chapter by chapter read as never ingested. Driven through the REAL ingest
//! path (`do_ingest_document`), so the stamp under test is the one production
//! writes, not a hand-inserted edge.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{check_already_ingested, do_ingest_document};
use sqlx::PgPool;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

fn document(doi: &str, chapter: Option<u64>) -> DocumentExtraction {
    let metadata = chapter
        .map(|n| format!(r#", "metadata": {{"chapter_index": {n}}}"#))
        .unwrap_or_default();
    let tag = chapter.map_or("whole".to_string(), |n| format!("ch{n}"));
    serde_json::from_str(&format!(
        r#"{{
          "source": {{
            "title": "G8 {tag} of {doi}",
            "doi": "{doi}",
            "source_type": "Textbook",
            "authors": [{{"name": "Alice Author", "affiliations": [], "roles": ["author"]}}]
            {metadata}
          }},
          "thesis": "G8 thesis {tag} {doi}",
          "thesis_derivation": "TopDown",
          "sections": [{{
            "title": "Sec",
            "paragraphs": [{{
              "text": "G8 compound claim {tag} {doi}",
              "atoms": ["G8 atom {tag} {doi}"],
              "generality": [3],
              "confidence": 0.8
            }}]
          }}],
          "relationships": []
        }}"#
    ))
    .expect("fixture parses")
}

async fn check(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    doi: &str,
    pipeline: Option<&str>,
) -> serde_json::Value {
    let mut args = serde_json::json!({ "doi": doi });
    if let Some(p) = pipeline {
        args["pipeline_version"] = serde_json::json!(p);
    }
    first_text(
        &check_already_ingested(server, viewer, serde_json::from_value(args).unwrap())
            .await
            .expect("check_already_ingested"),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_default_sees_a_chunked_ingest(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let doi = "10.1234/g8-chunked";

    do_ingest_document(&server, &viewer, &document(doi, Some(3)))
        .await
        .expect("chapter 3 ingest");

    let default = check(&server, &viewer, doi, None).await;
    assert_eq!(
        default["already_ingested"], true,
        "a chapter-3 ingest must read as ingested by default: {default}"
    );
    assert_eq!(
        default["matched_pipeline_versions"],
        serde_json::json!(["hierarchical_extraction_v2:ch3"]),
        "{default}"
    );
    assert!(default["paper_id"].is_string(), "{default}");

    // Explicit stamps stay EXACT: the chunk is found, the bare base is not.
    let ch3 = check(
        &server,
        &viewer,
        doi,
        Some("hierarchical_extraction_v2:ch3"),
    )
    .await;
    assert_eq!(ch3["already_ingested"], true, "{ch3}");
    let base = check(&server, &viewer, doi, Some("hierarchical_extraction_v2")).await;
    assert_eq!(base["already_ingested"], false, "{base}");
    assert_eq!(
        base["matched_pipeline_versions"],
        serde_json::json!([]),
        "{base}"
    );
    let ch4 = check(
        &server,
        &viewer,
        doi,
        Some("hierarchical_extraction_v2:ch4"),
    )
    .await;
    assert_eq!(ch4["already_ingested"], false, "{ch4}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_default_still_sees_a_whole_document_ingest_and_not_a_missing_one(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let doi = "10.1234/g8-whole";

    let missing = check(&server, &viewer, doi, None).await;
    assert_eq!(missing["already_ingested"], false, "{missing}");
    assert_eq!(missing["matched_pipeline_versions"], serde_json::json!([]));

    do_ingest_document(&server, &viewer, &document(doi, None))
        .await
        .expect("whole ingest");
    let whole = check(&server, &viewer, doi, None).await;
    assert_eq!(whole["already_ingested"], true, "{whole}");
    assert_eq!(
        whole["matched_pipeline_versions"],
        serde_json::json!(["hierarchical_extraction_v2"]),
        "{whole}"
    );
    assert_eq!(whole["pipeline_version"], "hierarchical_extraction_v2");
}
