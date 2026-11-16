//! The warn-only atomicity block reaches the RESPONSE of both document-ingest
//! handlers, on the queued arm and on the `wait=true` arm (backlog
//! `72850d43`, review minor 1).
//!
//! `ingestion.rs`'s unit tests cover `extraction_atomicity` and
//! `with_atomicity` as functions; nothing called the handlers, so dropping
//! the `.map(|r| with_atomicity(r, atomicity))` on the `wait=true` arm, or
//! passing `None` to `queued_response`, failed no test. These drive
//! `ingest_document_inline` and the file-path `ingest_document` and read the
//! JSON the caller gets back.
//!
//! Deliberately does NOT use `tests/common`: that helper DROPs
//! `uq_claims_content_hash_agent` (see `verify_claim_after_document_ingest.rs`).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{ingest_document, ingest_document_inline};
use epigraph_mcp::types::{IngestDocumentInlineParams, IngestDocumentParams};
use sqlx::PgPool;
use uuid::Uuid;

/// One compound atom per ingest: the queued walks run detached and
/// concurrently with the later calls, and two walks writing the same text for
/// the same author would race on its dedup key.
const COMPOUND: [&str; 4] = [
    "The pump failed, but the backup took over.",
    "The valve stuck, and the operator reset it.",
    "The fan stopped, and the room overheated.",
    "The belt snapped, but the line kept running.",
];
const ATOMIC: &str = "The alarm rang at noon.";

/// Built FROM A `ScopedPool`, so the walk runs the production
/// `begin_author_stamped_tx` path.
async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

fn extraction(doi: &str, atom: &str) -> DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {
            "title": format!("Atomicity {doi}"),
            "doi": doi,
            "source_type": "Paper",
            "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("Thesis of {doi}."),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "S",
            "paragraphs": [{
                "text": format!("Paragraph of {doi}."),
                "atoms": [atom],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        "relationships": []
    }))
    .expect("fixture parses")
}

fn body(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = &result
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text;
    serde_json::from_str(text).expect("JSON response")
}

async fn inline(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    doi: &str,
    atom: &str,
    wait: Option<bool>,
) -> serde_json::Value {
    let viewer = fixture::public_viewer(pool).await;
    let r = ingest_document_inline(
        server,
        &viewer,
        IngestDocumentInlineParams {
            wait,
            extraction: extraction(doi, atom),
            visibility: Some("public".to_string()),
            group_id: None,
        },
        None,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("ingest accepted");
    body(&r)
}

fn assert_warns(what: &str, b: &serde_json::Value) {
    assert_eq!(
        b["atomicity"]["compound_atoms"], 1,
        "{what}: the compound atom must be reported to the caller: {b}"
    );
    assert_eq!(b["atomicity"]["atoms_screened"], 1, "{what}: {b}");
}

/// A file under the current directory (the file-path handler refuses a path
/// outside it), removed on drop.
struct CwdFixture(std::path::PathBuf);

impl CwdFixture {
    fn write(extraction: &DocumentExtraction) -> Self {
        let path = std::env::current_dir()
            .expect("current dir")
            .join(format!("b42-atomicity-{}.json", Uuid::new_v4()));
        std::fs::write(&path, serde_json::to_string(extraction).expect("serialize"))
            .expect("write fixture");
        Self(path)
    }
}

impl Drop for CwdFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn both_ingest_handlers_return_the_atomicity_warning(pool: PgPool) {
    let server = make_server(pool.clone()).await;

    // The wait=true arms first, before any detached walk is running: the
    // walks share an author, and a concurrent walk resolving the same author
    // would race these.
    //
    // ingest_document_inline, wait=true: the walk runs in the request and
    // the warning is added to its result. Nothing is refused: the claims land.
    let waited = inline(
        &server,
        &pool,
        "10.9999/b42-waited",
        COMPOUND[1],
        Some(true),
    )
    .await;
    assert!(
        waited.get("status").is_none(),
        "wait=true returns the walk's result, not `queued`: {waited}"
    );
    assert_warns("inline wait=true", &waited);
    let landed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(COMPOUND[1])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(landed >= 1, "warn-only: the compound atom is still written");

    // The file-path ingest_document, wait=true then queued.
    let viewer = fixture::public_viewer(&pool).await;
    for (doi, atom, wait) in [
        ("10.9999/b42-file-waited", COMPOUND[3], Some(true)),
        ("10.9999/b42-file-queued", COMPOUND[2], None),
    ] {
        let file = CwdFixture::write(&extraction(doi, atom));
        let r = ingest_document(
            &server,
            &viewer,
            IngestDocumentParams {
                wait,
                file_path: file.0.display().to_string(),
                visibility: Some("public".to_string()),
                group_id: None,
            },
            None,
        )
        .await
        .map_err(|e| e.message.to_string())
        .expect("file ingest accepted");
        assert_warns(&format!("file-path wait={wait:?}"), &body(&r));
    }

    // Calibration: an atomic atom gets no block, so the blocks above are the
    // screen's verdict, not something every response carries.
    let quiet = inline(&server, &pool, "10.9999/b42-atomic", ATOMIC, None).await;
    assert_eq!(quiet["status"], "queued", "{quiet}");
    assert!(quiet.get("atomicity").is_none(), "{quiet}");

    // ingest_document_inline, queued arm.
    let queued = inline(&server, &pool, "10.9999/b42-queued", COMPOUND[0], None).await;
    assert_eq!(queued["status"], "queued", "{queued}");
    assert_warns("inline queued", &queued);

    // Let the detached walks finish before the test database is torn down.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
}
