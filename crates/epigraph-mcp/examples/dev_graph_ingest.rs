//! Ingest a real `DocumentExtraction` into an operator-chosen graph.
//!
//! The canonical `ingest_document` MCP tool is pinned to whatever
//! `--database-url` the running MCP server was launched with (production, in
//! practice), and there is no document-ingest CLI — so there is no first-class
//! way to ingest a document into an ad-hoc scratch/dev graph short of standing
//! up a second authenticated MCP server. This harness closes that gap *for one
//! task* by calling the exact same canonical entrypoint (`do_ingest_document`)
//! over a `PgPool` connected to a DB of the operator's choosing.
//!
//! It is a cargo example, not a test: it lived in `tests/` as an `#[ignore]`d
//! test that no gate ran (backlog 4ae8f96c), and it asserts nothing beyond the
//! ingest succeeding on the operator's input. `cargo test` and
//! `clippy --all-targets` still compile it. Drive it with:
//!
//! ```bash
//! SQLX_OFFLINE=true \
//! INGEST_TARGET_DB='postgres://epigraph:epigraph@localhost/epigraph_anxiety_ingest_dev' \
//! EXTRACTION_PATH='/abs/path/to/anxiety-deep-research-extraction.json' \
//!   cargo run -p epigraph-mcp --example dev_graph_ingest
//! ```
//!
//! Tracking the missing first-class capability: see the epigraph feature
//! request for a configurable ingest target (per-call DB / document-ingest CLI).

#[path = "../tests/viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::document::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::do_ingest_document;
use sqlx::PgPool;

/// Built FROM A `ScopedPool`: the document ingest walk now runs in one
/// transaction stamped from the ingesting agent and refuses (nothing written) on
/// a server that cannot stamp one. Against a BYPASSRLS owner DSN (the usual
/// scratch-graph login) the stamp is inert — what this buys is that the tool
/// drives the PRODUCTION code path (`begin_author_stamped_tx`) rather than the
/// refusal.
async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

/// An operator tool, not a test: a missing input is a usage error.
fn require_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        eprintln!("error: {name} is not set (see the run line at the top of this file)");
        std::process::exit(2);
    })
}

#[tokio::main]
async fn main() {
    let db = require_env("INGEST_TARGET_DB");
    let path = require_env("EXTRACTION_PATH");

    let pool = PgPool::connect(&db).await.expect("connect to target DB");

    let viewer = fixture::public_viewer(&pool).await;
    // Bring the chosen DB up to the repo schema; idempotent on an already-migrated DB.
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations to target DB");

    let raw = std::fs::read_to_string(&path).expect("read extraction JSON");
    let extraction: DocumentExtraction =
        serde_json::from_str(&raw).expect("parse DocumentExtraction");

    let server = make_server(pool.clone()).await;
    let result = do_ingest_document(
        &server,
        &viewer,
        &extraction,
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("do_ingest_document succeeds");

    let content = result.content.first().expect("at least one content block");
    let text = content.as_text().expect("text content").text.clone();
    println!("INGEST_RESULT_JSON: {text}");
}
