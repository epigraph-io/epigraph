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
//! It is `#[ignore]` so it never runs in the normal suite. Drive it with:
//!
//! ```bash
//! SQLX_OFFLINE=true \
//! INGEST_TARGET_DB='postgres://epigraph:epigraph@localhost/epigraph_anxiety_ingest_dev' \
//! EXTRACTION_PATH='/abs/path/to/anxiety-deep-research-extraction.json' \
//!   cargo test -p epigraph-mcp --test dev_graph_ingest -- --ignored --nocapture
//! ```
//!
//! Tracking the missing first-class capability: see the epigraph feature
//! request for a configurable ingest target (per-call DB / document-ingest CLI).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::do_ingest_document;
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

#[tokio::test]
#[ignore = "operator-driven: needs INGEST_TARGET_DB + EXTRACTION_PATH"]
async fn ingest_extraction_into_target_db() {
    let Ok(db) = std::env::var("INGEST_TARGET_DB") else {
        eprintln!(
            "SKIP: INGEST_TARGET_DB not set — this is a dev ingest harness, not a regression test"
        );
        return;
    };
    let Ok(path) = std::env::var("EXTRACTION_PATH") else {
        eprintln!(
            "SKIP: EXTRACTION_PATH not set — this is a dev ingest harness, not a regression test"
        );
        return;
    };

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
    let result = do_ingest_document(&server, &viewer, &extraction, None)
        .await
        .expect("do_ingest_document succeeds");

    let content = result.content.first().expect("at least one content block");
    let text = content.as_text().expect("text content").text.clone();
    println!("INGEST_RESULT_JSON: {text}");
}
