//! Document ingest's background work, on the application role: the detached
//! walk and the post-commit embedding loop are tracked by the server
//! (backlog b928ccc1), so a process that drains its tracker before exiting
//! ends with the walk committed and every claim it created embedded.
//!
//! Every pool the server holds is `epigraph_app` (NOSUPERUSER, NOBYPASSRLS);
//! seeding and assertions run on the harness pool. The embedder's provider is
//! replaced with `McpEmbedder::with_generator`, so vectors are stored without
//! a network call.
//!
//! `#[sqlx::test]` runs each test on a current-thread runtime, so a task the
//! tool spawned has not been polled when the tool returns: `running()` right
//! after the call counts exactly the tasks it left behind, deterministically.
//!
//! Verified to fail: with the detached walk spawned by a bare `tokio::spawn`,
//! `a_queued_ingest_is_tracked_until_its_walk_and_embeddings_finish` sees 0
//! tracked tasks; with the embedding loop spawned that way,
//! `a_waited_ingest_leaves_its_embedding_loop_tracked` does.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::sync::Arc;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::background::BackgroundTasks;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::ingest_document_inline;
use epigraph_mcp::types::IngestDocumentInlineParams;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// An app-role stdio server whose embedder stores a fixed vector for any text.
async fn app_role_server(pool: &PgPool, seed: u8) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(Arc::new(|_text: &str| Ok(vec![0.01_f32; 1536])));
    EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false).with_scoped_pool(scoped)
}

/// A full document: thesis, one section, one paragraph, two atoms.
fn doc(doi: &str) -> DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {"title": format!("Background embed {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": []},
        "thesis": format!("Background embed thesis {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Background embed paragraph {doi}"),
            "atoms": [format!("Background embed atom one {doi}"),
                      format!("Background embed atom two {doi}")],
            "generality": [3, 3], "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction")
}

fn params(
    doi: &str,
    wait: bool,
    visibility: Option<&str>,
    group: Option<Uuid>,
) -> IngestDocumentInlineParams {
    IngestDocumentInlineParams {
        extraction: doc(doi),
        wait: Some(wait),
        visibility: visibility.map(str::to_string),
        group_id: group.map(|g| g.to_string()),
    }
}

/// Ingest over stdio (the server's own agent authors); the response body.
async fn ingest(server: &EpiGraphMcpFull, p: IngestDocumentInlineParams) -> serde_json::Value {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("the stdio viewer");
    let out = ingest_document_inline(server, &viewer, p, None)
        .await
        .expect("the ingest");
    assert_ne!(out.is_error, Some(true), "{out:?}");
    let text = out
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("a text body");
    serde_json::from_str(&text).expect("a JSON body")
}

/// `(claims, embedded, visibility set)` over the document's `doi:` claims.
async fn doc_state(pool: &PgPool, doi: &str) -> (i64, i64, Vec<String>) {
    sqlx::query_as(
        "SELECT count(*), count(embedding), \
                coalesce(array_agg(DISTINCT visibility::text), '{}') \
           FROM claims WHERE $1 = ANY(labels)",
    )
    .bind(format!("doi:{doi}"))
    .fetch_one(pool)
    .await
    .expect("doc state")
}

async fn drained(tasks: &BackgroundTasks) {
    assert_eq!(
        tasks.drain(Duration::from_secs(60)).await,
        0,
        "every background task finishes inside the limit"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_queued_ingest_is_tracked_until_its_walk_and_embeddings_finish(pool: PgPool) {
    let server = app_role_server(&pool, 0xB1).await;
    let doi = "10.0/b928-queued";
    let body = ingest(&server, params(doi, false, Some("public"), None)).await;
    assert_eq!(body["status"], "queued", "{body}");

    let tasks = server.background_tasks();
    assert_eq!(
        tasks.running(),
        1,
        "the detached walk must be spawned on the server's tracker, or a stdio process \
         exits under it"
    );

    drained(&tasks).await;
    let (claims, embedded, _) = doc_state(&pool, doi).await;
    assert!(claims > 0, "the walk committed");
    assert_eq!(
        embedded, claims,
        "the walk's embedding loop is drained with it: every created claim has a vector"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_waited_ingest_leaves_its_embedding_loop_tracked(pool: PgPool) {
    let server = app_role_server(&pool, 0xB2).await;
    let doi = "10.0/b928-waited";
    let body = ingest(&server, params(doi, true, Some("public"), None)).await;
    assert!(body["claims_ingested"].as_u64().unwrap_or(0) > 0, "{body}");

    let tasks = server.background_tasks();
    assert_eq!(
        tasks.running(),
        1,
        "the post-commit embedding loop must be spawned on the server's tracker"
    );
    drained(&tasks).await;
    let (claims, embedded, _) = doc_state(&pool, doi).await;
    assert_eq!(embedded, claims, "every created claim has a vector");
}
