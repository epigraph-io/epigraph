//! A document-ingest author node is stored `key_kind = 'seed-derived'`
//! (backlog bfc2eff8, migration 230), and no signature verifier accepts its
//! key.
//!
//! The node's key is `did_key_for_author(None, name)`: the Ed25519 key of
//! `BLAKE3("author:{name}")`, whose private half anyone who knows the name can
//! compute. Before 230 the row took the column default `ed25519`, so
//! `AgentRepository::public_key_if_signer` (the packet-signature verifier's
//! key source) handed that key to the verifier.
//!
//! Driven through the real MCP ingest on the APPLICATION role, so the test
//! also proves migration 077's `agents_provision` policy admits the new kind
//! to the role that creates author nodes in production. All names are
//! invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use epigraph_ingest::document::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools;
use epigraph_mcp::types::IngestDocumentInlineParams;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// An ingesting server whose plain and scoped pools both run as
/// `epigraph_app`, signing with `signer`.
async fn app_role_server(pool: &PgPool, signer: AgentSigner) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let embedder = McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(plain, signer, embedder, false).with_scoped_pool(scoped)
}

fn doc(doi: &str, author: &str) -> DocumentExtraction {
    serde_json::from_value(json!({
        "source": {"title": format!("Seed-derived author {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": [{"name": author}]},
        "thesis": format!("Thesis of {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Paragraph of {doi}."),
            "atoms": [format!("Atom of {doi}.")],
            "generality": [3], "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction parses")
}

async fn key_kind_of_key(pool: &PgPool, key: &[u8; 32]) -> (Uuid, String) {
    sqlx::query_as("SELECT id, key_kind::text FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(pool)
        .await
        .expect("agent by key")
}

async fn verifier_key(pool: &PgPool, agent: Uuid) -> Option<Vec<u8>> {
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::public_key_if_signer(&mut conn, agent)
        .await
        .expect("public_key_if_signer")
}

/// The author node an ingest creates is `seed-derived`, and the verifier's
/// key source returns nothing for it; the ingesting server's own agent, whose
/// key is random, stays an `ed25519` verifier (calibration: the marking is
/// keyed on how the key was made, not applied to every row the ingest
/// touches).
#[sqlx::test(migrations = "../../migrations")]
async fn an_ingested_author_node_is_seed_derived_and_never_a_verifier(pool: PgPool) {
    let signer = AgentSigner::generate();
    let signer_key = signer.public_key();
    let server = app_role_server(&pool, signer).await;
    let name = "Ottoline Vashby";

    let viewer = fixture::public_viewer(&pool).await;
    tools::ingestion::ingest_document_inline(
        &server,
        &viewer,
        IngestDocumentInlineParams {
            extraction: doc("10.9999/seed-derived-author", name),
            wait: Some(true),
            visibility: Some("public".to_string()),
            group_id: None,
        },
        None,
    )
    .await
    .expect("ingest succeeds");

    let (_did, author_key) = epigraph_crypto::did_key::did_key_for_author(None, name);
    let (author, kind) = key_kind_of_key(&pool, &author_key).await;
    assert_eq!(
        kind, "seed-derived",
        "the author node's key is BLAKE3 of its public name; it must not be stored as a verifier"
    );
    assert_eq!(
        verifier_key(&pool, author).await,
        None,
        "public_key_if_signer must refuse a seed-derived key"
    );

    let (ingester, kind) = key_kind_of_key(&pool, &signer_key).await;
    assert_eq!(kind, "ed25519", "calibration: the random-key ingester");
    assert_eq!(
        verifier_key(&pool, ingester).await,
        Some(signer_key.to_vec()),
        "calibration: a real key still verifies"
    );
}
