//! A document ingest's claims are embedded whatever their visibility (backlog
//! 46902f71).
//!
//! `ingest_document`, `ingest_document_inline` (both through
//! `do_ingest_document`) and `ingest_document_spine` embed in a detached task.
//! That task used `McpEmbedder::embed_and_store`, whose store path finds the
//! claim's author by reading the row as PUBLIC. Since the 2026-11-10 visibility
//! ruling a document ingest's claims go to the author's team or stay private by
//! default, never silently public, so that read found nothing and every
//! background embed was refused with only a WARN. `consolidate_claims` embedded
//! its merged claim through the same path.
//!
//! Both server pools are `epigraph_app` (row security enforced): on the
//! `#[sqlx::test]` superuser any store path succeeds. The embedder carries a
//! deterministic generator, so "not embedded" cannot mean "no API key".
//!
//! The PUBLIC ingest is the control: it was embedded before the fix too, so a
//! failure there is a broken fixture, not the defect.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{do_ingest_document, ingest_document_spine};
use epigraph_mcp::types::{ConsolidateClaimsParams, IngestDocumentSpineParams};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0xE4; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(vec![0.01_f32; 1536])));
    EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false).with_scoped_pool(scoped)
}

fn extraction(doi: &str, with_atom: bool) -> DocumentExtraction {
    let atoms: Vec<String> = if with_atom {
        vec![format!("Embedding atom {doi}")]
    } else {
        Vec::new()
    };
    let generality: Vec<u8> = if with_atom { vec![3] } else { Vec::new() };
    serde_json::from_value(serde_json::json!({
        "source": {"title": format!("Embedding doc {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": []},
        "thesis": format!("Embedding thesis {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Embedding paragraph {doi}"),
            "atoms": atoms,
            "generality": generality, "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction")
}

/// `(claims of the document, of which embedded, of which public)`.
async fn doc_state(pool: &PgPool, doi: &str) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE embedding IS NOT NULL), \
                count(*) FILTER (WHERE visibility = 'public') \
           FROM claims WHERE $1 = ANY(labels)",
    )
    .bind(format!("doi:{doi}"))
    .fetch_one(pool)
    .await
    .expect("doc state")
}

/// The embed is detached, so wait for it: until every claim of `doi` carries a
/// vector, or the deadline passes. Returns the final state either way.
async fn wait_for_embeddings(pool: &PgPool, doi: &str) -> (i64, i64, i64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let state = doc_state(pool, doi).await;
        if (state.0 > 0 && state.0 == state.1) || tokio::time::Instant::now() >= deadline {
            return state;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_document_ingest_is_embedded(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");

    // The control: a public ingest, embedded before the fix as well.
    let public_doi = "10.9999/embed-public";
    do_ingest_document(
        &server,
        &viewer,
        &extraction(public_doi, true),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("public ingest");
    let (claims, embedded, public) = wait_for_embeddings(&pool, public_doi).await;
    assert!(
        claims >= 3,
        "fixture: thesis, paragraph and atom ({claims})"
    );
    assert_eq!(public, claims, "fixture: the control is public");
    assert_eq!(
        embedded, claims,
        "control: a public ingest's claims are embedded; if this fails the fixture is broken"
    );

    // The defect: the same document, private to the author's home group.
    let private_doi = "10.9999/embed-private";
    do_ingest_document(
        &server,
        &viewer,
        &extraction(private_doi, true),
        None,
        epigraph_core::VisibilityChoice::Private,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("private ingest");
    let (claims, embedded, public) = wait_for_embeddings(&pool, private_doi).await;
    assert!(
        claims >= 3,
        "fixture: thesis, paragraph and atom ({claims})"
    );
    assert_eq!(
        public, 0,
        "fixture: none of the private ingest's claims is public"
    );
    assert_eq!(
        embedded, claims,
        "every claim of a NON-PUBLIC ingest must be embedded too: {embedded} of {claims}. \
         Zero is the public-reader store path refusing each one"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_spine_ingest_is_embedded(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");

    let doi = "10.9999/embed-private-spine";
    ingest_document_spine(
        &server,
        &viewer,
        IngestDocumentSpineParams {
            extraction: extraction(doi, false),
            visibility: Some("private".to_string()),
            group_id: None,
        },
        None,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("private spine ingest");
    let (claims, embedded, public) = wait_for_embeddings(&pool, doi).await;
    assert!(claims >= 2, "fixture: thesis and paragraph ({claims})");
    assert_eq!(public, 0, "fixture: the spine is private");
    assert_eq!(
        embedded, claims,
        "a non-public spine's claims must be embedded: {embedded} of {claims}"
    );
}

/// `consolidate_claims` over group-private sources: the merged claim is
/// private to the same group and must come back embedded.
#[sqlx::test(migrations = "../../migrations")]
async fn a_merge_of_private_claims_is_embedded(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");
    let agent = server.server_agent_id().await.expect("server agent");
    let group = *epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("viewer")
        .writable_groups()
        .first()
        .expect("a writable group");

    let mut sources = Vec::new();
    for text in [
        "a private claim, first wording",
        "a private claim, second wording",
    ] {
        let id = Uuid::new_v4();
        let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id) \
             VALUES ($1, $2, $3, 0.6, $4, true, 'group', $5)",
        )
        .bind(id)
        .bind(text)
        .bind(&hash)
        .bind(agent)
        .bind(group)
        .execute(&pool)
        .await
        .expect("private source claim");
        sources.push(id.to_string());
    }

    let result = epigraph_mcp::tools::consolidate::consolidate_claims(
        &server,
        &viewer,
        ConsolidateClaimsParams {
            source_claim_ids: sources,
            merged_content: "a private claim, merged".to_string(),
            mode: "merge".to_string(),
            reason: "two wordings of one claim".to_string(),
            confidence: None,
        },
        None,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("the author merges its own private claims");
    let body = common::first_text(&result);
    let merged: Uuid = body["merged_claim_id"]
        .as_str()
        .expect("merged_claim_id")
        .parse()
        .expect("uuid");

    let (visibility, has_embedding): (String, bool) =
        sqlx::query_as("SELECT visibility, embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(merged)
            .fetch_one(&pool)
            .await
            .expect("merged claim");
    assert_eq!(
        visibility, "group",
        "fixture: the merged claim is private: {body}"
    );
    assert!(
        has_embedding,
        "the merged claim is current and must be embedded even though it is not public: {body}"
    );
}
