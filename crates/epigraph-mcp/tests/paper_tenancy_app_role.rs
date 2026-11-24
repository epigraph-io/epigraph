//! A document ingest's `papers` row carries the ingest's tenancy (migration
//! 246, backlog 34864fb5), measured through the MCP read tools on the
//! APPLICATION ROLE.
//!
//! Before 246 `papers` had no row security and an ingest wrote its row on the
//! plain pool with no tenancy, so a `private` (or `team`) ingest scoped its
//! claims but not its paper: any caller's `check_already_ingested` answered
//! `already_ingested: true` with the `paper_id` (the `processed_by` stamp onto
//! a paper was world-owned), and `query_paper` returned the title. And every
//! ingest of a DOI converged on one global row, so a second group's private
//! ingest landed on the first group's paper.
//!
//! Both server pools are `epigraph_app` (row security enforced); the harness
//! superuser only seeds agents and reads rows back for the assertions.
//!
//! * A private ingest: the ingesting member sees the paper as ingested and
//!   reads its title; a stranger gets `already_ingested: false`, no
//!   `paper_id`, and an empty `query_paper`, exactly as for an unknown DOI.
//! * Two agents' private ingests of one DOI give two rows; their public
//!   ingests share one (the control: a public ingest behaves as before).
//! * The queued entry point's walk writes the row with the ingest's tenancy
//!   too, under the random id its answer announced.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_core::VisibilityChoice;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_ingest::document::schema::DocumentExtraction;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools;
use epigraph_mcp::tools::ingestion::do_ingest_document;
use epigraph_mcp::types::{
    CheckAlreadyIngestedParams, IngestDocumentInlineParams, QueryPaperParams,
};
use rmcp::model::{CallToolResult, ContentBlock};
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x46; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(vec![0.01_f32; 1536])));
    EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false).with_scoped_pool(scoped)
}

/// An HTTP caller token naming `agent`, as `oauth/token.rs` mints one.
fn caller_token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Agent,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

fn extraction(doi: &str, title: &str) -> DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {"title": title, "doi": doi, "source_type": "Paper", "authors": []},
        "thesis": format!("Paper tenancy thesis {title}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Paper tenancy paragraph {title}"),
            "atoms": [format!("Paper tenancy atom {title}")],
            "generality": [3], "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction")
}

fn json_of(result: &CallToolResult) -> serde_json::Value {
    match result.content.first().expect("content") {
        ContentBlock::Text(t) => serde_json::from_str(&t.text).expect("json"),
        other => panic!("expected text, got {other:?}"),
    }
}

async fn checked(server: &EpiGraphMcpFull, viewer: &Viewer, doi: &str) -> serde_json::Value {
    json_of(
        &tools::ingestion::check_already_ingested(
            server,
            viewer,
            CheckAlreadyIngestedParams {
                doi: doi.to_string(),
                pipeline_version: None,
            },
        )
        .await
        .map_err(|e| e.message.to_string())
        .expect("check_already_ingested"),
    )
}

async fn queried(server: &EpiGraphMcpFull, viewer: &Viewer, doi: &str) -> serde_json::Value {
    json_of(
        &tools::paper_queries::query_paper(
            server,
            viewer,
            QueryPaperParams {
                doi: doi.to_string(),
                limit: None,
                offset: None,
                ingested_by: None,
            },
        )
        .await
        .map_err(|e| e.message.to_string())
        .expect("query_paper"),
    )
}

/// Ingest `doi` as `agent` (its own token and viewer), in the request.
async fn ingest_as(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    agent: Uuid,
    doi: &str,
    title: &str,
    choice: VisibilityChoice,
) -> Viewer {
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    let token = caller_token(agent);
    do_ingest_document(
        server,
        &viewer,
        &extraction(doi, title),
        Some(&token),
        choice,
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("ingest");
    viewer
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_ingests_paper_is_invisible_to_a_stranger(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (member, _) = fixture::seed_agent_with_group(&pool, "paper-member").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "paper-stranger").await;
    let stranger = Viewer::resolve(&pool, stranger).await.expect("stranger");

    // The control: a PUBLIC ingest is seen by everyone, as before 246.
    let public_doi = "10.9999/paper-tenancy-public";
    let m = ingest_as(
        &pool,
        &server,
        member,
        public_doi,
        "Open Paper",
        VisibilityChoice::Public,
    )
    .await;
    assert_eq!(
        checked(&server, &m, public_doi).await["already_ingested"],
        true
    );
    let open = checked(&server, &stranger, public_doi).await;
    assert_eq!(
        open["already_ingested"], true,
        "control: a public ingest is visible to a stranger; if this fails the fixture is broken"
    );
    assert_eq!(
        queried(&server, &stranger, public_doi).await["title"],
        "Open Paper"
    );

    // The defect: a PRIVATE ingest.
    let doi = "10.9999/paper-tenancy-private";
    let m = ingest_as(
        &pool,
        &server,
        member,
        doi,
        "Confidential Paper",
        VisibilityChoice::Private,
    )
    .await;
    let own = checked(&server, &m, doi).await;
    assert_eq!(
        own["already_ingested"], true,
        "the member sees its own ingest"
    );
    assert!(own["paper_id"].is_string());
    assert_eq!(
        queried(&server, &m, doi).await["title"],
        "Confidential Paper"
    );

    let seen = checked(&server, &stranger, doi).await;
    assert_eq!(
        seen["already_ingested"], false,
        "a stranger must not learn that a privately ingested document exists: {seen}"
    );
    assert!(
        seen["paper_id"].is_null(),
        "a stranger must not get the private paper's id: {seen}"
    );
    let q = queried(&server, &stranger, doi).await;
    assert_eq!(
        q["title"], "",
        "a stranger's query_paper must answer as for an unknown document: {q}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_private_ingests_of_one_doi_are_two_papers_and_public_ones_share_one(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (a, _) = fixture::seed_agent_with_group(&pool, "paper-a").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "paper-b").await;

    let doi = "10.9999/paper-tenancy-twice";
    // Distinct extractions of one DOI: identical structural text under one
    // title would converge on the same document-scoped CLAIM ids, a separate
    // question from the paper row this file is about.
    let va = ingest_as(
        &pool,
        &server,
        a,
        doi,
        "Title As A Read It",
        VisibilityChoice::Private,
    )
    .await;
    let vb = ingest_as(
        &pool,
        &server,
        b,
        doi,
        "Title As B Read It",
        VisibilityChoice::Private,
    )
    .await;
    let pa = checked(&server, &va, doi).await["paper_id"].clone();
    let pb = checked(&server, &vb, doi).await["paper_id"].clone();
    assert!(
        pa.is_string() && pb.is_string(),
        "each sees its own ingest: {pa} {pb}"
    );
    assert_ne!(
        pa, pb,
        "b's private ingest must get its own paper, not land on a's private row"
    );

    let open = "10.9999/paper-tenancy-open";
    let va = ingest_as(
        &pool,
        &server,
        a,
        open,
        "Open Title",
        VisibilityChoice::Public,
    )
    .await;
    let vb = ingest_as(
        &pool,
        &server,
        b,
        open,
        "Open Title",
        VisibilityChoice::Public,
    )
    .await;
    assert_eq!(
        checked(&server, &va, open).await["paper_id"],
        checked(&server, &vb, open).await["paper_id"],
        "two public ingests of one document share its one public paper"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_queued_entry_point_writes_the_paper_with_the_ingests_tenancy(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let viewer = tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");
    let doi = "10.9999/paper-tenancy-queued";
    let out = json_of(
        &tools::ingestion::ingest_document_inline(
            &server,
            &viewer,
            IngestDocumentInlineParams {
                extraction: extraction(doi, "Queued Paper"),
                wait: Some(false),
                visibility: Some("private".to_string()),
                group_id: None,
            },
            None,
        )
        .await
        .map_err(|e| e.message.to_string())
        .expect("queued ingest"),
    );
    let paper: Uuid = out["paper_id"]
        .as_str()
        .expect("paper_id")
        .parse()
        .expect("uuid");
    // The row is written by the detached walk, on its own transaction
    // (backlog b995f117): nothing is committed before it.
    assert!(
        server
            .background_tasks()
            .wait_idle(std::time::Duration::from_secs(60))
            .await,
        "the detached walk did not finish"
    );
    let rows: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, visibility::text FROM papers WHERE doi = $1")
            .bind(doi)
            .fetch_all(&pool)
            .await
            .expect("paper rows");
    assert_eq!(
        rows,
        vec![(paper, "group".to_string())],
        "one papers row, the group's (not world-readable), under the id the queued answer \
         announced: the walk inserts the private copy under the random id the handler chose"
    );
    assert_ne!(
        paper,
        epigraph_db::repos::paper::public_paper_id(doi),
        "a private copy's id is not derivable from the document key"
    );
}
