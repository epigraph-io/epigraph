//! K12a (supersede SPEC section 11 phase 1 K12 (a), ruling R-132) on the
//! hierarchical ingest: no generic writer creates a `supersedes` edge, in any
//! spelling.
//!
//! An extraction's `relationships[]` names a caller-chosen relationship
//! between two of its own paths, and both plan builders copy it verbatim into
//! the plan the walks INSERT (`document::builder::build_ingest_plan`,
//! `workflow::builder::build_ingest_plan`). Before this, nothing refused
//! `supersedes`, so an ingest wrote a lineage edge that retires nothing. Each
//! entry point now refuses the whole ingest before any write, as the caller's
//! payload error naming the act: the two detached document handlers
//! (`ingest_document_inline`, the file-path `ingest_document`) before the
//! `papers` row and the `queued` answer, the document cores
//! (`do_ingest_document`, which the CLI binary also calls, and
//! `do_ingest_document_spine`), and `ingest_workflow`.
//!
//! Each test has a CONTROL with `supports`, the same paths, that lands, so the
//! refusal is the relationship and nothing else. The HTTP workflow ingest is
//! pinned in `epigraph-api/tests/workflow_ingest_refuses_supersedes_http.rs`.
//!
//! Deliberately does NOT use `tests/common`'s claim helpers (it DROPs
//! `uq_claims_content_hash_agent`); only its server builder.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::build_scoped_test_server;
use epigraph_auth::{AuthContext, ClientType};
use epigraph_ingest::document::schema::DocumentExtraction;
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::errors::McpError;
use epigraph_mcp::tools;
use epigraph_mcp::tools::ingestion::{
    do_ingest_document, do_ingest_document_spine, ingest_document, ingest_document_inline,
};
use epigraph_mcp::types::{IngestDocumentInlineParams, IngestDocumentParams, IngestWorkflowParams};
use epigraph_mcp::EpiGraphMcpFull;
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

/// The shared refusal's words (`epigraph_core::edge::relationships::SUPERSEDES_ACT_ONLY`).
const ACT_ONLY: &str = "written only by the supersession act";

const SPELLINGS: [&str; 3] = ["supersedes", "SUPERSEDES", "Supersedes"];

async fn server(pool: &PgPool) -> EpiGraphMcpFull {
    build_scoped_test_server(pool.clone(), fixture::scoped_pool(pool).await)
}

/// A two-paragraph document whose one relationship is `relationship`, from
/// the second paragraph to the first (the spine writes paragraph edges too).
fn document(tag: &str, relationship: &str) -> DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {
            "title": format!("k12a ingest {tag}"),
            "doi": doi(tag),
            "source_type": "Paper",
            "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("k12a ingest {tag}: the thesis."),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": format!("k12a ingest {tag} section"),
            "paragraphs": [{
                "text": format!("k12a ingest {tag}: the first paragraph."),
                "atoms": [format!("k12a ingest {tag}: the first atom.")],
                "generality": [1],
                "confidence": 0.9
            }, {
                "text": format!("k12a ingest {tag}: the second paragraph."),
                "atoms": [format!("k12a ingest {tag}: the second atom.")],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        "relationships": [{
            "source_path": "sections/0/paragraphs/1",
            "target_path": "sections/0/paragraphs/0",
            "relationship": relationship
        }]
    }))
    .expect("fixture parses")
}

fn doi(tag: &str) -> String {
    format!("10.9999/k12a-ingest-{tag}")
}

async fn papers_with_doi(pool: &PgPool, doi: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM papers WHERE doi = $1")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("count papers")
}

/// Claims whose content carries `tag`'s marker.
async fn claims_tagged(pool: &PgPool, marker: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE content LIKE $1")
        .bind(format!("{marker}%"))
        .fetch_one(pool)
        .await
        .expect("count claims")
}

/// Edges of `relationship` in any spelling, anywhere.
async fn edges_spelled(pool: &PgPool, relationship: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM edges WHERE lower(relationship) = lower($1)")
        .bind(relationship)
        .fetch_one(pool)
        .await
        .expect("count edges")
}

/// The refusal is the caller's payload error naming the act and the
/// offending relationship spelling.
fn assert_refused(err: &McpError, spelling: &str, what: &str) {
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "{what}: {err:?}");
    assert!(
        err.message.contains(ACT_ONLY) && err.message.contains(spelling),
        "{what}: the refusal names the act and the spelling: {err:?}"
    );
}

/// The document refusal wrote nothing: no papers row, no claim, no lineage edge.
async fn assert_document_wrote_nothing(pool: &PgPool, tag: &str, what: &str) {
    assert_eq!(
        papers_with_doi(pool, &doi(tag)).await,
        0,
        "{what}: no papers row"
    );
    assert_eq!(
        claims_tagged(pool, &format!("k12a ingest {tag}")).await,
        0,
        "{what}: no claim"
    );
    assert_eq!(
        edges_spelled(pool, "supersedes").await,
        0,
        "{what}: no lineage edge"
    );
}

/// The inline handler answers `queued` and walks detached, so the refusal
/// must come from the handler, synchronously, before the `papers` row: a
/// refusal inside the walk would reach only the server log.
#[sqlx::test(migrations = "../../migrations")]
async fn an_inline_ingest_relationship_of_supersedes_is_refused_before_the_paper_node(
    pool: PgPool,
) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server(&pool).await;

    let ok = ingest_document_inline(
        &server,
        &viewer,
        IngestDocumentInlineParams {
            extraction: document("inline-control", "supports"),
            wait: None,
            visibility: Some("public".to_string()),
            group_id: None,
        },
        None,
    )
    .await
    .expect("CONTROL: a supports relationship is accepted");
    let ok_json = common::first_text(&ok);
    assert_eq!(ok_json["status"], "queued", "CONTROL: {ok_json}");
    assert_eq!(
        papers_with_doi(&pool, &doi("inline-control")).await,
        1,
        "CONTROL: the handler wrote its papers row"
    );

    for (i, spelling) in SPELLINGS.iter().enumerate() {
        let tag = format!("inline-{i}");
        let err = ingest_document_inline(
            &server,
            &viewer,
            IngestDocumentInlineParams {
                extraction: document(&tag, spelling),
                wait: None,
                visibility: Some("public".to_string()),
                group_id: None,
            },
            None,
        )
        .await
        .expect_err("a supersedes relationship is refused by the handler, not queued");
        assert_refused(&err, spelling, spelling);
        assert_document_wrote_nothing(&pool, &tag, spelling).await;
    }

    // Let the control's detached walk finish before teardown.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
}

/// A fixture file under the current directory (the file-path handler refuses
/// a path outside it), removed on drop.
struct CwdFixture(std::path::PathBuf);

impl CwdFixture {
    fn write(extraction: &DocumentExtraction) -> Self {
        let path = std::env::current_dir()
            .expect("current dir")
            .join(format!("k12a-ingest-fixture-{}.json", Uuid::new_v4()));
        std::fs::write(
            &path,
            serde_json::to_string(extraction).expect("serialize fixture"),
        )
        .expect("write fixture");
        Self(path)
    }

    fn params(&self) -> IngestDocumentParams {
        IngestDocumentParams {
            wait: None,
            file_path: self.0.display().to_string(),
            visibility: Some("public".to_string()),
            group_id: None,
        }
    }
}

impl Drop for CwdFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The file-path handler is the second detached entry point, with its own
/// synchronous check.
#[sqlx::test(migrations = "../../migrations")]
async fn a_file_path_ingest_relationship_of_supersedes_is_refused_before_the_paper_node(
    pool: PgPool,
) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server(&pool).await;

    let ok_file = CwdFixture::write(&document("file-control", "supports"));
    let ok = ingest_document(&server, &viewer, ok_file.params(), None)
        .await
        .expect("CONTROL: a supports relationship is accepted from a file");
    assert_eq!(common::first_text(&ok)["status"], "queued", "CONTROL");
    assert_eq!(
        papers_with_doi(&pool, &doi("file-control")).await,
        1,
        "CONTROL: the handler wrote its papers row"
    );

    let bad_file = CwdFixture::write(&document("file-refused", "SUPERSEDES"));
    let err = ingest_document(&server, &viewer, bad_file.params(), None)
        .await
        .expect_err("a supersedes relationship is refused by the handler, not queued");
    assert_refused(&err, "SUPERSEDES", "file path");
    assert_document_wrote_nothing(&pool, "file-refused", "file path").await;

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
}

/// The document core, which `wait: true` and the `ingest_document` CLI binary
/// run: it refuses on its own, before any write.
#[sqlx::test(migrations = "../../migrations")]
async fn the_document_core_refuses_a_supersedes_relationship_and_writes_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server(&pool).await;

    for (i, spelling) in SPELLINGS.iter().enumerate() {
        let tag = format!("core-{i}");
        let err = do_ingest_document(
            &server,
            &viewer,
            &document(&tag, spelling),
            None,
            epigraph_core::VisibilityChoice::Public,
        )
        .await
        .expect_err("the core refuses a supersedes relationship");
        assert_refused(&err, spelling, spelling);
        assert_document_wrote_nothing(&pool, &tag, spelling).await;
    }

    do_ingest_document(
        &server,
        &viewer,
        &document("core-control", "supports"),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("CONTROL: the same document with supports ingests");
    assert!(
        edges_spelled(&pool, "supports").await >= 1,
        "CONTROL: the relationship edge was written"
    );
}

/// The spine core runs in the request and writes the plan's paragraph edges.
#[sqlx::test(migrations = "../../migrations")]
async fn the_spine_refuses_a_supersedes_relationship_and_writes_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server(&pool).await;

    for (i, spelling) in SPELLINGS.iter().enumerate() {
        let tag = format!("spine-{i}");
        let err = do_ingest_document_spine(
            &server,
            &viewer,
            &document(&tag, spelling),
            None,
            epigraph_core::VisibilityChoice::Public,
        )
        .await
        .expect_err("the spine refuses a supersedes relationship");
        assert_refused(&err, spelling, spelling);
        assert_document_wrote_nothing(&pool, &tag, spelling).await;
    }

    do_ingest_document_spine(
        &server,
        &viewer,
        &document("spine-control", "supports"),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("CONTROL: the same spine with supports ingests");
    assert!(
        edges_spelled(&pool, "supports").await >= 1,
        "CONTROL: the relationship edge was written"
    );
}

fn token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type: ClientType::Human,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

/// A one-phase, two-step workflow whose one relationship is `relationship`,
/// from the second step to the first.
fn workflow(canonical: &str, relationship: &str) -> WorkflowExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {
            "canonical_name": canonical,
            "goal": format!("k12a workflow {canonical}: the goal"),
            "generation": 0,
            "authors": []
        },
        "thesis": format!("k12a workflow {canonical}: the thesis"),
        "thesis_derivation": "TopDown",
        "phases": [{
            "title": "Body",
            "summary": format!("k12a workflow {canonical}: the phase"),
            "steps": [{
                "compound": format!("k12a workflow {canonical}: the first step"),
                "rationale": "because",
                "operations": [],
                "generality": [1],
                "confidence": 0.7
            }, {
                "compound": format!("k12a workflow {canonical}: the second step"),
                "rationale": "because",
                "operations": [],
                "generality": [1],
                "confidence": 0.7
            }]
        }],
        "relationships": [{
            "source_path": "phases/0/steps/1",
            "target_path": "phases/0/steps/0",
            "relationship": relationship
        }]
    }))
    .expect("workflow fixture parses")
}

async fn workflows_named(pool: &PgPool, canonical: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = $1")
        .bind(canonical)
        .fetch_one(pool)
        .await
        .expect("count workflows")
}

/// MCP `ingest_workflow` refuses the whole ingest before its stamped
/// transaction: no workflows row, no claim, no lineage edge.
#[sqlx::test(migrations = "../../migrations")]
async fn an_ingest_workflow_relationship_of_supersedes_is_refused(pool: PgPool) {
    let server = server(&pool).await;
    let (h, _) = fixture::seed_human_operator(&pool, "k12a-wf").await;
    let auth = token(h);
    let viewer = tools::viewer::request_viewer(&server, Some(&auth))
        .await
        .expect("HTTP viewer");

    for (i, spelling) in SPELLINGS.iter().enumerate() {
        let canonical = format!("k12a-wf-{i}");
        let err = tools::workflow_ingest::ingest_workflow(
            &server,
            &viewer,
            IngestWorkflowParams {
                extraction: workflow(&canonical, spelling),
                tenancy: None,
                embed: Some(false),
            },
            Some(&auth),
        )
        .await
        .expect_err("a supersedes relationship is refused");
        assert_refused(&err, spelling, spelling);
        assert_eq!(
            workflows_named(&pool, &canonical).await,
            0,
            "{spelling}: no row"
        );
        assert_eq!(
            claims_tagged(&pool, &format!("k12a workflow {canonical}:")).await,
            0,
            "{spelling}: no claim"
        );
        assert_eq!(
            edges_spelled(&pool, "supersedes").await,
            0,
            "{spelling}: no lineage edge"
        );
    }

    tools::workflow_ingest::ingest_workflow(
        &server,
        &viewer,
        IngestWorkflowParams {
            extraction: workflow("k12a-wf-control", "supports"),
            tenancy: None,
            embed: Some(false),
        },
        Some(&auth),
    )
    .await
    .expect("CONTROL: the same workflow with supports ingests");
    assert_eq!(
        workflows_named(&pool, "k12a-wf-control").await,
        1,
        "CONTROL"
    );
    assert!(
        edges_spelled(&pool, "supports").await >= 1,
        "CONTROL: the relationship edge was written"
    );
}
