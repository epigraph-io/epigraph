//! Every MCP tool that files evidence stores the evidence's edge to its claim
//! (backlog 2d60f619; operator ruling: the Atlas leaf view draws stored
//! `evidence -> claim` edges only, so every evidence filing names a claim and
//! writes the edge).
//!
//! Each test goes through the real tool, then reads back EVERY evidence row it
//! filed and asserts, per row: exactly one edge to the row's claim, with the
//! relationship of the direction the caller gave (`supports` / `refutes`, the
//! canonical lower-case spelling), the evidence row's visibility (and its
//! owner, when it is not public), and a verifying attestation by the
//! server's key.
//!
//! The tools that file evidence on a claim they create themselves
//! (`submit_claim`, `batch_submit_claims`, `memorize`, both document ingests)
//! cannot be handed "no claim". The two that take a caller's claim
//! (`update_with_evidence`, `report_workflow_outcome`) refuse an unknown one
//! and write nothing.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_db::repos::EdgeSignatureRepository;
use epigraph_mcp::tools;
use epigraph_mcp::types::{
    BatchSubmitClaimsParams, MemorizeParams, ReportWorkflowOutcomeParams, StepExecution,
    SubmitClaimParams, UpdateWithEvidenceParams,
};
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

async fn server(pool: &PgPool) -> EpiGraphMcpFull {
    build_scoped_test_server(pool.clone(), fixture::scoped_pool(pool).await)
}

/// The key every `build_scoped_test_server` signs with.
async fn server_signer(pool: &PgPool) -> Uuid {
    let pk = AgentSigner::from_bytes(&[0xA7u8; 32])
        .expect("signer")
        .public_key();
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(pk.as_slice())
        .fetch_one(pool)
        .await
        .expect("the server's signer agent")
}

/// `(evidence id, claim id, owner, visibility)` of every evidence row on
/// `claims`.
async fn evidence_on(pool: &PgPool, claims: &[Uuid]) -> Vec<(Uuid, Uuid, Uuid, String)> {
    sqlx::query_as(
        "SELECT id, claim_id, owner_group_id, visibility::text FROM evidence \
          WHERE claim_id = ANY($1) ORDER BY id",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("evidence rows")
}

/// Every evidence row on `claims` (at least `min_rows`) has exactly one edge
/// to its own claim, with `relationship`, its own tenancy, attested by the
/// server.
async fn assert_every_evidence_edge(
    pool: &PgPool,
    tool: &str,
    claims: &[Uuid],
    relationship: &str,
    min_rows: usize,
) {
    let rows = evidence_on(pool, claims).await;
    assert!(
        rows.len() >= min_rows,
        "{tool}: expected at least {min_rows} evidence row(s), found {rows:?}"
    );
    let signer = server_signer(pool).await;
    let (_scoped, viewer) = fixture::bypass(pool).await;
    for (ev, claim, owner, vis) in rows {
        let edges: Vec<(Uuid, Uuid, String, Uuid, String)> = sqlx::query_as(
            "SELECT id, target_id, relationship, owner_group_id, visibility::text \
               FROM edges WHERE source_type = 'evidence' AND source_id = $1",
        )
        .bind(ev)
        .fetch_all(pool)
        .await
        .expect("edges");
        assert_eq!(
            edges.len(),
            1,
            "{tool}: evidence {ev} has exactly one edge: {edges:?}"
        );
        let (edge, target, rel, e_owner, e_vis) = edges[0].clone();
        assert_eq!(
            (target, rel.as_str()),
            (claim, relationship),
            "{tool}: evidence {ev}"
        );
        // The meet of the endpoints (the edges trigger): never wider than the
        // evidence row, and a non-public row's edge is owned exactly as the
        // row. Between two PUBLIC endpoints migration 120 (D8) owns the edge
        // by the writing session's group, so only its visibility is pinned.
        assert_eq!(e_vis, vis, "{tool}: the edge is as visible as its evidence");
        if vis != "public" {
            assert_eq!(e_owner, owner, "{tool}: a private edge has its row's owner");
        }
        let mut conn = pool.acquire().await.expect("conn");
        let check = EdgeSignatureRepository::verify_conn(&mut conn, &viewer, edge)
            .await
            .expect("verify")
            .expect("readable");
        assert!(
            check.signed && check.signature_valid && check.signer_id == Some(signer),
            "{tool}: evidence edge {edge} attested by the server: {check:?}"
        );
    }
}

async fn claim_by_content(pool: &PgPool, content: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("claim row")
}

fn submit_params(content: &str) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.to_string(),
        evidence_data: format!("evidence for {content}"),
        evidence_type: "empirical".to_string(),
        methodology: "bayesian".to_string(),
        confidence: 0.7,
        source_url: None,
        reasoning: None,
        labels: vec![],
        novelty_threshold: None,
        visibility: Some("public".to_string()),
        group_id: None,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_and_batch_submit_store_a_supports_edge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server(&pool).await;
    let content = format!("2d60f619 submit {}", Uuid::new_v4());
    tools::claims::submit_claim(&server, &viewer, submit_params(&content), None)
        .await
        .expect("submit_claim");
    let claim = claim_by_content(&pool, &content).await;
    assert_every_evidence_edge(&pool, "submit_claim", &[claim], "supports", 1).await;

    let a = format!("2d60f619 batch a {}", Uuid::new_v4());
    let b = format!("2d60f619 batch b {}", Uuid::new_v4());
    let params: BatchSubmitClaimsParams = serde_json::from_value(serde_json::json!({
        "claims": [
            {"content": a, "evidence_data": "batch evidence a", "evidence_type": "empirical",
             "visibility": "public"},
            {"content": b, "evidence_data": "batch evidence b", "evidence_type": "empirical",
             "visibility": "public"}
        ]
    }))
    .expect("batch params");
    tools::batch::batch_submit_claims(&server, &viewer, params, None)
        .await
        .expect("batch_submit_claims");
    let claims = [
        claim_by_content(&pool, &a).await,
        claim_by_content(&pool, &b).await,
    ];
    assert_every_evidence_edge(&pool, "batch_submit_claims", &claims, "supports", 2).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn memorize_stores_a_supports_edge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server(&pool).await;
    let content = format!("2d60f619 memorize {}", Uuid::new_v4());
    tools::memory::memorize(
        &server,
        &viewer,
        MemorizeParams {
            content: content.clone(),
            confidence: Some(0.7),
            tags: None,
            novelty_threshold: None,
            visibility: Some("public".to_string()),
            group_id: None,
        },
        None,
    )
    .await
    .expect("memorize");
    let claim = claim_by_content(&pool, &content).await;
    assert_every_evidence_edge(&pool, "memorize", &[claim], "supports", 1).await;
}

fn uwe(claim: &str, supports: bool) -> UpdateWithEvidenceParams {
    UpdateWithEvidenceParams {
        canonical_name: None,
        step_index: None,
        claim_id: claim.to_string(),
        evidence_type: "empirical".to_string(),
        evidence_data: format!("2d60f619 evidence, supports={supports}"),
        source_url: None,
        supports,
        strength: 0.8,
        labels: vec![],
    }
}

/// The direction the caller gives is the edge's relationship, and a claim
/// that does not exist is refused with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_stores_the_callers_direction_and_refuses_no_claim(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server(&pool).await;
    let against = seed_claim(&pool, &format!("2d60f619 against {}", Uuid::new_v4()), 0.5).await;
    let for_ = seed_claim(&pool, &format!("2d60f619 for {}", Uuid::new_v4()), 0.5).await;
    tools::claims::update_with_evidence(&server, &viewer, uwe(&against.to_string(), false), None)
        .await
        .expect("evidence against");
    tools::claims::update_with_evidence(&server, &viewer, uwe(&for_.to_string(), true), None)
        .await
        .expect("evidence for");
    assert_every_evidence_edge(&pool, "update_with_evidence", &[against], "refutes", 1).await;
    assert_every_evidence_edge(&pool, "update_with_evidence", &[for_], "supports", 1).await;

    let counts = || async {
        let ev: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence")
            .fetch_one(&pool)
            .await
            .expect("count");
        let ed: i64 = sqlx::query_scalar("SELECT count(*) FROM edges")
            .fetch_one(&pool)
            .await
            .expect("count");
        (ev, ed)
    };
    let before = counts().await;
    let refused = tools::claims::update_with_evidence(
        &server,
        &viewer,
        uwe(&Uuid::new_v4().to_string(), true),
        None,
    )
    .await;
    assert!(refused.is_err(), "evidence on no claim is refused");
    assert_eq!(counts().await, before, "and writes nothing");
}

#[sqlx::test(migrations = "../../migrations")]
async fn report_workflow_outcome_stores_the_outcomes_direction(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = server(&pool).await;
    for (success, rel) in [(false, "refutes"), (true, "supports")] {
        let wf = seed_workflow_claim(
            &pool,
            &format!("2d60f619 workflow {success} {}", Uuid::new_v4()),
            &["s1"],
        )
        .await;
        tools::workflows::report_workflow_outcome(
            &server,
            &viewer,
            ReportWorkflowOutcomeParams {
                workflow_id: wf.to_string(),
                success,
                execution_log: vec![StepExecution {
                    step_index: 0,
                    planned: "s1".to_string(),
                    actual: "s1".to_string(),
                    deviated: false,
                    deviation_reason: None,
                }],
                outcome_details: "ran".to_string(),
                quality: Some(0.8),
                goal_text: None,
            },
            None,
        )
        .await
        .expect("report_workflow_outcome");
        assert_every_evidence_edge(&pool, "report_workflow_outcome", &[wf], rel, 1).await;
    }
}

fn extraction(tag: &str) -> epigraph_ingest::schema::DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {
            "title": format!("2d60f619 {tag}: Evidence Edges"),
            "doi": format!("10.9999/2d60f619-{tag}"),
            "source_type": "Paper",
            "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("2d60f619 {tag}: ingested evidence carries its edge."),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Methods",
            "paragraphs": [{
                "text": format!("2d60f619 {tag}: every evidence row has an edge."),
                "atoms": [format!("2d60f619 {tag}: an atom's evidence has an edge.")],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        "relationships": []
    }))
    .expect("fixture parses")
}

/// Every claim an ingest wrote evidence on.
async fn claims_with_evidence(pool: &PgPool) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT DISTINCT claim_id FROM evidence")
        .fetch_all(pool)
        .await
        .expect("claims with evidence")
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_stores_an_edge_per_evidence_row(pool: PgPool) {
    let server = server(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    tools::ingestion::do_ingest_document(
        &server,
        &viewer,
        &extraction("document"),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("document ingests");
    let claims = claims_with_evidence(&pool).await;
    assert_every_evidence_edge(&pool, "ingest_document", &claims, "supports", 1).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_spine_stores_an_edge_per_evidence_row(pool: PgPool) {
    let server = server(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    tools::ingestion::do_ingest_document_spine(
        &server,
        &viewer,
        &extraction("spine"),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("spine ingests");
    let claims = claims_with_evidence(&pool).await;
    assert_every_evidence_edge(&pool, "ingest_document_spine", &claims, "supports", 1).await;
}
