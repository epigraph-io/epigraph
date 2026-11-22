//! `deprecate_workflow` answers a ROW-SECURITY refusal of its write as a
//! designed refusal, not an opaque internal error (backlog ab353d54).
//!
//! Since the delegate arm was added, the workflow authority gate admits a
//! DELEGATE: an agent whose live operator link names the workflow's submitter, acting
//! on a live delegated run token. That delegate writes the groups of its own
//! stamp (its own, and its operator's personal group through the link), not
//! necessarily the group that owns the workflow's claims. On a PUBLIC plan
//! those claims pass row security's read side, so the deprecation UPDATE is
//! refused at the claims tenancy policy's WITH CHECK (`42501`, `new row
//! violates row-level security policy`), the transaction aborted and nothing
//! written. The flat path, which has no gate, reaches the same refusal for
//! any caller that reads a public flat workflow claim it does not write.
//!
//! Both arms run on the APPLICATION ROLE (`epigraph_app`, no BYPASSRLS), the
//! only place the refusal exists; seeding runs on the superuser harness.
//!
//! VERIFIED TO FAIL before the fix: both arms answered INTERNAL_ERROR with the
//! redacted "internal error; the detail is in the server log".

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/delegation_fixture.rs"]
mod delegation;

mod common;

use common::{build_scoped_test_server, seed_caller};
use epigraph_auth::{AuthContext, ClientType};
use epigraph_crypto::AgentSigner;
use epigraph_db::{RunTokens, ScopedPool, SessionGucMode};
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools;
use epigraph_mcp::types::{DeprecateWorkflowParams, IngestWorkflowParams};
use epigraph_mcp::{EpiGraphMcpFull, SessionFactory};
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

const REFUSAL: &str = "does not write the group that owns";
const NOTHING_WRITTEN: &str = "Nothing was written";

/// One HTTP session of an APPLICATION-ROLE listener with run tokens on.
async fn app_role_http_session(pool: &PgPool, seed: u8) -> EpiGraphMcpFull {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    let template = EpiGraphMcpFull::new(plain, signer, embedder, false)
        .with_scoped_pool(scoped)
        .with_run_tokens(RunTokens::On);
    SessionFactory::new(template).session()
}

/// The delegated run token `d` issues: principal `d.principal`, acting for
/// its operator through a live link, `dlg = d.delegator`.
fn delegate_token(d: &delegation::Delegation) -> AuthContext {
    AuthContext {
        client_id: d.delegator_client,
        agent_id: Some(d.principal),
        owner_id: None,
        client_type: ClientType::Agent,
        scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        delegated_by: Some(d.delegator),
        admin_scopes: epigraph_auth::AdminScopePosture::Armed,
    }
}

fn extraction(canonical: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("ab353d54 workflow {canonical}"),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: None,
        thesis_derivation: ThesisDerivation::TopDown,
        phases: vec![Phase {
            title: "Body".to_string(),
            summary: format!("ab353d54 phase for {canonical}"),
            steps: vec![Step {
                compound: format!("the one step of {canonical}"),
                rationale: "because".to_string(),
                operations: vec![],
                generality: vec![],
                confidence: 0.7,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

/// A PUBLIC hierarchical workflow whose rows are owned by `writer`'s own
/// group, ingested by `writer` on the harness, and recorded as submitted by
/// `submitter`. Returns the workflow id and the claims it executes.
async fn public_plan(pool: &PgPool, canonical: &str, submitter: Uuid) -> (Uuid, Vec<Uuid>) {
    let harness = build_scoped_test_server(pool.clone(), fixture::scoped_pool(pool).await);
    let (_writer, writer_token, writer_viewer) = seed_caller(pool, &["claims:write"]).await;
    tools::workflow_ingest::ingest_workflow(
        &harness,
        &writer_viewer,
        IngestWorkflowParams {
            extraction: extraction(canonical),
            tenancy: Some(common::public_tenancy_for(&writer_viewer)),
            embed: None,
        },
        Some(&writer_token),
    )
    .await
    .expect("ingest");
    let wf: Uuid = sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1")
        .bind(canonical)
        .fetch_one(pool)
        .await
        .expect("the workflow row");
    sqlx::query(
        "UPDATE workflows SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), \
                '{epigraph_submitted_by}', to_jsonb($2::text)) WHERE id = $1",
    )
    .bind(wf)
    .bind(submitter.to_string())
    .execute(pool)
    .await
    .expect("record the submitter");
    let claims: Vec<Uuid> = sqlx::query_scalar(
        "SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'executes'",
    )
    .bind(wf)
    .fetch_all(pool)
    .await
    .expect("the executed claims");
    assert!(!claims.is_empty(), "the plan executes claims");
    (wf, claims)
}

async fn truth(pool: &PgPool, wf: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(pool)
        .await
        .expect("truth_value")
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("is_current")
}

fn params(id: Uuid) -> DeprecateWorkflowParams {
    DeprecateWorkflowParams {
        workflow_id: id.to_string(),
        reason: "ab353d54".to_string(),
        cascade: Some(false),
    }
}

/// A delegate the gate admits (its live link names the submitter, on a live
/// delegated run token) but that does not write the group owning the
/// workflow's claims gets a coded refusal naming the missing group write, and
/// nothing is written. The refusal is not the gate's: the gate's own text is
/// absent, so the gate admitted the delegate and the write was refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_gate_admitted_delegate_without_group_write_gets_a_designed_refusal(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "deprecate-rls").await;
    let (wf, claims) = public_plan(&pool, "ab353d54-delegate-plan", d.operator).await;
    let server = app_role_http_session(&pool, 0x71).await;
    let viewer = epigraph_db::Viewer::resolve(&pool, d.principal)
        .await
        .expect("the principal's viewer");

    let err = tools::workflows::deprecate_workflow(
        &server,
        &viewer,
        params(wf),
        Some(&delegate_token(&d)),
    )
    .await
    .expect_err("row security refuses the delegate's deprecation");
    let msg = err.message.to_string();
    assert_ne!(
        err.code,
        ErrorCode::INTERNAL_ERROR,
        "a row-security refusal is the caller's, not a server fault: {msg}"
    );
    assert_eq!(err.code, ErrorCode::INVALID_REQUEST, "{msg}");
    assert!(
        msg.contains(REFUSAL) && msg.contains(NOTHING_WRITTEN),
        "names the missing group write: {msg}"
    );
    assert!(
        !msg.contains("was submitted by agent"),
        "the gate admitted the delegate; the refusal is row security's: {msg}"
    );
    assert!(
        (truth(&pool, wf).await - 1.0).abs() < 1e-9,
        "the workflow row is unchanged"
    );
    for c in &claims {
        assert!(is_current(&pool, *c).await, "claim {c} is still current");
    }
}

/// The flat path (no gate): a caller that reads a public flat workflow claim
/// but does not write its owner group gets the same designed refusal, and the
/// claim stays current.
#[sqlx::test(migrations = "../../migrations")]
async fn a_flat_deprecation_refused_by_row_security_is_a_designed_refusal(pool: PgPool) {
    let (author, author_g) = fixture::seed_agent_with_group(&pool, "flat-author").await;
    let flat = Uuid::new_v4();
    let hash: Vec<u8> = flat.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, ARRAY['workflow'], true, 'public', $5)",
    )
    .bind(flat)
    .bind(format!("a flat workflow {flat}"))
    .bind(hash)
    .bind(author)
    .bind(author_g)
    .execute(&pool)
    .await
    .expect("the flat workflow claim");

    let d = delegation::live_delegation(&pool, "deprecate-rls-flat").await;
    let server = app_role_http_session(&pool, 0x72).await;
    let viewer = epigraph_db::Viewer::resolve(&pool, d.principal)
        .await
        .expect("the principal's viewer");
    let err = tools::workflows::deprecate_workflow(
        &server,
        &viewer,
        params(flat),
        Some(&delegate_token(&d)),
    )
    .await
    .expect_err("row security refuses the flat deprecation");
    let msg = err.message.to_string();
    assert_eq!(err.code, ErrorCode::INVALID_REQUEST, "{msg}");
    assert!(
        msg.contains(REFUSAL) && msg.contains(NOTHING_WRITTEN),
        "names the missing group write: {msg}"
    );
    assert!(
        is_current(&pool, flat).await,
        "the flat claim is still current"
    );
}
