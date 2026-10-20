//! MCP `evolve_step` is gated on authority over EVERY workflow that executes
//! the step's lineage, over the authenticated transport (the REST half, on the
//! production pool shape, is `epigraph-api/tests/evolve_step_lineage_authority.rs`).
//!
//! `add_step`, `delete_step` and `deprecate_workflow` require the workflow
//! authority of `tools/workflow_authority.rs` (the submitter, its operator, or
//! the audited `claims:admin` path); `evolve_step` checked none, so any
//! `claims:write` caller could branch or retire a step another caller's
//! workflow executes. These arms pin:
//!
//! * an authenticated stranger is refused, by id and by name, with nothing
//!   written; the submitter is admitted and the write recorded;
//! * an agent bound to the submitting human (allowlisted, through the real HTTP
//!   viewer; live-linked, at the gate) is refused, while the human, the
//!   submitter's operator, is admitted;
//! * the new head, which no workflow executes directly, is still gated;
//! * a server built without a `ScopedPool` gates too;
//! * the audited admin arm is admitted and recorded; a grantless admin is
//!   refused ADM02;
//! * stdio is unchanged (the batch H-b bar, as for the other workflow tools).
//!
//! The decision and the record are Rust-side and data-driven, so the superuser
//! harness observes them faithfully. Whether row security lets the gate SEE
//! the `executes` edges, and admits its provenance rows on the caller's stamp,
//! is the REST file's, on `epigraph_app`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, build_test_server, seed_caller};
use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::AgentRepository;
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::tools;
use epigraph_mcp::tools::evolve_step::EvolveStepParams;
use epigraph_mcp::types::IngestWorkflowParams;
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

const CALLER_WRITE: &str = "workflows.caller_write";
const ADMIN_WRITE: &str = "workflows.admin_write";

fn extraction(canonical: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("workflow-plan goal {canonical}"),
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
            summary: format!("phase of {canonical}"),
            steps: vec![Step {
                compound: format!("first step of {canonical}"),
                rationale: "because".to_string(),
                operations: vec![format!("op of {canonical}")],
                generality: vec![1],
                confidence: 0.7,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

/// A `claims:write` token for `agent` on OAuth client `client_id`.
fn token(agent: Uuid, client_id: Uuid) -> AuthContext {
    AuthContext {
        client_id,
        agent_id: Some(agent),
        owner_id: Some(client_id),
        client_type: ClientType::Agent,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
    }
}

/// Ingest `canonical` as `submitter` over the authenticated transport; returns
/// the workflow id and its level-2 step.
async fn ingest_as(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    canonical: &str,
    viewer: &epigraph_db::visibility::Viewer,
    auth: &AuthContext,
) -> (Uuid, Uuid) {
    tools::workflow_ingest::ingest_workflow(
        server,
        viewer,
        IngestWorkflowParams {
            extraction: extraction(canonical),
        },
        Some(auth),
    )
    .await
    .expect("ingest");
    sqlx::query_as(
        "SELECT w.id, e.target_id FROM workflows w \
           JOIN edges e ON e.source_id = w.id AND e.relationship = 'executes' \
           JOIN claims c ON c.id = e.target_id \
          WHERE w.canonical_name = $1 AND (c.properties->>'level')::int = 2",
    )
    .bind(canonical)
    .fetch_one(pool)
    .await
    .expect("the workflow's step")
}

/// Record `agent` as workflow `wf`'s submitter (harness).
async fn set_submitter(pool: &PgPool, wf: Uuid, agent: Uuid) {
    sqlx::query(
        "UPDATE workflows SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), \
                '{epigraph_submitted_by}', to_jsonb($2::text)) WHERE id = $1",
    )
    .bind(wf)
    .bind(agent.to_string())
    .execute(pool)
    .await
    .expect("record the submitter");
}

fn by_id(parent: Uuid, content: &str, edge_type: &str) -> EvolveStepParams {
    EvolveStepParams {
        parent_id: parent.to_string(),
        canonical_name: None,
        step_index: None,
        step_lineage_id: String::new(),
        content: content.to_string(),
        edge_type: edge_type.to_string(),
        rationale: Some("lineage authority".to_string()),
        level: Some(2),
    }
}

fn by_name(canonical: &str, content: &str) -> EvolveStepParams {
    EvolveStepParams {
        parent_id: String::new(),
        canonical_name: Some(canonical.to_string()),
        step_index: Some(0),
        ..by_id(Uuid::nil(), content, "revises")
    }
}

async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count claims")
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("is_current")
}

async fn evolve_rows(pool: &PgPool, event_type: &str) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT agent_id, details FROM security_events \
          WHERE event_type = $1 AND details->>'action' = 'evolve_step' \
          ORDER BY created_at, id",
    )
    .bind(event_type)
    .fetch_all(pool)
    .await
    .expect("read the evolve_step rows")
}

/// `evolve_step` must be refused with the workflow gate's text naming
/// `workflow`, and write nothing: no claim with the content, the parent still
/// current, no provenance row.
#[allow(clippy::too_many_arguments)]
async fn assert_refused(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    auth: &AuthContext,
    params: EvolveStepParams,
    parent: Uuid,
    workflow: Uuid,
    expect_text: &str,
) {
    let content = params.content.clone();
    let before = evolve_rows(pool, CALLER_WRITE).await.len();
    let err = tools::evolve_step::evolve_step(server, viewer, params, Some(auth))
        .await
        .expect_err("the workflow gate must refuse this evolve");
    let msg = err.message.to_string();
    assert!(msg.contains(expect_text), "{msg}");
    assert!(msg.contains("Nothing was written"), "{msg}");
    assert!(
        msg.contains(&workflow.to_string()),
        "names the workflow: {msg}"
    );
    assert_eq!(claims_with_content(pool, &content).await, 0, "no claim");
    assert!(is_current(pool, parent).await, "the parent is not retired");
    assert_eq!(evolve_rows(pool, CALLER_WRITE).await.len(), before);
}

fn claim_id(res: &rmcp::model::CallToolResult) -> Uuid {
    common::parse_uuid_field(&common::first_text(res), "claim_id")
}

/// A stranger is refused by id (both edge types) and by name; the submitter
/// evolves and the write is recorded; the new head, executed by nothing
/// directly, is still gated against the stranger.
#[sqlx::test(migrations = "../../migrations")]
async fn an_authenticated_stranger_cannot_evolve_an_executed_step(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (owner, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_s, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (wf, step) = ingest_as(
        &server,
        &pool,
        "acme-mcp-evolve",
        &owner_viewer,
        &owner_token,
    )
    .await;

    for edge_type in ["supersedes", "revises"] {
        assert_refused(
            &server,
            &pool,
            &stranger_viewer,
            &stranger_token,
            by_id(step, &format!("a stranger's {edge_type}"), edge_type),
            step,
            wf,
            "was submitted by agent",
        )
        .await;
    }
    assert_refused(
        &server,
        &pool,
        &stranger_viewer,
        &stranger_token,
        by_name("acme-mcp-evolve", "a stranger's revision by name"),
        step,
        wf,
        "was submitted by agent",
    )
    .await;

    let res = tools::evolve_step::evolve_step(
        &server,
        &owner_viewer,
        by_id(step, "the submitter's revision", "supersedes"),
        Some(&owner_token),
    )
    .await
    .expect("the submitter evolves its own step");
    let head = claim_id(&res);
    let rows = evolve_rows(&pool, CALLER_WRITE).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0].1;
    assert_eq!(d["workflow_id"], wf.to_string(), "{d}");
    assert_eq!(d["arm"], "submitter", "{d}");
    assert_eq!(d["acting_agent"], owner.to_string(), "{d}");
    assert_eq!(d["client_id"], owner_token.client_id.to_string(), "{d}");
    assert_eq!(d["write"]["parent_claim_id"], step.to_string(), "{d}");
    assert_eq!(d["write"]["claim_id"], head.to_string(), "{d}");

    assert_refused(
        &server,
        &pool,
        &stranger_viewer,
        &stranger_token,
        by_id(head, "a stranger's evolve of the new head", "supersedes"),
        head,
        wf,
        "was submitted by agent",
    )
    .await;
}

/// The operator ruling (2026-10-13) applies to `evolve_step`: on a workflow
/// whose submitter is a live-linked agent S of the human H, H is admitted
/// through the operator arm; an allowlisted agent bound to H and the
/// live-linked agent L of H (not the submitter) are refused.
#[sqlx::test(migrations = "../../migrations")]
async fn bound_agents_are_refused_and_the_submitters_operator_is_admitted(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (h, _) = fixture::seed_human_operator(&pool, "workflow-plan-human").await;
    let link = |label: &'static str| {
        let pool = pool.clone();
        async move {
            let (agent, _) = fixture::seed_agent_with_group(&pool, label).await;
            let mut conn = pool.acquire().await.expect("acquire");
            let out = AgentRepository::link_operator(&mut conn, agent, h)
                .await
                .expect("link");
            assert!(out.membership_live && out.link_live, "calibration: {out:?}");
            agent
        }
    };
    let s = link("workflow-plan-submitter").await;
    let l = link("workflow-plan-linked").await;
    let (_i, ingester_token, ingester_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (wf, step) = ingest_as(
        &server,
        &pool,
        "acme-mcp-evolve-bound",
        &ingester_viewer,
        &ingester_token,
    )
    .await;
    set_submitter(&pool, wf, s).await;

    // Allowlisted service client bound to H (migration 149, arm (c)).
    let (bound, _) = fixture::seed_agent_with_group(&pool, "workflow-plan-bound").await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'bound agent', 'service', ARRAY['claims:write'], 'active', $2, \
                 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("bound-agent-{bound}"))
    .bind(bound)
    .fetch_one(&pool)
    .await
    .expect("the bound agent's client");
    let binding: Option<String> =
        fixture::as_role(&pool, "epigraph_maintenance", |mut c| async move {
            let b = sqlx::query_scalar(
                "SELECT effective_binding \
                   FROM public.epigraph_allow_author_binding_client($1, $2, 'test')",
            )
            .bind(client)
            .bind(h)
            .fetch_one(&mut *c)
            .await
            .expect("allow the bound agent's client");
            (c, b)
        })
        .await;
    assert_eq!(
        binding.as_deref(),
        Some(epigraph_db::CLIENT_ALLOWLIST_BINDING),
        "calibration: bound to H"
    );
    let b_auth = token(bound, client);
    let b_viewer = tools::viewer::request_viewer(&server, Some(&b_auth))
        .await
        .expect("an allowlisted caller resolves an HTTP viewer");
    assert_refused(
        &server,
        &pool,
        &b_viewer,
        &b_auth,
        by_id(step, "the bound agent's revision", "revises"),
        step,
        wf,
        "was submitted by agent",
    )
    .await;
    let l_auth = token(l, Uuid::new_v4());
    let l_viewer = epigraph_db::visibility::Viewer::resolve(&pool, l)
        .await
        .expect("viewer");
    assert_refused(
        &server,
        &pool,
        &l_viewer,
        &l_auth,
        by_id(step, "the linked agent's revision", "revises"),
        step,
        wf,
        "was submitted by agent",
    )
    .await;

    let h_auth = token(h, Uuid::new_v4());
    let h_viewer = tools::viewer::request_viewer(&server, Some(&h_auth))
        .await
        .expect("H's viewer");
    tools::evolve_step::evolve_step(
        &server,
        &h_viewer,
        by_id(step, "the operator's revision", "revises"),
        Some(&h_auth),
    )
    .await
    .expect("the submitter's operator evolves the step");
    let rows = evolve_rows(&pool, CALLER_WRITE).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0].1;
    assert_eq!(d["arm"], "operator", "{d}");
    assert_eq!(d["operator"], h.to_string(), "{d}");
    assert_eq!(d["submitter"], s.to_string(), "{d}");
}

/// A server with no `ScopedPool` (the raw-pool branch of the tool) gates the
/// authenticated transport the same way.
#[sqlx::test(migrations = "../../migrations")]
async fn a_server_without_a_scoped_pool_still_gates(pool: PgPool) {
    let scoped = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_o, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (wf, step) = ingest_as(
        &scoped,
        &pool,
        "acme-mcp-evolve-raw",
        &owner_viewer,
        &owner_token,
    )
    .await;
    let raw = build_test_server(pool.clone());
    let (_s, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    assert_refused(
        &raw,
        &pool,
        &stranger_viewer,
        &stranger_token,
        by_id(step, "a stranger's revision on the raw pool", "supersedes"),
        step,
        wf,
        "was submitted by agent",
    )
    .await;
}

/// The audited admin arm: a live `claims:admin` grant is admitted and the
/// write records one `workflows.admin_write` row; the same scope with no
/// client grant is refused ADM02 with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_arm_is_audited_and_a_grantless_admin_is_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_o, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (wf, step) = ingest_as(
        &server,
        &pool,
        "acme-mcp-evolve-admin",
        &owner_viewer,
        &owner_token,
    )
    .await;

    let (grantless, grantless_viewer) = common::server_admin(&server).await;
    assert_refused(
        &server,
        &pool,
        &grantless_viewer,
        &grantless,
        by_id(step, "a grantless admin's revision", "revises"),
        step,
        wf,
        "ADM02",
    )
    .await;
    assert!(evolve_rows(&pool, ADMIN_WRITE).await.is_empty());

    let (admin, admin_viewer) = common::granted_server_admin(&server, &pool).await;
    let res = tools::evolve_step::evolve_step(
        &server,
        &admin_viewer,
        by_id(step, "the admin's revision", "revises"),
        Some(&admin),
    )
    .await
    .expect("the audited admin path");
    let rows = evolve_rows(&pool, ADMIN_WRITE).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (agent, d) = &rows[0];
    assert_eq!(*agent, admin.agent_id, "the audit row names the admin: {d}");
    assert_eq!(d["workflow_id"], wf.to_string(), "{d}");
    assert_eq!(d["write"]["claim_id"], claim_id(&res).to_string(), "{d}");
    assert!(evolve_rows(&pool, CALLER_WRITE).await.is_empty());
}

/// stdio is unchanged: with no token the gate does not run (the batch H-b bar
/// every workflow tool keeps), and nothing is recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_evolve_is_unchanged(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_o, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_wf, step) = ingest_as(
        &server,
        &pool,
        "acme-mcp-evolve-stdio",
        &owner_viewer,
        &owner_token,
    )
    .await;
    let viewer = tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");
    tools::evolve_step::evolve_step(
        &server,
        &viewer,
        by_id(step, "a stdio revision", "revises"),
        None,
    )
    .await
    .expect("stdio evolves as before");
    assert_eq!(claims_with_content(&pool, "a stdio revision").await, 1);
    assert!(evolve_rows(&pool, CALLER_WRITE).await.is_empty());
    assert!(evolve_rows(&pool, ADMIN_WRITE).await.is_empty());
}
