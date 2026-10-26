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
//! * the new head, which no workflow executes directly, is still gated, and
//!   the submitter still evolves it;
//! * a step two workflows execute needs authority over both;
//! * a retracted `executes` edge still counts;
//! * a server built without a `ScopedPool` gates too;
//! * the audited admin arm is admitted and recorded; a grantless admin is
//!   refused ADM02;
//! * stdio is unchanged (the batch H-b bar, as for the other workflow tools),
//!   and so is an authenticated evolve of a claim no workflow executes.
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
        delegated_by: None,
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
            tenancy: None,
            embed: None,
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

    // CALIBRATION: the submitter still evolves the unexecuted head, recorded
    // against the workflow; the gate admits through the lineage rather than
    // freezing executed heads.
    let res = tools::evolve_step::evolve_step(
        &server,
        &owner_viewer,
        by_id(head, "the submitter's revision of the head", "revises"),
        Some(&owner_token),
    )
    .await
    .expect("the submitter evolves the unexecuted head");
    let rows = evolve_rows(&pool, CALLER_WRITE).await;
    assert_eq!(rows.len(), 2, "exactly one new row: {rows:?}");
    let d = &rows[1].1;
    assert_eq!(d["workflow_id"], wf.to_string(), "{d}");
    assert_eq!(d["arm"], "submitter", "{d}");
    assert_eq!(d["write"]["parent_claim_id"], head.to_string(), "{d}");
    assert_eq!(d["write"]["claim_id"], claim_id(&res).to_string(), "{d}");
}

/// Executes `step` from workflow `wf` as well (harness edge).
async fn also_executes(pool: &PgPool, wf: Uuid, step: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes')",
    )
    .bind(wf)
    .bind(step)
    .execute(pool)
    .await
    .expect("the second workflow executes the step");
}

/// A step two workflows execute, over the authenticated transport: each
/// submitter is refused naming the OTHER workflow (so a gate that stops after
/// the first workflow it admits is caught whichever id sorts first). With
/// authority over both the evolve is admitted and recorded once per workflow.
#[sqlx::test(migrations = "../../migrations")]
async fn a_step_two_workflows_execute_needs_authority_over_both(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (a, a_token, a_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_b, b_token, b_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (wf_a, step) = ingest_as(
        &server,
        &pool,
        "acme-mcp-evolve-shared",
        &a_viewer,
        &a_token,
    )
    .await;
    let (wf_b, _) = ingest_as(
        &server,
        &pool,
        "acme-mcp-evolve-shared-b",
        &b_viewer,
        &b_token,
    )
    .await;
    also_executes(&pool, wf_b, step).await;

    assert_refused(
        &server,
        &pool,
        &a_viewer,
        &a_token,
        by_id(step, "the first submitter's revision", "revises"),
        step,
        wf_b,
        "was submitted by agent",
    )
    .await;
    assert_refused(
        &server,
        &pool,
        &b_viewer,
        &b_token,
        by_id(step, "the second submitter's revision", "revises"),
        step,
        wf_a,
        "was submitted by agent",
    )
    .await;
    assert!(evolve_rows(&pool, CALLER_WRITE).await.is_empty());

    // CALIBRATION: authority over both.
    set_submitter(&pool, wf_b, a).await;
    let res = tools::evolve_step::evolve_step(
        &server,
        &a_viewer,
        by_id(step, "a revision both allow", "revises"),
        Some(&a_token),
    )
    .await
    .expect("authority over both workflows");
    let new = claim_id(&res).to_string();
    let rows = evolve_rows(&pool, CALLER_WRITE).await;
    let mut recorded: Vec<String> = rows
        .iter()
        .map(|(_, d)| {
            assert_eq!(d["write"]["parent_claim_id"], step.to_string(), "{d}");
            assert_eq!(d["write"]["claim_id"], new, "{d}");
            d["workflow_id"].as_str().expect("id").to_string()
        })
        .collect();
    recorded.sort();
    let mut want = vec![wf_a.to_string(), wf_b.to_string()];
    want.sort();
    assert_eq!(recorded, want, "one provenance row per workflow");
}

/// A retracted `executes` edge still counts over the authenticated transport:
/// the stranger is refused naming the workflow, and the submitter is still
/// admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_executes_edge_still_gates_the_evolve(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_o, owner_token, owner_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (_s, stranger_token, stranger_viewer) = seed_caller(&pool, &["claims:write"]).await;
    let (wf, step) = ingest_as(
        &server,
        &pool,
        "acme-mcp-evolve-retracted",
        &owner_viewer,
        &owner_token,
    )
    .await;
    let retracted = sqlx::query(
        "UPDATE edges SET valid_to = now() \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes' \
            AND valid_to IS NULL",
    )
    .bind(wf)
    .bind(step)
    .execute(&pool)
    .await
    .expect("retract the executes edge")
    .rows_affected();
    assert_eq!(retracted, 1, "calibration: the executes edge is retracted");

    assert_refused(
        &server,
        &pool,
        &stranger_viewer,
        &stranger_token,
        by_id(
            step,
            "a stranger's revision after the retraction",
            "revises",
        ),
        step,
        wf,
        "was submitted by agent",
    )
    .await;
    tools::evolve_step::evolve_step(
        &server,
        &owner_viewer,
        by_id(
            step,
            "the submitter's revision after the retraction",
            "revises",
        ),
        Some(&owner_token),
    )
    .await
    .expect("the submitter is still admitted");
    let rows = evolve_rows(&pool, CALLER_WRITE).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].1["workflow_id"], wf.to_string(), "{}", rows[0].1);
}

/// A claim no workflow executes is evolved over the authenticated transport
/// exactly as before, twice (the second on the new head, so the lineage read
/// runs over a real `step_lineage_id`), and nothing is recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn an_authenticated_evolve_of_a_claim_no_workflow_executes_is_unaffected(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (caller, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let plain =
        fixture::seed_public_claim(&pool, caller, "a plain claim no workflow executes").await;

    let res = tools::evolve_step::evolve_step(
        &server,
        &viewer,
        by_id(plain, "the plain claim, revised", "revises"),
        Some(&token),
    )
    .await
    .expect("a claim no workflow executes is evolved");
    let head = claim_id(&res);
    tools::evolve_step::evolve_step(
        &server,
        &viewer,
        by_id(head, "the plain claim, superseded", "supersedes"),
        Some(&token),
    )
    .await
    .expect("and its new head too");
    assert_eq!(
        claims_with_content(&pool, "the plain claim, superseded").await,
        1
    );
    assert!(evolve_rows(&pool, CALLER_WRITE).await.is_empty());
    assert!(evolve_rows(&pool, ADMIN_WRITE).await.is_empty());
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
