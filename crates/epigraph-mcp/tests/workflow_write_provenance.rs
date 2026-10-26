//! The provenance every hierarchical-workflow write admitted over the
//! authenticated transport records, and the refusal of agents bound to the
//! submitting human (operator rulings, 2026-10-13).
//!
//! # The rule is NOT widened
//!
//! Over HTTP a workflow with a recorded submitter stays mutable only by the
//! submitter, the submitter's operator, or the audited `claims:admin` arm. An
//! agent bound to the submitting human — an allowlisted service client (the
//! shape a host's shared credential takes) or a live-linked agent — is refused,
//! with nothing written: the operator ruled that the shared host credential
//! must not gain edit rights over the human's workflows. (A live-linked agent
//! is refused its HTTP viewer before any tool runs; it is driven at the gate
//! directly here so the gate's own answer is pinned too.)
//!
//! # Provenance
//!
//! Every write admitted over the authenticated transport through the submitter
//! or operator arm records one `workflows.caller_write` `security_events` row
//! on the write's own transaction, naming the arm, the acting agent, the human
//! it acted for (operator arm), the submitter, the tool, the workflow and the
//! token; the admin arm keeps its `workflows.admin_write` row. Refusals write
//! neither the workflow rows nor a provenance row, read back from the database.
//! Who AUTHORED the claims a write creates is a graph edge, pinned in
//! `workflow_authored_edges.rs`.
//!
//! The decision and the record are Rust-side and data-driven, so the superuser
//! harness observes them faithfully, except whether row security admits the
//! provenance INSERT on the system-stamped transaction; that is
//! `the_provenance_row_is_admitted_on_the_application_role`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_caller};
use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::AgentRepository;
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::tools;
use epigraph_mcp::tools::step_ops::{AddStepParams, DeleteStepParams};
use epigraph_mcp::types::{
    DeprecateWorkflowParams, ImproveWorkflowHierarchyParams, IngestWorkflowParams,
};
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

const PROVENANCE: &str = "workflows.caller_write";

fn extraction(canonical: &str, generation: u32, summary: &str) -> WorkflowExtraction {
    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name: canonical.to_string(),
            goal: format!("linked-agent workflow {canonical}"),
            generation,
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
            summary: summary.to_string(),
            steps: vec![Step {
                compound: format!("{summary}: first step of {canonical}"),
                rationale: "because".to_string(),
                operations: vec![format!("op of {canonical} {summary}")],
                generality: vec![1],
                confidence: 0.7,
                evidence_type: None,
            }],
        }],
        relationships: vec![],
    }
}

fn add(canonical: &str, text: &str) -> AddStepParams {
    AddStepParams {
        canonical_name: canonical.to_string(),
        step_text: text.to_string(),
        position: None,
    }
}

/// A `claims:write` token for `agent` on OAuth client `client_id`, shaped as
/// `oauth/token.rs` mints one.
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

/// A registered human operator (migration 122 section 1c).
async fn human(pool: &PgPool, label: &str) -> Uuid {
    fixture::seed_human_operator(pool, label).await.0
}

/// An agent with a LIVE operator link to `operator` (migration 107), recorded
/// on the privileged harness connection as `epigraph-operator link` does.
async fn linked_agent(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link");
    assert!(out.membership_live && out.link_live, "calibration: {out:?}");
    agent
}

/// The agent of an ALLOWLISTED service client bound to `operator` (migration
/// 149, arm (c)), through the real maintenance definer. Returns the agent and
/// its OAuth client id.
async fn allowlisted_agent(pool: &PgPool, operator: Uuid, label: &str) -> (Uuid, Uuid) {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, 'service', ARRAY['claims:write'], 'active', $3, \
                 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("linked-agent-{label}-{agent}"))
    .bind(format!("linked-agent {label}"))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the agent's service client");
    let binding: Option<String> =
        fixture::as_role(pool, "epigraph_maintenance", |mut c| async move {
            let b = sqlx::query_scalar(
                "SELECT effective_binding \
                   FROM public.epigraph_allow_author_binding_client($1, $2, 'test')",
            )
            .bind(client)
            .bind(operator)
            .fetch_one(&mut *c)
            .await
            .expect("allow the agent's client");
            (c, b)
        })
        .await;
    assert_eq!(
        binding.as_deref(),
        Some(epigraph_db::CLIENT_ALLOWLIST_BINDING),
        "calibration: {label} is allowlisted"
    );
    (agent, client)
}

/// The caller's viewer through the REAL HTTP resolution (`request_viewer`),
/// which refuses an operated agent; the allowlisted callers below pass it.
async fn http_viewer(
    server: &EpiGraphMcpFull,
    auth: &AuthContext,
) -> epigraph_db::visibility::Viewer {
    tools::viewer::request_viewer(server, Some(auth))
        .await
        .expect("a caller with no operator link resolves an HTTP viewer")
}

/// The viewer a token's agent would hold, resolved directly: for an operated
/// caller, which `request_viewer` refuses over HTTP (see the module doc).
async fn direct_viewer(pool: &PgPool, agent: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("viewer")
}

/// Ingest `canonical` (generation 0) through an unrelated HTTP caller, then
/// record `submitter` as its submitter, as the audited backfill of legacy
/// workflows did. Returns the workflow id.
async fn workflow_submitted_by(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    canonical: &str,
    submitter: Uuid,
) -> Uuid {
    let (_ingester, ingester_token, ingester_viewer) = seed_caller(pool, &["claims:write"]).await;
    tools::workflow_ingest::ingest_workflow(
        server,
        &ingester_viewer,
        IngestWorkflowParams {
            extraction: extraction(canonical, 0, "gen0"),
            tenancy: None,
            embed: None,
        },
        Some(&ingester_token),
    )
    .await
    .expect("ingest");
    let wf: Uuid = sqlx::query_scalar(
        "UPDATE workflows \
            SET metadata = jsonb_set(metadata, '{epigraph_submitted_by}', to_jsonb($2::text)) \
          WHERE canonical_name = $1 RETURNING id",
    )
    .bind(canonical)
    .bind(submitter)
    .fetch_one(pool)
    .await
    .expect("record the submitter");
    wf
}

async fn steps(pool: &PgPool, canonical: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges e JOIN workflows w ON w.id = e.source_id \
          WHERE w.canonical_name = $1 AND e.relationship = 'executes'",
    )
    .bind(canonical)
    .fetch_one(pool)
    .await
    .expect("count executes edges")
}

async fn generations(pool: &PgPool, canonical: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = $1")
        .bind(canonical)
        .fetch_one(pool)
        .await
        .expect("count generations")
}

/// Every provenance row naming `workflow`, oldest first.
async fn provenance(pool: &PgPool, workflow: Uuid) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT agent_id, details FROM security_events \
          WHERE event_type = $1 AND details->>'workflow_id' = $2::text \
          ORDER BY created_at, id",
    )
    .bind(PROVENANCE)
    .bind(workflow)
    .fetch_all(pool)
    .await
    .expect("read provenance")
}

async fn provenance_total(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type = $1")
        .bind(PROVENANCE)
        .fetch_one(pool)
        .await
        .expect("count provenance")
}

/// The author (the stamp) of a claim the tool wrote: the workflow-ingest
/// system agent.
async fn author_of(pool: &PgPool, claim: &str) -> Uuid {
    sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1::uuid")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim author")
}

fn body(res: &rmcp::model::CallToolResult) -> serde_json::Value {
    common::first_text(res)
}

/// Assert one provenance row's exact fields.
#[allow(clippy::too_many_arguments)]
fn assert_provenance(
    row: &(Option<Uuid>, serde_json::Value),
    stamp: Uuid,
    action: &str,
    workflow: Uuid,
    submitter: Uuid,
    arm: &str,
    acting: Uuid,
    operator: Option<Uuid>,
    auth: &AuthContext,
) {
    let (agent_id, d) = row;
    assert_eq!(
        *agent_id,
        Some(stamp),
        "the row is attributed to the session that wrote it, the system stamp: {d}"
    );
    assert_eq!(d["action"], action, "{d}");
    assert_eq!(d["workflow_id"], workflow.to_string(), "{d}");
    assert_eq!(d["submitter"], submitter.to_string(), "{d}");
    assert_eq!(d["arm"], arm, "{d}");
    assert_eq!(d["acting_agent"], acting.to_string(), "{d}");
    assert_eq!(
        d["operator"],
        operator.map_or(serde_json::Value::Null, |o| o.to_string().into()),
        "{d}"
    );
    assert!(d.get("binding").is_none(), "no binding field: {d}");
    assert_eq!(d["client_id"], auth.client_id.to_string(), "{d}");
    assert_eq!(d["token_jti"], auth.jti.to_string(), "{d}");
}

/// Shared shape of every refusal: `add_step` refused with the workflow named,
/// and NOTHING written — no step, no provenance row.
async fn assert_refused(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: &AuthContext,
    canonical: &str,
    expect_text: &str,
) {
    let before_steps = steps(pool, canonical).await;
    let before_rows = provenance_total(pool).await;
    let err = tools::step_ops::add_step(
        server,
        viewer,
        add(canonical, "a step that must not land"),
        Some(auth),
    )
    .await
    .expect_err("refused");
    assert!(err.message.contains(expect_text), "{}", err.message);
    assert!(
        err.message.contains("Nothing was written"),
        "{}",
        err.message
    );
    assert_eq!(
        steps(pool, canonical).await,
        before_steps,
        "no step written"
    );
    assert_eq!(
        provenance_total(pool).await,
        before_rows,
        "no provenance row written"
    );
}

/// The operator ruling: on a workflow whose recorded submitter is the human
/// H, agents bound to H are refused (allowlisted, through the real HTTP viewer;
/// live-linked, at the gate), with nothing written, while H itself is admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn agents_bound_to_the_submitting_human_are_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let (allowlisted, client) = allowlisted_agent(&pool, h, "allowlisted").await;
    let linked = linked_agent(&pool, h, "linked").await;
    workflow_submitted_by(&pool, &server, "wp-bound", h).await;

    let a_auth = token(allowlisted, client);
    let a_viewer = http_viewer(&server, &a_auth).await;
    assert_refused(
        &pool,
        &server,
        &a_viewer,
        &a_auth,
        "wp-bound",
        "was submitted by agent",
    )
    .await;
    let l_auth = token(linked, Uuid::new_v4());
    let l_viewer = direct_viewer(&pool, linked).await;
    assert_refused(
        &pool,
        &server,
        &l_viewer,
        &l_auth,
        "wp-bound",
        "was submitted by agent",
    )
    .await;

    // CALIBRATION: the submitting human itself is admitted.
    let h_auth = token(h, Uuid::new_v4());
    let before = steps(&pool, "wp-bound").await;
    tools::step_ops::add_step(
        &server,
        &http_viewer(&server, &h_auth).await,
        add("wp-bound", "H's own step"),
        Some(&h_auth),
    )
    .await
    .expect("the submitter");
    assert_eq!(steps(&pool, "wp-bound").await, before + 1);
}

/// Calibration: an operated agent still gets no HTTP viewer.
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_linked_agent_still_gets_no_http_viewer(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let agent = linked_agent(&pool, h, "linked").await;
    let err = tools::viewer::request_viewer(&server, Some(&token(agent, Uuid::new_v4())))
        .await
        .expect_err("an operated agent gets no HTTP viewer");
    assert!(err.message.contains("stdio-only"), "{}", err.message);
}

/// `add_step` by the submitting human: one provenance row, exact fields.
#[sqlx::test(migrations = "../../migrations")]
async fn the_submitter_adds_a_step_with_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let wf = workflow_submitted_by(&pool, &server, "wp-add", h).await;
    let auth = token(h, Uuid::new_v4());
    let res = tools::step_ops::add_step(
        &server,
        &http_viewer(&server, &auth).await,
        add("wp-add", "H's step"),
        Some(&auth),
    )
    .await
    .expect("the submitter adds a step");
    let step = body(&res)["step_claim_id"]
        .as_str()
        .expect("step id")
        .to_string();
    let stamp = author_of(&pool, &step).await;
    assert_ne!(stamp, h, "the system agent still authors the step");
    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_provenance(
        &rows[0],
        stamp,
        "add_step",
        wf,
        h,
        "submitter",
        h,
        None,
        &auth,
    );
    assert_eq!(rows[0].1["write"]["step_claim_id"], step.as_str());
}

/// The operator arm, and `delete_step`: the submitter is a linked agent S of
/// H; H deletes a step. One row, arm `operator`, `operator` = H.
#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_deletes_a_step_with_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let s = linked_agent(&pool, h, "submitter").await;
    let wf = workflow_submitted_by(&pool, &server, "wp-delete", s).await;
    let lineage: Uuid = sqlx::query_scalar(
        "SELECT c.step_lineage_id FROM claims c JOIN edges e ON e.target_id = c.id \
          WHERE e.source_id = $1 AND c.step_lineage_id IS NOT NULL LIMIT 1",
    )
    .bind(wf)
    .fetch_one(&pool)
    .await
    .expect("a step lineage");
    let auth = token(h, Uuid::new_v4());
    let res = tools::step_ops::delete_step(
        &server,
        &http_viewer(&server, &auth).await,
        DeleteStepParams {
            canonical_name: "wp-delete".to_string(),
            step_lineage_id: lineage.to_string(),
        },
        Some(&auth),
    )
    .await
    .expect("the submitter's operator deletes a step");
    let step = body(&res)["step_claim_id"]
        .as_str()
        .expect("step id")
        .to_string();
    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_provenance(
        &rows[0],
        author_of(&pool, &step).await,
        "delete_step",
        wf,
        s,
        "operator",
        h,
        Some(h),
        &auth,
    );
    assert_eq!(rows[0].1["write"]["step_lineage_id"], lineage.to_string());
}

/// A NEW GENERATION by the submitter: the new row inherits the submitter, and
/// the authority exercised over the lineage head is recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn the_submitter_adds_a_generation_with_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let gen0 = workflow_submitted_by(&pool, &server, "wp-gen", h).await;
    assert_eq!(generations(&pool, "wp-gen").await, 1, "calibration");
    let auth = token(h, Uuid::new_v4());
    tools::workflow_ingest::improve_workflow_hierarchy(
        &server,
        &http_viewer(&server, &auth).await,
        ImproveWorkflowHierarchyParams {
            parent_canonical_name: "wp-gen".to_string(),
            extraction: extraction("ignored", 0, "gen1"),
        },
        Some(&auth),
    )
    .await
    .expect("the submitter adds a generation");
    assert_eq!(generations(&pool, "wp-gen").await, 2);
    let gen1: Uuid = sqlx::query_scalar(
        "SELECT id FROM workflows WHERE canonical_name = 'wp-gen' AND generation = 1",
    )
    .fetch_one(&pool)
    .await
    .expect("generation 1");
    let rows = provenance(&pool, gen0).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].1["action"], "workflow_ingest");
    assert_eq!(rows[0].1["arm"], "submitter");
    assert_eq!(rows[0].1["acting_agent"], h.to_string());
    assert_eq!(rows[0].1["write"]["created_workflow_id"], gen1.to_string());
}

/// `deprecate_workflow` by the submitter: one row per deprecated target.
#[sqlx::test(migrations = "../../migrations")]
async fn the_submitter_deprecates_with_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let wf = workflow_submitted_by(&pool, &server, "wp-deprecate", h).await;
    let auth = token(h, Uuid::new_v4());
    tools::workflows::deprecate_workflow(
        &server,
        &http_viewer(&server, &auth).await,
        DeprecateWorkflowParams {
            workflow_id: wf.to_string(),
            reason: "obsolete".into(),
            cascade: Some(false),
        },
        Some(&auth),
    )
    .await
    .expect("the submitter deprecates");
    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].1["action"], "deprecate_workflow");
    assert_eq!(rows[0].1["arm"], "submitter");
    assert_eq!(rows[0].1["acting_agent"], h.to_string());
}

/// A workflow with NO recorded submitter stays platform corpus: a bound agent
/// is refused there with "no recorded submitter".
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_workflow_stays_admin_only(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let (agent, client) = allowlisted_agent(&pool, h, "a").await;
    workflow_submitted_by(&pool, &server, "wp-legacy", h).await;
    sqlx::query(
        "UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' \
          WHERE canonical_name = 'wp-legacy'",
    )
    .execute(&pool)
    .await
    .expect("forget the submitter");
    let auth = token(agent, client);
    let viewer = http_viewer(&server, &auth).await;
    assert_refused(
        &pool,
        &server,
        &viewer,
        &auth,
        "wp-legacy",
        "no recorded submitter",
    )
    .await;
}

/// stdio is unchanged: no gate, and no provenance row (there is no token).
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_writes_record_no_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    workflow_submitted_by(&pool, &server, "wp-stdio", h).await;
    let viewer = tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");
    let before = steps(&pool, "wp-stdio").await;
    tools::step_ops::add_step(&server, &viewer, add("wp-stdio", "a stdio step"), None)
        .await
        .expect("stdio is not gated");
    assert_eq!(steps(&pool, "wp-stdio").await, before + 1);
    assert_eq!(provenance_total(&pool).await, 0);
}

/// Row security admits the provenance INSERT on the system-stamped
/// transaction: the submitter's `add_step` on a server whose every connection
/// is the APPLICATION ROLE (a superuser pool bypasses `security_events_append`
/// and would prove nothing).
#[sqlx::test(migrations = "../../migrations")]
async fn the_provenance_row_is_admitted_on_the_application_role(pool: PgPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(&pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: this arm is vacuous"
    );
    let seed_server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let wf = workflow_submitted_by(&pool, &seed_server, "wp-app-role", h).await;

    let url = fixture::database_url_for(&pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped);
    let auth = token(h, Uuid::new_v4());
    let viewer = http_viewer(&server, &auth).await;
    let before = steps(&pool, "wp-app-role").await;
    tools::step_ops::add_step(
        &server,
        &viewer,
        add("wp-app-role", "a step on the application role"),
        Some(&auth),
    )
    .await
    .expect("admitted on the application role");
    assert_eq!(steps(&pool, "wp-app-role").await, before + 1);
    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].1["arm"], "submitter");
    assert_eq!(rows[0].1["acting_agent"], h.to_string());
}
