//! The LINKED-AGENT arm of a hierarchical workflow's caller authority, and the
//! provenance every write admitted over the authenticated transport records.
//!
//! Operator ruling: widen `tools::workflow_authority::require_workflow_authority`
//! to admit an agent that is LIVE-bound to a human operator when that human is
//! the workflow's recorded submitter, or is the human the submitter belongs to
//! (agents of the same human); and record, on the write's own transaction, who
//! acted and on whose authority.
//!
//! "Live-bound" is the kernel's own notion, never a new one:
//! `epigraph_author_binding` (migration 122, widened by 149) answering
//! `live_link` (an `operator_links` row that is not retired, to a human that is
//! still a registered, active human operator) AND, for a link, migration 107's
//! acting read (`epigraph_operator_actor`: a live writer membership in the
//! operator's group); or `client_allowlist` (149: the agent of an allowlisted
//! service / agent OAuth client, bound to a live human operator). The target
//! side is `epigraph_human_of(submitter, false)`, the human the submitter
//! belongs to, retired links included (an operator keeps what a retired agent
//! wrote, as on the claim-ownership arm).
//!
//! # Which callers actually reach this arm over HTTP
//!
//! An agent with ANY `operator_links` record gets no HTTP viewer
//! (`tools::viewer::request_viewer`: "operated agents are stdio-only"), and on
//! stdio this gate does not run at all. So over the authenticated transport the
//! population the arm admits is the ALLOWLISTED one, and the admitted cases
//! below drive the allowlisted caller through the real `request_viewer` first.
//! The `live_link` arm is pinned too (driving the tool with a token directly,
//! as the batch H-b tests do), and
//! `a_live_linked_agent_still_gets_no_http_viewer` pins that this change does
//! NOT make operated agents usable over HTTP.
//!
//! # Provenance
//!
//! Every write admitted over the authenticated transport through the
//! submitter, operator or linked-agent arm records one
//! `workflows.caller_write` `security_events` row on the write's own
//! transaction, naming the arm, the acting agent, the human it acted for, the
//! submitter, the tool, the workflow and the token; the admin arm keeps its
//! `workflows.admin_write` row. Refusals write neither the workflow rows nor a
//! provenance row, which every refusal below reads back from the database.
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

/// An agent whose link to `operator` is RETIRED (107 section 7).
async fn retired_agent(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_retired_agent(&mut conn, agent, operator)
        .await
        .expect("retired link");
    assert!(
        out.link_retired && !out.membership_live,
        "calibration: {out:?}"
    );
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
        .expect("an allowlisted agent resolves an HTTP viewer")
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
    binding: Option<&str>,
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
    assert_eq!(
        d["binding"],
        binding.map_or(serde_json::Value::Null, |b| b.into()),
        "{d}"
    );
    assert_eq!(d["client_id"], auth.client_id.to_string(), "{d}");
    assert_eq!(d["token_jti"], auth.jti.to_string(), "{d}");
}

/// The operator's real case: the human H is the recorded submitter, and an
/// agent bound to H over HTTP (an allowlisted client of H) adds a step. It is
/// admitted, and the write records who acted and for whom.
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_agent_of_the_submitting_human_adds_a_step_with_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let (agent, client) = allowlisted_agent(&pool, h, "a").await;
    let wf = workflow_submitted_by(&pool, &server, "la-human", h).await;
    let auth = token(agent, client);
    let viewer = http_viewer(&server, &auth).await;
    let before = steps(&pool, "la-human").await;

    let res = tools::step_ops::add_step(
        &server,
        &viewer,
        add("la-human", "a step by H's agent"),
        Some(&auth),
    )
    .await
    .expect("an agent bound to the submitting human adds a step");
    assert_eq!(steps(&pool, "la-human").await, before + 1);

    let step = body(&res)["step_claim_id"]
        .as_str()
        .expect("step id")
        .to_string();
    let stamp = author_of(&pool, &step).await;
    assert_ne!(stamp, agent, "the system agent still authors the step");
    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 1, "exactly one provenance row: {rows:?}");
    assert_provenance(
        &rows[0],
        stamp,
        "add_step",
        wf,
        h,
        "linked_agent",
        agent,
        Some(h),
        Some(epigraph_db::CLIENT_ALLOWLIST_BINDING),
        &auth,
    );
    assert_eq!(rows[0].1["write"]["step_claim_id"], step.as_str());
}

/// The same human-submitted workflow, from an agent with a LIVE operator link
/// to H (migration 107). Driven with a token directly: over HTTP such an agent
/// is refused its viewer before any tool runs (see the module doc), so this
/// pins the gate's own decision for the `live_link` binding.
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_linked_agent_of_the_submitting_human_is_admitted_by_the_gate(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let agent = linked_agent(&pool, h, "linked").await;
    let wf = workflow_submitted_by(&pool, &server, "la-link", h).await;
    let auth = token(agent, Uuid::new_v4());
    let before = steps(&pool, "la-link").await;

    tools::step_ops::add_step(
        &server,
        &direct_viewer(&pool, agent).await,
        add("la-link", "a step by H's linked agent"),
        Some(&auth),
    )
    .await
    .expect("a live-linked agent of the submitting human is admitted by the gate");
    assert_eq!(steps(&pool, "la-link").await, before + 1);
    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].1["arm"], "linked_agent");
    assert_eq!(rows[0].1["acting_agent"], agent.to_string());
    assert_eq!(rows[0].1["operator"], h.to_string());
    assert_eq!(rows[0].1["binding"], epigraph_db::LIVE_LINK_BINDING);
}

/// Calibration for the module doc's claim: this change does not make an
/// operated agent usable over HTTP. Its token still gets no viewer.
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

/// Agents of the same human: the submitter is a live-linked agent S of H, and
/// another agent bound to H (allowlisted, over the real HTTP viewer) adds a
/// step. Admitted, with the submitter and the human recorded apart.
#[sqlx::test(migrations = "../../migrations")]
async fn a_sibling_agent_of_the_submitters_human_adds_a_step_with_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let s = linked_agent(&pool, h, "submitter").await;
    let (agent, client) = allowlisted_agent(&pool, h, "sibling").await;
    let wf = workflow_submitted_by(&pool, &server, "la-sibling", s).await;
    let auth = token(agent, client);
    let viewer = http_viewer(&server, &auth).await;
    let before = steps(&pool, "la-sibling").await;

    let res = tools::step_ops::add_step(
        &server,
        &viewer,
        add("la-sibling", "a sibling's step"),
        Some(&auth),
    )
    .await
    .expect("an agent of the submitter's human adds a step");
    assert_eq!(steps(&pool, "la-sibling").await, before + 1);
    let step = body(&res)["step_claim_id"]
        .as_str()
        .expect("step id")
        .to_string();
    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_provenance(
        &rows[0],
        author_of(&pool, &step).await,
        "add_step",
        wf,
        s,
        "linked_agent",
        agent,
        Some(h),
        Some(epigraph_db::CLIENT_ALLOWLIST_BINDING),
        &auth,
    );
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

/// A RETIRED-linked agent of H acts for no one: refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_agent_of_the_submitting_human_is_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let agent = retired_agent(&pool, h, "retired").await;
    workflow_submitted_by(&pool, &server, "la-retired", h).await;
    let viewer = direct_viewer(&pool, agent).await;
    assert_refused(
        &pool,
        &server,
        &viewer,
        &token(agent, Uuid::new_v4()),
        "la-retired",
        "was submitted by agent",
    )
    .await;
}

/// A live link whose writer membership the operator REVOKED (107's acting
/// read) acts for no one, although the link row itself is not retired.
#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_agent_whose_membership_was_revoked_is_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (h, hg) = fixture::seed_human_operator(&pool, "h").await;
    let agent = linked_agent(&pool, h, "revoked-member").await;
    workflow_submitted_by(&pool, &server, "la-revoked-member", h).await;
    epigraph_db::GroupMembershipRepository::revoke_member_unless_last_admin(&pool, hg, agent)
        .await
        .expect("revoke the agent's writer membership");
    let viewer = direct_viewer(&pool, agent).await;
    assert_refused(
        &pool,
        &server,
        &viewer,
        &token(agent, Uuid::new_v4()),
        "la-revoked-member",
        "was submitted by agent",
    )
    .await;
}

/// The human's registration REVOKED (migration 122 section 1c; the `OPL01`
/// semantics: its agents bind to no one): its allowlisted agent is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_of_a_revoked_human_operator_is_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let (agent, client) = allowlisted_agent(&pool, h, "a").await;
    workflow_submitted_by(&pool, &server, "la-revoked-human", h).await;
    let auth = token(agent, client);
    // The viewer first, while the binding is live, as a token minted before
    // the revoke would hold it.
    let viewer = http_viewer(&server, &auth).await;
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_now FROM public.epigraph_revoke_human_operator($1, $2)")
            .bind(h)
            .bind("test: revoke the human")
            .fetch_one(&pool)
            .await
            .expect("revoke the human operator");
    assert!(revoked, "calibration: the registration is revoked now");
    assert_refused(
        &pool,
        &server,
        &viewer,
        &auth,
        "la-revoked-human",
        "was submitted by agent",
    )
    .await;
}

/// The same revoke for a LINKED caller on a workflow submitted by a sibling
/// linked agent S. Here the target side still names H (S's link record
/// outlives H's registration), and migration 107's acting read still names H
/// (the revoke touches no membership), so only migration 122's binding — H is
/// no longer a registered human, so its links bind no one — refuses the call.
/// CALIBRATION: the same caller is admitted before the revoke.
#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_agent_of_a_revoked_human_operator_is_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let s = linked_agent(&pool, h, "submitter").await;
    let agent = linked_agent(&pool, h, "caller").await;
    workflow_submitted_by(&pool, &server, "la-revoked-link", s).await;
    let auth = token(agent, Uuid::new_v4());
    let viewer = direct_viewer(&pool, agent).await;
    tools::step_ops::add_step(
        &server,
        &viewer,
        add("la-revoked-link", "before the revoke"),
        Some(&auth),
    )
    .await
    .expect("calibration: admitted while H is a registered human");
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_now FROM public.epigraph_revoke_human_operator($1, $2)")
            .bind(h)
            .bind("test: revoke the human")
            .fetch_one(&pool)
            .await
            .expect("revoke the human operator");
    assert!(revoked, "calibration: the registration is revoked now");
    let still_acting = {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::operator_actor(&mut conn, agent)
            .await
            .expect("actor read")
    };
    assert_eq!(
        still_acting.map(|l| l.operator_id),
        Some(h),
        "calibration: 107's acting read alone would still admit"
    );
    assert_refused(
        &pool,
        &server,
        &viewer,
        &auth,
        "la-revoked-link",
        "was submitted by agent",
    )
    .await;
}

/// An agent bound to a DIFFERENT human is refused on H's workflow, whether H
/// submitted it or one of H's agents did.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_of_another_human_is_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let other = human(&pool, "other").await;
    let s = linked_agent(&pool, h, "submitter").await;
    let (agent, client) = allowlisted_agent(&pool, other, "foreign").await;
    workflow_submitted_by(&pool, &server, "la-foreign-h", h).await;
    workflow_submitted_by(&pool, &server, "la-foreign-s", s).await;
    let auth = token(agent, client);
    let viewer = http_viewer(&server, &auth).await;
    for canonical in ["la-foreign-h", "la-foreign-s"] {
        assert_refused(
            &pool,
            &server,
            &viewer,
            &auth,
            canonical,
            "was submitted by agent",
        )
        .await;
    }
}

/// An agent bound to no human is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unbound_agent_is_refused(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    workflow_submitted_by(&pool, &server, "la-unbound", h).await;
    let (_agent, auth, viewer) = seed_caller(&pool, &["claims:write"]).await;
    assert_refused(
        &pool,
        &server,
        &viewer,
        &auth,
        "la-unbound",
        "was submitted by agent",
    )
    .await;
}

/// A workflow with NO recorded submitter stays platform corpus: an agent bound
/// to a human is refused there too (the admin arm only).
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_workflow_stays_admin_only_for_a_bound_agent(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let (agent, client) = allowlisted_agent(&pool, h, "a").await;
    workflow_submitted_by(&pool, &server, "la-legacy", h).await;
    sqlx::query(
        "UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' \
          WHERE canonical_name = 'la-legacy'",
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
        "la-legacy",
        "no recorded submitter",
    )
    .await;
}

/// `delete_step` through the linked-agent arm: admitted, with provenance.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bound_agent_deletes_a_step_with_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let (agent, client) = allowlisted_agent(&pool, h, "a").await;
    let wf = workflow_submitted_by(&pool, &server, "la-delete", h).await;
    let lineage: Uuid = sqlx::query_scalar(
        "SELECT c.step_lineage_id FROM claims c JOIN edges e ON e.target_id = c.id \
          WHERE e.source_id = $1 AND c.step_lineage_id IS NOT NULL LIMIT 1",
    )
    .bind(wf)
    .fetch_one(&pool)
    .await
    .expect("a step lineage");
    let auth = token(agent, client);
    let viewer = http_viewer(&server, &auth).await;

    let res = tools::step_ops::delete_step(
        &server,
        &viewer,
        DeleteStepParams {
            canonical_name: "la-delete".to_string(),
            step_lineage_id: lineage.to_string(),
        },
        Some(&auth),
    )
    .await
    .expect("an agent of the submitting human deletes a step");
    let step = body(&res)["step_claim_id"]
        .as_str()
        .expect("step id")
        .to_string();
    let truth: f64 = sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1::uuid")
        .bind(&step)
        .fetch_one(&pool)
        .await
        .expect("truth");
    assert!((truth - 0.05).abs() < 1e-9, "the step is soft-deleted");
    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_provenance(
        &rows[0],
        author_of(&pool, &step).await,
        "delete_step",
        wf,
        h,
        "linked_agent",
        agent,
        Some(h),
        Some(epigraph_db::CLIENT_ALLOWLIST_BINDING),
        &auth,
    );
    assert_eq!(rows[0].1["write"]["step_lineage_id"], lineage.to_string());
}

/// A NEW GENERATION through the linked-agent arm (`improve_workflow_hierarchy`):
/// admitted, the new row inherits the lineage's submitter (H, never the
/// caller), and the authority exercised over the lineage head is recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bound_agent_adds_a_generation_with_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let (agent, client) = allowlisted_agent(&pool, h, "a").await;
    let gen0 = workflow_submitted_by(&pool, &server, "la-gen", h).await;
    assert_eq!(generations(&pool, "la-gen").await, 1, "calibration");
    let auth = token(agent, client);
    let viewer = http_viewer(&server, &auth).await;

    tools::workflow_ingest::improve_workflow_hierarchy(
        &server,
        &viewer,
        ImproveWorkflowHierarchyParams {
            parent_canonical_name: "la-gen".to_string(),
            extraction: extraction("ignored", 0, "gen1"),
        },
        Some(&auth),
    )
    .await
    .expect("an agent of the submitting human adds a generation");
    let (gen1, gen1_submitter): (Uuid, Option<String>) = sqlx::query_as(
        "SELECT id, metadata->>'epigraph_submitted_by' FROM workflows \
          WHERE canonical_name = 'la-gen' AND generation = 1",
    )
    .fetch_one(&pool)
    .await
    .expect("generation 1");
    assert_eq!(
        gen1_submitter,
        Some(h.to_string()),
        "the generation inherits the lineage's submitter, never the caller"
    );
    assert_eq!(generations(&pool, "la-gen").await, 2);
    let rows = provenance(&pool, gen0).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let stamp: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = (SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'executes' LIMIT 1)")
        .bind(gen1)
        .fetch_one(&pool)
        .await
        .expect("a gen1 claim's author");
    assert_provenance(
        &rows[0],
        stamp,
        "workflow_ingest",
        gen0,
        h,
        "linked_agent",
        agent,
        Some(h),
        Some(epigraph_db::CLIENT_ALLOWLIST_BINDING),
        &auth,
    );
    assert_eq!(rows[0].1["write"]["created_workflow_id"], gen1.to_string());
}

/// `deprecate_workflow` through the linked-agent arm: admitted, with
/// provenance per deprecated row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bound_agent_deprecates_a_workflow_with_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let (agent, client) = allowlisted_agent(&pool, h, "a").await;
    let wf = workflow_submitted_by(&pool, &server, "la-deprecate", h).await;
    let auth = token(agent, client);
    let viewer = http_viewer(&server, &auth).await;
    tools::workflows::deprecate_workflow(
        &server,
        &viewer,
        DeprecateWorkflowParams {
            workflow_id: wf.to_string(),
            reason: "obsolete".into(),
            cascade: Some(false),
        },
        Some(&auth),
    )
    .await
    .expect("an agent of the submitting human deprecates the workflow");
    let truth: f64 = sqlx::query_scalar("SELECT truth_value FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(&pool)
        .await
        .expect("truth");
    assert!((truth - 0.05).abs() < 1e-9, "deprecated");
    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].1["action"], "deprecate_workflow");
    assert_eq!(rows[0].1["arm"], "linked_agent");
    assert_eq!(rows[0].1["acting_agent"], agent.to_string());
    assert_eq!(rows[0].1["operator"], h.to_string());
}

/// The submitter and operator arms record provenance too, and the `arm` field
/// tells them apart from the linked-agent arm.
#[sqlx::test(migrations = "../../migrations")]
async fn the_submitter_and_operator_arms_record_their_arm(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    let s = linked_agent(&pool, h, "submitter").await;
    let wf = workflow_submitted_by(&pool, &server, "la-arms", s).await;

    let s_auth = token(s, Uuid::new_v4());
    tools::step_ops::add_step(
        &server,
        &direct_viewer(&pool, s).await,
        add("la-arms", "the submitter's step"),
        Some(&s_auth),
    )
    .await
    .expect("the submitter");
    let h_auth = token(h, Uuid::new_v4());
    tools::step_ops::add_step(
        &server,
        &direct_viewer(&pool, h).await,
        add("la-arms", "the operator's step"),
        Some(&h_auth),
    )
    .await
    .expect("the submitter's operator");

    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].1["arm"], "submitter");
    assert_eq!(rows[0].1["acting_agent"], s.to_string());
    assert_eq!(rows[0].1["operator"], serde_json::Value::Null);
    assert_eq!(rows[1].1["arm"], "operator");
    assert_eq!(rows[1].1["acting_agent"], h.to_string());
    assert_eq!(rows[1].1["operator"], h.to_string());
}

/// stdio is unchanged: no gate, and no provenance row (there is no token).
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_writes_record_no_provenance(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let h = human(&pool, "h").await;
    workflow_submitted_by(&pool, &server, "la-stdio", h).await;
    let viewer = tools::viewer::request_viewer(&server, None)
        .await
        .expect("stdio viewer");
    let before = steps(&pool, "la-stdio").await;
    tools::step_ops::add_step(&server, &viewer, add("la-stdio", "a stdio step"), None)
        .await
        .expect("stdio is not gated");
    assert_eq!(steps(&pool, "la-stdio").await, before + 1);
    assert_eq!(provenance_total(&pool).await, 0);
}

/// Row security admits the provenance INSERT on the system-stamped
/// transaction: the linked-agent `add_step` on a server whose every connection
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
    let (agent, client) = allowlisted_agent(&pool, h, "a").await;
    let wf = workflow_submitted_by(&pool, &seed_server, "la-app-role", h).await;

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
    let auth = token(agent, client);
    let viewer = http_viewer(&server, &auth).await;
    let before = steps(&pool, "la-app-role").await;

    tools::step_ops::add_step(
        &server,
        &viewer,
        add("la-app-role", "a step on the application role"),
        Some(&auth),
    )
    .await
    .expect("admitted on the application role");
    assert_eq!(steps(&pool, "la-app-role").await, before + 1);
    let rows = provenance(&pool, wf).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].1["arm"], "linked_agent");
    assert_eq!(rows[0].1["acting_agent"], agent.to_string());
}
