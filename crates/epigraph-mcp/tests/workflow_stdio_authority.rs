//! Backlog 222289f3: the stdio workflow mutation tools (`add_step`,
//! `delete_step`, `improve_workflow_hierarchy`, `deprecate_workflow`,
//! `evolve_step`) check the stdio caller's authority over the TARGET lineage,
//! as their HTTP twins check theirs.
//!
//! Before this change `tools::workflow_authority::require_workflow_authority`
//! returned an unchecked grant for every stdio call, and the writes run on the
//! workflow-ingest system agent's stamp, which writes every group the system
//! agent was made a writer of. So a stdio agent that could not even READ a
//! group-private lineage (every read of it answered "not found") could add a
//! step to it, soft-delete its steps, mint its next generation, or deprecate
//! it; the REST twins refused the same outsider (it is not the submitter).
//!
//! The rule on stdio, decided on the stdio identity (this server's agent):
//!
//! * the caller must READ the row on its OWN stamp, and for a group row WRITE
//!   its owner group; a row it cannot read is refused without its id;
//! * a row with a recorded submitter admits only the submitter or the
//!   submitter's operator (there is no admin arm without a token);
//! * every admitted write records one `workflows.caller_write` row naming the
//!   acting agent, with `transport = "stdio"` and no token.
//!
//! Every pool the servers hold is `epigraph_app` (a superuser pool bypasses
//! the row security the read check relies on); seeding runs on the superuser
//! pool. Two stdio servers share the database: `member` (a writer of the
//! team group, the lineage's submitter) and `outsider` (no membership).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use epigraph_db::{GroupRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools;
use epigraph_mcp::tools::evolve_step::EvolveStepParams;
use epigraph_mcp::tools::step_ops::{AddStepParams, DeleteStepParams};
use epigraph_mcp::types::{
    DeprecateWorkflowParams, ImproveWorkflowHierarchyParams, IngestWorkflowParams,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const MEMBER_SEED: u8 = 0x5A;
const OUTSIDER_SEED: u8 = 0x5B;

async fn app_role_server(pool: &PgPool, seed: u8) -> EpiGraphMcpFull {
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
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(plain, signer, embedder, false).with_scoped_pool(scoped)
}

/// The stdio viewer and agent id of `server` (what a stdio `#[tool]` body
/// resolves with no token).
async fn stdio(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    seed: u8,
) -> (epigraph_db::visibility::Viewer, Uuid) {
    let viewer = tools::viewer::request_viewer(server, None)
        .await
        .expect("the stdio viewer");
    let key = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32])
        .expect("signer")
        .public_key();
    let agent = sqlx::query_scalar::<_, Uuid>("SELECT id FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(pool)
        .await
        .expect("the stdio agent");
    (viewer, agent)
}

fn extraction(name: &str, step: &str) -> epigraph_ingest::workflow::WorkflowExtraction {
    serde_json::from_value(json!({
        "source": {"canonical_name": name, "goal": format!("workflow-plan goal for {name}"),
                   "generation": 0, "metadata": {}},
        "thesis_derivation": "TopDown",
        "phases": [{"title": "Body", "summary": format!("{name} phase"),
                    "steps": [{"compound": step, "rationale": "r",
                               "operations": [], "generality": [], "confidence": 0.8}]}],
        "relationships": []
    }))
    .expect("extraction")
}

async fn ingest(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    name: &str,
    group: Option<Uuid>,
) {
    let mut params = json!({ "extraction": extraction(name, &format!("{name} step")) });
    if let Some(g) = group {
        params["tenancy"] = json!({"visibility": "group", "owner_group_id": g});
    }
    let params: IngestWorkflowParams = serde_json::from_value(params).expect("params");
    tools::workflow_ingest::ingest_workflow(server, viewer, params, None)
        .await
        .expect("the stdio ingest");
}

/// A team group whose writers are the workflow-ingest system agent and
/// `member`; `outsider` holds nothing in it.
async fn team_group(pool: &PgPool, member: Uuid) -> Uuid {
    let system = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    let (admin, _) = fixture::seed_agent_with_group(pool, "stdio-authority-admin").await;
    let g = Uuid::new_v4();
    GroupRepository::create_with_admin(
        pool,
        g,
        Some("stdio-authority team group"),
        &format!("did:epigraph:test:stdio-authority:{g}"),
        blake3::hash(g.as_bytes()).as_bytes(),
        None,
        admin,
    )
    .await
    .expect("the team group");
    for agent in [system, member] {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(g)
        .bind(agent)
        .execute(pool)
        .await
        .expect("writer row");
    }
    g
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    rows: Vec<(i32, f64)>,
    executes: i64,
    step_truths: Vec<f64>,
    claims: i64,
    caller_writes: i64,
}

/// Everything a mutation of `name` could change, read on the superuser pool.
async fn snapshot(pool: &PgPool, name: &str) -> Snapshot {
    let rows: Vec<(i32, f64)> = sqlx::query_as(
        "SELECT generation, truth_value FROM workflows WHERE canonical_name = $1 \
          ORDER BY generation",
    )
    .bind(name)
    .fetch_all(pool)
    .await
    .expect("rows");
    let executes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges e JOIN workflows w ON w.id = e.source_id \
          WHERE w.canonical_name = $1 AND e.relationship = 'executes'",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("executes");
    let step_truths: Vec<f64> = sqlx::query_scalar(
        "SELECT c.truth_value FROM claims c JOIN edges e ON e.target_id = c.id \
           JOIN workflows w ON w.id = e.source_id \
          WHERE w.canonical_name = $1 AND e.relationship = 'executes' ORDER BY c.id",
    )
    .bind(name)
    .fetch_all(pool)
    .await
    .expect("step truths");
    let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(pool)
        .await
        .expect("claims");
    let caller_writes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'workflows.caller_write'",
    )
    .fetch_one(pool)
    .await
    .expect("caller writes");
    Snapshot {
        rows,
        executes,
        step_truths,
        claims,
        caller_writes,
    }
}

async fn head(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM workflows WHERE canonical_name = $1 ORDER BY generation DESC LIMIT 1",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("head")
}

async fn step_of(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    sqlx::query_as(
        "SELECT c.id, c.step_lineage_id FROM claims c JOIN edges e ON e.target_id = c.id \
           JOIN workflows w ON w.id = e.source_id \
          WHERE w.canonical_name = $1 AND e.relationship = 'executes' \
            AND c.step_lineage_id IS NOT NULL LIMIT 1",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("a step")
}

fn add(name: &str, text: &str) -> AddStepParams {
    AddStepParams {
        canonical_name: name.to_string(),
        step_text: text.to_string(),
        position: None,
    }
}

fn improve(name: &str, text: &str) -> ImproveWorkflowHierarchyParams {
    ImproveWorkflowHierarchyParams {
        parent_canonical_name: name.to_string(),
        extraction: extraction(name, text),
    }
}

fn deprecate(id: Uuid) -> DeprecateWorkflowParams {
    DeprecateWorkflowParams {
        workflow_id: id.to_string(),
        reason: "stdio authority".to_string(),
        cascade: Some(false),
    }
}

fn evolve(parent: Uuid, content: &str) -> EvolveStepParams {
    EvolveStepParams {
        parent_id: parent.to_string(),
        canonical_name: None,
        step_index: None,
        step_lineage_id: String::new(),
        content: content.to_string(),
        edge_type: "revises".to_string(),
        rationale: Some("stdio authority".to_string()),
        level: Some(2),
    }
}

/// Every stdio mutation tool, run by `server` as its stdio agent against
/// lineage `name`: `Some(message)` if refused, `None` if admitted, in the
/// order add_step, delete_step, improve_workflow_hierarchy, evolve_step,
/// deprecate_workflow.
async fn every_tool(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    name: &str,
    tag: &str,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Vec<(&'static str, Option<String>)> {
    let (step, lineage) = step_of(pool, name).await;
    let wf = head(pool, name).await;
    let refused = |r: Result<rmcp::model::CallToolResult, rmcp::ErrorData>| match r {
        Ok(out) if out.is_error == Some(true) => Some(format!("{out:?}")),
        Ok(_) => None,
        Err(e) => Some(e.message.to_string()),
    };
    vec![
        (
            "add_step",
            refused(
                tools::step_ops::add_step(server, viewer, add(name, &format!("{tag} add")), auth)
                    .await,
            ),
        ),
        (
            "delete_step",
            refused(
                tools::step_ops::delete_step(
                    server,
                    viewer,
                    DeleteStepParams {
                        canonical_name: name.to_string(),
                        step_lineage_id: lineage.to_string(),
                    },
                    auth,
                )
                .await,
            ),
        ),
        (
            "improve_workflow_hierarchy",
            refused(
                tools::workflow_ingest::improve_workflow_hierarchy(
                    server,
                    viewer,
                    improve(name, &format!("{tag} improved step")),
                    auth,
                )
                .await,
            ),
        ),
        (
            "evolve_step",
            refused(
                tools::evolve_step::evolve_step(
                    server,
                    viewer,
                    evolve(step, &format!("{tag} evolved")),
                    auth,
                )
                .await,
            ),
        ),
        (
            "deprecate_workflow",
            refused(
                tools::workflows::deprecate_workflow(server, viewer, deprecate(wf), auth).await,
            ),
        ),
    ]
}

/// The F0 shape: a GROUP-PRIVATE lineage the stdio outsider cannot read.
/// Every stdio mutation tool is refused with nothing written, and no refusal
/// names the hidden workflow's id. CALIBRATION: the member (the lineage's
/// submitter, a writer of the group) runs the same tools over stdio and is
/// admitted, so each refusal is the authority check and not a broken fixture.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_outsider_cannot_mutate_a_group_private_lineage(pool: PgPool) {
    let member_server = app_role_server(&pool, MEMBER_SEED).await;
    let outsider_server = app_role_server(&pool, OUTSIDER_SEED).await;
    let (member_viewer, member) = stdio(&pool, &member_server, MEMBER_SEED).await;
    let (outsider_viewer, outsider) = stdio(&pool, &outsider_server, OUTSIDER_SEED).await;
    assert_ne!(member, outsider);
    // A public ingest provisions the system agent before the group is made.
    ingest(&member_server, &member_viewer, "stdio-auth-warmup", None).await;
    let g = team_group(&pool, member).await;
    let member_viewer = tools::viewer::request_viewer(&member_server, None)
        .await
        .expect("the member's viewer, now in the group");
    let name = "stdio-auth-private";
    ingest(&member_server, &member_viewer, name, Some(g)).await;
    let wf = head(&pool, name).await;
    let row: (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM workflows WHERE id = $1")
            .bind(wf)
            .fetch_one(&pool)
            .await
            .expect("the row");
    assert_eq!(
        row,
        ("group".to_string(), g),
        "the fixture's lineage is private"
    );

    let before = snapshot(&pool, name).await;
    let outcomes = every_tool(
        &pool,
        &outsider_server,
        &outsider_viewer,
        name,
        "outsider",
        None,
    )
    .await;
    let admitted: Vec<&str> = outcomes
        .iter()
        .filter(|(_, o)| o.is_none())
        .map(|(t, _)| *t)
        .collect();
    assert!(
        admitted.is_empty(),
        "every stdio tool must refuse a non-member of the lineage's group; admitted: \
         {admitted:?}; all outcomes: {outcomes:?}"
    );
    for (tool, outcome) in &outcomes {
        let Some(message) = outcome else {
            unreachable!()
        };
        // `deprecate_workflow` takes the id as its parameter and echoes it.
        assert!(
            *tool == "deprecate_workflow" || !message.contains(&wf.to_string()),
            "{tool}: the refusal must not name the hidden workflow: {message}"
        );
    }
    assert_eq!(
        snapshot(&pool, name).await,
        before,
        "the refused stdio calls wrote nothing"
    );

    // The HTTP twin (the same tools over the authenticated transport): a
    // non-member token is refused by every tool as well, nothing written.
    let (_http, http_token, http_viewer) = common::seed_caller(&pool, &["claims:write"]).await;
    let outcomes = every_tool(
        &pool,
        &outsider_server,
        &http_viewer,
        name,
        "http outsider",
        Some(&http_token),
    )
    .await;
    assert!(
        outcomes.iter().all(|(_, o)| o.is_some()),
        "every HTTP tool refuses a non-member too: {outcomes:?}"
    );
    assert_eq!(
        snapshot(&pool, name).await,
        before,
        "nothing written over HTTP"
    );

    // CALIBRATION: the member is admitted by every tool but deprecate (run
    // last, after the others), and each admitted write is recorded.
    let outcomes = every_tool(&pool, &member_server, &member_viewer, name, "member", None).await;
    for (tool, outcome) in &outcomes {
        assert_eq!(outcome, &None, "stdio {tool} by the submitting member");
    }
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = 'workflows.caller_write' \
          ORDER BY created_at, id",
    )
    .fetch_all(&pool)
    .await
    .expect("caller writes");
    let actions: Vec<&str> = rows.iter().filter_map(|d| d["action"].as_str()).collect();
    for tool in [
        "add_step",
        "delete_step",
        "evolve_step",
        "deprecate_workflow",
    ] {
        assert!(actions.contains(&tool), "{tool} recorded: {actions:?}");
    }
    assert!(
        actions.contains(&"workflow_ingest"),
        "the new generation is recorded against its lineage head: {actions:?}"
    );
    for d in &rows {
        assert_eq!(d["acting_agent"], member.to_string(), "{d}");
        assert_eq!(d["transport"], "stdio", "{d}");
        assert_eq!(d["arm"], "submitter", "{d}");
        assert!(d["client_id"].is_null() && d["token_jti"].is_null(), "{d}");
    }
}

/// A PUBLIC lineage submitted by another stdio agent: the outsider reads it,
/// but is neither its submitter nor the submitter's operator, so every stdio
/// mutation tool refuses it, as the REST twins refuse a non-submitter.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_non_submitter_cannot_mutate_a_public_lineage(pool: PgPool) {
    let member_server = app_role_server(&pool, MEMBER_SEED).await;
    let outsider_server = app_role_server(&pool, OUTSIDER_SEED).await;
    let (member_viewer, member) = stdio(&pool, &member_server, MEMBER_SEED).await;
    let (outsider_viewer, _outsider) = stdio(&pool, &outsider_server, OUTSIDER_SEED).await;
    let name = "stdio-auth-public";
    ingest(&member_server, &member_viewer, name, None).await;
    let submitter: Option<String> = sqlx::query_scalar(
        "SELECT metadata->>'epigraph_submitted_by' FROM workflows WHERE canonical_name = $1",
    )
    .bind(name)
    .fetch_one(&pool)
    .await
    .expect("submitter");
    assert_eq!(
        submitter,
        Some(member.to_string()),
        "a stdio ingest records its agent"
    );

    let before = snapshot(&pool, name).await;
    let outcomes = every_tool(
        &pool,
        &outsider_server,
        &outsider_viewer,
        name,
        "outsider",
        None,
    )
    .await;
    let admitted: Vec<&str> = outcomes
        .iter()
        .filter(|(_, o)| o.is_none())
        .map(|(t, _)| *t)
        .collect();
    assert!(
        admitted.is_empty(),
        "every stdio tool must refuse a non-submitter; admitted: {admitted:?}; all \
         outcomes: {outcomes:?}"
    );
    for (tool, outcome) in &outcomes {
        let Some(message) = outcome else {
            unreachable!()
        };
        assert!(
            message.contains("submitter"),
            "{tool}: refused by the submitter rule, not for another reason: {message}"
        );
    }
    assert_eq!(snapshot(&pool, name).await, before, "nothing written");
}

/// The lineage's `name` ingested by the member into a fresh team group `g`,
/// as in the first test; returns `(g, member's agent id)`.
async fn private_lineage(
    pool: &PgPool,
    member_server: &EpiGraphMcpFull,
    name: &str,
) -> (Uuid, Uuid) {
    let (member_viewer, member) = stdio(pool, member_server, MEMBER_SEED).await;
    ingest(
        member_server,
        &member_viewer,
        &format!("{name}-warmup"),
        None,
    )
    .await;
    let g = team_group(pool, member).await;
    let member_viewer = tools::viewer::request_viewer(member_server, None)
        .await
        .expect("the member's viewer, now in the group");
    ingest(member_server, &member_viewer, name, Some(g)).await;
    let row: (String, Uuid) = sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM workflows WHERE canonical_name = $1",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("the row");
    assert_eq!(row, ("group".to_string(), g), "CALIBRATION: private");
    (g, member)
}

/// Every refusal of `outcomes`, insisting that none was admitted.
fn all_refused(outcomes: &[(&'static str, Option<String>)]) -> Vec<(&'static str, String)> {
    outcomes
        .iter()
        .map(|(tool, outcome)| match outcome {
            Some(message) => (*tool, message.clone()),
            None => panic!("{tool} was admitted; all outcomes: {outcomes:?}"),
        })
        .collect()
}

/// The group-write half of the stdio arm. The lineage's own SUBMITTER, a
/// writer of its group when it ingested, is demoted to READER: it still
/// reads the row, so only the "writes the owner group" check stands between
/// it and a write that lands in the group on the system agent's stamp. Every
/// tool refuses with that check's text. Then its membership is REVOKED: it no
/// longer reads the row, and every tool refuses without naming it. Nothing is
/// written either time. CALIBRATION: as a writer again it is admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_submitter_who_no_longer_writes_the_group_is_refused(pool: PgPool) {
    let member_server = app_role_server(&pool, MEMBER_SEED).await;
    let name = "stdio-auth-demoted";
    let (g, member) = private_lineage(&pool, &member_server, name).await;
    let wf = head(&pool, name).await;
    let before = snapshot(&pool, name).await;

    let n = sqlx::query(
        "UPDATE group_memberships SET role = 'reader' \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(g)
    .bind(member)
    .execute(&pool)
    .await
    .expect("demote")
    .rows_affected();
    assert_eq!(n, 1, "CALIBRATION: one live membership demoted");
    let viewer = tools::viewer::request_viewer(&member_server, None)
        .await
        .expect("the reader's viewer");
    let outcomes = every_tool(&pool, &member_server, &viewer, name, "reader", None).await;
    for (tool, message) in all_refused(&outcomes) {
        assert!(
            message.contains("does not write")
                && message.contains("owner group")
                && message.contains(&member.to_string()),
            "{tool}: refused by the group-write check: {message}"
        );
    }
    assert_eq!(
        snapshot(&pool, name).await,
        before,
        "the reader wrote nothing"
    );

    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(g)
    .bind(member)
    .execute(&pool)
    .await
    .expect("revoke");
    let viewer = tools::viewer::request_viewer(&member_server, None)
        .await
        .expect("the revoked agent's viewer");
    let outcomes = every_tool(&pool, &member_server, &viewer, name, "revoked", None).await;
    for (tool, message) in all_refused(&outcomes) {
        assert!(
            tool == "deprecate_workflow" || !message.contains(&wf.to_string()),
            "{tool}: the refusal must not name the now-hidden workflow: {message}"
        );
        let expected = match tool {
            // The gate's own masked refusal.
            "add_step" | "delete_step" | "improve_workflow_hierarchy" => "can read matches",
            // Both resolve their target on the caller's view first, and the
            // hidden step / row reads as absent.
            "evolve_step" => "not found",
            _ => "can read",
        };
        assert!(
            message.contains(expected),
            "{tool}: refused as a row the caller cannot read ({expected:?}): {message}"
        );
    }
    assert_eq!(
        snapshot(&pool, name).await,
        before,
        "the revoked agent wrote nothing"
    );

    // CALIBRATION: a writer again, the same agent is admitted (add_step).
    let n = sqlx::query(
        "UPDATE group_memberships SET revoked_at = NULL, role = 'writer' \
          WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(g)
    .bind(member)
    .execute(&pool)
    .await
    .expect("re-admit as a writer")
    .rows_affected();
    assert_eq!(n, 1, "CALIBRATION: the one membership row");
    let viewer = tools::viewer::request_viewer(&member_server, None)
        .await
        .expect("the writer's viewer");
    tools::step_ops::add_step(&member_server, &viewer, add(name, "writer again add"), None)
        .await
        .unwrap_or_else(|e| panic!("CALIBRATION: the writer adds: {}", e.message));
}

/// The undeclared-signer arm (`--agent-key` / `--agent-model` absent) admits
/// a non-submitter with a WARN only AFTER the read and group-write checks. An
/// outsider server with a generated signer identity is refused by every tool
/// on a group-private lineage, nothing written and the id not named. The
/// accepted residual is pinned too: on a PUBLIC lineage another agent
/// submitted, that server is admitted and the write is recorded as
/// `arm = undeclared_signer` over stdio.
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_signer_stdio_outsider_cannot_mutate_a_group_private_lineage(pool: PgPool) {
    let member_server = app_role_server(&pool, MEMBER_SEED).await;
    let outsider_server = app_role_server(&pool, OUTSIDER_SEED)
        .await
        .with_generated_signer_identity();
    let (outsider_viewer, outsider) = stdio(&pool, &outsider_server, OUTSIDER_SEED).await;
    let name = "stdio-auth-undeclared";
    let (_g, member) = private_lineage(&pool, &member_server, name).await;
    assert_ne!(member, outsider);
    let wf = head(&pool, name).await;
    let before = snapshot(&pool, name).await;
    let outcomes = every_tool(
        &pool,
        &outsider_server,
        &outsider_viewer,
        name,
        "undeclared",
        None,
    )
    .await;
    for (tool, message) in all_refused(&outcomes) {
        assert!(
            tool == "deprecate_workflow" || !message.contains(&wf.to_string()),
            "{tool}: the refusal must not name the hidden workflow: {message}"
        );
    }
    assert_eq!(snapshot(&pool, name).await, before, "nothing written");

    // The residual, pinned: a PUBLIC lineage the member submitted.
    let (member_viewer, _) = stdio(&pool, &member_server, MEMBER_SEED).await;
    let public = "stdio-auth-undeclared-public";
    ingest(&member_server, &member_viewer, public, None).await;
    tools::step_ops::add_step(
        &outsider_server,
        &outsider_viewer,
        add(public, "undeclared public add"),
        None,
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "the accepted residual: an undeclared stdio signer is admitted on a public lineage: {}",
            e.message
        )
    });
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = 'workflows.caller_write' \
          AND details->>'acting_agent' = $1",
    )
    .bind(outsider.to_string())
    .fetch_all(&pool)
    .await
    .expect("caller writes");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["arm"], "undeclared_signer", "{}", rows[0]);
    assert_eq!(rows[0]["transport"], "stdio", "{}", rows[0]);
    assert!(
        rows[0]["client_id"].is_null() && rows[0]["token_jti"].is_null(),
        "{}",
        rows[0]
    );
}
