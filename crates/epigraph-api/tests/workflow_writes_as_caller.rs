//! Workflow writes are made AS THE CALLER, into a group the caller writes.
//!
//! Every workflow write (`ingest_workflow`, `add_step`, `delete_step`,
//! `evolve_step`, on MCP and on REST) used to be authored by, and stamped
//! from, ONE shared workflow-ingest system agent, live-linked to one human.
//! Its rows landed in that human's group, and the caller was bound to the
//! system agent's human (`require_caller_write_authority`): any other human,
//! however fully onboarded into a team, was refused (`OPL02`) and nothing was
//! written.
//!
//! These tests pin the replacement, on the production pool shape: the router
//! runs on an `epigraph_app` `ScopedPool`, the MCP servers are app-role
//! servers, the database is ARMED (migration 122) with the system agent
//! registered (migration 148) and live-linked to an operator human, and no
//! extra PERMISSIVE policy exists. The harness superuser only seeds and
//! inspects.
//!
//! # The rule pinned
//!
//! * Every row a workflow write creates is authored by the CALLER's own agent
//!   (`claims.agent_id`), on a transaction stamped from the caller's viewer,
//!   and its `AUTHORED` edge comes from the caller.
//! * The owner group is, in order: the declared `tenancy` group (the caller
//!   must write it); else the caller's ONE live non-personal writer group
//!   (public, owned by that team); else the caller's own default group (its
//!   personal group, or its operator's for an operated agent), public.
//! * A team writer is admitted through EITHER membership shape: a role
//!   binding alone (migration 165, computed), or a direct roster row alone.
//! * A declared group the caller does not write is refused, on both
//!   transports, with nothing written.
//! * The operator's own path keeps working: an operator-linked agent with no
//!   team group writes into the operator's group, exactly where the system
//!   agent wrote, and edits a step the system agent wrote before this change.
//! * A new generation of a public lineage whose group the caller no longer
//!   writes lands in the caller's own group, with the parent link kept; a
//!   group-private lineage the caller no longer writes is refused.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const WRITE_SCOPES: &[&str] = &["claims:read", "claims:write", "edges:write"];
const ROLE: &str = "role:acmeteammember";

fn token(agent: Uuid) -> String {
    common::mint_token_with_agent(WRITE_SCOPES, agent)
}

fn uuid_of(v: &Value) -> Uuid {
    Uuid::parse_str(
        v.as_str()
            .unwrap_or_else(|| panic!("not a uuid string: {v}")),
    )
    .unwrap_or_else(|e| panic!("not a uuid: {v}: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// The production-shaped API and MCP servers
// ─────────────────────────────────────────────────────────────────────────────

async fn app_scoped(pool: &PgPool) -> ScopedPool {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

async fn router(pool: &PgPool) -> axum::Router {
    let state = AppState::with_scoped_pool(app_scoped(pool).await, ApiConfig::default());
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    epigraph_api::routes::create_router(state)
}

async fn call(router: &axum::Router, uri: &str, token: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("router");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, value)
}

/// An app-role MCP server whose own (stdio) agent is keyed by `seed`, with a
/// fixed-vector generator so its post-commit embeds run without a provider.
async fn mcp_server(pool: &PgPool, seed: u8) -> epigraph_mcp::server::EpiGraphMcpFull {
    let scoped = app_scoped(pool).await;
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(vec![0.5_f32; 1536])));
    epigraph_mcp::server::EpiGraphMcpFull::new(plain, signer, embedder, false)
        .with_scoped_pool(scoped)
}

/// The stdio server's own agent, created by its first viewer resolution.
async fn stdio_agent(pool: &PgPool, server: &epigraph_mcp::server::EpiGraphMcpFull, seed: u8) -> Uuid {
    epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("the stdio viewer");
    let key = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32])
        .expect("signer")
        .public_key();
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(pool)
        .await
        .expect("the stdio server's agent row")
}

fn http_auth(agent: Uuid) -> epigraph_auth::AuthContext {
    epigraph_auth::AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: epigraph_auth::ClientType::Agent,
        scopes: WRITE_SCOPES.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

fn tool_json(out: &rmcp::model::CallToolResult) -> Value {
    assert_ne!(out.is_error, Some(true), "the tool reported an error: {out:?}");
    let text = out
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("a text result");
    serde_json::from_str(&text).expect("a JSON result")
}

// ─────────────────────────────────────────────────────────────────────────────
// One caller on one transport
// ─────────────────────────────────────────────────────────────────────────────

/// How a test reaches the workflow tools: MCP over the authenticated
/// transport (`auth: Some`), MCP over stdio (`auth: None`, the server's own
/// agent), or REST.
enum Via<'a> {
    McpHttp(&'a epigraph_mcp::server::EpiGraphMcpFull, Uuid),
    McpStdio(&'a epigraph_mcp::server::EpiGraphMcpFull),
    Rest(&'a axum::Router, Uuid),
}

impl Via<'_> {
    fn auth(&self) -> Option<epigraph_auth::AuthContext> {
        match self {
            Via::McpHttp(_, agent) => Some(http_auth(*agent)),
            _ => None,
        }
    }

    async fn mcp_viewer(
        server: &epigraph_mcp::server::EpiGraphMcpFull,
        auth: Option<&epigraph_auth::AuthContext>,
    ) -> Result<epigraph_db::visibility::Viewer, String> {
        epigraph_mcp::tools::viewer::request_viewer(server, auth)
            .await
            .map_err(|e| e.message.to_string())
    }

    /// `ingest_workflow`; `Err` carries the refusal text (MCP) or
    /// `"<status>: <body>"` (REST).
    async fn ingest(&self, extraction: &Value, tenancy: Option<Uuid>) -> Result<Value, String> {
        match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let auth = self.auth();
                let viewer = Self::mcp_viewer(server, auth.as_ref()).await?;
                let mut params = json!({ "extraction": extraction });
                if let Some(g) = tenancy {
                    params["tenancy"] = json!({"visibility": "group", "owner_group_id": g});
                }
                let params = serde_json::from_value(params).expect("ingest params");
                epigraph_mcp::tools::workflow_ingest::ingest_workflow(
                    server,
                    &viewer,
                    params,
                    auth.as_ref(),
                )
                .await
                .map(|out| tool_json(&out))
                .map_err(|e| e.message.to_string())
            }
            Via::Rest(router, agent) => {
                let mut body = extraction.clone();
                if let Some(g) = tenancy {
                    body["tenancy"] = json!({"visibility": "group", "owner_group_id": g});
                }
                let (s, b) = call(router, "/api/v1/workflows/ingest", &token(*agent), &body).await;
                if s == StatusCode::OK {
                    Ok(b)
                } else {
                    Err(format!("{s}: {b}"))
                }
            }
        }
    }

    /// `evolve_step` (`revises`) of `parent`; returns the new claim id.
    async fn evolve(&self, parent: Uuid, content: &str) -> Result<Uuid, String> {
        match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let auth = self.auth();
                let viewer = Self::mcp_viewer(server, auth.as_ref()).await?;
                let params = serde_json::from_value(json!({
                    "parent_id": parent.to_string(),
                    "content": content,
                    "edge_type": "revises",
                }))
                .expect("evolve params");
                let out = epigraph_mcp::tools::evolve_step::evolve_step(
                    server,
                    &viewer,
                    params,
                    auth.as_ref(),
                )
                .await
                .map_err(|e| e.message.to_string())?;
                Ok(uuid_of(&tool_json(&out)["claim_id"]))
            }
            Via::Rest(router, agent) => {
                let (s, b) = call(
                    router,
                    &format!("/api/v1/workflows/steps/{parent}/evolve"),
                    &token(*agent),
                    &json!({"parent_id": parent, "content": content, "edge_type": "revises"}),
                )
                .await;
                if s == StatusCode::OK {
                    Ok(uuid_of(&b["claim_id"]))
                } else {
                    Err(format!("{s}: {b}"))
                }
            }
        }
    }

    /// `add_step` (appended); returns `(step claim id, step lineage id)`.
    async fn add_step(&self, name: &str, text: &str) -> Result<(Uuid, Uuid), String> {
        let out = match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let auth = self.auth();
                let viewer = Self::mcp_viewer(server, auth.as_ref()).await?;
                let params = epigraph_mcp::tools::step_ops::AddStepParams {
                    canonical_name: name.to_string(),
                    step_text: text.to_string(),
                    position: None,
                };
                let out = epigraph_mcp::tools::step_ops::add_step(
                    server,
                    &viewer,
                    params,
                    auth.as_ref(),
                )
                .await
                .map_err(|e| e.message.to_string())?;
                tool_json(&out)
            }
            Via::Rest(router, agent) => {
                let (s, b) = call(
                    router,
                    "/api/v1/workflows/steps",
                    &token(*agent),
                    &json!({"canonical_name": name, "step_text": text}),
                )
                .await;
                if s != StatusCode::OK {
                    return Err(format!("{s}: {b}"));
                }
                b
            }
        };
        Ok((
            uuid_of(&out["step_claim_id"]),
            uuid_of(&out["step_lineage_id"]),
        ))
    }

    /// `delete_step` of `lineage`; returns the soft-deleted claim id.
    async fn delete_step(&self, name: &str, lineage: Uuid) -> Result<Uuid, String> {
        let out = match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let auth = self.auth();
                let viewer = Self::mcp_viewer(server, auth.as_ref()).await?;
                let params = epigraph_mcp::tools::step_ops::DeleteStepParams {
                    canonical_name: name.to_string(),
                    step_lineage_id: lineage.to_string(),
                };
                let out = epigraph_mcp::tools::step_ops::delete_step(
                    server,
                    &viewer,
                    params,
                    auth.as_ref(),
                )
                .await
                .map_err(|e| e.message.to_string())?;
                tool_json(&out)
            }
            Via::Rest(router, agent) => {
                let (s, b) = call(
                    router,
                    "/api/v1/workflows/steps/delete",
                    &token(*agent),
                    &json!({"canonical_name": name, "step_lineage_id": lineage}),
                )
                .await;
                if s != StatusCode::OK {
                    return Err(format!("{s}: {b}"));
                }
                b
            }
        };
        Ok(uuid_of(&out["step_claim_id"]))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Payloads and harness reads
// ─────────────────────────────────────────────────────────────────────────────

/// One phase of `steps` level-2 steps, each with one operation atom; every
/// text embeds `name`.
fn extraction(name: &str, generation: u32, steps: usize) -> Value {
    let steps: Vec<Value> = (0..steps)
        .map(|i| {
            json!({"compound": format!("{name} step {i}"),
                   "rationale": "ordered",
                   "operations": [format!("{name} operation {i}")],
                   "generality": [], "confidence": 0.8})
        })
        .collect();
    json!({
        "source": {"canonical_name": name,
                   "goal": format!("workflow goal for {name}"),
                   "generation": generation, "metadata": {}},
        "thesis_derivation": "TopDown",
        "phases": [{"title": "Body", "summary": format!("{name} phase"), "steps": steps}],
        "relationships": []
    })
}

/// `(claims, edges, workflows, mass_functions)` row counts: a refusal that
/// writes nothing leaves every one of them unchanged.
async fn row_counts(pool: &PgPool) -> (i64, i64, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM claims), (SELECT count(*) FROM edges), \
                (SELECT count(*) FROM workflows), (SELECT count(*) FROM mass_functions)",
    )
    .fetch_one(pool)
    .await
    .expect("row counts")
}

async fn workflow_named(pool: &PgPool, name: &str, generation: i32) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1 AND generation = $2")
        .bind(name)
        .bind(generation)
        .fetch_optional(pool)
        .await
        .expect("workflow row")
}

/// The workflow row's `(visibility, owner group, recorded submitter, parent)`.
async fn workflow_row(pool: &PgPool, wf: Uuid) -> (String, Uuid, Option<String>, Option<Uuid>) {
    sqlx::query_as(
        "SELECT visibility::text, owner_group_id, metadata->>'epigraph_submitted_by', parent_id \
           FROM workflows WHERE id = $1",
    )
    .bind(wf)
    .fetch_one(pool)
    .await
    .expect("workflow row")
}

/// Every claim the workflow executes: `(id, level, author, visibility, owner)`.
async fn plan(pool: &PgPool, wf: Uuid) -> Vec<(Uuid, i32, Uuid, String, Uuid)> {
    sqlx::query_as(
        "SELECT c.id, (e.properties->>'level')::int, c.agent_id, c.visibility::text, \
                c.owner_group_id \
           FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
          ORDER BY (e.properties->>'plan_index')::int NULLS LAST, c.created_at",
    )
    .bind(wf)
    .fetch_all(pool)
    .await
    .expect("plan")
}

/// One claim's `(author, visibility, owner)`.
async fn claim_row(pool: &PgPool, id: Uuid) -> (Uuid, String, Uuid) {
    sqlx::query_as("SELECT agent_id, visibility::text, owner_group_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("claim row")
}

async fn authored_by(pool: &PgPool, agent: Uuid, claim: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM edges WHERE source_id = $1 AND source_type = 'agent' \
                         AND target_id = $2 AND relationship = 'AUTHORED')",
    )
    .bind(agent)
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("AUTHORED edge")
}

async fn truth(pool: &PgPool, id: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("truth value")
}

async fn step_lineage(pool: &PgPool, id: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT step_lineage_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("step lineage")
}

/// Every claim of `wf`'s plan, and the row itself, are `(visibility, owner)`
/// and authored by `author` (claims) / submitted by `author` (row), with an
/// `AUTHORED` edge from `author`. Returns the plan's level-2 step ids.
async fn assert_written_as(
    pool: &PgPool,
    wf: Uuid,
    author: Uuid,
    visibility: &str,
    owner: Uuid,
    what: &str,
) -> Vec<Uuid> {
    let (v, o, submitter, _) = workflow_row(pool, wf).await;
    assert_eq!((v.as_str(), o), (visibility, owner), "{what}: the workflow row's tenancy");
    assert_eq!(
        submitter,
        Some(author.to_string()),
        "{what}: the row records the caller as its submitter"
    );
    let plan = plan(pool, wf).await;
    assert!(plan.len() >= 3, "{what}: a phase, steps and atoms: {plan:?}");
    for (id, _, agent, v, o) in &plan {
        assert_eq!(
            *agent, author,
            "{what}: claim {id} is authored by the caller's own agent, not a shared system agent"
        );
        assert_eq!(
            (v.as_str(), *o),
            (visibility, owner),
            "{what}: claim {id}'s tenancy"
        );
        assert!(
            authored_by(pool, author, *id).await,
            "{what}: an AUTHORED edge from the caller to {id}"
        );
    }
    plan.into_iter()
        .filter(|(_, level, ..)| *level == 2)
        .map(|(id, ..)| id)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// The armed world
// ─────────────────────────────────────────────────────────────────────────────

async fn as_maintenance<T, F, Fut>(pool: &PgPool, f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    fixture::as_role(pool, "epigraph_maintenance", f).await
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    as_maintenance(pool, move |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_link_operator($1, $2)")
            .bind(agent)
            .bind(operator)
            .execute(&mut *conn)
            .await
            .unwrap_or_else(|e| panic!("link {agent} to {operator}: {e}"));
        (conn, ())
    })
    .await;
}

async fn arm(pool: &PgPool) {
    let armed: bool = as_maintenance(pool, |mut conn| async move {
        let armed: bool =
            sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
                .fetch_one(&mut *conn)
                .await
                .expect("arm");
        (conn, armed)
    })
    .await;
    assert!(armed, "the database arms");
}

/// A keyless team group made by migration 164's verb, administered by `admin`.
async fn team_group(pool: &PgPool, name: &'static str, admin: Uuid) -> Uuid {
    as_maintenance(pool, move |mut conn| async move {
        let g: Uuid = sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
            .bind(name)
            .bind(admin)
            .bind("workflow writes as caller test")
            .fetch_one(&mut *conn)
            .await
            .expect("create the team group");
        (conn, g)
    })
    .await
}

/// A DIRECT roster row through migration 164's verb.
async fn add_roster_row(pool: &PgPool, group: Uuid, agent: Uuid, role: &'static str) {
    as_maintenance(pool, move |mut conn| async move {
        let applied: bool = sqlx::query_scalar(
            "SELECT out_applied FROM public.epigraph_team_group_add_member($1, $2, $3, 'test')",
        )
        .bind(group)
        .bind(agent)
        .bind(role)
        .fetch_one(&mut *conn)
        .await
        .expect("add the roster row");
        assert!(applied, "the roster row is written");
        (conn, ())
    })
    .await;
}

async fn remove_roster_row(pool: &PgPool, group: Uuid, agent: Uuid) {
    as_maintenance(pool, move |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_team_group_remove_member($1, $2, 'test')")
            .bind(group)
            .bind(agent)
            .execute(&mut *conn)
            .await
            .expect("remove the roster row");
        (conn, ())
    })
    .await;
}

/// Define `ROLE` and bind it to `group` as `writer` (agents included).
async fn bind_role(pool: &PgPool, group: Uuid) {
    as_maintenance(pool, move |mut conn| async move {
        sqlx::query("SELECT public.epigraph_define_group_role($1, $2, $3, 'writer', true, 'test')")
            .bind(ROLE)
            .bind("synthetic team role")
            .bind(group)
            .execute(&mut *conn)
            .await
            .expect("define and bind the role");
        (conn, ())
    })
    .await;
}

/// Grant `ROLE` to `holder` from now, open-ended. Returns the assignment.
async fn grant_role(pool: &PgPool, holder: Uuid) -> Uuid {
    as_maintenance(pool, move |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_grant_role($1, $2, now(), NULL::timestamptz, NULL::uuid, 'test')",
        )
        .bind(ROLE)
        .bind(holder)
        .fetch_one(&mut *conn)
        .await
        .expect("grant the role");
        (conn, id)
    })
    .await
}

async fn end_role(pool: &PgPool, assignment: Uuid) {
    as_maintenance(pool, move |mut conn| async move {
        let ended: bool = sqlx::query_scalar("SELECT public.epigraph_end_role_assignment($1, 'test')")
            .bind(assignment)
            .fetch_one(&mut *conn)
            .await
            .expect("end the role");
        assert!(ended, "the assignment ends");
        (conn, ())
    })
    .await;
}

async fn writes(pool: &PgPool, agent: Uuid, group: Uuid) -> bool {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
        .writable_groups()
        .contains(&group)
}

/// The armed world.
///
/// * `op`: the operator human (personal group `op_g`). The registered system
///   agent is live-linked to `op`, as on a live instance, and is a writer of
///   both team groups. `op` administers both.
/// * `alpha`, `beta`: two team groups.
/// * `rb`: a human who writes `alpha` through a ROLE BINDING only.
/// * `dr`: a human who writes `alpha` through a DIRECT roster row only.
/// * `c` / `c_server`: an operator-linked stdio agent with no team group.
/// * `legacy`: a workflow the system agent wrote before this change (public,
///   in `op_g`, no recorded submitter).
struct World {
    router: axum::Router,
    mcp: epigraph_mcp::server::EpiGraphMcpFull,
    op: Uuid,
    op_g: Uuid,
    system: Uuid,
    alpha: Uuid,
    beta: Uuid,
    rb: Uuid,
    rb_g: Uuid,
    rb_role: Uuid,
    dr: Uuid,
    dr_g: Uuid,
    c: Uuid,
    c_server: epigraph_mcp::server::EpiGraphMcpFull,
}

const LEGACY: &str = "acme-legacy-system-written";

async fn world(pool: &PgPool) -> World {
    let (op, op_g) = fixture::seed_human_operator(pool, "acme-operator").await;
    let (rb, rb_g) = fixture::seed_human_operator(pool, "acme-role-member").await;
    let (dr, dr_g) = fixture::seed_human_operator(pool, "acme-roster-member").await;
    let system = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    assert!(fixture::register_system_agent(pool, system).await);
    link(pool, system, op).await;
    // A workflow the system agent wrote before this change: the unattended
    // executor path, on its own stamp, exactly as every pre-change ingest.
    {
        let scoped = app_scoped(pool).await;
        let authority = epigraph_ingest_executor::system_agent_write_authority(&scoped)
            .await
            .expect("the system agent's authority");
        let extraction: epigraph_ingest::workflow::WorkflowExtraction =
            serde_json::from_value(extraction(LEGACY, 0, 2)).expect("legacy extraction");
        let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
        let mut tx = scoped.begin_as(&authority.viewer).await.expect("stamp");
        epigraph_ingest_executor::execute_workflow_ingest_plan(&mut tx, &plan, &extraction)
            .await
            .expect("the legacy ingest");
        tx.commit().await.expect("commit the legacy ingest");
    }
    let alpha = team_group(pool, "acme-alpha", op).await;
    let beta = team_group(pool, "acme-beta", op).await;
    for g in [alpha, beta] {
        add_roster_row(pool, g, system, "writer").await;
    }
    bind_role(pool, alpha).await;
    let rb_role = grant_role(pool, rb).await;
    add_roster_row(pool, alpha, dr, "writer").await;
    let mcp = mcp_server(pool, 0xA1).await;
    let c_server = mcp_server(pool, 0xC1).await;
    let c = stdio_agent(pool, &c_server, 0xC1).await;
    link(pool, c, op).await;
    arm(pool).await;

    // The premises the tests rely on.
    assert!(writes(pool, rb, alpha).await, "PREMISE: rb writes alpha (role binding)");
    assert!(writes(pool, dr, alpha).await, "PREMISE: dr writes alpha (roster row)");
    for who in [rb, dr] {
        assert!(!writes(pool, who, beta).await, "PREMISE: {who} does not write beta");
    }
    let rb_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(alpha)
    .bind(rb)
    .fetch_one(pool)
    .await
    .expect("rb's rows");
    assert_eq!(rb_rows, 0, "PREMISE: rb's alpha membership is the binding alone");
    assert!(!writes(pool, c, alpha).await && !writes(pool, c, beta).await);
    assert!(writes(pool, c, op_g).await, "PREMISE: the linked agent writes op's group");

    World {
        router: router(pool).await,
        mcp,
        op,
        op_g,
        system,
        alpha,
        beta,
        rb,
        rb_g,
        rb_role,
        dr,
        dr_g,
        c,
        c_server,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A non-operator team writer: ingest, evolve, add, delete; refused elsewhere
// ─────────────────────────────────────────────────────────────────────────────

/// The whole cycle for one caller on one transport.
async fn team_writer_cycle(pool: &PgPool, w: &World, via: Via<'_>, caller: Uuid, tag: &str) {
    // 1. No tenancy: the caller's ONE team group, public.
    let name = format!("acme-{tag}-team-default");
    let out = via
        .ingest(&extraction(&name, 0, 2), None)
        .await
        .unwrap_or_else(|e| panic!("{tag}: a team writer's ingest is admitted: {e}"));
    let wf = uuid_of(&out["workflow_id"]);
    let steps = assert_written_as(pool, wf, caller, "public", w.alpha, tag).await;
    assert_eq!(steps.len(), 2, "{tag}: two steps");

    // 2. Its steps evolve, as the caller, in the workflow's group.
    let evolved = via
        .evolve(steps[0], &format!("{name} step 0, revised"))
        .await
        .unwrap_or_else(|e| panic!("{tag}: the submitter evolves its own step: {e}"));
    assert_eq!(
        claim_row(pool, evolved).await,
        (caller, "public".to_string(), w.alpha),
        "{tag}: the evolved step is the caller's, in alpha"
    );

    // 3. add_step and delete_step, as the caller.
    let (added, lineage) = via
        .add_step(&name, &format!("{name} step added"))
        .await
        .unwrap_or_else(|e| panic!("{tag}: the submitter adds a step: {e}"));
    assert_eq!(
        claim_row(pool, added).await,
        (caller, "public".to_string(), w.alpha),
        "{tag}: the added step is the caller's, in alpha"
    );
    assert!(authored_by(pool, caller, added).await, "{tag}: AUTHORED edge on the added step");
    let deleted = via
        .delete_step(&name, lineage)
        .await
        .unwrap_or_else(|e| panic!("{tag}: the submitter deletes a step: {e}"));
    assert_eq!(deleted, added);
    assert!((truth(pool, added).await - 0.05).abs() < 1e-9, "{tag}: soft-deleted");

    // 4. A declared tenancy the caller writes: ('group', alpha).
    let name = format!("acme-{tag}-declared");
    let out = via
        .ingest(&extraction(&name, 0, 1), Some(w.alpha))
        .await
        .unwrap_or_else(|e| panic!("{tag}: a declared ingest into alpha: {e}"));
    assert_written_as(pool, uuid_of(&out["workflow_id"]), caller, "group", w.alpha, tag).await;

    // 5. A declared group the caller does NOT write: refused, nothing written.
    let name = format!("acme-{tag}-refused");
    let before = row_counts(pool).await;
    let refused = via.ingest(&extraction(&name, 0, 1), Some(w.beta)).await;
    assert!(refused.is_err(), "{tag}: a group the caller does not write is refused: {refused:?}");
    assert_eq!(row_counts(pool).await, before, "{tag}: the refusal wrote nothing");
    assert_eq!(workflow_named(pool, &name, 0).await, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_role_bound_team_writer_works_through_mcp(pool: PgPool) {
    let w = world(&pool).await;
    team_writer_cycle(&pool, &w, Via::McpHttp(&w.mcp, w.rb), w.rb, "rb-mcp").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_role_bound_team_writer_works_through_rest(pool: PgPool) {
    let w = world(&pool).await;
    team_writer_cycle(&pool, &w, Via::Rest(&w.router, w.rb), w.rb, "rb-rest").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_roster_row_team_writer_works_through_mcp(pool: PgPool) {
    let w = world(&pool).await;
    team_writer_cycle(&pool, &w, Via::McpHttp(&w.mcp, w.dr), w.dr, "dr-mcp").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_roster_row_team_writer_works_through_rest(pool: PgPool) {
    let w = world(&pool).await;
    team_writer_cycle(&pool, &w, Via::Rest(&w.router, w.dr), w.dr, "dr-rest").await;
}

/// A team writer cannot touch the operator's workflows: the lineage gate
/// keeps its arms (submitter, its operator, the audited admin arm), so a
/// writer who is none of those is refused on every write tool, and a legacy
/// (unrecorded) workflow stays admin-only over the authenticated transport.
#[sqlx::test(migrations = "../../migrations")]
async fn the_lineage_gate_still_refuses_a_team_writer_on_another_submitters_workflow(pool: PgPool) {
    let w = world(&pool).await;
    // The operator's own workflow, ingested by its linked agent.
    let name = "acme-operator-owned";
    via_ok(Via::McpStdio(&w.c_server).ingest(&extraction(name, 0, 2), None).await);
    let wf = workflow_named(&pool, name, 0).await.expect("the operator's workflow");
    let steps: Vec<Uuid> = plan(&pool, wf)
        .await
        .into_iter()
        .filter(|(_, l, ..)| *l == 2)
        .map(|(id, ..)| id)
        .collect();
    for via in [Via::McpHttp(&w.mcp, w.rb), Via::Rest(&w.router, w.rb)] {
        let before = row_counts(&pool).await;
        assert!(via.add_step(name, "acme intruding step").await.is_err());
        assert!(via.evolve(steps[0], "acme intruding revision").await.is_err());
        let lineage = step_lineage(&pool, steps[0]).await;
        assert!(via.delete_step(name, lineage).await.is_err());
        assert!(via.add_step(LEGACY, "acme intruding legacy step").await.is_err());
        assert_eq!(row_counts(&pool).await, before, "the refusals wrote nothing");
    }
}

fn via_ok(r: Result<Value, String>) -> Value {
    r.unwrap_or_else(|e| panic!("expected success: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// The operator's own path
// ─────────────────────────────────────────────────────────────────────────────

/// An operator-linked agent with no team group writes where the system agent
/// wrote (the operator's group, public), but as ITSELF; and it edits a step of
/// the workflow the system agent wrote before this change (stdio's legacy arm:
/// it reads the row and writes its group).
#[sqlx::test(migrations = "../../migrations")]
async fn the_operators_linked_agent_writes_where_the_system_agent_did_but_as_itself(pool: PgPool) {
    let w = world(&pool).await;
    let via = Via::McpStdio(&w.c_server);
    let name = "acme-operator-path";
    let out = via_ok(via.ingest(&extraction(name, 0, 2), None).await);
    let steps =
        assert_written_as(&pool, uuid_of(&out["workflow_id"]), w.c, "public", w.op_g, "operator")
            .await;
    let evolved = via
        .evolve(steps[1], "acme operator path step 1, revised")
        .await
        .expect("the operator's agent evolves its step");
    assert_eq!(claim_row(&pool, evolved).await, (w.c, "public".into(), w.op_g));

    // The legacy, system-authored workflow: add a step, then delete one of
    // the steps the SYSTEM agent wrote.
    let legacy = workflow_named(&pool, LEGACY, 0).await.expect("legacy row");
    let legacy_steps: Vec<(Uuid, Uuid)> = plan(&pool, legacy)
        .await
        .into_iter()
        .filter(|(_, l, ..)| *l == 2)
        .map(|(id, _, a, ..)| (id, a))
        .collect();
    assert!(
        legacy_steps.iter().all(|(_, a)| *a == w.system),
        "PREMISE: the legacy steps are the system agent's"
    );
    let (added, _) = via
        .add_step(LEGACY, "acme legacy appended step")
        .await
        .expect("add a step to the legacy workflow");
    assert_eq!(claim_row(&pool, added).await, (w.c, "public".into(), w.op_g));
    let lineage = step_lineage(&pool, legacy_steps[0].0).await;
    let deleted = via
        .delete_step(LEGACY, lineage)
        .await
        .expect("soft-delete a system-authored step");
    assert_eq!(deleted, legacy_steps[0].0);
    assert!((truth(&pool, deleted).await - 0.05).abs() < 1e-9);
    let _ = (w.op, w.rb_g, w.dr_g, w.dr);
}

// ─────────────────────────────────────────────────────────────────────────────
// A new generation of a lineage whose group the caller no longer writes
// ─────────────────────────────────────────────────────────────────────────────

/// Public lineage: the next generation lands in the caller's OWN group, with
/// the parent link kept. Group-private lineage: refused, nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_generation_outside_the_lineages_group_follows_the_callers_order(pool: PgPool) {
    let w = world(&pool).await;
    let via = Via::McpHttp(&w.mcp, w.rb);
    let public_name = "acme-generations-public";
    let private_name = "acme-generations-private";
    let g0 = uuid_of(&via_ok(via.ingest(&extraction(public_name, 0, 1), None).await)["workflow_id"]);
    assert_eq!(workflow_row(&pool, g0).await.1, w.alpha, "gen 0 in alpha");
    via_ok(via.ingest(&extraction(private_name, 0, 1), Some(w.alpha)).await);

    end_role(&pool, w.rb_role).await;
    assert!(!writes(&pool, w.rb, w.alpha).await, "PREMISE: rb no longer writes alpha");

    let out = via_ok(via.ingest(&extraction(public_name, 1, 1), None).await);
    let g1 = uuid_of(&out["workflow_id"]);
    let (v, owner, submitter, parent) = workflow_row(&pool, g1).await;
    assert_eq!((v.as_str(), owner), ("public", w.rb_g), "gen 1 in the caller's own group");
    assert_eq!(submitter, Some(w.rb.to_string()), "the lineage's submitter is inherited");
    assert_eq!(parent, Some(g0), "the parent link is kept");
    let variant_of: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM edges WHERE source_id = $1 AND target_id = $2 \
                         AND relationship = 'variant_of')",
    )
    .bind(g1)
    .bind(g0)
    .fetch_one(&pool)
    .await
    .expect("variant_of");
    assert!(variant_of, "the variant_of edge is kept");

    let before = row_counts(&pool).await;
    let refused = via.ingest(&extraction(private_name, 1, 1), None).await;
    assert!(refused.is_err(), "a private lineage the caller no longer writes: {refused:?}");
    assert_eq!(row_counts(&pool).await, before, "the refusal wrote nothing");
    assert_eq!(workflow_named(&pool, private_name, 1).await, None);

    // A roster-row writer removed from the group behaves the same.
    let via = Via::Rest(&w.router, w.dr);
    let name = "acme-generations-roster";
    let g0 = uuid_of(&via_ok(via.ingest(&extraction(name, 0, 1), None).await)["workflow_id"]);
    remove_roster_row(&pool, w.alpha, w.dr).await;
    let g1 = uuid_of(&via_ok(via.ingest(&extraction(name, 1, 1), None).await)["workflow_id"]);
    let (v, owner, _, parent) = workflow_row(&pool, g1).await;
    assert_eq!((v.as_str(), owner, parent), ("public", w.dr_g, Some(g0)));
}
