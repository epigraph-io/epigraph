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
//! * The tenancy is, in order: the declared `tenancy` (`group` or, the only
//!   way to publish, `public`; the caller must write its group); else a new
//!   generation keeps its lineage's visibility; else the caller's ONE live
//!   non-personal writer group, private to it; else the caller's own default
//!   group (its personal group, or its operator's for an operated agent),
//!   private to it.
//! * A caller that writes a workflow's owner group may edit it (add, delete,
//!   evolve, next generation) whoever submitted it.
//! * A re-ingest of an existing workflow writes nothing to it.
//! * A team writer is admitted through EITHER membership shape: a role
//!   binding alone (migration 165, computed), or a direct roster row alone.
//! * A declared group the caller does not write is refused, on both
//!   transports, with nothing written.
//! * The operator's own path keeps working: an operator-linked agent with no
//!   team group writes into the operator's group (private to it now), and
//!   edits a step the system agent wrote before this change.
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
async fn stdio_agent(
    pool: &PgPool,
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    seed: u8,
) -> Uuid {
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
    assert_ne!(
        out.is_error,
        Some(true),
        "the tool reported an error: {out:?}"
    );
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
    /// `"<status>: <body>"` (REST). `tenancy: Some(g)` declares `('group', g)`.
    async fn ingest(&self, extraction: &Value, tenancy: Option<Uuid>) -> Result<Value, String> {
        self.ingest_with(
            extraction,
            tenancy.map(|g| json!({"visibility": "group", "owner_group_id": g})),
        )
        .await
    }

    /// `ingest_workflow` with any `tenancy` value (the explicit public form
    /// included).
    async fn ingest_with(
        &self,
        extraction: &Value,
        tenancy: Option<Value>,
    ) -> Result<Value, String> {
        match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let auth = self.auth();
                let viewer = Self::mcp_viewer(server, auth.as_ref()).await?;
                let mut params = json!({ "extraction": extraction });
                if let Some(t) = &tenancy {
                    params["tenancy"] = t.clone();
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
                if let Some(t) = &tenancy {
                    body["tenancy"] = t.clone();
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

    /// `store_workflow` (MCP) / `POST /api/v1/workflows` (REST) of `goal` with
    /// `steps`, and an optional `tenancy` value.
    async fn store(
        &self,
        goal: &str,
        steps: &[&str],
        tenancy: Option<Value>,
    ) -> Result<Value, String> {
        let mut body = json!({"goal": goal, "steps": steps});
        if let Some(t) = &tenancy {
            body["tenancy"] = t.clone();
        }
        match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let auth = self.auth();
                let viewer = Self::mcp_viewer(server, auth.as_ref()).await?;
                let params = serde_json::from_value(body).expect("store params");
                epigraph_mcp::tools::workflows::store_workflow(
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
                let (s, b) = call(router, "/api/v1/workflows", &token(*agent), &body).await;
                if s == StatusCode::OK {
                    Ok(b)
                } else {
                    Err(format!("{s}: {b}"))
                }
            }
        }
    }

    /// MCP `deprecate_workflow` of a hierarchical workflow, with `cascade`.
    async fn deprecate(&self, workflow: Uuid, cascade: bool) -> Result<Value, String> {
        match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let auth = self.auth();
                let viewer = Self::mcp_viewer(server, auth.as_ref()).await?;
                let params = serde_json::from_value(json!({
                    "workflow_id": workflow.to_string(),
                    "reason": "acme test deprecation",
                    "cascade": cascade,
                }))
                .expect("deprecate params");
                epigraph_mcp::tools::workflows::deprecate_workflow(
                    server,
                    &viewer,
                    params,
                    auth.as_ref(),
                )
                .await
                .map(|out| tool_json(&out))
                .map_err(|e| e.message.to_string())
            }
            Via::Rest(..) => panic!("hierarchical deprecation is an MCP tool"),
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
                let out =
                    epigraph_mcp::tools::step_ops::add_step(server, &viewer, params, auth.as_ref())
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

/// Every `events` row: the table has no row security, so an event is seen
/// by every reader of the stream.
async fn event_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(pool)
        .await
        .expect("event count")
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
    assert_eq!(
        (v.as_str(), o),
        (visibility, owner),
        "{what}: the workflow row's tenancy"
    );
    assert_eq!(
        submitter,
        Some(author.to_string()),
        "{what}: the row records the caller as its submitter"
    );
    let plan = plan(pool, wf).await;
    assert!(
        plan.len() >= 3,
        "{what}: a phase, steps and atoms: {plan:?}"
    );
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
        let ended: bool =
            sqlx::query_scalar("SELECT public.epigraph_end_role_assignment($1, 'test')")
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
    assert!(
        writes(pool, rb, alpha).await,
        "PREMISE: rb writes alpha (role binding)"
    );
    assert!(
        writes(pool, dr, alpha).await,
        "PREMISE: dr writes alpha (roster row)"
    );
    for who in [rb, dr] {
        assert!(
            !writes(pool, who, beta).await,
            "PREMISE: {who} does not write beta"
        );
    }
    let rb_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(alpha)
    .bind(rb)
    .fetch_one(pool)
    .await
    .expect("rb's rows");
    assert_eq!(
        rb_rows, 0,
        "PREMISE: rb's alpha membership is the binding alone"
    );
    assert!(!writes(pool, c, alpha).await && !writes(pool, c, beta).await);
    assert!(
        writes(pool, c, op_g).await,
        "PREMISE: the linked agent writes op's group"
    );

    World {
        router: router(pool).await,
        mcp,
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
    // 1. No tenancy: the caller's ONE team group, private to it.
    let name = format!("acme-{tag}-team-default");
    let out = via
        .ingest(&extraction(&name, 0, 2), None)
        .await
        .unwrap_or_else(|e| panic!("{tag}: a team writer's ingest is admitted: {e}"));
    let wf = uuid_of(&out["workflow_id"]);
    let steps = assert_written_as(pool, wf, caller, "group", w.alpha, tag).await;
    assert_eq!(steps.len(), 2, "{tag}: two steps");

    // 2. Its steps evolve, as the caller, in the workflow's group.
    let evolved = via
        .evolve(steps[0], &format!("{name} step 0, revised"))
        .await
        .unwrap_or_else(|e| panic!("{tag}: the submitter evolves its own step: {e}"));
    assert_eq!(
        claim_row(pool, evolved).await,
        (caller, "group".to_string(), w.alpha),
        "{tag}: the evolved step is the caller's, in alpha"
    );

    // 3. add_step and delete_step, as the caller.
    let (added, lineage) = via
        .add_step(&name, &format!("{name} step added"))
        .await
        .unwrap_or_else(|e| panic!("{tag}: the submitter adds a step: {e}"));
    assert_eq!(
        claim_row(pool, added).await,
        (caller, "group".to_string(), w.alpha),
        "{tag}: the added step is the caller's, in alpha"
    );
    assert!(
        authored_by(pool, caller, added).await,
        "{tag}: AUTHORED edge on the added step"
    );
    let deleted = via
        .delete_step(&name, lineage)
        .await
        .unwrap_or_else(|e| panic!("{tag}: the submitter deletes a step: {e}"));
    assert_eq!(deleted, added);
    assert!(
        (truth(pool, added).await - 0.05).abs() < 1e-9,
        "{tag}: soft-deleted"
    );

    // 4. A declared tenancy the caller writes: ('group', alpha).
    let name = format!("acme-{tag}-declared");
    let out = via
        .ingest(&extraction(&name, 0, 1), Some(w.alpha))
        .await
        .unwrap_or_else(|e| panic!("{tag}: a declared ingest into alpha: {e}"));
    assert_written_as(
        pool,
        uuid_of(&out["workflow_id"]),
        caller,
        "group",
        w.alpha,
        tag,
    )
    .await;

    // 5. A declared group the caller does NOT write: refused, nothing written.
    let name = format!("acme-{tag}-refused");
    let before = row_counts(pool).await;
    let refused = via.ingest(&extraction(&name, 0, 1), Some(w.beta)).await;
    assert!(
        refused.is_err(),
        "{tag}: a group the caller does not write is refused: {refused:?}"
    );
    assert_eq!(
        row_counts(pool).await,
        before,
        "{tag}: the refusal wrote nothing"
    );
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
    via_ok(
        Via::McpStdio(&w.c_server)
            .ingest(&extraction(name, 0, 2), None)
            .await,
    );
    let wf = workflow_named(&pool, name, 0)
        .await
        .expect("the operator's workflow");
    let steps: Vec<Uuid> = plan(&pool, wf)
        .await
        .into_iter()
        .filter(|(_, l, ..)| *l == 2)
        .map(|(id, ..)| id)
        .collect();
    for via in [Via::McpHttp(&w.mcp, w.rb), Via::Rest(&w.router, w.rb)] {
        let before = row_counts(&pool).await;
        assert!(via.add_step(name, "acme intruding step").await.is_err());
        assert!(via
            .evolve(steps[0], "acme intruding revision")
            .await
            .is_err());
        let lineage = step_lineage(&pool, steps[0]).await;
        assert!(via.delete_step(name, lineage).await.is_err());
        assert!(via
            .add_step(LEGACY, "acme intruding legacy step")
            .await
            .is_err());
        assert_eq!(
            row_counts(&pool).await,
            before,
            "the refusals wrote nothing"
        );
    }
}

fn via_ok(r: Result<Value, String>) -> Value {
    r.unwrap_or_else(|e| panic!("expected success: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// The operator's own path
// ─────────────────────────────────────────────────────────────────────────────

/// An operator-linked agent with no team group writes into the group the
/// system agent wrote to (the operator's group, now private to it), but as
/// ITSELF; and it edits a step of
/// the workflow the system agent wrote before this change (stdio's legacy arm:
/// it reads the row and writes its group).
#[sqlx::test(migrations = "../../migrations")]
async fn the_operators_linked_agent_writes_where_the_system_agent_did_but_as_itself(pool: PgPool) {
    let w = world(&pool).await;
    let via = Via::McpStdio(&w.c_server);
    let name = "acme-operator-path";
    let out = via_ok(via.ingest(&extraction(name, 0, 2), None).await);
    let steps = assert_written_as(
        &pool,
        uuid_of(&out["workflow_id"]),
        w.c,
        "group",
        w.op_g,
        "operator",
    )
    .await;
    let evolved = via
        .evolve(steps[1], "acme operator path step 1, revised")
        .await
        .expect("the operator's agent evolves its step");
    assert_eq!(
        claim_row(&pool, evolved).await,
        (w.c, "group".into(), w.op_g)
    );

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
    assert_eq!(
        claim_row(&pool, added).await,
        (w.c, "public".into(), w.op_g)
    );
    let lineage = step_lineage(&pool, legacy_steps[0].0).await;
    let deleted = via
        .delete_step(LEGACY, lineage)
        .await
        .expect("soft-delete a system-authored step");
    assert_eq!(deleted, legacy_steps[0].0);
    assert!((truth(&pool, deleted).await - 0.05).abs() < 1e-9);
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
    let public_alpha = json!({"visibility": "public", "owner_group_id": w.alpha});
    let g0 = uuid_of(
        &via_ok(
            via.ingest_with(&extraction(public_name, 0, 1), Some(public_alpha.clone()))
                .await,
        )["workflow_id"],
    );
    assert_eq!(workflow_row(&pool, g0).await.1, w.alpha, "gen 0 in alpha");
    via_ok(
        via.ingest(&extraction(private_name, 0, 1), Some(w.alpha))
            .await,
    );

    end_role(&pool, w.rb_role).await;
    assert!(
        !writes(&pool, w.rb, w.alpha).await,
        "PREMISE: rb no longer writes alpha"
    );

    let out = via_ok(via.ingest(&extraction(public_name, 1, 1), None).await);
    let g1 = uuid_of(&out["workflow_id"]);
    let (v, owner, submitter, parent) = workflow_row(&pool, g1).await;
    assert_eq!(
        (v.as_str(), owner),
        ("public", w.rb_g),
        "gen 1 in the caller's own group"
    );
    assert_eq!(
        submitter,
        Some(w.rb.to_string()),
        "the lineage's submitter is inherited"
    );
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
    assert!(
        refused.is_err(),
        "a private lineage the caller no longer writes: {refused:?}"
    );
    assert_eq!(row_counts(&pool).await, before, "the refusal wrote nothing");
    assert_eq!(workflow_named(&pool, private_name, 1).await, None);

    // A roster-row writer removed from the group behaves the same.
    let via = Via::Rest(&w.router, w.dr);
    let name = "acme-generations-roster";
    let g0 = uuid_of(
        &via_ok(
            via.ingest_with(&extraction(name, 0, 1), Some(public_alpha.clone()))
                .await,
        )["workflow_id"],
    );
    remove_roster_row(&pool, w.alpha, w.dr).await;
    let g1 = uuid_of(&via_ok(via.ingest(&extraction(name, 1, 1), None).await)["workflow_id"]);
    let (v, owner, _, parent) = workflow_row(&pool, g1).await;
    assert_eq!((v.as_str(), owner, parent), ("public", w.dr_g, Some(g0)));
}

// ─────────────────────────────────────────────────────────────────────────────
// A caller-chosen group is checked LIVE, inside the write's own transaction
// ─────────────────────────────────────────────────────────────────────────────

/// The caller's viewer is resolved, its transaction stamped from it, and THEN
/// its team membership ends. The stamp still carries the group (row security
/// would admit the rows), so only the in-transaction live check stands
/// between the stale viewer and a write into a group the caller no longer
/// writes: a declared ingest into it is refused with nothing written, and an
/// undeclared one no longer picks it as the caller's team group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_membership_ended_after_the_viewer_resolved_is_refused_live(pool: PgPool) {
    let w = world(&pool).await;
    let scoped = app_scoped(&pool).await;
    let stale = epigraph_db::visibility::Viewer::resolve(&pool, w.rb)
        .await
        .expect("resolve");
    assert!(
        stale.writable_groups().contains(&w.alpha),
        "PREMISE: the viewer writes alpha"
    );
    end_role(&pool, w.rb_role).await;
    assert!(
        !writes(&pool, w.rb, w.alpha).await,
        "PREMISE: rb no longer writes alpha"
    );

    let ingest = |name: &'static str| {
        let extraction: epigraph_ingest::workflow::WorkflowExtraction =
            serde_json::from_value(extraction(name, 0, 1)).expect("extraction");
        let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&extraction);
        (extraction, plan)
    };

    let before = row_counts(&pool).await;
    let (x, plan) = ingest("acme-live-declared");
    let mut tx = scoped
        .begin_as(&stale)
        .await
        .expect("stamp from the stale viewer");
    let refused = epigraph_ingest_executor::execute_workflow_ingest_plan_in_group(
        &mut tx,
        &plan,
        &x,
        &stale,
        Some(epigraph_core::TenancyDecl::group(w.alpha)),
    )
    .await;
    assert!(
        matches!(
            refused,
            Err(epigraph_ingest_executor::IngestExecutorError::CallerNotGroupWriter { caller, group })
                if caller == w.rb && group == w.alpha
        ),
        "a declared group the caller no longer writes is refused live: {refused:?}"
    );
    drop(tx);
    assert_eq!(row_counts(&pool).await, before, "the refusal wrote nothing");

    let (x, plan) = ingest("acme-live-undeclared");
    let mut tx = scoped
        .begin_as(&stale)
        .await
        .expect("stamp from the stale viewer");
    let out = epigraph_ingest_executor::execute_workflow_ingest_plan_in_group(
        &mut tx, &plan, &x, &stale, None,
    )
    .await
    .expect("an undeclared ingest still lands");
    tx.commit().await.expect("commit");
    let (v, owner, ..) = workflow_row(&pool, out.workflow_id).await;
    assert_eq!(
        (v.as_str(), owner),
        ("group", w.rb_g),
        "the ended team membership is not picked as the caller's team group"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A lineage with generations the caller cannot read is never written
// ─────────────────────────────────────────────────────────────────────────────

/// Workflow writes run on the caller's stamp, where a generation private to a
/// group the caller is not in is invisible. The caller below SUBMITTED the
/// lineage's visible public head, so the authority gate admits it over that
/// head; only migration 202's check knows a later, hidden generation exists.
/// Without it the caller would mint a public generation every member then
/// resolves as the head, add a step to a stale generation, or ingest a
/// "child" of the hidden lineage with its parent link silently dropped.
#[sqlx::test(migrations = "../../migrations")]
async fn a_lineage_with_a_generation_the_caller_cannot_read_is_never_written(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-hidden-head";
    let mcp = Via::McpHttp(&w.mcp, w.rb);
    via_ok(
        mcp.ingest_with(
            &extraction(name, 0, 1),
            Some(json!({"visibility": "public", "owner_group_id": w.alpha})),
        )
        .await,
    );
    via_ok(mcp.ingest(&extraction(name, 1, 1), Some(w.alpha)).await);
    end_role(&pool, w.rb_role).await;
    assert!(
        !writes(&pool, w.rb, w.alpha).await,
        "PREMISE: rb left alpha"
    );

    let before = row_counts(&pool).await;
    for via in [Via::McpHttp(&w.mcp, w.rb), Via::Rest(&w.router, w.rb)] {
        let refused = via.ingest(&extraction(name, 2, 1), None).await;
        assert!(
            refused.as_ref().is_err_and(|e| e.contains("cannot read")),
            "a generation over a hidden head is refused: {refused:?}"
        );
        let mut child = extraction("acme-hidden-head-child", 2, 1);
        child["source"]["parent_canonical_name"] = json!(name);
        let refused = via.ingest(&child, None).await;
        assert!(
            refused.as_ref().is_err_and(|e| e.contains("cannot read")),
            "a child naming a hidden parent is refused, never stored parentless: {refused:?}"
        );
        let refused = via.add_step(name, "acme step on a stale generation").await;
        assert!(
            refused.is_err(),
            "a step edit on the stale visible generation: {refused:?}"
        );
    }
    assert_eq!(row_counts(&pool).await, before, "nothing was written");
    assert_eq!(workflow_named(&pool, name, 2).await, None);

    // CALIBRATION: back in alpha, the same caller extends the same lineage
    // (the new generation inherits the private head's group).
    grant_role(&pool, w.rb).await;
    let out = via_ok(
        Via::Rest(&w.router, w.rb)
            .ingest(&extraction(name, 2, 1), None)
            .await,
    );
    let (v, owner, ..) = workflow_row(&pool, uuid_of(&out["workflow_id"])).await;
    assert_eq!((v.as_str(), owner), ("group", w.alpha));
}

// ─────────────────────────────────────────────────────────────────────────────
// Round 2: a re-ingest writes nothing; the owner-group writer arm; the
// owner-group default visibility; the cascade's hidden generations
// ─────────────────────────────────────────────────────────────────────────────

/// The whole `workflows` row as text (every column, the goal embedding
/// included): equal before and after means nothing touched the row.
async fn row_text(pool: &PgPool, wf: Uuid) -> String {
    sqlx::query_scalar("SELECT to_jsonb(w)::text FROM workflows w WHERE id = $1")
        .bind(wf)
        .fetch_one(pool)
        .await
        .expect("workflow row text")
}

/// Every `workflows.caller_write` provenance row about `wf`, as
/// `(arm, acting_agent, owner_group)`.
async fn caller_write_arms(pool: &PgPool, wf: Uuid) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT details->>'arm', details->>'acting_agent', details->>'owner_group' \
           FROM security_events \
          WHERE event_type = 'workflows.caller_write' AND details->>'workflow_id' = $1::text \
          ORDER BY created_at, id",
    )
    .bind(wf)
    .fetch_all(pool)
    .await
    .expect("provenance rows")
}

fn level2(plan: &[(Uuid, i32, Uuid, String, Uuid)]) -> Vec<Uuid> {
    plan.iter()
        .filter(|(_, l, ..)| *l == 2)
        .map(|(id, ..)| *id)
        .collect()
}

/// A caller that does not write the owner group of an existing PUBLIC
/// workflow re-ingests its exact `(canonical_name, generation)` with a goal
/// of its own, through every ingest entry point. The executor reports
/// `already_ingested`, and NOTHING about the existing row changes: not its
/// goal embedding (a re-ingest used to embed the REQUEST's goal and store it
/// on the existing row, re-ranking every caller's `find_workflow_hierarchical`
/// results), not its goal, metadata or truth, and no claim, edge, BBA or
/// `AUTHORED` edge is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_writers_exact_re_ingest_changes_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let legacy = workflow_named(&pool, LEGACY, 0).await.expect("legacy row");
    sqlx::query(
        "UPDATE workflows SET goal_embedding = array_fill(0.125::real, ARRAY[1536])::vector \
          WHERE id = $1",
    )
    .bind(legacy)
    .execute(&pool)
    .await
    .expect("seed a known goal embedding");
    let (v, owner, ..) = workflow_row(&pool, legacy).await;
    assert_eq!(
        (v.as_str(), owner),
        ("public", w.op_g),
        "PREMISE: a public row in the operator's group"
    );
    assert!(
        !writes(&pool, w.rb, w.op_g).await,
        "PREMISE: rb does not write it"
    );
    let row_before = row_text(&pool, legacy).await;
    let counts_before = row_counts(&pool).await;
    let events_before = event_count(&pool).await;

    let mut poisoned = extraction(LEGACY, 0, 2);
    poisoned["source"]["goal"] = json!("acme poisoned goal text");
    for via in [Via::McpHttp(&w.mcp, w.rb), Via::Rest(&w.router, w.rb)] {
        let out = via_ok(via.ingest(&poisoned, None).await);
        assert_eq!(out["already_ingested"], json!(true), "{out}");
        // `store_workflow` slugs the goal to the same canonical name.
        let out = via_ok(
            via.store("Acme legacy: system written!", &["acme other step"], None)
                .await,
        );
        assert_eq!(out["already_ingested"], json!(true), "{out}");
    }
    assert_eq!(
        row_text(&pool, legacy).await,
        row_before,
        "the existing row is untouched, its goal embedding included"
    );
    assert_eq!(
        row_counts(&pool).await,
        counts_before,
        "nothing else was written"
    );
    assert_eq!(
        event_count(&pool).await,
        events_before,
        "no `workflow.created` event announces the caller's goal for a row it did not create"
    );
}

/// An existing row that shows the caller NO plan (no `executes` edge: a row
/// left by the pre-transaction ingest) is not a re-ingest the executor
/// short-circuits: the walk would write the caller's claims and edges under a
/// row it has no authority over. It is refused unless the caller passes the
/// authority gate over that row, with nothing written; the operator's own
/// agent (which writes the row's group) fills it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_ingest_into_an_existing_row_with_no_plan_needs_authority_over_it(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-planless-row";
    {
        let scoped = app_scoped(&pool).await;
        let authority = epigraph_ingest_executor::system_agent_write_authority(&scoped)
            .await
            .expect("the system agent's authority");
        let x: epigraph_ingest::workflow::WorkflowExtraction =
            serde_json::from_value(extraction(name, 0, 1)).expect("extraction");
        let plan = epigraph_ingest::workflow::builder::build_ingest_plan(&x);
        let mut tx = scoped.begin_as(&authority.viewer).await.expect("stamp");
        epigraph_ingest_executor::execute_workflow_ingest_plan(&mut tx, &plan, &x)
            .await
            .expect("the system ingest");
        tx.commit().await.expect("commit");
    }
    let wf = workflow_named(&pool, name, 0).await.expect("the row");
    sqlx::query("DELETE FROM edges WHERE source_id = $1 AND relationship = 'executes'")
        .bind(wf)
        .execute(&pool)
        .await
        .expect("strip the plan");
    let row_before = row_text(&pool, wf).await;
    let counts_before = row_counts(&pool).await;
    let mut other = extraction(name, 0, 2);
    other["phases"][0]["steps"][1]["compound"] = json!("acme intruder step");
    for via in [Via::McpHttp(&w.mcp, w.rb), Via::Rest(&w.router, w.rb)] {
        let refused = via.ingest(&other, None).await;
        assert!(
            refused.is_err(),
            "a caller with no authority over the row is refused: {refused:?}"
        );
    }
    assert_eq!(
        row_text(&pool, wf).await,
        row_before,
        "the row is untouched"
    );
    assert_eq!(
        row_counts(&pool).await,
        counts_before,
        "nothing was written"
    );
    assert!(plan(&pool, wf).await.is_empty(), "no plan was attached");

    // CALIBRATION: the operator's agent writes the row's group, and the
    // owner-group arm admits it.
    via_ok(Via::McpStdio(&w.c_server).ingest(&other, None).await);
    assert!(!plan(&pool, wf).await.is_empty(), "the plan is attached");
}

/// The owner-group writer arm: a caller that writes a workflow's OWNER GROUP
/// may add, delete and evolve its steps and publish its next generation,
/// whoever submitted it, and whether or not a submitter is recorded. A caller
/// that does not write the group is refused, with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_of_the_owner_group_edits_a_workflow_it_did_not_submit(pool: PgPool) {
    let w = world(&pool).await;
    let (nw, _) = fixture::seed_human_operator(&pool, "acme-non-writer").await;
    assert!(
        !writes(&pool, nw, w.alpha).await,
        "PREMISE: nw is not in alpha"
    );

    // dr submits two workflows into alpha (its one team group).
    let dr = Via::McpHttp(&w.mcp, w.dr);
    let shared = "acme-team-shared";
    let unrecorded = "acme-team-unrecorded";
    via_ok(dr.ingest(&extraction(shared, 0, 3), None).await);
    via_ok(dr.ingest(&extraction(unrecorded, 0, 2), None).await);
    let shared_wf = workflow_named(&pool, shared, 0).await.expect("shared row");
    let unrecorded_wf = workflow_named(&pool, unrecorded, 0).await.expect("row");
    sqlx::query("UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' WHERE id = $1")
        .bind(unrecorded_wf)
        .execute(&pool)
        .await
        .expect("drop the recorded submitter");
    for wf in [shared_wf, unrecorded_wf] {
        assert_eq!(
            workflow_row(&pool, wf).await.1,
            w.alpha,
            "PREMISE: owned by alpha"
        );
    }
    assert_eq!(
        workflow_row(&pool, shared_wf).await.2,
        Some(w.dr.to_string()),
        "PREMISE: dr is the recorded submitter"
    );
    assert_eq!(workflow_row(&pool, unrecorded_wf).await.2, None);
    let steps = level2(&plan(&pool, shared_wf).await);
    let unrecorded_steps = level2(&plan(&pool, unrecorded_wf).await);

    // A non-writer: refused everywhere, nothing written.
    for via in [Via::McpHttp(&w.mcp, nw), Via::Rest(&w.router, nw)] {
        let before = row_counts(&pool).await;
        assert!(via.add_step(shared, "acme outsider step").await.is_err());
        assert!(via
            .add_step(unrecorded, "acme outsider step")
            .await
            .is_err());
        assert!(via
            .evolve(steps[0], "acme outsider revision")
            .await
            .is_err());
        let lineage = step_lineage(&pool, steps[0]).await;
        assert!(via.delete_step(shared, lineage).await.is_err());
        assert!(via.ingest(&extraction(shared, 1, 1), None).await.is_err());
        assert_eq!(
            row_counts(&pool).await,
            before,
            "the refusals wrote nothing"
        );
    }

    // A READER of alpha reads both rows, so its refusal is the gate's own
    // (the arm declined: it does not write the owner group), not a not-found.
    let (rd, _) = fixture::seed_human_operator(&pool, "acme-alpha-reader").await;
    add_roster_row(&pool, w.alpha, rd, "reader").await;
    assert!(
        !writes(&pool, rd, w.alpha).await,
        "PREMISE: rd reads alpha, does not write it"
    );
    for (via, tag) in [
        (Via::McpHttp(&w.mcp, rd), "mcp"),
        (Via::Rest(&w.router, rd), "rest"),
    ] {
        let by_the_gate = |what: &str, r: Result<String, String>| {
            let e = r.expect_err(&format!("{tag}: a reader is refused {what}"));
            let gate = if tag == "mcp" {
                e.contains("does not write the workflow's owner group")
            } else {
                e.starts_with("403") && e.contains("a writer of its owner group")
            };
            assert!(gate, "{tag}: {what} refused by the gate's arms: {e}");
        };
        let before = row_counts(&pool).await;
        by_the_gate(
            "add_step",
            via.add_step(shared, "acme reader step")
                .await
                .map(|_| String::new()),
        );
        by_the_gate(
            "add_step on the unrecorded row",
            via.add_step(unrecorded, "acme reader step")
                .await
                .map(|_| String::new()),
        );
        let lineage = step_lineage(&pool, steps[0]).await;
        by_the_gate(
            "delete_step",
            via.delete_step(shared, lineage)
                .await
                .map(|_| String::new()),
        );
        by_the_gate(
            "the next generation",
            via.ingest(&extraction(shared, 1, 1), None)
                .await
                .map(|_| String::new()),
        );
        let evolved = via.evolve(steps[0], "acme reader revision").await;
        assert!(evolved.is_err(), "{tag}: a reader is refused evolve_step");
        assert_eq!(
            row_counts(&pool).await,
            before,
            "{tag}: the reader's refusals wrote nothing"
        );
    }

    // rb writes alpha (role binding) and submitted neither: admitted on both
    // transports, on the submitted row and on the unrecorded one.
    for (via, tag) in [
        (Via::McpHttp(&w.mcp, w.rb), "mcp"),
        (Via::Rest(&w.router, w.rb), "rest"),
    ] {
        let (added, lineage) = via
            .add_step(shared, &format!("acme co-writer step {tag}"))
            .await
            .unwrap_or_else(|e| panic!("{tag}: a co-writer adds a step: {e}"));
        assert_eq!(
            claim_row(&pool, added).await.0,
            w.rb,
            "{tag}: authored by rb"
        );
        assert_eq!(claim_row(&pool, added).await.2, w.alpha, "{tag}: in alpha");
        via.delete_step(shared, lineage)
            .await
            .unwrap_or_else(|e| panic!("{tag}: a co-writer deletes a step: {e}"));
        let revised = via
            .evolve(
                steps[if tag == "mcp" { 1 } else { 2 }],
                &format!("acme co-writer revision {tag}"),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag}: a co-writer evolves a step: {e}"));
        assert_eq!(claim_row(&pool, revised).await.0, w.rb);
        via.add_step(unrecorded, &format!("acme co-writer legacy step {tag}"))
            .await
            .unwrap_or_else(|e| panic!("{tag}: a co-writer edits an unrecorded row: {e}"));
        let lineage = step_lineage(&pool, unrecorded_steps[0]).await;
        if tag == "mcp" {
            via.delete_step(unrecorded, lineage)
                .await
                .unwrap_or_else(|e| panic!("{tag}: delete on an unrecorded row: {e}"));
        }
    }
    let arms = caller_write_arms(&pool, shared_wf).await;
    assert!(
        arms.iter()
            .any(|(arm, acting, group)| arm == "owner_group_writer"
                && *acting == w.rb.to_string()
                && group.as_deref() == Some(w.alpha.to_string().as_str())),
        "the arm is recorded with the owner group: {arms:?}"
    );

    // The next generation, by the co-writer, stays in the lineage.
    let g1 = uuid_of(
        &via_ok(
            Via::Rest(&w.router, w.rb)
                .ingest(&extraction(shared, 1, 1), None)
                .await,
        )["workflow_id"],
    );
    let (_, owner, submitter, parent) = workflow_row(&pool, g1).await;
    assert_eq!(owner, w.alpha);
    assert_eq!(parent, Some(shared_wf));
    assert_eq!(
        submitter,
        Some(w.dr.to_string()),
        "the lineage keeps its submitter"
    );
    // ... and over MCP too, from the generation REST just published.
    let g2 = uuid_of(
        &via_ok(
            Via::McpHttp(&w.mcp, w.rb)
                .ingest(&extraction(shared, 2, 1), None)
                .await,
        )["workflow_id"],
    );
    let (v2, owner2, submitter2, parent2) = workflow_row(&pool, g2).await;
    assert_eq!(
        (v2.as_str(), owner2, parent2),
        ("group", w.alpha, Some(g1)),
        "the MCP generation stays in the lineage, private to alpha"
    );
    assert_eq!(submitter2, Some(w.dr.to_string()));

    // stdio: the linked agent joins alpha and edits dr's workflow as a writer:
    // add, delete, evolve and the next generation.
    add_roster_row(&pool, w.alpha, w.c, "writer").await;
    let stdio = Via::McpStdio(&w.c_server);
    let (added, added_lineage) = stdio
        .add_step(shared, "acme stdio co-writer step")
        .await
        .expect("a stdio co-writer adds a step");
    assert_eq!(claim_row(&pool, added).await.0, w.c);
    stdio
        .delete_step(shared, added_lineage)
        .await
        .expect("a stdio co-writer deletes a step");
    let revised = stdio
        .evolve(steps[0], "acme stdio co-writer revision")
        .await
        .expect("a stdio co-writer evolves a step");
    assert_eq!(claim_row(&pool, revised).await.0, w.c);
    let g3 = uuid_of(&via_ok(stdio.ingest(&extraction(shared, 3, 1), None).await)["workflow_id"]);
    let (_, owner3, _, parent3) = workflow_row(&pool, g3).await;
    assert_eq!((owner3, parent3), (w.alpha, Some(g2)));
    // The step tools act on the lineage's head, so the rows may name any
    // generation of it.
    let mut stdio_arms = Vec::new();
    for wf in [shared_wf, g1, g2] {
        stdio_arms.extend(caller_write_arms(&pool, wf).await);
    }
    assert!(
        stdio_arms
            .iter()
            .any(|(arm, acting, _)| arm == "owner_group_writer" && *acting == w.c.to_string()),
        "the stdio co-writer's arm is recorded: {stdio_arms:?}"
    );
}

/// An agent bound to a human through an allowlisted client (the shape a
/// host's shared credential takes) holds no membership of the human's
/// personal group, so the owner-group arm does not admit it over the
/// human's workflows (operator ruling 2026-10-13 stands).
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_agent_of_a_human_gains_no_edit_over_its_workflows(pool: PgPool) {
    let w = world(&pool).await;
    let (h, h_g) = fixture::seed_human_operator(&pool, "acme-bound-human").await;
    // An agent with its own personal group, so a refusal below is the arms'
    // and not a caller with nowhere to write.
    let (agent, _) = fixture::seed_agent_with_group(&pool, "acme-bound").await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'acme-bound', 'service', ARRAY['claims:write'], 'active', $2, \
                 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("acme-bound-{agent}"))
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("client");
    as_maintenance(&pool, move |mut conn| async move {
        sqlx::query(
            "SELECT effective_binding \
               FROM public.epigraph_allow_author_binding_client($1, $2, 'test')",
        )
        .bind(client)
        .bind(h)
        .execute(&mut *conn)
        .await
        .expect("allowlist the client for h");
        (conn, ())
    })
    .await;
    let name = "acme-bound-human-own";
    via_ok(
        Via::McpHttp(&w.mcp, h)
            .ingest(&extraction(name, 0, 1), None)
            .await,
    );
    let wf = workflow_named(&pool, name, 0).await.expect("row");
    assert_eq!(
        workflow_row(&pool, wf).await.1,
        h_g,
        "PREMISE: in h's group"
    );
    // Readable to the agent, so only the arms decide.
    sqlx::query("UPDATE workflows SET visibility = 'public' WHERE id = $1")
        .bind(wf)
        .execute(&pool)
        .await
        .expect("make the row public");
    // The token is shaped as `oauth/token.rs` mints it for the allowlisted
    // client: its id, the client row's (unset) owner, the client's agent. The
    // binding to `h` is found from that agent, so the call below is the bound
    // agent's own, and the refusal must be the gate's final one, after every
    // arm (submitter, operator, owner-group writer, admin) declined.
    let mut auth = http_auth(agent);
    auth.client_id = client;
    auth.owner_id = None;
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&w.mcp, Some(&auth))
        .await
        .expect("an allowlisted agent resolves an HTTP viewer");
    let before = row_counts(&pool).await;
    let refused = epigraph_mcp::tools::step_ops::add_step(
        &w.mcp,
        &viewer,
        epigraph_mcp::tools::step_ops::AddStepParams {
            canonical_name: name.to_string(),
            step_text: "acme bound agent step".to_string(),
            position: None,
        },
        Some(&auth),
    )
    .await
    .expect_err("the binding to h admits nothing");
    assert!(
        refused
            .message
            .contains(&format!("was submitted by agent {h}"))
            && refused
                .message
                .contains("does not write the workflow's owner group"),
        "refused by the gate itself, after every arm: {}",
        refused.message
    );
    assert_eq!(row_counts(&pool).await, before);
}

/// The default visibility of an undeclared workflow write is its OWNER GROUP:
/// the caller's one team group, else its own default group, group-visible.
/// Every MCP write embeds its claims and goal all the same (stored through the
/// caller, since a group-private claim is not readable as public), and no
/// instance-wide `workflow.created` event announces a group-private plan.
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_workflow_write_is_private_to_its_owner_group(pool: PgPool) {
    let w = world(&pool).await;
    let (nw, nw_g) = fixture::seed_human_operator(&pool, "acme-loner").await;

    let rb = Via::McpHttp(&w.mcp, w.rb);
    let name = "acme-default-team";
    let wf = uuid_of(&via_ok(rb.ingest(&extraction(name, 0, 2), None).await)["workflow_id"]);
    assert_written_as(&pool, wf, w.rb, "group", w.alpha, "team default").await;
    let unembedded: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' AND c.embedding IS NULL",
    )
    .bind(wf)
    .fetch_one(&pool)
    .await
    .expect("embedding count");
    assert_eq!(unembedded, 0, "every claim of the plan is embedded");
    let goal_embedded: bool =
        sqlx::query_scalar("SELECT goal_embedding IS NOT NULL FROM workflows WHERE id = $1")
            .bind(wf)
            .fetch_one(&pool)
            .await
            .expect("goal embedding");
    assert!(goal_embedded, "the goal is embedded");
    let (added, _) = rb
        .add_step(name, "acme default team added step")
        .await
        .expect("add a step");
    assert_eq!(
        claim_row(&pool, added).await,
        (w.rb, "group".into(), w.alpha)
    );
    let added_embedded: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(added)
            .fetch_one(&pool)
            .await
            .expect("added embedding");
    assert!(added_embedded, "the added step is embedded");

    // The linked agent: its operator's group, group-visible.
    let out = via_ok(
        Via::McpStdio(&w.c_server)
            .ingest(&extraction("acme-default-linked", 0, 1), None)
            .await,
    );
    assert_written_as(
        &pool,
        uuid_of(&out["workflow_id"]),
        w.c,
        "group",
        w.op_g,
        "linked",
    )
    .await;

    // A human with no team: its personal group, group-visible (REST).
    let out = via_ok(
        Via::Rest(&w.router, nw)
            .ingest(&extraction("acme-default-loner", 0, 1), None)
            .await,
    );
    assert_written_as(
        &pool,
        uuid_of(&out["workflow_id"]),
        nw,
        "group",
        nw_g,
        "loner",
    )
    .await;

    // store_workflow, both transports.
    for (via, goal) in [
        (Via::McpHttp(&w.mcp, w.rb), "Acme stored by MCP"),
        (Via::Rest(&w.router, w.dr), "Acme stored by REST"),
    ] {
        let out = via_ok(via.store(goal, &["acme stored step"], None).await);
        let wf = uuid_of(&out["workflow_id"]);
        let (v, owner, ..) = workflow_row(&pool, wf).await;
        assert_eq!((v.as_str(), owner), ("group", w.alpha), "{goal}");
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE event_type = 'workflow.created' \
               AND payload->>'canonical_name' = $1",
        )
        .bind(out["canonical_name"].as_str().expect("canonical_name"))
        .fetch_one(&pool)
        .await
        .expect("events");
        assert_eq!(
            events, 0,
            "{goal}: no instance-wide event for a group-private plan"
        );
    }
}

/// Public only when asked: `{"visibility": "public", "owner_group_id": G}`
/// makes the rows public, owned by G, which the caller must write.
#[sqlx::test(migrations = "../../migrations")]
async fn an_explicitly_public_workflow_write_is_public(pool: PgPool) {
    let w = world(&pool).await;
    let public_alpha = json!({"visibility": "public", "owner_group_id": w.alpha});
    for (via, tag) in [
        (Via::McpHttp(&w.mcp, w.rb), "mcp"),
        (Via::Rest(&w.router, w.dr), "rest"),
    ] {
        let caller = if tag == "mcp" { w.rb } else { w.dr };
        let name = format!("acme-public-{tag}");
        let out = via_ok(
            via.ingest_with(&extraction(&name, 0, 1), Some(public_alpha.clone()))
                .await,
        );
        assert_written_as(
            &pool,
            uuid_of(&out["workflow_id"]),
            caller,
            "public",
            w.alpha,
            &name,
        )
        .await;
        let out = via_ok(
            via.store(
                &format!("Acme public stored {tag}"),
                &["acme public stored step"],
                Some(public_alpha.clone()),
            )
            .await,
        );
        let (v, owner, ..) = workflow_row(&pool, uuid_of(&out["workflow_id"])).await;
        assert_eq!((v.as_str(), owner), ("public", w.alpha), "{tag} store");

        let before = row_counts(&pool).await;
        let refused = via
            .ingest_with(
                &extraction(&format!("acme-public-beta-{tag}"), 0, 1),
                Some(json!({"visibility": "public", "owner_group_id": w.beta})),
            )
            .await;
        assert!(
            refused.is_err(),
            "{tag}: public into a group not written: {refused:?}"
        );
        assert_eq!(row_counts(&pool).await, before, "{tag}: nothing written");
    }
}

/// A new generation keeps its lineage's visibility: public stays public (in
/// the lineage's group when the caller writes it, else the caller's own),
/// group stays group. Declaring public on a group-private lineage would
/// publish it, and is refused with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_new_generation_keeps_its_lineages_visibility(pool: PgPool) {
    let w = world(&pool).await;
    let via = Via::McpHttp(&w.mcp, w.rb);
    let public_name = "acme-keep-public";
    let group_name = "acme-keep-group";
    via_ok(
        via.ingest_with(
            &extraction(public_name, 0, 1),
            Some(json!({"visibility": "public", "owner_group_id": w.alpha})),
        )
        .await,
    );
    via_ok(via.ingest(&extraction(group_name, 0, 1), None).await);
    let g1 =
        uuid_of(&via_ok(via.ingest(&extraction(public_name, 1, 1), None).await)["workflow_id"]);
    let (v, owner, ..) = workflow_row(&pool, g1).await;
    assert_eq!(
        (v.as_str(), owner),
        ("public", w.alpha),
        "public lineage, same group"
    );
    let (added, _) = via
        .add_step(public_name, "acme keep public step")
        .await
        .expect("add");
    assert_eq!(
        claim_row(&pool, added).await,
        (w.rb, "public".into(), w.alpha)
    );
    let g1 = uuid_of(&via_ok(via.ingest(&extraction(group_name, 1, 1), None).await)["workflow_id"]);
    let (v, owner, ..) = workflow_row(&pool, g1).await;
    assert_eq!(
        (v.as_str(), owner),
        ("group", w.alpha),
        "group lineage stays group"
    );

    let before = row_counts(&pool).await;
    let refused = via
        .ingest_with(
            &extraction(group_name, 2, 1),
            Some(json!({"visibility": "public", "owner_group_id": w.alpha})),
        )
        .await;
    assert!(refused.is_err(), "publishing a group lineage: {refused:?}");
    assert_eq!(row_counts(&pool).await, before, "nothing written");
    assert_eq!(workflow_named(&pool, group_name, 2).await, None);

    end_role(&pool, w.rb_role).await;
    let g2 =
        uuid_of(&via_ok(via.ingest(&extraction(public_name, 2, 1), None).await)["workflow_id"]);
    let (v, owner, ..) = workflow_row(&pool, g2).await;
    assert_eq!(
        (v.as_str(), owner),
        ("public", w.rb_g),
        "a public lineage outside the caller's groups stays public, in its own group"
    );
}

/// `deprecate_workflow` with `cascade` reads the lineage on the caller's own
/// stamp, where a descendant generation private to a group the caller is not
/// in is invisible. It is refused, never a silent partial cascade.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cascade_deprecation_refuses_a_lineage_with_hidden_generations(pool: PgPool) {
    let w = world(&pool).await;
    let via = Via::McpHttp(&w.mcp, w.rb);
    let name = "acme-cascade-hidden";
    via_ok(via.ingest(&extraction(name, 0, 1), None).await);
    via_ok(via.ingest(&extraction(name, 1, 1), None).await);
    let g0 = workflow_named(&pool, name, 0).await.expect("g0");
    let g1 = workflow_named(&pool, name, 1).await.expect("g1");
    sqlx::query("UPDATE workflows SET visibility = 'public', owner_group_id = $2 WHERE id = $1")
        .bind(g0)
        .bind(w.alpha)
        .execute(&pool)
        .await
        .expect("g0 public in alpha");
    sqlx::query("UPDATE workflows SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(g1)
        .bind(w.beta)
        .execute(&pool)
        .await
        .expect("g1 private to beta");
    let (g0_before, g1_before) = (row_text(&pool, g0).await, row_text(&pool, g1).await);
    let counts_before = row_counts(&pool).await;
    let refused = via.deprecate(g0, true).await;
    assert!(
        refused.is_err(),
        "a cascade over a hidden generation: {refused:?}"
    );
    assert_eq!(row_text(&pool, g0).await, g0_before, "g0 untouched");
    assert_eq!(row_text(&pool, g1).await, g1_before, "g1 untouched");
    assert_eq!(row_counts(&pool).await, counts_before);
    // CALIBRATION: without cascade the visible row alone is deprecated.
    via_ok(via.deprecate(g0, false).await);
    assert_ne!(row_text(&pool, g0).await, g0_before);
}

/// A member of a team through BOTH a role binding (writer) and a direct
/// roster row (admin) has ONE team group, and an undeclared write lands
/// there. The two memberships are different `(group, role)` rows, so only the
/// team-group read's DISTINCT keeps them one group; counted twice, the caller
/// would have "two" team groups and fall back to its personal group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_member_by_role_and_by_roster_row_has_one_team_group(pool: PgPool) {
    let w = world(&pool).await;
    let (both, _) = fixture::seed_human_operator(&pool, "acme-both-shapes").await;
    grant_role(&pool, both).await;
    add_roster_row(&pool, w.alpha, both, "admin").await;
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(w.alpha)
    .bind(both)
    .fetch_one(&pool)
    .await
    .expect("rows");
    assert_eq!(rows, 1, "PREMISE: one direct row beside the role binding");
    for (via, name) in [
        (Via::McpHttp(&w.mcp, both), "acme-both-mcp"),
        (Via::Rest(&w.router, both), "acme-both-rest"),
    ] {
        let out = via_ok(via.ingest(&extraction(name, 0, 1), None).await);
        assert_eq!(
            workflow_row(&pool, uuid_of(&out["workflow_id"])).await.1,
            w.alpha,
            "{name}: the one team group"
        );
    }
}
