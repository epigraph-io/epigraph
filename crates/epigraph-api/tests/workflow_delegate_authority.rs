//! The DELEGATE arm of the workflow lineage gate: an agent whose LIVE operator
//! link names a workflow's submitter is admitted wherever the submitter itself
//! is admitted by identity (operator ruling R-183), on every transport.
//!
//! The gate (`routes/workflows.rs::workflow_authority`, and its MCP twin
//! `tools/workflow_authority.rs`, authenticated and stdio arms) admits, in
//! order: the submitter; the submitter's operator (#503, upward); a DELEGATE
//! (the caller's acting link names a principal admitted here by identity: the
//! submitter, or the submitter's operator. One hop on the caller's side, a
//! not-retired record and a live writer membership of the principal's own
//! group, `AgentRepository::operator_actor`); a writer of the row's owner
//! group; the audited `claims:admin` arm. A delegate's write is recorded in
//! its `workflows.caller_write` row as `"arm": "delegate"` with `operator` =
//! the principal it acted for, so an audit tells it from the submitter's own.
//!
//! Tenancy is unchanged, and pinned: where the gate admits a delegate over a
//! row whose group it does not write, row security still refuses the write
//! (steps, deprecation, and the claim ownership gate's widened arm alike).
//!
//! Tenancy is unchanged: a delegate writes only into groups it writes itself
//! (the rows a step creates on a public plan land in its own default group,
//! its operator's).
//!
//! On the authenticated transports an operated agent reaches the gate only
//! with a DELEGATED run token whose delegation is live (the viewer refuses it
//! otherwise), so the HTTP halves below use one.
//!
//! The world is production-shaped: the router runs on an `epigraph_app`
//! `ScopedPool`, the MCP servers are app-role servers, and the database is
//! ARMED (migration 122). The harness superuser only seeds and inspects.
#![cfg(feature = "db")]

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/delegation_fixture.rs"]
mod delegation;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{RunTokens, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const WRITE_SCOPES: &[&str] = &["claims:read", "claims:write", "edges:write"];
const ADMIN_SCOPES: &[&str] = &["claims:read", "claims:write", "edges:write", "claims:admin"];

fn uuid_of(v: &Value) -> Uuid {
    Uuid::parse_str(
        v.as_str()
            .unwrap_or_else(|| panic!("not a uuid string: {v}")),
    )
    .unwrap_or_else(|e| panic!("not a uuid: {v}: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Production-shaped servers
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

async fn api_state(pool: &PgPool) -> AppState {
    let state = AppState::with_scoped_pool(app_scoped(pool).await, ApiConfig::default())
        .with_run_tokens(RunTokens::On);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

/// An app-role MCP server whose own (stdio) agent is keyed by `seed`, with
/// run tokens on and a fixed-vector generator.
async fn mcp_server(pool: &PgPool, seed: u8) -> epigraph_mcp::server::EpiGraphMcpFull {
    let scoped = app_scoped(pool).await;
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(vec![0.5_f32; 1536])));
    epigraph_mcp::server::EpiGraphMcpFull::new(plain, signer, embedder, false)
        .with_scoped_pool(scoped)
        .with_run_tokens(RunTokens::On)
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

/// An authenticated MCP context for `agent`, `sub` = `client`, carrying
/// `dlg = delegated_by`.
fn mcp_auth(
    client: Uuid,
    agent: Uuid,
    delegated_by: Option<Uuid>,
    scopes: &[&str],
) -> epigraph_auth::AuthContext {
    epigraph_auth::AuthContext {
        client_id: client,
        agent_id: Some(agent),
        owner_id: None,
        client_type: epigraph_auth::ClientType::Agent,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by,
    }
}

/// A REST access token for `agent`, `sub` = `client`, carrying
/// `dlg = delegated_by`, signed with the state's own key.
fn rest_token(
    state: &AppState,
    client: Uuid,
    agent: Uuid,
    delegated_by: Option<Uuid>,
    scopes: &[&str],
) -> String {
    state
        .jwt_config
        .issue_access_token(
            client,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(agent),
            chrono::Duration::minutes(15),
            epigraph_auth::AccessTokenBinding {
                delegated_by,
                ..epigraph_auth::AccessTokenBinding::NONE
            },
        )
        .expect("mint")
        .0
}

async fn post(router: &axum::Router, uri: &str, token: &str, body: &Value) -> (StatusCode, Value) {
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

/// How a test reaches the workflow tools.
enum Via<'a> {
    /// MCP over the authenticated transport, with this context.
    McpHttp(
        &'a epigraph_mcp::server::EpiGraphMcpFull,
        epigraph_auth::AuthContext,
    ),
    /// MCP over stdio: the server's own agent.
    McpStdio(&'a epigraph_mcp::server::EpiGraphMcpFull),
    /// REST, with this bearer token.
    Rest(&'a axum::Router, String),
}

impl Via<'_> {
    fn label(&self) -> &'static str {
        match self {
            Via::McpHttp(..) => "mcp-http",
            Via::McpStdio(_) => "mcp-stdio",
            Via::Rest(..) => "rest",
        }
    }

    fn auth(&self) -> Option<&epigraph_auth::AuthContext> {
        match self {
            Via::McpHttp(_, a) => Some(a),
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

    /// `ingest_workflow` with an optional `tenancy` value.
    async fn ingest(&self, extraction: &Value, tenancy: Option<Value>) -> Result<Value, String> {
        match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let viewer = Self::mcp_viewer(server, self.auth()).await?;
                let mut params = json!({ "extraction": extraction });
                if let Some(t) = &tenancy {
                    params["tenancy"] = t.clone();
                }
                let params = serde_json::from_value(params).expect("ingest params");
                epigraph_mcp::tools::workflow_ingest::ingest_workflow(
                    server,
                    &viewer,
                    params,
                    self.auth(),
                )
                .await
                .map(|out| tool_json(&out))
                .map_err(|e| e.message.to_string())
            }
            Via::Rest(router, token) => {
                let mut body = extraction.clone();
                if let Some(t) = &tenancy {
                    body["tenancy"] = t.clone();
                }
                let (s, b) = post(router, "/api/v1/workflows/ingest", token, &body).await;
                if s == StatusCode::OK {
                    Ok(b)
                } else {
                    Err(format!("{s}: {b}"))
                }
            }
        }
    }

    /// `add_step` (appended); returns the step claim id.
    async fn add_step(&self, name: &str, text: &str) -> Result<Uuid, String> {
        let out = match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let viewer = Self::mcp_viewer(server, self.auth()).await?;
                let params = epigraph_mcp::tools::step_ops::AddStepParams {
                    canonical_name: name.to_string(),
                    step_text: text.to_string(),
                    position: None,
                };
                let out =
                    epigraph_mcp::tools::step_ops::add_step(server, &viewer, params, self.auth())
                        .await
                        .map_err(|e| e.message.to_string())?;
                tool_json(&out)
            }
            Via::Rest(router, token) => {
                let (s, b) = post(
                    router,
                    "/api/v1/workflows/steps",
                    token,
                    &json!({"canonical_name": name, "step_text": text}),
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

    /// `evolve_step` (`revises`) of `parent`; returns the new claim id.
    async fn evolve(&self, parent: Uuid, content: &str) -> Result<Uuid, String> {
        match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let viewer = Self::mcp_viewer(server, self.auth()).await?;
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
                    self.auth(),
                )
                .await
                .map_err(|e| e.message.to_string())?;
                Ok(uuid_of(&tool_json(&out)["claim_id"]))
            }
            Via::Rest(router, token) => {
                let (s, b) = post(
                    router,
                    &format!("/api/v1/workflows/steps/{parent}/evolve"),
                    token,
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
}

impl Via<'_> {
    /// `delete_step` of `lineage`; returns the soft-deleted claim id.
    async fn delete_step(&self, name: &str, lineage: Uuid) -> Result<Uuid, String> {
        let out = match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let viewer = Self::mcp_viewer(server, self.auth()).await?;
                let params = epigraph_mcp::tools::step_ops::DeleteStepParams {
                    canonical_name: name.to_string(),
                    step_lineage_id: lineage.to_string(),
                };
                let out = epigraph_mcp::tools::step_ops::delete_step(
                    server,
                    &viewer,
                    params,
                    self.auth(),
                )
                .await
                .map_err(|e| e.message.to_string())?;
                tool_json(&out)
            }
            Via::Rest(router, token) => {
                let (s, b) = post(
                    router,
                    "/api/v1/workflows/steps/delete",
                    token,
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

    /// MCP `deprecate_workflow` of a hierarchical workflow (no cascade). REST
    /// has no hierarchical deprecation (its `DELETE /workflows/:id` retires a
    /// flat workflow claim and does not run the lineage gate).
    async fn deprecate(&self, workflow: Uuid) -> Result<Value, String> {
        match self {
            Via::McpHttp(server, _) | Via::McpStdio(server) => {
                let viewer = Self::mcp_viewer(server, self.auth()).await?;
                let params = serde_json::from_value(json!({
                    "workflow_id": workflow.to_string(),
                    "reason": "acme delegate deprecation",
                }))
                .expect("deprecate params");
                epigraph_mcp::tools::workflows::deprecate_workflow(
                    server,
                    &viewer,
                    params,
                    self.auth(),
                )
                .await
                .map(|out| tool_json(&out))
                .map_err(|e| e.message.to_string())
            }
            Via::Rest(..) => panic!("hierarchical deprecation is an MCP tool"),
        }
    }
}

/// MCP `add_step` as `auth` with an explicitly given `viewer`, bypassing the
/// transport's own viewer resolution, so the lineage GATE is what decides.
async fn mcp_add_step_at_the_gate(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: &epigraph_auth::AuthContext,
    name: &str,
    text: &str,
) -> Result<Uuid, String> {
    let params = epigraph_mcp::tools::step_ops::AddStepParams {
        canonical_name: name.to_string(),
        step_text: text.to_string(),
        position: None,
    };
    let out = epigraph_mcp::tools::step_ops::add_step(server, viewer, params, Some(auth))
        .await
        .map_err(|e| e.message.to_string())?;
    Ok(uuid_of(&tool_json(&out)["step_claim_id"]))
}

// ─────────────────────────────────────────────────────────────────────────────
// Payloads and harness reads
// ─────────────────────────────────────────────────────────────────────────────

/// `extraction(name, steps)` as generation `generation` of `name`.
fn extraction_gen(name: &str, generation: u32, steps: usize) -> Value {
    let mut x = extraction(name, steps);
    x["source"]["generation"] = json!(generation);
    x
}

fn extraction(name: &str, steps: usize) -> Value {
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
                   "generation": 0, "metadata": {}},
        "thesis_derivation": "TopDown",
        "phases": [{"title": "Body", "summary": format!("{name} phase"), "steps": steps}],
        "relationships": []
    })
}

fn public_in(group: Uuid) -> Option<Value> {
    Some(json!({"visibility": "public", "owner_group_id": group}))
}

fn group_in(group: Uuid) -> Option<Value> {
    Some(json!({"visibility": "group", "owner_group_id": group}))
}

/// `(claims, edges, workflows, mass_functions)`: a refusal changes none.
async fn row_counts(pool: &PgPool) -> (i64, i64, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM claims), (SELECT count(*) FROM edges), \
                (SELECT count(*) FROM workflows), (SELECT count(*) FROM mass_functions)",
    )
    .fetch_one(pool)
    .await
    .expect("row counts")
}

async fn workflow_named(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1 AND generation = 0")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("workflow {name}: {e}"))
}

/// `(visibility, owner group, recorded submitter)` of a workflow row.
async fn workflow_row(pool: &PgPool, wf: Uuid) -> (String, Uuid, Option<String>) {
    sqlx::query_as(
        "SELECT visibility::text, owner_group_id, metadata->>'epigraph_submitted_by' \
           FROM workflows WHERE id = $1",
    )
    .bind(wf)
    .fetch_one(pool)
    .await
    .expect("workflow row")
}

/// The plan's level-2 step ids.
async fn steps_of(pool: &PgPool, wf: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT c.id FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
            AND (e.properties->>'level')::int = 2 \
          ORDER BY (e.properties->>'plan_index')::int NULLS LAST, c.created_at",
    )
    .bind(wf)
    .fetch_all(pool)
    .await
    .expect("plan steps")
}

/// The row id of generation `generation` of `name`, if any.
async fn workflow_gen(pool: &PgPool, name: &str, generation: i32) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1 AND generation = $2")
        .bind(name)
        .bind(generation)
        .fetch_optional(pool)
        .await
        .unwrap_or_else(|e| panic!("workflow {name} gen {generation}: {e}"))
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

/// One claim's `(author, visibility, owner)`.
async fn claim_row(pool: &PgPool, id: Uuid) -> (Uuid, String, Uuid) {
    sqlx::query_as("SELECT agent_id, visibility::text, owner_group_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("claim row")
}

/// One `workflows.caller_write` row: `(action, arm, operator, submitter,
/// transport)`.
type CallerWrite = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Every `workflows.caller_write` row about `wf` written by `acting`.
async fn caller_writes(pool: &PgPool, wf: Uuid, acting: Uuid) -> Vec<CallerWrite> {
    sqlx::query_as(
        "SELECT details->>'action', details->>'arm', details->>'operator', \
                details->>'submitter', details->>'transport' \
           FROM security_events \
          WHERE event_type = 'workflows.caller_write' \
            AND details->>'workflow_id' = $1::text AND details->>'acting_agent' = $2::text \
          ORDER BY created_at, id",
    )
    .bind(wf)
    .bind(acting)
    .fetch_all(pool)
    .await
    .expect("provenance rows")
}

/// The number of `workflows.admin_write` rows about `wf`.
async fn admin_writes(pool: &PgPool, wf: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = 'workflows.admin_write' AND details->>'workflow_id' = $1::text",
    )
    .bind(wf)
    .fetch_one(pool)
    .await
    .expect("admin rows")
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

/// Migration 107's link verb, as the operator CLI calls it.
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
            .bind("workflow delegate authority test")
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

async fn writes(pool: &PgPool, agent: Uuid, group: Uuid) -> bool {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
        .writable_groups()
        .contains(&group)
}

async fn acting_operator(pool: &PgPool, agent: Uuid) -> Option<Uuid> {
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::operator_actor(&mut conn, agent)
        .await
        .expect("operator_actor")
        .map(|l| l.operator_id)
}

/// The world.
///
/// * `p`: a registered human (personal group `p_g`), the SUBMITTER of the
///   workflows under test, and the administrator of team group `t`.
/// * `d` / `d_server`: a stdio agent LIVE-linked to `p` (a writer of `p_g`
///   through the link; not a member of `t`). Its delegated run tokens come
///   from `p_delegator` (an allowlisted client's agent of `p`).
/// * `q`: another registered human, with `e` / `e_server` live-linked to it
///   and `q_delegator`.
/// * `n` / `n_server`: a stdio agent with no link at all.
/// * `r` / `r_server`: a stdio agent linked to `p`, then RETIRED (its writer
///   membership of `p_g` stays live: the retired record alone must refuse).
/// * `pub_wf` (`PUB`): `p`'s workflow declared PUBLIC into `t`; nobody but `p`
///   and writers of `t` was admitted to it before R-183.
/// * `own_wf` (`OWN`): `p`'s workflow private to `p_g`, which `d` writes.
struct World {
    state: AppState,
    router: axum::Router,
    mcp: epigraph_mcp::server::EpiGraphMcpFull,
    p: Uuid,
    p_g: Uuid,
    t: Uuid,
    p_delegator: delegation::Delegation,
    d: Uuid,
    d_server: epigraph_mcp::server::EpiGraphMcpFull,
    q_delegator: delegation::Delegation,
    e: Uuid,
    e_server: epigraph_mcp::server::EpiGraphMcpFull,
    n: Uuid,
    n_server: epigraph_mcp::server::EpiGraphMcpFull,
    r: Uuid,
    r_server: epigraph_mcp::server::EpiGraphMcpFull,
    pub_wf: Uuid,
    own_wf: Uuid,
}

const PUB: &str = "acme-delegate-public-in-team";
const OWN: &str = "acme-delegate-own-group";

async fn world(pool: &PgPool) -> World {
    let (p, p_g) = delegation::human_operator(pool, "acme-principal").await;
    let (q, q_g) = delegation::human_operator(pool, "acme-other-principal").await;
    let t = team_group(pool, "acme-delegate-team", p).await;

    let d_server = mcp_server(pool, 0xD1).await;
    let d = stdio_agent(pool, &d_server, 0xD1).await;
    link(pool, d, p).await;
    let e_server = mcp_server(pool, 0xD2).await;
    let e = stdio_agent(pool, &e_server, 0xD2).await;
    link(pool, e, q).await;
    let n_server = mcp_server(pool, 0xD3).await;
    let n = stdio_agent(pool, &n_server, 0xD3).await;
    let r_server = mcp_server(pool, 0xD4).await;
    let r = stdio_agent(pool, &r_server, 0xD4).await;
    link(pool, r, p).await;
    delegation::retire_link(pool, r).await;

    let (pdc, pda) = delegation::delegator(pool, p, p_g, Some("writer"), true).await;
    let (qdc, qda) = delegation::delegator(pool, q, q_g, Some("writer"), true).await;
    let p_delegator = delegation::Delegation {
        operator: p,
        operator_group: p_g,
        delegator_client: pdc,
        delegator: pda,
        principal: d,
    };
    let q_delegator = delegation::Delegation {
        operator: q,
        operator_group: q_g,
        delegator_client: qdc,
        delegator: qda,
        principal: e,
    };
    arm(pool).await;

    let state = api_state(pool).await;
    let router = epigraph_api::routes::create_router(state.clone());
    let mcp = mcp_server(pool, 0xA1).await;

    // p's two workflows, ingested by p itself over REST.
    let p_rest = Via::Rest(
        &router,
        rest_token(&state, Uuid::new_v4(), p, None, WRITE_SCOPES),
    );
    p_rest
        .ingest(&extraction(PUB, 2), public_in(t))
        .await
        .unwrap_or_else(|e| panic!("p ingests {PUB}: {e}"));
    p_rest
        .ingest(&extraction(OWN, 2), group_in(p_g))
        .await
        .unwrap_or_else(|e| panic!("p ingests {OWN}: {e}"));
    let pub_wf = workflow_named(pool, PUB).await;
    let own_wf = workflow_named(pool, OWN).await;

    // The premises every test relies on.
    assert_eq!(
        workflow_row(pool, pub_wf).await,
        ("public".to_string(), t, Some(p.to_string())),
        "PREMISE: {PUB} is p's, public, in t"
    );
    assert_eq!(
        workflow_row(pool, own_wf).await,
        ("group".to_string(), p_g, Some(p.to_string())),
        "PREMISE: {OWN} is p's, private to p_g"
    );
    assert!(writes(pool, p, t).await, "PREMISE: p writes t");
    for who in [d, e, n, r] {
        assert!(
            !writes(pool, who, t).await,
            "PREMISE: {who} does not write t"
        );
    }
    assert!(writes(pool, d, p_g).await, "PREMISE: d writes p_g (link)");
    assert!(
        writes(pool, r, p_g).await,
        "PREMISE: the retired agent's membership of p_g is still live"
    );
    assert_eq!(
        acting_operator(pool, d).await,
        Some(p),
        "PREMISE: d acts for p"
    );
    assert_eq!(
        acting_operator(pool, e).await,
        Some(q),
        "PREMISE: e acts for q"
    );
    assert_eq!(
        acting_operator(pool, r).await,
        None,
        "PREMISE: r acts for nobody"
    );
    assert_eq!(
        acting_operator(pool, n).await,
        None,
        "PREMISE: n is unlinked"
    );

    World {
        state,
        router,
        mcp,
        p,
        p_g,
        t,
        p_delegator,
        d,
        d_server,
        q_delegator,
        e,
        e_server,
        n,
        n_server,
        r,
        r_server,
        pub_wf,
        own_wf,
    }
}

impl World {
    /// `d` on each transport: stdio, MCP HTTP and REST with its live
    /// delegated run token.
    fn d_vias(&self) -> [Via<'_>; 3] {
        let dl = &self.p_delegator;
        [
            Via::McpStdio(&self.d_server),
            Via::McpHttp(
                &self.mcp,
                mcp_auth(
                    dl.delegator_client,
                    self.d,
                    Some(dl.delegator),
                    WRITE_SCOPES,
                ),
            ),
            Via::Rest(
                &self.router,
                rest_token(
                    &self.state,
                    dl.delegator_client,
                    self.d,
                    Some(dl.delegator),
                    WRITE_SCOPES,
                ),
            ),
        ]
    }

    /// A plain (undelegated) token for `agent` on each authenticated transport.
    fn plain_vias(&self, agent: Uuid, scopes: &[&str], client: Uuid) -> [Via<'_>; 2] {
        [
            Via::McpHttp(&self.mcp, mcp_auth(client, agent, None, scopes)),
            Via::Rest(
                &self.router,
                rest_token(&self.state, client, agent, None, scopes),
            ),
        ]
    }
}

/// The lineage gate's own refusal over a row the caller reads (every
/// transport names the submitter there, before and after R-183). A guard
/// asserts it so a refusal from another layer (the transport, or the armed
/// database refusing a write the gate wrongly admitted) cannot pass for the
/// gate's.
const GATE_REFUSAL: &str = "was submitted by agent";

/// Refused with nothing written, with a refusal containing `expect`.
async fn assert_refused(pool: &PgPool, via: &Via<'_>, name: &str, what: &str, expect: &str) {
    let before = row_counts(pool).await;
    let out = via
        .add_step(name, &format!("acme {what} step via {}", via.label()))
        .await;
    let err = out.expect_err(&format!(
        "{what} ({}): must be refused on {name}",
        via.label()
    ));
    assert!(
        err.contains(expect),
        "{what} ({}): refused by the expected layer ({expect:?}): {err}",
        via.label()
    );
    assert_eq!(
        row_counts(pool).await,
        before,
        "{what} ({}): the refusal wrote nothing",
        via.label()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RED: the delegate arm
// ─────────────────────────────────────────────────────────────────────────────

/// A live delegate of the submitter adds a step to the submitter's PUBLIC
/// workflow in a team group the delegate does not write, on every transport:
/// before R-183 no arm admitted it (it is not the submitter, not its operator,
/// and does not write the owner group). The step is the delegate's own, in its
/// own default group (its operator's), and the provenance row says
/// `delegate`, naming the submitter it acted for.
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_delegate_of_the_submitter_writes_its_public_workflow(pool: PgPool) {
    let w = world(&pool).await;
    // Every transport's outcome first, so a red run shows all three.
    let mut outcomes = Vec::new();
    for via in w.d_vias() {
        let label = via.label();
        let added = via
            .add_step(PUB, &format!("acme delegate step via {label}"))
            .await;
        outcomes.push((label, added));
    }
    let admitted: Vec<(&str, bool)> = outcomes.iter().map(|(l, r)| (*l, r.is_ok())).collect();
    assert_eq!(
        admitted,
        vec![("mcp-stdio", true), ("mcp-http", true), ("rest", true)],
        "a live delegate of the submitter adds a step on every transport: {outcomes:?}"
    );
    for (label, added) in outcomes {
        assert_eq!(
            claim_row(&pool, added.expect("admitted")).await,
            (w.d, "public".to_string(), w.p_g),
            "{label}: the step is the delegate's, public, in its own default group"
        );
    }
    let rows = caller_writes(&pool, w.pub_wf, w.d).await;
    let transports: Vec<Option<String>> = rows.iter().map(|r| r.4.clone()).collect();
    assert_eq!(rows.len(), 3, "one provenance row per transport: {rows:?}");
    for (action, arm, operator, submitter, _) in &rows {
        assert_eq!(action, "add_step");
        assert_eq!(arm, "delegate", "the arm is recorded as delegate: {rows:?}");
        assert_eq!(
            operator.as_deref(),
            Some(w.p.to_string().as_str()),
            "the operator the delegate acted for is named: {rows:?}"
        );
        assert_eq!(submitter.as_deref(), Some(w.p.to_string().as_str()));
    }
    assert!(
        transports.contains(&Some("stdio".to_string())),
        "the stdio write is recorded: {transports:?}"
    );
    assert_eq!(admin_writes(&pool, w.pub_wf).await, 0, "no admin arm ran");
}

/// Where the owner-group writer arm would ALSO admit (the submitter's own
/// group, which a live link makes the delegate a writer of), the delegate arm
/// comes first, so the audit names the delegation and not a membership. This
/// is the R-183 motivating shape: a stdio agent live-linked to the submitter
/// evolves a step of the submitter's workflow.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegate_write_is_recorded_as_delegate_not_as_an_owner_group_write(pool: PgPool) {
    let w = world(&pool).await;
    let steps = steps_of(&pool, w.own_wf).await;
    assert_eq!(steps.len(), 2, "PREMISE: two steps");
    let vias = w.d_vias();
    let evolved = vias[0]
        .evolve(steps[0], "acme own step 0, revised by the delegate")
        .await
        .expect("the delegate evolves a step of the submitter's workflow over stdio");
    assert_eq!(
        claim_row(&pool, evolved).await,
        (w.d, "group".to_string(), w.p_g),
        "the revision is the delegate's, in the workflow's group"
    );
    // add, evolve and delete a step on every transport (evolve is its own
    // call site over REST: `require_api_lineage_authority`).
    for via in &vias {
        let label = via.label();
        let added = via
            .add_step(OWN, &format!("acme own step via {label}"))
            .await
            .unwrap_or_else(|e| panic!("{label}: add_step: {e}"));
        let revised = via
            .evolve(added, &format!("acme own step via {label}, revised"))
            .await
            .unwrap_or_else(|e| panic!("{label}: evolve_step: {e}"));
        assert_eq!(claim_row(&pool, revised).await.0, w.d, "{label}");
        let lineage = step_lineage(&pool, added).await;
        let deleted = via
            .delete_step(OWN, lineage)
            .await
            .unwrap_or_else(|e| panic!("{label}: delete_step: {e}"));
        assert!(
            truth(&pool, deleted).await < 0.5,
            "{label}: the step was soft-deleted"
        );
    }
    let rows = caller_writes(&pool, w.own_wf, w.d).await;
    let arms: Vec<(&str, &str, Option<&str>)> = rows
        .iter()
        .map(|(a, arm, op, ..)| (a.as_str(), arm.as_str(), op.as_deref()))
        .collect();
    let p = Some(w.p.to_string());
    let p = p.as_deref();
    let mut expected = vec![("evolve_step", "delegate", p)];
    for _ in 0..3 {
        expected.extend([
            ("add_step", "delegate", p),
            ("evolve_step", "delegate", p),
            ("delete_step", "delegate", p),
        ]);
    }
    assert_eq!(
        arms, expected,
        "every write is recorded as the delegate's, naming the submitter"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// GUARDS: what the delegate arm must NOT admit, and what it must not change
// ─────────────────────────────────────────────────────────────────────────────

/// A RETIRED link grants nothing, although the retired agent's writer
/// membership of the submitter's group is still live: refused on stdio, and
/// over HTTP its delegated token is refused at the viewer.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_link_grants_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let dl = &w.p_delegator;
    for via in [
        Via::McpStdio(&w.r_server),
        Via::McpHttp(
            &w.mcp,
            mcp_auth(dl.delegator_client, w.r, Some(dl.delegator), WRITE_SCOPES),
        ),
        Via::Rest(
            &w.router,
            rest_token(
                &w.state,
                dl.delegator_client,
                w.r,
                Some(dl.delegator),
                WRITE_SCOPES,
            ),
        ),
    ] {
        // On HTTP a retired link holds no live delegation, so the transport
        // refuses before the gate; on stdio the gate itself refuses.
        let expect = match &via {
            Via::McpStdio(_) => GATE_REFUSAL,
            _ => "not live",
        };
        assert_refused(&pool, &via, PUB, "a retired link", expect).await;
    }
    assert!(caller_writes(&pool, w.pub_wf, w.r).await.is_empty());
}

/// A link record that is not retired but whose writer membership of the
/// submitter's group was revoked is not ACTING (migration 107: the operator
/// ends an agent's authority with an ordinary revoke), so it grants nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_link_whose_membership_was_revoked_grants_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let v_server = mcp_server(&pool, 0xD8).await;
    let v = stdio_agent(&pool, &v_server, 0xD8).await;
    link(&pool, v, w.p).await;
    delegation::revoke_membership(&pool, v, w.p_g).await;
    assert_eq!(
        acting_operator(&pool, v).await,
        None,
        "PREMISE: v's link is not acting"
    );
    assert_refused(
        &pool,
        &Via::McpStdio(&v_server),
        PUB,
        "a revoked link membership",
        GATE_REFUSAL,
    )
    .await;
}

/// A live link to a DIFFERENT operator grants nothing over the submitter's
/// workflow, on every transport (its delegated token is live: the gate
/// refuses).
#[sqlx::test(migrations = "../../migrations")]
async fn a_link_to_another_operator_grants_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let ql = &w.q_delegator;
    for via in [
        Via::McpStdio(&w.e_server),
        Via::McpHttp(
            &w.mcp,
            mcp_auth(ql.delegator_client, w.e, Some(ql.delegator), WRITE_SCOPES),
        ),
        Via::Rest(
            &w.router,
            rest_token(
                &w.state,
                ql.delegator_client,
                w.e,
                Some(ql.delegator),
                WRITE_SCOPES,
            ),
        ),
    ] {
        // CALIBRATION: the delegated context reaches the gate (its viewer
        // resolves), so the refusal is the gate's, not the transport's.
        if let Via::McpHttp(server, auth) = &via {
            epigraph_mcp::tools::viewer::request_viewer(server, Some(auth))
                .await
                .expect("CALIBRATION: e's delegation is live");
        }
        assert_refused(&pool, &via, PUB, "a link to another operator", GATE_REFUSAL).await;
    }
}

/// No link grants nothing, on every transport.
#[sqlx::test(migrations = "../../migrations")]
async fn no_link_grants_nothing(pool: PgPool) {
    let w = world(&pool).await;
    assert_refused(
        &pool,
        &Via::McpStdio(&w.n_server),
        PUB,
        "no link",
        GATE_REFUSAL,
    )
    .await;
    for via in w.plain_vias(w.n, WRITE_SCOPES, Uuid::new_v4()) {
        assert_refused(&pool, &via, PUB, "no link", GATE_REFUSAL).await;
    }
}

/// ONE hop: an agent operated by an agent operated by the submitter is not
/// admitted. Migration 107's link verb refuses to build such a chain, so the
/// fixture writes it directly (triggers off, superuser), to show the gate
/// itself follows one hop only. Only stdio can carry it: a delegated run token
/// names its principal's direct operator, which must be a registered human,
/// and a registered human is never operated.
#[sqlx::test(migrations = "../../migrations")]
async fn a_two_hop_chain_grants_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let (b, b_g) = fixture::seed_agent_with_group(&pool, "acme-middle").await;
    link(&pool, b, w.p).await;
    let a_server = mcp_server(&pool, 0xD5).await;
    let a = stdio_agent(&pool, &a_server, 0xD5).await;
    {
        use sqlx::Executor;
        let mut tx = pool.begin().await.expect("begin");
        tx.execute("SET LOCAL session_replication_role = replica")
            .await
            .expect("triggers off for the forged chain");
        sqlx::query(
            "INSERT INTO operator_links (agent_id, operator_id, operator_group_id, retired) \
             VALUES ($1, $2, $3, false)",
        )
        .bind(a)
        .bind(b)
        .bind(b_g)
        .execute(&mut *tx)
        .await
        .expect("forge a -> b");
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(b_g)
        .bind(a)
        .execute(&mut *tx)
        .await
        .expect("a writes b's group");
        tx.commit().await.expect("commit the forged chain");
    }
    assert_eq!(
        acting_operator(&pool, a).await,
        Some(b),
        "PREMISE: a acts for b"
    );
    assert_eq!(
        acting_operator(&pool, b).await,
        Some(w.p),
        "PREMISE: b acts for p"
    );
    assert!(!writes(&pool, a, w.t).await, "PREMISE: a does not write t");
    assert_refused(
        &pool,
        &Via::McpStdio(&a_server),
        PUB,
        "a two-hop chain",
        GATE_REFUSAL,
    )
    .await;
    // Nor over a workflow of p's other agent: a's link names b, and b is not
    // the sibling's operator (p is).
    let (_, _) = sibling_workflow(&pool, &w, 0xC4, "acme-delegate-chain-sibling", false).await;
    assert_refused(
        &pool,
        &Via::McpStdio(&a_server),
        "acme-delegate-chain-sibling",
        "a two-hop chain over a sibling's workflow",
        GATE_REFUSAL,
    )
    .await;
}

/// The upward arm (#503) is unchanged: the OPERATOR of a workflow's submitter
/// is admitted, recorded as `operator` (not `delegate`), on every transport.
#[sqlx::test(migrations = "../../migrations")]
async fn the_upward_operator_arm_still_admits(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-delegate-submitted-by-the-agent";
    Via::McpStdio(&w.d_server)
        .ingest(&extraction(name, 1), None)
        .await
        .expect("d ingests its own workflow");
    let wf = workflow_named(&pool, name).await;
    assert_eq!(workflow_row(&pool, wf).await.2, Some(w.d.to_string()));
    // stdio, where the server's own agent is a registered human operating d.
    let s_server = mcp_server(&pool, 0xD6).await;
    let s = stdio_agent(&pool, &s_server, 0xD6).await;
    fixture::make_human_operator(&pool, s).await;
    let s_agent_server = mcp_server(&pool, 0xD7).await;
    let s_agent = stdio_agent(&pool, &s_agent_server, 0xD7).await;
    link(&pool, s_agent, s).await;
    let s_name = "acme-delegate-submitted-by-s-agent";
    Via::McpStdio(&s_agent_server)
        .ingest(&extraction(s_name, 1), None)
        .await
        .expect("s's agent ingests its own workflow");
    let s_wf = workflow_named(&pool, s_name).await;
    Via::McpStdio(&s_server)
        .add_step(s_name, "acme operator step via mcp-stdio")
        .await
        .expect("stdio: the submitter's operator adds a step");
    assert_eq!(
        caller_writes(&pool, s_wf, s)
            .await
            .into_iter()
            .map(|r| (r.1, r.2))
            .collect::<Vec<_>>(),
        vec![("operator".to_string(), Some(s.to_string()))],
        "stdio: recorded as the operator arm"
    );
    for via in w.plain_vias(w.p, WRITE_SCOPES, Uuid::new_v4()) {
        let label = via.label();
        via.add_step(name, &format!("acme operator step via {label}"))
            .await
            .unwrap_or_else(|e| panic!("{label}: the submitter's operator adds a step: {e}"));
    }
    let arms: Vec<(String, Option<String>)> = caller_writes(&pool, wf, w.p)
        .await
        .into_iter()
        .map(|r| (r.1, r.2))
        .collect();
    let p = Some(w.p.to_string());
    assert_eq!(
        arms,
        vec![
            ("operator".to_string(), p.clone()),
            ("operator".to_string(), p.clone())
        ],
        "recorded as the operator arm"
    );
}

/// The owner-group writer arm (#785) is unchanged: a writer of the owner
/// group with no link to the submitter is admitted and recorded as such.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_group_writer_arm_is_unchanged(pool: PgPool) {
    let w = world(&pool).await;
    let (m, _) = fixture::seed_human_operator(&pool, "acme-team-writer").await;
    add_roster_row(&pool, w.t, m, "writer").await;
    for via in w.plain_vias(m, WRITE_SCOPES, Uuid::new_v4()) {
        let label = via.label();
        via.add_step(PUB, &format!("acme team writer step via {label}"))
            .await
            .unwrap_or_else(|e| panic!("{label}: a writer of t adds a step: {e}"));
    }
    let arms: Vec<String> = caller_writes(&pool, w.pub_wf, m)
        .await
        .into_iter()
        .map(|r| r.1)
        .collect();
    assert_eq!(arms, vec!["owner_group_writer", "owner_group_writer"]);
}

/// The audited admin arm is unchanged: a live `claims:admin` holder with no
/// link and no membership is admitted through it (a `workflows.admin_write`
/// row, no caller-write row); a `claims:admin` token whose client record
/// grants nothing is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_arm_is_unchanged(pool: PgPool) {
    let w = world(&pool).await;
    let (z, _) = fixture::seed_human_operator(&pool, "acme-admin").await;
    let ungranted = Uuid::new_v4();
    for via in w.plain_vias(z, ADMIN_SCOPES, ungranted) {
        assert_refused(&pool, &via, PUB, "an ungranted admin token", "ADM02").await;
    }
    let client = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id) \
         VALUES ($1, $2, 'test admin', 'human', ARRAY['claims:admin'], ARRAY['claims:admin'], \
                 'active', $3)",
    )
    .bind(client)
    .bind(format!("test-admin-{client}"))
    .bind(z)
    .execute(&pool)
    .await
    .expect("the admin's client record");
    for via in w.plain_vias(z, ADMIN_SCOPES, client) {
        let label = via.label();
        via.add_step(PUB, &format!("acme admin step via {label}"))
            .await
            .unwrap_or_else(|e| panic!("{label}: a live admin adds a step: {e}"));
    }
    assert_eq!(
        admin_writes(&pool, w.pub_wf).await,
        2,
        "two audited admin rows"
    );
    assert!(
        caller_writes(&pool, w.pub_wf, z).await.is_empty(),
        "an admin write records no caller-write row"
    );
}

/// R-100 masking holds for a delegate too: over the authenticated transports,
/// a delegate asking about its operator's workflow in a group it cannot read
/// gets exactly the answer an unknown name / unknown step gets, and nothing is
/// written or recorded. (The delegate arm, like the operator arm, does not
/// consult the caller's view; the step routes' own hidden-row answers and row
/// security keep the row unnamed and unwritten.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegate_is_answered_as_unknown_on_a_row_it_cannot_read(pool: PgPool) {
    let w = world(&pool).await;
    let hidden = "acme-delegate-hidden-in-team";
    Via::Rest(
        &w.router,
        rest_token(&w.state, Uuid::new_v4(), w.p, None, WRITE_SCOPES),
    )
    .ingest(&extraction(hidden, 1), group_in(w.t))
    .await
    .expect("p ingests a workflow private to t");
    let wf = workflow_named(&pool, hidden).await;
    assert_eq!(
        workflow_row(&pool, wf).await,
        ("group".to_string(), w.t, Some(w.p.to_string())),
        "PREMISE: p's, private to t, which d does not read"
    );
    let step = steps_of(&pool, wf).await[0];
    let unknown_name = "acme-delegate-hidden-in-tean";
    let unknown_step = Uuid::new_v4();
    let [_, http, rest] = w.d_vias();
    for via in [http, rest] {
        let label = via.label();
        let before = row_counts(&pool).await;
        let refused = via
            .add_step(hidden, "acme hidden step")
            .await
            .expect_err("add_step on a row the delegate cannot read is refused")
            .replace(hidden, "<name>");
        let unknown = via
            .add_step(unknown_name, "acme hidden step")
            .await
            .expect_err("add_step on an unknown name is refused")
            .replace(unknown_name, "<name>");
        assert_eq!(
            refused, unknown,
            "{label}: add_step answers as for an unknown name"
        );
        let refused = via
            .evolve(step, "acme hidden revision")
            .await
            .expect_err("evolve on a step the delegate cannot read is refused")
            .replace(&step.to_string(), "<id>");
        let unknown = via
            .evolve(unknown_step, "acme hidden revision")
            .await
            .expect_err("evolve on an unknown step is refused")
            .replace(&unknown_step.to_string(), "<id>");
        assert_eq!(
            refused, unknown,
            "{label}: evolve answers as for an unknown step"
        );
        assert_eq!(
            row_counts(&pool).await,
            before,
            "{label}: nothing was written"
        );
    }
    assert!(
        caller_writes(&pool, wf, w.d).await.is_empty(),
        "no provenance row for a refused write"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The sibling shape: the submitter is the principal's OTHER agent
// ─────────────────────────────────────────────────────────────────────────────

/// Another agent `s` of `p` (live-linked, then optionally RETIRED), a writer
/// of `t` through a roster row of its own, submits workflow `name` PUBLIC in
/// `t`. `p` itself is admitted over it by identity (the upward arm, #503,
/// retired links included); `d` writes neither `t` nor anything of `s`'s.
/// Returns `(s, workflow)`.
async fn sibling_workflow(
    pool: &PgPool,
    w: &World,
    seed: u8,
    name: &str,
    retire: bool,
) -> (Uuid, Uuid) {
    let s_server = mcp_server(pool, seed).await;
    let s = stdio_agent(pool, &s_server, seed).await;
    link(pool, s, w.p).await;
    add_roster_row(pool, w.t, s, "writer").await;
    Via::McpStdio(&s_server)
        .ingest(&extraction(name, 2), public_in(w.t))
        .await
        .unwrap_or_else(|e| panic!("the sibling ingests {name}: {e}"));
    let wf = workflow_named(pool, name).await;
    if retire {
        delegation::retire_link(pool, s).await;
    }
    assert_eq!(
        workflow_row(pool, wf).await,
        ("public".to_string(), w.t, Some(s.to_string())),
        "PREMISE: {name} is the sibling's, public, in t"
    );
    let mut conn = pool.acquire().await.expect("acquire");
    let op = epigraph_db::AgentRepository::operator_of_author(&mut conn, s)
        .await
        .expect("operator_of_author")
        .expect("PREMISE: the sibling has a link record");
    assert_eq!(
        (op.operator_id, op.retired),
        (w.p, retire),
        "PREMISE: p operates the sibling"
    );
    assert!(!writes(pool, w.d, w.t).await, "PREMISE: d does not write t");
    (s, wf)
}

/// R-183: a delegate is admitted wherever its principal is admitted BY
/// IDENTITY, and `p` is admitted over its other agents' workflows by the
/// upward arm (#503), retired agents included. So `d` (live-linked to `p`)
/// adds a step to a public workflow its sibling submitted, in a group `d` does
/// not write, on every transport, recorded as `delegate` naming `p` (the
/// principal it acted for), not the sibling. One hop holds on the caller's
/// side: `d`'s own link is the only delegation followed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegate_of_the_submitters_operator_writes_its_sibling_agents_workflow(pool: PgPool) {
    let w = world(&pool).await;
    let (live_sib, sib_wf) =
        sibling_workflow(&pool, &w, 0xC1, "acme-delegate-sibling", false).await;
    let (retired_sib, rsib_wf) =
        sibling_workflow(&pool, &w, 0xC2, "acme-delegate-retired-sibling", true).await;
    let p = w.p.to_string();
    for (name, wf, submitter) in [
        ("acme-delegate-sibling", sib_wf, live_sib),
        ("acme-delegate-retired-sibling", rsib_wf, retired_sib),
    ] {
        let mut outcomes = Vec::new();
        for via in w.d_vias() {
            let label = via.label();
            let added = via
                .add_step(name, &format!("acme sibling step via {label}"))
                .await;
            outcomes.push((label, added));
        }
        let admitted: Vec<(&str, bool)> = outcomes.iter().map(|(l, r)| (*l, r.is_ok())).collect();
        assert_eq!(
            admitted,
            vec![("mcp-stdio", true), ("mcp-http", true), ("rest", true)],
            "{name}: a live delegate of the submitter's operator is admitted: {outcomes:?}"
        );
        for (label, added) in outcomes {
            assert_eq!(
                claim_row(&pool, added.expect("admitted")).await,
                (w.d, "public".to_string(), w.p_g),
                "{name} ({label}): the step is the delegate's, in its own default group"
            );
        }
        let rows = caller_writes(&pool, wf, w.d).await;
        let arms: Vec<(&str, &str, Option<&str>, Option<&str>)> = rows
            .iter()
            .map(|(a, arm, op, sub, _)| (a.as_str(), arm.as_str(), op.as_deref(), sub.as_deref()))
            .collect();
        let sub = submitter.to_string();
        assert_eq!(
            arms,
            vec![("add_step", "delegate", Some(p.as_str()), Some(sub.as_str())); 3],
            "{name}: recorded as delegate, naming p as the principal and the sibling as submitter"
        );
    }
    // GUARD: a live delegate of ANOTHER principal is refused by the gate.
    let ql = &w.q_delegator;
    for via in [
        Via::McpStdio(&w.e_server),
        Via::McpHttp(
            &w.mcp,
            mcp_auth(ql.delegator_client, w.e, Some(ql.delegator), WRITE_SCOPES),
        ),
        Via::Rest(
            &w.router,
            rest_token(
                &w.state,
                ql.delegator_client,
                w.e,
                Some(ql.delegator),
                WRITE_SCOPES,
            ),
        ),
    ] {
        assert_refused(
            &pool,
            &via,
            "acme-delegate-sibling",
            "another principal's delegate on a sibling workflow",
            GATE_REFUSAL,
        )
        .await;
    }
    // GUARD: an unlinked agent, and the retired agent `r` on stdio.
    for (via, what) in [
        (Via::McpStdio(&w.n_server), "no link"),
        (Via::McpStdio(&w.r_server), "a retired link"),
    ] {
        assert_refused(&pool, &via, "acme-delegate-sibling", what, GATE_REFUSAL).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The HTTP gate's live-delegation conjunct, reached directly
// ─────────────────────────────────────────────────────────────────────────────

/// Over HTTP the delegate arm admits only a context that carries a LIVE
/// delegation (`dlg`). The transport's viewer refuses an operated principal
/// without one first, so this test hands the tool a viewer resolved on the
/// harness pool, and the lineage GATE is what decides: `d` without `dlg` is
/// refused on `PUB` (where only the delegate arm could admit it) and on the
/// sibling's workflow; the same call with `dlg` is admitted (calibration).
/// On `OWN`, where `d` writes the owner group, a no-`dlg` call is admitted by
/// the owner-group arm and recorded as such, never as `delegate`. The retired
/// agent `r` with a delegator context is refused by the gate too.
#[sqlx::test(migrations = "../../migrations")]
async fn an_http_delegate_needs_a_live_delegated_token_at_the_gate(pool: PgPool) {
    let w = world(&pool).await;
    let (_, sib_wf) = sibling_workflow(&pool, &w, 0xC3, "acme-delegate-gate-sibling", false).await;
    let dl = &w.p_delegator;
    let viewer = epigraph_db::Viewer::resolve(&pool, w.d)
        .await
        .expect("d's viewer");
    let plain = mcp_auth(dl.delegator_client, w.d, None, WRITE_SCOPES);
    for (name, wf) in [(PUB, w.pub_wf), ("acme-delegate-gate-sibling", sib_wf)] {
        let before = row_counts(&pool).await;
        let err = mcp_add_step_at_the_gate(&w.mcp, &viewer, &plain, name, "acme no-dlg step")
            .await
            .expect_err("no dlg: the delegate arm does not admit");
        assert!(
            err.contains(GATE_REFUSAL),
            "{name}: refused by the lineage gate: {err}"
        );
        assert_eq!(row_counts(&pool).await, before, "{name}: nothing written");
        assert!(caller_writes(&pool, wf, w.d).await.is_empty());
        // CALIBRATION: the same call with a live delegation is admitted.
        let delegated = mcp_auth(dl.delegator_client, w.d, Some(dl.delegator), WRITE_SCOPES);
        mcp_add_step_at_the_gate(&w.mcp, &viewer, &delegated, name, "acme dlg step")
            .await
            .unwrap_or_else(|e| {
                panic!("CALIBRATION {name}: with dlg the delegate is admitted: {e}")
            });
        let arms: Vec<String> = caller_writes(&pool, wf, w.d)
            .await
            .into_iter()
            .map(|r| r.1)
            .collect();
        assert_eq!(arms, vec!["delegate"], "{name}");
    }
    // OWN: no dlg, so the delegate arm is skipped and the owner-group arm
    // admits (d writes p_g through its link membership).
    mcp_add_step_at_the_gate(&w.mcp, &viewer, &plain, OWN, "acme no-dlg own step")
        .await
        .expect("the owner-group arm admits a writer of p_g");
    let arms: Vec<String> = caller_writes(&pool, w.own_wf, w.d)
        .await
        .into_iter()
        .map(|r| r.1)
        .collect();
    assert_eq!(
        arms,
        vec!["owner_group_writer"],
        "without dlg the write is not labelled a delegation"
    );
    // The retired agent with a delegator context, at the gate.
    let r_viewer = epigraph_db::Viewer::resolve(&pool, w.r)
        .await
        .expect("r's viewer");
    let r_ctx = mcp_auth(dl.delegator_client, w.r, Some(dl.delegator), WRITE_SCOPES);
    let before = row_counts(&pool).await;
    let err = mcp_add_step_at_the_gate(&w.mcp, &r_viewer, &r_ctx, PUB, "acme retired step")
        .await
        .expect_err("a retired link is no delegate at the gate");
    assert!(err.contains(GATE_REFUSAL), "refused by the gate: {err}");
    assert_eq!(row_counts(&pool).await, before);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tenancy is unchanged: the gate admits, row security still decides
// ─────────────────────────────────────────────────────────────────────────────

/// The delegate passes the lineage gate on `PUB` (public, owned by team group
/// `t`, which `d` reads but does not write), but the writes that would touch
/// `t`'s own claims are refused by ROW SECURITY, not by the gate, and nothing
/// is written or recorded: evolving a `PUB` step (the revision would land in
/// the step's group) and soft-deleting a `PUB` step (an update of a `t`-owned
/// claim). R-183 leaves tenancy unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegate_passes_the_gate_but_not_tenancy_on_a_group_it_does_not_write(pool: PgPool) {
    let w = world(&pool).await;
    let steps = steps_of(&pool, w.pub_wf).await;
    let target = steps[0];
    let lineage = step_lineage(&pool, target).await;
    let truth_before = truth(&pool, target).await;
    for via in w.d_vias() {
        let label = via.label();
        let before = row_counts(&pool).await;
        let evolved = via.evolve(target, "acme pub step, revised by d").await;
        let deleted = via.delete_step(PUB, lineage).await;
        let (Err(evolve_err), Err(delete_err)) = (&evolved, &deleted) else {
            panic!("{label}: tenancy refuses both: evolve {evolved:?}, delete {deleted:?}");
        };
        // The write paths' own tenancy refusals (measured on every transport;
        // REST answers 403 with the same text).
        for (verb, err, tenancy) in [
            (
                "evolve",
                evolve_err,
                "no write authority over the group that owns this step",
            ),
            (
                "delete_step",
                delete_err,
                "this session cannot write its claim, so it was not soft-deleted",
            ),
        ] {
            assert!(
                !err.contains(GATE_REFUSAL) && err.contains(tenancy),
                "{label} {verb}: refused by tenancy ({tenancy:?}), not by the gate: {err}"
            );
            if matches!(via, Via::Rest(..)) {
                assert!(err.starts_with("403"), "{label} {verb}: 403: {err}");
            }
        }
        assert_eq!(row_counts(&pool).await, before, "{label}: nothing written");
        assert_eq!(
            truth(&pool, target).await,
            truth_before,
            "{label}: the step is unchanged"
        );
    }
    assert!(
        caller_writes(&pool, w.pub_wf, w.d).await.is_empty(),
        "no provenance row survives a refused write"
    );
}

/// A new generation of `p`'s public lineage published by `d` (the delegate
/// arm admits it over the lineage head, on every transport) INHERITS the
/// lineage's submitter `p`, not `d`, and lands public in `d`'s own default
/// group (`d` does not write the lineage's group `t`). Each anchor check is
/// recorded as `delegate`. Another principal's delegate is refused by the
/// gate with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegate_publishes_the_next_generation_and_the_submitter_is_inherited(pool: PgPool) {
    let w = world(&pool).await;
    let ql = &w.q_delegator;
    let before = row_counts(&pool).await;
    let err = Via::McpHttp(
        &w.mcp,
        mcp_auth(ql.delegator_client, w.e, Some(ql.delegator), WRITE_SCOPES),
    )
    .ingest(&extraction_gen(PUB, 1, 1), None)
    .await
    .expect_err("another principal's delegate cannot extend p's lineage");
    assert!(err.contains(GATE_REFUSAL), "refused by the gate: {err}");
    assert_eq!(row_counts(&pool).await, before, "nothing written");
    assert_eq!(workflow_gen(&pool, PUB, 1).await, None);

    let p = w.p.to_string();
    let mut generation = 0;
    for via in w.d_vias() {
        let label = via.label();
        generation += 1;
        let head = workflow_gen(&pool, PUB, generation - 1)
            .await
            .expect("the lineage head");
        via.ingest(&extraction_gen(PUB, generation as u32, 1), None)
            .await
            .unwrap_or_else(|e| panic!("{label}: the delegate publishes gen {generation}: {e}"));
        let created = workflow_gen(&pool, PUB, generation)
            .await
            .expect("the new generation");
        assert_eq!(
            workflow_row(&pool, created).await,
            ("public".to_string(), w.p_g, Some(p.clone())),
            "{label}: public, in d's own default group, submitter INHERITED from the lineage"
        );
        let rows = caller_writes(&pool, head, w.d).await;
        assert!(!rows.is_empty(), "{label}: the anchor check is recorded");
        for (action, arm, operator, submitter, _) in &rows {
            assert_eq!(
                (
                    action.as_str(),
                    arm.as_str(),
                    operator.as_deref(),
                    submitter.as_deref()
                ),
                (
                    "workflow_ingest",
                    "delegate",
                    Some(p.as_str()),
                    Some(p.as_str())
                ),
                "{label}: {rows:?}"
            );
        }
    }
}

async fn workflow_truth(pool: &PgPool, wf: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(pool)
        .await
        .expect("workflow truth")
}

/// `deprecate_workflow` (MCP; REST has no hierarchical deprecation) by `p`'s
/// delegate. Over `p`'s workflow private to `p_g` (which `d` writes through
/// its link) it is admitted on stdio and MCP-HTTP and recorded as `delegate`
/// naming `p`. Over `p`'s public workflow in team group `t` (which `d` does
/// not write) the gate admits it but row security refuses the deprecation of
/// `t`'s claims, so nothing is written or recorded (tenancy unchanged; the
/// refusal surfaces as the tool's opaque internal error, the write path's
/// existing answer to a row-security refusal there). Another principal's
/// delegate is refused by the gate itself.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegate_deprecates_its_operators_workflow(pool: PgPool) {
    let w = world(&pool).await;
    let p_rest = Via::Rest(
        &w.router,
        rest_token(&w.state, Uuid::new_v4(), w.p, None, WRITE_SCOPES),
    );
    let in_t = "acme-delegate-deprecated-in-team";
    p_rest
        .ingest(&extraction(in_t, 1), public_in(w.t))
        .await
        .expect("p ingests a public workflow in t");
    let in_t = workflow_named(&pool, in_t).await;

    let ql = &w.q_delegator;
    let before = row_counts(&pool).await;
    let err = Via::McpHttp(
        &w.mcp,
        mcp_auth(ql.delegator_client, w.e, Some(ql.delegator), WRITE_SCOPES),
    )
    .deprecate(in_t)
    .await
    .expect_err("another principal's delegate cannot deprecate it");
    assert!(err.contains(GATE_REFUSAL), "refused by the gate: {err}");
    assert_eq!(row_counts(&pool).await, before);

    let [stdio, http, _] = w.d_vias();
    let truth_before = workflow_truth(&pool, in_t).await;
    let step = steps_of(&pool, in_t).await[0];
    let step_truth = truth(&pool, step).await;
    let err = http
        .deprecate(in_t)
        .await
        .expect_err("tenancy refuses the delegate's deprecation of t's claims");
    assert_eq!(
        err, "internal error; the detail is in the server log",
        "admitted by the gate (not its refusal), refused below it: {err}"
    );
    assert_eq!(row_counts(&pool).await, before, "nothing written");
    assert_eq!(workflow_truth(&pool, in_t).await, truth_before);
    assert_eq!(truth(&pool, step).await, step_truth);
    assert!(caller_writes(&pool, in_t, w.d).await.is_empty());

    for (i, via) in [stdio, http].into_iter().enumerate() {
        let label = via.label();
        let name = format!("acme-delegate-deprecated-own-{i}");
        p_rest
            .ingest(&extraction(&name, 1), group_in(w.p_g))
            .await
            .expect("p ingests a workflow private to p_g");
        let wf = workflow_named(&pool, &name).await;
        let out = via
            .deprecate(wf)
            .await
            .unwrap_or_else(|e| panic!("{label}: the delegate deprecates it: {e}"));
        assert!(
            workflow_truth(&pool, wf).await < 0.5,
            "{label}: deprecated: {out}"
        );
        let arms: Vec<(String, String, Option<String>)> = caller_writes(&pool, wf, w.d)
            .await
            .into_iter()
            .map(|r| (r.0, r.1, r.2))
            .collect();
        assert_eq!(
            arms,
            vec![(
                "deprecate_workflow".to_string(),
                "delegate".to_string(),
                Some(w.p.to_string())
            )],
            "{label}: recorded as delegate"
        );
    }
}

/// stdio half of the R-100 masking guard: a stdio delegate asking about its
/// operator's workflow in a group it cannot read is refused by the stdio
/// read pre-check (which runs before every arm) without the row's id or
/// submitter, and nothing is written or recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_delegate_is_refused_unnamed_on_a_row_it_cannot_read(pool: PgPool) {
    let w = world(&pool).await;
    let hidden = "acme-delegate-hidden-stdio";
    Via::Rest(
        &w.router,
        rest_token(&w.state, Uuid::new_v4(), w.p, None, WRITE_SCOPES),
    )
    .ingest(&extraction(hidden, 1), group_in(w.t))
    .await
    .expect("p ingests a workflow private to t");
    let wf = workflow_named(&pool, hidden).await;
    let before = row_counts(&pool).await;
    let err = Via::McpStdio(&w.d_server)
        .add_step(hidden, "acme hidden step")
        .await
        .expect_err("refused");
    assert!(
        !err.contains(&wf.to_string()) && !err.contains(&w.p.to_string()),
        "the refusal names neither the row nor its submitter: {err}"
    );
    assert!(!err.contains(GATE_REFUSAL), "{err}");
    assert_eq!(row_counts(&pool).await, before);
    assert!(caller_writes(&pool, wf, w.d).await.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// The claim ownership gate's delegate arm: tenancy is unchanged
// ─────────────────────────────────────────────────────────────────────────────

/// The ownership gate's refusals (stdio, HTTP), before and after R-183.
const CLAIM_GATE_STDIO: &str = "cannot retire it";
const CLAIM_GATE_HTTP: &str = "requires claims:admin scope or ownership";

/// `(is_current, labels)` of a claim.
async fn claim_state(pool: &PgPool, id: Uuid) -> (bool, Vec<String>) {
    sqlx::query_as("SELECT is_current, labels FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("claim state")
}

/// The claim verbs a delegate now owns, by name.
const CLAIM_VERBS: [&str; 4] = [
    "supersede (stdio)",
    "resolve (stdio)",
    "resolve (mcp-http)",
    "update_labels resolved (stdio)",
];

/// One claim verb `verb` (of [`CLAIM_VERBS`]) as `d` on `target`:
/// `supersede_claim` (stdio), `resolve_backlog_item` (stdio, and HTTP with
/// `d`'s live delegated context) or `update_labels` adding the retirement
/// label (stdio).
async fn d_claim_verb(w: &World, target: Uuid, verb: &str) -> Result<(), String> {
    let dl = &w.p_delegator;
    let ctx = mcp_auth(dl.delegator_client, w.d, Some(dl.delegator), WRITE_SCOPES);
    let (server, auth) = if verb.contains("mcp-http") {
        (&w.mcp, Some(&ctx))
    } else {
        (&w.d_server, None)
    };
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, auth)
        .await
        .map_err(|e| format!("viewer: {}", e.message))?;
    let out = if verb.starts_with("supersede") {
        epigraph_mcp::tools::supersede::supersede_claim(
            server,
            &viewer,
            epigraph_mcp::types::SupersedeClaimParams {
                claim_id: target.to_string(),
                content: format!("acme replacement for {target}"),
                truth_value: 0.7,
                reason: "delegate tenancy test".to_string(),
            },
            auth,
        )
        .await
    } else if verb.starts_with("resolve") {
        epigraph_mcp::tools::claims::resolve_backlog_item(
            server,
            &viewer,
            epigraph_mcp::types::ResolveBacklogItemParams {
                original_id: target.to_string(),
                resolution_content: format!("acme resolved {target} via {verb}"),
                methodology: None,
                basis_claim_ids: Vec::new(),
            },
            auth,
        )
        .await
    } else {
        epigraph_mcp::tools::claims::update_labels(
            server,
            &viewer,
            epigraph_mcp::types::UpdateLabelsParams {
                claim_id: target.to_string(),
                add: vec!["resolved".to_string()],
                remove: Vec::new(),
            },
            auth,
        )
        .await
    };
    match out {
        Ok(r) if r.is_error == Some(true) => Err(format!("tool error: {r:?}")),
        Ok(_) => Ok(()),
        Err(e) => Err(e.message.to_string()),
    }
}

/// R-183 widened the claim ownership gate: `d` now OWNS `p`'s own claims by
/// authorship, wherever they live. Tenancy is the only barrier left for a
/// `p`-authored claim owned by a group `d` does not write, and it must hold:
/// on `PUB`'s step (public, authored by `p`, owned by `t`) every verb is
/// refused by ROW SECURITY, not by the ownership gate, and nothing changes.
/// CALIBRATION on the same app-role servers: the same verbs on `p`-authored
/// claims owned by `p_g` (which `d` writes through its link) succeed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegate_owns_but_cannot_write_its_operators_claim_in_a_group_it_does_not_write(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let foreign = steps_of(&pool, w.pub_wf).await[0];
    assert_eq!(
        claim_row(&pool, foreign).await,
        (w.p, "public".to_string(), w.t),
        "PREMISE: p's claim, owned by t"
    );
    assert!(
        !writes(&pool, w.d, w.t).await,
        "PREMISE: d does not write t"
    );
    let state_before = claim_state(&pool, foreign).await;
    let counts_before = row_counts(&pool).await;
    let mut outcomes = Vec::new();
    for verb in CLAIM_VERBS {
        outcomes.push((verb, d_claim_verb(&w, foreign, verb).await));
    }
    for (verb, out) in &outcomes {
        let err = out
            .as_ref()
            .expect_err(&format!("{verb}: refused on a t-owned claim: {outcomes:?}"));
        // Each verb's own write-time refusal (measured): the database refused
        // the write on the caller's stamp; the ownership gate had admitted it.
        let tenancy = match *verb {
            "supersede (stdio)" => "no write authority over the group that owns this claim",
            "update_labels resolved (stdio)" => "holds no live writer or admin membership",
            _ => "could not label",
        };
        assert!(
            !err.contains(CLAIM_GATE_STDIO)
                && !err.contains(CLAIM_GATE_HTTP)
                && err.contains(tenancy)
                && (err.contains("Nothing was written") || err.contains("nothing was written")),
            "{verb}: refused by tenancy ({tenancy:?}), not by the ownership gate: {err}"
        );
    }
    assert_eq!(
        claim_state(&pool, foreign).await,
        state_before,
        "the claim is unchanged"
    );
    assert_eq!(row_counts(&pool).await, counts_before, "nothing written");

    // CALIBRATION: p-authored claims in p_g, one per verb.
    let p_rest = Via::Rest(
        &w.router,
        rest_token(&w.state, Uuid::new_v4(), w.p, None, WRITE_SCOPES),
    );
    let mut own = steps_of(&pool, w.own_wf).await;
    for i in 0..2 {
        own.push(
            p_rest
                .add_step(OWN, &format!("acme p's own step {i}"))
                .await
                .expect("p adds a step to its own workflow"),
        );
    }
    for (i, verb) in CLAIM_VERBS.into_iter().enumerate() {
        let target = own[i];
        assert_eq!(
            claim_row(&pool, target).await,
            (w.p, "group".to_string(), w.p_g),
            "PREMISE: p's claim in p_g"
        );
        let state = claim_state(&pool, target).await;
        d_claim_verb(&w, target, verb)
            .await
            .unwrap_or_else(|e| panic!("CALIBRATION {verb}: admitted and written in p_g: {e}"));
        assert_ne!(
            claim_state(&pool, target).await,
            state,
            "CALIBRATION {verb}: the claim changed"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A row with no recorded submitter
// ─────────────────────────────────────────────────────────────────────────────

/// A delegate inherits what its principal is admitted to BY IDENTITY. A
/// workflow with NO recorded submitter has no principal to act for: every
/// transport admits there only a live writer of its owner group (and, with a
/// token, the audited admin arm). So the delegate arm admits nothing on such
/// a row, and in particular it does not reopen the any-reader admission
/// stdio used to give it.
///
/// The row is public in team group `t`: `p` writes `t`, its delegate `d` only
/// reads it. `d` is refused `add_step` and a new generation on every
/// transport, and `deprecate_workflow` on both MCP transports, by the
/// no-submitter rule's own text, with nothing written and nothing recorded.
/// CALIBRATIONS (after the refusals, since they write): `p` itself is
/// admitted there through its MEMBERSHIP (recorded `owner_group_writer`),
/// which a delegate does not inherit; and once the same row records `p` as
/// its submitter, `d` is admitted over stdio as `p`'s delegate, so the
/// missing submitter alone is what refused it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegate_admits_nothing_on_a_row_with_no_recorded_submitter(pool: PgPool) {
    let w = world(&pool).await;
    const UNRECORDED: &str = "acme-delegate-unrecorded";
    Via::Rest(
        &w.router,
        rest_token(&w.state, Uuid::new_v4(), w.p, None, WRITE_SCOPES),
    )
    .ingest(&extraction(UNRECORDED, 2), public_in(w.t))
    .await
    .unwrap_or_else(|e| panic!("p ingests {UNRECORDED}: {e}"));
    let wf = workflow_named(&pool, UNRECORDED).await;
    sqlx::query("UPDATE workflows SET metadata = metadata - 'epigraph_submitted_by' WHERE id = $1")
        .bind(wf)
        .execute(&pool)
        .await
        .expect("drop the recorded submitter");
    assert_eq!(
        workflow_row(&pool, wf).await,
        ("public".to_string(), w.t, None),
        "PREMISE: public in t, no recorded submitter"
    );
    assert!(
        !writes(&pool, w.d, w.t).await,
        "PREMISE: d does not write t"
    );
    assert_eq!(
        acting_operator(&pool, w.d).await,
        Some(w.p),
        "PREMISE: d acts for p, who writes t"
    );
    let row_before = workflow_row(&pool, wf).await;
    let truth_before = workflow_truth(&pool, wf).await;
    let counts_before = row_counts(&pool).await;

    // Every outcome first, so a red run shows every transport and verb.
    let mut outcomes: Vec<(String, Result<Value, String>)> = Vec::new();
    for via in w.d_vias() {
        let label = via.label();
        outcomes.push((
            format!("{label} add_step"),
            via.add_step(UNRECORDED, &format!("acme unrecorded step via {label}"))
                .await
                .map(|id| json!(id)),
        ));
        outcomes.push((
            format!("{label} generation 1"),
            via.ingest(&extraction_gen(UNRECORDED, 1, 1), None).await,
        ));
        if !matches!(via, Via::Rest(..)) {
            outcomes.push((format!("{label} deprecate"), via.deprecate(wf).await));
        }
    }
    let admitted: Vec<&str> = outcomes
        .iter()
        .filter(|(_, r)| r.is_ok())
        .map(|(what, _)| what.as_str())
        .collect();
    assert!(
        admitted.is_empty(),
        "a delegate is admitted nowhere on a row with no recorded submitter: {admitted:?} \
         ({outcomes:?})"
    );
    for (what, outcome) in &outcomes {
        let err = outcome.as_ref().expect_err("refused");
        assert!(
            err.contains("no recorded submitter") && err.contains("owner group"),
            "{what}: refused by the no-submitter rule itself, naming it: {err}"
        );
    }
    assert_eq!(
        caller_writes(&pool, wf, w.d).await,
        Vec::<CallerWrite>::new(),
        "no provenance row records an admission of d"
    );
    assert_eq!(admin_writes(&pool, wf).await, 0, "no admin arm ran");
    assert_eq!(
        workflow_gen(&pool, UNRECORDED, 1).await,
        None,
        "no generation 1"
    );
    assert_eq!(
        workflow_row(&pool, wf).await,
        row_before,
        "the row is untouched"
    );
    assert_eq!(
        workflow_truth(&pool, wf).await,
        truth_before,
        "the row is not deprecated"
    );
    assert_eq!(
        row_counts(&pool).await,
        counts_before,
        "nothing was written"
    );

    // CALIBRATION A: p itself is admitted on this row, by its membership of t.
    Via::Rest(
        &w.router,
        rest_token(&w.state, Uuid::new_v4(), w.p, None, WRITE_SCOPES),
    )
    .add_step(UNRECORDED, "acme unrecorded step by p")
    .await
    .expect("CALIBRATION A: p, a writer of t, adds a step");
    let p_rows = caller_writes(&pool, wf, w.p).await;
    assert_eq!(
        p_rows
            .iter()
            .map(|r| (r.0.as_str(), r.1.as_str()))
            .collect::<Vec<_>>(),
        vec![("add_step", "owner_group_writer")],
        "CALIBRATION A: p is admitted by membership, not identity: {p_rows:?}"
    );

    // CALIBRATION B: the same row with p recorded as its submitter admits d.
    sqlx::query(
        "UPDATE workflows SET metadata = metadata || \
                jsonb_build_object('epigraph_submitted_by', $2::text) WHERE id = $1",
    )
    .bind(wf)
    .bind(w.p)
    .execute(&pool)
    .await
    .expect("record p as the submitter");
    Via::McpStdio(&w.d_server)
        .add_step(UNRECORDED, "acme recorded step by d")
        .await
        .expect("CALIBRATION B: with p recorded, d is admitted as p's delegate");
    let p_str = w.p.to_string();
    assert_eq!(
        caller_writes(&pool, wf, w.d).await,
        vec![(
            "add_step".to_string(),
            "delegate".to_string(),
            Some(p_str.clone()),
            Some(p_str),
            Some("stdio".to_string()),
        )],
        "CALIBRATION B: recorded as the delegation"
    );
}
