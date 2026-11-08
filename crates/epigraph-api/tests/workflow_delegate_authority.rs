//! The DELEGATE arm of the workflow lineage gate: an agent whose LIVE operator
//! link names a workflow's submitter is admitted wherever the submitter itself
//! is admitted by identity (operator ruling R-183), on every transport.
//!
//! The gate (`routes/workflows.rs::workflow_authority`, and its MCP twin
//! `tools/workflow_authority.rs`, authenticated and stdio arms) admits, in
//! order: the submitter; the submitter's operator (#503, upward); a DELEGATE
//! of the submitter (the caller's acting link names the submitter: one hop,
//! a not-retired record and a live writer membership of the submitter's own
//! group, `AgentRepository::operator_actor`); a writer of the row's owner
//! group; the audited `claims:admin` arm. A delegate's write is recorded in
//! its `workflows.caller_write` row as `"arm": "delegate"` with `operator` =
//! the submitter it acted for, so an audit tells it from the submitter's own.
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

// ─────────────────────────────────────────────────────────────────────────────
// Payloads and harness reads
// ─────────────────────────────────────────────────────────────────────────────

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
    for via in w.d_vias() {
        let label = via.label();
        let added = via
            .add_step(PUB, &format!("acme delegate step via {label}"))
            .await
            .unwrap_or_else(|e| {
                panic!("{label}: a live delegate of the submitter adds a step: {e}")
            });
        assert_eq!(
            claim_row(&pool, added).await,
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
    let [stdio, http, rest] = w.d_vias();
    let evolved = stdio
        .evolve(steps[0], "acme own step 0, revised by the delegate")
        .await
        .expect("the delegate evolves a step of the submitter's workflow over stdio");
    assert_eq!(
        claim_row(&pool, evolved).await,
        (w.d, "group".to_string(), w.p_g),
        "the revision is the delegate's, in the workflow's group"
    );
    http.add_step(OWN, "acme own step via mcp-http")
        .await
        .expect("mcp-http add_step");
    rest.add_step(OWN, "acme own step via rest")
        .await
        .expect("rest add_step");
    let rows = caller_writes(&pool, w.own_wf, w.d).await;
    assert_eq!(rows.len(), 3, "{rows:?}");
    let arms: Vec<(&str, &str, Option<&str>)> = rows
        .iter()
        .map(|(a, arm, op, ..)| (a.as_str(), arm.as_str(), op.as_deref()))
        .collect();
    let p = w.p.to_string();
    assert_eq!(
        arms,
        vec![
            ("evolve_step", "delegate", Some(p.as_str())),
            ("add_step", "delegate", Some(p.as_str())),
            ("add_step", "delegate", Some(p.as_str())),
        ],
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
