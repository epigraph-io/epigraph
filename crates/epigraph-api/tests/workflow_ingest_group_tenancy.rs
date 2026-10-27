//! Group-private workflow ingest: `ingest_workflow` with a declared `tenancy`.
//!
//! A hierarchical ingest used to have one tenancy: every claim it wrote was
//! public, owned by the ingest system agent's default group. These tests pin
//! the declared form, `tenancy: {"visibility": "group", "owner_group_id": G}`,
//! on the production pool shape: the router runs on an `epigraph_app`
//! `ScopedPool` (`AppState::with_scoped_pool`), the MCP server is an app-role
//! stdio server, the database is ARMED (migration 122) with the ingest system
//! agent registered (migration 148) and live-linked to a human operator `H`,
//! and no extra PERMISSIVE policy is installed. The harness superuser only
//! seeds and inspects.
//!
//! # The rules pinned
//!
//! * The new claims land `('group', G)`, and so do their `executes` edges. The
//!   rows are written on a transaction stamped from the SYSTEM agent, so the
//!   row-security `WITH CHECK` on `claims`/`edges` passes only because that
//!   agent writes G: the success arms below are the measurement of that check.
//! * The CALLER AGENT ITSELF must hold a live writer/admin membership of G.
//!   Its human's memberships do not count: a fleet agent linked to `H`, who
//!   writes G, is refused when it is not a member of G itself. A refusal
//!   writes nothing.
//! * The system agent must write G too, or the ingest is refused before any
//!   row is written (rather than failing on the first INSERT).
//! * Every claim the ingest did NOT create (a reused step of an earlier
//!   generation, a shared operation atom, a whole re-ingest) whose tenancy is
//!   not `('group', G)` is listed in `reused_items`, with its tenancy. Nothing
//!   re-tenants it.
//! * `embed: false` makes no embedding call and writes no claim embedding and
//!   no goal embedding, on REST and on stdio MCP (the stdio servers here embed
//!   through a counting generator, `McpEmbedder::with_generator`).
//! * A plan that reuses a claim private to a group the caller does not write
//!   is refused before any edge is written: those edges would be owned by that
//!   group and written on the system agent's stamp.
//! * Without `tenancy` nothing changes: public, and no `reused_items` key.
//!
//! # The ownership the tests use: the operator group, and a team group
//!
//! The group-creation HTTP routes are not usable on the application role, so a
//! role-owned workflow lives either in the human's operator group (the
//! fallback) or in a team group provisioned on a maintenance session (here,
//! the harness). Both are exercised. The fallback has a stated consequence the
//! tests pin rather than hide: linking an agent to `H` gives it a writer row in
//! `H`'s operator group, so under the fallback every agent linked to `H` passes
//! the own-membership check. Only a separate team group separates a curator
//! from the rest of `H`'s agents.
//!
//! # Why the HTTP refusal of an operated agent is not new here
//!
//! Over HTTP an operated agent gets no viewer at all (`request_viewer`, and the
//! REST `ViewerExtractor`), whatever the request. The own-membership check is
//! therefore observable over HTTP only for a caller that is NOT operated: the
//! human itself, naming a group it does not write. Both are pinned; only the
//! second depends on this change.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::repos::privatization::PrivatizationRepository;
use epigraph_db::{GroupRepository, ScopedPool, SessionGucMode};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const WRITE_SCOPES: &[&str] = &["claims:read", "claims:write", "edges:write"];
const READ_SCOPES: &[&str] = &["claims:read"];

fn token(agent: Uuid, scopes: &[&str]) -> String {
    common::mint_token_with_agent(scopes, agent)
}

fn uuid_of(v: &Value) -> Uuid {
    Uuid::parse_str(
        v.as_str()
            .unwrap_or_else(|| panic!("not a uuid string: {v}")),
    )
    .unwrap_or_else(|e| panic!("not a uuid: {v}: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// The production-shaped API, with a mock embedder
// ─────────────────────────────────────────────────────────────────────────────

struct Api {
    router: axum::Router,
    /// The router's embedding service, kept so a test can count its calls:
    /// `MockProvider` adds every text it embeds to its token usage.
    embedder: std::sync::Arc<MockProvider>,
}

impl Api {
    /// The router over an `epigraph_app` `ScopedPool` (the `bin/server.rs`
    /// wiring), with a mock embedding service so the post-commit embeds run.
    async fn prod_shaped(pool: &PgPool) -> Self {
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
        let scoped =
            ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
                .await
                .expect("app-role ScopedPool");
        let embedder = std::sync::Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
        let service: std::sync::Arc<dyn EmbeddingService> = embedder.clone();
        let state = AppState::with_scoped_pool(scoped, ApiConfig::default())
            .with_embedding_service(service);
        state
            .load_entity_type_cache()
            .await
            .expect("load the entity-type cache");
        Self {
            router: epigraph_api::routes::create_router(state),
            embedder,
        }
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        token: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let body = match body {
            Some(b) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let resp = self
            .router
            .clone()
            .oneshot(req.body(body).expect("request"))
            .await
            .expect("router");
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

    async fn get(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        self.call(Method::GET, uri, token, None).await
    }

    /// `POST /api/v1/workflows/ingest` with `body` as sent.
    async fn ingest(&self, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(Method::POST, "/api/v1/workflows/ingest", token, Some(body))
            .await
    }

    /// The ingest, insisting on 200.
    async fn ingest_ok(&self, token: &str, body: &Value) -> Value {
        let (status, out) = self.ingest(token, body).await;
        assert_eq!(status, StatusCode::OK, "ingest: {out}");
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Payloads
// ─────────────────────────────────────────────────────────────────────────────

/// One phase of `steps.len()` level-2 steps; step `i` carries the operation
/// atoms `steps[i]`. Step and phase texts embed `name`, so a count of claims
/// mentioning `name` is a count of what this payload wrote.
fn extraction(name: &str, generation: u32, steps: &[&[&str]]) -> Value {
    let steps: Vec<Value> = steps
        .iter()
        .enumerate()
        .map(|(i, ops)| {
            json!({"compound": format!("{name} step {i}"),
                   "rationale": "ordered", "operations": ops, "generality": [],
                   "confidence": 0.8})
        })
        .collect();
    json!({
        "source": {"canonical_name": name,
                   "goal": format!("workflow-plan goal for {name}"),
                   "generation": generation, "metadata": {}},
        "thesis_derivation": "TopDown",
        "phases": [{"title": "Body", "summary": format!("{name} phase"), "steps": steps}],
        "relationships": []
    })
}

/// `extraction` plus the declared tenancy (and `embed`, when given), as the
/// REST body carries them: siblings of the extraction's own keys.
fn declared(mut body: Value, group: Uuid, embed: Option<bool>) -> Value {
    body["tenancy"] = json!({"visibility": "group", "owner_group_id": group});
    if let Some(embed) = embed {
        body["embed"] = json!(embed);
    }
    body
}

/// The MCP tool's parameters: the extraction under `extraction`, the tenancy
/// beside it. Built from JSON, as a client sends them.
fn mcp_params(extraction: Value, group: Option<Uuid>) -> epigraph_mcp::types::IngestWorkflowParams {
    mcp_params_embed(extraction, group, None)
}

/// [`mcp_params`] with an explicit `embed`.
fn mcp_params_embed(
    extraction: Value,
    group: Option<Uuid>,
    embed: Option<bool>,
) -> epigraph_mcp::types::IngestWorkflowParams {
    let mut params = json!({ "extraction": extraction });
    if let Some(g) = group {
        params["tenancy"] = json!({"visibility": "group", "owner_group_id": g});
    }
    if let Some(embed) = embed {
        params["embed"] = json!(embed);
    }
    serde_json::from_value(params).expect("the tool's parameters")
}

// ─────────────────────────────────────────────────────────────────────────────
// Harness reads
// ─────────────────────────────────────────────────────────────────────────────

async fn workflow_id_named(pool: &PgPool, name: &str, generation: i32) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM workflows WHERE canonical_name = $1 AND generation = $2")
        .bind(name)
        .bind(generation)
        .fetch_optional(pool)
        .await
        .expect("workflow row")
}

async fn workflows_named(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("count workflows")
}

/// Claims whose content mentions `name`: the phase and step claims of
/// a payload built by [`extraction`].
async fn claims_mentioning(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE strpos(content, $1) > 0")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("count claims")
}

/// `(claims, edges, workflows, mass_functions)` row counts: a refusal that
/// "writes nothing" leaves every one of them unchanged, whatever text or ids
/// the payload carried (operation atoms, AUTHORED edges, BBAs included).
async fn row_counts(pool: &PgPool) -> (i64, i64, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM claims), (SELECT count(*) FROM edges), \
                (SELECT count(*) FROM workflows), (SELECT count(*) FROM mass_functions)",
    )
    .fetch_one(pool)
    .await
    .expect("row counts")
}

/// `(planned claims, of them embedded, goal embedded)` for the workflow `out`
/// names.
async fn embedding_state(pool: &PgPool, out: &Value) -> (i64, i64, bool) {
    let wf = uuid_of(&out["workflow_id"]);
    let ids: Vec<Uuid> = plan_ids(pool, wf).await.into_iter().collect();
    let (all, embedded): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE embedding IS NOT NULL) \
           FROM claims WHERE id = ANY($1)",
    )
    .bind(&ids)
    .fetch_one(pool)
    .await
    .expect("embedding counts");
    let goal: bool =
        sqlx::query_scalar("SELECT goal_embedding IS NOT NULL FROM workflows WHERE id = $1")
            .bind(wf)
            .fetch_one(pool)
            .await
            .expect("goal embedding");
    (all, embedded, goal)
}

/// Every `(claim id, visibility, owner group)` the workflow executes.
async fn plan_tenancy(pool: &PgPool, workflow_id: Uuid) -> Vec<(Uuid, String, Uuid)> {
    sqlx::query_as(
        "SELECT c.id, c.visibility::text, c.owner_group_id FROM edges e \
           JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
          ORDER BY (e.properties->>'plan_index')::int",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .expect("plan tenancy")
}

/// Every `executes` edge's `(visibility, owner group)`.
async fn executes_tenancy(pool: &PgPool, workflow_id: Uuid) -> Vec<(String, Uuid)> {
    sqlx::query_as(
        "SELECT visibility::text, owner_group_id FROM edges \
          WHERE source_id = $1 AND relationship = 'executes'",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await
    .expect("edge tenancy")
}

/// The claims the workflow executes, as a set.
async fn plan_ids(pool: &PgPool, workflow_id: Uuid) -> BTreeSet<Uuid> {
    plan_tenancy(pool, workflow_id)
        .await
        .into_iter()
        .map(|(id, _, _)| id)
        .collect()
}

/// `reused_items` as `{claim_id -> (visibility, owner_group_id)}`.
fn reused(out: &Value) -> std::collections::BTreeMap<Uuid, (Value, Value)> {
    out.get("reused_items")
        .unwrap_or_else(|| panic!("the response carries no reused_items: {out}"))
        .as_array()
        .unwrap_or_else(|| panic!("reused_items is not an array: {out}"))
        .iter()
        .map(|i| {
            (
                uuid_of(&i["claim_id"]),
                (i["visibility"].clone(), i["owner_group_id"].clone()),
            )
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// The armed, production-shaped world
// ─────────────────────────────────────────────────────────────────────────────

async fn as_maintenance(
    pool: &PgPool,
    sql: &'static str,
    a: Uuid,
    b: Uuid,
) -> Result<(), sqlx::Error> {
    fixture::as_role(pool, "epigraph_maintenance", move |mut conn| async move {
        let r = sqlx::query(sql)
            .bind(a)
            .bind(b)
            .execute(&mut *conn)
            .await
            .map(|_| ());
        (conn, r)
    })
    .await
}

/// `epigraph-operator link`, as the maintenance role runs it.
async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    as_maintenance(
        pool,
        "SELECT * FROM public.epigraph_link_operator($1, $2)",
        agent,
        operator,
    )
    .await
    .unwrap_or_else(|e| panic!("link {agent} to {operator}: {e}"));
}

async fn arm(pool: &PgPool) {
    let armed: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
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

/// A `team` group whose creator `admin` is its admin (harness, standing in for
/// the maintenance session that provisions a role group).
async fn team_group(pool: &PgPool, admin: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let public_key = blake3::hash(id.as_bytes()).as_bytes().to_vec();
    GroupRepository::create_with_admin(
        pool,
        id,
        Some("workflow-plan team group"),
        &format!("did:epigraph:test:workflow-plan:{id}"),
        &public_key,
        None,
        admin,
    )
    .await
    .expect("the team group");
    id
}

async fn add_member(pool: &PgPool, g: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(g)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("the {role} row: {e}"));
}

/// The number of texts a stdio server's embedder was asked to embed.
type EmbedCalls = std::sync::Arc<std::sync::atomic::AtomicUsize>;

fn embed_calls(calls: &EmbedCalls) -> usize {
    calls.load(std::sync::atomic::Ordering::SeqCst)
}

/// An app-role stdio MCP server whose own agent is keyed by `seed`, as a
/// container's `epigraph-mcp` is. Its embedder stores through the production
/// author-stamped path, but its provider is a counting generator
/// (`McpEmbedder::with_generator`): every text it is asked to embed is
/// counted, and a fixed 1536-dimension vector is returned, so a test can tell
/// "no text reached the provider" from "every claim was embedded".
async fn mcp_server(
    pool: &PgPool,
    seed: u8,
) -> (epigraph_mcp::server::EpiGraphMcpFull, EmbedCalls) {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let calls: EmbedCalls = std::sync::Arc::default();
    let counter = calls.clone();
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(move |_text: &str| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![0.5_f32; 1536])
        }));
    let server = epigraph_mcp::server::EpiGraphMcpFull::new(plain, signer, embedder, false)
        .with_scoped_pool(scoped);
    (server, calls)
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

/// MCP `ingest_workflow` on the stdio transport, as the server's own agent.
async fn stdio_ingest(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    params: epigraph_mcp::types::IngestWorkflowParams,
) -> Result<Value, String> {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .map_err(|e| e.message.to_string())?;
    let out = epigraph_mcp::tools::workflow_ingest::ingest_workflow(server, &viewer, params, None)
        .await
        .map_err(|e| e.message.to_string())?;
    Ok(tool_json(&out))
}

/// MCP `ingest_workflow` on the stdio transport, expected to be refused: the
/// error itself, so a test can pin its code and not only its message.
async fn stdio_ingest_refused(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    params: epigraph_mcp::types::IngestWorkflowParams,
) -> rmcp::model::ErrorData {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("the stdio viewer");
    match epigraph_mcp::tools::workflow_ingest::ingest_workflow(server, &viewer, params, None).await
    {
        Ok(out) => panic!("expected a refusal, got {out:?}"),
        Err(e) => e,
    }
}

/// MCP `ingest_workflow` on the authenticated transport, as `agent`.
async fn http_mcp_ingest(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    agent: Uuid,
    params: epigraph_mcp::types::IngestWorkflowParams,
) -> Result<Value, String> {
    let auth = epigraph_auth::AuthContext {
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
    };
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, Some(&auth))
        .await
        .map_err(|e| e.message.to_string())?;
    let out =
        epigraph_mcp::tools::workflow_ingest::ingest_workflow(server, &viewer, params, Some(&auth))
            .await
            .map_err(|e| e.message.to_string())?;
    Ok(tool_json(&out))
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

/// The armed world: human `h` (operator group `og`), the registered system
/// agent live-linked to `h`, a curator `c` and a fleet agent `f` (both stdio
/// servers, both linked to `h`), and a team group `g` that `h` administers and
/// the system agent and `c` write. `f` is NOT a member of `g`. A second human
/// `h2` (group `og2`) writes neither `og` nor `g`.
struct World {
    api: Api,
    h: Uuid,
    og: Uuid,
    h2: Uuid,
    og2: Uuid,
    system: Uuid,
    g: Uuid,
    c: Uuid,
    c_server: epigraph_mcp::server::EpiGraphMcpFull,
    /// Texts `c_server`'s embedder was asked to embed.
    c_embeds: EmbedCalls,
    f: Uuid,
    f_server: epigraph_mcp::server::EpiGraphMcpFull,
}

async fn world(pool: &PgPool) -> World {
    let (h, og) = fixture::seed_human_operator(pool, "workflow-plan-holder").await;
    let (h2, og2) = fixture::seed_human_operator(pool, "workflow-plan-other").await;
    let system = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    assert!(fixture::register_system_agent(pool, system).await);
    let api = Api::prod_shaped(pool).await;
    // History first, as on a live instance: the system agent ingested (and so
    // was provisioned its personal group) before it was linked.
    let (history, _) = fixture::seed_agent_with_group(pool, "workflow-plan-history").await;
    api.ingest_ok(
        &token(history, WRITE_SCOPES),
        &extraction("acme-tenancy-history", 0, &[&[]]),
    )
    .await;
    link(pool, system, h).await;
    let (c_server, c_embeds) = mcp_server(pool, 0xC1).await;
    let c = stdio_agent(pool, &c_server, 0xC1).await;
    link(pool, c, h).await;
    let (f_server, _) = mcp_server(pool, 0xF1).await;
    let f = stdio_agent(pool, &f_server, 0xF1).await;
    link(pool, f, h).await;
    let g = team_group(pool, h).await;
    add_member(pool, g, system, "writer").await;
    add_member(pool, g, c, "writer").await;
    arm(pool).await;
    World {
        api,
        h,
        og,
        h2,
        og2,
        system,
        g,
        c,
        c_server,
        c_embeds,
        f,
        f_server,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Where a declared ingest lands
// ─────────────────────────────────────────────────────────────────────────────

/// The human publishes over REST into its operator group (the fallback
/// ownership). Every new claim and every `executes` edge is `('group', og)`;
/// the row-security `WITH CHECK` on the system-agent stamp passed for every
/// one of them, on the application role. A non-member reads no edge and no
/// claim; the post-commit embeds and the operation atoms' BBAs still land.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_ingest_lands_every_claim_and_executes_edge_in_the_group(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-tenancy-fallback";
    let out = w
        .api
        .ingest_ok(
            &token(w.h, WRITE_SCOPES),
            &declared(
                extraction(
                    name,
                    0,
                    &[
                        &["acme fallback operation one"],
                        &["acme fallback operation two"],
                    ],
                ),
                w.og,
                None,
            ),
        )
        .await;
    let wf = uuid_of(&out["workflow_id"]);
    let plan = plan_tenancy(&pool, wf).await;
    assert_eq!(
        plan.len(),
        5,
        "the phase, two steps and two atoms (no thesis is declared): {plan:?}"
    );
    assert!(
        plan.iter().all(|(_, v, o)| v == "group" && *o == w.og),
        "every planned claim is ('group', og): {plan:?}"
    );
    let edges = executes_tenancy(&pool, wf).await;
    assert_eq!(edges.len(), plan.len());
    assert!(
        edges.iter().all(|(v, o)| v == "group" && *o == w.og),
        "every executes edge is ('group', og): {edges:?}"
    );
    assert_eq!(reused(&out).len(), 0, "a fresh plan reuses nothing: {out}");

    // Private in fact: the second human reads no edge and no claim.
    let stranger = token(w.h2, READ_SCOPES);
    let (s, b) = w
        .api
        .get(
            &format!("/api/v1/edges?source_id={wf}&relationship=executes"),
            &stranger,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        b.as_array().map(Vec::len),
        Some(0),
        "a non-member reads no edge: {b}"
    );
    for (id, _, _) in &plan {
        let (s, b) = w.api.get(&format!("/api/v1/claims/{id}"), &stranger).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "a non-member reads no claim: {b}");
    }
    let (s, b) = w
        .api
        .get(
            &format!("/api/v1/edges?source_id={wf}&relationship=executes"),
            &token(w.h, READ_SCOPES),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(
        b.as_array().map(Vec::len),
        Some(plan.len()),
        "the member reads every edge: {b}"
    );

    // The best-effort post-commit work did not silently fail on the group rows.
    let unembedded: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = ANY($1) AND embedding IS NULL")
            .bind(plan.iter().map(|p| p.0).collect::<Vec<_>>())
            .fetch_one(&pool)
            .await
            .expect("embedding count");
    assert_eq!(unembedded, 0, "every new group claim carries an embedding");
    let goal_embedded: bool =
        sqlx::query_scalar("SELECT goal_embedding IS NOT NULL FROM workflows WHERE id = $1")
            .bind(wf)
            .fetch_one(&pool)
            .await
            .expect("goal embedding");
    assert!(goal_embedded, "the workflow's goal is embedded");
}

/// A curator that itself writes the team group publishes into it over stdio.
/// The operation atoms' BBAs land in the same group (the DS wiring runs on
/// the system-agent stamp, which writes it).
#[sqlx::test(migrations = "../../migrations")]
async fn a_curator_that_writes_the_team_group_publishes_into_it_over_stdio(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-tenancy-curator";
    let out = stdio_ingest(
        &w.c_server,
        mcp_params(
            extraction(name, 0, &[&["acme curator operation"]]),
            Some(w.g),
        ),
    )
    .await
    .expect("the curator publishes into the team group");
    let wf = uuid_of(&out["workflow_id"]);
    let plan = plan_tenancy(&pool, wf).await;
    assert_eq!(plan.len(), 3, "the phase, the step and the atom: {plan:?}");
    assert!(
        plan.iter().all(|(_, v, o)| v == "group" && *o == w.g),
        "every planned claim is ('group', g): {plan:?}"
    );
    assert!(
        executes_tenancy(&pool, wf)
            .await
            .iter()
            .all(|(v, o)| v == "group" && *o == w.g),
        "every executes edge is ('group', g)"
    );
    assert_eq!(reused(&out).len(), 0, "{out}");
    let atom_bbas: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions m JOIN claims c ON c.id = m.claim_id \
          WHERE c.content = 'acme curator operation' AND m.owner_group_id = $1",
    )
    .bind(w.g)
    .fetch_one(&pool)
    .await
    .expect("atom BBA count");
    assert!(
        atom_bbas >= 1,
        "the operation atom's BBA landed in the group"
    );
    let _ = (w.system, w.c);
}

// ─────────────────────────────────────────────────────────────────────────────
// Who may declare a group
// ─────────────────────────────────────────────────────────────────────────────

/// A fleet agent linked to the group's writer, but not itself a member, is
/// refused on stdio and writes nothing: the check is on the calling agent's own
/// memberships, never its human's. Over HTTP it is refused as an operated
/// agent before the check is reached (a guard; see the module doc). Under the
/// operator-group fallback the same agent IS admitted, because its link gave it
/// a writer row in the operator group: the residual of the fallback, pinned.
#[sqlx::test(migrations = "../../migrations")]
async fn a_fleet_agent_operated_by_a_group_writer_is_refused_unless_it_is_a_member(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-tenancy-fleet";
    let before = row_counts(&pool).await;
    let refused = stdio_ingest(
        &w.f_server,
        mcp_params(extraction(name, 0, &[&[]]), Some(w.g)),
    )
    .await
    .expect_err("a non-member fleet agent must not declare the team group");
    assert!(
        refused.contains(&w.f.to_string()) && refused.contains(&w.g.to_string()),
        "the refusal names the caller and the group: {refused}"
    );
    assert_eq!(workflows_named(&pool, name).await, 0, "no workflow row");
    assert_eq!(claims_mentioning(&pool, name).await, 0, "no claim");

    // HTTP, both transports: an operated agent has no HTTP authority at all.
    let (s, b) = w
        .api
        .ingest(
            &token(w.f, WRITE_SCOPES),
            &declared(extraction(name, 0, &[&[]]), w.g, None),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    assert!(
        b.to_string().contains("operated agents are stdio-only"),
        "{b}"
    );
    let refused = http_mcp_ingest(
        &w.f_server,
        w.f,
        mcp_params(extraction(name, 0, &[&[]]), Some(w.g)),
    )
    .await
    .expect_err("an operated agent over HTTP MCP");
    assert!(
        refused.contains("operated agents are stdio-only"),
        "{refused}"
    );
    assert_eq!(workflows_named(&pool, name).await, 0);
    assert_eq!(
        row_counts(&pool).await,
        before,
        "the three refusals wrote no claim, edge, workflow or BBA"
    );

    // The fallback residual: the operator group admits every agent of `h`.
    let fallback = "acme-tenancy-fleet-fallback";
    let out = stdio_ingest(
        &w.f_server,
        mcp_params(extraction(fallback, 0, &[&[]]), Some(w.og)),
    )
    .await
    .expect("an agent linked to h writes og, so it may declare og");
    let wf = uuid_of(&out["workflow_id"]);
    assert!(
        plan_tenancy(&pool, wf)
            .await
            .iter()
            .all(|(_, v, o)| v == "group" && *o == w.og),
        "the fleet agent's plan landed in og"
    );
}

/// The human, over REST and over MCP-HTTP, naming a group it does not write
/// (another human's group, and a team group where it holds only a reader row)
/// is refused with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_is_refused_for_a_group_it_does_not_write(pool: PgPool) {
    let w = world(&pool).await;
    let read_only = team_group(&pool, w.h2).await;
    add_member(&pool, read_only, w.h, "reader").await;
    for (name, group) in [
        ("acme-tenancy-foreign", w.og2),
        ("acme-tenancy-reader", read_only),
    ] {
        let before = row_counts(&pool).await;
        let (s, b) = w
            .api
            .ingest(
                &token(w.h, WRITE_SCOPES),
                &declared(
                    extraction(name, 0, &[&["acme refused operation"]]),
                    group,
                    None,
                ),
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{name}: {b}");
        // Refused as the CALLER's refusal (it names the caller), not only by
        // the system agent's check that would follow it.
        assert!(
            b.to_string().contains(&group.to_string()) && b.to_string().contains(&w.h.to_string()),
            "{name}: names the group and the caller: {b}"
        );
        assert_eq!(
            workflows_named(&pool, name).await,
            0,
            "{name}: no workflow row"
        );
        assert_eq!(claims_mentioning(&pool, name).await, 0, "{name}: no claim");

        let refused = http_mcp_ingest(
            &w.c_server,
            w.h,
            mcp_params(extraction(name, 0, &[&[]]), Some(group)),
        )
        .await
        .expect_err("MCP-HTTP: refused too");
        assert!(
            refused.contains(&group.to_string()) && refused.contains(&w.h.to_string()),
            "{name}: names the group and the caller: {refused}"
        );
        assert_eq!(
            workflows_named(&pool, name).await,
            0,
            "{name}: no workflow row"
        );
        assert_eq!(
            row_counts(&pool).await,
            before,
            "{name}: neither refusal wrote a claim (the operation atom included), an edge, a \
             workflow or a BBA"
        );
    }
}

/// A group the caller writes but the ingest system agent does not: refused
/// before any row is written, naming the system agent, rather than failing on
/// the first INSERT. On REST (the human) and on stdio (the curator, a writer
/// of the group, which the MCP transport maps to its own refusal arm).
#[sqlx::test(migrations = "../../migrations")]
async fn the_ingest_system_agent_must_write_the_declared_group(pool: PgPool) {
    let w = world(&pool).await;
    let unprovisioned = team_group(&pool, w.h).await;
    add_member(&pool, unprovisioned, w.c, "writer").await;
    let name = "acme-tenancy-unprovisioned";
    let before = row_counts(&pool).await;
    let (s, b) = w
        .api
        .ingest(
            &token(w.h, WRITE_SCOPES),
            &declared(extraction(name, 0, &[&[]]), unprovisioned, None),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    assert!(
        b.to_string().contains(&w.system.to_string()),
        "the refusal names the system agent: {b}"
    );
    assert_eq!(workflows_named(&pool, name).await, 0, "no workflow row");
    assert_eq!(claims_mentioning(&pool, name).await, 0, "no claim");

    let refused = stdio_ingest_refused(
        &w.c_server,
        mcp_params(
            extraction(name, 0, &[&["acme unprovisioned operation"]]),
            Some(unprovisioned),
        ),
    )
    .await;
    assert_eq!(
        refused.code,
        rmcp::model::ErrorCode::INVALID_REQUEST,
        "a denial, not an internal error: {refused:?}"
    );
    let refused = refused.message.to_string();
    assert!(
        refused.contains(&w.system.to_string()) && refused.contains(&unprovisioned.to_string()),
        "the stdio refusal names the system agent and the group: {refused}"
    );
    assert!(
        !refused.contains(&w.c.to_string()),
        "refused by the system-agent check, not as the caller: {refused}"
    );
    assert_eq!(
        row_counts(&pool).await,
        before,
        "neither refusal wrote a claim, an edge, a workflow or a BBA"
    );
}

/// Only `visibility: "group"` is a declaration; anything else is refused and
/// writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_tenancy_other_than_group_is_refused(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-tenancy-public-declared";
    let mut body = extraction(name, 0, &[&[]]);
    body["tenancy"] = json!({"visibility": "public", "owner_group_id": w.og});
    let before = row_counts(&pool).await;
    let (s, b) = w.api.ingest(&token(w.h, WRITE_SCOPES), &body).await;
    assert!(
        s.is_client_error(),
        "refused as the caller's error: {s} {b}"
    );
    assert_eq!(workflows_named(&pool, name).await, 0, "no workflow row");
    assert_eq!(row_counts(&pool).await, before, "nothing written");
}

// ─────────────────────────────────────────────────────────────────────────────
// reused_items
// ─────────────────────────────────────────────────────────────────────────────

/// A public generation 0, then a declared generation 1 of the same name: the
/// steps it keeps and the operation atom it shares are the claims generation 0
/// wrote, still public. Each is listed in `reused_items` with its tenancy, and
/// none is re-tenanted; every claim generation 1 created is `('group', og)`.
#[sqlx::test(migrations = "../../migrations")]
async fn reused_items_lists_every_reused_claim_whose_tenancy_differs(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-tenancy-reuse";
    let h = token(w.h, WRITE_SCOPES);
    let gen0 = w
        .api
        .ingest_ok(&h, &extraction(name, 0, &[&["acme shared operation"], &[]]))
        .await;
    assert!(
        gen0.get("reused_items").is_none(),
        "no tenancy, no reused_items: {gen0}"
    );
    let gen0_plan = plan_ids(&pool, uuid_of(&gen0["workflow_id"])).await;

    let mut gen1_body = extraction(
        name,
        1,
        &[&["acme shared operation"], &[], &["acme new operation"]],
    );
    gen1_body["source"]["parent_canonical_name"] = json!(name);
    let gen1 = w.api.ingest_ok(&h, &declared(gen1_body, w.og, None)).await;
    let gen1_wf = uuid_of(&gen1["workflow_id"]);
    let gen1_plan = plan_tenancy(&pool, gen1_wf).await;

    let carried: BTreeSet<Uuid> = gen1_plan
        .iter()
        .map(|p| p.0)
        .filter(|id| gen0_plan.contains(id))
        .collect();
    assert_eq!(
        carried.len(),
        4,
        "generation 1 carries the phase, both steps and the shared atom: {carried:?}"
    );
    let listed = reused(&gen1);
    assert_eq!(
        listed.keys().copied().collect::<BTreeSet<_>>(),
        carried,
        "reused_items is exactly the carried claims: {gen1}"
    );
    for (id, (vis, owner)) in &listed {
        assert_eq!(vis, &json!("public"), "{id}: {gen1}");
        assert_eq!(owner, &json!(w.og), "{id}: {gen1}");
    }
    for (id, v, o) in &gen1_plan {
        if carried.contains(id) {
            assert_eq!(
                (v.as_str(), *o),
                ("public", w.og),
                "{id} is not re-tenanted"
            );
        } else {
            assert_eq!(
                (v.as_str(), *o),
                ("group", w.og),
                "{id} is new, so it is in the group"
            );
        }
    }
}

/// A declared generation 1 that carries claims from a declared generation 0
/// of the SAME group reuses them, and lists none: their tenancy is the
/// declared one. A re-ingest of that generation lists none either.
#[sqlx::test(migrations = "../../migrations")]
async fn reused_items_omits_reused_claims_already_in_the_declared_group(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-tenancy-same-group";
    let h = token(w.h, WRITE_SCOPES);
    let gen0 = w
        .api
        .ingest_ok(
            &h,
            &declared(
                extraction(name, 0, &[&["acme same-group operation"], &[]]),
                w.og,
                None,
            ),
        )
        .await;
    assert_eq!(reused(&gen0).len(), 0, "{gen0}");
    let mut gen1_body = extraction(name, 1, &[&["acme same-group operation"], &[], &[]]);
    gen1_body["source"]["parent_canonical_name"] = json!(name);
    let gen1_body = declared(gen1_body, w.og, None);
    let gen1 = w.api.ingest_ok(&h, &gen1_body).await;
    assert_eq!(
        gen1["claims_skipped_dedup"],
        json!(4),
        "the phase, two steps and the atom are reused: {gen1}"
    );
    assert_eq!(
        reused(&gen1).len(),
        0,
        "all of them are already ('group', og): {gen1}"
    );
    let again = w.api.ingest_ok(&h, &gen1_body).await;
    assert_eq!(again["already_ingested"], json!(true), "{again}");
    assert_eq!(reused(&again).len(), 0, "{again}");
}

/// A fresh declared ingest whose plan reuses a claim private to a group the
/// CALLER does not write is refused before any edge is written, even when the
/// ingest's own system-agent stamp writes that group: the `executes` and
/// `decomposes_to` edges to it would be owned by that group, written on the
/// system agent's stamp on behalf of a caller with no membership of it. The
/// refusal never names the group. Here the fleet agent `f` (not a member of
/// the team group `g`) declares `og`, and its plan names an operation atom
/// private to `g`, which the system agent writes. Calibrated by the curator
/// `c`, a member of `g`, which may link the same atom and is told its tenancy.
///
/// A re-ingest writes nothing, so it is not refused: there a reused claim the
/// caller cannot read is listed with a null tenancy, and again the response
/// never names its group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reused_claim_private_to_a_group_the_caller_does_not_write_refuses_the_ingest(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let owner = extraction("acme-hidden-atom-owner", 0, &[&["acme hidden operation"]]);
    let seeded = stdio_ingest(&w.c_server, mcp_params(owner.clone(), Some(w.g)))
        .await
        .expect("the curator seeds a g-private atom");
    let seeded_plan = plan_tenancy(&pool, uuid_of(&seeded["workflow_id"])).await;
    let atom: Uuid = sqlx::query_scalar(
        "SELECT c.id FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
            AND c.content = 'acme hidden operation'",
    )
    .bind(uuid_of(&seeded["workflow_id"]))
    .fetch_one(&pool)
    .await
    .expect("the atom");

    let name = "acme-hidden-atom-user";
    let before = row_counts(&pool).await;
    let refused = stdio_ingest(
        &w.f_server,
        mcp_params(
            extraction(name, 0, &[&["acme hidden operation"]]),
            Some(w.og),
        ),
    )
    .await
    .expect_err("f may not link an atom private to a group it does not write");
    assert!(
        refused.contains(&atom.to_string())
            && refused.contains("private to a group the calling agent does not write"),
        "refused by the reused-claim check, naming the claim: {refused}"
    );
    assert!(
        !refused.contains(&w.g.to_string()),
        "the refusal never names g to a non-member: {refused}"
    );
    assert_eq!(workflows_named(&pool, name).await, 0, "no workflow row");
    assert_eq!(
        row_counts(&pool).await,
        before,
        "the refusal wrote no claim, edge, workflow or BBA"
    );

    // A re-ingest of the owner's generation by f: nothing is written, so it
    // is answered, and every g-private claim is listed without its tenancy.
    let again = stdio_ingest(&w.f_server, mcp_params(owner, Some(w.og)))
        .await
        .expect("a re-ingest writes nothing, so it is not refused");
    assert_eq!(again["already_ingested"], json!(true), "{again}");
    let listed = reused(&again);
    assert_eq!(
        listed.keys().copied().collect::<BTreeSet<_>>(),
        seeded_plan.iter().map(|p| p.0).collect::<BTreeSet<_>>(),
        "every planned claim is listed: {again}"
    );
    assert!(
        listed.values().all(|t| t == &(Value::Null, Value::Null)),
        "listed without the tenancy f cannot read: {again}"
    );
    assert!(
        !again.to_string().contains(&w.g.to_string()),
        "the response never names g to a non-member: {again}"
    );
    assert_eq!(
        row_counts(&pool).await,
        before,
        "the re-ingest wrote nothing"
    );

    // Calibration: c writes g, so it may link the same atom from og.
    let out = stdio_ingest(
        &w.c_server,
        mcp_params(
            extraction("acme-hidden-atom-member", 0, &[&["acme hidden operation"]]),
            Some(w.og),
        ),
    )
    .await
    .expect("c declares og; the same atom is reused");
    assert_eq!(
        reused(&out).get(&atom),
        Some(&(json!("group"), json!(w.g))),
        "a member of g is told the atom's tenancy: {out}"
    );
}

/// Re-ingesting an existing public `(name, generation)` with a declared
/// tenancy changes nothing: `already_ingested`, every planned claim listed as
/// public, no claim re-tenanted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_re_ingest_lists_every_claim_and_re_tenants_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-tenancy-reingest";
    let h = token(w.h, WRITE_SCOPES);
    let body = extraction(name, 0, &[&["acme reingest operation"], &[]]);
    let first = w.api.ingest_ok(&h, &body).await;
    let wf = uuid_of(&first["workflow_id"]);
    let before = plan_tenancy(&pool, wf).await;

    let again = w.api.ingest_ok(&h, &declared(body, w.og, None)).await;
    assert_eq!(again["already_ingested"], json!(true), "{again}");
    let listed = reused(&again);
    assert_eq!(
        listed.keys().copied().collect::<BTreeSet<_>>(),
        before.iter().map(|p| p.0).collect::<BTreeSet<_>>(),
        "every planned claim is listed: {again}"
    );
    assert!(
        listed.values().all(|(v, _)| v == &json!("public")),
        "{again}"
    );
    assert_eq!(plan_tenancy(&pool, wf).await, before, "nothing re-tenanted");
}

// ─────────────────────────────────────────────────────────────────────────────
// Unchanged behaviour, and embed
// ─────────────────────────────────────────────────────────────────────────────

/// Without `tenancy` an ingest is what it was: public, owned by the system
/// agent's default group, and the response has no `reused_items` key, on both
/// transports.
#[sqlx::test(migrations = "../../migrations")]
async fn without_tenancy_the_ingest_is_public_and_reports_no_reused_items(pool: PgPool) {
    let w = world(&pool).await;
    let out = w
        .api
        .ingest_ok(
            &token(w.h, WRITE_SCOPES),
            &extraction("acme-tenancy-absent", 0, &[&["acme absent operation"]]),
        )
        .await;
    assert!(out.get("reused_items").is_none(), "{out}");
    let plan = plan_tenancy(&pool, uuid_of(&out["workflow_id"])).await;
    assert!(
        plan.iter().all(|(_, v, o)| v == "public" && *o == w.og),
        "{plan:?}"
    );
    let out = stdio_ingest(
        &w.c_server,
        mcp_params(extraction("acme-tenancy-absent-mcp", 0, &[&[]]), None),
    )
    .await
    .expect("stdio, no tenancy");
    assert!(out.get("reused_items").is_none(), "{out}");
    assert!(plan_tenancy(&pool, uuid_of(&out["workflow_id"]))
        .await
        .iter()
        .all(|(_, v, o)| v == "public" && *o == w.og));
}

/// `embed: false` makes no embedding call and writes no claim or goal
/// embedding, with and without a declared tenancy. Calibrated by the default
/// (`embed` absent), which calls the provider and embeds every claim on the
/// same mock-embedder API. The call count is the provider's token usage.
#[sqlx::test(migrations = "../../migrations")]
async fn embed_false_writes_no_embedding(pool: PgPool) {
    let w = world(&pool).await;
    let h = token(w.h, WRITE_SCOPES);
    let provider_tokens = |api: &Api| api.embedder.token_usage().total_tokens;
    w.api.embedder.reset_token_usage();
    let calibration = w
        .api
        .ingest_ok(
            &h,
            &declared(
                extraction("acme-embed-default", 0, &[&["acme embed default op"]]),
                w.og,
                None,
            ),
        )
        .await;
    let (all, embedded, goal) = embedding_state(&pool, &calibration).await;
    assert!(
        all == 3 && embedded == all && goal,
        "calibration embeds: {all} {embedded} {goal}"
    );
    assert!(
        provider_tokens(&w.api) > 0,
        "the calibration called the provider"
    );

    w.api.embedder.reset_token_usage();
    let declared_off = w
        .api
        .ingest_ok(
            &h,
            &declared(
                extraction("acme-embed-off", 0, &[&["acme embed off op"]]),
                w.og,
                Some(false),
            ),
        )
        .await;
    let (all, embedded, goal) = embedding_state(&pool, &declared_off).await;
    assert_eq!(all, 3, "the phase, the step and the atom");
    assert_eq!(
        (embedded, goal),
        (0, false),
        "embed:false with tenancy embeds nothing"
    );
    assert_eq!(
        provider_tokens(&w.api),
        0,
        "embed:false with tenancy calls no provider"
    );

    w.api.embedder.reset_token_usage();
    let mut public_off = extraction("acme-embed-off-public", 0, &[&["acme embed off public op"]]);
    public_off["embed"] = json!(false);
    let public_off = w.api.ingest_ok(&h, &public_off).await;
    let (all, embedded, goal) = embedding_state(&pool, &public_off).await;
    assert_eq!(all, 3, "the phase, the step and the atom");
    assert_eq!(
        (embedded, goal),
        (0, false),
        "embed:false without tenancy embeds nothing"
    );
    assert_eq!(
        provider_tokens(&w.api),
        0,
        "embed:false without tenancy calls no provider"
    );
}

/// The stdio MCP transport, which is the curator's (an operated agent has no
/// HTTP authority): with `embed` absent every claim the call created and the
/// workflow goal are embedded, ONE provider call each, and a DECLARED group's
/// claims are stored too (through their known author: the embedder's
/// public-reader store path cannot resolve a group-private claim's author).
/// `embed: false` makes no provider call at all and stores no vector, with and
/// without a declared tenancy. The call count is the counting generator's.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_ingest_embeds_every_created_claim_unless_embed_is_false(pool: PgPool) {
    let w = world(&pool).await;
    for (name, group) in [
        ("acme-stdio-embed-declared", Some(w.g)),
        ("acme-stdio-embed-public", None),
    ] {
        let label = if group.is_some() {
            "declared"
        } else {
            "public"
        };
        let start = embed_calls(&w.c_embeds);
        let on = stdio_ingest(
            &w.c_server,
            mcp_params(extraction(name, 0, &[&[&format!("{name} op")]]), group),
        )
        .await
        .unwrap_or_else(|e| panic!("{label}: embed absent: {e}"));
        let (all, embedded, goal) = embedding_state(&pool, &on).await;
        assert_eq!(all, 3, "{label}: the phase, the step and the atom");
        assert_eq!(
            (embedded, goal),
            (3, true),
            "{label}: embed absent stores every claim vector and the goal's"
        );
        assert_eq!(
            embed_calls(&w.c_embeds) - start,
            4,
            "{label}: one provider call per created claim, and one for the goal"
        );
        if let Some(g) = group {
            assert!(
                plan_tenancy(&pool, uuid_of(&on["workflow_id"]))
                    .await
                    .iter()
                    .all(|(_, v, o)| v == "group" && *o == g),
                "the embedded claims are the group-private ones"
            );
        }

        let off_name = format!("{name}-off");
        let start = embed_calls(&w.c_embeds);
        let off = stdio_ingest(
            &w.c_server,
            mcp_params_embed(
                extraction(&off_name, 0, &[&[&format!("{off_name} op")]]),
                group,
                Some(false),
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("{label}: embed false: {e}"));
        let (all, embedded, goal) = embedding_state(&pool, &off).await;
        assert_eq!(all, 3, "{label}: embed:false still writes the plan");
        assert_eq!(
            (embedded, goal),
            (0, false),
            "{label}: embed:false stores no vector"
        );
        assert_eq!(
            embed_calls(&w.c_embeds) - start,
            0,
            "{label}: embed:false sends no text to the provider"
        );
    }
}

/// MCP over HTTP: the human (not an operated agent, so it has HTTP authority)
/// declares its operator group through the authenticated transport. The plan
/// lands `('group', og)`, and the response carries `reused_items`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_declares_its_operator_group_over_mcp_http(pool: PgPool) {
    let w = world(&pool).await;
    let out = http_mcp_ingest(
        &w.c_server,
        w.h,
        mcp_params(
            extraction("acme-tenancy-mcp-http", 0, &[&["acme mcp http operation"]]),
            Some(w.og),
        ),
    )
    .await
    .expect("the human declares og over MCP-HTTP");
    let plan = plan_tenancy(&pool, uuid_of(&out["workflow_id"])).await;
    assert_eq!(plan.len(), 3, "the phase, the step and the atom: {plan:?}");
    assert!(
        plan.iter().all(|(_, v, o)| v == "group" && *o == w.og),
        "every planned claim is ('group', og): {plan:?}"
    );
    assert!(
        executes_tenancy(&pool, uuid_of(&out["workflow_id"]))
            .await
            .iter()
            .all(|(v, o)| v == "group" && *o == w.og),
        "every executes edge is ('group', og)"
    );
    assert_eq!(
        reused(&out).len(),
        0,
        "present, and empty for a fresh plan: {out}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Characterization: an operation atom already private to another group
// ─────────────────────────────────────────────────────────────────────────────

/// Operation atoms are keyed by their text alone, across every workflow and
/// document. When the atom a plan names already exists as a claim private to
/// a group neither the caller nor the ingest system agent writes, the whole
/// declared ingest is refused with a 403 (the reused-claim check; the stamp
/// cannot even read the atom) and writes nothing, rather than failing on the
/// `executes` edge's `WITH CHECK`. The refusal does not name that group.
/// (Availability: a publisher cannot use that operation text until the atom is
/// public or in a group it writes.)
#[sqlx::test(migrations = "../../migrations")]
async fn an_atom_private_to_another_group_refuses_the_whole_ingest(pool: PgPool) {
    let w = world(&pool).await;
    let h = token(w.h, WRITE_SCOPES);
    let seeded = w
        .api
        .ingest_ok(
            &h,
            &extraction("acme-atom-owner", 0, &[&["acme contested operation"]]),
        )
        .await;
    let atom: Uuid = sqlx::query_scalar(
        "SELECT c.id FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
            AND c.content = 'acme contested operation'",
    )
    .bind(uuid_of(&seeded["workflow_id"]))
    .fetch_one(&pool)
    .await
    .expect("the atom");
    let mut conn = pool.acquire().await.expect("acquire");
    PrivatizationRepository::restrict_claims_conn(&mut conn, &[atom], w.og2)
        .await
        .expect("restrict the atom to another human's group");
    drop(conn);

    let name = "acme-atom-contender";
    let before = row_counts(&pool).await;
    let (s, b) = w
        .api
        .ingest(
            &h,
            &declared(
                extraction(name, 0, &[&["acme contested operation"]]),
                w.og,
                None,
            ),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "refused as a denial: {b}");
    assert!(
        b.to_string().contains(&atom.to_string())
            && b.to_string()
                .contains("private to a group the calling agent does not write"),
        "refused by the reused-claim check: {b}"
    );
    assert!(
        !b.to_string().contains(&w.og2.to_string()),
        "the refusal never names the other group: {b}"
    );
    assert_eq!(workflows_named(&pool, name).await, 0, "no workflow row");
    assert_eq!(claims_mentioning(&pool, name).await, 0, "no claim");
    assert!(workflow_id_named(&pool, name, 0).await.is_none());
    assert_eq!(row_counts(&pool).await, before, "nothing written");
}

// ─────────────────────────────────────────────────────────────────────────────
// What a re-ingest reports
// ─────────────────────────────────────────────────────────────────────────────

/// The `executes` edges of `workflow_id` the harness (superuser) counts: the
/// true size of the plan.
async fn executes_count(pool: &PgPool, workflow_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND source_type = 'workflow' \
            AND relationship = 'executes'",
    )
    .bind(workflow_id)
    .fetch_one(pool)
    .await
    .expect("count executes edges")
}

/// `out` without the keys that name the request itself (`workflow_id`,
/// `canonical_name`) or list the caller's own planned ids (`reused_items`):
/// what is left is the part of the answer that could describe the plan.
fn plan_answer(out: &Value) -> Value {
    let mut out = out.clone();
    let obj = out.as_object_mut().expect("a JSON object");
    for key in ["workflow_id", "canonical_name", "reused_items"] {
        obj.remove(key);
    }
    out
}

/// A re-ingest of an existing `(canonical_name, generation)` is answered with
/// `already_ingested: true` and the existing plan's `executes` count. That
/// count is the CALLER's view of the plan, never the ingest stamp's: the
/// system agent writes (and so reads) every group it serves, so a count read
/// on its stamp would tell a non-member how many private steps a group's
/// workflow has. A non-member re-ingesting two group-private workflows of
/// different sizes, declared or not, gets the same answer for both; a member
/// gets each plan's true size; a public plan's size is everyone's. Runs on the
/// application role with FORCE row security on `claims` and `edges`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_re_ingest_reports_only_the_plan_the_caller_can_read(pool: PgPool) {
    let w = world(&pool).await;
    for table in ["claims", "edges"] {
        let (enabled, forced): (bool, bool) = sqlx::query_as(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
              WHERE oid = ('public.' || $1)::regclass",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("read row-security flags");
        assert!(
            enabled && forced,
            "{table}: row security must be enabled and FORCEd, or every arm here is vacuous"
        );
    }

    let small = extraction("acme-plan-size-small", 0, &[&[], &[]]);
    let large = extraction("acme-plan-size-large", 0, &[&[], &[], &[], &[], &[]]);
    let mut true_sizes = Vec::new();
    for body in [&small, &large] {
        let out = stdio_ingest(&w.c_server, mcp_params(body.clone(), Some(w.g)))
            .await
            .expect("the curator publishes a g-private workflow");
        let wf = uuid_of(&out["workflow_id"]);
        assert!(
            plan_tenancy(&pool, wf)
                .await
                .iter()
                .all(|(_, v, o)| v == "group" && *o == w.g),
            "the seeded plan is g-private"
        );
        true_sizes.push(executes_count(&pool, wf).await);
    }
    assert_ne!(
        true_sizes[0], true_sizes[1],
        "premise: the two private plans differ in size"
    );

    let before = row_counts(&pool).await;

    // f writes og but is not a member of g: undeclared, and declared into og.
    for declared_group in [None, Some(w.og)] {
        let mut answers = Vec::new();
        for body in [&small, &large] {
            let out = stdio_ingest(&w.f_server, mcp_params(body.clone(), declared_group))
                .await
                .expect("a re-ingest writes nothing, so it is answered");
            assert_eq!(out["already_ingested"], json!(true), "{out}");
            answers.push(plan_answer(&out));
        }
        assert_eq!(
            answers[0], answers[1],
            "a non-member's answer must not depend on the private plan's size \
             (declared {declared_group:?}): {answers:?}"
        );
        assert_eq!(
            answers[0]["executes_edges"],
            json!(0),
            "a non-member reads none of the private plan's executes edges: {answers:?}"
        );
    }

    // c is a member of g: each plan's true size.
    for (body, size) in [&small, &large].into_iter().zip(&true_sizes) {
        let out = stdio_ingest(&w.c_server, mcp_params(body.clone(), Some(w.g)))
            .await
            .expect("the member's re-ingest");
        assert_eq!(out["already_ingested"], json!(true), "{out}");
        assert_eq!(
            out["executes_edges"],
            json!(size),
            "a member is told the plan's true size: {out}"
        );
    }

    assert_eq!(
        row_counts(&pool).await,
        before,
        "no re-ingest wrote anything"
    );

    // Calibration: a public plan's size is everyone's, f's included.
    let public = extraction("acme-plan-size-public", 0, &[&[], &[], &[]]);
    let seeded = w.api.ingest_ok(&token(w.h, WRITE_SCOPES), &public).await;
    let public_size = executes_count(&pool, uuid_of(&seeded["workflow_id"])).await;
    let before_public = row_counts(&pool).await;
    let out = stdio_ingest(&w.f_server, mcp_params(public, None))
        .await
        .expect("f re-ingests the public plan");
    assert_eq!(out["already_ingested"], json!(true), "{out}");
    assert_eq!(
        out["executes_edges"],
        json!(public_size),
        "a public plan's size is unchanged for any caller: {out}"
    );
    assert_eq!(
        row_counts(&pool).await,
        before_public,
        "the public re-ingest wrote nothing"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Backlog c0ab097a (2), ruling R-74: a workflow row has the plan's tenancy
// ─────────────────────────────────────────────────────────────────────────────

/// `(use_count, number of behavioral_executions rows)` of `workflow_id`.
async fn outcome_written(pool: &PgPool, workflow_id: Uuid) -> (Option<i64>, i64) {
    let use_count: Option<i64> =
        sqlx::query_scalar("SELECT (metadata->>'use_count')::bigint FROM workflows WHERE id = $1")
            .bind(workflow_id)
            .fetch_one(pool)
            .await
            .expect("metadata");
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM behavioral_executions WHERE workflow_id = $1")
            .bind(workflow_id)
            .fetch_one(pool)
            .await
            .expect("row count");
    (use_count, rows)
}

/// A public generation 0 (`W1`) and a generation 1 (`W2`) declared into the
/// operator group `og`, where W2 keeps W1's step 0 text and adds a step of its
/// own: W2's plan has a public step (the one it shares with W1, through a
/// public `executes` edge) and a group-private one. The fixture-shape
/// assertions pin that mixed plan.
async fn reused_step_generations(w: &World, pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let h = token(w.h, WRITE_SCOPES);
    let gen0 = w
        .api
        .ingest_ok(&h, &extraction(name, 0, &[&["acme reused-step op"]]))
        .await;
    let w1 = uuid_of(&gen0["workflow_id"]);
    let mut gen1_body = extraction(name, 1, &[&["acme reused-step op"], &["acme private op"]]);
    gen1_body["source"]["parent_canonical_name"] = json!(name);
    let gen1 = w.api.ingest_ok(&h, &declared(gen1_body, w.og, None)).await;
    let w2 = uuid_of(&gen1["workflow_id"]);

    let shared_steps: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT c.id, c.visibility::text, e2.visibility::text \
           FROM edges e1 JOIN edges e2 ON e2.target_id = e1.target_id \
           JOIN claims c ON c.id = e1.target_id \
          WHERE e1.source_id = $1 AND e2.source_id = $2 \
            AND e1.relationship = 'executes' AND e2.relationship = 'executes' \
            AND (c.properties->>'level')::int = 2",
    )
    .bind(w1)
    .bind(w2)
    .fetch_all(pool)
    .await
    .expect("shared steps");
    assert_eq!(
        shared_steps.len(),
        1,
        "fixture shape: W1 and W2 share step 0: {shared_steps:?}"
    );
    assert_eq!(
        (shared_steps[0].1.as_str(), shared_steps[0].2.as_str()),
        ("public", "public"),
        "fixture shape: the shared step and W2's executes edge to it are public: {shared_steps:?}"
    );
    let own_private: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
            AND (c.properties->>'level')::int = 2 \
            AND c.visibility::text = 'group' AND c.owner_group_id = $2",
    )
    .bind(w2)
    .bind(w.og)
    .fetch_one(pool)
    .await
    .expect("W2's own steps");
    assert_eq!(
        own_private, 1,
        "fixture shape: W2's new step is group-private"
    );
    (w1, w2)
}

/// The outcome-report body the REST tests send.
fn outcome_body() -> Value {
    json!({"success": true, "outcome_details": "probe", "step_executions": []})
}

/// Ruling R-74: the outcome-report gate decides on the PLAN's tenancy. A
/// caller outside the group that W2 was declared into is refused with the
/// unknown-id 404 and nothing is written, whatever of W2's plan it reads. The
/// group's member reports on W2, and the non-member still reports on the
/// public W1.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_step_reused_by_a_private_generation_does_not_admit_a_non_member(pool: PgPool) {
    let w = world(&pool).await;
    let (w1, w2) = reused_step_generations(&w, &pool, "acme-reused-step-report").await;
    let stranger = token(w.h2, WRITE_SCOPES);
    let uri = |id: Uuid| format!("/api/v1/workflows/hierarchical/{id}/outcome");

    let (status, out) = w
        .api
        .call(Method::POST, &uri(w2), &stranger, Some(&outcome_body()))
        .await;
    let (unknown_status, unknown_out) = w
        .api
        .call(
            Method::POST,
            &uri(Uuid::nil()),
            &stranger,
            Some(&outcome_body()),
        )
        .await;
    assert_eq!(
        (status, outcome_written(&pool, w2).await),
        (StatusCode::NOT_FOUND, (None, 0)),
        "a non-member of W2's group is refused and nothing is written: {out}"
    );
    assert_eq!(unknown_status, StatusCode::NOT_FOUND, "{unknown_out}");
    assert_eq!(
        out.to_string().replace(&w2.to_string(), "<id>"),
        unknown_out
            .to_string()
            .replace(&Uuid::nil().to_string(), "<id>"),
        "the refusal is the unknown-id answer"
    );

    let (status, out) = w
        .api
        .call(
            Method::POST,
            &uri(w2),
            &token(w.h, WRITE_SCOPES),
            Some(&outcome_body()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the group's member reports: {out}");
    assert_eq!(outcome_written(&pool, w2).await, (Some(1), 0));

    let (status, out) = w
        .api
        .call(Method::POST, &uri(w1), &stranger, Some(&outcome_body()))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a public plan stays reportable: {out}"
    );
    assert_eq!(outcome_written(&pool, w1).await, (Some(1), 0));
}

/// Both MCP entry points (`report_hierarchical_outcome` and
/// `report_workflow_outcome`'s hierarchical branch), as `agent`, on
/// `workflow_id`. Each call's result as `Ok(())` or `Err(message)`.
async fn mcp_reports(
    w: &World,
    pool: &PgPool,
    agent: Uuid,
    workflow_id: Uuid,
) -> Vec<Result<(), String>> {
    let viewer = epigraph_db::Viewer::resolve(pool, agent)
        .await
        .expect("viewer");
    let direct = epigraph_mcp::tools::workflow_hierarchical::report_hierarchical_outcome(
        &w.c_server,
        &viewer,
        epigraph_mcp::types::ReportHierarchicalOutcomeParams {
            workflow_id: workflow_id.to_string(),
            success: true,
            step_executions: Vec::new(),
            outcome_details: "probe".to_string(),
            quality: Some(0.9),
            run_label: None,
            goal_text: None,
        },
    )
    .await;
    let delegated = epigraph_mcp::tools::workflows::report_workflow_outcome(
        &w.c_server,
        &viewer,
        epigraph_mcp::types::ReportWorkflowOutcomeParams {
            workflow_id: workflow_id.to_string(),
            success: true,
            execution_log: Vec::new(),
            outcome_details: "probe".to_string(),
            quality: Some(0.9),
            goal_text: None,
        },
        None,
    )
    .await;
    [direct, delegated]
        .into_iter()
        .map(|r| {
            r.map(|out| assert_ne!(out.is_error, Some(true), "{out:?}"))
                .map_err(|e| e.message.replace(&workflow_id.to_string(), "<id>"))
        })
        .collect()
}

/// The MCP twin of
/// [`a_public_step_reused_by_a_private_generation_does_not_admit_a_non_member`]:
/// both MCP outcome tools refuse the non-member on W2 exactly as they refuse
/// an unknown id, and write nothing; the member's reports and the
/// non-member's reports on the public W1 are recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn over_mcp_a_public_step_reused_by_a_private_generation_does_not_admit_a_non_member(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let (w1, w2) = reused_step_generations(&w, &pool, "acme-reused-step-mcp").await;

    let refused = mcp_reports(&w, &pool, w.h2, w2).await;
    let unknown = mcp_reports(&w, &pool, w.h2, Uuid::new_v4()).await;
    assert!(
        refused.iter().all(Result::is_err),
        "a non-member of W2's group is refused on both tools: {refused:?}"
    );
    assert_eq!(
        refused, unknown,
        "each tool answers W2 exactly as it answers an unknown id"
    );
    assert_eq!(
        outcome_written(&pool, w2).await,
        (None, 0),
        "a refused report writes nothing"
    );

    let member = mcp_reports(&w, &pool, w.h, w2).await;
    assert!(
        member.iter().all(Result::is_ok),
        "the member reports: {member:?}"
    );
    assert_eq!(outcome_written(&pool, w2).await, (Some(2), 0));

    let public = mcp_reports(&w, &pool, w.h2, w1).await;
    assert!(
        public.iter().all(Result::is_ok),
        "a public plan stays reportable: {public:?}"
    );
    assert_eq!(outcome_written(&pool, w1).await, (Some(2), 0));
}

/// Ruling R-74: the `workflows` row of a declared generation is the group's.
/// `GET /api/v1/workflows/:id` answers a non-member exactly as an unknown id
/// (the typed 404), and the hierarchical search lists it for no non-member;
/// the member reads both, and the public generation stays readable to anyone.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_generations_workflow_row_is_hidden_from_a_non_member(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-hidden-row";
    let (w1, w2) = reused_step_generations(&w, &pool, name).await;
    let stranger = token(w.h2, READ_SCOPES);
    let member = token(w.h, READ_SCOPES);

    let (status, out) = w
        .api
        .get(&format!("/api/v1/workflows/{w2}"), &stranger)
        .await;
    let (unknown_status, unknown) = w
        .api
        .get(&format!("/api/v1/workflows/{}", Uuid::nil()), &stranger)
        .await;
    assert_eq!(
        (status, unknown_status),
        (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND),
        "the non-member gets the unknown-id answer: {out}"
    );
    assert_eq!(
        out.to_string().replace(&w2.to_string(), "<id>"),
        unknown
            .to_string()
            .replace(&Uuid::nil().to_string(), "<id>"),
        "the same typed body as an unknown id"
    );
    let (status, out) = w.api.get(&format!("/api/v1/workflows/{w2}"), &member).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["workflow_id"], json!(w2), "{out}");
    let (status, out) = w
        .api
        .get(&format!("/api/v1/workflows/{w1}"), &stranger)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the public row stays readable: {out}"
    );
    assert_eq!(out["canonical_name"], json!(name), "{out}");

    let ids = |out: &Value| -> BTreeSet<Uuid> {
        out["workflows"]
            .as_array()
            .unwrap_or_else(|| panic!("a workflows array: {out}"))
            .iter()
            .map(|r| uuid_of(&r["workflow_id"]))
            .collect()
    };
    let search = format!("/api/v1/workflows/hierarchical/search?q={name}&limit=50&min_truth=0");
    let (status, out) = w.api.get(&search, &stranger).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(
        ids(&out),
        BTreeSet::from([w1]),
        "a non-member's search lists the public generation only: {out}"
    );
    let (status, out) = w.api.get(&search, &member).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(ids(&out), BTreeSet::from([w1, w2]), "{out}");
}

/// Guard: a non-member cannot extend a lineage whose head is a generation
/// declared into a group it does not read, by ingesting the next generation or
/// by `add_step` on the lineage's name. Both decide on the head's authority on
/// the ingest system agent's stamp, which reads the group, so the hidden head
/// is the row checked; nothing is written. (It holds before and after
/// migration 183: the change must not move the check to an older, public
/// generation.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_cannot_extend_a_lineage_whose_head_is_private(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-private-head";
    let (_w1, _w2) = reused_step_generations(&w, &pool, name).await;
    let stranger = token(w.h2, WRITE_SCOPES);
    let before = row_counts(&pool).await;

    let mut gen2 = extraction(name, 2, &[&["acme next-generation op"]]);
    gen2["source"]["parent_canonical_name"] = json!(name);
    let (status, out) = w.api.ingest(&stranger, &gen2).await;
    assert!(
        status.is_client_error(),
        "the next generation of a private head is refused: {status} {out}"
    );
    assert_eq!(row_counts(&pool).await, before, "the refusal wrote nothing");
    assert_eq!(workflows_named(&pool, name).await, 2, "no generation 2");

    let (status, out) = w
        .api
        .call(
            Method::POST,
            "/api/v1/workflows/steps",
            &stranger,
            Some(&json!({"canonical_name": name, "step_text": "acme appended step"})),
        )
        .await;
    assert!(
        status.is_client_error(),
        "add_step on a private head is refused: {status} {out}"
    );
    assert_eq!(row_counts(&pool).await, before, "the refusal wrote nothing");
}
