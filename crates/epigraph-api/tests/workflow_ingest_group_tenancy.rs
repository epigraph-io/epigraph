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
    reused_step_generations_into(w, pool, name, w.og).await
}

/// [`reused_step_generations`] with W2 declared into `group` (a group `h`
/// writes: its operator group `og`, or the team group `g`).
async fn reused_step_generations_into(
    w: &World,
    pool: &PgPool,
    name: &str,
    group: Uuid,
) -> (Uuid, Uuid) {
    let h = token(w.h, WRITE_SCOPES);
    let gen0 = w
        .api
        .ingest_ok(&h, &extraction(name, 0, &[&["acme reused-step op"]]))
        .await;
    let w1 = uuid_of(&gen0["workflow_id"]);
    let mut gen1_body = extraction(name, 1, &[&["acme reused-step op"], &["acme private op"]]);
    gen1_body["source"]["parent_canonical_name"] = json!(name);
    let gen1 = w.api.ingest_ok(&h, &declared(gen1_body, group, None)).await;
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
    .bind(group)
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
/// is the row checked; nothing is written. The caller holds workflow authority
/// over the older, public W1 (it is recorded as W1's submitter), so a check
/// that moved to W1 would admit it: the refusal is the head's. (It holds
/// before and after migration 183.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_cannot_extend_a_lineage_whose_head_is_private(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-private-head";
    let (w1, _w2) = reused_step_generations(&w, &pool, name).await;
    set_submitter(&pool, w1, w.h2).await;
    let stranger = token(w.h2, WRITE_SCOPES);
    let before = row_counts(&pool).await;

    let mut gen2 = extraction(name, 2, &[&["acme next-generation op"]]);
    gen2["source"]["parent_canonical_name"] = json!(name);
    let (status, out) = w.api.ingest(&stranger, &gen2).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the next generation of a private head is refused: {out}"
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
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "add_step on a private head is refused: {out}"
    );
    assert_eq!(row_counts(&pool).await, before, "the refusal wrote nothing");
}

/// The MCP twin of the search half of
/// [`a_declared_generations_workflow_row_is_hidden_from_a_non_member`]:
/// `find_workflow_hierarchical` reads as its caller, so the non-member finds
/// the public generation only and the member finds both. The goal embeddings
/// are cleared first so both callers take the same (text) path; the stamp
/// applies to the embedding path identically.
#[sqlx::test(migrations = "../../migrations")]
async fn over_mcp_a_declared_generation_is_found_only_by_its_group(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-hidden-mcp-search";
    let (w1, w2) = reused_step_generations(&w, &pool, name).await;
    sqlx::query("UPDATE workflows SET goal_embedding = NULL")
        .execute(&pool)
        .await
        .expect("clear goal embeddings");
    let found = |agent: Uuid| {
        let pool = pool.clone();
        let server = &w.c_server;
        async move {
            let viewer = epigraph_db::Viewer::resolve(&pool, agent)
                .await
                .expect("viewer");
            let out = epigraph_mcp::tools::workflow_hierarchical::find_workflow_hierarchical(
                server,
                &viewer,
                epigraph_mcp::types::FindWorkflowHierarchicalParams {
                    query: name.to_string(),
                    limit: Some(50),
                    resolve_to_latest: None,
                    min_truth: Some(0.0),
                },
            )
            .await
            .expect("the search runs");
            let body = tool_json(&out);
            body["workflows"]
                .as_array()
                .unwrap_or_else(|| panic!("a workflows array: {body}"))
                .iter()
                .map(|r| uuid_of(&r["workflow_id"]))
                .filter(|id| *id == w1 || *id == w2)
                .collect::<BTreeSet<Uuid>>()
        }
    };
    assert_eq!(
        found(w.h2).await,
        BTreeSet::from([w1]),
        "a non-member finds the public generation only"
    );
    assert_eq!(found(w.h).await, BTreeSet::from([w1, w2]));
}

/// CHARACTERIZATION (operator question, R-74 residual): a member improves a
/// lineage whose only generation is declared into its group. The new
/// generation is numbered past the group's head (`new_generation` 1, read on
/// the ingest system agent's stamp, which reads the group), and the call
/// succeeds; the new generation is NOT declared into the group, so its row is
/// public, as before migration 183. Whether a new generation should inherit
/// its head's group (as a superseding claim does) is the open question.
#[sqlx::test(migrations = "../../migrations")]
async fn characterization_improving_a_group_lineage_numbers_past_its_head(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-improve-group-head";
    stdio_ingest(
        &w.c_server,
        mcp_params(extraction(name, 0, &[&["acme improve op"]]), Some(w.g)),
    )
    .await
    .expect("the curator declares generation 0 into the team group");
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&w.c_server, None)
        .await
        .expect("the stdio viewer");
    let params: epigraph_mcp::types::ImproveWorkflowHierarchyParams =
        serde_json::from_value(json!({
            "parent_canonical_name": name,
            "extraction": extraction(name, 0, &[&["acme improve op"], &["acme improved op"]]),
        }))
        .expect("the tool's parameters");
    let out = epigraph_mcp::tools::workflow_ingest::improve_workflow_hierarchy(
        &w.c_server,
        &viewer,
        params,
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("the improvement is accepted: {}", e.message));
    let body = tool_json(&out);
    assert_eq!(body["new_generation"], json!(1), "{body}");
    let tenancy: Vec<(i32, String)> = sqlx::query_as(
        "SELECT generation, visibility::text FROM workflows \
          WHERE canonical_name = $1 ORDER BY generation",
    )
    .bind(name)
    .fetch_all(&pool)
    .await
    .expect("lineage rows");
    assert_eq!(
        tenancy,
        vec![(0, "group".to_string()), (1, "public".to_string())],
        "CHARACTERIZATION: the new generation is public (operator question)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// R-74: every reader of a declared generation's row decides on the row
// ─────────────────────────────────────────────────────────────────────────────

/// The authenticated-transport `AuthContext` of `agent`, as the MCP HTTP
/// transport builds it from a bearer token.
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

/// The level-2 step W1 and W2 both execute (`reused_step_generations`).
async fn shared_step(pool: &PgPool, w1: Uuid, w2: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT e1.target_id FROM edges e1 \
           JOIN edges e2 ON e2.target_id = e1.target_id \
           JOIN claims c ON c.id = e1.target_id \
          WHERE e1.source_id = $1 AND e2.source_id = $2 \
            AND e1.relationship = 'executes' AND e2.relationship = 'executes' \
            AND (c.properties->>'level')::int = 2",
    )
    .bind(w1)
    .bind(w2)
    .fetch_one(pool)
    .await
    .expect("the shared step")
}

async fn claim_owner(pool: &PgPool, claim: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim owner")
}

async fn claim_is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("is_current")
}

async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count claims")
}

async fn workflow_truth(pool: &PgPool, wf: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value::float8 FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(pool)
        .await
        .expect("workflow truth")
}

/// A writer row of `agent` in `g`, unless it already holds one (harness).
async fn ensure_writer(pool: &PgPool, g: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer') ON CONFLICT DO NOTHING",
    )
    .bind(g)
    .bind(agent)
    .execute(pool)
    .await
    .expect("the writer row");
}

/// The 1536-dimension vector the stdio servers' generator returns for every
/// text (`mcp_server`): a goal embedding equal to it is the closest possible
/// match for any query, so the embedding legs run deterministically.
fn generator_pgvec() -> String {
    format!("[{}]", vec!["0.5"; 1536].join(","))
}

async fn seed_goal_embeddings(pool: &PgPool, ids: &[Uuid]) {
    sqlx::query("UPDATE workflows SET goal_embedding = $1::vector WHERE id = ANY($2)")
        .bind(generator_pgvec())
        .bind(ids)
        .execute(pool)
        .await
        .expect("seed goal embeddings");
}

/// An app-role MCP server whose embedder is KEYED (`is_mock()` is false, so
/// the embedding search paths run) and generates through the same fixed
/// vector as [`mcp_server`]: no request leaves the process.
async fn keyed_search_server(pool: &PgPool) -> epigraph_mcp::server::EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x5E; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), Some("test-key".into()))
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(vec![0.5_f32; 1536])));
    epigraph_mcp::server::EpiGraphMcpFull::new(plain, signer, embedder, false)
        .with_scoped_pool(scoped)
}

/// `ids` restricted to W1 and W2.
fn of_pair(ids: impl IntoIterator<Item = Uuid>, w1: Uuid, w2: Uuid) -> BTreeSet<Uuid> {
    ids.into_iter()
        .filter(|id| *id == w1 || *id == w2)
        .collect()
}

/// The resolver plan route (`GET /api/v1/workflows/:id/plan`) answers a
/// non-member of W2's group exactly as an unknown id: the typed 404 whose
/// `details.entity` is `workflow plan` (the body the host's plan probe keys
/// on), and nothing of the plan. Before migration 183 the non-member read W2's
/// public row and its public executes edge, and got a 200 partial plan with
/// W2's goal. The member reads both steps; the public W1 stays readable.
#[sqlx::test(migrations = "../../migrations")]
async fn the_plan_route_answers_a_non_member_of_a_declared_generation_as_an_unknown_id(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let name = "acme-hidden-plan";
    let (w1, w2) = reused_step_generations(&w, &pool, name).await;
    let step = shared_step(&pool, w1, w2).await;
    let stranger = token(w.h2, READ_SCOPES);

    let (status, out) = w
        .api
        .get(&format!("/api/v1/workflows/{w2}/plan"), &stranger)
        .await;
    let (unknown_status, unknown) = w
        .api
        .get(
            &format!("/api/v1/workflows/{}/plan", Uuid::nil()),
            &stranger,
        )
        .await;
    assert_eq!(
        (status, unknown_status),
        (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND),
        "the non-member gets the plan route's unknown-id answer: {out}"
    );
    assert_eq!(
        out.to_string().replace(&w2.to_string(), "<id>"),
        unknown
            .to_string()
            .replace(&Uuid::nil().to_string(), "<id>"),
        "the same typed body as an unknown id"
    );
    assert_eq!(out["error"], json!("NotFound"), "{out}");
    assert_eq!(out["details"]["entity"], json!("workflow plan"), "{out}");
    let text = out.to_string();
    assert!(
        !text.contains("workflow-plan goal") && !text.contains(&step.to_string()),
        "no goal text and no claim id in the refusal: {text}"
    );

    let (status, out) = w
        .api
        .get(
            &format!("/api/v1/workflows/{w2}/plan"),
            &token(w.h, READ_SCOPES),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the member reads W2's plan: {out}");
    let steps = out["items"]
        .as_array()
        .unwrap_or_else(|| panic!("an items array: {out}"))
        .iter()
        .filter(|i| i["level"] == json!(2))
        .count();
    assert_eq!(steps, 2, "the member reads both of W2's steps: {out}");

    let (status, out) = w
        .api
        .get(&format!("/api/v1/workflows/{w1}/plan"), &stranger)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the public plan stays readable: {out}"
    );
    assert_eq!(out["workflow_id"], json!(w1), "{out}");
}

/// MCP `get_workflow_plan`, as `agent`, on `workflow_id`: the plan, or the
/// error message with the id replaced by `<id>`.
async fn mcp_plan(
    w: &World,
    pool: &PgPool,
    agent: Uuid,
    workflow_id: Uuid,
) -> Result<Value, String> {
    let viewer = epigraph_db::Viewer::resolve(pool, agent)
        .await
        .expect("viewer");
    let params: epigraph_mcp::types::GetWorkflowPlanParams =
        serde_json::from_value(json!({"workflow_id": workflow_id.to_string()}))
            .expect("the tool's parameters");
    epigraph_mcp::tools::workflow_plan::get_workflow_plan(&w.c_server, &viewer, params)
        .await
        .map(|out| tool_json(&out))
        .map_err(|e| e.message.replace(&workflow_id.to_string(), "<id>"))
}

/// The MCP twin of
/// [`the_plan_route_answers_a_non_member_of_a_declared_generation_as_an_unknown_id`].
#[sqlx::test(migrations = "../../migrations")]
async fn over_mcp_the_plan_of_a_declared_generation_is_its_groups_alone(pool: PgPool) {
    let w = world(&pool).await;
    let (w1, w2) = reused_step_generations(&w, &pool, "acme-hidden-plan-mcp").await;

    let refused = mcp_plan(&w, &pool, w.h2, w2).await;
    let unknown = mcp_plan(&w, &pool, w.h2, Uuid::new_v4()).await;
    assert!(
        refused.is_err(),
        "the non-member is refused W2's plan: {refused:?}"
    );
    assert_eq!(refused, unknown, "the refusal is the unknown-id answer");

    let member = mcp_plan(&w, &pool, w.h, w2)
        .await
        .expect("the member reads W2's plan");
    assert_eq!(member["workflow_id"], json!(w2), "{member}");
    let public = mcp_plan(&w, &pool, w.h2, w1)
        .await
        .expect("the public plan stays readable");
    assert_eq!(public["workflow_id"], json!(w1), "{public}");
}

/// MCP `find_workflow` (the flat + hierarchical union) as `agent`: the
/// workflow ids it returns.
async fn mcp_find_workflow(w: &World, pool: &PgPool, agent: Uuid, goal: &str) -> Vec<Uuid> {
    let viewer = epigraph_db::Viewer::resolve(pool, agent)
        .await
        .expect("viewer");
    let params: epigraph_mcp::types::FindWorkflowParams =
        serde_json::from_value(json!({"goal": goal, "min_truth": 0.0, "limit": 50}))
            .expect("the tool's parameters");
    let out = epigraph_mcp::tools::workflows::find_workflow(&w.c_server, &viewer, params)
        .await
        .expect("find_workflow runs");
    tool_json(&out)
        .as_array()
        .unwrap_or_else(|| panic!("a result array"))
        .iter()
        .map(|r| uuid_of(&r["workflow_id"]))
        .collect()
}

/// MCP `find_workflow`'s hierarchical legs read `workflows` rows as the
/// caller: the non-member finds the public W1 only, the member finds W1 and
/// W2. The goal embeddings equal the query's, so the embedding leg is the one
/// that matches. (Before migration 183 every caller found W2; between 183 and
/// the caller-stamped read the member lost it.)
#[sqlx::test(migrations = "../../migrations")]
async fn over_mcp_find_workflow_finds_a_declared_generation_only_for_its_group(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-hidden-find";
    let (w1, w2) = reused_step_generations(&w, &pool, name).await;
    seed_goal_embeddings(&pool, &[w1, w2]).await;

    assert_eq!(
        of_pair(mcp_find_workflow(&w, &pool, w.h2, name).await, w1, w2),
        BTreeSet::from([w1]),
        "a non-member finds the public generation only"
    );
    assert_eq!(
        of_pair(mcp_find_workflow(&w, &pool, w.h, name).await, w1, w2),
        BTreeSet::from([w1, w2]),
        "the member finds its group's generation"
    );
}

/// MCP `recall` with `include_workflows`: the workflows leg reads rows as the
/// caller. The non-member recalls the public W1 only; the member recalls both.
#[sqlx::test(migrations = "../../migrations")]
async fn over_mcp_recall_includes_a_declared_generation_only_for_its_group(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-hidden-recall";
    let (w1, w2) = reused_step_generations(&w, &pool, name).await;
    seed_goal_embeddings(&pool, &[w1, w2]).await;
    let recalled = |agent: Uuid| {
        let pool = pool.clone();
        let server = &w.c_server;
        async move {
            let viewer = epigraph_db::Viewer::resolve(&pool, agent)
                .await
                .expect("viewer");
            let params: epigraph_mcp::types::RecallParams = serde_json::from_value(json!({
                "query": name, "include_workflows": true, "min_truth": 0.0, "limit": 50
            }))
            .expect("the tool's parameters");
            let out = epigraph_mcp::tools::memory::recall(server, &viewer, params)
                .await
                .expect("recall runs");
            let body = tool_json(&out);
            let ids: Vec<Uuid> = body["results"]
                .as_array()
                .unwrap_or_else(|| panic!("a results array: {body}"))
                .iter()
                .filter(|r| r["result_type"] == json!("workflow"))
                .map(|r| uuid_of(&r["claim_id"]))
                .collect();
            ids
        }
    };
    assert_eq!(
        of_pair(recalled(w.h2).await, w1, w2),
        BTreeSet::from([w1]),
        "a non-member recalls the public generation only"
    );
    assert_eq!(
        of_pair(recalled(w.h).await, w1, w2),
        BTreeSet::from([w1, w2]),
        "the member recalls its group's generation"
    );
}

/// MCP `verify_claim` on a workflow step whose stored digest is scoped by its
/// workflow's `canonical_name` recovers that name from the executing
/// `workflows` row, read as the caller. The step here is PUBLIC (add_step
/// writes a public step into a group plan, an R-74 residual) and executed only
/// by the group row W2: the member's check matches; a non-member, who cannot
/// read W2, gets `hash_matches: null` (not applicable), never a verdict
/// computed from a row it cannot read.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_claim_seeds_a_step_digest_only_from_rows_the_caller_reads(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-hidden-verify";
    let (_w1, w2) = reused_step_generations(&w, &pool, name).await;
    let step_text = "acme appended public step";
    let (status, out) = w
        .api
        .call(
            Method::POST,
            "/api/v1/workflows/steps",
            &token(w.h, WRITE_SCOPES),
            Some(&json!({"canonical_name": name, "step_text": step_text})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the submitter appends a step: {out}"
    );
    let step: Uuid = sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(step_text)
        .fetch_one(&pool)
        .await
        .expect("the appended step");
    let executors: Vec<Uuid> = sqlx::query_scalar(
        "SELECT source_id FROM edges WHERE target_id = $1 AND relationship = 'executes'",
    )
    .bind(step)
    .fetch_all(&pool)
    .await
    .expect("executors");
    assert_eq!(
        executors,
        vec![w2],
        "fixture shape: only W2 executes the step"
    );
    let visibility: String =
        sqlx::query_scalar("SELECT visibility::text FROM claims WHERE id = $1")
            .bind(step)
            .fetch_one(&pool)
            .await
            .expect("step visibility");
    assert_eq!(
        visibility, "public",
        "fixture shape: the appended step is public"
    );

    let verify = |agent: Uuid| {
        let pool = pool.clone();
        let server = &w.c_server;
        async move {
            let viewer = epigraph_db::Viewer::resolve(&pool, agent)
                .await
                .expect("viewer");
            let params: epigraph_mcp::types::VerifyClaimParams =
                serde_json::from_value(json!({"claim_id": step.to_string()}))
                    .expect("the tool's parameters");
            let out = epigraph_mcp::tools::claims::verify_claim(server, &viewer, params)
                .await
                .expect("verify_claim runs");
            tool_json(&out)["hash_matches"].clone()
        }
    };
    assert_eq!(
        verify(w.h2).await,
        Value::Null,
        "a non-member's check is not applicable: it cannot read the executing row"
    );
    assert_eq!(
        verify(w.h).await,
        json!(true),
        "the member's check recovers the name from W2 and matches"
    );
}

/// `find_workflow_hierarchical` on the EMBEDDING path (the goal embeddings
/// equal the query's) and with `resolve_to_latest`: a non-member finds W1
/// only, and W1's lineage resolves to W1, never to the hidden head W2; the
/// member finds both.
#[sqlx::test(migrations = "../../migrations")]
async fn over_mcp_the_hierarchical_embedding_path_finds_a_declared_generation_only_for_its_group(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let name = "acme-hidden-embedding";
    let (w1, w2) = reused_step_generations(&w, &pool, name).await;
    seed_goal_embeddings(&pool, &[w1, w2]).await;
    let keyed = keyed_search_server(&pool).await;
    let found = |agent: Uuid, resolve_to_latest: bool| {
        let pool = pool.clone();
        let server = &keyed;
        async move {
            let viewer = epigraph_db::Viewer::resolve(&pool, agent)
                .await
                .expect("viewer");
            let out = epigraph_mcp::tools::workflow_hierarchical::find_workflow_hierarchical(
                server,
                &viewer,
                epigraph_mcp::types::FindWorkflowHierarchicalParams {
                    query: name.to_string(),
                    limit: Some(50),
                    resolve_to_latest: Some(resolve_to_latest),
                    min_truth: Some(0.0),
                },
            )
            .await
            .expect("the search runs");
            let body = tool_json(&out);
            assert_eq!(body["search_path"], json!("embedding"), "{body}");
            let ids: Vec<Uuid> = body["workflows"]
                .as_array()
                .unwrap_or_else(|| panic!("a workflows array: {body}"))
                .iter()
                .map(|r| uuid_of(&r["workflow_id"]))
                .collect();
            ids
        }
    };
    assert_eq!(
        of_pair(found(w.h2, false).await, w1, w2),
        BTreeSet::from([w1]),
        "a non-member finds the public generation only"
    );
    assert_eq!(
        of_pair(found(w.h2, true).await, w1, w2),
        BTreeSet::from([w1]),
        "resolving to the latest generation never surfaces the hidden head"
    );
    assert_eq!(
        of_pair(found(w.h, false).await, w1, w2),
        BTreeSet::from([w1, w2])
    );
}

/// `evolve_step`'s authority set is read from the `executes` edges, not from a
/// join to `workflows` (whose row security would drop a row the caller cannot
/// read). A caller who holds workflow authority over the public W1, and writes
/// the shared step's owning group, but does not read W2's group is refused
/// evolving the step W1 and W2 both execute, and nothing is written. A member
/// who holds authority over both evolves it.
#[sqlx::test(migrations = "../../migrations")]
async fn evolving_a_step_a_hidden_generation_executes_needs_authority_over_it(pool: PgPool) {
    let w = world(&pool).await;
    let (w1, w2) = reused_step_generations_into(&w, &pool, "acme-hidden-evolve", w.g).await;
    let step = shared_step(&pool, w1, w2).await;
    let owner = claim_owner(&pool, step).await;
    assert_ne!(
        owner, w.g,
        "premise: W2's group does not own the shared step"
    );
    // The caller writes the shared step's owning group (so row security admits
    // the evolve), but does not read W2's group.
    ensure_writer(&pool, owner, w.h2).await;
    set_submitter(&pool, w1, w.h2).await;
    let evolve = |agent: Uuid, content: &'static str| {
        let api = &w.api;
        async move {
            api.call(
                Method::POST,
                &format!("/api/v1/workflows/steps/{step}/evolve"),
                &token(agent, WRITE_SCOPES),
                Some(&json!({"parent_id": step, "content": content, "edge_type": "supersedes"})),
            )
            .await
        }
    };

    let before = row_counts(&pool).await;
    let refused = "acme hidden-evolve revision by a non-member";
    let (status, out) = evolve(w.h2, refused).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the hidden W2 stays in the authority set: {out}"
    );
    assert!(out.to_string().contains("Nothing was written"), "{out}");
    assert_eq!(row_counts(&pool).await, before, "the refusal wrote nothing");
    assert_eq!(claims_with_content(&pool, refused).await, 0);
    assert!(
        claim_is_current(&pool, step).await,
        "the step is not retired"
    );

    set_submitter(&pool, w1, w.h).await;
    let admitted = "acme hidden-evolve revision by the member";
    let (status, out) = evolve(w.h, admitted).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the member with authority over both evolves: {out}"
    );
    assert_eq!(claims_with_content(&pool, admitted).await, 1);
}

/// The MCP twin of
/// [`evolving_a_step_a_hidden_generation_executes_needs_authority_over_it`],
/// on the authenticated transport (the stdio transport checks no workflow
/// authority).
#[sqlx::test(migrations = "../../migrations")]
async fn over_mcp_evolving_a_step_a_hidden_generation_executes_needs_authority_over_it(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let (w1, w2) = reused_step_generations_into(&w, &pool, "acme-hidden-evolve-mcp", w.g).await;
    let step = shared_step(&pool, w1, w2).await;
    let owner = claim_owner(&pool, step).await;
    assert_ne!(
        owner, w.g,
        "premise: W2's group does not own the shared step"
    );
    // The caller writes the shared step's owning group (so row security admits
    // the evolve), but does not read W2's group.
    ensure_writer(&pool, owner, w.h2).await;
    set_submitter(&pool, w1, w.h2).await;
    let evolve = |agent: Uuid, content: &'static str| {
        let server = &w.c_server;
        async move {
            let auth = http_auth(agent);
            let viewer = epigraph_mcp::tools::viewer::request_viewer(server, Some(&auth))
                .await
                .map_err(|e| e.message.to_string())?;
            let params: epigraph_mcp::tools::evolve_step::EvolveStepParams =
                serde_json::from_value(json!({
                    "parent_id": step.to_string(), "content": content,
                    "edge_type": "supersedes"
                }))
                .expect("the tool's parameters");
            epigraph_mcp::tools::evolve_step::evolve_step(server, &viewer, params, Some(&auth))
                .await
                .map(|out| tool_json(&out))
                .map_err(|e| e.message.to_string())
        }
    };

    let before = row_counts(&pool).await;
    let refused = "acme hidden-evolve-mcp revision by a non-member";
    let err = evolve(w.h2, refused)
        .await
        .expect_err("the hidden W2 stays in the authority set");
    assert!(err.contains("Nothing was written"), "{err}");
    assert_eq!(row_counts(&pool).await, before, "the refusal wrote nothing");
    assert_eq!(claims_with_content(&pool, refused).await, 0);
    assert!(
        claim_is_current(&pool, step).await,
        "the step is not retired"
    );

    set_submitter(&pool, w1, w.h).await;
    let admitted = "acme hidden-evolve-mcp revision by the member";
    evolve(w.h, admitted)
        .await
        .unwrap_or_else(|e| panic!("the member with authority over both evolves: {e}"));
    assert_eq!(claims_with_content(&pool, admitted).await, 1);
}

/// A `('group', group)` workflows row for `(name, 0)`, as a plan declared into
/// a group the ingest system agent does not read leaves it (harness).
async fn seed_hidden_row(pool: &PgPool, name: &str, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, visibility, owner_group_id) \
         VALUES ($1, $2, 0, 'a goal another group holds', 'group', $3)",
    )
    .bind(id)
    .bind(name)
    .bind(group)
    .execute(pool)
    .await
    .expect("the hidden row");
    id
}

/// An ingest whose `(canonical_name, generation)` is already held by a
/// `workflows` row its stamp cannot read (a group the ingest system agent does
/// not read) is refused with a typed conflict on REST and on stdio MCP, before
/// any claim or edge is written, and the answer names neither the row nor its
/// group. A free name ingests as before.
#[sqlx::test(migrations = "../../migrations")]
async fn an_ingest_whose_name_is_held_by_a_row_it_cannot_read_is_refused(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-held-elsewhere";
    let hidden = seed_hidden_row(&pool, name, w.og2).await;
    let before = row_counts(&pool).await;

    let (status, out) = w
        .api
        .ingest(
            &token(w.h, WRITE_SCOPES),
            &extraction(name, 0, &[&["acme held op"]]),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{out}");
    let text = out.to_string();
    assert!(
        text.contains("not readable by this ingest") && text.contains("Nothing was written"),
        "{text}"
    );
    assert!(
        !text.contains(&hidden.to_string()) && !text.contains(&w.og2.to_string()),
        "the refusal names neither the row nor its group: {text}"
    );

    let refused = stdio_ingest_refused(
        &w.c_server,
        mcp_params(extraction(name, 0, &[&["acme held op"]]), None),
    )
    .await;
    assert_eq!(
        refused.code,
        rmcp::model::ErrorCode::INVALID_REQUEST,
        "{refused:?}"
    );
    assert!(
        refused.message.contains("not readable by this ingest"),
        "{refused:?}"
    );

    assert_eq!(row_counts(&pool).await, before, "nothing was written");
    assert_eq!(
        executes_count(&pool, hidden).await,
        0,
        "no edge under the row"
    );
    let tenancy: (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM workflows WHERE id = $1")
            .bind(hidden)
            .fetch_one(&pool)
            .await
            .expect("row tenancy");
    assert_eq!(
        tenancy,
        ("group".to_string(), w.og2),
        "the row is unchanged"
    );

    w.api
        .ingest_ok(
            &token(w.h, WRITE_SCOPES),
            &extraction("acme-held-elsewhere-free", 0, &[&["acme held op"]]),
        )
        .await;
}

/// MCP `deprecate_workflow` on the authenticated transport, as `agent`: the
/// response, or the error message.
async fn mcp_deprecate(
    w: &World,
    agent: Uuid,
    workflow_id: Uuid,
    cascade: bool,
) -> Result<Value, String> {
    let auth = http_auth(agent);
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&w.c_server, Some(&auth))
        .await
        .map_err(|e| e.message.to_string())?;
    let params: epigraph_mcp::types::DeprecateWorkflowParams = serde_json::from_value(json!({
        "workflow_id": workflow_id.to_string(), "reason": "probe", "cascade": cascade
    }))
    .expect("the tool's parameters");
    epigraph_mcp::tools::workflows::deprecate_workflow(&w.c_server, &viewer, params, Some(&auth))
        .await
        .map(|out| tool_json(&out))
        .map_err(|e| e.message.to_string())
}

/// MCP `deprecate_workflow` answers a non-member of W2's group exactly as an
/// unknown id and changes nothing; W2's submitter, a member, deprecates it.
#[sqlx::test(migrations = "../../migrations")]
async fn over_mcp_deprecating_a_declared_generation_is_its_groups_alone(pool: PgPool) {
    let w = world(&pool).await;
    let (w1, w2) = reused_step_generations(&w, &pool, "acme-hidden-deprecate").await;
    let (t1, t2) = (
        workflow_truth(&pool, w1).await,
        workflow_truth(&pool, w2).await,
    );

    let unknown_id = Uuid::new_v4();
    let refused = mcp_deprecate(&w, w.h2, w2, false)
        .await
        .map_err(|m| m.replace(&w2.to_string(), "<id>"));
    let unknown = mcp_deprecate(&w, w.h2, unknown_id, false)
        .await
        .map_err(|m| m.replace(&unknown_id.to_string(), "<id>"));
    assert!(refused.is_err(), "the non-member is refused: {refused:?}");
    assert_eq!(refused, unknown, "the refusal is the unknown-id answer");
    assert_eq!(workflow_truth(&pool, w2).await, t2, "W2 is unchanged");

    let out = mcp_deprecate(&w, w.h, w2, false)
        .await
        .unwrap_or_else(|e| panic!("W2's submitter deprecates it: {e}"));
    assert_eq!(out["deprecated_ids"], json!([w2.to_string()]), "{out}");
    assert!((workflow_truth(&pool, w2).await - 0.05).abs() < 1e-9);
    assert_eq!(workflow_truth(&pool, w1).await, t1, "W1 is untouched");
}

/// CHARACTERIZATION (operator question, R-74 residual): a cascading
/// deprecation walks the lineage on the ingest system agent's stamp, which
/// reads every group the system agent serves, not on the caller's.
///
/// Over the authenticated transport only a caller of the system agent's own
/// operator reaches the walk (any other is refused OPL02 first, writing
/// nothing), and each descendant then needs the caller's workflow authority.
/// On the stdio transport, which checks no workflow authority (the process
/// holds the DSN; not a trust boundary), a fleet agent of that operator that
/// does NOT read W2's group cascades W1's deprecation into W2: W2 is
/// deprecated and its id is reported to the agent.
#[sqlx::test(migrations = "../../migrations")]
async fn characterization_a_stdio_cascade_deprecates_a_descendant_the_agent_cannot_read(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let (w1, w2) = reused_step_generations_into(&w, &pool, "acme-hidden-cascade", w.g).await;
    let reads_g: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM group_memberships WHERE group_id = $1 AND agent_id = $2)",
    )
    .bind(w.g)
    .bind(w.f)
    .fetch_one(&pool)
    .await
    .expect("f's membership");
    assert!(
        !reads_g,
        "premise: the fleet agent is not a member of W2's group"
    );

    let viewer = epigraph_mcp::tools::viewer::request_viewer(&w.f_server, None)
        .await
        .expect("the stdio viewer");
    let params: epigraph_mcp::types::DeprecateWorkflowParams = serde_json::from_value(json!({
        "workflow_id": w1.to_string(), "reason": "probe", "cascade": true
    }))
    .expect("the tool's parameters");
    let out =
        epigraph_mcp::tools::workflows::deprecate_workflow(&w.f_server, &viewer, params, None)
            .await
            .unwrap_or_else(|e| panic!("the stdio cascade runs: {}", e.message));
    let body = tool_json(&out);
    assert_eq!(
        body["deprecated_ids"],
        json!([w1.to_string(), w2.to_string()]),
        "CHARACTERIZATION: the cascade deprecates (and names) W2: {body}"
    );
    assert!((workflow_truth(&pool, w2).await - 0.05).abs() < 1e-9);
}

/// CHARACTERIZATION: `DELETE /api/v1/workflows/:id` deprecates FLAT workflow
/// claims only. A hierarchical row's id is the unknown-id 404 for every caller,
/// W2's member and submitter included (MCP `deprecate_workflow` is the
/// hierarchical path), and nothing changes.
#[sqlx::test(migrations = "../../migrations")]
async fn characterization_rest_deprecation_serves_no_hierarchical_row(pool: PgPool) {
    let w = world(&pool).await;
    let (_w1, w2) = reused_step_generations(&w, &pool, "acme-hidden-rest-deprecate").await;
    let t2 = workflow_truth(&pool, w2).await;
    for agent in [w.h2, w.h] {
        let caller = token(agent, WRITE_SCOPES);
        let (status, out) = w
            .api
            .call(
                Method::DELETE,
                &format!("/api/v1/workflows/{w2}?reason=probe"),
                &caller,
                None,
            )
            .await;
        let (_, unknown) = w
            .api
            .call(
                Method::DELETE,
                &format!("/api/v1/workflows/{}?reason=probe", Uuid::nil()),
                &caller,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{out}");
        assert_eq!(
            out.to_string().replace(&w2.to_string(), "<id>"),
            unknown
                .to_string()
                .replace(&Uuid::nil().to_string(), "<id>"),
        );
    }
    assert_eq!(workflow_truth(&pool, w2).await, t2, "W2 is unchanged");
}
