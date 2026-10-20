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
//! * `embed: false` writes no claim embedding and no goal embedding.
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
        let embedder: std::sync::Arc<dyn EmbeddingService> =
            std::sync::Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
        let state = AppState::with_scoped_pool(scoped, ApiConfig::default())
            .with_embedding_service(embedder);
        state
            .load_entity_type_cache()
            .await
            .expect("load the entity-type cache");
        Self {
            router: epigraph_api::routes::create_router(state),
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
    let mut params = json!({ "extraction": extraction });
    if let Some(g) = group {
        params["tenancy"] = json!({"visibility": "group", "owner_group_id": g});
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

/// An app-role stdio MCP server whose own agent is keyed by `seed`, as a
/// container's `epigraph-mcp` is.
async fn mcp_server(pool: &PgPool, seed: u8) -> epigraph_mcp::server::EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
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
    let c_server = mcp_server(pool, 0xC1).await;
    let c = stdio_agent(pool, &c_server, 0xC1).await;
    link(pool, c, h).await;
    let f_server = mcp_server(pool, 0xF1).await;
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
        assert!(
            b.to_string().contains(&group.to_string()),
            "{name}: names the group: {b}"
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
        assert!(refused.contains(&group.to_string()), "{name}: {refused}");
        assert_eq!(
            workflows_named(&pool, name).await,
            0,
            "{name}: no workflow row"
        );
    }
}

/// A group the caller writes but the ingest system agent does not: refused
/// before any row is written, naming the system agent, rather than failing on
/// the first INSERT.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ingest_system_agent_must_write_the_declared_group(pool: PgPool) {
    let w = world(&pool).await;
    let unprovisioned = team_group(&pool, w.h).await;
    let name = "acme-tenancy-unprovisioned";
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
}

/// Only `visibility: "group"` is a declaration; anything else is refused and
/// writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_tenancy_other_than_group_is_refused(pool: PgPool) {
    let w = world(&pool).await;
    let name = "acme-tenancy-public-declared";
    let mut body = extraction(name, 0, &[&[]]);
    body["tenancy"] = json!({"visibility": "public", "owner_group_id": w.og});
    let (s, b) = w.api.ingest(&token(w.h, WRITE_SCOPES), &body).await;
    assert!(
        s.is_client_error(),
        "refused as the caller's error: {s} {b}"
    );
    assert_eq!(workflows_named(&pool, name).await, 0, "no workflow row");
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

/// A reused claim the CALLER cannot read is listed with a null tenancy, even
/// when the ingest's own system-agent stamp can read it: the response never
/// tells a caller the owner group of a claim it cannot see. Here the fleet
/// agent `f` (not a member of the team group `g`) declares `og`, and its plan
/// names an operation atom that is private to `g`, which the system agent
/// writes. Calibrated by the curator `c`, a member of `g`, which is told the
/// atom's real tenancy for the same plan text.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reused_claim_the_caller_cannot_read_is_listed_without_its_tenancy(pool: PgPool) {
    let w = world(&pool).await;
    let seeded = stdio_ingest(
        &w.c_server,
        mcp_params(
            extraction("acme-hidden-atom-owner", 0, &[&["acme hidden operation"]]),
            Some(w.g),
        ),
    )
    .await
    .expect("the curator seeds a g-private atom");
    let atom: Uuid = sqlx::query_scalar(
        "SELECT c.id FROM edges e JOIN claims c ON c.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'executes' \
            AND c.content = 'acme hidden operation'",
    )
    .bind(uuid_of(&seeded["workflow_id"]))
    .fetch_one(&pool)
    .await
    .expect("the atom");

    let out = stdio_ingest(
        &w.f_server,
        mcp_params(
            extraction("acme-hidden-atom-user", 0, &[&["acme hidden operation"]]),
            Some(w.og),
        ),
    )
    .await
    .expect("f declares og; the hidden atom is reused");
    let listed = reused(&out);
    assert_eq!(
        listed.get(&atom),
        Some(&(Value::Null, Value::Null)),
        "the atom is listed, without the tenancy f cannot read: {out}"
    );
    assert!(
        !out.to_string().contains(&w.g.to_string()),
        "the response never names g to a non-member: {out}"
    );

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

/// `embed: false` writes no claim embedding and no goal embedding, with and
/// without a declared tenancy. Calibrated by the default (`embed` absent),
/// which embeds every claim on the same mock-embedder API.
#[sqlx::test(migrations = "../../migrations")]
async fn embed_false_writes_no_embedding(pool: PgPool) {
    let w = world(&pool).await;
    let h = token(w.h, WRITE_SCOPES);
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Characterization: an operation atom already private to another group
// ─────────────────────────────────────────────────────────────────────────────

/// CHARACTERIZATION. Operation atoms are keyed by their text alone, across
/// every workflow and document. When the atom a plan names already exists as
/// a claim private to a group the ingest system agent does not write, the
/// `executes` edge to it inherits that group and its `WITH CHECK` fails: the
/// whole declared ingest is refused and writes nothing. (Availability: a
/// publisher cannot use that operation text until the atom is public or in its
/// own group.)
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
    assert!(!s.is_success(), "refused: {s} {b}");
    assert_eq!(workflows_named(&pool, name).await, 0, "no workflow row");
    assert_eq!(claims_mentioning(&pool, name).await, 0, "no claim");
    assert!(workflow_id_named(&pool, name, 0).await.is_none());
}
