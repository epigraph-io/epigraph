//! Answers to a caller that cannot READ a group-private `workflows` row do not
//! name it (backlog c831df4a, ruling R-100), on REST and on the authenticated
//! MCP transport.
//!
//! Workflow ids are deterministic (`workflow_root_id`, which a pinned host
//! recomputes), so the ruling keeps them and asks only that no answer hand a
//! hidden id over. Before the fix several did, because the step tools and the
//! ingest read the row on the workflow-ingest SYSTEM agent's stamp, which
//! reads every group that agent writes:
//!
//! * `add_step` (REST and MCP) by a non-member named the hidden workflow and
//!   its submitter in its refusal;
//! * a re-ingest of an existing `(canonical_name, generation)` returned the
//!   hidden row's id with `already_ingested: true`;
//! * a new generation of a hidden lineage named the head and its submitter;
//! * `evolve_step` of a public step that a hidden workflow executes read the
//!   row on the caller's own stamp, found no submitter, and called the hidden
//!   workflow, by id, a "legacy platform workflow".
//!
//! Now a row the caller cannot read gets the call site's own not-found answer
//! (byte-identical to an unknown name / missing parent, after replacing the
//! caller-sent name or id), or, for an ingest of its lineage, a refusal
//! without `workflow_id`. Since workflow writes are made as the caller (on its
//! own stamp), a lineage with rows the caller cannot read is not written at
//! all (migration 202), so a re-ingest is refused rather than answered. A
//! member still gets the id and the arms. A GROUP row with no recorded
//! submitter is no longer called a "legacy platform workflow".
//!
//! Production pool shape: the router and the MCP server run on an
//! `epigraph_app` `ScopedPool`; the harness superuser only seeds and inspects.
//! The database is not armed (migration 122), so the outsider reaches the
//! workflow gates rather than an operator-binding refusal.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{GroupRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const WRITE_SCOPES: &[&str] = &["claims:read", "claims:write", "edges:write"];

fn token(agent: Uuid) -> String {
    common::mint_token_with_agent(WRITE_SCOPES, agent)
}

struct Api {
    router: axum::Router,
}

impl Api {
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
        let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
        state
            .load_entity_type_cache()
            .await
            .expect("load the entity-type cache");
        Self {
            router: epigraph_api::routes::create_router(state),
        }
    }

    async fn post(&self, uri: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        let resp = self.router.clone().oneshot(req).await.expect("router");
        let status = resp.status();
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, value)
    }
}

fn extraction(name: &str, generation: u32) -> Value {
    json!({
        "source": {"canonical_name": name,
                   "goal": format!("masking goal for {name}"),
                   "generation": generation, "metadata": {}},
        "thesis_derivation": "TopDown",
        "phases": [{"title": "Body", "summary": format!("{name} phase g{generation}"),
                    "steps": [{"compound": format!("{name} step g{generation}"),
                               "rationale": "ordered", "operations": [],
                               "generality": [], "confidence": 0.8}]}],
        "relationships": []
    })
}

fn declared(mut body: Value, group: Uuid) -> Value {
    body["tenancy"] = json!({"visibility": "group", "owner_group_id": group});
    body
}

/// The world: a registered workflow-ingest system agent that writes team group
/// `g`; `member`, `g`'s admin, ingests a plan declared into `g`, so its
/// `workflows` row is `('group', g)`; `outsider` is in no group but its own.
struct World {
    api: Api,
    server: epigraph_mcp::server::EpiGraphMcpFull,
    member: Uuid,
    member_group: Uuid,
    outsider: Uuid,
    name: String,
    workflow: Uuid,
}

async fn world(pool: &PgPool) -> World {
    let system = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    assert!(fixture::register_system_agent(pool, system).await);
    let (member, member_group) = fixture::seed_agent_with_group(pool, "mask-member").await;
    let (outsider, _) = fixture::seed_agent_with_group(pool, "mask-outsider").await;
    let g = Uuid::new_v4();
    let public_key = blake3::hash(g.as_bytes()).as_bytes().to_vec();
    GroupRepository::create_with_admin(
        pool,
        g,
        Some("masking team group"),
        &format!("did:epigraph:test:masking:{g}"),
        &public_key,
        None,
        member,
    )
    .await
    .expect("the team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(g)
    .bind(system)
    .execute(pool)
    .await
    .expect("the system agent writes g");

    let api = Api::prod_shaped(pool).await;
    let name = format!("mask-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let (status, out) = api
        .post(
            "/api/v1/workflows/ingest",
            &token(member),
            &declared(extraction(&name, 0), g),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the member's declared ingest: {out}"
    );
    let workflow = Uuid::parse_str(out["workflow_id"].as_str().expect("id")).expect("uuid");
    let tenancy: (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM workflows WHERE id = $1")
            .bind(workflow)
            .fetch_one(pool)
            .await
            .expect("row tenancy");
    assert_eq!(tenancy, ("group".to_string(), g), "the row is the group's");

    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x5A; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    let server = epigraph_mcp::server::EpiGraphMcpFull::new(plain, signer, embedder, false)
        .with_scoped_pool(scoped);
    World {
        api,
        server,
        member,
        member_group,
        outsider,
        name,
        workflow,
    }
}

fn auth_for(agent: Uuid) -> epigraph_auth::AuthContext {
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

/// An MCP tool's answer over the authenticated transport, as `Ok(json)` or
/// `Err((code, message))`.
type ToolAnswer = Result<Value, (i32, String)>;

fn tool_answer(
    r: Result<rmcp::model::CallToolResult, epigraph_mcp::errors::McpError>,
) -> ToolAnswer {
    match r {
        Ok(out) => {
            let text = out
                .content
                .first()
                .and_then(|c| c.as_text())
                .map(|t| t.text.clone())
                .expect("a text result");
            Ok(serde_json::from_str(&text).expect("a JSON result"))
        }
        Err(e) => Err((e.code.0, e.message.to_string())),
    }
}

async fn mcp_add_step(w: &World, agent: Uuid, name: &str) -> ToolAnswer {
    let auth = auth_for(agent);
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&w.server, Some(&auth))
        .await
        .expect("viewer");
    let params: epigraph_mcp::tools::step_ops::AddStepParams =
        serde_json::from_value(json!({"canonical_name": name, "step_text": "an added step"}))
            .expect("params");
    tool_answer(
        epigraph_mcp::tools::step_ops::add_step(&w.server, &viewer, params, Some(&auth)).await,
    )
}

async fn mcp_ingest(w: &World, agent: Uuid, extraction: Value) -> ToolAnswer {
    let auth = auth_for(agent);
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&w.server, Some(&auth))
        .await
        .expect("viewer");
    let params: epigraph_mcp::types::IngestWorkflowParams =
        serde_json::from_value(json!({ "extraction": extraction })).expect("params");
    tool_answer(
        epigraph_mcp::tools::workflow_ingest::ingest_workflow(
            &w.server,
            &viewer,
            params,
            Some(&auth),
        )
        .await,
    )
}

async fn mcp_evolve(w: &World, agent: Uuid, parent: Uuid, content: &str) -> ToolAnswer {
    let auth = auth_for(agent);
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&w.server, Some(&auth))
        .await
        .expect("viewer");
    let params: epigraph_mcp::tools::evolve_step::EvolveStepParams =
        serde_json::from_value(json!({
            "parent_id": parent.to_string(), "content": content,
            "edge_type": "revises", "level": 2
        }))
        .expect("params");
    tool_answer(
        epigraph_mcp::tools::evolve_step::evolve_step(&w.server, &viewer, params, Some(&auth))
            .await,
    )
}

/// The serialized answer, for "names nothing hidden" checks.
fn text_of<T: std::fmt::Debug>(v: &T) -> String {
    format!("{v:?}")
}

fn assert_names_nothing_hidden(w: &World, what: &str, answer: &str) {
    assert!(
        !answer.contains(&w.workflow.to_string()),
        "{what}: the answer names the hidden workflow: {answer}"
    );
    assert!(
        !answer.contains(&w.member.to_string()),
        "{what}: the answer names the hidden workflow's submitter: {answer}"
    );
}

/// `add_step`, a re-ingest and a new generation, by a non-member of the group
/// that owns the row, on REST and MCP: nothing names the row, the step tools
/// answer exactly as for an unknown name, and the re-ingest leaves the id out.
/// The member gets the id and is admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn step_and_ingest_answers_to_a_non_member_do_not_name_the_hidden_workflow(pool: PgPool) {
    let w = world(&pool).await;
    let unknown = format!("{}-unknown", w.name);

    // REST add_step: the hidden name answers as an unknown one.
    let step = |name: &str| json!({"canonical_name": name, "step_text": "an added step"});
    let (s_hidden, b_hidden) = w
        .api
        .post(
            "/api/v1/workflows/steps",
            &token(w.outsider),
            &step(&w.name),
        )
        .await;
    let (s_unknown, b_unknown) = w
        .api
        .post(
            "/api/v1/workflows/steps",
            &token(w.outsider),
            &step(&unknown),
        )
        .await;
    assert_names_nothing_hidden(&w, "REST add_step", &b_hidden.to_string());
    assert_eq!(s_unknown, StatusCode::NOT_FOUND, "{b_unknown}");
    assert_eq!(
        (s_hidden, b_hidden.to_string().replace(&w.name, "<name>")),
        (s_unknown, b_unknown.to_string().replace(&unknown, "<name>")),
        "REST add_step on a hidden workflow answers exactly as on an unknown name"
    );

    // MCP add_step (authenticated): the same.
    let m_hidden = mcp_add_step(&w, w.outsider, &w.name).await;
    let m_unknown = mcp_add_step(&w, w.outsider, &unknown).await;
    assert_names_nothing_hidden(&w, "MCP add_step", &text_of(&m_hidden));
    let norm = |a: &ToolAnswer, n: &str| text_of(a).replace(n, "<name>");
    assert!(
        m_unknown.is_err(),
        "an unknown name is refused: {m_unknown:?}"
    );
    assert_eq!(
        norm(&m_hidden, &w.name),
        norm(&m_unknown, &unknown),
        "MCP add_step on a hidden workflow answers exactly as on an unknown name"
    );

    // A re-ingest of the hidden (name, generation): workflow writes run on
    // the caller's own stamp, and a lineage with rows the caller cannot read
    // is not written (migration 202): refused (409 / MCP INVALID_REQUEST),
    // with no id and nothing hidden named.
    let (s, out) = w
        .api
        .post(
            "/api/v1/workflows/ingest",
            &token(w.outsider),
            &extraction(&w.name, 0),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{out}");
    assert!(
        out.get("workflow_id").is_none(),
        "REST re-ingest by a non-member carries no id: {out}"
    );
    assert_names_nothing_hidden(&w, "REST re-ingest", &out.to_string());
    let m = mcp_ingest(&w, w.outsider, extraction(&w.name, 0)).await;
    assert!(
        m.is_err(),
        "the MCP re-ingest by a non-member is refused: {m:?}"
    );
    assert_names_nothing_hidden(&w, "MCP re-ingest", &text_of(&m));

    // A new generation of the hidden lineage: refused, naming nothing hidden.
    let (s, out) = w
        .api
        .post(
            "/api/v1/workflows/ingest",
            &token(w.outsider),
            &extraction(&w.name, 1),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{out}");
    assert_names_nothing_hidden(&w, "REST new generation", &out.to_string());
    let m = mcp_ingest(&w, w.outsider, extraction(&w.name, 1)).await;
    assert!(
        m.is_err(),
        "MCP new generation by a non-member is refused: {m:?}"
    );
    assert_names_nothing_hidden(&w, "MCP new generation", &text_of(&m));
    let generations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = $1")
            .bind(&w.name)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(generations, 1, "no generation was written by the outsider");

    // The member: the re-ingest reports the id on both transports, and its
    // add_step is admitted (the gate is the caller's view, not a blanket mask).
    let (s, out) = w
        .api
        .post(
            "/api/v1/workflows/ingest",
            &token(w.member),
            &extraction(&w.name, 0),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert_eq!(out["workflow_id"], json!(w.workflow), "{out}");
    let out = mcp_ingest(&w, w.member, extraction(&w.name, 0))
        .await
        .expect("the member's MCP re-ingest");
    assert_eq!(out["workflow_id"], json!(w.workflow.to_string()), "{out}");
    let (s, out) = w
        .api
        .post("/api/v1/workflows/steps", &token(w.member), &step(&w.name))
        .await;
    assert_eq!(s, StatusCode::OK, "the member adds a step: {out}");
}

/// `evolve_step` of a PUBLIC step that only a group workflow executes: the
/// outsider reads the step and its `executes` edge (the edge takes the step's
/// tenancy) but not the workflow row. It answers as a missing parent on REST
/// and MCP, naming nothing hidden. The member, who reads the row, is the
/// submitter and evolves the step; once the row records no submitter, the
/// member's refusal does not call the GROUP row a "legacy platform workflow".
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_of_a_step_a_hidden_workflow_executes_answers_as_a_missing_parent(pool: PgPool) {
    let w = world(&pool).await;
    // A public step in the member's own group (so the member can write its
    // successor), executed by the group workflow alone.
    let step = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'public', $5)",
    )
    .bind(step)
    .bind(format!("a public step {step}"))
    .bind(step.as_bytes().repeat(2))
    .bind(w.member)
    .bind(w.member_group)
    .execute(&pool)
    .await
    .expect("seed the public step");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'claim', 'executes')",
    )
    .bind(w.workflow)
    .bind(step)
    .execute(&pool)
    .await
    .expect("the group workflow executes the public step");
    let edge_visibility: String = sqlx::query_scalar(
        "SELECT visibility::text FROM edges WHERE source_id = $1 AND target_id = $2",
    )
    .bind(w.workflow)
    .bind(step)
    .fetch_one(&pool)
    .await
    .expect("edge");
    assert_eq!(edge_visibility, "public", "the outsider reads the edge");
    let missing = Uuid::new_v4();
    let evolve = |p: Uuid| json!({"parent_id": p, "content": "a revision", "edge_type": "revises"});

    // REST.
    let (s_hidden, b_hidden) = w
        .api
        .post(
            &format!("/api/v1/workflows/steps/{step}/evolve"),
            &token(w.outsider),
            &evolve(step),
        )
        .await;
    let (s_missing, b_missing) = w
        .api
        .post(
            &format!("/api/v1/workflows/steps/{missing}/evolve"),
            &token(w.outsider),
            &evolve(missing),
        )
        .await;
    assert_names_nothing_hidden(&w, "REST evolve", &b_hidden.to_string());
    assert_eq!(s_missing, StatusCode::NOT_FOUND, "{b_missing}");
    assert_eq!(
        (
            s_hidden,
            b_hidden.to_string().replace(&step.to_string(), "<id>")
        ),
        (
            s_missing,
            b_missing.to_string().replace(&missing.to_string(), "<id>")
        ),
        "REST evolve answers as for a missing parent"
    );

    // MCP (authenticated).
    let m_hidden = mcp_evolve(&w, w.outsider, step, "an MCP revision").await;
    let m_missing = mcp_evolve(&w, w.outsider, missing, "an MCP revision").await;
    assert_names_nothing_hidden(&w, "MCP evolve", &text_of(&m_hidden));
    assert!(m_missing.is_err(), "{m_missing:?}");
    assert_eq!(
        text_of(&m_hidden).replace(&step.to_string(), "<id>"),
        text_of(&m_missing).replace(&missing.to_string(), "<id>"),
        "MCP evolve answers as for a missing parent"
    );
    let written: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claims WHERE content LIKE 'a%revision'")
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(written, 0, "the outsider wrote nothing");

    // The member reads the row and is its submitter: admitted.
    let (s, out) = w
        .api
        .post(
            &format!("/api/v1/workflows/steps/{step}/evolve"),
            &token(w.member),
            &evolve(step),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "the member evolves the step: {out}");

    // A GROUP row with no recorded submitter is not "legacy platform" corpus.
    sqlx::query("UPDATE workflows SET metadata = metadata - $2 WHERE id = $1")
        .bind(w.workflow)
        .bind(epigraph_db::WorkflowRepository::SUBMITTER_KEY)
        .execute(&pool)
        .await
        .expect("drop the submitter record");
    let (s, out) = w
        .api
        .post(
            &format!("/api/v1/workflows/steps/{step}/evolve"),
            &token(w.member),
            &evolve(step),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{out}");
    let text = out.to_string();
    assert!(
        text.contains("no recorded submitter") && text.contains("a group workflow"),
        "the member is told the group row has no submitter: {text}"
    );
    assert!(
        !text.contains("platform"),
        "not called platform corpus: {text}"
    );
    let m = mcp_evolve(&w, w.member, step, "a member MCP revision").await;
    let text = text_of(&m);
    assert!(
        m.is_err() && text.contains("no recorded submitter") && text.contains("a group workflow"),
        "MCP: the member is told the group row has no submitter: {text}"
    );
    assert!(
        !text.contains("platform"),
        "MCP: not called platform corpus: {text}"
    );
}

/// `store_workflow` (REST `POST /api/v1/workflows` and the MCP tool) is idempotent
/// on `(slugify(goal), 0)`, so a goal whose slug is the hidden plan's
/// `canonical_name` is a re-ingest of the hidden row. The non-member is
/// refused without the id (and emits no `workflow.created` event); the
/// member's answer carries it.
#[sqlx::test(migrations = "../../migrations")]
async fn store_workflow_re_ingest_by_a_non_member_leaves_the_id_out(pool: PgPool) {
    let w = world(&pool).await;
    // `w.name` is already a slug, so it slugifies to itself.
    let body = json!({"goal": w.name, "steps": ["a stored step"]});

    // Workflow writes run on the caller's own stamp, and a lineage with rows
    // the caller cannot read is not written (migration 202): the non-member's
    // store is refused (409 / MCP INVALID_REQUEST), with no id, nothing
    // hidden named, and no `workflow.created` event.
    let (s, out) = w
        .api
        .post("/api/v1/workflows", &token(w.outsider), &body)
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{out}");
    assert!(
        out.get("workflow_id").is_none(),
        "REST store_workflow by a non-member carries no id: {out}"
    );
    assert_names_nothing_hidden(&w, "REST store_workflow", &out.to_string());
    let events: Vec<Value> = sqlx::query_scalar(
        "SELECT payload FROM events WHERE event_type = 'workflow.created' \
           AND payload->>'canonical_name' = $1",
    )
    .bind(&w.name)
    .fetch_all(&pool)
    .await
    .expect("events");
    assert!(
        events.is_empty(),
        "a refused store emits no event: {events:?}"
    );

    let auth = auth_for(w.outsider);
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&w.server, Some(&auth))
        .await
        .expect("viewer");
    let params: epigraph_mcp::types::StoreWorkflowParams =
        serde_json::from_value(body.clone()).expect("params");
    let m = tool_answer(
        epigraph_mcp::tools::workflows::store_workflow(&w.server, &viewer, params, Some(&auth))
            .await,
    );
    assert!(
        m.is_err(),
        "the MCP store_workflow by a non-member is refused: {m:?}"
    );
    assert_names_nothing_hidden(&w, "MCP store_workflow", &text_of(&m));

    // The member's answers carry the id.
    let (s, out) = w
        .api
        .post("/api/v1/workflows", &token(w.member), &body)
        .await;
    assert_eq!(s, StatusCode::OK, "{out}");
    assert_eq!(out["workflow_id"], json!(w.workflow), "{out}");
    let auth = auth_for(w.member);
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&w.server, Some(&auth))
        .await
        .expect("viewer");
    let params: epigraph_mcp::types::StoreWorkflowParams =
        serde_json::from_value(body).expect("params");
    let out = tool_answer(
        epigraph_mcp::tools::workflows::store_workflow(&w.server, &viewer, params, Some(&auth))
            .await,
    )
    .expect("the member's MCP store_workflow");
    assert_eq!(out["workflow_id"], json!(w.workflow.to_string()), "{out}");
}

/// A REST token for `agent` minted on OAuth client `client`, so a test can
/// give that client a record (or none) for migration 111's admin re-check.
fn token_for_client(client: Uuid, agent: Uuid, scopes: &[&str]) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    cfg.issue_access_token(
        client,
        scopes.iter().map(|s| (*s).to_string()).collect(),
        "service",
        None,
        Some(agent),
        chrono::Duration::minutes(60),
        epigraph_auth::AccessTokenBinding::NONE,
    )
    .expect("test JWT")
    .0
}

const ADMIN_SCOPES: &[&str] = &["claims:read", "claims:write", "edges:write", "claims:admin"];

/// The MCP twin of [`token_for_client`].
fn admin_auth(client: Uuid, agent: Uuid) -> epigraph_auth::AuthContext {
    epigraph_auth::AuthContext {
        client_id: client,
        scopes: ADMIN_SCOPES.iter().map(|s| (*s).to_string()).collect(),
        ..auth_for(agent)
    }
}

/// An ACTIVE client record granting `claims:admin` to `agent`, which the
/// audited admin arm re-checks (ADM02).
async fn grant_admin(pool: &PgPool, client: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id) \
         VALUES ($1, $2, 'test admin', 'human', ARRAY['claims:admin'], ARRAY['claims:admin'], \
                 'active', $3)",
    )
    .bind(client)
    .bind(format!("test-admin-{client}"))
    .bind(agent)
    .execute(pool)
    .await
    .expect("the admin's client record");
}

async fn mcp_delete_step(
    w: &World,
    auth: &epigraph_auth::AuthContext,
    name: &str,
    lineage: Uuid,
) -> ToolAnswer {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(&w.server, Some(auth))
        .await
        .expect("viewer");
    let params: epigraph_mcp::tools::step_ops::DeleteStepParams = serde_json::from_value(
        json!({"canonical_name": name, "step_lineage_id": lineage.to_string()}),
    )
    .expect("params");
    tool_answer(
        epigraph_mcp::tools::step_ops::delete_step(&w.server, &viewer, params, Some(auth)).await,
    )
}

/// Every `truth_value` of the lineage's claims, to show a refusal changed none.
async fn lineage_truths(pool: &PgPool, lineage: Uuid) -> Vec<f64> {
    sqlx::query_scalar("SELECT truth_value FROM claims WHERE step_lineage_id = $1 ORDER BY id")
        .bind(lineage)
        .fetch_all(pool)
        .await
        .expect("lineage truths")
}

/// `(agent_id, details)` of every `workflows.admin_write` row for `delete_step`.
async fn delete_admin_rows(pool: &PgPool) -> Vec<(Option<Uuid>, Value)> {
    sqlx::query_as(
        "SELECT agent_id, details FROM security_events \
          WHERE event_type = 'workflows.admin_write' AND details->>'action' = 'delete_step' \
          ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("admin rows")
}

/// `delete_step` over a hidden group workflow, REST and MCP.
///
/// * A non-member, and a `claims:admin` token whose client record grants
///   nothing (ADM02), are refused exactly as for an unknown name, naming
///   nothing hidden, with the step untouched.
/// * A live `claims:admin` holder OUTSIDE the group is now refused the same
///   way, with nothing written and no `workflows.admin_write` row: workflow
///   writes run on the caller's own stamp, and no caller writes a group it
///   does not write through any path, the audited admin arm included. (It was
///   admitted through the shared system agent's stamp before.) The masking
///   still changes no arm: an admin who writes the group is admitted by it.
/// * The member (the submitter) is admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_step_over_a_hidden_workflow_is_masked_and_admits_only_writers_of_its_group(
    pool: PgPool,
) {
    let w = world(&pool).await;
    let unknown = format!("{}-unknown", w.name);
    let first: Uuid = sqlx::query_scalar(
        "SELECT c.step_lineage_id FROM claims c JOIN edges e ON e.target_id = c.id \
           JOIN workflows wf ON wf.id = e.source_id \
          WHERE wf.id = $1 AND e.relationship = 'executes' AND c.step_lineage_id IS NOT NULL \
          LIMIT 1",
    )
    .bind(w.workflow)
    .fetch_one(&pool)
    .await
    .expect("a step lineage of the hidden plan");
    let truths = lineage_truths(&pool, first).await;
    let delete =
        |name: &str, lineage: Uuid| json!({"canonical_name": name, "step_lineage_id": lineage});

    // Refused callers: the outsider, and an admin token with no live grant.
    let (admin, _) = fixture::seed_agent_with_group(&pool, "mask-admin").await;
    let grantless_client = Uuid::new_v4();
    let refused = [
        ("outsider", token(w.outsider), auth_for(w.outsider)),
        (
            "grantless admin",
            token_for_client(grantless_client, admin, ADMIN_SCOPES),
            admin_auth(grantless_client, admin),
        ),
    ];
    for (who, rest_token, mcp_auth) in &refused {
        let (s_hidden, b_hidden) = w
            .api
            .post(
                "/api/v1/workflows/steps/delete",
                rest_token,
                &delete(&w.name, first),
            )
            .await;
        let (s_unknown, b_unknown) = w
            .api
            .post(
                "/api/v1/workflows/steps/delete",
                rest_token,
                &delete(&unknown, first),
            )
            .await;
        assert_names_nothing_hidden(
            &w,
            &format!("REST delete_step ({who})"),
            &b_hidden.to_string(),
        );
        assert_eq!(s_unknown, StatusCode::NOT_FOUND, "{who}: {b_unknown}");
        assert_eq!(
            (s_hidden, b_hidden.to_string().replace(&w.name, "<name>")),
            (s_unknown, b_unknown.to_string().replace(&unknown, "<name>")),
            "REST delete_step ({who}) on a hidden workflow answers exactly as on an unknown name"
        );

        let m_hidden = mcp_delete_step(&w, mcp_auth, &w.name, first).await;
        let m_unknown = mcp_delete_step(&w, mcp_auth, &unknown, first).await;
        assert_names_nothing_hidden(&w, &format!("MCP delete_step ({who})"), &text_of(&m_hidden));
        assert!(
            m_unknown.is_err(),
            "{who}: an unknown name is refused: {m_unknown:?}"
        );
        assert_eq!(
            text_of(&m_hidden).replace(&w.name, "<name>"),
            text_of(&m_unknown).replace(&unknown, "<name>"),
            "MCP delete_step ({who}) on a hidden workflow answers exactly as on an unknown name"
        );
        assert_eq!(
            lineage_truths(&pool, first).await,
            truths,
            "{who}: the step is untouched"
        );
    }
    assert!(
        delete_admin_rows(&pool).await.is_empty(),
        "no refused call is audited as an admin write"
    );

    // Three more lineages, added by the member (the submitter).
    let mut added = Vec::new();
    for i in 0..3 {
        let (s, out) = w
            .api
            .post(
                "/api/v1/workflows/steps",
                &token(w.member),
                &json!({"canonical_name": w.name, "step_text": format!("a member step {i}")}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "the member adds step {i}: {out}");
        added.push(
            Uuid::parse_str(out["step_lineage_id"].as_str().expect("lineage")).expect("uuid"),
        );
    }

    // A live claims:admin holder OUTSIDE the group: refused on REST and on
    // MCP as for an unknown name, nothing written, nothing audited (workflow
    // writes are made as the caller, and the admin does not write the group).
    let client = Uuid::new_v4();
    grant_admin(&pool, client, admin).await;
    let truths_first = lineage_truths(&pool, first).await;
    let truths_added = lineage_truths(&pool, added[0]).await;
    let (s, out) = w
        .api
        .post(
            "/api/v1/workflows/steps/delete",
            &token_for_client(client, admin, ADMIN_SCOPES),
            &delete(&w.name, first),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "an admin outside the group cannot delete its step: {out}"
    );
    assert_names_nothing_hidden(&w, "REST delete_step (live admin)", &out.to_string());
    let m = mcp_delete_step(&w, &admin_auth(client, admin), &w.name, added[0]).await;
    assert!(
        m.is_err(),
        "an admin outside the group is refused over MCP: {m:?}"
    );
    assert_names_nothing_hidden(&w, "MCP delete_step (live admin)", &text_of(&m));
    assert_eq!(lineage_truths(&pool, first).await, truths_first);
    assert_eq!(lineage_truths(&pool, added[0]).await, truths_added);
    assert!(
        delete_admin_rows(&pool).await.is_empty(),
        "a refused admin call is not audited as an admin write"
    );

    // The member (the submitter): admitted on both transports, not audited
    // as an admin.
    let (s, out) = w
        .api
        .post(
            "/api/v1/workflows/steps/delete",
            &token(w.member),
            &delete(&w.name, added[1]),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "the member deletes over REST: {out}");
    mcp_delete_step(&w, &auth_for(w.member), &w.name, added[2])
        .await
        .expect("the member deletes over MCP");
    assert!(
        delete_admin_rows(&pool).await.is_empty(),
        "the member is no admin write"
    );
}
