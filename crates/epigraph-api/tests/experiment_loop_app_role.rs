//! The experiment loop and the method catalog over HTTP on the APPLICATION
//! ROLE (backlog 30c84267).
//!
//! # What was wrong, measured before this file
//!
//! `routes/experiment_loop.rs` gated every route on the hypothesis through the
//! caller's viewer (the hypothesis write gate) and then wrote on `state.db_pool`. On a production
//! deployment that pool is `epigraph_app` with no tenancy stamp, under FORCEd
//! row security. Two of the loop's writes take the HYPOTHESIS's tenancy: the
//! `tests_hypothesis` / `provides_evidence` edges onto it and the
//! error-derived BBA on it. Unstamped, `WITH CHECK` sees an empty writable set
//! and refuses both for every group-owned hypothesis, so for a caller with full
//! write authority:
//!
//! * `POST /api/v1/experiments/new` answered 200 with an experiment no edge tied
//!   to its hypothesis (the edge's error was dropped by `.ok()`);
//! * `POST .../analyze` answered 500 after its analysis row, its `analyzes`
//!   edge and the `analyzing` status had already committed.
//!
//! Every superuser-pool experiment test passes either way, because a superuser
//! bypasses row security; `hypothesis_promote_standing_app_role.rs` seeds its
//! analysis through a superuser app for exactly this reason.
//!
//! # The instrument
//!
//! The app under test runs both its raw `db_pool` and its stamped `ScopedPool`
//! as `epigraph_app`, as on production. The hypothesis is group-private and its
//! author is the group's admin. Every effect is read back through the
//! superuser seeding pool.
//!
//! Verified to fail on the pre-conversion handlers: the loop arm fails at its
//! first edge check (`tests_hypothesis` edge count 0, expected 1), and with
//! that check removed at `analyze` (500). The method-catalog arm is a
//! regression pin for the two `routes/experiments.rs` handlers moved onto the
//! caller's stamped connection: both tables carry no tenancy, so it passes on
//! either tree, and it is not offered as proof of a defect.
//!
//! # The refusals the stamp brings
//!
//! * A role-attached agent outside its holder window (migration 166, ROL01) is
//!   now refused on these tables, because the per-statement check sees the
//!   real principal. It answers the coded 403 every write surface answers,
//!   not a 500 server fault.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;
mod viewer_fixture;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use epigraph_api::embedding_restore::EmbeddingProviderKind;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::experiment_loop::{create_experiment, CreateExperimentRequest};
use epigraph_api::routes::experiments::{add_method, AddMethodRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

const RW: &[&str] = &["claims:read", "claims:write"];

/// The state under test: raw and stamped pools both `epigraph_app`, with a
/// mock embedder declared as the provider that owns the stored vector columns
/// (so `POST /api/v1/methods` stores a method embedding `find_methods` can
/// rank).
async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let service: std::sync::Arc<dyn EmbeddingService> =
        std::sync::Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    let mut state = AppState::with_db(raw, ApiConfig::default())
        .with_embedding_service(service)
        .with_embedding_provider(EmbeddingProviderKind::OpenAi);
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

/// The app under test, served over HTTP on [`app_role_state`].
async fn spawn_app_role(pool: &PgPool) -> (SocketAddr, oneshot::Sender<()>) {
    let app = epigraph_api::routes::create_router(app_role_state(pool).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (addr, tx)
}

async fn ensure_frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['true','false']::text[]) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {name} frame: {e}"))
}

async fn send(
    addr: SocketAddr,
    agent: Uuid,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let token = common::mint_token_with_agent(RW, agent);
    let mut req = reqwest::Client::new()
        .request(method, format!("http://{addr}{path}"))
        .bearer_auth(&token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let res = req.send().await.expect("request");
    let status = res.status().as_u16();
    let text = res.text().await.unwrap_or_default();
    let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, value)
}

async fn post(addr: SocketAddr, agent: Uuid, path: &str, body: Value) -> (u16, Value) {
    send(addr, agent, reqwest::Method::POST, path, Some(body)).await
}

fn uuid_at(body: &Value, key: &str) -> Uuid {
    Uuid::parse_str(
        body[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} in {body}")),
    )
    .expect("uuid")
}

/// Edges `source -relationship-> target` (any validity), read as superuser.
async fn edges(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
         AND relationship = $3",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("count edges")
}

async fn experiment_status(pool: &PgPool, experiment: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM experiments WHERE id = $1")
        .bind(experiment)
        .fetch_one(pool)
        .await
        .expect("experiment status")
}

/// A group writer runs the whole loop on a group-private hypothesis, on the
/// application role, and every write lands: the experiment with its
/// `tests_hypothesis` edge, the result with its `result_of` edge, the
/// measurements, and the analysis with both its edges and its BBA.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_writer_runs_the_experiment_loop_on_the_application_role(pool: PgPool) {
    let hyp_frame = ensure_frame(&pool, "hypothesis_assessment").await;
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "30c84267-owner").await;
    let hypothesis = viewer_fixture::seed_group_claim(
        &pool,
        owner,
        group,
        &format!("30c84267 hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let visibility: String = sqlx::query_scalar("SELECT visibility FROM claims WHERE id = $1")
        .bind(hypothesis)
        .fetch_one(&pool)
        .await
        .expect("hypothesis visibility");
    assert_eq!(
        visibility, "group",
        "fixture: the hypothesis must be group-private, or row security has nothing to refuse"
    );
    let (addr, _shutdown) = spawn_app_role(&pool).await;

    // 1. Create: the experiment AND its edge onto the hypothesis.
    let (status, body) = post(
        addr,
        owner,
        "/api/v1/experiments/new",
        json!({ "hypothesis_id": hypothesis, "protocol": "30c84267 protocol" }),
    )
    .await;
    assert_eq!(status, 200, "create: {body}");
    let experiment = uuid_at(&body, "experiment_id");
    assert_eq!(
        edges(&pool, experiment, hypothesis, "tests_hypothesis").await,
        1,
        "create answered 200, so the experiment's `tests_hypothesis` edge onto the \
         group-private hypothesis must exist (on the unstamped pool row security refused it \
         and the handler dropped the error)"
    );

    // 2. Start.
    let (status, body) = post(
        addr,
        owner,
        &format!("/api/v1/experiments/{experiment}/start"),
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "start: {body}");
    assert_eq!(experiment_status(&pool, experiment).await, "running");

    // 3. Results: the result, its edge and the `collecting` status.
    let (status, body) = post(
        addr,
        owner,
        &format!("/api/v1/experiments/{experiment}/results"),
        json!({
            "data_source": "instrument",
            "measurements": [
                {"value": 1.2, "random_error": 0.05, "systematic_error": 0.02},
            ],
        }),
    )
    .await;
    assert_eq!(status, 200, "results: {body}");
    let result = uuid_at(&body, "result_id");
    assert_eq!(edges(&pool, result, experiment, "result_of").await, 1);
    assert_eq!(experiment_status(&pool, experiment).await, "collecting");

    // 4. More measurements on that result.
    let (status, body) = post(
        addr,
        owner,
        &format!("/api/v1/experiments/{experiment}/results/{result}/measurements"),
        json!({
            "measurements": [
                {"value": 1.1, "random_error": 0.05, "systematic_error": 0.02},
            ],
        }),
    )
    .await;
    assert_eq!(status, 200, "measurements: {body}");
    assert_eq!(body["total_measurements"], 2, "measurements: {body}");

    // 5. Analyze: the analysis, both edges, the BBA and both statuses.
    let (status, body) = post(
        addr,
        owner,
        &format!("/api/v1/experiments/{experiment}/results/{result}/analyze"),
        json!({
            "direction": "supports",
            "scope_limitations": [{"type": "small_sample_size"}],
            "expected_value": 0.0,
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "analyze by the hypothesis's group admin must succeed on the application role: {body}"
    );
    let analysis = uuid_at(&body, "analysis_id");
    assert_eq!(uuid_at(&body, "hypothesis_id"), hypothesis);
    assert_eq!(edges(&pool, analysis, result, "analyzes").await, 1);
    assert_eq!(
        edges(&pool, analysis, hypothesis, "provides_evidence").await,
        1
    );
    let bbas: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2 \
         AND source_agent_id = $3 AND combination_method = 'error_derived'",
    )
    .bind(hypothesis)
    .bind(hyp_frame)
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("count BBAs");
    assert_eq!(
        bbas, 1,
        "the analysis's error-derived BBA on the hypothesis"
    );
    let result_status: String =
        sqlx::query_scalar("SELECT status FROM experiment_results WHERE id = $1")
            .bind(result)
            .fetch_one(&pool)
            .await
            .expect("result status");
    assert_eq!(result_status, "complete");
    assert_eq!(experiment_status(&pool, experiment).await, "complete");

    // 6. List.
    let (status, body) = send(
        addr,
        owner,
        reqwest::Method::GET,
        &format!("/api/v1/experiments?hypothesis_id={hypothesis}"),
        None,
    )
    .await;
    assert_eq!(status, 200, "list: {body}");
    let listed: Vec<&str> = body["experiments"]
        .as_array()
        .expect("experiments array")
        .iter()
        .filter_map(|e| e["id"].as_str())
        .collect();
    assert_eq!(
        listed,
        vec![experiment.to_string().as_str()],
        "list: {body}"
    );
}

/// Regression pin: the method catalog's write and search run on the caller's
/// stamped connection on the application role. Not a defect proof (see the
/// module doc).
#[sqlx::test(migrations = "../../migrations")]
async fn the_method_catalog_writes_and_searches_on_the_application_role(pool: PgPool) {
    let (agent, _group) = viewer_fixture::seed_agent_with_group(&pool, "30c84267-methods").await;
    let (addr, _shutdown) = spawn_app_role(&pool).await;
    let name = format!("30c84267 method {}", Uuid::new_v4());

    let (status, body) = post(
        addr,
        agent,
        "/api/v1/methods",
        json!({
            "name": name,
            "technique_type": "characterization",
            "measures": "lattice constant",
            "capabilities": ["lattice_constant", "phase_identification"],
        }),
    )
    .await;
    assert_eq!(status, 200, "add_method: {body}");
    let method = uuid_at(&body, "method_id");
    assert_eq!(body["capabilities_linked"], 2, "add_method: {body}");
    assert_eq!(body["embedded"], true, "add_method: {body}");
    let links: i64 =
        sqlx::query_scalar("SELECT count(*) FROM method_capabilities WHERE method_id = $1")
            .bind(method)
            .fetch_one(&pool)
            .await
            .expect("count capability links");
    assert_eq!(links, 2, "both capability links committed with the method");

    let (status, body) = send(
        addr,
        agent,
        reqwest::Method::GET,
        "/api/v1/methods/search?query=lattice%20constant&technique_type=characterization&limit=50",
        None,
    )
    .await;
    assert_eq!(status, 200, "find_methods: {body}");
    let hit = body["methods"]
        .as_array()
        .expect("methods array")
        .iter()
        .find(|m| m["id"] == json!(method))
        .unwrap_or_else(|| panic!("find_methods must return the new method: {body}"));
    let mut caps: Vec<&str> = hit["capabilities"]
        .as_array()
        .expect("capabilities array")
        .iter()
        .filter_map(|c| c["capability"].as_str())
        .collect();
    caps.sort_unstable();
    assert_eq!(caps, vec!["lattice_constant", "phase_identification"]);
}

// ── The refusals the stamp brings ─────────────────────────────────────────

/// A `public` claim owned by `group` (not the world group), so the hypothesis
/// write gate admits exactly the members who write `group`, while any viewer
/// can read it.
async fn public_claim_in(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed public claim");
    let (visibility, owner): (String, Uuid) =
        sqlx::query_as("SELECT visibility, owner_group_id FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read the seeded claim back");
    assert_eq!(
        (visibility.as_str(), owner),
        ("public", group),
        "fixture: a public claim owned by the group"
    );
    id
}

/// Experiments filed against `hypothesis`, read as superuser.
async fn experiments_on(pool: &PgPool, hypothesis: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM experiments WHERE hypothesis_id = $1")
        .bind(hypothesis)
        .fetch_one(pool)
        .await
        .expect("count experiments")
}

/// Methods named `name`, read as superuser.
async fn methods_named(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM methods WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("count methods")
}

/// The role the ROL01 fixture attaches an agent to.
const ROL01_ROLE: &str = "role:test-experiment-loop-rol01";

/// A platform role with its role node (as `role_attached_agents.rs` seeds it).
async fn seed_role(pool: &PgPool, key: &str) {
    let node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type, role, labels) \
         VALUES ($1, uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), $2, 'role', \
                 'custom', ARRAY['role'])",
    )
    .bind(node)
    .bind(key)
    .execute(pool)
    .await
    .expect("role node");
    sqlx::query(
        "INSERT INTO platform_roles (key, elevates, reads_audit, role_node_id, description) \
         VALUES ($1, false, false, $2, 'test role')",
    )
    .bind(key)
    .bind(node)
    .execute(pool)
    .await
    .expect("platform role");
}

/// Attach `agent` to `role` through the maintenance definer, live from a few
/// seconds ago.
async fn attach_to_role(pool: &PgPool, role: &str, agent: Uuid) {
    let role = role.to_string();
    viewer_fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let _: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_attach_agent_to_role($1, $2, now() - interval '5 seconds', \
                                                         NULL, 'test attach')",
        )
        .bind(&role)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("the maintenance role attaches");
        (conn, ())
    })
    .await;
}

/// Grant `role` to `holder`, live from a few seconds ago, open-ended.
async fn grant_role(pool: &PgPool, role: &str, holder: Uuid) {
    let _: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now() - interval '5 seconds', NULL, NULL, \
                'test grant')",
    )
    .bind(role)
    .bind(holder)
    .fetch_one(pool)
    .await
    .expect("grant role");
}

/// The body's reason text, whichever key the error renders it under.
fn reason_of(body: &Value) -> String {
    body["details"]["reason"]
        .as_str()
        .or_else(|| body["reason"].as_str())
        .or_else(|| body["message"].as_str())
        .map_or_else(|| body.to_string(), str::to_string)
}

/// The ROL01 (migration 166) fixture. X is bound to human A and writes A's
/// group, but X is attached to a role nobody holds, so once armed the
/// database's per-statement check refuses X's first write on any table the
/// application role writes. Returns `(state, a, x, hypothesis)`, the
/// hypothesis public and owned by A's group.
///
/// The handlers are called directly with X's resolved viewer, as
/// `supersede_coded_denials_http.rs` drives its ROL01 pin: the HTTP bearer
/// layer refuses an operated agent's token before any handler runs, and what
/// is under test is how the handler maps the database's refusal. The
/// unstamped pool never ran the check at all (no principal).
async fn rol01_fixture(pool: &PgPool, label: &str) -> (AppState, Uuid, Uuid, Uuid) {
    seed_role(pool, ROL01_ROLE).await;
    let (a, ag) = viewer_fixture::seed_human_operator(pool, &format!("{label}-human-a")).await;
    let (x, _) = viewer_fixture::seed_agent_with_group(pool, &format!("{label}-agent-x")).await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, x, a)
            .await
            .expect("live link");
    }
    let hypothesis = public_claim_in(pool, a, ag, &format!("{label} hypothesis")).await;
    attach_to_role(pool, ROL01_ROLE, x).await;
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
    (app_role_state(pool).await, a, x, hypothesis)
}

/// ROL01 on the experiment loop: filing an experiment as an agent of an
/// unheld role is the coded 403 every write surface answers, with nothing
/// written. Before, the refusal came back as a 500, a server fault the
/// caller could not act on.
///
/// CONTROL: once A holds the role, the same request lands with its edge, so
/// the refusal was the role's and nothing else (not the hypothesis gate).
#[sqlx::test(migrations = "../../migrations")]
async fn a_role_attached_agent_without_its_holder_files_no_experiment(pool: PgPool) {
    let (state, a, x, hypothesis) = rol01_fixture(&pool, "30c84267-rol01-loop").await;

    let viewer = Viewer::resolve(&pool, x).await.expect("resolve");
    let e = create_as(&state, viewer, x, hypothesis)
        .await
        .expect_err("an agent of an unheld role may not file an experiment once armed");
    let (status, reason) = rendered(e).await;
    assert_eq!(status, 403, "{reason}");
    assert!(reason.starts_with("ROL01"), "the code is named: {reason}");
    assert!(
        !reason.contains(&x.to_string()),
        "the database's text (naming the agent) stays in the log: {reason}"
    );
    assert_eq!(
        experiments_on(&pool, hypothesis).await,
        0,
        "nothing written"
    );

    grant_role(&pool, ROL01_ROLE, a).await;
    let viewer = Viewer::resolve(&pool, x).await.expect("resolve");
    let created = create_as(&state, viewer, x, hypothesis)
        .await
        .unwrap_or_else(|e| panic!("CONTROL: A now holds the role: {e:?}"));
    let experiment = uuid_at(&created, "experiment_id");
    assert_eq!(
        edges(&pool, experiment, hypothesis, "tests_hypothesis").await,
        1
    );
}

/// ROL01 on the method catalog: `POST /api/v1/methods` as an agent of an
/// unheld role is the coded 403, with no method written.
///
/// CONTROL: once A holds the role, the same request lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_role_attached_agent_without_its_holder_adds_no_method(pool: PgPool) {
    let (state, a, x, _hypothesis) = rol01_fixture(&pool, "30c84267-rol01-method").await;
    let name = format!("30c84267 rol01 method {}", Uuid::new_v4());
    let request = || {
        Json(AddMethodRequest {
            name: name.clone(),
            technique_type: "characterization".into(),
            measures: None,
            resolution: None,
            limitations: None,
            required_equipment: None,
            conditions: None,
            capabilities: Some(vec!["lattice_constant".into()]),
        })
    };

    let viewer = Viewer::resolve(&pool, x).await.expect("resolve");
    let e = add_method(
        ViewerExtractor(viewer),
        State(state.clone()),
        bearer(x),
        request(),
    )
    .await
    .expect_err("an agent of an unheld role may not add a method once armed");
    let (status, reason) = rendered(e).await;
    assert_eq!(status, 403, "{reason}");
    assert!(reason.starts_with("ROL01"), "the code is named: {reason}");
    assert_eq!(methods_named(&pool, &name).await, 0, "nothing written");

    grant_role(&pool, ROL01_ROLE, a).await;
    let viewer = Viewer::resolve(&pool, x).await.expect("resolve");
    let Json(body) = add_method(
        ViewerExtractor(viewer),
        State(state.clone()),
        bearer(x),
        request(),
    )
    .await
    .unwrap_or_else(|e| panic!("CONTROL: A now holds the role: {e:?}"));
    assert_eq!(body["capabilities_linked"], 1, "CONTROL: {body}");
    assert_eq!(methods_named(&pool, &name).await, 1, "CONTROL: it landed");
}

fn bearer(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Agent,
        scopes: RW.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

async fn rendered(e: ApiError) -> (u16, String) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, reason_of(&body))
}

async fn create_as(
    state: &AppState,
    viewer: Viewer,
    caller: Uuid,
    hypothesis: Uuid,
) -> Result<Value, ApiError> {
    create_experiment(
        ViewerExtractor(viewer),
        State(state.clone()),
        bearer(caller),
        Json(CreateExperimentRequest {
            hypothesis_id: hypothesis,
            agent_id: None,
            method_ids: None,
            protocol: Some("30c84267 direct call".into()),
        }),
    )
    .await
    .map(|Json(v)| v)
}
