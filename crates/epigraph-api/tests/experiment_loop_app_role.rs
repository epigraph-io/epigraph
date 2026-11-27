//! The experiment loop and the method catalog over HTTP on the APPLICATION
//! ROLE (backlog 30c84267).
//!
//! # What was wrong, measured before this file
//!
//! `routes/experiment_loop.rs` gated every route on the hypothesis through the
//! caller's viewer (R-51) and then wrote on `state.db_pool`. On a production
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
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;
mod viewer_fixture;

use epigraph_api::embedding_restore::EmbeddingProviderKind;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

const RW: &[&str] = &["claims:read", "claims:write"];

/// The app under test: raw and stamped pools both `epigraph_app`, with a mock
/// embedder declared as the provider that owns the stored vector columns (so
/// `POST /api/v1/methods` stores a method embedding `find_methods` can rank).
async fn spawn_app_role(pool: &PgPool) -> (SocketAddr, oneshot::Sender<()>) {
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
    let app = epigraph_api::routes::create_router(state);
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
