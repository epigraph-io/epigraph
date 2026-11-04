#![cfg(feature = "db")]
//! Handlers that held a `Viewer` and spent it on something other than the row
//! they act on or return (backlog 4815dcf7, `F-single-spend-handlers-unreviewed`).
//!
//! Each arm here is a handler the review behind `viewer_spend_lint.rs` found
//! spending its viewer on a side read while the read or write that matters ran
//! without it. Every arm asserts the EFFECT (rows written, nodes returned) and
//! carries a calibration call that must succeed, so a refusal cannot come from
//! a broken fixture.
//!
//! The test database connects as a superuser, which bypasses row security. What
//! these arms discriminate is therefore the viewer's in-query predicate, which
//! applies whatever the connection's role.
mod common;
mod viewer_fixture;

use std::collections::BTreeSet;

use axum::{extract::State, Json};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::graph_query::{execute_graph_query, GraphQueryRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn shared_pool() -> (String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    (url, pool)
}

// ── POST /api/v1/experiments/:eid/results/:rid/analyze ─────────────────────

/// An experiment on `hypothesis` with one result; returns `(experiment, result)`.
async fn seed_experiment(pool: &PgPool, hypothesis: Uuid, creator: Uuid) -> (Uuid, Uuid) {
    let experiment: Uuid = sqlx::query_scalar(
        "INSERT INTO experiments (hypothesis_id, created_by, status) \
         VALUES ($1, $2, 'collecting') RETURNING id",
    )
    .bind(hypothesis)
    .bind(creator)
    .fetch_one(pool)
    .await
    .expect("seed experiment");
    let result: Uuid = sqlx::query_scalar(
        "INSERT INTO experiment_results (experiment_id, data_source, raw_measurements, measurement_count) \
         VALUES ($1, 'instrument', $2, 2) RETURNING id",
    )
    .bind(experiment)
    .bind(serde_json::json!([
        {"value": 1.2, "random_error": 0.05, "systematic_error": 0.02},
        {"value": 1.1, "random_error": 0.05, "systematic_error": 0.02}
    ]))
    .fetch_one(pool)
    .await
    .expect("seed result");
    (experiment, result)
}

/// What `analyze` writes against the hypothesis: (error-derived BBAs,
/// `provides_evidence` edges, the experiment's status).
async fn analyze_footprint(
    pool: &PgPool,
    hypothesis: Uuid,
    experiment: Uuid,
) -> (i64, i64, String) {
    let bbas: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions \
         WHERE claim_id = $1 AND combination_method = 'error_derived'",
    )
    .bind(hypothesis)
    .fetch_one(pool)
    .await
    .expect("count BBAs");
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges \
         WHERE target_id = $1 AND relationship = 'provides_evidence'",
    )
    .bind(hypothesis)
    .fetch_one(pool)
    .await
    .expect("count edges");
    let status: String = sqlx::query_scalar("SELECT status FROM experiments WHERE id = $1")
        .bind(experiment)
        .fetch_one(pool)
        .await
        .expect("read experiment status");
    (bbas, edges, status)
}

/// `analyze_result` spent its viewer on the measurement-source grounding check
/// and on choosing the evidence frame, and never read the hypothesis it files
/// evidence on. A caller who cannot read the hypothesis claim could still put
/// a BBA and a `provides_evidence` edge on it. Now the hypothesis is read as
/// the caller first: an unreadable one is 404, exactly like a missing one, and
/// nothing is written.
#[tokio::test(flavor = "multi_thread")]
async fn analyze_on_a_hypothesis_the_caller_cannot_read_is_404_and_writes_nothing() {
    let (url, pool) = shared_pool().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    sqlx::query(
        "INSERT INTO frames (name, hypotheses) VALUES ('hypothesis_assessment', \
         ARRAY['true','false']::text[]) ON CONFLICT (name) DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("seed hypothesis_assessment frame");

    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "a12-analyze-owner").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "a12-analyze-stranger").await;
    let hypothesis = viewer_fixture::seed_group_claim(
        &pool,
        owner,
        group,
        &format!("a12 analyze hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let http = reqwest::Client::new();
    let analyze = |agent: Uuid, experiment: Uuid, result: Uuid| {
        let http = http.clone();
        async move {
            let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
            http.post(format!(
                "http://{addr}/api/v1/experiments/{experiment}/results/{result}/analyze"
            ))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "agent_id": agent,
                "direction": "supports",
                "scope_limitations": [],
                "expected_value": 0.0,
            }))
            .send()
            .await
            .expect("analyze request")
            .status()
            .as_u16()
        }
    };

    // The stranger: a member of its own group only.
    let (experiment, result) = seed_experiment(&pool, hypothesis, owner).await;
    let before = analyze_footprint(&pool, hypothesis, experiment).await;
    let status = analyze(stranger, experiment, result).await;
    let after = analyze_footprint(&pool, hypothesis, experiment).await;
    assert_eq!(
        status, 404,
        "analyzing onto a hypothesis the caller cannot read must be 404, got {status}"
    );
    assert_eq!(
        after, before,
        "a refused analyze must write no BBA, no edge and no status change"
    );

    // CALIBRATION: the hypothesis's owner, same route, same shape of request.
    let (experiment, result) = seed_experiment(&pool, hypothesis, owner).await;
    let status = analyze(owner, experiment, result).await;
    let (bbas, edges, exp_status) = analyze_footprint(&pool, hypothesis, experiment).await;
    assert_eq!(status, 200, "calibration: the owner's analyze must succeed");
    assert!(
        bbas >= 1 && edges >= 1 && exp_status == "complete",
        "calibration: the owner's analyze must land (bbas {bbas}, edges {edges}, status {exp_status})"
    );
}

/// The analyze route takes the experiment and the result from two path
/// segments and loaded each on its own, so the hypothesis gate above covered
/// the EXPERIMENT only. A caller who owns one experiment could name another
/// group's result under it: the hidden result's measurements were analyzed onto
/// the caller's own hypothesis (the response's masses are derived from them)
/// and the hidden result was linked and marked complete. A result that does not
/// belong to the named experiment is now the same 404 as a missing one, before
/// the hypothesis gate and before any write.
#[tokio::test(flavor = "multi_thread")]
async fn analyze_refuses_a_result_that_belongs_to_another_experiment() {
    let (url, pool) = shared_pool().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    sqlx::query(
        "INSERT INTO frames (name, hypotheses) VALUES ('hypothesis_assessment', \
         ARRAY['true','false']::text[]) ON CONFLICT (name) DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("seed hypothesis_assessment frame");

    // The caller's own experiment, on a hypothesis it can read.
    let (caller, caller_group) =
        viewer_fixture::seed_agent_with_group(&pool, "a12-idor-caller").await;
    let own_hypothesis = viewer_fixture::seed_group_claim(
        &pool,
        caller,
        caller_group,
        &format!("a12 idor own hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let (own_experiment, own_result) = seed_experiment(&pool, own_hypothesis, caller).await;
    // Another group's experiment and result, on a hypothesis the caller cannot read.
    let (other, other_group) = viewer_fixture::seed_agent_with_group(&pool, "a12-idor-other").await;
    let hidden_hypothesis = viewer_fixture::seed_group_claim(
        &pool,
        other,
        other_group,
        &format!("a12 idor hidden hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let (hidden_experiment, hidden_result) = seed_experiment(&pool, hidden_hypothesis, other).await;

    let result_footprint = |result: Uuid| {
        let pool = pool.clone();
        async move {
            let status: String =
                sqlx::query_scalar("SELECT status FROM experiment_results WHERE id = $1")
                    .bind(result)
                    .fetch_one(&pool)
                    .await
                    .expect("read result status");
            let analyzed: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'analyzes'",
            )
            .bind(result)
            .fetch_one(&pool)
            .await
            .expect("count analyzes edges");
            (status, analyzed)
        }
    };
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], caller);
    let http = reqwest::Client::new();
    let analyze = |experiment: Uuid, result: Uuid| {
        let (http, token) = (http.clone(), token.clone());
        async move {
            let res = http
                .post(format!(
                    "http://{addr}/api/v1/experiments/{experiment}/results/{result}/analyze"
                ))
                .bearer_auth(&token)
                .json(&serde_json::json!({
                    "agent_id": caller,
                    "direction": "supports",
                    "scope_limitations": [],
                    "expected_value": 0.0,
                }))
                .send()
                .await
                .expect("analyze request");
            let status = res.status().as_u16();
            let body: serde_json::Value = res.json().await.unwrap_or(serde_json::Value::Null);
            (status, body)
        }
    };
    // A 404 body with the named result id masked, so two refusals naming
    // different ids can be compared.
    let masked = |body: &serde_json::Value, id: Uuid| -> String {
        body.to_string().replace(&id.to_string(), "<id>")
    };

    let before_hidden = result_footprint(hidden_result).await;
    let before_own = analyze_footprint(&pool, own_hypothesis, own_experiment).await;
    let (status, body) = analyze(own_experiment, hidden_result).await;
    assert_eq!(
        status, 404,
        "a result named under an experiment it does not belong to must be 404, got {status}"
    );
    // ORACLE: the refusal is the same 404 as a result that does not exist.
    let missing = Uuid::new_v4();
    let (missing_status, missing_body) = analyze(own_experiment, missing).await;
    assert_eq!(missing_status, 404, "calibration: a missing result is 404");
    assert_eq!(
        masked(&body, hidden_result),
        masked(&missing_body, missing),
        "a mismatched result must be indistinguishable from a missing one"
    );
    assert_eq!(
        body["details"]["entity"], "result",
        "the refusal names the result, not anything behind it: {body}"
    );
    assert_eq!(
        result_footprint(hidden_result).await,
        before_hidden,
        "the other experiment's result must be neither linked nor marked complete"
    );
    assert_eq!(
        analyze_footprint(&pool, own_hypothesis, own_experiment).await,
        before_own,
        "nothing derived from the other result may land on the caller's hypothesis"
    );

    // ORDER: the pairing is checked BEFORE the hypothesis read. The caller's
    // own result named under the hidden experiment is the `result` 404; were
    // the pairing checked after the gate, the hidden experiment's unreadable
    // hypothesis would answer first with a `hypothesis` 404.
    let before_own_result = result_footprint(own_result).await;
    let (status, body) = analyze(hidden_experiment, own_result).await;
    assert_eq!(
        status, 404,
        "a mismatched pair under a hidden experiment is 404"
    );
    assert_eq!(
        body["details"]["entity"], "result",
        "the pairing must refuse before the hypothesis gate runs: {body}"
    );
    assert_eq!(
        result_footprint(own_result).await,
        before_own_result,
        "the refused pair must not touch the caller's own result"
    );

    // CALIBRATION: the caller's own result under its own experiment, and the
    // footprint above sees exactly what it writes (an `analyzes` edge onto the
    // result, the result marked complete), so its "unchanged" is not vacuous.
    let (status, _) = analyze(own_experiment, own_result).await;
    assert_eq!(status, 200, "calibration: the matching pair must succeed");
    assert_ne!(
        before_own_result.0, "complete",
        "calibration: a fresh result is not complete before its analyze"
    );
    assert_eq!(
        result_footprint(own_result).await,
        ("complete".to_string(), 1),
        "calibration: the matching analyze links the result and marks it complete"
    );
}

// ── POST /api/v1/clusters and POST /api/v1/frames/:id/assign-claim ─────────

async fn frame_rows(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claim_frames WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count claim_frames")
}

/// A `claims:admin` caller, an owner with a private group, and an http client.
async fn frame_world(pool: &PgPool) -> (String, Uuid, Uuid) {
    let (token, _) = common::test_bearer_token_with_seeded_client(
        pool,
        &["claims:read", "claims:write", "claims:admin"],
    )
    .await;
    let (owner, group) = viewer_fixture::seed_agent_with_group(pool, "a12-frame-owner").await;
    (token, owner, group)
}

async fn seed_frame_target(pool: &PgPool, owner: Uuid, group: Uuid, readable: bool) -> Uuid {
    let content = format!("a12 frame target {readable} {}", Uuid::new_v4());
    if readable {
        viewer_fixture::seed_public_claim(pool, owner, &content).await
    } else {
        viewer_fixture::seed_group_claim(pool, owner, group, &content).await
    }
}

/// `assign_claim_to_frame` spent its viewer on the FRAME and never read the
/// CLAIM it binds to it, so a `claims:admin` caller could bind a claim it cannot
/// read. Its siblings (`reassign_claim`, and `forget_convention` in
/// `conventions.rs`) already read their claim through the viewer first. Now it
/// does: an unreadable claim is 404 and no `claim_frames` row is written.
#[tokio::test(flavor = "multi_thread")]
async fn assigning_a_claim_the_caller_cannot_read_to_a_frame_is_404_and_writes_nothing() {
    let (url, pool) = shared_pool().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, owner, group) = frame_world(&pool).await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['in','out']::text[]) RETURNING id",
    )
    .bind(format!("a12-frame-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let http = reqwest::Client::new();

    for readable in [true, false] {
        let claim = seed_frame_target(&pool, owner, group, readable).await;
        let status = http
            .post(format!("http://{addr}/api/v1/frames/{frame}/assign-claim"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"claim_id": claim, "hypothesis_index": 0}))
            .send()
            .await
            .expect("assign-claim request")
            .status()
            .as_u16();
        let rows = frame_rows(&pool, claim).await;
        if readable {
            assert_eq!(
                status, 201,
                "calibration: assign-claim on a public claim must succeed"
            );
            assert_eq!(rows, 1, "calibration: the binding must land");
        } else {
            assert_eq!(
                status, 404,
                "binding a claim the caller cannot read must be 404, got {status}"
            );
            assert_eq!(rows, 0, "a refused assign-claim must write no binding");
        }
    }
}

async fn cluster_frames(pool: &PgPool, label: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM frames WHERE name = $1")
        .bind(format!("cluster:{label}"))
        .fetch_one(pool)
        .await
        .expect("count cluster frames")
}

/// `upsert_cluster` has the same shape as `assign_claim_to_frame`, and its
/// FIRST write is the find-or-create of the `cluster:<label>` frame. A refused
/// upsert must write neither that frame nor the binding.
#[tokio::test(flavor = "multi_thread")]
async fn clustering_a_claim_the_caller_cannot_read_is_404_and_creates_nothing() {
    let (url, pool) = shared_pool().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, owner, group) = frame_world(&pool).await;
    let http = reqwest::Client::new();

    for readable in [true, false] {
        let claim = seed_frame_target(&pool, owner, group, readable).await;
        let label = format!("a12-{}", Uuid::new_v4());
        let status = http
            .post(format!("http://{addr}/api/v1/clusters"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"claim_id": claim, "cluster_label": label}))
            .send()
            .await
            .expect("clusters request")
            .status()
            .as_u16();
        let (rows, frames) = (
            frame_rows(&pool, claim).await,
            cluster_frames(&pool, &label).await,
        );
        if readable {
            assert_eq!(
                status, 201,
                "calibration: clustering a public claim must succeed"
            );
            assert_eq!(
                (rows, frames),
                (1, 1),
                "calibration: the cluster frame and the binding must land"
            );
        } else {
            assert_eq!(
                status, 404,
                "clustering a claim the caller cannot read must be 404, got {status}"
            );
            assert_eq!(
                (rows, frames),
                (0, 0),
                "a refused cluster upsert must create no `cluster:<label>` frame and no binding"
            );
        }
    }
}

// ── POST /api/v1/graph/query ───────────────────────────────────────────────

/// A claim carrying `properties.probe`, public or private to `group`.
async fn seed_probe(pool: &PgPool, agent: Uuid, group: Option<Uuid>, probe: &str) -> Uuid {
    let content = format!("a12 graph query probe {probe} {}", Uuid::new_v4());
    let claim = match group {
        Some(g) => viewer_fixture::seed_group_claim(pool, agent, g, &content).await,
        None => viewer_fixture::seed_public_claim(pool, agent, &content).await,
    };
    sqlx::query(
        "UPDATE claims SET properties = jsonb_build_object('probe', $2::text) WHERE id = $1",
    )
    .bind(claim)
    .bind(probe)
    .execute(pool)
    .await
    .expect("tag probe claim");
    claim
}

async fn run_as(pool: &PgPool, viewer: Viewer, query: String) -> BTreeSet<Uuid> {
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    let Json(out) = execute_graph_query(
        ViewerExtractor(viewer),
        State(state),
        Json(GraphQueryRequest {
            query,
            agent_id: None,
        }),
    )
    .await
    .expect("graph query succeeds");
    out.nodes.into_iter().map(|n| n.id).collect()
}

/// `execute_graph_query` spent its viewer on the final node projection
/// (`load_subgraph`) only. The id selection and the `edges` walk that decide
/// WHICH nodes are projected ran with no predicate. Three consequences, one arm
/// each below.
struct GraphWorld {
    owner: Uuid,
    group: Uuid,
    stranger: Uuid,
}

async fn graph_world(pool: &PgPool) -> GraphWorld {
    let (owner, group) = viewer_fixture::seed_agent_with_group(pool, "a12-gq-owner").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(pool, "a12-gq-stranger").await;
    GraphWorld {
        owner,
        group,
        stranger,
    }
}

async fn viewer_of(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve viewer")
}

/// A caller-chosen property predicate matched a claim the caller cannot read,
/// and the walk from it returned its readable neighbour. The edge is forced
/// public (`viewer_fixture::seed_edge_owned_by`) so only the anchor's own
/// predicate can exclude the row.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_query_does_not_anchor_on_a_claim_the_caller_cannot_read(pool: PgPool) {
    let w = graph_world(&pool).await;
    let world = viewer_fixture::world_group(&pool).await;
    let probe = Uuid::new_v4().to_string();
    let private_anchor = seed_probe(&pool, w.owner, Some(w.group), &probe).await;
    let target = viewer_fixture::seed_public_claim(&pool, w.owner, "a12 gq anchor target").await;
    viewer_fixture::seed_edge_owned_by(&pool, private_anchor, target, "public", world).await;
    let q = format!("MATCH (n:claim)-[:supports]->(m:claim) WHERE n.probe = '{probe}' RETURN *");
    assert_eq!(
        run_as(&pool, viewer_of(&pool, w.owner).await, q.clone()).await,
        BTreeSet::from([target]),
        "calibration: the anchor's owner reaches its target"
    );
    let got = run_as(&pool, viewer_of(&pool, w.stranger).await, q).await;
    assert!(
        got.is_empty(),
        "a property predicate must not anchor on a claim the caller cannot read; got {got:?}"
    );
}

/// The walk crossed edges the caller cannot read, so a readable claim two hops
/// away came back through an unreadable one: public anchor -> (group edge) ->
/// group claim -> (group edge) -> public claim.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_query_does_not_walk_edges_the_caller_cannot_read(pool: PgPool) {
    let w = graph_world(&pool).await;
    let probe = Uuid::new_v4().to_string();
    let anchor = seed_probe(&pool, w.owner, None, &probe).await;
    let middle = viewer_fixture::seed_group_claim(&pool, w.owner, w.group, "a12 gq middle").await;
    let far = viewer_fixture::seed_public_claim(&pool, w.owner, "a12 gq far").await;
    viewer_fixture::seed_edge(&pool, anchor, middle).await;
    viewer_fixture::seed_edge(&pool, middle, far).await;
    let q =
        format!("MATCH (n:claim)-[:supports*2..2]->(m:claim) WHERE n.probe = '{probe}' RETURN *");
    assert!(
        run_as(&pool, viewer_of(&pool, w.owner).await, q.clone())
            .await
            .contains(&far),
        "calibration: the owner walks through its own claim to the far one"
    );
    let got = run_as(&pool, viewer_of(&pool, w.stranger).await, q).await;
    assert!(
        !got.contains(&far),
        "the walk must not cross edges the caller cannot read; got {got:?}"
    );
}

/// Unreadable rows filled the LIMIT window before the projection dropped them:
/// the newest probe row is private, an older one public, and `LIMIT 1` came
/// back empty for the stranger.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_query_limit_counts_only_rows_the_caller_can_read(pool: PgPool) {
    let w = graph_world(&pool).await;
    let probe = Uuid::new_v4().to_string();
    let older_public = seed_probe(&pool, w.owner, None, &probe).await;
    let newer_private = seed_probe(&pool, w.owner, Some(w.group), &probe).await;
    sqlx::query("UPDATE claims SET created_at = now() - interval '1 day' WHERE id = $1")
        .bind(older_public)
        .execute(&pool)
        .await
        .expect("age the public probe");
    let q = format!("MATCH (n:claim) WHERE n.probe = '{probe}' RETURN * LIMIT 1");
    assert_eq!(
        run_as(&pool, viewer_of(&pool, w.owner).await, q.clone()).await,
        BTreeSet::from([newer_private]),
        "calibration: the owner's window holds its newest probe row"
    );
    assert_eq!(
        run_as(&pool, viewer_of(&pool, w.stranger).await, q).await,
        BTreeSet::from([older_public]),
        "LIMIT must count only rows the caller can read"
    );
}
