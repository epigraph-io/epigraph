#![cfg(feature = "db")]
//! The experiment write routes attribute what they write to the AUTHENTICATED
//! CALLER, never to an agent the request body names (backlog d817613e,
//! follow-up of R-51/R-52/R-52a; the evidence-author rule of 2026-10-22).
//!
//! * `POST /api/v1/experiments/new` records `experiments.created_by`;
//! * `POST /api/v1/experiments/:eid/results/:rid/analyze` records
//!   `analyses.agent_id` and the BBA's `source_agent_id` on the hypothesis.
//!
//! Both took that author from the body's `agent_id`, so a caller with
//! `claims:write` on the hypothesis could file an experiment, or evidence on
//! the hypothesis, in another agent's name. Now an omitted `agent_id` is the
//! caller's own and a named one that is not the caller is `403`, with nothing
//! written. The forging caller here is a `writer` member of the hypothesis's
//! group, so it PASSES the hypothesis gate: the refusal is the author rule's.
//!
//! `POST /api/v1/experiments/design` writes nothing but echoes the body's
//! `hypothesis_id`; it now reads that hypothesis through the caller's viewer
//! like every R-51 route, so a hidden hypothesis is the same 404 as a missing
//! one.
//!
//! The binding is Rust logic in the handlers, not row security, so these arms
//! use the same superuser-connected harness as `experiment_hypothesis_gate.rs`.
mod common;
mod viewer_fixture;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::SocketAddr;
use uuid::Uuid;

struct World {
    pool: PgPool,
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    /// Admin of the hypothesis's group.
    owner: Uuid,
    /// `writer` member of that group: passes the hypothesis write gate.
    writer: Uuid,
    /// A member of its own group only: cannot read the hypothesis.
    stranger: Uuid,
    hypothesis: Uuid,
}

async fn world(label: &str) -> World {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    let (addr, shutdown) = common::spawn_app(&url).await;
    let (owner, group) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-owner")).await;
    let (writer, _) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-writer")).await;
    let (stranger, _) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-stranger")).await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(group)
    .bind(writer)
    .execute(&pool)
    .await
    .expect("writer membership");
    let hypothesis = viewer_fixture::seed_group_claim(
        &pool,
        owner,
        group,
        &format!("{label} hypothesis {}", Uuid::new_v4()),
    )
    .await;
    World {
        pool,
        addr,
        _shutdown: shutdown,
        owner,
        writer,
        stranger,
        hypothesis,
    }
}

const RW: &[&str] = &["claims:read", "claims:write"];

async fn post(
    addr: SocketAddr,
    agent: Uuid,
    path: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let token = common::mint_token_with_agent(RW, agent);
    let res = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(serde_json::Value::Null))
}

/// The refusal is the author rule's: not the scope 403, not `not_owner`.
fn assert_author_refused(status: u16, body: &serde_json::Value, what: &str) {
    assert_eq!(
        status, 403,
        "{what}: naming another agent as the author must be 403, got {status} {body}"
    );
    assert_eq!(body["error"], "Forbidden", "{what}: {body}");
    let reason = body["details"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("agent_id must be the authenticated caller"),
        "{what}: the 403 names the author rule, not a scope or ownership check: {body}"
    );
}

async fn created_by_on(pool: &PgPool, hypothesis: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT created_by FROM experiments WHERE hypothesis_id = $1")
        .bind(hypothesis)
        .fetch_all(pool)
        .await
        .expect("experiments")
}

// ── POST /api/v1/experiments/new ───────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn creating_an_experiment_is_attributed_to_the_caller() {
    let w = world("d817-new").await;

    // A writer of the hypothesis names the group's admin as the creator.
    let (status, body) = post(
        w.addr,
        w.writer,
        "/api/v1/experiments/new",
        serde_json::json!({ "hypothesis_id": w.hypothesis, "agent_id": w.owner }),
    )
    .await;
    assert_author_refused(status, &body, "new, naming another agent");
    assert!(
        created_by_on(&w.pool, w.hypothesis).await.is_empty(),
        "a refused create records no experiment"
    );

    // Omitted: the caller's own.
    let (status, body) = post(
        w.addr,
        w.writer,
        "/api/v1/experiments/new",
        serde_json::json!({ "hypothesis_id": w.hypothesis }),
    )
    .await;
    assert_eq!(status, 200, "an omitted agent_id is the caller's: {body}");
    assert_eq!(
        created_by_on(&w.pool, w.hypothesis).await,
        vec![w.writer],
        "the experiment is created by the caller"
    );

    // Named as itself: unchanged.
    let (status, body) = post(
        w.addr,
        w.writer,
        "/api/v1/experiments/new",
        serde_json::json!({ "hypothesis_id": w.hypothesis, "agent_id": w.writer }),
    )
    .await;
    assert_eq!(status, 200, "naming itself is admitted: {body}");
    assert_eq!(
        created_by_on(&w.pool, w.hypothesis).await,
        vec![w.writer, w.writer]
    );
}

// ── POST /api/v1/experiments/:eid/results/:rid/analyze ─────────────────────

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

async fn ensure_hypothesis_frame(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO frames (name, hypotheses) VALUES ('hypothesis_assessment', \
         ARRAY['true','false']::text[]) ON CONFLICT (name) DO NOTHING",
    )
    .execute(pool)
    .await
    .expect("seed hypothesis_assessment frame");
}

/// Everything an analyze writes, by author: (error-derived BBAs on the
/// hypothesis authored by `agent`, analyses authored by `agent`, every
/// `provides_evidence` edge on the hypothesis, the experiment's status).
async fn footprint(
    pool: &PgPool,
    hypothesis: Uuid,
    experiment: Uuid,
    agent: Uuid,
) -> (i64, i64, i64, String) {
    let bbas: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 \
         AND combination_method = 'error_derived' AND source_agent_id = $2",
    )
    .bind(hypothesis)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("count BBAs");
    let analyses: i64 = sqlx::query_scalar("SELECT count(*) FROM analyses WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("count analyses");
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'provides_evidence'",
    )
    .bind(hypothesis)
    .fetch_one(pool)
    .await
    .expect("count edges");
    let status: String = sqlx::query_scalar("SELECT status FROM experiments WHERE id = $1")
        .bind(experiment)
        .fetch_one(pool)
        .await
        .expect("experiment status");
    (bbas, analyses, edges, status)
}

fn analyze_body(agent: Option<Uuid>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "direction": "supports",
        "scope_limitations": [],
        "expected_value": 0.0,
    });
    if let Some(a) = agent {
        body["agent_id"] = serde_json::json!(a);
    }
    body
}

#[tokio::test(flavor = "multi_thread")]
async fn analyzing_a_result_is_attributed_to_the_caller() {
    let w = world("d817-analyze").await;
    ensure_hypothesis_frame(&w.pool).await;
    let (experiment, result) = seed_experiment(&w.pool, w.hypothesis, w.owner).await;
    let path = format!("/api/v1/experiments/{experiment}/results/{result}/analyze");

    // A writer of the hypothesis files the analysis in the admin's name.
    let before = footprint(&w.pool, w.hypothesis, experiment, w.owner).await;
    let (status, body) = post(w.addr, w.writer, &path, analyze_body(Some(w.owner))).await;
    assert_author_refused(status, &body, "analyze, naming another agent");
    assert_eq!(
        footprint(&w.pool, w.hypothesis, experiment, w.owner).await,
        before,
        "a refused analyze writes no BBA or analysis in the named agent's name, no edge, \
         and no status change"
    );
    assert_eq!(before.3, "collecting", "fixture: untouched experiment");

    // Omitted: the caller's own, on the BBA and on the analysis row.
    let (status, body) = post(w.addr, w.writer, &path, analyze_body(None)).await;
    assert_eq!(status, 200, "an omitted agent_id is the caller's: {body}");
    let (bbas, analyses, edges, status) =
        footprint(&w.pool, w.hypothesis, experiment, w.writer).await;
    assert_eq!(
        (bbas, analyses, edges, status.as_str()),
        (1, 1, 1, "complete"),
        "the caller authors the BBA and the analysis"
    );
    let (owner_bbas, owner_analyses, _, _) =
        footprint(&w.pool, w.hypothesis, experiment, w.owner).await;
    assert_eq!(
        (owner_bbas, owner_analyses),
        (0, 0),
        "nothing is attributed to the group admin"
    );
}

// ── POST /api/v1/experiments/design ────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn designing_on_a_hidden_hypothesis_is_the_missing_hypothesis_404() {
    let w = world("d817-design").await;
    let design =
        |hypothesis: Uuid| serde_json::json!({ "hypothesis_id": hypothesis, "method_ids": [] });
    let path = "/api/v1/experiments/design";

    let (hidden_status, hidden_body) = post(w.addr, w.stranger, path, design(w.hypothesis)).await;
    let missing = Uuid::new_v4();
    let (missing_status, missing_body) = post(w.addr, w.stranger, path, design(missing)).await;
    assert_eq!(
        hidden_status, 404,
        "a hypothesis the caller cannot read is 404, got {hidden_status} {hidden_body}"
    );
    assert_eq!(missing_status, 404, "{missing_body}");
    assert_eq!(
        hidden_body
            .to_string()
            .replace(&w.hypothesis.to_string(), "<id>"),
        missing_body
            .to_string()
            .replace(&missing.to_string(), "<id>"),
        "a hidden hypothesis answers exactly as a missing one"
    );

    let (status, body) = post(w.addr, w.owner, path, design(w.hypothesis)).await;
    assert_eq!(status, 200, "calibration: the owner designs: {body}");
    assert_eq!(body["hypothesis_id"], w.hypothesis.to_string(), "{body}");
}
