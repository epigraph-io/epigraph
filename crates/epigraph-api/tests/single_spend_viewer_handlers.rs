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
