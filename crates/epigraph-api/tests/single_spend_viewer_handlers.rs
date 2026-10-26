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

// ── POST /api/v1/clusters and POST /api/v1/frames/:id/assign-claim ─────────

async fn frame_rows(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claim_frames WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count claim_frames")
}

/// `upsert_cluster` and `assign_claim_to_frame` spent their viewer on the FRAME
/// and never read the CLAIM they bind to it, so a `claims:admin` caller could
/// bind a claim it cannot read. Their siblings in the same file
/// (`reassign_claim`, and `forget_convention` in `conventions.rs`) already read
/// their claim through the viewer first. Now these two do: an unreadable claim
/// is 404 and no `claim_frames` row is written.
#[tokio::test(flavor = "multi_thread")]
async fn binding_a_claim_the_caller_cannot_read_to_a_frame_is_404_and_writes_nothing() {
    let (url, pool) = shared_pool().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(
        &pool,
        &["claims:read", "claims:write", "claims:admin"],
    )
    .await;
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "a12-frame-owner").await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['in','out']::text[]) RETURNING id",
    )
    .bind(format!("a12-frame-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let http = reqwest::Client::new();

    for (visibility, readable) in [("public", true), ("group", false)] {
        let content = format!("a12 frame target {visibility} {}", Uuid::new_v4());
        let seed = || async {
            if readable {
                viewer_fixture::seed_public_claim(&pool, owner, &content).await
            } else {
                viewer_fixture::seed_group_claim(&pool, owner, group, &content).await
            }
        };

        // ── assign-claim ──
        let claim = seed().await;
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
                "calibration ({visibility}): assign-claim must succeed"
            );
            assert_eq!(rows, 1, "calibration: the binding must land");
        } else {
            assert_eq!(
                status, 404,
                "binding a claim the caller cannot read must be 404, got {status}"
            );
            assert_eq!(rows, 0, "a refused assign-claim must write no binding");
        }

        // ── clusters ──
        let claim = seed().await;
        let status = http
            .post(format!("http://{addr}/api/v1/clusters"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "claim_id": claim,
                "cluster_label": format!("a12-{}", Uuid::new_v4()),
            }))
            .send()
            .await
            .expect("clusters request")
            .status()
            .as_u16();
        let rows = frame_rows(&pool, claim).await;
        if readable {
            assert_eq!(
                status, 201,
                "calibration ({visibility}): clusters must succeed"
            );
            assert_eq!(rows, 1, "calibration: the cluster binding must land");
        } else {
            assert_eq!(
                status, 404,
                "clustering a claim the caller cannot read must be 404, got {status}"
            );
            assert_eq!(rows, 0, "a refused cluster upsert must write no binding");
        }
    }
}
