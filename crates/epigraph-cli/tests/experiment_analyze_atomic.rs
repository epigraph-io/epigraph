//! `experiment analyze` is one transaction (backlog 2e64b8a2): the analysis
//! node, its `analyzes` and `provides_evidence` edges, the error-derived BBA
//! and the two status writes commit together or not at all.
//!
//! Each statement used to run on the pool by itself, so an analyze that
//! failed part-way (here: the evidence frame is missing, which is read after
//! the analysis and its edges were written) left an analysis that
//! `provides_evidence` to the hypothesis with no BBA behind it. That orphan
//! satisfies the promotion gate's "completed experiment with analysis" count
//! without filing any evidence. The status writes discarded their errors.
//!
//! The real binary runs via `CARGO_BIN_EXE_experiment` against the
//! `#[sqlx::test]` database, with both DSN variables set explicitly (see
//! `hypothesis_promote_moves_bba.rs`).

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

#[sqlx::test(migrations = "../../migrations")]
async fn an_analyze_that_fails_part_way_writes_nothing(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "2e64b8a2-analyze").await;
    let claim = fixture::seed_public_claim(&pool, agent, "2e64b8a2 hypothesis analyzed").await;
    // No `hypothesis_assessment` frame: the analyze fails at the frame
    // lookup, after the analysis node and its edges.
    let experiment: Uuid = sqlx::query_scalar(
        "INSERT INTO experiments (hypothesis_id, created_by, status) \
         VALUES ($1, $2, 'running') RETURNING id",
    )
    .bind(claim)
    .bind(agent)
    .fetch_one(&pool)
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
    .fetch_one(&pool)
    .await
    .expect("seed result");

    let url = fixture::database_url_for(&pool).await;
    let out = Command::new(env!("CARGO_BIN_EXE_experiment"))
        .args([
            "analyze",
            &result.to_string(),
            "--direction",
            "supports",
            "--agent-id",
            &agent.to_string(),
        ])
        .env("DATABASE_URL", &url)
        .env("MAINTENANCE_DATABASE_URL", &url)
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn experiment");
    assert!(
        !out.status.success(),
        "CALIBRATION: with no evidence frame the analyze must fail; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let analyses: i64 = sqlx::query_scalar("SELECT count(*) FROM analyses WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("count analyses");
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_type = 'analysis' \
          AND (target_id = $1 OR target_id = $2)",
    )
    .bind(claim)
    .bind(result)
    .fetch_one(&pool)
    .await
    .expect("count analysis edges");
    let bbas: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("count BBAs");
    let statuses: (String, String) = sqlx::query_as(
        "SELECT e.status, r.status FROM experiments e JOIN experiment_results r \
           ON r.experiment_id = e.id WHERE r.id = $1",
    )
    .bind(result)
    .fetch_one(&pool)
    .await
    .expect("read statuses");
    assert_eq!(
        (analyses, edges, bbas),
        (0, 0, 0),
        "a failed analyze leaves no analysis, no edge and no BBA"
    );
    assert_ne!(
        statuses.0, "complete",
        "the experiment is not marked complete"
    );
    assert_ne!(statuses.1, "complete", "the result is not marked complete");
}
