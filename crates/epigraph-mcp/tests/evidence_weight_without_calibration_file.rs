//! The MCP evidence write paths must take their evidence-type weight from the
//! calibration the process SERVES, not from a `calibration.toml` that happens
//! to sit in the working directory (backlog d83b998a).
//!
//! # The defect
//!
//! `tools/claims.rs` (`submit_claim`, `update_with_evidence`) and
//! `tools/workflows.rs` (`report_workflow_outcome`) each carried a private
//! `load_evidence_type_weight` that read the file `CALIBRATION_PATH` named, else
//! `calibration.toml` in the cwd, and on any failure returned 0.7. Every other
//! DS path resolves through `CalibrationConfig::cached()`: the
//! `CALIBRATION_PATH` file when it loads, else the copy compiled into the
//! binary. A server started with `CALIBRATION_PATH` unset from a directory
//! without the file (every deploy that does not happen to run from a checkout)
//! therefore baked `source_strength = 0.7` into each `auto_wire` BBA, where
//! the shipped calibration says `empirical = 1.0` (and `observation` aliases to
//! `empirical`).
//!
//! # The condition under test
//!
//! Exactly that deployment: `CALIBRATION_PATH` unset and a cwd that has no
//! `calibration.toml`. The served calibration is a process-wide `LazyLock`, so
//! [`isolate_from_the_workspace_file`] runs before anything in this process can
//! resolve it, and every test re-checks the condition it relies on. The
//! expected weight is the shipped `[evidence_type_weights] empirical`, read
//! from the workspace file by path (not through the code under test).
//!
//! Each test goes through the real tool and reads the stored `auto_wire` row
//! back. `source_strength` is the weight the writer stored, verbatim
//! (`ds_auto::auto_wire_ds_update_filed_on`: `Some(weight)`).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use epigraph_engine::calibration::CalibrationConfig;
use epigraph_mcp::tools;
use epigraph_mcp::types::{
    ReportWorkflowOutcomeParams, StepExecution, SubmitClaimParams, UpdateWithEvidenceParams,
};
use sqlx::PgPool;
use uuid::Uuid;

/// The fallback the removed loaders returned when they found no file.
const OLD_FALLBACK: f64 = 0.7;

/// Put this process in the reported deployment: `CALIBRATION_PATH` unset, and
/// a fresh, empty working directory (a unique one, so a stray
/// `calibration.toml` in a shared temp dir cannot hide the defect). Runs once;
/// every caller then re-checks the condition.
fn isolate_from_the_workspace_file() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    let dir = DIR.get_or_init(|| {
        std::env::remove_var("CALIBRATION_PATH");
        let dir = std::env::temp_dir().join(format!(
            "d83b998a-no-calibration-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("create the empty working directory");
        std::env::set_current_dir(&dir).expect("enter the empty working directory");
        dir
    });
    assert!(
        std::env::var_os("CALIBRATION_PATH").is_none(),
        "the condition under test needs CALIBRATION_PATH unset"
    );
    let cwd = std::env::current_dir().expect("cwd");
    assert_eq!(cwd, *dir, "the test process runs from the empty directory");
    assert!(
        !cwd.join("calibration.toml").exists(),
        "the condition under test needs a cwd without calibration.toml"
    );
    dir
}

/// `[evidence_type_weights] empirical` of the workspace `calibration.toml`,
/// read by absolute path, independent of the served calibration.
fn shipped_empirical_weight() -> f64 {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../calibration.toml");
    let shipped = CalibrationConfig::load(&path).expect("workspace calibration.toml");
    let w = *shipped
        .evidence_type_weights
        .get("empirical")
        .expect("the shipped calibration types `empirical`");
    // Non-vacuity: if the shipped weight were the old fallback, a pass could
    // not tell the served calibration from the fallback.
    assert!(
        (w - OLD_FALLBACK).abs() > 1e-9,
        "the shipped empirical weight must differ from the 0.7 fallback for this test to bite"
    );
    w
}

/// The `source_strength` of the single `auto_wire` BBA stored for `claim_id`.
/// Exactly one row is required, so a path that wrote nothing cannot pass.
async fn auto_wire_source_strength(pool: &PgPool, claim_id: Uuid) -> f64 {
    let rows: Vec<Option<f64>> = sqlx::query_scalar(
        "SELECT source_strength FROM mass_functions \
         WHERE claim_id = $1 AND combination_method = 'auto_wire'",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .expect("read auto_wire BBAs");
    assert_eq!(rows.len(), 1, "exactly one auto_wire BBA for {claim_id}");
    rows[0].expect("an auto_wire BBA stores its evidence-type weight")
}

fn assert_served_weight(got: f64, want: f64, path: &str) {
    assert!(
        (got - want).abs() < 1e-9,
        "{path}: stored source_strength {got}, want the served empirical weight {want} \
         (0.7 is the removed cwd loader's fallback)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_weights_empirical_from_the_served_calibration(pool: PgPool) {
    isolate_from_the_workspace_file();
    let want = shipped_empirical_weight();
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = format!("d83b998a submit_claim weight {}", Uuid::new_v4());

    tools::claims::submit_claim(
        &server,
        &viewer,
        SubmitClaimParams {
            content: content.clone(),
            evidence_data: "a measured value".to_string(),
            evidence_type: "empirical".to_string(),
            methodology: "bayesian".to_string(),
            confidence: 0.8,
            source_url: None,
            reasoning: None,
            labels: vec![],
            novelty_threshold: None,
            visibility: Some("public".to_string()),
            group_id: None,
        },
        None,
    )
    .await
    .expect("submit_claim");

    let claim_id: Uuid = sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(&content)
        .fetch_one(&pool)
        .await
        .expect("the claim row");
    assert_served_weight(
        auto_wire_source_strength(&pool, claim_id).await,
        want,
        "submit_claim",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_weights_empirical_from_the_served_calibration(pool: PgPool) {
    isolate_from_the_workspace_file();
    let want = shipped_empirical_weight();
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    // t = 0.5 writes no truth_value seed, so the auto_wire row is the evidence.
    let claim_id = seed_claim(&pool, &format!("d83b998a uwe {}", Uuid::new_v4()), 0.5).await;

    tools::claims::update_with_evidence(
        &server,
        &viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".to_string(),
            evidence_data: "a measurement".to_string(),
            source_url: None,
            supports: true,
            strength: 0.8,
            labels: vec![],
        },
        None,
    )
    .await
    .expect("update_with_evidence");

    assert_served_weight(
        auto_wire_source_strength(&pool, claim_id).await,
        want,
        "update_with_evidence",
    );
}

/// `report_workflow_outcome` types its own evidence row `observation`, which
/// `[evidence_type_aliases]` resolves to `empirical`.
#[sqlx::test(migrations = "../../migrations")]
async fn report_workflow_outcome_weights_its_observation_from_the_served_calibration(pool: PgPool) {
    isolate_from_the_workspace_file();
    let want = shipped_empirical_weight();
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let claim_id = seed_workflow_claim(&pool, "d83b998a workflow outcome", &["s1"]).await;

    tools::workflows::report_workflow_outcome(
        &server,
        &viewer,
        ReportWorkflowOutcomeParams {
            workflow_id: claim_id.to_string(),
            success: true,
            execution_log: vec![StepExecution {
                step_index: 0,
                planned: "s1".to_string(),
                actual: "s1".to_string(),
                deviated: false,
                deviation_reason: None,
            }],
            outcome_details: "ran".to_string(),
            quality: Some(0.8),
            goal_text: None,
        },
        None,
    )
    .await
    .expect("report_workflow_outcome");

    assert_served_weight(
        auto_wire_source_strength(&pool, claim_id).await,
        want,
        "report_workflow_outcome",
    );
}
