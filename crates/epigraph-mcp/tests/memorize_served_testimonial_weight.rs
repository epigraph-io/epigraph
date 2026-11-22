//! `memorize` must weigh its testimony BBA by the calibration the process
//! SERVES (backlog 26a12f41, part 1).
//!
//! # The defect
//!
//! `tools/memory.rs::memorize` built its `DsAutoInput` with the literal
//! `weight: 0.6`. That equals the shipped `[evidence_type_weights]
//! testimonial`, so the default deployment could not tell, but a
//! `CALIBRATION_PATH` override that retunes `testimonial` never reached
//! `memorize`, while `submit_claim` and `update_with_evidence` (which resolve
//! through `CalibrationConfig::cached()`) honoured it.
//!
//! # The condition under test
//!
//! `CALIBRATION_PATH` names a full copy of the workspace `calibration.toml`
//! with ONLY `testimonial` changed to [`VARIANT_TESTIMONIAL`], a value distinct
//! from both the old literal (0.6) and the 0.5 unknown-type fallback. The
//! served calibration is a process-wide `LazyLock`, so this file is its own
//! test binary and [`serve_the_variant`] sets the variable before anything in
//! the process resolves it, then checks the served weight IS the variant (so
//! a pass cannot come from an unloaded file). The tool's stored `auto_wire`
//! row is read back: `source_strength` is the weight the writer stored,
//! verbatim.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use epigraph_engine::calibration::{CalibrationConfig, CalibrationSource};
use epigraph_mcp::tools;
use epigraph_mcp::types::MemorizeParams;
use sqlx::PgPool;
use uuid::Uuid;

/// The literal `memorize` used to pass.
const OLD_LITERAL: f64 = 0.6;

/// The variant's `[evidence_type_weights] testimonial`.
const VARIANT_TESTIMONIAL: f64 = 0.37;

/// Write the variant calibration once and point `CALIBRATION_PATH` at it,
/// before the served calibration is first resolved; every caller then
/// re-checks that the process serves it.
fn serve_the_variant() -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    let path = PATH.get_or_init(|| {
        let shipped = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../calibration.toml"),
        )
        .expect("workspace calibration.toml");
        let mut section = String::new();
        let mut replaced = 0;
        let variant: String = shipped
            .lines()
            .map(|line| {
                let t = line.trim();
                if t.starts_with('[') {
                    section = t.to_string();
                }
                let key = t.split('=').next().unwrap_or("").trim();
                if section == "[evidence_type_weights]" && key == "testimonial" && t.contains('=') {
                    replaced += 1;
                    format!("testimonial = {VARIANT_TESTIMONIAL}")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            replaced, 1,
            "exactly one [evidence_type_weights] testimonial line"
        );
        let dir = std::env::temp_dir().join(format!("26a12f41-memorize-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create the variant directory");
        let path = dir.join("calibration.toml");
        std::fs::write(&path, variant + "\n").expect("write the variant calibration");
        std::env::set_var("CALIBRATION_PATH", &path);
        path
    });
    assert_eq!(
        CalibrationConfig::cached_source(),
        &CalibrationSource::Path(path.clone()),
        "the process serves the variant file"
    );
    let served = CalibrationConfig::cached().get_evidence_type_weight("testimony");
    assert!(
        (served - VARIANT_TESTIMONIAL).abs() < 1e-12,
        "the served calibration weighs testimony at the variant {VARIANT_TESTIMONIAL}, got {served}"
    );
    assert!(
        (VARIANT_TESTIMONIAL - OLD_LITERAL).abs() > 1e-9
            && (VARIANT_TESTIMONIAL - 0.5).abs() > 1e-9,
        "the variant must differ from the old literal and the unknown-type fallback to bite"
    );
    path
}

#[sqlx::test(migrations = "../../migrations")]
async fn memorize_weighs_testimony_from_the_served_calibration(pool: PgPool) {
    serve_the_variant();
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = format!("26a12f41 memorize weight {}", Uuid::new_v4());

    tools::memory::memorize(
        &server,
        &viewer,
        MemorizeParams {
            content: content.clone(),
            confidence: Some(0.8),
            tags: None,
            novelty_threshold: None,
            visibility: Some("public".to_string()),
            group_id: None,
        },
        None,
    )
    .await
    .expect("memorize");

    let (claim_id, truth): (Uuid, f64) =
        sqlx::query_as("SELECT id, truth_value FROM claims WHERE content = $1")
            .bind(&content)
            .fetch_one(&pool)
            .await
            .expect("the claim row");
    // memorize seeds truth_value = confidence * weight and does not overwrite
    // it from the BBA (persist_truth_from_pignistic = false).
    let want_truth = 0.8 * VARIANT_TESTIMONIAL;
    assert!(
        (truth - want_truth).abs() < 1e-9,
        "memorize seeded truth_value {truth}, want 0.8 * the served testimonial weight \
         = {want_truth} (0.8 * {OLD_LITERAL} = 0.48 is the removed literal)"
    );
    let rows: Vec<(Option<f64>, Option<String>)> = sqlx::query_as(
        "SELECT source_strength, evidence_type FROM mass_functions \
         WHERE claim_id = $1 AND combination_method = 'auto_wire'",
    )
    .bind(claim_id)
    .fetch_all(&pool)
    .await
    .expect("read auto_wire BBAs");
    assert_eq!(
        rows.len(),
        1,
        "exactly one auto_wire BBA for the memorized claim"
    );
    let (strength, evidence_type) = &rows[0];
    assert_eq!(evidence_type.as_deref(), Some("testimonial"));
    let got = strength.expect("an auto_wire BBA stores its evidence-type weight");
    assert!(
        (got - VARIANT_TESTIMONIAL).abs() < 1e-9,
        "memorize stored source_strength {got}, want the served testimonial weight \
         {VARIANT_TESTIMONIAL} ({OLD_LITERAL} is the removed literal)"
    );
}
