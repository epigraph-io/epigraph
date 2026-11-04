//! `backfill_factors --phase evidence` must weight each evidence row by the
//! calibration the binary SERVES, not by a `calibration.toml` in its working
//! directory (backlog d83b998a).
//!
//! The bin carried a private `load_evidence_type_weight` that read the file
//! `CALIBRATION_PATH` named, else `calibration.toml` in the cwd, and returned
//! 0.7 on any failure. Run with `CALIBRATION_PATH` unset from a directory
//! without the file, it baked `source_strength = 0.7` into every BBA it wired,
//! where the shipped calibration weights an `observation` (alias of
//! `empirical`) at 1.0. Every other DS path resolves through
//! `CalibrationConfig::cached()`: the `CALIBRATION_PATH` file when it loads,
//! else the copy compiled into the binary.
//!
//! The bin runs as a real process with a cleared environment against a
//! fixture `/health` that reports the default belief modes (a writing run
//! checks them first; see `belief_mode_check_bins.rs`). Each case is its own
//! process, so each resolves the calibration afresh:
//!
//! - `CALIBRATION_PATH` unset, empty cwd: the compiled-in weight (was 0.7);
//! - `CALIBRATION_PATH` set to a missing file: the compiled-in weight, with
//!   the resolver's ERROR (was 0.7: the old loader fell back on ANY failure);
//! - `CALIBRATION_PATH` unset, a `calibration.toml` with different values in
//!   the cwd: the compiled-in weight, the cwd file ignored (was the cwd value,
//!   so a process started from a checkout weighted from that branch's file);
//! - `CALIBRATION_PATH` set to a loadable variant: the variant's weight. Green
//!   before the fix too; it pins `cached()` (override honoured) rather than
//!   `embedded()` at this call site.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use epigraph_engine::calibration::CalibrationConfig;
use sqlx::PgPool;
use uuid::Uuid;

const BACKFILL_FACTORS: &str = env!("CARGO_BIN_EXE_backfill_factors");

/// The fallback the removed loader returned when it found no file.
const OLD_FALLBACK: f64 = 0.7;

/// Serve the `/health` body of a server with no belief flag set, forever, on a
/// loopback port. Returns the base URL.
fn legacy_health() -> String {
    let body = serde_json::json!({
        "status": "healthy",
        "version": "0.0.0-fixture",
        "timestamp": "2026-01-01T00:00:00Z",
        "belief_modes": {
            "atom_fold": "legacy",
            "compound_belief": "legacy",
            "compound_write_guard": "warn",
            "compound_source_edges": "frozen",
            "atom_cache_mode": "display",
            "inference": "off",
            "bp_apply": "off",
        },
    })
    .to_string();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let addr = listener.local_addr().expect("fixture address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let mut head = Vec::new();
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// A fresh directory with no `calibration.toml` (a unique one, so a stray file
/// in a shared temp dir cannot hide the defect).
fn empty_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("d83b998a-backfill-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create the empty working directory");
    assert!(!dir.join("calibration.toml").exists());
    dir
}

/// The workspace `calibration.toml`, by absolute path.
fn workspace_calibration() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../calibration.toml")
}

/// The weight the variant file gives `empirical` (and so `observation`).
const VARIANT_EMPIRICAL: f64 = 0.42;

/// A full copy of the workspace `calibration.toml` with ONLY
/// `[evidence_type_weights] empirical` changed to [`VARIANT_EMPIRICAL`],
/// written to `dir/name`. A full copy, so it loads (a partial file could fail
/// to load and silently serve the compiled-in copy); checked to load with the
/// variant weight before the bin runs.
fn write_variant(dir: &Path, name: &str) -> PathBuf {
    let shipped = std::fs::read_to_string(workspace_calibration()).expect("workspace calibration");
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
            if section == "[evidence_type_weights]" && key == "empirical" && t.contains('=') {
                replaced += 1;
                format!("empirical = {VARIANT_EMPIRICAL}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        replaced, 1,
        "exactly one [evidence_type_weights] empirical line"
    );
    let path = dir.join(name);
    std::fs::write(&path, variant + "\n").expect("write the variant calibration");
    let loaded = CalibrationConfig::load(&path).expect("the variant calibration loads");
    assert!(
        (loaded.get_evidence_type_weight("observation") - VARIANT_EMPIRICAL).abs() < 1e-12,
        "the variant weights observation at {VARIANT_EMPIRICAL}"
    );
    path
}

/// `[evidence_type_weights] empirical` of the workspace `calibration.toml`,
/// read by absolute path, independent of the code under test.
fn shipped_empirical_weight() -> f64 {
    let shipped =
        CalibrationConfig::load(&workspace_calibration()).expect("workspace calibration.toml");
    let w = shipped.get_evidence_type_weight("observation");
    assert!(
        (w - OLD_FALLBACK).abs() > 1e-9 && (w - VARIANT_EMPIRICAL).abs() > 1e-9,
        "the shipped observation weight must differ from the 0.7 fallback and the variant \
         for these tests to bite"
    );
    assert!(
        (w - shipped.evidence_type_weights["empirical"]).abs() < 1e-12,
        "observation aliases to empirical in the shipped calibration"
    );
    w
}

/// A current claim with no BBA and one signed, typed `observation` evidence
/// row: exactly what the evidence phase selects (signer set; `properties.type`
/// set, so it is not filtered as telemetry). Returns the claim.
async fn seed_factorless_claim_with_evidence(pool: &PgPool) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'd83b998a-backfill', 'system', \
                 ARRAY['test']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent");
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ('d83b998a factorless claim ' || gen_random_uuid(), \
                 sha256(gen_random_uuid()::text::bytea), 0.5, $1, true) RETURNING id",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim");
    sqlx::query(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content, \
                               signature, signer_id, properties) \
         VALUES ($1, 'observation', sha256(gen_random_uuid()::text::bytea), \
                 'd83b998a measured', sha512(gen_random_uuid()::text::bytea), $2, \
                 '{\"type\": \"measurement\"}'::jsonb)",
    )
    .bind(claim)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed evidence");
    claim
}

/// Run `backfill_factors --phase evidence` from `cwd` with a cleared
/// environment (plus `CALIBRATION_PATH` when given) and return the
/// `source_strength` of the one BBA it wires for a freshly seeded claim, and
/// the bin's output (its log goes to stdout; stderr appended).
async fn wired_weight(pool: &PgPool, calibration_path: Option<&Path>, cwd: &Path) -> (f64, String) {
    let claim = seed_factorless_claim_with_evidence(pool).await;
    let db = fixture::database_url_for(pool).await;
    let api = legacy_health();

    let mut cmd = Command::new(BACKFILL_FACTORS);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "warn")
        .env("DATABASE_URL", &db)
        .env("EPIGRAPH_API_URL", &api)
        .args(["--phase", "evidence"])
        .current_dir(cwd);
    if let Some(p) = calibration_path {
        cmd.env("CALIBRATION_PATH", p);
    }
    let out = cmd.output().expect("run backfill_factors");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );

    let rows: Vec<Option<f64>> = sqlx::query_scalar(
        "SELECT source_strength FROM mass_functions \
         WHERE claim_id = $1 AND combination_method = 'auto_wire'",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read BBAs");
    assert_eq!(
        rows.len(),
        1,
        "the evidence phase wires exactly one BBA for the seeded claim\nstdout: {stdout}"
    );
    let got = rows[0].expect("a wired BBA stores its evidence-type weight");
    (got, format!("{stdout}\n{stderr}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn evidence_phase_weights_from_the_served_calibration_without_a_cwd_file(pool: PgPool) {
    let want = shipped_empirical_weight();
    let (got, _) = wired_weight(&pool, None, &empty_dir()).await;
    assert!(
        (got - want).abs() < 1e-9,
        "backfill_factors stored source_strength {got}, want the served observation weight \
         {want} (0.7 is the removed cwd loader's fallback)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn evidence_phase_serves_the_compiled_in_weight_when_the_override_cannot_load(pool: PgPool) {
    let want = shipped_empirical_weight();
    let cwd = empty_dir();
    let missing = cwd.join("missing.toml");
    assert!(!missing.exists());
    let (got, output) = wired_weight(&pool, Some(&missing), &cwd).await;
    assert!(
        (got - want).abs() < 1e-9,
        "with CALIBRATION_PATH set to a missing file, backfill_factors stored \
         source_strength {got}, want the compiled-in observation weight {want} (0.7 is \
         the removed loader's fallback for any load failure)\noutput: {output}"
    );
    assert!(
        output.contains("missing.toml"),
        "the unloadable override is reported, naming the path\noutput: {output}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn evidence_phase_ignores_a_calibration_file_in_the_cwd(pool: PgPool) {
    let want = shipped_empirical_weight();
    let cwd = empty_dir();
    write_variant(&cwd, "calibration.toml");
    let (got, _) = wired_weight(&pool, None, &cwd).await;
    assert!(
        (got - want).abs() < 1e-9,
        "with a calibration.toml weighting empirical at {VARIANT_EMPIRICAL} in the cwd and \
         CALIBRATION_PATH unset, backfill_factors stored source_strength {got}, want the \
         compiled-in observation weight {want}: a cwd file must not be read"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn evidence_phase_honours_a_loadable_calibration_override(pool: PgPool) {
    let cwd = empty_dir();
    let variant = write_variant(
        &std::env::temp_dir(),
        &format!("d83b998a-{}.toml", Uuid::new_v4()),
    );
    let (got, _) = wired_weight(&pool, Some(&variant), &cwd).await;
    assert!(
        (got - VARIANT_EMPIRICAL).abs() < 1e-9,
        "with CALIBRATION_PATH naming a calibration that weights empirical at \
         {VARIANT_EMPIRICAL}, backfill_factors stored source_strength {got}: the override \
         must apply (a switch to the compiled-in copy alone would store 1.0)"
    );
}
