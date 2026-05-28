//! Pure-unit tests for `effective_source_strength` (Phase 2 of issue #197).
//!
//! No DB. Synthetic `MassFunctionRow` + the real `CalibrationConfig` loaded
//! from `calibration.toml`. Exercises every branch of the fallback chain
//! documented on the helper.
//!
//! Locked decisions (issue #197 Phase 2):
//!   * Q3 vocabulary: `intra_self_cite`, `intra_methodological_overlap`,
//!     `cross`, `unknown`. Helper treats any `locality_tag.starts_with("intra")`
//!     as intra-source.
//!   * Q5 path 1: when `evidence_type` is set but not calibrated (e.g.
//!     legacy `"CORROBORATES"`), fall back to stored `source_strength`.
//!   * Q5 path 2: calibration.toml carries `[evidence_type_aliases]` entries
//!     for relationships (`supports → derived_support`, etc.) so the
//!     helper resolves a real weight via the alias chain.
//!
//! Phase 4 extension hook: the signature is intentionally (`row`,
//! `per_frame_intra_factor`, `calibration`). Phase 4 will widen with a
//! fourth parameter `per_frame_evidence_weights` per the Phase 4 spec.

use chrono::Utc;
use epigraph_db::MassFunctionRow;
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::edge_factor::effective_source_strength;
use uuid::Uuid;

// ── Fixtures ───────────────────────────────────────────────────────────────

fn load_calibration() -> CalibrationConfig {
    CalibrationConfig::from_workspace_root().expect("calibration.toml should load")
}

/// Build a synthetic `MassFunctionRow` for unit testing. Only the fields
/// the helper inspects (`evidence_type`, `locality_tag`, `source_strength`)
/// vary; everything else is filler.
fn row(
    evidence_type: Option<&str>,
    locality_tag: &str,
    source_strength: Option<f64>,
) -> MassFunctionRow {
    MassFunctionRow {
        id: Uuid::new_v4(),
        claim_id: Uuid::new_v4(),
        frame_id: Uuid::new_v4(),
        source_agent_id: None,
        perspective_id: None,
        masses: serde_json::json!({"0": 0.5, "0,1": 0.5}),
        conflict_k: None,
        combination_method: Some("test".to_string()),
        source_strength,
        evidence_type: evidence_type.map(String::from),
        locality_tag: locality_tag.to_string(),
        evidence_id: None,
        created_at: Utc::now(),
    }
}

fn approx(actual: f64, expected: f64, label: &str) {
    let tol = 1e-9;
    assert!(
        (actual - expected).abs() < tol,
        "{label}: expected {expected}, got {actual} (Δ={})",
        (actual - expected).abs()
    );
}

// ── Step (2): evidence_type calibrated, locality applied ───────────────────

#[test]
fn empirical_intra_self_cite_applies_global_factor() {
    let cfg = load_calibration();
    let r = row(Some("empirical"), "intra_self_cite", Some(1.0));
    // empirical = 1.0; intra factor 0.3 from calibration.toml → 0.3.
    approx(
        effective_source_strength(&r, None, &cfg),
        1.0 * 0.3,
        "empirical/intra_self_cite",
    );
}

#[test]
fn empirical_intra_methodological_overlap_applies_global_factor() {
    let cfg = load_calibration();
    // Documents Q3: any locality_tag starting with "intra" is intra.
    let r = row(Some("empirical"), "intra_methodological_overlap", Some(1.0));
    approx(
        effective_source_strength(&r, None, &cfg),
        1.0 * 0.3,
        "empirical/intra_methodological_overlap",
    );
}

#[test]
fn empirical_cross_no_discount() {
    let cfg = load_calibration();
    let r = row(Some("empirical"), "cross", Some(0.21));
    approx(
        effective_source_strength(&r, None, &cfg),
        1.0,
        "empirical/cross (source_strength cache ignored at tier 2)",
    );
}

#[test]
fn empirical_unknown_locality_no_discount() {
    let cfg = load_calibration();
    // 'unknown' (and any non-"intra" string) → cross behaviour.
    let r = row(Some("empirical"), "unknown", Some(1.0));
    approx(
        effective_source_strength(&r, None, &cfg),
        1.0,
        "empirical/unknown",
    );
}

#[test]
fn derived_support_intra_self_cite() {
    let cfg = load_calibration();
    // Phase 2: derived_support = 0.7 in calibration.toml.
    let r = row(Some("derived_support"), "intra_self_cite", Some(0.21));
    approx(
        effective_source_strength(&r, None, &cfg),
        0.7 * 0.3,
        "derived_support/intra",
    );
}

#[test]
fn derived_support_cross_no_discount() {
    let cfg = load_calibration();
    let r = row(Some("derived_support"), "cross", Some(0.7));
    approx(
        effective_source_strength(&r, None, &cfg),
        0.7,
        "derived_support/cross",
    );
}

/// Q5 path 2: raw relationship resolves through `[evidence_type_aliases]`
/// to the canonical key without the helper knowing about it. Tier 2 wins.
#[test]
fn supports_relationship_resolves_via_alias() {
    let cfg = load_calibration();
    let r = row(Some("supports"), "cross", None);
    // calibration.toml: supports → derived_support → 0.7.
    approx(
        effective_source_strength(&r, None, &cfg),
        0.7,
        "supports (via alias chain)",
    );
}

#[test]
fn supports_relationship_intra_resolves_and_discounts() {
    let cfg = load_calibration();
    let r = row(Some("supports"), "intra_self_cite", None);
    approx(
        effective_source_strength(&r, None, &cfg),
        0.7 * 0.3,
        "supports/intra (via alias chain)",
    );
}

#[test]
fn testimonial_intra_self_cite() {
    let cfg = load_calibration();
    // testimonial = 0.6 in calibration.toml; intra factor 0.3 → 0.18.
    let r = row(Some("testimonial"), "intra_self_cite", None);
    approx(
        effective_source_strength(&r, None, &cfg),
        0.6 * 0.3,
        "testimonial/intra",
    );
}

/// **The key Phase 2 invariant**: changing the per-frame factor flows
/// through to the helper output without any DB rewrite. Without this
/// the helper is dead code at recalibration time.
#[test]
fn per_frame_factor_override_recalibrates_without_db_write() {
    let cfg = load_calibration();
    let r = row(Some("empirical"), "intra_self_cite", Some(0.3));

    // Default factor (0.3 from calibration.toml).
    approx(
        effective_source_strength(&r, None, &cfg),
        1.0 * 0.3,
        "empirical/intra default factor",
    );

    // Per-frame override 0.5.
    approx(
        effective_source_strength(&r, Some(0.5), &cfg),
        1.0 * 0.5,
        "empirical/intra per-frame factor 0.5",
    );

    // Per-frame override 0.9 (e.g. a textbook frame where intra-source
    // citation IS the assertion-grounding move).
    approx(
        effective_source_strength(&r, Some(0.9), &cfg),
        1.0 * 0.9,
        "empirical/intra per-frame factor 0.9",
    );
}

// ── Step (1): evidence_type=None legacy fallback ───────────────────────────

#[test]
fn null_evidence_type_with_source_strength_returns_stored() {
    let cfg = load_calibration();
    // 5202ded backfill cohort: source_strength set, evidence_type NULL.
    let r = row(None, "unknown", Some(0.85));
    approx(
        effective_source_strength(&r, None, &cfg),
        0.85,
        "null evidence_type, source_strength=0.85",
    );
}

#[test]
fn null_evidence_type_with_source_strength_ignores_locality() {
    let cfg = load_calibration();
    // The legacy cache path does NOT compose with locality — the stored
    // value is already a final discount weight from the 5202ded era.
    // Documents the "stored value is authoritative" semantics for the
    // null-evidence_type cohort.
    let r = row(None, "intra_self_cite", Some(0.85));
    approx(
        effective_source_strength(&r, None, &cfg),
        0.85,
        "null evidence_type, intra locality — locality NOT re-applied",
    );
}

#[test]
fn null_evidence_type_null_source_strength_falls_back_to_half() {
    let cfg = load_calibration();
    let r = row(None, "unknown", None);
    approx(
        effective_source_strength(&r, None, &cfg),
        0.5,
        "both null → 0.5 unknown-key fallback",
    );
}

// ── Step (3): evidence_type set but uncalibrated → cache bridge ────────────

#[test]
fn unknown_evidence_type_with_source_strength_returns_cache() {
    let cfg = load_calibration();
    // Path 1 sentinel from Phase 2 spec § 4: a string that neither lives
    // in `[evidence_type_weights]` nor in `[evidence_type_aliases]`.
    let r = row(Some("totally_unknown_key"), "intra_self_cite", Some(0.42));
    approx(
        effective_source_strength(&r, None, &cfg),
        0.42,
        "unknown evidence_type → source_strength cache bridge",
    );
}

#[test]
fn unknown_evidence_type_with_null_source_strength_falls_back_to_half() {
    let cfg = load_calibration();
    let r = row(Some("totally_unknown_key"), "intra_self_cite", None);
    approx(
        effective_source_strength(&r, None, &cfg),
        0.5,
        "unknown evidence_type, no cache → 0.5",
    );
}

// ── Clamping ───────────────────────────────────────────────────────────────

#[test]
fn output_is_clamped_to_unit_interval() {
    let cfg = load_calibration();
    // Negative cached source_strength — synthetic, but the helper must
    // clamp on the way out so downstream `combination::discount` never
    // sees an out-of-range reliability.
    let r = row(None, "unknown", Some(-0.1));
    approx(
        effective_source_strength(&r, None, &cfg),
        0.0,
        "negative cached source_strength → clamped to 0.0",
    );

    // Above-1.0 cached source_strength is also synthetic but the clamp
    // must catch it before `discount` panics.
    let r = row(None, "unknown", Some(1.5));
    approx(
        effective_source_strength(&r, None, &cfg),
        1.0,
        "above-unit cached source_strength → clamped to 1.0",
    );
}

// ── Phase 2 fallback config (calibration.toml missing) ─────────────────────

#[test]
fn fallback_config_preserves_pre_phase2_invariants() {
    // When calibration.toml fails to load, the synthetic fallback config
    // makes every evidence_type lookup fall through to the 0.5 unknown
    // fallback. The helper's step (3) cache bridge then kicks in for any
    // row that has source_strength set.
    let cfg = CalibrationConfig::default_for_phase2_fallback();
    let r = row(Some("empirical"), "intra_self_cite", Some(0.21));
    // empirical isn't in the empty map → step (3) cache returns 0.21.
    approx(
        effective_source_strength(&r, None, &cfg),
        0.21,
        "fallback config: empirical lookup misses, cache returns 0.21",
    );

    // Without a cache value, fall through to 0.5.
    let r = row(Some("empirical"), "intra_self_cite", None);
    approx(
        effective_source_strength(&r, None, &cfg),
        0.5,
        "fallback config: empirical lookup misses, no cache → 0.5",
    );
}
