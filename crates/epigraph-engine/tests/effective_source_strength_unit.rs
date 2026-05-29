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
//! Phase 4 (issue #197) extension: the signature is
//! `(row, per_frame_intra_factor, per_frame_evidence_weights, calibration)`.
//! Per-frame evidence-type weight overrides win at Tier 1 strict-key
//! when present; otherwise falls through to Phase 2 Tier 2 (global
//! calibration with aliases) and Tier 3 (legacy source_strength cache).
//! See `docs/superpowers/specs/2026-05-28-per-frame-evidence-type-weights-spec.md`.

use chrono::Utc;
use epigraph_db::MassFunctionRow;
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::edge_factor::effective_source_strength;
use std::collections::HashMap;
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
        effective_source_strength(&r, None, None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
        1.0 * 0.3,
        "empirical/intra_methodological_overlap",
    );
}

#[test]
fn empirical_cross_no_discount() {
    let cfg = load_calibration();
    let r = row(Some("empirical"), "cross", Some(0.21));
    approx(
        effective_source_strength(&r, None, None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
        0.7 * 0.3,
        "derived_support/intra",
    );
}

#[test]
fn derived_support_cross_no_discount() {
    let cfg = load_calibration();
    let r = row(Some("derived_support"), "cross", Some(0.7));
    approx(
        effective_source_strength(&r, None, None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
        0.7,
        "supports (via alias chain)",
    );
}

#[test]
fn supports_relationship_intra_resolves_and_discounts() {
    let cfg = load_calibration();
    let r = row(Some("supports"), "intra_self_cite", None);
    approx(
        effective_source_strength(&r, None, None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
        1.0 * 0.3,
        "empirical/intra default factor",
    );

    // Per-frame override 0.5.
    approx(
        effective_source_strength(&r, Some(0.5), None, &cfg),
        1.0 * 0.5,
        "empirical/intra per-frame factor 0.5",
    );

    // Per-frame override 0.9 (e.g. a textbook frame where intra-source
    // citation IS the assertion-grounding move).
    approx(
        effective_source_strength(&r, Some(0.9), None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
        0.85,
        "null evidence_type, intra locality — locality NOT re-applied",
    );
}

#[test]
fn null_evidence_type_null_source_strength_falls_back_to_half() {
    let cfg = load_calibration();
    let r = row(None, "unknown", None);
    approx(
        effective_source_strength(&r, None, None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
        0.42,
        "unknown evidence_type → source_strength cache bridge",
    );
}

#[test]
fn unknown_evidence_type_with_null_source_strength_falls_back_to_half() {
    let cfg = load_calibration();
    let r = row(Some("totally_unknown_key"), "intra_self_cite", None);
    approx(
        effective_source_strength(&r, None, None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
        0.0,
        "negative cached source_strength → clamped to 0.0",
    );

    // Above-1.0 cached source_strength is also synthetic but the clamp
    // must catch it before `discount` panics.
    let r = row(None, "unknown", Some(1.5));
    approx(
        effective_source_strength(&r, None, None, &cfg),
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
        effective_source_strength(&r, None, None, &cfg),
        0.21,
        "fallback config: empirical lookup misses, cache returns 0.21",
    );

    // Without a cache value, fall through to 0.5.
    let r = row(Some("empirical"), "intra_self_cite", None);
    approx(
        effective_source_strength(&r, None, None, &cfg),
        0.5,
        "fallback config: empirical lookup misses, no cache → 0.5",
    );
}

// ── Phase 4 (#197): per-frame evidence-type weight overrides ───────────────
//
// All cases below pass a non-None per-frame override map and exercise
// the Tier 1 (strict-key) lookup. Map values must be in [0.0, 1.0]
// (Q10 locked decision; repo accessor drops out-of-range entries at
// read time, so the helper itself does no bounds enforcement at
// construction here — but composed output is still clamped to [0,1]).

fn pf_map(entries: &[(&str, f64)]) -> HashMap<String, f64> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_string(), *v))
        .collect()
}

/// Tier 1 wins over global calibration when key matches the canonical
/// `empirical` weight. Override 0.5 < global 1.0; composed with cross
/// (no discount), result is 0.5.
#[test]
fn phase4_per_frame_override_matches_canonical_key() {
    let cfg = load_calibration();
    let r = row(Some("empirical"), "cross", Some(1.0));
    let pf = pf_map(&[("empirical", 0.5)]);
    approx(
        effective_source_strength(&r, None, Some(&pf), &cfg),
        0.5,
        "empirical/cross + per-frame{empirical: 0.5} → 0.5 (Tier 1)",
    );
}

/// Tier 1 strict-key: override keyed on `observation` matches BBAs
/// tagged literally `observation` (case-insensitive). Does NOT
/// transitively apply to BBAs tagged the aliased canonical `empirical`.
#[test]
fn phase4_per_frame_override_matches_alias_key_literally() {
    let cfg = load_calibration();
    // calibration: observation → empirical → 1.0
    // override: observation = 0.4
    // row tagged "observation" → Tier 1 hit → 0.4 (cross locality, no discount)
    let r = row(Some("observation"), "cross", None);
    let pf = pf_map(&[("observation", 0.4)]);
    approx(
        effective_source_strength(&r, None, Some(&pf), &cfg),
        0.4,
        "observation tag + per-frame{observation: 0.4} → 0.4 (Tier 1 strict-key)",
    );
}

/// Tier 1 strict-key: override on canonical `empirical` does NOT
/// reverse-alias to BBAs literally tagged `observation`. Documents
/// the Phase 4 spec § 5 contract that aliases are NOT resolved at
/// Tier 1.
#[test]
fn phase4_per_frame_override_strict_no_reverse_alias() {
    let cfg = load_calibration();
    // row tagged "observation"; per-frame map has only "empirical".
    // Tier 1 misses; Tier 2 resolves observation → empirical → 1.0.
    let r = row(Some("observation"), "cross", None);
    let pf = pf_map(&[("empirical", 0.5)]);
    approx(
        effective_source_strength(&r, None, Some(&pf), &cfg),
        1.0,
        "observation tag + per-frame{empirical: 0.5} → 1.0 (Tier 2; no reverse alias)",
    );
}

/// Case-insensitive Tier 1 lookup: BBA tagged `Reference` (mixed
/// case) matches per-frame `reference` (lowercase). Production has
/// 104 `reference` and some mixed-case rows; the helper must
/// normalize on lookup.
#[test]
fn phase4_per_frame_override_case_insensitive() {
    let cfg = load_calibration();
    let r = row(Some("Reference"), "cross", None);
    // Per-frame map's keys are already lowercased by the repo
    // accessor; the helper lowercases the BBA's evidence_type before
    // probing the map.
    let pf = pf_map(&[("reference", 0.6)]);
    approx(
        effective_source_strength(&r, None, Some(&pf), &cfg),
        0.6,
        "Reference tag + per-frame{reference: 0.6} → 0.6 (case-insensitive Tier 1)",
    );
}

/// Phase 4 side-benefit: an operator can patch the relationship
/// vocabulary leak (e.g. `CORROBORATES` → calibration alias resolves
/// it to `derived_support` but this test pins the case where the
/// operator wants a frame-specific override for the relationship
/// itself).
#[test]
fn phase4_per_frame_override_relationship_vocab_key() {
    let cfg = load_calibration();
    let r = row(Some("CORROBORATES"), "cross", None);
    // Per-frame override on the lowercased relationship string —
    // wins at Tier 1 strict-key.
    let pf = pf_map(&[("corroborates", 0.65)]);
    approx(
        effective_source_strength(&r, None, Some(&pf), &cfg),
        0.65,
        "CORROBORATES tag + per-frame{corroborates: 0.65} → 0.65 (Tier 1)",
    );
}

/// Per-frame override present but does not contain BBA's evidence
/// type; global calibration hits at Tier 2.
#[test]
fn phase4_per_frame_override_key_absent_global_hits() {
    let cfg = load_calibration();
    let r = row(Some("logical"), "cross", None);
    // Map has empirical but not logical → Tier 1 miss; Tier 2 returns
    // logical = 0.85.
    let pf = pf_map(&[("empirical", 0.5)]);
    approx(
        effective_source_strength(&r, None, Some(&pf), &cfg),
        0.85,
        "logical/cross + per-frame{empirical: 0.5} → 0.85 (Tier 2 fallthrough)",
    );
}

/// Per-frame override present, key absent, global misses, but
/// row.source_strength is set → Tier 3 cache bridge.
#[test]
fn phase4_per_frame_override_falls_through_to_source_strength_cache() {
    let cfg = load_calibration();
    // "totally_unknown_xyz" isn't in calibration or aliases; map
    // doesn't include it; cache returns 0.21.
    let r = row(Some("totally_unknown_xyz"), "intra_self_cite", Some(0.21));
    let pf = pf_map(&[("empirical", 0.5)]);
    approx(
        effective_source_strength(&r, None, Some(&pf), &cfg),
        0.21,
        "unknown evidence_type + per-frame{empirical: 0.5} + cache(0.21) → 0.21 (Tier 4)",
    );
}

/// Phase 4 strict superset: when the per-frame map is `Some(empty
/// HashMap)`, behavior is identical to `None`. The repo accessor
/// returns `Ok(None)` on empty-after-parse, but defensive: the helper
/// must handle `Some({})` gracefully.
#[test]
fn phase4_empty_map_is_strict_superset_of_none() {
    let cfg = load_calibration();
    let r = row(Some("empirical"), "intra_self_cite", Some(1.0));
    let empty_map: HashMap<String, f64> = HashMap::new();

    let with_none = effective_source_strength(&r, None, None, &cfg);
    let with_empty = effective_source_strength(&r, None, Some(&empty_map), &cfg);
    approx(
        with_empty,
        with_none,
        "Some(empty HashMap) must be identical to None — Phase 4 is a strict superset",
    );
}

/// Phase 4 is a no-op on the legacy null-`evidence_type` cohort
/// (278 K of 279 K production rows). Tier 1 misses (no key to look
/// up); Tier 2 (in the row-NULL case the helper short-circuits to
/// the source_strength cache via step 1 of the fallback chain).
#[test]
fn phase4_null_evidence_type_is_unaffected() {
    let cfg = load_calibration();
    let r = row(None, "intra_self_cite", Some(0.85));
    let pf = pf_map(&[("empirical", 0.5)]);
    approx(
        effective_source_strength(&r, None, Some(&pf), &cfg),
        0.85,
        "null evidence_type + per-frame override → cache bridge (override is a no-op)",
    );

    // And without a cache value: 0.5 unknown-key fallback.
    let r = row(None, "intra_self_cite", None);
    approx(
        effective_source_strength(&r, None, Some(&pf), &cfg),
        0.5,
        "null evidence_type + per-frame override + no cache → 0.5",
    );
}

/// Phase 4 + intra locality composition. The Tier 1 override is
/// composed with the locality discount, identical to Tier 2.
/// `empirical` override 0.5 + intra locality (global 0.3 default)
/// → 0.5 * 0.3 = 0.15.
#[test]
fn phase4_per_frame_override_composes_with_locality() {
    let cfg = load_calibration();
    let r = row(Some("empirical"), "intra_self_cite", None);
    let pf = pf_map(&[("empirical", 0.5)]);
    approx(
        effective_source_strength(&r, None, Some(&pf), &cfg),
        0.5 * 0.3,
        "empirical/intra + per-frame{empirical: 0.5} → 0.5 * 0.3 = 0.15",
    );

    // Per-frame intra factor 0.9 stacks on top of Tier 1 override 0.5.
    approx(
        effective_source_strength(&r, Some(0.9), Some(&pf), &cfg),
        0.5 * 0.9,
        "empirical/intra + per-frame{empirical: 0.5} + intra_factor 0.9 → 0.45",
    );
}

// ── Perspective overrides (frame function): effective_source_strength_with_perspective ──
//
// The querying perspective sits at the TOP of both tier chains (evidence-type
// weight and locality factor). A perspective with no matching key reduces to
// the global computation.

use epigraph_engine::edge_factor::{
    effective_source_strength_with_perspective, PerspectiveReliability,
};

fn perspective(source: &[(&str, f64)], locality: &[(&str, f64)]) -> PerspectiveReliability {
    PerspectiveReliability {
        source_reliability: source.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
        locality_reliability: locality
            .iter()
            .map(|(k, v)| ((*k).to_string(), *v))
            .collect(),
    }
}

#[test]
fn perspective_evidence_weight_overrides_calibration() {
    let cfg = load_calibration();
    let r = row(Some("empirical"), "unknown", Some(1.0));
    // Global: empirical 1.0 × locality(unknown→1.0) = 1.0.
    approx(
        effective_source_strength(&r, None, None, &cfg),
        1.0,
        "global empirical",
    );
    // Perspective downweights empirical to 0.5 → 0.5 × 1.0.
    let p = perspective(&[("empirical", 0.5)], &[]);
    approx(
        effective_source_strength_with_perspective(&r, None, None, &cfg, &p),
        0.5,
        "perspective empirical 0.5",
    );
}

#[test]
fn perspective_locality_overrides_intra_factor() {
    let cfg = load_calibration();
    let r = row(Some("empirical"), "intra_self_cite", Some(1.0));
    // Global: empirical 1.0 × intra 0.3 = 0.3.
    approx(
        effective_source_strength(&r, None, None, &cfg),
        0.3,
        "global intra",
    );
    // Perspective trusts intra_self_cite more (0.8) → 1.0 × 0.8.
    let p = perspective(&[], &[("intra_self_cite", 0.8)]);
    approx(
        effective_source_strength_with_perspective(&r, None, None, &cfg, &p),
        0.8,
        "perspective locality 0.8",
    );
}

#[test]
fn perspective_composes_evidence_and_locality() {
    let cfg = load_calibration();
    let r = row(Some("testimonial"), "intra_self_cite", Some(1.0));
    // Both tiers overridden: base 0.5 × locality 0.5 = 0.25.
    let p = perspective(&[("testimonial", 0.5)], &[("intra_self_cite", 0.5)]);
    approx(
        effective_source_strength_with_perspective(&r, None, None, &cfg, &p),
        0.25,
        "0.5 × 0.5",
    );
}

#[test]
fn perspective_without_matching_key_equals_global() {
    let cfg = load_calibration();
    let r = row(Some("empirical"), "unknown", Some(1.0));
    // Perspective has opinions, but none touch this BBA → identical to global.
    let p = perspective(&[("statistical", 0.1)], &[("cross", 0.2)]);
    approx(
        effective_source_strength_with_perspective(&r, None, None, &cfg, &p),
        effective_source_strength(&r, None, None, &cfg),
        "non-matching perspective == global",
    );
    // Empty perspective is likewise a no-op.
    let empty = PerspectiveReliability::default();
    assert!(empty.is_empty());
    approx(
        effective_source_strength_with_perspective(&r, None, None, &cfg, &empty),
        effective_source_strength(&r, None, None, &cfg),
        "empty perspective == global",
    );
}

#[test]
fn perspective_locality_applies_to_untagged_evidence() {
    let cfg = load_calibration();
    // No evidence_type → base falls to stored source_strength (0.6). A
    // perspective locality opinion still applies on top.
    let r = row(None, "intra_self_cite", Some(0.6));
    // Global leaves untyped rows at the stored source_strength (no locality).
    approx(
        effective_source_strength(&r, None, None, &cfg),
        0.6,
        "global untyped",
    );
    let p = perspective(&[], &[("intra_self_cite", 0.5)]);
    approx(
        effective_source_strength_with_perspective(&r, None, None, &cfg, &p),
        0.6 * 0.5,
        "untyped base 0.6 × perspective locality 0.5",
    );
    // With no relevant override, untyped row still equals global.
    let unrelated = perspective(&[("empirical", 0.1)], &[("cross", 0.2)]);
    approx(
        effective_source_strength_with_perspective(&r, None, None, &cfg, &unrelated),
        0.6,
        "untyped, no matching override → global 0.6",
    );
}
