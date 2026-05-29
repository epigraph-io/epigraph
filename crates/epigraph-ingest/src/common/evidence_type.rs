//! Canonical evidence-type vocabulary for extraction.
//!
//! The extracting LLM tags each paragraph/atom with an `evidence_type` chosen
//! from [`EVIDENCE_TYPES`]. That tag lands on the BBA's
//! `mass_functions.evidence_type`, where two consumers key on it:
//!
//! - **Global belief** — `effective_source_strength` resolves the tag to a
//!   reliability weight via `calibration.toml`'s `[evidence_type_weights]`
//!   (issue #197 Phase 2). An unrecognised tag falls through to the 0.5
//!   unknown-key default, silently flattening the calibration — so we
//!   normalise to the canonical set at plan-build time and drop anything else.
//! - **Per-perspective belief** — the frame function (`get_perspective_belief`)
//!   discounts each BBA by the querying perspective's reliability for its tag.
//!
//! These keys are therefore a **subset of the calibration `evidence_type_weights`
//! keys**; `evidence_type_set_is_calibration_subset` (in epigraph-mcp tests)
//! guards that invariant against drift between this list and `calibration.toml`.

/// Canonical evidence types the extractor may assign. Mirrors the canonical
/// keys in `calibration.toml` `[evidence_type_weights]`.
///
/// - `regulatory` — a binding rule, statute, standard, or approval.
/// - `empirical` — direct observation/measurement/experiment.
/// - `statistical` — aggregate/quantitative analysis over a sample.
/// - `logical` — derivation or assertion argued within the text.
/// - `testimonial` — explicit attributed testimony or expert statement.
/// - `circumstantial` — indirect/inferred support.
/// - `conversational` — informal/anecdotal report (e.g. transcript remark).
pub const EVIDENCE_TYPES: &[&str] = &[
    "regulatory",
    "empirical",
    "statistical",
    "logical",
    "testimonial",
    "circumstantial",
    "conversational",
];

/// Normalise an extractor-supplied evidence-type tag to a canonical key.
///
/// Case-insensitive and whitespace-trimming. Returns `Some(canonical)` only for
/// a value in [`EVIDENCE_TYPES`]; any other value (including `None` or an
/// unrecognised string) returns `None`, so the BBA is stored untagged rather
/// than with a tag that would hit the 0.5 unknown-key fallback. Dropping an
/// unmappable tag is deliberate: an untagged BBA cleanly inherits its stored
/// `source_strength` (global) and α = 1.0 (per-perspective).
#[must_use]
pub fn normalize_evidence_type(raw: Option<&str>) -> Option<String> {
    let key = raw?.trim().to_lowercase();
    EVIDENCE_TYPES
        .iter()
        .find(|&&t| t == key)
        .map(|&t| t.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_case_insensitively() {
        assert_eq!(
            normalize_evidence_type(Some("empirical")).as_deref(),
            Some("empirical")
        );
        assert_eq!(
            normalize_evidence_type(Some("  Statistical ")).as_deref(),
            Some("statistical")
        );
        assert_eq!(
            normalize_evidence_type(Some("TESTIMONIAL")).as_deref(),
            Some("testimonial")
        );
    }

    #[test]
    fn drops_unknown_and_none() {
        assert_eq!(normalize_evidence_type(Some("western_clinical")), None);
        assert_eq!(normalize_evidence_type(Some("")), None);
        assert_eq!(normalize_evidence_type(None), None);
    }
}
