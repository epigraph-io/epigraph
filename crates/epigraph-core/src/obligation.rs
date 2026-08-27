//! Coverage standards and the arithmetic that closes them (backlog 4b48ffb5).
//!
//! An *obligation* records what an answer OWES — a declared coverage standard
//! over a countable unit — so a completeness assertion can be settled by
//! counting rather than believed because it was asserted confidently.
//!
//! # MVP — NEEDS ELABORATION
//!
//! This module is an **arithmetic** checker, not a completeness checker for
//! the whole vocabulary. It counts; it does not judge. Three of the five
//! standards are therefore NOT decided here, and each records why in
//! [`CoverageAssessment::missing_contract_fields`] rather than being papered
//! over with an invented threshold:
//!
//! 1. **materiality criterion** ([`CoverageStandard::Material`]) — no count
//!    supplies a judgement about which units change the conclusion. Inventing
//!    a percentage would be exactly the false confidence this layer exists to
//!    stop, so `material` returns [`CoverageVerdict::Indeterminate`] always.
//! 2. **sampling frame** ([`CoverageStandard::Representative`]) — a defensible
//!    sample is defensible relative to a frame nothing here has. Always
//!    `Indeterminate`.
//! 3. **unit-key identity** ([`CoverageStandard::NativeComplete`]) — the count
//!    is decided, but count equality does not prove the units counted are the
//!    units declared. `native_complete` is settled on cardinality and ALWAYS
//!    self-reports `declared_unit_keys` as missing.
//!
//! # The zero-denominator rule
//!
//! `declared_total == 0` under a counting standard is `Indeterminate`, never
//! `Satisfied`. This is the direct encoding of the motivating failure:
//! epiclaw-host's false `TASK_SILENT` was an assertion that ZERO events had
//! been emitted, and counting the anchors you produced cannot settle it
//! because you produced none either way. A checker that returned
//! `0 == 0 -> satisfied` would have blessed the exact bug this layer was
//! built for.
//!
//! # Layering
//!
//! Pure: no `sqlx`, no I/O, no clock. `epigraph-db`'s
//! `ObligationRepository` owns every statement; this module owns the rule
//! table so it is unit-testable with no database.

use std::fmt;
use std::str::FromStr;

/// How complete an answer claims to be over its unit.
///
/// The wire vocabulary is lowercase with underscores; [`FromStr`] also accepts
/// hyphens and mixed case (see its docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoverageStandard {
    /// Every unit in the population. Settled by counting.
    Exhaustive,
    /// Every unit the source itself names. Settled by counting, but the
    /// identity of the units counted is NOT checked.
    NativeComplete,
    /// Every unit that changes the conclusion. Not decidable by count.
    Material,
    /// A defensible sample. Not decidable by count.
    Representative,
    /// No completeness owed.
    Summary,
}

/// Raised when a wire value is not one of the five standards.
///
/// Callers must surface this as a parameter error. Defaulting an unrecognised
/// standard to [`CoverageStandard::Summary`] would silently make it owe
/// nothing, which is the failure mode the vocabulary exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownCoverageStandard(pub String);

impl fmt::Display for UnknownCoverageStandard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown coverage standard {:?}; expected one of {}",
            self.0,
            CoverageStandard::VOCABULARY.join(", ")
        )
    }
}

impl std::error::Error for UnknownCoverageStandard {}

impl CoverageStandard {
    /// Every accepted standard, in decidability order.
    pub const VOCABULARY: &'static [&'static str] = &[
        "exhaustive",
        "native_complete",
        "material",
        "representative",
        "summary",
    ];

    /// The DB vocabulary (`obligations_standard_vocab`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exhaustive => "exhaustive",
            Self::NativeComplete => "native_complete",
            Self::Material => "material",
            Self::Representative => "representative",
            Self::Summary => "summary",
        }
    }

    /// Whether counting alone can decide this standard.
    #[must_use]
    pub const fn is_countable(self) -> bool {
        matches!(self, Self::Exhaustive | Self::NativeComplete)
    }
}

impl FromStr for CoverageStandard {
    type Err = UnknownCoverageStandard;

    /// Parse the wire vocabulary.
    ///
    /// Case-insensitive, and hyphens normalise to underscores
    /// (`native-complete` -> `native_complete`) — mirroring `parse_methodology`
    /// in `epigraph-mcp/src/tools/claims.rs`, since the backlog spec writes the
    /// standard with a hyphen while the DB CHECK constraint stores underscores.
    ///
    /// # Errors
    /// Returns [`UnknownCoverageStandard`] for anything outside
    /// [`CoverageStandard::VOCABULARY`]. Never defaults.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().replace('-', "_").as_str() {
            "exhaustive" => Ok(Self::Exhaustive),
            "native_complete" => Ok(Self::NativeComplete),
            "material" => Ok(Self::Material),
            "representative" => Ok(Self::Representative),
            "summary" => Ok(Self::Summary),
            _ => Err(UnknownCoverageStandard(s.to_string())),
        }
    }
}

/// What an answer bound itself to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageContract {
    pub standard: CoverageStandard,
    /// What is being counted, e.g. `"claim"`, `"emitter"`, `"section"`.
    pub unit: String,
    /// The denominator. `0` is meaningful and deliberately not decidable —
    /// see the zero-denominator rule in the module docs.
    pub declared_total: u32,
}

/// The outcome of counting a contract's anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageVerdict {
    /// The count closes the contract.
    Satisfied,
    /// The count contradicts the contract. A SURPLUS is a breach too: an
    /// over-count means the denominator was wrong, which is a finding.
    Breach,
    /// Not decidable from what the contract supplies.
    Indeterminate,
    /// The standard owes no completeness.
    NotApplicable,
}

impl CoverageVerdict {
    /// The DB vocabulary (`obligations_verdict_vocab`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Breach => "breach",
            Self::Indeterminate => "indeterminate",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// One evaluation of a contract against a count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageAssessment {
    pub verdict: CoverageVerdict,
    /// The numerator actually counted. Recorded for every standard, including
    /// the ones that do not decide on it.
    pub observed_total: u32,
    /// Human-readable justification, stored verbatim in
    /// `obligations.verdict_reason`.
    pub reason: String,
    /// What this contract has not specified about ITSELF. Non-empty is not an
    /// error — it is the contract naming its own gap.
    pub missing_contract_fields: Vec<String>,
}

/// Missing field a `material` contract always reports.
pub const FIELD_MATERIALITY_CRITERION: &str = "materiality_criterion";
/// Missing field a `representative` contract always reports.
pub const FIELD_SAMPLING_FRAME: &str = "sampling_frame";
/// Missing field a `native_complete` contract always reports.
pub const FIELD_DECLARED_UNIT_KEYS: &str = "declared_unit_keys";
/// Missing field a zero-denominator counting contract reports.
pub const FIELD_POPULATION_SOURCE: &str = "population_source";

/// Decide a contract against an observed count.
///
/// The decidability table, in full — deliberately incomplete, because
/// arithmetic genuinely cannot settle three of the five standards:
///
/// | standard          | verdict                                   | always-missing fields   |
/// |-------------------|-------------------------------------------|-------------------------|
/// | `exhaustive`      | `observed == declared` -> satisfied, else breach | —                 |
/// | `native_complete` | same count equality                       | `declared_unit_keys`    |
/// | `material`        | always indeterminate                      | `materiality_criterion` |
/// | `representative`  | always indeterminate                      | `sampling_frame`        |
/// | `summary`         | always not-applicable                     | —                       |
///
/// Under the two counting standards, `declared_total == 0` short-circuits to
/// indeterminate with `population_source` missing, whatever `observed_total`
/// is.
#[must_use]
pub fn evaluate(contract: &CoverageContract, observed_total: u32) -> CoverageAssessment {
    let unit = contract.unit.as_str();
    let declared = contract.declared_total;

    match contract.standard {
        CoverageStandard::Summary => CoverageAssessment {
            verdict: CoverageVerdict::NotApplicable,
            observed_total,
            reason: format!(
                "summary owes no completeness; {observed_total} {unit} recorded against a \
                 declared {declared} for information only"
            ),
            missing_contract_fields: Vec::new(),
        },

        CoverageStandard::Material => CoverageAssessment {
            verdict: CoverageVerdict::Indeterminate,
            observed_total,
            reason: format!(
                "material coverage is not settled by counting: {observed_total} of {declared} \
                 {unit} anchored, but no count says which units change the conclusion. Supply \
                 {FIELD_MATERIALITY_CRITERION} to make this decidable."
            ),
            missing_contract_fields: vec![FIELD_MATERIALITY_CRITERION.to_string()],
        },

        CoverageStandard::Representative => CoverageAssessment {
            verdict: CoverageVerdict::Indeterminate,
            observed_total,
            reason: format!(
                "representative coverage is not settled by counting: {observed_total} of \
                 {declared} {unit} anchored, but a sample is defensible only against a frame. \
                 Supply {FIELD_SAMPLING_FRAME} to make this decidable."
            ),
            missing_contract_fields: vec![FIELD_SAMPLING_FRAME.to_string()],
        },

        // The two countable standards share the arithmetic and differ only in
        // what they must additionally confess.
        CoverageStandard::Exhaustive | CoverageStandard::NativeComplete => {
            let mut missing = Vec::new();
            if contract.standard == CoverageStandard::NativeComplete {
                // Count equality does not prove the units counted are the
                // units declared; say so on every verdict, satisfied included.
                missing.push(FIELD_DECLARED_UNIT_KEYS.to_string());
            }
            let label = contract.standard.as_str();

            // THE ZERO-DENOMINATOR RULE. "I covered all zero of them" is the
            // shape of the motivating false TASK_SILENT: counting what you
            // produced cannot settle an assertion that there was nothing to
            // produce.
            if declared == 0 {
                missing.push(FIELD_POPULATION_SOURCE.to_string());
                return CoverageAssessment {
                    verdict: CoverageVerdict::Indeterminate,
                    observed_total,
                    reason: format!(
                        "{label} over a declared total of 0 {unit} cannot be closed by counting: \
                         an empty denominator asserts that nothing existed to cover, which the \
                         anchors do not witness either way. Supply {FIELD_POPULATION_SOURCE}."
                    ),
                    missing_contract_fields: missing,
                };
            }

            let (verdict, reason) = match observed_total.cmp(&declared) {
                std::cmp::Ordering::Equal => (
                    CoverageVerdict::Satisfied,
                    format!("{observed_total} of {declared} {unit} anchored ({label})"),
                ),
                std::cmp::Ordering::Less => (
                    CoverageVerdict::Breach,
                    format!(
                        "{label} shortfall: {observed_total} of {declared} {unit} anchored, \
                         {} unaccounted for",
                        declared - observed_total
                    ),
                ),
                // A surplus is a breach, not a pass: the answer counted more
                // than it bound itself to, so the denominator was wrong.
                std::cmp::Ordering::Greater => (
                    CoverageVerdict::Breach,
                    format!(
                        "{label} surplus: {observed_total} {unit} anchored against a declared \
                         {declared}; the denominator is wrong, not the coverage"
                    ),
                ),
            };

            CoverageAssessment {
                verdict,
                observed_total,
                reason,
                missing_contract_fields: missing,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract(standard: CoverageStandard, declared_total: u32) -> CoverageContract {
        CoverageContract {
            standard,
            unit: "claim".to_string(),
            declared_total,
        }
    }

    /// Exact equality is the only pass. A surplus is a breach because an
    /// over-count means the denominator was wrong — a finding, not a pass.
    #[test]
    fn exhaustive_is_satisfied_only_on_exact_equality() {
        let c = contract(CoverageStandard::Exhaustive, 3);

        let exact = evaluate(&c, 3);
        assert_eq!(exact.verdict, CoverageVerdict::Satisfied);
        assert_eq!(exact.observed_total, 3);
        assert!(exact.missing_contract_fields.is_empty());

        let short = evaluate(&c, 2);
        assert_eq!(short.verdict, CoverageVerdict::Breach, "{}", short.reason);
        assert_eq!(short.observed_total, 2);

        let surplus = evaluate(&c, 4);
        assert_eq!(
            surplus.verdict,
            CoverageVerdict::Breach,
            "a surplus is a wrong denominator, not a pass: {}",
            surplus.reason
        );
    }

    /// THE MOTIVATING CASE. epiclaw-host's false TASK_SILENT asserted that
    /// zero events were emitted; a checker that blessed `0 == 0` would have
    /// blessed exactly that bug.
    #[test]
    fn zero_declared_total_under_exhaustive_is_indeterminate() {
        let a = evaluate(&contract(CoverageStandard::Exhaustive, 0), 0);
        assert_eq!(
            a.verdict,
            CoverageVerdict::Indeterminate,
            "0 == 0 must NOT be satisfied: {}",
            a.reason
        );
        assert_eq!(a.observed_total, 0);
        assert_eq!(a.missing_contract_fields, vec![FIELD_POPULATION_SOURCE]);

        // Same rule under the other counting standard, which also keeps its
        // own always-missing field.
        let n = evaluate(&contract(CoverageStandard::NativeComplete, 0), 0);
        assert_eq!(n.verdict, CoverageVerdict::Indeterminate);
        assert_eq!(
            n.missing_contract_fields,
            vec![FIELD_DECLARED_UNIT_KEYS, FIELD_POPULATION_SOURCE]
        );
    }

    /// `native_complete` is decided on cardinality, but cardinality equality
    /// does not prove the units counted are the units declared — so it
    /// confesses `declared_unit_keys` even when satisfied.
    #[test]
    fn native_complete_decides_on_count_but_flags_missing_unit_keys() {
        let c = contract(CoverageStandard::NativeComplete, 3);

        let ok = evaluate(&c, 3);
        assert_eq!(ok.verdict, CoverageVerdict::Satisfied);
        assert_eq!(ok.missing_contract_fields, vec![FIELD_DECLARED_UNIT_KEYS]);

        let short = evaluate(&c, 1);
        assert_eq!(short.verdict, CoverageVerdict::Breach);
        assert_eq!(
            short.missing_contract_fields,
            vec![FIELD_DECLARED_UNIT_KEYS]
        );
    }

    /// THIS TEST IS THE MVP BOUNDARY. It fails the moment someone quietly
    /// invents a materiality threshold or a sampling heuristic.
    #[test]
    fn material_and_representative_never_return_satisfied() {
        for (standard, field) in [
            (CoverageStandard::Material, FIELD_MATERIALITY_CRITERION),
            (CoverageStandard::Representative, FIELD_SAMPLING_FRAME),
        ] {
            let c = contract(standard, 3);
            for observed in [3u32, 2, 4] {
                let a = evaluate(&c, observed);
                assert_eq!(
                    a.verdict,
                    CoverageVerdict::Indeterminate,
                    "{} at observed={observed} must stay indeterminate: {}",
                    standard.as_str(),
                    a.reason
                );
                assert_eq!(a.observed_total, observed);
                assert_eq!(a.missing_contract_fields, vec![field.to_string()]);
            }
        }
    }

    #[test]
    fn summary_owes_no_completeness() {
        let a = evaluate(&contract(CoverageStandard::Summary, 3), 1);
        assert_eq!(a.verdict, CoverageVerdict::NotApplicable);
        // The count is still recorded — a summary owes nothing, but the
        // arithmetic is not discarded.
        assert_eq!(a.observed_total, 1);
        assert!(a.missing_contract_fields.is_empty());
    }

    #[test]
    fn standard_parses_the_wire_vocabulary_and_rejects_the_unknown() {
        assert_eq!(
            "native-complete".parse::<CoverageStandard>().unwrap(),
            CoverageStandard::NativeComplete
        );
        assert_eq!(
            "NATIVE_COMPLETE".parse::<CoverageStandard>().unwrap(),
            CoverageStandard::NativeComplete
        );
        assert_eq!(
            "  Exhaustive ".parse::<CoverageStandard>().unwrap(),
            CoverageStandard::Exhaustive
        );

        // Never silently defaulted: a typo that resolved to `summary` would
        // make an unrecognised standard owe nothing.
        let err = "vibes".parse::<CoverageStandard>().unwrap_err();
        assert_eq!(err, UnknownCoverageStandard("vibes".to_string()));
        assert!(err.to_string().contains("native_complete"));
    }

    /// Round-trip the two DB vocabularies so a rename cannot drift from the
    /// CHECK constraints in `migrations/073_obligations.sql`.
    #[test]
    fn db_vocabularies_round_trip() {
        for name in CoverageStandard::VOCABULARY {
            let parsed: CoverageStandard = name.parse().unwrap();
            assert_eq!(parsed.as_str(), *name);
        }
        for v in [
            CoverageVerdict::Satisfied,
            CoverageVerdict::Breach,
            CoverageVerdict::Indeterminate,
            CoverageVerdict::NotApplicable,
        ] {
            assert!(!v.as_str().is_empty());
        }
        assert!(CoverageStandard::Exhaustive.is_countable());
        assert!(!CoverageStandard::Material.is_countable());
    }
}
