//! Legacy evidence-type backfill for `mass_functions` (backlog bc06ec6f).
//!
//! # What it is for
//!
//! #573 made every BBA write path store the canonical evidence type. Rows
//! written before it keep `evidence_type` NULL, and an untyped row is invisible
//! to the perspective lens and to `calibration.toml [evidence_type_weights]`:
//! `effective_source_strength` returns its stored `source_strength` (or 0.5)
//! instead. This module types the legacy rows whose stored provenance
//! DETERMINES their type, and leaves every other row NULL, counted by reason.
//!
//! # How a type is derived: the way #573's writers do, never guessed
//!
//! Every type goes through [`CalibrationConfig::canonical_evidence_type`], the
//! function #573's writers call, and must resolve to a calibrated key. The
//! rules (first match wins) are the strict safe set of the 2026-10-12 typing
//! study (precision 0.995 on its sample), each tied to the #573 writer it
//! mirrors:
//!
//! * the claim's own declared type (`properties.evidence_type`), only when it
//!   is one of the five keys `submit_claim` accepts ([`DECLARABLE_TYPES`]), as
//!   `ds_auto.rs::auto_wire_ds_for_claim` stores canonical(param);
//! * the linked evidence row's tag when that tag is `reference`, as
//!   `backfill_factors` stores canonical(linked tag);
//! * `interview_extraction` rows as `testimonial`, the value #573 names for
//!   that writer.
//!
//! A row is left NULL, and counted, when it is:
//!
//! * a cached combination row (the SAME predicate the combine-input readers
//!   exclude, `epigraph_db::repos::mass_function::cached_combination_predicate`),
//!   or an unlabelled agent-less row sharing its (claim, frame) with another BBA
//!   (the pre-b5cb3efb single-input cache copy): an aggregate has no single type;
//! * from a writer #573 keeps untyped on purpose (`error_derived`, `prior`):
//!   their only type source is caller-declared and would RAISE the weight;
//! * not evidence (`test`, `backlog*` / `content-draft` labels), or a
//!   propagated BBA whose relationship was never stored;
//! * typed by a rule the study measured as unsafe or provisional: a linked
//!   `observation` / `testimony` / `computation` / `document` tag (right on 7
//!   of 53 `observation` rows), a declared alias or a generic declared type, a
//!   deciding methodology, a regulatory hint, a claim `source_type`;
//! * an OpenStax extractor row with nothing but its agent's NAME to go on. The
//!   study measured that rule at 524/524, but it is an inference from a name,
//!   not a stored type, and it moves ~120k rows from 0.3 to 0.85: that is an
//!   operator decision, so it is counted separately and never applied here;
//! * anything else with no determining stored field.
//!
//! # What it changes
//!
//! Only `mass_functions.evidence_type`, only on rows that are still untyped
//! when the batch is written. The effect on belief is exactly the documented
//! lens effect: `effective_source_strength` switches a typed row from its
//! stored `source_strength` to the calibrated weight of its type (times the
//! locality factor). No calibration weight, mass, source_strength or other
//! column changes, and no cached belief is recomputed: run the belief
//! recompute afterwards.

use std::collections::BTreeMap;

use epigraph_db::repos::mass_function::{MassFunctionRepository, UntypedBbaProvenance};
use epigraph_engine::calibration::CalibrationConfig;
use serde::Serialize;
use uuid::Uuid;

/// The keys `submit_claim` accepts as a declared evidence type
/// (`epigraph-mcp/src/tools/claims.rs::parse_evidence_type`). A claim's
/// declared type is copied only when it is one of these, spelled as a key.
pub const DECLARABLE_TYPES: [&str; 5] = [
    "empirical",
    "statistical",
    "logical",
    "testimonial",
    "circumstantial",
];

/// Why a rule typed a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    /// The claim's declared `properties.evidence_type`.
    DeclaredType,
    /// The linked evidence row's `reference` tag.
    LinkedReference,
    /// An `interview_extraction` BBA.
    InterviewExtraction,
}

/// Why a row is left NULL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaveNull {
    CachedCombination,
    UnlabelledSharedSlot,
    UntypedByDesign,
    NotEvidence,
    RelationshipNotStored,
    RegulatoryProvisional,
    DeclaredTypeNotDeclarable,
    DeclaredTypeWithMethodology,
    MethodologyOnly,
    LinkedTagUnreliable,
    GenericDeclaredType,
    SourceTypeProvisional,
    OpenstaxAgentNameOnly,
    Uncalibrated,
    NoDeterminingField,
}

/// The decision for one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Type { evidence_type: String, rule: Rule },
    LeaveNull(LeaveNull),
}

/// Writers #573 keeps untyped on purpose: their only type source is declared
/// by the submitter and would raise the weight (`error_derived`), or the row
/// is not evidence at all (`prior`, a vacuous hypothesis prior).
const UNTYPED_BY_DESIGN: [&str; 2] = ["error_derived", "prior"];

/// Methodologies that decide nothing about the kind of support (the typing
/// study's rules fall through them to the evidence row). Any other non-blank
/// methodology may contradict a declared or linked type, so it stops the rules.
const NON_DECIDING_METHODOLOGIES: [&str; 5] = [
    "extraction",
    "llm_extraction",
    "negative_result",
    "inductive",
    "inductive_generalization",
];

/// The claim `source_type`s the study's provisional D10 rule would have typed
/// `logical`. Measured on too few rows to apply; they stop the rules.
const PROVISIONAL_SOURCE_TYPES: [&str; 3] = ["textbook", "paper", "internaldocument"];

fn norm(v: Option<&str>) -> Option<String> {
    v.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty())
}

/// `raw` through the writers' canonicalization, kept only when it names a
/// calibrated key: a type the lens cannot weigh is not worth writing.
fn canonical_calibrated(calibration: &CalibrationConfig, raw: &str) -> Option<String> {
    calibration
        .canonical_evidence_type(raw)
        .filter(|k| calibration.evidence_type_weight_present(k))
}

fn typed_or_uncalibrated(calibration: &CalibrationConfig, raw: &str, rule: Rule) -> Decision {
    canonical_calibrated(calibration, raw).map_or(
        Decision::LeaveNull(LeaveNull::Uncalibrated),
        |evidence_type| Decision::Type {
            evidence_type,
            rule,
        },
    )
}

/// Decide one row's type from its stored provenance. First match wins; see
/// the module documentation for each rule and each reason.
#[must_use]
pub fn decide(row: &UntypedBbaProvenance, calibration: &CalibrationConfig) -> Decision {
    use LeaveNull as N;

    // An aggregate has no single type.
    if row.cached_combination {
        return Decision::LeaveNull(N::CachedCombination);
    }
    if row.unlabelled_slot_shared {
        return Decision::LeaveNull(N::UnlabelledSharedSlot);
    }

    let method = row.combination_method.as_deref().unwrap_or("");
    if UNTYPED_BY_DESIGN.contains(&method) {
        return Decision::LeaveNull(N::UntypedByDesign);
    }
    let not_evidence_label = row
        .claim_labels
        .iter()
        .any(|l| l == "backlog" || l.starts_with("backlog:") || l == "content-draft");
    if method == "test" || not_evidence_label {
        return Decision::LeaveNull(N::NotEvidence);
    }
    if method.starts_with("propagated_") {
        return Decision::LeaveNull(N::RelationshipNotStored);
    }
    let regulatory_doi =
        norm(row.claim_source_doi.as_deref()).is_some_and(|d| d.starts_with("cbc-"));
    let regulatory_perspective =
        norm(row.perspective_name.as_deref()).is_some_and(|p| p.contains("regulatory"));
    if regulatory_doi || regulatory_perspective {
        return Decision::LeaveNull(N::RegulatoryProvisional);
    }

    let deciding_methodology = norm(row.claim_methodology.as_deref())
        .is_some_and(|m| !NON_DECIDING_METHODOLOGIES.contains(&m.as_str()));
    let declared = norm(row.claim_evidence_type.as_deref());
    let generic_declared = declared
        .as_deref()
        .is_some_and(|d| d == "document" || d == "reference");

    // The claim's own declared type, as submit_claim would have stored it.
    if let Some(d) = declared.as_deref().filter(|_| !generic_declared) {
        if !DECLARABLE_TYPES.contains(&d) {
            return Decision::LeaveNull(N::DeclaredTypeNotDeclarable);
        }
        if deciding_methodology {
            return Decision::LeaveNull(N::DeclaredTypeWithMethodology);
        }
        return typed_or_uncalibrated(calibration, d, Rule::DeclaredType);
    }
    if deciding_methodology {
        return Decision::LeaveNull(N::MethodologyOnly);
    }

    // The linked evidence row's tag: only `reference` is reliable enough.
    if let Some(tag) = norm(row.linked_evidence_type.as_deref()) {
        if tag == "reference" {
            return typed_or_uncalibrated(calibration, &tag, Rule::LinkedReference);
        }
        return Decision::LeaveNull(N::LinkedTagUnreliable);
    }
    if generic_declared {
        return Decision::LeaveNull(N::GenericDeclaredType);
    }
    if norm(row.claim_source_type.as_deref())
        .is_some_and(|s| PROVISIONAL_SOURCE_TYPES.contains(&s.as_str()))
    {
        return Decision::LeaveNull(N::SourceTypeProvisional);
    }
    if method == "interview_extraction" {
        return typed_or_uncalibrated(calibration, "testimonial", Rule::InterviewExtraction);
    }

    // An OpenStax extractor, known only by its agent's NAME: an operator
    // decision (see the module documentation), never applied here.
    let openstax = norm(row.agent_name.as_deref()).is_some_and(|a| {
        a.split_once(':').is_some_and(|(class, suffix)| {
            (class == "textbook-extractor" || class == "paper-extractor")
                && suffix.starts_with("openstax")
        })
    });
    if openstax {
        return Decision::LeaveNull(N::OpenstaxAgentNameOnly);
    }
    Decision::LeaveNull(N::NoDeterminingField)
}

/// Per-writer counts. The writer is `combination_method`, `<null>` when NULL.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WriterCounts {
    pub scanned: u64,
    /// Rows typed (in a dry run: that would be typed), by type.
    pub typed: BTreeMap<String, u64>,
    /// Rows typed, by rule.
    pub typed_by_rule: BTreeMap<Rule, u64>,
    /// Rows left NULL, by reason.
    pub left_null: BTreeMap<LeaveNull, u64>,
}

/// What a run did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub applied: bool,
    pub batches: u64,
    pub scanned: u64,
    /// Rows the decision typed (in a dry run: would type).
    pub decided_typed: u64,
    /// Rows actually written (always 0 in a dry run).
    pub written: u64,
    pub left_null: u64,
    /// The last id scanned: pass it as `--after` to resume.
    pub last_id: Option<Uuid>,
    /// FALSE when the run stopped at `max_batches` with rows left to scan.
    pub complete: bool,
    pub per_writer: BTreeMap<String, WriterCounts>,
}

/// How to run.
#[derive(Debug, Clone)]
pub struct Options {
    pub apply: bool,
    pub batch: i64,
    pub after: Option<Uuid>,
    pub max_batches: Option<u64>,
}

/// Scan every untyped BBA after `opts.after` in `id` order, `opts.batch` at a
/// time, decide each, and (with `opts.apply`) write each batch's typed rows in
/// its own transaction. `conn` must be the maintenance connection.
///
/// # Errors
/// A database error. Batches already written stay written; the error's
/// batch is rolled back, and `--after` resumes from the last good batch.
pub async fn run(
    conn: &mut sqlx::PgConnection,
    calibration: &CalibrationConfig,
    opts: &Options,
) -> Result<Report, epigraph_db::DbError> {
    use sqlx::Acquire as _;

    let batch = opts.batch.max(1);
    let mut report = Report {
        applied: opts.apply,
        last_id: opts.after,
        ..Report::default()
    };
    let mut after = opts.after;
    loop {
        if opts.max_batches.is_some_and(|m| report.batches >= m) {
            report.complete = false;
            return Ok(report);
        }
        let page =
            MassFunctionRepository::untyped_provenance_page(&mut *conn, after, batch).await?;
        let Some(last) = page.last() else {
            report.complete = true;
            return Ok(report);
        };
        after = Some(last.id);
        report.batches += 1;

        let mut ids = Vec::new();
        let mut types = Vec::new();
        for row in &page {
            let writer = row
                .combination_method
                .clone()
                .unwrap_or_else(|| "<null>".to_string());
            let counts = report.per_writer.entry(writer).or_default();
            counts.scanned += 1;
            report.scanned += 1;
            match decide(row, calibration) {
                Decision::Type {
                    evidence_type,
                    rule,
                } => {
                    *counts.typed.entry(evidence_type.clone()).or_default() += 1;
                    *counts.typed_by_rule.entry(rule).or_default() += 1;
                    report.decided_typed += 1;
                    ids.push(row.id);
                    types.push(evidence_type);
                }
                Decision::LeaveNull(reason) => {
                    *counts.left_null.entry(reason).or_default() += 1;
                    report.left_null += 1;
                }
            }
        }

        if opts.apply && !ids.is_empty() {
            let mut tx = conn.begin().await?;
            report.written += MassFunctionRepository::backfill_evidence_type_where_untyped(
                &mut *tx, &ids, &types,
            )
            .await?;
            tx.commit().await?;
        }
        report.last_id = after;
        if i64::try_from(page.len()).unwrap_or(i64::MAX) < batch {
            report.complete = true;
            return Ok(report);
        }
    }
}
