//! Promotion gate: determines if a hypothesis is ready to move from
//! hypothesis_assessment to research_validity frame.
//!
//! All four criteria must be met:
//! 1. Real evidence exists (experiment with completed analysis)
//! 2. Provenance independence (v1: at least one completed experiment)
//! 3. Belief threshold: Bel({supported}) >= 0.60 OR Bel({unsupported}) >= 0.60
//! 4. Scope is explicit (analysis has non-empty scope_limitations)

/// Inputs gathered from the database for promotion evaluation.
#[derive(Debug, Clone)]
pub struct PromotionInput {
    /// Belief in {supported} from hypothesis_assessment frame
    pub bel_supported: f64,
    /// Belief in {unsupported} from hypothesis_assessment frame
    pub bel_unsupported: f64,
    /// Number of completed experiments with analysis nodes
    pub completed_experiments_with_analysis: usize,
    /// Whether any analysis has non-empty scope_limitations
    pub has_explicit_scope: bool,
}

/// Result of promotion gate evaluation.
#[derive(Debug, Clone)]
pub struct PromotionResult {
    pub ready: bool,
    pub failures: Vec<PromotionFailure>,
}

/// Individual promotion criterion failure.
#[derive(Debug, Clone, PartialEq)]
pub enum PromotionFailure {
    NoRealEvidence,
    InsufficientBelief {
        bel_supported: f64,
        bel_unsupported: f64,
        threshold: f64,
    },
    NoExplicitScope,
}

const PROMOTION_THRESHOLD: f64 = 0.60;

/// The frame a hypothesis is assessed on until it is promoted.
pub const HYPOTHESIS_ASSESSMENT_FRAME: &str = "hypothesis_assessment";

/// The frame a promotion MOVES the hypothesis's latest assessment onto (the
/// source row is retired in the same transaction, backlog 846b808e).
pub const RESEARCH_VALIDITY_FRAME: &str = "research_validity";

/// The `properties.hypothesis_status` a promotion writes.
pub const PROMOTED_STATUS: &str = "promoted";

/// The frame a hypothesis's status reads its belief from, given its
/// `properties.hypothesis_status`: [`RESEARCH_VALIDITY_FRAME`] once it is
/// promoted, since the promotion moved its evidence there, and
/// [`HYPOTHESIS_ASSESSMENT_FRAME`] otherwise. Reading the old frame after a
/// promotion reports zero belief, or another agent's later BBA (backlog
/// 090221d9).
#[must_use]
pub fn status_belief_frame(hypothesis_status: Option<&str>) -> &'static str {
    if hypothesis_status == Some(PROMOTED_STATUS) {
        RESEARCH_VALIDITY_FRAME
    } else {
        HYPOTHESIS_ASSESSMENT_FRAME
    }
}

/// The frame NEW evidence on a hypothesis is filed on, given its
/// `properties.hypothesis_status`: the frame its status reads
/// ([`status_belief_frame`]). Writers follow the readers (operator ruling
/// R-8): evidence filed on `hypothesis_assessment` after a promotion is read by
/// no reader of the promoted hypothesis.
#[must_use]
pub fn evidence_frame(hypothesis_status: Option<&str>) -> &'static str {
    status_belief_frame(hypothesis_status)
}

/// For a writer whose caller NAMES the frame (`POST /frames/:id/evidence`, MCP
/// `submit_ds_evidence`): the frame the evidence goes to instead of `named`, if
/// any. Only [`HYPOTHESIS_ASSESSMENT_FRAME`] on a promoted hypothesis is
/// redirected (to [`evidence_frame`]'s answer, `research_validity`); every
/// other frame is the caller's to choose.
#[must_use]
pub fn redirected_evidence_frame(
    named: &str,
    hypothesis_status: Option<&str>,
) -> Option<&'static str> {
    if named != HYPOTHESIS_ASSESSMENT_FRAME {
        return None;
    }
    let target = evidence_frame(hypothesis_status);
    (target != named).then_some(target)
}

/// `properties.hypothesis_status` of `hypothesis`, read through `viewer`
/// (`None` for a claim the viewer cannot read, or one without a status).
async fn hypothesis_status_of(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    hypothesis: uuid::Uuid,
) -> Result<Option<String>, epigraph_db::DbError> {
    Ok(
        epigraph_db::ClaimRepository::content_and_properties(&mut *conn, viewer, hypothesis)
            .await?
            .and_then(|(_, props)| {
                props
                    .get("hypothesis_status")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            }),
    )
}

/// The name of the frame a hypothesis-evidence writer (the experiment
/// `analyze` route and CLI) files `hypothesis`'s new evidence on:
/// [`evidence_frame`] of its status, read through `viewer`.
///
/// # Errors
/// `DbError` when the read fails.
pub async fn hypothesis_evidence_frame(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    hypothesis: uuid::Uuid,
) -> Result<&'static str, epigraph_db::DbError> {
    let status = hypothesis_status_of(&mut *conn, viewer, hypothesis).await?;
    Ok(evidence_frame(status.as_deref()))
}

/// For a writer whose caller names `frame_id`: the frame row new evidence on
/// `claim` goes to INSTEAD ([`redirected_evidence_frame`]), or `None` to file
/// it where it was named. Reads the named frame, the claim's status and the
/// target frame through `viewer`.
///
/// # Errors
/// `DbError::NotFound` when the target frame does not exist (no promotion can
/// have happened without it); `DbError::InvalidData` when it has a different
/// number of hypotheses than the named frame (the caller's masses would not
/// address it); `DbError` when a read fails.
pub async fn promoted_hypothesis_evidence_frame(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim: uuid::Uuid,
    frame_id: uuid::Uuid,
) -> Result<Option<epigraph_db::FrameRow>, epigraph_db::DbError> {
    use epigraph_db::FrameRepository;
    let Some(named) = FrameRepository::get_by_id(&mut *conn, viewer, frame_id).await? else {
        return Ok(None);
    };
    if named.name != HYPOTHESIS_ASSESSMENT_FRAME {
        return Ok(None);
    }
    let status = hypothesis_status_of(&mut *conn, viewer, claim).await?;
    let Some(target) = redirected_evidence_frame(&named.name, status.as_deref()) else {
        return Ok(None);
    };
    let Some(row) = FrameRepository::get_by_name(&mut *conn, viewer, target).await? else {
        return Err(epigraph_db::DbError::NotFound {
            entity: format!("frame {target}"),
            id: frame_id,
        });
    };
    if row.hypotheses.len() != named.hypotheses.len() {
        return Err(epigraph_db::DbError::InvalidData {
            reason: format!(
                "hypothesis {claim} is promoted, so its evidence is filed on {target}, but \
                 {target} has {} hypotheses and {} has {}; nothing was written",
                row.hypotheses.len(),
                named.name,
                named.hypotheses.len()
            ),
        });
    }
    Ok(Some(row))
}

/// The warning a redirected write returns ([`promoted_hypothesis_evidence_frame`]).
#[must_use]
pub fn redirected_evidence_warning(
    claim: uuid::Uuid,
    named: uuid::Uuid,
    filed: uuid::Uuid,
) -> String {
    format!(
        "hypothesis {claim} is promoted: its readers read {RESEARCH_VALIDITY_FRAME}, so this \
         evidence was filed on {RESEARCH_VALIDITY_FRAME} ({filed}) instead of the named \
         {HYPOTHESIS_ASSESSMENT_FRAME} frame ({named})."
    )
}

/// Evaluate whether a hypothesis meets promotion criteria.
pub fn evaluate_promotion(input: &PromotionInput) -> PromotionResult {
    let mut failures = Vec::new();

    // Criterion 1 & 2: Real evidence from completed experiment
    if input.completed_experiments_with_analysis == 0 {
        failures.push(PromotionFailure::NoRealEvidence);
    }

    // Criterion 3: Belief threshold (either direction)
    if input.bel_supported < PROMOTION_THRESHOLD && input.bel_unsupported < PROMOTION_THRESHOLD {
        failures.push(PromotionFailure::InsufficientBelief {
            bel_supported: input.bel_supported,
            bel_unsupported: input.bel_unsupported,
            threshold: PROMOTION_THRESHOLD,
        });
    }

    // Criterion 4: Explicit scope
    if !input.has_explicit_scope {
        failures.push(PromotionFailure::NoExplicitScope);
    }

    PromotionResult {
        ready: failures.is_empty(),
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reads_research_validity_only_once_promoted() {
        assert_eq!(status_belief_frame(Some("promoted")), "research_validity");
        for other in [None, Some("open"), Some("testing"), Some("Promoted")] {
            assert_eq!(
                status_belief_frame(other),
                "hypothesis_assessment",
                "{other:?}"
            );
        }
    }

    #[test]
    fn evidence_follows_the_status_reader() {
        for status in [None, Some("active"), Some("promoted"), Some("Promoted")] {
            assert_eq!(
                evidence_frame(status),
                status_belief_frame(status),
                "{status:?}"
            );
        }
        assert_eq!(
            redirected_evidence_frame("hypothesis_assessment", Some("promoted")),
            Some("research_validity")
        );
        for (named, status) in [
            ("hypothesis_assessment", None),
            ("hypothesis_assessment", Some("active")),
            ("research_validity", Some("promoted")),
            ("binary_truth", Some("promoted")),
        ] {
            assert_eq!(
                redirected_evidence_frame(named, status),
                None,
                "{named} {status:?}"
            );
        }
    }

    #[test]
    fn all_criteria_met_supported() {
        let input = PromotionInput {
            bel_supported: 0.72,
            bel_unsupported: 0.05,
            completed_experiments_with_analysis: 1,
            has_explicit_scope: true,
        };
        let result = evaluate_promotion(&input);
        assert!(result.ready);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn all_criteria_met_unsupported() {
        let input = PromotionInput {
            bel_supported: 0.05,
            bel_unsupported: 0.65,
            completed_experiments_with_analysis: 1,
            has_explicit_scope: true,
        };
        let result = evaluate_promotion(&input);
        assert!(result.ready);
    }

    #[test]
    fn no_evidence_fails() {
        let input = PromotionInput {
            bel_supported: 0.72,
            bel_unsupported: 0.05,
            completed_experiments_with_analysis: 0,
            has_explicit_scope: true,
        };
        let result = evaluate_promotion(&input);
        assert!(!result.ready);
        assert!(result.failures.contains(&PromotionFailure::NoRealEvidence));
    }

    #[test]
    fn insufficient_belief_fails() {
        let input = PromotionInput {
            bel_supported: 0.45,
            bel_unsupported: 0.30,
            completed_experiments_with_analysis: 1,
            has_explicit_scope: true,
        };
        let result = evaluate_promotion(&input);
        assert!(!result.ready);
        assert!(result
            .failures
            .iter()
            .any(|f| matches!(f, PromotionFailure::InsufficientBelief { .. })));
    }

    #[test]
    fn no_scope_fails() {
        let input = PromotionInput {
            bel_supported: 0.72,
            bel_unsupported: 0.05,
            completed_experiments_with_analysis: 1,
            has_explicit_scope: false,
        };
        let result = evaluate_promotion(&input);
        assert!(!result.ready);
        assert!(result.failures.contains(&PromotionFailure::NoExplicitScope));
    }

    #[test]
    fn multiple_failures_collected() {
        let input = PromotionInput {
            bel_supported: 0.30,
            bel_unsupported: 0.20,
            completed_experiments_with_analysis: 0,
            has_explicit_scope: false,
        };
        let result = evaluate_promotion(&input);
        assert!(!result.ready);
        assert_eq!(result.failures.len(), 3);
    }

    #[test]
    fn exactly_at_threshold_passes() {
        let input = PromotionInput {
            bel_supported: 0.60,
            bel_unsupported: 0.10,
            completed_experiments_with_analysis: 1,
            has_explicit_scope: true,
        };
        let result = evaluate_promotion(&input);
        assert!(result.ready);
    }
}
