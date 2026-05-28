//! Library-level `get_belief` function.
//!
//! Lifted from `epigraph-mcp/src/tools/ds.rs` so episcience and other crates
//! can call it with `(pool, claim_id, frame_id)` without spawning MCP-over-stdio.
//!
//! The MCP handler in `tools/ds.rs` becomes a thin adapter that delegates here
//! and shapes the result into a `CallToolResult`.

use std::collections::BTreeSet;

use epigraph_core::ClaimId;
use epigraph_db::{
    ClaimRepository, FrameRepository, MassFunctionRepository, MassFunctionRow,
    PerspectiveRepository, PgPool,
};
use epigraph_ds::{
    combination::{self, CombinationMethod},
    FocalElement, FrameOfDiscernment, MassFunction,
};
use thiserror::Error;
use uuid::Uuid;

/// Errors from the library-level `get_belief` function.
#[derive(Debug, Error)]
pub enum BeliefQueryError {
    /// Database access failed.
    #[error("database error: {0}")]
    Db(#[from] epigraph_db::DbError),

    /// Dempster-Shafer computation failed (e.g. total conflict, empty frame).
    #[error("DS computation error: {0}")]
    Ds(#[from] epigraph_ds::DsError),

    /// Failed to parse mass function JSON (returned as `String` by `from_json_masses`).
    #[error("failed to parse mass function: {0}")]
    ParseMasses(String),

    /// The requested frame does not exist.
    #[error("frame {0} not found")]
    FrameNotFound(Uuid),

    /// The requested claim does not exist.
    #[error("claim {0} not found")]
    ClaimNotFound(Uuid),
}

/// Result of a belief query.
///
/// Mirrors the fields returned by the MCP `get_belief` tool.
#[derive(Debug, Clone, PartialEq)]
pub struct BeliefInterval {
    /// Dempster-Shafer belief (lower bound on probability).
    pub belief: f64,
    /// Dempster-Shafer plausibility (upper bound on probability).
    pub plausibility: f64,
    /// Pignistic probability (BetP) — use this for ordering claims.
    pub pignistic_prob: f64,
    /// Mass on the conflict focal element.
    pub mass_on_conflict: f64,
    /// Mass on the missing focal element.
    pub mass_on_missing: f64,
    /// `true` when the result was computed from a specific frame; `false` for
    /// the unframed cached fallback.
    pub framed: bool,
    /// Short string describing how the value was derived.
    ///
    /// Possible values: `"recomputed"`, `"no_bbas"`, `"cached"`.
    pub source: String,
}

impl BeliefInterval {
    /// Default returned when the frame exists but has no BBAs for this claim.
    pub fn empty_frame(hypothesis_count: usize) -> Self {
        Self {
            belief: 0.0,
            plausibility: 1.0,
            pignistic_prob: 1.0 / hypothesis_count as f64,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.0,
            framed: true,
            source: "no_bbas".to_string(),
        }
    }

    /// Default returned when no frame is specified and the claim has no DS data.
    pub fn cached_from_truth(truth_value: f64) -> Self {
        Self {
            belief: truth_value,
            plausibility: 1.0,
            pignistic_prob: truth_value,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.0,
            framed: false,
            source: "cached".to_string(),
        }
    }
}

/// Query belief for `claim_id`, optionally scoped to `frame_id`.
///
/// - If `frame_id` is `Some`, live-recomputes Bel/Pl/BetP from stored BBAs
///   using Dempster's combination rule (mirrors the MCP framed path).
/// - If `frame_id` is `None`, returns the cached DS columns from the claim row
///   (mirrors the MCP unframed path).
///
/// # Errors
///
/// Returns `BeliefQueryError::FrameNotFound` when `frame_id` is specified but
/// the frame does not exist.  Returns `BeliefQueryError::ClaimNotFound` when
/// the claim does not exist (unframed path only).
pub async fn get_belief(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Option<Uuid>,
) -> Result<BeliefInterval, BeliefQueryError> {
    if let Some(frame_id) = frame_id {
        // ── Framed path: live recomputation from stored BBAs ──────────────
        let frame_row = FrameRepository::get_by_id(pool, frame_id)
            .await?
            .ok_or(BeliefQueryError::FrameNotFound(frame_id))?;

        let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())?;

        let assignment = FrameRepository::get_claim_assignment(pool, claim_id, frame_id).await?;
        let hypothesis_index = assignment.and_then(|a| a.hypothesis_index).unwrap_or(0) as usize;

        let all_bbas =
            MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id).await?;

        if all_bbas.is_empty() {
            return Ok(BeliefInterval::empty_frame(frame.hypothesis_count()));
        }

        let mut mass_fns: Vec<MassFunction> = Vec::with_capacity(all_bbas.len());
        for row in &all_bbas {
            let mf = MassFunction::from_json_masses(frame.clone(), &row.masses)
                .map_err(BeliefQueryError::ParseMasses)?;
            mass_fns.push(mf);
        }

        let combined = if mass_fns.len() == 1 {
            mass_fns.into_iter().next().expect("checked len == 1")
        } else {
            let mut result = mass_fns[0].clone();
            for mf in &mass_fns[1..] {
                result = combination::redistribute(&result, mf, CombinationMethod::Dempster, None)
                    .map_err(BeliefQueryError::Ds)?;
            }
            result
        };

        let target = FocalElement::positive(BTreeSet::from([hypothesis_index]));
        let bel = epigraph_ds::measures::belief(&combined, &target);
        let pl = epigraph_ds::measures::plausibility(&combined, &target);
        let betp = epigraph_ds::measures::pignistic_probability(&combined, hypothesis_index);

        return Ok(BeliefInterval {
            belief: bel,
            plausibility: pl,
            pignistic_prob: betp,
            mass_on_conflict: combined.mass_of_conflict(),
            mass_on_missing: combined.mass_of_missing(),
            framed: true,
            source: "recomputed".to_string(),
        });
    }

    // ── Unframed path: cached DS columns from claim row ───────────────────
    let claim = ClaimRepository::get_by_id(pool, ClaimId::from_uuid(claim_id))
        .await?
        .ok_or(BeliefQueryError::ClaimNotFound(claim_id))?;

    Ok(BeliefInterval::cached_from_truth(claim.truth_value.value()))
}

/// Compute a **perspective-scoped** belief on demand — the "frame function".
///
/// This is `get_belief`'s framed path re-weighted from one observer's
/// viewpoint: every stored BBA on `(claim, frame)` is Shafer-discounted by the
/// perspective's reliability for that BBA's `evidence_type` tag before
/// combination. Because it recomputes from the labelled BBAs, it works
/// regardless of how the evidence was ingested — there is no cache to populate
/// and no dependency on a particular write path. A perspective with no
/// `source_reliability` map (or an absent perspective) discounts nothing, so it
/// reproduces the global `get_belief` value.
///
/// # Errors
/// `FrameNotFound` if `frame_id` is absent; `ParseMasses`/`Ds` on malformed or
/// uncombinable BBAs; `Db` on query failure.
pub async fn get_perspective_belief(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Uuid,
    perspective_id: Uuid,
) -> Result<BeliefInterval, BeliefQueryError> {
    let frame_row = FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(BeliefQueryError::FrameNotFound(frame_id))?;
    let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())?;

    let assignment = FrameRepository::get_claim_assignment(pool, claim_id, frame_id).await?;
    let hypothesis_index = assignment.and_then(|a| a.hypothesis_index).unwrap_or(0) as usize;

    let all_bbas = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id).await?;
    if all_bbas.is_empty() {
        return Ok(BeliefInterval::empty_frame(frame.hypothesis_count()));
    }

    // The perspective's source-reliability map; None when the perspective is
    // absent or declares no map → no discount → equals the global belief.
    let reliability = PerspectiveRepository::get_by_id(pool, perspective_id)
        .await?
        .and_then(|p| p.source_reliability());

    let combined = combine_perspective_masses(&all_bbas, reliability.as_ref(), &frame)?
        .expect("all_bbas is non-empty so combination yields Some");

    let target = FocalElement::positive(BTreeSet::from([hypothesis_index]));
    Ok(BeliefInterval {
        belief: epigraph_ds::measures::belief(&combined, &target),
        plausibility: epigraph_ds::measures::plausibility(&combined, &target),
        pignistic_prob: epigraph_ds::measures::pignistic_probability(&combined, hypothesis_index),
        mass_on_conflict: combined.mass_of_conflict(),
        mass_on_missing: combined.mass_of_missing(),
        framed: true,
        source: "recomputed_perspective".to_string(),
    })
}

/// Discount each BBA by `reliability[evidence_type]` (α = 1.0 when the tag is
/// `None` or unmapped) and Dempster-combine, mirroring `get_belief`'s framed
/// combination. Returns `Ok(None)` only when `rows` is empty.
///
/// Pure given its inputs (no DB), so the frame-function math is unit-testable
/// without seeding a claim/frame.
pub fn combine_perspective_masses(
    rows: &[MassFunctionRow],
    reliability: Option<&std::collections::HashMap<String, f64>>,
    frame: &FrameOfDiscernment,
) -> Result<Option<MassFunction>, BeliefQueryError> {
    let mut mass_fns: Vec<MassFunction> = Vec::with_capacity(rows.len());
    for row in rows {
        let mf = MassFunction::from_json_masses(frame.clone(), &row.masses)
            .map_err(BeliefQueryError::ParseMasses)?;
        let alpha = reliability
            .and_then(|m| row.evidence_type.as_deref().and_then(|t| m.get(t)))
            .copied()
            .unwrap_or(1.0);
        mass_fns.push(combination::discount(&mf, alpha)?);
    }

    if mass_fns.is_empty() {
        return Ok(None);
    }
    let combined = if mass_fns.len() == 1 {
        mass_fns.into_iter().next().expect("checked len == 1")
    } else {
        let mut result = mass_fns[0].clone();
        for mf in &mass_fns[1..] {
            result = combination::redistribute(&result, mf, CombinationMethod::Dempster, None)?;
        }
        result
    };
    Ok(Some(combined))
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_ds::measures;
    use std::collections::{BTreeMap, HashMap};

    fn binary() -> FrameOfDiscernment {
        FrameOfDiscernment::new("binary", vec!["H0".to_string(), "H1".to_string()]).unwrap()
    }

    /// A supporting BBA: `mass` on TRUE (H0), the rest on Θ, tagged `evidence_type`.
    fn row(frame: &FrameOfDiscernment, evidence_type: Option<&str>, mass: f64) -> MassFunctionRow {
        let mut bba = BTreeMap::new();
        bba.insert(FocalElement::positive(BTreeSet::from([0])), mass);
        bba.insert(FocalElement::theta(frame), 1.0 - mass);
        let mf = MassFunction::new(frame.clone(), bba).unwrap();
        MassFunctionRow {
            id: Uuid::new_v4(),
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            source_agent_id: None,
            perspective_id: None,
            masses: mf.masses_to_json(),
            conflict_k: None,
            combination_method: Some("auto_wire".to_string()),
            source_strength: Some(1.0),
            evidence_type: evidence_type.map(str::to_string),
            locality_tag: "unknown".to_string(),
            evidence_id: None,
            created_at: chrono::Utc::now(),
        }
    }

    fn bel_h0(frame: &FrameOfDiscernment, mf: &MassFunction) -> f64 {
        let _ = frame;
        measures::belief(mf, &FocalElement::positive(BTreeSet::from([0])))
    }

    #[test]
    fn divergent_beliefs_from_same_evidence() {
        // Same two BBAs (a clinical result + an interview), two observers who
        // trust the interview differently → different belief in H0.
        let frame = binary();
        let rows = [
            row(&frame, Some("western_clinical"), 0.6),
            row(&frame, Some("practitioner_interview"), 0.7),
        ];
        let skeptic = HashMap::from([
            ("western_clinical".to_string(), 1.0),
            ("practitioner_interview".to_string(), 0.3),
        ]);
        let believer = HashMap::from([
            ("western_clinical".to_string(), 1.0),
            ("practitioner_interview".to_string(), 1.0),
        ]);

        let s = combine_perspective_masses(&rows, Some(&skeptic), &frame)
            .unwrap()
            .unwrap();
        let b = combine_perspective_masses(&rows, Some(&believer), &frame)
            .unwrap()
            .unwrap();
        let (sb, bb) = (bel_h0(&frame, &s), bel_h0(&frame, &b));
        assert!(
            sb < bb,
            "skeptic {sb} should believe less than believer {bb}"
        );
        assert!(sb > 0.0 && bb < 1.0);
    }

    #[test]
    fn neutral_perspective_reproduces_global() {
        // An all-α=1.0 believer and the no-map (global) case must combine
        // identically — neutral observer == global belief.
        let frame = binary();
        let rows = [
            row(&frame, Some("western_clinical"), 0.6),
            row(&frame, Some("practitioner_interview"), 0.7),
        ];
        let believer = HashMap::from([
            ("western_clinical".to_string(), 1.0),
            ("practitioner_interview".to_string(), 1.0),
        ]);
        let with_map = combine_perspective_masses(&rows, Some(&believer), &frame)
            .unwrap()
            .unwrap();
        let no_map = combine_perspective_masses(&rows, None, &frame)
            .unwrap()
            .unwrap();
        assert!((bel_h0(&frame, &with_map) - bel_h0(&frame, &no_map)).abs() < 1e-12);
    }

    #[test]
    fn untagged_evidence_is_not_discounted() {
        // A BBA with no evidence_type passes through at α=1.0 even when the
        // perspective has a (non-matching) map — you can't down-weight what you
        // can't identify.
        let frame = binary();
        let tagged = [row(&frame, None, 0.8)];
        let map = HashMap::from([("practitioner_interview".to_string(), 0.1)]);
        let out = combine_perspective_masses(&tagged, Some(&map), &frame)
            .unwrap()
            .unwrap();
        assert!((bel_h0(&frame, &out) - 0.8).abs() < 1e-12);
    }

    #[test]
    fn empty_rows_yield_none() {
        let frame = binary();
        assert!(combine_perspective_masses(&[], None, &frame)
            .unwrap()
            .is_none());
    }
}
