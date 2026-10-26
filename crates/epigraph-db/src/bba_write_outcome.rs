//! What a BBA upsert does to the writer's own row (backlogs bcbe34b2, 6f82db4f).
//!
//! A BBA is upserted on `(claim, frame, source agent, perspective)`
//! (`mass_functions_unique_per_perspective`), and the upsert returns only the
//! row id, so an identical resubmission, a silent replacement and a first
//! submission all look alike to the caller. Both evidence-submission surfaces,
//! MCP `submit_ds_evidence` and `POST /api/v1/frames/:id/evidence`, read the
//! caller's row for the key on their write transaction before storing, and
//! report with [`classify`] what the store does to it. One probe, so the two
//! transports cannot disagree about the same write.
//!
//! The comparison is against what the CALLER'S path stores, column for column
//! ([`BbaWrite`]): the two paths store different things for the same request
//! (the REST route stores reliability-discounted masses with
//! `source_strength = 1.0` under `'discount'`; MCP stores its masses with a
//! NULL `source_strength` under the caller's combination method).
//!
//! No SQL lives here: the prior row comes from the caller's own repository
//! read (`MassFunctionRepository::get_for_claim_frame`, filtered by
//! [`prior_for`]).

use crate::MassFunctionRow;
use uuid::Uuid;

/// Masses closer than this are the same mass (they round-trip through JSONB).
const MASS_EPSILON: f64 = 1e-12;

/// What one BBA upsert does to the writer's row for its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbaWriteOutcome {
    /// No row held the key: a new BBA.
    Inserted,
    /// The row already held exactly this BBA: nothing changed, and nothing new
    /// is combined on its account.
    Unchanged,
    /// The row held a different BBA, which this write overwrote under the same
    /// id (the key holds one row; it is not added beside it).
    Replaced,
}

impl BbaWriteOutcome {
    /// The wire value (`write_outcome`): `inserted`, `unchanged`, `replaced`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inserted => "inserted",
            Self::Unchanged => "unchanged",
            Self::Replaced => "replaced",
        }
    }

    /// The `deduplicated` flag: true exactly when [`Self::Unchanged`].
    #[must_use]
    pub const fn deduplicated(self) -> bool {
        matches!(self, Self::Unchanged)
    }
}

/// Every column the upsert writes, as the caller is about to write it.
#[derive(Debug, Clone, Copy)]
pub struct BbaWrite<'a> {
    /// The masses as stored (after any discount the path applies).
    pub masses: &'a serde_json::Value,
    pub combination_method: &'a str,
    pub evidence_type: Option<&'a str>,
    pub locality_tag: &'a str,
    pub source_strength: Option<f64>,
    pub conflict_k: Option<f64>,
    pub evidence_id: Option<Uuid>,
}

/// The writer's row for the upsert key among `rows` (one claim and frame):
/// the row whose source agent and perspective are the write's.
#[must_use]
pub fn prior_for(
    rows: &[MassFunctionRow],
    agent: Option<Uuid>,
    perspective: Option<Uuid>,
) -> Option<&MassFunctionRow> {
    rows.iter()
        .find(|row| row.source_agent_id == agent && row.perspective_id == perspective)
}

/// Whether `row` already holds exactly what `write` stores: the same focal
/// elements with masses within 1e-12, and the same value in every other
/// column the upsert writes.
#[must_use]
pub fn restates(row: &MassFunctionRow, write: &BbaWrite<'_>) -> bool {
    let same_masses = match (row.masses.as_object(), write.masses.as_object()) {
        (Some(old), Some(new)) => {
            old.len() == new.len()
                && new.iter().all(|(k, v)| {
                    match (old.get(k).and_then(serde_json::Value::as_f64), v.as_f64()) {
                        (Some(a), Some(b)) => (a - b).abs() <= MASS_EPSILON,
                        _ => false,
                    }
                })
        }
        _ => false,
    };
    let same_scalar = |a: Option<f64>, b: Option<f64>| match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => (a - b).abs() <= MASS_EPSILON,
        _ => false,
    };
    same_masses
        && row.combination_method.as_deref() == Some(write.combination_method)
        && row.evidence_type.as_deref() == write.evidence_type
        && row.locality_tag == write.locality_tag
        && same_scalar(row.source_strength, write.source_strength)
        && same_scalar(row.conflict_k, write.conflict_k)
        && row.evidence_id == write.evidence_id
}

/// What storing `write` does to `prior`, the writer's row for its key.
#[must_use]
pub fn classify(prior: Option<&MassFunctionRow>, write: &BbaWrite<'_>) -> BbaWriteOutcome {
    match prior {
        None => BbaWriteOutcome::Inserted,
        Some(row) if restates(row, write) => BbaWriteOutcome::Unchanged,
        Some(_) => BbaWriteOutcome::Replaced,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(masses: serde_json::Value, strength: Option<f64>) -> MassFunctionRow {
        MassFunctionRow {
            id: Uuid::nil(),
            claim_id: Uuid::nil(),
            frame_id: Uuid::nil(),
            source_agent_id: None,
            perspective_id: None,
            masses,
            conflict_k: None,
            combination_method: Some("discount".to_string()),
            source_strength: strength,
            evidence_type: Some("statistical".to_string()),
            locality_tag: "unknown".to_string(),
            evidence_id: None,
            created_at: chrono::Utc::now(),
        }
    }

    fn write<'a>(masses: &'a serde_json::Value, strength: Option<f64>) -> BbaWrite<'a> {
        BbaWrite {
            masses,
            combination_method: "discount",
            evidence_type: Some("statistical"),
            locality_tag: "unknown",
            source_strength: strength,
            conflict_k: None,
            evidence_id: None,
        }
    }

    #[test]
    fn each_outcome_and_the_source_strength_column() {
        let m = serde_json::json!({"0": 0.56, "0,1": 0.44});
        let stored = row(m.clone(), Some(1.0));
        assert_eq!(
            classify(None, &write(&m, Some(1.0))),
            BbaWriteOutcome::Inserted
        );
        assert_eq!(
            classify(Some(&stored), &write(&m, Some(1.0))),
            BbaWriteOutcome::Unchanged
        );
        // The REST path stores source_strength 1.0; a probe that assumed MCP's
        // NULL would call every identical REST resubmission a replacement.
        assert_eq!(
            classify(Some(&stored), &write(&m, None)),
            BbaWriteOutcome::Replaced
        );
        let other = serde_json::json!({"0": 0.35, "0,1": 0.65});
        assert_eq!(
            classify(Some(&stored), &write(&other, Some(1.0))),
            BbaWriteOutcome::Replaced
        );
        let wider = serde_json::json!({"0": 0.56, "1": 0.0, "0,1": 0.44});
        assert_eq!(
            classify(Some(&stored), &write(&wider, Some(1.0))),
            BbaWriteOutcome::Replaced,
            "an extra focal element is a different BBA"
        );
        assert!(BbaWriteOutcome::Unchanged.deduplicated());
        assert!(!BbaWriteOutcome::Replaced.deduplicated());
        assert_eq!(BbaWriteOutcome::Replaced.as_str(), "replaced");
    }
}
