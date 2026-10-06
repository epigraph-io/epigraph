//! Typed call behind the match-candidates page.
//!
//! `GET /api/v1/match_candidates` (`routes/cross_source.rs::list_candidates`,
//! `claims:read`) answers a bare array, ordered by score, highest first. It
//! has no total and no offset. `limit` is required (a request without it is
//! refused before the handler runs) and is not clamped upstream. An absent
//! `status` means every status, so the page always sends one. A candidate is
//! returned only when the viewer may read BOTH claims it names, so an empty
//! list means "none you can read", not "none".

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Api, UpstreamError};

/// The statuses upstream accepts, in the order the switcher shows them.
/// Mirrors the kernel's own validation; anything else is a 400 there.
pub const CANDIDATE_STATUSES: [&str; 4] = ["pending", "promoted", "rejected", "stale"];
/// The status shown when none is asked for.
pub const DEFAULT_STATUS: &str = "pending";
/// Candidates asked for per page. There is no paging upstream, so a list
/// this long may have been cut.
pub const CANDIDATES_LIMIT: u32 = 100;

/// One `PendingCandidateOut`: a pair of claims the matcher scored as
/// possibly the same finding, with each claim's excerpt (cut at 200
/// characters upstream).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Candidate {
    pub id: Uuid,
    pub claim_a: Uuid,
    pub claim_a_excerpt: String,
    pub claim_b: Uuid,
    pub claim_b_excerpt: String,
    pub score: f64,
    #[serde(default)]
    pub verifier_verdict: Option<String>,
    /// Free text written from both claims' content.
    #[serde(default)]
    pub verifier_rationale: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Api<'_> {
    /// `GET /api/v1/match_candidates?status=&limit=`: candidates in `status`
    /// whose two claims the viewer may read, highest score first. `status`
    /// must be one of [`CANDIDATE_STATUSES`]; the caller checks.
    pub async fn match_candidates(
        &self,
        status: &str,
        limit: u32,
    ) -> Result<Vec<Candidate>, UpstreamError> {
        #[derive(Serialize)]
        struct Q<'a> {
            status: &'a str,
            limit: u32,
        }
        let q = Q { status, limit };
        self.get_query("/api/v1/match_candidates", &q).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_candidate_decodes_the_kernels_shape() {
        let row: Candidate = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-4000-9000-000000000001",
            "claim_a": "00000000-0000-4000-8000-000000000001",
            "claim_a_excerpt": "a",
            "claim_b": "00000000-0000-4000-8000-000000000002",
            "claim_b_excerpt": "b",
            "score": 0.5,
            "verifier_verdict": null,
            "verifier_rationale": null,
            "created_at": "2026-09-30T08:09:10.123456+00:00"
        }))
        .expect("decodes");
        assert_eq!(row.claim_b_excerpt, "b");
        assert_eq!(row.verifier_verdict, None);
    }
}
