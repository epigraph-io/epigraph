//! Upstream DTOs and typed calls for the entities area (history, agents,
//! frames, evidence). OWNED BY THE ENTITIES AREA.
//!
//! Field names are copied from the source-verified mapping reports
//! (claims-endpoints §7, graph-entity-endpoints §4-§9). Upstream omits
//! optional fields rather than sending `null`, so everything that is not
//! guaranteed present is `Option<_>` or `#[serde(default)]`. Timestamps stay
//! strings: their format differs per endpoint (`Z` vs `+00:00`), and a
//! display-only field must never fail a whole page's decode. The pages parse
//! them for display and fall back to the raw text.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Api, UpstreamError};

/// Upstream clamps `/agents/:id/claims?limit=` to `1..=100` (`agents.rs:450-461`).
pub const MAX_AGENT_CLAIMS_LIMIT: u32 = 100;
/// `/frames/:id/claims?limit=` is NOT clamped upstream (a negative value is a
/// 500), so the BFF enforces this cap itself (plan §3.5).
pub const MAX_FRAME_CLAIMS_LIMIT: u32 = 100;
/// `sort_by` values `/frames/:id/claims` accepts; anything else is a 400.
pub const FRAME_CLAIM_SORTS: &[&str] = &["belief", "plausibility", "ignorance"];
/// `order` values `/frames/:id/claims` accepts; anything else is a 400.
pub const FRAME_CLAIM_ORDERS: &[&str] = &["desc", "asc"];

// ---- GET /api/v1/claims/:id/history (versioning.rs:102-131) ------------------

/// The `supersedes` chain through a claim, oldest first. NOT `/genealogy`
/// (political propagation, plan §1.3).
///
/// Walks back along `claims.supersedes`, then forward one successor at a
/// time. `mark_duplicate` writes `dup.supersedes = canonical`, so a
/// duplicate appears as a *later*, non-current version of its canonical
/// claim; see `pages::entities::present::duplicate_of`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct VersionHistoryResponse {
    /// Echoes the requested id.
    pub claim_id: Uuid,
    #[serde(default)]
    pub versions: Vec<ClaimVersion>,
    #[serde(default)]
    pub total_versions: usize,
    /// 1-indexed; stays 1 when no version is current.
    #[serde(default)]
    pub current_version: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ClaimVersion {
    pub claim_id: Uuid,
    /// The version's text. `versioning::claim_history` filters the chain
    /// per version (each one is a distinct claim with its own ownership
    /// row) and 404s when nothing is left, so a version this viewer may not
    /// read is a MISSING ROW, never a blanked one. `version` numbering is
    /// positional over what came back.
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub truth_value: Option<f64>,
    /// 1-indexed, oldest first.
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub is_current: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub superseded_by: Option<Uuid>,
}

// ---- GET /api/v1/agents/:id (agents.rs:58-67) --------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct AgentResponse {
    pub id: Uuid,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Hex Ed25519 key (64 chars).
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub orcid: Option<String>,
    #[serde(default)]
    pub ror_id: Option<String>,
}

// ---- GET /api/v1/agents/:id/claims (agents.rs:450-544) -----------------------

/// `PaginatedResponse<AttributedClaimResponse>` (`claims.rs:204-209`).
///
/// "Attributed" is literal: only claims linked by a claim→agent
/// `attributed_to` edge (paper authorship at ingestion). Claims the agent
/// submitted itself (`claims.agent_id`) are NOT here.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct AgentClaimsPage {
    #[serde(default)]
    pub items: Vec<AttributedClaim>,
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// A flattened `ClaimResponse` plus `attribution`; labels and the privacy
/// fields are always omitted (`agents.rs:516-530`).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct AttributedClaim {
    pub id: Uuid,
    /// The claim's text. `agents::agent_claims` filters the rows AND the
    /// `total` off one connection (attribution to a readable agent says
    /// nothing about who may read the claim), so a claim this viewer may
    /// not read is absent and the paging still terminates.
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub truth_value: Option<f64>,
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    #[serde(default)]
    pub trace_id: Option<Uuid>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    /// The edge's `properties` (`{}` by default).
    #[serde(default)]
    pub attribution: serde_json::Value,
}

// ---- GET /api/v1/agents/:id/epistemic-profile (political.rs:39-56) -----------

/// Unbounded upstream (every claim of the agent is loaded), so it can be
/// slow; the page degrades it independently.
///
/// Its claim set is `claims.agent_id` OR attributed/originated edges — a
/// different definition from [`AgentClaimsPage`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EpistemicProfileResponse {
    pub agent_id: Uuid,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub claim_count: u64,
    /// `evidence.evidence_type` column values → fraction.
    #[serde(default)]
    pub evidence_distribution: BTreeMap<String, f64>,
    /// `refuted` / `contested` / `verified` / `active` → fraction.
    #[serde(default)]
    pub epistemic_status_distribution: BTreeMap<String, f64>,
    #[serde(default)]
    pub mean_truth_value: Option<f64>,
    #[serde(default)]
    pub refutation_rate: Option<f64>,
    /// Every distinct label on every claim; can be huge.
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub time_range: Option<TimeRange>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TimeRange {
    #[serde(default)]
    pub first: Option<String>,
    #[serde(default)]
    pub last: Option<String>,
}

// ---- GET /api/v1/frames/:id (belief.rs:50-76) --------------------------------

/// `FrameDetailResponse`. Its `claims` array (every `claim_frames` row,
/// unpaginated) is deliberately not decoded: the page reads claims from the
/// paged `/frames/:id/claims` instead.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct FrameDetailResponse {
    pub frame: FrameResponse,
    #[serde(default)]
    pub claim_count: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct FrameResponse {
    pub id: Uuid,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub hypotheses: Vec<String>,
    #[serde(default)]
    pub parent_frame_id: Option<Uuid>,
    #[serde(default)]
    pub is_refinable: bool,
    #[serde(default)]
    pub version: Option<i32>,
    #[serde(default)]
    pub created_at: Option<String>,
}

// ---- GET /api/v1/frames/:id/claims (belief.rs:209-241) -----------------------

/// One row of the bare JSON array `/frames/:id/claims` returns. There is no
/// `total`: a page that comes back full means "maybe more".
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct FrameClaimRow {
    pub claim_id: Uuid,
    /// The claim's text. `frame_claims_sorted` carries a viewer, so a row
    /// this viewer may not read is absent from the list.
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub hypothesis_index: Option<i32>,
    #[serde(default)]
    pub belief: Option<f64>,
    #[serde(default)]
    pub plausibility: Option<f64>,
    #[serde(default)]
    pub ignorance: Option<f64>,
    #[serde(default)]
    pub mass_on_missing: Option<f64>,
}

// ---- GET /api/v1/evidence/:id (edges.rs:1948-1974) ---------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EvidenceDetailResponse {
    pub id: Uuid,
    /// From a claim→evidence edge (`LIMIT 1`), not the `evidence.claim_id`
    /// column, so it is null for packet-submitted evidence.
    #[serde(default)]
    pub claim_id: Option<Uuid>,
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    /// `properties->>'evidence_type'`, `"unknown"` when absent. A different
    /// vocabulary from `/claims/:id/evidence` and `/search/evidence`.
    #[serde(default)]
    pub evidence_type: Option<String>,
    /// The evidence text. `detail_by_id` carries a viewer and returns
    /// `None` — a 404, byte-identical to a missing row — rather than a
    /// blanked body, so this never holds a placeholder.
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub content_hash: Option<String>,
    /// A URL or a bare DOI; null when none was recorded.
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub figure_id: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub page: Option<i64>,
    #[serde(default)]
    pub doi: Option<String>,
    #[serde(default)]
    pub extraction_target: Option<String>,
    #[serde(default)]
    pub page_range: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

// ---- typed calls -------------------------------------------------------------

impl Api<'_> {
    /// `GET /api/v1/claims/:id/history`.
    pub async fn claim_versions(&self, id: Uuid) -> Result<VersionHistoryResponse, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}/history")).await
    }

    /// `GET /api/v1/agents/:id`.
    pub async fn agent_detail(&self, id: Uuid) -> Result<AgentResponse, UpstreamError> {
        self.get(&format!("/api/v1/agents/{id}")).await
    }

    /// `GET /api/v1/agents/:id/claims?limit=&offset=`; `limit` is clamped to
    /// `1..=MAX_AGENT_CLAIMS_LIMIT`.
    pub async fn agent_attributed_claims(
        &self,
        id: Uuid,
        limit: u32,
        offset: u64,
    ) -> Result<AgentClaimsPage, UpstreamError> {
        #[derive(Serialize)]
        struct Q {
            limit: u32,
            offset: u64,
        }
        let q = Q {
            limit: limit.clamp(1, MAX_AGENT_CLAIMS_LIMIT),
            offset,
        };
        self.get_query(&format!("/api/v1/agents/{id}/claims"), &q)
            .await
    }

    /// `GET /api/v1/agents/:id/epistemic-profile`.
    pub async fn agent_epistemic_profile(
        &self,
        id: Uuid,
    ) -> Result<EpistemicProfileResponse, UpstreamError> {
        self.get(&format!("/api/v1/agents/{id}/epistemic-profile"))
            .await
    }

    /// `GET /api/v1/frames/:id`.
    pub async fn frame_detail(&self, id: Uuid) -> Result<FrameDetailResponse, UpstreamError> {
        self.get(&format!("/api/v1/frames/{id}")).await
    }

    /// `GET /api/v1/frames/:id/claims`. `sort_by`/`order` fall back to the
    /// upstream defaults unless they are in [`FRAME_CLAIM_SORTS`] /
    /// [`FRAME_CLAIM_ORDERS`] (an unknown value would be a 400), and `limit`
    /// is clamped to `1..=MAX_FRAME_CLAIMS_LIMIT`.
    pub async fn frame_claims_page(
        &self,
        id: Uuid,
        sort_by: &str,
        order: &str,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<FrameClaimRow>, UpstreamError> {
        #[derive(Serialize)]
        struct Q<'s> {
            sort_by: &'s str,
            order: &'s str,
            limit: u32,
            offset: u64,
        }
        let q = Q {
            sort_by: if FRAME_CLAIM_SORTS.contains(&sort_by) {
                sort_by
            } else {
                FRAME_CLAIM_SORTS[0]
            },
            order: if FRAME_CLAIM_ORDERS.contains(&order) {
                order
            } else {
                FRAME_CLAIM_ORDERS[0]
            },
            limit: limit.clamp(1, MAX_FRAME_CLAIMS_LIMIT),
            offset,
        };
        self.get_query(&format!("/api/v1/frames/{id}/claims"), &q)
            .await
    }

    /// `GET /api/v1/evidence/:id`.
    pub async fn evidence_detail(&self, id: Uuid) -> Result<EvidenceDetailResponse, UpstreamError> {
        self.get(&format!("/api/v1/evidence/{id}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "00000000-0000-0000-0000-00000000000a";
    const B: &str = "00000000-0000-0000-0000-00000000000b";

    #[test]
    fn history_decodes_the_versioning_shape() {
        let h: VersionHistoryResponse = serde_json::from_value(json!({
            "claim_id": A,
            "versions": [
                {"claim_id": A, "content": "old", "truth_value": 0.5, "version": 1,
                 "is_current": false, "created_at": "2026-01-02T03:04:05Z", "superseded_by": B},
                {"claim_id": B, "content": "new", "truth_value": 0.7, "version": 2,
                 "is_current": true, "created_at": "2026-02-02T03:04:05Z", "superseded_by": null}
            ],
            "total_versions": 2,
            "current_version": 2
        }))
        .unwrap();
        assert_eq!(h.versions.len(), 2);
        assert_eq!(
            h.versions[0].superseded_by,
            Some(Uuid::parse_str(B).unwrap())
        );
        assert!(h.versions[1].is_current);
        assert_eq!(h.current_version, 2);
    }

    #[test]
    fn agent_shapes_tolerate_omitted_optionals() {
        let a: AgentResponse = serde_json::from_value(json!({
            "id": A, "display_name": null, "public_key": "ab".repeat(32),
            "created_at": "2026-01-02T03:04:05Z", "labels": [], "orcid": null, "ror_id": null
        }))
        .unwrap();
        assert!(a.display_name.is_none());

        // AttributedClaimResponse omits labels and every privacy field.
        let p: AgentClaimsPage = serde_json::from_value(json!({
            "items": [{"id": B, "content": "c", "truth_value": 0.4, "agent_id": A,
                       "trace_id": null, "created_at": "2026-01-02T03:04:05Z",
                       "updated_at": "2026-01-02T03:04:05Z", "attribution": {}}],
            "total": 1, "limit": 20, "offset": 0
        }))
        .unwrap();
        assert_eq!(p.items[0].id, Uuid::parse_str(B).unwrap());

        let e: EpistemicProfileResponse = serde_json::from_value(json!({
            "agent_id": A, "display_name": "X", "claim_count": 3,
            "evidence_distribution": {"document": 0.5, "observation": 0.5},
            "epistemic_status_distribution": {"active": 1.0},
            "mean_truth_value": 0.6, "refutation_rate": 0.0,
            "topics": ["a"], "time_range": null
        }))
        .unwrap();
        assert!(e.time_range.is_none());
        assert_eq!(e.evidence_distribution.len(), 2);
    }

    #[test]
    fn frame_detail_skips_the_unbounded_claims_array() {
        let f: FrameDetailResponse = serde_json::from_value(json!({
            "frame": {"id": A, "name": "F", "description": null, "hypotheses": ["h0", "h1"],
                      "parent_frame_id": null, "is_refinable": true, "version": 1,
                      "created_at": "2026-01-02T03:04:05+00:00"},
            "claim_count": 2,
            "claims": [{"claim_id": B, "hypothesis_index": 0},
                       {"claim_id": A, "hypothesis_index": null}]
        }))
        .unwrap();
        assert_eq!(f.claim_count, 2);
        assert_eq!(f.frame.hypotheses, ["h0", "h1"]);

        let rows: Vec<FrameClaimRow> = serde_json::from_value(json!([
            {"claim_id": B, "content": "A frame claim.", "hypothesis_index": null,
             "belief": null, "plausibility": 0.9, "ignorance": null, "mass_on_missing": null}
        ]))
        .unwrap();
        assert_eq!(rows[0].plausibility, Some(0.9));
    }

    #[test]
    fn evidence_omitted_fields_default() {
        let e: EvidenceDetailResponse = serde_json::from_value(json!({
            "id": A, "claim_id": null, "agent_id": null, "evidence_type": "unknown",
            "content": null, "content_hash": "00ff", "source_url": null,
            "created_at": "2026-01-02T03:04:05+00:00"
        }))
        .unwrap();
        assert!(e.figure_id.is_none() && e.page.is_none() && e.doi.is_none());
        assert_eq!(e.evidence_type.as_deref(), Some("unknown"));
    }
}
