//! Shared upstream DTOs.
//!
//! Discipline (plan §3.4 "Deserialization"): upstream *omits* optional fields
//! rather than sending `null`, so every field that is not guaranteed present
//! is `Option<_>` or `#[serde(default)]`. Unknown fields are ignored. Field
//! names are copied from the source-verified mapping reports; do not rename.
//!
//! Area-specific DTOs live next to their client methods in
//! `upstream/{core,entities,graph}.rs`, not here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Error body of every `ApiError` response: `{error, message, details?}`
/// (`errors.rs:58-148`). NOT RFC 6749 — OAuth errors use this shape too.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct ApiErrorBody {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

/// `GET /api/v1/claims/:id` (`claims.rs:86-115`).
///
/// Has no `is_current`/`supersedes`/belief: those come from `/history` and
/// `/belief`. `truth_value` is evidence-derived, not the DS belief.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ClaimResponse {
    pub id: Uuid,
    /// Full text (≤ 64 KB). Always the real text: upstream 404s a claim
    /// this viewer may not read rather than returning it blanked.
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub truth_value: Option<f64>,
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    #[serde(default)]
    pub trace_id: Option<Uuid>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub privacy_tier: Option<String>,
    #[serde(default)]
    pub encrypted_content: Option<String>,
    #[serde(default)]
    pub encryption_epoch: Option<i32>,
    #[serde(default)]
    pub group_id: Option<Uuid>,
    /// Omitted entirely when empty.
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub was_created: bool,
}

/// `GET /api/v1/claims/:id/belief` (`belief.rs:35-47`). Every field is
/// always present upstream; numbers may be `null`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct BeliefResponse {
    pub claim_id: Uuid,
    #[serde(default)]
    pub belief: Option<f64>,
    #[serde(default)]
    pub plausibility: Option<f64>,
    /// `plausibility - belief`, null if either is null.
    #[serde(default)]
    pub ignorance: Option<f64>,
    /// The renamed `claims.mass_on_empty` column.
    #[serde(default)]
    pub mass_on_conflict: Option<f64>,
    #[serde(default)]
    pub mass_on_missing: Option<f64>,
    #[serde(default)]
    pub pignistic_prob: Option<f64>,
    #[serde(default)]
    pub mass_function_count: i64,
}

// ---- GET /api/v1/claims/:id/ego (plan §2.2) ----------------------------------

/// Depth-1, hydrated, degree-capped neighbourhood.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EgoResponse {
    pub center: EgoNode,
    #[serde(default)]
    pub nodes: Vec<EgoNode>,
    #[serde(default)]
    pub edges: Vec<EgoEdge>,
    /// Edge count before the degree cap.
    #[serde(default)]
    pub total_edges: u64,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EgoNode {
    pub id: Uuid,
    /// `claim`, `agent`, `evidence`, `frame`, `paper`, … — see
    /// [`crate::links::Links::entity`] for which have pages.
    pub entity_type: String,
    /// ≤ 160 chars; `entity_type` for types upstream cannot hydrate.
    #[serde(default)]
    pub label: String,
    /// Claims only.
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub truth_value: Option<f64>,
    #[serde(default)]
    pub pignistic_prob: Option<f64>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub is_current: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EgoEdge {
    pub id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    #[serde(default)]
    pub source_type: String,
    #[serde(default)]
    pub target_type: String,
    /// Raw stored string: mixed case, with aliases. Fold before grouping.
    #[serde(default)]
    pub relationship: String,
    #[serde(default)]
    pub direction: EdgeDirection,
}

impl EgoEdge {
    /// The endpoint that is not the centre.
    pub fn neighbour_id(&self) -> Uuid {
        match self.direction {
            EdgeDirection::In => self.source_id,
            _ => self.target_id,
        }
    }
}

/// Relative to the centre: `Out` = the centre is the source.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EdgeDirection {
    In,
    Out,
    #[default]
    #[serde(other)]
    Unknown,
}

// ---- GET /api/v1/claims/:id/placement (plan §2.3) ----------------------------

/// All-null is a normal answer: clustering is operator-triggered and only
/// leaf claims get neighbourhoods. The ids are NOT permalinks.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PlacementResponse {
    pub claim_id: Uuid,
    #[serde(default)]
    pub theme_id: Option<Uuid>,
    #[serde(default)]
    pub cluster_run_id: Option<Uuid>,
    #[serde(default)]
    pub cluster_id: Option<Uuid>,
    #[serde(default)]
    pub neighborhood_id: Option<Uuid>,
    #[serde(default)]
    pub run_completed_at: Option<DateTime<Utc>>,
}

// ---- GET /api/v1/stats (plan §2.4) --------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct StatsResponse {
    #[serde(default)]
    pub claims: i64,
    #[serde(default)]
    pub edges: i64,
    #[serde(default)]
    pub evidence: i64,
    #[serde(default)]
    pub embeddings: i64,
    #[serde(default)]
    pub agents: i64,
    #[serde(default)]
    pub frames: i64,
    #[serde(default)]
    pub workflows: i64,
    #[serde(default)]
    pub computed_at: Option<DateTime<Utc>>,
}

// ---- GET /api/v1/claims/:id/provenance-chain (plan §2.1) ---------------------

/// Claim → claim derivation chain. Distinct from `/claims/:id/provenance`
/// (claim → trace → evidence); the claim page shows both.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ProvenanceChainResponse {
    pub root: Uuid,
    #[serde(default)]
    pub nodes: Vec<ChainNode>,
    #[serde(default)]
    pub edges: Vec<ChainEdge>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub cycles: Vec<Vec<Uuid>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ChainNode {
    pub id: Uuid,
    /// The claim text. A node the viewer may not read is absent from
    /// `nodes` entirely, so this is never a placeholder.
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub truth_value: Option<f64>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub is_current: Option<bool>,
    #[serde(default)]
    pub depth: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ChainEdge {
    pub source: Uuid,
    pub target: Uuid,
    #[serde(default)]
    pub relationship: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn claim_tolerates_omitted_fields() {
        // labels and every skip_serializing_if field omitted, `Z` timestamps.
        let c: ClaimResponse = serde_json::from_value(json!({
            "id": "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
            "content": "Water boils at 100 °C at sea level.",
            "truth_value": 0.8,
            "agent_id": "1b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
            "trace_id": null,
            "created_at": "2026-01-02T03:04:05Z",
            "updated_at": "2026-01-02T03:04:05.123456Z"
        }))
        .unwrap();
        assert!(c.labels.is_empty());
        assert!(c.trace_id.is_none());
        assert!(c.updated_at.is_some());

        let r: ClaimResponse = serde_json::from_value(json!({
            "id": "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
            "content": "Sodium is a metal.",
            "labels": ["a", "b"],
            "created_at": "2026-01-02T03:04:05+00:00"
        }))
        .unwrap();
        assert!(r.updated_at.is_none());
        assert_eq!(r.labels, ["a", "b"]);
    }

    #[test]
    fn belief_nulls() {
        let b: BeliefResponse = serde_json::from_value(json!({
            "claim_id": "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
            "belief": null, "plausibility": null, "ignorance": null,
            "mass_on_conflict": null, "mass_on_missing": null,
            "pignistic_prob": 0.4, "mass_function_count": 3
        }))
        .unwrap();
        assert_eq!(b.pignistic_prob, Some(0.4));
        assert_eq!(b.mass_function_count, 3);
    }

    #[test]
    fn ego_round_trip_and_direction() {
        let e: EgoResponse = serde_json::from_value(json!({
            "center": {"id": "00000000-0000-0000-0000-000000000001", "entity_type": "claim",
                       "label": "c", "content": "c", "truth_value": 0.5, "labels": [],
                       "is_current": true},
            "nodes": [{"id": "00000000-0000-0000-0000-000000000002", "entity_type": "paper",
                       "label": "paper"}],
            "edges": [
                {"id": "00000000-0000-0000-0000-00000000000a",
                 "source_id": "00000000-0000-0000-0000-000000000002",
                 "target_id": "00000000-0000-0000-0000-000000000001",
                 "source_type": "paper", "target_type": "claim",
                 "relationship": "asserts", "direction": "in"},
                {"id": "00000000-0000-0000-0000-00000000000b",
                 "source_id": "00000000-0000-0000-0000-000000000001",
                 "target_id": "00000000-0000-0000-0000-000000000003",
                 "source_type": "claim", "target_type": "claim",
                 "relationship": "SUPPORTS", "direction": "sideways"}
            ],
            "total_edges": 2,
            "truncated": false
        }))
        .unwrap();
        assert_eq!(e.edges[0].direction, EdgeDirection::In);
        assert_eq!(e.edges[0].neighbour_id(), e.nodes[0].id);
        assert_eq!(e.edges[1].direction, EdgeDirection::Unknown);
        assert!(e.nodes[0].content.is_none());
    }

    #[test]
    fn placement_all_null_and_stats() {
        let p: PlacementResponse = serde_json::from_value(json!({
            "claim_id": "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
            "theme_id": null, "cluster_run_id": null, "cluster_id": null,
            "neighborhood_id": null, "run_completed_at": null
        }))
        .unwrap();
        assert!(p.theme_id.is_none() && p.run_completed_at.is_none());

        let s: StatsResponse = serde_json::from_value(json!({
            "claims": 343000, "edges": 1, "evidence": 2, "embeddings": 3,
            "agents": 4, "frames": 5, "workflows": 6,
            "computed_at": "2026-09-15T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(s.claims, 343000);
    }

    #[test]
    fn provenance_chain() {
        let c: ProvenanceChainResponse = serde_json::from_value(json!({
            "root": "00000000-0000-0000-0000-000000000001",
            "nodes": [{"id": "00000000-0000-0000-0000-000000000001", "content": "x",
                       "truth_value": 0.5, "labels": ["l"], "is_current": true,
                       "depth": 0}],
            "edges": [{"source": "00000000-0000-0000-0000-000000000002",
                       "target": "00000000-0000-0000-0000-000000000001",
                       "relationship": "supports"}],
            "truncated": false,
            "cycles": [["00000000-0000-0000-0000-000000000001"]]
        }))
        .unwrap();
        assert_eq!(c.nodes[0].depth, 0);
        assert_eq!(c.cycles.len(), 1);
    }

    /// Cross-lane contract pin for the four routes the kernel lane added for
    /// this service. The payloads below are what the kernel's own serde
    /// structs emit, field for field:
    ///
    /// - `crates/epigraph-api/src/routes/ego.rs:52-93` — `EgoNode`'s five
    ///   claim-only fields carry `skip_serializing_if = "Option::is_none"`, so
    ///   a non-claim neighbour arrives as three keys and nothing else; `label`
    ///   is always present. `labels` is `Option<Vec<String>>` upstream and
    ///   `Vec<String>` here, which is only safe because the skip means it is
    ///   *omitted* rather than `null`.
    ///
    /// Neither `EgoNode` nor `ChainNode` carries a `redacted` flag: a node the
    /// viewer may not read is omitted from the response (`68b8a8b1`).
    /// - `crates/epigraph-api/src/routes/placement.rs:29-40` — the one route
    ///   that deliberately serialises nulls: "no neighbourhood" has to be
    ///   distinguishable from "field not read".
    /// - `crates/epigraph-api/src/routes/stats.rs:18-31` — all eight fields
    ///   always present.
    /// - `crates/epigraph-api/src/routes/provenance_chain.rs:54-84` —
    ///   `ChainNode.truth_value`/`is_current` are bare `f64`/`bool` upstream
    ///   and `Option` here (widening, safe); `depth` is `i32` upstream and
    ///   `u32` here, which holds because the BFS seeds at 0 and only
    ///   increments (`repos/provenance_chain.rs:143,151`).
    #[test]
    fn kernel_routes_serialize_into_these_dtos() {
        // ego: an unhydratable neighbour (every optional key omitted), and
        // the `direction` values the kernel emits.
        let e: EgoResponse = serde_json::from_value(json!({
            "center": {"id": "00000000-0000-0000-0000-000000000001",
                       "entity_type": "claim", "label": "Water boils.",
                       "content": "Water boils."},
            "nodes": [{"id": "00000000-0000-0000-0000-000000000002",
                       "entity_type": "workflow", "label": "workflow"}],
            "edges": [{"id": "00000000-0000-0000-0000-00000000000a",
                       "source_id": "00000000-0000-0000-0000-000000000001",
                       "target_id": "00000000-0000-0000-0000-000000000002",
                       "source_type": "claim", "target_type": "workflow",
                       "relationship": "derived_from", "direction": "out"}],
            "total_edges": 1, "truncated": false
        }))
        .unwrap();
        assert_eq!(e.center.content.as_deref(), Some("Water boils."));
        assert!(e.nodes[0].labels.is_empty(), "omitted labels read as empty");
        assert!(e.nodes[0].truth_value.is_none() && e.nodes[0].is_current.is_none());
        assert_eq!(e.edges[0].direction, EdgeDirection::Out);
        assert_eq!(e.edges[0].neighbour_id(), e.nodes[0].id);

        // placement: the unclustered answer is explicit nulls.
        let p: PlacementResponse = serde_json::from_value(json!({
            "claim_id": "00000000-0000-0000-0000-000000000001",
            "theme_id": null, "cluster_run_id": null, "cluster_id": null,
            "neighborhood_id": null, "run_completed_at": null
        }))
        .unwrap();
        assert!(p.theme_id.is_none() && p.cluster_run_id.is_none());

        // stats: every field, and `computed_at` as chrono renders it.
        let s: StatsResponse = serde_json::from_value(json!({
            "claims": 1, "edges": 2, "evidence": 3, "embeddings": 4,
            "agents": 5, "frames": 6, "workflows": 7,
            "computed_at": "2026-09-16T12:00:00.123456789Z"
        }))
        .unwrap();
        assert_eq!((s.claims, s.workflows), (1, 7));
        assert!(s.computed_at.is_some());

        // provenance-chain: bare (non-Option) upstream scalars, and a cycle.
        let c: ProvenanceChainResponse = serde_json::from_value(json!({
            "root": "00000000-0000-0000-0000-000000000001",
            "nodes": [{"id": "00000000-0000-0000-0000-000000000001",
                       "content": "Derived.", "truth_value": 0.0,
                       "labels": [], "is_current": false, "depth": 3}],
            "edges": [{"source": "00000000-0000-0000-0000-000000000001",
                       "target": "00000000-0000-0000-0000-000000000002",
                       "relationship": "derived_from"}],
            "truncated": true,
            "cycles": [["00000000-0000-0000-0000-000000000001",
                        "00000000-0000-0000-0000-000000000002"]]
        }))
        .unwrap();
        assert_eq!(c.nodes[0].depth, 3);
        assert_eq!(c.nodes[0].is_current, Some(false));
        assert!(c.truncated);
        assert_eq!(c.cycles[0].len(), 2);
    }

    #[test]
    fn api_error_body() {
        let e: ApiErrorBody = serde_json::from_value(json!({
            "error": "NotFound", "message": "Claim with ID x not found",
            "details": {"entity": "Claim", "id": "x"}
        }))
        .unwrap();
        assert_eq!(e.error.as_deref(), Some("NotFound"));
        let e: ApiErrorBody = serde_json::from_value(json!({})).unwrap();
        assert_eq!(e, ApiErrorBody::default());
    }
}
