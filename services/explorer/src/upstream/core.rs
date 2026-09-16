//! Upstream DTOs and typed calls for the core area (search, and the claim
//! page's evidence / challenges / provenance sub-calls). OWNED BY THE CORE
//! AREA.
//!
//! Field names are copied from the mapping reports (`claims-endpoints.md`,
//! `search-overview-endpoints.md`, `critique.md` §8). Upstream omits optional
//! fields rather than sending `null`, so everything not guaranteed is
//! `Option` or `#[serde(default)]`. Timestamps that upstream formats by hand
//! (`to_rfc3339()`, `+00:00`) stay `String`s: one odd row must not fail the
//! whole list.
//!
//! Method names carry a `claim_` / `search_` / `landing_` prefix so they
//! cannot collide with the other areas' `impl Api<'_>` blocks.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Api, UpstreamError};

/// Semantic search is silently capped at 100 upstream; the BFF caps every
/// search surface at 50 (plan §3.5).
pub const MAX_SEARCH_LIMIT: u32 = 50;

// ---- GET /api/v1/claims/:id/evidence (claims.rs:1057-1066) ------------------

/// One row of the column-based evidence list: the only complete list of a
/// claim's evidence (critique.md "Which evidence list is canonical").
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ClaimEvidence {
    /// A UUID, serialized upstream as a plain string.
    pub id: String,
    #[serde(default)]
    pub claim_id: String,
    /// `raw_content` or `""`; never null.
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub content_hash: String,
    /// A URL, a bare DOI (literature/figure), or a testimony source.
    #[serde(default)]
    pub source_url: Option<String>,
    /// `empirical | testimonial | analytical | statistical | figure`.
    #[serde(default)]
    pub evidence_type: String,
    /// `to_rfc3339()` — `+00:00`, not `Z`.
    #[serde(default)]
    pub created_at: String,
}

// ---- GET /api/v1/claims/:id/{supporting,contradicting}-evidence -------------

/// `{claim_id, relationship, evidence, total}` (edges.rs:2405-2497). An empty
/// list when the centre claim is redacted for this viewer.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EvidenceEdgeList {
    pub claim_id: Uuid,
    /// `"SUPPORTS"` or `"CONTRADICTS"`.
    #[serde(default)]
    pub relationship: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceEdge>,
    #[serde(default)]
    pub total: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EvidenceEdge {
    pub edge_id: Uuid,
    pub evidence_id: Uuid,
    #[serde(default)]
    pub evidence_content: Option<String>,
    /// Defaults to 0.5 upstream when the edge has no `strength` property.
    #[serde(default)]
    pub strength: Option<f64>,
    #[serde(default)]
    pub created_at: String,
}

// ---- GET /api/v1/claims/:id/challenges (challenge.rs:55-91) -----------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ChallengeList {
    #[serde(default)]
    pub challenges: Vec<Challenge>,
    #[serde(default)]
    pub total: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Challenge {
    pub id: Uuid,
    #[serde(default)]
    pub claim_id: Option<Uuid>,
    /// The nil UUID when the DB value is NULL.
    #[serde(default)]
    pub challenger_id: Option<Uuid>,
    #[serde(default)]
    pub challenge_type: String,
    #[serde(default)]
    pub explanation: String,
    /// `pending | accepted | rejected`.
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    /// Omitted when null.
    #[serde(default)]
    pub resolved_at: Option<DateTime<Utc>>,
    /// Omitted when null.
    #[serde(default)]
    pub resolved_by: Option<Uuid>,
}

// ---- GET /api/v1/claims/:id/provenance (edges.rs:2155-2177) -----------------

/// Claim → reasoning trace → evidence. NOT the claim → claim derivation
/// chain (`/provenance-chain`); the page shows both, separately.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ClaimProvenance {
    pub claim_id: Uuid,
    #[serde(default)]
    pub chains: Vec<ProvenancePath>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ProvenancePath {
    #[serde(default)]
    pub path: Vec<ProvenanceStep>,
    /// Omitted when None.
    #[serde(default)]
    pub source_doi: Option<String>,
    /// `https://doi.org/<doi>` when there is a DOI, else the evidence URL.
    /// Omitted when None.
    #[serde(default)]
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ProvenanceStep {
    pub id: Uuid,
    /// `claim | trace | evidence`.
    #[serde(default)]
    pub entity_type: String,
    #[serde(default)]
    pub label: String,
}

// ---- POST /api/v1/search/semantic (search.rs:56-239) ------------------------

#[derive(Debug, Clone, Serialize)]
struct SemanticSearchRequest<'q> {
    query: &'q str,
    limit: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SemanticSearchResponse {
    #[serde(default)]
    pub results: Vec<SemanticHit>,
    /// `results.len()`, not a pre-limit count.
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub query_time_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SemanticHit {
    pub claim_id: Uuid,
    /// `claims.content`; `"[REDACTED]"` once the kernel redaction sweep
    /// (plan §2.6) lands.
    #[serde(default)]
    pub statement: String,
    #[serde(default)]
    pub similarity: Option<f64>,
    #[serde(default)]
    pub epistemic: Epistemic,
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    /// `labels[1]`, whatever it is; omitted when None.
    #[serde(default)]
    pub claim_type: Option<String>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct Epistemic {
    #[serde(default)]
    pub belief: Option<f64>,
    #[serde(default)]
    pub plausibility: Option<f64>,
    #[serde(default)]
    pub ignorance: Option<f64>,
    #[serde(default)]
    pub truth_value: Option<f64>,
}

// ---- GET /api/v1/claims/by-labels (claims.rs:1633-1671) ---------------------

/// One element of the bare JSON array (no envelope, no total).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LabelHit {
    pub id: Uuid,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub truth_value: Option<f64>,
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    /// An RFC 3339 string formatted by hand upstream.
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub is_current: Option<bool>,
    #[serde(default)]
    pub supersedes: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
struct ByLabelsQuery<'q> {
    labels: &'q str,
    current_only: bool,
    limit: u32,
    offset: u64,
}

// ---- GET /api/v1/search/evidence (rag.rs:683-704) ---------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EvidenceSearchResponse {
    #[serde(default)]
    pub results: Vec<EvidenceHit>,
    #[serde(default)]
    pub count: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EvidenceHit {
    pub evidence_id: Uuid,
    pub claim_id: Uuid,
    #[serde(default)]
    pub raw_content: Option<String>,
    /// The `evidence.evidence_type` column: `document | observation |
    /// testimony | computation | reference | figure | conversational`.
    #[serde(default)]
    pub evidence_type: String,
    #[serde(default)]
    pub similarity: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceSearchQuery<'q> {
    /// The parameter is `query`, not `q`.
    query: &'q str,
    limit: u32,
}

// ---- landing overviews (protected upstream routes) ---------------------------

/// `GET /api/v1/graph/themes/overview` (graph.rs:389-407). Unpaginated;
/// ordered `claim_count DESC, label ASC`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ThemesOverview {
    #[serde(default)]
    pub themes: Vec<ThemeSummary>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ThemeSummary {
    pub id: Uuid,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub claim_count: i64,
}

/// `GET /api/v1/graph/communities/overview` (graph.rs:92-231): Louvain graph
/// clusters of the latest run. `cluster_edges` is not read.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CommunitiesOverview {
    #[serde(default)]
    pub run_id: Option<Uuid>,
    #[serde(default)]
    pub generated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub degraded: bool,
    /// `"no_clusters_computed"` when no run exists; otherwise omitted.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub supernodes: Vec<Supernode>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Supernode {
    pub cluster_id: Uuid,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub mean_betp: Option<f64>,
    #[serde(default)]
    pub dominant_type: Option<String>,
    #[serde(default)]
    pub dominant_frame_id: Option<Uuid>,
}

impl Api<'_> {
    /// `GET /api/v1/claims/:id/evidence` — a bare array.
    pub async fn claim_evidence_list(&self, id: Uuid) -> Result<Vec<ClaimEvidence>, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}/evidence")).await
    }

    /// `GET /api/v1/claims/:id/supporting-evidence`.
    pub async fn claim_supporting_evidence(
        &self,
        id: Uuid,
    ) -> Result<EvidenceEdgeList, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}/supporting-evidence"))
            .await
    }

    /// `GET /api/v1/claims/:id/contradicting-evidence`.
    pub async fn claim_contradicting_evidence(
        &self,
        id: Uuid,
    ) -> Result<EvidenceEdgeList, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}/contradicting-evidence"))
            .await
    }

    /// `GET /api/v1/claims/:id/challenges`.
    pub async fn claim_challenges(&self, id: Uuid) -> Result<ChallengeList, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}/challenges")).await
    }

    /// `GET /api/v1/claims/:id/provenance` (claim → trace → evidence).
    pub async fn claim_provenance_summary(
        &self,
        id: Uuid,
    ) -> Result<ClaimProvenance, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}/provenance")).await
    }

    /// `POST /api/v1/search/semantic`; `limit` is clamped to
    /// `1..=MAX_SEARCH_LIMIT`. No offset exists upstream.
    pub async fn search_semantic(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<SemanticSearchResponse, UpstreamError> {
        let body = SemanticSearchRequest {
            query,
            limit: limit.clamp(1, MAX_SEARCH_LIMIT),
        };
        self.post("/api/v1/search/semantic", &body).await
    }

    /// `GET /api/v1/claims/by-labels`: claims carrying ALL of the
    /// comma-separated `labels`, current versions only, newest first.
    pub async fn search_by_labels(
        &self,
        labels: &str,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<LabelHit>, UpstreamError> {
        let q = ByLabelsQuery {
            labels,
            current_only: true,
            limit: limit.clamp(1, MAX_SEARCH_LIMIT),
            offset,
        };
        self.get_query("/api/v1/claims/by-labels", &q).await
    }

    /// `GET /api/v1/search/evidence`; `limit` is clamped to
    /// `1..=MAX_SEARCH_LIMIT`. No offset exists upstream.
    pub async fn search_evidence(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<EvidenceSearchResponse, UpstreamError> {
        let q = EvidenceSearchQuery {
            query,
            limit: limit.clamp(1, MAX_SEARCH_LIMIT),
        };
        self.get_query("/api/v1/search/evidence", &q).await
    }

    /// `GET /api/v1/graph/themes/overview` (needs a bearer).
    pub async fn landing_themes(&self) -> Result<ThemesOverview, UpstreamError> {
        self.get("/api/v1/graph/themes/overview").await
    }

    /// `GET /api/v1/graph/communities/overview` (needs a bearer).
    pub async fn landing_communities(&self) -> Result<CommunitiesOverview, UpstreamError> {
        self.get("/api/v1/graph/communities/overview").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "00000000-0000-0000-0000-00000000000a";
    const B: &str = "00000000-0000-0000-0000-00000000000b";

    #[test]
    fn claim_evidence_rows_keep_string_ids_and_plus_offsets() {
        let v: Vec<ClaimEvidence> = serde_json::from_value(json!([{
            "id": A, "claim_id": B, "content": "", "content_hash": "ab",
            "source_url": null, "evidence_type": "analytical",
            "created_at": "2026-01-02T03:04:05.123+00:00"
        }]))
        .unwrap();
        assert_eq!(v[0].id, A);
        assert!(v[0].source_url.is_none());
    }

    #[test]
    fn challenges_tolerate_omitted_resolution() {
        let c: ChallengeList = serde_json::from_value(json!({
            "challenges": [{
                "id": A, "claim_id": B,
                "challenger_id": "00000000-0000-0000-0000-000000000000",
                "challenge_type": "factual_error", "explanation": "no",
                "state": "pending", "created_at": "2026-01-02T03:04:05Z"
            }],
            "total": 1
        }))
        .unwrap();
        assert!(c.challenges[0].resolved_at.is_none());
        assert_eq!(c.challenges[0].challenger_id, Some(Uuid::nil()));
    }

    #[test]
    fn provenance_chains_omit_sources() {
        let p: ClaimProvenance = serde_json::from_value(json!({
            "claim_id": A,
            "chains": [{"path": [{"id": A, "entity_type": "claim", "label": "x"},
                                 {"id": B, "entity_type": "trace", "label": "deductive (0.90)"}]}]
        }))
        .unwrap();
        assert!(p.chains[0].source_url.is_none() && p.chains[0].source_doi.is_none());
        assert_eq!(p.chains[0].path.len(), 2);
    }

    #[test]
    fn semantic_hits_omit_optional_fields() {
        let r: SemanticSearchResponse = serde_json::from_value(json!({
            "results": [{
                "claim_id": A, "statement": "s", "similarity": 0.9,
                "epistemic": {"belief": null, "plausibility": null, "ignorance": null,
                              "truth_value": 0.5},
                "agent_id": B
            }],
            "total": 1, "query_time_ms": 3
        }))
        .unwrap();
        assert_eq!(r.results[0].epistemic.truth_value, Some(0.5));
        assert!(r.results[0].claim_type.is_none());
    }

    #[test]
    fn label_hits_and_evidence_hits() {
        let v: Vec<LabelHit> = serde_json::from_value(json!([{
            "id": A, "content": "c", "truth_value": 0.1, "agent_id": B,
            "created_at": "2026-01-02T03:04:05+00:00", "labels": ["x"],
            "is_current": true, "supersedes": null
        }]))
        .unwrap();
        assert_eq!(v[0].labels, ["x"]);

        let e: EvidenceSearchResponse = serde_json::from_value(json!({
            "results": [{"evidence_id": A, "claim_id": B, "raw_content": null,
                         "evidence_type": "document", "similarity": 0.4}],
            "count": 1
        }))
        .unwrap();
        assert!(e.results[0].raw_content.is_none());
    }

    #[test]
    fn overviews_decode_with_and_without_a_run() {
        let c: CommunitiesOverview = serde_json::from_value(json!({
            "run_id": null, "generated_at": null, "degraded": false,
            "status": "no_clusters_computed", "supernodes": [], "cluster_edges": []
        }))
        .unwrap();
        assert_eq!(c.status.as_deref(), Some("no_clusters_computed"));

        let c: CommunitiesOverview = serde_json::from_value(json!({
            "run_id": A, "generated_at": "2026-01-02T03:04:05Z", "degraded": false,
            "supernodes": [{"cluster_id": B, "label": "cluster-3", "size": 12,
                            "mean_betp": null, "dominant_type": null,
                            "dominant_frame_id": null}],
            "cluster_edges": [{"a": A, "b": B, "weight": 2}]
        }))
        .unwrap();
        assert_eq!(c.supernodes[0].size, 12);

        let t: ThemesOverview = serde_json::from_value(json!({
            "themes": [{"id": A, "label": "Thermodynamics", "claim_count": 40}]
        }))
        .unwrap();
        assert_eq!(t.themes[0].claim_count, 40);
    }
}
