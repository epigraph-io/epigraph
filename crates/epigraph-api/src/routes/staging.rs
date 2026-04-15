//! Staging ingestion endpoints for the screening UI.
//!
//! These endpoints create staging subgraphs from various sources (JSON claims,
//! git repositories) that can be reviewed and selectively merged into the main
//! graph. PDF ingestion is handled separately via the extract_pdf.py script.

use crate::errors::ApiError;
use crate::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Request / Response types ─────────────────────────────────────────────────

/// A claim in the staging subgraph (not yet persisted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagingClaim {
    pub id: String,
    pub statement: String,
    pub truth_value: f64,
    pub confidence: f64,
    pub methodology: String,
    pub source: Option<String>,
    pub domain: Option<String>,
    pub evidence: Vec<StagingEvidence>,
}

/// Evidence attached to a staging claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagingEvidence {
    pub content: String,
    pub evidence_type: String,
    pub source_url: Option<String>,
}

/// A proposed connection between a staging claim and an existing claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedConnection {
    pub staging_claim_id: String,
    pub existing_claim_id: String,
    pub edge_type: String,
    pub strength: f64,
    pub method: String,
}

/// A staging edge between two staging claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagingEdge {
    pub id: String,
    pub source_claim_id: String,
    pub target_claim_id: String,
    pub edge_type: String,
    pub strength: f64,
}

/// The complete staging subgraph returned from ingestion endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagingSubgraph {
    pub claims: Vec<StagingClaim>,
    pub edges: Vec<StagingEdge>,
    pub proposed_connections: Vec<ProposedConnection>,
}

// ── JSON Ingestion ───────────────────────────────────────────────────────────

/// Request body for JSON claims ingestion.
#[derive(Debug, Deserialize)]
pub struct IngestJsonRequest {
    pub claims: Vec<IngestJsonClaim>,
}

/// A single claim in the JSON ingestion format.
#[derive(Debug, Deserialize)]
pub struct IngestJsonClaim {
    pub statement: String,
    pub confidence: Option<f64>,
    pub methodology: Option<String>,
    pub source: Option<String>,
    pub domain: Option<String>,
    pub evidence: Option<Vec<IngestJsonEvidence>>,
}

/// Evidence in the JSON ingestion format.
#[derive(Debug, Deserialize)]
pub struct IngestJsonEvidence {
    pub content: String,
    pub evidence_type: Option<String>,
    pub source_url: Option<String>,
}

/// POST /api/v1/staging/ingest/json
///
/// Accepts a JSON array of claims, validates them, and returns a staging
/// subgraph for review. No data is persisted until merge is called.
pub async fn ingest_json(
    State(_state): State<AppState>,
    Json(request): Json<IngestJsonRequest>,
) -> Result<Json<StagingSubgraph>, ApiError> {
    if request.claims.is_empty() {
        return Err(ApiError::ValidationError {
            field: "claims".to_string(),
            reason: "At least one claim is required".to_string(),
        });
    }

    if request.claims.len() > 1000 {
        return Err(ApiError::ValidationError {
            field: "claims".to_string(),
            reason: "Maximum 1000 claims per ingestion".to_string(),
        });
    }

    let mut staging_claims = Vec::with_capacity(request.claims.len());

    for claim in &request.claims {
        if claim.statement.trim().is_empty() {
            return Err(ApiError::ValidationError {
                field: "statement".to_string(),
                reason: "Claim statement cannot be empty".to_string(),
            });
        }

        let confidence = claim.confidence.unwrap_or(0.5);
        if !(0.0..=1.0).contains(&confidence) {
            return Err(ApiError::ValidationError {
                field: "confidence".to_string(),
                reason: format!("Confidence must be between 0.0 and 1.0, got {confidence}"),
            });
        }

        let evidence: Vec<StagingEvidence> = claim
            .evidence
            .as_ref()
            .map(|evs| {
                evs.iter()
                    .map(|e| StagingEvidence {
                        content: e.content.clone(),
                        evidence_type: e
                            .evidence_type
                            .clone()
                            .unwrap_or_else(|| "document".to_string()),
                        source_url: e.source_url.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Calculate initial truth from evidence count and methodology
        let evidence_count = evidence.len();
        let methodology = claim.methodology.as_deref().unwrap_or("heuristic");
        let truth_value = calculate_staging_truth(evidence_count, methodology, confidence);

        staging_claims.push(StagingClaim {
            id: Uuid::new_v4().to_string(),
            statement: claim.statement.clone(),
            truth_value,
            confidence,
            methodology: methodology.to_string(),
            source: claim.source.clone(),
            domain: claim.domain.clone(),
            evidence,
        });
    }

    Ok(Json(StagingSubgraph {
        claims: staging_claims,
        edges: Vec::new(),
        proposed_connections: Vec::new(),
    }))
}

// ── Git Ingestion ────────────────────────────────────────────────────────────

/// Request body for git repository ingestion.
#[derive(Debug, Deserialize)]
pub struct IngestGitRequest {
    pub repo_path: String,
    pub since: Option<String>,
    pub limit: Option<usize>,
}

/// POST /api/v1/staging/ingest/git
///
/// Accepts a git repository path and parameters, runs the git ingester in
/// dry-run mode, and returns a staging subgraph. The actual `ingest_git` binary
/// would need to be invoked server-side; for now this validates the request and
/// returns the structure for the UI to preview.
pub async fn ingest_git(
    State(_state): State<AppState>,
    Json(request): Json<IngestGitRequest>,
) -> Result<Json<StagingSubgraph>, ApiError> {
    if request.repo_path.trim().is_empty() {
        return Err(ApiError::ValidationError {
            field: "repo_path".to_string(),
            reason: "Repository path is required".to_string(),
        });
    }

    // For now, return an empty staging subgraph.
    // Full implementation will invoke ingest_git --dry-run and parse output.
    Ok(Json(StagingSubgraph {
        claims: Vec::new(),
        edges: Vec::new(),
        proposed_connections: Vec::new(),
    }))
}

// ── Merge ────────────────────────────────────────────────────────────────────

/// Request body for merging accepted staging claims into the main graph.
#[derive(Debug, Deserialize)]
pub struct MergeRequest {
    pub staging: StagingSubgraph,
    pub accepted_edge_ids: Vec<String>,
}

/// POST /api/v1/staging/merge
///
/// Merges accepted claims and edges from a staging subgraph into the main
/// graph via the existing submit/packet endpoint. Only edges in
/// `accepted_edge_ids` are included.
pub async fn merge_staging(
    State(_state): State<AppState>,
    Json(request): Json<MergeRequest>,
) -> Result<Json<MergeResponse>, ApiError> {
    if request.staging.claims.is_empty() {
        return Err(ApiError::ValidationError {
            field: "staging.claims".to_string(),
            reason: "No claims to merge".to_string(),
        });
    }

    // Filter edges to only include accepted ones
    let accepted_edges: Vec<&StagingEdge> = request
        .staging
        .edges
        .iter()
        .filter(|e| request.accepted_edge_ids.contains(&e.id))
        .collect();

    let accepted_connections: Vec<&ProposedConnection> = request
        .staging
        .proposed_connections
        .iter()
        .filter(|c| {
            // Accept connections where the staging claim is being merged
            request
                .staging
                .claims
                .iter()
                .any(|cl| cl.id == c.staging_claim_id)
        })
        .collect();

    // In a full implementation, this would:
    // 1. Create EpistemicPackets for each claim
    // 2. Submit them via the existing submit/packet handler
    // 3. Create edges between accepted claims
    // For now, return the count of what would be merged
    Ok(Json(MergeResponse {
        merged_claims: request.staging.claims.len(),
        merged_edges: accepted_edges.len(),
        merged_connections: accepted_connections.len(),
    }))
}

/// Response from a merge operation.
#[derive(Debug, Serialize)]
pub struct MergeResponse {
    pub merged_claims: usize,
    pub merged_edges: usize,
    pub merged_connections: usize,
}

// ── Rejection Cascade Analysis ───────────────────────────────────────────────

/// Request body for analyzing the cascade effect of rejecting an edge.
#[derive(Debug, Deserialize)]
pub struct AnalyzeRejectionRequest {
    pub staging: StagingSubgraph,
    pub rejected_edge_id: String,
}

/// An affected claim from cascade analysis.
#[derive(Debug, Serialize)]
pub struct AffectedClaim {
    pub claim_id: String,
    pub statement: String,
    pub original_truth: f64,
    pub new_truth: f64,
    pub delta: f64,
}

/// A broken support chain resulting from edge rejection.
#[derive(Debug, Serialize)]
pub struct BrokenChain {
    pub source_id: String,
    pub target_id: String,
    pub chain: Vec<String>,
}

/// Response from rejection cascade analysis.
#[derive(Debug, Serialize)]
pub struct RejectionCascadeResponse {
    pub affected_claims: Vec<AffectedClaim>,
    pub broken_chains: Vec<BrokenChain>,
    pub newly_unsupported: Vec<String>,
}

/// POST /api/v1/staging/analyze-rejection
///
/// Given a staging subgraph and a rejected edge, compute the 3-hop cascade
/// impact: which claims lose truth value, which support chains break, and
/// which claims become newly unsupported.
pub async fn analyze_rejection(
    State(_state): State<AppState>,
    Json(request): Json<AnalyzeRejectionRequest>,
) -> Result<Json<RejectionCascadeResponse>, ApiError> {
    // Find the rejected edge
    let rejected_edge = request
        .staging
        .edges
        .iter()
        .find(|e| e.id == request.rejected_edge_id)
        .ok_or_else(|| ApiError::NotFound {
            entity: "edge".to_string(),
            id: request.rejected_edge_id.clone(),
        })?;

    // Compute 3-hop neighborhood from the target of the rejected edge
    let affected_claims = compute_cascade(&request.staging, &rejected_edge.target_claim_id, 3);

    // Find broken support chains
    let broken_chains = find_broken_chains(&request.staging, &request.rejected_edge_id);

    // Find claims that become unsupported after rejection
    let newly_unsupported = find_newly_unsupported(&request.staging, &request.rejected_edge_id);

    Ok(Json(RejectionCascadeResponse {
        affected_claims,
        broken_chains,
        newly_unsupported,
    }))
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Calculate initial truth for staging claims.
/// Mirrors the main submission logic: no evidence → low truth.
fn calculate_staging_truth(evidence_count: usize, methodology: &str, confidence: f64) -> f64 {
    let methodology_weight = match methodology {
        "formal_proof" => 1.2,
        "deductive" => 1.1,
        "bayesian" => 1.0,
        "inductive" => 0.9,
        "instrumental" => 0.85,
        "extraction" => 0.75,
        "abductive" => 0.7,
        "heuristic" => 0.5,
        _ => 0.5,
    };

    if evidence_count == 0 {
        return (0.1_f64 + methodology_weight * 0.1).min(0.25);
    }

    let evidence_factor = 1.0 - (-0.3 * evidence_count as f64).exp();
    let method_factor = methodology_weight / 1.2;
    let conf_factor = confidence.clamp(0.0, 1.0);

    (0.3 + evidence_factor * 0.5 * method_factor * conf_factor).clamp(0.0, 1.0)
}

/// Compute cascade of truth value changes within N hops of a target claim.
fn compute_cascade(
    staging: &StagingSubgraph,
    target_id: &str,
    max_hops: usize,
) -> Vec<AffectedClaim> {
    let mut affected = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut frontier = vec![target_id.to_string()];

    for _hop in 0..max_hops {
        let mut next_frontier = Vec::new();

        for node_id in &frontier {
            if !visited.insert(node_id.clone()) {
                continue;
            }

            // Find the claim
            if let Some(claim) = staging.claims.iter().find(|c| c.id == *node_id) {
                // Estimate truth reduction (simplified: -10% per hop from rejection)
                let decay = 0.9_f64.powi((_hop + 1) as i32);
                let new_truth = (claim.truth_value * decay).clamp(0.0, 1.0);
                let delta = new_truth - claim.truth_value;

                if delta.abs() > 0.001 {
                    affected.push(AffectedClaim {
                        claim_id: claim.id.clone(),
                        statement: claim.statement.clone(),
                        original_truth: claim.truth_value,
                        new_truth,
                        delta,
                    });
                }
            }

            // Find downstream edges (edges where this node is source)
            for edge in &staging.edges {
                if edge.source_claim_id == *node_id && !visited.contains(&edge.target_claim_id) {
                    next_frontier.push(edge.target_claim_id.clone());
                }
            }
        }

        frontier = next_frontier;
    }

    affected
}

/// Find support chains broken by rejecting an edge.
fn find_broken_chains(staging: &StagingSubgraph, rejected_edge_id: &str) -> Vec<BrokenChain> {
    let mut chains = Vec::new();

    // Find chains that pass through the rejected edge
    if let Some(rejected) = staging.edges.iter().find(|e| e.id == rejected_edge_id) {
        // Simple: report the direct chain that's broken
        chains.push(BrokenChain {
            source_id: rejected.source_claim_id.clone(),
            target_id: rejected.target_claim_id.clone(),
            chain: vec![
                rejected.source_claim_id.clone(),
                rejected.target_claim_id.clone(),
            ],
        });

        // Find transitive chains (2-hop) that relied on this edge
        for edge in &staging.edges {
            if edge.target_claim_id == rejected.source_claim_id && edge.edge_type == "supports" {
                chains.push(BrokenChain {
                    source_id: edge.source_claim_id.clone(),
                    target_id: rejected.target_claim_id.clone(),
                    chain: vec![
                        edge.source_claim_id.clone(),
                        rejected.source_claim_id.clone(),
                        rejected.target_claim_id.clone(),
                    ],
                });
            }
        }
    }

    chains
}

/// Find claims that become unsupported after edge rejection.
fn find_newly_unsupported(staging: &StagingSubgraph, rejected_edge_id: &str) -> Vec<String> {
    let rejected = match staging.edges.iter().find(|e| e.id == rejected_edge_id) {
        Some(e) => e,
        None => return Vec::new(),
    };

    let target_id = &rejected.target_claim_id;

    // Check if the target has any other supporting edges
    let has_other_support = staging.edges.iter().any(|e| {
        e.id != rejected_edge_id && e.target_claim_id == *target_id && e.edge_type == "supports"
    });

    if has_other_support {
        Vec::new()
    } else {
        vec![target_id.clone()]
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── calculate_staging_truth ──────────────────────────────────────────

    #[test]
    fn truth_no_evidence_is_low() {
        let truth = calculate_staging_truth(0, "heuristic", 1.0);
        assert!(
            truth < 0.3,
            "No evidence should give low truth, got {truth}"
        );
    }

    #[test]
    fn truth_no_evidence_capped_at_025() {
        let truth = calculate_staging_truth(0, "formal_proof", 1.0);
        assert!(truth <= 0.25, "No evidence should cap at 0.25, got {truth}");
    }

    #[test]
    fn truth_with_evidence_higher_than_without() {
        let no_evidence = calculate_staging_truth(0, "extraction", 0.8);
        let with_evidence = calculate_staging_truth(3, "extraction", 0.8);
        assert!(
            with_evidence > no_evidence,
            "Evidence should increase truth: {with_evidence} vs {no_evidence}"
        );
    }

    #[test]
    fn truth_more_evidence_means_higher_truth() {
        let few = calculate_staging_truth(1, "deductive", 0.8);
        let many = calculate_staging_truth(5, "deductive", 0.8);
        assert!(many > few, "More evidence → higher truth: {many} vs {few}");
    }

    #[test]
    fn truth_bounded_zero_one() {
        let truth = calculate_staging_truth(100, "formal_proof", 1.0);
        assert!((0.0..=1.0).contains(&truth), "Truth out of bounds: {truth}");
    }

    #[test]
    fn truth_methodology_affects_result() {
        let heuristic = calculate_staging_truth(3, "heuristic", 0.8);
        let deductive = calculate_staging_truth(3, "deductive", 0.8);
        assert!(
            deductive > heuristic,
            "Deductive should score higher than heuristic: {deductive} vs {heuristic}"
        );
    }

    // ── ingest_json validation ───────────────────────────────────────────

    #[test]
    fn staging_claim_serialization() {
        let claim = StagingClaim {
            id: "test-id".to_string(),
            statement: "Test claim".to_string(),
            truth_value: 0.5,
            confidence: 0.8,
            methodology: "extraction".to_string(),
            source: Some("test".to_string()),
            domain: None,
            evidence: vec![],
        };
        let json = serde_json::to_string(&claim).unwrap();
        let deserialized: StagingClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.statement, "Test claim");
    }

    #[test]
    fn staging_subgraph_serialization() {
        let sg = StagingSubgraph {
            claims: vec![],
            edges: vec![],
            proposed_connections: vec![],
        };
        let json = serde_json::to_string(&sg).unwrap();
        let deserialized: StagingSubgraph = serde_json::from_str(&json).unwrap();
        assert!(deserialized.claims.is_empty());
    }

    // ── compute_cascade ──────────────────────────────────────────────────

    #[test]
    fn cascade_empty_graph() {
        let staging = StagingSubgraph {
            claims: vec![],
            edges: vec![],
            proposed_connections: vec![],
        };
        let affected = compute_cascade(&staging, "nonexistent", 3);
        assert!(affected.is_empty());
    }

    #[test]
    fn cascade_single_claim() {
        let staging = StagingSubgraph {
            claims: vec![StagingClaim {
                id: "c1".to_string(),
                statement: "Claim 1".to_string(),
                truth_value: 0.8,
                confidence: 0.8,
                methodology: "deductive".to_string(),
                source: None,
                domain: None,
                evidence: vec![],
            }],
            edges: vec![],
            proposed_connections: vec![],
        };
        let affected = compute_cascade(&staging, "c1", 3);
        assert_eq!(affected.len(), 1);
        assert!(affected[0].delta < 0.0, "Truth should decrease");
    }

    #[test]
    fn cascade_respects_max_hops() {
        let staging = StagingSubgraph {
            claims: vec![
                make_staging_claim("c1", 0.8),
                make_staging_claim("c2", 0.7),
                make_staging_claim("c3", 0.6),
                make_staging_claim("c4", 0.5),
            ],
            edges: vec![
                make_staging_edge("e1", "c1", "c2"),
                make_staging_edge("e2", "c2", "c3"),
                make_staging_edge("e3", "c3", "c4"),
            ],
            proposed_connections: vec![],
        };
        // 1 hop from c1 should only reach c1 and c2
        let affected = compute_cascade(&staging, "c1", 1);
        assert!(affected.len() <= 2, "1-hop should reach at most 2 claims");
    }

    // ── find_newly_unsupported ───────────────────────────────────────────

    #[test]
    fn unsupported_single_support() {
        let staging = StagingSubgraph {
            claims: vec![make_staging_claim("c1", 0.8), make_staging_claim("c2", 0.7)],
            edges: vec![StagingEdge {
                id: "e1".to_string(),
                source_claim_id: "c1".to_string(),
                target_claim_id: "c2".to_string(),
                edge_type: "supports".to_string(),
                strength: 0.9,
            }],
            proposed_connections: vec![],
        };
        let unsupported = find_newly_unsupported(&staging, "e1");
        assert_eq!(unsupported, vec!["c2"]);
    }

    #[test]
    fn unsupported_multiple_supports() {
        let staging = StagingSubgraph {
            claims: vec![
                make_staging_claim("c1", 0.8),
                make_staging_claim("c2", 0.8),
                make_staging_claim("c3", 0.7),
            ],
            edges: vec![
                StagingEdge {
                    id: "e1".to_string(),
                    source_claim_id: "c1".to_string(),
                    target_claim_id: "c3".to_string(),
                    edge_type: "supports".to_string(),
                    strength: 0.9,
                },
                StagingEdge {
                    id: "e2".to_string(),
                    source_claim_id: "c2".to_string(),
                    target_claim_id: "c3".to_string(),
                    edge_type: "supports".to_string(),
                    strength: 0.8,
                },
            ],
            proposed_connections: vec![],
        };
        let unsupported = find_newly_unsupported(&staging, "e1");
        assert!(unsupported.is_empty(), "c3 still has support from e2");
    }

    // ── find_broken_chains ───────────────────────────────────────────────

    #[test]
    fn broken_chains_direct() {
        let staging = StagingSubgraph {
            claims: vec![make_staging_claim("c1", 0.8), make_staging_claim("c2", 0.7)],
            edges: vec![StagingEdge {
                id: "e1".to_string(),
                source_claim_id: "c1".to_string(),
                target_claim_id: "c2".to_string(),
                edge_type: "supports".to_string(),
                strength: 0.9,
            }],
            proposed_connections: vec![],
        };
        let chains = find_broken_chains(&staging, "e1");
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].chain, vec!["c1", "c2"]);
    }

    #[test]
    fn broken_chains_transitive() {
        let staging = StagingSubgraph {
            claims: vec![
                make_staging_claim("c1", 0.8),
                make_staging_claim("c2", 0.7),
                make_staging_claim("c3", 0.6),
            ],
            edges: vec![
                StagingEdge {
                    id: "e1".to_string(),
                    source_claim_id: "c1".to_string(),
                    target_claim_id: "c2".to_string(),
                    edge_type: "supports".to_string(),
                    strength: 0.9,
                },
                StagingEdge {
                    id: "e2".to_string(),
                    source_claim_id: "c2".to_string(),
                    target_claim_id: "c3".to_string(),
                    edge_type: "supports".to_string(),
                    strength: 0.8,
                },
            ],
            proposed_connections: vec![],
        };
        let chains = find_broken_chains(&staging, "e2");
        // Direct chain c2→c3 + transitive chain c1→c2→c3
        assert_eq!(chains.len(), 2);
    }

    // ── Test helpers ─────────────────────────────────────────────────────

    fn make_staging_claim(id: &str, truth: f64) -> StagingClaim {
        StagingClaim {
            id: id.to_string(),
            statement: format!("Claim {id}"),
            truth_value: truth,
            confidence: 0.8,
            methodology: "deductive".to_string(),
            source: None,
            domain: None,
            evidence: vec![],
        }
    }

    fn make_staging_edge(id: &str, source: &str, target: &str) -> StagingEdge {
        StagingEdge {
            id: id.to_string(),
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            edge_type: "supports".to_string(),
            strength: 0.8,
        }
    }
}
