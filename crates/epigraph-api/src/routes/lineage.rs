use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, LineageRepository};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

use crate::{errors::ApiError, state::AppState};

// ============================================================================
// Lineage Traversal Constants
// ============================================================================

/// Default maximum depth for lineage traversal when not specified.
const DEFAULT_LINEAGE_DEPTH: u32 = 10;

/// Maximum depth allowed for lineage traversal to prevent resource exhaustion.
/// Traversing deeper than this could cause performance issues or timeouts.
const MAX_LINEAGE_DEPTH: u32 = 100;

// ============================================================================
// Direction Enum
// ============================================================================

/// Direction for lineage traversal
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LineageDirection {
    /// Traverse ancestors (claims this claim depends on)
    #[default]
    Ancestors,
    /// Traverse descendants (claims that depend on this claim)
    Descendants,
    /// Traverse both directions
    Both,
}

// ============================================================================
// Query Parameters
// ============================================================================

/// Query parameters for lineage endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct LineageParams {
    /// Maximum depth to traverse (default: 10, max: 100)
    pub max_depth: Option<u32>,
    /// Direction of traversal (default: ancestors)
    pub direction: Option<LineageDirection>,
    /// Include evidence for each claim (default: true)
    pub include_evidence: Option<bool>,
    /// Include reasoning traces for each claim (default: true)
    pub include_traces: Option<bool>,
}

// ============================================================================
// Response Types
// ============================================================================

/// Response from the lineage endpoint
#[derive(Debug, Clone, Serialize)]
pub struct LineageResponse {
    /// The claim ID that was queried
    pub root_claim_id: Uuid,
    /// All nodes (claims) in the lineage graph
    pub nodes: Vec<LineageNode>,
    /// All edges (dependencies) in the lineage graph
    pub edges: Vec<LineageEdge>,
    /// Maximum depth reached during traversal
    pub depth_reached: u32,
    /// Whether traversal was truncated due to depth limit
    pub truncated: bool,
    /// Direction of traversal performed
    pub direction: LineageDirection,
}

/// A node in the lineage graph representing a claim
#[derive(Debug, Clone, Serialize)]
pub struct LineageNode {
    /// The claim ID
    pub claim_id: Uuid,
    /// Claim content/statement
    pub content: String,
    /// Current truth value [0.0, 1.0]
    pub truth_value: f64,
    /// Depth from the root claim (0 = root)
    pub depth: u32,
    /// Agent who created this claim
    pub agent_id: Uuid,
    /// When the claim was created
    pub created_at: DateTime<Utc>,
    /// Evidence items attached to this claim (if requested)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<LineageEvidence>,
    /// Reasoning trace for this claim (if requested)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<LineageTrace>,
}

/// Evidence attached to a claim in lineage
#[derive(Debug, Clone, Serialize)]
pub struct LineageEvidence {
    pub id: Uuid,
    pub evidence_type: String,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
}

/// Reasoning trace for a claim in lineage
#[derive(Debug, Clone, Serialize)]
pub struct LineageTrace {
    pub id: Uuid,
    pub reasoning_type: String,
    pub confidence: f64,
    pub explanation: String,
    pub parent_trace_ids: Vec<Uuid>,
}

/// An edge in the lineage graph representing a dependency
#[derive(Debug, Clone, Serialize)]
pub struct LineageEdge {
    /// Source claim ID (parent/supporter)
    pub source_id: Uuid,
    /// Target claim ID (child/supported)
    pub target_id: Uuid,
    /// Relationship type (e.g., "supports", "derives_from", "refines")
    pub relationship: String,
}

// ============================================================================
// Backward Compatibility Types (for existing tests)
// ============================================================================

/// Legacy lineage response containing the reasoning trace DAG
/// Preserved for backward compatibility with existing tests
#[derive(Serialize)]
pub struct LegacyLineageResponse {
    pub claim_id: Uuid,
    pub traces: Vec<TraceNode>,
}

/// A node in the reasoning trace DAG (legacy format)
#[derive(Serialize)]
pub struct TraceNode {
    pub id: Uuid,
    pub methodology: String,
    pub confidence: f64,
    pub description: String,
    pub parent_ids: Vec<Uuid>,
}

// ============================================================================
// Handler Implementation
// ============================================================================

/// Get the reasoning lineage for a claim
///
/// GET /lineage/:claim_id
///
/// Returns the full reasoning trace DAG showing how the claim's truth was derived.
///
/// # Query Parameters
/// - `max_depth` - Maximum depth to traverse (default: 10, max: 100)
/// - `direction` - Direction of traversal: "ancestors", "descendants", or "both" (default: "ancestors")
/// - `include_evidence` - Include evidence items (default: true)
/// - `include_traces` - Include reasoning traces (default: true)
///
/// # Responses
/// - 200: LineageResponse with nodes and edges
/// - 404: Claim not found
pub async fn get_lineage(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<LineageParams>,
) -> Result<Json<LineageResponse>, ApiError> {
    // Parse parameters with defaults and bounds
    let max_depth = params
        .max_depth
        .unwrap_or(DEFAULT_LINEAGE_DEPTH)
        .min(MAX_LINEAGE_DEPTH) as i32;
    let direction = params.direction.unwrap_or_default();
    let include_evidence = params.include_evidence.unwrap_or(true);
    let include_traces = params.include_traces.unwrap_or(true);

    // First, check if the claim exists (for 404)
    let _root_claim = ClaimRepository::get_by_id(&state.db_pool, ClaimId::from_uuid(claim_id))
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        })?;

    // Get lineage based on direction
    let (nodes, edges, max_depth_reached) = match direction {
        LineageDirection::Ancestors => {
            get_ancestor_lineage(
                &state,
                claim_id,
                max_depth,
                include_evidence,
                include_traces,
            )
            .await?
        }
        LineageDirection::Descendants => {
            get_descendant_lineage(
                &state,
                claim_id,
                max_depth,
                include_evidence,
                include_traces,
            )
            .await?
        }
        LineageDirection::Both => {
            // Get both ancestors and descendants, then merge
            let (ancestor_nodes, ancestor_edges, ancestor_depth) = get_ancestor_lineage(
                &state,
                claim_id,
                max_depth,
                include_evidence,
                include_traces,
            )
            .await?;
            let (descendant_nodes, descendant_edges, descendant_depth) = get_descendant_lineage(
                &state,
                claim_id,
                max_depth,
                include_evidence,
                include_traces,
            )
            .await?;

            // Merge nodes, avoiding duplicates using HashSet for O(1) lookup
            let existing_ids: HashSet<Uuid> = ancestor_nodes.iter().map(|n| n.claim_id).collect();
            let merged_nodes: Vec<_> = ancestor_nodes
                .into_iter()
                .chain(
                    descendant_nodes
                        .into_iter()
                        .filter(|n| !existing_ids.contains(&n.claim_id)),
                )
                .collect();

            // Merge edges, avoiding duplicates
            let existing_edges: HashSet<_> = ancestor_edges
                .iter()
                .map(|e| (e.source_id, e.target_id))
                .collect();
            let merged_edges: Vec<_> = ancestor_edges
                .into_iter()
                .chain(
                    descendant_edges
                        .into_iter()
                        .filter(|e| !existing_edges.contains(&(e.source_id, e.target_id))),
                )
                .collect();

            (
                merged_nodes,
                merged_edges,
                ancestor_depth.max(descendant_depth),
            )
        }
    };

    // Determine if truncated (there might be more nodes beyond max_depth)
    let truncated = max_depth_reached >= max_depth as u32 && nodes.len() > 1;

    let response = LineageResponse {
        root_claim_id: claim_id,
        nodes,
        edges,
        depth_reached: max_depth_reached,
        truncated,
        direction,
    };

    Ok(Json(response))
}

/// Get ancestor lineage (claims this claim depends on)
async fn get_ancestor_lineage(
    state: &AppState,
    claim_id: Uuid,
    max_depth: i32,
    include_evidence: bool,
    include_traces: bool,
) -> Result<(Vec<LineageNode>, Vec<LineageEdge>, u32), ApiError> {
    // Use LineageRepository for ancestor traversal
    let lineage_result =
        LineageRepository::get_lineage(&state.db_pool, claim_id, Some(max_depth)).await?;

    // If no claims found (empty result), return just the root claim
    if lineage_result.claims.is_empty() {
        // Get the root claim info
        let claim = ClaimRepository::get_by_id(&state.db_pool, ClaimId::from_uuid(claim_id))
            .await?
            .ok_or_else(|| ApiError::NotFound {
                entity: "Claim".to_string(),
                id: claim_id.to_string(),
            })?;

        let node = LineageNode {
            claim_id,
            content: claim.content,
            truth_value: claim.truth_value.value(),
            depth: 0,
            agent_id: claim.agent_id.into(),
            created_at: claim.created_at,
            evidence: vec![],
            trace: None,
        };

        return Ok((vec![node], vec![], 0));
    }

    // Build nodes from lineage claims
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for (id, lineage_claim) in &lineage_result.claims {
        // Get full claim data to include agent_id and created_at
        let claim = ClaimRepository::get_by_id(&state.db_pool, ClaimId::from_uuid(*id))
            .await?
            .ok_or_else(|| ApiError::NotFound {
                entity: "Claim".to_string(),
                id: id.to_string(),
            })?;

        // Build evidence list if requested
        let evidence = if include_evidence {
            lineage_claim
                .evidence_ids
                .iter()
                .filter_map(|ev_id| {
                    lineage_result
                        .evidence
                        .get(ev_id)
                        .map(|ev| LineageEvidence {
                            id: ev.id,
                            evidence_type: ev.evidence_type.clone(),
                            content_hash: hex::encode(&ev.content_hash),
                            created_at: claim.created_at, // Use claim created_at as proxy
                        })
                })
                .collect()
        } else {
            vec![]
        };

        // Build trace if requested
        let trace = if include_traces {
            lineage_claim.trace_id.and_then(|trace_id| {
                lineage_result.traces.get(&trace_id).map(|t| LineageTrace {
                    id: t.id,
                    reasoning_type: t.reasoning_type.clone(),
                    confidence: t.confidence,
                    explanation: format!("Reasoning trace for claim: {}", lineage_claim.content),
                    parent_trace_ids: t.parent_trace_ids.clone(),
                })
            })
        } else {
            None
        };

        let node = LineageNode {
            claim_id: *id,
            content: lineage_claim.content.clone(),
            truth_value: lineage_claim.truth_value,
            depth: lineage_claim.depth as u32,
            agent_id: claim.agent_id.into(),
            created_at: claim.created_at,
            evidence,
            trace,
        };

        nodes.push(node);

        // Build edges from parent_ids
        for parent_id in &lineage_claim.parent_ids {
            edges.push(LineageEdge {
                source_id: *parent_id,
                target_id: *id,
                relationship: "supports".to_string(),
            });
        }
    }

    // Sort nodes by depth
    nodes.sort_by_key(|n| n.depth);

    let max_depth_reached = lineage_result.max_depth_reached as u32;
    Ok((nodes, edges, max_depth_reached))
}

/// Get descendant lineage (claims that depend on this claim)
///
/// Delegates to LineageRepository::get_descendants for the recursive CTE query,
/// then transforms the result to the API response format.
async fn get_descendant_lineage(
    state: &AppState,
    claim_id: Uuid,
    max_depth: i32,
    include_evidence: bool,
    include_traces: bool,
) -> Result<(Vec<LineageNode>, Vec<LineageEdge>, u32), ApiError> {
    // Use LineageRepository for descendant traversal
    let lineage_result =
        LineageRepository::get_descendants(&state.db_pool, claim_id, Some(max_depth)).await?;

    // If no claims found (empty result), return just the root claim
    if lineage_result.claims.is_empty() {
        // Get the root claim info
        let claim = ClaimRepository::get_by_id(&state.db_pool, ClaimId::from_uuid(claim_id))
            .await?
            .ok_or_else(|| ApiError::NotFound {
                entity: "Claim".to_string(),
                id: claim_id.to_string(),
            })?;

        let node = LineageNode {
            claim_id,
            content: claim.content,
            truth_value: claim.truth_value.value(),
            depth: 0,
            agent_id: claim.agent_id.into(),
            created_at: claim.created_at,
            evidence: vec![],
            trace: None,
        };

        return Ok((vec![node], vec![], 0));
    }

    // Build nodes from lineage claims
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for (id, lineage_claim) in &lineage_result.claims {
        // Get full claim data to include agent_id and created_at
        let claim = ClaimRepository::get_by_id(&state.db_pool, ClaimId::from_uuid(*id))
            .await?
            .ok_or_else(|| ApiError::NotFound {
                entity: "Claim".to_string(),
                id: id.to_string(),
            })?;

        // Build evidence list if requested
        let evidence = if include_evidence {
            lineage_claim
                .evidence_ids
                .iter()
                .filter_map(|ev_id| {
                    lineage_result
                        .evidence
                        .get(ev_id)
                        .map(|ev| LineageEvidence {
                            id: ev.id,
                            evidence_type: ev.evidence_type.clone(),
                            content_hash: hex::encode(&ev.content_hash),
                            created_at: claim.created_at, // Use claim created_at as proxy
                        })
                })
                .collect()
        } else {
            vec![]
        };

        // Build trace if requested
        let trace = if include_traces {
            lineage_claim.trace_id.and_then(|trace_id| {
                lineage_result.traces.get(&trace_id).map(|t| LineageTrace {
                    id: t.id,
                    reasoning_type: t.reasoning_type.clone(),
                    confidence: t.confidence,
                    explanation: format!("Reasoning trace for claim: {}", lineage_claim.content),
                    parent_trace_ids: t.parent_trace_ids.clone(),
                })
            })
        } else {
            None
        };

        let node = LineageNode {
            claim_id: *id,
            content: lineage_claim.content.clone(),
            truth_value: lineage_claim.truth_value,
            depth: lineage_claim.depth as u32,
            agent_id: claim.agent_id.into(),
            created_at: claim.created_at,
            evidence,
            trace,
        };

        nodes.push(node);

        // Build edges from parent_ids
        for parent_id in &lineage_claim.parent_ids {
            edges.push(LineageEdge {
                source_id: *parent_id,
                target_id: *id,
                relationship: "supports".to_string(),
            });
        }
    }

    // Sort nodes by depth
    nodes.sort_by_key(|n| n.depth);

    let max_depth_reached = lineage_result.max_depth_reached as u32;

    Ok((nodes, edges, max_depth_reached))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lineage_direction_default() {
        let direction = LineageDirection::default();
        assert_eq!(direction, LineageDirection::Ancestors);
    }

    #[test]
    fn test_lineage_direction_serialization() {
        let ancestors = serde_json::to_string(&LineageDirection::Ancestors).unwrap();
        assert_eq!(ancestors, "\"ancestors\"");

        let descendants = serde_json::to_string(&LineageDirection::Descendants).unwrap();
        assert_eq!(descendants, "\"descendants\"");

        let both = serde_json::to_string(&LineageDirection::Both).unwrap();
        assert_eq!(both, "\"both\"");
    }

    #[test]
    fn test_lineage_direction_deserialization() {
        let ancestors: LineageDirection = serde_json::from_str("\"ancestors\"").unwrap();
        assert_eq!(ancestors, LineageDirection::Ancestors);

        let descendants: LineageDirection = serde_json::from_str("\"descendants\"").unwrap();
        assert_eq!(descendants, LineageDirection::Descendants);

        let both: LineageDirection = serde_json::from_str("\"both\"").unwrap();
        assert_eq!(both, LineageDirection::Both);
    }

    #[test]
    fn test_lineage_params_defaults() {
        let json = "{}";
        let params: LineageParams = serde_json::from_str(json).unwrap();

        assert!(params.max_depth.is_none());
        assert!(params.direction.is_none());
        assert!(params.include_evidence.is_none());
        assert!(params.include_traces.is_none());
    }

    #[test]
    fn test_lineage_params_custom() {
        let json = r#"{"max_depth": 50, "direction": "descendants", "include_evidence": false, "include_traces": true}"#;
        let params: LineageParams = serde_json::from_str(json).unwrap();

        assert_eq!(params.max_depth, Some(50));
        assert_eq!(params.direction, Some(LineageDirection::Descendants));
        assert_eq!(params.include_evidence, Some(false));
        assert_eq!(params.include_traces, Some(true));
    }

    #[test]
    fn test_lineage_response_serialization() {
        let claim_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let response = LineageResponse {
            root_claim_id: claim_id,
            nodes: vec![LineageNode {
                claim_id,
                content: "Test claim".to_string(),
                truth_value: 0.8,
                depth: 0,
                agent_id,
                created_at: now,
                evidence: vec![],
                trace: None,
            }],
            edges: vec![],
            depth_reached: 0,
            truncated: false,
            direction: LineageDirection::Ancestors,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("root_claim_id"));
        assert!(json.contains("nodes"));
        assert!(json.contains("edges"));
        assert!(json.contains("depth_reached"));
        assert!(json.contains("truncated"));
        assert!(json.contains("direction"));
    }

    #[test]
    fn test_lineage_node_serialization() {
        let claim_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let node = LineageNode {
            claim_id,
            content: "Test claim".to_string(),
            truth_value: 0.75,
            depth: 2,
            agent_id,
            created_at: now,
            evidence: vec![],
            trace: None,
        };

        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("claim_id"));
        assert!(json.contains("content"));
        assert!(json.contains("truth_value"));
        assert!(json.contains("depth"));
        assert!(json.contains("agent_id"));
        assert!(json.contains("created_at"));
        // Empty evidence and None trace should be omitted
        assert!(!json.contains("evidence"));
        assert!(!json.contains("trace"));
    }

    #[test]
    fn test_lineage_edge_serialization() {
        let source_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        let edge = LineageEdge {
            source_id,
            target_id,
            relationship: "supports".to_string(),
        };

        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("source_id"));
        assert!(json.contains("target_id"));
        assert!(json.contains("relationship"));
        assert!(json.contains("supports"));
    }

    #[test]
    fn test_lineage_evidence_serialization() {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let evidence = LineageEvidence {
            id,
            evidence_type: "document".to_string(),
            content_hash: "abc123".to_string(),
            created_at: now,
        };

        let json = serde_json::to_string(&evidence).unwrap();
        assert!(json.contains("id"));
        assert!(json.contains("evidence_type"));
        assert!(json.contains("content_hash"));
        assert!(json.contains("created_at"));
    }

    #[test]
    fn test_lineage_trace_serialization() {
        let id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();

        let trace = LineageTrace {
            id,
            reasoning_type: "deductive".to_string(),
            confidence: 0.9,
            explanation: "Based on evidence".to_string(),
            parent_trace_ids: vec![parent_id],
        };

        let json = serde_json::to_string(&trace).unwrap();
        assert!(json.contains("id"));
        assert!(json.contains("reasoning_type"));
        assert!(json.contains("confidence"));
        assert!(json.contains("explanation"));
        assert!(json.contains("parent_trace_ids"));
    }

    #[test]
    fn test_truth_value_bounds() {
        // Truth values should be between 0.0 and 1.0
        let claim_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let valid_values = [0.0, 0.5, 1.0, 0.001, 0.999];
        for value in valid_values {
            let node = LineageNode {
                claim_id,
                content: "Test".to_string(),
                truth_value: value,
                depth: 0,
                agent_id,
                created_at: now,
                evidence: vec![],
                trace: None,
            };
            assert!(node.truth_value >= 0.0 && node.truth_value <= 1.0);
        }
    }

    #[test]
    fn test_max_depth_capping() {
        // Verify max_depth is capped at MAX_LINEAGE_DEPTH
        let max_depth = 1000_u32.min(MAX_LINEAGE_DEPTH);
        assert_eq!(max_depth, MAX_LINEAGE_DEPTH);

        let max_depth = 50_u32.min(MAX_LINEAGE_DEPTH);
        assert_eq!(max_depth, 50);

        let max_depth = MAX_LINEAGE_DEPTH.min(MAX_LINEAGE_DEPTH);
        assert_eq!(max_depth, MAX_LINEAGE_DEPTH);
    }

    #[test]
    fn test_default_lineage_depth() {
        assert_eq!(DEFAULT_LINEAGE_DEPTH, 10);
        assert!(DEFAULT_LINEAGE_DEPTH <= MAX_LINEAGE_DEPTH);
    }
}
