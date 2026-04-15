//! Structural feature extractor endpoint (§3.2 Privacy-Preserving Features)
//!
//! Computes statistical graph features without exposing content.
//! Enables ML training on private subgraph topology.
//!
//! Public (GET):
//! - `GET /api/v1/structural-features/:owner_id` — statistical features for owner's subgraph

#[cfg(feature = "db")]
use crate::access_control::COARSE_EDGE_TYPES;
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;
#[cfg(feature = "db")]
use axum::extract::State;
use axum::{
    extract::{Path, Query},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Query parameters for structural feature extraction
#[derive(Debug, Deserialize)]
pub struct StructuralFeaturesQuery {
    /// Differential privacy epsilon (higher = less noise, less privacy)
    /// Set to 0.0 to disable noise. Default: 0.0 (no noise).
    #[serde(default)]
    pub epsilon: f64,
}

/// Statistical features of a subgraph (no content exposed)
#[derive(Debug, Serialize)]
pub struct StructuralFeaturesResponse {
    pub owner_id: Uuid,
    /// Node counts by type
    pub node_counts: Vec<NodeTypeCount>,
    /// Edge counts by relationship type (coarse schema only)
    pub edge_counts: Vec<EdgeTypeCount>,
    /// Degree distribution statistics
    pub degree_stats: DegreeStats,
    /// Belief interval width distribution (mean, variance)
    pub belief_stats: BeliefStats,
    /// Number of distinct frames touched by owned claims
    pub frame_coverage: i64,
    /// Temporal activity: binned update frequency (last 30 days, 7-day bins)
    pub temporal_bins: Vec<TemporalBin>,
    /// Local clustering coefficient (mean, variance)
    pub clustering_stats: ClusteringStats,
    /// Number of distinct communities the owner's perspectives belong to
    pub community_membership_count: i64,
    /// Conflict coefficient distribution across owned claims' combined beliefs
    pub conflict_stats: ConflictStats,
    /// Whether Laplacian noise was applied
    pub noise_applied: bool,
}

/// Count of nodes by type
#[derive(Debug, Serialize)]
pub struct NodeTypeCount {
    pub node_type: String,
    pub count: i64,
}

/// Count of edges by relationship type
#[derive(Debug, Serialize)]
pub struct EdgeTypeCount {
    pub relationship: String,
    pub count: i64,
}

/// Degree distribution statistics
#[derive(Debug, Serialize)]
pub struct DegreeStats {
    pub mean: f64,
    pub variance: f64,
    pub max_degree: i64,
    pub total_nodes: i64,
}

/// Belief interval width statistics
#[derive(Debug, Serialize)]
pub struct BeliefStats {
    /// Mean of (plausibility - belief) across owned claims
    pub mean_interval_width: f64,
    /// Variance of interval width
    pub variance_interval_width: f64,
    /// Mean pignistic probability
    pub mean_pignistic: f64,
    /// Number of claims with belief data
    pub claims_with_belief: i64,
}

/// Temporal activity bin
#[derive(Debug, Serialize)]
pub struct TemporalBin {
    pub bin_label: String,
    pub count: i64,
}

/// Local clustering coefficient statistics
#[derive(Debug, Serialize)]
pub struct ClusteringStats {
    /// Mean local clustering coefficient across owned nodes with degree >= 2
    pub mean: f64,
    /// Variance of local clustering coefficient
    pub variance: f64,
    /// Number of nodes with degree >= 2 (eligible for clustering)
    pub eligible_nodes: i64,
}

/// Conflict coefficient distribution statistics
#[derive(Debug, Serialize)]
pub struct ConflictStats {
    /// Mean conflict coefficient across owned claims' global combined beliefs
    pub mean: f64,
    /// Maximum conflict coefficient
    pub max: f64,
    /// Number of combined belief entries with conflict data
    pub entries: i64,
}

// =============================================================================
// HANDLERS (db feature)
// =============================================================================

/// Compute structural features for an owner's subgraph
///
/// `GET /api/v1/structural-features/:owner_id`
///
/// Returns statistical aggregates over the owner's nodes and edges.
/// No content (claim text, evidence bodies, etc.) is exposed.
#[cfg(feature = "db")]
pub async fn get_structural_features(
    State(state): State<AppState>,
    Path(owner_id): Path<Uuid>,
    Query(params): Query<StructuralFeaturesQuery>,
) -> Result<Json<StructuralFeaturesResponse>, ApiError> {
    let pool = &state.db_pool;
    let apply_noise = params.epsilon > 0.0;

    // 1. Node counts by type from ownership table
    let node_counts: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT node_type, COUNT(*) as count
        FROM ownership
        WHERE owner_id = $1
        GROUP BY node_type
        ORDER BY count DESC
        "#,
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    let node_type_counts: Vec<NodeTypeCount> = node_counts
        .into_iter()
        .map(|(node_type, count)| NodeTypeCount {
            node_type,
            count: maybe_add_noise(count, apply_noise, params.epsilon),
        })
        .collect();

    // 2. Edge counts by relationship type for owned nodes
    //    Only coarse edge types from §1.2 are included (privacy-preserving).
    let coarse_types: Vec<String> = COARSE_EDGE_TYPES.iter().map(|s| s.to_string()).collect();
    let edge_counts: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT e.relationship, COUNT(*) as count
        FROM edges e
        JOIN ownership o ON (e.source_id = o.node_id OR e.target_id = o.node_id)
        WHERE o.owner_id = $1
          AND e.relationship = ANY($2)
        GROUP BY e.relationship
        ORDER BY count DESC
        "#,
    )
    .bind(owner_id)
    .bind(&coarse_types)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    let edge_type_counts: Vec<EdgeTypeCount> = edge_counts
        .into_iter()
        .map(|(relationship, count)| EdgeTypeCount {
            relationship,
            count: maybe_add_noise(count, apply_noise, params.epsilon),
        })
        .collect();

    // 3. Degree distribution stats for owned nodes
    let degree_rows: Vec<(i64,)> = sqlx::query_as(
        r#"
        SELECT COALESCE(deg, 0) as degree FROM (
            SELECT o.node_id,
                   (SELECT COUNT(*) FROM edges WHERE source_id = o.node_id OR target_id = o.node_id) as deg
            FROM ownership o
            WHERE o.owner_id = $1
        ) sub
        "#,
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    let degrees: Vec<f64> = degree_rows.iter().map(|(d,)| *d as f64).collect();
    let degree_stats = compute_degree_stats(&degrees);

    // 4. Belief interval width stats for owned claims
    let belief_rows: Vec<(Option<f64>, Option<f64>, Option<f64>)> = sqlx::query_as(
        r#"
        SELECT c.belief, c.plausibility, c.pignistic_prob
        FROM claims c
        JOIN ownership o ON o.node_id = c.id
        WHERE o.owner_id = $1
          AND o.node_type = 'claim'
          AND c.belief IS NOT NULL
          AND c.plausibility IS NOT NULL
        "#,
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    let belief_stats = compute_belief_stats(&belief_rows);

    // 5. Frame coverage: distinct frames touched by owned claims
    let frame_coverage: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT cf.frame_id) as count
        FROM claim_frames cf
        JOIN ownership o ON o.node_id = cf.claim_id
        WHERE o.owner_id = $1 AND o.node_type = 'claim'
        "#,
    )
    .bind(owner_id)
    .fetch_one(pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    // 6. Temporal activity (last 30 days, 7-day bins)
    let temporal_rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT
            TO_CHAR(DATE_TRUNC('week', o.created_at), 'YYYY-MM-DD') as bin_label,
            COUNT(*) as count
        FROM ownership o
        WHERE o.owner_id = $1
          AND o.created_at >= NOW() - INTERVAL '30 days'
        GROUP BY DATE_TRUNC('week', o.created_at)
        ORDER BY DATE_TRUNC('week', o.created_at) ASC
        "#,
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    let temporal_bins: Vec<TemporalBin> = temporal_rows
        .into_iter()
        .map(|(bin_label, count)| TemporalBin {
            bin_label,
            count: maybe_add_noise(count, apply_noise, params.epsilon),
        })
        .collect();

    // 7. Local clustering coefficient for owned nodes with degree >= 2
    //    For each node: cc = 2T / (d*(d-1)) where T = triangles through node
    let clustering_rows: Vec<(f64,)> = sqlx::query_as(
        r#"
        WITH owned_nodes AS (
            SELECT node_id FROM ownership WHERE owner_id = $1
        ),
        node_degrees AS (
            SELECT o.node_id, COUNT(*) as deg
            FROM owned_nodes o
            JOIN edges e ON (e.source_id = o.node_id OR e.target_id = o.node_id)
            GROUP BY o.node_id
            HAVING COUNT(*) >= 2
        ),
        triangles AS (
            SELECT nd.node_id, nd.deg,
                   COUNT(*) as tri_count
            FROM node_degrees nd
            JOIN edges e1 ON (e1.source_id = nd.node_id OR e1.target_id = nd.node_id)
            JOIN edges e2 ON (e2.source_id = nd.node_id OR e2.target_id = nd.node_id)
                         AND e2.id > e1.id
            WHERE EXISTS (
                SELECT 1 FROM edges e3
                WHERE (e3.source_id = CASE WHEN e1.source_id = nd.node_id THEN e1.target_id ELSE e1.source_id END
                   AND e3.target_id = CASE WHEN e2.source_id = nd.node_id THEN e2.target_id ELSE e2.source_id END)
                   OR (e3.source_id = CASE WHEN e2.source_id = nd.node_id THEN e2.target_id ELSE e2.source_id END
                   AND e3.target_id = CASE WHEN e1.source_id = nd.node_id THEN e1.target_id ELSE e1.source_id END)
            )
            GROUP BY nd.node_id, nd.deg
        )
        SELECT COALESCE(2.0 * tri_count / (deg * (deg - 1.0)), 0.0) as cc
        FROM triangles
        "#,
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let clustering_stats = compute_clustering_stats(&clustering_rows);

    // 8. Community membership count
    let community_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT cm.community_id) as count
        FROM community_members cm
        JOIN perspectives p ON p.id = cm.perspective_id
        WHERE p.owner_agent_id = $1
        "#,
    )
    .bind(owner_id)
    .fetch_one(pool)
    .await
    .map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })?;

    // 9. Conflict coefficient distribution for owned claims' global combined beliefs
    let conflict_rows: Vec<(Option<f64>,)> = sqlx::query_as(
        r#"
        SELECT dcb.conflict_k
        FROM ds_combined_beliefs dcb
        JOIN ownership o ON o.node_id = dcb.claim_id
        WHERE o.owner_id = $1
          AND o.node_type = 'claim'
          AND dcb.scope_type = 'global'
          AND dcb.conflict_k IS NOT NULL
        "#,
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let conflict_stats = compute_conflict_stats(&conflict_rows);

    Ok(Json(StructuralFeaturesResponse {
        owner_id,
        node_counts: node_type_counts,
        edge_counts: edge_type_counts,
        degree_stats,
        belief_stats,
        frame_coverage: maybe_add_noise(frame_coverage.0, apply_noise, params.epsilon),
        temporal_bins,
        clustering_stats,
        community_membership_count: maybe_add_noise(community_count.0, apply_noise, params.epsilon),
        conflict_stats,
        noise_applied: apply_noise,
    }))
}

#[cfg(feature = "db")]
fn compute_degree_stats(degrees: &[f64]) -> DegreeStats {
    if degrees.is_empty() {
        return DegreeStats {
            mean: 0.0,
            variance: 0.0,
            max_degree: 0,
            total_nodes: 0,
        };
    }

    let n = degrees.len() as f64;
    let mean = degrees.iter().sum::<f64>() / n;
    let variance = degrees.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / n;
    let max_degree = degrees.iter().cloned().fold(0.0_f64, f64::max) as i64;

    DegreeStats {
        mean,
        variance,
        max_degree,
        total_nodes: degrees.len() as i64,
    }
}

#[cfg(feature = "db")]
fn compute_belief_stats(rows: &[(Option<f64>, Option<f64>, Option<f64>)]) -> BeliefStats {
    if rows.is_empty() {
        return BeliefStats {
            mean_interval_width: 0.0,
            variance_interval_width: 0.0,
            mean_pignistic: 0.0,
            claims_with_belief: 0,
        };
    }

    let widths: Vec<f64> = rows
        .iter()
        .filter_map(|(bel, pl, _)| match (bel, pl) {
            (Some(b), Some(p)) => Some(p - b),
            _ => None,
        })
        .collect();

    let pignistics: Vec<f64> = rows.iter().filter_map(|(_, _, betp)| *betp).collect();

    let n = widths.len() as f64;
    let mean_width = if n > 0.0 {
        widths.iter().sum::<f64>() / n
    } else {
        0.0
    };
    let var_width = if n > 0.0 {
        widths.iter().map(|w| (w - mean_width).powi(2)).sum::<f64>() / n
    } else {
        0.0
    };
    let mean_pignistic = if !pignistics.is_empty() {
        pignistics.iter().sum::<f64>() / pignistics.len() as f64
    } else {
        0.0
    };

    BeliefStats {
        mean_interval_width: mean_width,
        variance_interval_width: var_width,
        mean_pignistic,
        claims_with_belief: rows.len() as i64,
    }
}

#[cfg(feature = "db")]
fn compute_clustering_stats(rows: &[(f64,)]) -> ClusteringStats {
    if rows.is_empty() {
        return ClusteringStats {
            mean: 0.0,
            variance: 0.0,
            eligible_nodes: 0,
        };
    }
    let n = rows.len() as f64;
    let values: Vec<f64> = rows.iter().map(|(cc,)| *cc).collect();
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    ClusteringStats {
        mean,
        variance,
        eligible_nodes: rows.len() as i64,
    }
}

#[cfg(feature = "db")]
fn compute_conflict_stats(rows: &[(Option<f64>,)]) -> ConflictStats {
    let values: Vec<f64> = rows.iter().filter_map(|(v,)| *v).collect();
    if values.is_empty() {
        return ConflictStats {
            mean: 0.0,
            max: 0.0,
            entries: 0,
        };
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let max = values.iter().cloned().fold(0.0_f64, f64::max);
    ConflictStats {
        mean,
        max,
        entries: values.len() as i64,
    }
}

/// Add Laplacian noise for differential privacy if enabled.
/// Uses Laplace mechanism: noise ~ Lap(sensitivity/epsilon).
/// Sensitivity for count queries is 1.
fn maybe_add_noise(value: i64, apply: bool, epsilon: f64) -> i64 {
    if !apply || epsilon <= 0.0 {
        return value;
    }
    // Laplace noise: sample = -b * sign(u) * ln(1 - 2|u|) where u ~ Uniform(-0.5, 0.5)
    // b = sensitivity/epsilon = 1/epsilon
    let b = 1.0 / epsilon;
    let u: f64 = rand_simple() - 0.5;
    let noise = -b * u.signum() * (1.0 - 2.0 * u.abs()).ln();
    (value as f64 + noise).round().max(0.0) as i64
}

/// Simple pseudo-random number in [0, 1) using thread-local state.
/// Not cryptographic — sufficient for differential privacy noise.
fn rand_simple() -> f64 {
    use std::time::SystemTime;
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    // Simple LCG
    ((seed.wrapping_mul(1103515245).wrapping_add(12345) >> 16) as f64) / 32768.0
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn get_structural_features(
    Path(owner_id): Path<Uuid>,
    Query(_params): Query<StructuralFeaturesQuery>,
) -> Result<Json<StructuralFeaturesResponse>, ApiError> {
    Ok(Json(StructuralFeaturesResponse {
        owner_id,
        node_counts: Vec::new(),
        edge_counts: Vec::new(),
        degree_stats: DegreeStats {
            mean: 0.0,
            variance: 0.0,
            max_degree: 0,
            total_nodes: 0,
        },
        belief_stats: BeliefStats {
            mean_interval_width: 0.0,
            variance_interval_width: 0.0,
            mean_pignistic: 0.0,
            claims_with_belief: 0,
        },
        frame_coverage: 0,
        temporal_bins: Vec::new(),
        clustering_stats: ClusteringStats {
            mean: 0.0,
            variance: 0.0,
            eligible_nodes: 0,
        },
        community_membership_count: 0,
        conflict_stats: ConflictStats {
            mean: 0.0,
            max: 0.0,
            entries: 0,
        },
        noise_applied: false,
    }))
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_features_query_defaults() {
        let q: StructuralFeaturesQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.epsilon, 0.0);
    }

    #[test]
    fn maybe_add_noise_no_noise_when_disabled() {
        assert_eq!(maybe_add_noise(42, false, 1.0), 42);
        assert_eq!(maybe_add_noise(42, true, 0.0), 42);
    }

    #[test]
    fn maybe_add_noise_never_negative() {
        // With high epsilon (low noise), result should stay near value
        for _ in 0..100 {
            let noisy = maybe_add_noise(5, true, 10.0);
            assert!(
                noisy >= 0,
                "Noisy count should not be negative, got {noisy}"
            );
        }
    }

    #[test]
    fn structural_features_response_serializes() {
        let resp = StructuralFeaturesResponse {
            owner_id: Uuid::new_v4(),
            node_counts: vec![NodeTypeCount {
                node_type: "claim".to_string(),
                count: 10,
            }],
            edge_counts: vec![EdgeTypeCount {
                relationship: "SUPPORTS".to_string(),
                count: 5,
            }],
            degree_stats: DegreeStats {
                mean: 2.5,
                variance: 1.2,
                max_degree: 8,
                total_nodes: 10,
            },
            belief_stats: BeliefStats {
                mean_interval_width: 0.3,
                variance_interval_width: 0.05,
                mean_pignistic: 0.75,
                claims_with_belief: 8,
            },
            frame_coverage: 3,
            temporal_bins: vec![TemporalBin {
                bin_label: "2026-02-17".to_string(),
                count: 4,
            }],
            clustering_stats: ClusteringStats {
                mean: 0.4,
                variance: 0.05,
                eligible_nodes: 6,
            },
            community_membership_count: 2,
            conflict_stats: ConflictStats {
                mean: 0.15,
                max: 0.3,
                entries: 4,
            },
            noise_applied: false,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("node_counts"));
        assert!(json.contains("edge_counts"));
        assert!(json.contains("degree_stats"));
        assert!(json.contains("belief_stats"));
        assert!(json.contains("frame_coverage"));
        assert!(json.contains("clustering_stats"));
        assert!(json.contains("community_membership_count"));
        assert!(json.contains("conflict_stats"));
    }

    #[test]
    fn coarse_edge_types_used_in_filter() {
        use crate::access_control::COARSE_EDGE_TYPES;
        // Verify all coarse types are valid uppercase relationship names
        assert_eq!(COARSE_EDGE_TYPES.len(), 15);
        for t in COARSE_EDGE_TYPES {
            assert!(
                t.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "Edge type should be SCREAMING_SNAKE: {t}"
            );
        }
    }

    #[test]
    fn degree_stats_serializes() {
        let stats = DegreeStats {
            mean: 3.5,
            variance: 2.1,
            max_degree: 12,
            total_nodes: 50,
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("3.5"));
        assert!(json.contains("2.1"));
    }
}
