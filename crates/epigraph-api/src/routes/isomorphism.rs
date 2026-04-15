//! Structural isomorphism and pattern detection endpoints
//!
//! Public (POST/GET):
//! - `POST /api/v1/isomorphism/detect` — detect patterns in a subgraph
//! - `POST /api/v1/isomorphism/compare` — compare two subgraphs
//! - `GET /api/v1/isomorphism/patterns` — list pattern templates from DB

use crate::errors::ApiError;
use crate::state::AppState;
use axum::{extract::State, Json};
use epigraph_db::PatternTemplateRepository;
use epigraph_isomorphism::{
    compare_subgraphs, detect_patterns, skeleton_from_template_json, PatternTemplate, SkeletonEdge,
    SubgraphSkeleton,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// An edge in the request skeleton
#[derive(Debug, Deserialize)]
pub struct EdgeInput {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
}

/// Request to detect patterns in a subgraph
#[derive(Debug, Deserialize)]
pub struct DetectPatternsRequest {
    /// Edges defining the target subgraph
    pub edges: Vec<EdgeInput>,
    /// Optional: only match against templates in this category
    pub category: Option<String>,
}

/// A matched pattern in the detection result
#[derive(Debug, Serialize)]
pub struct PatternMatchResponse {
    pub template_id: Uuid,
    pub template_name: String,
    pub category: String,
    /// Whether this was an exact VF2 match (true) or fingerprint-approximate (false)
    pub exact_match: bool,
    /// Similarity score (1.0 for exact, 0.0-1.0 for approximate)
    pub similarity: f64,
}

/// Response from pattern detection
#[derive(Debug, Serialize)]
pub struct DetectPatternsResponse {
    pub matches: Vec<PatternMatchResponse>,
    /// Structural fingerprint summary
    pub fingerprint: FingerprintSummary,
}

/// Compact fingerprint summary for API responses
#[derive(Debug, Serialize)]
pub struct FingerprintSummary {
    pub node_count: usize,
    pub edge_count: usize,
    pub edge_type_histogram: std::collections::HashMap<String, usize>,
    pub avg_clustering_coefficient: f64,
    pub diameter: Option<usize>,
}

/// Request to compare two subgraphs
#[derive(Debug, Deserialize)]
pub struct CompareSubgraphsRequest {
    pub group_a_id: Uuid,
    pub edges_a: Vec<EdgeInput>,
    pub group_b_id: Uuid,
    pub edges_b: Vec<EdgeInput>,
}

/// Response from subgraph comparison
#[derive(Debug, Serialize)]
pub struct CompareSubgraphsResponse {
    pub group_a_id: Uuid,
    pub group_b_id: Uuid,
    pub similarity: f64,
    pub matching_features: Vec<String>,
}

/// A pattern template from the database
#[derive(Debug, Serialize)]
pub struct PatternTemplateResponse {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub description: Option<String>,
    pub min_confidence: f64,
    pub created_at: String,
}

// =============================================================================
// HELPERS
// =============================================================================

fn edges_to_skeleton(edges: &[EdgeInput]) -> SubgraphSkeleton {
    let skeleton_edges: Vec<SkeletonEdge> = edges
        .iter()
        .map(|e| SkeletonEdge {
            source: e.source,
            target: e.target,
            relationship: e.relationship.clone(),
        })
        .collect();
    SubgraphSkeleton::from_edges(skeleton_edges)
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Detect structural patterns in a subgraph by comparing against stored templates.
///
/// First loads templates from the database, converts their JSON skeletons to
/// `PatternTemplate` structs, then runs fingerprint pre-filtering + VF2 exact
/// matching.
pub async fn detect(
    State(state): State<AppState>,
    Json(req): Json<DetectPatternsRequest>,
) -> Result<Json<DetectPatternsResponse>, ApiError> {
    if req.edges.is_empty() {
        return Err(ApiError::BadRequest {
            message: "At least one edge is required".to_string(),
        });
    }

    let target = edges_to_skeleton(&req.edges);

    // Load templates from DB
    let template_rows = match &req.category {
        Some(cat) => PatternTemplateRepository::get_by_category(&state.db_pool, cat)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to load templates: {e}"),
            })?,
        None => PatternTemplateRepository::get_all(&state.db_pool)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to load templates: {e}"),
            })?,
    };

    // Convert DB rows to PatternTemplate structs
    let templates: Vec<PatternTemplate> = template_rows
        .iter()
        .filter_map(|row| {
            let skeleton = match skeleton_from_template_json(&row.skeleton) {
                Some(s) => s,
                None => {
                    tracing::warn!(
                        template_id = %row.id,
                        template_name = %row.name,
                        "Failed to parse template skeleton JSON — skipping"
                    );
                    return None;
                }
            };
            Some(PatternTemplate {
                id: row.id,
                name: row.name.clone(),
                category: row.category.clone(),
                description: row.description.clone().unwrap_or_default(),
                skeleton,
                min_confidence: row.min_confidence,
            })
        })
        .collect();

    // Run detection
    let result = detect_patterns(&target, &templates);

    // Build response
    let mut matches = Vec::new();

    for (template, _vf2_match) in &result.exact_matches {
        matches.push(PatternMatchResponse {
            template_id: template.id,
            template_name: template.name.clone(),
            category: template.category.clone(),
            exact_match: true,
            similarity: 1.0,
        });
    }

    // Add approximate matches that weren't already exact
    let exact_ids: std::collections::HashSet<Uuid> =
        result.exact_matches.iter().map(|(t, _)| t.id).collect();

    for (template, similarity) in &result.similar_patterns {
        if !exact_ids.contains(&template.id) {
            matches.push(PatternMatchResponse {
                template_id: template.id,
                template_name: template.name.clone(),
                category: template.category.clone(),
                exact_match: false,
                similarity: *similarity,
            });
        }
    }

    let fp = &result.fingerprint;
    let fingerprint = FingerprintSummary {
        node_count: fp.node_count,
        edge_count: fp.edge_count,
        edge_type_histogram: fp.edge_type_histogram.clone(),
        avg_clustering_coefficient: fp.avg_clustering_coefficient,
        diameter: fp.diameter,
    };

    Ok(Json(DetectPatternsResponse {
        matches,
        fingerprint,
    }))
}

/// Compare two subgraphs and produce a collaboration similarity signal.
///
/// This is a content-free structural comparison: only edge topology and
/// relationship types are compared (no claim text is revealed).
pub async fn compare(
    Json(req): Json<CompareSubgraphsRequest>,
) -> Result<Json<CompareSubgraphsResponse>, ApiError> {
    if req.edges_a.is_empty() || req.edges_b.is_empty() {
        return Err(ApiError::BadRequest {
            message: "Both subgraphs must have at least one edge".to_string(),
        });
    }

    let skeleton_a = edges_to_skeleton(&req.edges_a);
    let skeleton_b = edges_to_skeleton(&req.edges_b);

    let signal = compare_subgraphs(req.group_a_id, &skeleton_a, req.group_b_id, &skeleton_b);

    Ok(Json(CompareSubgraphsResponse {
        group_a_id: signal.group_a_id,
        group_b_id: signal.group_b_id,
        similarity: signal.similarity,
        matching_features: signal.matching_features,
    }))
}

/// List all pattern templates from the database.
pub async fn list_patterns(
    State(state): State<AppState>,
) -> Result<Json<Vec<PatternTemplateResponse>>, ApiError> {
    let rows = PatternTemplateRepository::get_all(&state.db_pool)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to load templates: {e}"),
        })?;

    let templates: Vec<PatternTemplateResponse> = rows
        .into_iter()
        .map(|row| PatternTemplateResponse {
            id: row.id,
            name: row.name,
            category: row.category,
            description: row.description,
            min_confidence: row.min_confidence,
            created_at: row.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(templates))
}
