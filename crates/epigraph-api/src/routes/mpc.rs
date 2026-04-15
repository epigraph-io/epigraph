//! Multi-party computation endpoints for privacy-preserving similarity search
//!
//! Protected (POST):
//! - `POST /api/v1/mpc/joint-recall` — MPC cosine similarity across consenting groups

use crate::errors::ApiError;
use axum::Json;
use epigraph_privacy::mpc::{split_embedding, SecureComputation, SimulatedMpc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// A single embedding contributed by a group for the joint recall
#[derive(Debug, Deserialize)]
pub struct GroupEmbedding {
    pub group_id: Uuid,
    /// The embedding vector (f32 values)
    pub embedding: Vec<f32>,
}

/// Request for MPC joint recall: compute similarity across groups
/// without revealing raw embeddings.
#[derive(Debug, Deserialize)]
pub struct JointRecallRequest {
    /// The query embedding to compare against
    pub query: GroupEmbedding,
    /// Candidate embeddings from consenting groups
    pub candidates: Vec<GroupEmbedding>,
    /// Number of secret-sharing parties (default: 3)
    #[serde(default = "default_num_parties")]
    pub num_parties: u8,
    /// Threshold for reconstruction (default: 2)
    #[serde(default = "default_threshold")]
    pub threshold: u8,
    /// Minimum similarity to include in results (default: 0.0)
    #[serde(default)]
    pub min_similarity: f32,
}

fn default_num_parties() -> u8 {
    3
}

fn default_threshold() -> u8 {
    2
}

/// A similarity result from the joint recall
#[derive(Debug, Serialize)]
pub struct SimilarityResult {
    pub group_id: Uuid,
    pub similarity: f32,
}

/// Response from the MPC joint recall
#[derive(Debug, Serialize)]
pub struct JointRecallResponse {
    /// Results sorted by similarity (descending)
    pub results: Vec<SimilarityResult>,
    /// Number of candidates that were compared
    pub candidates_compared: usize,
    /// Protocol used (always "simulated" for now)
    pub protocol: String,
}

// =============================================================================
// HANDLERS
// =============================================================================

/// Compute privacy-preserving cosine similarity between a query embedding
/// and candidate embeddings from consenting groups.
///
/// Each embedding is secret-shared using Shamir's scheme, then similarity
/// is computed over shares using the SimulatedMpc backend. The raw embeddings
/// are never transmitted or stored — only shares are used in the computation.
///
/// **Note:** The current implementation uses a simulated MPC backend that
/// reconstructs locally. This provides the correct API surface and will be
/// replaced with a real SPDZ protocol when needed.
pub async fn joint_recall(
    Json(req): Json<JointRecallRequest>,
) -> Result<Json<JointRecallResponse>, ApiError> {
    // Validate parameters
    const MAX_DIMENSIONS: usize = 4096;
    const MAX_CANDIDATES: usize = 200;

    if req.query.embedding.is_empty() {
        return Err(ApiError::BadRequest {
            message: "Query embedding cannot be empty".to_string(),
        });
    }

    if req.query.embedding.len() > MAX_DIMENSIONS {
        return Err(ApiError::BadRequest {
            message: format!(
                "Query embedding dimension {} exceeds maximum of {MAX_DIMENSIONS}",
                req.query.embedding.len()
            ),
        });
    }

    if req.candidates.is_empty() {
        return Err(ApiError::BadRequest {
            message: "At least one candidate is required".to_string(),
        });
    }

    if req.candidates.len() > MAX_CANDIDATES {
        return Err(ApiError::BadRequest {
            message: format!(
                "Candidate count {} exceeds maximum of {MAX_CANDIDATES}",
                req.candidates.len()
            ),
        });
    }

    if req.threshold == 0 || req.num_parties == 0 {
        return Err(ApiError::BadRequest {
            message: "num_parties and threshold must be >= 1".to_string(),
        });
    }

    if req.threshold > req.num_parties {
        return Err(ApiError::BadRequest {
            message: format!(
                "threshold ({}) must be <= num_parties ({})",
                req.threshold, req.num_parties
            ),
        });
    }

    let query_dim = req.query.embedding.len();

    // Split the query embedding into shares
    let query_shares = split_embedding(&req.query.embedding, req.num_parties, req.threshold)
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to split query embedding: {e}"),
        })?;

    let mpc = SimulatedMpc;
    let mut results = Vec::new();

    for candidate in &req.candidates {
        if candidate.embedding.len() != query_dim {
            tracing::warn!(
                group_id = %candidate.group_id,
                expected = query_dim,
                got = candidate.embedding.len(),
                "Skipping candidate with dimension mismatch"
            );
            continue;
        }

        // Split candidate embedding into shares
        let candidate_shares =
            split_embedding(&candidate.embedding, req.num_parties, req.threshold).map_err(|e| {
                ApiError::InternalError {
                    message: format!(
                        "Failed to split candidate embedding for group {}: {e}",
                        candidate.group_id
                    ),
                }
            })?;

        // Compute similarity over shares (using threshold subset)
        let threshold = req.threshold as usize;
        match mpc.cosine_similarity(&query_shares[..threshold], &candidate_shares[..threshold]) {
            Ok(similarity) => {
                if similarity >= req.min_similarity {
                    results.push(SimilarityResult {
                        group_id: candidate.group_id,
                        similarity,
                    });
                }
            }
            Err(e) => {
                tracing::warn!(
                    group_id = %candidate.group_id,
                    error = %e,
                    "Skipping candidate due to similarity computation error"
                );
            }
        }
    }

    // Sort by similarity descending
    results.sort_by(|a, b| {
        b.similarity
            .partial_cmp(&a.similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let candidates_compared = results.len();

    Ok(Json(JointRecallResponse {
        results,
        candidates_compared,
        protocol: "simulated".to_string(),
    }))
}
