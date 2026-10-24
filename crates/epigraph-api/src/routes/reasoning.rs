//! Reasoning analysis endpoint for the epistemic knowledge graph.
//!
//! Exposes the Ascent-based reasoning engine via `POST /api/v1/reasoning/analyze`.
//! The endpoint is **read-only** — it consumes graph data (persisted claims read
//! as the caller, plus caller-supplied or auto-loaded edges) and returns
//! analytical insights: transitive
//! support chains, contradictions, support clusters, connected components, and
//! unsupported claims.
//!
//! The endpoint performs no mutations, so it needs no request signature. It is
//! a READ, and it reads as its caller: the token must carry
//! `analysis:reasoning`, and the auto-loaded edge set is the caller's own view
//! of the graph (`EdgeRepository::claim_edges_for_reasoning`, on a
//! viewer-stamped connection). Every derived result names the endpoint claim
//! ids of the edges it came from, so the edge read must be the caller's own.

use crate::errors::ApiError;
use crate::middleware::bearer::{AuthContext, ViewerExtractor};
use crate::state::AppState;
use axum::{extract::State, Extension, Json};
use epigraph_engine::{ReasoningClaim, ReasoningEdge, ReasoningEngine};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Request body for `POST /api/v1/reasoning/analyze`.
///
/// Callers may supply edges explicitly (since the in-memory store does not
/// persist typed edges) and optionally restrict analysis to a subset of
/// claims via `claim_ids`. Parameter overrides tune engine thresholds.
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    /// Optional subset of claim IDs to include. When absent (or empty), the
    /// endpoints of the analysed edges are loaded; without the `db` feature,
    /// all claims from the in-memory store.
    pub claim_ids: Option<Vec<Uuid>>,
    /// Edges to analyze. When empty (the default), edges are auto-loaded
    /// from the database — all claim-to-claim edges whose source or target
    /// is in the analysed claim set.  Pass explicit edges to override.
    #[serde(default)]
    pub edges: Vec<EdgeInput>,
    // -- parameter overrides (reserved for future engine tuning) --
    pub min_similarity: Option<f64>,
    pub link_threshold: Option<f64>,
    pub decay_factor: Option<f64>,
    pub propagation_depth: Option<usize>,
    pub transitive_support_threshold: Option<f64>,
    pub contradiction_threshold: Option<f64>,
}

/// A single edge supplied in the analysis request.
#[derive(Debug, Clone, Deserialize)]
pub struct EdgeInput {
    pub source_id: Uuid,
    pub target_id: Uuid,
    /// Relationship type: `"supports"`, `"refutes"`, `"elaborates"`, etc.
    pub relationship: String,
    /// Edge strength in [0.0, 1.0].
    pub strength: f64,
}

/// Full analysis response returned from the reasoning engine.
#[derive(Debug, Serialize)]
pub struct AnalyzeResponse {
    pub transitive_supports: Vec<TransitiveSupportDto>,
    pub contradictions: Vec<ContradictionDto>,
    pub support_clusters: Vec<SupportClusterDto>,
    pub indirect_challenges: Vec<IndirectChallengeDto>,
    pub connected_components: Vec<ConnectedComponentDto>,
    pub unsupported_claims: Vec<String>,
    pub stats: StatsDto,
}

#[derive(Debug, Serialize)]
pub struct TransitiveSupportDto {
    pub source_id: String,
    pub target_id: String,
    pub cumulative_strength: f64,
}

#[derive(Debug, Serialize)]
pub struct ContradictionDto {
    pub claim_a_id: String,
    pub claim_b_id: String,
    pub target_id: String,
    pub support_strength: f64,
    pub refute_strength: f64,
}

#[derive(Debug, Serialize)]
pub struct SupportClusterDto {
    pub target_id: String,
    pub supporting_claim_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IndirectChallengeDto {
    pub challenger_id: String,
    pub target_id: String,
}

#[derive(Debug, Serialize)]
pub struct ConnectedComponentDto {
    pub claim_ids: Vec<String>,
    pub edge_count: usize,
    pub avg_truth: f64,
}

#[derive(Debug, Serialize)]
pub struct StatsDto {
    pub claims_loaded: usize,
    pub edges_loaded: usize,
    pub transitive_supports_found: usize,
    pub contradictions_found: usize,
    pub components: usize,
    pub unsupported_claims_found: usize,
}

// =============================================================================
// HANDLER
// =============================================================================

/// `POST /api/v1/reasoning/analyze`
///
/// Loads the claims the caller can read (the request's `claim_ids`, or the
/// endpoints of the analysed edges when it names none) with their effective
/// belief, combines them with caller-supplied or auto-loaded edges, and
/// delegates to `ReasoningEngine::analyze()` for Datalog-based graph analysis.
/// Without the `db` feature, claims come from the in-memory claim store.
///
/// Returns transitive supports, contradictions, support clusters, connected
/// components, indirect challenges, and unsupported claims.
///
/// Requires `analysis:reasoning`. Auto-loaded edges are those the caller's
/// viewer can read.
pub async fn analyze(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<Extension<AuthContext>>,
    Json(request): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, ApiError> {
    // Unconditional: a request with no AuthContext is refused here on its own
    // terms, not by whichever extractor happens to run first.
    let Some(Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["analysis:reasoning"])?;

    // Validate input bounds to prevent DoS
    const MAX_CLAIM_IDS: usize = 5_000;
    const MAX_EDGES: usize = 10_000;

    if request.edges.len() > MAX_EDGES {
        return Err(ApiError::ValidationError {
            field: "edges".to_string(),
            reason: format!("Too many edges: max {MAX_EDGES}"),
        });
    }
    if let Some(ids) = &request.claim_ids {
        if ids.len() > MAX_CLAIM_IDS {
            return Err(ApiError::ValidationError {
                field: "claim_ids".to_string(),
                reason: format!("Too many claim IDs: max {MAX_CLAIM_IDS}"),
            });
        }
    }

    // Validate edge strengths
    for (i, edge) in request.edges.iter().enumerate() {
        if !(0.0..=1.0).contains(&edge.strength) {
            return Err(ApiError::ValidationError {
                field: format!("edges[{i}].strength"),
                reason: format!(
                    "Edge strength must be between 0.0 and 1.0, got {}",
                    edge.strength
                ),
            });
        }
        if edge.relationship.trim().is_empty() {
            return Err(ApiError::ValidationError {
                field: format!("edges[{i}].relationship"),
                reason: "Relationship type cannot be empty".to_string(),
            });
        }
    }

    // Both reads below run on ONE viewer-stamped connection.
    //
    // 1. If no edges were supplied, claim-to-claim edges are auto-loaded, so
    //    callers need not pre-fetch them.
    // 2. The claims analysed are PERSISTED claims, read as the caller: the
    //    request's `claim_ids`, or, when it names none, the endpoints of the
    //    edges being analysed. Each enters with its effective belief
    //    (`ClaimRepository::effective_belief_batch`: the pignistic probability
    //    when the DS state is complete, the truth value otherwise). A claim the
    //    caller cannot read, or an id naming no `claims` row, is absent from
    //    that read and so contributes neither its id nor its score.
    //
    // The in-memory `claim_store` is written by nothing in a database build,
    // so it is read only by the non-DB arm below.
    #[cfg(feature = "db")]
    let (reasoning_claims, request_edges) = {
        let mut read = state.read_as(&viewer).await.map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_read",
                error = %e,
                handler = "reasoning_analyze",
                "could not acquire a viewer-stamped connection"
            );
            ApiError::InternalError {
                message: "Failed to acquire a scoped connection".to_string(),
            }
        })?;

        let request_edges: Vec<EdgeInput> = if request.edges.is_empty() {
            load_edges_from_db(&mut read, &viewer, &request.claim_ids).await?
        } else {
            request.edges
        };

        let claim_ids: Vec<Uuid> = match request.claim_ids.as_deref() {
            Some(ids) if !ids.is_empty() => ids.to_vec(),
            _ => request_edges
                .iter()
                .flat_map(|e| [e.source_id, e.target_id])
                .collect(),
        };
        let mut seen = std::collections::HashSet::new();
        let claim_ids: Vec<Uuid> = claim_ids
            .into_iter()
            .filter(|id| seen.insert(*id))
            .collect();

        let scores =
            epigraph_db::ClaimRepository::effective_belief_batch(&mut *read, &viewer, &claim_ids)
                .await?;
        let reasoning_claims: Vec<ReasoningClaim> = claim_ids
            .into_iter()
            .filter_map(|id| {
                scores
                    .get(&id)
                    .map(|&truth_value| ReasoningClaim { id, truth_value })
            })
            .collect();
        (reasoning_claims, request_edges)
    };

    #[cfg(not(feature = "db"))]
    let (reasoning_claims, request_edges) = {
        // No database, so no tenancy-bearing read: the viewer has nothing to
        // filter. Its extraction still enforced authentication. Claims come
        // from the in-memory store (optionally filtered by `claim_ids`).
        let _ = &viewer;
        let store = state.claim_store.read().await;
        let reasoning_claims: Vec<ReasoningClaim> = match &request.claim_ids {
            Some(ids) => ids
                .iter()
                .filter_map(|id| store.get(id))
                .map(|claim| ReasoningClaim {
                    id: claim.id.as_uuid(),
                    truth_value: claim.truth_value.value(),
                })
                .collect(),
            None => store
                .values()
                .map(|claim| ReasoningClaim {
                    id: claim.id.as_uuid(),
                    truth_value: claim.truth_value.value(),
                })
                .collect(),
        };
        drop(store);
        (reasoning_claims, request.edges)
    };

    // Convert input edges to engine types
    let reasoning_edges: Vec<ReasoningEdge> = request_edges
        .iter()
        .map(|e| ReasoningEdge {
            source_id: e.source_id,
            target_id: e.target_id,
            relationship: e.relationship.clone(),
            strength: e.strength,
        })
        .collect();

    // Delegate to the Ascent-based reasoning engine
    let result = ReasoningEngine::analyze(&reasoning_claims, &reasoning_edges);

    // Build a claim-id-to-truth lookup for connected component avg_truth
    let truth_map: std::collections::HashMap<Uuid, f64> = reasoning_claims
        .iter()
        .map(|c| (c.id, c.truth_value))
        .collect();

    // Count edges per connected component for the response
    let edge_set: std::collections::HashSet<(Uuid, Uuid)> = reasoning_edges
        .iter()
        .map(|e| (e.source_id, e.target_id))
        .collect();

    // Convert engine results to response DTOs
    let transitive_supports: Vec<TransitiveSupportDto> = result
        .transitive_supports
        .iter()
        .map(|ts| TransitiveSupportDto {
            source_id: ts.source.to_string(),
            target_id: ts.target.to_string(),
            cumulative_strength: ts.chain_strength,
        })
        .collect();

    let contradictions: Vec<ContradictionDto> = result
        .contradictions
        .iter()
        .map(|c| ContradictionDto {
            claim_a_id: c.claim_a.to_string(),
            claim_b_id: c.claim_b.to_string(),
            target_id: c.target.to_string(),
            support_strength: c.support_strength,
            refute_strength: c.refute_strength,
        })
        .collect();

    let support_clusters: Vec<SupportClusterDto> = result
        .support_clusters
        .iter()
        .map(|sc| SupportClusterDto {
            target_id: sc.target.to_string(),
            supporting_claim_ids: sc.supporters.iter().map(|id| id.to_string()).collect(),
        })
        .collect();

    let indirect_challenges: Vec<IndirectChallengeDto> = result
        .indirect_challenges
        .iter()
        .map(|ic| IndirectChallengeDto {
            challenger_id: ic.challenger.to_string(),
            target_id: ic.target.to_string(),
        })
        .collect();

    let connected_components: Vec<ConnectedComponentDto> = result
        .connected_components
        .iter()
        .map(|component| {
            let claim_ids: Vec<String> = component.iter().map(|id| id.to_string()).collect();
            let component_set: std::collections::HashSet<&Uuid> = component.iter().collect();

            // Count edges whose both endpoints are within this component
            let edge_count = edge_set
                .iter()
                .filter(|(src, tgt)| component_set.contains(src) && component_set.contains(tgt))
                .count();

            // Average truth value for claims in this component
            let (sum, count) = component.iter().fold((0.0_f64, 0_usize), |(s, c), id| {
                if let Some(&truth) = truth_map.get(id) {
                    (s + truth, c + 1)
                } else {
                    (s, c)
                }
            });
            let avg_truth = if count > 0 { sum / count as f64 } else { 0.0 };

            ConnectedComponentDto {
                claim_ids,
                edge_count,
                avg_truth,
            }
        })
        .collect();

    let unsupported_claims: Vec<String> = result
        .unsupported_claims
        .iter()
        .map(|id| id.to_string())
        .collect();

    let stats = StatsDto {
        claims_loaded: result.stats.claims_loaded,
        edges_loaded: result.stats.edges_loaded,
        transitive_supports_found: result.stats.transitive_supports_found,
        contradictions_found: result.stats.contradictions_found,
        components: result.stats.components,
        unsupported_claims_found: result.stats.unsupported_claims_found,
    };

    Ok(Json(AnalyzeResponse {
        transitive_supports,
        contradictions,
        support_clusters,
        indirect_challenges,
        connected_components,
        unsupported_claims,
        stats,
    }))
}

// =============================================================================
// DB EDGE LOADER
// =============================================================================

/// Load the claim-to-claim edges `viewer` can read.
///
/// When `claim_ids` is a non-empty `Some`, only edges whose source **and**
/// target are in that set are returned. Otherwise every readable
/// claim-to-claim edge, capped at 10 000 rows to prevent OOM on large graphs.
///
/// `conn` is the caller's viewer-stamped connection (`AppState::read_as`) and
/// the statement carries the edge-visibility predicate, so the row-level
/// policies and the in-query predicate agree about which edges the caller may
/// see.
///
/// The edge `strength` field is stored inside the `properties` JSONB column
/// (key `"strength"`).  If absent or non-numeric the edge defaults to 0.5.
#[cfg(feature = "db")]
async fn load_edges_from_db(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::Viewer,
    claim_ids: &Option<Vec<Uuid>>,
) -> Result<Vec<EdgeInput>, ApiError> {
    /// Row cap on the unscoped arm.
    const UNSCOPED_EDGE_CAP: i64 = 10_000;

    // A present-but-empty `claim_ids` takes the unscoped arm, as it always has.
    let among = claim_ids.as_deref().filter(|ids| !ids.is_empty());
    let limit = if among.is_some() {
        None
    } else {
        Some(UNSCOPED_EDGE_CAP)
    };

    let rows =
        epigraph_db::EdgeRepository::claim_edges_for_reasoning(&mut *conn, viewer, among, limit)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: format!("Failed to load edges for reasoning: {e}"),
            })?;

    Ok(rows
        .into_iter()
        .map(|(source_id, target_id, relationship, properties)| {
            let strength = properties
                .get("strength")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5);
            EdgeInput {
                source_id,
                target_id,
                relationship,
                strength,
            }
        })
        .collect())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(all(test, not(feature = "db")))]
mod tests {
    use super::*;
    use crate::state::{ApiConfig, AppState};
    use axum::extract::State;
    use axum::Json;
    use epigraph_core::{AgentId, Claim, ClaimId, TraceId, TruthValue};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// Helper: an `AuthContext` holding `scopes`, for a direct handler call.
    fn auth_with(scopes: &[&str]) -> AuthContext {
        let principal = uuid::Uuid::new_v4();
        AuthContext {
            client_id: principal,
            agent_id: Some(principal),
            owner_id: Some(principal),
            client_type: crate::middleware::ClientType::Service,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: uuid::Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        }
    }

    /// Helper: call the handler as an authenticated caller holding
    /// `analysis:reasoning`.
    async fn run(
        state: AppState,
        request: AnalyzeRequest,
    ) -> Result<Json<AnalyzeResponse>, ApiError> {
        analyze(
            ViewerExtractor(crate::middleware::bearer::NoDbViewer),
            State(state),
            Some(Extension(auth_with(&["analysis:reasoning"]))),
            Json(request),
        )
        .await
    }

    /// Helper: build an AppState with the given claims pre-loaded.
    fn state_with_claims(claims: Vec<Claim>) -> AppState {
        let mut store = HashMap::new();
        for claim in claims {
            store.insert(claim.id.as_uuid(), claim);
        }
        let mut state = AppState::new(ApiConfig::default());
        state.claim_store = Arc::new(RwLock::new(store));
        state
    }

    /// Helper: build a minimal claim with the given numeric ID and truth.
    fn make_claim(n: u128, truth: f64) -> Claim {
        let claim_id = ClaimId::from_uuid(uuid::Uuid::from_u128(n));
        let now = chrono::Utc::now();
        Claim::with_id(
            claim_id,
            format!("Claim {n}"),
            AgentId::new(),
            [0u8; 32],
            [0u8; 32],
            Some(TraceId::new()),
            None,
            TruthValue::new(truth).unwrap(),
            now,
            now,
        )
    }

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn edge(src: u128, tgt: u128, rel: &str, strength: f64) -> EdgeInput {
        EdgeInput {
            source_id: id(src),
            target_id: id(tgt),
            relationship: rel.to_string(),
            strength,
        }
    }

    // -- 1. Empty graph returns empty results --

    #[tokio::test]
    async fn test_empty_graph_returns_empty_results() {
        let state = state_with_claims(vec![]);
        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await.unwrap();
        let resp = result.0;

        assert!(resp.transitive_supports.is_empty());
        assert!(resp.contradictions.is_empty());
        assert!(resp.support_clusters.is_empty());
        assert!(resp.indirect_challenges.is_empty());
        assert!(resp.connected_components.is_empty());
        assert!(resp.unsupported_claims.is_empty());
        assert_eq!(resp.stats.claims_loaded, 0);
        assert_eq!(resp.stats.edges_loaded, 0);
    }

    // -- 2. Single support edge returns one transitive support --

    #[tokio::test]
    async fn test_single_support_edge() {
        let state = state_with_claims(vec![make_claim(1, 0.8), make_claim(2, 0.7)]);
        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![edge(1, 2, "supports", 0.9)],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await.unwrap();
        let resp = result.0;

        assert_eq!(
            resp.transitive_supports.len(),
            1,
            "Single support edge should produce one transitive support"
        );
        assert_eq!(resp.transitive_supports[0].source_id, id(1).to_string());
        assert_eq!(resp.transitive_supports[0].target_id, id(2).to_string());
        assert!(
            (resp.transitive_supports[0].cumulative_strength - 0.9).abs() < 1e-10,
            "Direct edge strength should be preserved"
        );
    }

    // -- 3. Opposing edges (support + refute) create a contradiction --

    #[tokio::test]
    async fn test_opposing_edges_create_contradiction() {
        let state = state_with_claims(vec![
            make_claim(1, 0.8),
            make_claim(2, 0.7),
            make_claim(3, 0.5),
        ]);
        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![edge(1, 3, "supports", 0.8), edge(2, 3, "refutes", 0.7)],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await.unwrap();
        let resp = result.0;

        assert_eq!(
            resp.contradictions.len(),
            1,
            "Support + refute to same target should produce exactly one contradiction"
        );
        assert_eq!(resp.contradictions[0].target_id, id(3).to_string());
    }

    // -- 4. Connected components are correctly identified --

    #[tokio::test]
    async fn test_connected_components() {
        // Two separate clusters: {1, 2} and {3, 4} with claim 5 isolated
        let state = state_with_claims(vec![
            make_claim(1, 0.8),
            make_claim(2, 0.7),
            make_claim(3, 0.6),
            make_claim(4, 0.5),
            make_claim(5, 0.9),
        ]);
        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![edge(1, 2, "supports", 0.8), edge(3, 4, "supports", 0.7)],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await.unwrap();
        let resp = result.0;

        assert_eq!(
            resp.connected_components.len(),
            3,
            "Expected 3 components: {{1,2}}, {{3,4}}, {{5}}"
        );

        let sizes: std::collections::HashSet<usize> = resp
            .connected_components
            .iter()
            .map(|c| c.claim_ids.len())
            .collect();
        assert!(sizes.contains(&2), "Expected two 2-node components");
        assert!(sizes.contains(&1), "Expected one 1-node component");
    }

    // -- 5. Unsupported claims are detected --

    #[tokio::test]
    async fn test_unsupported_claims_detected() {
        // Claim 1 supports claim 2; claims 1 and 3 have no incoming support
        let state = state_with_claims(vec![
            make_claim(1, 0.8),
            make_claim(2, 0.7),
            make_claim(3, 0.6),
        ]);
        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![edge(1, 2, "supports", 0.8)],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await.unwrap();
        let resp = result.0;

        // Claims 1 and 3 have no incoming support edges
        assert!(
            resp.unsupported_claims.contains(&id(1).to_string()),
            "Claim 1 has no incoming support and should be unsupported"
        );
        assert!(
            resp.unsupported_claims.contains(&id(3).to_string()),
            "Claim 3 has no incoming support and should be unsupported"
        );
        assert!(
            !resp.unsupported_claims.contains(&id(2).to_string()),
            "Claim 2 is supported by claim 1 and should NOT be unsupported"
        );
    }

    // -- 6. Validation rejects out-of-bounds edge strength --

    #[tokio::test]
    async fn test_rejects_invalid_edge_strength() {
        let state = state_with_claims(vec![make_claim(1, 0.8), make_claim(2, 0.7)]);
        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![edge(1, 2, "supports", 1.5)],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await;
        assert!(result.is_err(), "Should reject edge strength > 1.0");
    }

    // -- 7. Validation rejects empty relationship --

    #[tokio::test]
    async fn test_rejects_empty_relationship() {
        let state = state_with_claims(vec![make_claim(1, 0.8), make_claim(2, 0.7)]);
        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![edge(1, 2, "", 0.8)],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await;
        assert!(result.is_err(), "Should reject empty relationship");
    }

    // -- 8. Transitive chain produces correct cumulative strength --

    #[tokio::test]
    async fn test_transitive_chain_cumulative_strength() {
        let state = state_with_claims(vec![
            make_claim(1, 0.8),
            make_claim(2, 0.7),
            make_claim(3, 0.6),
        ]);
        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![edge(1, 2, "supports", 0.9), edge(2, 3, "supports", 0.8)],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await.unwrap();
        let resp = result.0;

        // Find the transitive support from claim 1 to claim 3
        let chain = resp
            .transitive_supports
            .iter()
            .find(|ts| ts.source_id == id(1).to_string() && ts.target_id == id(3).to_string());

        assert!(chain.is_some(), "Expected transitive support from 1 to 3");
        let expected = 0.9 * 0.8;
        assert!(
            (chain.unwrap().cumulative_strength - expected).abs() < 1e-10,
            "Expected cumulative strength {expected}, got {}",
            chain.unwrap().cumulative_strength
        );
    }

    // -- 9. claim_ids filter limits which claims are loaded --

    #[tokio::test]
    async fn test_claim_ids_filter() {
        let state = state_with_claims(vec![
            make_claim(1, 0.8),
            make_claim(2, 0.7),
            make_claim(3, 0.6),
        ]);
        // Only load claims 1 and 2
        let request = AnalyzeRequest {
            claim_ids: Some(vec![id(1), id(2)]),
            edges: vec![edge(1, 2, "supports", 0.8)],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await.unwrap();
        let resp = result.0;

        assert_eq!(resp.stats.claims_loaded, 2, "Should only load 2 claims");
        // Claim 3 is not loaded, so it should not appear as unsupported
        assert!(
            !resp.unsupported_claims.contains(&id(3).to_string()),
            "Claim 3 was not loaded and should not appear in results"
        );
    }

    // -- 10. Support cluster detection --

    #[tokio::test]
    async fn test_support_clusters() {
        let state = state_with_claims(vec![
            make_claim(1, 0.8),
            make_claim(2, 0.7),
            make_claim(3, 0.6),
        ]);
        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![edge(1, 3, "supports", 0.8), edge(2, 3, "supports", 0.7)],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await.unwrap();
        let resp = result.0;

        assert_eq!(
            resp.support_clusters.len(),
            1,
            "Two claims supporting the same target should form one cluster"
        );
        assert_eq!(resp.support_clusters[0].target_id, id(3).to_string());
        assert!(resp.support_clusters[0]
            .supporting_claim_ids
            .contains(&id(1).to_string()));
        assert!(resp.support_clusters[0]
            .supporting_claim_ids
            .contains(&id(2).to_string()));
    }

    // -- 11. Connected component avg_truth is correct --

    #[tokio::test]
    async fn test_connected_component_avg_truth() {
        let state = state_with_claims(vec![make_claim(1, 0.8), make_claim(2, 0.6)]);
        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![edge(1, 2, "supports", 0.9)],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, request).await.unwrap();
        let resp = result.0;

        assert_eq!(resp.connected_components.len(), 1);
        let expected_avg = (0.8 + 0.6) / 2.0;
        assert!(
            (resp.connected_components[0].avg_truth - expected_avg).abs() < 1e-10,
            "Expected avg_truth {expected_avg}, got {}",
            resp.connected_components[0].avg_truth
        );
    }
}

// =============================================================================
// DB INTEGRATION TESTS
// =============================================================================
//
// These tests require a live PostgreSQL database reachable via DATABASE_URL.
// They are compiled and run only when the `db` feature is enabled:
//
//   cargo test -p epigraph-api --features db --test '*' -- reasoning
//
// The test inserts minimal rows directly (bypassing the API write path) to
// keep setup simple and to isolate the reasoning endpoint from unrelated
// code.

#[cfg(all(test, feature = "db"))]
mod db_tests {
    use super::*;
    use crate::state::{ApiConfig, AppState};
    use axum::extract::State;
    use axum::Json;
    use epigraph_db::PgPool;
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;

    /// Connect to the test database using DATABASE_URL, or return `None` to skip.
    ///
    /// Tests call `test_pool_or_skip!()` at their start so they become
    /// no-ops (passing) when no database is available.
    async fn try_test_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .ok()?;
        // Run migrations so all tables exist before tests touch the DB.
        sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    /// Skip the enclosing test when DATABASE_URL is unset or unreachable.
    macro_rules! test_pool_or_skip {
        () => {{
            match try_test_pool().await {
                Some(p) => p,
                None => {
                    eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                    return;
                }
            }
        }};
    }

    /// An `AppState` over a viewer-stamping `ScopedPool` on the test database,
    /// which `AppState::read_as` requires.
    async fn scoped_state() -> AppState {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL is set when a pool exists");
        let scoped = epigraph_db::ScopedPool::connect_with_options(
            &url,
            epigraph_db::SessionGucMode::Session,
            epigraph_db::ScopedPoolOptions {
                max_connections: 2,
                ..Default::default()
            },
        )
        .await
        .expect("connect scoped pool");
        AppState::with_scoped_pool(scoped, ApiConfig::default())
    }

    /// Call the handler as the public viewer (the nil principal, no groups)
    /// with `analysis:reasoning`. The fixtures below write no tenancy columns,
    /// so their claims and edges are public and this viewer reads them.
    async fn run(
        state: AppState,
        pool: &PgPool,
        request: AnalyzeRequest,
    ) -> Result<Json<AnalyzeResponse>, ApiError> {
        let viewer = epigraph_db::Viewer::resolve(pool, Uuid::nil())
            .await
            .expect("resolve the public viewer");
        let principal = Uuid::new_v4();
        let auth = AuthContext {
            client_id: principal,
            agent_id: Some(principal),
            owner_id: Some(principal),
            client_type: crate::middleware::ClientType::Service,
            scopes: vec!["analysis:reasoning".to_string()],
            jti: Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        };
        analyze(
            ViewerExtractor(viewer),
            State(state),
            Some(Extension(auth)),
            Json(request),
        )
        .await
    }

    /// Insert a minimal claim row directly into the DB for test setup.
    /// Returns the inserted UUID.
    async fn insert_claim(pool: &PgPool, id: Uuid, truth: f64) -> Uuid {
        // We need a minimal agent row first to satisfy the FK.
        // Use an upsert so repeated test runs don't fail on duplicate key.
        sqlx::query(
            r#"
            INSERT INTO agents (id, public_key, created_at, updated_at)
            VALUES ($1, sha256($1::text::bytea), NOW(), NOW())
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(id) // reuse claim id as agent id for simplicity
        .execute(pool)
        .await
        .expect("Failed to upsert test agent");

        sqlx::query(
            r#"
            INSERT INTO claims (id, content, agent_id, content_hash, truth_value, created_at, updated_at)
            VALUES ($1, $2, $3, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
                    $4, NOW(), NOW())
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(id)
        .bind(format!("test claim {id}"))
        .bind(id) // agent_id = same UUID
        .bind(truth)
        .execute(pool)
        .await
        .expect("Failed to insert test claim");

        id
    }

    /// Insert a minimal edge row for test setup.
    async fn insert_edge(pool: &PgPool, src: Uuid, tgt: Uuid, rel: &str, strength: f64) {
        sqlx::query(
            r#"
            INSERT INTO edges (source_id, target_id, source_type, target_type, relationship, properties)
            VALUES ($1, $2, 'claim', 'claim', $3, $4)
            "#,
        )
        .bind(src)
        .bind(tgt)
        .bind(rel)
        .bind(json!({ "strength": strength }))
        .execute(pool)
        .await
        .expect("Failed to insert test edge");
    }

    /// Clean up test rows inserted by a specific test (best-effort).
    async fn cleanup(pool: &PgPool, ids: &[Uuid]) {
        let _ = sqlx::query("DELETE FROM edges WHERE source_id = ANY($1) OR target_id = ANY($1)")
            .bind(ids)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM claims WHERE id = ANY($1)")
            .bind(ids)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE id = ANY($1)")
            .bind(ids)
            .execute(pool)
            .await;
    }

    // -- DB-1. Auto-load edges when request.edges is empty --
    //
    // Creates two claims + one support edge in the DB, calls analyze with an
    // empty edges vec, and asserts the engine found the transitive support.

    #[tokio::test]
    async fn test_db_auto_loads_edges_when_empty() {
        let pool = test_pool_or_skip!();

        // Use deterministic UUIDs so cleanup is reliable.
        let src_id = Uuid::from_u128(0xDEAD_BEEF_0000_0001_0000_0000_0000_0001);
        let tgt_id = Uuid::from_u128(0xDEAD_BEEF_0000_0001_0000_0000_0000_0002);

        insert_claim(&pool, src_id, 0.8).await;
        insert_claim(&pool, tgt_id, 0.7).await;
        insert_edge(&pool, src_id, tgt_id, "supports", 0.9).await;

        // Build AppState with a viewer-stamping pool on the real DB.
        let state = scoped_state().await;

        let request = AnalyzeRequest {
            claim_ids: Some(vec![src_id, tgt_id]),
            edges: vec![], // <-- intentionally empty; should be auto-loaded
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, &pool, request).await;
        cleanup(&pool, &[src_id, tgt_id]).await;

        let resp = result.expect("analyze should succeed").0;

        assert_eq!(
            resp.stats.edges_loaded, 1,
            "Engine should report 1 edge loaded from DB"
        );
        assert!(
            !resp.transitive_supports.is_empty(),
            "Auto-loaded support edge should produce at least one transitive support"
        );
        let ts = resp
            .transitive_supports
            .iter()
            .find(|ts| ts.source_id == src_id.to_string() && ts.target_id == tgt_id.to_string())
            .expect("Expected transitive support from src to tgt");
        assert!(
            (ts.cumulative_strength - 0.9).abs() < 1e-6,
            "Direct edge strength should be preserved; got {}",
            ts.cumulative_strength
        );
    }

    // -- DB-2. Explicit edges override DB auto-load --
    //
    // Even with a DB edge present, explicit request.edges takes precedence.
    // The engine should see only the explicitly supplied edge, not the DB one.

    #[tokio::test]
    async fn test_db_explicit_edges_skip_db_load() {
        let pool = test_pool_or_skip!();

        let src_id = Uuid::from_u128(0xDEAD_BEEF_0000_0002_0000_0000_0000_0001);
        let tgt_id = Uuid::from_u128(0xDEAD_BEEF_0000_0002_0000_0000_0000_0002);
        let other_id = Uuid::from_u128(0xDEAD_BEEF_0000_0002_0000_0000_0000_0003);

        insert_claim(&pool, src_id, 0.8).await;
        insert_claim(&pool, tgt_id, 0.7).await;
        insert_claim(&pool, other_id, 0.6).await;
        // DB has src → other, but caller will supply src → tgt explicitly.
        insert_edge(&pool, src_id, other_id, "supports", 0.9).await;

        let state = scoped_state().await;

        let request = AnalyzeRequest {
            claim_ids: None,
            edges: vec![EdgeInput {
                source_id: src_id,
                target_id: tgt_id,
                relationship: "supports".to_string(),
                strength: 0.5,
            }],
            min_similarity: None,
            link_threshold: None,
            decay_factor: None,
            propagation_depth: None,
            transitive_support_threshold: None,
            contradiction_threshold: None,
        };

        let result = run(state, &pool, request).await;
        cleanup(&pool, &[src_id, tgt_id, other_id]).await;

        let resp = result.expect("analyze should succeed").0;

        // Only one edge was passed explicitly; DB edge should not be loaded.
        assert_eq!(
            resp.stats.edges_loaded, 1,
            "Only the explicit edge should be used"
        );
        let ts = resp
            .transitive_supports
            .iter()
            .find(|ts| ts.source_id == src_id.to_string() && ts.target_id == tgt_id.to_string());
        assert!(
            ts.is_some(),
            "Explicit edge should produce transitive support"
        );
        // Verify the DB edge (src→other) was NOT loaded by checking other_id is not a target.
        let other_ts = resp
            .transitive_supports
            .iter()
            .find(|ts| ts.target_id == other_id.to_string());
        assert!(
            other_ts.is_none(),
            "DB edge src→other should not appear when explicit edges are provided"
        );
    }
}
