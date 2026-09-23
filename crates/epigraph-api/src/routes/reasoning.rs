//! Reasoning analysis endpoint for the epistemic knowledge graph.
//!
//! Exposes the Ascent-based reasoning engine via `POST /api/v1/reasoning/analyze`.
//! The endpoint is **read-only** — it consumes graph data (claims from the in-memory
//! store plus caller-supplied edges) and returns analytical insights: transitive
//! support chains, contradictions, support clusters, connected components, and
//! unsupported claims.
//!
//! The endpoint needs no request signature, because it performs no mutations.
//! It does need a bearer token: it sits on the authenticated router and takes a
//! `ViewerExtractor`.
//!
//! # Tenancy (`F-FAH-A1`)
//!
//! When the caller sends no edges, the handler loads them from the database
//! through [`EdgeRepository::claim_edges_for_reasoning`], on ONE
//! [`AppState::read_as`] connection stamped with the caller's `Viewer`. That
//! read returns only edges in force that the caller may read, between claims
//! the caller may read. Before deferred-commitment screen key
//! `f-fah-a1-reasoning-analyze`, the load ran two inline statements here, on the
//! raw pool, with no viewer predicate. With no `claim_ids` it scanned every
//! tenant's claim-to-claim edges. See [`load_edges_from_db`].
//!
//! [`EdgeRepository::claim_edges_for_reasoning`]: epigraph_db::EdgeRepository::claim_edges_for_reasoning

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::state::AppState;
use axum::{extract::State, Json};
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
    /// Optional subset of claim IDs to include. When absent, all claims
    /// from the in-memory store are loaded.
    pub claim_ids: Option<Vec<Uuid>>,
    /// Edges to analyze. When empty (the default), edges are auto-loaded
    /// from the database: the claim-to-claim edges in force that the caller
    /// may read, between claims the caller may read. With `claim_ids`, both
    /// endpoints must be in that set; without it, every such edge up to a
    /// 10 000-row cap. Pass explicit edges to override.
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
/// Loads claims from the in-memory claim store (optionally filtered by
/// `claim_ids`), combines them with caller-supplied edges, and delegates
/// to `ReasoningEngine::analyze()` for Datalog-based graph analysis.
///
/// Returns transitive supports, contradictions, support clusters, connected
/// components, indirect challenges, and unsupported claims.
///
/// # Tenancy (`F-FAH-A1`)
///
/// When `edges` is empty, they are read on ONE [`AppState::read_as`]
/// connection, filtered by the caller's `Viewer`; see [`load_edges_from_db`].
///
/// Before this, that read ran on the raw pool with no viewer. There were two
/// failure postures:
///
/// * On an RLS-forced application role, the unstamped read saw only public
///   edges. The caller's own group-private edges were silently left out, and
///   the analysis came back as a 200 with the wrong answer.
/// * On a pool that bypasses RLS, nothing filtered the edges. Other tenants'
///   private edges reached the engine and came back in the response: claim
///   ids, relationships and strengths.
///
/// In both postures, retracted edges were analysed as live.
///
/// A state built without a `ScopedPool` gets a fixed 500 when it sends no
/// edges, because `read_as` refuses it. So does a `Bypass` viewer, which
/// `read_as` also refuses; `ViewerExtractor` only ever resolves a scoped
/// viewer, so no HTTP caller reaches that arm. Both refusals are deliberate:
/// there is no fallback to the raw pool.
pub async fn analyze(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Json(request): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, ApiError> {
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

    // Load claims from the in-memory store
    let store = state.claim_store.read().await;
    let reasoning_claims: Vec<ReasoningClaim> = match &request.claim_ids {
        Some(ids) => {
            let mut claims = Vec::with_capacity(ids.len());
            for id in ids {
                if let Some(claim) = store.get(id) {
                    claims.push(ReasoningClaim {
                        id: claim.id.as_uuid(),
                        truth_value: claim.truth_value.value(),
                    });
                }
                // Silently skip missing IDs — partial analysis is acceptable
            }
            claims
        }
        None => store
            .values()
            .map(|claim| ReasoningClaim {
                id: claim.id.as_uuid(),
                truth_value: claim.truth_value.value(),
            })
            .collect(),
    };
    // Release the read lock before doing computation
    drop(store);

    // If no edges were supplied, auto-load claim-to-claim edges from the DB.
    //
    // Rationale: callers should not have to pre-fetch edges to get useful
    // results from the reasoning engine.  The fallback is behind `#[cfg(feature = "db")]`
    // so the non-DB build path is unaffected.
    #[cfg(feature = "db")]
    let request_edges: Vec<EdgeInput> = if request.edges.is_empty() {
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
        let edges = load_edges_from_db(&mut read, &viewer, request.claim_ids.as_deref()).await?;
        crate::routes::finish_scoped_read(read, "reasoning_analyze").await?;
        edges
    } else {
        request.edges
    };

    // The no-db `ViewerExtractor` carries no authority; it is taken only so
    // both builds refuse an unauthenticated request identically.
    #[cfg(not(feature = "db"))]
    let request_edges: Vec<EdgeInput> = {
        let _ = viewer;
        request.edges
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

/// The most edges the database auto-load hands the engine. It matches the
/// `MAX_EDGES` bound on caller-supplied edges, so the engine never sees more
/// than 10 000 edges from either source.
#[cfg(feature = "db")]
const MAX_DB_EDGES: i64 = 10_000;

/// Load the claim-to-claim edges `viewer` may analyse, on the handler's
/// stamped connection.
///
/// When `claim_ids` is a non-empty set, only edges whose source AND target are
/// both in it are returned. Otherwise every such edge is returned, up to
/// [`MAX_DB_EDGES`]. Either way the read is
/// `EdgeRepository::claim_edges_for_reasoning`: edges in force that `viewer`
/// may read, between claims `viewer` may read. That function's doc gives the
/// predicates. This helper runs no SQL of its own.
///
/// It replaces two inline statements that ran here on `state.db_pool` with no
/// viewer predicate and no retraction filter (`F-FAH-A1`). Its doc used to say
/// "source **or** target" while its SQL required both. The SQL was right, and
/// the doc now says what the SQL does.
///
/// The edge `strength` is stored in the `properties` JSONB column under the key
/// `"strength"`. If it is absent or non-numeric, the edge defaults to 0.5.
///
/// A failed read is a 500 with a fixed message. The database error goes to the
/// operator's log and never into the response body.
#[cfg(feature = "db")]
async fn load_edges_from_db(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::Viewer,
    claim_ids: Option<&[Uuid]>,
) -> Result<Vec<EdgeInput>, ApiError> {
    let among = claim_ids.filter(|ids| !ids.is_empty());
    let rows =
        epigraph_db::EdgeRepository::claim_edges_for_reasoning(conn, viewer, among, MAX_DB_EDGES)
            .await
            .map_err(|e| {
                tracing::error!(
                    target: "tenancy.scoped_read",
                    error = %e,
                    handler = "reasoning_analyze",
                    statement = "claim_edges_for_reasoning",
                    "could not load edges for reasoning"
                );
                ApiError::InternalError {
                    message: "Failed to load edges for reasoning".to_string(),
                }
            })?;

    Ok(rows
        .into_iter()
        .map(|(source_id, target_id, relationship, properties)| {
            let strength = properties
                .get("strength")
                .and_then(serde_json::Value::as_f64)
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
    use crate::middleware::bearer::NoDbViewer;
    use crate::state::{ApiConfig, AppState};
    use axum::extract::State;
    use axum::Json;
    use epigraph_core::{AgentId, Claim, ClaimId, TraceId, TruthValue};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request))
            .await
            .unwrap();
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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request))
            .await
            .unwrap();
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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request))
            .await
            .unwrap();
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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request))
            .await
            .unwrap();
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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request))
            .await
            .unwrap();
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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request)).await;
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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request)).await;
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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request))
            .await
            .unwrap();
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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request))
            .await
            .unwrap();
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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request))
            .await
            .unwrap();
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

        let result = analyze(ViewerExtractor(NoDbViewer), State(state), Json(request))
            .await
            .unwrap();
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

// The database-backed tests live in `crates/epigraph-api/tests/reasoning_scoped_read.rs`.
// They moved out of this file when the edge load was converted onto the
// caller's `Viewer` (`F-FAH-A1`). The old in-module copies connected to
// `DATABASE_URL` directly, seeded rows with no tenancy, and read through an
// `AppState` with no `ScopedPool`, which the converted handler refuses.
