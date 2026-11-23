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

use crate::middleware::bearer::ViewerExtractor;
use crate::{errors::ApiError, state::AppState};

// ============================================================================
// Lineage Traversal Constants
// ============================================================================

/// Default maximum depth for lineage traversal when not specified.
const DEFAULT_LINEAGE_DEPTH: u32 = 10;

/// Maximum depth allowed for lineage traversal to prevent resource exhaustion.
/// Traversing deeper than this could cause performance issues or timeouts.
const MAX_LINEAGE_DEPTH: u32 = 100;

/// The default must fit inside the cap, otherwise the `.min(MAX_LINEAGE_DEPTH)`
/// in `get_lineage` would silently truncate a request that specified nothing.
/// Enforced at compile time so a bad edit cannot reach a test run.
const _: () = assert!(DEFAULT_LINEAGE_DEPTH <= MAX_LINEAGE_DEPTH);

/// Default cap on the number of claims (`nodes`) one response carries.
///
/// `max_depth` bounds how FAR the walk goes, not how WIDE: a claim with many
/// parents or children per layer returns a lineage whose size, and the cost of
/// serialising it on one pooled connection, grows with that fan-out at any
/// depth (backlog 04007084). A response cut by this cap says so exactly
/// (`truncated`, `nodes_omitted`), so the cap never hides part of the lineage
/// silently.
const DEFAULT_LINEAGE_NODES: u32 = 500;

/// Server-side ceiling on a caller-supplied `max_nodes`.
const MAX_LINEAGE_NODES: u32 = 2000;

/// Same compile-time guard as the depth pair: a request that names no cap
/// must not be cut by the ceiling.
const _: () = assert!(DEFAULT_LINEAGE_NODES <= MAX_LINEAGE_NODES);

/// The effective node cap for a request: the default when none is given,
/// clamped to `1..=MAX_LINEAGE_NODES`. Never zero: the root is always served,
/// and a zero cap would reach the walk helpers' empty-walk branch, which
/// serves the root as a COMPLETE lineage.
fn effective_max_nodes(requested: Option<u32>) -> u32 {
    requested
        .unwrap_or(DEFAULT_LINEAGE_NODES)
        .clamp(1, MAX_LINEAGE_NODES)
}

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
    /// Maximum number of claims in `nodes`, root included (default: 500,
    /// clamped to 1..=2000). With `direction=both` it bounds the MERGED set.
    pub max_nodes: Option<u32>,
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
    /// Maximum depth reached during traversal. Measured on the WALK, before
    /// the node cap trims it, so when the cap cut (`nodes_omitted > 0`) it can
    /// exceed the deepest `depth` in `nodes`.
    pub depth_reached: u32,
    /// Whether the lineage shown is not complete: `truncated_by_depth`, or
    /// the node cap cut a walk (`nodes_omitted > 0`, except in the `both`
    /// corner case described on `nodes_omitted`).
    pub truncated: bool,
    /// Whether a claim the viewer can read lies past `max_depth` (in either
    /// direction, for `both`). Raise `max_depth` to see it.
    pub truncated_by_depth: bool,
    /// How many claims the viewer can read, within `max_depth`, the node cap
    /// left out of `nodes`. EXACT: the walk reaches every such claim before
    /// the cap trims, and for `both` a claim one walk cut but the other kept
    /// is in `nodes` and is not counted. Claims past `max_depth` are not
    /// counted here (see `truncated_by_depth`). Raise `max_nodes` to see them.
    ///
    /// In that `both` corner case (every claim one walk cut is served by the
    /// other) this is 0 while `truncated` stays `true`: the claims are all
    /// present, but edges the cut walk alone would have reported may not be.
    pub nodes_omitted: u32,
    /// The node cap this response was served under, after defaults and
    /// clamping; `nodes.len()` never exceeds it.
    pub max_nodes: u32,
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
/// - `max_nodes` - Maximum number of claims in `nodes`, root included
///   (default: 500, clamped to 1..=2000); see "Node cap" below
/// - `direction` - Direction of traversal: "ancestors", "descendants", or "both" (default: "ancestors")
/// - `include_evidence` - Include evidence items (default: true)
/// - `include_traces` - Include reasoning traces (default: true)
///
/// # Responses
/// - 200: LineageResponse with nodes and edges
/// - 404: Claim not found
///
/// # Tenancy: ONE viewer-stamped connection for the whole request
///
/// PR-26 converts this handler's seven raw-pool reads onto
/// [`AppState::read_as`]. The connection is acquired ONCE, here, and threaded
/// into both private helpers — including the `Both` arm, which calls both. Two
/// acquires would be two separately-stamped checkouts (two transactions, in
/// `SessionGucMode::Transaction`), and a lineage assembled across them can be
/// internally inconsistent: edges naming claims the claim query did not return.
///
/// `read_as` and not `acquire_as`: the latter hard-refuses
/// `EPIGRAPH_SESSION_GUC_MODE=transaction`, the pooler fallback `bin/server.rs`
/// advertises to operators.
///
/// # Footprint — a FIXED number of statements
///
/// The handle is held across `1 + 5` statements on `ancestors` and on
/// `descendants` (the existence probe, then the walk's five), and `1 + 10` on
/// `both`, which runs both walks on the same handle. The count does not depend
/// on how many claims the walk returns: each node's `agent_id` and
/// `created_at` come from the walk's own projection, which the visibility
/// predicate already filtered, rather than from one `get_by_id_conn` per node.
/// `tests/lineage_scoped_read.rs::the_lineage_statement_count_does_not_grow_with_the_lineage`
/// pins that.
///
/// This closes `F-PR26-lineage-holds-one-connection-for-n-round-trips` in
/// `docs/tenancy/progress.json`. What remains is the walk's own cost: the
/// recursive statement's runtime still grows with the lineage (backlog
/// f889c86f / c07884a9); the node cap below bounds the follow-up statements
/// and the response, not that statement.
///
/// # Node cap (backlog 04007084)
///
/// `max_depth` bounds how far the walk goes, not how wide, so the response is
/// also capped at `max_nodes` claims. Each walk keeps the root and the claims
/// NEAREST it (`LineageRepository`'s `max_nodes`), trimmed before the edges,
/// evidence and traces statements, so every edge served joins two served
/// claims. The cut is never silent: `truncated` is set, and `nodes_omitted` is
/// the exact number of readable claims within `max_depth` left out, because the
/// walk reaches all of them before the cap trims (`truncated_by_depth` says
/// separately whether a claim lies past `max_depth`).
///
/// `both` shares ONE budget across its two walks: the ancestor walk runs under
/// the full cap, then the descendant walk under what is left (plus one, for
/// the root both walks return), so the MERGED `nodes` never exceeds
/// `max_nodes`. Ancestors therefore take priority when both sides are wide.
pub async fn get_lineage(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<LineageParams>,
) -> Result<Json<LineageResponse>, ApiError> {
    // Parse parameters with defaults and bounds
    let max_depth = params
        .max_depth
        .unwrap_or(DEFAULT_LINEAGE_DEPTH)
        .min(MAX_LINEAGE_DEPTH) as i32;
    let max_nodes = effective_max_nodes(params.max_nodes);
    let direction = params.direction.unwrap_or_default();
    let include_evidence = params.include_evidence.unwrap_or(true);
    let include_traces = params.include_traces.unwrap_or(true);

    // THE ERROR SHAPE IS PART OF THE TEMPLATE (see `routes/conflicts.rs::classify_conflict`).
    // `read_as`'s refusal reason is a paragraph of internal design prose aimed
    // at whoever mis-built the `AppState`; `errors.rs` serialises
    // `ApiError::InternalError { message }` verbatim into the response body, so
    // it is logged in full and answered with an opaque message.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_lineage",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // First, check if the claim exists (for 404).
    //
    // THIS IS THE ROOT'S ONLY DISCLOSURE DECISION, and the row is kept rather
    // than dropped on the floor. Both helpers serve the root's CONTENT when the
    // walk comes back empty; before PR-26's review they each re-fetched it with
    // a second `get_by_id_conn`, so the same viewer's access to the same row was
    // decided twice by two separately-written call sites. Two predicate
    // evaluations where one will do is a divergence surface, and the direction
    // it fails in is disclosure. Fetched once, here, and threaded down.
    let root_claim =
        ClaimRepository::get_by_id_conn(&mut read, &viewer, ClaimId::from_uuid(claim_id))
            .await?
            .ok_or_else(|| ApiError::NotFound {
                entity: "Claim".to_string(),
                id: claim_id.to_string(),
            })?;

    // Get lineage based on direction
    // `truncated_by_depth` comes from the walks themselves, which decide it
    // exactly (a visible claim lies past `max_depth`), and is OR-ed across the
    // `both` arm, as is whether the node cap cut a walk.
    let out = match direction {
        LineageDirection::Ancestors => {
            get_ancestor_lineage(
                &mut read,
                &viewer,
                &root_claim,
                claim_id,
                max_depth,
                max_nodes as usize,
                include_evidence,
                include_traces,
            )
            .await?
        }
        LineageDirection::Descendants => {
            get_descendant_lineage(
                &mut read,
                &viewer,
                &root_claim,
                claim_id,
                max_depth,
                max_nodes as usize,
                include_evidence,
                include_traces,
            )
            .await?
        }
        LineageDirection::Both => {
            // Get both ancestors and descendants, then merge. BOTH walks run on
            // the SAME connection: that is what makes the merged graph a single
            // consistent read rather than two.
            let ancestors = get_ancestor_lineage(
                &mut read,
                &viewer,
                &root_claim,
                claim_id,
                max_depth,
                max_nodes as usize,
                include_evidence,
                include_traces,
            )
            .await?;
            // ONE budget for the merged response. The ancestor walk served at
            // most `max_nodes` claims, the root among them; the descendant
            // walk also returns the root, which the merge dedups, so it may
            // keep `max_nodes - ancestors + 1` and the union stays within the
            // cap. Never below 1: the root is always served.
            let descendant_budget = (max_nodes as usize)
                .saturating_sub(ancestors.nodes.len())
                .saturating_add(1)
                .max(1);
            let descendants = get_descendant_lineage(
                &mut read,
                &viewer,
                &root_claim,
                claim_id,
                max_depth,
                descendant_budget,
                include_evidence,
                include_traces,
            )
            .await?;

            // Merge nodes, avoiding duplicates using HashSet for O(1) lookup
            let existing_ids: HashSet<Uuid> = ancestors.nodes.iter().map(|n| n.claim_id).collect();
            let merged_nodes: Vec<_> = ancestors
                .nodes
                .into_iter()
                .chain(
                    descendants
                        .nodes
                        .into_iter()
                        .filter(|n| !existing_ids.contains(&n.claim_id)),
                )
                .collect();

            // Merge edges, avoiding duplicates
            let existing_edges: HashSet<_> = ancestors
                .edges
                .iter()
                .map(|e| (e.source_id, e.target_id))
                .collect();
            let merged_edges: Vec<_> = ancestors
                .edges
                .into_iter()
                .chain(
                    descendants
                        .edges
                        .into_iter()
                        .filter(|e| !existing_edges.contains(&(e.source_id, e.target_id))),
                )
                .collect();

            WalkOut {
                nodes: merged_nodes,
                edges: merged_edges,
                depth_reached: ancestors.depth_reached.max(descendants.depth_reached),
                truncated_by_depth: ancestors.truncated_by_depth || descendants.truncated_by_depth,
                omitted: ancestors
                    .omitted
                    .into_iter()
                    .chain(descendants.omitted)
                    .collect(),
            }
        }
    };

    // The exact count of claims the cap kept out of `nodes`. The two walks
    // follow DIFFERENT edges (derivation edges up, every claim-to-claim edge
    // down), so one claim can be reached by both, cut by one and kept by the
    // other: count each id once, and only when it is not served. Summing the
    // walks' own counts would over-report exactly that claim.
    let served: HashSet<Uuid> = out.nodes.iter().map(|n| n.claim_id).collect();
    let nodes_omitted = out
        .omitted
        .iter()
        .filter(|id| !served.contains(id))
        .collect::<HashSet<_>>()
        .len();
    let cut_by_cap = !out.omitted.is_empty();

    // Read-only, so an un-committed transaction arm would merely roll back —
    // but `ScopedRead` has no `Drop` impl and finishing explicitly is what
    // returns the connection without a wasted round trip under
    // `SessionGucMode::Transaction`.
    // Same shape as the acquire arm above, and for the same reason: the reason
    // goes to the operator's log, the client gets an opaque message. A
    // `format!`-ed `DbError` here would render its `#[source]` driver text into
    // the response body, since `errors.rs` serialises
    // `ApiError::InternalError { message }` verbatim.
    read.commit().await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_lineage",
            "could not finish a viewer-stamped read"
        );
        ApiError::InternalError {
            message: "Failed to finish the scoped read".to_string(),
        }
    })?;

    let response = LineageResponse {
        root_claim_id: claim_id,
        nodes: out.nodes,
        edges: out.edges,
        depth_reached: out.depth_reached,
        truncated: out.truncated_by_depth || cut_by_cap,
        truncated_by_depth: out.truncated_by_depth,
        nodes_omitted: u32::try_from(nodes_omitted).unwrap_or(u32::MAX),
        max_nodes,
        direction,
    };

    Ok(Json(response))
}

/// One walk's share of a lineage response.
struct WalkOut {
    nodes: Vec<LineageNode>,
    edges: Vec<LineageEdge>,
    depth_reached: u32,
    /// A claim the viewer can read lies past `max_depth`.
    truncated_by_depth: bool,
    /// The claims the node cap cut from this walk
    /// (`LineageResult::omitted_by_node_cap`); may repeat across the `both`
    /// arm's two walks and may name a claim the other walk served.
    omitted: Vec<Uuid>,
}

/// Get ancestor lineage (claims this claim depends on)
///
/// Takes the caller's viewer-stamped connection rather than the `AppState`: the
/// acquire belongs to [`get_lineage`], which calls this and
/// [`get_descendant_lineage`] on the SAME handle.
///
/// `root` is the row [`get_lineage`]'s existence probe already fetched under
/// this viewer on this connection. It is passed in rather than re-fetched
/// because the empty-walk branch below serves the root's CONTENT: re-fetching
/// would put a SECOND, independently-written predicate evaluation in front of
/// the same disclosure, and the two could only ever agree by coincidence.
#[allow(clippy::too_many_arguments)]
async fn get_ancestor_lineage(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    root: &epigraph_core::Claim,
    claim_id: Uuid,
    max_depth: i32,
    max_nodes: usize,
    include_evidence: bool,
    include_traces: bool,
) -> Result<WalkOut, ApiError> {
    // Use LineageRepository for ancestor traversal
    let lineage_result = LineageRepository::get_lineage_conn(
        &mut *conn,
        viewer,
        claim_id,
        Some(max_depth),
        Some(max_nodes),
    )
    .await?;

    // If no claims found (empty result), return just the root claim.
    //
    // The row comes from the caller's existence probe, NOT from a second
    // `get_by_id_conn` here. This branch serves the root's content, so a
    // re-fetch would mean two independently-written visibility predicates
    // voting on one disclosure; they happen to be the same predicate today, but
    // that is a property of two hand-written queries rather than a control, and
    // `get_by_id_conn` has drifted from its sibling before.
    if lineage_result.claims.is_empty() {
        let node = LineageNode {
            claim_id,
            content: root.content.clone(),
            truth_value: root.truth_value.value(),
            depth: 0,
            agent_id: root.agent_id.into(),
            created_at: root.created_at,
            evidence: vec![],
            trace: None,
        };

        return Ok(WalkOut {
            nodes: vec![node],
            edges: vec![],
            depth_reached: 0,
            truncated_by_depth: lineage_result.truncated_by_depth,
            omitted: lineage_result.omitted_by_node_cap,
        });
    }

    // Build nodes from lineage claims
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for (id, lineage_claim) in &lineage_result.claims {
        // `agent_id` and `created_at` come from the walk's own projection,
        // which the viewer predicate already filtered. No per-node point read:
        // the connection's statement count does not grow with the lineage.
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
                            created_at: lineage_claim.created_at, // Use claim created_at as proxy
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
            agent_id: lineage_claim.agent_id,
            created_at: lineage_claim.created_at,
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

    Ok(WalkOut {
        nodes,
        edges,
        depth_reached: lineage_result.max_depth_reached as u32,
        truncated_by_depth: lineage_result.truncated_by_depth,
        omitted: lineage_result.omitted_by_node_cap,
    })
}

/// Get descendant lineage (claims that depend on this claim)
///
/// Delegates to LineageRepository::get_descendants for the recursive CTE query,
/// then transforms the result to the API response format.
///
/// Same connection and same `root` row as [`get_ancestor_lineage`], and for the
/// same reasons: one acquire per request, one disclosure decision on the root.
#[allow(clippy::too_many_arguments)]
async fn get_descendant_lineage(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    root: &epigraph_core::Claim,
    claim_id: Uuid,
    max_depth: i32,
    max_nodes: usize,
    include_evidence: bool,
    include_traces: bool,
) -> Result<WalkOut, ApiError> {
    // Use LineageRepository for descendant traversal
    let lineage_result = LineageRepository::get_descendants_conn(
        &mut *conn,
        viewer,
        claim_id,
        Some(max_depth),
        Some(max_nodes),
    )
    .await?;

    // If no claims found (empty result), return just the root claim.
    //
    // The row comes from the caller's existence probe, NOT from a second
    // `get_by_id_conn` here. This branch serves the root's content, so a
    // re-fetch would mean two independently-written visibility predicates
    // voting on one disclosure; they happen to be the same predicate today, but
    // that is a property of two hand-written queries rather than a control, and
    // `get_by_id_conn` has drifted from its sibling before.
    if lineage_result.claims.is_empty() {
        let node = LineageNode {
            claim_id,
            content: root.content.clone(),
            truth_value: root.truth_value.value(),
            depth: 0,
            agent_id: root.agent_id.into(),
            created_at: root.created_at,
            evidence: vec![],
            trace: None,
        };

        return Ok(WalkOut {
            nodes: vec![node],
            edges: vec![],
            depth_reached: 0,
            truncated_by_depth: lineage_result.truncated_by_depth,
            omitted: lineage_result.omitted_by_node_cap,
        });
    }

    // Build nodes from lineage claims
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for (id, lineage_claim) in &lineage_result.claims {
        // `agent_id` and `created_at` come from the walk's own projection,
        // which the viewer predicate already filtered. No per-node point read:
        // the connection's statement count does not grow with the lineage.
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
                            created_at: lineage_claim.created_at, // Use claim created_at as proxy
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
            agent_id: lineage_claim.agent_id,
            created_at: lineage_claim.created_at,
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

    Ok(WalkOut {
        nodes,
        edges,
        depth_reached: lineage_result.max_depth_reached as u32,
        truncated_by_depth: lineage_result.truncated_by_depth,
        omitted: lineage_result.omitted_by_node_cap,
    })
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
        assert!(params.max_nodes.is_none());
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
            truncated_by_depth: false,
            nodes_omitted: 0,
            max_nodes: DEFAULT_LINEAGE_NODES,
            direction: LineageDirection::Ancestors,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("root_claim_id"));
        assert!(json.contains("nodes"));
        assert!(json.contains("edges"));
        assert!(json.contains("depth_reached"));
        assert!(json.contains("truncated"));
        assert!(json.contains("truncated_by_depth"));
        assert!(json.contains("nodes_omitted"));
        assert!(json.contains("max_nodes"));
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
    fn test_effective_max_nodes_defaults_and_clamps() {
        assert_eq!(effective_max_nodes(None), DEFAULT_LINEAGE_NODES);
        assert_eq!(effective_max_nodes(Some(7)), 7);
        assert_eq!(
            effective_max_nodes(Some(0)),
            1,
            "a zero cap would serve the root as a complete lineage"
        );
        assert_eq!(effective_max_nodes(Some(u32::MAX)), MAX_LINEAGE_NODES);
    }

    #[test]
    fn test_default_lineage_depth() {
        assert_eq!(DEFAULT_LINEAGE_DEPTH, 10);
        // `DEFAULT_LINEAGE_DEPTH <= MAX_LINEAGE_DEPTH` is asserted at compile
        // time next to the constants themselves.
    }
}
