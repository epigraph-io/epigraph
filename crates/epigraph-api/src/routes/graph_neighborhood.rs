//! /api/v1/graph/neighborhoods/:id/expand — compound + atomic modes.
//!
//! Compound mode (the default): nodes are compound claims (those with
//! decomposes_to children inside the neighborhood) plus standalone claims
//! (no decomposes_to in either direction). Edges are induced from atom-level
//! relationships (mass-weighted by `forward_strength`) plus direct
//! compound-compound edges that exist outside the decomposition hierarchy.
//!
//! Atomic mode (`?mode=atomic`) returns the neighborhood's member claims
//! themselves, the epistemic edges between them (`decomposes_to` excluded,
//! positive `forward_strength` only), and the compound groups those atoms
//! belong to. Neither mode applies `budget` yet, so both report
//! `truncated: false`.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::middleware::bearer::ViewerExtractor;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct ExpandParams {
    #[serde(default = "default_budget")]
    pub budget: i64,
    #[serde(default = "default_mode")]
    pub mode: String,
}
fn default_budget() -> i64 {
    200
}
fn default_mode() -> String {
    "compound".to_string()
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum NeighborhoodExpandResponse {
    Compound(CompoundResponse),
    Atomic(AtomicResponse),
}

#[derive(Debug, Serialize)]
pub struct CompoundResponse {
    pub neighborhood_id: Uuid,
    pub truncated: bool,
    pub nodes: Vec<CompoundNode>,
    pub induced_edges: Vec<InducedEdge>,
    pub direct_edges: Vec<DirectEdge>,
    /// Structural edges between compound nodes that don't have direct or
    /// induced epistemic edges but ARE connected through the decomposes_to
    /// hierarchy: either by sharing an atom child (atoms are many-to-many
    /// parented in this data — 47k atoms have ≥2 parents) or by sharing a
    /// common decomposes_to ancestor.
    pub structural_edges: Vec<StructuralEdge>,
}

#[derive(Debug, Serialize)]
pub struct StructuralEdge {
    pub source: Uuid,
    pub target: Uuid,
    /// "shared_atom" — both compounds parent the same atom (within this neighborhood).
    /// "shared_ancestor" — both compounds are decomposes_to children of the same parent.
    pub kind: String,
    pub atom_count: i32,
}

#[derive(Debug, Serialize)]
pub struct CompoundNode {
    pub id: Uuid,
    pub label: String,
    pub kind: String, // "compound" | "standalone"
    pub atom_count: i32,
    pub pignistic_prob: Option<f64>,
    pub frame_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct InducedEdge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
    pub strength: f64,
    pub atom_edge_count: i32,
}

#[derive(Debug, Serialize)]
pub struct DirectEdge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
}

#[derive(Debug, Serialize)]
pub struct AtomicResponse {
    pub neighborhood_id: Uuid,
    pub truncated: bool,
    pub nodes: Vec<AtomicNode>,
    pub edges: Vec<AtomicEdge>,
    pub compound_groups: Vec<CompoundGroup>,
}

#[derive(Debug, Serialize)]
pub struct AtomicNode {
    pub id: Uuid,
    pub label: String,
    pub compound_id: Option<Uuid>,
    pub pignistic_prob: Option<f64>,
    pub frame_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct AtomicEdge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
}

#[derive(Debug, Serialize)]
pub struct CompoundGroup {
    pub compound_id: Uuid,
    pub label: String,
    pub member_atom_ids: Vec<Uuid>,
}

/// Expand a precomputed neighborhood.
///
/// Every node and edge projection is read as the caller's `Viewer` through
/// `GraphViewRepository`: node `label`s are `claims.content`, and every
/// `edges` read is filtered (F-edges-unfiltered), so the node and edge arrays
/// describe one graph. The neighborhood/run metadata is not viewer-filtered;
/// it carries no tenancy columns (see `GraphViewRepository`'s module docs).
pub async fn expand(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(neighborhood_id): Path<Uuid>,
    Query(params): Query<ExpandParams>,
) -> Result<Json<NeighborhoodExpandResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    // Conversion shard 5. ONE viewer-stamped connection for the whole response.
    //
    // The run lookup and the existence probe immediately below read the
    // clustering-run tables; measured at migration head 92 NEITHER carries row
    // level security (`pg_class.relrowsecurity` is false on both, and no policy
    // exists on either), so stamping these statements narrows nothing and the
    // probe is NOT made viewer-filtered by the change. What the stamp is for is
    // the node projections in `atomic_response` / `compound_response`, which
    // read `claims`, `edges` and `claim_neighborhood_membership`.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "expand",
            "could not acquire a viewer-stamped connection"
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to acquire a scoped connection".to_string(),
        )
    })?;
    // The latest-run lookup was a SUBQUERY inside the existence probe below.
    // It is split out so it goes through `ClusterRunRepository::latest`, the
    // one spelling `GET /claims/:id/placement` also reads: this route must
    // accept the `neighborhood_id`s that route hands out, and two copies of
    // "newest completed_at" are free to drift the day either changes. The
    // lookup runs on the same viewer-stamped connection as the probe.
    //
    // Splitting it also makes "no run has ever completed" its own arm. The
    // subquery form returned NULL there, the probe matched nothing, and the
    // handler answered "neighborhood not found in latest run" — the same 404
    // this arm returns, so the behaviour is unchanged.
    let latest_run = epigraph_db::ClusterRunRepository::latest(&mut *read)
        .await
        .map_err(internal)?;
    let Some(run_id) = latest_run.map(|r| r.run_id) else {
        return Err((
            StatusCode::NOT_FOUND,
            "neighborhood not found in latest run".into(),
        ));
    };
    let exists: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM graph_neighborhoods WHERE id = $1 AND run_id = $2")
            .bind(neighborhood_id)
            .bind(run_id)
            .fetch_optional(&mut *read)
            .await
            .map_err(internal)?;
    if exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "neighborhood not found in latest run".into(),
        ));
    }

    match params.mode.as_str() {
        "atomic" => Ok(Json(NeighborhoodExpandResponse::Atomic(
            atomic_response(&mut read, &viewer, neighborhood_id, params.budget).await?,
        ))),
        _ => Ok(Json(NeighborhoodExpandResponse::Compound(
            compound_response(&mut read, &viewer, neighborhood_id, params.budget).await?,
        ))),
    }
}

/// Conversion shard 5 took this from `pool: &PgPool` to a borrowed connection so
/// that its four statements run on the caller's ONE viewer-stamped connection
/// rather than on four arbitrary raw-pool checkouts. `&mut PgConnection` rather
/// than a by-value `E: PgExecutor`, because a by-value executor is MOVED by its
/// first use and this body has four; `&mut *conn` is reborrowed per call.
async fn compound_response(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::Viewer,
    neighborhood_id: Uuid,
    _budget: i64,
) -> Result<CompoundResponse, (axum::http::StatusCode, String)> {
    let nodes: Vec<CompoundNode> = epigraph_db::GraphViewRepository::neighborhood_compound_nodes(
        &mut *conn,
        viewer,
        neighborhood_id,
    )
    .await
    .map_err(internal)?
    .into_iter()
    .map(|r| CompoundNode {
        id: r.id,
        label: r.label,
        kind: r.kind,
        atom_count: r.atom_count,
        pignistic_prob: r.pignistic_prob,
        frame_id: r.frame_id,
    })
    .collect();

    // The three edge projections walk the same graph as `nodes`: each repo
    // function filters every `edges` read it makes and uses the node
    // projection's `atoms` CTE (F-edges-unfiltered). See
    // `GraphViewRepository::neighborhood_direct_edges` for why the
    // compound/standalone classification must match `nodes` exactly.
    let induced_edges: Vec<InducedEdge> =
        epigraph_db::GraphViewRepository::neighborhood_induced_edges(
            &mut *conn,
            viewer,
            neighborhood_id,
        )
        .await
        .map_err(internal)?
        .into_iter()
        .map(|r| InducedEdge {
            source: r.source,
            target: r.target,
            relationship: r.relationship,
            strength: r.strength,
            atom_edge_count: r.atom_edge_count,
        })
        .collect();

    let direct_edges: Vec<DirectEdge> =
        epigraph_db::GraphViewRepository::neighborhood_direct_edges(
            &mut *conn,
            viewer,
            neighborhood_id,
        )
        .await
        .map_err(internal)?
        .into_iter()
        .map(|r| DirectEdge {
            source: r.source_id,
            target: r.target_id,
            relationship: r.relationship,
        })
        .collect();

    // Structural edges: surface decomposes_to-chain connections between
    // compound nodes that lack direct/induced epistemic edges. Two compounds
    // are connected if they parent the same atom (multi-parent atoms exist
    // in this data) OR if they share a common decomposes_to ancestor.
    let structural_edges: Vec<StructuralEdge> =
        epigraph_db::GraphViewRepository::neighborhood_structural_edges(
            &mut *conn,
            viewer,
            neighborhood_id,
        )
        .await
        .map_err(internal)?
        .into_iter()
        .map(|r| StructuralEdge {
            source: r.source,
            target: r.target,
            kind: r.kind,
            atom_count: r.atom_count as i32,
        })
        .collect();

    // PR-07: every edge array is constrained to endpoints that survived the
    // node projection, restoring the invariant "every edges[].source/target
    // appears in nodes[].id". The edge statements filter the `edges` rows they
    // walk, but they do not check that a COMPOUND endpoint's own `claims` row
    // is readable (the endpoints are computed, not selected), so this filter is
    // still what keeps an unreadable compound's id out of the edge arrays. It
    // mirrors `graph.rs::expand`, which derives its edge query's id set from
    // the filtered nodes.
    let visible: std::collections::HashSet<Uuid> = nodes.iter().map(|n| n.id).collect();
    let induced_edges: Vec<InducedEdge> = induced_edges
        .into_iter()
        .filter(|e| visible.contains(&e.source) && visible.contains(&e.target))
        .collect();
    let direct_edges: Vec<DirectEdge> = direct_edges
        .into_iter()
        .filter(|e| visible.contains(&e.source) && visible.contains(&e.target))
        .collect();
    let structural_edges: Vec<StructuralEdge> = structural_edges
        .into_iter()
        .filter(|e| visible.contains(&e.source) && visible.contains(&e.target))
        .collect();

    Ok(CompoundResponse {
        neighborhood_id,
        truncated: false,
        nodes,
        induced_edges,
        direct_edges,
        structural_edges,
    })
}

/// Conversion shard 5 took this from `pool: &PgPool` to a borrowed connection,
/// for the reason given on [`compound_response`].
async fn atomic_response(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::Viewer,
    neighborhood_id: Uuid,
    _budget: i64,
) -> Result<AtomicResponse, (axum::http::StatusCode, String)> {
    let nodes: Vec<AtomicNode> = epigraph_db::GraphViewRepository::neighborhood_atomic_nodes(
        &mut *conn,
        viewer,
        neighborhood_id,
    )
    .await
    .map_err(internal)?
    .into_iter()
    .map(|r| AtomicNode {
        id: r.id,
        label: r.label,
        compound_id: r.compound_id,
        pignistic_prob: r.pignistic_prob,
        frame_id: r.frame_id,
    })
    .collect();

    let edges: Vec<AtomicEdge> = epigraph_db::GraphViewRepository::neighborhood_atomic_edges(
        &mut *conn,
        viewer,
        neighborhood_id,
    )
    .await
    .map_err(internal)?
    .into_iter()
    .map(|r| AtomicEdge {
        source: r.source_id,
        target: r.target_id,
        relationship: r.relationship,
    })
    .collect();

    let compound_groups: Vec<CompoundGroup> =
        epigraph_db::GraphViewRepository::neighborhood_compound_groups(
            &mut *conn,
            viewer,
            neighborhood_id,
        )
        .await
        .map_err(internal)?
        .into_iter()
        .map(|r| CompoundGroup {
            compound_id: r.compound_id,
            label: r.label,
            member_atom_ids: r.member_atom_ids,
        })
        .collect();

    // PR-07: same node/edge consistency fix as `compound_response`. `edges`
    // and each group's `member_atom_ids` walk only readable `edges` and
    // membership rows, but not the far endpoint's `claims` row, so both are
    // constrained to the ids that survived the viewer-filtered node
    // projection. A group left with no
    // visible members is dropped rather than returned empty — an empty group
    // still discloses that a compound exists and parents something here.
    let visible: std::collections::HashSet<Uuid> = nodes.iter().map(|n| n.id).collect();
    let edges: Vec<AtomicEdge> = edges
        .into_iter()
        .filter(|e| visible.contains(&e.source) && visible.contains(&e.target))
        .collect();
    let compound_groups: Vec<CompoundGroup> = compound_groups
        .into_iter()
        .filter_map(|mut g| {
            g.member_atom_ids.retain(|id| visible.contains(id));
            if g.member_atom_ids.is_empty() {
                None
            } else {
                Some(g)
            }
        })
        .collect();

    Ok(AtomicResponse {
        neighborhood_id,
        truncated: false,
        nodes,
        edges,
        compound_groups,
    })
}

// ---------------------------------------------------------------------------
// /api/v1/claims/:id/compound_neighborhood
//
// Given a clicked claim X, surface its 1-hop neighborhood projected onto the
// compound layer: walk through atoms (X's children, or X itself if X is an
// atom) following positive-weight epistemic edges, then resolve each
// connected atom to its parent compound (or to itself for standalones).
// Aggregate by parent compound, count contributing atom-edges, return the
// merged set.
//
// Used by the GUI when "Collapse equivalents" mode is on — instead of a raw
// 1-hop claim neighborhood (which surfaces atomic siblings), this surfaces
// the next-hop compound claims as if intervening atoms weren't visible.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CompoundNeighborhoodParams {
    #[serde(default = "default_compound_budget")]
    pub budget: i64,
}
fn default_compound_budget() -> i64 {
    50
}

#[derive(Debug, Serialize)]
pub struct CompoundNeighborhoodResponse {
    pub center_id: Uuid,
    pub nodes: Vec<CompoundNeighborNode>,
    pub edges: Vec<CompoundNeighborEdge>,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct CompoundNeighborNode {
    pub id: Uuid,
    pub label: String,
    pub kind: String, // "self" | "compound" | "standalone" | "atom"
    pub atom_link_count: i32,
    pub pignistic_prob: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct CompoundNeighborEdge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
    pub atom_edge_count: i32,
    pub total_strength: f64,
}

/// Compound-level neighborhood of a single claim.
///
/// Both the centre's content and every neighbour's content are read as the
/// caller's `Viewer`. Before PR-07 this handler ran
/// `SELECT content FROM claims WHERE id = $1` with no predicate — a bare
/// content-and-existence oracle for any claim id — and then returned every
/// adjacent compound's `content` alongside it.
pub async fn claim_compound_neighborhood(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<CompoundNeighborhoodParams>,
) -> Result<Json<CompoundNeighborhoodResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    // Conversion shard 5: one viewer-stamped connection across all four
    // statements, so the centre's visibility check and the neighbour
    // aggregation describe the same corpus.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "claim_compound_neighborhood",
            "could not acquire a viewer-stamped connection"
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to acquire a scoped connection".to_string(),
        )
    })?;
    let budget = params.budget.clamp(1, 200);

    // Fetch center claim content + verify the VIEWER can see it. A claim the
    // viewer cannot read is reported as absent, identically to one that does
    // not exist.
    let center =
        epigraph_db::GraphViewRepository::compound_center_content(&mut *read, &viewer, claim_id)
            .await
            .map_err(internal)?;
    let Some(center_content) = center else {
        return Err((StatusCode::NOT_FOUND, "claim not found".into()));
    };

    // Aggregate (other_compound, relationship) -> (atom_edge_count, sum(forward_strength)).
    // Both endpoints of every epistemic edge are projected to their parent
    // compound (or themselves if standalone). The center claim's projection
    // is filtered out so we don't return self-loops.
    let rows = epigraph_db::GraphViewRepository::compound_neighbors(
        &mut *read,
        &viewer,
        claim_id,
        budget + 1, // +1 so we can detect truncation
    )
    .await
    .map_err(internal)?;

    let truncated = rows.len() as i64 > budget;
    let kept = rows.into_iter().take(budget as usize);

    // Determine the kind of the center: compound if it has children;
    // standalone if no decomposes_to in either direction; else atom. Both
    // probes count only edges the viewer can read.
    let (has_children, has_parent) =
        epigraph_db::GraphViewRepository::center_decomposition(&mut *read, &viewer, claim_id)
            .await
            .map_err(internal)?;
    let center_kind = match (has_children, has_parent) {
        (true, _) => "compound",
        (false, true) => "atom",
        (false, false) => "standalone",
    };

    let mut nodes_by_id: std::collections::HashMap<Uuid, CompoundNeighborNode> =
        std::collections::HashMap::new();
    let mut edges: Vec<CompoundNeighborEdge> = Vec::new();
    for epigraph_db::CompoundNeighborRow {
        id,
        content,
        relationship,
        atom_edge_count,
        total_strength,
        pignistic_prob,
    } in kept
    {
        let entry = nodes_by_id
            .entry(id)
            .or_insert_with(|| CompoundNeighborNode {
                id,
                label: content,
                kind: "compound_or_standalone".to_string(),
                atom_link_count: 0,
                pignistic_prob,
            });
        entry.atom_link_count += atom_edge_count as i32;
        edges.push(CompoundNeighborEdge {
            source: claim_id,
            target: id,
            relationship,
            atom_edge_count: atom_edge_count as i32,
            total_strength,
        });
    }
    let mut nodes: Vec<CompoundNeighborNode> = nodes_by_id.into_values().collect();
    nodes.sort_by_key(|n| std::cmp::Reverse(n.atom_link_count));

    // Push the center node first
    nodes.insert(
        0,
        CompoundNeighborNode {
            id: claim_id,
            label: center_content,
            kind: center_kind.to_string(),
            atom_link_count: edges.iter().map(|e| e.atom_edge_count).sum(),
            pignistic_prob: None,
        },
    );

    Ok(Json(CompoundNeighborhoodResponse {
        center_id: claim_id,
        nodes,
        edges,
        truncated,
    }))
}

/// A 500 for a failed statement. The driver's error is LOGGED, never sent:
/// the body is [`crate::errors::INTERNAL_ERROR_BODY`], as for every
/// `ApiError::InternalError` (F-route-error-text-remainder).
fn internal<E: std::fmt::Display>(e: E) -> (axum::http::StatusCode, String) {
    tracing::error!(target: "api.internal_error", route = "graph_neighborhood", detail = %e, "internal error");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        crate::errors::INTERNAL_ERROR_BODY.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every failed statement in this file answers through `internal`, which
    /// may not hand the driver's error text to the caller
    /// (F-route-error-text-remainder).
    #[test]
    fn internal_answers_never_carry_the_driver_error() {
        let (status, body) = internal(sqlx::Error::Protocol(
            "relation \"neighborhoods\" does not exist".to_string(),
        ));
        assert_eq!(status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains("neighborhoods"), "{body}");
        assert!(!body.contains("does not exist"), "{body}");
        assert_eq!(body, crate::errors::INTERNAL_ERROR_BODY);
    }
}
