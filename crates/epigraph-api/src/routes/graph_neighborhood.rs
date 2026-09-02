//! /api/v1/graph/neighborhoods/:id/expand — compound + atomic modes.
//!
//! Compound mode (this file): nodes are compound claims (those with
//! decomposes_to children inside the neighborhood) plus standalone claims
//! (no decomposes_to in either direction). Edges are induced from atom-level
//! relationships (mass-weighted by `forward_strength`) plus direct
//! compound-compound edges that exist outside the decomposition hierarchy.
//!
//! Atomic mode is implemented in Task 8 — for now `atomic_response` returns
//! an empty placeholder.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
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
/// Atomic mode's node projection is read as the caller's `Viewer` — its
/// `label` is `claims.content`. The neighborhood/run metadata and the `edges`
/// traversals are not viewer-filtered; see `GraphViewRepository`'s module docs
/// for why, and the PR-07 report for the residual that leaves.
pub async fn expand(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(neighborhood_id): Path<Uuid>,
    Query(params): Query<ExpandParams>,
) -> Result<Json<NeighborhoodExpandResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    let pool: &PgPool = &state.db_pool;
    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM graph_neighborhoods WHERE id = $1 \
         AND run_id = (SELECT run_id FROM graph_cluster_runs ORDER BY completed_at DESC LIMIT 1)",
    )
    .bind(neighborhood_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "neighborhood not found in latest run".into(),
        ));
    }

    match params.mode.as_str() {
        "atomic" => Ok(Json(NeighborhoodExpandResponse::Atomic(
            atomic_response(pool, &viewer, neighborhood_id, params.budget).await?,
        ))),
        _ => Ok(Json(NeighborhoodExpandResponse::Compound(
            compound_response(pool, &viewer, neighborhood_id, params.budget).await?,
        ))),
    }
}

async fn compound_response(
    pool: &PgPool,
    viewer: &epigraph_db::Viewer,
    neighborhood_id: Uuid,
    _budget: i64,
) -> Result<CompoundResponse, (axum::http::StatusCode, String)> {
    let nodes: Vec<CompoundNode> = epigraph_db::GraphViewRepository::neighborhood_compound_nodes(
        pool,
        viewer,
        neighborhood_id,
    )
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
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

    let induced_edges: Vec<InducedEdge> = sqlx::query_as::<_, (Uuid, Uuid, String, f64, i32)>(
        r#"
        WITH atoms AS (
            SELECT m.claim_id FROM claim_neighborhood_membership m WHERE m.neighborhood_id = $1
        ),
        atom_to_compound AS (
            SELECT e.target_id AS atom_id, e.source_id AS compound_id
            FROM edges e JOIN atoms a ON a.claim_id = e.target_id
            WHERE e.relationship = 'decomposes_to'
        )
        SELECT a2c_s.compound_id AS source,
               a2c_t.compound_id AS target,
               e.relationship,
               SUM(ft.forward_strength)::double precision AS strength,
               COUNT(*)::int AS atom_edge_count
        FROM edges e
        JOIN atoms a_s ON a_s.claim_id = e.source_id
        JOIN atoms a_t ON a_t.claim_id = e.target_id
        JOIN atom_to_compound a2c_s ON a2c_s.atom_id = e.source_id
        JOIN atom_to_compound a2c_t ON a2c_t.atom_id = e.target_id
        LEFT JOIN LATERAL edge_to_factor_type(e.relationship) ft ON true
        WHERE a2c_s.compound_id <> a2c_t.compound_id
          AND e.relationship <> 'decomposes_to'
          AND ft.forward_strength > 0
        GROUP BY 1, 2, 3
        "#,
    )
    .bind(neighborhood_id)
    .fetch_all(pool)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .map(
        |(source, target, relationship, strength, atom_edge_count)| InducedEdge {
            source,
            target,
            relationship,
            strength,
            atom_edge_count,
        },
    )
    .collect();

    let direct_edges: Vec<DirectEdge> = sqlx::query_as::<_, (Uuid, Uuid, String)>(
        r#"
        WITH neighborhood_compounds AS (
            SELECT DISTINCT e.source_id AS id
            FROM edges e
            JOIN claim_neighborhood_membership m ON m.claim_id = e.target_id
            WHERE m.neighborhood_id = $1 AND e.relationship = 'decomposes_to'
        ),
        neighborhood_standalones AS (
            SELECT m.claim_id AS id
            FROM claim_neighborhood_membership m
            WHERE m.neighborhood_id = $1
              AND NOT EXISTS (SELECT 1 FROM edges e WHERE e.source_id = m.claim_id AND e.relationship = 'decomposes_to')
              AND NOT EXISTS (SELECT 1 FROM edges e WHERE e.target_id = m.claim_id AND e.relationship = 'decomposes_to')
        ),
        compound_universe AS (
            SELECT id FROM neighborhood_compounds UNION SELECT id FROM neighborhood_standalones
        )
        SELECT e.source_id, e.target_id, e.relationship
        FROM edges e
        JOIN compound_universe a ON a.id = e.source_id
        JOIN compound_universe b ON b.id = e.target_id
        -- No relationship filter: if both endpoints are displayed, the edge
        -- is displayed. Users hide unwanted types via GraphControls toggles.
        "#,
    )
    .bind(neighborhood_id)
    .fetch_all(pool).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .map(|(source, target, relationship)| DirectEdge { source, target, relationship })
    .collect();

    // Structural edges: surface decomposes_to-chain connections between
    // compound nodes that lack direct/induced epistemic edges. Two compounds
    // are connected if they parent the same atom (multi-parent atoms exist
    // in this data) OR if they share a common decomposes_to ancestor.
    let structural_edges: Vec<StructuralEdge> = sqlx::query_as::<_, (Uuid, Uuid, String, i64)>(
        r#"
        WITH nbhd_atoms AS (
            SELECT m.claim_id FROM claim_neighborhood_membership m
            WHERE m.neighborhood_id = $1
        ),
        parent_of_atom AS (
            -- For each atom in the neighborhood: its parent compounds
            SELECT e.source_id AS parent_id, e.target_id AS atom_id
            FROM edges e
            JOIN nbhd_atoms a ON a.claim_id = e.target_id
            WHERE e.relationship = 'decomposes_to'
        ),
        nbhd_compounds AS (
            SELECT DISTINCT parent_id AS id FROM parent_of_atom
        ),
        shared_atom_pairs AS (
            -- Compounds A,B that both parent the same atom in this neighborhood
            SELECT
                LEAST(p1.parent_id, p2.parent_id)    AS source,
                GREATEST(p1.parent_id, p2.parent_id) AS target,
                'shared_atom'::text                  AS kind,
                COUNT(*)::bigint                     AS atom_count
            FROM parent_of_atom p1
            JOIN parent_of_atom p2
              ON p1.atom_id = p2.atom_id AND p1.parent_id < p2.parent_id
            GROUP BY 1, 2, 3
        ),
        shared_ancestor_pairs AS (
            -- Compounds A,B in the neighborhood with a common decomposes_to ancestor
            SELECT
                LEAST(c1.id, c2.id)    AS source,
                GREATEST(c1.id, c2.id) AS target,
                'shared_ancestor'::text AS kind,
                COUNT(DISTINCT pa1.source_id)::bigint AS atom_count
            FROM nbhd_compounds c1
            JOIN nbhd_compounds c2 ON c1.id < c2.id
            JOIN edges pa1 ON pa1.target_id = c1.id AND pa1.relationship = 'decomposes_to'
            JOIN edges pa2 ON pa2.target_id = c2.id AND pa2.relationship = 'decomposes_to'
                          AND pa1.source_id = pa2.source_id
            GROUP BY 1, 2, 3
        )
        SELECT * FROM shared_atom_pairs
        UNION ALL
        SELECT * FROM shared_ancestor_pairs
        "#,
    )
    .bind(neighborhood_id)
    .fetch_all(pool)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .map(|(source, target, kind, atom_count)| StructuralEdge {
        source,
        target,
        kind,
        atom_count: atom_count as i32,
    })
    .collect();

    // PR-07: `nodes` is viewer-filtered; the three edge projections above are
    // not. Before PR-07 nodes and edges were drawn from the same unfiltered
    // set, so the payload was at least internally consistent. Filtering only
    // the nodes broke that: the edge arrays would still name the ids of
    // compounds that were never viewer-checked, which is an id-enumeration
    // oracle feeding every other by-id endpoint, and a graph client indexing
    // edges against the node map would synthesize phantom label-less nodes.
    //
    // Constraining each edge to endpoints that survived the node filter
    // restores the invariant "every edges[].source/target appears in
    // nodes[].id" and removes the oracle. This mirrors what `graph.rs::expand`
    // already does by deriving its edge query's id set from the filtered nodes;
    // it is done in Rust here because these three statements are structural
    // aggregates whose endpoints are computed, not selected.
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

async fn atomic_response(
    pool: &PgPool,
    viewer: &epigraph_db::Viewer,
    neighborhood_id: Uuid,
    _budget: i64,
) -> Result<AtomicResponse, (axum::http::StatusCode, String)> {
    let nodes: Vec<AtomicNode> =
        epigraph_db::GraphViewRepository::neighborhood_atomic_nodes(pool, viewer, neighborhood_id)
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .into_iter()
            .map(|r| AtomicNode {
                id: r.id,
                label: r.label,
                compound_id: r.compound_id,
                pignistic_prob: r.pignistic_prob,
                frame_id: r.frame_id,
            })
            .collect();

    let edges: Vec<AtomicEdge> = sqlx::query_as::<_, (Uuid, Uuid, String)>(
        r#"
        SELECT e.source_id, e.target_id, e.relationship
        FROM edges e
        JOIN claim_neighborhood_membership ms ON ms.claim_id = e.source_id AND ms.neighborhood_id = $1
        JOIN claim_neighborhood_membership mt ON mt.claim_id = e.target_id AND mt.neighborhood_id = $1
        LEFT JOIN LATERAL edge_to_factor_type(e.relationship) ft ON true
        WHERE e.relationship <> 'decomposes_to'
          AND ft.forward_strength > 0
        "#,
    )
    .bind(neighborhood_id).fetch_all(pool).await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .into_iter()
    .map(|(source, target, relationship)| AtomicEdge { source, target, relationship })
    .collect();

    let compound_groups: Vec<CompoundGroup> =
        epigraph_db::GraphViewRepository::neighborhood_compound_groups(
            pool,
            viewer,
            neighborhood_id,
        )
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_iter()
        .map(|r| CompoundGroup {
            compound_id: r.compound_id,
            label: r.label,
            member_atom_ids: r.member_atom_ids,
        })
        .collect();

    // PR-07: same node/edge consistency fix as `compound_response`. `edges`
    // and each group's `member_atom_ids` are aggregated from unfiltered
    // `edges`/membership rows, so both are constrained to the ids that
    // survived the viewer-filtered node projection. A group left with no
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
    let pool: &PgPool = &state.db_pool;
    let budget = params.budget.clamp(1, 200);

    // Fetch center claim content + verify the VIEWER can see it. A claim the
    // viewer cannot read is reported as absent, identically to one that does
    // not exist.
    let center = epigraph_db::GraphViewRepository::compound_center_content(pool, &viewer, claim_id)
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
        pool,
        &viewer,
        claim_id,
        budget + 1, // +1 so we can detect truncation
    )
    .await
    .map_err(internal)?;

    let truncated = rows.len() as i64 > budget;
    let kept = rows.into_iter().take(budget as usize);

    // Determine the kind of the center: compound if it has children;
    // standalone if no decomposes_to in either direction; else atom.
    let has_children: bool = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM edges WHERE source_id = $1 AND relationship = 'decomposes_to'",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .map_err(internal)?
        > 0;
    let has_parent: bool = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM edges WHERE target_id = $1 AND relationship = 'decomposes_to'",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .map_err(internal)?
        > 0;
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

fn internal<E: std::fmt::Display>(e: E) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}
