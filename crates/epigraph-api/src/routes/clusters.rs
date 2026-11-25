//! Cluster construction endpoints.
//!
//! Currently exposes:
//! - `POST /api/v1/clusters/build-from-bridges` — Louvain over `decomposes_to`
//!   bridges between paragraph-level claims (level=2). Two paragraphs are
//!   bridge-connected if they share ≥1 atom child via `decomposes_to`. Edge
//!   weight = count of shared atoms.
//!
//! The bridge graph captures structural overlap between paragraphs, which is
//! orthogonal to the epistemic SUPPORTS/CONTRADICTS clustering produced by the
//! nightly `cluster_graph` job. Both run results live in the same physical
//! tables (`graph_cluster_runs`, `graph_clusters`, `claim_cluster_membership`)
//! and are discriminated by the `algo` column on `graph_cluster_runs`.

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::middleware::bearer::ViewerExtractor;
#[cfg(feature = "db")]
use crate::state::AppState;
#[cfg(feature = "db")]
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct BuildFromBridgesRequest {
    /// Minimum number of shared atom children required to draw a bridge edge
    /// between two paragraphs. Default: 1.
    pub min_shared_atoms: Option<u32>,
    /// Louvain modularity resolution parameter. Default: 1.0.
    pub resolution: Option<f64>,
    /// How many bridge runs to retain after this one completes. Older runs
    /// (and their clusters / memberships) are GCed. Default: 5.
    pub retain_runs: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct BuildFromBridgesResponse {
    pub run_id: Uuid,
    pub cluster_count: usize,
    pub paragraph_count: usize,
    pub bridge_edge_count: usize,
}

/// `POST /api/v1/clusters/build-from-bridges`.
///
/// # Tenancy: one stamped transaction, reads and writes (backlog 67c905a3)
///
/// Every statement runs on ONE transaction stamped with the caller's viewer
/// ([`AppState::write_as`]), through `epigraph_db::ClusterRunRepository`:
///
/// * the two reads (bridge edges, paragraph nodes) splice the viewer, so a
///   paragraph the caller cannot read is not clustered and an edge it cannot
///   read is not a bridge;
/// * the INSERTS (run, clusters, memberships) are decided by row security
///   against the same stamp. A membership row inherits its paragraph's
///   tenancy, so the run commits only if the caller may write every paragraph
///   it clusters; a refusal (`42501`) there is a 403 and nothing is committed.
/// * the retention sweep is NOT owner-scoped: `graph_cluster_runs` and
///   `graph_clusters` carry no tenancy, and memberships go with their cluster
///   through a foreign-key cascade, so it keeps the newest `retain_runs`
///   bridge runs across ALL callers (see
///   `ClusterRunRepository::gc_bridge_runs`). A failure there is a 500, never
///   the 403 above: a `42501` from the sweep can only be a missing table
///   grant, and a 403 would send an operator to group membership instead.
///
/// Before this the reads and the writes ran on the raw pool with no viewer:
/// on a login that bypasses row security every paragraph in the database was
/// clustered for any `claims:admin` bearer. Reads and writes had to move
/// together, because stamping only the reads would hand an unstamped writer
/// membership rows for claims its own session cannot see.
#[cfg(feature = "db")]
pub async fn build_from_bridges(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    ViewerExtractor(viewer): ViewerExtractor,
    Json(req): Json<BuildFromBridgesRequest>,
) -> Result<Json<BuildFromBridgesResponse>, ApiError> {
    let auth = auth_ctx
        .ok_or(crate::errors::ApiError::Unauthorized {
            reason: "build_from_bridges requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;
    use epigraph_db::ClusterRunRepository;
    use epigraph_jobs::cluster_graph::louvain::{louvain, LouvainInput};
    use std::collections::HashMap;

    let min_shared = i64::from(req.min_shared_atoms.unwrap_or(1));
    let resolution = req.resolution.unwrap_or(1.0);
    let retain_runs = req.retain_runs.unwrap_or(5);

    let mut tx = state.write_as(&viewer, "build_from_bridges").await?;

    // -- Step 1: the bridge edges (pairs of level-2 paragraphs sharing at least
    //    `min_shared` atom children) and the paragraph nodes, both as the
    //    caller may see them.
    let edges = ClusterRunRepository::bridge_edges(&mut tx, &viewer, min_shared)
        .await
        .map_err(|e| internal("bridge edge query", &e))?;
    let paragraphs = ClusterRunRepository::bridge_paragraphs(&mut tx, &viewer)
        .await
        .map_err(|e| internal("paragraph node query", &e))?;

    // -- Step 2: a dense node index for Louvain (nodes are 0..n). Seeded with
    //    every paragraph node so isolates are nodes too, then both endpoints
    //    of each bridge edge.
    let mut node_idx: HashMap<Uuid, u32> = HashMap::new();
    let mut order: Vec<Uuid> = Vec::new();
    let endpoints = edges.iter().flat_map(|e| [e.para_a, e.para_b]);
    for id in paragraphs.iter().copied().chain(endpoints) {
        if let std::collections::hash_map::Entry::Vacant(slot) = node_idx.entry(id) {
            slot.insert(order.len() as u32);
            order.push(id);
        }
    }

    let louvain_edges: Vec<(u32, u32, f64)> = edges
        .iter()
        .map(|e| (node_idx[&e.para_a], node_idx[&e.para_b], e.weight as f64))
        .collect();

    // -- Step 3: run Louvain.
    let assignments: Vec<u32> = if node_idx.is_empty() {
        Vec::new()
    } else {
        let input = LouvainInput {
            node_count: node_idx.len(),
            edges: louvain_edges,
            resolution,
        };
        louvain(&input)
            .map_err(|e| ApiError::InternalError {
                message: format!("louvain: {e}"),
            })?
            .assignments
    };

    // -- Step 4: persist the run, clusters and memberships, then GC old runs,
    //    all on the stamped transaction; commit once.
    let members: Vec<(Uuid, u32)> = order
        .iter()
        .copied()
        .zip(assignments.iter().copied())
        .collect();
    let run_id = ClusterRunRepository::insert_bridge_run(&mut tx, &members)
        .await
        .map_err(refused_or_internal)?;
    ClusterRunRepository::gc_bridge_runs(&mut tx, retain_runs)
        .await
        .map_err(|e| internal("retention sweep", &e))?;
    tx.commit().await.map_err(|e| internal("commit", &e))?;

    let cluster_count: usize = {
        use std::collections::BTreeSet;
        assignments.iter().copied().collect::<BTreeSet<_>>().len()
    };

    Ok(Json(BuildFromBridgesResponse {
        run_id,
        cluster_count,
        paragraph_count: node_idx.len(),
        bridge_edge_count: edges.len(),
    }))
}

/// A repo failure as the 500 this handler has always answered, with the stage
/// named in the log rather than the response.
#[cfg(feature = "db")]
fn internal(stage: &'static str, e: &epigraph_db::DbError) -> ApiError {
    tracing::error!(
        target: "tenancy.scoped_write",
        error = %e,
        handler = "build_from_bridges",
        stage,
        "build_from_bridges failed"
    );
    ApiError::InternalError {
        message: format!("{stage}: {e}"),
    }
}

/// For the INSERTS of a run only: a write refused by row security (`42501`:
/// the run would cluster a paragraph whose membership row the caller may not
/// write) is a 403, and the transaction is dropped uncommitted. Anything else
/// is a 500. Not used for the retention sweep, whose `42501` cannot be a row
/// refusal (its tables carry no row security) and so is a misconfigured grant.
#[cfg(feature = "db")]
fn refused_or_internal(e: epigraph_db::DbError) -> ApiError {
    if crate::errors::db_is_insufficient_privilege(&e) {
        crate::errors::write_refused("bridge cluster run")
    } else {
        internal("persist bridge run", &e)
    }
}

#[cfg(not(feature = "db"))]
pub async fn build_from_bridges(
    axum::extract::Json(_req): axum::extract::Json<BuildFromBridgesRequest>,
) -> Result<axum::Json<BuildFromBridgesResponse>, axum::http::StatusCode> {
    Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
}
