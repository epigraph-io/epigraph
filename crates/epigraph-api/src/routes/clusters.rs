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

/// Algorithm discriminator written to `graph_cluster_runs.algo` so this run is
/// distinguishable from the nightly SUPPORTS/CONTRADICTS Louvain run (which
/// uses `algo='louvain'`).
#[cfg(feature = "db")]
const ALGO_LOUVAIN_BRIDGE: &str = "louvain_bridge";

#[cfg(feature = "db")]
pub async fn build_from_bridges(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(req): Json<BuildFromBridgesRequest>,
) -> Result<Json<BuildFromBridgesResponse>, ApiError> {
    let auth = auth_ctx
        .ok_or(crate::errors::ApiError::Unauthorized {
            reason: "build_from_bridges requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;
    use epigraph_jobs::cluster_graph::louvain::{louvain, LouvainConfig, LouvainInput};
    use std::collections::HashMap;

    let pool = &state.db_pool;

    let min_shared = req.min_shared_atoms.unwrap_or(1) as i64;
    let resolution = req.resolution.unwrap_or(1.0);
    let retain_runs = req.retain_runs.unwrap_or(5);

    // -- Step 1: pre-aggregate bridge edges via SQL.
    //
    // For each pair of paragraph-level claims (level=2), count the number of
    // atom-level children (level=3 — by convention; we don't strictly require
    // it on the child side because the parent gate is what matters for the
    // bridge graph) they share via `decomposes_to`.
    //
    // The `paragraph_id < other.paragraph_id` join condition emits each
    // unordered pair exactly once.
    #[derive(sqlx::FromRow)]
    struct BridgeEdgeRow {
        para_a: Uuid,
        para_b: Uuid,
        weight: i64,
    }
    let edges: Vec<BridgeEdgeRow> = sqlx::query_as::<_, BridgeEdgeRow>(
        r#"WITH atom_parents AS (
            SELECT e.target_id AS atom_id, e.source_id AS paragraph_id
            FROM edges e
            JOIN claims p ON p.id = e.source_id
            WHERE e.relationship = 'decomposes_to'
              AND (p.properties->>'level')::int = 2
        )
        SELECT
            a.paragraph_id  AS para_a,
            b.paragraph_id  AS para_b,
            COUNT(*)::bigint AS weight
        FROM atom_parents a
        JOIN atom_parents b
            ON a.atom_id = b.atom_id
           AND a.paragraph_id < b.paragraph_id
        GROUP BY a.paragraph_id, b.paragraph_id
        HAVING COUNT(*) >= $1
        "#,
    )
    .bind(min_shared)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("bridge edge query: {e}"),
    })?;

    // -- Step 2a: enumerate paragraph nodes.
    //
    // A paragraph is a node in the bridge graph if it is level=2 and has at
    // least one atom child via `decomposes_to`. This keeps singleton
    // paragraphs in the result (they get their own cluster) — matching the
    // Phase 5.B spec contract that paragraph_count counts "paragraphs in the
    // bridge graph", not just paragraphs with at least one bridge.
    let para_rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT DISTINCT e.source_id
         FROM edges e
         JOIN claims p ON p.id = e.source_id
         WHERE e.relationship = 'decomposes_to'
           AND (p.properties->>'level')::int = 2",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("paragraph node query: {e}"),
    })?;

    // -- Step 2b: build a dense node index for Louvain.
    //
    // Louvain expects nodes to be 0..n. We seed the index with every
    // paragraph node (so isolates are nodes too), then ensure both endpoints
    // of each bridge edge are present.
    let mut node_idx: HashMap<Uuid, u32> = HashMap::new();
    for (id,) in &para_rows {
        let next = node_idx.len() as u32;
        node_idx.entry(*id).or_insert(next);
    }
    for e in &edges {
        let next = node_idx.len() as u32;
        node_idx.entry(e.para_a).or_insert(next);
        let next = node_idx.len() as u32;
        node_idx.entry(e.para_b).or_insert(next);
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
        louvain(&input, &LouvainConfig::default())
            .map_err(|e| ApiError::InternalError {
                message: format!("louvain: {e}"),
            })?
            .assignments
    };

    // -- Step 4: persist run row + clusters + memberships, then GC old runs.
    let run_id = persist_bridge_run(pool, &node_idx, &assignments).await?;
    gc_bridge_runs(pool, retain_runs).await?;

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

#[cfg(not(feature = "db"))]
pub async fn build_from_bridges(
    axum::extract::Json(_req): axum::extract::Json<BuildFromBridgesRequest>,
) -> Result<axum::Json<BuildFromBridgesResponse>, axum::http::StatusCode> {
    Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
}

/// Insert a `graph_cluster_runs` row + `graph_clusters` rows for each unique
/// community + `claim_cluster_membership` rows tying each paragraph (looked up
/// via the reverse of `node_idx`) to its assigned cluster id.
///
/// Mirrors `epigraph_jobs::cluster_graph::runner::write_clusters` for the
/// epistemic Louvain runs but operates over paragraph nodes only and writes
/// `algo='louvain_bridge'` on the run row.
#[cfg(feature = "db")]
async fn persist_bridge_run(
    pool: &sqlx::PgPool,
    node_idx: &std::collections::HashMap<Uuid, u32>,
    assignments: &[u32],
) -> Result<Uuid, ApiError> {
    use std::collections::HashMap;

    let run_id = Uuid::new_v4();

    // Reverse mapping: dense u32 idx -> paragraph UUID.
    let mut idx_to_id: HashMap<u32, Uuid> = HashMap::with_capacity(node_idx.len());
    for (id, idx) in node_idx {
        idx_to_id.insert(*idx, *id);
    }

    // Group node indices by assigned community id.
    let mut groups: HashMap<u32, Vec<u32>> = HashMap::new();
    for (idx, comm) in assignments.iter().enumerate() {
        groups.entry(*comm).or_default().push(idx as u32);
    }

    let mut tx = pool.begin().await.map_err(|e| ApiError::InternalError {
        message: format!("begin tx: {e}"),
    })?;

    // 1. Run row. NOTE: the existing schema has columns
    //    (run_id, completed_at, cluster_count, degraded). Migration 027 adds
    //    `algo`. `degraded` is FALSE for bridge runs since we don't fall back
    //    to per-frame grouping when the graph is sparse — empty graphs simply
    //    produce zero clusters and that's the truthful answer.
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded, algo)
         VALUES ($1, $2, FALSE, $3)",
    )
    .bind(run_id)
    .bind(groups.len() as i32)
    .bind(ALGO_LOUVAIN_BRIDGE)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("insert run: {e}"),
    })?;

    // 2. Cluster rows + memberships.
    let mut cluster_id_map: HashMap<u32, Uuid> = HashMap::with_capacity(groups.len());
    for (comm, members) in &groups {
        let cluster_id = Uuid::new_v4();
        cluster_id_map.insert(*comm, cluster_id);
        let size = members.len() as i32;
        let label = format!("bridge-cluster-{comm}");

        sqlx::query(
            "INSERT INTO graph_clusters
             (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded)
             VALUES ($1, $2, $3, $4, NULL, 'paragraph', NULL, FALSE)",
        )
        .bind(cluster_id)
        .bind(run_id)
        .bind(&label)
        .bind(size)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("insert cluster: {e}"),
        })?;
    }

    // 3. Membership rows. Batch in chunks of 1000 to keep the query plan small.
    let chunk = 1000usize;
    let mut batch: Vec<(Uuid, Uuid)> = Vec::with_capacity(chunk);
    for (idx, comm) in assignments.iter().enumerate() {
        let cluster_id = cluster_id_map[comm];
        let claim_id = idx_to_id[&(idx as u32)];
        batch.push((claim_id, cluster_id));
        if batch.len() == chunk {
            flush_membership(&mut tx, &batch, run_id).await?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        flush_membership(&mut tx, &batch, run_id).await?;
    }

    tx.commit().await.map_err(|e| ApiError::InternalError {
        message: format!("commit tx: {e}"),
    })?;

    Ok(run_id)
}

#[cfg(feature = "db")]
async fn flush_membership(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    batch: &[(Uuid, Uuid)],
    run_id: Uuid,
) -> Result<(), ApiError> {
    let mut q =
        String::from("INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) VALUES ");
    let placeholders: Vec<String> = (0..batch.len())
        .map(|i| {
            let base = i * 3;
            format!("(${}, ${}, ${})", base + 1, base + 2, base + 3)
        })
        .collect();
    q.push_str(&placeholders.join(", "));

    let mut query = sqlx::query(&q);
    for (claim_id, cluster_id) in batch {
        query = query.bind(claim_id).bind(cluster_id).bind(run_id);
    }
    query
        .execute(&mut **tx)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("insert membership: {e}"),
        })?;
    Ok(())
}

/// Garbage-collect old `louvain_bridge` runs, keeping only the newest
/// `retain` runs by `completed_at`. Scoped by `algo` so we don't touch the
/// nightly epistemic Louvain runs.
#[cfg(feature = "db")]
async fn gc_bridge_runs(pool: &sqlx::PgPool, retain: u32) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        WITH old AS (
            SELECT run_id FROM graph_cluster_runs
            WHERE algo = $2
            ORDER BY completed_at DESC
            OFFSET $1
        )
        DELETE FROM graph_cluster_runs WHERE run_id IN (SELECT run_id FROM old)
        "#,
    )
    .bind(retain as i64)
    .bind(ALGO_LOUVAIN_BRIDGE)
    .execute(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("gc runs: {e}"),
    })?;

    // Cascade: clean up clusters + memberships whose run no longer exists.
    // (`graph_clusters` is not declared FK to `graph_cluster_runs`, and
    // `claim_cluster_membership.run_id` isn't either; only
    // `claim_cluster_membership.cluster_id` cascades. So we explicitly clean.)
    sqlx::query(
        "DELETE FROM claim_cluster_membership
         WHERE run_id NOT IN (SELECT run_id FROM graph_cluster_runs)",
    )
    .execute(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("gc memberships: {e}"),
    })?;
    sqlx::query(
        "DELETE FROM graph_clusters
         WHERE run_id NOT IN (SELECT run_id FROM graph_cluster_runs)",
    )
    .execute(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("gc clusters: {e}"),
    })?;

    Ok(())
}
