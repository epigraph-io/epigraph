//! Per-theme Louvain pass: builds a Louvain decomposition of each
//! semantic theme's atomic-claim subgraph, persisted to `graph_neighborhoods`,
//! `claim_neighborhood_membership`, and `neighborhood_edges`.
//!
//! ## What is "atomic"?
//!
//! A claim is included in the theme subgraph when it:
//!   - has `claims.theme_id = <theme>`, AND
//!   - has **no outgoing** `decomposes_to` edge (i.e. it is a leaf in the
//!     decomposition tree — an atom or a standalone claim).
//!
//! This deliberately matches how the visualizer defines an "atom": the
//! finest-grained epistemic unit that has no further sub-structure.
//!
//! ## Edge weights
//!
//! Edge weight = `forward_strength` from `edge_to_factor_type(relationship)`
//! (see migration 011). Edges whose `forward_strength = 0` (e.g. CONTRADICTS,
//! DERIVED_FROM) contribute nothing to the modularity signal — the Louvain
//! filter `weight > 0` discards them before they reach the algorithm.
//!
//! ## Skip thresholds
//!
//! When a theme has fewer than `SKIP_THRESHOLD_NODES` nodes **or** fewer than
//! `SKIP_THRESHOLD_EDGES` positive-weight edges we skip Louvain and produce a
//! **single synthetic neighborhood** holding all claims.  This avoids spending
//! Louvain iterations on trivially small subgraphs.
//!
//! Both thresholds default to **50 nodes** and **10 edges**.  When a theme has
//! fewer than `skip_threshold_nodes` nodes **or** fewer than
//! `skip_threshold_edges` positive-weight edges we skip Louvain and produce a
//! single synthetic neighborhood.  These values are overridable via `Config`
//! so that integration tests can set them to 0 and always exercise the Louvain
//! path without needing large fixtures.

use std::collections::HashMap;

use sqlx::PgPool;
use uuid::Uuid;

use super::louvain::{louvain, LouvainInput};

/// Configuration for the per-theme neighborhood pass.
#[derive(Debug)]
pub struct Config {
    pub resolution: f64,
    /// Minimum number of in-theme nodes required to run Louvain.
    /// Themes with fewer nodes than this emit a single synthetic neighborhood.
    pub skip_threshold_nodes: usize,
    /// Minimum number of positive-weight edges required to run Louvain.
    /// Themes with fewer edges than this emit a single synthetic neighborhood.
    pub skip_threshold_edges: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            resolution: 1.0,
            skip_threshold_nodes: SKIP_THRESHOLD_NODES,
            skip_threshold_edges: SKIP_THRESHOLD_EDGES,
        }
    }
}

/// Minimum number of in-theme nodes required to run Louvain (production default).
/// Below this, we emit a single synthetic neighborhood.
pub const SKIP_THRESHOLD_NODES: usize = 50;

/// Minimum number of positive-weight edges required to run Louvain (production default).
/// Below this, we emit a single synthetic neighborhood.
pub const SKIP_THRESHOLD_EDGES: usize = 10;

#[derive(Debug, sqlx::FromRow)]
struct ThemeRow {
    id: Uuid,
}

#[derive(Debug, sqlx::FromRow)]
struct AtomRow {
    id: Uuid,
    pignistic_prob: Option<f64>,
    frame_id: Option<Uuid>,
}

#[derive(Debug, sqlx::FromRow)]
struct WeightedEdgeRow {
    source: Uuid,
    target: Uuid,
    weight: f64,
}

/// Run the neighborhood detection pass for themes.
///
/// When `theme_ids` is `None`, all themes in `claim_themes` are processed.
/// When `Some(ids)`, only the specified themes are processed.  Scoping by
/// theme is useful for incremental re-runs (e.g., after a new ingest) and
/// for integration tests running against a live DB that has many themes.
///
/// For each theme, fetches its atomic claims, runs Louvain community detection
/// over the SUPPORTS/positive-weight subgraph, and writes the results to:
/// - `graph_neighborhoods` (one row per community)
/// - `claim_neighborhood_membership` (one row per claim)
/// - `neighborhood_edges` (one row per cross-neighborhood edge with weight > 0)
///
/// An error in one theme is logged and skipped; other themes continue.
pub async fn run_theme_neighborhoods(
    pool: &PgPool,
    run_id: Uuid,
    cfg: &Config,
    theme_ids: Option<&[Uuid]>,
) -> Result<(), sqlx::Error> {
    let themes: Vec<ThemeRow> = match theme_ids {
        None => {
            sqlx::query_as("SELECT id FROM claim_themes")
                .fetch_all(pool)
                .await?
        }
        Some(ids) => {
            sqlx::query_as("SELECT id FROM claim_themes WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(pool)
                .await?
        }
    };

    for theme in themes {
        if let Err(e) = run_one_theme(pool, run_id, theme.id, cfg).await {
            tracing::warn!(
                theme_id = %theme.id,
                error = ?e,
                "neighborhood pass failed for theme; skipping"
            );
        }
    }
    Ok(())
}

/// Run the neighborhood detection pass for a single theme.
async fn run_one_theme(
    pool: &PgPool,
    run_id: Uuid,
    theme_id: Uuid,
    cfg: &Config,
) -> Result<(), sqlx::Error> {
    // Fetch atomic/standalone claims: those in this theme that have no
    // outgoing `decomposes_to` edge (i.e. they are leaves in the claim tree).
    // Uses DISTINCT ON (c.id) to collapse multiple frame memberships to one row.
    let atoms: Vec<AtomRow> = sqlx::query_as::<_, AtomRow>(
        r#"
        SELECT DISTINCT ON (c.id) c.id, c.pignistic_prob, cf.frame_id
        FROM claims c
        LEFT JOIN claim_frames cf ON cf.claim_id = c.id
        WHERE c.theme_id = $1
          AND NOT EXISTS (
              SELECT 1 FROM edges e
              WHERE e.source_id = c.id
                AND e.relationship = 'decomposes_to'
          )
        ORDER BY c.id, cf.frame_id
        "#,
    )
    .bind(theme_id)
    .fetch_all(pool)
    .await?;

    if atoms.is_empty() {
        return Ok(());
    }

    let atom_ids: Vec<Uuid> = atoms.iter().map(|a| a.id).collect();

    // Pull positive-weight edges between in-theme atoms.
    // Uses a LATERAL join on edge_to_factor_type() to evaluate the function
    // once per row (cheaper than a correlated subquery).
    let edges: Vec<WeightedEdgeRow> = sqlx::query_as::<_, WeightedEdgeRow>(
        r#"
        SELECT e.source_id AS source,
               e.target_id AS target,
               ft.forward_strength AS weight
        FROM edges e
        LEFT JOIN LATERAL edge_to_factor_type(e.relationship) ft ON true
        WHERE e.source_id = ANY($1)
          AND e.target_id = ANY($1)
          AND ft.forward_strength > 0
        "#,
    )
    .bind(&atom_ids)
    .fetch_all(pool)
    .await?;

    // Below threshold: emit a single synthetic neighborhood.
    if atoms.len() < cfg.skip_threshold_nodes || edges.len() < cfg.skip_threshold_edges {
        return write_single_neighborhood(pool, run_id, theme_id, &atoms).await;
    }

    // Map UUIDs → dense u32 indices for Louvain.
    let mut id_to_idx: HashMap<Uuid, u32> = HashMap::with_capacity(atoms.len());
    for (i, a) in atoms.iter().enumerate() {
        id_to_idx.insert(a.id, i as u32);
    }

    let mut weighted_pairs: Vec<(u32, u32, f64)> = Vec::with_capacity(edges.len());
    for e in &edges {
        let (Some(&a), Some(&b)) = (id_to_idx.get(&e.source), id_to_idx.get(&e.target)) else {
            continue;
        };
        if a == b {
            continue;
        }
        weighted_pairs.push((a, b, e.weight));
    }

    let result = louvain(&LouvainInput {
        node_count: atoms.len(),
        edges: weighted_pairs,
        resolution: cfg.resolution,
    })
    .map_err(|e| sqlx::Error::Protocol(format!("louvain: {e}")))?;

    write_neighborhoods(pool, run_id, theme_id, &atoms, &result.assignments).await?;
    write_neighborhood_edges(pool, run_id, theme_id).await?;
    Ok(())
}

/// Emit a single neighborhood containing all atoms (used when the subgraph is
/// too small for Louvain to be meaningful).
async fn write_single_neighborhood(
    pool: &PgPool,
    run_id: Uuid,
    theme_id: Uuid,
    atoms: &[AtomRow],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let neighborhood_id = Uuid::new_v4();
    let (mean_betp, dominant_frame) = aggregate_neighborhood(atoms, |_| true);

    sqlx::query(
        r#"INSERT INTO graph_neighborhoods
           (id, run_id, theme_id, label, size, mean_betp, dominant_frame_id)
           VALUES ($1, $2, $3, 'neighborhood-1', $4, $5, $6)"#,
    )
    .bind(neighborhood_id)
    .bind(run_id)
    .bind(theme_id)
    .bind(atoms.len() as i32)
    .bind(mean_betp)
    .bind(dominant_frame)
    .execute(&mut *tx)
    .await?;

    for a in atoms {
        sqlx::query(
            "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id)
             VALUES ($1, $2, $3)",
        )
        .bind(run_id)
        .bind(a.id)
        .bind(neighborhood_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

/// Write Louvain community results to the neighborhoods tables.
async fn write_neighborhoods(
    pool: &PgPool,
    run_id: Uuid,
    theme_id: Uuid,
    atoms: &[AtomRow],
    assignments: &[u32],
) -> Result<(), sqlx::Error> {
    let mut groups: HashMap<u32, Vec<usize>> = HashMap::new();
    for (idx, comm) in assignments.iter().enumerate() {
        groups.entry(*comm).or_default().push(idx);
    }

    let mut tx = pool.begin().await?;
    for (n_idx, (comm, members)) in groups.iter().enumerate() {
        let neighborhood_id = Uuid::new_v4();
        let (mean_betp, dominant_frame) = aggregate_neighborhood(atoms, |i| members.contains(&i));
        let label = dominant_frame
            .map(|f| f.to_string())
            .unwrap_or_else(|| format!("neighborhood-{}", n_idx + 1));

        sqlx::query(
            r#"INSERT INTO graph_neighborhoods
               (id, run_id, theme_id, label, size, mean_betp, dominant_frame_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(neighborhood_id)
        .bind(run_id)
        .bind(theme_id)
        .bind(label)
        .bind(members.len() as i32)
        .bind(mean_betp)
        .bind(dominant_frame)
        .execute(&mut *tx)
        .await?;

        for &m in members {
            sqlx::query(
                "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id)
                 VALUES ($1, $2, $3)",
            )
            .bind(run_id)
            .bind(atoms[m].id)
            .bind(neighborhood_id)
            .execute(&mut *tx)
            .await?;
        }

        // Suppress unused-variable warning for comm — only used as map key.
        let _ = comm;
    }
    tx.commit().await
}

/// Compute inter-neighborhood edges by summing forward_strength of all
/// cross-neighborhood edges for this (run_id, theme_id).
///
/// Uses `LEAST`/`GREATEST` to canonicalize the (a, b) pair so that the
/// `neighborhood_edges_check` constraint `neighborhood_a < neighborhood_b`
/// is always satisfied.
///
/// The lateral join on `edge_to_factor_type` evaluates the function once per
/// row (not once per aggregate call), avoiding the double-evaluation that a
/// correlated subquery inside `SUM(...)` would cause.
async fn write_neighborhood_edges(
    pool: &PgPool,
    run_id: Uuid,
    theme_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO neighborhood_edges (run_id, neighborhood_a, neighborhood_b, weight)
        SELECT $1::uuid                                          AS run_id,
               LEAST(ma.neighborhood_id, mb.neighborhood_id)    AS a,
               GREATEST(ma.neighborhood_id, mb.neighborhood_id) AS b,
               SUM(COALESCE(ft.forward_strength, 0))            AS weight
        FROM edges e
        JOIN claim_neighborhood_membership ma
          ON ma.claim_id = e.source_id AND ma.run_id = $1
        JOIN claim_neighborhood_membership mb
          ON mb.claim_id = e.target_id AND mb.run_id = $1
        JOIN graph_neighborhoods na
          ON na.id = ma.neighborhood_id AND na.theme_id = $2
        JOIN graph_neighborhoods nb
          ON nb.id = mb.neighborhood_id AND nb.theme_id = $2
        LEFT JOIN LATERAL edge_to_factor_type(e.relationship) ft ON true
        WHERE ma.neighborhood_id <> mb.neighborhood_id
        GROUP BY 1, 2, 3
        HAVING SUM(COALESCE(ft.forward_strength, 0)) > 0
        "#,
    )
    .bind(run_id)
    .bind(theme_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Compute mean pignistic probability and dominant frame for a subset of atoms.
fn aggregate_neighborhood<F: Fn(usize) -> bool>(
    atoms: &[AtomRow],
    member: F,
) -> (Option<f64>, Option<Uuid>) {
    let mut sum = 0.0_f64;
    let mut n = 0i32;
    let mut frame_counts: HashMap<Uuid, i32> = HashMap::new();

    for (i, a) in atoms.iter().enumerate() {
        if !member(i) {
            continue;
        }
        if let Some(b) = a.pignistic_prob {
            sum += b;
            n += 1;
        }
        if let Some(f) = a.frame_id {
            *frame_counts.entry(f).or_insert(0) += 1;
        }
    }

    let mean_betp = if n > 0 { Some(sum / n as f64) } else { None };
    let dominant = frame_counts
        .iter()
        .max_by_key(|(_, c)| **c)
        .map(|(k, _)| *k);
    (mean_betp, dominant)
}
