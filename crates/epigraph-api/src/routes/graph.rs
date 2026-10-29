//! /api/v1/graph/{overview, clusters/:id/expand, neighborhood} — read-only
//! endpoints over the latest successful clustering run.
//!
//! # Tenancy: 1 of this file's 4 raw-pool sites is converted
//!
//! Conversion shard 7. `expand` is ONE register site whose alias was spent on
//! FOUR statements, and all four now run on a viewer-stamped connection from
//! [`AppState::read_as`]: two inline run/cluster-metadata probes, the
//! viewer-spliced `GraphViewRepository::expand_cluster_nodes`, and the private
//! helper `fetch_subgraph_edges`.
//!
//! **`fetch_subgraph_edges` changed signature in place rather than gaining a
//! `_conn` primitive beside a pool-shaped wrapper.** Shard 6 needed the wrapper
//! for `graph_query_utils::load_subgraph` because that spelling had other
//! callers; this one has exactly one caller workspace-wide, so a wrapper would
//! have zero call sites, and a new route-layer primitive that no register
//! watches is a worse thing to create than a signature to change.
//!
//! **Only ONE of the four statements narrows, and that is stated rather than
//! implied.** `graph_cluster_runs`, `graph_clusters` and the `edges` read carry
//! no viewer predicate OF THEIR OWN; the first two carry no tenancy columns and
//! no RLS at migration head 92. The `edges` case is different in kind and the
//! difference matters: `fetch_subgraph_edges` runs
//! `WHERE source_id = ANY($1) AND target_id = ANY($1)` over `node_ids` produced
//! by the viewer-spliced `GraphViewRepository::expand_cluster_nodes`, so BOTH
//! endpoints are already restricted to the visible node set and the statement
//! needs no predicate of its own. A reader should not take the sentence above as
//! naming an unowned route-layer gap to re-file or to "fix". The suppression
//! `expand` offers comes from the node projection alone. In particular this
//! shard does NOT discharge
//! `F-edges-unfiltered` (`epigraph-db/src/repos/graph_view.rs`, owner: the
//! conversion tail). Converting an executor is not that entry's remedy, it
//! stays open, and nothing further about it is recorded here — see
//! `docs/tenancy/progress.json`.
//!
//! The other 3 sites — `overview`, `themes_overview`, `themes_expand` — are
//! routed GETs that hold no `Viewer` at all. Their owner is
//! `D-PR16-theme-cluster-viewer-scope`, an open entry that explicitly has no
//! control.
//!
//! [`AppState::read_as`]: crate::AppState::read_as

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::middleware::bearer::ViewerExtractor;
use crate::AppState;

/// Claim-level edge relationships exposed to the graph view.
///
/// Covers the dominant epistemic relationship types in the corpus —
/// hierarchical decomposition, corroboration, support/contradiction,
/// refinement, equivalence, evidence, etc. — plus their case variants.
///
/// This is intentionally *broader* than [`epigraph_jobs::cluster_graph::runner::EPISTEMIC_RELATIONSHIPS`]
/// (which is the clustering job's edge set). Rendering filters by readability;
/// clustering filters by what it weights as community-formation signal.
///
/// Excluded by design (kept out to keep the subgraph readable):
///   `same_source`, `produced` — provenance, not epistemic
///   `has_method_capability` — agent↔method, not claim↔claim
///   `section_follows`, `CONTAINS` — document structure
///   `DUPLICATE` — flagged for triage, not render
const GRAPH_VIEW_RELATIONSHIPS: &[&str] = &[
    // Hierarchical
    "decomposes_to",
    "refines",
    "REFINES",
    "specializes",
    // Corroboration / support
    "CORROBORATES",
    "corroborates",
    "supports",
    "SUPPORTS",
    "provides_evidence",
    "asserts",
    "enables",
    // Contradiction / challenge
    "refutes",
    "contradicts",
    "CONTRADICTS",
    "challenges",
    // Argument continuation
    "continues_argument",
    "elaborates",
    // Equivalence / variants
    "same_as",
    "equivalent_to",
    "analogous",
    "variant_of",
    "definitional_variant_of",
    // Generic / cross-reference
    "relates_to",
    "RELATES_TO",
    // Lineage / temporal
    "supersedes",
    "SUPERSEDES",
    "derived_from",
    "DERIVED_FROM",
    "derives_from",
];

/// Resolve the effective relationship allowlist for a single request.
///
/// `None` → default (`GRAPH_VIEW_RELATIONSHIPS`).
/// `Some("*")` or `Some("all")` → returns `None` (caller treats as "no filter").
/// Otherwise → comma-split, trimmed, non-empty entries.
///
/// Every entry is expanded to all its stored spellings
/// (`epigraph_core::edge::relationships::relationship_spellings`), so a
/// case-folded relationship (`supports`, `contradicts`, `corroborates`,
/// `refutes`) matches its legacy upper-case rows and its canonical lower-case
/// ones whichever spelling the caller named (backlog 3ce5e00c). Any other
/// entry stays the single exact spelling it was (`REFINES` != `refines`).
/// Order is kept and repeats are dropped.
fn resolve_relationship_filter(override_param: Option<&str>) -> Option<Vec<String>> {
    let entries: Vec<&str> = match override_param.map(str::trim).filter(|s| !s.is_empty()) {
        None => GRAPH_VIEW_RELATIONSHIPS.to_vec(),
        Some(s) if s == "*" || s.eq_ignore_ascii_case("all") => return None,
        Some(s) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect(),
    };
    let mut out: Vec<String> = Vec::with_capacity(entries.len());
    for spelling in entries
        .into_iter()
        .flat_map(epigraph_core::edge::relationships::relationship_spellings)
    {
        if !out.contains(&spelling) {
            out.push(spelling);
        }
    }
    Some(out)
}

#[derive(Debug, Serialize)]
pub struct OverviewResponse {
    pub run_id: Option<Uuid>,
    pub generated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub degraded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
    pub supernodes: Vec<Supernode>,
    pub cluster_edges: Vec<ClusterEdgeOut>,
    /// Count of every supernode in the run. Emitted only when the request
    /// carried a bound (see [`OverviewParams::is_bounded`]), so the default
    /// body keeps its exact shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_supernodes: Option<i64>,
    /// `true` when the bound actually cut supernodes or edges. Emitted only
    /// when the request carried a bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Supernode {
    pub cluster_id: Uuid,
    pub label: String,
    pub size: i32,
    pub mean_betp: Option<f64>,
    pub dominant_type: Option<String>,
    pub dominant_frame_id: Option<Uuid>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ClusterEdgeOut {
    pub a: Uuid,
    pub b: Uuid,
    pub weight: i32,
}

/// Query params of `GET /api/v1/graph/communities/overview`.
///
/// Every bound is opt-in: with none of `limit`, `min_size`, `include_edges`
/// or `edge_limit` present the handler returns today's unbounded body,
/// unchanged. `color_by` is not a bound.
///
/// The presence of ANY of those four keys selects the bounded response shape,
/// even when its value bounds nothing: `?include_edges=true` alone still adds
/// `total_supernodes` / `truncated` and orders edges by `weight DESC`. The
/// keys are typed, so a malformed value (`?limit=abc`, `?include_edges=1`)
/// is a 400 from the query extractor rather than being ignored.
#[derive(Debug, Deserialize)]
pub struct OverviewParams {
    #[serde(default)]
    pub color_by: Option<String>,
    /// Return only the top-N supernodes by `size DESC, id ASC`. Clamped to
    /// `1..=OVERVIEW_BOUND_MAX`.
    #[serde(default)]
    pub limit: Option<i64>,
    /// Drop supernodes whose `size` is below this. A FILTER, not a cap: with
    /// no `limit` every qualifying supernode and (without `edge_limit`) every
    /// edge among them still comes back, so a caller with a body budget must
    /// also pass `limit` and `edge_limit`.
    #[serde(default)]
    pub min_size: Option<i32>,
    /// `false` returns `cluster_edges: []` without reading them. Default `true`.
    #[serde(default)]
    pub include_edges: Option<bool>,
    /// Keep only the heaviest N edges (`weight DESC`). Clamped to
    /// `1..=OVERVIEW_BOUND_MAX`.
    #[serde(default)]
    pub edge_limit: Option<i64>,
}

/// Ceiling for `limit` and `edge_limit`, so a client cannot ask for a negative
/// or absurd `LIMIT`.
pub const OVERVIEW_BOUND_MAX: i64 = 10_000;

impl OverviewParams {
    /// Whether the request opted into the bounded response. `color_by` does
    /// not count: it never changed the body and must not start to.
    #[must_use]
    pub const fn is_bounded(&self) -> bool {
        self.limit.is_some()
            || self.min_size.is_some()
            || self.include_edges.is_some()
            || self.edge_limit.is_some()
    }
}

#[derive(Debug, Serialize)]
pub struct ExpandResponse {
    pub cluster_id: Uuid,
    pub truncated: bool,
    pub total_size: i64,
    pub nodes: Vec<NodeOut>,
    pub edges: Vec<EdgeOut>,
    /// Count of edges between the returned `nodes` whose `relationship` is
    /// not in `GRAPH_VIEW_RELATIONSHIPS` (e.g. `produced`, `same_source`,
    /// `CONTAINS`). Lets the GUI render "this node has N relationships not
    /// shown in the readability tier" instead of an ambiguous empty payload.
    pub filtered_edge_count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct NodeOut {
    pub id: Uuid,
    pub label: String,
    pub entity_type: String,
    pub pignistic_prob: Option<f64>,
    pub frame_id: Option<Uuid>,
    pub cluster_id: Option<Uuid>,
    pub conflict_k: Option<f64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EdgeOut {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
}

#[derive(Debug, Deserialize)]
pub struct ExpandParams {
    #[serde(default = "default_budget")]
    pub budget: i64,
    /// Override the default relationship allowlist for this request.
    /// Comma-separated list of relationship strings, or "*" / "all" for no filter.
    /// When absent, uses `GRAPH_VIEW_RELATIONSHIPS`.
    #[serde(default)]
    pub relationships: Option<String>,
}
const fn default_budget() -> i64 {
    200
}

#[derive(Debug, Deserialize)]
pub struct NeighborhoodParams {
    pub node_id: Uuid,
    #[serde(default = "default_hops")]
    pub hops: i64,
    #[serde(default = "default_budget")]
    pub budget: i64,
    /// Override the default relationship allowlist for this request.
    /// Comma-separated list of relationship strings, or "*" / "all" for no filter.
    /// When absent, uses `GRAPH_VIEW_RELATIONSHIPS`.
    #[serde(default)]
    pub relationships: Option<String>,
}
const fn default_hops() -> i64 {
    1
}

/// Cluster-level overview of the latest clustering run: supernodes and the
/// edges between them.
///
/// With no bound in the query string this returns EVERY supernode of the run
/// (`size DESC`) and EVERY cluster edge, exactly as before the bounds existed;
/// epigraph-gui reads that shape. A caller with a body budget (the Explorer
/// BFF) opts in with [`OverviewParams`]:
///
/// * `limit` / `min_size` select the top supernodes by `size DESC, id ASC`,
///   and then only the edges INDUCED among the returned supernodes come back;
/// * `edge_limit` keeps the heaviest edges (`weight DESC, cluster_a,
///   cluster_b`);
/// * `include_edges=false` skips the edge read entirely.
///
/// A bounded response also carries `total_supernodes` and `truncated`.
pub async fn overview(
    State(state): State<AppState>,
    Query(params): Query<OverviewParams>,
) -> Result<Json<OverviewResponse>, (axum::http::StatusCode, String)> {
    let pool: &PgPool = &state.db_pool;
    let latest: Option<(Uuid, chrono::DateTime<chrono::Utc>, bool)> = sqlx::query_as(
        "SELECT run_id, completed_at, degraded
         FROM graph_cluster_runs
         ORDER BY completed_at DESC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(internal)?;
    let Some((run_id, generated_at, degraded)) = latest else {
        return Ok(Json(OverviewResponse {
            run_id: None,
            generated_at: None,
            degraded: false,
            status: Some("no_clusters_computed"),
            supernodes: vec![],
            cluster_edges: vec![],
            total_supernodes: None,
            truncated: None,
        }));
    };
    if params.is_bounded() {
        return overview_bounded(pool, run_id, generated_at, degraded, &params).await;
    }
    let supernodes: Vec<Supernode> = sqlx::query_as::<_, Supernode>(
        "SELECT id AS cluster_id, label, size, mean_betp, dominant_type, dominant_frame_id
         FROM graph_clusters
         WHERE run_id = $1
         ORDER BY size DESC",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    let cluster_edges: Vec<ClusterEdgeOut> = sqlx::query_as::<_, ClusterEdgeOut>(
        "SELECT cluster_a AS a, cluster_b AS b, weight
         FROM cluster_edges
         WHERE run_id = $1",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    Ok(Json(OverviewResponse {
        run_id: Some(run_id),
        generated_at: Some(generated_at),
        degraded,
        status: None,
        supernodes,
        cluster_edges,
        total_supernodes: None,
        truncated: None,
    }))
}

/// The opt-in bounded body of [`overview`]. Runs on the caller's `pool` so the
/// handler keeps its single `.db_pool` site.
async fn overview_bounded(
    pool: &PgPool,
    run_id: Uuid,
    generated_at: chrono::DateTime<chrono::Utc>,
    degraded: bool,
    params: &OverviewParams,
) -> Result<Json<OverviewResponse>, (axum::http::StatusCode, String)> {
    let clamp = |n: i64| n.clamp(1, OVERVIEW_BOUND_MAX);
    let node_limit = params.limit.map(clamp);
    // `LIMIT NULL` is `LIMIT ALL` in Postgres.
    let supernodes: Vec<Supernode> = sqlx::query_as::<_, Supernode>(
        "SELECT id AS cluster_id, label, size, mean_betp, dominant_type, dominant_frame_id
         FROM graph_clusters
         WHERE run_id = $1 AND ($2::int IS NULL OR size >= $2)
         ORDER BY size DESC, id ASC
         LIMIT $3",
    )
    .bind(run_id)
    .bind(params.min_size)
    .bind(node_limit)
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    let (total,): (i64,) = sqlx::query_as("SELECT count(*) FROM graph_clusters WHERE run_id = $1")
        .bind(run_id)
        .fetch_one(pool)
        .await
        .map_err(internal)?;
    let nodes_cut = i64::try_from(supernodes.len()).unwrap_or(i64::MAX) < total;

    let mut edges_cut = false;
    let cluster_edges = if params.include_edges.unwrap_or(true) {
        // Restrict to the induced subgraph only when the supernode set was
        // actually bounded; with `edge_limit` alone every cluster is returned
        // and shipping every id as an array would be pure overhead.
        let induced: Option<Vec<Uuid>> = (params.limit.is_some() || params.min_size.is_some())
            .then(|| supernodes.iter().map(|s| s.cluster_id).collect());
        let edge_limit = params.edge_limit.map(clamp);
        // One row past the cap distinguishes "cut" from "exactly fit".
        let mut edges: Vec<ClusterEdgeOut> = sqlx::query_as::<_, ClusterEdgeOut>(
            "SELECT cluster_a AS a, cluster_b AS b, weight
             FROM cluster_edges
             WHERE run_id = $1
               AND ($2::uuid[] IS NULL OR (cluster_a = ANY($2) AND cluster_b = ANY($2)))
             ORDER BY weight DESC, cluster_a, cluster_b
             LIMIT $3",
        )
        .bind(run_id)
        .bind(induced)
        .bind(edge_limit.map(|n| n + 1))
        .fetch_all(pool)
        .await
        .map_err(internal)?;
        if let Some(cap) = edge_limit.and_then(|n| usize::try_from(n).ok()) {
            if edges.len() > cap {
                edges.truncate(cap);
                edges_cut = true;
            }
        }
        edges
    } else {
        vec![]
    };
    Ok(Json(OverviewResponse {
        run_id: Some(run_id),
        generated_at: Some(generated_at),
        degraded,
        status: None,
        supernodes,
        cluster_edges,
        total_supernodes: Some(total),
        truncated: Some(nodes_cut || edges_cut),
    }))
}

/// Expand one cluster into its member claims.
///
/// The node projection is read as the caller's `Viewer`. `label` here is
/// `claims.content` verbatim, so before PR-07 this endpoint returned other
/// tenants' claim text to any authenticated principal that knew (or guessed,
/// from `/graph/overview`) a cluster id. The surrounding run/cluster metadata
/// is not viewer-filtered — those tables carry no tenancy columns; see
/// `GraphViewRepository`'s module docs.
pub async fn expand(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(cluster_id): Path<Uuid>,
    Query(params): Query<ExpandParams>,
) -> Result<Json<ExpandResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    // ONE viewer-stamped connection for all four statements this handler runs:
    // the two run/cluster metadata probes below, `expand_cluster_nodes`, and
    // `fetch_subgraph_edges`. Only the node projection is viewer-filtered —
    // `graph_cluster_runs`, `graph_clusters` and the `edges` read carry no
    // predicate here, and stamping the connection does not give them one. What
    // the shared connection buys is that the filtered read runs under the same
    // tenancy context as the unfiltered metadata it is joined to in the
    // response, rather than under a different one.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "expand",
            "could not acquire a viewer-stamped connection"
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to acquire a scoped connection".to_string(),
        )
    })?;
    let latest_run: Option<(Uuid,)> =
        sqlx::query_as("SELECT run_id FROM graph_cluster_runs ORDER BY completed_at DESC LIMIT 1")
            .fetch_optional(&mut *read)
            .await
            .map_err(internal)?;
    let Some((run_id,)) = latest_run else {
        return Err((StatusCode::NOT_FOUND, "no completed run".into()));
    };
    let cluster_exists: Option<(i64,)> =
        sqlx::query_as("SELECT size::bigint FROM graph_clusters WHERE id = $1 AND run_id = $2")
            .bind(cluster_id)
            .bind(run_id)
            .fetch_optional(&mut *read)
            .await
            .map_err(internal)?;
    let Some((total_size,)) = cluster_exists else {
        return Err((StatusCode::NOT_FOUND, "cluster not in latest run".into()));
    };

    let budget = params.budget.max(1);
    let allowlist = resolve_relationship_filter(params.relationships.as_deref());
    // For ordering by allowlisted-degree, fall back to the full default list
    // when the request opts into "no filter" (i.e. `*`/`all`); otherwise the
    // ORDER BY collapses to all-zero and ordering becomes arbitrary.
    let degree_list: Vec<String> = match allowlist.as_deref() {
        Some(list) => list.to_vec(),
        None => GRAPH_VIEW_RELATIONSHIPS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    };
    let nodes: Vec<NodeOut> = epigraph_db::GraphViewRepository::expand_cluster_nodes(
        &mut *read,
        &viewer,
        cluster_id,
        run_id,
        &degree_list,
        budget,
    )
    .await
    .map_err(internal_db)?
    .into_iter()
    .map(|r| NodeOut {
        id: r.id,
        label: r.label,
        entity_type: r.entity_type,
        pignistic_prob: r.pignistic_prob,
        frame_id: r.frame_id,
        cluster_id: r.cluster_id,
        conflict_k: r.conflict_k,
    })
    .collect();

    let node_ids: Vec<Uuid> = nodes.iter().map(|n| n.id).collect();
    let (edges, filtered_edge_count) =
        fetch_subgraph_edges(&mut read, &node_ids, allowlist.as_deref()).await?;

    // PR-07: `truncated` means "the budget cut this response short", so it is
    // derived from the budget, not from `graph_clusters.size`.
    //
    // `total_size` is raw cluster metadata (`graph_clusters` carries no tenancy
    // columns), while `nodes` is now viewer-filtered. `total_size > nodes.len()`
    // therefore reports `true` for a response that is complete *for this
    // viewer*, and a client paging on the flag would page forever without ever
    // seeing another row. The difference `total_size - nodes.len()` was also an
    // exact count of how many claims in the cluster the caller cannot see.
    Ok(Json(ExpandResponse {
        cluster_id,
        truncated: nodes.len() as i64 >= budget,
        total_size,
        nodes,
        edges,
        filtered_edge_count,
    }))
}

pub async fn neighborhood(
    State(_state): State<AppState>,
    Query(_params): Query<NeighborhoodParams>,
) -> Result<Json<()>, (axum::http::StatusCode, String)> {
    Err((
        axum::http::StatusCode::GONE,
        "GET /api/v1/graph/neighborhood is deprecated; use /graph/themes/{theme_id}/expand and /graph/neighborhoods/{neighborhood_id}/expand".into(),
    ))
}

/// Fetch edges *between* the given node ids, partitioned into:
/// - edges whose `relationship` is in `rel_list` (returned as `edges`)
/// - edges whose `relationship` is *not* in `rel_list` (returned as count)
///
/// Single round-trip: tags each row with an `is_allowed` flag computed in
/// the SELECT list, then partitions in Rust.
///
/// Takes a `&mut PgConnection` rather than a `&PgPool` so that its statement
/// runs on the same viewer-stamped connection as the rest of [`expand`], its
/// ONLY caller workspace-wide. Changed in place rather than split into a
/// `_conn` primitive beside a pool-shaped wrapper: with one caller a wrapper
/// would have zero call sites, and a route-layer helper that no register
/// watches is a worse thing to create than a signature to change.
async fn fetch_subgraph_edges(
    conn: &mut sqlx::PgConnection,
    node_ids: &[Uuid],
    rel_list: Option<&[String]>,
) -> Result<(Vec<EdgeOut>, i64), (axum::http::StatusCode, String)> {
    if node_ids.is_empty() {
        return Ok((Vec::new(), 0));
    }
    let rows: Vec<(Uuid, Uuid, String, bool)> = match rel_list {
        Some(allowlist) => {
            sqlx::query_as(
                "SELECT source_id, target_id, relationship, \
                    (relationship = ANY($2)) AS is_allowed \
             FROM edges \
             WHERE source_id = ANY($1) AND target_id = ANY($1)",
            )
            .bind(node_ids)
            .bind(allowlist)
            .fetch_all(&mut *conn)
            .await
        }
        None => {
            sqlx::query_as(
                "SELECT source_id, target_id, relationship, true AS is_allowed \
             FROM edges \
             WHERE source_id = ANY($1) AND target_id = ANY($1)",
            )
            .bind(node_ids)
            .fetch_all(&mut *conn)
            .await
        }
    }
    .map_err(internal)?;

    let mut edges = Vec::new();
    let mut filtered: i64 = 0;
    for (source, target, relationship, is_allowed) in rows {
        if is_allowed {
            edges.push(EdgeOut {
                source,
                target,
                relationship,
            });
        } else {
            filtered += 1;
        }
    }
    Ok((edges, filtered))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ThemeOut {
    pub id: Uuid,
    pub label: String,
    pub claim_count: i32,
}

#[derive(Debug, Serialize)]
pub struct ThemesOverviewResponse {
    pub themes: Vec<ThemeOut>,
}

pub async fn themes_overview(
    State(state): State<AppState>,
) -> Result<Json<ThemesOverviewResponse>, (axum::http::StatusCode, String)> {
    let pool: &PgPool = &state.db_pool;
    let themes: Vec<ThemeOut> = sqlx::query_as::<_, ThemeOut>(
        "SELECT id, label, claim_count FROM claim_themes ORDER BY claim_count DESC, label ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(internal)?;
    Ok(Json(ThemesOverviewResponse { themes }))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct NeighborhoodOut {
    pub id: Uuid,
    pub label: String,
    pub size: i32,
    pub mean_betp: Option<f64>,
    pub dominant_frame_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct NeighborhoodEdgeOut {
    pub a: Uuid,
    pub b: Uuid,
    pub weight: f64,
}

#[derive(Debug, Serialize)]
pub struct ThemeExpandResponse {
    pub theme_id: Uuid,
    pub truncated: bool,
    pub neighborhoods: Vec<NeighborhoodOut>,
    pub neighborhood_edges: Vec<NeighborhoodEdgeOut>,
}

pub async fn themes_expand(
    State(state): State<AppState>,
    Path(theme_id): Path<Uuid>,
    Query(params): Query<ExpandParams>,
) -> Result<Json<ThemeExpandResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    let pool: &PgPool = &state.db_pool;

    let exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM claim_themes WHERE id = $1")
        .bind(theme_id)
        .fetch_optional(pool)
        .await
        .map_err(internal)?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "theme not found".into()));
    }

    let latest_run: Option<(Uuid,)> =
        sqlx::query_as("SELECT run_id FROM graph_cluster_runs ORDER BY completed_at DESC LIMIT 1")
            .fetch_optional(pool)
            .await
            .map_err(internal)?;
    let Some((run_id,)) = latest_run else {
        return Ok(Json(synthesize_pre_run_response(theme_id)));
    };

    let budget = params.budget.max(1);
    let neighborhoods: Vec<NeighborhoodOut> = sqlx::query_as::<_, NeighborhoodOut>(
        "SELECT id, label, size, mean_betp, dominant_frame_id \
         FROM graph_neighborhoods \
         WHERE run_id = $1 AND theme_id = $2 \
         ORDER BY size DESC LIMIT $3",
    )
    .bind(run_id)
    .bind(theme_id)
    .bind(budget)
    .fetch_all(pool)
    .await
    .map_err(internal)?;

    if neighborhoods.is_empty() {
        return Ok(Json(synthesize_pre_run_response(theme_id)));
    }

    let nbr_id_set: Vec<Uuid> = neighborhoods.iter().map(|n| n.id).collect();
    let edges: Vec<NeighborhoodEdgeOut> = sqlx::query_as::<_, (Uuid, Uuid, f64)>(
        "SELECT neighborhood_a, neighborhood_b, weight FROM neighborhood_edges \
         WHERE run_id = $1 AND neighborhood_a = ANY($2) AND neighborhood_b = ANY($2)",
    )
    .bind(run_id)
    .bind(&nbr_id_set)
    .fetch_all(pool)
    .await
    .map_err(internal)?
    .into_iter()
    .map(|(a, b, w)| NeighborhoodEdgeOut { a, b, weight: w })
    .collect();

    Ok(Json(ThemeExpandResponse {
        theme_id,
        truncated: false,
        neighborhoods,
        neighborhood_edges: edges,
    }))
}

fn synthesize_pre_run_response(theme_id: Uuid) -> ThemeExpandResponse {
    ThemeExpandResponse {
        theme_id,
        truncated: false,
        neighborhoods: vec![NeighborhoodOut {
            id: theme_id,
            label: "synthetic".into(),
            size: 0,
            mean_betp: None,
            dominant_frame_id: None,
        }],
        neighborhood_edges: vec![],
    }
}

/// A 500 for a failed statement. The driver's error is LOGGED, never sent:
/// the body is [`crate::errors::INTERNAL_ERROR_BODY`], as for every
/// `ApiError::InternalError` (F-route-error-text-remainder).
fn internal(e: sqlx::Error) -> (axum::http::StatusCode, String) {
    tracing::error!(target: "api.internal_error", route = "graph", detail = %e, "internal error");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        crate::errors::INTERNAL_ERROR_BODY.to_string(),
    )
}

/// `internal` for the repo layer, which surfaces `DbError` rather than a raw
/// `sqlx::Error`.
fn internal_db(e: epigraph_db::DbError) -> (axum::http::StatusCode, String) {
    tracing::error!(target: "api.internal_error", route = "graph", detail = %e, "internal error");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        crate::errors::INTERNAL_ERROR_BODY.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every failed statement in this file answers through `internal` /
    /// `internal_db`; neither may hand the driver's error text to the caller
    /// (F-route-error-text-remainder).
    #[test]
    fn internal_answers_never_carry_the_driver_error() {
        let driver = "relation \"graph_runs\" does not exist";
        for (status, body) in [
            internal(sqlx::Error::Protocol(driver.to_string())),
            internal_db(epigraph_db::DbError::QueryFailed {
                source: sqlx::Error::Protocol(driver.to_string()),
            }),
        ] {
            assert_eq!(status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            assert!(!body.contains("graph_runs"), "{body}");
            assert!(!body.contains("does not exist"), "{body}");
            assert_eq!(body, crate::errors::INTERNAL_ERROR_BODY);
        }
    }

    /// Relationship types we expect the graph view to traverse.
    /// Adding a row here without adding the matching string to
    /// `GRAPH_VIEW_RELATIONSHIPS` will fail this test, which is the point:
    /// the constant is the single source of truth for what the GUI's
    /// expand-this-node action will surface.
    const EXPECTED_INCLUDED: &[&str] = &[
        // Hierarchical
        "decomposes_to",
        "refines",
        "REFINES",
        "specializes",
        // Corroboration / support
        "CORROBORATES",
        "corroborates",
        "supports",
        "SUPPORTS",
        "provides_evidence",
        "asserts",
        "enables",
        // Contradiction / challenge
        "refutes",
        "contradicts",
        "CONTRADICTS",
        "challenges",
        // Argument continuation
        "continues_argument",
        "elaborates",
        // Equivalence / variants
        "same_as",
        "equivalent_to",
        "analogous",
        "variant_of",
        "definitional_variant_of",
        // Generic / cross-reference
        "relates_to",
        "RELATES_TO",
        // Lineage / temporal
        "supersedes",
        "SUPERSEDES",
        "derived_from",
        "DERIVED_FROM",
        "derives_from",
    ];

    /// Relationships the design explicitly excludes — keep them out so a
    /// future "just add everything" refactor doesn't pollute the subgraph.
    const EXPECTED_EXCLUDED: &[&str] = &[
        "same_source",
        "produced",
        "has_method_capability",
        "section_follows",
        "CONTAINS",
        "DUPLICATE",
    ];

    #[test]
    fn graph_view_allowlist_contains_expected_relationships() {
        for rel in EXPECTED_INCLUDED {
            assert!(
                GRAPH_VIEW_RELATIONSHIPS.contains(rel),
                "missing from allowlist: {rel}",
            );
        }
    }

    #[test]
    fn graph_view_allowlist_excludes_design_excluded_relationships() {
        for rel in EXPECTED_EXCLUDED {
            assert!(
                !GRAPH_VIEW_RELATIONSHIPS.contains(rel),
                "should not be in allowlist: {rel}",
            );
        }
    }

    #[test]
    fn expand_response_serializes_filtered_count() {
        let r = ExpandResponse {
            cluster_id: Uuid::nil(),
            truncated: false,
            total_size: 1,
            nodes: Vec::new(),
            edges: Vec::new(),
            filtered_edge_count: 7,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["filtered_edge_count"], 7);
    }

    #[test]
    fn resolve_filter_none_returns_default_allowlist() {
        let result = resolve_relationship_filter(None).unwrap();
        // Pick any well-known default from GRAPH_VIEW_RELATIONSHIPS to avoid coupling
        // this test to the full set. Either "decomposes_to" or "supports" is a stable
        // choice — see the constant definition near the top of graph.rs.
        assert!(result.contains(&"decomposes_to".to_string()));
        assert!(result.contains(&"supports".to_string()));
    }

    #[test]
    fn resolve_filter_empty_string_falls_back_to_default() {
        let result = resolve_relationship_filter(Some("")).unwrap();
        assert!(result.contains(&"decomposes_to".to_string()));
    }

    #[test]
    fn resolve_filter_whitespace_only_falls_back_to_default() {
        let result = resolve_relationship_filter(Some("   ")).unwrap();
        assert!(result.contains(&"decomposes_to".to_string()));
    }

    #[test]
    fn resolve_filter_star_returns_none() {
        assert!(resolve_relationship_filter(Some("*")).is_none());
    }

    #[test]
    fn resolve_filter_all_case_insensitive() {
        assert!(resolve_relationship_filter(Some("ALL")).is_none());
        assert!(resolve_relationship_filter(Some("All")).is_none());
        assert!(resolve_relationship_filter(Some("all")).is_none());
    }

    #[test]
    fn resolve_filter_expands_a_folded_relationship_to_both_spellings() {
        // Backlog 3ce5e00c: `?relationships=SUPPORTS` used to bind the one
        // spelling, so every canonical lower-case `supports` edge was counted
        // as filtered out, and `?relationships=supports` hid the legacy rows.
        for asked in ["SUPPORTS", "supports", "Supports"] {
            assert_eq!(
                resolve_relationship_filter(Some(asked)).unwrap(),
                vec!["supports".to_string(), "SUPPORTS".to_string()],
                "{asked}"
            );
        }
        // Mixed with an unfolded entry; repeats collapse.
        assert_eq!(
            resolve_relationship_filter(Some("contradicts,REFINES,CONTRADICTS")).unwrap(),
            vec![
                "contradicts".to_string(),
                "CONTRADICTS".to_string(),
                "REFINES".to_string()
            ]
        );
        // The default allow-list covers both spellings of every folded one.
        let default = resolve_relationship_filter(None).unwrap();
        for rel in ["supports", "contradicts", "corroborates", "refutes"] {
            assert!(default.contains(&rel.to_string()), "{rel}");
            assert!(default.contains(&rel.to_ascii_uppercase()), "{rel}");
        }
    }

    #[test]
    fn resolve_filter_comma_separated_trims_and_filters_empty() {
        let result =
            resolve_relationship_filter(Some("produced, same_source ,  ,CONTAINS")).unwrap();
        assert_eq!(
            result,
            vec![
                "produced".to_string(),
                "same_source".to_string(),
                "CONTAINS".to_string()
            ]
        );
    }
}
