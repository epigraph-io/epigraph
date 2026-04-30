//! /api/v1/graph/{overview, clusters/:id/expand, neighborhood} — read-only
//! endpoints over the latest successful clustering run.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

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
fn resolve_relationship_filter(override_param: Option<&str>) -> Option<Vec<String>> {
    match override_param.map(str::trim).filter(|s| !s.is_empty()) {
        None => Some(
            GRAPH_VIEW_RELATIONSHIPS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        ),
        Some(s) if s == "*" || s.eq_ignore_ascii_case("all") => None,
        Some(s) => Some(
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        ),
    }
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

#[derive(Debug, Deserialize)]
pub struct OverviewParams {
    #[serde(default)]
    pub color_by: Option<String>,
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

pub async fn overview(
    State(state): State<AppState>,
    Query(_params): Query<OverviewParams>,
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
        }));
    };
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
    }))
}

pub async fn expand(
    State(state): State<AppState>,
    Path(cluster_id): Path<Uuid>,
    Query(params): Query<ExpandParams>,
) -> Result<Json<ExpandResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    let pool: &PgPool = &state.db_pool;
    let latest_run: Option<(Uuid,)> =
        sqlx::query_as("SELECT run_id FROM graph_cluster_runs ORDER BY completed_at DESC LIMIT 1")
            .fetch_optional(pool)
            .await
            .map_err(internal)?;
    let Some((run_id,)) = latest_run else {
        return Err((StatusCode::NOT_FOUND, "no completed run".into()));
    };
    let cluster_exists: Option<(i64,)> =
        sqlx::query_as("SELECT size::bigint FROM graph_clusters WHERE id = $1 AND run_id = $2")
            .bind(cluster_id)
            .bind(run_id)
            .fetch_optional(pool)
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
    let nodes: Vec<NodeOut> = sqlx::query_as::<_, NodeOut>(
        "WITH degree AS (
            SELECT m.claim_id, COUNT(e.*) AS deg
            FROM claim_cluster_membership m
            LEFT JOIN edges e ON (e.source_id = m.claim_id OR e.target_id = m.claim_id)
                              AND e.relationship = ANY($3)
            WHERE m.cluster_id = $1 AND m.run_id = $2
            GROUP BY m.claim_id
        )
        SELECT c.id,
               COALESCE(c.content, c.id::text) AS label,
               'claim'::text AS entity_type,
               c.pignistic_prob,
               (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1) AS frame_id,
               $1::uuid AS cluster_id,
               NULL::float8 AS conflict_k
        FROM degree d
        JOIN claims c ON c.id = d.claim_id
        ORDER BY d.deg DESC NULLS LAST, c.pignistic_prob DESC NULLS LAST
        LIMIT $4",
    )
    .bind(cluster_id)
    .bind(run_id)
    .bind(degree_list)
    .bind(budget)
    .fetch_all(pool)
    .await
    .map_err(internal)?;

    let node_ids: Vec<Uuid> = nodes.iter().map(|n| n.id).collect();
    let (edges, filtered_edge_count) =
        fetch_subgraph_edges(pool, &node_ids, allowlist.as_deref()).await?;

    Ok(Json(ExpandResponse {
        cluster_id,
        truncated: total_size > nodes.len() as i64,
        total_size,
        nodes,
        edges,
        filtered_edge_count,
    }))
}

pub async fn neighborhood(
    State(state): State<AppState>,
    Query(params): Query<NeighborhoodParams>,
) -> Result<Json<ExpandResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;
    let pool: &PgPool = &state.db_pool;
    let hops = params.hops.clamp(1, 2);
    let budget = params.budget.max(1);
    let allowlist = resolve_relationship_filter(params.relationships.as_deref());

    // BFS traverses via *all* edge types so that the response can report
    // `filtered_edge_count` for nodes whose only edges are design-excluded
    // (e.g. `produced`, `same_source`). The render filter applies in
    // `fetch_subgraph_edges` below; the BFS only bounds the neighborhood by
    // hop depth and the overall `budget`.
    let nodes: Vec<NodeOut> = sqlx::query_as::<_, NodeOut>(
        r#"
        WITH RECURSIVE bfs(id, depth) AS (
            SELECT $1::uuid, 0
            UNION
            SELECT CASE WHEN e.source_id = b.id THEN e.target_id ELSE e.source_id END,
                   b.depth + 1
            FROM bfs b
            JOIN edges e
              ON (e.source_id = b.id OR e.target_id = b.id)
            WHERE b.depth < $2
        )
        SELECT DISTINCT
               c.id,
               COALESCE(c.content, c.id::text) AS label,
               'claim'::text AS entity_type,
               c.pignistic_prob,
               (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1) AS frame_id,
               NULL::uuid AS cluster_id,
               NULL::float8 AS conflict_k
        FROM bfs b JOIN claims c ON c.id = b.id
        LIMIT $3
        "#,
    )
    .bind(params.node_id)
    .bind(hops)
    .bind(budget)
    .fetch_all(pool)
    .await
    .map_err(internal)?;

    if nodes.is_empty() {
        return Err((StatusCode::NOT_FOUND, "seed node not found".into()));
    }

    let ids: Vec<Uuid> = nodes.iter().map(|n| n.id).collect();
    let (edges, filtered_edge_count) =
        fetch_subgraph_edges(pool, &ids, allowlist.as_deref()).await?;

    Ok(Json(ExpandResponse {
        cluster_id: Uuid::nil(),
        truncated: false,
        total_size: nodes.len() as i64,
        nodes,
        edges,
        filtered_edge_count,
    }))
}

/// Fetch edges *between* the given node ids, partitioned into:
/// - edges whose `relationship` is in `rel_list` (returned as `edges`)
/// - edges whose `relationship` is *not* in `rel_list` (returned as count)
///
/// Single round-trip: tags each row with an `is_allowed` flag computed in
/// the SELECT list, then partitions in Rust.
async fn fetch_subgraph_edges(
    pool: &PgPool,
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
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as(
                "SELECT source_id, target_id, relationship, true AS is_allowed \
             FROM edges \
             WHERE source_id = ANY($1) AND target_id = ANY($1)",
            )
            .bind(node_ids)
            .fetch_all(pool)
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

fn internal(e: sqlx::Error) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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

#[cfg(all(test, feature = "db"))]
mod integration_tests {
    use super::*;
    use crate::state::{ApiConfig, AppState};
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use sqlx::PgPool;
    use tower::ServiceExt;

    fn test_state(pool: PgPool) -> AppState {
        AppState::with_db(pool, ApiConfig::default())
    }

    fn graph_router(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/graph/neighborhood", get(neighborhood))
            .route("/api/v1/graph/clusters/:id/expand", get(expand))
            .with_state(state)
    }

    async fn parse_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Insert a system agent for tests (mirrors the pattern in policies.rs).
    async fn ensure_test_agent(pool: &PgPool) -> Uuid {
        let pub_key = vec![1u8; 32];
        if let Some(id) =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM agents WHERE public_key = $1")
                .bind(&pub_key)
                .fetch_optional(pool)
                .await
                .unwrap()
        {
            return id;
        }
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
        )
        .bind(&pub_key)
        .bind("graph-test-agent")
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Seed two claims and return their ids.
    async fn seed_two_claims(pool: &PgPool) -> (Uuid, Uuid) {
        let agent_id = ensure_test_agent(pool).await;
        let a_content = format!("graph-test-claim-a-{}", Uuid::new_v4());
        let b_content = format!("graph-test-claim-b-{}", Uuid::new_v4());
        let a_hash = epigraph_crypto::ContentHasher::hash(a_content.as_bytes());
        let b_hash = epigraph_crypto::ContentHasher::hash(b_content.as_bytes());
        let a = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
             VALUES ($1, $2, $3, 0.5) RETURNING id",
        )
        .bind(&a_content)
        .bind(a_hash.as_slice())
        .bind(agent_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let b = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
             VALUES ($1, $2, $3, 0.5) RETURNING id",
        )
        .bind(&b_content)
        .bind(b_hash.as_slice())
        .bind(agent_id)
        .fetch_one(pool)
        .await
        .unwrap();
        (a, b)
    }

    /// Seed a claim->claim edge with the given relationship.
    async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'claim', $2, 'claim', $3)",
        )
        .bind(source)
        .bind(target)
        .bind(relationship)
        .execute(pool)
        .await
        .unwrap();
    }

    /// Build a `GET /api/v1/graph/neighborhood` request scoped to `node_id`,
    /// with optional `?relationships=` override.
    fn neighborhood_request(node_id: Uuid, relationships: Option<&str>) -> Request<Body> {
        let uri = match relationships {
            Some(r) => format!(
                "/api/v1/graph/neighborhood?node_id={}&relationships={}",
                node_id, r
            ),
            None => format!("/api/v1/graph/neighborhood?node_id={}", node_id),
        };
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn neighborhood_relationships_param_overrides_allowlist(pool: PgPool) {
        let (a, b) = seed_two_claims(&pool).await;
        seed_edge(&pool, a, b, "produced").await; // NOT in default allowlist

        let state = test_state(pool.clone());
        let router = graph_router(state);

        // Without relationships override: edge is filtered.
        let response = router
            .clone()
            .oneshot(neighborhood_request(a, None))
            .await
            .unwrap();
        let body: serde_json::Value = parse_body(response).await;
        assert_eq!(body["edges"].as_array().unwrap().len(), 0);
        assert_eq!(body["filtered_edge_count"], 1);

        // With relationships=produced: edge is returned.
        let response = router
            .oneshot(neighborhood_request(a, Some("produced")))
            .await
            .unwrap();
        let body: serde_json::Value = parse_body(response).await;
        assert_eq!(body["edges"].as_array().unwrap().len(), 1);
        assert_eq!(body["edges"][0]["relationship"], "produced");
    }
}
