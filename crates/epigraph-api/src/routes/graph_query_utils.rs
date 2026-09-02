use crate::errors::ApiError;
use crate::routes::edges::{FullGraphEdge, FullGraphNode, FullGraphResponse};
use axum::Json;
use uuid::Uuid;

// Row types for sqlx::query_as
#[derive(sqlx::FromRow)]
struct AgentGraphRow {
    id: Uuid,
    display_name: Option<String>,
}
#[derive(sqlx::FromRow)]
struct TraceGraphRow {
    id: Uuid,
    methodology: String,
    confidence: f64,
}

/// Build a subgraph response for an arbitrary node id set.
///
/// # Viewer
///
/// PR-07 gave this helper a `&Viewer`. It previously took none and ran
/// `SELECT id, content, ... FROM claims WHERE id = ANY($1)` unfiltered,
/// building each node's `label` from `content` — so all three call sites
/// (`graph_query.rs` twice, `edges.rs` once) looked filtered and none was.
/// Because the signature carried no viewer, there was nothing at the call site
/// for a reviewer to notice; that is why it is fixed in the signature rather
/// than at the callers.
///
/// `claims`, `evidence` and `edges` are all `tier_a` roots in migration 062 and
/// are filtered on their own predicates. `agents` and `reasoning_traces` are
/// NOT in `tier_a` — they have no `owner_group_id` to filter on — so those two
/// projections stay unfiltered, deliberately. They carry no claim content:
/// `agents` contributes a display name and `reasoning_traces` a methodology
/// label and a confidence number.
#[cfg(feature = "db")]
pub async fn load_subgraph(
    pool: &epigraph_db::PgPool,
    viewer: &epigraph_db::Viewer,
    node_ids: Vec<Uuid>,
) -> Result<Json<FullGraphResponse>, ApiError> {
    // 1. Fetch all edges WHERE both source and target are in our node_ids set
    let edge_rows = epigraph_db::GraphViewRepository::subgraph_edges(pool, viewer, &node_ids)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Fetch subgraph edges: {e}"),
        })?;

    // 2. We need to figure out which nodes belong to which table to do efficient batch fetches
    // A small side effect is we don't strictly know the entity_type of every node_id passed in unless
    // we query each table, BUT realistically we just try to fetch the known set from each table
    let mut nodes: Vec<FullGraphNode> = Vec::new();

    // 3. Fetch claims (viewer-filtered)
    let claim_rows = epigraph_db::GraphViewRepository::subgraph_claims(pool, viewer, &node_ids)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Fetch claims: {e}"),
        })?;

    for row in claim_rows {
        let label = if row.content.chars().count() > 60 {
            let truncated: String = row.content.chars().take(57).collect();
            format!("{truncated}...")
        } else {
            row.content.clone()
        };
        nodes.push(FullGraphNode {
            id: row.id,
            entity_type: "claim".to_string(),
            label,
            truth_value: Some(row.truth_value),
            evidence_type: None,
            display_name: None,
            confidence: row.confidence,
            methodology: row.methodology,
            belief: row.belief,
            plausibility: row.plausibility,
            pignistic_prob: row.pignistic_prob,
            mass_on_missing: row.mass_on_missing,
        });
    }

    // 4. Fetch agents
    let agent_rows: Vec<AgentGraphRow> =
        sqlx::query_as("SELECT id, display_name FROM agents WHERE id = ANY($1)")
            .bind(&node_ids)
            .fetch_all(pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Fetch agents: {e}"),
            })?;

    for row in agent_rows {
        let label = row
            .display_name
            .clone()
            .unwrap_or_else(|| row.id.to_string()[..8].to_string());
        nodes.push(FullGraphNode {
            id: row.id,
            entity_type: "agent".to_string(),
            label,
            truth_value: None,
            evidence_type: None,
            display_name: row.display_name,
            confidence: None,
            methodology: None,
            belief: None,
            plausibility: None,
            pignistic_prob: None,
            mass_on_missing: None,
        });
    }

    // 5. Fetch evidence (viewer-filtered)
    let evidence_rows =
        epigraph_db::GraphViewRepository::subgraph_evidence(pool, viewer, &node_ids)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Fetch evidence: {e}"),
            })?;

    for row in evidence_rows {
        let props = &row.properties;
        let ev_type = props
            .get("evidence_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let caption = props.get("caption").and_then(|v| v.as_str()).unwrap_or("");
        let doi = props.get("doi").and_then(|v| v.as_str()).unwrap_or("");

        let label = if !caption.is_empty() {
            if caption.chars().count() > 60 {
                let t: String = caption.chars().take(57).collect();
                format!("{t}...")
            } else {
                caption.to_string()
            }
        } else if !doi.is_empty() {
            format!("Evidence: {doi}")
        } else if let Some(url) = &row.source_url {
            format!("Evidence: {url}")
        } else {
            format!("Evidence {}", &row.id.to_string()[..8])
        };

        nodes.push(FullGraphNode {
            id: row.id,
            entity_type: "evidence".to_string(),
            label,
            truth_value: None,
            evidence_type: Some(ev_type.to_string()),
            display_name: None,
            confidence: None,
            methodology: None,
            belief: None,
            plausibility: None,
            pignistic_prob: None,
            mass_on_missing: None,
        });
    }

    // 6. Fetch reasoning traces
    let trace_rows: Vec<TraceGraphRow> = sqlx::query_as(
        "SELECT id, reasoning_type as methodology, confidence FROM reasoning_traces WHERE id = ANY($1)"
    )
    .bind(&node_ids)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError { message: format!("Fetch traces: {e}") })?;

    for row in trace_rows {
        let label = format!("{} ({:.2})", row.methodology, row.confidence);
        nodes.push(FullGraphNode {
            id: row.id,
            entity_type: "trace".to_string(),
            label,
            truth_value: None,
            evidence_type: None,
            display_name: None,
            confidence: Some(row.confidence),
            methodology: Some(row.methodology),
            belief: None,
            plausibility: None,
            pignistic_prob: None,
            mass_on_missing: None,
        });
    }

    // 8. Build edges
    let edges: Vec<FullGraphEdge> = edge_rows
        .into_iter()
        .map(|r| {
            let strength = r
                .properties
                .get("strength")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5);
            let prov_type = r
                .properties
                .get("prov_type")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            FullGraphEdge {
                id: r.id,
                source_id: r.source_id,
                target_id: r.target_id,
                source_type: r.source_type,
                target_type: r.target_type,
                relationship: r.relationship,
                strength,
                prov_type,
            }
        })
        .collect();

    let total_nodes = nodes.len();
    let total_edges = edges.len();

    Ok(Json(FullGraphResponse {
        nodes,
        edges,
        total_nodes,
        total_edges,
    }))
}
