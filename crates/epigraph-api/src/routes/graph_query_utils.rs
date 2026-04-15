use crate::errors::ApiError;
use crate::routes::edges::{FullGraphEdge, FullGraphNode, FullGraphResponse};
use axum::Json;
use serde_json::Value;
use uuid::Uuid;

// Row types for sqlx::query_as
#[derive(sqlx::FromRow)]
struct ClaimGraphRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    confidence: Option<f64>,
    methodology: Option<String>,
    belief: Option<f64>,
    plausibility: Option<f64>,
    pignistic_prob: Option<f64>,
    mass_on_missing: Option<f64>,
}
#[derive(sqlx::FromRow)]
struct AgentGraphRow {
    id: Uuid,
    display_name: Option<String>,
}
#[derive(sqlx::FromRow)]
struct EvidenceGraphRow {
    id: Uuid,
    source_url: Option<String>,
    properties: Value,
}
#[derive(sqlx::FromRow)]
struct TraceGraphRow {
    id: Uuid,
    methodology: String,
    confidence: f64,
}
#[derive(sqlx::FromRow)]
struct EdgeGraphRow {
    id: Uuid,
    source_id: Uuid,
    target_id: Uuid,
    source_type: String,
    target_type: String,
    relationship: String,
    properties: Value,
}

#[cfg(feature = "db")]
pub async fn load_subgraph(
    pool: &epigraph_db::PgPool,
    node_ids: Vec<Uuid>,
) -> Result<Json<FullGraphResponse>, ApiError> {
    // 1. Fetch all edges WHERE both source and target are in our node_ids set
    let edge_rows: Vec<EdgeGraphRow> = sqlx::query_as(
        r#"
        SELECT id, source_id, target_id, source_type, target_type, relationship, properties
        FROM edges 
        WHERE source_id = ANY($1) AND target_id = ANY($1)
        "#,
    )
    .bind(&node_ids)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Fetch subgraph edges: {e}"),
    })?;

    // 2. We need to figure out which nodes belong to which table to do efficient batch fetches
    // A small side effect is we don't strictly know the entity_type of every node_id passed in unless
    // we query each table, BUT realistically we just try to fetch the known set from each table
    let mut nodes: Vec<FullGraphNode> = Vec::new();

    // 3. Fetch claims
    let claim_rows: Vec<ClaimGraphRow> = sqlx::query_as(
        "SELECT id, content, truth_value, (properties->>'confidence')::float8 as confidence, properties->>'methodology' as methodology, belief, plausibility, pignistic_prob, mass_on_missing FROM claims WHERE id = ANY($1)"
    )
    .bind(&node_ids)
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError { message: format!("Fetch claims: {e}") })?;

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

    // 5. Fetch evidence
    let evidence_rows: Vec<EvidenceGraphRow> =
        sqlx::query_as("SELECT id, source_url, properties FROM evidence WHERE id = ANY($1)")
            .bind(&node_ids)
            .fetch_all(pool)
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
