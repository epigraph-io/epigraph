#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::GetProvenanceParams;

use epigraph_db::LineageRepository;

pub async fn get_provenance(
    server: &EpiGraphMcpFull,
    params: GetProvenanceParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;

    let lineage = LineageRepository::get_lineage(&server.pool, claim_id, Some(5))
        .await
        .map_err(internal_error)?;

    // Build W3C PROV-O style JSON-LD
    let mut entities = Vec::new();

    for (id, lc) in &lineage.claims {
        entities.push(serde_json::json!({
            "@type": "prov:Entity",
            "@id": format!("claim:{id}"),
            "content": lc.content,
            "truth_value": lc.truth_value,
            "depth": lc.depth,
            "parent_ids": lc.parent_ids.iter().map(|p| format!("claim:{p}")).collect::<Vec<_>>(),
            "evidence_ids": lc.evidence_ids.iter().map(|e| format!("evidence:{e}")).collect::<Vec<_>>(),
        }));
    }

    for (id, le) in &lineage.evidence {
        entities.push(serde_json::json!({
            "@type": "prov:Entity",
            "@id": format!("evidence:{id}"),
            "claim_id": format!("claim:{}", le.claim_id),
            "evidence_type": le.evidence_type,
        }));
    }

    for (id, lt) in &lineage.traces {
        entities.push(serde_json::json!({
            "@type": "prov:Activity",
            "@id": format!("trace:{id}"),
            "claim_id": format!("claim:{}", lt.claim_id),
            "reasoning_type": lt.reasoning_type,
            "confidence": lt.confidence,
            "parent_trace_ids": lt.parent_trace_ids.iter().map(|p| format!("trace:{p}")).collect::<Vec<_>>(),
        }));
    }

    let prov_bundle = serde_json::json!({
        "@context": "https://www.w3.org/ns/prov#",
        "root_claim": format!("claim:{claim_id}"),
        "entities": entities,
        "topological_order": lineage.topological_order.iter().map(|id| format!("claim:{id}")).collect::<Vec<_>>(),
        "cycle_detected": lineage.cycle_detected,
        "max_depth_reached": lineage.max_depth_reached,
    });

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&prov_bundle).map_err(internal_error)?,
    )]))
}
