#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{EdgeRepository, PerspectiveRepository};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// Create a new perspective (frame of discernment viewpoint).
pub async fn create_perspective(
    server: &EpiGraphMcpFull,
    params: CreatePerspectiveParams,
) -> Result<CallToolResult, McpError> {
    if params.name.is_empty() || params.name.len() > 200 {
        return Err(invalid_params("name must be between 1 and 200 characters"));
    }

    let calibration = params.confidence_calibration.unwrap_or(0.5);
    if !(0.0..=1.0).contains(&calibration) {
        return Err(invalid_params("confidence_calibration must be in [0, 1]"));
    }

    let owner_agent_id = if let Some(ref id) = params.owner_agent_id {
        Some(parse_uuid(id)?)
    } else {
        Some(server.agent_id().await?)
    };

    let frame_ids: Vec<uuid::Uuid> = params
        .frame_ids
        .unwrap_or_default()
        .iter()
        .map(|s| parse_uuid(s))
        .collect::<Result<Vec<_>, _>>()?;

    let perspective_type = params.perspective_type.as_deref().unwrap_or("analytical");
    let extraction_method = params
        .extraction_method
        .as_deref()
        .unwrap_or("ai_generated");

    let row = PerspectiveRepository::create(
        &server.pool,
        &params.name,
        params.description.as_deref(),
        owner_agent_id,
        Some(perspective_type),
        &frame_ids,
        Some(extraction_method),
        Some(calibration),
    )
    .await
    .map_err(internal_error)?;

    // Materialize PERSPECTIVE_OF edge if owner specified
    if let Some(agent_id) = owner_agent_id {
        let _ = EdgeRepository::create(
            &server.pool,
            row.id,
            "perspective",
            agent_id,
            "agent",
            "PERSPECTIVE_OF",
            None,
            None,
            None,
        )
        .await;
    }

    success_json(&serde_json::json!({
        "perspective_id": row.id.to_string(),
        "name": row.name,
        "description": row.description,
        "owner_agent_id": row.owner_agent_id.map(|id| id.to_string()),
        "perspective_type": row.perspective_type,
        "frame_ids": row.frame_ids.map(|ids| ids.iter().map(|id| id.to_string()).collect::<Vec<_>>()),
        "confidence_calibration": row.confidence_calibration,
        "created_at": row.created_at.to_rfc3339(),
    }))
}

/// Set a perspective's source-reliability map (the frame-function lens): evidence-type
/// tag -> alpha in [0,1], merged into `properties.source_reliability`. Empty map clears it.
pub async fn set_source_reliability(
    server: &EpiGraphMcpFull,
    params: SetSourceReliabilityParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.perspective_id)?;
    for (tag, &alpha) in &params.source_reliability {
        if alpha.is_nan() || !(0.0..=1.0).contains(&alpha) {
            return Err(invalid_params(format!(
                "reliability for '{tag}' must be in [0, 1]"
            )));
        }
    }
    PerspectiveRepository::set_source_reliability(&server.pool, id, &params.source_reliability)
        .await
        .map_err(internal_error)?;

    // Backlog 86ee2d30 (G12): a tag the lens can never apply is still stored —
    // the vocabulary is operator-extensible, so this is a WARNING, never a
    // refusal — but the caller is told, instead of the key silently doing
    // nothing while every matching BBA keeps its default weight.
    let (unknown_keys, warnings) = unknown_source_reliability_keys(
        params.source_reliability.keys().map(String::as_str),
        &epigraph_engine::calibration::CalibrationConfig::from_workspace_root().unwrap_or_else(
            |_| epigraph_engine::calibration::CalibrationConfig::default_for_phase2_fallback(),
        ),
    );
    let mut out = serde_json::json!({
        "perspective_id": id.to_string(),
        "source_reliability": params.source_reliability,
        "status": "set",
    });
    if !unknown_keys.is_empty() {
        out["unknown_keys"] = serde_json::json!(unknown_keys);
        out["warnings"] = serde_json::json!(warnings);
    }
    success_json(&out)
}

/// The keys of a perspective `source_reliability` map that the frame-function
/// lens can never match, with one warning sentence each (backlog 86ee2d30).
///
/// Two ways a key is dead, both read off
/// `edge_factor::effective_source_strength_with_perspective`, which looks the
/// map up with the BBA's LOWERCASED `evidence_type`, strict-key:
/// 1. the key is not lowercase — it can never equal a lowercased string;
/// 2. the key is outside the engine's evidence-type vocabulary
///    ([`epigraph_engine::edge_factor::is_known_evidence_type_key`]). No
///    write path tags a BBA with such a string except `submit_ds_evidence`
///    naming it verbatim, which reports it as unknown in turn.
///
/// Sorted, so the response is deterministic.
fn unknown_source_reliability_keys<'a>(
    keys: impl Iterator<Item = &'a str>,
    calibration: &epigraph_engine::calibration::CalibrationConfig,
) -> (Vec<String>, Vec<String>) {
    let mut keys: Vec<&str> = keys.collect();
    keys.sort_unstable();
    let mut unknown = Vec::new();
    let mut warnings = Vec::new();
    for key in keys {
        if key != key.to_lowercase() {
            warnings.push(format!(
                "source_reliability key {key:?} is stored but can never apply: BBA evidence \
                 types are matched lowercased and strict-key, so spell it {:?}.",
                key.to_lowercase()
            ));
            unknown.push(key.to_string());
        } else if !epigraph_engine::edge_factor::is_known_evidence_type_key(key, calibration) {
            warnings.push(format!(
                "source_reliability key {key:?} is stored but is not in the evidence-type \
                 vocabulary (calibration.toml [evidence_type_weights] keys, \
                 [evidence_type_aliases], or the edge relationship names). It applies only to \
                 BBAs whose evidence_type is that same unrecognised string, which no write path \
                 produces except a submit_ds_evidence call naming it (reported there as unknown \
                 too); if it is a typo it changes no belief. Known keys: {}.",
                crate::tools::ds::known_evidence_type_keys().join(", ")
            ));
            unknown.push(key.to_string());
        }
    }
    (unknown, warnings)
}

/// List all perspectives with optional pagination.
pub async fn list_perspectives(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ListPerspectivesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let rows = PerspectiveRepository::list(&server.pool, viewer, limit, 0)
        .await
        .map_err(internal_error)?;

    let results: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "perspective_id": r.id.to_string(),
                "name": r.name,
                "description": r.description,
                "owner_agent_id": r.owner_agent_id.map(|id| id.to_string()),
                "perspective_type": r.perspective_type,
                "confidence_calibration": r.confidence_calibration,
                "created_at": r.created_at.to_rfc3339(),
                // Lens maps so an agent can SEE what a perspective up/down-weights
                // before choosing it as a (frame, perspective) lens. Serialize as
                // a JSON object when present, `null` when the perspective sets no
                // override (Option<HashMap> → object/null).
                "source_reliability": r.source_reliability(),
                "locality_reliability": r.locality_reliability(),
            })
        })
        .collect();

    success_json(&results)
}

/// Get a single perspective by ID.
pub async fn get_perspective(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetPerspectiveParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.perspective_id)?;

    let row = PerspectiveRepository::get_by_id(&server.pool, viewer, id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("perspective {id} not found")))?;

    success_json(&serde_json::json!({
        "perspective_id": row.id.to_string(),
        "name": row.name,
        "description": row.description,
        "owner_agent_id": row.owner_agent_id.map(|id| id.to_string()),
        "perspective_type": row.perspective_type,
        "frame_ids": row.frame_ids.map(|ids| ids.iter().map(|id| id.to_string()).collect::<Vec<_>>()),
        "extraction_method": row.extraction_method,
        "confidence_calibration": row.confidence_calibration,
        "created_at": row.created_at.to_rfc3339(),
    }))
}

// PR-14 deleted three tools from this file: `assign_ownership` (was here at
// :297), `get_ownership` (:354) and `update_partition` (:386), together with
// the `require_declassify_authority` gate helper that guarded the two writes.
//
// They were the last readers and writers of the legacy `ownership` ACL table,
// a partition model that the tenancy columns replaced. Their read half
// (`get_ownership`) took no `Viewer` and disclosed a node's owner and
// partition to anyone who asked, which made it an oracle for the very input
// the write gate decides on; deleting the surface is the resolution
// `progress.json::F-PR11-ownership-reads-are-an-owner-oracle` names.
//
// Their deletion also closes the scope asymmetry PR-12 recorded: the MCP
// `assign_ownership` entry sat at `claims:write` while the HTTP route with the
// identical declassification power required `claims:admin`. With both surfaces
// gone there is no longer a cheaper transport for the same power.
