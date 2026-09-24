//! `get_recall_events` MCP tool (backlog 8cbffa0e / design F5).
//!
//! Read side of the recall audit log: "what did this agent retrieve, and
//! which queries ever surfaced this claim?"

use rmcp::model::{CallToolResult, Content};
use serde::Serialize;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::GetRecallEventsParams;

use epigraph_db::RecallEventRepository;

#[derive(Debug, Serialize)]
struct RecallEventOut {
    id: String,
    agent_id: Option<String>,
    tool: String,
    query_text: String,
    /// Hex BLAKE3 of the query vector; `None` for a lexical-only (embedder
    /// down) recall. Same text + same hash + different claims => the corpus
    /// changed; same text + different hash => the embedder changed.
    query_embedding_hash: Option<String>,
    params: serde_json::Value,
    returned_claim_ids: Vec<String>,
    created_at: String,
}

fn parse_opt_uuid(raw: Option<&str>, field: &str) -> Result<Option<uuid::Uuid>, McpError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => uuid::Uuid::parse_str(s)
            .map(Some)
            .map_err(|e| invalid_params(format!("invalid {field} {s:?}: {e}"))),
    }
}

fn parse_opt_time(
    raw: Option<&str>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, McpError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|d| Some(d.with_timezone(&chrono::Utc)))
            .map_err(|e| invalid_params(format!("invalid {field} {s:?} (want RFC3339): {e}"))),
    }
}

pub async fn get_recall_events(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetRecallEventsParams,
) -> Result<CallToolResult, McpError> {
    let agent_id = parse_opt_uuid(params.agent_id.as_deref(), "agent_id")?;
    let claim_id = parse_opt_uuid(params.claim_id.as_deref(), "claim_id")?;
    let since = parse_opt_time(params.since.as_deref(), "since")?;
    let until = parse_opt_time(params.until.as_deref(), "until")?;

    let rows = RecallEventRepository::list(
        &server.pool,
        viewer,
        agent_id,
        claim_id,
        since,
        until,
        params.limit.unwrap_or(50),
        params.offset.unwrap_or(0),
    )
    .await
    .map_err(internal_error)?;

    let out: Vec<RecallEventOut> = rows
        .into_iter()
        .map(|r| RecallEventOut {
            id: r.id.to_string(),
            agent_id: r.agent_id.map(|a| a.to_string()),
            tool: r.tool,
            query_text: r.query_text,
            query_embedding_hash: r.query_embedding_hash.map(hex::encode),
            params: r.params,
            returned_claim_ids: r
                .returned_claim_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&out).map_err(internal_error)?,
    )]))
}
