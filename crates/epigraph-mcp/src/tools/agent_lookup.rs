//! `find_agent` and `get_agent`: look up a person, an LLM agent or a system
//! identity by name or by id (backlog 94cc12db, 8b29593c).
//!
//! Both read through `epigraph_db::AgentLookupRepository`, the code that
//! serves `GET /api/v1/agents/search`, on ONE connection stamped from the
//! caller's viewer (`ScopedPool::read_as`), so the MCP and HTTP surfaces apply
//! the same viewer rules. What a card discloses, and why each field is safe to
//! show the caller, is that module's doc.

use rmcp::model::{CallToolResult, ContentBlock};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{FindAgentParams, GetAgentParams};

fn scoped<'a>(
    server: &'a EpiGraphMcpFull,
    tool: &str,
) -> Result<&'a epigraph_db::ScopedPool, McpError> {
    server.scoped.as_ref().ok_or_else(|| {
        crate::errors::internal_error_text(format!(
            "{tool} needs a tenancy-aware pool; this server has none"
        ))
    })
}

fn db_param_error(e: epigraph_db::DbError) -> McpError {
    match e {
        epigraph_db::DbError::InvalidData { reason } => invalid_params(reason),
        other => internal_error(other),
    }
}

/// `find_agent(name, kind?, role?, limit?)`.
///
/// # Errors
/// `invalid_params` for a name outside 2..=200 characters, an unknown kind or
/// a blank role; `internal_error` for a server without a tenancy-aware pool
/// and for a database fault.
pub async fn find_agent(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: FindAgentParams,
) -> Result<CallToolResult, McpError> {
    let query = epigraph_db::FindAgentQuery::new(
        &params.name,
        params.kind.as_deref(),
        params.role.as_deref(),
        params.limit,
    )
    .map_err(db_param_error)?;
    let mut read = scoped(server, "find_agent")?
        .read_as(viewer)
        .await
        .map_err(internal_error)?;
    let result = epigraph_db::AgentLookupRepository::find(&mut read, viewer, &query)
        .await
        .map_err(internal_error)?;
    read.commit().await.map_err(internal_error)?;
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&result).map_err(internal_error)?,
    )]))
}

/// `get_agent(agent_id)`.
///
/// # Errors
/// `invalid_params` for a malformed id and for an id with no agent;
/// `internal_error` as [`find_agent`].
pub async fn get_agent(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetAgentParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.agent_id)?;
    let mut read = scoped(server, "get_agent")?
        .read_as(viewer)
        .await
        .map_err(internal_error)?;
    let card = epigraph_db::AgentLookupRepository::card(&mut read, viewer, id)
        .await
        .map_err(internal_error)?;
    read.commit().await.map_err(internal_error)?;
    let card = card.ok_or_else(|| invalid_params(format!("agent {id} not found")))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&card).map_err(internal_error)?,
    )]))
}
