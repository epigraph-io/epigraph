use axum::Json;
use serde_json::Value;

/// GET /api/v1/mcp/tools
///
/// Returns all MCP tools registered on the live server as a JSON array.
/// Each entry includes `name`, `description`, and `inputSchema` (JSON Schema).
///
/// This endpoint exists to break the circular dependency in the master workflow
/// designer: it uses graph queries to find documented tools, but only finds tools
/// already stored in the graph. Runtime introspection via this endpoint provides
/// the ground truth for newly deployed tools.
///
/// No authentication required — tool names and schemas are non-sensitive metadata.
#[cfg(feature = "db")]
pub async fn list_mcp_tools() -> Json<Value> {
    Json(epigraph_mcp::list_tools())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn test_list_mcp_tools_returns_array() {
        use super::list_mcp_tools;
        let response = list_mcp_tools().await;
        assert!(
            response.0.is_array(),
            "expected JSON array, got: {}",
            response.0
        );
        let tools = response.0.as_array().unwrap();
        assert!(!tools.is_empty(), "tool list must not be empty");
        // Every entry must have a name field
        for tool in tools {
            assert!(
                tool.get("name").is_some(),
                "tool entry missing 'name': {tool}"
            );
        }
    }

    #[cfg(feature = "db")]
    #[tokio::test]
    async fn test_list_mcp_tools_includes_meta_tool() {
        use super::list_mcp_tools;
        let response = list_mcp_tools().await;
        let tools = response.0.as_array().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(
            names.contains(&"list_mcp_tools"),
            "list_mcp_tools must appear in its own output; got: {names:?}"
        );
    }
}
