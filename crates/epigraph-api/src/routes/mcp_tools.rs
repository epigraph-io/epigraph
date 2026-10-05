use axum::{Extension, Json};
use serde_json::Value;

use crate::middleware::bearer::AuthContext;

/// GET /api/v1/mcp/tools
///
/// Returns the MCP tools registered on the live server as a JSON array, as the
/// caller may see them. Each entry includes `name`, `description`, and
/// `inputSchema` (JSON Schema).
///
/// This endpoint exists to break the circular dependency in the master workflow
/// designer: it uses graph queries to find documented tools, but only finds tools
/// already stored in the graph. Runtime introspection via this endpoint provides
/// the ground truth for newly deployed tools.
///
/// Behind bearer auth (see `routes/mod.rs`). Filtered as the MCP manifest is
/// (elevation plan EL-11, `epigraph_mcp::catalog_for`): an admin-only-scoped
/// tool only where the caller's scope gate would admit it (armed: an elevated
/// request), and never `sudo`/`unsudo`, which an MCP connection lists to a
/// role holder itself.
#[cfg(feature = "db")]
pub async fn list_mcp_tools(Extension(auth): Extension<AuthContext>) -> Json<Value> {
    Json(epigraph_mcp::catalog_for(&auth))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "db")]
    fn caller(
        scopes: &[&str],
        posture: crate::middleware::bearer::AdminScopePosture,
    ) -> axum::Extension<super::AuthContext> {
        axum::Extension(super::AuthContext {
            client_id: uuid::Uuid::new_v4(),
            agent_id: Some(uuid::Uuid::new_v4()),
            owner_id: None,
            client_type: crate::middleware::bearer::ClientType::Human,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: uuid::Uuid::new_v4(),
            family_id: Some(uuid::Uuid::new_v4()),
            elevation_claim: None,
            elevation: None,
            admin_scopes: posture,
        })
    }

    #[cfg(feature = "db")]
    async fn names(ext: axum::Extension<super::AuthContext>) -> Vec<String> {
        super::list_mcp_tools(ext)
            .await
            .0
            .as_array()
            .expect("array")
            .iter()
            .map(|t| t["name"].as_str().expect("name").to_string())
            .collect()
    }

    /// The REST catalog never lists `sudo`/`unsudo` (the MCP manifest lists
    /// them to a role holder), and lists an admin-only-scoped tool only where
    /// the caller's scope gate would admit it: an unarmed standing holder
    /// keeps `delete_edge`, an armed one and a caller without the scope do
    /// not (elevation plan EL-11). Mutations: the route answering the
    /// unfiltered `list_tools()` (sudo listed, admin tools to everyone).
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn the_catalog_hides_sudo_and_admin_tools_the_caller_cannot_call() {
        use crate::middleware::bearer::AdminScopePosture::{Armed, Unarmed};
        // The scope `delete_edge` requires (SCOPE_MAP), so this test spells no
        // admin-only scope itself (admin_scope_literals).
        let admin = epigraph_mcp::scope_map::required_scope("delete_edge").expect("mapped");
        assert!(epigraph_auth::is_admin_only_scope(admin), "CALIBRATION");
        let holder_unarmed = names(caller(&["claims:read", admin], Unarmed)).await;
        let holder_armed = names(caller(&["claims:read", admin], Armed)).await;
        let reader = names(caller(&["claims:read"], Unarmed)).await;
        for list in [&holder_unarmed, &holder_armed, &reader] {
            assert!(
                list.iter().any(|n| n == "get_claim"),
                "CALIBRATION: {list:?}"
            );
            assert!(
                !list.iter().any(|n| n == "sudo" || n == "unsudo"),
                "never sudo/unsudo over REST: {list:?}"
            );
        }
        assert!(
            holder_unarmed.iter().any(|n| n == "delete_edge"),
            "unarmed holder"
        );
        assert!(
            !holder_armed.iter().any(|n| n == "delete_edge"),
            "armed standing scope"
        );
        assert!(!reader.iter().any(|n| n == "delete_edge"), "no scope");
    }

    #[cfg(feature = "db")]
    #[tokio::test]
    async fn test_list_mcp_tools_returns_array() {
        use super::list_mcp_tools;
        let response = list_mcp_tools(caller(
            &["claims:read"],
            crate::middleware::bearer::AdminScopePosture::Unarmed,
        ))
        .await;
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
        let response = list_mcp_tools(caller(
            &["claims:read"],
            crate::middleware::bearer::AdminScopePosture::Unarmed,
        ))
        .await;
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
