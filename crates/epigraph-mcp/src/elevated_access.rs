//! The MCP server's per-access recorder (elevation plan EL-8): every tool call
//! served to an ELEVATED request is recorded in migration 127's
//! `elevated_access` log BEFORE its result is returned, or the result is
//! withheld.
//!
//! # Where it runs
//!
//! `server.rs::call_tool`, on the HTTP transport, for a request that MAY be
//! elevated (a token carrying an elevation claim, or a family with the
//! connector switch on). The request's viewer is resolved ONCE there:
//!
//! * elevated: the tool runs, and its result (or its error) is recorded here,
//!   on its own transaction stamped with that elevated viewer, before it is
//!   returned; a recording failure replaces the result with an internal error,
//!   so an unrecorded elevated result is never sent;
//! * not elevated: the elevation claim and the family are STRIPPED from the
//!   `AuthContext` the tool sees, so the tool cannot resolve an elevated
//!   viewer the recorder did not see (a connector-mode session confirmed
//!   between the two resolutions, for one).
//!
//! stdio has no `AuthContext` and never elevates. Federated tools are proxied
//! under the caller's own token before this point (a residual: the
//! extension's server decides what that token reads).

use epigraph_db::repos::elevated_access::{bounded, candidate_ids_in, id_fields_in, rows_in};
use rmcp::model::{CallToolResult, ErrorData as McpError};

/// The rows a tool result carried: [`rows_in`] over its structured content
/// and over every text content item that is itself a JSON document (the
/// tools answer JSON as text).
fn rows_of(result: &serde_json::Value) -> i32 {
    let mut n = rows_in(
        result
            .get("structuredContent")
            .unwrap_or(&serde_json::Value::Null),
    );
    for item in result
        .get("content")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(text) = item.get("text").and_then(serde_json::Value::as_str) {
            if let Ok(inner) = serde_json::from_str::<serde_json::Value>(text) {
                n = n.saturating_add(rows_in(&inner));
            }
        }
    }
    n
}

/// Record one elevated tool call and hand its result back, or withhold it.
///
/// `arguments` are the call's arguments (only their id-shaped fields are
/// kept); `jti` is the presenting token's.
///
/// # Errors
/// The tool's own error (recorded first), or an internal error replacing a
/// result that could not be recorded.
pub async fn record_elevated_call(
    server: &crate::server::EpiGraphMcpFull,
    viewer: &epigraph_db::Viewer,
    tool: &str,
    arguments: Option<&serde_json::Map<String, serde_json::Value>>,
    jti: uuid::Uuid,
    result: Result<CallToolResult, McpError>,
) -> Result<CallToolResult, McpError> {
    let (value, is_error) = match &result {
        Ok(r) => (serde_json::to_value(r), r.is_error.unwrap_or(false)),
        Err(e) => (serde_json::to_value(e), true),
    };
    let withheld = |why: &str| {
        tracing::error!(
            target: "elevation",
            tool,
            reason = %why,
            "an elevated tool result could not be recorded; withheld"
        );
        McpError::internal_error(
            "ELEVATED ACCESS NOT RECORDED: the result is withheld".to_string(),
            None,
        )
    };
    let value = match value {
        Ok(v) => v,
        Err(e) => return Err(withheld(&e.to_string())),
    };
    let body = value.to_string();
    let args = arguments.map_or_else(
        || serde_json::json!({}),
        |a| id_fields_in(&serde_json::Value::Object(a.clone())),
    );
    let access = epigraph_db::ElevatedAccess {
        surface: bounded(
            &format!("mcp:{tool}"),
            epigraph_db::repos::elevated_access::MAX_SURFACE_LEN,
        ),
        args: serde_json::json!({
            "tool": tool,
            "arguments": args,
            "jti": jti,
            "is_error": is_error,
        }),
        row_count: rows_of(&value),
        candidate_ids: candidate_ids_in(body.as_bytes()),
    };
    let Some(scoped) = server.scoped.as_ref() else {
        return Err(withheld("no ScopedPool to record on"));
    };
    if let Err(e) = scoped.record_elevated_access(viewer, &access).await {
        return Err(withheld(&e.to_string()));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::rows_of;

    #[test]
    fn rows_are_counted_inside_json_text_content() {
        let a = "0f8fad5b-d9cb-469f-a165-70867728950e";
        let b = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
        let inner = serde_json::json!({"claims": [{"id": a}, {"id": b}]}).to_string();
        let result = serde_json::json!({
            "content": [{"type": "text", "text": inner}, {"type": "text", "text": "not json"}],
        });
        assert_eq!(rows_of(&result), 2);
        let structured = serde_json::json!({"structuredContent": {"id": a}, "content": []});
        assert_eq!(rows_of(&structured), 1);
    }
}
