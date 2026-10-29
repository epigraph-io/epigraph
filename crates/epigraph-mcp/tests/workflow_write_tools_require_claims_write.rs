//! The MCP twins of the REST workflow write routes refuse a `claims:read`
//! token over HTTP (backlog 05eb8b4a).
//!
//! The REST routes `POST /api/v1/workflows/ingest`, `POST /api/v1/workflows`,
//! `POST /api/v1/workflows/:id/outcome` and `DELETE /api/v1/workflows/:id`
//! checked no scope; they now require `claims:write`, which is what their MCP
//! twins already required. This pins the MCP half of that parity: over HTTP,
//! `call_tool` runs `enforce_tool_scope` before dispatch, and each twin's
//! `SCOPE_MAP` row is `claims:write`, so a read-only token is refused naming
//! the scope, and a `claims:write` token passes the gate.
//!
//! stdio carries no token and so no scope: `call_tool` skips
//! `enforce_tool_scope` there, and a stdio write is governed by the process
//! boundary (the server's own agent identity) and the per-tool authority
//! checks, not by this map.

use epigraph_auth::{AuthContext, ClientType};
use epigraph_mcp::server::EpiGraphMcpFull;
use uuid::Uuid;

const TWINS: &[&str] = &[
    "ingest_workflow",
    "store_workflow",
    "report_workflow_outcome",
    "deprecate_workflow",
];

fn bearer(scopes: &[&str]) -> AuthContext {
    let agent = Uuid::new_v4();
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Agent,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

#[test]
fn every_workflow_write_twin_refuses_a_read_only_token_over_http() {
    let read_only = bearer(&["claims:read"]);
    let writer = bearer(&["claims:read", "claims:write"]);
    for tool in TWINS {
        let err = EpiGraphMcpFull::enforce_tool_scope(Some(&read_only), tool)
            .expect_err("a claims:read token must not reach a workflow write tool");
        assert!(
            err.message.contains("requires scope 'claims:write'"),
            "{tool}: the refusal names claims:write: {}",
            err.message
        );
        assert!(
            EpiGraphMcpFull::enforce_tool_scope(Some(&writer), tool).is_ok(),
            "{tool}: a claims:write token passes the scope gate"
        );
    }
}
