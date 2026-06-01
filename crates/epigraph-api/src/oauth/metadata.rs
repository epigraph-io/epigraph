//! OAuth 2.0 discovery documents: RFC 8414 (authorization server metadata)
//! and RFC 9728 (protected resource metadata). Pure functions of public_base_url.

use axum::{extract::State, response::Json};
use serde_json::{json, Value};

use crate::state::AppState;

/// RFC 8414 — GET /.well-known/oauth-authorization-server
pub async fn authorization_server_metadata(State(state): State<AppState>) -> Json<Value> {
    let base = state.config.public_base_url.trim_end_matches('/');
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "introspection_endpoint": format!("{base}/oauth/introspect"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "scopes_supported": [
            "claims:read", "claims:write", "evidence:read", "evidence:write",
            "edges:read", "edges:write", "agents:read", "analysis:belief",
            "analysis:propagation", "ingest:write"
        ]
    }))
}

/// RFC 9728 — GET /.well-known/oauth-protected-resource
pub async fn protected_resource_metadata(State(state): State<AppState>) -> Json<Value> {
    let base = state.config.public_base_url.trim_end_matches('/');
    Json(json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
        "scopes_supported": ["claims:read", "claims:write", "analysis:belief"],
        "bearer_methods_supported": ["header"]
    }))
}
