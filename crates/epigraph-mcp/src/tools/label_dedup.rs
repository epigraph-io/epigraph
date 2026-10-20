//! `plan_label_dedup`, `apply_label_dedup` and `probe_label_dedup`: thin MCP
//! tools over the pure `epigraph_engine::label_dedup` planner.

use std::path::PathBuf;

use rmcp::model::CallToolResult;

use crate::errors::McpError;
use crate::server::EpiGraphMcpFull;
use crate::types::{ApplyLabelDedupParams, PlanLabelDedupParams, ProbeLabelDedupParams};

/// The default and the server cap of `max_claims`.
pub const DEFAULT_MAX_CLAIMS: usize = 5000;

/// The environment variable naming the directory stdio `profile_path` must
/// resolve under.
pub const PROFILE_ROOT_ENV: &str = "EPIGRAPH_MCP_PROFILE_ROOT";
/// The environment variable carrying the profile hash a stdio caller must pin.
pub const PROFILE_PIN_ENV: &str = "EPIGRAPH_MCP_PROFILE_PIN";

/// Per-process label-dedup settings, read once at startup.
#[derive(Debug, Clone)]
pub struct LabelDedupConfig {
    /// Where stdio `profile_path` must resolve. `None`: path mode refused.
    pub profile_root: Option<PathBuf>,
    /// The hash a stdio `profile_hash` must equal. `None`: no pin.
    pub profile_pin: Option<String>,
    /// The server cap on `max_claims`.
    pub max_claims_cap: usize,
}

impl Default for LabelDedupConfig {
    fn default() -> Self {
        Self {
            profile_root: None,
            profile_pin: None,
            max_claims_cap: DEFAULT_MAX_CLAIMS,
        }
    }
}

impl LabelDedupConfig {
    /// Read [`PROFILE_ROOT_ENV`] and [`PROFILE_PIN_ENV`]; an empty value is
    /// unset.
    #[must_use]
    pub fn from_env() -> Self {
        Self::default()
    }
}

fn not_implemented() -> McpError {
    McpError {
        code: rmcp::model::ErrorCode::INTERNAL_ERROR,
        message: "NOT_IMPLEMENTED".into(),
        data: Some(serde_json::json!({ "code": "NOT_IMPLEMENTED" })),
    }
}

/// Plan a label-family dedup pass. Read-only.
///
/// # Errors
/// A refusal carrying `data.code`.
pub async fn plan_label_dedup(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: PlanLabelDedupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let _ = (server, viewer, params, auth);
    Err(not_implemented())
}

/// Re-plan from live state and apply the plan the caller reviewed.
///
/// # Errors
/// A refusal carrying `data.code`.
pub async fn apply_label_dedup(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ApplyLabelDedupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let _ = (server, viewer, params, auth);
    Err(not_implemented())
}

/// Classify would-be claims against the family index. Read-only.
///
/// # Errors
/// A refusal carrying `data.code`.
pub async fn probe_label_dedup(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ProbeLabelDedupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let _ = (server, viewer, params, auth);
    Err(not_implemented())
}
