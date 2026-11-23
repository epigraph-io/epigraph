//! `POST /api/v1/papers/:id/authors/countersign`: the REST twin of MCP
//! `countersign_authorship` (backlog 04c02296).
//!
//! A person another principal's document ingest named as an author, without
//! speaking for them, holds a PENDING authorship of that paper (an
//! `agent -authored-> paper` row marked `pending_countersign`, the naming
//! ingest's word). Here the named person, or that agent's live operator,
//! confirms it (it stops being pending on every surface: the claim's
//! `authored_by`, the agent card, the paper listing) or declines it (the
//! naming is retracted).
//!
//! The route writes nothing itself: it calls the one countersign definer
//! (migration 208, `epigraph_db::CountersignRepository::countersign_conn`)
//! on a transaction stamped from the CALLER's own viewer
//! ([`AppState::write_as`]), exactly as the MCP tool does, so the database
//! decides who may act (the named agent itself, or its live operator: its
//! operator link while not retired, else its unrevoked client allowance) and
//! audits each act in `security_events`.
//!
//! * 401 without authentication; 403 without `claims:write`;
//! * 400 for a `decision` other than `confirm` / `decline`;
//! * 403 for a caller the definer refuses, with the definer's coded reason
//!   (`CSG01`: no authenticated principal; `CSG02`: not the named agent nor
//!   its live operator) and nothing written;
//! * 200 with the rows changed (`changed`, each `confirmed` or `declined`);
//! * 200 with `changed: []` and a `message` when nothing is pending (never
//!   pending, already confirmed or declined, or a repeat): nothing written,
//!   nothing audited. This is the MCP tool's answer, not a refusal.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;
#[cfg(feature = "db")]
use axum::{
    extract::{Path, State},
    Json,
};

/// The scope the route requires (the MCP tool's, `scope_map.rs`).
pub const COUNTERSIGN_SCOPE: &str = "claims:write";

/// The answer when no in-force authorship awaits a countersignature; the
/// MCP tool's text, word for word.
pub const NOTHING_PENDING_MESSAGE: &str =
    "nothing pending: no in-force authorship of this agent on this paper awaits a \
     countersignature (it was never pending, or was already confirmed or declined); \
     nothing was written";

/// Body of `POST /api/v1/papers/{id}/authors/countersign`.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CountersignAuthorshipRequest {
    /// `confirm` (you are an author of this document: the naming stops being
    /// pending) or `decline` (you are not: the naming is retracted).
    pub decision: String,
    /// The agent named, when you act as its live human operator; default:
    /// yourself.
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    /// Only the naming by this ingester (the paper listing's `ingested_by`
    /// on the pending author); default: every pending naming of the agent on
    /// this paper.
    #[serde(default)]
    pub ingested_by: Option<Uuid>,
}

/// One authorship row the act changed.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CountersignedRowView {
    pub edge_id: Uuid,
    /// The principal whose ingest named the person.
    pub ingested_by: Option<Uuid>,
    /// `confirmed` or `declined`.
    pub outcome: String,
}

/// What the countersign did.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CountersignAuthorshipResponse {
    pub paper_id: Uuid,
    /// `confirm` or `decline`, normalised.
    pub decision: String,
    /// The rows changed; empty when nothing was pending.
    pub changed: Vec<CountersignedRowView>,
    /// Present only when `changed` is empty: why nothing was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `POST /api/v1/papers/:id/authors/countersign`. See the module doc.
///
/// # Errors
/// 401 without authentication; 403 without `claims:write` or when the
/// definer refuses the caller (`CSG01` / `CSG02`); 400 for a bad decision;
/// 500 on a database failure (nothing is written).
#[cfg(feature = "db")]
pub async fn countersign_authorship(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(paper): Path<Uuid>,
    Json(body): Json<CountersignAuthorshipRequest>,
) -> Result<Json<CountersignAuthorshipResponse>, ApiError> {
    // Fail closed: no AuthContext is a 401, never a skipped scope check.
    let auth = auth_ctx
        .ok_or_else(|| ApiError::Unauthorized {
            reason: "POST /api/v1/papers/:id/authors/countersign requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &[COUNTERSIGN_SCOPE])?;
    let decision = epigraph_db::CountersignDecision::parse(&body.decision).map_err(|e| {
        ApiError::ValidationError {
            field: "decision".to_string(),
            reason: match e {
                epigraph_db::DbError::InvalidData { reason } => reason,
                other => other.to_string(),
            },
        }
    })?;

    let mut tx = state.write_as(&viewer, "countersign_authorship").await?;
    // A `CSG01` / `CSG02` refusal is `DbError::Refused { Authority }`, which
    // `ApiError::from` answers 403 with the definer's coded text.
    let rows = epigraph_db::CountersignRepository::countersign_conn(
        &mut tx,
        paper,
        body.agent_id,
        decision,
        body.ingested_by,
    )
    .await
    .map_err(ApiError::from)?;
    tx.commit().await.map_err(|e| ApiError::DatabaseError {
        message: format!("Failed to commit the countersign: {e}"),
    })?;

    let message = rows.is_empty().then(|| NOTHING_PENDING_MESSAGE.to_string());
    Ok(Json(CountersignAuthorshipResponse {
        paper_id: paper,
        decision: decision.as_str().to_string(),
        changed: rows
            .into_iter()
            .map(|r| CountersignedRowView {
                edge_id: r.edge_id,
                ingested_by: r.ingested_by,
                outcome: r.outcome,
            })
            .collect(),
        message,
    }))
}
