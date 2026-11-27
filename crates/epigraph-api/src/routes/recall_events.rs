//! `GET /api/v1/recall-events`: the caller's OWN recall history (backlog
//! 2cf7b6a1, decided under backlog ecf1b34f).
//!
//! The recall audit log (`recall_events`, migration 058) records, for every
//! recall an agent runs, its query text and the claim ids it returned. This
//! route lists those rows for the caller and for nobody else: it has no agent
//! parameter. It is the REST read of the MCP `get_recall_events` tool, with
//! the same row fields, restricted to the caller's own rows.
//!
//! # Whose rows, three times over
//!
//! 1. The read runs on the caller's viewer-stamped connection
//!    ([`AppState::read_as`]), where `recall_events_tenancy` (migration 077)
//!    admits only rows whose `agent_id` is the session principal.
//! 2. [`RecallEventRepository::list_own`] filters `agent_id = <the viewer's
//!    principal>` itself, so an elevated session (126's read arm) or a
//!    legacy `'public'`-stamped row does not widen the answer.
//! 3. An `agent_id` query parameter naming anyone but the caller is refused
//!    (400), rather than ignored, so a client that expects the MCP tool's
//!    `agent_id` filter learns that this route does not take one instead of
//!    reading its own rows as someone else's.
//!
//! # Pages
//!
//! The list-endpoint convention (`docs/conventions/api-pagination.md`):
//! `?after=` and `?limit=`, answered with [`Page`]`{items, next_cursor}`.
//! Rows come newest first; `limit` defaults to [`DEFAULT_LIMIT`] and is
//! clamped to `[1, MAX_LIMIT]`. The cursor is an unsigned keyset position
//! (`k1.<created_at micros>.<id>`, the `LabelCursor` token): it names a row
//! the caller was already served, and a forged one only moves the start of a
//! read that stays restricted to the caller's rows.
//!
//! `since`, `until` (RFC 3339) and `claim_id` narrow the read; none of them
//! can widen it.

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use epigraph_db::repos::claim::LabelCursor;
use epigraph_db::{OwnRecallFilter, RecallEventRepository, RecallEventRow};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::{AuthContext, ViewerExtractor};
use crate::routes::pagination::Page;
use crate::state::AppState;

/// The scope the route requires (the MCP tool's, `scope_map.rs`).
pub const REQUIRED_SCOPE: &str = "claims:read";
/// Rows a page holds when the caller names no `limit`.
pub const DEFAULT_LIMIT: u32 = 20;
/// The largest `limit` honoured; a larger one is clamped to it.
pub const MAX_LIMIT: u32 = 200;

const BAD_CURSOR: &str =
    "malformed `after` cursor; pass back the `next_cursor` of the previous page unchanged";

/// `GET /api/v1/recall-events` query.
#[derive(Debug, Default, Deserialize)]
pub struct RecallEventsQuery {
    /// The `next_cursor` of the previous page.
    #[serde(default)]
    pub after: Option<String>,
    /// Rows per page, clamped to `[1, MAX_LIMIT]`.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Only rows created at or after this RFC 3339 instant.
    #[serde(default)]
    pub since: Option<String>,
    /// Only rows created at or before this RFC 3339 instant.
    #[serde(default)]
    pub until: Option<String>,
    /// Only queries that returned this claim.
    #[serde(default)]
    pub claim_id: Option<String>,
    /// Accepted only when it names the caller; see the module doc.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// One recall, as the MCP `get_recall_events` tool returns it.
#[derive(Debug, Serialize)]
pub struct RecallEventView {
    pub id: Uuid,
    pub agent_id: Option<Uuid>,
    /// The tool that ran the recall (`recall`, `recall_with_context`, ...).
    pub tool: String,
    pub query_text: String,
    /// Hex BLAKE3 of the query vector; `null` for a lexical-only recall (the
    /// embedder was down).
    pub query_embedding_hash: Option<String>,
    pub params: serde_json::Value,
    pub returned_claim_ids: Vec<Uuid>,
    /// RFC 3339.
    pub created_at: String,
}

impl From<RecallEventRow> for RecallEventView {
    fn from(r: RecallEventRow) -> Self {
        Self {
            id: r.id,
            agent_id: r.agent_id,
            tool: r.tool,
            query_text: r.query_text,
            query_embedding_hash: r.query_embedding_hash.map(hex::encode),
            params: r.params,
            returned_claim_ids: r.returned_claim_ids,
            created_at: r.created_at.to_rfc3339(),
        }
    }
}

fn bad_request(message: impl Into<String>) -> ApiError {
    ApiError::BadRequest {
        message: message.into(),
    }
}

fn parse_time(
    raw: Option<&str>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, ApiError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|d| Some(d.with_timezone(&chrono::Utc)))
            .map_err(|_| bad_request(format!("`{field}` must be an RFC 3339 timestamp"))),
    }
}

fn parse_uuid(raw: Option<&str>, field: &str) -> Result<Option<Uuid>, ApiError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => Uuid::parse_str(s)
            .map(Some)
            .map_err(|_| bad_request(format!("`{field}` must be a UUID"))),
    }
}

/// `GET /api/v1/recall-events`: one page of the caller's own recall history,
/// newest first (`claims:read`).
///
/// # Errors
/// 401 without a principal; 403 without `claims:read`; 400 for a malformed
/// `after`, `since`, `until` or `claim_id`, and for an `agent_id` that is not
/// the caller.
pub async fn list_own_recall_events(
    State(state): State<AppState>,
    auth_ctx: Option<Extension<AuthContext>>,
    ViewerExtractor(viewer): ViewerExtractor,
    Query(q): Query<RecallEventsQuery>,
) -> Result<Json<Page<RecallEventView>>, ApiError> {
    let Some(Extension(auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "recall history requires authentication".into(),
        });
    };
    crate::middleware::scopes::check_scopes(&auth, &[REQUIRED_SCOPE])?;
    let Some(principal) = viewer.principal() else {
        return Err(ApiError::Unauthorized {
            reason: "recall history requires an authenticated agent".into(),
        });
    };
    if let Some(named) = parse_uuid(q.agent_id.as_deref(), "agent_id")? {
        if named != principal {
            return Err(bad_request(
                "this route lists only the caller's own recall events; drop `agent_id`",
            ));
        }
    }
    let after = q
        .after
        .as_deref()
        .map(|raw| LabelCursor::decode(raw).ok_or_else(|| bad_request(BAD_CURSOR)))
        .transpose()?;
    let filter = OwnRecallFilter {
        claim_id: parse_uuid(q.claim_id.as_deref(), "claim_id")?,
        since: parse_time(q.since.as_deref(), "since")?,
        until: parse_time(q.until.as_deref(), "until")?,
    };
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let mut read = super::open_scoped_read(&state, &viewer, "list_own_recall_events").await?;
    // One row past the page: whether it comes back says whether a next page
    // exists, so the last page carries `next_cursor: null`.
    let rows = RecallEventRepository::list_own(
        &mut *read,
        &viewer,
        &filter,
        after,
        i64::from(limit) + 1,
    )
    .await
    .map_err(|e| {
        tracing::error!(target: "recall_events.route", error = %e, "list own recall events");
        ApiError::InternalError {
            message: "recall history: could not read the audit log".into(),
        }
    })?;
    super::finish_scoped_read(read, "list_own_recall_events").await?;

    let page = Page::from_overfetch(rows, limit as usize, |r| {
        LabelCursor {
            created_at: r.created_at,
            id: r.id,
        }
        .encode()
    });
    Ok(Json(Page {
        items: page.items.into_iter().map(RecallEventView::from).collect(),
        next_cursor: page.next_cursor,
    }))
}
