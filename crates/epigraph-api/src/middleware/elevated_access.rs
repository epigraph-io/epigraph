//! The API's per-access recorder (elevation plan EL-8): every request served
//! to an ELEVATED viewer is recorded in migration 127's `elevated_access` log
//! BEFORE its response leaves, or the response is withheld.
//!
//! # How a request is known to be elevated
//!
//! Only [`super::bearer::ViewerExtractor`] decides it, by resolving the
//! token's elevation claim against the database. So this layer, which runs
//! around the handler, hands the extractor a [`ElevatedAccessSlot`] in the
//! request's extensions, and the extractor MARKS it when (and only when) it
//! builds an elevated viewer. After the handler, a marked slot means the
//! response was produced for an elevated viewer, and it is recorded. A request
//! whose token claims an elevation that is not live resolves the scoped viewer,
//! leaves the slot unmarked, and is served as before. The extractor REFUSES an
//! elevated viewer to a request that carries no slot, so no handler can be
//! handed one outside this layer (`ViewerExtractor`'s doc).
//!
//! # Cost
//!
//! Nothing for a token without an elevation claim (`elv`): the layer passes it
//! straight through. A token with one has its request body buffered (bounded by
//! the router's body limit) for the request's id-shaped fields; a MARKED
//! request has its response buffered (at most [`MAX_RECORDED_BODY`]), scanned
//! for ids, and recorded on its own stamped transaction (one viewer
//! resolution, one recorder call).
//!
//! # Fail-closed
//!
//! Any failure after the handler ran for an elevated viewer (a body too large
//! to scan, the viewer no longer elevated, the recorder refusing or failing)
//! answers 500 and the handler's body is DROPPED: an elevated read that is not
//! recorded is never sent.

use crate::errors::ApiError;
use crate::middleware::bearer::AuthContext;
use crate::state::AppState;
use axum::body::{to_bytes, Body};
use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use epigraph_db::repos::elevated_access::{
    bounded, candidate_ids_in, id_fields_in, rows_in, MAX_SURFACE_LEN,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// The largest response body the layer will buffer to record. A larger
/// elevated response is withheld (500), never sent unscanned.
pub const MAX_RECORDED_BODY: usize = 64 * 1024 * 1024;

/// The longest path or query string the log keeps.
const MAX_ARG_TEXT: usize = 2048;

/// What the extractor knew when it built an elevated viewer: enough to build
/// it again for the recorder's own transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElevatedMark {
    /// The elevated principal.
    pub principal: Uuid,
    /// The live elevation session the database answered for.
    pub session_id: Uuid,
    /// Its refresh family.
    pub family_id: Uuid,
}

/// The slot this layer hands the viewer extractor (request extensions). The
/// extractor marks it when it builds an elevated viewer.
#[derive(Debug, Clone, Default)]
pub struct ElevatedAccessSlot(Arc<Mutex<Option<ElevatedMark>>>);

impl ElevatedAccessSlot {
    /// Record that this request's viewer is elevated.
    pub fn mark(&self, mark: ElevatedMark) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(mark);
        }
    }

    /// The mark, if the request's viewer was elevated. A poisoned lock is
    /// read as marked-with-nothing-known, which the caller treats as a
    /// failure to record (fail-closed).
    fn take(&self) -> Result<Option<ElevatedMark>, ()> {
        self.0.lock().map(|mut s| s.take()).map_err(|_| ())
    }
}

fn withheld(reason: &str) -> Response {
    tracing::error!(
        target: "elevation",
        reason = %reason,
        "an elevated response could not be recorded; withheld"
    );
    ApiError::InternalError {
        message: "ELEVATED ACCESS NOT RECORDED: the response is withheld".to_string(),
    }
    .into_response()
}

/// The layer (installed as a route layer on the authenticated router, inside
/// the bearer middleware, so the `AuthContext` and the matched route are
/// known).
pub async fn record_elevated_access(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(auth) = request.extensions().get::<AuthContext>().cloned() else {
        return next.run(request).await;
    };
    if auth.elevation_claim.is_none() {
        return next.run(request).await;
    }

    let surface = bounded(
        &format!(
            "{} {}",
            request.method(),
            request
                .extensions()
                .get::<MatchedPath>()
                .map_or_else(|| request.uri().path(), MatchedPath::as_str)
        ),
        MAX_SURFACE_LEN,
    );
    let path = bounded(request.uri().path(), MAX_ARG_TEXT);
    let query = request
        .uri()
        .query()
        .map(|q| bounded(q, MAX_ARG_TEXT))
        .unwrap_or_default();

    // The request body, for its id-shaped fields (never its content). Bounded
    // by the router's own body limit.
    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, state.config.max_request_size).await else {
        return ApiError::BadRequest {
            message: "request body too large or unreadable".to_string(),
        }
        .into_response();
    };
    let body_ids = serde_json::from_slice::<serde_json::Value>(&bytes)
        .map(|v| id_fields_in(&v))
        .unwrap_or_else(|_| serde_json::json!({}));
    let mut request = Request::from_parts(parts, Body::from(bytes));
    let slot = ElevatedAccessSlot::default();
    request.extensions_mut().insert(slot.clone());

    let response = next.run(request).await;

    let mark = match slot.take() {
        Ok(None) => return response,
        Ok(Some(mark)) => mark,
        Err(()) => return withheld("the elevation slot was poisoned"),
    };
    let (parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_RECORDED_BODY).await else {
        return withheld("the elevated response is too large to record");
    };
    let row_count = serde_json::from_slice::<serde_json::Value>(&bytes)
        .map(|v| rows_in(&v))
        .unwrap_or(0);
    let access = epigraph_db::ElevatedAccess {
        surface,
        args: serde_json::json!({
            "path": path,
            "query": query,
            "body_ids": body_ids,
            "jti": auth.jti,
            "status": parts.status.as_u16(),
        }),
        row_count,
        candidate_ids: candidate_ids_in(&bytes),
    };
    let Some(scoped) = state.scoped.as_ref() else {
        return withheld("no ScopedPool to record on");
    };
    let viewer = match epigraph_db::Viewer::resolve_elevated(
        scoped,
        mark.principal,
        Some(mark.session_id),
        mark.family_id,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return withheld(&e.to_string()),
    };
    if let Err(e) = scoped.record_elevated_access(&viewer, &access).await {
        return withheld(&e.to_string());
    }
    Response::from_parts(parts, Body::from(bytes))
}
