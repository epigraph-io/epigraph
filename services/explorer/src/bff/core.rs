//! `/bff/claim/:id`, `/bff/search` (plan §3.4). OWNED BY THE CORE AREA.
//!
//! Both serve exactly what the matching page renders (the composition lives
//! in `crate::pages::core`), as JSON. Degraded sections serialize as
//! `{"status":"unavailable","reason":…}`.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use sha2::{Digest, Sha256};

use crate::auth::SignedIn;
use crate::error::AppError;
use crate::pages::core::claim_view::compose;
use crate::pages::core::parse_claim_id;
use crate::pages::core::search_view::{self, RawSearchQuery, SearchOutcome, SearchParams};
use crate::state::AppState;

/// Composed per viewer, so never shared; revalidate every time (the ETag
/// makes that cheap for the client).
const CLAIM_CACHE_CONTROL: &str = "private, no-cache";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/bff/claim/{id}", get(claim))
        .route("/bff/search", get(search))
}

/// The composed claim view, with a weak ETag over the serialized body
/// (plan §3.5: `updated_at` does not move when edges are added, so it cannot
/// be the validator). A matching `If-None-Match` gets 304 with no body.
async fn claim(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let id = parse_claim_id(&raw)?;
    let api = user.api(&state);
    let view = compose(&api, &state.links, id).await?;
    let body = serde_json::to_vec(&view)
        .map_err(|e| AppError::Internal(format!("serializing claim view: {e}")))?;
    let etag = weak_etag(&body);

    let not_modified = headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| if_none_match_hits(v, &etag));

    let mut resp = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut r = Response::new(Body::from(body));
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        r
    };
    let h = resp.headers_mut();
    h.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).expect("hex etag is a valid header"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CLAIM_CACHE_CONTROL),
    );
    h.insert(header::VARY, HeaderValue::from_static("Cookie"));
    Ok(resp)
}

/// `W/"<32 hex digits of sha256(body)>"`.
pub fn weak_etag(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("W/\"{hex}\"")
}

/// RFC 9110 §13.1.2: `If-None-Match` uses weak comparison, so `W/` is
/// ignored on both sides; `*` matches any current representation.
pub fn if_none_match_hits(header_value: &str, etag: &str) -> bool {
    let opaque = |t: &str| {
        let t = t.trim();
        t.strip_prefix("W/").unwrap_or(t).to_string()
    };
    let ours = opaque(etag);
    header_value
        .split(',')
        .map(str::trim)
        .any(|t| t == "*" || opaque(t) == ours)
}

/// As `/search`, as JSON. An empty or invalid query is a 400 here (the page
/// shows the form instead).
async fn search(
    State(state): State<AppState>,
    user: SignedIn,
    Query(raw): Query<RawSearchQuery>,
) -> Result<Json<SearchOutcome>, AppError> {
    let params = SearchParams::from_raw(&raw);
    if params.q.is_empty() {
        return Err(AppError::BadRequest("Enter a search query.".into()));
    }
    let api = user.api(&state);
    let outcome = search_view::run(&api, &state.links, &params).await?;
    if let Some(problem) = &outcome.problem {
        return Err(AppError::BadRequest(problem.clone()));
    }
    Ok(Json(outcome))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etags_are_weak_and_body_derived() {
        let a = weak_etag(b"{\"a\":1}");
        assert!(
            a.starts_with("W/\"") && a.ends_with('"') && a.len() == 36,
            "{a}"
        );
        assert_eq!(a, weak_etag(b"{\"a\":1}"));
        assert_ne!(a, weak_etag(b"{\"a\":2}"));
    }

    #[test]
    fn if_none_match_uses_weak_comparison() {
        let e = weak_etag(b"x");
        let strong = e.trim_start_matches("W/").to_string();
        assert!(if_none_match_hits(&e, &e));
        assert!(if_none_match_hits(&strong, &e));
        assert!(if_none_match_hits(&format!("\"other\", {e}"), &e));
        assert!(if_none_match_hits("*", &e));
        assert!(!if_none_match_hits("W/\"other\"", &e));
        assert!(!if_none_match_hits("", &e));
    }
}
