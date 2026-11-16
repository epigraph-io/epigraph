//! `/bff/atlas/maps/*` and `/bff/atlas/claim-leaf/*`: the nested Atlas levels
//! of the per-team maps (backlog W10). OWNED BY THE ATLAS AREA.
//!
//! | Route | Upstream |
//! |---|---|
//! | `maps/{key}/{hierarchy}/{id}` | `GET /api/v1/atlas/maps/:map/:hierarchy/levels/:id` |
//! | `claim-leaf/{key}/{hierarchy}/{claim_id}` | `GET /api/v1/atlas/maps/:map/:hierarchy/claims/:claim_id/leaf` |
//!
//! `{key}` is the map's `data-atlas-maps` key (`public` or `team-<32 hex>`,
//! [`KernelMap::key`]), so a map's `level_url` is `/bff/atlas/maps/<key>/` and
//! a level is `<level_url><hierarchy>/<id>` (`crate::atlas_maps`).
//!
//! # Tenancy
//!
//! Every call carries the viewer's own bearer; the kernel reads on the
//! viewer's stamped session and filters each leaf for that session. The BFF
//! passes the kernel's level bytes through unchanged. It decodes them only to
//! check they are the map, hierarchy and level asked for (a mismatch is a
//! 502). Absent, unreadable and forbidden are one 404 with the contract's
//! `bff_not_found` body, and so is a key, hierarchy or id that names nothing.
//!
//! # Caching and compression
//!
//! - `Cache-Control: private, no-cache` and `Vary: Cookie`: team data never
//!   goes into a shared cache, and the browser revalidates every use.
//! - `ETag: W/"<run id>.<level id>.<digest>"`, the digest being 16 hex digits
//!   of the SHA-256 of the bytes served. The run and the level say which
//!   stored document it is; the digest is there because the kernel filters a
//!   leaf per viewer, so two viewers' bytes for one (run, level) can differ.
//!   Weak, because the bytes on the wire depend on the encoding.
//! - A matching `If-None-Match` gets a 304, but only AFTER the kernel answered
//!   200 for this viewer: a member who has lost access gets the 404, never a
//!   304 for a body they may no longer read.
//! - The prod reverse proxy compresses nothing, and the 150 KB budget is gzip
//!   bytes, so these routes compress their own answers (gzip or br, as the
//!   client accepts; gzip at flate2's default level, the level the budget is
//!   measured at, and br at tower-http's default quality 4).

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use sha2::{Digest, Sha256};
use tower_http::compression::{CompressionLayer, CompressionLevel};
use uuid::Uuid;

use crate::atlas_maps::parse_hierarchy;
use crate::auth::SignedIn;
use crate::error::AppError;
use crate::state::AppState;
use crate::upstream::atlas_level::{AtlasLevel, Hierarchy};
use crate::upstream::atlas_maps::{KernelMap, CLAIM_LEAF_SCHEMA_VERSION};
use crate::upstream::UpstreamError;

/// The cache policy of a level answer.
pub const LEVEL_CACHE_CONTROL: &str = "private, no-cache";
/// The cache policy of a claim-to-leaf answer.
pub const CLAIM_LEAF_CACHE_CONTROL: &str = "private, no-store";
/// What a refused level is called in the not-found body.
pub const LEVEL_WHAT: &str = "atlas level";
/// What a refused claim-to-leaf lookup is called in the not-found body.
pub const CLAIM_LEAF_WHAT: &str = "claim on this map";
/// The path prefix of the level route (and of every map's `level_url`).
pub const MAPS_PREFIX: &str = "/bff/atlas/maps/";
/// The path prefix of the claim-to-leaf route.
pub const CLAIM_LEAF_PREFIX: &str = "/bff/atlas/claim-leaf/";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/bff/atlas/maps/{key}/{hierarchy}/{id}", get(level))
        .route(
            "/bff/atlas/claim-leaf/{key}/{hierarchy}/{claim}",
            get(claim_leaf),
        )
        .layer(
            CompressionLayer::new()
                .gzip(true)
                .br(true)
                .quality(CompressionLevel::Default),
        )
}

/// The ETag of `body`, served as level `level_id` of run `run_id`.
pub fn level_etag(run_id: Uuid, level_id: Uuid, body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("W/\"{run_id}.{level_id}.{hex}\"")
}

/// Whether an `If-None-Match` header names `etag` (weak comparison) or `*`.
pub fn if_none_match(headers: &HeaderMap, etag: &str) -> bool {
    let strip = |t: &str| t.trim().trim_start_matches("W/").to_string();
    let want = strip(etag);
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim() == "*" || strip(t) == want)
}

fn bad_answer(what: &str) -> AppError {
    AppError::from(UpstreamError::Decode(format!(
        "the API answered with {what} than the one asked for"
    )))
}

/// Absent, unreadable and forbidden: one 404.
fn refused(what: &'static str) -> impl Fn(UpstreamError) -> AppError {
    move |e| match e {
        UpstreamError::NotFound { .. } | UpstreamError::Forbidden { .. } => {
            AppError::NotFound(what.into())
        }
        other => other.into(),
    }
}

fn parse_request(
    key: &str,
    hierarchy: &str,
    id: &str,
    what: &'static str,
) -> Result<(KernelMap, Hierarchy, Uuid), AppError> {
    let nf = || AppError::NotFound(what.into());
    let map = KernelMap::from_key(key).ok_or_else(nf)?;
    let h = parse_hierarchy(hierarchy).ok_or_else(nf)?;
    let id = Uuid::try_parse(id).map_err(|_| nf())?;
    Ok((map, h, id))
}

/// One level of a map, as the kernel served it to this viewer.
async fn level(
    State(state): State<AppState>,
    user: SignedIn,
    headers: HeaderMap,
    Path((key, hierarchy, id)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let (map, h, id) = parse_request(&key, &hierarchy, &id, LEVEL_WHAT)?;
    let body = user
        .api(&state)
        .atlas_level_raw(map, h, id)
        .await
        .map_err(refused(LEVEL_WHAT))?;
    let doc: AtlasLevel = serde_json::from_slice(&body)
        .map_err(|e| AppError::from(UpstreamError::Decode(format!("an atlas level: {e}"))))?;
    let (scope, group, hier, level_id, run_id) = match &doc {
        AtlasLevel::Group(g) => (
            g.map_scope,
            g.map_group_id,
            g.hierarchy,
            g.level_id,
            g.run_id,
        ),
        AtlasLevel::Leaf(l) => (
            l.map_scope,
            l.map_group_id,
            l.hierarchy,
            l.level_id,
            l.run_id,
        ),
    };
    if (scope, group) != map.scope() || hier != h || level_id != id {
        tracing::error!(%id, ?map, "the API answered a level request with another level");
        return Err(bad_answer("another map, hierarchy or level"));
    }
    let etag = level_etag(run_id, level_id, &body);
    let fresh = if_none_match(&headers, &etag);
    let mut resp = if fresh {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response()
    };
    let h = resp.headers_mut();
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(LEVEL_CACHE_CONTROL),
    );
    h.append(header::VARY, HeaderValue::from_static("Cookie"));
    h.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(|e| AppError::Internal(format!("etag: {e}")))?,
    );
    Ok(resp)
}

/// The leaf of a map holding a claim the viewer can read.
async fn claim_leaf(
    State(state): State<AppState>,
    user: SignedIn,
    Path((key, hierarchy, claim)): Path<(String, String, String)>,
) -> Result<Response, AppError> {
    let (map, h, claim) = parse_request(&key, &hierarchy, &claim, CLAIM_LEAF_WHAT)?;
    let leaf = user
        .api(&state)
        .atlas_claim_leaf(map, h, claim)
        .await
        .map_err(refused(CLAIM_LEAF_WHAT))?;
    if leaf.schema_version != CLAIM_LEAF_SCHEMA_VERSION
        || (leaf.map_scope, leaf.map_group_id) != map.scope()
        || leaf.hierarchy != h
        || leaf.claim_id != claim
    {
        tracing::error!(%claim, ?map, "the API answered a claim-to-leaf request for another claim or map");
        return Err(bad_answer("another map, hierarchy or claim"));
    }
    let bytes = serde_json::to_vec(&leaf)
        .map_err(|e| AppError::Internal(format!("encoding a claim leaf: {e}")))?;
    let mut resp = (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        bytes,
    )
        .into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CLAIM_LEAF_CACHE_CONTROL),
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_etag_names_run_level_and_bytes() {
        let (r, l) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let a = level_etag(r, l, b"{\"a\":1}");
        assert!(a.starts_with(&format!("W/\"{r}.{l}.")), "{a}");
        assert_ne!(a, level_etag(r, l, b"{\"a\":2}"), "the bytes count");
        assert_ne!(a, level_etag(Uuid::from_u128(3), l, b"{\"a\":1}"));
    }

    #[test]
    fn if_none_match_compares_weakly_and_lists() {
        let etag = level_etag(Uuid::nil(), Uuid::nil(), b"x");
        let mut h = HeaderMap::new();
        assert!(!if_none_match(&h, &etag));
        h.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_str(&format!("\"other\", {}", etag.trim_start_matches("W/")))
                .unwrap(),
        );
        assert!(if_none_match(&h, &etag));
        let mut star = HeaderMap::new();
        star.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(if_none_match(&star, &etag));
        let mut other = HeaderMap::new();
        other.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("W/\"nope\""),
        );
        assert!(!if_none_match(&other, &etag));
    }
}
