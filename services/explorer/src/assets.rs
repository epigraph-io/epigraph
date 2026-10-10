//! `/static/*`: compiled-in assets (see `build.rs`).
//!
//! A request whose `?v=` matches the asset's content hash is served
//! `immutable` for a year; anything else gets a short max-age so a stale link
//! cannot pin an old file. Both carry a strong ETag and answer
//! `If-None-Match` with 304.

use axum::extract::{Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::error::AppError;

/// One compiled-in file under `static/`.
pub struct Asset {
    /// Path relative to `static/`, `/`-separated (`"app.css"`, `"img/x.svg"`).
    pub path: &'static str,
    pub bytes: &'static [u8],
    /// 16 hex chars; changes whenever the bytes do.
    pub hash: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/static_assets.rs"));

pub fn find(path: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|a| a.path == path)
}

/// `Content-Type` by extension. Text types carry an explicit charset.
pub fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

pub const CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";
pub const CACHE_SHORT: &str = "public, max-age=300";

#[derive(Deserialize)]
pub struct VersionQuery {
    v: Option<String>,
}

pub async fn serve(
    Path(path): Path<String>,
    Query(q): Query<VersionQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let asset = find(&path).ok_or_else(|| AppError::NotFound("static asset".into()))?;
    let etag = format!("\"{}\"", asset.hash);
    let cache = if q.v.as_deref() == Some(asset.hash) {
        CACHE_IMMUTABLE
    } else {
        CACHE_SHORT
    };

    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag || t.trim() == "*"));

    let mut resp = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_type(asset.path)),
            )],
            asset.bytes,
        )
            .into_response()
    };
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    h.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).expect("hex etag is a valid header value"),
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_css_is_compiled_in() {
        let a = find("app.css").expect("static/app.css is embedded");
        assert!(!a.bytes.is_empty());
        assert_eq!(a.hash.len(), 16);
        assert!(find("../Cargo.toml").is_none());
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type("app.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("graph.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("x.SVG"), "image/svg+xml");
        assert_eq!(content_type("noext"), "application/octet-stream");
    }
}
