//! Security headers on every response (plan §3.5).
//!
//! No inline scripts or styles anywhere: templates link `/static/*` files
//! only, so `script-src 'self'` / `style-src 'self'` hold without nonces.
//! There is deliberately no `X-Frame-Options`: framing is governed by CSP
//! `frame-ancestors` alone (the Notion embed needs it).

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::AppState;

/// The CSP with `frame-ancestors` from config (already validated to be a
/// plain source list).
pub fn content_security_policy(
    frame_ancestors: &str,
) -> Result<HeaderValue, header::InvalidHeaderValue> {
    HeaderValue::from_str(&format!(
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
         connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors {frame_ancestors}"
    ))
}

/// Default `Cache-Control` for anything that is not a static asset.
///
/// Every page the Explorer renders is per-viewer: the API filters each read
/// by the signed-in viewer, so the same URL is a different document for two
/// readers, and a claim page carries claim text verbatim. `private` keeps it
/// out of any shared cache; `no-store` keeps it off disk, out of a Back-
/// Forward cache replay after sign-out, and out of a proxy that ignores
/// `private`. The `/bff/*` JSON already sends its own value.
pub const PAGE_CACHE_CONTROL: &str = "private, no-store";

pub async fn security_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, state.csp.clone());
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    // Only where the handler said nothing. `assets::serve` sets its own
    // `public, max-age=…` (static files hold no viewer data and must stay
    // cacheable), and the auth routes and the BFF set theirs; a handler's
    // choice is never overridden.
    h.entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static(PAGE_CACHE_CONTROL));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_matches_the_plan() {
        let v = content_security_policy("https://www.notion.so https://*.notion.so").unwrap();
        assert_eq!(
            v.to_str().unwrap(),
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; form-action 'self'; base-uri 'none'; \
             frame-ancestors https://www.notion.so https://*.notion.so"
        );
    }
}
