//! Security headers on every response (plan §3.5).
//!
//! No inline scripts or styles anywhere: templates link `/static/*` files
//! only, so `script-src 'self'` / `style-src 'self'` hold without nonces.
//! There is deliberately no `X-Frame-Options`: framing is governed by CSP
//! `frame-ancestors` alone (the Notion embed needs it).
//!
//! Routes in [`UNFRAMABLE_ROUTES`] (pages next to an action the viewer takes
//! elsewhere, such as confirming an admin act with a passkey) get
//! `frame-ancestors 'none'` and `Referrer-Policy: no-referrer` instead, on
//! every response for that path, error and redirect responses included.
//!
//! A response that sets no cache policy of its own gets
//! [`DEFAULT_CACHE_CONTROL`] plus `Vary: Cookie`: pages render what one
//! signed-in viewer may read, so no browser history cache or shared cache
//! may keep them. Responses with their own policy (`/static/*`, the `/bff`
//! ETag routes, auth and error responses) keep it.

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::AppState;

/// Cache policy for every response that did not choose one.
pub const DEFAULT_CACHE_CONTROL: &str = "private, no-store";

/// Route paths (base path stripped) that no site may frame and that send
/// no referrer: `/acts` links out to the API's own confirmation page for an
/// admin act, so it must not be clickjacked or name itself to that page.
///
/// Every other page is framable by `frame-ancestors`, and its default
/// admits pages anyone can publish: every Notion page shares the `notion.so`
/// site, so a viewer signed in to the embed on their own page is signed in
/// inside an Explorer frame on a stranger's public page too (the partitioned
/// cookie is keyed by that site). Today the only consequential control on a
/// framable page is Sign out. A page that adds a control with consequences
/// (anything that changes state, or links out to a confirmation) must be
/// listed here.
pub const UNFRAMABLE_ROUTES: &[&str] = &["/acts"];

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

pub async fn security_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let unframable = UNFRAMABLE_ROUTES.contains(&state.links.strip_base(req.uri().path()));
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let (csp, referrer) = if unframable {
        (state.csp_unframable.clone(), "no-referrer")
    } else {
        (state.csp.clone(), "same-origin")
    };
    h.insert(header::CONTENT_SECURITY_POLICY, csp);
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static(referrer));
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(DEFAULT_CACHE_CONTROL),
        );
        h.append(header::VARY, HeaderValue::from_static("Cookie"));
    }
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
