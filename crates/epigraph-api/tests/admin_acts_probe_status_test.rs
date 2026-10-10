#![cfg(feature = "db")]
//! What this router answers to the exact request a client uses to detect the
//! admin-acts feature.
//!
//! The Explorer (`services/explorer`, `upstream::capabilities::ADMIN_ACTS_PROBE`)
//! shows its "Admin acts" page only when the API has the admin-acts listing
//! route (`GET /api/v1/admin/acts`, `routes/admin_acts.rs::list_acts`). It
//! sends `GET /api/v1/admin/acts?mine&limit=1` with the viewer's own bearer and
//! maps the status:
//!
//! - 2xx with the listing's `{"acts": [...]}` envelope: present;
//! - 404 or 405: absent, so the page and its nav item stay hidden;
//! - 403: present, but this viewer may not use it;
//! - anything else: unknown, so the feature stays hidden and is re-probed.
//!
//! This test used to pin the 404 a router WITHOUT the route gave that request
//! (`the_admin_acts_probe_is_404_on_main`). The elevation stack is now on
//! main, so it pins what the probe gets instead: a 200 with the envelope, for
//! an ordinary viewer holding exactly the scopes the Explorer asks for, with
//! no admin scope and no elevation. `list_acts` lists the caller's OWN acts
//! only, so an ordinary viewer gets an empty listing, not a refusal.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// The Explorer's probe request, byte for byte (`ADMIN_ACTS_PROBE`).
const ADMIN_ACTS_PROBE: &str = "/api/v1/admin/acts?mine&limit=1";

/// The scopes the Explorer's sign-in asks for (`auth::oauth::SCOPE`).
const EXPLORER_SCOPES: &[&str] = &["claims:read", "audit:read"];

async fn router(pool: &PgPool) -> Router {
    create_router(AppState::with_scoped_pool(
        fixture::scoped_pool(pool).await,
        ApiConfig::default(),
    ))
}

async fn get(router: &Router, uri: &str, bearer: &str) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

/// Verified to fail with the route's registration removed from
/// `routes/mod.rs` (404, which the Explorer reads as `Absent`).
#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_acts_probe_gets_the_listing_envelope_on_main(pool: PgPool) {
    let app = router(&pool).await;
    let agent = common::seed_system_agent(&pool).await;
    let bearer = common::mint_token_with_agent(EXPLORER_SCOPES, agent);

    let (status, body) = get(&app, ADMIN_ACTS_PROBE, &bearer).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the probe must get a 2xx, which the Explorer reads as `Present`: {body}"
    );
    assert_eq!(
        body,
        json!({ "acts": [] }),
        "the listing envelope the Explorer decodes, empty for a viewer who proposed nothing"
    );

    // Calibration: an unauthenticated probe is refused by the bearer layer,
    // so the 200 above is the route answering this viewer, not a public page.
    let (status, _) = get(&app, ADMIN_ACTS_PROBE, "not-a-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // And a random agent id (no `agents` row) is served the same way, so the
    // Explorer's probe never depends on the viewer having history.
    let stranger = common::mint_token_with_agent(EXPLORER_SCOPES, Uuid::new_v4());
    let (status, body) = get(&app, ADMIN_ACTS_PROBE, &stranger).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "acts": [] }));
}
