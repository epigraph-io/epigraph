#![cfg(feature = "db")]
//! What this router answers to a route it does not register, measured with
//! the exact request a client uses to detect an optional feature.
//!
//! The Explorer (`services/explorer`, `upstream::capabilities::ADMIN_ACTS_PROBE`)
//! shows its "Admin acts" page only when the API has the admin-acts listing
//! route. That route (`GET /api/v1/admin/acts`, `routes/admin_acts.rs::list_acts`)
//! exists only on the unmerged elevation stack (`feat/mt-c-elevation`, read at
//! `3387413f`). The Explorer sends `GET /api/v1/admin/acts?mine&limit=1` with
//! the viewer's own bearer and maps the status:
//!
//! - 2xx: present;
//! - 404 or 405: absent, so the page and its nav item stay hidden;
//! - 403: present, but this viewer may not use it;
//! - anything else: unknown, so the feature stays hidden and is re-probed.
//!
//! That mapping is only right if a router WITHOUT the route answers 404 to
//! that request. The path sits under the `/api/v1/admin/` prefix other routes
//! use, and the router has no `.fallback`, so 404 is expected, but a bearer
//! layer or a rate limiter could answer first (401, 403, 429), and 403 would
//! read as "present". This test measures it, with a bearer carrying exactly
//! the scopes the Explorer asks for.
//!
//! When the elevation stack merges, the route exists and this test fails by
//! design: replace it with one that pins the 2xx the probe then gets.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, ApiConfig, AppState};
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

async fn status_of(router: &Router, uri: &str, bearer: &str) -> StatusCode {
    router
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
        .unwrap()
        .status()
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_acts_probe_is_404_on_main(pool: PgPool) {
    let app = router(&pool).await;
    let bearer = common::mint_token_with_agent(EXPLORER_SCOPES, Uuid::new_v4());

    // Calibration: the same bearer is accepted on a registered read route,
    // so whatever the probe gets is not a bearer refusal.
    assert_eq!(
        status_of(&app, "/api/v1/stats", &bearer).await,
        StatusCode::OK,
        "the probe's bearer must be valid on a registered route"
    );

    assert_eq!(
        status_of(&app, ADMIN_ACTS_PROBE, &bearer).await,
        StatusCode::NOT_FOUND,
        "a router without the admin-acts route must answer the probe 404, \
         which the Explorer reads as `Absent`"
    );
}
