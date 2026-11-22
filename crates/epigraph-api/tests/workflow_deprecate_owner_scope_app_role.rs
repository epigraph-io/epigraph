//! Migration 237 (backlog 524f89c1) at `DELETE /api/v1/workflows/:id`, on the
//! APPLICATION ROLE.
//!
//! The route deprecates a flat workflow CLAIM and mirrors the deprecation onto
//! the hierarchical `workflows` row that shares its id, in one transaction.
//! Since 237 a `workflows` UPDATE reaches only a row whose owner group the
//! caller WRITES, and a filtered row raises nothing, so a caller that writes
//! the claim's group and not the row's would commit the claim's half alone.
//! The route refuses that (403, nothing written) unless the row already reads
//! deprecated; a flat-only id and a row the caller writes are unchanged.
//!
//! The router runs on an `epigraph_app` `ScopedPool` (a superuser pool
//! bypasses row security and proves nothing here); the harness superuser only
//! seeds and inspects.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

async fn router(pool: &PgPool) -> axum::Router {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    epigraph_api::routes::create_router(state)
}

async fn deprecate(router: &axum::Router, id: Uuid, agent: Uuid) -> StatusCode {
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/v1/workflows/{id}?reason=obsolete"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    router.clone().oneshot(req).await.expect("router").status()
}

/// A flat workflow claim by `agent`, public in `group`.
async fn flat_claim(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, labels) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'public', $5, ARRAY['workflow'])",
    )
    .bind(id)
    .bind(format!("a flat workflow {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("flat workflow claim");
    id
}

/// A hierarchical `workflows` row with id `id`, public in `group`.
async fn row_with_id(pool: &PgPool, id: Uuid, group: Uuid) {
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, visibility, owner_group_id) \
         VALUES ($1, $2, 'a goal', 'public', $3)",
    )
    .bind(id)
    .bind(format!("wf237-rest-{id}"))
    .bind(group)
    .execute(pool)
    .await
    .expect("the row sharing its id");
}

async fn is_current(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("claim")
}

async fn truth(pool: &PgPool, id: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value FROM workflows WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("row")
}

/// The claim's half is never committed alone: with the row in a group the
/// caller does not write, the request is refused (403), the claim stays
/// current and the row live. Before this change it answered 200 and left the
/// row at 1.0. Calibrations: a flat-only id, and a row in the caller's own
/// group, are deprecated as before.
#[sqlx::test(migrations = "../../migrations")]
async fn a_flat_deprecation_never_leaves_its_hierarchical_row_live(pool: PgPool) {
    let router = router(&pool).await;
    let (owner, own) = fixture::seed_human_operator(&pool, "wf237-rest-owner").await;
    let (_, other) = fixture::seed_human_operator(&pool, "wf237-rest-other").await;

    let split = flat_claim(&pool, owner, own).await;
    row_with_id(&pool, split, other).await;
    assert_eq!(
        deprecate(&router, split, owner).await,
        StatusCode::FORBIDDEN,
        "the row cannot be written, so nothing may be"
    );
    assert!(is_current(&pool, split).await, "the claim stays current");
    assert!(
        (truth(&pool, split).await - 1.0).abs() < 1e-12,
        "row untouched"
    );

    // CALIBRATION: a flat-only workflow is deprecated (no row is the normal
    // answer), and so is one whose row the caller writes.
    let flat = flat_claim(&pool, owner, own).await;
    assert_eq!(deprecate(&router, flat, owner).await, StatusCode::OK);
    assert!(!is_current(&pool, flat).await);
    let both = flat_claim(&pool, owner, own).await;
    row_with_id(&pool, both, own).await;
    assert_eq!(deprecate(&router, both, owner).await, StatusCode::OK);
    assert!(!is_current(&pool, both).await);
    assert!((truth(&pool, both).await - 0.05).abs() < 1e-12);
}
