#![cfg(feature = "db")]
//! `PUT /api/v1/perspectives/:id/source-reliability` writes only what the
//! caller may write, and says so when it writes nothing (backlog 0f2f9ddb).
//!
//! The handler ran `PerspectiveRepository::set_source_reliability` on the
//! unstamped pool, checked no scope, and answered `204` unconditionally. So a
//! `claims:read` token could rewrite a lens and a caller could rewrite another
//! group's perspective. (A nonexistent id already answered `404`: the
//! repository's own row count refuses it. The backlog item's "204 even when no
//! row changed" holds for rows the unstamped pool could change but the caller
//! may not, not for missing ones.) It now takes `claims:write`, runs
//! `set_source_reliability_conn` on the caller's stamped transaction, and maps
//! what that changed: a perspective the caller cannot see (or that does not
//! exist) is `404`, one it can see but not update is `403`.
//!
//! The raw pool is the harness superuser, which bypasses row security: the old
//! handler's write landed on every row below. Only the stamped transaction
//! (the `epigraph_app` `ScopedPool`) is held to the policies, so each refusal
//! here is the policy's, reached because the handler now uses it.
//! Every arm asserts the row's `source_reliability` after the call, and the
//! owner's own call is the calibration that the route can write at all.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const READ_ONLY: &[&str] = &["claims:read"];
const READ_WRITE: &[&str] = &["claims:read", "claims:write"];

/// `privileged_raw_state`'s shape: the raw `db_pool` is the harness
/// superuser, so an unstamped UPDATE lands on any row (the old handler's
/// path), while the `ScopedPool` is `epigraph_app`, so a write through
/// `AppState::write_as` is held to the caller's own write authority.
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
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let mut state = epigraph_api::state::AppState::with_db(
        pool.clone(),
        epigraph_api::state::ApiConfig::default(),
    );
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    epigraph_api::routes::create_router(state)
}

/// A perspective owned by `group` with `visibility`, and `owner` as its agent.
async fn seed_perspective(pool: &PgPool, owner: Uuid, group: Uuid, visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO perspectives (id, name, owner_agent_id, visibility, owner_group_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(format!("reliability lens {id}"))
    .bind(owner)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed perspective");
    id
}

/// The perspective's stored `source_reliability`, `Null` when unset.
async fn stored(pool: &PgPool, id: Uuid) -> Value {
    sqlx::query_scalar::<_, Option<Value>>(
        "SELECT properties->'source_reliability' FROM perspectives WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read perspective")
    .unwrap_or(Value::Null)
}

async fn put(
    router: &axum::Router,
    id: Uuid,
    agent: Uuid,
    scopes: &[&str],
    map: &Value,
) -> (StatusCode, String) {
    let token = common::mint_token_with_agent(scopes, agent);
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/v1/perspectives/{id}/source-reliability"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "source_reliability": map }).to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("router");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_sets_it_with_claims_write_and_not_without(pool: PgPool) {
    let app = router(&pool).await;
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "rel-owner").await;
    let lens = seed_perspective(&pool, owner, group, "group").await;
    let map = json!({ "observation": 0.4 });

    let (status, body) = put(&app, lens, owner, READ_ONLY, &map).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a claims:read token is refused: {body}"
    );
    assert!(body.contains("claims:write"), "names the scope: {body}");
    assert_eq!(stored(&pool, lens).await, Value::Null, "nothing written");

    let (status, body) = put(&app, lens, owner, READ_WRITE, &map).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "CALIBRATION: the owner writes its own lens: {body}"
    );
    assert_eq!(stored(&pool, lens).await, map, "the map is stored");
}

#[sqlx::test(migrations = "../../migrations")]
async fn another_groups_perspective_is_refused_and_unchanged(pool: PgPool) {
    let app = router(&pool).await;
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "rel-own").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "rel-stranger").await;
    let private = seed_perspective(&pool, owner, group, "group").await;
    let public = seed_perspective(&pool, owner, group, "public").await;
    let map = json!({ "observation": 0.1 });

    // Not visible to the stranger: indistinguishable from a missing id.
    let (status, body) = put(&app, private, stranger, READ_WRITE, &map).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a perspective private to another group is 404: {body}"
    );
    assert_eq!(stored(&pool, private).await, Value::Null, "unchanged");

    // Visible (public), but owned by a group the stranger cannot write.
    let (status, body) = put(&app, public, stranger, READ_WRITE, &map).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a readable perspective of another group is 403: {body}"
    );
    assert_eq!(stored(&pool, public).await, Value::Null, "unchanged");
}

/// A regression pin, not a red test: measured on the old handler this already
/// answered 404, because the repository's `seen`/`done` count refuses a
/// missing row even on the pool form. Kept so the new mapping cannot regress
/// it to a 204.
#[sqlx::test(migrations = "../../migrations")]
async fn a_nonexistent_perspective_is_404_not_204(pool: PgPool) {
    let app = router(&pool).await;
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "rel-none").await;
    let (status, body) = put(
        &app,
        Uuid::new_v4(),
        agent,
        READ_WRITE,
        &json!({ "observation": 0.5 }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "setting a missing perspective must not answer 204: {body}"
    );
}
