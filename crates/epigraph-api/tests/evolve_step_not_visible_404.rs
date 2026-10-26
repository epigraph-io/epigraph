#![cfg(feature = "db")]
//! `POST /api/v1/workflows/steps/:id/evolve` on a parent the caller cannot
//! see answers 404, the same as a parent that does not exist, on the
//! APPLICATION ROLE where row security is in force (backlog 769989ae: the
//! route's refusal arms are 400 / 409 / 404, never 500).
//!
//! A regression pin, green before and after the 769989ae fix: the parent's
//! `FOR UPDATE` read in `ClaimRepository::evolve_step_conn` returns no row for
//! an invisible claim, which is `DbError::NotFound`. It guards the mapping the
//! fix rewrote, so a later arm that sends `NotFound` (or anything an invisible
//! parent produces) to 500 or 403 fails here.
//!
//! The same module pins the route's answer to a parent the caller CAN see but
//! whose retirement the database refuses (backlog d34f5096): 403 with nothing
//! written, not 500.
//!
//! No orphan permissive policy is installed (unlike
//! `claim_routes_bind_the_caller.rs`): `FOR ALL USING (true)` would make every
//! claim visible and this test vacuous.

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group, seed_group_claim};

async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the invisible arm is vacuous"
    );
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

async fn evolve_as(
    pool: &PgPool,
    state: &AppState,
    caller: Uuid,
    parent: Uuid,
    content: &str,
    edge_type: &str,
) -> (StatusCode, String) {
    let viewer = Viewer::resolve(pool, caller).await.expect("viewer");
    let auth = AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(caller),
        owner_id: Some(caller),
        client_type: ClientType::Service,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    };
    let req: epigraph_api::routes::workflows::EvolveStepRequest =
        serde_json::from_value(serde_json::json!({
            "parent_id": parent, "content": content, "edge_type": edge_type
        }))
        .expect("request");
    let resp = epigraph_api::routes::workflows::evolve_step(
        ViewerExtractor(viewer),
        State(state.clone()),
        Some(Extension(auth)),
        axum::extract::Path(parent),
        Json(req),
    )
    .await
    .into_response();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_on_a_parent_the_caller_cannot_see_returns_404(pool: PgPool) {
    let (a, a_group) = seed_agent_with_group(&pool, "owner-a").await;
    let (b, _) = seed_agent_with_group(&pool, "outsider-b").await;
    let parent = seed_group_claim(
        &pool,
        a,
        a_group,
        &format!("A's group-private step {}", Uuid::new_v4()),
    )
    .await;
    let state = app_role_state(&pool).await;

    let content = format!("evolved by an outsider {}", Uuid::new_v4());
    let (status, body) = evolve_as(&pool, &state, b, parent, &content, "revises").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a parent the caller cannot see is a 404, as a missing one is: {body}"
    );
    assert!(
        !body.contains("A's group-private step"),
        "the refusal discloses nothing of the parent: {body}"
    );
    assert_eq!(claims_with_content(&pool, &content).await, 0);

    // Control: the owner, who can see the parent, evolves it on the same
    // state, so the 404 above is the visibility and not the harness.
    let content = format!("evolved by the owner {}", Uuid::new_v4());
    let (status, body) = evolve_as(&pool, &state, a, parent, &content, "revises").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owner evolves its own step: {body}"
    );
    assert_eq!(claims_with_content(&pool, &content).await, 1);
}

/// `supersedes` on a parent the caller can see and evolve, whose retirement
/// the database refuses, answers 403 with nothing written (backlog d34f5096).
///
/// Row security that refuses an UPDATE through its USING clause matches zero
/// rows without raising; `ClaimRepository::evolve_step_conn` turns that into
/// `DbError::WriteRefused`, a denial the route must render as 403 (as
/// `From<DbError>` does everywhere else), not fold into its 500 arm. A
/// `BEFORE UPDATE` trigger that skips only the parent's `is_current` change
/// stands in for the refusing policy deterministically.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_whose_retire_is_refused_returns_403_and_writes_nothing(
    pool: PgPool,
) {
    let (a, a_group) = seed_agent_with_group(&pool, "owner-a").await;
    let parent = seed_group_claim(
        &pool,
        a,
        a_group,
        &format!("A's unretirable step {}", Uuid::new_v4()),
    )
    .await;
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION aaa_test_skip_step_retire() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RETURN NULL; END $$; \
         CREATE TRIGGER aaa_test_skip_step_retire BEFORE UPDATE ON claims FOR EACH ROW \
         WHEN (OLD.id = '{parent}'::uuid AND NEW.is_current IS DISTINCT FROM OLD.is_current) \
         EXECUTE FUNCTION aaa_test_skip_step_retire();"
    ))
    .execute(&pool)
    .await
    .expect("install the retirement stand-in");
    let state = app_role_state(&pool).await;

    let content = format!("successor of an unretirable step {}", Uuid::new_v4());
    let (status, body) = evolve_as(&pool, &state, a, parent, &content, "supersedes").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a refused retirement is a write refusal, not a server fault: {body}"
    );
    assert_eq!(
        claims_with_content(&pool, &content).await,
        0,
        "no successor"
    );
    let still_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .expect("parent");
    assert!(still_current, "the parent is untouched");
}
