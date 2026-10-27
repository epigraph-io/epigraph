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

/// Current claims on `parent`'s lineage, counted without its lineage id: the
/// parent plus anything written as its successor, by column or by edge.
async fn current_heads(pool: &PgPool, parent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims \
         WHERE (id = $1 OR supersedes = $1 \
                OR id IN (SELECT source_id FROM edges WHERE target_id = $1)) \
           AND COALESCE(is_current, true)",
    )
    .bind(parent)
    .fetch_one(pool)
    .await
    .expect("count heads")
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
/// A retire that changes no row does not raise; `ClaimRepository::evolve_step_conn`
/// turns it into `DbError::WriteRefused`, a denial the route must render as
/// 403 (as `From<DbError>` does everywhere else), not fold into its 500 arm. A
/// `BEFORE UPDATE` trigger that skips only the parent's `is_current` change
/// produces the zero-row retire deterministically; the next test pins what
/// the real policies do instead.
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
    // The 403 is the refused retire (`DbError::WriteRefused` on the parent),
    // not another denial on the route such as its lineage authority gate.
    assert!(
        body.contains("was refused") && body.contains(&parent.to_string()),
        "the 403 names the refused supersede of the parent: {body}"
    );
    assert_eq!(
        claims_with_content(&pool, &content).await,
        0,
        "no successor"
    );
    assert_eq!(current_heads(&pool, parent).await, 1, "one current head");
    let still_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .expect("parent");
    assert!(still_current, "the parent is untouched");

    // Control: without the stand-in, the same owner supersedes the same
    // parent on the same state, so the 403 above is the refused retire and
    // not the harness or an authority gate.
    sqlx::raw_sql("DROP TRIGGER aaa_test_skip_step_retire ON claims")
        .execute(&pool)
        .await
        .expect("drop the retirement stand-in");
    let content = format!("successor of a retirable step {}", Uuid::new_v4());
    let (status, body) = evolve_as(&pool, &state, a, parent, &content, "supersedes").await;
    assert_eq!(status, StatusCode::OK, "the owner may supersede: {body}");
    assert_eq!(claims_with_content(&pool, &content).await, 1);
    assert_eq!(
        current_heads(&pool, parent).await,
        1,
        "the successor is the one current head"
    );
    let still_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .expect("parent");
    assert!(!still_current, "the parent is retired");
}

/// `supersedes` on a PUBLIC step the caller can read but does not own, on the
/// application role with the real row-security policies and no stand-in: a
/// refusal with nothing written and the lineage's one current head intact
/// (backlog d34f5096).
///
/// A regression pin, green before and after the d34f5096 fix. It measures what
/// the real policies do on the path the stand-in above exercises: the parent's
/// `SELECT ... FOR UPDATE` returns the readable row, and the claims tenancy
/// policy refuses the write by RAISING at its WITH CHECK (SQLSTATE 42501, the
/// transaction aborted), not by matching zero rows. The successor inherits the
/// parent's owner group and INSERT and UPDATE share that WITH CHECK, so "may
/// write the successor but not retire the predecessor" cannot arise through
/// the claims policies today. Only the invariant is pinned, not the status:
/// the route currently answers that refusal 500, a separate defect.
#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_of_a_readable_step_the_caller_cannot_write_is_refused_and_writes_nothing(
    pool: PgPool,
) {
    let (a, a_group) = seed_agent_with_group(&pool, "owner-a").await;
    let (b, _) = seed_agent_with_group(&pool, "reader-b").await;
    // Owned by A's group and published: every viewer may read it, only A's
    // group may write it. Seeded directly, as the fixture's seeders do (they
    // pair `public` only with the world group, which nobody writes).
    let parent = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.8, $4, true, 'public', $5)",
    )
    .bind(parent)
    .bind(format!("A's public step {parent}"))
    .bind(parent.as_bytes().repeat(2))
    .bind(a)
    .bind(a_group)
    .execute(&pool)
    .await
    .expect("seed A's public step");
    let state = app_role_state(&pool).await;

    let content = format!("successor by a reader {}", Uuid::new_v4());
    let (status, body) = evolve_as(&pool, &state, b, parent, &content, "supersedes").await;
    assert!(
        !status.is_success(),
        "a step the caller may read but not write is refused: {status} {body}"
    );
    assert_eq!(
        claims_with_content(&pool, &content).await,
        0,
        "no successor"
    );
    assert_eq!(current_heads(&pool, parent).await, 1, "one current head");
    let still_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(parent)
        .fetch_one(&pool)
        .await
        .expect("parent");
    assert!(still_current, "the parent is untouched");

    // Control: the owner, who can write the parent, supersedes it on the same
    // state, so the refusal above is the caller's lack of write authority and
    // not the harness.
    let content = format!("successor by the owner {}", Uuid::new_v4());
    let (status, body) = evolve_as(&pool, &state, a, parent, &content, "supersedes").await;
    assert_eq!(status, StatusCode::OK, "the owner may supersede: {body}");
    assert_eq!(claims_with_content(&pool, &content).await, 1);
    assert_eq!(current_heads(&pool, parent).await, 1, "one current head");
}
