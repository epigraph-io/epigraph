#![cfg(feature = "db")]
//! `POST /api/v1/claims/:id/dedup`: an act that fails WITHOUT refusing is a
//! server fault, not a 409 (backlog dca9ed56 part 2).
//!
//! The route used to answer every remaining `DbError::QueryFailed` of the act
//! with 409 "claim already superseded or invalid input". That arm predates the
//! repo layer's `DbError::Refused`, which now carries every designed refusal
//! of the act with its kind (already superseded and not current are State,
//! 409); what is left in `QueryFailed` is the database failing (a lock or
//! statement timeout, a lost connection, a broken definer), which the caller
//! cannot fix by changing its request. It is answered by `From<DbError>`: a
//! reviewed coded refusal keeps its code, anything else is the redacted 500.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::versioning::{mark_duplicate, DedupRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group};

/// Both pools on the application role; no maintenance connection, so a dedup
/// that lands defers its cascade in its own transaction.
async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "epigraph_app holds BYPASSRLS: vacuous");
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

fn human(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("{content} {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// The status and the whole rendered body.
async fn rendered(e: ApiError) -> (u16, String) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// The duplicate's row is held by another transaction, so the act's row lock
/// times out (SQLSTATE 55P03, a `QueryFailed`): 500 with the redacted body,
/// never the old 409 "claim already superseded or invalid input", and never
/// the driver's text. Nothing is written.
///
/// CONTROL: once the row is released the same dedup lands, so the 500 is the
/// lock's and not the fixture's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_act_that_fails_without_refusing_is_a_redacted_500(pool: PgPool) {
    // Per test database (`sqlx::test` creates one), so no other test sees it;
    // set before the application pools connect, so their sessions inherit it.
    sqlx::query(
        "DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET lock_timeout = %L', \
                                    current_database(), '300ms'); END $$",
    )
    .execute(&pool)
    .await
    .expect("lock_timeout for this database");
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "dca9-http-lock").await;
    let dup = claim_of(&pool, h, hg, "dca9 duplicate").await;
    let canonical = claim_of(&pool, h, hg, "dca9 canonical").await;
    let viewer = Viewer::resolve(&pool, h).await.expect("resolve");
    let timeout: String = {
        let mut conn = state.db_pool.acquire().await.expect("app connection");
        sqlx::query_scalar("SHOW lock_timeout")
            .fetch_one(&mut *conn)
            .await
            .expect("show")
    };
    assert_eq!(timeout, "300ms", "calibration: the app sessions time out");

    let mut holder = pool.begin().await.expect("holder");
    sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR UPDATE")
        .bind(dup)
        .execute(&mut *holder)
        .await
        .expect("hold the duplicate's row");
    let e = mark_duplicate(
        ViewerExtractor(Viewer::resolve(&pool, h).await.expect("resolve")),
        State(state.clone()),
        human(h),
        Path(dup),
        Json(DedupRequest {
            canonical_id: canonical,
            reason: None,
        }),
    )
    .await
    .expect_err("the act cannot lock the duplicate");
    holder.rollback().await.expect("release");

    let (status, body) = rendered(e).await;
    assert_eq!(status, 500, "a database failure is the server's: {body}");
    assert!(
        !body.contains("already superseded") && !body.contains("invalid input"),
        "not the old state refusal's words: {body}"
    );
    assert!(
        !body.to_lowercase().contains("lock"),
        "the driver's text stays in the server log: {body}"
    );
    let (supersedes, current): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("dup");
    assert_eq!((supersedes, current), (None, true), "nothing was written");

    let Json(resp) = mark_duplicate(
        ViewerExtractor(viewer),
        State(state),
        human(h),
        Path(dup),
        Json(DedupRequest {
            canonical_id: canonical,
            reason: None,
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("CONTROL: the released row is marked: {e:?}"));
    assert_eq!(resp.duplicate_id, dup, "CONTROL: the dedup landed");
}
