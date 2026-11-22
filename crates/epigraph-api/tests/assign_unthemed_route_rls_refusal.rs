#![cfg(feature = "db")]
//! `POST /api/v1/themes/assign-unthemed` on the PRODUCTION pool shape answers
//! row security's refusal as a 403 that names the operator CLI, not a 500
//! (backlog d5f9829a).
//!
//! # The defect, reproduced
//!
//! The route runs `ClaimThemeRepository::assign_unthemed_batch` on
//! `state.db_pool`, which in production logs in as `epigraph_app` (neither
//! superuser nor `BYPASSRLS`) against `claims`, whose row security is FORCEd.
//! A batch holding a claim the caller can read but not write (a public claim
//! owned by another group) fails as a whole: "new row violates row-level
//! security policy for table claims", SQLSTATE 42501. Measured on prod
//! 2026-11-21: every batch failed that way, answered 500, so the 34,547
//! unthemed embedded claims could not be assigned through the API at all.
//!
//! The instrument is `http_public_only_reads.rs`'s `production_state`:
//! `AppState::with_scoped_pool` on `ScopedPool::connect_downgraded_for_tests(..,
//! "epigraph_app")`, calibrated to be the application role and subject to row
//! security, so the refusal is the database's, not a fixture's.
//!
//! # Verified to fail
//!
//! With the route's 42501 arm removed, the handler returns
//! `ApiError::DatabaseError` (a 500) and this test fails on that variant.

mod viewer_fixture;

use axum::extract::State;
use axum::{Extension, Json};
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::crud::{assign_unthemed, AssignUnthemedRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, seed_agent_with_group, seed_public_claim, set_claim_embedding,
};

const DIM: usize = 1536;

/// `AppState` exactly as `bin/server.rs` builds it, on the application role.
async fn production_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("epigraph_app ScopedPool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
    let (user, privileged): (String, bool) = sqlx::query_as(
        "SELECT current_user::text, rolsuper OR rolbypassrls \
           FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&state.db_pool)
    .await
    .expect("role of the production pool");
    assert_eq!(
        user, "epigraph_app",
        "CALIBRATION: db_pool must run as the application role, as production does"
    );
    assert!(
        !privileged,
        "CALIBRATION: epigraph_app must be subject to row security, or the refusal \
         this test pins cannot happen"
    );
    state
}

fn admin_auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: vec!["claims:admin".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

fn axis_vector(axis: usize) -> String {
    let mut v = vec![0.0_f32; DIM];
    v[axis] = 1.0;
    format!(
        "[{}]",
        v.iter().map(f32::to_string).collect::<Vec<_>>().join(",")
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_rls_refused_batch_is_a_403_naming_the_cli_not_a_500(pool: PgPool) {
    let (caller, _caller_group) = seed_agent_with_group(&pool, "d5f9829a-caller").await;
    let (author, _) = seed_agent_with_group(&pool, "d5f9829a-author").await;
    // A public claim the caller can READ but whose owning group it cannot
    // write: the shape prod's batches hit.
    let claim = seed_public_claim(&pool, author, "d5f9829a public unthemed claim").await;
    set_claim_embedding(&pool, claim, &axis_vector(3)).await;
    sqlx::query("INSERT INTO claim_themes (label, centroid) VALUES ($1, $2::vector)")
        .bind("d5f9829a theme")
        .bind(axis_vector(3))
        .execute(&pool)
        .await
        .expect("seed theme");

    let state = production_state(&pool).await;
    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve viewer");
    let result = assign_unthemed(
        ViewerExtractor(viewer),
        State(state),
        admin_auth(caller),
        Json(AssignUnthemedRequest { batch_size: None }),
    )
    .await;

    let still_unthemed: bool =
        sqlx::query_scalar("SELECT theme_id IS NULL FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read the claim");
    assert!(
        still_unthemed,
        "PREMISE: the refused batch must not have assigned the claim"
    );

    match result {
        Err(ApiError::Forbidden { reason }) => {
            // The scope gate also answers Forbidden; only the refusal arm
            // names the CLI, so this is what tells the two apart.
            assert!(
                reason.contains("assign_unthemed_themes"),
                "the 403 must point to the operator CLI: {reason}"
            );
            assert!(
                reason.contains("0 claims were assigned by earlier batches"),
                "the 403 must say what earlier batches committed: {reason}"
            );
        }
        Err(e) => panic!("expected a 403 naming the CLI, got {e:?}"),
        Ok(Json(body)) => panic!(
            "expected the database to refuse the batch on the application role, got 200 {body}"
        ),
    }
}
