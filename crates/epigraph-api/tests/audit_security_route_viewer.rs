//! `GET /api/v1/audit/security` (`routes/audit.rs::query_security_events`)
//! answers each caller from a connection stamped with that caller's viewer
//! (backlog 8a168dd6), so the `security_events_read` row-security policy
//! decides the result per principal.
//!
//! Both pools of the `AppState` are `epigraph_app` (no BYPASSRLS, the table's
//! policies FORCEd), as in `entity_triple_write_app_role.rs`: the result is
//! what the policy admits for the caller, never what the pool's role sees.
//!
//! Expected, from the policy (migration 169's latest definition): an ordinary
//! principal reads the rows that name it; a platform custodian with the admin
//! switch disarmed reads every row.
#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::{Query, State};
use axum::Extension;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::audit::{query_security_events, SecurityEventQuery};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, make_custodian, seed_agent_with_group};

const EVENT_TYPE: &str = "test.audit_route_viewer";

async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
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
}

fn auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["audit:read".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

async fn seed_event(pool: &PgPool, agent: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO security_events (event_type, agent_id, success, details) \
         VALUES ($1, $2, true, '{}'::jsonb) RETURNING id",
    )
    .bind(EVENT_TYPE)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed security event")
}

/// The seeded event ids `agent` reads through the route.
async fn read_as(pool: &PgPool, state: &AppState, agent: Uuid) -> BTreeSet<Uuid> {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let axum::Json(rows) = query_security_events(
        ViewerExtractor(viewer),
        State(state.clone()),
        auth(agent),
        Query(SecurityEventQuery {
            agent_id: None,
            event_type: Some(EVENT_TYPE.to_string()),
            since: None,
            until: None,
            failures_only: None,
            limit: None,
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("query_security_events as {agent}: {e:?}"));
    rows.into_iter().map(|r| r.id).collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_principal_reads_its_own_rows_and_a_custodian_reads_every_row(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (alice, _) = seed_agent_with_group(&pool, "audit-viewer-a").await;
    let (bob, _) = seed_agent_with_group(&pool, "audit-viewer-b").await;
    let (carol, _) = seed_agent_with_group(&pool, "audit-viewer-c").await;
    make_custodian(&pool, carol).await;

    let a = seed_event(&pool, alice).await;
    let b = seed_event(&pool, bob).await;

    // CALIBRATION: both rows exist (read on the superuser harness), and the
    // admin switch is disarmed, so the custodian arm needs no elevation.
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type = $1")
            .bind(EVENT_TYPE)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(stored, 2, "CALIBRATION: both seeded rows are stored");
    let armed: bool = sqlx::query_scalar("SELECT public.epigraph_admin_scopes_armed()")
        .fetch_one(&pool)
        .await
        .expect("armed");
    assert!(!armed, "CALIBRATION: the admin switch is disarmed");

    assert_eq!(
        read_as(&pool, &state, alice).await,
        BTreeSet::from([a]),
        "the first principal reads exactly its own row"
    );
    assert_eq!(
        read_as(&pool, &state, bob).await,
        BTreeSet::from([b]),
        "the second principal reads exactly its own row"
    );
    assert_eq!(
        read_as(&pool, &state, carol).await,
        BTreeSet::from([a, b]),
        "a custodian reads every row"
    );
}
