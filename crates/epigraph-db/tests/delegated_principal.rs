//! `AgentRepository::delegated_principal_pool`, the per-request liveness check
//! of a delegated run token, on the APPLICATION role.
//!
//! The request sites call it on the unstamped application pool before any
//! viewer exists. The `#[sqlx::test]` harness is a superuser, which would hide
//! a missing EXECUTE grant (`42501`) on any of the definers the one statement
//! composes, so every answer here is read on a pool downgraded to
//! `epigraph_app` and compared with the superuser's. The site behaviour lives
//! in `epigraph-api/tests/delegated_run_token_viewer.rs` and its MCP twin.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "support/delegation_fixture.rs"]
mod delegation;

use epigraph_db::{AgentRepository, DelegationLive, RunTokens};
use sqlx::PgPool;
use uuid::Uuid;

async fn check(
    pool: &PgPool,
    switch: RunTokens,
    delegator: Uuid,
    principal: Uuid,
) -> Option<DelegationLive> {
    AgentRepository::delegated_principal_pool(pool, switch, delegator, principal)
        .await
        .expect("the check must answer on this role")
}

/// A live delegation reads `Some(operator, operator group)` on the app role
/// exactly as on the superuser; the switch off reads `None` without a query;
/// an unlinked principal and a reader-only delegator read `None` on the app
/// role too (so the app role is not merely answering `Some` to everything).
#[sqlx::test(migrations = "../../migrations")]
async fn the_check_answers_on_the_application_role(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "app-role").await;
    let (unlinked, _) = delegation::agent_with_group(&pool, "app-role-unlinked").await;
    let (_, reader) =
        delegation::delegator(&pool, d.operator, d.operator_group, Some("reader"), true).await;
    let expected = DelegationLive {
        operator_id: d.operator,
        operator_group_id: d.operator_group,
    };
    assert_eq!(
        check(&pool, RunTokens::On, d.delegator, d.principal).await,
        Some(expected),
        "CALIBRATION: the superuser reads the live delegation"
    );

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    assert_eq!(
        check(&app, RunTokens::On, d.delegator, d.principal).await,
        Some(expected),
        "the application role must read the same live delegation"
    );
    assert_eq!(
        check(&app, RunTokens::Off, d.delegator, d.principal).await,
        None
    );
    assert_eq!(
        check(&app, RunTokens::On, d.delegator, unlinked).await,
        None
    );
    assert_eq!(check(&app, RunTokens::On, reader, d.principal).await, None);
}
