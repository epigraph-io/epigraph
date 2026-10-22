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

/// The allowlist conjunct (`epigraph_author_binding(delegator) =
/// 'client_allowlist'`) on the application role. The other conjuncts admit
/// two delegators it alone refuses: an agent LIVE-LINKED to the same operator
/// (its human is that operator, and its link gives it a writer row of the
/// operator's group) and the human operator ITSELF (its own human, admin of
/// its personal group). Neither is a delegator.
#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_agent_or_the_operator_itself_is_no_delegator_on_the_application_role(
    pool: PgPool,
) {
    let d = delegation::live_delegation(&pool, "app-role-allowlist").await;
    let sibling = delegation::linked_principal(&pool, d.operator, "app-role-sibling").await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    assert!(
        check(&app, RunTokens::On, d.delegator, d.principal)
            .await
            .is_some(),
        "CALIBRATION: the allowlisted delegator"
    );
    // Both read before either is asserted, so a failure shows both answers.
    let as_sibling = check(&app, RunTokens::On, sibling, d.principal).await;
    let as_operator = check(&app, RunTokens::On, d.operator, d.principal).await;
    assert_eq!(
        (as_sibling, as_operator),
        (None, None),
        "(a linked agent of the same operator, the operator itself) as the delegator"
    );
}

/// Every way of ending a delegation reads `None` on the APPLICATION role, each
/// on its own fresh delegation that read `Some` there first: the principal's
/// link retired, the delegator's client suspended, its allowance revoked, and
/// its writer row in the operator's group revoked.
#[sqlx::test(migrations = "../../migrations")]
async fn every_revocation_reads_none_on_the_application_role(pool: PgPool) {
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&app)
        .await
        .expect("current_user");
    assert_eq!(role, "epigraph_app", "PREMISE: the downgraded pool");

    for case in [
        "retire",
        "suspend",
        "revoke-allowance",
        "revoke-delegator-row",
    ] {
        let d = delegation::live_delegation(&pool, &format!("app-role-{case}")).await;
        assert!(
            check(&app, RunTokens::On, d.delegator, d.principal)
                .await
                .is_some(),
            "CALIBRATION ({case}): live before"
        );
        match case {
            "retire" => delegation::retire_link(&pool, d.principal).await,
            "suspend" => {
                delegation::set_client_status(&pool, d.delegator_client, "suspended").await;
            }
            "revoke-allowance" => delegation::revoke_allowance(&pool, d.delegator_client).await,
            _ => delegation::revoke_membership(&pool, d.delegator, d.operator_group).await,
        }
        assert_eq!(
            check(&app, RunTokens::On, d.delegator, d.principal).await,
            None,
            "{case}: the application role must read the delegation as ended"
        );
    }
}
