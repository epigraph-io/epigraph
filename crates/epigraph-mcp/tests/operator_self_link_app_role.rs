//! Operator binding (migration 122) and operator decision D9: a per-agent
//! stdio process holds only an `epigraph_app` DSN, where
//! `epigraph_link_operator` is 42501. The host therefore records the agent's
//! LIVE link on a maintenance connection before starting it
//! (`epigraph-operator link`), and the startup self-link must ACCEPT that
//! recorded link instead of failing on the call it can no longer make.
//!
//! Driven through `epigraph_mcp::operator::self_link` on a server whose pools
//! are downgraded to `epigraph_app` (a superuser pool would execute the link
//! function and prove nothing). The link is recorded on the superuser harness
//! pool, standing in for the host's maintenance connection.
//!
//! Verified to fail: with the recorded-link read removed from `self_link`, the
//! second call returns the 42501 refusal and `a_declared_agent_on_an_app_dsn_starts_once_the_host_linked_it`
//! fails.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: this test is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    (server, agent)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_agent_on_an_app_dsn_starts_once_the_host_linked_it(pool: PgPool) {
    let (server, agent) = app_role_server(&pool).await;
    let (operator, _) = fixture::seed_human_operator(&pool, "operator").await;

    // Not linked yet: the process cannot record the link itself on an app DSN,
    // and the refusal names the host-side command that fixes it.
    let refused = epigraph_mcp::operator::self_link(&server, operator)
        .await
        .expect_err("an app DSN cannot record a link");
    assert!(
        refused.contains("epigraph-operator link") && refused.contains(&agent.to_string()),
        "the startup refusal must name the fix for this agent: {refused}"
    );

    // The host records the live link on its maintenance connection.
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, agent, operator)
            .await
            .expect("the host links the agent");
    }

    let outcome = epigraph_mcp::operator::self_link(&server, operator)
        .await
        .expect("a recorded live link must let the app-DSN process start");
    assert!(outcome.link_live && !outcome.link_retired);
    assert!(
        !outcome.membership_created && !outcome.group_created && !outcome.edge_created,
        "the app-DSN start must record nothing: {outcome:?}"
    );

    // A declaration naming a DIFFERENT operator is not satisfied by that link.
    let (other, _) = fixture::seed_human_operator(&pool, "other-operator").await;
    epigraph_mcp::operator::self_link(&server, other)
        .await
        .expect_err("a link to another operator must not satisfy the declaration");
}
