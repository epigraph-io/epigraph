//! Backlog c6949159: `link_hierarchical` writes an `agent -asserts-> claim`
//! edge, so a dropped attribution of a claim to its asserting agent can be
//! restored over MCP (before, only the HTTP edges route or a CLI could).
//!
//! `asserts` from an agent puts words in that agent's mouth, so the tool takes
//! the HTTP route's rule (`POST /api/v1/edges`, `epigraph_db::credited_agent_end`
//! and `AgentRepository::speaks_for`): only the agent itself, or the human
//! operating it through a binding in force, may write it. A stranger is
//! refused with the HTTP refusal text and nothing is written, and so is the
//! human once the binding is retired.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::AgentRepository;
use epigraph_mcp::tools::link_hierarchical::do_link_hierarchical;
use epigraph_mcp::types::LinkHierarchicalParams;
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

fn token(agent: Uuid, client_type: ClientType) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

fn asserts(agent: Uuid, claim: Uuid) -> LinkHierarchicalParams {
    LinkHierarchicalParams {
        source_claim_id: agent.to_string(),
        target_claim_id: claim.to_string(),
        relationship: "asserts".to_string(),
        source_type: Some("agent".to_string()),
        target_type: Some("claim".to_string()),
        ..Default::default()
    }
}

/// Call `link_hierarchical` as `auth` over the HTTP path.
async fn call(
    server: &EpiGraphMcpFull,
    auth: &AuthContext,
    params: LinkHierarchicalParams,
) -> Result<rmcp::model::CallToolResult, rmcp::model::ErrorData> {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, Some(auth))
        .await
        .expect("HTTP viewer");
    do_link_hierarchical(server, &viewer, params, Some(auth)).await
}

async fn asserts_count(pool: &PgPool, agent: Uuid, claim: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND source_type = 'agent' \
           AND target_id = $2 AND target_type = 'claim' AND relationship = 'asserts'",
    )
    .bind(agent)
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("count asserts edges")
}

async fn link_operator(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("link");
    assert!(out.link_live, "CALIBRATION: the link is live");
}

async fn retire(pool: &PgPool, agent: Uuid) {
    let outcome: String = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: String = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_retire_operator_link($1, 'asserts test', true)",
        )
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("retire the link");
        (conn, r)
    })
    .await;
    assert_eq!(outcome, "retired", "CALIBRATION: the link was live");
}

fn assert_attribution_refusal(err: &rmcp::model::ErrorData, what: &str) {
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "{what}: {err:?}"
    );
    assert_eq!(
        err.message,
        epigraph_db::AGENT_ATTRIBUTION_REFUSAL,
        "{what}: the HTTP route's refusal text"
    );
}

/// The agent itself writes its `asserts`, typed `agent -> claim`; a stranger
/// naming that agent is refused with the HTTP refusal text and nothing is
/// written; `asserts` is `agent -> claim` only.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_asserts_a_claim_and_a_stranger_cannot_assert_for_it(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (author, _) = fixture::seed_agent_with_group(&pool, "asserts-author").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "asserts-stranger").await;
    let claim = fixture::seed_public_claim(&pool, author, "a claim its author asserts").await;

    let err = call(
        &server,
        &token(stranger, ClientType::Agent),
        asserts(author, claim),
    )
    .await
    .expect_err("a stranger cannot assert for another agent");
    assert_attribution_refusal(&err, "stranger");
    assert_eq!(
        asserts_count(&pool, author, claim).await,
        0,
        "nothing written"
    );

    let ok = call(
        &server,
        &token(author, ClientType::Agent),
        asserts(author, claim),
    )
    .await
    .expect("the agent writes its own asserts edge");
    let ok = first_text(&ok);
    assert_eq!(ok["created"], serde_json::json!(true), "{ok}");
    assert_eq!(
        ok["owned_by_caller"],
        serde_json::json!(false),
        "an agent's edge onto a public claim is world-owned, as over HTTP: {ok}"
    );
    assert_eq!(asserts_count(&pool, author, claim).await, 1);
    let again = call(
        &server,
        &token(author, ClientType::Agent),
        asserts(author, claim),
    )
    .await
    .expect("idempotent");
    assert_eq!(first_text(&again)["created"], serde_json::json!(false));
    assert_eq!(asserts_count(&pool, author, claim).await, 1);

    // The relationship's type pair: `asserts` is from an agent only.
    let other = fixture::seed_public_claim(&pool, author, "another claim").await;
    let mut from_claim = asserts(other, claim);
    from_claim.source_type = Some("claim".to_string());
    let err = call(&server, &token(author, ClientType::Agent), from_claim)
        .await
        .expect_err("claim -asserts-> claim is not this tool's");
    assert!(
        err.message.contains("does not link claim -> claim"),
        "{}",
        err.message
    );
    // An agent id that names no agent is not found.
    let err = call(
        &server,
        &token(author, ClientType::Agent),
        asserts(Uuid::new_v4(), claim),
    )
    .await
    .expect_err("an unknown agent");
    assert!(err.message.contains("not found"), "{}", err.message);
}

/// The human operating an agent through a live binding writes that agent's
/// `asserts`, as over HTTP; once the binding is retired it no longer may.
#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_asserts_for_its_live_agent_only(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (human, _) = fixture::seed_human_operator(&pool, "asserts-human").await;
    let (bot, _) = fixture::seed_agent_with_group(&pool, "asserts-bot").await;
    link_operator(&pool, bot, human).await;
    let first = fixture::seed_public_claim(&pool, bot, "the bot's first claim").await;
    let second = fixture::seed_public_claim(&pool, bot, "the bot's second claim").await;
    let human_token = token(human, ClientType::Human);

    call(&server, &human_token, asserts(bot, first))
        .await
        .expect("the operator restores its agent's asserts edge");
    assert_eq!(asserts_count(&pool, bot, first).await, 1);

    retire(&pool, bot).await;
    let err = call(&server, &human_token, asserts(bot, second))
        .await
        .expect_err("a retired binding confers nothing");
    assert_attribution_refusal(&err, "after retirement");
    assert_eq!(
        asserts_count(&pool, bot, second).await,
        0,
        "nothing written"
    );
}
