//! MCP `publish_event` attributes an event to the CALLING PRINCIPAL.
//!
//! Deferred-commitment screen key `events-actor-id-binding`. Until this change
//! `tools/events.rs::publish_event` parsed `params.actor_id` and handed it to
//! `EventRepository::insert` unchecked, and its `server.rs` dispatch body took
//! no `extensions`, so it never saw who was calling. Any `claims:write` caller
//! could record an event attributed to any existing agent, and `list_events`'
//! `actor_id` filter would return that row as the named agent's.
//!
//! Both transports are driven through the REAL tool function with the argument
//! the dispatch body passes it. On HTTP that is `Some(&AuthContext)`, and on
//! stdio it is `None`. The last test pins that the dispatch body really does
//! pass the request's `AuthContext`, because a body passing `None`
//! unconditionally would still compile, and on HTTP it would attribute every
//! caller's event to the server's shared signer agent.
//!
//! Every agent here is a real `agents` row: `events.actor_id` carries a foreign
//! key to `agents(id)` (`events_actor_id_fkey`, migration 001), so a fabricated
//! victim id would be refused by the FK and make the unbound code look safe.

mod common;
mod lint_text;

use common::{build_test_server, seed_agent};
use epigraph_auth::{AuthContext, ClientType};
use epigraph_mcp::tools::events::publish_event;
use epigraph_mcp::types::PublishEventParams;
use rmcp::model::{CallToolResult, ErrorCode};
use sqlx::PgPool;
use uuid::Uuid;

/// The `AuthContext` `bearer_auth_middleware` leaves on an HTTP request for a
/// token minted for `agent_id`.
fn http_auth(agent_id: Option<Uuid>) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id,
        // Populated on purpose for the principal-less case: the refusal must
        // not fall back to `owner_id` (or `client_id`) as the actor.
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Agent,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
    }
}

fn params(event_type: &str, actor_id: Option<Uuid>) -> PublishEventParams {
    PublishEventParams {
        event_type: event_type.to_string(),
        actor_id: actor_id.map(|a| a.to_string()),
        payload: serde_json::json!({ "probe": event_type }),
    }
}

fn body(result: &CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("publish_event returns one text block");
    serde_json::from_str(&text).expect("publish_event returns JSON")
}

/// Every persisted `actor_id` for `event_type`, in insertion order.
async fn stored_actors(pool: &PgPool, event_type: &str) -> Vec<Option<Uuid>> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT actor_id FROM events WHERE event_type = $1 ORDER BY graph_version",
    )
    .bind(event_type)
    .fetch_all(pool)
    .await
    .expect("read back events")
}

// ── HTTP arm ────────────────────────────────────────────────────────────────

/// The reported defect: a caller authenticated as A names B as the actor.
#[sqlx::test(migrations = "../../migrations")]
async fn http_a_forged_actor_is_refused_and_nothing_is_written(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let caller = seed_agent(&pool).await;
    let victim = seed_agent(&pool).await;
    let event_type = "test.publish_actor.http_forged";

    let err = publish_event(
        &server,
        params(event_type, Some(victim)),
        Some(&http_auth(Some(caller))),
    )
    .await
    .expect_err("an event attributed to another agent must be refused");
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "{}", err.message);

    assert!(
        stored_actors(&pool, event_type).await.is_empty(),
        "a refused event must not have been persisted"
    );
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM events WHERE actor_id = $1")
        .bind(victim)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 0, "no row anywhere may carry the forged actor");
}

/// Omitting `actor_id` attributes the event to the token's agent. Before the
/// change the row was written with `actor_id IS NULL`.
#[sqlx::test(migrations = "../../migrations")]
async fn http_an_absent_actor_is_the_tokens_agent(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let caller = seed_agent(&pool).await;
    let event_type = "test.publish_actor.http_absent";

    let result = publish_event(
        &server,
        params(event_type, None),
        Some(&http_auth(Some(caller))),
    )
    .await
    .expect("an unattributed publish is attributed, not refused");

    assert_eq!(body(&result)["actor_id"], serde_json::json!(caller));
    assert_eq!(stored_actors(&pool, event_type).await, vec![Some(caller)]);

    // The server's own signer agent is the WRONG answer on HTTP: every caller
    // of the listener shares it, so it attributes nothing. Pin that it was not
    // chosen.
    let server_agent = server.server_agent_id().await.expect("server agent");
    assert_ne!(
        caller, server_agent,
        "fixture: the caller must be distinguishable from the server agent"
    );
}

/// Naming yourself is accepted. Without this case the file could not tell
/// "bound to the principal" from "`actor_id` is now refused whenever present".
#[sqlx::test(migrations = "../../migrations")]
async fn http_the_callers_own_actor_is_accepted(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let caller = seed_agent(&pool).await;
    let event_type = "test.publish_actor.http_self";

    publish_event(
        &server,
        params(event_type, Some(caller)),
        Some(&http_auth(Some(caller))),
    )
    .await
    .expect("self-attribution must succeed");

    assert_eq!(stored_actors(&pool, event_type).await, vec![Some(caller)]);
}

/// A token with no `agent_id` has no principal. It is refused, not attributed
/// to its `owner_id`, its `client_id` or the server agent, and nothing is
/// written. Before the change it was accepted with whatever it sent.
#[sqlx::test(migrations = "../../migrations")]
async fn http_a_principal_less_token_is_refused_and_nothing_is_written(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let event_type = "test.publish_actor.http_no_principal";
    let named = seed_agent(&pool).await;

    for actor in [None, Some(named)] {
        let err = publish_event(&server, params(event_type, actor), Some(&http_auth(None)))
            .await
            .expect_err("a token carrying no agent_id has nothing to attribute to");
        assert!(
            err.message.contains("no agent principal"),
            "the refusal must say why: {}",
            err.message
        );
    }
    assert!(stored_actors(&pool, event_type).await.is_empty());
}

// ── stdio arm ───────────────────────────────────────────────────────────────

/// No `AuthContext` means stdio, where the process is the principal: the
/// event is attributed to the server's own agent.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_an_absent_actor_is_the_server_agent(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let event_type = "test.publish_actor.stdio_absent";

    publish_event(&server, params(event_type, None), None)
        .await
        .expect("stdio publish succeeds");

    let server_agent = server.server_agent_id().await.expect("server agent");
    assert_eq!(
        stored_actors(&pool, event_type).await,
        vec![Some(server_agent)]
    );
}

/// The rule is not relaxed on stdio. A stdio caller naming another agent is
/// refused as well, so "an event's actor is the principal that published it"
/// holds on every transport.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_a_forged_actor_is_refused(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let victim = seed_agent(&pool).await;
    let event_type = "test.publish_actor.stdio_forged";

    let err = publish_event(&server, params(event_type, Some(victim)), None)
        .await
        .expect_err("stdio must not attribute an event to another agent either");
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "{}", err.message);
    assert!(stored_actors(&pool, event_type).await.is_empty());
}

/// A malformed `actor_id` is still `invalid_params`, and is rejected before the
/// principal is resolved.
#[sqlx::test(migrations = "../../migrations")]
async fn a_malformed_actor_id_is_invalid_params(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let event_type = "test.publish_actor.malformed";
    let caller = seed_agent(&pool).await;

    let err = publish_event(
        &server,
        PublishEventParams {
            event_type: event_type.to_string(),
            actor_id: Some("not-a-uuid".to_string()),
            payload: serde_json::json!({}),
        },
        Some(&http_auth(Some(caller))),
    )
    .await
    .expect_err("a malformed actor_id is refused");
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert!(stored_actors(&pool, event_type).await.is_empty());
}

// ── the dispatch body ───────────────────────────────────────────────────────

/// The tests above drive the tool function with the argument the dispatch body
/// SHOULD pass. This pins that it does.
///
/// A `server.rs` body calling `publish_event(self, params, None)` would compile
/// and pass every test above. On HTTP it would then attribute every caller's
/// event to the server's shared signer agent. That is unforgeable, but it
/// destroys attribution as thoroughly as the forgery did. Driving the router
/// needs an `rmcp::service::RequestContext`, which no test in this crate
/// synthesizes (see `http_calls_cannot_reach_a_tool_without_an_auth_context.rs`),
/// so this is a source lock over comment-stripped `server.rs`, as that file's
/// locks are.
#[test]
fn the_dispatch_body_passes_the_requests_auth_context() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server.rs");
    let src = lint_text::strip_comments(&std::fs::read_to_string(&path).expect("read server.rs"));

    let start = src
        .find("async fn publish_event(")
        .expect("server.rs must still define the publish_event dispatch body");
    let rest = &src[start..];
    let end = rest.find("#[tool(").unwrap_or(rest.len());
    let body = &rest[..end];

    assert!(
        body.contains("extensions: rmcp::model::Extensions"),
        "the publish_event dispatch body must take the request extensions:\n{body}"
    );
    assert!(
        body.contains("extensions.get::<epigraph_auth::AuthContext>()"),
        "the publish_event dispatch body must read the request's AuthContext:\n{body}"
    );
    assert!(
        body.contains("tools::events::publish_event(self, params, auth)"),
        "the publish_event dispatch body must pass that AuthContext to the tool, \
         not `None` and not a server-derived identity:\n{body}"
    );
}
