#![cfg(feature = "db")]
//! `POST /api/v1/events` attributes an event to the AUTHENTICATED PRINCIPAL.
//!
//! Deferred-commitment screen key `events-actor-id-binding`. Until this change
//! `routes/events.rs::create_event` took no auth extractor at all and bound the
//! body's `actor_id` straight into `EventRepository::insert`, so any caller that
//! got past `bearer_auth_middleware` could record an event attributed to any
//! agent UUID. Such a row is indistinguishable from a genuine one in
//! `GET /api/v1/events`, in MCP `list_events`' `actor_id` filter and in
//! `GET /api/v1/graph/snapshot/:version` replay.
//!
//! Every assertion here is on the STORED ROW as well as on the status code: a
//! handler that answered 403 but had already written, or answered 200 while
//! persisting a different actor than it echoed, would pass a status-only test.
//!
//! Drives the real router (`create_router`), so `bearer_auth_middleware` and the
//! `RequirePrincipal` extractor are both in the path. `#[sqlx::test]` gives each
//! case a fresh database, so "no row was written" is a statement about the whole
//! `events` table rather than about a filter.
//!
//! # Both principals are real `agents` rows, deliberately
//!
//! `events.actor_id` carries a foreign key to `agents(id)`
//! (`events_actor_id_fkey`, migration 001). So the forgery was never "any UUID":
//! a fabricated id fails the insert with a 500. It was "any EXISTING agent",
//! which is the case that matters — agent ids are not secret (every claim
//! carries its author's) — and a fixture using random ids would have made the
//! pre-fix handler look safe by tripping the FK instead of the missing check.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Mint a JWT the production middleware accepts. `agent_id: None` reproduces a
/// principal-less token (a `ClientType::Service` credential, or an OAuth client
/// registered before PR-02 populated `oauth_clients.agent_id`).
fn token(agent_id: Option<Uuid>) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (t, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:write".to_string()],
            if agent_id.is_some() {
                "agent"
            } else {
                "service"
            },
            None,
            agent_id,
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    t
}

/// Insert a real `agents` row, so the `events_actor_id_fkey` foreign key is
/// satisfied and only the attribution rule can refuse the write.
async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn post_event(pool: &PgPool, bearer: &str, body: Value) -> (StatusCode, Value) {
    let app = create_router(AppState::with_db(pool.clone(), ApiConfig::default()));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/events")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Every persisted `(actor_id)` for `event_type`, in insertion order.
async fn stored_actors(pool: &PgPool, event_type: &str) -> Vec<Option<Uuid>> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT actor_id FROM events WHERE event_type = $1 ORDER BY graph_version",
    )
    .bind(event_type)
    .fetch_all(pool)
    .await
    .expect("read back events")
}

/// The reported defect: a caller authenticated as A names B as the actor. It
/// must be refused, and refused BEFORE the write.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_actor_id_is_refused_and_nothing_is_written(pool: PgPool) {
    let caller = seed_agent(&pool).await;
    let victim = seed_agent(&pool).await;
    let event_type = "test.actor_binding.forged";

    let (status, body) = post_event(
        &pool,
        &token(Some(caller)),
        json!({ "event_type": event_type, "actor_id": victim, "payload": {"n": 1} }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an event attributed to another agent must be refused; got {body}"
    );
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

/// Omitting `actor_id` — and sending an explicit JSON `null`, which serde reads
/// as the same `None` — attributes the event to the caller rather than to
/// nobody. Before the change both produced a row with `actor_id IS NULL`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_absent_actor_id_is_filled_from_the_principal(pool: PgPool) {
    let caller = seed_agent(&pool).await;
    let event_type = "test.actor_binding.absent";

    for body in [
        json!({ "event_type": event_type, "payload": {"shape": "omitted"} }),
        json!({ "event_type": event_type, "actor_id": null, "payload": {"shape": "null"} }),
    ] {
        let (status, resp) = post_event(&pool, &token(Some(caller)), body).await;
        assert_eq!(status, StatusCode::OK, "the write must succeed: {resp}");
        assert_eq!(
            resp["actor_id"],
            json!(caller),
            "the response must echo the actor that was PERSISTED"
        );
    }

    assert_eq!(
        stored_actors(&pool, event_type).await,
        vec![Some(caller), Some(caller)],
        "both rows must be attributed to the authenticated principal"
    );
}

/// The caller naming itself is the one explicit value that is accepted.
/// Without this case the test file could not tell "bound to the principal" from
/// "`actor_id` is now rejected whenever present".
#[sqlx::test(migrations = "../../migrations")]
async fn the_callers_own_actor_id_is_accepted(pool: PgPool) {
    let caller = seed_agent(&pool).await;
    let event_type = "test.actor_binding.self";

    let (status, resp) = post_event(
        &pool,
        &token(Some(caller)),
        json!({ "event_type": event_type, "actor_id": caller, "payload": {} }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "self-attribution must succeed: {resp}"
    );
    assert_eq!(resp["actor_id"], json!(caller));
    assert_eq!(stored_actors(&pool, event_type).await, vec![Some(caller)]);
}

/// A token that names no agent has no principal to attribute to. It used to be
/// accepted with whatever `actor_id` it sent (or NULL); it is now 401, the same
/// branch `ViewerExtractor` takes, and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_principal_less_token_is_refused_and_nothing_is_written(pool: PgPool) {
    let event_type = "test.actor_binding.no_principal";

    for body in [
        json!({ "event_type": event_type, "payload": {} }),
        json!({ "event_type": event_type, "actor_id": seed_agent(&pool).await, "payload": {} }),
    ] {
        let (status, resp) = post_event(&pool, &token(None), body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a token carrying no agent_id must be refused: {resp}"
        );
    }
    assert!(
        stored_actors(&pool, event_type).await.is_empty(),
        "a refused event must not have been persisted"
    );
}
