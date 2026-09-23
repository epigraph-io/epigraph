#![cfg(feature = "db")]
//! `POST /api/v1/claims/:id/challenge` attributes its `claim.challenged` event
//! to the AUTHENTICATED PRINCIPAL.
//!
//! Review follow-up to deferred-commitment screen key `events-actor-id-binding`
//! (`D-PR25-event-actor-id-unbound`). That change bound `actor_id` on
//! `POST /api/v1/events` and MCP `publish_event`, and its register entry then
//! said no event-log write path still took a caller-supplied actor. This route
//! was a third door. `routes/challenge.rs::submit_challenge` took no principal
//! extractor and wrote `EventRepository::insert(.., "claim.challenged",
//! Some(request.challenger_id), ..)`, where `challenger_id` is an unchecked body
//! field. Any caller past `bearer_auth_middleware` could therefore put an
//! `events` row under any existing agent's name, and that row cannot be told
//! apart from a genuine one in `GET /api/v1/events`, in MCP `list_events`'
//! `actor_id` filter or in snapshot replay.
//!
//! # What is asserted, and what is deliberately not
//!
//! The EVENT's actor. It is the event log's attribution, it needs no operator
//! decision, and it now comes from the token.
//!
//! NOT `challenges.challenger_id`. Whether a caller may name another agent as
//! the challenger is delegated authorship, the same question as
//! `claims.agent_id`, and it is the open operator decision
//! `D-PR16-claim-authorship-is-not-a-credential` (progress.json assigns this
//! handler's write to it). No test here asserts what that column holds, in
//! either direction, so the decision is not pre-empted and not pinned.
//!
//! Every case asserts the STORED ROW, not only the status. Drives the real
//! router, so `bearer_auth_middleware` and `RequirePrincipal` are both in the
//! path. Both agents are real `agents` rows: `events_actor_id_fkey` and the
//! `challenges` foreign key both require one, and a random id would fail the
//! insert with a 500 instead of exercising the attribution rule.

mod viewer_fixture;

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
use viewer_fixture::{seed_agent_with_group, seed_public_claim};

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

async fn post_challenge(
    pool: &PgPool,
    bearer: &str,
    claim: Uuid,
    challenger: Uuid,
) -> (StatusCode, Value) {
    let app = create_router(AppState::with_db(pool.clone(), ApiConfig::default()));
    let body = json!({
        "challenger_id": challenger,
        "challenge_type": "insufficient_evidence",
        "explanation": "No supporting studies are cited.",
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/claims/{claim}/challenge"))
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

/// The persisted `actor_id` of every `claim.challenged` event, in insertion
/// order. `#[sqlx::test]` gives each case a fresh database, so this is the
/// whole table's worth.
async fn challenged_event_actors(pool: &PgPool) -> Vec<(Option<Uuid>, Value)> {
    sqlx::query_as::<_, (Option<Uuid>, Value)>(
        "SELECT actor_id, payload FROM events \
         WHERE event_type = 'claim.challenged' ORDER BY graph_version",
    )
    .fetch_all(pool)
    .await
    .expect("read back claim.challenged events")
}

/// The reported defect. A caller authenticated as A names B as the challenger.
/// The event must record A, the agent that made the request. Before the fix
/// it recorded B.
#[sqlx::test(migrations = "../../migrations")]
async fn a_challenge_naming_another_agent_records_the_caller_as_the_event_actor(pool: PgPool) {
    let (caller, _) = seed_agent_with_group(&pool, "challenge-caller").await;
    let (victim, _) = seed_agent_with_group(&pool, "challenge-victim").await;
    let claim = seed_public_claim(&pool, victim, "a claim someone will dispute").await;

    let (status, resp) = post_challenge(&pool, &token(Some(caller)), claim, victim).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the challenge itself is not refused here: whether a caller may NAME another \
         challenger is D-PR16's operator decision, not this rule. Got {resp}"
    );
    let challenge_id = resp["id"].clone();

    let events = challenged_event_actors(&pool).await;
    assert_eq!(
        events.len(),
        1,
        "exactly one claim.challenged event: {events:?}"
    );
    assert_eq!(
        events[0].1["challenge_id"], challenge_id,
        "CALIBRATION: the event read back must be the one this request wrote"
    );
    assert_eq!(
        events[0].0,
        Some(caller),
        "the event log must attribute the challenge to the authenticated caller, \
         not to the body's challenger_id"
    );

    let (under_victim,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM events WHERE actor_id = $1")
        .bind(victim)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        under_victim, 0,
        "no event row anywhere may carry the agent the caller named"
    );
}

/// The control. A caller naming itself is attributed to itself, before the fix
/// and after. Without it this file could not tell "bound to the principal" from
/// "the event is no longer written".
#[sqlx::test(migrations = "../../migrations")]
async fn a_callers_own_challenge_is_attributed_to_the_caller(pool: PgPool) {
    let (caller, _) = seed_agent_with_group(&pool, "challenge-self").await;
    let (author, _) = seed_agent_with_group(&pool, "challenge-author").await;
    let claim = seed_public_claim(&pool, author, "a claim its author will not dispute").await;

    let (status, resp) = post_challenge(&pool, &token(Some(caller)), claim, caller).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "self-challenge must succeed: {resp}"
    );

    let events = challenged_event_actors(&pool).await;
    assert_eq!(
        events.len(),
        1,
        "exactly one claim.challenged event: {events:?}"
    );
    assert_eq!(events[0].0, Some(caller));
}

/// A token that names no agent has no principal to attribute the event to. It
/// used to be accepted, with the event filed under whatever challenger it
/// named. It is now 401, `ViewerExtractor`'s branch, and nothing is written:
/// no challenge and no event.
#[sqlx::test(migrations = "../../migrations")]
async fn a_principal_less_token_is_refused_and_nothing_is_written(pool: PgPool) {
    let (victim, _) = seed_agent_with_group(&pool, "challenge-victim-np").await;
    let claim = seed_public_claim(&pool, victim, "a claim a service token disputes").await;

    let (status, resp) = post_challenge(&pool, &token(None), claim, victim).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a token carrying no agent_id must be refused: {resp}"
    );

    assert!(
        challenged_event_actors(&pool).await.is_empty(),
        "a refused challenge must not have written an event"
    );
    let (challenges,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM challenges WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        challenges, 0,
        "a refused challenge must not have been persisted"
    );
}
