#![cfg(feature = "db")]
//! `POST /api/v1/frames/:id/evidence` attributes every event it emits to the
//! AUTHENTICATED PRINCIPAL.
//!
//! Second review follow-up to deferred-commitment screen key
//! `events-actor-id-binding` (`D-PR25-event-actor-id-unbound`). That change
//! bound the event actor on `POST /api/v1/events`, MCP `publish_event` and then
//! `POST /api/v1/claims/:id/challenge`, and its register entry went on to say
//! every caller-facing writer taking an actor from a request field other than
//! `claims.agent_id` was bound. This route was a fourth door.
//! `routes/belief.rs::submit_evidence` held a `ViewerExtractor` and never
//! consulted it for attribution: it pushed up to nine events
//! (`contradiction.predicted`, `frame.incomplete`, `conflict.genuine`,
//! `evidence.submitted`, `belief.updated`, `velocity.suspicious`,
//! `conflict.detected`, `silence.suspicious`, `divergence.spike`) into the
//! in-process ring buffer with `actor_id = request.agent_id`, an unchecked body
//! field. The db build's `GET /api/v1/events` merges that ring buffer into its
//! response, and `retain_visible_events` filters on payload uuids, never on the
//! actor. So a caller authenticated as A could file `evidence.submitted` and
//! its siblings as agent B on any claim it can see, without even the
//! `events_actor_id_fkey` bound the persisted table has.
//!
//! # What is asserted, and what is deliberately not
//!
//! The EVENTS' actor, as `GET /api/v1/events` serves it to the caller and as
//! the ring buffer holds it. It is the event log's attribution, it needs no
//! operator decision, and it now comes from the token.
//!
//! NOT the mass function's `source_agent_id`, its `GENERATED_BY` edge, the
//! competence discount keyed on the body's `agent_id`, or the
//! `evidence.submitted` payload's `agent_id` field that mirrors them. Whether a
//! caller may submit evidence on another agent's behalf is delegated
//! authorship, the open operator decision
//! `D-PR16-claim-authorship-is-not-a-credential`, the same question as
//! `claims.agent_id` and `challenges.challenger_id`. Nothing here asserts what
//! those hold, in either direction, so the decision is neither pre-empted nor
//! pinned.
//!
//! # The ring buffer is process-wide
//!
//! `global_event_store()` is one `OnceLock` shared by every test in this
//! binary, and `#[sqlx::test]` cases run concurrently. So every read here is
//! narrowed to events whose payload names THIS case's claim, and every "no
//! event carries B" check is keyed on B, a fresh agent id no other case can
//! have minted.

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

/// Mint a JWT the production middleware accepts, bound to `agent`.
fn token(agent: Uuid) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (t, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string(), "claims:write".to_string()],
            "agent",
            None,
            Some(agent),
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    t
}

async fn call(
    pool: &PgPool,
    bearer: &str,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = create_router(AppState::with_db(pool.clone(), ApiConfig::default()));
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    let body = match body {
        Some(b) => {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Create a two-hypothesis frame through the real route, as `bearer`.
async fn create_frame(pool: &PgPool, bearer: &str) -> Uuid {
    let (status, resp) = call(
        pool,
        bearer,
        Method::POST,
        "/api/v1/frames",
        Some(json!({
            "name": format!("evidence-actor-{}", Uuid::new_v4()),
            "hypotheses": ["holds", "does not hold"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create frame: {resp}");
    resp["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("frame id in {resp}"))
}

/// Submit one BBA to `frame` about `claim`, naming `agent_id` in the body
/// (`None` omits the field). Returns the status and body.
async fn submit(
    pool: &PgPool,
    bearer: &str,
    frame: Uuid,
    claim: Uuid,
    agent_id: Option<Uuid>,
    masses: Value,
) -> (StatusCode, Value) {
    let mut body = json!({
        "claim_id": claim,
        "masses": masses,
        "reliability": 1.0,
        "assume_independent": true,
    });
    if let Some(a) = agent_id {
        body["agent_id"] = json!(a);
    }
    call(
        pool,
        bearer,
        Method::POST,
        &format!("/api/v1/frames/{frame}/evidence"),
        Some(body),
    )
    .await
}

/// Every event `GET /api/v1/events` serves `bearer` whose payload names
/// `claim`, as `(event_type, actor_id)`. The payload filter is what keeps this
/// case's events apart from the concurrent cases sharing the ring buffer.
async fn events_for_claim(pool: &PgPool, bearer: &str, claim: Uuid) -> Vec<(String, Option<Uuid>)> {
    let (status, resp) = call(pool, bearer, Method::GET, "/api/v1/events?limit=1000", None).await;
    assert_eq!(status, StatusCode::OK, "GET /api/v1/events: {resp}");
    let claim = claim.to_string();
    resp["events"]
        .as_array()
        .unwrap_or_else(|| panic!("events array in {resp}"))
        .iter()
        .filter(|e| e["payload"]["claim_id"].as_str() == Some(claim.as_str()))
        .map(|e| {
            (
                e["event_type"].as_str().unwrap_or_default().to_string(),
                e["actor_id"].as_str().and_then(|s| s.parse().ok()),
            )
        })
        .collect()
}

/// Every event anywhere in the process-wide ring buffer whose actor is
/// `agent`. `agent` is minted by the calling case, so no other case can have
/// produced a match.
async fn ring_buffer_events_by(agent: Uuid) -> Vec<String> {
    let filter = epigraph_api::routes::events::EventFilter {
        since: None,
        event_type: None,
        limit: Some(usize::MAX),
        offset: None,
    };
    let (all, _) = epigraph_api::_test_event_store().list(&filter).await;
    all.into_iter()
        .filter(|e| e.actor_id == Some(agent))
        .map(|e| e.event_type)
        .collect()
}

/// The reported defect. A caller authenticated as A submits evidence naming B
/// as the source agent, then contradicting evidence naming C. Two named agents
/// rather than one because `mass_functions` upserts on
/// `(claim_id, frame_id, source_agent_id, perspective_id)`: a second BBA under
/// the same name REPLACES the first, leaving one source and no combination, so
/// the conflict push sites would never be reached. With two sources the
/// second submission combines them and reaches the conditional
/// `conflict.detected` site as well as the two unconditional ones. Every event
/// must record A. Before the fix each recorded whichever agent its request
/// named.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_naming_other_agents_attributes_every_event_to_the_caller(pool: PgPool) {
    let (caller, _) = seed_agent_with_group(&pool, "evidence-caller").await;
    let (victim_b, _) = seed_agent_with_group(&pool, "evidence-victim-b").await;
    let (victim_c, _) = seed_agent_with_group(&pool, "evidence-victim-c").await;
    let claim = seed_public_claim(&pool, victim_b, "a claim someone will weigh evidence on").await;
    let bearer = token(caller);
    let frame = create_frame(&pool, &bearer).await;

    for (named, masses) in [
        (victim_b, json!({"0": 0.9, "0,1": 0.1})),
        (victim_c, json!({"1": 0.9, "0,1": 0.1})),
    ] {
        let (status, resp) = submit(&pool, &bearer, frame, claim, Some(named), masses).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "the submission itself is not refused here: whether a caller may NAME \
             another source agent is D-PR16's operator decision, not this rule. Got {resp}"
        );
    }

    let events = events_for_claim(&pool, &bearer, claim).await;
    let count = |ty: &str| events.iter().filter(|(t, _)| t == ty).count();
    assert_eq!(
        (count("evidence.submitted"), count("belief.updated")),
        (2, 2),
        "CALIBRATION: both submissions must reach the two unconditional push sites, \
         or this case proves nothing about them: {events:?}"
    );
    assert!(
        count("conflict.detected") >= 1,
        "CALIBRATION: the contradicting second BBA must reach the conditional \
         conflict.detected site: {events:?}"
    );
    for (ty, actor) in &events {
        assert_eq!(
            *actor,
            Some(caller),
            "{ty} must be attributed to the authenticated caller, not to the body's \
             agent_id: {events:?}"
        );
    }
    for named in [victim_b, victim_c] {
        assert!(
            ring_buffer_events_by(named).await.is_empty(),
            "no event anywhere in the ring buffer may carry an agent the caller named"
        );
        let (persisted,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM events WHERE actor_id = $1")
                .bind(named)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            persisted, 0,
            "nor may any persisted events row carry an agent the caller named"
        );
    }
}

/// An omitted `agent_id` used to push every event with `actor_id = NULL`, an
/// unattributed row. It is now the caller's.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_without_an_agent_id_is_attributed_to_the_caller(pool: PgPool) {
    let (caller, _) = seed_agent_with_group(&pool, "evidence-anon-caller").await;
    let (author, _) = seed_agent_with_group(&pool, "evidence-anon-author").await;
    let claim = seed_public_claim(&pool, author, "a claim weighed without a named source").await;
    let bearer = token(caller);
    let frame = create_frame(&pool, &bearer).await;

    let (status, resp) = submit(
        &pool,
        &bearer,
        frame,
        claim,
        None,
        json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "submission: {resp}");

    let events = events_for_claim(&pool, &bearer, claim).await;
    assert!(
        events.iter().any(|(t, _)| t == "evidence.submitted"),
        "CALIBRATION: the submission's evidence.submitted event must be read back: {events:?}"
    );
    for (ty, actor) in &events {
        assert_eq!(
            *actor,
            Some(caller),
            "{ty} must be attributed to the caller, not left unattributed: {events:?}"
        );
    }
}

/// The control. A caller naming itself is attributed to itself, before the fix
/// and after. Without it this file could not tell "bound to the principal"
/// from "the events are no longer pushed".
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_naming_the_caller_is_attributed_to_the_caller(pool: PgPool) {
    let (caller, _) = seed_agent_with_group(&pool, "evidence-self").await;
    let (author, _) = seed_agent_with_group(&pool, "evidence-self-author").await;
    let claim = seed_public_claim(&pool, author, "a claim its weigher names itself on").await;
    let bearer = token(caller);
    let frame = create_frame(&pool, &bearer).await;

    let (status, resp) = submit(
        &pool,
        &bearer,
        frame,
        claim,
        Some(caller),
        json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "submission: {resp}");

    let events = events_for_claim(&pool, &bearer, claim).await;
    assert!(
        events.iter().any(|(t, _)| t == "evidence.submitted"),
        "CALIBRATION: the submission's evidence.submitted event must be read back: {events:?}"
    );
    assert!(
        events.iter().all(|(_, actor)| *actor == Some(caller)),
        "self-attributed evidence must stay attributed to the caller: {events:?}"
    );
}
