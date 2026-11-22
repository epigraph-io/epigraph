//! `POST /api/v1/spans` and `POST /api/v1/events` bind their attribution to
//! the caller (backlog 1dea9589), on the APPLICATION ROLE.
//!
//! Both handlers stored the body's `agent_id` / `actor_id` as given, and a
//! root span's `agent -attributed_to-> span` edge was written, signed by the
//! server, on the raw unstamped pool, so any `claims:write` holder could
//! credit another agent with activity it never performed. Now:
//!
//! * a body naming an agent the caller does not speak for is `403` with
//!   nothing written;
//! * an omitted (or self-naming) agent is the caller;
//! * a human naming the agent it operates through a live binding is admitted
//!   (the `AgentRepository::speaks_for` rule `POST /api/v1/edges` applies),
//!   but not once that link is retired, and never the other way round (an
//!   agent does not speak for its human);
//! * the span and its edge are written on a transaction stamped with the
//!   caller's viewer, so the edge records the caller's writer group.
//!
//! Both pools of the `AppState` are `epigraph_app` (no BYPASSRLS, FORCEd
//! tenancy policies).
#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::State;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::{AuthContext, RequireScopeWrite, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::events::{create_event, CreateEventRequest};
use epigraph_api::routes::spans::{create_span, CreateSpanRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    as_role, database_url_for, downgraded_pool, seed_agent_with_group, seed_human_operator,
};

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
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

async fn viewer(pool: &PgPool, agent: Uuid) -> ViewerExtractor {
    ViewerExtractor(Viewer::resolve(pool, agent).await.expect("resolve"))
}

fn write_scope(agent: Uuid) -> RequireScopeWrite {
    RequireScopeWrite(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    })
}

fn span_request(trace: &str, agent: Option<Uuid>, parent: Option<&str>) -> Json<CreateSpanRequest> {
    Json(
        serde_json::from_value(serde_json::json!({
            "trace_id": trace,
            "parent_span_id": parent,
            "span_name": "1dea9589 span",
            "agent_id": agent,
        }))
        .expect("span request"),
    )
}

fn event_request(event_type: &str, actor: Option<Uuid>) -> Json<CreateEventRequest> {
    Json(
        serde_json::from_value(serde_json::json!({
            "event_type": event_type,
            "actor_id": actor,
            "payload": {"probe": "1dea9589"},
        }))
        .expect("event request"),
    )
}

/// `(agent_id, span id)` of every span on `trace`, read as the superuser.
async fn spans_on(pool: &PgPool, trace: &str) -> Vec<(Option<Uuid>, Uuid)> {
    sqlx::query_as("SELECT agent_id, id FROM agent_spans WHERE trace_id = $1")
        .bind(trace)
        .fetch_all(pool)
        .await
        .expect("spans")
}

/// `(source agent, writer_group_id)` of every `attributed_to` edge onto `span`.
async fn attributions_of(pool: &PgPool, span: Uuid) -> Vec<(Uuid, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT source_id, writer_group_id FROM edges \
          WHERE target_id = $1 AND target_type = 'span' AND relationship = 'attributed_to'",
    )
    .bind(span)
    .fetch_all(pool)
    .await
    .expect("edges")
}

/// `actor_id` of every event of `event_type`, read as the superuser.
async fn actors_of(pool: &PgPool, event_type: &str) -> Vec<Option<Uuid>> {
    sqlx::query_scalar("SELECT actor_id FROM events WHERE event_type = $1")
        .bind(event_type)
        .fetch_all(pool)
        .await
        .expect("events")
}

fn assert_not_spoken_for<T: std::fmt::Debug>(res: Result<T, ApiError>, what: &str) {
    match res {
        Err(ApiError::Forbidden { reason }) => assert!(
            reason.contains("does not speak for"),
            "{what}: the 403 is the attribution rule's: {reason}"
        ),
        other => panic!("{what}: naming another agent must be 403, got {other:?}"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_span_naming_another_agent_is_refused_and_writes_nothing(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "span-forge-caller").await;
    let (other, _) = seed_agent_with_group(&pool, "span-forge-other").await;
    let trace = Uuid::new_v4().simple().to_string();

    let res = create_span(
        write_scope(caller),
        viewer(&pool, caller).await,
        State(state),
        span_request(&trace, Some(other), None),
    )
    .await
    .map(|(s, _)| s);
    assert_not_spoken_for(res, "span");
    assert!(spans_on(&pool, &trace).await.is_empty(), "no span written");
    let forged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'attributed_to'",
    )
    .bind(other)
    .fetch_one(&pool)
    .await
    .expect("edges");
    assert_eq!(forged, 0, "no edge credits the other agent");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_callers_span_is_its_own_and_its_edge_carries_the_callers_stamp(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (caller, caller_group) = seed_agent_with_group(&pool, "span-own-caller").await;
    let trace = Uuid::new_v4().simple().to_string();

    // Omitted: the caller's own root span, with its attribution edge written
    // on the caller's stamped transaction.
    let (status, Json(root)) = create_span(
        write_scope(caller),
        viewer(&pool, caller).await,
        State(state.clone()),
        span_request(&trace, None, None),
    )
    .await
    .unwrap_or_else(|e| panic!("the caller's root span: {e:?}"));
    assert_eq!(status.as_u16(), 201);
    assert_eq!(spans_on(&pool, &trace).await, vec![(Some(caller), root.id)]);
    assert_eq!(
        attributions_of(&pool, root.id).await,
        vec![(caller, Some(caller_group))],
        "the root span is attributed to the caller, on the caller's stamp"
    );

    // Named as itself, as a child span: attributed, and no edge for a child.
    let (status, Json(child)) = create_span(
        write_scope(caller),
        viewer(&pool, caller).await,
        State(state),
        span_request(&trace, Some(caller), Some(&root.span_id)),
    )
    .await
    .unwrap_or_else(|e| panic!("the caller's child span: {e:?}"));
    assert_eq!(status.as_u16(), 201);
    assert!(spans_on(&pool, &trace)
        .await
        .contains(&(Some(caller), child.id)));
    assert!(attributions_of(&pool, child.id).await.is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_operator_may_attribute_a_span_and_an_event_to_the_agent_it_operates(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (human, human_group) = seed_human_operator(&pool, "span-operator").await;
    let (agent, _) = seed_agent_with_group(&pool, "span-operated").await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("live link");
    drop(conn);
    let trace = Uuid::new_v4().simple().to_string();

    let (status, Json(span)) = create_span(
        write_scope(human),
        viewer(&pool, human).await,
        State(state.clone()),
        span_request(&trace, Some(agent), None),
    )
    .await
    .unwrap_or_else(|e| panic!("the operator's span for its agent: {e:?}"));
    assert_eq!(status.as_u16(), 201);
    assert_eq!(spans_on(&pool, &trace).await, vec![(Some(agent), span.id)]);
    assert_eq!(
        attributions_of(&pool, span.id).await,
        vec![(agent, Some(human_group))],
        "attributed to the operated agent, written on the operator's stamp"
    );

    let event_type = format!("test.operated_{}", Uuid::new_v4().simple());
    let Json(event) = create_event(
        write_scope(human),
        viewer(&pool, human).await,
        State(state),
        event_request(&event_type, Some(agent)),
    )
    .await
    .unwrap_or_else(|e| panic!("the operator's event for its agent: {e:?}"));
    assert_eq!(event.actor_id, Some(agent));
    assert_eq!(actors_of(&pool, &event_type).await, vec![Some(agent)]);
}

/// Retire `agent`'s operator link as the maintenance role, as an operator does.
async fn retire_link(pool: &PgPool, agent: Uuid) {
    let outcome: String = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: String = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_retire_operator_link($1, 'span test', true)",
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

/// The binding speaks one way and only while it is in force: an agent naming
/// its own human is refused, and so is the human once the link is retired.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reversed_or_retired_operator_link_speaks_for_no_one(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (human, _) = seed_human_operator(&pool, "span-reverse-human").await;
    let (agent, _) = seed_agent_with_group(&pool, "span-reverse-agent").await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("live link");
    drop(conn);

    // The agent naming its human: the binding does not run that way.
    let reversed = Uuid::new_v4().simple().to_string();
    let res = create_span(
        write_scope(agent),
        viewer(&pool, agent).await,
        State(state.clone()),
        span_request(&reversed, Some(human), None),
    )
    .await
    .map(|(s, _)| s);
    assert_not_spoken_for(res, "an agent naming its own human");
    assert!(
        spans_on(&pool, &reversed).await.is_empty(),
        "no span written"
    );
    let event_type = format!("test.reversed_{}", Uuid::new_v4().simple());
    let res = create_event(
        write_scope(agent),
        viewer(&pool, agent).await,
        State(state.clone()),
        event_request(&event_type, Some(human)),
    )
    .await;
    assert_not_spoken_for(res, "an agent's event naming its own human");
    assert!(
        actors_of(&pool, &event_type).await.is_empty(),
        "nothing written"
    );

    // CALIBRATION: while the link is live the human speaks for the agent.
    let live = Uuid::new_v4().simple().to_string();
    let (status, _) = create_span(
        write_scope(human),
        viewer(&pool, human).await,
        State(state.clone()),
        span_request(&live, Some(agent), None),
    )
    .await
    .unwrap_or_else(|e| panic!("CALIBRATION: the live link admits: {e:?}"));
    assert_eq!(status.as_u16(), 201, "CALIBRATION: the live link admits");

    retire_link(&pool, agent).await;
    let retired = Uuid::new_v4().simple().to_string();
    let res = create_span(
        write_scope(human),
        viewer(&pool, human).await,
        State(state.clone()),
        span_request(&retired, Some(agent), None),
    )
    .await
    .map(|(s, _)| s);
    assert_not_spoken_for(res, "a human naming an agent whose link is retired");
    assert!(
        spans_on(&pool, &retired).await.is_empty(),
        "no span written"
    );
    let event_type = format!("test.retired_{}", Uuid::new_v4().simple());
    let res = create_event(
        write_scope(human),
        viewer(&pool, human).await,
        State(state),
        event_request(&event_type, Some(agent)),
    )
    .await;
    assert_not_spoken_for(res, "an event naming an agent whose link is retired");
    assert!(
        actors_of(&pool, &event_type).await.is_empty(),
        "nothing written"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_event_actor_is_the_caller_unless_it_speaks_for_another(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "event-caller").await;
    let (other, _) = seed_agent_with_group(&pool, "event-other").await;

    let forged = format!("test.forged_{}", Uuid::new_v4().simple());
    let res = create_event(
        write_scope(caller),
        viewer(&pool, caller).await,
        State(state.clone()),
        event_request(&forged, Some(other)),
    )
    .await;
    assert_not_spoken_for(res, "event");
    assert!(
        actors_of(&pool, &forged).await.is_empty(),
        "nothing written"
    );

    let omitted = format!("test.omitted_{}", Uuid::new_v4().simple());
    let Json(event) = create_event(
        write_scope(caller),
        viewer(&pool, caller).await,
        State(state.clone()),
        event_request(&omitted, None),
    )
    .await
    .unwrap_or_else(|e| panic!("the caller's event: {e:?}"));
    assert_eq!(event.actor_id, Some(caller));
    assert_eq!(actors_of(&pool, &omitted).await, vec![Some(caller)]);

    let named = format!("test.self_{}", Uuid::new_v4().simple());
    let Json(event) = create_event(
        write_scope(caller),
        viewer(&pool, caller).await,
        State(state),
        event_request(&named, Some(caller)),
    )
    .await
    .unwrap_or_else(|e| panic!("naming itself: {e:?}"));
    assert_eq!(event.actor_id, Some(caller));
}
