//! `POST /api/v1/reasoning-traces` on the APPLICATION ROLE (backlog f64cf9c6).
//!
//! The handler took its author from the body's `agent_id` and wrote on the
//! unstamped pool. Now:
//!
//! * an absent `AuthContext` is `401` with nothing written;
//! * a body `agent_id` naming another agent is `403` with nothing written;
//! * an omitted (or self-naming) `agent_id` is the caller, and the trace is
//!   written on a transaction stamped with the caller's viewer, so the database
//!   decides its owner from the caller's writable groups;
//! * a claim the caller cannot read answers exactly as a nonexistent one
//!   (`404`, same body), and a claim it reads but may not write is `403`.
//!
//! Both pools of the `AppState` are `epigraph_app` (no BYPASSRLS, FORCEd
//! tenancy policies), as in `entity_triple_write_app_role.rs`: a write that
//! passed on the test superuser and was refused in production fails here.
//!
//! The trace in the admitted arm is attached to a PUBLIC claim owned by
//! ANOTHER group, so the writer-owned branch decides its owner: it must be the
//! caller's group. On the caller's own claim the trace would inherit the
//! claim's group, which is the caller's anyway, and the assertion could not
//! tell the right owner from a coincidence.
#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::State;
use axum::Extension;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::crud::{create_reasoning_trace, CreateReasoningTraceRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group};

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

async fn viewer(pool: &PgPool, agent: Uuid) -> ViewerExtractor {
    ViewerExtractor(Viewer::resolve(pool, agent).await.expect("resolve"))
}

fn auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

async fn public_claim_of(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("f64cf9c6 public claim {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

fn request(claim: Uuid, agent_id: Option<Uuid>) -> CreateReasoningTraceRequest {
    CreateReasoningTraceRequest {
        claim_id: claim,
        agent_id,
        methodology: "deductive".to_string(),
        confidence: 0.7,
        explanation: "f64cf9c6 trace".to_string(),
        inputs: None,
    }
}

/// `(owner_group_id, writer_owned)` of every trace on `claim`, read on the
/// superuser harness connection so nothing is filtered.
async fn traces_on(pool: &PgPool, claim: Uuid) -> Vec<(Uuid, bool)> {
    sqlx::query_as("SELECT owner_group_id, writer_owned FROM reasoning_traces WHERE claim_id = $1")
        .bind(claim)
        .fetch_all(pool)
        .await
        .expect("traces")
}

struct World {
    pool: PgPool,
    state: AppState,
    caller: Uuid,
    caller_group: Uuid,
    other: Uuid,
    claim: Uuid,
}

async fn world(pool: PgPool, label: &str) -> World {
    let state = app_role_state(&pool).await;
    let (caller, caller_group) = seed_agent_with_group(&pool, &format!("{label}-caller")).await;
    let (other, other_group) = seed_agent_with_group(&pool, &format!("{label}-other")).await;
    let claim = public_claim_of(&pool, other, other_group).await;
    World {
        pool,
        state,
        caller,
        caller_group,
        other,
        claim,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unauthenticated_trace_is_refused_and_writes_nothing(pool: PgPool) {
    let w = world(pool, "f64-unauth").await;
    let res = create_reasoning_trace(
        viewer(&w.pool, w.caller).await,
        State(w.state.clone()),
        None,
        Json(request(w.claim, None)),
    )
    .await;
    assert!(
        matches!(res, Err(ApiError::Unauthorized { .. })),
        "no AuthContext must be 401, got {:?}",
        res.map(|(s, _)| s)
    );
    assert!(
        traces_on(&w.pool, w.claim).await.is_empty(),
        "nothing written"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_trace_naming_another_agent_is_refused_and_writes_nothing(pool: PgPool) {
    let w = world(pool, "f64-forge").await;
    let res = create_reasoning_trace(
        viewer(&w.pool, w.caller).await,
        State(w.state.clone()),
        auth(w.caller),
        Json(request(w.claim, Some(w.other))),
    )
    .await;
    match res {
        Err(ApiError::Forbidden { reason }) => assert!(
            reason.contains("agent_id must be the authenticated caller"),
            "the 403 is the author rule's: {reason}"
        ),
        other => panic!(
            "naming another agent must be 403, got {:?}",
            other.map(|(s, _)| s)
        ),
    }
    assert!(
        traces_on(&w.pool, w.claim).await.is_empty(),
        "nothing written"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_callers_trace_commits_on_the_app_role_owned_by_the_callers_group(pool: PgPool) {
    let w = world(pool, "f64-own").await;

    // Omitted: the caller's own.
    let (status, Json(body)) = create_reasoning_trace(
        viewer(&w.pool, w.caller).await,
        State(w.state.clone()),
        auth(w.caller),
        Json(request(w.claim, None)),
    )
    .await
    .unwrap_or_else(|e| panic!("the caller's trace on the app role: {e:?}"));
    assert_eq!(status.as_u16(), 201);
    assert_eq!(
        body.agent_id, w.caller,
        "the trace is attributed to the caller"
    );
    assert_eq!(
        traces_on(&w.pool, w.claim).await,
        vec![(w.caller_group, true)],
        "the trace on another group's public claim is the caller's, owned by the \
         caller's group"
    );
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
            AND relationship = 'HAS_TRACE'",
    )
    .bind(w.claim)
    .bind(body.id)
    .fetch_one(&w.pool)
    .await
    .expect("edges");
    assert_eq!(edges, 1, "the HAS_TRACE edge commits with the trace");

    // Named as itself: unchanged.
    let (status, Json(body)) = create_reasoning_trace(
        viewer(&w.pool, w.caller).await,
        State(w.state.clone()),
        auth(w.caller),
        Json(request(w.claim, Some(w.caller))),
    )
    .await
    .unwrap_or_else(|e| panic!("naming itself: {e:?}"));
    assert_eq!(status.as_u16(), 201);
    assert_eq!(body.agent_id, w.caller);
    assert_eq!(traces_on(&w.pool, w.claim).await.len(), 2);
}

/// A `'group'`-visibility claim owned by `group`, readable only by its members.
async fn group_claim_of(pool: &PgPool, agent: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'group', $5)",
    )
    .bind(id)
    .bind(format!("f64cf9c6 group claim {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed group claim");
    id
}

/// The refusal rendered as the client sees it: status and body bytes, with the
/// request's own claim id replaced by a fixed token (the 404 echoes the id the
/// caller sent, which it already knows).
async fn rendered(
    res: Result<(axum::http::StatusCode, Json<impl Sized>), ApiError>,
    claim: Uuid,
) -> (u16, String) {
    use axum::response::IntoResponse;
    let err = match res {
        Ok((status, _)) => panic!("expected a refusal, got {status}"),
        Err(e) => e,
    };
    let response = err.into_response();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let body = String::from_utf8(bytes.to_vec())
        .expect("utf-8 body")
        .replace(&claim.to_string(), "<claim>");
    (status, body)
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_claim_answers_exactly_as_a_missing_one(pool: PgPool) {
    let w = world(pool, "f64-oracle").await;
    let (_, hidden_group) = seed_agent_with_group(&w.pool, "f64-oracle-hidden").await;
    let hidden = group_claim_of(&w.pool, w.other, hidden_group).await;
    let missing = Uuid::new_v4();

    let unreadable = rendered(
        create_reasoning_trace(
            viewer(&w.pool, w.caller).await,
            State(w.state.clone()),
            auth(w.caller),
            Json(request(hidden, None)),
        )
        .await,
        hidden,
    )
    .await;
    let absent = rendered(
        create_reasoning_trace(
            viewer(&w.pool, w.caller).await,
            State(w.state.clone()),
            auth(w.caller),
            Json(request(missing, None)),
        )
        .await,
        missing,
    )
    .await;

    assert_eq!(
        unreadable.0, 404,
        "an unreadable claim is 404: {unreadable:?}"
    );
    assert_eq!(
        unreadable, absent,
        "an unreadable claim and a nonexistent one must be indistinguishable"
    );
    assert!(
        traces_on(&w.pool, hidden).await.is_empty(),
        "nothing written"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_readable_claim_the_caller_cannot_write_is_refused(pool: PgPool) {
    let w = world(pool, "f64-reader").await;
    let (author, read_only_group) = seed_agent_with_group(&w.pool, "f64-reader-owner").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(read_only_group)
    .bind(w.caller)
    .execute(&w.pool)
    .await
    .expect("seed reader membership");
    let claim = group_claim_of(&w.pool, author, read_only_group).await;

    let res = create_reasoning_trace(
        viewer(&w.pool, w.caller).await,
        State(w.state.clone()),
        auth(w.caller),
        Json(request(claim, None)),
    )
    .await;
    match res {
        Err(ApiError::Forbidden { .. }) => {}
        other => panic!(
            "a claim the caller reads but may not write must be 403, got {:?}",
            other.map(|(s, _)| s)
        ),
    }
    assert!(
        traces_on(&w.pool, claim).await.is_empty(),
        "nothing written"
    );
}
