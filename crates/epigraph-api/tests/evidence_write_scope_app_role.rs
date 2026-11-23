//! The two HTTP evidence writers that wrote on the raw, unstamped pool
//! (backlog 73d4f7ff): `POST /api/v1/evidence` (`crud::create_evidence`) and
//! `POST /api/v1/conventions` (`conventions::learn_convention`).
//!
//! Unstamped, nothing told the database who wrote the row: on a public claim
//! the evidence inherited the CLAIM's group and its `evidence -> claim` edge
//! (and `create_evidence`'s `claim -> evidence` `DERIVED_FROM` edge) landed
//! `('public', world)`, administrative from birth, so the writer could not
//! later retract or patch them. Stamped with the caller's viewer, migration
//! 114's attach rule owns the evidence by the caller's group (`writer_owned`)
//! and migration 120 owns each edge by it.
//!
//! Every admitted arm attaches to a PUBLIC claim owned by ANOTHER group, so the
//! writer-owned branch decides the owner: on the caller's own claim the rows
//! would inherit the caller's group anyway, and the assertion could not tell
//! the right owner from a coincidence.
//!
//! Two deployment shapes:
//!
//! * both pools on the application role (no BYPASSRLS, FORCEd tenancy
//!   policies): the shape production serves from, where an unstamped evidence
//!   INSERT is refused outright;
//! * a privileged raw pool with an application-role `ScopedPool` (a deployment
//!   whose `DATABASE_URL` is the owner): the shape in which the unstamped write
//!   SUCCEEDED and the rows took no caller ownership. `learn_convention` is
//!   measured here only, because it still writes its system-authored claim on
//!   the raw pool (see the module doc of `routes/conventions.rs`).
#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::State;
use axum::{Extension, Json};
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::conventions::{learn_convention, LearnConventionRequest};
use epigraph_api::routes::crud::{create_evidence, CreateEvidenceRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group, world_group};

async fn app_role_scoped(pool: &PgPool) -> ScopedPool {
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
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// Both pools on the application role.
async fn app_role_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(app_role_scoped(pool).await);
    state
}

/// The raw pool is the harness superuser; the stamped pool is the app role.
async fn privileged_raw_state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(app_role_scoped(pool).await);
    state
}

async fn viewer(pool: &PgPool, agent: Uuid) -> ViewerExtractor {
    ViewerExtractor(Viewer::resolve(pool, agent).await.expect("resolve"))
}

fn auth(agent: Uuid, scope: &str) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: vec![scope.to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid, visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, $5, $6)",
    )
    .bind(id)
    .bind(format!("73d4f7ff {visibility} claim {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

fn evidence_request(agent: Uuid, claim: Uuid) -> Json<CreateEvidenceRequest> {
    Json(
        serde_json::from_value(serde_json::json!({
            "agent_id": agent,
            "claim_id": claim,
            "raw_content": format!("73d4f7ff evidence {}", Uuid::new_v4()),
            "evidence_type": {
                "type": "observation", "observed_at": chrono::Utc::now(),
                "method": "73d4f7ff", "location": null
            },
        }))
        .expect("request"),
    )
}

/// `(owner_group_id, writer_owned)` of every evidence row on `claim`, read on
/// the superuser harness connection so nothing is filtered.
async fn evidence_on(pool: &PgPool, claim: Uuid) -> Vec<(Uuid, Uuid, bool)> {
    sqlx::query_as("SELECT id, owner_group_id, writer_owned FROM evidence WHERE claim_id = $1")
        .bind(claim)
        .fetch_all(pool)
        .await
        .expect("evidence")
}

/// `(relationship, owner_group_id)` of every edge between `evidence` and
/// `claim`, in either direction, sorted.
async fn edges_between(pool: &PgPool, evidence: Uuid, claim: Uuid) -> Vec<(String, Uuid)> {
    let mut rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT relationship, owner_group_id FROM edges \
          WHERE (source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)",
    )
    .bind(evidence)
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("edges");
    rows.sort();
    rows
}

/// The caller's evidence on another group's public claim, with both of its
/// edges, is owned by the caller's group.
async fn assert_post_evidence_is_the_callers(pool: PgPool, state: AppState, label: &str) {
    let (caller, caller_group) = seed_agent_with_group(&pool, &format!("{label}-caller")).await;
    let (other, other_group) = seed_agent_with_group(&pool, &format!("{label}-other")).await;
    let claim = claim_of(&pool, other, other_group, "public").await;

    let (status, Json(body)) = create_evidence(
        viewer(&pool, caller).await,
        State(state),
        auth(caller, "evidence:write"),
        evidence_request(caller, claim),
    )
    .await
    .unwrap_or_else(|e| panic!("{label}: the caller's evidence: {e:?}"));
    assert_eq!(status.as_u16(), 201, "{label}");
    assert_eq!(
        evidence_on(&pool, claim).await,
        vec![(body.id, caller_group, true)],
        "{label}: the evidence on another group's public claim is owned by the caller's group"
    );
    assert_eq!(
        edges_between(&pool, body.id, claim).await,
        vec![
            ("DERIVED_FROM".to_string(), caller_group),
            ("supports".to_string(), caller_group),
        ],
        "{label}: both edges are the caller's, not world-owned ({})",
        world_group(&pool).await
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn post_evidence_on_the_app_role_is_owned_by_the_callers_group(pool: PgPool) {
    let state = app_role_state(&pool).await;
    assert_post_evidence_is_the_callers(pool, state, "app-role").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn post_evidence_on_a_privileged_raw_pool_is_owned_by_the_callers_group(pool: PgPool) {
    let state = privileged_raw_state(&pool).await;
    assert_post_evidence_is_the_callers(pool, state, "privileged-raw").await;
}

/// The refusal as the client sees it: status and body, with the request's own
/// claim id masked (the 404 echoes the id the caller sent).
async fn rendered<T>(res: Result<T, ApiError>, claim: Uuid) -> (u16, String) {
    use axum::response::IntoResponse;
    let Err(err) = res else {
        panic!("expected a refusal")
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
async fn post_evidence_on_an_unreadable_claim_answers_as_a_missing_one(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "oracle-caller").await;
    let (other, other_group) = seed_agent_with_group(&pool, "oracle-other").await;
    let hidden = claim_of(&pool, other, other_group, "group").await;
    let missing = Uuid::new_v4();

    let unreadable = rendered(
        create_evidence(
            viewer(&pool, caller).await,
            State(state.clone()),
            auth(caller, "evidence:write"),
            evidence_request(caller, hidden),
        )
        .await,
        hidden,
    )
    .await;
    let absent = rendered(
        create_evidence(
            viewer(&pool, caller).await,
            State(state),
            auth(caller, "evidence:write"),
            evidence_request(caller, missing),
        )
        .await,
        missing,
    )
    .await;
    assert_eq!(unreadable.0, 404, "{unreadable:?}");
    assert_eq!(
        unreadable, absent,
        "an unreadable claim and a nonexistent one must be indistinguishable"
    );
    assert!(
        evidence_on(&pool, hidden).await.is_empty(),
        "nothing written"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn learned_convention_evidence_is_owned_by_the_callers_group(pool: PgPool) {
    let state = privileged_raw_state(&pool).await;
    let (admin, admin_group) = seed_agent_with_group(&pool, "convention-admin").await;
    let request: LearnConventionRequest = serde_json::from_value(serde_json::json!({
        "content": format!("73d4f7ff convention {}", Uuid::new_v4()),
        "evidence": "seen in three reviews",
    }))
    .expect("request");

    let (status, Json(created)) = learn_convention(
        viewer(&pool, admin).await,
        State(state),
        auth(admin, "claims:admin"),
        Json(request),
    )
    .await
    .expect("the convention is learned");
    assert_eq!(status.as_u16(), 201);

    // The convention claim is the system agent's, public, in another group.
    let (visibility, claim_group): (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM claims WHERE id = $1")
            .bind(created.claim_id)
            .fetch_one(&pool)
            .await
            .expect("the convention claim");
    assert_eq!(visibility, "public");
    assert_ne!(
        claim_group, admin_group,
        "calibration: the claim is not the caller's, so the writer-owned branch decides"
    );

    let rows = evidence_on(&pool, created.claim_id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (evidence, owner, writer_owned) = rows[0];
    assert_eq!(
        (owner, writer_owned),
        (admin_group, true),
        "the learned convention's evidence is the caller's"
    );
    assert_eq!(
        edges_between(&pool, evidence, created.claim_id).await,
        vec![("supports".to_string(), admin_group)],
        "the supports edge is the caller's, not world-owned"
    );
}
