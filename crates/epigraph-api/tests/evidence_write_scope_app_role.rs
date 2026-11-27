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
//!   SUCCEEDED and the rows took no caller ownership.
//!
//! `learn_convention` (backlog 1c822492) also wrote its convention CLAIM on the
//! raw pool, authored by a zero-key system agent: on the application role that
//! INSERT was refused by `claims_tenancy`'s `WITH CHECK` (a 500), and on a
//! privileged raw pool the claim was owned by the system agent's group. A
//! convention is now authored by its `claims:admin` caller and owned by the
//! caller's home group, and every row of the request (claim, labels, evidence,
//! trace, edges) is one write on the caller's stamped transaction. Its arms run
//! on both shapes, and a caller without `claims:admin` is refused with nothing
//! written.
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

/// `(relationship, source_type, target_type)` of every edge touching `claim`
/// with no evidence endpoint (the convention's structural AUTHORED / TRACES /
/// HAS_TRACE edges), sorted.
async fn structural_edges_of(pool: &PgPool, claim: Uuid) -> Vec<(String, String, String)> {
    let mut rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT relationship, source_type, target_type FROM edges \
          WHERE (source_id = $1 OR target_id = $1) \
            AND source_type <> 'evidence' AND target_type <> 'evidence'",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("structural edges");
    rows.sort();
    rows
}

fn convention_request(content: &str) -> Json<LearnConventionRequest> {
    Json(
        serde_json::from_value(serde_json::json!({
            "content": content,
            "evidence": "seen in three reviews",
            "tags": ["rust-style"],
        }))
        .expect("request"),
    )
}

/// A `claims:admin` caller learns a convention. The claim, its labels, its
/// evidence and `supports` edge, its trace and its structural edges are ONE
/// write on the caller's stamped transaction: the claim is authored by the
/// caller and owned by the caller's home group (public), and the evidence and
/// its edge are the caller's too.
async fn assert_learn_convention_is_the_callers(pool: PgPool, state: AppState, label: &str) {
    let (admin, admin_group) = seed_agent_with_group(&pool, &format!("{label}-admin")).await;
    let content = format!("1c822492 {label} convention {}", Uuid::new_v4());

    let (status, Json(created)) = learn_convention(
        viewer(&pool, admin).await,
        State(state),
        auth(admin, "claims:admin"),
        convention_request(&content),
    )
    .await
    .unwrap_or_else(|e| panic!("{label}: the convention is learned: {e:?}"));
    assert_eq!(status.as_u16(), 201, "{label}");

    let (visibility, claim_group, author, has_trace, labels): (
        String,
        Uuid,
        Uuid,
        bool,
        Vec<String>,
    ) = sqlx::query_as(
        "SELECT visibility::text, owner_group_id, agent_id, trace_id IS NOT NULL, labels \
           FROM claims WHERE id = $1",
    )
    .bind(created.claim_id)
    .fetch_one(&pool)
    .await
    .expect("the convention claim");
    assert_eq!(
        (visibility.as_str(), claim_group, author),
        ("public", admin_group, admin),
        "{label}: the convention is public, authored by the caller and owned by its home group"
    );
    assert!(has_trace, "{label}: the claim carries its reasoning trace");
    for want in ["convention", "learned", "rust-style"] {
        assert!(
            labels.iter().any(|l| l == want),
            "{label}: label {want} stored: {labels:?}"
        );
    }

    let rows = evidence_on(&pool, created.claim_id).await;
    assert_eq!(rows.len(), 1, "{label}: {rows:?}");
    let (evidence, owner, _) = rows[0];
    assert_eq!(owner, admin_group, "{label}: the evidence is the caller's");
    assert_eq!(
        edges_between(&pool, evidence, created.claim_id).await,
        vec![("supports".to_string(), admin_group)],
        "{label}: the supports edge is the caller's, not world-owned ({})",
        world_group(&pool).await
    );
    assert_eq!(
        structural_edges_of(&pool, created.claim_id).await,
        vec![
            (
                "AUTHORED".to_string(),
                "agent".to_string(),
                "claim".to_string()
            ),
            (
                "HAS_TRACE".to_string(),
                "claim".to_string(),
                "trace".to_string()
            ),
            (
                "TRACES".to_string(),
                "trace".to_string(),
                "claim".to_string()
            ),
        ],
        "{label}: the structural edges are written with the claim"
    );
    let authored_by: Uuid = sqlx::query_scalar(
        "SELECT source_id FROM edges WHERE target_id = $1 AND relationship = 'AUTHORED'",
    )
    .bind(created.claim_id)
    .fetch_one(&pool)
    .await
    .expect("AUTHORED edge");
    assert_eq!(
        authored_by, admin,
        "{label}: the caller authored the convention"
    );
}

/// Both pools on the application role: the production shape, where the
/// unstamped claim INSERT was refused by `claims_tenancy`'s `WITH CHECK` (a
/// 500) before the handler reached its evidence.
#[sqlx::test(migrations = "../../migrations")]
async fn learn_convention_on_the_app_role_is_owned_by_the_callers_home_group(pool: PgPool) {
    let state = app_role_state(&pool).await;
    assert_learn_convention_is_the_callers(pool, state, "app-role").await;
}

/// A privileged raw pool: the shape in which the unstamped claim write
/// succeeded, authored by a zero-key system agent and owned by that agent's
/// group rather than the caller's.
#[sqlx::test(migrations = "../../migrations")]
async fn learn_convention_on_a_privileged_raw_pool_is_owned_by_the_callers_home_group(
    pool: PgPool,
) {
    let state = privileged_raw_state(&pool).await;
    assert_learn_convention_is_the_callers(pool, state, "privileged-raw").await;
}

/// A caller without `claims:admin` is refused (403) and nothing is written:
/// no claim with the content, no evidence, no agent minted for the request.
#[sqlx::test(migrations = "../../migrations")]
async fn learn_convention_without_claims_admin_is_refused_and_writes_nothing(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (writer, _) = seed_agent_with_group(&pool, "convention-writer").await;
    let content = format!("1c822492 refused convention {}", Uuid::new_v4());
    let agents_before: i64 = sqlx::query_scalar("SELECT count(*) FROM agents")
        .fetch_one(&pool)
        .await
        .expect("agents");

    let res = learn_convention(
        viewer(&pool, writer).await,
        State(state),
        auth(writer, "claims:write"),
        convention_request(&content),
    )
    .await;
    let (status, _) = rendered(res, Uuid::nil()).await;
    assert_eq!(
        status, 403,
        "a claims:write caller may not learn a convention"
    );

    let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(&content)
        .fetch_one(&pool)
        .await
        .expect("claims");
    let evidence: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM evidence WHERE raw_content = 'seen in three reviews'",
    )
    .fetch_one(&pool)
    .await
    .expect("evidence");
    let agents_after: i64 = sqlx::query_scalar("SELECT count(*) FROM agents")
        .fetch_one(&pool)
        .await
        .expect("agents");
    assert_eq!(
        (claims, evidence, agents_after),
        (0, 0, agents_before),
        "nothing written"
    );
}
