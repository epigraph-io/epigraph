//! Operator ruling R-55 through the HTTP routes, on the APPLICATION ROLE: a
//! repo-authored refusal (`DbError::Refused`) is answered by its KIND, with
//! its own words in the body. `authority` is 403, `state` is 409, and a
//! target whose existence must not leak stays 404, byte-identical to a
//! missing one. (`input` is 400; no route reaches an input refusal past its
//! own validation, so `errors.rs` pins that arm on the rendered response.)
//!
//! Before R-55 the dedup route answered every refusal with the same fixed
//! 409 text, an authority refusal included, and the supersede route matched
//! the refusal's text and answered a state refusal 400.
//!
//! Both pools of the `AppState` are the application role, so the database's
//! row security decides what the session may write, as in
//! `own_claim_authority_http.rs`. Handlers are invoked directly with the
//! caller's `ViewerExtractor`; the `ApiError` is rendered into the HTTP
//! response the router would send.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::versioning::{
    mark_duplicate, supersede_claim, DedupRequest, SupersedeRequest,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{FrameRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
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
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

fn human(agent: Uuid, scopes: &[&str]) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

async fn claim_of(
    pool: &PgPool,
    agent: Uuid,
    group: Uuid,
    visibility: &str,
    content: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, $5, $6)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("is_current")
}

fn dedup_body(canonical: Uuid) -> Json<DedupRequest> {
    Json(DedupRequest {
        canonical_id: canonical,
        reason: None,
    })
}

async fn rendered(e: ApiError) -> (u16, serde_json::Value) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// AUTHORITY -> 403, the refusal's words in `details.reason`. The caller holds
/// `claims:admin`, which admits any readable canonical past the route's
/// per-claim rule, so the act itself decides: its duplicate is bound to
/// `binary_truth` at FALSE and cited by another claim, and the public
/// canonical (another writer's) has no binding, which only that writer may
/// give it (FA07). Nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn an_authority_refusal_is_403_with_its_reason(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "r55-http-human").await;
    let (x, xg) = seed_agent_with_group(&pool, "r55-http-x").await;
    let dup = claim_of(&pool, h, hg, "public", "the human's FALSE-bound duplicate").await;
    let canonical = claim_of(&pool, x, xg, "public", "X's unbound canonical").await;
    let citing = claim_of(&pool, x, xg, "public", "X cites the duplicate").await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports')",
    )
    .bind(Uuid::new_v4())
    .bind(citing)
    .bind(dup)
    .execute(&pool)
    .await
    .expect("seed the citing edge");
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        Some("R-55 authority fixture"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("seed frame")
    .id;
    FrameRepository::assign_claim(&pool, dup, frame, Some(1))
        .await
        .expect("bind the duplicate to FALSE");

    let e = mark_duplicate(
        ViewerExtractor(viewer(&pool, h).await),
        State(state.clone()),
        human(h, &["claims:write", "claims:admin"]),
        Path(dup),
        dedup_body(canonical),
    )
    .await
    .expect_err("the act refuses to hand the canonical a binding");
    let (status, body) = rendered(e).await;
    assert_eq!(status, 403, "an authority refusal is a denial: {body}");
    assert_eq!(body["error"], "Forbidden", "{body}");
    let reason = body["details"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("FA07") && reason.contains(&canonical.to_string()),
        "the refusal's own words reach the caller: {body}"
    );
    assert!(is_current(&pool, dup).await, "nothing was written");
}

/// STATE -> 409, the refusal's words in `details.reason`: superseding a claim
/// that is already retired. The claim is the caller's own, so the route's
/// authority check admits it and the act's state check is what refuses.
#[sqlx::test(migrations = "../../migrations")]
async fn a_state_refusal_is_409_with_its_reason(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "r55-http-author").await;
    let old = claim_of(&pool, h, hg, "public", "the author's retired claim").await;
    sqlx::query(
        "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
          WHERE id = $1",
    )
    .bind(old)
    .execute(&pool)
    .await
    .expect("retire the claim");

    let e = supersede_claim(
        ViewerExtractor(viewer(&pool, h).await),
        State(state.clone()),
        human(h, &["claims:write"]),
        Path(old),
        Json(SupersedeRequest {
            content: format!("a correction of {old}"),
            truth_value: 0.6,
            reason: "R-55 state refusal".to_string(),
        }),
    )
    .await
    .expect_err("a retired claim cannot be superseded again");
    let (status, body) = rendered(e).await;
    assert_eq!(status, 409, "a state refusal is a conflict: {body}");
    assert_eq!(body["error"], "Conflict", "{body}");
    let reason = body["details"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("already been superseded") && reason.contains(&old.to_string()),
        "the refusal's own words reach the caller: {body}"
    );
    let successors: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE supersedes = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .expect("successors");
    assert_eq!(successors, 0, "nothing was written");
}

/// The existence-sensitive answer is unchanged: a canonical the caller cannot
/// READ is 404, byte-identical (ids replaced) to a canonical that does not
/// exist, even with `claims:admin`, and never one of the kinds' 403/409 that
/// would confirm it exists.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hidden_canonical_stays_404_like_a_missing_one(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "r55-http-human").await;
    let (x, xg) = seed_agent_with_group(&pool, "r55-http-x").await;
    let dup = claim_of(&pool, h, hg, "public", "the human's duplicate").await;
    let hidden = claim_of(&pool, x, xg, "group", "X's private canonical").await;
    let missing = Uuid::new_v4();

    let mut answers = Vec::new();
    for target in [hidden, missing] {
        let e = mark_duplicate(
            ViewerExtractor(viewer(&pool, h).await),
            State(state.clone()),
            human(h, &["claims:write", "claims:admin"]),
            Path(dup),
            dedup_body(target),
        )
        .await
        .expect_err("an unreadable canonical is refused");
        let (status, body) = rendered(e).await;
        answers.push((
            status,
            body.to_string().replace(&target.to_string(), "<id>"),
        ));
    }
    assert_eq!(answers[0], answers[1], "hidden and missing answer alike");
    assert_eq!(answers[0].0, 404, "{}", answers[0].1);
    assert!(is_current(&pool, dup).await, "nothing was written");
}
