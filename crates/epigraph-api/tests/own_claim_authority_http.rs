//! Batch OA1 (operator decision D1) through the HTTP routes, on the
//! APPLICATION ROLE: `POST /api/v1/claims/:id/supersede` and
//! `POST /api/v1/claims/:id/dedup` at `claims:write` plus the per-claim rule
//! (`epigraph_auth::claim_act`).
//!
//! Before OA1 the dedup route demanded `claims:admin`, and the supersede route
//! admitted only a token whose owner WAS the claim's author. Now either act is
//! open to the claim's author and to a writer of its owning group, and
//! `claims:admin` remains the arm for any claim the caller can read. A claim the
//! caller cannot read is 404, exactly like a missing one; a readable claim it
//! may not retire is `403 not_owner` with `rule = "not_claim_writer"`.
//!
//! Both pools of the `AppState` are the application role (the stamped
//! `ScopedPool` and the raw `db_pool`), so the database's own row security
//! decides the write. Handlers are invoked directly, with the caller's
//! `ViewerExtractor`, as `writer_owned_edges_http.rs` does.

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
use epigraph_db::{ScopedPool, SessionGucMode};
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

/// A human's token: its graph agent is `agent`; its login principal
/// (`owner_id`) is NOT that agent, so the pre-OA1 token-owner rule is not what
/// admits it.
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

async fn edge_between(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    let e = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports')",
    )
    .bind(e)
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("seed edge");
    e
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("is_current")
}

async fn edge_target(pool: &PgPool, edge: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge")
}

async fn deferral_agent(
    pool: &PgPool,
    cascade: &epigraph_engine::admin_cascade::CascadeStatus,
) -> Option<Uuid> {
    let v = serde_json::to_value(cascade).expect("cascade");
    assert_eq!(v["status"], "deferred", "{v}");
    let id = cascade.audit_event_id.expect("the deferral's audit row");
    let (et, who): (String, Option<Uuid>) =
        sqlx::query_as("SELECT event_type::text, agent_id FROM security_events WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("the deferral row");
    assert_eq!(et, "cascade.deferred");
    who
}

async fn replay_now(pool: &PgPool, label: &str) -> epigraph_engine::admin_cascade::ReplayReport {
    let url = database_url_for(pool).await;
    let maintenance = downgraded_pool(pool, "epigraph_maintenance").await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("ScopedPool")
            .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, admin_viewer) = session.split();
    epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        label,
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay")
}

fn supersede_body(claim: Uuid) -> Json<SupersedeRequest> {
    Json(SupersedeRequest {
        content: format!("a correction of {claim}"),
        truth_value: 0.6,
        reason: "oa1 http test".to_string(),
    })
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

async fn assert_not_claim_writer(e: ApiError, claim: Uuid) {
    let (status, body) = rendered(e).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "not_owner", "{body}");
    assert_eq!(body["rule"], "not_claim_writer", "{body}");
    assert_eq!(body["claim_id"], claim.to_string(), "{body}");
    assert_eq!(body["retryable"], false, "{body}");
}

/// A hidden claim's answer and a random id's, each id replaced by a
/// placeholder, must be byte-identical.
async fn assert_same_as_missing(
    hidden: ApiError,
    hidden_id: Uuid,
    missing: ApiError,
    missing_id: Uuid,
) {
    let (hs, hb) = rendered(hidden).await;
    let (ms, mb) = rendered(missing).await;
    let h = hb.to_string().replace(&hidden_id.to_string(), "<id>");
    let m = mb.to_string().replace(&missing_id.to_string(), "<id>");
    assert_eq!((hs, &h), (ms, &m));
    assert_eq!(hs, 404, "{h}");
}

/// The author supersedes and dedups its own claims with `claims:write` alone;
/// each act is stamped with the author's own authority (the deferral row names
/// it), and the replay applies each cascade.
#[sqlx::test(migrations = "../../migrations")]
async fn the_author_supersedes_and_dedups_its_own_claims_over_http(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "oa1-http-human").await;
    let (x, xg) = seed_agent_with_group(&pool, "oa1-http-x").await;
    let old = claim_of(&pool, h, hg, "group", "the human's private claim").await;
    let dup = claim_of(&pool, h, hg, "public", "the human's duplicate").await;
    // A canonical the author writes: at claims:write the canonical is a target
    // claim too (see `a_canonical_the_caller_cannot_write_is_refused_by_name`).
    let canonical = claim_of(&pool, h, hg, "public", "the human's canonical").await;
    let xc = claim_of(&pool, x, xg, "public", "X cites the duplicate").await;
    let incoming = edge_between(&pool, xc, dup).await;

    let (status, Json(resp)) = supersede_claim(
        ViewerExtractor(viewer(&pool, h).await),
        State(state.clone()),
        human(h, &["claims:write"]),
        Path(old),
        supersede_body(old),
    )
    .await
    .expect("the author's supersede lands at claims:write");
    assert_eq!(status.as_u16(), 201);
    assert!(!is_current(&pool, old).await);
    assert_eq!(deferral_agent(&pool, &resp.cascade).await, Some(h));

    let Json(resp) = mark_duplicate(
        ViewerExtractor(viewer(&pool, h).await),
        State(state.clone()),
        human(h, &["claims:write"]),
        Path(dup),
        dedup_body(canonical),
    )
    .await
    .expect("the author's dedup lands at claims:write");
    assert!(!is_current(&pool, dup).await);
    assert_eq!(deferral_agent(&pool, &resp.cascade).await, Some(h));
    assert_eq!(edge_target(&pool, incoming).await, dup, "deferred");

    let report = replay_now(&pool, "oa1-http").await;
    assert_eq!((report.applied, report.failed), (2, 0), "{report:?}");
    assert_eq!(
        edge_target(&pool, incoming).await,
        canonical,
        "the replay re-pointed another writer's edge onto the canonical"
    );
}

/// A `writer` of the owning group, who did not author the claim, may supersede
/// it over HTTP; a `reader` of the same group is refused by name.
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_of_the_owning_group_may_supersede_over_http(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "oa1-http-human").await;
    let (w, _) = seed_agent_with_group(&pool, "oa1-http-writer").await;
    let (rd, _) = seed_agent_with_group(&pool, "oa1-http-reader").await;
    add_member(&pool, hg, w, "writer").await;
    add_member(&pool, hg, rd, "reader").await;
    let c = claim_of(&pool, h, hg, "group", "the group's claim").await;

    let err = supersede_claim(
        ViewerExtractor(viewer(&pool, rd).await),
        State(state.clone()),
        human(rd, &["claims:write"]),
        Path(c),
        supersede_body(c),
    )
    .await
    .expect_err("a reader is refused");
    assert_not_claim_writer(err, c).await;
    assert!(is_current(&pool, c).await);

    let (_, Json(resp)) = supersede_claim(
        ViewerExtractor(viewer(&pool, w).await),
        State(state.clone()),
        human(w, &["claims:write"]),
        Path(c),
        supersede_body(c),
    )
    .await
    .expect("a writer of the owning group supersedes");
    assert!(!is_current(&pool, c).await);
    assert_eq!(deferral_agent(&pool, &resp.cascade).await, Some(w));
}

/// Authorship is not write authority, over HTTP as over MCP: the author of a
/// claim in a group whose `writer` membership it has lost is refused BY NAME on
/// both routes (before OA1's shared rule it reached the database, whose row
/// security refused it with a generic 403), and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn an_author_who_no_longer_writes_the_owning_group_is_refused_by_name(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (_, og) = seed_agent_with_group(&pool, "oa1-http-owner").await;
    let (h, hg) = seed_agent_with_group(&pool, "oa1-http-revoked-author").await;
    add_member(&pool, og, h, "writer").await;
    let c = claim_of(&pool, h, og, "public", "written while a member").await;
    let mine = claim_of(&pool, h, hg, "public", "the author's own claim").await;
    let n = sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(og)
    .bind(h)
    .execute(&pool)
    .await
    .expect("revoke")
    .rows_affected();
    assert_eq!(n, 1);

    let e = supersede_claim(
        ViewerExtractor(viewer(&pool, h).await),
        State(state.clone()),
        human(h, &["claims:write"]),
        Path(c),
        supersede_body(c),
    )
    .await
    .expect_err("a revoked author may not supersede");
    assert_not_claim_writer(e, c).await;

    let e = mark_duplicate(
        ViewerExtractor(viewer(&pool, h).await),
        State(state.clone()),
        human(h, &["claims:write"]),
        Path(c),
        dedup_body(mine),
    )
    .await
    .expect_err("a revoked author may not mark a duplicate");
    assert_not_claim_writer(e, c).await;

    assert!(is_current(&pool, c).await, "nothing was written");
    assert!(is_current(&pool, mine).await, "nothing was written");
}

/// The dedup's canonical needs write authority too at `claims:write`: a
/// readable public canonical in another writer's group is `403 not_owner`
/// naming the CANONICAL, with nothing written; `claims:admin` admits it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_canonical_the_caller_cannot_write_is_refused_by_name(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "oa1-http-human").await;
    let (x, xg) = seed_agent_with_group(&pool, "oa1-http-x").await;
    let dup = claim_of(&pool, h, hg, "public", "the human's duplicate").await;
    let theirs = claim_of(&pool, x, xg, "public", "X's attractive canonical").await;

    let e = mark_duplicate(
        ViewerExtractor(viewer(&pool, h).await),
        State(state.clone()),
        human(h, &["claims:write"]),
        Path(dup),
        dedup_body(theirs),
    )
    .await
    .expect_err("a canonical the caller cannot write is refused");
    assert_not_claim_writer(e, theirs).await;
    assert!(is_current(&pool, dup).await, "nothing was written");

    let Json(resp) = mark_duplicate(
        ViewerExtractor(viewer(&pool, h).await),
        State(state.clone()),
        human(h, &["claims:write", "claims:admin"]),
        Path(dup),
        dedup_body(theirs),
    )
    .await
    .expect("claims:admin admits any readable canonical");
    assert!(!is_current(&pool, dup).await);
    assert_eq!(deferral_agent(&pool, &resp.cascade).await, Some(h));
}

/// A bystander with `claims:write`: `403 not_owner` on a claim it can read (on
/// both routes, nothing written); on a claim it cannot read, byte-for-byte the
/// 404 a random id gets (the supersede target, the duplicate, the canonical).
#[sqlx::test(migrations = "../../migrations")]
async fn a_bystander_is_refused_by_name_and_learns_nothing_of_a_hidden_claim(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "oa1-http-human").await;
    let (b, bg) = seed_agent_with_group(&pool, "oa1-http-bystander").await;
    let public = claim_of(&pool, h, hg, "public", "the human's public claim").await;
    let hidden = claim_of(&pool, h, hg, "group", "the human's private claim").await;
    let mine = claim_of(&pool, b, bg, "public", "the bystander's own claim").await;
    let random = Uuid::new_v4();
    let tok = || human(b, &["claims:read", "claims:write"]);
    let st = || State(state.clone());
    let bv = || async { ViewerExtractor(viewer(&pool, b).await) };

    let e = supersede_claim(
        bv().await,
        st(),
        tok(),
        Path(public),
        supersede_body(public),
    )
    .await
    .expect_err("refused");
    assert_not_claim_writer(e, public).await;
    let e = mark_duplicate(bv().await, st(), tok(), Path(public), dedup_body(mine))
        .await
        .expect_err("refused");
    assert_not_claim_writer(e, public).await;

    let eh = supersede_claim(
        bv().await,
        st(),
        tok(),
        Path(hidden),
        supersede_body(hidden),
    )
    .await
    .expect_err("hidden");
    let er = supersede_claim(
        bv().await,
        st(),
        tok(),
        Path(random),
        supersede_body(random),
    )
    .await
    .expect_err("random");
    assert_same_as_missing(eh, hidden, er, random).await;

    let eh = mark_duplicate(bv().await, st(), tok(), Path(hidden), dedup_body(mine))
        .await
        .expect_err("hidden duplicate");
    let er = mark_duplicate(bv().await, st(), tok(), Path(random), dedup_body(mine))
        .await
        .expect_err("random duplicate");
    assert_same_as_missing(eh, hidden, er, random).await;

    let eh = mark_duplicate(bv().await, st(), tok(), Path(mine), dedup_body(hidden))
        .await
        .expect_err("hidden canonical");
    let er = mark_duplicate(bv().await, st(), tok(), Path(mine), dedup_body(random))
        .await
        .expect_err("random canonical");
    assert_same_as_missing(eh, hidden, er, random).await;

    for c in [public, hidden, mine] {
        assert!(is_current(&pool, c).await, "nothing was written");
    }
}

/// `claims:admin` passes the per-claim rule for a claim the caller neither
/// wrote nor writes, where `claims:write` alone is refused by name. What
/// happens next is the database's decision: the HTTP act runs on the CALLER's
/// stamp, and on the application role that stamp cannot write the claim's
/// group, so the write is refused (`403`, but the generic write refusal, not
/// `not_owner`) with nothing written. That residual predates OA1.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_admin_passes_the_rule_and_the_database_still_decides(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "oa1-http-human").await;
    let (a, _) = seed_agent_with_group(&pool, "oa1-http-admin").await;
    let c = claim_of(&pool, h, hg, "public", "the human's public claim").await;

    let e = supersede_claim(
        ViewerExtractor(viewer(&pool, a).await),
        State(state.clone()),
        human(a, &["claims:write"]),
        Path(c),
        supersede_body(c),
    )
    .await
    .expect_err("claims:write alone is refused");
    assert_not_claim_writer(e, c).await;

    let e = supersede_claim(
        ViewerExtractor(viewer(&pool, a).await),
        State(state.clone()),
        human(a, &["claims:write", "claims:admin"]),
        Path(c),
        supersede_body(c),
    )
    .await
    .expect_err("the database refuses a row the admin's stamp cannot write");
    let (status, body) = rendered(e).await;
    assert_eq!(status, 403, "{body}");
    assert_ne!(
        body["error"], "not_owner",
        "claims:admin passed the per-claim rule; the refusal is the database's: {body}"
    );
    assert!(is_current(&pool, c).await, "nothing was written");
}
