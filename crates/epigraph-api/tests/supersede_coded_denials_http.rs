#![cfg(feature = "db")]
//! K5 (supersede SPEC §11 phase 1; backlog 09c2f9d0 part 3, 80be64b5), HTTP
//! twin of `epigraph-mcp/tests/supersede_coded_denials.rs`: a refused
//! `POST /api/v1/claims/:id/supersede` answers a CODED 403, with nothing
//! written, on the APPLICATION ROLE.
//!
//! Before K5 the route's act mapper knew only row security's `42501`,
//! `WriteRefused`, `Refused` and "not found":
//!
//! * the operator binding's OPL01 / OPL02 (migration 122, armed) fell to a
//!   500, although `From<DbError> for ApiError` maps both to 403;
//! * migration 120's CX03 (SQLSTATE 42501), raised by the act's cascade
//!   deferral, was a 500 from the deferral helper, and through the act mapper
//!   it would have read as the generic group-write 403 with its code dropped.
//!
//! The route's 42501 arm already answers a row-security refusal of the act
//! with 403 "no write authority over the group that owns this claim": that is
//! pinned here, end to end, as the realistic refusal (addendum c2).
//!
//! CX03 is not reached by a supersede on a clean schema at head, so its
//! mapping is pinned on a REAL CX03 that the deferral definer raises for a
//! supersession that never happened, through the mapper and through the
//! deferral path the route uses. No test here installs a policy.

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
    supersede_claim, supersede_refusal, supersede_session_or_deferral, SupersedeRequest,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_engine::admin_cascade::{CascadeCause, CascadeTrigger};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group};

/// `write_refused("claim")`'s words: the group-write denial both transports
/// give a stamp that does not write the claim's group.
const GROUP_WRITE_REFUSED: &str = "no write authority over the group that owns this claim";

async fn app_scoped(pool: &PgPool) -> ScopedPool {
    let url = database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// Both pools are `epigraph_app`; no maintenance connection, so an act defers
/// its cascade in its own transaction.
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
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(app_scoped(pool).await);
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

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
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

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("live link");
}

async fn arm(pool: &PgPool) {
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("is_current")
}

async fn successors(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE supersedes = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("successors")
}

async fn deferrals(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type = 'cascade.deferred'")
        .fetch_one(pool)
        .await
        .expect("count deferrals")
}

async fn assert_nothing_written(pool: &PgPool, claim: Uuid, what: &str) {
    assert!(is_current(pool, claim).await, "{what}: nothing retired");
    assert_eq!(successors(pool, claim).await, 0, "{what}: no successor");
    assert_eq!(deferrals(pool).await, 0, "{what}: no cascade deferral");
}

/// The status and the body's `reason`.
async fn rendered(e: ApiError) -> (u16, String) {
    let resp = e.into_response();
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    let reason = body["details"]["reason"]
        .as_str()
        .or_else(|| body["reason"].as_str())
        .or_else(|| body["message"].as_str())
        .map_or_else(|| body.to_string(), str::to_string);
    (status, reason)
}

async fn http_supersede(
    pool: &PgPool,
    state: &AppState,
    caller: Uuid,
    scopes: &[&str],
    claim: Uuid,
) -> Result<Uuid, ApiError> {
    supersede_claim(
        ViewerExtractor(viewer(pool, caller).await),
        State(state.clone()),
        human(caller, scopes),
        Path(claim),
        Json(SupersedeRequest {
            content: format!("a correction of {claim}"),
            truth_value: 0.6,
            reason: "k5 coded denial".to_string(),
        }),
    )
    .await
    .map(|(_, Json(resp))| resp.new_claim_id)
}

/// K5 / addendum (c1): CX03 (SQLSTATE 42501, message `CX03: ...`) answers 403
/// with the code and the claim in the reason, through the mapper and through
/// the deferral path the route uses. Red before K5: the mapper read it as the
/// generic 42501 group-write 403 (code dropped), and the deferral path
/// answered 500.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cx03_from_the_supersede_deferral_is_a_coded_403(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (h, hg) = seed_agent_with_group(&pool, "k5-http-cx03-author").await;
    let c = claim_of(&pool, h, hg, "a claim that was never superseded").await;
    let hv = viewer(&pool, h).await;
    let scoped = app_scoped(&pool).await;
    let trigger = CascadeTrigger::new(
        CascadeCause::Supersede,
        Some(h),
        None,
        c,
        Some(Uuid::new_v4()),
    );

    let raw = {
        let mut tx = scoped.begin_as(&hv).await.expect("stamped tx");
        epigraph_engine::admin_cascade::record_deferral(&mut *tx, &trigger, "k5 test")
            .await
            .expect_err("a deferral for a supersession that never happened is refused")
    };
    match &raw {
        epigraph_db::DbError::QueryFailed {
            source: sqlx::Error::Database(d),
        } => {
            assert_eq!(d.code().as_deref(), Some("42501"), "calibration: {raw:?}");
            assert!(d.message().starts_with("CX03:"), "calibration: {raw:?}");
        }
        other => panic!("calibration: CX03 arrives as a database error: {other:?}"),
    }

    let (status, reason) = rendered(supersede_refusal(c, raw)).await;
    assert_eq!(status, 403, "{reason}");
    assert!(
        reason.starts_with("CX03:")
            && reason.contains(&c.to_string())
            && reason.contains("does not write the group")
            && reason.contains("nothing was written"),
        "the denial carries the code, the claim and what it means: {reason}"
    );

    let mut tx = scoped.begin_as(&hv).await.expect("stamped tx");
    let via_path = match supersede_session_or_deferral(&state, &mut tx, &trigger).await {
        Ok(_) => panic!("the phantom supersede's deferral must be refused"),
        Err(e) => e,
    };
    drop(tx);
    let (path_status, path_reason) = rendered(via_path).await;
    assert_eq!(
        (path_status, path_reason.as_str()),
        (status, reason.as_str()),
        "the deferral path answers exactly what the mapper answers"
    );
    assert_eq!(deferrals(&pool).await, 0, "no deferral was recorded");
}

struct Armed {
    state: AppState,
    a: Uuid,
    ag: Uuid,
    x_claim: Uuid,
}

async fn armed(pool: &PgPool, label: &str) -> Armed {
    let state = app_role_state(pool).await;
    let (a, ag) = viewer_fixture::seed_human_operator(pool, &format!("{label}-human-a")).await;
    let (x, _) = seed_agent_with_group(pool, &format!("{label}-a-agent-x")).await;
    link(pool, x, a).await;
    let x_claim = claim_of(pool, x, ag, "X's claim").await;
    Armed {
        state,
        a,
        ag,
        x_claim,
    }
}

/// K5, OPL01: an unbound writer's supersede, armed, is 403 naming OPL01 with
/// nothing written. Red before K5: 500. CONTROL: once linked, it lands.
#[sqlx::test(migrations = "../../migrations")]
async fn an_opl01_supersede_is_a_coded_403(pool: PgPool) {
    let s = armed(&pool, "k5-http-opl01").await;
    let (u, _) = seed_agent_with_group(&pool, "k5-http-opl01-unbound-u").await;
    add_member(&pool, s.ag, u, "writer").await;
    arm(&pool).await;

    let e = http_supersede(&pool, &s.state, u, &["claims:write"], s.x_claim)
        .await
        .expect_err("an unbound caller may not supersede once armed");
    let (status, reason) = rendered(e).await;
    assert_eq!(status, 403, "{reason}");
    assert!(reason.contains("OPL01"), "the code is named: {reason}");
    assert_nothing_written(&pool, s.x_claim, "OPL01").await;

    link(&pool, u, s.a).await;
    http_supersede(&pool, &s.state, u, &["claims:write"], s.x_claim)
        .await
        .unwrap_or_else(|e| panic!("CONTROL: U, now bound to A, supersedes: {e:?}"));
    assert!(!is_current(&pool, s.x_claim).await, "CONTROL: it landed");
}

/// K5, OPL02: a bound writer whose human does not write the group, armed, is
/// 403 naming OPL02 with nothing written. Red before K5: 500. CONTROL: once
/// its human writes the group, it lands.
#[sqlx::test(migrations = "../../migrations")]
async fn an_opl02_supersede_is_a_coded_403(pool: PgPool) {
    let s = armed(&pool, "k5-http-opl02").await;
    let (c_human, _) = viewer_fixture::seed_human_operator(&pool, "k5-http-opl02-human-c").await;
    let (z, _) = seed_agent_with_group(&pool, "k5-http-opl02-c-agent-z").await;
    link(&pool, z, c_human).await;
    add_member(&pool, s.ag, z, "writer").await;
    arm(&pool).await;

    let e = http_supersede(&pool, &s.state, z, &["claims:write"], s.x_claim)
        .await
        .expect_err("an agent whose human does not write the group may not supersede");
    let (status, reason) = rendered(e).await;
    assert_eq!(status, 403, "{reason}");
    assert!(reason.contains("OPL02"), "the code is named: {reason}");
    assert!(
        !reason.contains("OPL01"),
        "calibration: Z is bound: {reason}"
    );
    assert_nothing_written(&pool, s.x_claim, "OPL02").await;

    add_member(&pool, s.ag, c_human, "writer").await;
    http_supersede(&pool, &s.state, z, &["claims:write"], s.x_claim)
        .await
        .unwrap_or_else(|e| panic!("CONTROL: C now writes the group: {e:?}"));
    assert!(!is_current(&pool, s.x_claim).await, "CONTROL: it landed");
}

/// K5 / addendum (c2) on HTTP: a `claims:admin` caller that does not write a
/// PUBLIC claim's owner group passes the per-claim rule, and the act (on the
/// caller's own stamp; HTTP never borrows) is refused by row security: 403
/// with the group-write denial, nothing written, no deferral, and not CX03.
/// Already the answer before K5 (addendum d: the route's 42501 arm); a pin,
/// not a red test.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claims_admin_outside_the_owner_group_is_the_named_group_write_denial(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (x, xg) = seed_agent_with_group(&pool, "k5-http-admin-author-x").await;
    let (admin, _) = seed_agent_with_group(&pool, "k5-http-admin").await;
    let c = claim_of(&pool, x, xg, "X's public claim").await;

    let e = http_supersede(&pool, &state, admin, &["claims:write", "claims:admin"], c)
        .await
        .expect_err("the caller's stamp cannot write X's group");
    let (status, reason) = rendered(e).await;
    assert_eq!(status, 403, "{reason}");
    assert!(
        reason.contains(GROUP_WRITE_REFUSED) && reason.contains("nothing was written"),
        "{reason}"
    );
    assert!(!reason.contains("CX03"), "{reason}");
    assert_nothing_written(&pool, c, "claims:admin").await;
}
