//! `GET /api/v1/audit/security`, and the security-event half of
//! `GET /api/v1/agents/:id/timeline`, read a caller's own security events, and
//! an instance administrator's view of everyone's, on a viewer-stamped
//! connection.
//!
//! Deferred-commitment screen key `f-pr18a-b1-audit-scoped-read`
//! (`docs/tenancy/progress.json`, finding `F-PR18a-B1`). Before the fix,
//! `routes/audit.rs::query_security_events` called
//! `SecurityEventRepository::query(&state.db_pool, filter)`. It checked
//! `audit:read`, which every role carries, and it passed a caller-supplied
//! `?agent_id=` straight through. The only per-principal narrowing was
//! migration 083's `security_events_read` policy.
//!
//! `routes/timeline.rs::get_agent_timeline` read the same table through the same
//! function, with the path's `:id` as its only filter and no scope check at all.
//! It was found while re-deriving the finding and is covered by the
//! `the_timeline_*` arms below.
//!
//! # The instrument
//!
//! Every arm calls the handler directly, the way the conversion-shard files
//! do, with an `AppState` whose two pools differ:
//!
//! * `state.scoped` is an ordinary `ScopedPool`: stamped, and a SUPERUSER
//!   session, so RLS filters nothing on it. Whatever narrowing the handler's
//!   read shows, the in-query conjunct did it, not the policy.
//! * `state.db_pool` is downgraded to an unstamped `epigraph_app` session. A
//!   handler that went back to `&state.db_pool` would lose the caller's OWN
//!   rows there, because the policy has no principal to admit them by.
//!
//! So a read that is too wide fails the stranger-row assertions, and a read
//! that moved back to the raw pool fails the own-row assertions. Both are
//! checked by id.

mod viewer_fixture;

use std::collections::BTreeSet;

use axum::extract::{Path, Query, State};
use axum::Extension;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::audit::{query_security_events, SecurityEventQuery};
use epigraph_api::routes::timeline::get_agent_timeline;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::repos::instance_admin::InstanceAdminRepository;
use epigraph_db::repos::security_event::{SecurityEventRepository, SecurityEventRow};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{downgraded_pool, scoped_pool, seed_agent_with_group};

struct Seeded {
    a: Uuid,
    b: Uuid,
    admin: Uuid,
    a_rows: BTreeSet<Uuid>,
    b_row: Uuid,
    admin_row: Uuid,
    unattributed_row: Uuid,
}

impl Seeded {
    fn all(&self) -> BTreeSet<Uuid> {
        let mut all = self.a_rows.clone();
        all.extend([self.b_row, self.admin_row, self.unattributed_row]);
        all
    }
}

async fn log(pool: &PgPool, agent: Option<Uuid>) -> Uuid {
    let row = SecurityEventRow {
        id: Uuid::new_v4(),
        event_type: "auth_attempt".to_string(),
        agent_id: agent,
        success: Some(false),
        details: serde_json::json!({ "probe": "f-pr18a-b1-http" }),
        ip_address: Some("198.51.100.4".to_string()),
        user_agent: None,
        correlation_id: Some(Uuid::new_v4().to_string()),
        created_at: chrono::Utc::now(),
    };
    let id = row.id;
    SecurityEventRepository::log(pool, row)
        .await
        .expect("seed security event");
    id
}

async fn seed(pool: &PgPool) -> Seeded {
    let (a, _) = seed_agent_with_group(pool, "audit-a").await;
    let (b, _) = seed_agent_with_group(pool, "audit-b").await;
    let (admin, _) = seed_agent_with_group(pool, "audit-admin").await;
    InstanceAdminRepository::grant(pool, admin, None, Some("audit-security-scoped-read"))
        .await
        .expect("grant instance admin");

    let a_rows = [log(pool, Some(a)).await, log(pool, Some(a)).await]
        .into_iter()
        .collect();
    Seeded {
        a,
        b,
        admin,
        a_rows,
        b_row: log(pool, Some(b)).await,
        admin_row: log(pool, Some(admin)).await,
        unattributed_row: log(pool, None).await,
    }
}

/// `scoped` stamped-but-superuser, `db_pool` filtered-but-unstamped. See the
/// module doc.
async fn split_state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(
        downgraded_pool(pool, "epigraph_app").await,
        ApiConfig::default(),
    );
    state.scoped = Some(scoped_pool(pool).await);

    let raw_is_privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&state.db_pool)
    .await
    .expect("raw pool role");
    assert!(
        !raw_is_privileged,
        "CALIBRATION: db_pool must be a role RLS filters, or a handler that went back \
         to it would not lose any rows and the own-row arms would prove nothing"
    );
    let scoped_is_privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(state.scoped.as_ref().expect("scoped").inner())
    .await
    .expect("scoped pool role");
    assert!(
        scoped_is_privileged,
        "CALIBRATION: the scoped pool must be a session RLS does not filter, so any \
         narrowing observed is the in-query conjunct's"
    );
    state
}

fn auth(agent: Uuid, scopes: &[&str]) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type: ClientType::Agent,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
    }
}

fn query(agent_id: Option<Uuid>) -> SecurityEventQuery {
    SecurityEventQuery {
        agent_id,
        event_type: None,
        since: None,
        until: None,
        failures_only: None,
        limit: None,
    }
}

async fn call(
    state: &AppState,
    pool: &PgPool,
    caller: Uuid,
    scopes: &[&str],
    agent_id: Option<Uuid>,
) -> Result<BTreeSet<Uuid>, ApiError> {
    let viewer = epigraph_db::Viewer::resolve(pool, caller)
        .await
        .expect("resolve");
    query_security_events(
        ViewerExtractor(viewer),
        State(state.clone()),
        Some(Extension(auth(caller, scopes))),
        Query(query(agent_id)),
    )
    .await
    .map(|axum::Json(rows)| rows.into_iter().map(|r| r.id).collect())
}

const AUDIT_READ: &[&str] = &["audit:read"];

/// The regression. A principal holding `audit:read` reads its own events and
/// no one else's: not B's, not the instance admin's, not the unattributed row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_reads_only_its_own_events(pool: PgPool) {
    let s = seed(&pool).await;
    let state = split_state(&pool).await;

    let got = call(&state, &pool, s.a, AUDIT_READ, None)
        .await
        .expect("A's own read must succeed");
    assert_eq!(
        got, s.a_rows,
        "A must read exactly its own two events. Extra rows mean the read is not narrowed \
         to the principal. Missing rows mean it moved back to the unstamped raw pool"
    );
    for (row, whose) in [
        (s.b_row, "B's"),
        (s.admin_row, "the instance admin's"),
        (s.unattributed_row, "the unattributed"),
    ] {
        assert!(!got.contains(&row), "A must not read {whose} event");
    }

    let b = call(&state, &pool, s.b, AUDIT_READ, None)
        .await
        .expect("B's own read must succeed");
    assert_eq!(
        b,
        BTreeSet::from([s.b_row]),
        "B reads exactly its own event"
    );

    // Naming yourself is allowed and changes nothing.
    let a_self = call(&state, &pool, s.a, AUDIT_READ, Some(s.a))
        .await
        .expect("filtering on one's own agent_id must succeed");
    assert_eq!(a_self, s.a_rows);
}

/// `?agent_id=` naming another principal is refused to a non-admin, instead of
/// returning an empty list that reads as "that agent has no events".
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_admin_naming_another_principal_is_refused(pool: PgPool) {
    let s = seed(&pool).await;
    let state = split_state(&pool).await;

    let err = call(&state, &pool, s.a, AUDIT_READ, Some(s.b))
        .await
        .expect_err("A naming B must be refused");
    assert!(
        matches!(&err, ApiError::Forbidden { reason } if reason.contains("instance-admin")),
        "expected 403 naming the missing authority, got {err:?}"
    );

    // The same refusal for an agent that does not exist, so the 403 is not an
    // existence oracle about the target.
    let err = call(&state, &pool, s.a, AUDIT_READ, Some(Uuid::new_v4()))
        .await
        .expect_err("A naming an unknown agent must be refused the same way");
    assert!(
        matches!(&err, ApiError::Forbidden { reason } if reason.contains("instance-admin")),
        "expected the same 403 for a nonexistent agent, got {err:?}"
    );
}

/// A live instance administrator reads every principal's events and the
/// unattributed ones, and may filter on any agent.
#[sqlx::test(migrations = "../../migrations")]
async fn an_instance_admin_reads_every_principal_and_the_unattributed_rows(pool: PgPool) {
    let s = seed(&pool).await;
    let state = split_state(&pool).await;

    let all = call(&state, &pool, s.admin, AUDIT_READ, None)
        .await
        .expect("the admin's read must succeed");
    assert_eq!(
        all,
        s.all(),
        "an instance admin must read all five events, including the unattributed one"
    );

    let only_b = call(&state, &pool, s.admin, AUDIT_READ, Some(s.b))
        .await
        .expect("the admin may filter on B");
    assert_eq!(only_b, BTreeSet::from([s.b_row]));

    // After revocation the former admin is an ordinary principal again.
    InstanceAdminRepository::revoke(&pool, s.admin)
        .await
        .expect("revoke");
    let own = call(&state, &pool, s.admin, AUDIT_READ, None)
        .await
        .expect("a revoked admin still reads its own events");
    assert_eq!(own, BTreeSet::from([s.admin_row]));
    let err = call(&state, &pool, s.admin, AUDIT_READ, Some(s.b))
        .await
        .expect_err("a revoked admin naming B must be refused");
    assert!(matches!(err, ApiError::Forbidden { .. }), "got {err:?}");
}

/// `audit:read` is still required, and it is checked before anything is read.
#[sqlx::test(migrations = "../../migrations")]
async fn audit_read_is_still_required(pool: PgPool) {
    let s = seed(&pool).await;
    let state = split_state(&pool).await;

    let err = call(&state, &pool, s.admin, &["claims:read"], None)
        .await
        .expect_err("no audit:read, no read, even for an instance admin");
    assert!(matches!(err, ApiError::Forbidden { .. }), "got {err:?}");
}

/// Without a `ScopedPool` the handler refuses. It must not fall back to the
/// raw pool, where it would have to rely on a policy that does not bind on a
/// privileged session and hides everything on an unstamped one.
#[sqlx::test(migrations = "../../migrations")]
async fn the_route_refuses_rather_than_falls_back_without_a_scoped_pool(pool: PgPool) {
    let s = seed(&pool).await;
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    assert!(state.scoped.is_none(), "CALIBRATION: no ScopedPool");

    // CALIBRATION: the raw pool has rows to give, so the refusal below is not
    // "there was nothing to read".
    let on_raw: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(&state.db_pool)
        .await
        .expect("count on the raw pool");
    assert_eq!(on_raw, i64::try_from(s.all().len()).expect("small"));

    let err = call(&state, &pool, s.a, AUDIT_READ, None)
        .await
        .expect_err("no ScopedPool, no read");
    assert!(
        matches!(&err, ApiError::InternalError { message } if message.contains("scoped connection")),
        "expected the opaque read_as refusal, got {err:?}"
    );
}

/// The timeline's security-event entries, by id, as `caller` sees `agent`'s
/// timeline, plus its activity entries.
async fn timeline(
    state: &AppState,
    pool: &PgPool,
    caller: Uuid,
    agent: Uuid,
) -> Result<(BTreeSet<Uuid>, BTreeSet<Uuid>), ApiError> {
    let viewer = epigraph_db::Viewer::resolve(pool, caller)
        .await
        .expect("resolve");
    let axum::Json(entries) =
        get_agent_timeline(ViewerExtractor(viewer), State(state.clone()), Path(agent)).await?;
    let ids = |kind: &str| -> BTreeSet<Uuid> {
        entries
            .iter()
            .filter(|e| e.entry_type == kind)
            .map(|e| {
                e.details["id"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .expect("every timeline entry carries its row id")
            })
            .collect()
    };
    Ok((ids("security_event"), ids("activity")))
}

async fn seed_activity(pool: &PgPool, agent: Uuid) -> Uuid {
    epigraph_db::ActivityRepository::create(
        pool,
        "timeline_probe",
        chrono::Utc::now(),
        Some(agent),
        Some("f-pr18a-b1 timeline probe"),
        serde_json::json!({}),
    )
    .await
    .expect("seed activity")
}

/// The sibling route. A caller sees security events on its own timeline, none
/// on another agent's, and an instance admin sees them on anyone's. The
/// activity half is served in every case, so a foreign timeline is narrowed
/// and not refused.
#[sqlx::test(migrations = "../../migrations")]
async fn the_timeline_serves_only_the_security_events_the_caller_may_read(pool: PgPool) {
    let s = seed(&pool).await;
    let b_activity = seed_activity(&pool, s.b).await;
    let state = split_state(&pool).await;

    let (events, _) = timeline(&state, &pool, s.a, s.a)
        .await
        .expect("A's own timeline");
    assert_eq!(
        events, s.a_rows,
        "A's own timeline must carry exactly A's security events. Fewer means the read \
         moved back to the unstamped raw pool"
    );

    let (events, activities) = timeline(&state, &pool, s.a, s.b)
        .await
        .expect("A may still open B's timeline");
    assert!(
        events.is_empty(),
        "A must see none of B's security events on B's timeline; got {events:?}"
    );
    assert_eq!(
        activities,
        BTreeSet::from([b_activity]),
        "CALIBRATION: B's timeline still serves its activity half to A, so the empty \
         security-event half is narrowing and not a failed or refused read"
    );

    let (events, activities) = timeline(&state, &pool, s.admin, s.b)
        .await
        .expect("the admin's view of B's timeline");
    assert_eq!(
        events,
        BTreeSet::from([s.b_row]),
        "an instance admin sees B's security events on B's timeline"
    );
    assert_eq!(activities, BTreeSet::from([b_activity]));
}

/// Like the audit route, the timeline refuses without a `ScopedPool` rather
/// than reading security events off the raw pool.
#[sqlx::test(migrations = "../../migrations")]
async fn the_timeline_refuses_rather_than_falls_back_without_a_scoped_pool(pool: PgPool) {
    let s = seed(&pool).await;
    let state = AppState::with_db(pool.clone(), ApiConfig::default());

    let err = timeline(&state, &pool, s.a, s.a)
        .await
        .expect_err("no ScopedPool, no timeline");
    assert!(
        matches!(&err, ApiError::InternalError { message } if message.contains("scoped connection")),
        "expected the opaque read_as refusal, got {err:?}"
    );
}
