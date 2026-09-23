//! `SecurityEventRepository::query_for_principal_conn`: the principal-narrowed
//! read behind `GET /api/v1/audit/security` and the security-event half of
//! `GET /api/v1/agents/:id/timeline`.
//!
//! Deferred-commitment screen key `f-pr18a-b1-audit-scoped-read`
//! (`docs/tenancy/progress.json`, finding `F-PR18a-B1`). Before this function,
//! the only per-principal narrowing on `security_events` was migration 083's
//! `security_events_read` policy. RLS filters nothing on a superuser or
//! `BYPASSRLS` session, so on such a session the old read returned every
//! principal's events to any caller holding `audit:read`.
//!
//! # What each test proves, and on which connection
//!
//! * [`the_conjunct_narrows_on_a_superuser_connection_where_rls_cannot`] runs
//!   on the `#[sqlx::test]` pool, which is a superuser. Its calibration shows
//!   RLS returning all five seeded rows on that connection, so any narrowing
//!   the function then does is the in-query conjunct's. This is the test that
//!   fails if the conjunct is deleted and the fix is left to rely on RLS alone.
//! * [`the_conjunct_agrees_with_security_events_read_on_a_stamped_app_role_connection`]
//!   runs where the POLICY also binds: a `ScopedPool::read_as` connection
//!   downgraded to `epigraph_app`, which is the posture after plan §9.2 step
//!   11d. Its calibration counts what the policy alone admits, and the
//!   function must return exactly that set. That catches a conjunct that is
//!   narrower than the policy. The instance-admin arm matters most here,
//!   because on an app-role session `epigraph_is_instance_admin` answers only
//!   for the session principal.
//! * [`an_unstamped_app_role_connection_reads_nothing_even_for_the_owner`] is
//!   the failure `AppState::read_as` exists to prevent. Unstamped, the policy
//!   hides a principal's own rows, and the answer is an empty result and not
//!   an error.
//!
//! Assertions are by id and exact, in both directions, so a result that is
//! too wide and a result that is too narrow both fail.

mod viewer_fixture;

use std::collections::BTreeSet;

use epigraph_db::repos::instance_admin::InstanceAdminRepository;
use epigraph_db::repos::security_event::{
    SecurityEventFilter, SecurityEventRepository, SecurityEventRow,
};
use epigraph_db::Viewer;
use sqlx::{Executor, PgPool};
use uuid::Uuid;
use viewer_fixture as fixture;

/// The seeded rows, by owner.
struct Seeded {
    a: Uuid,
    b: Uuid,
    admin: Uuid,
    a_rows: BTreeSet<Uuid>,
    b_row: Uuid,
    admin_row: Uuid,
    /// `agent_id IS NULL`: the shape pre-authentication paths write.
    unattributed_row: Uuid,
}

impl Seeded {
    fn all(&self) -> BTreeSet<Uuid> {
        let mut all = self.a_rows.clone();
        all.extend([self.b_row, self.admin_row, self.unattributed_row]);
        all
    }
}

async fn log(pool: &PgPool, agent: Option<Uuid>, success: bool) -> Uuid {
    let row = SecurityEventRow {
        id: Uuid::new_v4(),
        event_type: "auth_attempt".to_string(),
        agent_id: agent,
        success: Some(success),
        details: serde_json::json!({ "probe": "f-pr18a-b1" }),
        ip_address: Some("192.0.2.7".to_string()),
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

/// Three principals (A, B, and an instance admin) and five events: two of A's,
/// one each of B's and the admin's, and one attributed to nobody.
async fn seed(pool: &PgPool) -> Seeded {
    let (a, _) = fixture::seed_agent_with_group(pool, "secev-a").await;
    let (b, _) = fixture::seed_agent_with_group(pool, "secev-b").await;
    let (admin, _) = fixture::seed_agent_with_group(pool, "secev-admin").await;

    // Granted on the superuser pool, which is a bypass session for the grant's
    // own policy. The operator CLI grants over `epigraph_maintenance`;
    // `privatization_authz.rs` covers that path, and this file needs only the row.
    InstanceAdminRepository::grant(pool, admin, None, Some("security-event-principal-read"))
        .await
        .expect("grant instance admin");

    let a_rows: BTreeSet<Uuid> = [
        log(pool, Some(a), true).await,
        log(pool, Some(a), false).await,
    ]
    .into_iter()
    .collect();
    let b_row = log(pool, Some(b), false).await;
    let admin_row = log(pool, Some(admin), true).await;
    let unattributed_row = log(pool, None, false).await;

    Seeded {
        a,
        b,
        admin,
        a_rows,
        b_row,
        admin_row,
        unattributed_row,
    }
}

async fn read(
    conn: &mut sqlx::PgConnection,
    principal: Uuid,
    agent_id: Option<Uuid>,
) -> BTreeSet<Uuid> {
    SecurityEventRepository::query_for_principal_conn(
        conn,
        principal,
        SecurityEventFilter {
            agent_id,
            ..Default::default()
        },
    )
    .await
    .expect("query_for_principal_conn")
    .into_iter()
    .map(|r| r.id)
    .collect()
}

/// How many of the seeded rows the connection itself can see: the policy
/// alone, with no conjunct of ours.
async fn visible_to_session(conn: &mut sqlx::PgConnection, ids: &BTreeSet<Uuid>) -> i64 {
    let ids: Vec<Uuid> = ids.iter().copied().collect();
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE id = ANY($1)")
        .bind(&ids)
        .fetch_one(&mut *conn)
        .await
        .expect("count visible rows")
}

/// The regression test. On a superuser connection RLS returns all five rows,
/// and the function must still hand each principal only what the policy would.
#[sqlx::test(migrations = "../../migrations")]
async fn the_conjunct_narrows_on_a_superuser_connection_where_rls_cannot(pool: PgPool) {
    let s = seed(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");

    // CALIBRATION. The session really is one RLS ignores. Without this, the
    // narrowing below could be the policy's work and the test would not show
    // the conjunct doing anything.
    let privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("role probe");
    assert!(
        privileged,
        "CALIBRATION: this arm needs a session RLS does not filter"
    );
    assert_eq!(
        visible_to_session(&mut conn, &s.all()).await,
        5,
        "CALIBRATION: RLS must return every seeded row on this session. If it \
         filters, this arm no longer tells the conjunct and the policy apart"
    );

    // A principal reads its own rows and nothing else. B's row and the
    // unattributed row are both absent, by id.
    assert_eq!(
        read(&mut conn, s.a, None).await,
        s.a_rows,
        "A must read exactly its own two events on a session RLS does not filter. \
         Anything more means the in-query conjunct is not narrowing"
    );

    // Naming another principal's agent_id does not reach that principal's rows.
    assert!(
        read(&mut conn, s.a, Some(s.b)).await.is_empty(),
        "A filtering on B's agent_id must read nothing: the caller-supplied filter is \
         ANDed with the principal conjunct, not substituted for it"
    );
    assert_eq!(
        read(&mut conn, s.a, Some(s.a)).await,
        s.a_rows,
        "A filtering on its own agent_id reads its own rows"
    );

    // A live instance admin reads every row, the unattributed one included.
    assert_eq!(
        read(&mut conn, s.admin, None).await,
        s.all(),
        "an instance admin must read every principal's events and the unattributed row"
    );
    assert_eq!(
        read(&mut conn, s.admin, Some(s.b)).await,
        BTreeSet::from([s.b_row]),
        "an instance admin filtering on B reads exactly B's row"
    );

    // Revocation is honoured at statement time. The admin keeps its own row,
    // like any other principal, and loses everyone else's.
    assert!(
        InstanceAdminRepository::revoke(&pool, s.admin)
            .await
            .expect("revoke"),
        "CALIBRATION: the revoke must have changed a row"
    );
    assert_eq!(
        read(&mut conn, s.admin, None).await,
        BTreeSet::from([s.admin_row]),
        "a revoked instance admin must read only its own events"
    );

    // Under the nil principal only the admin arm could admit anything, and nil
    // is never an instance admin.
    assert!(
        read(&mut conn, Uuid::nil(), None).await.is_empty(),
        "the nil principal must read nothing"
    );
}

/// After plan §9.2 step 11d: a stamped `epigraph_app` session, where the
/// policy binds too. The function must return exactly what the policy admits,
/// for an ordinary principal and for an instance admin.
#[sqlx::test(migrations = "../../migrations")]
async fn the_conjunct_agrees_with_security_events_read_on_a_stamped_app_role_connection(
    pool: PgPool,
) {
    let s = seed(&pool).await;
    let scoped = fixture::scoped_pool(&pool).await;

    for (principal, expected, who) in [
        (s.a, s.a_rows.clone(), "principal A"),
        (s.b, BTreeSet::from([s.b_row]), "principal B"),
        (s.admin, s.all(), "the instance admin"),
    ] {
        // Resolved on the superuser pool; see `viewer_fixture::downgraded_pool`
        // for why resolving on an app-role session would read an empty group set.
        let viewer = Viewer::resolve(&pool, principal).await.expect("resolve");
        let mut r = scoped.read_as(&viewer).await.expect("read_as");
        r.execute("SET SESSION AUTHORIZATION epigraph_app")
            .await
            .expect("SET SESSION AUTHORIZATION needs a superuser connection");

        let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
            .fetch_one(&mut *r)
            .await
            .expect("epigraph_bypass()");
        assert!(
            !bypass,
            "CALIBRATION ({who}): the downgraded session must not be a bypass session, \
             or the policy is not what is being compared against"
        );
        let policy_admits = visible_to_session(&mut r, &s.all()).await;
        assert_eq!(
            policy_admits,
            i64::try_from(expected.len()).expect("small"),
            "CALIBRATION ({who}): security_events_read alone must admit exactly the \
             expected rows on a stamped app-role session"
        );

        assert_eq!(
            read(&mut r, principal, None).await,
            expected,
            "{who}: on a stamped app-role session the conjunct must agree with the \
             policy, row for row. Fewer rows means the conjunct is narrower than \
             security_events_read"
        );

        r.execute("RESET SESSION AUTHORIZATION")
            .await
            .expect("reset");
        r.commit().await.expect("commit");
    }
}

/// The failure `read_as` prevents: an app-role session with no principal
/// stamped. The policy hides a principal's own rows, and the caller gets an
/// empty result rather than an error.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unstamped_app_role_connection_reads_nothing_even_for_the_owner(pool: PgPool) {
    let s = seed(&pool).await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let mut conn = app.acquire().await.expect("acquire");

    let principal: Option<Uuid> = sqlx::query_scalar("SELECT public.epigraph_principal_id()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_principal_id()");
    assert_eq!(
        principal, None,
        "CALIBRATION: the downgraded pool must be unstamped"
    );

    assert!(
        read(&mut conn, s.a, None).await.is_empty(),
        "unstamped, the policy hides A's own rows. This is why the routes read \
         through AppState::read_as and never through the raw pool"
    );
    assert!(
        read(&mut conn, s.admin, None).await.is_empty(),
        "unstamped, epigraph_is_instance_admin answers false for everyone, so even the \
         instance admin reads nothing"
    );
}
