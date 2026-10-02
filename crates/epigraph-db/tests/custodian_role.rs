//! Migration 123: the custodian role. Instance administration is a ROLE held
//! by a registered human through a timestamped, append-only ASSIGNMENT
//! (`role_assignments`), never a flag on an agent.
//!
//! Most arms write through the maintenance role (`fixture::as_role`), which is
//! the only role the write policies admit; the application-role arms run as
//! `epigraph_app` under `SET SESSION AUTHORIZATION`, stamped exactly as
//! `ScopedPool` stamps a request. Each test names the mutation of
//! `migrations/123_custodian_role.sql` it was run against.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use uuid::Uuid;

const CUSTODIAN: &str = "role:platform-custodian";
const AUDITOR: &str = "role:auditor";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(sqlstate)
}

fn assert_code<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>, code: &str, what: &str) {
    assert_eq!(
        code_of(r).as_deref(),
        Some(code),
        "{what}: expected SQLSTATE {code}, got {r:?}"
    );
}

/// A raw `role_assignments` INSERT on a maintenance session: the path every
/// guard must hold for, whatever wrote it. `valid_from` is `now()` plus
/// `offset` (an SQL interval literal, e.g. `'0'` or `'-1 hour'`).
async fn maint_insert(
    pool: &PgPool,
    role: &str,
    holder: Uuid,
    offset: &str,
    valid_to: Option<&str>,
    granted_by: Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    let role = role.to_string();
    let offset = offset.to_string();
    let valid_to = valid_to.map(str::to_string);
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO role_assignments (role, holder_person_id, valid_from, valid_to, \
                                           granted_by, reason) \
             VALUES ($1, $2, now() + $3::interval, now() + $4::interval, $5, 'custodian test') \
             RETURNING id",
        )
        .bind(&role)
        .bind(holder)
        .bind(&offset)
        .bind(valid_to.as_deref())
        .bind(granted_by)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// One statement on a maintenance session; rows affected.
async fn maint_exec(pool: &PgPool, sql: &str, id: Uuid) -> Result<u64, sqlx::Error> {
    let sql = sql.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(&sql)
            .bind(id)
            .execute(&mut *conn)
            .await
            .map(|d| d.rows_affected());
        (conn, r)
    })
    .await
}

/// Run `f` as `epigraph_app` stamped as `principal` (or unstamped when
/// `None`) with `groups` as its read and writable set: the GUCs `ScopedPool`
/// stamps. The stamp is cleared afterwards.
async fn as_app<F, Fut, T>(pool: &PgPool, principal: Option<Uuid>, groups: &[Uuid], f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let set = groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let principal = principal.map(|p| p.to_string()).unwrap_or_default();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $2, false)",
        )
        .bind(&principal)
        .bind(&set)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let (mut conn, out) = f(conn).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

/// The catalog row of `role`: its projection node.
async fn role_node(pool: &PgPool, role: &str) -> Uuid {
    sqlx::query_scalar("SELECT role_node_id FROM platform_roles WHERE key = $1")
        .bind(role)
        .fetch_one(pool)
        .await
        .expect("catalog role")
}

async fn assignments_of(pool: &PgPool, holder: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM role_assignments WHERE holder_person_id = $1")
        .bind(holder)
        .fetch_one(pool)
        .await
        .expect("count")
}

// =====================================================================
// T1. Agents never hold a role.
// =====================================================================

/// A live `operator_links` row making `agent` an agent of `operator`, written
/// by a superuser with triggers off (`session_replication_role = replica`),
/// i.e. PAST 123's role-holder link guard: the shape the read-time checks
/// must still hold against. The operator's group is its own personal group.
async fn link_past_the_guard(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .expect("triggers off");
    let r = sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) \
         SELECT $1, $2, m.group_id FROM group_memberships m \
          WHERE m.agent_id = $2 AND m.role = 'admin' AND m.revoked_at IS NULL \
          ORDER BY m.group_id LIMIT 1",
    )
    .bind(agent)
    .bind(operator)
    .execute(&mut *conn)
    .await;
    sqlx::query("SET session_replication_role = DEFAULT")
        .execute(&mut *conn)
        .await
        .expect("triggers on");
    assert_eq!(
        r.expect("a link written past the guard").rows_affected(),
        1,
        "one link row"
    );
}

/// Only a REGISTERED HUMAN (`epigraph_is_human_operator`: a live registry row
/// and its active human client) holds a role. A live-linked agent, a
/// retired-linked agent, an unbound agent, a role's own projection node and a
/// human whose client was suspended are all refused `CUS01`, on the
/// maintenance role, by the table's own trigger.
///
/// Verified to fail: guard (a) removed -> every agent's assignment lands;
/// guard (a) reading "holds a live operator link" instead of
/// `epigraph_is_human_operator` -> the live-linked agent's lands and the
/// human's is refused; the guard's `operator_links` test removed -> the
/// linked registered humans are granted; the same test removed from
/// `epigraph_live_role_assignment` -> the custodian linked past the guard
/// still holds; the `operator_links` holder guard's trigger not created ->
/// the custodian's link lands (review SEC-MTC-9's residual); that guard's
/// lapse clause (`valid_to > clock_timestamp()`) removed -> the lapsed
/// holder's link is refused (review R2-OQ-TST-2).
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_never_holds_a_role(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "custodian-human").await;
    let (live, _) = fixture::seed_agent_with_group(&pool, "live-linked").await;
    let (retired, _) = fixture::seed_agent_with_group(&pool, "retired-linked").await;
    let (unbound, _) = fixture::seed_agent_with_group(&pool, "unbound").await;
    let (suspended, _) = fixture::seed_human_operator(&pool, "suspended-human").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, live, human)
            .await
            .expect("live link");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, retired, human)
            .await
            .expect("retired link");
    }
    sqlx::query("UPDATE oauth_clients SET status = 'suspended' WHERE agent_id = $1")
        .bind(suspended)
        .execute(&pool)
        .await
        .expect("suspend the human's client");
    let node = role_node(&pool, CUSTODIAN).await;

    let first = maint_insert(&pool, CUSTODIAN, human, "0", None, None).await;
    assert!(
        first.is_ok(),
        "a registered human is granted (bootstrap): {first:?}"
    );
    for (agent, what) in [
        (live, "a live-linked agent"),
        (retired, "a retired-linked agent"),
        (unbound, "an unbound agent"),
        (node, "the role's own projection node"),
        (suspended, "a human whose client is suspended"),
    ] {
        for role in [CUSTODIAN, AUDITOR] {
            let r = maint_insert(&pool, role, agent, "0", None, Some(human)).await;
            assert_code(&r, "CUS01", &format!("{what} granted {role}"));
            let text = r.expect_err("refused").to_string();
            assert!(
                text.contains("agents never hold a role"),
                "{what}: the refusal says why: {text}"
            );
        }
        assert_eq!(
            assignments_of(&pool, agent).await,
            0,
            "{what} holds nothing"
        );
    }

    // A REGISTERED human that is also linked as another human's agent, live
    // or retired, is an operated agent: refused at the grant, and a custodian
    // linked AFTER its grant stops holding at once (review SEC-MTC-9).
    let (linked_human, _) = fixture::seed_human_operator(&pool, "linked-human").await;
    let (retired_human, _) = fixture::seed_human_operator(&pool, "retired-human").await;
    let (later, _) = fixture::seed_human_operator(&pool, "linked-after-grant").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, linked_human, human)
            .await
            .expect("122 links a registered human live");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, retired_human, human)
            .await
            .expect("122 links a registered human retired");
    }
    for (agent, what) in [
        (linked_human, "a registered human live-linked as an agent"),
        (
            retired_human,
            "a registered human retired-linked as an agent",
        ),
    ] {
        let r = maint_insert(&pool, CUSTODIAN, agent, "0", None, Some(human)).await;
        assert_code(&r, "CUS01", what);
        assert_eq!(
            assignments_of(&pool, agent).await,
            0,
            "{what} holds nothing"
        );
    }
    let later_asg = maint_insert(&pool, CUSTODIAN, later, "0", None, Some(human))
        .await
        .expect("an unlinked registered human is granted");
    assert!(holds_at(&pool, later, CUSTODIAN, "now()").await, "it holds");

    // Linking a HOLDER as an agent is refused (CUS01), live or retired, and a
    // not-yet-begun assignment counts: its holding ends only through
    // end-role-assignment, whose end is audited (`platform.role_ended`).
    let (future, _) = fixture::seed_human_operator(&pool, "future-holder").await;
    maint_insert(&pool, AUDITOR, future, "1 day", None, Some(human))
        .await
        .expect("an auditor assignment that begins tomorrow");
    for (agent, retired_link, what) in [
        (later, false, "a live link of a custodian"),
        (later, true, "a retired link of a custodian"),
        (future, false, "a live link of a not-yet-begun holder"),
    ] {
        let mut conn = pool.acquire().await.expect("acquire");
        let r = if retired_link {
            epigraph_db::AgentRepository::link_retired_agent(&mut conn, agent, human)
                .await
                .map(|_| ())
        } else {
            epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
                .await
                .map(|_| ())
        };
        drop(conn);
        let text = format!("{r:?}");
        assert!(
            r.is_err() && text.contains("CUS01") && text.contains("end-role-assignment"),
            "{what} must be refused CUS01, naming the way out: {text}"
        );
        let links: i64 =
            sqlx::query_scalar("SELECT count(*) FROM operator_links WHERE agent_id = $1")
                .bind(agent)
                .fetch_one(&pool)
                .await
                .expect("links");
        assert_eq!(links, 0, "{what}: no link row");
    }
    assert!(
        holds_at(&pool, later, CUSTODIAN, "now()").await,
        "the refused link changed nothing"
    );

    // A LAPSED assignment (past its valid_to, never ended) holds nothing, so
    // it does not block a link (review R2-OQ-TST-2).
    let (lapsing, _) = fixture::seed_human_operator(&pool, "lapsed-holder").await;
    maint_insert(&pool, AUDITOR, lapsing, "0", Some("1 second"), Some(human))
        .await
        .expect("an auditor assignment for one second");
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert!(
        !holds_at(&pool, lapsing, AUDITOR, "now()").await,
        "PREMISE: the assignment has lapsed"
    );
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, lapsing, human)
            .await
            .expect("a holder whose assignment lapsed is linked");
    }
    assert_eq!(
        holding_and_links(&pool, lapsing).await,
        (1, 1),
        "linked, its lapsed row untouched"
    );

    // The way out: end the assignment (audited), then link.
    assert!(end_role(&pool, later_asg).await.expect("end"), "ended");
    assert_eq!(
        events_for(&pool, "platform.role_ended", later_asg).await,
        1,
        "the end is audited"
    );
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, later, human)
            .await
            .expect("a former custodian is linked once its assignment has ended");
    }

    // Defence in depth: a link that reached the table past the guard (here a
    // superuser with triggers off) still ends holding at READ time.
    let (bypassed, _) = fixture::seed_human_operator(&pool, "linked-past-the-guard").await;
    maint_insert(&pool, CUSTODIAN, bypassed, "0", None, Some(human))
        .await
        .expect("granted");
    link_past_the_guard(&pool, bypassed, human).await;
    assert!(
        !holds_at(&pool, bypassed, CUSTODIAN, "now()").await,
        "a custodian linked as an agent holds nothing"
    );
    let admin: bool = sqlx::query_scalar("SELECT public.epigraph_is_instance_admin($1)")
        .bind(bypassed)
        .fetch_one(&pool)
        .await
        .expect("is_instance_admin");
    assert!(!admin, "nor is it an instance admin");
}

/// Whether some backend of THIS database waits on an advisory lock: polled
/// until one does (true), or `task` finishes or 10 s pass (false). A fixed
/// pause cannot tell "blocked" from "slow".
async fn waits_on_an_advisory_lock<T>(pool: &PgPool, task: &tokio::task::JoinHandle<T>) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_locks l \
                             WHERE l.locktype = 'advisory' AND NOT l.granted \
                               AND l.database = (SELECT oid FROM pg_database \
                                                  WHERE datname = current_database()))",
        )
        .fetch_one(pool)
        .await
        .expect("pg_locks");
        if waiting {
            return true;
        }
        if task.is_finished() || std::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// `epigraph_grant_role` inside an open transaction (superuser: privileged).
async fn grant_in(
    conn: &mut sqlx::PgConnection,
    role: &str,
    holder: Uuid,
    granted_by: Uuid,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT public.epigraph_grant_role($1, $2, NULL, NULL, $3, 'race test')",
    )
    .bind(role)
    .bind(holder)
    .bind(granted_by)
    .fetch_one(conn)
    .await
}

/// A direct maintenance `INSERT INTO operator_links` (no link function, so
/// none of 107's locks): only the table's own triggers stand in its way.
async fn raw_link_in(
    conn: &mut sqlx::PgConnection,
    agent: Uuid,
    operator: Uuid,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) \
         SELECT $1, $2, m.group_id FROM group_memberships m \
          WHERE m.agent_id = $2 AND m.role = 'admin' AND m.revoked_at IS NULL \
          ORDER BY m.group_id LIMIT 1",
    )
    .bind(agent)
    .bind(operator)
    .execute(conn)
    .await
    .map(|d| d.rows_affected())
}

/// `(un-ended assignments, operator_links rows as the agent)` of `who`.
async fn holding_and_links(pool: &PgPool, who: Uuid) -> (i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM role_assignments \
                  WHERE holder_person_id = $1 AND revoked_at IS NULL), \
                (SELECT count(*) FROM operator_links WHERE agent_id = $1)",
    )
    .bind(who)
    .fetch_one(pool)
    .await
    .expect("holding and links")
}

/// A grant and a link of ONE principal, run concurrently, see each other
/// (review R2-OQ-SEC-2 / R2-OQ-COR-2). Review measured both committing,
/// under READ COMMITTED and REPEATABLE READ alike: the holder ended up linked
/// as an agent with its assignment un-ended and no `platform.role_ended` row,
/// the state the role-holder link guard exists to refuse.
///
/// Connection 1 holds one side uncommitted; connection 2's other side must
/// WAIT (an ungranted advisory lock in `pg_locks`, polled), and once
/// connection 1 commits it is refused `CUS01`. In every order, and for a
/// direct `operator_links` INSERT that no link function wraps.
/// REPEATABLE READ is refused `CUS06` on both sides; under SERIALIZABLE the
/// race ends in a serialization failure, never in both rows.
///
/// Verified to fail: the grant guard's `pg_advisory_xact_lock` removed -> the
/// link-first grant does not wait and is admitted; the role-holder link
/// guard's lock removed -> the direct INSERT does not wait and is admitted;
/// either `CUS06` test removed -> that side is admitted under REPEATABLE READ.
#[sqlx::test(migrations = "../../migrations")]
async fn a_concurrent_grant_and_link_see_each_other(pool: PgPool) {
    let (custodian, _) = fixture::seed_human_operator(&pool, "race-custodian").await;
    let (operator, _) = fixture::seed_human_operator(&pool, "race-operator").await;
    maint_insert(&pool, CUSTODIAN, custodian, "0", None, None)
        .await
        .expect("bootstrap custodian");

    // (a) Grant first; the link function waits, then is refused.
    let (grant_first, _) = fixture::seed_human_operator(&pool, "grant-first").await;
    let mut c1 = pool.begin().await.expect("begin connection 1");
    grant_in(&mut c1, AUDITOR, grant_first, custodian)
        .await
        .expect("grant on connection 1");
    let pool2 = pool.clone();
    let link = tokio::spawn(async move {
        let mut c2 = pool2.acquire().await.expect("acquire connection 2");
        epigraph_db::AgentRepository::link_operator(&mut c2, grant_first, operator)
            .await
            .map(|_| ())
    });
    assert!(
        waits_on_an_advisory_lock(&pool, &link).await,
        "the link finished while the grant was uncommitted: they were not serialised"
    );
    c1.commit().await.expect("commit connection 1");
    let r = link.await.expect("join connection 2");
    assert!(
        format!("{r:?}").contains("CUS01"),
        "grant first: the link after the grant commits is refused CUS01: {r:?}"
    );
    assert_eq!(holding_and_links(&pool, grant_first).await, (1, 0));

    // (b) Link first; the grant waits, then is refused.
    let (link_first, _) = fixture::seed_human_operator(&pool, "link-first").await;
    let mut c1 = pool.begin().await.expect("begin connection 1");
    epigraph_db::AgentRepository::link_operator(&mut c1, link_first, operator)
        .await
        .expect("link on connection 1");
    let pool2 = pool.clone();
    let grant = tokio::spawn(async move {
        let mut c2 = pool2.acquire().await.expect("acquire connection 2");
        grant_in(&mut c2, AUDITOR, link_first, custodian).await
    });
    assert!(
        waits_on_an_advisory_lock(&pool, &grant).await,
        "the grant finished while the link was uncommitted: they were not serialised"
    );
    c1.commit().await.expect("commit connection 1");
    let r = grant.await.expect("join connection 2");
    assert_code(&r, "CUS01", "link first: the grant after the link commits");
    assert_eq!(holding_and_links(&pool, link_first).await, (0, 1));

    // (c) Grant first; a DIRECT link INSERT (no link function's lock) waits on
    // the link guard's own lock, then is refused.
    let (raw, _) = fixture::seed_human_operator(&pool, "raw-link").await;
    let mut c1 = pool.begin().await.expect("begin connection 1");
    grant_in(&mut c1, AUDITOR, raw, custodian)
        .await
        .expect("grant on connection 1");
    let pool2 = pool.clone();
    let insert = tokio::spawn(async move {
        let mut c2 = pool2.acquire().await.expect("acquire connection 2");
        raw_link_in(&mut c2, raw, operator).await
    });
    assert!(
        waits_on_an_advisory_lock(&pool, &insert).await,
        "the direct link INSERT finished while the grant was uncommitted"
    );
    c1.commit().await.expect("commit connection 1");
    let r = insert.await.expect("join connection 2");
    assert_code(&r, "CUS01", "grant first: the direct link INSERT");
    assert_eq!(holding_and_links(&pool, raw).await, (1, 0));

    // (d) REPEATABLE READ: refused on both sides, before anything is read.
    let (rr, _) = fixture::seed_human_operator(&pool, "repeatable-read").await;
    let mut c = pool.begin().await.expect("begin");
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *c)
        .await
        .expect("RR");
    let r = grant_in(&mut c, AUDITOR, rr, custodian).await;
    assert_code(&r, "CUS06", "a grant under REPEATABLE READ");
    c.rollback().await.expect("rollback");
    let mut c = pool.begin().await.expect("begin");
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *c)
        .await
        .expect("RR");
    let r = raw_link_in(&mut c, rr, operator).await;
    assert_code(&r, "CUS06", "a link under REPEATABLE READ");
    c.rollback().await.expect("rollback");
    assert_eq!(holding_and_links(&pool, rr).await, (0, 0));

    // (e) SERIALIZABLE: grant first, the link waits, and the write skew ends
    // in a serialization failure (or the refusal), never in both rows.
    let (ser, _) = fixture::seed_human_operator(&pool, "serializable").await;
    let mut c1 = pool.begin().await.expect("begin connection 1");
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *c1)
        .await
        .expect("SERIALIZABLE");
    grant_in(&mut c1, AUDITOR, ser, custodian)
        .await
        .expect("grant on connection 1");
    let pool2 = pool.clone();
    let link = tokio::spawn(async move {
        let mut c2 = pool2.begin().await.expect("begin connection 2");
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *c2)
            .await
            .expect("SERIALIZABLE");
        raw_link_in(&mut c2, ser, operator).await?;
        c2.commit().await.map(|()| 1)
    });
    assert!(
        waits_on_an_advisory_lock(&pool, &link).await,
        "SERIALIZABLE: the link finished while the grant was uncommitted"
    );
    c1.commit().await.expect("commit connection 1");
    let r = link.await.expect("join connection 2");
    assert!(
        matches!(code_of(&r).as_deref(), Some("40001" | "CUS01")),
        "SERIALIZABLE: the link is a serialization failure or the refusal: {r:?}"
    );
    assert_eq!(holding_and_links(&pool, ser).await, (1, 0));
}

/// The legacy bulk link (`epigraph_link_legacy_authors`) skips a principal
/// whose assignment the role-holder link guard would refuse to see linked,
/// as `skipped:role_holder`, instead of letting that guard's `CUS01` roll the
/// WHOLE call back (review R2-OQ-SEC-3 / R2-OQ-TST-1). The case: a holder
/// whose human registration and client were revoked while nobody ended its
/// assignment is no longer "a registered human", so the bulk link took it as
/// a candidate; review measured the call abort and link nothing, the plain
/// legacy author included.
///
/// The skip uses the guard's own predicate: an un-ended assignment, live or
/// not yet begun, blocks; a LAPSED one (past `valid_to`) does not, so that
/// former holder is linked.
///
/// Verified to fail: the `skipped:role_holder` arm removed -> the call
/// aborts `CUS01`; its lapse clause removed -> the lapsed holder is skipped;
/// its `revoked_at IS NULL` test removed -> the ended holder is skipped.
#[sqlx::test(migrations = "../../migrations")]
async fn a_departed_holder_never_aborts_the_legacy_bulk_link(pool: PgPool) {
    let (operator, _) = fixture::seed_human_operator(&pool, "bulk-operator").await;
    let (custodian, _) = fixture::seed_human_operator(&pool, "bulk-custodian").await;
    maint_insert(&pool, CUSTODIAN, custodian, "0", None, None)
        .await
        .expect("bootstrap custodian");
    let (live, _) = fixture::seed_human_operator(&pool, "departed-live").await;
    let (future, _) = fixture::seed_human_operator(&pool, "departed-future").await;
    let (lapsed, _) = fixture::seed_human_operator(&pool, "departed-lapsed").await;
    let (ended, _) = fixture::seed_human_operator(&pool, "departed-ended").await;
    maint_insert(&pool, AUDITOR, live, "0", None, Some(custodian))
        .await
        .expect("a live auditor");
    maint_insert(&pool, AUDITOR, future, "1 day", None, Some(custodian))
        .await
        .expect("an auditor from tomorrow");
    maint_insert(
        &pool,
        AUDITOR,
        lapsed,
        "0",
        Some("1 second"),
        Some(custodian),
    )
    .await
    .expect("an auditor for one second");
    let ended_asg = maint_insert(&pool, AUDITOR, ended, "0", None, Some(custodian))
        .await
        .expect("an auditor, ended below");
    assert!(end_role(&pool, ended_asg).await.expect("end"), "ended");
    let plain = bare_agent(&pool).await;
    for who in [live, future, lapsed, ended, plain] {
        fixture::seed_public_claim(&pool, who, &format!("legacy claim by {who}")).await;
    }
    // They leave: registration and client revoked, assignments NOT ended.
    for who in [live, future, lapsed, ended] {
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'departed')")
                .bind(who)
                .execute(&mut *conn)
                .await
                .expect("revoke the registration");
            (conn, ())
        })
        .await;
        sqlx::query("UPDATE oauth_clients SET status = 'revoked' WHERE agent_id = $1")
            .bind(who)
            .execute(&pool)
            .await
            .expect("revoke the client");
    }
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let un_ended: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM role_assignments \
          WHERE holder_person_id = ANY($1) AND revoked_at IS NULL",
    )
    .bind(vec![live, future, lapsed])
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        un_ended, 3,
        "PREMISE: the departed holders' rows are un-ended"
    );

    let rows: Result<Vec<(Uuid, String)>, sqlx::Error> =
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query_as(
                "SELECT agent_id, outcome FROM public.epigraph_link_legacy_authors($1, '{}', NULL)",
            )
            .bind(operator)
            .fetch_all(&mut *conn)
            .await;
            (conn, r)
        })
        .await;
    let rows = rows.expect("the bulk link completes; one departed holder never aborts it");
    let outcome = |who: Uuid| {
        rows.iter()
            .find(|(a, _)| *a == who)
            .map(|(_, o)| o.clone())
            .unwrap_or_else(|| panic!("{who} is a candidate: {rows:?}"))
    };
    for (who, expected, what) in [
        (live, "skipped:role_holder", "a departed live holder"),
        (
            future,
            "skipped:role_holder",
            "a departed not-yet-begun holder",
        ),
        (
            lapsed,
            "linked",
            "a departed holder whose assignment lapsed",
        ),
        (
            ended,
            "linked",
            "a departed holder whose assignment was ended",
        ),
        (plain, "linked", "a plain legacy author"),
    ] {
        assert_eq!(outcome(who), expected, "{what}");
    }
    assert_eq!(
        holding_and_links(&pool, live).await,
        (1, 0),
        "the skipped holder is untouched"
    );
}

// =====================================================================
// T2. Assignments are append-only.
// =====================================================================

/// An assignment is never edited: no column but the revoke stamp ever
/// changes, the revoke happens once and is stamped `now()`, nothing is
/// back-dated, and no role deletes a row (the maintenance role included; no
/// DELETE policy exists).
///
/// Verified to fail: the update guard's column comparison removed -> the
/// `valid_to` / holder / role edits land; any one of `valid_from`,
/// `granted_by`, `grant_act_id`, `created_at` dropped from that comparison ->
/// its edit lands (review TST-MTC-5); the `revoked_at = now()` test removed ->
/// the back-dated revoke lands; the `revoked_by = session_user` test removed ->
/// the forged revoker lands; the "an ended assignment is final" test removed
/// -> the well-formed second revoke re-dates the end (review TST-MTC-4); the
/// insert guard's revoke-field test removed -> the pre-ended INSERT lands
/// (review TST-MTC-8); its provenance test removed -> the INSERTs posing as
/// the 123 carry-over, back-dated or carrying an act id land (review
/// SEC-MTC-2); the back-date test on `valid_from` removed -> the back-dated
/// grant lands; a `FOR DELETE` policy added -> the catalog arm fails.
#[sqlx::test(migrations = "../../migrations")]
async fn assignments_are_append_only(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "h").await;
    let (h2, _) = fixture::seed_human_operator(&pool, "h2").await;
    let id = maint_insert(&pool, CUSTODIAN, h, "0", None, None)
        .await
        .expect("bootstrap grant");

    // Each column edit rides on an otherwise well-formed revoke, so it is the
    // column comparison, not the missing revoke stamp, that refuses it.
    let edits = [
        (
            "UPDATE role_assignments SET valid_to = now() + interval '1 day' WHERE id = $1",
            "valid_to alone",
        ),
        (
            "UPDATE role_assignments SET valid_to = now() + interval '1 day', revoked_at = now(), \
                    revoked_by = session_user, revoked_reason = 'x' WHERE id = $1",
            "valid_to",
        ),
        (
            "UPDATE role_assignments SET role = 'role:auditor', revoked_at = now(), \
                    revoked_by = session_user, revoked_reason = 'x' WHERE id = $1",
            "role",
        ),
        (
            "UPDATE role_assignments SET reason = 'rewritten', revoked_at = now(), \
                    revoked_by = session_user, revoked_reason = 'x' WHERE id = $1",
            "reason",
        ),
        (
            "UPDATE role_assignments SET granted_via = 'someone else', revoked_at = now(), \
                    revoked_by = session_user, revoked_reason = 'x' WHERE id = $1",
            "granted_via",
        ),
        (
            "UPDATE role_assignments SET valid_from = valid_from - interval '1 second', \
                    revoked_at = now(), revoked_by = session_user, revoked_reason = 'x' \
              WHERE id = $1",
            "valid_from",
        ),
        (
            "UPDATE role_assignments SET granted_by = holder_person_id, revoked_at = now(), \
                    revoked_by = session_user, revoked_reason = 'x' WHERE id = $1",
            "granted_by",
        ),
        (
            "UPDATE role_assignments SET grant_act_id = gen_random_uuid(), revoked_at = now(), \
                    revoked_by = session_user, revoked_reason = 'x' WHERE id = $1",
            "grant_act_id",
        ),
        (
            "UPDATE role_assignments SET created_at = created_at - interval '1 hour', \
                    revoked_at = now(), revoked_by = session_user, revoked_reason = 'x' \
              WHERE id = $1",
            "created_at",
        ),
        (
            "UPDATE role_assignments SET id = gen_random_uuid(), revoked_at = now(), \
                    revoked_by = session_user, revoked_reason = 'x' WHERE id = $1",
            "id",
        ),
        (
            "UPDATE role_assignments SET holder_group_id = (SELECT id FROM groups LIMIT 1), \
                    revoked_at = now(), revoked_by = session_user, revoked_reason = 'x' \
              WHERE id = $1",
            "holder_group_id",
        ),
        (
            "UPDATE role_assignments SET revoked_at = now(), revoked_by = 'someone-else', \
                    revoked_reason = 'x' WHERE id = $1",
            "a revoke naming another login as its revoker",
        ),
        (
            "UPDATE role_assignments SET revoked_at = now() - interval '1 hour', \
                    revoked_by = session_user, revoked_reason = 'back-dated' WHERE id = $1",
            "a back-dated revoke",
        ),
        (
            "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                    revoked_reason = '  ' WHERE id = $1",
            "a revoke with no reason",
        ),
    ];
    for (sql, what) in edits {
        assert_code(&maint_exec(&pool, sql, id).await, "CUS02", what);
    }
    let holder_edit = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(
            "UPDATE role_assignments SET holder_person_id = $2, revoked_at = now(), \
                    revoked_by = session_user, revoked_reason = 'x' WHERE id = $1",
        )
        .bind(id)
        .bind(h2)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_code(&holder_edit, "CUS02", "holder");

    let revoke = "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                  revoked_reason = 'ended by test' WHERE id = $1";
    assert_eq!(
        maint_exec(&pool, revoke, id).await.expect("the revoke"),
        1,
        "the one admitted change"
    );
    let ended_at = move |pool: PgPool| async move {
        sqlx::query_as::<_, (String, String, String)>(
            "SELECT revoked_at::text, revoked_by, revoked_reason FROM role_assignments \
              WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("the end")
    };
    let first_end = ended_at(pool.clone()).await;
    // A WELL-FORMED second revoke (stamped now, by this login, with a reason):
    // only the "an ended assignment is final" test can refuse it.
    assert_code(
        &maint_exec(
            &pool,
            "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                    revoked_reason = 'again' WHERE id = $1",
            id,
        )
        .await,
        "CUS02",
        "a second, well-formed revoke",
    );
    assert_eq!(
        ended_at(pool.clone()).await,
        first_end,
        "the end is not re-dated or re-explained"
    );

    let deleted = maint_exec(&pool, "DELETE FROM role_assignments WHERE id = $1", id).await;
    assert!(
        matches!(&deleted, Ok(0)) || code_of(&deleted).as_deref() == Some("42501"),
        "the maintenance role deletes nothing: {deleted:?}"
    );
    let delete_policies: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policy WHERE polrelid IN \
            ('public.role_assignments'::regclass, 'public.platform_roles'::regclass) \
           AND polcmd IN ('d', '*')",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert_eq!(delete_policies, 0, "no DELETE (or FOR ALL) policy");

    let back_dated = maint_insert(&pool, CUSTODIAN, h2, "-1 hour", None, Some(h)).await;
    assert_code(&back_dated, "CUS02", "a back-dated valid_from");
    // The insert guard's other CUS02 arms: a row recorded already ended, and
    // provenance the writer supplies instead of the database. (With `h` ended
    // there is no live custodian, so each is a well-formed bootstrap grant
    // but for the one column under test.)
    for (columns, values, what) in [
        (
            "revoked_at, revoked_by, revoked_reason",
            "now(), session_user, 'pre-ended'",
            "an assignment INSERTed already ended",
        ),
        (
            "granted_via",
            "'migration 123'",
            "an INSERT posing as the 123 carry-over",
        ),
        (
            "created_at",
            "'2020-01-01T00:00:00Z'::timestamptz",
            "a back-dated created_at",
        ),
        (
            "grant_act_id",
            "gen_random_uuid()",
            "an INSERT naming an act id",
        ),
    ] {
        let sql = format!(
            "INSERT INTO role_assignments (role, holder_person_id, valid_from, reason, {columns}) \
             VALUES ('role:platform-custodian', $1, now(), 'custodian test', {values})"
        );
        let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query(&sql).bind(h2).execute(&mut *conn).await;
            (conn, r)
        })
        .await;
        assert_code(&r, "CUS02", what);
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM role_assignments")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 1, "nothing but the one grant was written");
}

// =====================================================================
// T3. The application role cannot write assignments.
// =====================================================================

/// The application role reads only its OWN assignments (and nothing when
/// unstamped) and writes none, on either table: no grant, and a write policy
/// it cannot satisfy.
///
/// Verified to fail: `GRANT INSERT ON role_assignments TO epigraph_app` -> the
/// privilege arm; the SELECT policy widened to `true` -> the stamped session
/// sees the other holder's row and the unstamped one sees both.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_write_assignments(pool: PgPool) {
    let (h, hg) = fixture::seed_human_operator(&pool, "h").await;
    let (h2, _) = fixture::seed_human_operator(&pool, "h2").await;
    let id = maint_insert(&pool, CUSTODIAN, h, "0", None, None)
        .await
        .expect("grant h");
    maint_insert(&pool, AUDITOR, h2, "0", None, Some(h))
        .await
        .expect("grant h2");

    for table in ["role_assignments", "platform_roles"] {
        for privilege in ["INSERT", "UPDATE", "DELETE", "TRUNCATE"] {
            let held: bool =
                sqlx::query_scalar("SELECT has_table_privilege('epigraph_app', $1, $2)")
                    .bind(format!("public.{table}"))
                    .bind(privilege)
                    .fetch_one(&pool)
                    .await
                    .expect("privilege");
            assert!(!held, "epigraph_app holds {privilege} on {table}");
        }
        let select: bool =
            sqlx::query_scalar("SELECT has_table_privilege('epigraph_app', $1, 'SELECT')")
                .bind(format!("public.{table}"))
                .fetch_one(&pool)
                .await
                .expect("privilege");
        assert!(select, "epigraph_app reads {table}");
    }

    let (insert, update, seen) = as_app(&pool, Some(h), &[hg], |mut conn| async move {
        let insert = sqlx::query(
            "INSERT INTO role_assignments (role, holder_person_id, valid_from, reason) \
             VALUES ('role:platform-custodian', $1, now(), 'self-service')",
        )
        .bind(h)
        .execute(&mut *conn)
        .await;
        let update = sqlx::query(
            "UPDATE role_assignments SET revoked_at = now(), revoked_by = 'x', \
                    revoked_reason = 'x' WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *conn)
        .await;
        let seen: Vec<Uuid> = sqlx::query_scalar("SELECT holder_person_id FROM role_assignments")
            .fetch_all(&mut *conn)
            .await
            .expect("app SELECT");
        (conn, (insert, update, seen))
    })
    .await;
    assert_code(&insert, "42501", "an app INSERT");
    assert_code(&update, "42501", "an app UPDATE");
    assert_eq!(
        seen,
        vec![h],
        "a stamped app session reads its own rows only"
    );

    let unstamped: Vec<Uuid> = as_app(&pool, None, &[], |mut conn| async move {
        let seen = sqlx::query_scalar("SELECT holder_person_id FROM role_assignments")
            .fetch_all(&mut *conn)
            .await
            .expect("app SELECT");
        (conn, seen)
    })
    .await;
    assert!(
        unstamped.is_empty(),
        "an unstamped app session reads none: {unstamped:?}"
    );
    let catalog: i64 = as_app(&pool, None, &[], |mut conn| async move {
        let n = sqlx::query_scalar("SELECT count(*) FROM platform_roles")
            .fetch_one(&mut *conn)
            .await
            .expect("catalog read");
        (conn, n)
    })
    .await;
    assert_eq!(catalog, 2, "the catalog is public");
}

// =====================================================================
// T8. The grantor rule.
// =====================================================================

/// Bootstrap: with no live custodian, an assignment with no grantor is
/// admitted. Once one exists, every grant names a LIVE custodian as its
/// grantor, and a holder never extends itself while another holder exists.
///
/// Verified to fail: guard (d) removed -> B's self-extension, the
/// non-custodian grantor and the grantor-less grant all land.
#[sqlx::test(migrations = "../../migrations")]
async fn the_grantor_rule(pool: PgPool) {
    let (a, _) = fixture::seed_human_operator(&pool, "a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "b").await;
    let (c, _) = fixture::seed_human_operator(&pool, "c").await;

    maint_insert(&pool, CUSTODIAN, a, "0", None, None)
        .await
        .expect("bootstrap: no live custodian, no grantor");
    maint_insert(&pool, CUSTODIAN, a, "0", Some("30 days"), Some(a))
        .await
        .expect("the ONLY holder extends itself");
    assert_code(
        &maint_insert(&pool, CUSTODIAN, b, "0", None, None).await,
        "CUS03",
        "no grantor once a custodian exists",
    );
    assert_code(
        &maint_insert(&pool, CUSTODIAN, b, "0", None, Some(c)).await,
        "CUS03",
        "a grantor that holds no custodian assignment",
    );
    maint_insert(&pool, CUSTODIAN, b, "0", None, Some(a))
        .await
        .expect("A grants B");
    assert_code(
        &maint_insert(&pool, CUSTODIAN, b, "0", Some("1 year"), Some(b)).await,
        "CUS03",
        "B extends B while A holds",
    );
    assert_code(
        &maint_insert(&pool, CUSTODIAN, a, "0", Some("1 year"), Some(a)).await,
        "CUS03",
        "A extends A while B holds",
    );
    maint_insert(&pool, AUDITOR, c, "0", None, Some(b))
        .await
        .expect("B grants C the auditor role");
    assert_code(
        &maint_insert(&pool, AUDITOR, b, "0", None, Some(c)).await,
        "CUS03",
        "an auditor is no grantor",
    );
}

/// The catalog's identity is fixed: a role's key, whether it elevates or
/// reads the audit, and its projection node never change (`CUS02`), on the
/// maintenance role; only the description may (review TST-MTC-9).
///
/// Verified to fail: the `platform_roles_guard_update` comparison removed ->
/// the auditor role is made to elevate and the node is re-pointed.
#[sqlx::test(migrations = "../../migrations")]
async fn the_catalog_identity_is_fixed(pool: PgPool) {
    let other_node = role_node(&pool, CUSTODIAN).await;
    for (sql, what) in [
        (
            "UPDATE platform_roles SET elevates = true WHERE key = 'role:auditor'",
            "the auditor role made to elevate",
        ),
        (
            "UPDATE platform_roles SET reads_audit = false WHERE key = 'role:auditor'",
            "the auditor role made blind",
        ),
        (
            "UPDATE platform_roles SET key = 'role:superuser' WHERE key = 'role:auditor'",
            "a role renamed",
        ),
        (
            "UPDATE platform_roles SET created_by = 'someone' WHERE key = 'role:auditor'",
            "its provenance rewritten",
        ),
    ] {
        let sql = sql.to_string();
        let r = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query(&sql).execute(&mut *conn).await;
            (conn, r)
        })
        .await;
        assert_code(&r, "CUS02", what);
    }
    let repoint = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r =
            sqlx::query("UPDATE platform_roles SET role_node_id = $1 WHERE key = 'role:auditor'")
                .bind(other_node)
                .execute(&mut *conn)
                .await;
        (conn, r)
    })
    .await;
    assert!(
        repoint.is_err(),
        "the projection node is never re-pointed: {repoint:?}"
    );
    let described = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(
            "UPDATE platform_roles SET description = 'reads the trail' \
              WHERE key = 'role:auditor'",
        )
        .execute(&mut *conn)
        .await
        .map(|d| d.rows_affected());
        (conn, r)
    })
    .await;
    assert_eq!(described.expect("the description may change"), 1);
    let unchanged: (bool, bool) = sqlx::query_as(
        "SELECT elevates, reads_audit FROM platform_roles WHERE key = 'role:auditor'",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert_eq!(
        unchanged,
        (false, true),
        "the auditor role is what 123 made it"
    );
}

/// The grantor rule counts only LIVE custodians, re-checked as
/// `epigraph_live_role_assignment` answers it: a custodian whose human
/// registration was revoked, or who was linked as an agent, holds nothing,
/// so it neither grants nor blocks the bootstrap (review TST-MTC-10 (a)).
///
/// Verified to fail: the grantor rule's live-custodian test reading the
/// assignment row alone (no holder re-check) -> the bootstrap grant after
/// the only custodian's human was revoked is refused CUS03.
#[sqlx::test(migrations = "../../migrations")]
async fn the_grantor_rule_counts_only_live_custodians(pool: PgPool) {
    let (a, _) = fixture::seed_human_operator(&pool, "a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "b").await;
    maint_insert(&pool, CUSTODIAN, a, "0", None, None)
        .await
        .expect("bootstrap A");
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'test')")
            .bind(a)
            .execute(&mut *conn)
            .await
            .expect("revoke A's human registration");
        (conn, ())
    })
    .await;
    assert_code(
        &maint_insert(&pool, CUSTODIAN, b, "0", None, Some(a)).await,
        "CUS03",
        "a revoked human is no grantor",
    );
    maint_insert(&pool, CUSTODIAN, b, "0", None, None)
        .await
        .expect("with no live custodian left, the bootstrap is admitted again");
}

// =====================================================================
// T4 / T5. Holding a role: bounded in time, bound to its subject.
// =====================================================================

/// `epigraph_holds_role(principal, role, at)` on a privileged session.
async fn holds_at(pool: &PgPool, who: Uuid, role: &str, at: &str) -> bool {
    sqlx::query_scalar(&format!("SELECT public.epigraph_holds_role($1, $2, {at})"))
        .bind(who)
        .bind(role)
        .fetch_one(pool)
        .await
        .expect("holds_role")
}

/// An assignment confers the role on `[valid_from, valid_to)` and nowhere
/// else; an ended assignment confers nothing at any time; and a holder whose
/// human registration is revoked holds nothing, its assignment untouched.
///
/// Verified to fail: `p_at < ra.valid_to` widened to `<=` -> holds at
/// valid_to; `ra.revoked_at IS NULL` dropped -> holds after the revoke; the
/// `epigraph_is_human_operator` re-check dropped -> holds after the human is
/// revoked.
#[sqlx::test(migrations = "../../migrations")]
async fn holding_is_bounded_in_time(pool: PgPool) {
    let (h, _) = fixture::seed_human_operator(&pool, "h").await;
    let (h2, _) = fixture::seed_human_operator(&pool, "h2").await;
    let id = maint_insert(&pool, CUSTODIAN, h, "0", Some("1 day"), None)
        .await
        .expect("grant h");
    let id2 = maint_insert(&pool, CUSTODIAN, h2, "0", None, Some(h))
        .await
        .expect("grant h2");
    let window = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT quote_literal(valid_from) || '::timestamptz', \
                        quote_literal(valid_to) || '::timestamptz' \
                   FROM role_assignments WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("window")
        }
    };
    let (from, to) = window(id).await;
    let to = to.expect("bounded");
    let micro = " - interval '1 microsecond'";
    assert!(
        !holds_at(&pool, h, CUSTODIAN, &format!("{from}{micro}")).await,
        "before"
    );
    assert!(holds_at(&pool, h, CUSTODIAN, &from).await, "at valid_from");
    assert!(
        holds_at(&pool, h, CUSTODIAN, &format!("{to}{micro}")).await,
        "inside"
    );
    assert!(
        !holds_at(&pool, h, CUSTODIAN, &to).await,
        "at valid_to (exclusive)"
    );
    assert!(!holds_at(&pool, h, AUDITOR, &from).await, "another role");
    let assignment: Option<Uuid> =
        sqlx::query_scalar("SELECT public.epigraph_role_assignment_for($1, $2, now())")
            .bind(h)
            .bind(CUSTODIAN)
            .fetch_one(&pool)
            .await
            .expect("assignment_for");
    assert_eq!(assignment, Some(id), "the assignment is named");

    // Ended: nothing, at any time inside the old window.
    maint_exec(
        &pool,
        "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                revoked_reason = 'ended' WHERE id = $1",
        id,
    )
    .await
    .expect("end");
    assert!(
        !holds_at(&pool, h, CUSTODIAN, "now()").await,
        "after the revoke"
    );
    assert!(
        !holds_at(&pool, h, CUSTODIAN, &from).await,
        "the past is re-read too"
    );

    // The human registration revoked: the assignment confers nothing.
    let (from2, _) = window(id2).await;
    assert!(holds_at(&pool, h2, CUSTODIAN, &from2).await, "h2 holds");
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'test')")
            .bind(h2)
            .execute(&mut *conn)
            .await
            .expect("revoke the human");
        (conn, ())
    })
    .await;
    assert!(
        !holds_at(&pool, h2, CUSTODIAN, &from2).await,
        "a revoked human holds nothing"
    );
    let still_live: bool =
        sqlx::query_scalar("SELECT revoked_at IS NULL FROM role_assignments WHERE id = $1")
            .bind(id2)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert!(still_live, "the assignment row itself is untouched");
}

/// The subject is bound in the body (083's rule): an application session
/// learns only about its OWN principal, never about another agent; a
/// privileged session asks about anyone. Unstamped, nothing.
///
/// Verified to fail: `epigraph_definer_bypass()` added as a disjunct of the
/// subject test (it is always true in the definer frame) -> X learns Y's
/// assignment; the principal test dropped -> the same.
#[sqlx::test(migrations = "../../migrations")]
async fn holds_role_is_subject_bound(pool: PgPool) {
    let (x, xg) = fixture::seed_human_operator(&pool, "x").await;
    let (y, yg) = fixture::seed_human_operator(&pool, "y").await;
    let id = maint_insert(&pool, CUSTODIAN, y, "0", None, None)
        .await
        .expect("grant y");
    let ask = |principal: Option<Uuid>, groups: Vec<Uuid>| {
        let pool = pool.clone();
        async move {
            as_app(&pool, principal, &groups, |mut conn| async move {
                let r: (bool, Option<Uuid>) = sqlx::query_as(
                    "SELECT public.epigraph_holds_role($1, $2, now()), \
                            public.epigraph_role_assignment_for($1, $2, now())",
                )
                .bind(y)
                .bind(CUSTODIAN)
                .fetch_one(&mut *conn)
                .await
                .expect("ask");
                (conn, r)
            })
            .await
        }
    };
    assert_eq!(
        ask(Some(x), vec![xg]).await,
        (false, None),
        "X asks about Y"
    );
    assert_eq!(
        ask(None, vec![]).await,
        (false, None),
        "unstamped asks about Y"
    );
    assert_eq!(
        ask(Some(y), vec![yg]).await,
        (true, Some(id)),
        "Y asks about itself"
    );
    let privileged: (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT public.epigraph_holds_role($1, $2, now()), \
                public.epigraph_role_assignment_for($1, $2, now())",
    )
    .bind(y)
    .bind(CUSTODIAN)
    .fetch_one(&pool)
    .await
    .expect("privileged ask");
    assert_eq!(
        privileged,
        (true, Some(id)),
        "a privileged session asks about Y"
    );

    for (func, granted) in [
        ("public.epigraph_holds_role(uuid, text, timestamptz)", true),
        (
            "public.epigraph_role_assignment_for(uuid, text, timestamptz)",
            true,
        ),
        (
            "public.epigraph_live_role_assignment(uuid, text, timestamptz)",
            false,
        ),
    ] {
        let has: bool =
            sqlx::query_scalar("SELECT has_function_privilege('epigraph_app', $1, 'EXECUTE')")
                .bind(func)
                .fetch_one(&pool)
                .await
                .expect("privilege");
        assert_eq!(has, granted, "epigraph_app EXECUTE on {func}");
    }
}

// =====================================================================
// T9. Every assignment change is audited, and the audit is unforgeable.
// =====================================================================

/// `security_events` rows of `event_type` naming `assignment`.
async fn events_for(pool: &PgPool, event_type: &str, assignment: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = $1 AND details->>'assignment_id' = $2::text",
    )
    .bind(event_type)
    .bind(assignment)
    .fetch_one(pool)
    .await
    .expect("events")
}

/// `epigraph_grant_role` on a maintenance session.
async fn grant_role(
    pool: &PgPool,
    role: &str,
    holder: Uuid,
    granted_by: Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    let role = role.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_grant_role($1, $2, NULL, NULL, $3, 'custodian test')",
        )
        .bind(&role)
        .bind(holder)
        .bind(granted_by)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// `epigraph_end_role_assignment` on a maintenance session.
async fn end_role(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query_scalar::<_, bool>(
            "SELECT public.epigraph_end_role_assignment($1, 'custodian test end')",
        )
        .bind(id)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

/// One `platform.role_granted` per grant and one `platform.role_ended` per
/// end, whichever path wrote it (the definers or a raw maintenance
/// statement), naming the assignment. No application session writes a
/// `platform.` row of its own, attributed or not, and no role edits or deletes
/// one. The audit reader answers a role that reads the audit and nobody else.
///
/// Verified to fail: the `role_assignments_audit` trigger not created -> no
/// events; the `security_events_platform_privileged` policy not created -> the
/// application session's forged `platform.custodial_act` lands; the policy's
/// prefix test made case-sensitive again (`left(event_type, 9)`) -> the
/// `Platform.` rows land; its `created_at = now()` test removed -> the
/// back-dated maintenance row lands; the audit reader's role test dropped ->
/// the plain human reads the trail.
#[sqlx::test(migrations = "../../migrations")]
async fn every_assignment_change_is_audited_and_unforgeable(pool: PgPool) {
    let (a, ag) = fixture::seed_human_operator(&pool, "a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "b").await;
    let (c, cg) = fixture::seed_human_operator(&pool, "c").await;
    let (d, dg) = fixture::seed_human_operator(&pool, "d").await;

    let via_definer = grant_role(&pool, CUSTODIAN, a, None)
        .await
        .expect("the definer grants");
    let raw = maint_insert(&pool, CUSTODIAN, b, "0", None, Some(a))
        .await
        .expect("a raw maintenance INSERT");
    let auditor = grant_role(&pool, AUDITOR, c, Some(a))
        .await
        .expect("an auditor");
    for id in [via_definer, raw, auditor] {
        assert_eq!(
            events_for(&pool, "platform.role_granted", id).await,
            1,
            "one grant event for {id}"
        );
    }
    let detail: (Uuid, String, String) = sqlx::query_as(
        "SELECT agent_id, details->>'role', details->>'reason' FROM security_events \
          WHERE event_type = 'platform.role_granted' AND details->>'assignment_id' = $1::text",
    )
    .bind(raw)
    .fetch_one(&pool)
    .await
    .expect("detail");
    assert_eq!(
        detail,
        (b, CUSTODIAN.to_string(), "custodian test".to_string()),
        "the event names the holder, the role and the reason"
    );

    assert!(
        end_role(&pool, via_definer).await.expect("end"),
        "ended now"
    );
    assert!(
        !end_role(&pool, via_definer).await.expect("end again"),
        "an ended assignment reports false and is not re-ended"
    );
    maint_exec(
        &pool,
        "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                revoked_reason = 'raw end' WHERE id = $1",
        raw,
    )
    .await
    .expect("a raw maintenance end");
    for id in [via_definer, raw] {
        assert_eq!(
            events_for(&pool, "platform.role_ended", id).await,
            1,
            "one end event for {id}"
        );
    }

    // Forgery: an application session stamped as a holder writes no
    // `platform.` row, attributed to itself or unattributed.
    let forged = as_app(&pool, Some(c), &[cg], |mut conn| async move {
        let mine = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ('platform.custodial_act', $1, true, '{}'::jsonb)",
        )
        .bind(c)
        .execute(&mut *conn)
        .await;
        let anonymous = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ('platform.role_granted', NULL, true, '{}'::jsonb)",
        )
        .execute(&mut *conn)
        .await;
        let ordinary = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ('platform_lookalike', $1, true, '{}'::jsonb)",
        )
        .bind(c)
        .execute(&mut *conn)
        .await;
        // The reserved prefix ignores case and surrounding blanks (review
        // SEC-MTC-7): these are the prefix, not look-alikes.
        let mut cased = Vec::new();
        for event in [
            "Platform.custodial_act",
            "PLATFORM.role_ended",
            " platform.role_granted",
        ] {
            cased.push(
                sqlx::query(
                    "INSERT INTO security_events (event_type, agent_id, success, details) \
                     VALUES ($1, $2, true, '{}'::jsonb)",
                )
                .bind(event)
                .bind(c)
                .execute(&mut *conn)
                .await
                .map(|_| event),
            );
        }
        (conn, (mine, anonymous, ordinary, cased))
    })
    .await;
    for r in &forged.3 {
        assert_code(
            r,
            "42501",
            "a mixed-case or padded platform. row from the app",
        );
    }
    // A privileged session's platform. row is stamped now(): never back-dated.
    let back_dated = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details, created_at) \
             VALUES ('platform.custodial_act', $1, true, '{}'::jsonb, \
                     '2026-01-01T00:00:00Z'::timestamptz)",
        )
        .bind(a)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_code(
        &back_dated,
        "42501",
        "a back-dated platform. row on the maintenance role",
    );
    assert_code(
        &forged.0,
        "42501",
        "an attributed platform. row from the app",
    );
    assert_code(
        &forged.1,
        "42501",
        "an unattributed platform. row from the app",
    );
    assert!(
        forged.2.is_ok(),
        "the prefix test is exact: other events still land: {:?}",
        forged.2
    );
    for sql in [
        "UPDATE security_events SET details = '{}'::jsonb \
          WHERE event_type = 'platform.role_granted' AND details->>'assignment_id' = $1::text",
        "DELETE FROM security_events \
          WHERE event_type = 'platform.role_granted' AND details->>'assignment_id' = $1::text",
    ] {
        let r = sqlx::query(sql).bind(raw).execute(&pool).await;
        assert!(
            r.is_err(),
            "the audit row is immutable, superuser included: {r:?}"
        );
    }

    // The reader: a custodian or an auditor, as itself; nobody else.
    let read = |who: Uuid, groups: Vec<Uuid>| {
        let pool = pool.clone();
        async move {
            as_app(&pool, Some(who), &groups, |mut conn| async move {
                let n: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM public.epigraph_platform_audit(NULL, 1000)",
                )
                .fetch_one(&mut *conn)
                .await
                .expect("audit reader");
                (conn, n)
            })
            .await
        }
    };
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type LIKE 'platform.%'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert!(total >= 5, "the trail holds every change: {total}");
    assert_eq!(
        read(c, vec![cg]).await,
        total,
        "the auditor reads the trail"
    );
    assert_eq!(read(d, vec![dg]).await, 0, "a plain human reads none of it");
    assert_eq!(
        read(a, vec![ag]).await,
        0,
        "an ENDED custodian reads none of it"
    );

    for (func, app) in [
        (
            "public.epigraph_grant_role(text, uuid, timestamptz, timestamptz, uuid, text)",
            false,
        ),
        ("public.epigraph_end_role_assignment(uuid, text)", false),
        ("public.epigraph_platform_audit(timestamptz, integer)", true),
    ] {
        let (has_app, has_maint): (bool, bool) = sqlx::query_as(
            "SELECT has_function_privilege('epigraph_app', $1, 'EXECUTE'), \
                    has_function_privilege('epigraph_maintenance', $1, 'EXECUTE')",
        )
        .bind(func)
        .fetch_one(&pool)
        .await
        .expect("privilege");
        assert_eq!((has_app, has_maint), (app, true), "EXECUTE on {func}");
    }
}

// =====================================================================
// T10. OCCUPIES is a projection, never an authority.
// =====================================================================

/// The OCCUPIES edge(s) projecting `assignment`:
/// (source, target, valid_from = assignment's, valid_to, never_effective).
async fn projection_of(
    pool: &PgPool,
    assignment: Uuid,
) -> Vec<(Uuid, Uuid, bool, Option<String>, bool)> {
    sqlx::query_as(
        "SELECT e.source_id, e.target_id, e.valid_from = ra.valid_from, \
                e.valid_to::text, COALESCE((e.properties->>'never_effective')::boolean, false) \
           FROM edges e JOIN role_assignments ra ON ra.id = $1 \
          WHERE e.relationship = 'OCCUPIES' \
            AND e.properties @> jsonb_build_object('assignment_id', $1::text)",
    )
    .bind(assignment)
    .fetch_all(pool)
    .await
    .expect("projection")
}

/// Each assignment is projected as ONE `OCCUPIES` edge, holder -> the role's
/// node, carrying the assignment's window in the edge's own
/// `valid_from` / `valid_to`; an end closes it, and an assignment ended before
/// it began is marked `never_effective` (the edge's `temporal_ordering` CHECK
/// needs `valid_to > valid_from`). Deleting the edge changes nothing anyone
/// holds: no policy or definer reads OCCUPIES for authority, and no Rust
/// source mentions it outside a comment. The role node itself is never linked
/// or registered, so it can never become a writer.
///
/// Verified to fail: the projection INSERT removed -> no edge; the revoke's
/// edge UPDATE removed -> the ended assignment's edge stays open; the
/// never-effective branch removed -> the end of a future assignment raises the
/// CHECK; `epigraph_live_role_assignment` reading the edges -> deleting the edge
/// ends the holding (and the catalog ratchet names it); the role-node guard
/// trigger on `operator_links` not created -> the role node is linked.
#[sqlx::test(migrations = "../../migrations")]
async fn occupies_mirrors_assignments_and_is_never_read_for_authz(pool: PgPool) {
    let (a, _) = fixture::seed_human_operator(&pool, "a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "b").await;
    let (c, _) = fixture::seed_human_operator(&pool, "c").await;
    let custodian_node = role_node(&pool, CUSTODIAN).await;
    let auditor_node = role_node(&pool, AUDITOR).await;

    let ia = maint_insert(&pool, CUSTODIAN, a, "0", None, None)
        .await
        .expect("a");
    let ib = maint_insert(&pool, CUSTODIAN, b, "0", Some("30 days"), Some(a))
        .await
        .expect("b");
    let ic = maint_insert(&pool, AUDITOR, c, "1 day", None, Some(a))
        .await
        .expect("c, from tomorrow");
    assert_eq!(
        projection_of(&pool, ia).await,
        vec![(a, custodian_node, true, None, false)],
        "one open edge for A"
    );
    let pb = projection_of(&pool, ib).await;
    assert_eq!(pb.len(), 1, "one edge for B");
    let b_to: Option<String> =
        sqlx::query_scalar("SELECT valid_to::text FROM role_assignments WHERE id = $1")
            .bind(ib)
            .fetch_one(&pool)
            .await
            .expect("b window");
    assert_eq!(
        (pb[0].0, pb[0].1, pb[0].2, pb[0].3.clone()),
        (b, custodian_node, true, b_to),
        "B's edge carries B's window"
    );

    maint_exec(
        &pool,
        "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                revoked_reason = 'ended' WHERE id = $1",
        ia,
    )
    .await
    .expect("end A");
    let closed: bool = sqlx::query_scalar(
        "SELECT e.valid_to = ra.revoked_at FROM edges e JOIN role_assignments ra ON ra.id = $1 \
          WHERE e.relationship = 'OCCUPIES' \
            AND e.properties @> jsonb_build_object('assignment_id', $1::text)",
    )
    .bind(ia)
    .fetch_one(&pool)
    .await
    .expect("closed");
    assert!(closed, "the end closes the edge at revoked_at");

    maint_exec(
        &pool,
        "UPDATE role_assignments SET revoked_at = now(), revoked_by = session_user, \
                revoked_reason = 'never began' WHERE id = $1",
        ic,
    )
    .await
    .expect("end C before it began");
    let pc = projection_of(&pool, ic).await;
    assert_eq!(pc.len(), 1, "C's edge stays");
    assert_eq!(
        (pc[0].0, pc[0].1, pc[0].4),
        (c, auditor_node, true),
        "never effective"
    );

    // The edge is never authority: delete B's, B still holds.
    sqlx::query(
        "DELETE FROM edges WHERE relationship = 'OCCUPIES' \
            AND properties @> jsonb_build_object('assignment_id', $1::text)",
    )
    .bind(ib)
    .execute(&pool)
    .await
    .expect("delete the projection");
    let holds: bool = sqlx::query_scalar(
        "SELECT public.epigraph_holds_role($1, 'role:platform-custodian', now())",
    )
    .bind(b)
    .fetch_one(&pool)
    .await
    .expect("holds");
    assert!(holds, "deleting the projection does not end B's holding");

    // Catalog ratchet: at head, no policy and no function but the projection
    // reads OCCUPIES.
    let readers: Vec<String> = sqlx::query_scalar(
        "SELECT p.proname::text FROM pg_proc p \
          WHERE p.pronamespace = 'public'::regnamespace \
            AND p.prosrc ILIKE '%occupies%' \
            AND p.proname <> 'epigraph_role_assignments_audit' \
         UNION ALL \
         SELECT c.relname || '.' || pol.polname FROM pg_policy pol \
           JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE COALESCE(pg_get_expr(pol.polqual, pol.polrelid), '') ILIKE '%occupies%' \
             OR COALESCE(pg_get_expr(pol.polwithcheck, pol.polrelid), '') ILIKE '%occupies%'",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    assert!(
        readers.is_empty(),
        "OCCUPIES is a projection, never read for authority: {readers:?}"
    );

    // The role node is never a link or registry subject.
    let link = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, custodian_node, a).await
    };
    assert!(link.is_err(), "a role node is never linked: {link:?}");
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ('role-node-client', 'role node', 'human', ARRAY['claims:write'], 'active', $1)",
    )
    .bind(custodian_node)
    .execute(&pool)
    .await
    .expect("a client naming the role node");
    let registered =
        sqlx::query("INSERT INTO human_operators (agent_id, reason) VALUES ($1, 'probe')")
            .bind(custodian_node)
            .execute(&pool)
            .await;
    assert!(
        registered.is_err(),
        "a role node is never registered as a human: {registered:?}"
    );
}

/// No Rust source reads OCCUPIES: a mention outside a `//` comment fails, so
/// authority can never quietly come to depend on the projection.
#[test]
fn no_rust_source_queries_the_occupies_projection() {
    fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("read");
                for (n, line) in text.lines().enumerate() {
                    // The relationship's own spelling, or any spelling next
                    // to the column that names it (an ILIKE probe). Prose
                    // such as a chemistry prompt's "occupies on-top sites"
                    // is neither.
                    let lower = line.to_ascii_lowercase();
                    let names_edge = line.contains("OCCUPIES")
                        || (lower.contains("occupies") && lower.contains("relationship"));
                    if names_edge && !line.trim_start().starts_with("//") {
                        out.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                    }
                }
            }
        }
    }
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut hits = Vec::new();
    for krate in std::fs::read_dir(&crates).expect("crates") {
        let src = krate.expect("crate").path().join("src");
        if src.is_dir() {
            walk(&src, &mut hits);
        }
    }
    assert!(
        hits.is_empty(),
        "OCCUPIES is a projection of role_assignments and is never read for authority; read \
         epigraph_holds_role / epigraph_role_assignment_for instead:\n  {}",
        hits.join("\n  ")
    );
    // CALIBRATION: the walk reaches this crate's sources.
    assert!(crates.join("epigraph-db/src/lib.rs").is_file());
}

// =====================================================================
// T6 / T7. instance_admins: answered from the role, migrated, frozen.
// =====================================================================

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// A plain agent row (no group): enough for an `instance_admins` key.
async fn bare_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("agent");
    id
}

/// A legacy `instance_admins` row, written while the schema is at 122.
async fn legacy_admin(pool: &PgPool, agent: Uuid, granted_at: &str, revoked: bool, note: &str) {
    sqlx::query(&format!(
        "INSERT INTO instance_admins (agent_id, granted_at, revoked_at, note) \
         VALUES ($1, {granted_at}, {}, $2)",
        if revoked { "now()" } else { "NULL" }
    ))
    .bind(agent)
    .bind(note)
    .execute(pool)
    .await
    .expect("legacy instance_admins row");
}

/// `epigraph_is_instance_admin(agent)` and the number of `security_events`
/// rows visible, on an application session stamped as `agent`.
async fn admin_view(pool: &PgPool, agent: Uuid) -> (bool, i64) {
    as_app(pool, Some(agent), &[], |mut conn| async move {
        let r: (bool, i64) = sqlx::query_as(
            "SELECT public.epigraph_is_instance_admin($1), \
                    (SELECT count(*) FROM security_events)",
        )
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("admin view");
        (conn, r)
    })
    .await
}

/// `epigraph_is_instance_admin` answers from `role:platform-custodian` alone.
/// A legacy `instance_admins` row confers nothing (here: a live row of an
/// agent that was not a registered human at migration time, so it was not
/// carried over, and that is registered afterwards). An assignment confers
/// it; its end takes it away. The 083 read arm that keys on the function
/// (`security_events_read`) widens and narrows with it.
///
/// Verified to fail: 083's body left in place (reads `instance_admins`) -> the
/// legacy row alone answers true.
#[sqlx::test(migrations = false)]
async fn is_instance_admin_answers_from_the_role(pool: PgPool) {
    let mut legacy = Uuid::nil();
    fixture::db_at_122_then_head(&pool, &MIGRATOR, |pool| {
        let legacy = &mut legacy;
        async move {
            *legacy = bare_agent(&pool).await;
            legacy_admin(&pool, *legacy, "now()", false, "legacy").await;
        }
    })
    .await;
    // Registered as a human only after 123: the legacy row was skipped.
    fixture::make_human_operator(&pool, legacy).await;
    let (other, _) = fixture::seed_human_operator(&pool, "other").await;
    sqlx::query(
        "INSERT INTO security_events (event_type, agent_id, success) \
         VALUES ('probe.other', $1, true)",
    )
    .bind(other)
    .execute(&pool)
    .await
    .expect("another principal's event");

    let (admin, seen_before) = admin_view(&pool, legacy).await;
    assert!(!admin, "a legacy instance_admins row alone confers nothing");
    let id = grant_role(&pool, CUSTODIAN, legacy, None)
        .await
        .expect("grant");
    let (admin, seen_admin) = admin_view(&pool, legacy).await;
    assert!(admin, "the assignment confers it");
    assert!(
        seen_admin > seen_before,
        "security_events_read widens for a custodian ({seen_before} -> {seen_admin})"
    );
    assert!(end_role(&pool, id).await.expect("end"));
    let (admin, seen_after) = admin_view(&pool, legacy).await;
    assert!(!admin, "the end takes it away");
    assert!(
        seen_after < seen_admin,
        "and the read arm narrows again ({seen_admin} -> {seen_after})"
    );
}

/// Migration 123 carries every LIVE `instance_admins` row of a REGISTERED
/// HUMAN into a `role:platform-custodian` assignment that starts at the
/// row's `granted_at` (and is audited and projected like any grant); a live
/// row of anything else is skipped LOUDLY (a `platform.role_migration_skipped`
/// event; nothing vanishes silently); a revoked row is not carried. After 123
/// the table is frozen for every role, the superuser included, except one
/// change: a `revoked_at` stamp, which ending the role (and revoking the
/// human) mirrors into it, so a rollback to 083's body cannot resurrect it.
///
/// Verified to fail: the seed's human filter dropped -> the non-human gets an
/// assignment; the seed's `operator_links` test dropped -> the linked human
/// is carried; the skipped-row event removed -> no event; the skip reason
/// collapsed to one text -> the suspended human reads as "not registered"
/// (review COR-MTC-3); the freeze trigger not created -> the later INSERT
/// lands; the freeze's `= now()` test removed -> the back-dated stamp lands
/// (review TST-MTC-10 (c)); the freeze's no-live-assignment test removed ->
/// the N-1 revoke of a live custodian reports success (review COR-MTC-1);
/// the role-end mirror removed -> the legacy row stays live; the mirror's
/// "last un-ended assignment" test removed -> ending ONE of two assignments
/// stamps it (review TST-MTC-10 (b)); the human-revoke mirror trigger not
/// created -> the legacy row stays live.
#[sqlx::test(migrations = false)]
async fn instance_admins_is_migrated_then_frozen(pool: PgPool) {
    let mut ids = (Uuid::nil(), Uuid::nil(), Uuid::nil(), Uuid::nil());
    let mut more = (Uuid::nil(), Uuid::nil());
    fixture::db_at_122_then_head(&pool, &MIGRATOR, |pool| {
        let (ids, more) = (&mut ids, &mut more);
        async move {
            let (human, _) = fixture::seed_human_operator(&pool, "legacy-human").await;
            let (second, _) = fixture::seed_human_operator(&pool, "legacy-second").await;
            let (revoked, _) = fixture::seed_human_operator(&pool, "legacy-revoked").await;
            let (suspended, _) = fixture::seed_human_operator(&pool, "legacy-suspended").await;
            let (linked, _) = fixture::seed_human_operator(&pool, "legacy-linked").await;
            sqlx::query("UPDATE oauth_clients SET status = 'suspended' WHERE agent_id = $1")
                .bind(suspended)
                .execute(&pool)
                .await
                .expect("suspend the human's client");
            {
                let mut conn = pool.acquire().await.expect("acquire");
                epigraph_db::AgentRepository::link_operator(&mut conn, linked, human)
                    .await
                    .expect("a registered human linked as another human's agent");
            }
            legacy_admin(&pool, suspended, "now()", false, "suspended client").await;
            legacy_admin(&pool, linked, "now()", false, "linked as an agent").await;
            *more = (suspended, linked);
            let agent = bare_agent(&pool).await;
            legacy_admin(
                &pool,
                human,
                "'2026-01-02T03:04:05Z'::timestamptz",
                false,
                "first operator",
            )
            .await;
            legacy_admin(&pool, second, "now()", false, "second").await;
            legacy_admin(&pool, revoked, "now()", true, "revoked").await;
            legacy_admin(&pool, agent, "now()", false, "an agent").await;
            *ids = (human, second, revoked, agent);
        }
    })
    .await;
    let (human, second, revoked, agent) = ids;
    let (suspended, linked) = more;

    let migrated: Vec<(Uuid, String, bool, String)> = sqlx::query_as(
        "SELECT holder_person_id, role, valid_from = '2026-01-02T03:04:05Z'::timestamptz, \
                granted_via FROM role_assignments ORDER BY valid_from",
    )
    .fetch_all(&pool)
    .await
    .expect("assignments");
    assert_eq!(
        migrated.len(),
        2,
        "the two live human rows, nothing else: {migrated:?}"
    );
    assert_eq!(
        migrated[0],
        (
            human,
            CUSTODIAN.to_string(),
            true,
            "migration 123".to_string()
        ),
        "valid_from = granted_at"
    );
    assert_eq!(migrated[1].0, second);
    let flagged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'platform.role_granted' \
            AND (details->>'migrated')::boolean AND agent_id = $1",
    )
    .bind(human)
    .fetch_one(&pool)
    .await
    .expect("events");
    assert_eq!(flagged, 1, "the carried row is audited as migrated");
    let mut skipped: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT agent_id, details->>'reason' FROM security_events \
          WHERE event_type = 'platform.role_migration_skipped'",
    )
    .fetch_all(&pool)
    .await
    .expect("skipped");
    skipped.sort();
    let mut expected = vec![
        (agent, "not a registered human operator".to_string()),
        (
            suspended,
            "a registered human whose human OAuth client is not active".to_string(),
        ),
        (
            linked,
            "linked to a human operator as its agent".to_string(),
        ),
    ];
    expected.sort();
    assert_eq!(
        skipped, expected,
        "every row not carried is skipped loudly, naming why"
    );
    assert_eq!(
        assignments_of(&pool, revoked).await,
        0,
        "a revoked row is not carried"
    );
    let projected: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship = 'OCCUPIES' AND source_id = $1",
    )
    .bind(human)
    .fetch_one(&pool)
    .await
    .expect("projection");
    assert_eq!(projected, 1, "and projected");

    // Frozen, the superuser included.
    let fresh = bare_agent(&pool).await;
    let insert = sqlx::query("INSERT INTO instance_admins (agent_id) VALUES ($1)")
        .bind(fresh)
        .execute(&pool)
        .await;
    assert_code(&insert, "CUS05", "a new instance_admins row");
    let note = sqlx::query("UPDATE instance_admins SET note = 'edited' WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await;
    assert_code(&note, "CUS05", "an edit of a legacy row");
    let revive = sqlx::query("UPDATE instance_admins SET revoked_at = NULL WHERE agent_id = $1")
        .bind(revoked)
        .execute(&pool)
        .await;
    assert_code(&revive, "CUS05", "reviving a revoked legacy row");
    let back_dated = sqlx::query(
        "UPDATE instance_admins SET revoked_at = now() - interval '1 day' WHERE agent_id = $1",
    )
    .bind(agent)
    .execute(&pool)
    .await;
    assert_code(&back_dated, "CUS05", "a back-dated revoked_at stamp");
    // The N-1 `epigraph-instance-admin revoke` (083's repository SQL) on a
    // LIVE custodian: refused, not a success the role contradicts.
    let old_revoke = sqlx::query(
        "UPDATE instance_admins SET revoked_at = now() WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(second)
    .execute(&pool)
    .await;
    assert_code(&old_revoke, "CUS05", "an old revoke of a live custodian");
    let still: bool = sqlx::query_scalar("SELECT public.epigraph_is_instance_admin($1)")
        .bind(second)
        .fetch_one(&pool)
        .await
        .expect("is_instance_admin");
    assert!(still, "the refused revoke changed nothing");
    sqlx::query("UPDATE instance_admins SET revoked_at = now() WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .expect("the one admitted change: a revoked_at stamp");

    // The mirrors.
    let live_legacy = |who: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT revoked_at IS NULL FROM instance_admins WHERE agent_id = $1",
            )
            .bind(who)
            .fetch_one(&pool)
            .await
            .expect("legacy row")
        }
    };
    let carried: Uuid =
        sqlx::query_scalar("SELECT id FROM role_assignments WHERE holder_person_id = $1")
            .bind(human)
            .fetch_one(&pool)
            .await
            .expect("carried");
    assert!(live_legacy(human).await);
    // A second assignment for the same holder: ending ONE of the two leaves
    // the legacy row live; ending the last stamps it.
    let extra = grant_role(&pool, CUSTODIAN, human, Some(second))
        .await
        .expect("a second assignment for the carried holder");
    assert!(end_role(&pool, carried).await.expect("end"));
    assert!(
        live_legacy(human).await,
        "the holder still holds: its legacy row is not stamped"
    );
    assert!(end_role(&pool, extra).await.expect("end the last"));
    assert!(
        !live_legacy(human).await,
        "ending the last assignment stamps the legacy row"
    );
    assert!(live_legacy(second).await);
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'test')")
            .bind(second)
            .execute(&mut *conn)
            .await
            .expect("revoke the human");
        (conn, ())
    })
    .await;
    assert!(
        !live_legacy(second).await,
        "revoking the human stamps the legacy row"
    );
}

// =====================================================================
// T11. A custodian is never relieved on an application session (OQ-1 (b)).
// =====================================================================

/// Arm the operator binding as the maintenance role would.
async fn arm(pool: &PgPool) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_arm_operator_binding()")
            .execute(&mut *conn)
            .await
            .expect("arm");
        (conn, ())
    })
    .await;
}

/// A `('public', group)` claim by `author` on whatever connection `exec` is.
async fn insert_claim<'e, E>(exec: E, author: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("custodian probe {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(author)
    .bind(group)
    .execute(exec)
    .await?;
    Ok(id)
}

/// `Err` with SQLSTATE `OPL02` whose message carries `fragment`: the check
/// that refused is the one named, not an earlier one.
fn assert_opl02_by<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>, fragment: &str, what: &str) {
    assert_code(r, "OPL02", what);
    let text = r.as_ref().expect_err("refused").to_string();
    assert!(
        text.contains(fragment),
        "{what}: expected the refusal to say {fragment:?}, got {text}"
    );
}

/// Operator ruling OQ-1 (b): the custodial relief from the cross-human scope
/// (OPL02) is `epigraph_bypass()` ONLY, the maintenance DSN on which the
/// audited `epigraph-operator custodial-supersede` runs. A principal that
/// HOLDS role:platform-custodian is relieved of nothing on an application
/// session: at each of 122's five relief points it is refused exactly as any
/// other human is. Holding is not using (DESIGN 6.1a): the app-settable
/// principal stamp never carries admin power across humans.
///
/// The five points, each reached on its OWN check (the message names it):
/// the claims-path writer scope (into another human's group); the attribution
/// arm (in the custodian's own group, a claim attributed to another human's
/// live agent); the retired-attribution arm (the same with another human's
/// RETIRED identity, valve open, so the binding check is out of the way); a
/// re-attribution (its own claim handed to another human's agent); and the
/// membership door (`epigraph_require_operator_scope`, as the request path
/// calls it). A privileged session is relieved at each of the five, and a
/// custodian on an application session leaves no `platform.` relief row.
///
/// Verified to fail: `epigraph_operator_scope_exempt()` given back 122's
/// principal arm (`OR epigraph_is_instance_admin(epigraph_principal_id())`,
/// i.e. OQ-1 (a)) -> the custodian's writer-scope write lands (the five
/// points all read that one function).
#[sqlx::test(migrations = "../../migrations")]
async fn a_custodian_is_never_relieved_on_an_application_session(pool: PgPool) {
    let (k, kg) = fixture::seed_human_operator(&pool, "custodian-k").await;
    let (a, ag) = fixture::seed_human_operator(&pool, "human-a").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "a-live-x").await;
    let (y, _) = fixture::seed_agent_with_group(&pool, "c-live-y").await;
    let (c, _) = fixture::seed_human_operator(&pool, "human-c").await;
    let (l, _) = fixture::seed_agent_with_group(&pool, "a-retired-l").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, x, a)
            .await
            .expect("X live to A");
        epigraph_db::AgentRepository::link_operator(&mut conn, y, c)
            .await
            .expect("Y live to C");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, l, a)
            .await
            .expect("L retired to A");
    }
    fixture::make_custodian(&pool, k).await;
    let k_own = insert_claim(&pool, k, kg).await.expect("K's own claim");
    arm(&pool).await;
    let holds: bool = sqlx::query_scalar(
        "SELECT public.epigraph_live_role_assignment($1, 'role:platform-custodian', now()) \
                IS NOT NULL",
    )
    .bind(k)
    .fetch_one(&pool)
    .await
    .expect("holds");
    assert!(holds, "CALIBRATION: K holds the custodian role");
    let k_sets = [kg, ag];

    // CALIBRATION: K writes its own group on an application session.
    as_app(&pool, Some(k), &k_sets, |mut conn| async move {
        let r = insert_claim(&mut *conn, k, kg).await;
        (conn, r)
    })
    .await
    .expect("K writes its own group");

    // 1. writer_scope: K's own claim in A's group.
    let r = as_app(&pool, Some(k), &k_sets, |mut conn| async move {
        let r = insert_claim(&mut *conn, k, ag).await;
        (conn, r)
    })
    .await;
    assert_opl02_by(&r, "holds no writer/admin membership", "writer_scope");

    // 2. attribution: in K's own group, a claim attributed to A's live X.
    let r = as_app(&pool, Some(k), &k_sets, |mut conn| async move {
        let r = insert_claim(&mut *conn, x, kg).await;
        (conn, r)
    })
    .await;
    assert_opl02_by(&r, "writes a claim attributed to", "attribution");

    // 3. attribution_retired: the same with A's retired L, valve open.
    let r = as_app(&pool, Some(k), &k_sets, |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', 'off', false)")
            .execute(&mut *conn)
            .await
            .expect("open the valve");
        let r = insert_claim(&mut *conn, l, kg).await;
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
            .execute(&mut *conn)
            .await
            .expect("close the valve");
        (conn, r)
    })
    .await;
    assert_opl02_by(&r, "writes a claim attributed to", "attribution_retired");

    // 4. reattribute: K's own claim handed to A's X.
    let r = as_app(&pool, Some(k), &k_sets, |mut conn| async move {
        let r = sqlx::query("UPDATE claims SET agent_id = $2 WHERE id = $1")
            .bind(k_own)
            .bind(x)
            .execute(&mut *conn)
            .await
            .map(|d| d.rows_affected());
        (conn, r)
    })
    .await;
    assert_opl02_by(&r, "does not re-attribute", "reattribute");

    // 5. operator_scope: C's live Y named on a row of A's group, through the
    //    membership door's function as the request path calls it.
    let r = as_app(&pool, Some(k), &k_sets, |mut conn| async move {
        let r = sqlx::query("SELECT public.epigraph_require_operator_scope($1, $2)")
            .bind(y)
            .bind(ag)
            .execute(&mut *conn)
            .await
            .map(|_| ());
        (conn, r)
    })
    .await;
    assert_opl02_by(&r, "a linked agent writes only where", "operator_scope");

    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(k_own)
        .fetch_one(&pool)
        .await
        .expect("author");
    assert_eq!(author, k, "K's claim is still K's");
    let platform_reliefs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE lower(event_type) LIKE 'platform.%' AND event_type NOT IN \
                ('platform.role_granted', 'platform.role_ended')",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(platform_reliefs, 0, "no relief row: nothing was relieved");

    // The custodial path: a PRIVILEGED session is relieved at each point.
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        insert_claim(&mut *conn, k, ag)
            .await
            .expect("bypass: writer_scope");
        sqlx::query("SELECT public.epigraph_require_attributable($1, $2, false)")
            .bind(x)
            .bind(k)
            .execute(&mut *conn)
            .await
            .expect("bypass: attribution");
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', 'off', false)")
            .execute(&mut *conn)
            .await
            .expect("open the valve");
        sqlx::query("SELECT public.epigraph_require_attributable($1, $2, false)")
            .bind(l)
            .bind(k)
            .execute(&mut *conn)
            .await
            .expect("bypass: attribution_retired");
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
            .execute(&mut *conn)
            .await
            .expect("close the valve");
        sqlx::query("UPDATE claims SET agent_id = $2 WHERE id = $1")
            .bind(k_own)
            .bind(x)
            .execute(&mut *conn)
            .await
            .expect("bypass: reattribute");
        sqlx::query("SELECT public.epigraph_require_operator_scope($1, $2)")
            .bind(y)
            .bind(ag)
            .execute(&mut *conn)
            .await
            .expect("bypass: operator_scope");
        (conn, ())
    })
    .await;
}

// =====================================================================
// The repository, and a custodial act names a live assignment of its actor.
// =====================================================================

fn db_code(e: &epigraph_db::DbError) -> Option<String> {
    match e {
        epigraph_db::DbError::QueryFailed { source } => sqlstate(source),
        _ => None,
    }
}

/// `RoleAssignmentRepository` on a DOWNGRADED maintenance connection (so the
/// policies, not the superuser's bypass, admit it): grant, read back, record
/// a custodial act, end. A custodial act is recorded only against a LIVE
/// custodian assignment held by its actor (CUS04 for another holder's, an
/// ended one and one not yet begun) and only for an enumerated act (22023);
/// the application role cannot record one at all. `privatization_authority`
/// names the assignment behind condition 2.
///
/// Verified to fail: the CUS04 holder test (`holder_person_id IS DISTINCT
/// FROM p_actor`) removed -> another holder's assignment records an act; the
/// revoked test removed -> the ended assignment records one; the role test
/// removed -> an AUDITOR assignment records one; the `valid_to` test removed
/// -> the expired assignment records one; the actor's human re-check removed
/// -> a revoked human records one; the actor's link test removed -> a
/// custodian linked as an agent records one (reviews TST-MTC-6, SEC-MTC-9);
/// the `custodian_assignment_id` select dropped (always NULL) -> the
/// authority names nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_custodial_act_names_a_live_assignment_of_its_actor(pool: PgPool) {
    use epigraph_db::repos::instance_admin::InstanceAdminRepository;
    use epigraph_db::RoleAssignmentRepository;

    let (a, a_group) = fixture::seed_human_operator(&pool, "custodian-a").await;
    let (b, _) = fixture::seed_human_operator(&pool, "custodian-b").await;
    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let mut conn = maint.acquire().await.expect("maintenance connection");

    let ia =
        RoleAssignmentRepository::grant(&mut conn, CUSTODIAN, a, None, None, None, "bootstrap")
            .await
            .expect("grant A");
    let ib =
        RoleAssignmentRepository::grant(&mut conn, CUSTODIAN, b, None, None, Some(a), "second")
            .await
            .expect("A grants B");
    let future = RoleAssignmentRepository::grant(
        &mut conn,
        CUSTODIAN,
        b,
        Some(chrono::Utc::now() + chrono::Duration::days(1)),
        None,
        Some(a),
        "from tomorrow",
    )
    .await
    .expect("a future assignment for B");
    assert_eq!(
        RoleAssignmentRepository::live_for(&mut conn, a, CUSTODIAN)
            .await
            .expect("live_for"),
        Some(ia)
    );
    let listed = RoleAssignmentRepository::list(&mut conn, Some(CUSTODIAN), false)
        .await
        .expect("list");
    assert_eq!(listed.len(), 3, "the three un-ended assignments");
    let row = RoleAssignmentRepository::get(&mut conn, ia)
        .await
        .expect("get")
        .expect("row");
    assert_eq!((row.holder_person_id, row.granted_by), (Some(a), None));

    let target = Uuid::new_v4();
    let act = RoleAssignmentRepository::record_custodial_act(
        &mut conn,
        ia,
        a,
        "claim.supersede",
        "claim",
        target,
        serde_json::json!({"reason": "test"}),
    )
    .await
    .expect("A records an act against A's live assignment");
    let named: (String, String, String) = sqlx::query_as(
        "SELECT event_type, details->>'assignment_id', details->>'act' FROM security_events \
          WHERE id = $1",
    )
    .bind(act)
    .fetch_one(&pool)
    .await
    .expect("the act");
    assert_eq!(
        named,
        (
            "platform.custodial_act".to_string(),
            ia.to_string(),
            "claim.supersede".to_string()
        )
    );

    for (assignment, actor, act, code, what) in [
        (
            ib,
            a,
            "claim.supersede",
            "CUS04",
            "another holder's assignment",
        ),
        (
            future,
            b,
            "claim.supersede",
            "CUS04",
            "an assignment not yet begun",
        ),
        (ia, a, "claim.delete", "22023", "an act outside the list"),
    ] {
        let r = RoleAssignmentRepository::record_custodial_act(
            &mut conn,
            assignment,
            actor,
            act,
            "claim",
            target,
            serde_json::json!({}),
        )
        .await;
        let code_seen = r.as_ref().err().and_then(db_code);
        assert_eq!(code_seen.as_deref(), Some(code), "{what}: {r:?}");
    }
    assert!(RoleAssignmentRepository::end(&mut conn, ib, "ended")
        .await
        .expect("end B"));
    let ended = RoleAssignmentRepository::record_custodial_act(
        &mut conn,
        ib,
        b,
        "claim.supersede",
        "claim",
        target,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        ended.as_ref().err().and_then(db_code).as_deref(),
        Some("CUS04"),
        "an ended assignment: {ended:?}"
    );

    // An AUDITOR assignment is no custodial authority; nor is an expired
    // custodian assignment, nor one whose holder's human was revoked or who
    // was linked as an agent (each row itself untouched).
    let (c, _) = fixture::seed_human_operator(&pool, "auditor-c").await;
    let (d, _) = fixture::seed_human_operator(&pool, "expiring-d").await;
    let (e, _) = fixture::seed_human_operator(&pool, "revoked-e").await;
    let (f, _) = fixture::seed_human_operator(&pool, "linked-f").await;
    let auditor =
        RoleAssignmentRepository::grant(&mut conn, AUDITOR, c, None, None, Some(a), "audit")
            .await
            .expect("an auditor");
    let expiring = RoleAssignmentRepository::grant(
        &mut conn,
        CUSTODIAN,
        d,
        None,
        Some(chrono::Utc::now() + chrono::Duration::milliseconds(1500)),
        Some(a),
        "expires in a moment",
    )
    .await
    .expect("a time-bounded custodian");
    let of_e = RoleAssignmentRepository::grant(&mut conn, CUSTODIAN, e, None, None, Some(a), "e")
        .await
        .expect("E");
    let of_f = RoleAssignmentRepository::grant(&mut conn, CUSTODIAN, f, None, None, Some(a), "f")
        .await
        .expect("F");
    sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'test')")
        .bind(e)
        .execute(&mut *conn)
        .await
        .expect("revoke E's human registration");
    // F is linked as A's agent PAST the holder link guard (a superuser with
    // triggers off: the guard refuses a holder's link, CUS01), so the act's
    // own link check is what refuses below.
    link_past_the_guard(&pool, f, a).await;
    sqlx::query("SELECT pg_sleep(2)")
        .execute(&mut *conn)
        .await
        .expect("let the time-bounded assignment expire");
    for (assignment, actor, what) in [
        (auditor, c, "an auditor assignment"),
        (expiring, d, "an assignment past its valid_to"),
        (of_e, e, "a holder whose human was revoked"),
        (of_f, f, "a holder linked as an agent"),
    ] {
        let r = RoleAssignmentRepository::record_custodial_act(
            &mut conn,
            assignment,
            actor,
            "claim.supersede",
            "claim",
            target,
            serde_json::json!({}),
        )
        .await;
        assert_eq!(
            r.as_ref().err().and_then(db_code).as_deref(),
            Some("CUS04"),
            "{what}: {r:?}"
        );
    }

    // The application role records nothing.
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let mut app_conn = app.acquire().await.expect("app connection");
    let refused = RoleAssignmentRepository::record_custodial_act(
        &mut app_conn,
        ia,
        a,
        "claim.supersede",
        "claim",
        target,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        refused.as_ref().err().and_then(db_code).as_deref(),
        Some("42501"),
        "the app role: {refused:?}"
    );

    // privatization_authority names the assignment behind condition 2.
    let authority = InstanceAdminRepository::privatization_authority(&mut conn, a, a_group)
        .await
        .expect("authority");
    assert!(authority.is_instance_admin);
    assert_eq!(authority.custodian_assignment_id, Some(ia));
    let none = InstanceAdminRepository::privatization_authority(&mut conn, b, a_group)
        .await
        .expect("authority");
    assert_eq!(
        (none.is_instance_admin, none.custodian_assignment_id),
        (false, None),
        "B's only live-shaped assignment is not yet begun"
    );
}

// =====================================================================
// T19. The registers know every 123 object.
// =====================================================================

/// Every SECURITY DEFINER migration 123 creates or re-bodies is on
/// `epigraph-tenancy-backfill verify`'s ownership list (a silently no-opped
/// `OWNER TO` is invisible to every behavioural test, because the harness
/// migrates as a superuser), and both new tables are in the API's FORCE
/// register and the 079 kill switch.
///
/// Verified to fail: one `("epigraph_holds_role", 123)` entry removed from
/// `DEFERRED_DEFINER_FUNCTIONS` -> named here.
#[test]
fn every_123_object_is_registered() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    };
    let migration = read("migrations/123_custodian_role.sql");
    let backfill = read("crates/epigraph-cli/src/bin/tenancy_backfill.rs");
    let state = read("crates/epigraph-api/src/state.rs");
    let undo = read("docs/runbooks/079-undo.sql");

    let mut definers = Vec::new();
    let mut rest = migration.as_str();
    while let Some(i) = rest.find("CREATE OR REPLACE FUNCTION public.") {
        let after = &rest[i + "CREATE OR REPLACE FUNCTION public.".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let body_end = after.find("$$;").unwrap_or(after.len());
        let header_end = after.find(" AS $$").unwrap_or(body_end);
        if after[..header_end].contains("SECURITY DEFINER") {
            definers.push(name);
        }
        rest = &after[body_end..];
    }
    definers.sort();
    definers.dedup();
    assert!(
        definers.len() >= 15,
        "CALIBRATION: the scan found only {definers:?}"
    );
    let missing: Vec<&String> = definers
        .iter()
        .filter(|n| !backfill.contains(&format!("(\"{n}\", ")))
        .collect();
    assert!(
        missing.is_empty(),
        "migration 123 definers missing from tenancy_backfill.rs's ownership lists: {missing:?}"
    );
    for table in ["platform_roles", "role_assignments"] {
        assert!(
            state.contains(&format!("\"{table}\"")),
            "state.rs FORCE_PROTECTED_SET lacks {table}"
        );
        assert!(
            undo.contains(&format!("'{table}'")),
            "079-undo.sql lacks {table}"
        );
    }
}

// =====================================================================
// T18. The rollback restores 122 and 083, and resurrects nobody.
// =====================================================================

/// The functions `docs/runbooks/123-undo.sql` restores, by signature.
const RESTORED: &[&str] = &[
    "public.epigraph_is_instance_admin(uuid)",
    "public.epigraph_operator_scope_exempt()",
    "public.epigraph_require_operator_scope(uuid, uuid)",
    "public.epigraph_require_writer_scope(uuid, uuid)",
    "public.epigraph_require_attributable(uuid, uuid, boolean)",
    "public.epigraph_claims_require_operator_binding()",
    "public.epigraph_link_legacy_authors(uuid, uuid[], timestamp with time zone)",
];

async fn functiondefs(pool: &PgPool) -> Vec<String> {
    let mut out = Vec::new();
    for f in RESTORED {
        let def: String = sqlx::query_scalar(&format!(
            "SELECT pg_get_functiondef('{f}'::regprocedure) || \
                    ' owner=' || (SELECT proowner::regrole::text FROM pg_proc \
                                   WHERE oid = '{f}'::regprocedure)"
        ))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{f}: {e}"));
        out.push(def);
    }
    out
}

/// `docs/runbooks/123-undo.sql`, applied to a database that went 122 -> 123,
/// leaves each function 123 re-bodied BYTE-EQUAL (`pg_get_functiondef`, owner
/// included) to the same database's definition at 122, drops every 123
/// definer, and resurrects no authority 123 ended: a custodian whose
/// assignment was ended, and one whose human registration was revoked, are
/// not instance admins under 083's restored body (their legacy rows were
/// stamped by 123's mirrors), nor is an agent 123 skipped (the undo's own
/// belt stamps its row), while a custodian still live keeps it.
///
/// Verified to fail: the undo's re-application of
/// `epigraph_operator_scope_exempt` removed -> its 123 body (`epigraph_bypass()`
/// alone, OQ-1 (b)) stays and differs; 123's role-end mirror removed (and the
/// undo's belt with it) -> the ended custodian is an instance admin again;
/// the undo's belt alone removed -> the skipped agent is one again. (Each of
/// the mirror and the belt alone is covered by the other here; the mirror
/// alone is pinned by `instance_admins_is_migrated_then_frozen`.)
#[sqlx::test(migrations = false)]
async fn the_rollback_restores_122_and_083(pool: PgPool) {
    let mut at_122: Vec<String> = Vec::new();
    let mut ids = (Uuid::nil(), Uuid::nil(), Uuid::nil(), Uuid::nil());
    let mut kept_group = Uuid::nil();
    fixture::db_at_122_then_head(&pool, &MIGRATOR, |pool| {
        let (at_122, ids, kept_group) = (&mut at_122, &mut ids, &mut kept_group);
        async move {
            *at_122 = functiondefs(&pool).await;
            let (ended, _) = fixture::seed_human_operator(&pool, "ended").await;
            let (revoked, _) = fixture::seed_human_operator(&pool, "revoked").await;
            let (kept, kg) = fixture::seed_human_operator(&pool, "kept").await;
            *kept_group = kg;
            let skipped = bare_agent(&pool).await;
            for h in [ended, revoked, kept, skipped] {
                legacy_admin(&pool, h, "now()", false, "pre-123 admin").await;
            }
            *ids = (ended, revoked, kept, skipped);
        }
    })
    .await;
    let (ended, revoked, kept, skipped) = ids;
    let carried: Uuid =
        sqlx::query_scalar("SELECT id FROM role_assignments WHERE holder_person_id = $1")
            .bind(ended)
            .fetch_one(&pool)
            .await
            .expect("the carried assignment");
    assert!(end_role(&pool, carried).await.expect("end"));
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'test')")
            .bind(revoked)
            .execute(&mut *conn)
            .await
            .expect("revoke the human");
        (conn, ())
    })
    .await;
    assert_ne!(
        functiondefs(&pool).await,
        at_122,
        "CALIBRATION: 123 re-bodied these functions"
    );

    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/123-undo.sql"),
    )
    .expect("123-undo.sql");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("the undo script applies");

    let restored = functiondefs(&pool).await;
    for ((f, now), then) in RESTORED.iter().zip(&restored).zip(&at_122) {
        assert_eq!(
            now, then,
            "{f} is not 122's (or 083's) definition after the undo"
        );
    }
    let left: Vec<String> = sqlx::query_scalar(
        "SELECT proname::text FROM pg_proc WHERE pronamespace = 'public'::regnamespace \
            AND proname IN ('epigraph_platform_audit', 'epigraph_holds_role', \
                            'epigraph_role_assignment_for', 'epigraph_grant_role', \
                            'epigraph_record_custodial_act', 'epigraph_live_role_assignment', \
                            'epigraph_instance_admins_frozen')",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    assert!(left.is_empty(), "123 definers left behind: {left:?}");

    for (who, expected, what) in [
        (ended, false, "a custodian whose assignment was ended"),
        (
            revoked,
            false,
            "a custodian whose human registration was revoked",
        ),
        (kept, true, "a custodian still live"),
        (
            skipped,
            false,
            "an agent 123 skipped (agents never hold the role; only the undo's belt \
             stamps its legacy row, since no assignment ever mirrored into it)",
        ),
    ] {
        let admin: bool = sqlx::query_scalar("SELECT public.epigraph_is_instance_admin($1)")
            .bind(who)
            .fetch_one(&pool)
            .await
            .expect("083's body");
        assert_eq!(admin, expected, "{what}");
    }

    // 122's BEHAVIOUR, not only its bodies (review TST-MTC-12): the freeze,
    // the `platform.` reservation and the self-supersede refusal are gone, so
    // no 123 trigger or policy was left attached.
    let fresh = bare_agent(&pool).await;
    sqlx::query("INSERT INTO instance_admins (agent_id, note) VALUES ($1, 'after the undo')")
        .bind(fresh)
        .execute(&pool)
        .await
        .expect("instance_admins takes a row again (083)");
    let from_app = as_app(&pool, Some(kept), &[], |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success) \
             VALUES ('platform.probe', $1, true)",
        )
        .bind(kept)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert!(
        from_app.is_ok(),
        "the platform. reservation is gone: {from_app:?}"
    );
    let probe = insert_claim(&pool, kept, kept_group)
        .await
        .expect("a claim");
    sqlx::query("UPDATE claims SET supersedes = id WHERE id = $1")
        .bind(probe)
        .execute(&pool)
        .await
        .expect("122 has no self-supersede refusal");
    let left_triggers: Vec<String> = sqlx::query_scalar(
        "SELECT tgname::text FROM pg_trigger WHERE NOT tgisinternal AND tgname IN \
            ('instance_admins_frozen', 'human_operators_mirror_instance_admins', \
             'human_operators_refuse_role_node', 'operator_links_refuse_role_node', \
             'operator_links_refuse_role_holder', \
             'role_assignments_audit', 'role_assignments_guard_insert', \
             'role_assignments_guard_update', 'platform_roles_guard_update')",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    assert!(
        left_triggers.is_empty(),
        "123 triggers left behind: {left_triggers:?}"
    );
}
