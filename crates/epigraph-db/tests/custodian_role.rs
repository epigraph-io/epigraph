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
/// `epigraph_live_role_assignment` -> the custodian linked after its grant
/// still holds.
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
    maint_insert(&pool, CUSTODIAN, later, "0", None, Some(human))
        .await
        .expect("an unlinked registered human is granted");
    assert!(holds_at(&pool, later, CUSTODIAN, "now()").await, "it holds");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, later, human)
            .await
            .expect("link the custodian as an agent");
    }
    assert!(
        !holds_at(&pool, later, CUSTODIAN, "now()").await,
        "a custodian linked as an agent holds nothing"
    );
    let admin: bool = sqlx::query_scalar("SELECT public.epigraph_is_instance_admin($1)")
        .bind(later)
        .fetch_one(&pool)
        .await
        .expect("is_instance_admin");
    assert!(!admin, "nor is it an instance admin");
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
/// `valid_to` / holder / role edits land; the `revoked_at = now()` test
/// removed -> the back-dated revoke lands; the back-date test on
/// `valid_from` removed -> the back-dated grant lands; a `FOR DELETE` policy
/// added -> the catalog arm fails.
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
    assert_code(
        &maint_exec(
            &pool,
            "UPDATE role_assignments SET revoked_reason = 'again' WHERE id = $1",
            id,
        )
        .await,
        "CUS02",
        "a second revoke",
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
/// assignment; the skipped-row event removed -> no event; the freeze trigger
/// not created -> the later INSERT lands; the role-end mirror removed -> the
/// legacy row stays live; the human-revoke mirror trigger not created -> the
/// same.
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
    assert!(end_role(&pool, carried).await.expect("end"));
    assert!(
        !live_legacy(human).await,
        "ending the role stamps the legacy row"
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
// T11. A custodian's relief from the cross-human scope is audited.
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

async fn relief_events(pool: &PgPool) -> Vec<(Option<Uuid>, String, Option<String>)> {
    sqlx::query_as(
        "SELECT agent_id, details->>'check', details->>'assignment_id' FROM security_events \
          WHERE event_type = 'platform.custodial_exempt' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("relief events")
}

/// Once armed, a principal that holds the custodian role is relieved of the
/// cross-human scope (OPL02) on an application session, and EVERY relief it
/// actually receives is one `platform.custodial_exempt` row naming the
/// assignment and the check. A privileged session's relief is not audited
/// (it is the operator's own login); a non-custodian is refused OPL02 and
/// leaves nothing. A refused write's relief rolls back with it.
///
/// Verified to fail: the relief's audit INSERT removed -> no event; the
/// bypass arm made to audit too -> a second event; the relief keyed on
/// `epigraph_bypass()` only (OQ-1 (b)) -> the custodian is refused OPL02.
/// NOT caught behaviourally: `epigraph_require_writer_scope` left STABLE.
/// Measured on the test cluster, a STABLE plpgsql function that calls a
/// VOLATILE one which INSERTs does not error; `schema_contract.rs` pins the
/// `provolatile` of the three checks instead.
#[sqlx::test(migrations = "../../migrations")]
async fn custodial_relief_is_audited_with_the_assignment(pool: PgPool) {
    let (a, _) = fixture::seed_human_operator(&pool, "custodian-a").await;
    let (b, bg) = fixture::seed_human_operator(&pool, "human-b").await;
    let (c, cg) = fixture::seed_human_operator(&pool, "human-c").await;
    let assignment = fixture::make_custodian(&pool, a).await;
    arm(&pool).await;

    let crossed = as_app(&pool, Some(a), &[bg], |mut conn| async move {
        let r = insert_claim(&mut *conn, a, bg).await;
        (conn, r)
    })
    .await;
    assert!(
        crossed.is_ok(),
        "a custodian writes into a group its human does not write: {crossed:?}"
    );
    assert_eq!(
        relief_events(&pool).await,
        vec![(
            Some(a),
            "writer_scope".to_string(),
            Some(assignment.to_string())
        )],
        "exactly one relief row, naming the assignment"
    );

    // A privileged session's relief is not a custodial act.
    insert_claim(&pool, a, bg)
        .await
        .expect("the superuser writes A's claim into B's group");
    assert_eq!(relief_events(&pool).await.len(), 1, "no row for bypass");

    // A non-custodian is refused, and leaves nothing.
    let refused = as_app(&pool, Some(c), &[cg, bg], |mut conn| async move {
        let r = insert_claim(&mut *conn, c, bg).await;
        (conn, r)
    })
    .await;
    assert_code(&refused, "OPL02", "a human who is no custodian");
    // A custodian's write refused for ANOTHER reason (an unbound author:
    // OPL01, after the scope check already relieved it) rolls its relief row
    // back with it.
    let (unbound, _) = fixture::seed_agent_with_group(&pool, "unbound").await;
    let rolled_back = as_app(&pool, Some(a), &[bg], |mut conn| async move {
        let r = insert_claim(&mut *conn, unbound, bg).await;
        (conn, r)
    })
    .await;
    assert_code(
        &rolled_back,
        "OPL01",
        "an unbound author, even for a custodian",
    );
    assert_eq!(
        relief_events(&pool).await.len(),
        1,
        "a refused write leaves no relief row"
    );
    let _ = b;
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
/// revoked test removed -> the ended assignment records one; the
/// `custodian_assignment_id` select dropped (always NULL) -> the authority
/// names nothing.
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
/// `epigraph_require_writer_scope` removed -> its 123 body (VOLATILE, the
/// audited relief) stays and differs; 123's role-end mirror removed (and the
/// undo's belt with it) -> the ended custodian is an instance admin again;
/// the undo's belt alone removed -> the skipped agent is one again. (Each of
/// the mirror and the belt alone is covered by the other here; the mirror
/// alone is pinned by `instance_admins_is_migrated_then_frozen`.)
#[sqlx::test(migrations = false)]
async fn the_rollback_restores_122_and_083(pool: PgPool) {
    let mut at_122: Vec<String> = Vec::new();
    let mut ids = (Uuid::nil(), Uuid::nil(), Uuid::nil(), Uuid::nil());
    fixture::db_at_122_then_head(&pool, &MIGRATOR, |pool| {
        let (at_122, ids) = (&mut at_122, &mut ids);
        async move {
            *at_122 = functiondefs(&pool).await;
            let (ended, _) = fixture::seed_human_operator(&pool, "ended").await;
            let (revoked, _) = fixture::seed_human_operator(&pool, "revoked").await;
            let (kept, _) = fixture::seed_human_operator(&pool, "kept").await;
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
            AND proname IN ('epigraph_custodial_relief', 'epigraph_holds_role', \
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
}
