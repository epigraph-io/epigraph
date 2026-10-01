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
/// human's is refused.
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
        assert_eq!(assignments_of(&pool, agent).await, 0, "{what} holds nothing");
    }
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
            let held: bool = sqlx::query_scalar("SELECT has_table_privilege('epigraph_app', $1, $2)")
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
    assert_eq!(seen, vec![h], "a stamped app session reads its own rows only");

    let unstamped: Vec<Uuid> = as_app(&pool, None, &[], |mut conn| async move {
        let seen = sqlx::query_scalar("SELECT holder_person_id FROM role_assignments")
            .fetch_all(&mut *conn)
            .await
            .expect("app SELECT");
        (conn, seen)
    })
    .await;
    assert!(unstamped.is_empty(), "an unstamped app session reads none: {unstamped:?}");
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
    sqlx::query_scalar(&format!(
        "SELECT public.epigraph_holds_role($1, $2, {at})"
    ))
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
    assert_eq!(ask(Some(x), vec![xg]).await, (false, None), "X asks about Y");
    assert_eq!(ask(None, vec![]).await, (false, None), "unstamped asks about Y");
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
/// application session's forged `platform.custodial_act` lands; the audit
/// reader's role test dropped -> the plain human reads the trail.
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

    assert!(end_role(&pool, via_definer).await.expect("end"), "ended now");
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
        (conn, (mine, anonymous, ordinary))
    })
    .await;
    assert_code(&forged.0, "42501", "an attributed platform. row from the app");
    assert_code(&forged.1, "42501", "an unattributed platform. row from the app");
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
        assert!(r.is_err(), "the audit row is immutable, superuser included: {r:?}");
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
    assert_eq!(read(c, vec![cg]).await, total, "the auditor reads the trail");
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
