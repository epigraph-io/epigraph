//! Migration 356 (backlog d7ee64a6): the declared agent scopes record, its
//! arming flag and its two audited maintenance verbs. No write door reads any
//! of it yet; these tests pin the record itself.
//!
//! * `the_app_role_holds_no_privilege_on_agent_scopes`: the application role
//!   can neither SELECT, INSERT, UPDATE, DELETE nor TRUNCATE `agent_scopes`,
//!   read from the catalog AND measured as the role (42501 each), with a
//!   calibration read of `agent_scope_arming` on the same session.
//! * `the_app_role_cannot_call_the_verbs`: no EXECUTE on either verb (42501),
//!   and with EXECUTE granted by a drifted migration the bodies still refuse a
//!   non-maintenance session (42501, `AGS02`).
//! * `grant_and_revoke_each_write_exactly_one_audit_row`: on the maintenance
//!   role a grant writes one row and exactly one `security_events` row
//!   (`platform.agent_scope_granted`, naming the scope), a revoke exactly one
//!   (`platform.agent_scope_revoked`), and a second revoke of the same scope
//!   changes nothing and writes nothing.
//! * `arming_is_installed_off_and_only_a_superuser_moves_it`: one row,
//!   `armed = false`; neither the application nor the maintenance role can
//!   insert, update or delete it.
//! * `the_record_refuses_what_the_model_forbids`: an unknown action class, a
//!   blank reason, a human as the agent, a second un-revoked row for the same
//!   key, another agent's role attachment, an edit other than the revoke, a
//!   DELETE and a TRUNCATE are each refused.
//! * `the_356_undo_returns_the_catalog_below_356`: `docs/runbooks/356-undo.sql`
//!   leaves the `public` catalog exactly as it was below 356, and a second run
//!   changes nothing.
//!
//! # Verified to fail
//!
//! Each mutation of migration 356 applied alone, then restored:
//!
//! * the `REVOKE ALL ON public.agent_scopes FROM epigraph_app` dropped: fails
//!   `the_app_role_holds_no_privilege_on_agent_scopes` (077's default
//!   privileges hand the role SELECT, INSERT, UPDATE and DELETE).
//! * `GRANT EXECUTE` on both verbs to `epigraph_app` instead of the REVOKE:
//!   fails `the_app_role_cannot_call_the_verbs` (the catalog arm; the body
//!   arm still refuses, which is the test's second half).
//! * the verbs' session check removed: fails the second half of
//!   `the_app_role_cannot_call_the_verbs` (the drifted grant then writes a
//!   scope from the application session).
//! * a second grant INSERT in the audit trigger: fails
//!   `grant_and_revoke_each_write_exactly_one_audit_row` ("a grant writes one
//!   event"); the revoke arm disabled: fails it at "a revoke writes one event".
//! * the arming row seeded `armed = true`: fails
//!   `arming_is_installed_off_and_only_a_superuser_moves_it` (and the
//!   calibration read in `the_app_role_holds_no_privilege_on_agent_scopes`).
//! * the guard's role-attachment arm removed: fails
//!   `the_record_refuses_what_the_model_forbids`.
//!
//! Before 356 every test here fails on the missing relation or function; the
//! mutations above are what show each assertion is not vacuous.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const APP: &str = "epigraph_app";
const MAINT: &str = "epigraph_maintenance";

/// The SQLSTATE of a failed statement, or a panic naming the success.
fn sqlstate<T: std::fmt::Debug>(r: Result<T, sqlx::Error>, what: &str) -> (String, String) {
    match r {
        Ok(v) => panic!("{what}: expected a refusal, got {v:?}"),
        Err(e) => {
            let db = e
                .as_database_error()
                .unwrap_or_else(|| panic!("{what}: not a database error: {e}"));
            (
                db.code().map(|c| c.to_string()).unwrap_or_default(),
                db.message().to_string(),
            )
        }
    }
}

/// Run `sql` (no binds; ids are formatted in by the test) as `role`.
async fn exec_as(pool: &PgPool, role: &str, sql: String) -> Result<u64, sqlx::Error> {
    fixture::as_role(pool, role, |mut conn| async move {
        let r = sqlx::query(&sql)
            .execute(&mut *conn)
            .await
            .map(|d| d.rows_affected());
        (conn, r)
    })
    .await
}

/// Fetch one scalar of `sql` as `role`.
async fn scalar_as<T>(pool: &PgPool, role: &str, sql: String) -> Result<T, sqlx::Error>
where
    T: Send + Unpin + for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
    T: 'static,
{
    fixture::as_role(pool, role, |mut conn| async move {
        let r = sqlx::query_scalar::<_, T>(&sql).fetch_one(&mut *conn).await;
        (conn, r)
    })
    .await
}

/// An agent identity (not a human) and a group to declare it in.
async fn agent_and_group(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    fixture::seed_agent_with_group(pool, label).await
}

async fn grant_as_maintenance(pool: &PgPool, agent: Uuid, group: Uuid, class: &str) -> Uuid {
    scalar_as::<Uuid>(
        pool,
        MAINT,
        format!(
            "SELECT public.epigraph_agent_scope_grant('{agent}', '{group}', '{class}', \
             'test grant', NULL, NULL, NULL)"
        ),
    )
    .await
    .expect("the maintenance role grants a scope")
}

/// Every `security_events` row, counted on the harness (superuser) pool.
async fn events_total(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*)::bigint FROM public.security_events")
        .fetch_one(pool)
        .await
        .expect("count events")
}

async fn events_for(pool: &PgPool, event_type: &str, scope: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*)::bigint FROM public.security_events \
          WHERE event_type = $1 AND details ->> 'scope_id' = $2::text",
    )
    .bind(event_type)
    .bind(scope)
    .fetch_one(pool)
    .await
    .expect("count scope events")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_holds_no_privilege_on_agent_scopes(pool: PgPool) {
    for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"] {
        let has: bool = sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
            .bind(APP)
            .bind("public.agent_scopes")
            .bind(privilege)
            .fetch_one(&pool)
            .await
            .expect("privilege probe");
        assert!(!has, "{APP} holds {privilege} on agent_scopes");
    }
    // CALIBRATION: the same probe sees the role's ordinary grants, so a false
    // above is not a role that holds nothing anywhere.
    let calibration: bool =
        sqlx::query_scalar("SELECT has_table_privilege($1, 'public.claims', 'SELECT')")
            .bind(APP)
            .fetch_one(&pool)
            .await
            .expect("calibration probe");
    assert!(calibration, "CALIBRATION: {APP} reads claims");

    let (agent, group) = agent_and_group(&pool, "scope-app").await;
    let scope = grant_as_maintenance(&pool, agent, group, "edge_write").await;

    // CALIBRATION: the application session works and reads what it may.
    let armed = scalar_as::<bool>(
        &pool,
        APP,
        "SELECT armed FROM public.agent_scope_arming".into(),
    )
    .await
    .expect("CALIBRATION: the application role reads the arming flag");
    assert!(!armed);

    for (what, sql) in [
        (
            "SELECT",
            "SELECT count(*) FROM public.agent_scopes".to_string(),
        ),
        (
            "INSERT",
            format!(
                "INSERT INTO public.agent_scopes (agent_id, group_id, action_class, reason) \
                 VALUES ('{agent}', '{group}', 'claim_write', 'forged')"
            ),
        ),
        (
            "UPDATE",
            format!(
                "UPDATE public.agent_scopes SET action_class = 'group_admin' WHERE id = '{scope}'"
            ),
        ),
        (
            "DELETE",
            format!("DELETE FROM public.agent_scopes WHERE id = '{scope}'"),
        ),
        ("TRUNCATE", "TRUNCATE public.agent_scopes".to_string()),
    ] {
        let (code, msg) = sqlstate(exec_as(&pool, APP, sql).await, what);
        assert_eq!(code, "42501", "{APP} {what} on agent_scopes: {msg}");
    }

    // Nothing the application tried changed the record.
    let (class, revoked): (String, bool) = sqlx::query_as(
        "SELECT action_class, revoked_at IS NOT NULL FROM public.agent_scopes WHERE id = $1",
    )
    .bind(scope)
    .fetch_one(&pool)
    .await
    .expect("the scope row");
    assert_eq!((class.as_str(), revoked), ("edge_write", false));
    let rows: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM public.agent_scopes")
        .fetch_one(&pool)
        .await
        .expect("count scopes");
    assert_eq!(rows, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_call_the_verbs(pool: PgPool) {
    const GRANT_SIG: &str = "public.epigraph_agent_scope_grant(uuid, uuid, text, text, \
                             timestamptz, timestamptz, uuid)";
    const REVOKE_SIG: &str = "public.epigraph_agent_scope_revoke(uuid, text)";
    for (role, sig, expected) in [
        (APP, GRANT_SIG, false),
        (APP, REVOKE_SIG, false),
        (MAINT, GRANT_SIG, true),
        (MAINT, REVOKE_SIG, true),
    ] {
        let has: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
            .bind(role)
            .bind(sig)
            .fetch_one(&pool)
            .await
            .expect("function privilege probe");
        assert_eq!(has, expected, "{role} EXECUTE on {sig}");
    }

    let (agent, group) = agent_and_group(&pool, "scope-verbs").await;
    let scope = grant_as_maintenance(&pool, agent, group, "claim_write").await;
    let grant_sql = format!(
        "SELECT public.epigraph_agent_scope_grant('{agent}', '{group}', 'label_write', \
         'from the app', NULL, NULL, NULL)::text"
    );
    let revoke_sql =
        format!("SELECT public.epigraph_agent_scope_revoke('{scope}', 'from the app')::text");

    for (what, sql) in [("grant", grant_sql.clone()), ("revoke", revoke_sql.clone())] {
        let (code, msg) = sqlstate(scalar_as::<String>(&pool, APP, sql).await, what);
        assert_eq!(code, "42501", "{APP} calls the {what} verb: {msg}");
    }

    // A later migration that grants EXECUTE too widely still opens nothing:
    // the bodies refuse a session that is not maintenance.
    for sig in [GRANT_SIG, REVOKE_SIG] {
        sqlx::query(&format!("GRANT EXECUTE ON FUNCTION {sig} TO {APP}"))
            .execute(&pool)
            .await
            .expect("simulate a drifted grant");
    }
    for (what, sql) in [("grant", grant_sql), ("revoke", revoke_sql)] {
        let (code, msg) = sqlstate(scalar_as::<String>(&pool, APP, sql).await, what);
        assert_eq!(
            code, "42501",
            "the {what} body refuses the application session: {msg}"
        );
        assert!(msg.starts_with("AGS02:"), "{what}: {msg}");
    }
    let (rows, live): (i64, i64) = sqlx::query_as(
        "SELECT count(*)::bigint, count(*) FILTER (WHERE revoked_at IS NULL)::bigint \
           FROM public.agent_scopes",
    )
    .fetch_one(&pool)
    .await
    .expect("count scopes");
    assert_eq!((rows, live), (1, 1), "the application changed nothing");
}

#[sqlx::test(migrations = "../../migrations")]
async fn grant_and_revoke_each_write_exactly_one_audit_row(pool: PgPool) {
    let (agent, group) = agent_and_group(&pool, "scope-audit").await;

    let before = events_total(&pool).await;
    let scope = grant_as_maintenance(&pool, agent, group, "evidence_write").await;
    assert_eq!(
        events_total(&pool).await - before,
        1,
        "a grant writes one event"
    );
    assert_eq!(
        events_for(&pool, "platform.agent_scope_granted", scope).await,
        1,
        "the one event is the grant's, naming the scope"
    );
    let (ev_agent, ev_class, ev_by): (Option<Uuid>, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT agent_id, details ->> 'action_class', details ->> 'granted_by' \
               FROM public.security_events \
              WHERE event_type = 'platform.agent_scope_granted' \
                AND details ->> 'scope_id' = $1::text",
        )
        .bind(scope)
        .fetch_one(&pool)
        .await
        .expect("the grant event");
    assert_eq!(
        (ev_agent, ev_class.as_deref(), ev_by.as_deref()),
        (Some(agent), Some("evidence_write"), Some(MAINT))
    );

    // The maintenance session reads the row it wrote, recorded as its own.
    let granted_by = scalar_as::<String>(
        &pool,
        MAINT,
        format!("SELECT granted_by FROM public.agent_scopes WHERE id = '{scope}'"),
    )
    .await
    .expect("the maintenance role reads the scope");
    assert_eq!(granted_by, MAINT);

    let before = events_total(&pool).await;
    let revoked = scalar_as::<bool>(
        &pool,
        MAINT,
        format!("SELECT public.epigraph_agent_scope_revoke('{scope}', 'test revoke')"),
    )
    .await
    .expect("the maintenance role revokes");
    assert!(revoked, "the first revoke revokes");
    assert_eq!(
        events_total(&pool).await - before,
        1,
        "a revoke writes one event"
    );
    assert_eq!(
        events_for(&pool, "platform.agent_scope_revoked", scope).await,
        1,
        "the one event is the revoke's, naming the scope"
    );
    let (revoked_by, reason): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT revoked_by, revoke_reason FROM public.agent_scopes WHERE id = $1")
            .bind(scope)
            .fetch_one(&pool)
            .await
            .expect("the revoked row");
    assert_eq!(
        (revoked_by.as_deref(), reason.as_deref()),
        (Some(MAINT), Some("test revoke"))
    );

    // A second revoke of the same scope changes nothing and writes nothing.
    let before = events_total(&pool).await;
    let again = scalar_as::<bool>(
        &pool,
        MAINT,
        format!("SELECT public.epigraph_agent_scope_revoke('{scope}', 'again')"),
    )
    .await
    .expect("a repeated revoke is answered, not refused");
    assert!(!again, "a repeated revoke reports it revoked nothing");
    assert_eq!(events_total(&pool).await, before, "and writes no event");

    // A revoked key may be granted again, as a new row with its own event.
    let before = events_total(&pool).await;
    let regrant = grant_as_maintenance(&pool, agent, group, "evidence_write").await;
    assert_ne!(regrant, scope);
    assert_eq!(events_total(&pool).await - before, 1);

    // An unknown scope is not silently "already revoked".
    let (code, _) = sqlstate(
        scalar_as::<bool>(
            &pool,
            MAINT,
            format!(
                "SELECT public.epigraph_agent_scope_revoke('{}', 'nothing')",
                Uuid::new_v4()
            ),
        )
        .await,
        "revoke of an unknown scope",
    );
    assert_eq!(code, "P0002");
}

#[sqlx::test(migrations = "../../migrations")]
async fn arming_is_installed_off_and_only_a_superuser_moves_it(pool: PgPool) {
    let rows: Vec<(bool, bool)> =
        sqlx::query_as("SELECT singleton, armed FROM public.agent_scope_arming")
            .fetch_all(&pool)
            .await
            .expect("arming rows");
    assert_eq!(rows, vec![(true, false)], "one row, disarmed");

    for role in [APP, MAINT] {
        for (what, sql) in [
            (
                "UPDATE",
                "UPDATE public.agent_scope_arming SET armed = true",
            ),
            (
                "INSERT",
                "INSERT INTO public.agent_scope_arming (singleton, armed, reason) \
                 VALUES (true, true, 'forged')",
            ),
            ("DELETE", "DELETE FROM public.agent_scope_arming"),
        ] {
            let (code, msg) = sqlstate(exec_as(&pool, role, sql.into()).await, what);
            assert_eq!(code, "42501", "{role} {what} on agent_scope_arming: {msg}");
        }
    }
    let armed: bool = sqlx::query_scalar("SELECT armed FROM public.agent_scope_arming")
        .fetch_one(&pool)
        .await
        .expect("arming");
    assert!(!armed, "still disarmed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_record_refuses_what_the_model_forbids(pool: PgPool) {
    let (agent, group) = agent_and_group(&pool, "scope-guard").await;
    let grant = |class: &str, reason: &str, attachment: Option<Uuid>, who: Uuid| {
        let attachment = attachment
            .map(|a| format!("'{a}'::uuid"))
            .unwrap_or_else(|| "NULL".into());
        format!(
            "SELECT public.epigraph_agent_scope_grant('{who}', '{group}', '{class}', \
             '{reason}', NULL, NULL, {attachment})"
        )
    };

    // An action class outside the closed set.
    let (code, msg) = sqlstate(
        scalar_as::<Uuid>(&pool, MAINT, grant("read_everything", "r", None, agent)).await,
        "unknown class",
    );
    assert_eq!(code, "23514", "{msg}");

    // A blank reason.
    let (code, msg) = sqlstate(
        scalar_as::<Uuid>(&pool, MAINT, grant("claim_write", "   ", None, agent)).await,
        "blank reason",
    );
    assert_eq!(code, "22004", "{msg}");

    // A human is not given declared scopes.
    let (human, _) = fixture::seed_human_operator(&pool, "scope-human").await;
    let (code, msg) = sqlstate(
        scalar_as::<Uuid>(&pool, MAINT, grant("claim_write", "r", None, human)).await,
        "human agent",
    );
    assert_eq!(code, "55000", "{msg}");
    assert!(msg.starts_with("AGS02:"), "{msg}");

    // One un-revoked row per (agent, group, class).
    let scope = grant_as_maintenance(&pool, agent, group, "claim_write").await;
    let (code, msg) = sqlstate(
        scalar_as::<Uuid>(&pool, MAINT, grant("claim_write", "again", None, agent)).await,
        "duplicate",
    );
    assert_eq!(code, "23505", "{msg}");

    // A scope rides only the SAME agent's live role attachment.
    let (other, _) = agent_and_group(&pool, "scope-other").await;
    // Written directly on the harness pool: the attach verb also requires a
    // host registration (ROL03), which is not what this test is about; 166's
    // table guard still checks the row.
    let attachment: Uuid = sqlx::query_scalar(
        "INSERT INTO public.role_agents (role, agent_id, reason) \
         VALUES ('role:auditor', $1, 'test attach') RETURNING id",
    )
    .bind(other)
    .fetch_one(&pool)
    .await
    .expect("attach the other agent");
    let (code, msg) = sqlstate(
        scalar_as::<Uuid>(
            &pool,
            MAINT,
            grant("edge_write", "r", Some(attachment), agent),
        )
        .await,
        "another agent's attachment",
    );
    assert_eq!(code, "55000", "{msg}");
    assert!(msg.starts_with("AGS02:"), "{msg}");
    // CALIBRATION: the attachment's own agent may ride it.
    scalar_as::<Uuid>(
        &pool,
        MAINT,
        grant("edge_write", "r", Some(attachment), other),
    )
    .await
    .expect("CALIBRATION: the attached agent's own scope rides its attachment");

    // The maintenance role edits nothing but the revoke columns.
    let (code, msg) = sqlstate(
        exec_as(
            &pool,
            MAINT,
            format!(
                "UPDATE public.agent_scopes SET action_class = 'group_admin' WHERE id = '{scope}'"
            ),
        )
        .await,
        "widen a scope",
    );
    assert_eq!(code, "42501", "{msg}");
    // A revoke that names someone else as the revoker is refused.
    let (code, msg) = sqlstate(
        exec_as(
            &pool,
            MAINT,
            format!(
                "UPDATE public.agent_scopes SET revoked_at = now(), revoked_by = 'someone', \
                 revoke_reason = 'r' WHERE id = '{scope}'"
            ),
        )
        .await,
        "forged revoker",
    );
    assert_eq!(code, "55000", "{msg}");

    // Nobody deletes or truncates a scope, the superuser included.
    for (what, sql) in [
        (
            "DELETE",
            format!("DELETE FROM public.agent_scopes WHERE id = '{scope}'"),
        ),
        ("TRUNCATE", "TRUNCATE public.agent_scopes".to_string()),
    ] {
        let (code, msg) = sqlstate(sqlx::query(&sql).execute(&pool).await, what);
        assert_eq!(code, "55000", "superuser {what}: {msg}");
        assert!(msg.starts_with("AGS02:"), "{msg}");
    }
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM public.agent_scopes WHERE revoked_at IS NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(live, 2, "the two admitted grants stand");
}

fn up_to(max: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

/// Run `migrator` on one connection and reset it: 001's pg_dump header leaves
/// session-level SETs behind.
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// The `public` catalog by name: relations (with ACL), functions (whole
/// definition by md5, owner and ACL), policies, triggers and constraints.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text || ' ' \
                || COALESCE(c.relacl::text, '-') \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[sqlx::test(migrations = false)]
async fn the_356_undo_returns_the_catalog_below_356(pool: PgPool) {
    migrate(&pool, &up_to(355)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(356)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    for name in [
        "rel agent_scopes r",
        "rel agent_scope_arming r",
        "fn epigraph_agent_scope_grant(",
        "fn epigraph_agent_scope_revoke(",
        "fn epigraph_agent_scopes_guard(",
        "fn epigraph_agent_scopes_audit(",
        "pol agent_scopes.agent_scopes_privileged_read",
        "trg agent_scopes.agent_scopes_audit",
    ] {
        assert!(
            added.iter().any(|e| e.starts_with(name)),
            "CALIBRATION: 356 adds {name}: {added:?}"
        );
    }
    assert!(
        removed.is_empty(),
        "CALIBRATION: 356 only adds; it changes nothing that existed: {removed:?}"
    );

    let undo = repo_file("docs/runbooks/356-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 356"
        );
    }
}
