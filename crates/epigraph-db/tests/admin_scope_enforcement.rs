//! Migration 128's ADMIN-SCOPE ARMING SWITCH (elevation plan EL-9): it ships
//! unarmed, only the maintenance role changes it, every change is audited
//! whatever path made it, and the would-strip measurement the token endpoint
//! records while unarmed is real, bounded and the application cannot forge.
//!
//! Every authority probe runs as `epigraph_app` or `epigraph_maintenance`
//! (`SET SESSION AUTHORIZATION`); the harness (superuser) only seeds and
//! counts. Each test names the mutation it was run against ("Verified to
//! fail").

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use uuid::Uuid;

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code().map(|c| c.to_string()))
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    match r {
        Ok(v) => panic!("expected a refusal, got {v:?}"),
        Err(e) => sqlstate(e),
    }
}

fn message_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> String {
    match r {
        Ok(v) => panic!("expected a refusal, got {v:?}"),
        Err(e) => e.to_string(),
    }
}

async fn armed(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT public.epigraph_admin_scopes_armed()")
        .fetch_one(pool)
        .await
        .expect("armed()")
}

async fn events(pool: &PgPool, event_type: &str) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = $1 ORDER BY created_at, id",
    )
    .bind(event_type)
    .fetch_all(pool)
    .await
    .expect("events")
}

/// `epigraph_set_admin_scope_enforcement(armed, reason)` as the maintenance
/// role: `(changed, armed, changed_by)`.
async fn set_as_maintenance(pool: &PgPool, arm: bool, reason: &str) -> (bool, bool, String) {
    let reason = reason.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let row: (bool, bool, String) = sqlx::query_as(
            "SELECT changed, armed, changed_by \
               FROM public.epigraph_set_admin_scope_enforcement($1, $2)",
        )
        .bind(arm)
        .bind(&reason)
        .fetch_one(&mut *conn)
        .await
        .expect("maintenance set");
        (conn, row)
    })
    .await
}

/// An active human client holding `scopes` in both arrays.
async fn client_with(pool: &PgPool, scopes: &[&str]) -> Uuid {
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status) \
         VALUES ($1, 'el9 client', 'human', $2, $2, 'active') RETURNING id",
    )
    .bind(format!("el9_{}", Uuid::new_v4().simple()))
    .bind(&scopes)
    .fetch_one(pool)
    .await
    .expect("seed client")
}

/// `epigraph_record_admin_scope_would_strip` as the application role.
async fn record_as_app(
    pool: &PgPool,
    client: Uuid,
    grant: &str,
    scopes: &[&str],
) -> Result<bool, sqlx::Error> {
    let grant = grant.to_string();
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let r =
            sqlx::query_scalar("SELECT public.epigraph_record_admin_scope_would_strip($1, $2, $3)")
                .bind(client)
                .bind(&grant)
                .bind(&scopes)
                .fetch_one(&mut *conn)
                .await;
        (conn, r)
    })
    .await
}

/// The switch ships UNARMED; the maintenance role arms and disarms it with a
/// reason; each change writes exactly one `platform.` event naming it, and
/// asking for the state it is already in changes and records nothing.
///
/// Verified to fail with: the audit trigger dropped from 128 (no events); the
/// setter's UPDATE removed (armed stays false); the setter recording a no-op
/// (`IF v_was IS DISTINCT FROM p_armed` dropped -> the guard refuses the
/// repeat, ADS01).
#[sqlx::test(migrations = "../../migrations")]
async fn the_switch_ships_unarmed_and_every_change_is_audited(pool: PgPool) {
    assert!(!armed(&pool).await, "128 ships the switch unarmed");
    let (seeded_by, reason): (String, String) =
        sqlx::query_as("SELECT changed_by, reason FROM admin_scope_enforcement")
            .fetch_one(&pool)
            .await
            .expect("the seeded row");
    assert!(!seeded_by.is_empty(), "the seed names the migrating login");
    assert_eq!(reason, "migration 128: shipped unarmed");
    assert!(events(&pool, "platform.admin_scopes_armed")
        .await
        .is_empty());

    let (changed, now_armed, by) = set_as_maintenance(&pool, true, "would-strip read zero").await;
    assert!(changed && now_armed, "arming changes the switch");
    assert_eq!(by, "epigraph_maintenance", "the guard stamps session_user");
    assert!(armed(&pool).await, "armed() reads the row");
    let armed_events = events(&pool, "platform.admin_scopes_armed").await;
    assert_eq!(
        armed_events.len(),
        1,
        "one event per arming: {armed_events:?}"
    );
    assert_eq!(armed_events[0]["reason"], "would-strip read zero");
    assert_eq!(armed_events[0]["was_armed"], false);
    assert_eq!(armed_events[0]["recorded_by"], "epigraph_maintenance");

    let (changed, now_armed, _) = set_as_maintenance(&pool, true, "again").await;
    assert!(
        !changed && now_armed,
        "arming an armed switch changes nothing"
    );
    assert_eq!(
        events(&pool, "platform.admin_scopes_armed").await.len(),
        1,
        "a no-op records nothing"
    );

    let (changed, now_armed, _) = set_as_maintenance(&pool, false, "a consumer broke").await;
    assert!(changed && !now_armed, "disarming changes the switch");
    assert!(!armed(&pool).await);
    let disarmed = events(&pool, "platform.admin_scopes_disarmed").await;
    assert_eq!(disarmed.len(), 1, "{disarmed:?}");
    assert_eq!(disarmed[0]["reason"], "a consumer broke");
    assert_eq!(disarmed[0]["was_armed"], true);
}

/// The application role reads the switch and changes it by no path: not the
/// setter, not a direct INSERT, UPDATE or DELETE. Nothing moves and nothing
/// is recorded.
///
/// Verified to fail with: EXECUTE on the setter granted to `epigraph_app`
/// (the body's own ADS02 still refuses: the test then sees ADS02's 42501
/// where it asserts the grant's, so it names the missing layer); the
/// `REVOKE ALL ... FROM epigraph_app` removed from 128 (the app UPDATE then
/// reaches the guard, which stamps and audits it: armed).
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_cannot_arm_or_disarm(pool: PgPool) {
    let outcome = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let who: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&mut *conn)
            .await
            .expect("current_user");
        assert_eq!(who, "epigraph_app", "CALIBRATION: the application role");
        let reads: bool = sqlx::query_scalar("SELECT public.epigraph_admin_scopes_armed()")
            .fetch_one(&mut *conn)
            .await
            .expect("the app reads the switch");
        let row: bool = sqlx::query_scalar("SELECT armed FROM admin_scope_enforcement")
            .fetch_one(&mut *conn)
            .await
            .expect("the app reads the row");
        let set = sqlx::query("SELECT * FROM public.epigraph_set_admin_scope_enforcement(true, 'x')")
            .execute(&mut *conn)
            .await;
        let set_msg = message_of(&set);
        let set_code = code_of(&set);
        let upd = sqlx::query("UPDATE admin_scope_enforcement SET armed = true, reason = 'x'")
            .execute(&mut *conn)
            .await;
        let ins = sqlx::query(
            "INSERT INTO admin_scope_enforcement (singleton, armed, reason) VALUES (true, true, 'x')",
        )
        .execute(&mut *conn)
        .await;
        let del = sqlx::query("DELETE FROM admin_scope_enforcement")
            .execute(&mut *conn)
            .await;
        (
            conn,
            (reads, row, set_code, set_msg, code_of(&upd), code_of(&ins), code_of(&del)),
        )
    })
    .await;
    let (reads, row, set_code, set_msg, upd, ins, del) = outcome;
    assert!(!reads && !row, "the app reads an unarmed switch");
    assert_eq!(set_code.as_deref(), Some("42501"), "setter: {set_msg}");
    assert!(
        set_msg.contains("permission denied for function"),
        "the setter is refused by its grant, not only by its body: {set_msg}"
    );
    assert_eq!(upd.as_deref(), Some("42501"), "direct UPDATE");
    assert_eq!(ins.as_deref(), Some("42501"), "direct INSERT");
    assert_eq!(del.as_deref(), Some("42501"), "direct DELETE");
    assert!(!armed(&pool).await, "still unarmed");
    assert!(events(&pool, "platform.admin_scopes_armed")
        .await
        .is_empty());
}

/// A DIRECT maintenance UPDATE (not the setter) is held to the same rules
/// and the same audit: it must change `armed` and carry a reason, it cannot
/// write the stamp columns, and it records one `platform.` event with the
/// guard's stamp.
///
/// Verified to fail with: the guard's no-op refusal removed (the repeat
/// update succeeds); the guard's stamp removed (changed_at stays the seed's);
/// `GRANT UPDATE (armed, reason)` widened to a table-wide UPDATE (the
/// changed_by write succeeds).
#[sqlx::test(migrations = "../../migrations")]
async fn a_direct_maintenance_update_is_held_to_the_same_rules(pool: PgPool) {
    let seeded_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT changed_at FROM admin_scope_enforcement")
            .fetch_one(&pool)
            .await
            .expect("seed");
    let out = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let noop = sqlx::query("UPDATE admin_scope_enforcement SET reason = 'same state'")
            .execute(&mut *conn)
            .await;
        let blank = sqlx::query("UPDATE admin_scope_enforcement SET armed = true, reason = '  '")
            .execute(&mut *conn)
            .await;
        let stamp = sqlx::query(
            "UPDATE admin_scope_enforcement SET armed = true, reason = 'x', \
                    changed_by = 'someone else'",
        )
        .execute(&mut *conn)
        .await;
        let ok = sqlx::query("UPDATE admin_scope_enforcement SET armed = true, reason = 'direct'")
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected());
        (
            conn,
            (message_of(&noop), code_of(&blank), code_of(&stamp), ok),
        )
    })
    .await;
    let (noop, blank, stamp, ok) = out;
    assert!(noop.contains("ADS01"), "a no-op update is refused: {noop}");
    assert!(
        blank.as_deref() == Some("22023") || blank.as_deref() == Some("23514"),
        "a blank reason is refused: {blank:?}"
    );
    assert_eq!(
        stamp.as_deref(),
        Some("42501"),
        "the stamp columns are not writable"
    );
    assert_eq!(ok.expect("a real change is admitted"), 1);

    let (now_armed, by, at): (bool, String, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT armed, changed_by, changed_at FROM admin_scope_enforcement")
            .fetch_one(&pool)
            .await
            .expect("row");
    assert!(now_armed);
    assert_eq!(by, "epigraph_maintenance", "the guard's stamp");
    assert!(
        at > seeded_at,
        "the guard stamps now(): {at} vs seed {seeded_at}"
    );
    let ev = events(&pool, "platform.admin_scopes_armed").await;
    assert_eq!(ev.len(), 1, "the direct update is audited: {ev:?}");
    assert_eq!(ev[0]["reason"], "direct");
}

/// The row is never inserted again and never deleted, by ANY login, a
/// superuser included.
///
/// Verified to fail with: the guard's DELETE branch removed (the superuser
/// delete succeeds and the switch reads unarmed with no row); the guard's
/// INSERT branch removed (the second row is refused by the primary key
/// instead: 23505, not ADS01).
#[sqlx::test(migrations = "../../migrations")]
async fn the_row_is_never_inserted_again_or_deleted(pool: PgPool) {
    let del = sqlx::query("DELETE FROM admin_scope_enforcement")
        .execute(&pool)
        .await;
    assert!(
        message_of(&del).contains("ADS01"),
        "superuser DELETE: {del:?}"
    );
    let ins = sqlx::query(
        "INSERT INTO admin_scope_enforcement (singleton, armed, reason) VALUES (true, true, 'x')",
    )
    .execute(&pool)
    .await;
    assert!(
        message_of(&ins).contains("ADS01"),
        "superuser INSERT: {ins:?}"
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_scope_enforcement")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 1);
}

/// The would-strip measurement: the application records it, once per client
/// per hour, only for a real grant label and scopes the client holds, and
/// never once the switch is armed.
///
/// Verified to fail with: the per-hour check removed (two events for one
/// client); the subset check removed (a scope the client does not hold is
/// recorded); the armed early return removed (an armed database records).
#[sqlx::test(migrations = "../../migrations")]
async fn the_would_strip_record_is_bounded_real_and_unarmed_only(pool: PgPool) {
    let c1 = client_with(&pool, &["claims:read", "claims:admin", "groups:admin"]).await;
    let c2 = client_with(&pool, &["claims:admin"]).await;

    assert!(
        record_as_app(
            &pool,
            c1,
            "refresh_token",
            &["claims:admin", "groups:admin"]
        )
        .await
        .expect("the app records"),
        "the first record of a client is written"
    );
    assert!(
        !record_as_app(&pool, c1, "authorization_code", &["claims:admin"])
            .await
            .expect("second call"),
        "a second record of the same client inside the hour is not"
    );
    assert!(
        record_as_app(&pool, c2, "device", &["claims:admin"])
            .await
            .expect("another client"),
        "the window is per client"
    );
    let ev = events(&pool, "oauth.admin_scope_would_strip").await;
    assert_eq!(ev.len(), 2, "{ev:?}");
    assert_eq!(ev[0]["client"], c1.to_string());
    assert_eq!(ev[0]["grant"], "refresh_token");
    assert_eq!(
        ev[0]["scopes"],
        serde_json::json!(["claims:admin", "groups:admin"])
    );

    for (grant, scopes, what) in [
        ("password", vec!["claims:admin"], "an unknown grant label"),
        ("refresh_token", vec![], "no scope"),
        (
            "refresh_token",
            vec!["instance:admin"],
            "a scope the client does not hold",
        ),
    ] {
        let r = record_as_app(&pool, c2, grant, &scopes).await;
        assert_eq!(code_of(&r).as_deref(), Some("22023"), "{what}: {r:?}");
    }
    let r = record_as_app(&pool, Uuid::new_v4(), "refresh_token", &["claims:admin"]).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some("22023"),
        "an unknown client: {r:?}"
    );

    set_as_maintenance(&pool, true, "armed for the test").await;
    let c3 = client_with(&pool, &["claims:admin"]).await;
    assert!(
        !record_as_app(&pool, c3, "refresh_token", &["claims:admin"])
            .await
            .expect("armed call"),
        "an armed database records nothing (nothing is kept to measure)"
    );
    assert_eq!(
        events(&pool, "oauth.admin_scope_would_strip").await.len(),
        2
    );
}

/// Why the measurement is a definer: `oauth.` is a privileged event prefix
/// (118), so the application cannot write the would-strip event directly.
/// A calibration for the design, and for the plan's "add it to the app's
/// allowed event types" (there is no allowlist; the prefix is refused).
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_cannot_write_the_would_strip_event_itself(pool: PgPool) {
    let r = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ('oauth.admin_scope_would_strip', NULL, true, '{}'::jsonb)",
        )
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert_eq!(code_of(&r).as_deref(), Some("42501"), "{r:?}");
}

// =====================================================================
// The rollback (docs/runbooks/128-undo.sql)
// =====================================================================

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The repository's migrations up to and including `max`.
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

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// The catalog facts 128 could leave behind, by name: relations, functions
/// (body and owner), policies, triggers and constraints in `public`.
async fn catalog(pool: &PgPool) -> std::collections::BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || md5(p.prosrc) || ' ' || p.proowner::regrole::text \
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

fn undo_128() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/128-undo.sql"),
    )
    .expect("128-undo.sql")
}

/// `docs/runbooks/128-undo.sql`, applied to a database that went 127 -> 128
/// and was then ARMED, returns its catalog (relations, function bodies and
/// owners, policies, triggers, constraints) to the same database's at 127,
/// records the removal as exactly one `platform.admin_scopes_disarmed` event
/// (an undo must not silently end enforcement), and changes nothing on a
/// second run. Cut at 128, not head: a later migration is undone first.
///
/// Verified to fail: the undo's disarm UPDATE removed (no disarm event); the
/// DROP of `epigraph_admin_scopes_armed` removed (left behind).
#[sqlx::test(migrations = false)]
async fn the_rollback_returns_the_catalog_to_127_and_records_the_disarm(pool: PgPool) {
    migrate(&pool, &up_to(127)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(128)).await;
    assert_ne!(
        catalog(&pool).await,
        before,
        "CALIBRATION: 128 changed the catalog"
    );
    set_as_maintenance(&pool, true, "armed before the undo").await;

    for run in 1..=2 {
        sqlx::raw_sql(&undo_128())
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the undo script applies (run {run}): {e}"));
    }
    let after = catalog(&pool).await;
    let left: Vec<&String> = after.difference(&before).collect();
    let lost: Vec<&String> = before.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the catalog is not 127's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
    let disarms = events(&pool, "platform.admin_scopes_disarmed").await;
    assert_eq!(disarms.len(), 1, "one disarm, across two runs: {disarms:?}");
    assert!(
        disarms[0]["reason"]
            .as_str()
            .is_some_and(|r| r.starts_with("128-undo")),
        "{disarms:?}"
    );
    assert_eq!(events(&pool, "platform.admin_scopes_armed").await.len(), 1);
}

// =====================================================================
// The registers know every 128 object.
// =====================================================================

/// The functions a migration file creates in `public`, read from its text:
/// `(SECURITY DEFINER ones, all)`.
fn functions_of(migration: &str) -> (Vec<String>, Vec<String>) {
    let mut definers = Vec::new();
    let mut all = Vec::new();
    let mut rest = migration;
    while let Some(i) = rest.find("CREATE OR REPLACE FUNCTION public.") {
        let after = &rest[i + "CREATE OR REPLACE FUNCTION public.".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let body_end = after.find("$$;").unwrap_or(after.len());
        let header_end = after.find(" AS $$").unwrap_or(body_end);
        if after[..header_end].contains("SECURITY DEFINER") {
            definers.push(name.clone());
        }
        all.push(name);
        rest = &after[body_end..];
    }
    definers.sort();
    definers.dedup();
    all.sort();
    all.dedup();
    (definers, all)
}

/// Every SECURITY DEFINER migration 128 creates is on
/// `epigraph-tenancy-backfill verify`'s ownership list at 128 (a silently
/// no-opped `OWNER TO` is invisible to every behavioural test, because the
/// harness migrates as a superuser), every app-callable one is on its grant
/// register, and every function it creates is dropped by
/// `docs/runbooks/128-undo.sql`.
///
/// Verified to fail: the `("epigraph_record_admin_scope_would_strip", 128)`
/// entry removed from `DEFERRED_DEFINER_FUNCTIONS` -> named here.
#[test]
fn every_128_object_is_registered() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    };
    let migration = read("migrations/128_admin_scope_enforcement.sql");
    let backfill = read("crates/epigraph-cli/src/bin/tenancy_backfill.rs");
    let undo = read("docs/runbooks/128-undo.sql");

    let (definers, all) = functions_of(&migration);
    assert_eq!(
        definers.len(),
        5,
        "CALIBRATION: 128 creates 5 SECURITY DEFINER functions; the scan found {definers:?}"
    );
    assert_eq!(definers, all, "every function 128 creates is a definer");
    let missing: Vec<&String> = definers
        .iter()
        .filter(|n| !backfill.contains(&format!("(\"{n}\", 128)")))
        .collect();
    assert!(
        missing.is_empty(),
        "migration 128 definers missing from tenancy_backfill.rs's ownership list at 128: \
         {missing:?}"
    );
    for callable in [
        "public.epigraph_admin_scopes_armed()",
        "public.epigraph_record_admin_scope_would_strip(uuid, text, text[])",
        "public.epigraph_set_admin_scope_enforcement(boolean, text)",
    ] {
        assert!(
            backfill.contains(&format!("\"{callable}\"")),
            "{callable} is missing from tenancy_backfill.rs's grant register"
        );
    }
    let undropped: Vec<&String> = all
        .iter()
        .filter(|n| !undo.contains(&format!("DROP FUNCTION IF EXISTS public.{n}(")))
        .collect();
    assert!(
        undropped.is_empty(),
        "128-undo.sql does not drop: {undropped:?}"
    );
    assert!(
        undo.contains("DROP TABLE IF EXISTS public.admin_scope_enforcement;"),
        "128-undo.sql does not drop the switch's table"
    );
}

// =====================================================================
// The Rust half (repos::admin_scope_enforcement)
// =====================================================================

/// `AdminScopeEnforcement::read` on the APPLICATION role: unarmed, then armed;
/// a database whose switch function is gone (no 128) reads `Absent` (unarmed:
/// it cannot have been armed); any OTHER failure (EXECUTE revoked) is an
/// error, never a silent "unarmed", because the mint chokepoint fails closed
/// on an error.
///
/// Verified to fail with `read` mapping every error to `Absent` (the revoked
/// read is not an error) and with the 42883 arm removed (the dropped function
/// is an error, not `Absent`).
#[sqlx::test(migrations = "../../migrations")]
async fn the_repository_reads_absent_as_absent_and_a_refusal_as_an_error(pool: PgPool) {
    use epigraph_db::{AdminScopeEnforcement, AdminScopeSwitch};
    async fn read_as_app(pool: &PgPool) -> Result<AdminScopeSwitch, epigraph_db::DbError> {
        fixture::as_role(pool, "epigraph_app", |mut conn| async move {
            let r = AdminScopeEnforcement::read(&mut *conn).await;
            (conn, r)
        })
        .await
    }
    assert_eq!(
        read_as_app(&pool).await.expect("unarmed read"),
        AdminScopeSwitch::Unarmed
    );
    set_as_maintenance(&pool, true, "repository test").await;
    let armed = read_as_app(&pool).await.expect("armed read");
    assert_eq!(armed, AdminScopeSwitch::Armed);
    assert!(armed.is_armed());

    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.epigraph_admin_scopes_armed() FROM epigraph_app",
    )
    .execute(&pool)
    .await
    .expect("revoke");
    let refused = read_as_app(&pool).await;
    assert!(
        refused.is_err(),
        "a refused read is an error, not a state: {refused:?}"
    );

    sqlx::query("DROP FUNCTION public.epigraph_admin_scopes_armed() CASCADE")
        .execute(&pool)
        .await
        .expect("drop");
    let absent = read_as_app(&pool).await.expect("absent read");
    assert_eq!(absent, AdminScopeSwitch::Absent);
    assert!(!absent.is_armed(), "a database without 128 is unarmed");
}

/// `AdminScopeEnforcement::set` arms on a maintenance connection and reports
/// the change; on the application role it is refused; `state` reads the row;
/// `record_would_strip` records once.
#[sqlx::test(migrations = "../../migrations")]
async fn the_repository_sets_only_on_maintenance_and_records_once(pool: PgPool) {
    use epigraph_db::AdminScopeEnforcement;
    let change = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let c = AdminScopeEnforcement::set(&mut conn, true, "repo arm").await;
        let s = AdminScopeEnforcement::state(&mut conn).await;
        (conn, (c, s))
    })
    .await;
    let (c, s) = change;
    let c = c.expect("maintenance arms");
    assert!(c.changed && c.armed);
    assert_eq!(c.changed_by, "epigraph_maintenance");
    let s = s.expect("state");
    assert!(s.armed);
    assert_eq!(s.reason, "repo arm");

    let refused = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = AdminScopeEnforcement::set(&mut conn, false, "app disarm").await;
        (conn, r)
    })
    .await;
    assert!(refused.is_err(), "the app cannot disarm: {refused:?}");
    assert!(armed(&pool).await);

    set_as_maintenance(&pool, false, "back to unarmed").await;
    let client = client_with(&pool, &["claims:admin"]).await;
    let recorded = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let one = AdminScopeEnforcement::record_would_strip(
            &mut *conn,
            client,
            "client_credentials",
            &["claims:admin".to_string()],
        )
        .await;
        let two = AdminScopeEnforcement::record_would_strip(
            &mut *conn,
            client,
            "client_credentials",
            &["claims:admin".to_string()],
        )
        .await;
        (conn, (one, two))
    })
    .await;
    assert_eq!(
        (recorded.0.expect("first"), recorded.1.expect("second")),
        (true, false)
    );
}

// =====================================================================
// Migration 129: the standing admin read arms follow this switch
// =====================================================================

/// The four standing-arm policies 129 rewrites.
const STANDING_ARMS: [&str; 4] = [
    "security_events_read",
    "privatization_audit_read",
    "privatization_plans_read",
    "privatization_plan_items_read",
];

/// Each standing-arm policy's command and qualifier as the catalog prints it.
async fn standing_arm_bodies(pool: &PgPool) -> Vec<(String, String, String)> {
    sqlx::query_as(
        "SELECT pol.polname::text, pol.polcmd::text, pg_get_expr(pol.polqual, pol.polrelid) \
           FROM pg_policy pol \
          WHERE pol.polname = ANY($1) ORDER BY 1",
    )
    .bind(STANDING_ARMS.to_vec())
    .fetch_all(pool)
    .await
    .expect("standing arm bodies")
}

fn undo_129() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/129-undo.sql"),
    )
    .expect("129-undo.sql")
}

/// 129 rewrites exactly the four standing arms into the switch form (each one
/// calls `epigraph_admin_scopes_armed()` and `epigraph_is_elevated()` and still
/// calls `epigraph_is_instance_admin`), and `docs/runbooks/129-undo.sql`
/// returns every one of them, byte for byte as the catalog prints it, and the
/// whole catalog, to the database's state at 128, twice over. The order the
/// undo states holds: 128-undo refuses while 129's policies exist (its
/// `DROP FUNCTION` has no CASCADE) and applies once 129-undo has run. Cut at
/// 129, not head: a later migration is undone first.
///
/// Verified to fail: the undo's `security_events_read` recreated with the 129
/// body (the qualifier differs from 128's); one DROP/CREATE pair removed from
/// the undo (that policy keeps 129's body).
#[sqlx::test(migrations = false)]
async fn the_129_rollback_restores_the_standing_arms_and_runs_before_128s(pool: PgPool) {
    migrate(&pool, &up_to(128)).await;
    let bodies_128 = standing_arm_bodies(&pool).await;
    let catalog_128 = catalog(&pool).await;
    assert_eq!(
        bodies_128.len(),
        4,
        "CALIBRATION: the four arms exist at 128"
    );
    for (name, _, qual) in &bodies_128 {
        assert!(
            qual.contains("epigraph_is_instance_admin") && !qual.contains("admin_scopes_armed"),
            "CALIBRATION: {name} is the standing form at 128: {qual}"
        );
    }

    migrate(&pool, &up_to(129)).await;
    let bodies_129 = standing_arm_bodies(&pool).await;
    assert_eq!(bodies_129.len(), 4, "129 keeps the four arms");
    for ((name, cmd, qual), (_, cmd_128, _)) in bodies_129.iter().zip(&bodies_128) {
        assert_eq!(cmd, cmd_128, "{name} stays a {cmd_128} policy");
        assert!(
            qual.contains("epigraph_admin_scopes_armed()")
                && qual.contains("epigraph_is_elevated()")
                && qual.contains("epigraph_is_instance_admin"),
            "{name} is the switch form after 129: {qual}"
        );
    }
    let mut conn = pool.acquire().await.expect("acquire");
    let early = sqlx::raw_sql(&undo_128()).execute(&mut *conn).await;
    let refusal = early
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    sqlx::query("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("end the refused undo's transaction");
    drop(conn);
    assert!(
        refusal.contains("depend"),
        "128-undo must refuse while 129's policies call the switch: {early:?}"
    );

    for run in 1..=2 {
        sqlx::raw_sql(&undo_129())
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the 129 undo applies (run {run}): {e}"));
    }
    assert_eq!(
        standing_arm_bodies(&pool).await,
        bodies_128,
        "after 129-undo every standing arm reads exactly as at 128"
    );
    let after = catalog(&pool).await;
    assert_eq!(after, catalog_128, "after 129-undo the catalog is 128's");
    sqlx::raw_sql(&undo_128())
        .execute(&pool)
        .await
        .expect("128-undo applies once 129-undo has run");
}
