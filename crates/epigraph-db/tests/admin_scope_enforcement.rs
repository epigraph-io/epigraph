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
