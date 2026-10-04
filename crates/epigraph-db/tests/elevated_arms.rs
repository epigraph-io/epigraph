//! What migration 126's elevated arms DO (elevation plan EL-7): an elevated
//! session reads another person's private rows in every armed class and
//! writes nothing, while the same principal unelevated reads none of them and
//! writes as before. `elevation_arms_census.rs` pins which policies exist;
//! this file pins what they admit and refuse.
//!
//! THE WORLD. P is a custodian (a registered human holding an `elevates`
//! role, with a passkey and a refresh family) with a confirmed session seeded
//! through migration 125's definers. B is another person with its own
//! personal group and B-private rows: a claim, its evidence and reasoning
//! trace (T-OWN, T-DER via 070's inheritance), an edge between two B-private
//! claims (T-EDGE), a recall event (T-OWN-PRIV), its group and membership
//! (T-GROUP) and a security event (T-AUDIT).
//!
//! EVERY READ AND WRITE runs as `epigraph_app` on a SESSION-MODE (autocommit)
//! connection from `ScopedPool::acquire_as`, stamped from the viewer: the
//! path EL-6 left to these policies (its Rust refusal covers `begin_as`, and
//! transaction-mode elevated reads are `BEGIN READ ONLY`). Each connection
//! asserts its own state first (`current_user`, `epigraph_is_elevated()`), and
//! every refused write is paired with the identical write succeeding for the
//! same principal unelevated, so no refusal passes because the write was
//! malformed.
//!
//! Each test names the mutation it was run against ("Verified to fail").

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ScopedPool, ScopedPoolOptions, SessionGucMode, Viewer};
use sqlx::{Executor, PgPool};
use uuid::Uuid;

// =====================================================================
// fixtures (the minimal subset of elevated_viewer.rs's)
// =====================================================================

/// Run `f` as `epigraph_app` with the principal stamped and no elevation.
async fn as_app<F, Fut, T>(pool: &PgPool, principal: Option<Uuid>, f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let principal = principal.map(|p| p.to_string()).unwrap_or_default();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.elevation_id', '', false), \
                    set_config('epigraph.family_id', '', false)",
        )
        .bind(&principal)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let (mut conn, out) = f(conn).await;
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("unstamp");
        (conn, out)
    })
    .await
}

struct Holder {
    person: Uuid,
    group: Uuid,
    client: Uuid,
    cred: Vec<u8>,
    family: Uuid,
}

async fn holder(pool: &PgPool, label: &str, n: u8) -> Holder {
    // 125 ships no session live until the per-access recorder is installed;
    // these tests are about what a LIVE session does.
    fixture::open_elevated_access_gate(pool).await;
    let (person, group) = fixture::seed_human_operator(pool, label).await;
    let client: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("the human's client");
    fixture::make_custodian(pool, person).await;
    let e: Uuid = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let e = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'elevated arms test', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("enroll");
        (conn, e)
    })
    .await;
    let mut cred = vec![0xA5_u8; 16];
    cred[0] = n;
    let c = cred.clone();
    as_app(pool, None, |mut conn| async move {
        sqlx::query(
            "SELECT public.epigraph_set_passkey_enrollment_challenge($1, '{\"rs\": 1}'::jsonb)",
        )
        .bind(e)
        .execute(&mut *conn)
        .await
        .expect("enrollment challenge");
        sqlx::query(
            "SELECT public.epigraph_complete_passkey_enrollment($1, $2, \
                    '{\"cred\": 1}'::jsonb, '00000000-0000-0000-0000-000000000000'::uuid, \
                    'none', true, false)",
        )
        .bind(e)
        .bind(c)
        .execute(&mut *conn)
        .await
        .expect("complete the enrollment");
        (conn, ())
    })
    .await;
    let hash: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    let family: Uuid = sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(&hash)
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a refresh token");
    Holder {
        person,
        group,
        client,
        cred,
        family,
    }
}

/// A confirmed grant-mode session for `h`; its id.
async fn session(pool: &PgPool, h: &Holder) -> Uuid {
    let (client, fam) = (h.client, h.family);
    let ticket: Uuid = as_app(pool, Some(h.person), |mut conn| async move {
        let t = sqlx::query_scalar(
            "SELECT public.epigraph_create_elevation_ticket($1, $2, 'grant', \
                    'elevated arms test', sha256('an elevated arms secret'::bytea))",
        )
        .bind(client)
        .bind(fam)
        .fetch_one(&mut *conn)
        .await
        .expect("a ticket");
        (conn, t)
    })
    .await;
    let cred = h.cred.clone();
    as_app(pool, None, |mut conn| async move {
        sqlx::query(
            "SELECT public.epigraph_set_elevation_ticket_challenge($1, '{\"st\": 1}'::jsonb)",
        )
        .bind(ticket)
        .execute(&mut *conn)
        .await
        .expect("the ceremony's challenge");
        let (outcome, session): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT outcome, session_id \
               FROM public.epigraph_confirm_elevation($1, $2, 0, false, '{\"ev\": 1}'::jsonb)",
        )
        .bind(ticket)
        .bind(cred)
        .fetch_one(&mut *conn)
        .await
        .expect("confirm");
        assert_eq!(outcome, "confirmed", "CALIBRATION: the ceremony confirms");
        (conn, session.expect("a session"))
    })
    .await
}

async fn scoped(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_with_options(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        ScopedPoolOptions {
            max_connections: 2,
            ..ScopedPoolOptions::default()
        },
    )
    .await
    .expect("ScopedPool")
}

/// P elevated (a live session on its family) and P unelevated (no claim),
/// both RESOLVED on an application-role pool (`session_user` = `epigraph_app`):
/// 125 answers "not live" to the superuser login of [`scoped`].
async fn viewers(pool: &PgPool, p: &Holder, live: Uuid) -> (Viewer, Viewer) {
    let s = &ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("application-role ScopedPool");
    let elevated = Viewer::resolve_elevated(s, p.person, Some(live), p.family)
        .await
        .expect("resolve_elevated");
    assert!(elevated.is_elevated(), "CALIBRATION: P resolves elevated");
    let plain = Viewer::resolve_elevated(s, p.person, None, p.family)
        .await
        .expect("resolve");
    assert!(
        !plain.is_elevated(),
        "CALIBRATION: no claim resolves scoped"
    );
    (elevated, plain)
}

/// A session-mode checkout stamped from `v`, switched to `epigraph_app`, with
/// its state asserted: the application role, elevated exactly as `v` is.
async fn app_conn<'a>(s: &'a ScopedPool, v: &Viewer) -> epigraph_db::ScopedConn<'a> {
    let mut conn = s.acquire_as(v).await.expect("acquire_as");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("as epigraph_app");
    let (role, elevated): (String, bool) =
        sqlx::query_as("SELECT current_user::text, public.epigraph_is_elevated()")
            .fetch_one(&mut *conn)
            .await
            .expect("connection state");
    assert_eq!(role, "epigraph_app", "CALIBRATION: the application role");
    assert_eq!(
        elevated,
        v.is_elevated(),
        "CALIBRATION: the database agrees the connection is (not) elevated"
    );
    conn
}

async fn release(mut conn: epigraph_db::ScopedConn<'_>) {
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
}

/// B's private rows, one or more per class: `(table, id column, id)`.
async fn seed_b_world(pool: &PgPool, b: Uuid, b_group: Uuid) -> Vec<(&'static str, String, Uuid)> {
    let claim = fixture::seed_group_claim(pool, b, b_group, "B's private claim").await;
    let other = fixture::seed_group_claim(pool, b, b_group, "B's other private claim").await;
    let evidence = fixture::seed_evidence(pool, claim, "observation").await;
    let trace = fixture::seed_reasoning_trace(pool, claim, "deductive").await;
    let edge = fixture::seed_edge(pool, claim, other).await;
    let recall: Uuid = sqlx::query_scalar(
        "INSERT INTO recall_events (agent_id, tool, query_text, params, returned_claim_ids, \
                                    owner_group_id, visibility) \
         VALUES ($1, 'recall', 'B private query', '{}'::jsonb, ARRAY[]::uuid[], $2, 'group') \
         RETURNING id",
    )
    .bind(b)
    .bind(b_group)
    .fetch_one(pool)
    .await
    .expect("B's recall event");
    let event: Uuid = sqlx::query_scalar(
        "INSERT INTO security_events (event_type, agent_id, success, details) \
         VALUES ('test.elevated_arms', $1, true, '{}'::jsonb) RETURNING id",
    )
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("B's security event");
    vec![
        ("claims", "id".into(), claim),
        ("evidence", "id".into(), evidence),
        ("reasoning_traces", "id".into(), trace),
        ("edges", "id".into(), edge),
        ("recall_events", "id".into(), recall),
        ("groups", "id".into(), b_group),
        ("group_memberships", "agent_id".into(), b),
        ("security_events", "id".into(), event),
    ]
}

async fn count_row(conn: &mut sqlx::PgConnection, table: &str, col: &str, id: Uuid) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT count(*) FROM public.{table} WHERE {col} = $1"
    ))
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .unwrap_or_else(|e| panic!("read {table}: {e}"))
}

// =====================================================================
// Reads
// =====================================================================

/// P elevated reads B's private row in every class (T-OWN, T-DER, T-EDGE,
/// T-OWN-PRIV, T-GROUP, T-AUDIT); P unelevated reads none of them, except
/// B's security event, which 083's standing instance-admin arm still shows a
/// custodian until the admin-scope arming switch (plan EL-10).
///
/// Verified to fail with 126's `evidence_elevated_read` USING (false) (the
/// evidence row is not read elevated) and with `claims_elevated_read` USING
/// (true) (P unelevated reads B's claim).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_session_reads_a_foreign_private_row_in_every_class(pool: PgPool) {
    let p = holder(&pool, "arms-read-p", 11).await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "arms-read-b").await;
    let rows = seed_b_world(&pool, b, b_group).await;
    let s = scoped(&pool).await;
    let live = session(&pool, &p).await;
    let (elevated, plain) = viewers(&pool, &p, live).await;

    let mut conn = app_conn(&s, &plain).await;
    let mut unelevated = Vec::new();
    for (t, col, id) in &rows {
        unelevated.push((*t, count_row(&mut conn, t, col, *id).await));
    }
    release(conn).await;

    let mut conn = app_conn(&s, &elevated).await;
    let mut seen = Vec::new();
    for (t, col, id) in &rows {
        seen.push((*t, count_row(&mut conn, t, col, *id).await));
    }
    release(conn).await;

    for (t, n) in &unelevated {
        // `security_events` keeps 083's STANDING read arm for an instance
        // admin, which 123 answers from the custodian role P holds: P reads
        // B's security event unelevated today. That arm becomes an elevated
        // arm behind the admin-scope arming switch (plan EL-10), which must
        // flip this to 0.
        let want = i64::from(*t == "security_events");
        assert_eq!(
            *n, want,
            "P unelevated reads {want} B-private row(s) of {t}"
        );
    }
    for (t, n) in &seen {
        assert!(*n >= 1, "P elevated reads B's private row of {t}");
    }
}

/// The arm admits EVERY row of EVERY table that carries one: on an elevated
/// application connection each armed table counts exactly what the
/// unfiltered harness counts. Non-vacuous where the B world put a private
/// row (the unelevated count is lower there).
///
/// Verified to fail with 126's `reasoning_traces_elevated_read` dropped (the
/// elevated count of reasoning_traces falls short).
#[sqlx::test(migrations = "../../migrations")]
async fn the_elevated_read_arm_admits_every_row_of_every_armed_table(pool: PgPool) {
    let p = holder(&pool, "arms-all-p", 12).await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "arms-all-b").await;
    seed_b_world(&pool, b, b_group).await;
    let s = scoped(&pool).await;
    let live = session(&pool, &p).await;
    let (elevated, plain) = viewers(&pool, &p, live).await;

    let armed: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
            AND p.polname = c.relname || '_elevated_read' ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("armed tables");
    assert!(
        armed.len() >= 27,
        "CALIBRATION: 126's arms ({})",
        armed.len()
    );

    let mut total = Vec::new();
    for t in &armed {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM public.{t}"))
            .fetch_one(&pool)
            .await
            .expect("harness count");
        total.push(n);
    }
    let mut conn = app_conn(&s, &elevated).await;
    let mut as_elevated = Vec::new();
    for t in &armed {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM public.{t}"))
            .fetch_one(&mut *conn)
            .await
            .expect("elevated count");
        as_elevated.push(n);
    }
    release(conn).await;
    let mut conn = app_conn(&s, &plain).await;
    let mut as_plain = Vec::new();
    for t in &armed {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM public.{t}"))
            .fetch_one(&mut *conn)
            .await
            .expect("unelevated count");
        as_plain.push(n);
    }
    release(conn).await;

    let mut narrowed = 0;
    for (i, t) in armed.iter().enumerate() {
        assert_eq!(
            as_elevated[i], total[i],
            "{t}: an elevated session reads every row ({} of {})",
            as_elevated[i], total[i]
        );
        if as_plain[i] < total[i] {
            narrowed += 1;
        }
    }
    assert!(
        narrowed >= 7,
        "CALIBRATION: the unelevated session is narrowed on the seeded tables ({narrowed})"
    );
}

// =====================================================================
// Writes
// =====================================================================

/// The SQLSTATE a statement failed with, or the rows it affected.
async fn outcome(
    conn: &mut sqlx::PgConnection,
    sql: &str,
    p: Uuid,
    g: Uuid,
) -> Result<u64, String> {
    sqlx::query(sql)
        .bind(p)
        .bind(g)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| {
            e.as_database_error()
                .and_then(|d| d.code())
                .map_or_else(|| e.to_string(), |c| c.to_string())
        })
}

/// Writes in each refused class, as `(what, SQL)` over `$1` = P, `$2` = P's
/// personal group. Each is a write P's own scoped viewer may make.
const WRITES: &[(&str, &str)] = &[
    (
        "INSERT claims (T-OWN)",
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ('P writes', sha256(gen_random_uuid()::text::bytea), 0.5, $1, true, 'group', $2)",
    ),
    (
        "UPDATE claims (T-OWN)",
        "UPDATE claims SET truth_value = 0.6 WHERE agent_id = $1 AND owner_group_id = $2 \
           AND content = 'P own claim'",
    ),
    (
        "DELETE claims (T-OWN)",
        "DELETE FROM claims WHERE agent_id = $1 AND owner_group_id = $2 \
           AND content = 'P claim to delete'",
    ),
    (
        "INSERT recall_events (T-OWN-PRIV)",
        "INSERT INTO recall_events (agent_id, tool, query_text, params, returned_claim_ids, \
                                    owner_group_id, visibility) \
         VALUES ($1, 'recall', 'P query', '{}'::jsonb, ARRAY[]::uuid[], $2, 'group')",
    ),
    (
        "UPDATE agents (T-AGENT)",
        "UPDATE agents SET display_name = 'P renamed' WHERE id = $1 AND $2 IS NOT NULL",
    ),
    (
        "UPDATE group_memberships (T-GROUP)",
        "UPDATE group_memberships SET epoch = epoch WHERE agent_id = $1 AND group_id = $2",
    ),
    (
        "INSERT communities (T-DROP)",
        "INSERT INTO communities (name, owner_group_id, visibility) \
         VALUES ('P community ' || $1::text, $2, 'group')",
    ),
];

/// On a session-mode (autocommit) application connection, an elevated
/// session's INSERT fails its WITH CHECK (42501), and its UPDATE and DELETE
/// see no row (0 affected), in every refused class, while the same principal
/// unelevated makes each write. The T-AUDIT trail stays writable elevated.
/// After the session ENDS, the same connection (still carrying the ended
/// session's id) writes again: the database, not the stamp, decides.
///
/// Verified to fail with each of 126's `claims_elevated_no_insert`,
/// `claims_elevated_no_delete`, `recall_events_elevated_no_insert`,
/// `agents_elevated_no_update`, `group_memberships_elevated_no_update` and
/// `communities_elevated_no_insert` dropped (that write is accepted
/// elevated), and with `security_events` given an insert refusal (the audit
/// append is refused).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_session_writes_nothing_until_it_ends(pool: PgPool) {
    let p = holder(&pool, "arms-write-p", 13).await;
    fixture::seed_group_claim(&pool, p.person, p.group, "P own claim").await;
    fixture::seed_group_claim(&pool, p.person, p.group, "P claim to delete").await;
    let s = scoped(&pool).await;
    let live = session(&pool, &p).await;
    let (elevated, plain) = viewers(&pool, &p, live).await;

    // Elevated: every write refused.
    let mut conn = app_conn(&s, &elevated).await;
    let mut refused = Vec::new();
    for (what, sql) in WRITES {
        refused.push((*what, outcome(&mut conn, sql, p.person, p.group).await));
    }
    let audit = outcome(
        &mut conn,
        "INSERT INTO security_events (event_type, agent_id, success, details) \
         VALUES ('test.elevated_audit', $1, true, jsonb_build_object('g', $2::text))",
        p.person,
        p.group,
    )
    .await;
    release(conn).await;
    for (what, got) in &refused {
        if what.starts_with("INSERT") {
            assert_eq!(
                got.as_ref().err().map(String::as_str),
                Some("42501"),
                "{what}: an elevated INSERT fails its WITH CHECK, got {got:?}"
            );
        } else {
            assert_eq!(got, &Ok(0), "{what}: an elevated UPDATE/DELETE sees no row");
        }
    }
    assert_eq!(audit, Ok(1), "the audit trail stays writable elevated");

    // Unelevated, the same principal: every write lands (the calibration).
    let mut conn = app_conn(&s, &plain).await;
    for (what, sql) in WRITES {
        let got = outcome(&mut conn, sql, p.person, p.group).await;
        assert!(
            matches!(got, Ok(n) if n >= 1),
            "CALIBRATION: P unelevated makes the write {what}: {got:?}"
        );
    }
    release(conn).await;

    // The session ends; the elevated stamp no longer elevates anything.
    let ended: bool = as_app(&pool, Some(p.person), |mut conn| async move {
        let e = sqlx::query_scalar("SELECT public.epigraph_end_elevation($1, 'ended')")
            .bind(live)
            .fetch_one(&mut *conn)
            .await
            .expect("end");
        (conn, e)
    })
    .await;
    assert!(ended, "CALIBRATION: the session ended");
    let mut conn = s.acquire_as(&elevated).await.expect("acquire_as");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("as epigraph_app");
    let (stamped, is_elevated): (String, bool) = sqlx::query_as(
        "SELECT current_setting('epigraph.elevation_id', true), public.epigraph_is_elevated()",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("state");
    assert_eq!(
        stamped,
        live.to_string(),
        "the ended session is still stamped"
    );
    assert!(!is_elevated, "an ended session elevates nothing");
    let got = outcome(&mut conn, WRITES[0].1, p.person, p.group).await;
    release(conn).await;
    assert_eq!(got, Ok(1), "P writes again once the session has ended");
}
