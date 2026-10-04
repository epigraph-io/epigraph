//! The elevated viewer (elevation plan EL-6): how it is resolved, what it
//! stamps, and what it reads through migration 126's elevated read arm (EL-7;
//! the per-table census of arms and refusals is `elevation_arms_census.rs`).
//!
//! `Viewer::resolve_elevated` is the only constructor of the elevated shape
//! (`no_anonymous_viewer.rs` counts the construction sites). These tests pin
//! the other half: that it builds the shape ONLY when migration 125's
//! principal-bound `epigraph_elevation_live` answered for a live session of
//! this principal on this family, that every other answer (a forged claim,
//! another family, another principal, an ended or expired session, a liveness
//! check that fails) yields the plain scoped viewer, and that an elevated
//! checkout stamps the session the database returned.
//!
//! Sessions are seeded through migration 125's definers with synthetic
//! evidence, as `elevation_sessions.rs` does: the database cannot verify a
//! signature, so the binding is what is under test here. Reads that row
//! policies govern run as `epigraph_app` (`SET SESSION AUTHORIZATION` on the
//! stamped connection, which keeps its session GUCs), never as the harness
//! superuser, which no policy filters.
//!
//! Each test names the mutation it was run against ("Verified to fail").

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{
    ClaimRepository, DbError, ScopedPool, ScopedPoolOptions, SessionGucMode, Viewer,
};
use sqlx::{Executor, PgPool};
use uuid::Uuid;

// =====================================================================
// fixtures (the minimal subset of elevation_sessions.rs's)
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

fn credential(n: u8) -> Vec<u8> {
    let mut id = vec![0xA5_u8; 16];
    id[0] = n;
    id
}

/// A registered human holding `role:platform-custodian`, with one live
/// passkey and one live refresh family of its own human client, and its own
/// personal group.
struct Holder {
    person: Uuid,
    group: Uuid,
    client: Uuid,
    cred: Vec<u8>,
    family: Uuid,
}

async fn family(pool: &PgPool, client: Uuid) -> Uuid {
    let hash: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(&hash)
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a refresh token")
}

async fn holder(pool: &PgPool, label: &str, n: u8) -> Holder {
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
            "SELECT public.epigraph_create_passkey_enrollment($1, 'elevated viewer test', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("enroll");
        (conn, e)
    })
    .await;
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
        .bind(credential(n))
        .execute(&mut *conn)
        .await
        .expect("complete the enrollment");
        (conn, ())
    })
    .await;
    let family = family(pool, client).await;
    Holder {
        person,
        group,
        client,
        cred: credential(n),
        family,
    }
}

/// A confirmed session for `h` in `mode` (`grant` or `connector`); its id.
async fn session(pool: &PgPool, h: &Holder, mode: &str) -> Uuid {
    let (client, fam, mode_s) = (h.client, h.family, mode.to_string());
    let secret: Option<Vec<u8>> = (mode == "grant").then(|| b"an elevated viewer secret".to_vec());
    let ticket: Uuid = as_app(pool, Some(h.person), |mut conn| async move {
        let t = sqlx::query_scalar(
            "SELECT public.epigraph_create_elevation_ticket($1, $2, $3, 'elevated viewer test', \
                    CASE WHEN $4::bytea IS NULL THEN NULL ELSE sha256($4::bytea) END)",
        )
        .bind(client)
        .bind(fam)
        .bind(&mode_s)
        .bind(secret)
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

/// A `ScopedPool` over the test database (superuser login; reads that policies
/// govern switch the stamped connection to `epigraph_app`).
async fn scoped(pool: &PgPool, max_connections: u32) -> ScopedPool {
    ScopedPool::connect_with_options(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        ScopedPoolOptions {
            max_connections,
            ..ScopedPoolOptions::default()
        },
    )
    .await
    .expect("ScopedPool")
}

/// A `ScopedPool` whose every connection is DOWNGRADED to `epigraph_app`
/// (`SET SESSION AUTHORIZATION`, so `session_user` moves): the login an
/// elevation can be live on. 125 answers "not live" to the superuser login of
/// [`scoped`], so every resolution runs here.
async fn app_scoped(pool: &PgPool, mode: SessionGucMode) -> ScopedPool {
    ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        mode,
        "epigraph_app",
    )
    .await
    .expect("application-role ScopedPool")
}

async fn resolve(s: &ScopedPool, who: Uuid, elv: Option<Uuid>, fam: Uuid) -> Viewer {
    Viewer::resolve_elevated(s, who, elv, fam)
        .await
        .expect("resolve_elevated")
}

/// The scoped fragment (not the always-true one) and no elevation.
fn assert_scoped(v: &Viewer, what: &str) {
    assert!(!v.is_elevated(), "{what}: resolved ELEVATED");
    assert!(v.elevation().is_none(), "{what}: carries an elevation");
    assert_ne!(
        v.predicate_fragment(),
        " ",
        "{what}: rendered the always-true fragment"
    );
    assert!(!v.bypass_bind(), "{what}: the static-form flag is set");
}

// =====================================================================
// Resolution
// =====================================================================

/// A live grant-mode session, claimed by its id on its family, resolves
/// ELEVATED, carrying the session the database returned; every other claim
/// resolves scoped and the request is not refused.
///
/// Verified to fail with `resolve_elevated` building the elevated shape from
/// the claim without asking the database (every scoped arm below elevates),
/// and with the family cross-check dropped AND the definer's family clause
/// dropped together (the other-family arm elevates).
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_live_session_of_this_principal_and_family_resolves_elevated(pool: PgPool) {
    let p = holder(&pool, "elevated-p", 1).await;
    let b = holder(&pool, "elevated-b", 2).await;
    let app = app_scoped(&pool, SessionGucMode::Session).await;
    let live = session(&pool, &p, "grant").await;

    let v = resolve(&app, p.person, Some(live), p.family).await;
    assert!(v.is_elevated(), "CALIBRATION: the live session elevates");
    let e = v.elevation().expect("an elevation");
    assert_eq!(
        (e.session_id, e.family_id, e.connector),
        (live, p.family, false)
    );
    assert_eq!(v.predicate_fragment(), " ");
    assert_eq!(v.principal(), Some(p.person));

    assert_scoped(
        &resolve(&app, p.person, Some(Uuid::new_v4()), p.family).await,
        "a forged session id",
    );
    let other_family = family(&pool, p.client).await;
    assert_scoped(
        &resolve(&app, p.person, Some(live), other_family).await,
        "the right session on another family of the same person",
    );
    assert_scoped(
        &resolve(&app, b.person, Some(live), p.family).await,
        "another principal presenting P's session and family",
    );
    assert_scoped(
        &resolve(&app, p.person, None, p.family).await,
        "no claim on a GRANT-mode session (only connector sessions are found by family)",
    );

    // Ended: the principal ends its own session, then presents it again.
    let ended: bool = as_app(&pool, Some(p.person), |mut conn| async move {
        let r = sqlx::query_scalar("SELECT public.epigraph_end_elevation($1, 'ended')")
            .bind(live)
            .fetch_one(&mut *conn)
            .await
            .expect("end");
        (conn, r)
    })
    .await;
    assert!(ended, "CALIBRATION: the session ended");
    assert_scoped(
        &resolve(&app, p.person, Some(live), p.family).await,
        "an ended session",
    );
}

/// A connector-mode session is found by its FAMILY (no claim), and resolves
/// elevated with the session id the database returned; aged past its expiry
/// it resolves scoped.
///
/// Verified to fail with the stamped elevation id taken from the claim rather
/// than the database's answer (the connector stamp is empty, so
/// `epigraph_is_elevated()` is false on the elevated checkout), and with the
/// expiry clause dropped from `epigraph_elevation_live` (the aged session
/// elevates).
#[sqlx::test(migrations = "../../migrations")]
async fn a_connector_session_resolves_by_family_and_not_once_expired(pool: PgPool) {
    let p = holder(&pool, "connector-p", 3).await;
    let app = app_scoped(&pool, SessionGucMode::Session).await;
    let live = session(&pool, &p, "connector").await;

    let v = resolve(&app, p.person, None, p.family).await;
    let e = *v
        .elevation()
        .expect("a connector session elevates by family");
    assert_eq!(
        (e.session_id, e.family_id, e.connector),
        (live, p.family, true)
    );

    // The checkout stamps the SESSION the database returned, so the database
    // agrees that this statement is elevated (on the application role).
    let mut conn = app.acquire_as(&v).await.expect("acquire_as");
    let (elv, fam, elevated): (String, String, bool) = sqlx::query_as(
        "SELECT current_setting('epigraph.elevation_id', true), \
                current_setting('epigraph.family_id', true), \
                public.epigraph_is_elevated()",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("read the stamp back");
    assert_eq!(
        (elv, fam, elevated),
        (live.to_string(), p.family.to_string(), true)
    );
    drop(conn);

    let mut c = pool.acquire().await.expect("acquire");
    c.execute("SET session_replication_role = replica")
        .await
        .expect("triggers off");
    sqlx::query(
        "UPDATE elevation_sessions SET started_at = started_at - interval '1 hour', \
                                       expires_at = expires_at - interval '1 hour' \
          WHERE id = $1",
    )
    .bind(live)
    .execute(&mut *c)
    .await
    .expect("age the session");
    c.execute("SET session_replication_role = DEFAULT")
        .await
        .expect("triggers on");
    drop(c);
    assert_scoped(
        &resolve(&app, p.person, None, p.family).await,
        "an expired connector session",
    );
}

/// A liveness check that FAILS degrades to the scoped viewer, never an error:
/// the request is served unelevated. Staged as the plan names it, a database
/// without migration 125's function (renamed away for the duration).
///
/// Verified to fail with the liveness error propagated out of
/// `resolve_elevated` (the `expect` below panics).
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_liveness_check_serves_the_request_unelevated(pool: PgPool) {
    let p = holder(&pool, "degrade-p", 4).await;
    let app = app_scoped(&pool, SessionGucMode::Session).await;
    let live = session(&pool, &p, "grant").await;
    assert!(
        resolve(&app, p.person, Some(live), p.family)
            .await
            .is_elevated(),
        "CALIBRATION: the session is live"
    );

    pool.execute(
        "ALTER FUNCTION public.epigraph_elevation_live(uuid, uuid) \
         RENAME TO epigraph_elevation_live_gone",
    )
    .await
    .expect("rename the liveness definer away");
    let v = Viewer::resolve_elevated(&app, p.person, Some(live), p.family)
        .await
        .expect("a failed liveness check is not an error");
    assert_scoped(&v, "a database without the liveness definer");
    assert!(
        v.group_bind().is_some_and(|g| g.contains(&p.group)),
        "the degraded viewer is the principal's full scoped viewer, not an empty one"
    );
}

/// A pool on a PRIVILEGED login never resolves an elevated viewer (review
/// cp2: SEC-02, COR-1). On such a login (here the harness superuser; a unit
/// on a BYPASSRLS request DSN is the production shape) the elevated shape's
/// always-true fragment would read and decide writes on every tenant's rows,
/// with no row policy to narrow it. The same live session, the same claim,
/// resolved on the application role is elevated (the calibration that the
/// refusal is the login's, not the session's), and still is afterwards.
///
/// Verified to fail with 125's privileged-login conjuncts dropped from
/// `epigraph_elevation_session_is_live` (the superuser pool resolves
/// ELEVATED).
#[sqlx::test(migrations = "../../migrations")]
async fn a_privileged_pool_never_resolves_elevated(pool: PgPool) {
    let p = holder(&pool, "privileged-pool-p", 10).await;
    let privileged = scoped(&pool, 2).await;
    let app = app_scoped(&pool, SessionGucMode::Session).await;
    let live = session(&pool, &p, "grant").await;
    assert!(
        resolve(&app, p.person, Some(live), p.family)
            .await
            .is_elevated(),
        "CALIBRATION: the session elevates the application role"
    );

    let v = resolve(&privileged, p.person, Some(live), p.family).await;
    assert_scoped(&v, "a privileged (superuser) pool");
    assert!(
        v.group_bind().is_some_and(|g| g.contains(&p.group)),
        "the privileged pool's viewer is the principal's scoped viewer, not an empty one"
    );
    assert!(
        resolve(&app, p.person, Some(live), p.family)
            .await
            .is_elevated(),
        "CALIBRATION: the session is still live on the application role"
    );
}

// =====================================================================
// Stamping and the pool
// =====================================================================

/// The plan's pool test: on ONE connection, an elevated checkout is elevated
/// in the database (as `epigraph_app`), with the principal's own groups
/// stamped; a plain checkout of the released connection reads the elevation
/// pair empty (the scrub), and the next SCOPED checkout for the SAME principal
/// reads it empty and is not elevated (the stamp). Same backend each time, so
/// the emptiness is the scrub's and the stamp's, not a fresh connection's.
///
/// Verified to fail with the stamp binding `group_bind()` instead of the
/// session groups (the elevated checkout's `epigraph_session_groups()` is
/// empty), and with the elevated stamp writing an empty elevation id (the
/// database does not agree the checkout is elevated). The scrub's own
/// mutations are `qual_guc_coherence::the_scrub_resets_all_five_gucs_on_the_same_backend`'s.
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_checkout_leaves_nothing_for_the_next_one(pool: PgPool) {
    let p = holder(&pool, "pool-p", 5).await;
    let s = scoped(&pool, 1).await;
    let app = app_scoped(&pool, SessionGucMode::Session).await;
    let live = session(&pool, &p, "grant").await;
    let elevated = resolve(&app, p.person, Some(live), p.family).await;
    assert!(elevated.is_elevated(), "CALIBRATION");

    let pid: i32 = {
        let mut conn = s.acquire_as(&elevated).await.expect("acquire_as");
        conn.execute("SET SESSION AUTHORIZATION epigraph_app")
            .await
            .expect("as epigraph_app");
        let (is_elevated, groups, pid): (bool, Vec<Uuid>, i32) = sqlx::query_as(
            "SELECT public.epigraph_is_elevated(), public.epigraph_session_groups(), \
                    pg_backend_pid()",
        )
        .fetch_one(&mut *conn)
        .await
        .expect("as epigraph_app");
        conn.execute("RESET SESSION AUTHORIZATION")
            .await
            .expect("reset");
        assert!(is_elevated, "the database agrees the checkout is elevated");
        assert!(
            groups.contains(&p.group),
            "the elevated checkout stamps the principal's OWN groups: {groups:?}"
        );
        pid
    };

    // A PLAIN checkout of the released connection: what the scrub left.
    {
        let mut next = s.inner().acquire().await.expect("plain acquire");
        let (pid2, elv, fam): (i32, String, String) = sqlx::query_as(
            "SELECT pg_backend_pid(), \
                    COALESCE(current_setting('epigraph.elevation_id', true), ''), \
                    COALESCE(current_setting('epigraph.family_id', true), '')",
        )
        .fetch_one(&mut *next)
        .await
        .expect("read back");
        assert_eq!(pid2, pid, "CALIBRATION: the same backend");
        assert_eq!(
            (elv.as_str(), fam.as_str()),
            ("", ""),
            "the scrub left the pair"
        );
    }

    // And a SCOPED checkout for the same principal.
    let scoped_viewer = Viewer::resolve(s.inner(), p.person).await.expect("resolve");
    let mut conn = s.acquire_as(&scoped_viewer).await.expect("acquire_as");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("as epigraph_app");
    let (pid3, elv, fam, is_elevated): (i32, String, String, bool) = sqlx::query_as(
        "SELECT pg_backend_pid(), current_setting('epigraph.elevation_id', true), \
                current_setting('epigraph.family_id', true), public.epigraph_is_elevated()",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("as epigraph_app");
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    assert_eq!(pid3, pid, "CALIBRATION: the same backend");
    assert_eq!(
        (elv.as_str(), fam.as_str(), is_elevated),
        ("", "", false),
        "a scoped checkout of the same principal stamps the elevation pair empty"
    );
}

/// THROUGH migration 126's elevated read arm (EL-7), an elevated viewer on an
/// APPLICATION connection with its GUCs stamped reads another person's
/// group-private row, and its own. Before 126 the same test asserted the
/// opposite for the foreign row (`elevated_reads_nothing_foreign_before_arms`:
/// the elevated shape alone granted no row, so the always-true fragment
/// returned exactly what the policies admitted); 126's commit flipped that last
/// arm, as the EL-6 hand-off required.
///
/// Four arms on the same connection, so none passes for a wrong reason: the
/// connection IS the application role (not the BYPASSRLS harness login), the
/// database says the statement IS elevated (the stamp landed), the viewer's
/// own private row is visible (its groups were stamped), and B's private row is
/// visible too, which only the elevated arm admits.
///
/// Verified to fail with 126's `claims_elevated_read` dropped (B's row is not
/// read) and with the stamp binding `group_bind()` (P's own row disappears).
#[sqlx::test(migrations = "../../migrations")]
async fn elevated_reads_a_foreign_private_row_through_the_arm(pool: PgPool) {
    let p = holder(&pool, "arms-p", 6).await;
    let (b, b_group) = fixture::seed_agent_with_group(&pool, "arms-b").await;
    let mine = fixture::seed_group_claim(&pool, p.person, p.group, "P's private row").await;
    let theirs = fixture::seed_group_claim(&pool, b, b_group, "B's private row").await;
    let s = scoped(&pool, 2).await;
    let app = app_scoped(&pool, SessionGucMode::Session).await;
    let live = session(&pool, &p, "grant").await;
    let v = resolve(&app, p.person, Some(live), p.family).await;
    assert!(v.is_elevated(), "CALIBRATION");

    let mut conn = s.acquire_as(&v).await.expect("acquire_as");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("as epigraph_app");
    let (is_elevated, role): (bool, String) =
        sqlx::query_as("SELECT public.epigraph_is_elevated(), current_user::text")
            .fetch_one(&mut *conn)
            .await
            .expect("is_elevated");
    let own = ClaimRepository::get_by_id(&mut *conn, &v, mine.into())
        .await
        .expect("get_by_id");
    let foreign = ClaimRepository::get_by_id(&mut *conn, &v, theirs.into())
        .await
        .expect("get_by_id");
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    assert_eq!(
        role, "epigraph_app",
        "the read runs as the application role"
    );
    assert!(is_elevated, "the statement is elevated in the database");
    assert!(
        own.is_some(),
        "the elevated viewer reads its own private row"
    );
    assert!(
        foreign.is_some(),
        "migration 126's elevated read arm admits another person's private row to an \
         elevated session"
    );
}

/// An elevated viewer DETACHES as the principal's plain scoped viewer: the
/// copy a detached task takes reads what the principal's own scoped viewer
/// reads, and its checkout stamps no elevation, so the database does not
/// treat the task as elevated even while the session is live.
///
/// Verified to fail with `detach_scoped` copying the elevated shape (the
/// detached checkout is elevated in the database) and with it answering
/// `None` for the elevated shape (the `expect` panics).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_viewer_detaches_as_the_principals_scoped_viewer(pool: PgPool) {
    let p = holder(&pool, "detach-p", 7).await;
    let mine = fixture::seed_group_claim(&pool, p.person, p.group, "P's private row").await;
    let s = scoped(&pool, 2).await;
    let app = app_scoped(&pool, SessionGucMode::Session).await;
    let live = session(&pool, &p, "grant").await;
    let v = resolve(&app, p.person, Some(live), p.family).await;
    assert!(v.is_elevated(), "CALIBRATION");

    let d = v.detach_scoped().expect("an elevated viewer detaches");
    assert_scoped(&d, "the detached copy");

    let mut conn = s.acquire_as(&d).await.expect("acquire_as");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("as epigraph_app");
    let (is_elevated, elv): (bool, String) = sqlx::query_as(
        "SELECT public.epigraph_is_elevated(), current_setting('epigraph.elevation_id', true)",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("read back");
    let own = ClaimRepository::get_by_id(&mut *conn, &d, mine.into())
        .await
        .expect("get_by_id");
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    assert_eq!((is_elevated, elv.as_str()), (false, ""));
    assert!(
        own.is_some(),
        "the detached copy keeps the principal's own authority"
    );
}

// =====================================================================
// The Rust write refusal
// =====================================================================

/// An INSERT on `conn`, answering the SQLSTATE it failed with (or `None`).
async fn insert_sqlstate(conn: &mut sqlx::PgConnection) -> Option<String> {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(&mut *conn)
        .await
        .err()
        .and_then(|e| {
            e.as_database_error()
                .and_then(|d| d.code())
                .map(|c| c.to_string())
        })
}

/// `begin_as` refuses an elevated viewer outright (`ElevatedReadOnly`), and
/// the one transaction it may open, `begin_read_as`, is READ ONLY in the
/// database: the INSERT fails with `25006` while the statement is elevated.
/// Calibration: the principal's scoped viewer opens a writable transaction
/// through `begin_as`, where the same INSERT succeeds.
///
/// Verified to fail with the elevated check removed from `begin_as` (it opens
/// a transaction), and with `begin_read_as` issuing a plain `BEGIN` (the
/// INSERT succeeds).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_viewer_gets_no_write_transaction(pool: PgPool) {
    let p = holder(&pool, "write-p", 8).await;
    let s = scoped(&pool, 2).await;
    let app = app_scoped(&pool, SessionGucMode::Session).await;
    let live = session(&pool, &p, "grant").await;
    let v = resolve(&app, p.person, Some(live), p.family).await;
    assert!(v.is_elevated(), "CALIBRATION");

    match app.begin_as(&v).await {
        Err(DbError::ElevatedReadOnly) => {}
        other => panic!("begin_as must refuse an elevated viewer: {other:?}"),
    }

    let mut tx = app.begin_read_as(&v).await.expect("begin_read_as");
    let elevated: bool = sqlx::query_scalar("SELECT public.epigraph_is_elevated()")
        .fetch_one(&mut *tx)
        .await
        .expect("is_elevated");
    assert!(elevated, "the read-only transaction is stamped elevated");
    assert_eq!(insert_sqlstate(&mut tx).await.as_deref(), Some("25006"));
    tx.rollback().await.expect("rollback");

    let plain = Viewer::resolve(s.inner(), p.person).await.expect("resolve");
    let mut tx = s
        .begin_as(&plain)
        .await
        .expect("CALIBRATION: scoped begin_as");
    assert_eq!(
        insert_sqlstate(&mut tx).await,
        None,
        "CALIBRATION: the same INSERT succeeds in a writable transaction"
    );
    tx.rollback().await.expect("rollback");
}

/// In `Transaction` mode `read_as` serves an elevated viewer (the mode-dispatch
/// helper must not route it to the refused `begin_as`), on the READ ONLY arm.
///
/// Verified to fail with `read_as` routing the elevated viewer to `begin_as`
/// (the read is refused).
#[sqlx::test(migrations = "../../migrations")]
async fn read_as_serves_an_elevated_viewer_read_only_in_transaction_mode(pool: PgPool) {
    let p = holder(&pool, "txmode-p", 9).await;
    let s = app_scoped(&pool, SessionGucMode::Transaction).await;
    let live = session(&pool, &p, "grant").await;
    let v = resolve(&s, p.person, Some(live), p.family).await;
    assert!(
        v.is_elevated(),
        "CALIBRATION: resolution works in transaction mode"
    );

    let mut r = s
        .read_as(&v)
        .await
        .expect("read_as serves the elevated viewer");
    assert_eq!(r.mode(), SessionGucMode::Transaction);
    let elevated: bool = sqlx::query_scalar("SELECT public.epigraph_is_elevated()")
        .fetch_one(&mut *r)
        .await
        .expect("is_elevated");
    assert!(elevated);
    assert_eq!(insert_sqlstate(&mut r).await.as_deref(), Some("25006"));
}
