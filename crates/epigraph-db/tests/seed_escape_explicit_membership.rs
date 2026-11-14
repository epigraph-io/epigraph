//! Migration 216 (backlog 0512ca33): the tenancy seed escape hatch needs an
//! EXPLICIT grant of `epigraph_seed`. Being a superuser no longer counts.
//!
//! # The defect
//!
//! Migration 074's three `*_require_tenancy` bodies stamp an undeclared row
//! `('public', <seed group>)` instead of raising 23502 when
//! `pg_has_role(session_user, 'epigraph_seed', 'MEMBER')` holds.
//! `pg_has_role` is true of EVERY superuser, whatever `pg_auth_members`
//! says, so every superuser session took the hatch although nobody was ever
//! granted the role, and its undeclared rows became owned by a group with no
//! members.
//!
//! # The roles these tests run as exist only inside a rolled-back transaction
//!
//! Roles are CLUSTER-global, so a role a `#[sqlx::test]` commits outlives
//! the per-test database, and two of these are superusers. `CREATE ROLE` and
//! `GRANT` are transactional, so every test creates its roles inside ONE
//! transaction on ONE connection, does all its work there (the writes as the
//! role, and the reads that check them, which no other connection can see),
//! and never commits. A panic drops the connection, which aborts the
//! transaction, so the roles vanish either way.
//!
//! Parallel tests queue on the first `CREATE ROLE` (the second waits for the
//! first transaction to end, then succeeds), and every test issues the DDL in
//! the same order, so they cannot deadlock.
//!
//! None of these tests uses the harness role itself: whether IT holds the
//! grant is cluster state this file does not own
//! (`tenancy_required.rs::the_harness_role_can_take_the_seed_escape_hatch`
//! asserts that precondition).

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::{Executor, PgPool, Row};
use uuid::Uuid;

/// A superuser with NO grant of `epigraph_seed`, direct or indirect.
const NONSEED_SUPERUSER: &str = "seedx_nonseed_superuser";
/// A superuser that reaches `epigraph_seed` only through [`SEED_VIA`].
const SEED_SUPERUSER: &str = "seedx_seed_superuser";
/// The intermediate role between [`SEED_SUPERUSER`] and `epigraph_seed`.
const SEED_VIA: &str = "seedx_seed_via";
/// A non-superuser holding an ADMIN-only grant of `epigraph_seed` (admin
/// true, inherit false, set false): it administers the role's membership, it
/// does not act as the role.
const ADMIN_ONLY: &str = "seedx_admin_only";
/// A non-superuser holding an ADMIN-only grant of [`SEED_VIA`], which is
/// itself a real seed: the ADMIN-only edge is one hop from `epigraph_seed`.
const ADMIN_VIA: &str = "seedx_admin_via";

/// The role DDL, in the one order every test issues it.
const ROLE_DDL: &[&str] = &[
    "CREATE ROLE seedx_nonseed_superuser NOLOGIN SUPERUSER",
    "CREATE ROLE seedx_seed_superuser NOLOGIN SUPERUSER",
    "CREATE ROLE seedx_seed_via NOLOGIN",
    "CREATE ROLE seedx_admin_only NOLOGIN",
    "CREATE ROLE seedx_admin_via NOLOGIN",
    "GRANT epigraph_seed TO seedx_seed_via",
    "GRANT seedx_seed_via TO seedx_seed_superuser",
    "GRANT epigraph_seed TO seedx_admin_only WITH ADMIN TRUE, INHERIT FALSE, SET FALSE",
    "GRANT seedx_seed_via TO seedx_admin_via WITH ADMIN TRUE, INHERIT FALSE, SET FALSE",
];

/// One connection, one open transaction, and the test roles created inside
/// it. Never committed: dropping it (or `rollback`) removes the roles.
async fn roles_tx(pool: &PgPool) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut tx = pool.begin().await.expect("begin the role transaction");
    for stmt in ROLE_DDL {
        tx.execute(*stmt).await.unwrap_or_else(|e| {
            panic!(
                "`{stmt}`: {e}. If this is `already exists`, a role of that name was \
                 COMMITTED on this cluster by something else; remove it once with `DROP ROLE \
                 IF EXISTS seedx_seed_superuser, seedx_admin_via, seedx_seed_via, \
                 seedx_admin_only, seedx_nonseed_superuser`"
            )
        });
    }
    tx
}

/// `SET SESSION AUTHORIZATION role` on the transaction's connection. NOT
/// `SET ROLE`: the triggers read `session_user`, which `SET ROLE` leaves alone.
async fn become_role(conn: &mut sqlx::PgConnection, role: &str) {
    conn.execute(format!("SET SESSION AUTHORIZATION {role}").as_str())
        .await
        .unwrap_or_else(|e| panic!("SET SESSION AUTHORIZATION {role}: {e}"));
}

async fn reset_role(conn: &mut sqlx::PgConnection) {
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("RESET SESSION AUTHORIZATION");
}

/// Run one statement that must FAIL, inside a savepoint so the failure does
/// not abort the enclosing transaction (and with it the roles).
async fn refused(
    conn: &mut sqlx::PgConnection,
    q: sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
    what: &str,
) -> sqlx::Error {
    conn.execute("SAVEPOINT seedx_refusal")
        .await
        .expect("savepoint");
    let e = q.execute(&mut *conn).await.expect_err(what);
    conn.execute("ROLLBACK TO SAVEPOINT seedx_refusal")
        .await
        .expect("rollback to savepoint");
    e
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

/// `(owner_group_id, visibility)` of one row, read on the transaction.
async fn tenancy_in(conn: &mut sqlx::PgConnection, table: &str, id: Uuid) -> (Uuid, String) {
    let row = sqlx::query(&format!(
        "SELECT owner_group_id, visibility FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .expect("read tenancy");
    (row.get(0), row.get(1))
}

/// `(rolsuper, pg_has_role(session_user, 'epigraph_seed', 'MEMBER'),
/// epigraph_session_is_seed())` as `role` sees itself.
async fn seed_facts(conn: &mut sqlx::PgConnection, role: &str) -> (bool, bool, bool) {
    become_role(conn, role).await;
    let r: (bool, bool, bool) = sqlx::query_as(
        "SELECT (SELECT rolsuper FROM pg_roles WHERE rolname = session_user), \
                pg_has_role(session_user, 'epigraph_seed', 'MEMBER'), \
                public.epigraph_session_is_seed()",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("seed facts");
    reset_role(conn).await;
    r
}

/// The precondition of every behavioural test below, asserted rather than
/// assumed WITHOUT calling the function under test: [`NONSEED_SUPERUSER`] is
/// a superuser that `pg_has_role` calls a seed member (the trap) and that
/// holds no `pg_auth_members` row of any kind.
async fn assert_nonseed_superuser(conn: &mut sqlx::PgConnection) {
    become_role(conn, NONSEED_SUPERUSER).await;
    let (sup, implied, grants): (bool, bool, i64) = sqlx::query_as(
        "SELECT (SELECT rolsuper FROM pg_roles WHERE rolname = session_user), \
                pg_has_role(session_user, 'epigraph_seed', 'MEMBER'), \
                (SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member \
                  WHERE r.rolname = session_user)",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("precondition facts");
    reset_role(conn).await;
    assert!(sup, "{NONSEED_SUPERUSER} must be a superuser");
    assert!(
        implied,
        "pg_has_role must report a superuser as a member of epigraph_seed; that implication \
         is the defect migration 216 routes around, and these tests are only meaningful \
         while it holds"
    );
    assert_eq!(
        grants, 0,
        "{NONSEED_SUPERUSER} must hold no role grant at all"
    );
}

const INSERT_UNDECLARED_CLAIM: &str =
    "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) \
     VALUES (gen_random_uuid(), $1, $2, 0.7, $3, true) RETURNING id";

// =============================================================================
// THE DEFECT, behaviourally: one test per trigger body that has a reachable
// seed arm (claims, and a parentless root). The derived body's seed arm is
// pinned structurally below.
// =============================================================================

/// An undeclared claim written on a superuser session that holds no grant of
/// `epigraph_seed` must RAISE 23502, as it does for every other non-seed
/// writer (D1: tenancy is declared, never defaulted). Before migration 216 it
/// was silently stamped `('public', <seed group>)`: this is how production
/// claims written over superuser DSNs became owned by a memberless group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_superuser_undeclared_claim_is_refused_not_stamped_onto_the_seed_group(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "seedx-author").await;
    let mut tx = roles_tx(&pool).await;
    assert_nonseed_superuser(&mut tx).await;

    become_role(&mut tx, NONSEED_SUPERUSER).await;
    let err = refused(
        &mut tx,
        sqlx::query(INSERT_UNDECLARED_CLAIM)
            .bind("undeclared on a superuser session")
            .bind(vec![31u8; 32])
            .bind(agent),
        "claims accepted an undeclared INSERT on a superuser that holds no grant of \
         epigraph_seed: the seed escape hatch fired on superuser implication (backlog \
         0512ca33)",
    )
    .await;
    reset_role(&mut tx).await;
    assert_eq!(sqlstate(&err).as_deref(), Some("23502"), "got {err}");
    assert!(
        err.to_string().contains("epigraph tenancy"),
        "the refusal must be the tenancy trigger's own, not an incidental constraint: {err}"
    );
    tx.rollback().await.expect("rollback");
}

/// A parentless root row (here `frames`) written undeclared on a superuser
/// session that holds no grant must RAISE 23502. Before 216 it landed on the
/// seed group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_superuser_undeclared_root_row_is_refused(pool: PgPool) {
    let mut tx = roles_tx(&pool).await;
    assert_nonseed_superuser(&mut tx).await;
    become_role(&mut tx, NONSEED_SUPERUSER).await;
    let err = refused(
        &mut tx,
        sqlx::query("INSERT INTO frames (name, hypotheses) VALUES ('seedx-root', ARRAY['a','b'])"),
        "frames accepted an undeclared INSERT on a superuser that holds no grant of \
         epigraph_seed: the root row took the seed escape hatch (backlog 0512ca33)",
    )
    .await;
    reset_role(&mut tx).await;
    assert_eq!(sqlstate(&err).as_deref(), Some("23502"), "got {err}");
    tx.rollback().await.expect("rollback");
}

/// The hatch itself still works for a session that WAS granted the role, here
/// a superuser that reaches it through an intermediate role, so the grant is
/// what decides and superuser status is not. Both the claim and the root body
/// stamp `('public', <seed group>)`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_superuser_with_an_explicit_seed_grant_still_takes_the_hatch(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "seedx-seeded").await;
    let seed = fixture::seed_group(&pool).await;
    let mut tx = roles_tx(&pool).await;
    become_role(&mut tx, SEED_SUPERUSER).await;
    let claim: Uuid = sqlx::query_scalar(INSERT_UNDECLARED_CLAIM)
        .bind("seeded")
        .bind(vec![35u8; 32])
        .bind(agent)
        .fetch_one(&mut *tx)
        .await
        .expect("an explicitly granted seed takes the hatch on claims");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ('seedx-seeded', ARRAY['a','b']) \
         RETURNING id",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("an explicitly granted seed takes the hatch on a root");
    reset_role(&mut tx).await;
    assert_eq!(
        tenancy_in(&mut tx, "claims", claim).await,
        (seed, "public".to_string())
    );
    assert_eq!(
        tenancy_in(&mut tx, "frames", frame).await,
        (seed, "public".to_string())
    );
    tx.rollback().await.expect("rollback");
}

// =============================================================================
// The membership predicate
// =============================================================================

/// What `epigraph_session_is_seed()` answers, per kind of session: a
/// superuser without a grant is NOT a seed although `pg_has_role` says it is;
/// a superuser that reaches the role through an intermediate grant IS; the
/// application role is not.
#[sqlx::test(migrations = "../../migrations")]
async fn superuser_seed_membership_is_explicit_not_implied(pool: PgPool) {
    let mut tx = roles_tx(&pool).await;
    assert_eq!(
        seed_facts(&mut tx, NONSEED_SUPERUSER).await,
        (true, true, false),
        "(rolsuper, pg_has_role, epigraph_session_is_seed) for a superuser with no grant"
    );
    assert_eq!(
        seed_facts(&mut tx, SEED_SUPERUSER).await,
        (true, true, true),
        "a superuser granted epigraph_seed through {SEED_VIA} must be a seed: the walk over \
         pg_auth_members follows indirect grants"
    );
    assert_eq!(
        seed_facts(&mut tx, "epigraph_app").await,
        (false, false, false),
        "the application role is not a seed"
    );
    tx.rollback().await.expect("rollback");
}

/// An ADMIN-only grant (admin true, inherit false, set false) administers the
/// role's membership; it does not confer the role. `pg_has_role(..., 'MEMBER')`
/// counts it anyway, which is the same shape of trap as superuser
/// implication. PostgreSQL 16 also writes such a grant on its own (a
/// non-superuser CREATEROLE role that creates a role gets an ADMIN-only grant
/// back to it), so this is not only a hand-made case. Neither the direct edge
/// nor an ADMIN-only edge one hop from `epigraph_seed` may make a seed.
#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_only_grant_of_the_seed_role_is_not_a_seed(pool: PgPool) {
    let mut tx = roles_tx(&pool).await;
    for role in [ADMIN_ONLY, ADMIN_VIA] {
        let (sup, implied, explicit) = seed_facts(&mut tx, role).await;
        assert!(!sup, "{role} is not a superuser");
        assert!(
            implied,
            "precondition: pg_has_role(MEMBER) counts {role}'s ADMIN-only edge; without that \
             the test would not be exercising the trap"
        );
        assert!(
            !explicit,
            "{role} holds only an ADMIN-only grant on the path to epigraph_seed and was \
             reported a seed: an edge that confers neither INHERIT nor SET was followed"
        );
    }
    tx.rollback().await.expect("rollback");
}

/// Structurally, from the LIVE catalog: none of the three `*_require_tenancy`
/// bodies, nor `epigraph_session_is_seed()`, CALLS `pg_has_role` (the one
/// predicate a superuser satisfies without a grant), and each of the three
/// asks `epigraph_session_is_seed()` instead. The behavioural tests cover
/// `claims` and one root; this covers the derived body too, whose seed arm no
/// row with a parent claim reaches, and any later redefinition of the others.
#[sqlx::test(migrations = "../../migrations")]
async fn no_require_tenancy_body_asks_pg_has_role(pool: PgPool) {
    let bodies: Vec<(String, String)> = sqlx::query_as(
        "SELECT p.proname::text, p.prosrc FROM pg_proc p \
           JOIN pg_namespace n ON n.oid = p.pronamespace \
          WHERE n.nspname = 'public' \
            AND p.proname IN ('epigraph_claims_require_tenancy', \
                              'epigraph_derived_require_tenancy', \
                              'epigraph_root_require_tenancy', 'epigraph_session_is_seed') \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("read bodies");
    let names: Vec<&str> = bodies.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "epigraph_claims_require_tenancy",
            "epigraph_derived_require_tenancy",
            "epigraph_root_require_tenancy",
            "epigraph_session_is_seed",
        ],
        "all four functions must exist"
    );
    for (name, src) in &bodies {
        assert!(
            !src.contains("pg_has_role("),
            "{name} calls pg_has_role, which every superuser satisfies (migration 216)"
        );
        if name != "epigraph_session_is_seed" {
            assert!(
                src.contains("IF public.epigraph_session_is_seed() THEN"),
                "{name} must key its seed arm on public.epigraph_session_is_seed()"
            );
        }
    }
}

/// The API's two boot posture probes ask the seed question through
/// `seed_posture::SESSION_IS_SEED_SQL`, an inline copy of 216's walk (one
/// statement has to parse below 216 too, so it cannot name the function
/// directly). The copy must give the trigger's answer for every kind of
/// session, and below 216 it must not error and must give 074's answer.
#[sqlx::test(migrations = "../../migrations")]
async fn the_boot_probe_asks_the_seed_question_the_triggers_ask(pool: PgPool) {
    use epigraph_db::repos::seed_posture::{SEED_FUNCTION_EXISTS_SQL, SESSION_IS_SEED_SQL};
    let both = format!(
        "SELECT {SESSION_IS_SEED_SQL}, public.epigraph_session_is_seed(), \
                {SEED_FUNCTION_EXISTS_SQL}"
    );
    let mut tx = roles_tx(&pool).await;
    for (role, want) in [
        (NONSEED_SUPERUSER, false),
        (SEED_SUPERUSER, true),
        (ADMIN_ONLY, false),
        (ADMIN_VIA, false),
        ("epigraph_app", false),
    ] {
        become_role(&mut tx, role).await;
        let got: (bool, bool, bool) = sqlx::query_as(&both)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("probe as {role}: {e}"));
        reset_role(&mut tx).await;
        assert_eq!(
            got,
            (want, want, true),
            "as {role}: (boot probe, epigraph_session_is_seed(), function exists). The boot \
             probe must answer the question the triggers ask"
        );
    }

    // Below 216 the function does not exist. Functions are per database, so
    // dropping it here touches no other test; the rollback restores it. CASCADE
    // is not needed: plpgsql bodies do not record a dependency on it.
    tx.execute("DROP FUNCTION public.epigraph_session_is_seed()")
        .await
        .expect("drop the function inside the transaction");
    become_role(&mut tx, NONSEED_SUPERUSER).await;
    let below: (bool, bool) = sqlx::query_as(&format!(
        "SELECT {SESSION_IS_SEED_SQL}, {SEED_FUNCTION_EXISTS_SQL}"
    ))
    .fetch_one(&mut *tx)
    .await
    .expect("below 216 the probe must still parse and run");
    reset_role(&mut tx).await;
    assert_eq!(
        below,
        (true, false),
        "below 216 the triggers ask pg_has_role, which a superuser satisfies, so the probe \
         must report the superuser as a seed there"
    );
    tx.rollback().await.expect("rollback");
}

// =============================================================================
// The undo runbook
// =============================================================================

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The embedded migrations with `version <= max`.
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

/// Every function in `public`, hashed by its whole definition
/// (`pg_get_functiondef`: SECURITY DEFINER, the pinned `search_path`,
/// volatility and body) with its owner and ACL. 216 touches functions only.
async fn function_catalog(pool: &PgPool) -> std::collections::BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("function catalog");
    rows.into_iter().collect()
}

/// `docs/runbooks/216-undo.sql` returns every function in `public` to its
/// definition below 216 (which pins that it restates 074's three bodies byte
/// for byte, owner and ACL included), and a second run changes nothing.
/// Mutation: one character of a restated body edited, or the DROP removed ->
/// that function is named in the diff.
#[sqlx::test(migrations = false)]
async fn the_216_undo_returns_the_catalog_below_216(pool: PgPool) {
    migrate(&pool, &up_to(215)).await;
    let before = function_catalog(&pool).await;
    migrate(&pool, &up_to(216)).await;
    let through = function_catalog(&pool).await;
    let changed: std::collections::BTreeSet<String> = through
        .symmetric_difference(&before)
        .map(|e| e.split('(').next().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        changed,
        [
            "epigraph_claims_require_tenancy",
            "epigraph_derived_require_tenancy",
            "epigraph_root_require_tenancy",
            "epigraph_session_is_seed",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        "CALIBRATION: 216 re-states the three *_require_tenancy bodies and adds \
         epigraph_session_is_seed(), nothing else"
    );

    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/216-undo.sql"),
    )
    .expect("read the undo runbook");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = function_catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run every public function is exactly as below 216"
        );
    }
}
