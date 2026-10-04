//! The census of migration 126's elevated arms (elevation plan EL-7, §1.5),
//! read from the CATALOG, never from the migration text.
//!
//! Every table with row security sits in exactly ONE checked-in list below:
//! armed read + write refusal, armed read only, armed write refusal only, or
//! excluded with a reason. A new row-security table fails
//! `every_row_security_table_is_classified_exactly_once` until it is placed.
//! Each armed table carries exactly its elevated policies, each pinned by
//! name, command, PERMISSIVE vs RESTRICTIVE, role and expression text, so a
//! missing policy, a swapped kind, a `TO public` or a widened expression each
//! fail `every_armed_table_carries_exactly_its_elevated_policies`. What an
//! elevated session reads through the arm is pinned in `elevated_viewer.rs`.
//!
//! The lock plan (one table per committed `DO` block, a transaction-local
//! lock timeout, drop-before-create) is pinned here by running the file
//! itself: a rerun changes nothing, and a held lock on one table fails the
//! file there, leaves the tables before it armed, and a rerun finishes it.
//!
//! Each test names the mutation it was run against ("Verified to fail").

use sqlx::{Connection, Executor, PgPool};
use std::collections::{BTreeMap, BTreeSet};

/// The migration itself, run again by the lock tests exactly as sqlx runs it
/// (one simple-query message over the whole file).
const MIGRATION_126: &str = include_str!("../../../migrations/126_elevated_arms.sql");

/// Read arm + write refusal: the classes DESIGN 6.3 arms. `(table, class)`.
const ARMED_READ_WRITE: &[(&str, &str)] = &[
    ("agents", "T-AGENT"),
    ("challenges", "T-DER"),
    ("claim_cluster_membership", "T-DER"),
    ("claim_clusters", "T-DER"),
    ("claim_frames", "T-DER"),
    ("claim_neighborhood_membership", "T-DER"),
    ("claim_signature_revocations", "T-DER"),
    ("claim_versions", "T-DER"),
    ("claims", "T-OWN"),
    ("contexts", "T-OWN"),
    ("ds_bayesian_divergence", "T-DER"),
    ("ds_combined_beliefs", "T-DER"),
    ("edges", "T-EDGE"),
    ("entity_mentions", "T-DER"),
    ("evidence", "T-OWN"),
    ("frames", "T-OWN"),
    ("group_memberships", "T-GROUP"),
    ("groups", "T-GROUP"),
    ("harvester_claim_provenance", "T-DER"),
    ("harvester_fragments", "T-OWN"),
    ("mass_functions", "T-DER"),
    ("perspectives", "T-OWN"),
    ("reasoning_traces", "T-DER"),
    ("recall_events", "T-OWN-PRIV"),
    ("triples", "T-DER"),
];

/// Read arm only (T-AUDIT): appended by definers and an allowlisted append
/// policy while the caller may be elevated, so a refusal would break the
/// trail. Neither grants the application an UPDATE or a DELETE.
const ARMED_READ_ONLY: &[(&str, &str)] = &[
    ("privatization_audit", "T-AUDIT"),
    ("security_events", "T-AUDIT"),
];

/// Write refusal only (T-DROP): retired machinery the application can still
/// write, so an elevated session must not; not a class DESIGN 6.3 widens, and
/// the encryption tables and `group_key_epochs` hold ciphertext and wrapped
/// key material.
const ARMED_REFUSE_ONLY: &[(&str, &str)] = &[
    ("claim_encryption", "T-DROP"),
    ("claim_version_encryption", "T-DROP"),
    ("communities", "T-DROP"),
    ("edge_encryption", "T-DROP"),
    ("evidence_encryption", "T-DROP"),
    ("experiment_entity_mentions", "T-DROP"),
    ("experiment_triples", "T-DROP"),
    ("group_key_epochs", "T-DROP"),
];

/// No elevated policy, each for a reason. None grants the application a write
/// (`no_excluded_or_read_only_table_lets_the_application_write_unrefused`).
const EXCLUDED: &[(&str, &str)] = &[
    (
        "elevation_sessions",
        "the elevation record itself (125); read by epigraph_is_elevated()",
    ),
    ("elevation_tickets", "the elevation record itself (125)"),
    (
        "elevated_access",
        "the log of elevated reads (127): read by its subjects' admins and the audit reader, \
         written by the recorder definer while the caller IS elevated",
    ),
    ("person_authenticators", "passkey material (124)"),
    ("passkey_enrollments", "passkey enrollment state (124)"),
    (
        "role_assignments",
        "read by epigraph_is_elevated(); definer-written governance (123)",
    ),
    (
        "platform_roles",
        "read by epigraph_is_elevated(); a public catalog already (123)",
    ),
    (
        "operator_links",
        "read by epigraph_is_elevated(); definer-written (107)",
    ),
    ("instance_admins", "frozen legacy registry (123)"),
    (
        "evidence_visibility_pins",
        "definer-read, maintenance-written (110)",
    ),
    (
        "privatization_plans",
        "its admin read arm becomes elevated behind the admin-scope arming switch, later",
    ),
    (
        "privatization_plan_items",
        "its admin read arm becomes elevated behind the admin-scope arming switch, later",
    ),
    (
        "jobs",
        "bypass-only: the application reads and writes no row",
    ),
    (
        "rls_canary",
        "bypass-only boot canary: the application reads and writes no row",
    ),
];

/// THE READ-PATH WRITE CENSUS (plan §1.5), checked in. An elevated READ breaks
/// if a read route or read tool writes, as a side effect, into a table the
/// elevated session may not write. Measured on the branch by a static scan:
/// (1) every `ScopedPool::read_as` / `acquire_as` site in `epigraph-api`
/// reaches only read repository calls; (2) no GET handler opens
/// `write_as` / `begin_as` / `begin_claim_write`; (3) the MCP read tools read
/// on the server's unstamped pool (never elevated); (4) the side-effect writes
/// that DO run while a request is elevated are listed here with how they stay
/// served. The scan follows no helper calls, so it is a heuristic; the
/// elevated-read tests through the real router and the MCP tool path
/// (`epigraph-api/tests/elevation_ceremony.rs`,
/// `epigraph-mcp/tests/elevated_request_viewer.rs`) are its measurement.
///
/// `(table, site, how it stays served while elevated)`. `allowed` = the
/// table carries no elevated refusal, so the write itself is admitted;
/// `unelevated` = the write runs on a connection stamped WITHOUT the
/// elevation (a detached task's scoped viewer, or a definer).
const READ_PATH_WRITES: &[(&str, &str, &str)] = &[
    (
        "recall_events",
        "MCP recall / recall_with_context audit (tools::recall::write_recall_audit)",
        "unelevated",
    ),
    (
        "security_events",
        "request-path audit appends (oauth / platform events)",
        "allowed",
    ),
    (
        "privatization_audit",
        "privatization read routes' audit appends",
        "allowed",
    ),
    (
        "elevated_access",
        "the per-access recorder (API response layer, MCP tool-call wrapper; definer 127)",
        "allowed",
    ),
];

const READ_ARM: &str = "( SELECT epigraph_is_elevated() AS epigraph_is_elevated)";
const REFUSAL: &str = "(NOT ( SELECT epigraph_is_elevated() AS epigraph_is_elevated))";

/// One expected or observed elevated policy: `(name, cmd, permissive, roles,
/// USING, WITH CHECK)`.
type Pol = (
    String,
    String,
    bool,
    Vec<String>,
    Option<String>,
    Option<String>,
);

/// One catalog row: `(table, name, cmd, permissive, roles, USING, WITH CHECK)`.
type PolRow = (
    String,
    String,
    String,
    bool,
    Vec<String>,
    Option<String>,
    Option<String>,
);

fn read_arm(t: &str) -> Pol {
    (
        format!("{t}_elevated_read"),
        "r".into(),
        true,
        vec!["epigraph_app".into()],
        Some(READ_ARM.into()),
        None,
    )
}

fn refusals(t: &str) -> Vec<Pol> {
    vec![
        (
            format!("{t}_elevated_no_insert"),
            "a".into(),
            false,
            vec!["epigraph_app".into()],
            None,
            Some(REFUSAL.into()),
        ),
        (
            format!("{t}_elevated_no_update"),
            "w".into(),
            false,
            vec!["epigraph_app".into()],
            Some(REFUSAL.into()),
            None,
        ),
        (
            format!("{t}_elevated_no_delete"),
            "d".into(),
            false,
            vec!["epigraph_app".into()],
            Some(REFUSAL.into()),
            None,
        ),
    ]
}

fn expected() -> BTreeMap<String, BTreeSet<Pol>> {
    let mut m: BTreeMap<String, BTreeSet<Pol>> = BTreeMap::new();
    for (t, _) in ARMED_READ_WRITE {
        let mut s: BTreeSet<Pol> = refusals(t).into_iter().collect();
        s.insert(read_arm(t));
        m.insert((*t).to_string(), s);
    }
    for (t, _) in ARMED_READ_ONLY {
        m.insert((*t).to_string(), [read_arm(t)].into_iter().collect());
    }
    for (t, _) in ARMED_REFUSE_ONLY {
        m.insert((*t).to_string(), refusals(t).into_iter().collect());
    }
    for (t, _) in EXCLUDED {
        m.insert((*t).to_string(), BTreeSet::new());
    }
    m
}

/// Every policy in `public` that names `epigraph_is_elevated` in either
/// expression, or whose name says it is an elevated policy, by table.
async fn observed<'e, E: Executor<'e, Database = sqlx::Postgres>>(
    e: E,
) -> BTreeMap<String, BTreeSet<Pol>> {
    let rows: Vec<PolRow> = sqlx::query_as(
        "SELECT c.relname::text, p.polname::text, p.polcmd::text, p.polpermissive, \
                ARRAY(SELECT CASE WHEN r = 0 THEN 'public' ELSE r::regrole::text END \
                        FROM unnest(p.polroles) r ORDER BY 1), \
                pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid) \
           FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
            AND (p.polname LIKE '%\\_elevated\\_%' \
                 OR coalesce(pg_get_expr(p.polqual, p.polrelid), '') \
                    || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') \
                    LIKE '%epigraph_is_elevated%')",
    )
    .fetch_all(e)
    .await
    .expect("the elevated policy catalog");
    let mut m: BTreeMap<String, BTreeSet<Pol>> = BTreeMap::new();
    for (t, name, cmd, permissive, roles, using, check) in rows {
        m.entry(t)
            .or_default()
            .insert((name, cmd, permissive, roles, using, check));
    }
    m
}

fn all_listed() -> Vec<&'static str> {
    ARMED_READ_WRITE
        .iter()
        .chain(ARMED_READ_ONLY)
        .chain(ARMED_REFUSE_ONLY)
        .chain(EXCLUDED)
        .map(|(t, _)| *t)
        .collect()
}

/// Every table in `public` with row security is in exactly one list, and
/// every listed table exists with row security.
///
/// Verified to fail with a list entry deleted (an unclassified table), with a
/// table listed twice, and with a new row-security table created in the test
/// database (unclassified).
#[sqlx::test(migrations = "../../migrations")]
async fn every_row_security_table_is_classified_exactly_once(pool: PgPool) {
    let catalog: BTreeSet<String> = sqlx::query_scalar(
        "SELECT relname::text FROM pg_class \
          WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' AND relrowsecurity",
    )
    .fetch_all(&pool)
    .await
    .expect("row-security tables")
    .into_iter()
    .collect();
    assert!(
        catalog.len() >= 40,
        "CALIBRATION: the row-security set collapsed ({}), every assertion below is vacuous",
        catalog.len()
    );

    let listed = all_listed();
    let mut seen = BTreeSet::new();
    let twice: Vec<&str> = listed
        .iter()
        .copied()
        .filter(|t| !seen.insert(*t))
        .collect();
    assert!(
        twice.is_empty(),
        "listed in more than one census list (or twice in one): {twice:?}"
    );
    let listed: BTreeSet<String> = listed.into_iter().map(str::to_string).collect();
    let unclassified: Vec<&String> = catalog.difference(&listed).collect();
    assert!(
        unclassified.is_empty(),
        "row-security tables in no census list: {unclassified:?}. Place each in \
         migration 126's census (armed read + refusal, read only, refusal only, or \
         excluded with a reason), arm it in a migration if it is armed, and list it here."
    );
    let stale: Vec<&String> = listed.difference(&catalog).collect();
    assert!(
        stale.is_empty(),
        "listed but not a row-security table: {stale:?}"
    );
}

/// Each armed table carries EXACTLY its elevated policies (the read arm, the
/// three refusals, or both), each with its command, kind, role
/// (`epigraph_app` only: a definer runs as `epigraph_maintenance` and must
/// not meet them) and expression text; an excluded table carries none, and no
/// other policy anywhere reads `epigraph_is_elevated()`.
///
/// Verified to fail with a refusal dropped (missing), with the read arm
/// created RESTRICTIVE and a refusal PERMISSIVE (kind swapped), with a refusal
/// `TO public`, with the read arm's USING widened to `true`, and with an
/// excluded table (`role_assignments`) given a read arm.
#[sqlx::test(migrations = "../../migrations")]
async fn every_armed_table_carries_exactly_its_elevated_policies(pool: PgPool) {
    let want = expected();
    let got = observed(&pool).await;
    assert!(
        got.values().map(BTreeSet::len).sum::<usize>() >= 100,
        "CALIBRATION: migration 126's policies are absent; every assertion is vacuous"
    );
    let mut wrong = Vec::new();
    for (t, w) in &want {
        let g = got.get(t).cloned().unwrap_or_default();
        if &g != w {
            let missing: Vec<_> = w.difference(&g).collect();
            let extra: Vec<_> = g.difference(w).collect();
            wrong.push(format!("{t}: missing {missing:?}; unexpected {extra:?}"));
        }
    }
    for (t, g) in &got {
        if !want.contains_key(t) {
            wrong.push(format!("{t} (not a listed table): {g:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "the elevated policies differ from the census:\n  {}",
        wrong.join("\n  ")
    );
}

/// The privilege invariant behind the census: every row-security table on
/// which the APPLICATION holds INSERT, UPDATE or DELETE (table-level, or
/// UPDATE on any column, as `agents` has) refuses that write to an elevated
/// session, unless it is a T-AUDIT table (read only, by design) or a
/// bypass-only table (whose only policy admits no application row at all).
/// So an elevated session can write nothing an ordinary one could, except
/// the audit trail.
///
/// Verified to fail with a T-DROP table moved to the excluded list and its
/// refusals dropped (a writable table without refusal), and with an
/// application UPDATE granted on an excluded table.
#[sqlx::test(migrations = "../../migrations")]
async fn no_excluded_or_read_only_table_lets_the_application_write_unrefused(pool: PgPool) {
    let writable: Vec<(String, bool, bool, bool)> = sqlx::query_as(
        "SELECT c.relname::text, \
                has_table_privilege('epigraph_app', c.oid, 'INSERT'), \
                has_table_privilege('epigraph_app', c.oid, 'UPDATE') \
                  OR has_any_column_privilege('epigraph_app', c.oid, 'UPDATE'), \
                has_table_privilege('epigraph_app', c.oid, 'DELETE') \
           FROM pg_class c \
          WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' \
            AND c.relrowsecurity",
    )
    .fetch_all(&pool)
    .await
    .expect("application privileges");
    let refused: BTreeSet<&str> = ARMED_READ_WRITE
        .iter()
        .chain(ARMED_REFUSE_ONLY)
        .map(|(t, _)| *t)
        .collect();
    let audit: BTreeSet<&str> = ARMED_READ_ONLY.iter().map(|(t, _)| *t).collect();
    const BYPASS_ONLY: &[&str] = &["jobs", "rls_canary"];
    let mut writable_count = 0;
    let mut unrefused = Vec::new();
    for (t, ins, upd, del) in &writable {
        if !(ins | upd | del) {
            continue;
        }
        writable_count += 1;
        if refused.contains(t.as_str()) {
            continue;
        }
        if audit.contains(t.as_str()) && !upd && !del {
            continue;
        }
        if BYPASS_ONLY.contains(&t.as_str()) {
            continue;
        }
        unrefused.push(format!("{t} (insert={ins}, update={upd}, delete={del})"));
    }
    assert!(
        writable_count >= 30,
        "CALIBRATION: the application-writable set collapsed ({writable_count})"
    );
    assert!(
        unrefused.is_empty(),
        "the application may write these row-security tables and an elevated session is \
         not refused: {unrefused:?}"
    );

    // The two bypass-only tables really are: their policies name no session
    // predicate beyond the two bypass helpers.
    for t in BYPASS_ONLY {
        let bodies: Vec<String> = sqlx::query_scalar(
            "SELECT coalesce(pg_get_expr(polqual, polrelid), '') || ' ' || \
                    coalesce(pg_get_expr(polwithcheck, polrelid), '') \
               FROM pg_policy WHERE polrelid = $1::regclass",
        )
        .bind(*t)
        .fetch_all(&pool)
        .await
        .expect("bypass-only bodies");
        assert!(!bodies.is_empty(), "{t} has a policy");
        for b in bodies {
            let rest = b
                .replace("( SELECT epigraph_bypass() AS epigraph_bypass)", "")
                .replace(
                    "( SELECT epigraph_definer_bypass() AS epigraph_definer_bypass)",
                    "",
                )
                .replace(['(', ')', ' '], "")
                .replace("OR", "");
            assert!(
                rest.is_empty(),
                "{t} is listed bypass-only but a policy admits more: {b}"
            );
        }
    }
}

/// The read-path write census is consistent with the catalog: an `allowed`
/// write lands on a table that carries no elevated refusal, an `unelevated`
/// one may land on a refused table (it does not run as the elevated viewer),
/// and every census table is classified.
///
/// Verified to fail with `security_events` given 126's refusals (an
/// `allowed` entry on a refused table).
#[sqlx::test(migrations = "../../migrations")]
async fn the_read_path_write_census_matches_the_catalog(pool: PgPool) {
    let got = observed(&pool).await;
    let listed: BTreeSet<&str> = all_listed().into_iter().collect();
    for (t, site, how) in READ_PATH_WRITES {
        assert!(listed.contains(t), "{t} ({site}) is not classified");
        let refuses = got
            .get(*t)
            .is_some_and(|s| s.iter().any(|p| !p.2 && p.0.contains("_elevated_no_")));
        match *how {
            "allowed" => assert!(
                !refuses,
                "{t}: {site} writes while the request is elevated, and the table refuses \
                 an elevated write"
            ),
            "unelevated" => {}
            other => panic!("{t}: unknown census decision {other}"),
        }
    }
}

// =====================================================================
// The lock plan, measured by running the file again
// =====================================================================

async fn lock_timeout(conn: &mut sqlx::PgConnection) -> String {
    sqlx::query_scalar("SELECT current_setting('lock_timeout')")
        .fetch_one(&mut *conn)
        .await
        .expect("lock_timeout")
}

/// Drop every elevated policy, as a stand-in for "126 not yet applied".
async fn disarm(conn: &mut sqlx::PgConnection) {
    sqlx::raw_sql(
        "DO $$ DECLARE r record; BEGIN \
           FOR r IN SELECT p.polname, c.relname FROM pg_policy p \
                      JOIN pg_class c ON c.oid = p.polrelid \
                     WHERE c.relnamespace = 'public'::regnamespace \
                       AND p.polname LIKE '%\\_elevated\\_%' LOOP \
             EXECUTE format('DROP POLICY %I ON public.%I', r.polname, r.relname); \
           END LOOP; END $$",
    )
    .execute(&mut *conn)
    .await
    .expect("disarm");
}

/// Running 126 again changes nothing: the same policies, the same bodies, and
/// the migrator connection's `lock_timeout` is what it was before (each
/// block's timeout is transaction-local).
///
/// Verified to fail with one block's `set_config(..., true)` made `false`
/// (the timeout outlives the file), and with a `DROP POLICY IF EXISTS`
/// removed (the rerun fails: the policy already exists).
#[sqlx::test(migrations = "../../migrations")]
async fn rerunning_126_changes_nothing(pool: PgPool) {
    let before = observed(&pool).await;
    let mut conn = pool.acquire().await.expect("a connection");
    let timeout_before = lock_timeout(&mut conn).await;
    sqlx::raw_sql(MIGRATION_126)
        .execute(&mut *conn)
        .await
        .expect("126 reruns cleanly");
    assert_eq!(
        lock_timeout(&mut conn).await,
        timeout_before,
        "the per-table lock timeout must not outlive the file on the migrator's connection"
    );
    assert_eq!(observed(&mut *conn).await, before, "a rerun is a no-op");
    assert_eq!(
        before,
        expected()
            .into_iter()
            .filter(|(_, s)| !s.is_empty())
            .collect()
    );
}

/// A held lock on ONE table fails the file at that table within its lock
/// timeout; the tables committed before it stay armed, the table and those
/// after it are not, the migrator connection keeps its own `lock_timeout`;
/// and once the lock is released a rerun arms everything.
///
/// The held lock is `ACCESS SHARE` (any reader's), which `CREATE POLICY`'s
/// ACCESS EXCLUSIVE waits for.
///
/// Verified to fail with the `COMMIT;` after `claim_versions` removed (its
/// block and the ones before it back to the previous COMMIT roll back with
/// the failure, so `claim_versions` is not armed) and with one block's lock
/// timeout removed (the file waits for the lock: the 20 s bound fires).
#[sqlx::test(migrations = "../../migrations")]
async fn a_held_lock_fails_one_table_and_a_rerun_resumes(pool: PgPool) {
    let full = observed(&pool).await;
    let url = {
        let db: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&pool)
            .await
            .expect("db");
        let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let (head, _) = base.rsplit_once('/').expect("a database url");
        format!("{head}/{db}")
    };
    let mut migrator = sqlx::PgConnection::connect(&url).await.expect("migrator");
    let mut holder = sqlx::PgConnection::connect(&url).await.expect("holder");
    disarm(&mut migrator).await;
    assert!(
        observed(&mut migrator).await.is_empty(),
        "CALIBRATION: disarmed"
    );
    let timeout_before = lock_timeout(&mut migrator).await;

    holder
        .execute("BEGIN; LOCK TABLE public.claims IN ACCESS SHARE MODE")
        .await
        .expect("hold a reader's lock on claims");
    let started = std::time::Instant::now();
    let failed = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        sqlx::raw_sql(MIGRATION_126).execute(&mut migrator),
    )
    .await
    .expect("the file must fail within its lock timeout, not wait for the lock");
    let elapsed = started.elapsed();
    let err = failed.expect_err("126 must fail on the locked table");
    let code = err
        .as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.to_string());
    assert_eq!(code.as_deref(), Some("55P03"), "lock_not_available: {err}");
    assert!(
        elapsed >= std::time::Duration::from_secs(2),
        "the lock timeout waited ({elapsed:?})"
    );
    assert_eq!(
        lock_timeout(&mut migrator).await,
        timeout_before,
        "the failed block's lock timeout did not outlive it"
    );

    let partial = observed(&mut migrator).await;
    let armed: BTreeSet<&str> = partial.keys().map(String::as_str).collect();
    let before_claims: BTreeSet<&str> = [
        "agents",
        "challenges",
        "claim_cluster_membership",
        "claim_clusters",
        "claim_frames",
        "claim_neighborhood_membership",
        "claim_signature_revocations",
        "claim_versions",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        armed, before_claims,
        "exactly the tables committed before the locked one are armed"
    );
    for t in &before_claims {
        assert_eq!(partial.get(*t), full.get(*t), "{t} is armed completely");
    }

    holder.execute("ROLLBACK").await.expect("release");
    sqlx::raw_sql(MIGRATION_126)
        .execute(&mut migrator)
        .await
        .expect("the rerun finishes");
    assert_eq!(observed(&mut migrator).await, full, "the rerun resumed");
}

// =====================================================================
// The undo
// =====================================================================

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

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

/// Every policy in `public`, by table and name, with its kind, command,
/// roles and both expressions.
async fn policies(pool: &PgPool) -> BTreeSet<String> {
    sqlx::query_scalar(
        "SELECT c.relname || '.' || p.polname || ' ' || p.polcmd::text || ' ' || \
                p.polpermissive::text || ' ' || p.polroles::regrole[]::text || ' ' || \
                coalesce(pg_get_expr(p.polqual, p.polrelid), '-') || ' ' || \
                coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '-') \
           FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("policies")
    .into_iter()
    .collect()
}

fn runbook(name: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/runbooks")
            .join(name),
    )
    .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// `docs/runbooks/126-undo.sql`, applied to a database that went 125 -> 126,
/// returns its policy set exactly to the same database's at 125; a rerun is a
/// no-op; and 125's undo, which refuses while any policy reads
/// `epigraph_is_elevated()`, then applies (the deploy order: 126-undo BEFORE
/// 125-undo). Cut at 126, not head, so a later migration cannot break it.
///
/// Verified to fail with one table's DROP of its read arm removed from the
/// undo (the policy is left behind, and 125-undo refuses).
#[sqlx::test(migrations = false)]
async fn the_undo_returns_the_policies_to_125_and_unblocks_its_undo(pool: PgPool) {
    migrate(&pool, &up_to(125)).await;
    let at_125 = policies(&pool).await;
    migrate(&pool, &up_to(126)).await;
    assert_ne!(
        policies(&pool).await,
        at_125,
        "CALIBRATION: 126 changed the policy set"
    );

    let undo = runbook("126-undo.sql");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("the undo applies");
    let after = policies(&pool).await;
    let left: Vec<&String> = after.difference(&at_125).collect();
    let lost: Vec<&String> = at_125.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the policies are not 125's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("the undo reruns");
    assert_eq!(policies(&pool).await, at_125, "a rerun is a no-op");

    sqlx::raw_sql(&runbook("125-undo.sql"))
        .execute(&pool)
        .await
        .expect("125-undo applies once 126 is undone");
}
