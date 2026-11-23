//! Every function that pins a `search_path`, SECURITY INVOKER included, lists
//! `pg_temp` LAST, and every trigger function pins one (backlog eff4aaf5,
//! migration 271).
//!
//! # The defect class
//!
//! A `search_path` that does not list `pg_temp` searches the session's
//! temporary schema FIRST for relation and type names (PostgreSQL's
//! documented resolution order; `definer_search_path_ratchet.rs`'s
//! `a_path_without_pg_temp_searches_the_temporary_schema_first` pins it).
//! Migration 190 fixed that for every SECURITY DEFINER function. It left the
//! SECURITY INVOKER functions that pin their own path, and an invoker body
//! runs as whoever calls it: inside a definer, as the definer's OWNER. A
//! trigger an application-executable definer's write fires, or a helper the
//! definer calls, that resets the path to one without `pg_temp`, so resolves
//! the CALLER's temporary types and relations with the owner's privileges. A
//! temporary domain's CHECK names any function the caller wrote, so the
//! caller's own code runs as the owner.
//!
//! An invoker trigger function that pins NO path inherits the path in effect
//! where it fires. Inside a definer that is the definer's (pg_temp last), but
//! a row trigger a foreign-key action fires can run as the referencing table's
//! owner with the SESSION's path, which the caller sets. So every trigger
//! function pins its own path, pg_temp last.
//!
//! # What is pinned
//!
//! * [`every_function_that_pins_a_search_path_lists_pg_temp_last`] -- no
//!   function outside the system schemas and extensions, definer or invoker,
//!   pins a path that omits `pg_temp` or lists it anywhere but last. No
//!   allowlist.
//! * [`every_trigger_function_pins_a_search_path`] -- no such function that
//!   returns `trigger` or is attached to a trigger is unpinned. No allowlist.
//! * [`an_application_login_cannot_run_its_own_type_as_the_definer_owner`] --
//!   the behavioural proof on REAL NOSUPERUSER logins: an application login
//!   plants a temporary `text` domain whose CHECK records `current_user`, then
//!   un-retracts a mass function through 184's application-executable definer,
//!   whose write fires 184's invoker retract guard. The guard's clear arm
//!   resolves the type name `text`; it must resolve `pg_catalog.text`, so the
//!   planted check never runs as `epigraph_maintenance`.
//! * [`migration_271_changes_only_search_paths`],
//!   [`migration_271_refuses_pg_temp_before_another_schema`],
//!   [`migration_271_pins_an_empty_path_and_an_unpinned_trigger_in_any_schema`],
//!   [`migration_271_refuses_a_crafted_stored_path_and_runs_none_of_it`],
//!   [`migration_271_reads_path_items_as_postgres_does`],
//!   [`the_271_precheck_lists_exactly_what_271_refuses`] and
//!   [`the_271_undo_restores_the_paths_below_271`] -- what 271 changes, its
//!   refusals (including a stored path whose items are SQL: 271 never splices
//!   catalog text into a statement, and an upper-case `PG_TEMP`, which
//!   PostgreSQL reads as `pg_temp`), its non-append branches, its precheck
//!   query and its undo runbook.
//! * [`a_lower_migration_applied_after_271_keeps_both_rules`] -- both rules in
//!   the PRODUCTION order: a test database applies migrations in version
//!   order, so 271 always runs last and masks a lower-numbered migration that
//!   re-states a path without `pg_temp`
//!   ([`in_version_order_271_masks_a_bad_lower_migration`] shows it), while
//!   production applies such a migration after 271. This test applies
//!   everything up to 235, then 271, then the rest.
//!
//! # The rule for later migrations
//!
//! A new function that pins a path lists `pg_temp` last (`pg_catalog,
//! pg_temp` on 172's form, or `pg_catalog, public, pg_temp`). A new trigger
//! function pins one. A `CREATE OR REPLACE` replaces the path whole, so a
//! re-statement of any function states its path with `pg_temp` last.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended for one test.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "support/retracted_bba_fixture.rs"]
mod retracted;

use epigraph_db::repos::mass_function::MassFunctionRepository;
use epigraph_db::visibility::Viewer;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::postgres::PgConnectOptions;
use sqlx::{ConnectOptions, Connection, PgConnection, PgPool};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Every function 271 changes on a database at main's head when 271 was
/// written: the nine whose pinned path omitted `pg_temp` (six of them
/// triggers) and the ten unpinned trigger functions. A later re-statement may
/// fix one of them first, so 271 changing FEWER is fine; changing one not
/// listed here is not (a new function must state its own path).
///
/// Do NOT add a function here to make a test pass. A new migration states
/// `pg_temp` last itself, and pins every trigger function it creates: in
/// production a migration numbered below 271 may be applied after it, and
/// 271 does not sweep it then.
const CHANGED_BY_271: &[&str] = &[
    "public.epigraph_agent_keys_attested_guard()",
    "public.epigraph_agents_competence_guard()",
    "public.epigraph_claims_supersedes_guard()",
    "public.epigraph_edge_writer_scope(text, text)",
    "public.epigraph_edges_repoint_unsign()",
    "public.epigraph_identity_attestor_faults()",
    "public.epigraph_lockdown_privileged()",
    "public.epigraph_mass_function_retract_guard()",
    "public.epigraph_match_candidates_stale_guard()",
    "public.cascade_delete_edges()",
    "public.epigraph_audit_immutable()",
    "public.epigraph_block_group_delete()",
    "public.epigraph_claims_block_widening()",
    "public.epigraph_no_public_sealed()",
    "public.epigraph_privatization_approver_guard()",
    "public.epigraph_privatization_plan_guard()",
    "public.raise_immutable_error()",
    "public.trigger_validate_edge_refs()",
    "public.update_updated_at_column()",
];

/// One function's catalog facts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Routine {
    secdef: bool,
    /// `search_path` as the catalog stores it, `None` when unpinned.
    path: Option<String>,
    /// Every `proconfig` entry, in order.
    config: Vec<String>,
    /// Returns `trigger`, or is attached to a (non-internal) trigger.
    trigger: bool,
    lang: String,
    owner: String,
    acl: Option<String>,
    volatile: String,
    src_md5: String,
}

type RoutineRow = (
    String,
    bool,
    Option<String>,
    Option<Vec<String>>,
    bool,
    String,
    String,
    Option<String>,
    String,
    String,
);

/// Every function and procedure outside the system schemas and outside any
/// extension, by `schema.name(argument types)`.
async fn routines(conn: &mut PgConnection) -> BTreeMap<String, Routine> {
    let rows: Vec<RoutineRow> = sqlx::query_as(
        "SELECT pg_catalog.format('%s.%s(%s)', n.nspname, p.proname, \
                                  pg_catalog.oidvectortypes(p.proargtypes)), \
                p.prosecdef, \
                (SELECT pg_catalog.substr(c, 13) FROM pg_catalog.unnest(p.proconfig) c \
                  WHERE c LIKE 'search_path=%' LIMIT 1), \
                p.proconfig, \
                p.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype \
                  OR EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t \
                              WHERE t.tgfoid = p.oid AND NOT t.tgisinternal), \
                l.lanname::pg_catalog.text, \
                pg_catalog.pg_get_userbyid(p.proowner)::pg_catalog.text, \
                p.proacl::pg_catalog.text, p.provolatile::pg_catalog.text, \
                pg_catalog.md5(p.prosrc) \
           FROM pg_catalog.pg_proc p \
           JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
           JOIN pg_catalog.pg_language l ON l.oid = p.prolang \
          WHERE p.prokind IN ('f', 'p') \
            AND n.nspname NOT IN ('pg_catalog', 'information_schema') \
            AND n.nspname !~ '^pg_(toast|temp)' \
            AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
                             WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass \
                               AND d.objid = p.oid AND d.deptype = 'e')",
    )
    .fetch_all(&mut *conn)
    .await
    .expect("read the functions");
    rows.into_iter()
        .map(
            |(sig, secdef, path, config, trigger, lang, owner, acl, volatile, src_md5)| {
                (
                    sig,
                    Routine {
                        secdef,
                        path,
                        config: config.unwrap_or_default(),
                        trigger,
                        lang,
                        owner,
                        acl,
                        volatile,
                        src_md5,
                    },
                )
            },
        )
        .collect()
}

async fn routines_of(pool: &PgPool) -> BTreeMap<String, Routine> {
    let mut conn = pool.acquire().await.expect("acquire");
    routines(&mut conn).await
}

/// The whitespace PostgreSQL's list parser skips around an item.
const PATH_SPACE: &[char] = &[' ', '\t', '\n', '\r', '\x0C', '\x0B'];

/// Each item of a stored `search_path` as PostgreSQL reads it: an unquoted
/// item ASCII lower-cased, a quoted one with its quotes stripped and `""`
/// unescaped. So `PG_TEMP` and `"pg_temp"` both read as `pg_temp`. 271's
/// sweep and postcondition and `docs/runbooks/271-precheck.sql` read items
/// the same way.
fn path_items(path: &str) -> Vec<String> {
    if path.trim_matches(PATH_SPACE).is_empty() {
        return Vec::new();
    }
    path.split(',')
        .map(|s| {
            let t = s.trim_matches(PATH_SPACE);
            if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
                t[1..t.len() - 1].replace("\"\"", "\"")
            } else {
                t.to_ascii_lowercase()
            }
        })
        .collect()
}

/// Why `path` does not list `pg_temp` exactly once, last; `None` when it does.
fn temp_not_last(path: &str) -> Option<String> {
    let items = path_items(path);
    if items.last().map(String::as_str) != Some("pg_temp") {
        return Some(format!("pg_temp is not listed last: {path:?}"));
    }
    if items.iter().filter(|s| *s == "pg_temp").count() != 1 {
        return Some(format!("pg_temp listed twice: {path:?}"));
    }
    None
}

/// The functions that pin a path that does not list `pg_temp` exactly once,
/// last, with the reason.
fn temp_shadowable(fns: &BTreeMap<String, Routine>) -> BTreeMap<String, String> {
    fns.iter()
        .filter_map(|(sig, r)| {
            r.path
                .as_deref()
                .and_then(temp_not_last)
                .map(|w| (sig.clone(), w))
        })
        .collect()
}

/// The trigger functions (not C or internal) that pin no path.
fn unpinned_triggers(fns: &BTreeMap<String, Routine>) -> BTreeSet<String> {
    fns.iter()
        .filter(|(_, r)| r.trigger && r.path.is_none() && r.lang != "c" && r.lang != "internal")
        .map(|(s, _)| s.clone())
        .collect()
}

fn listing<'a>(items: impl IntoIterator<Item = (&'a String, String)>) -> String {
    items
        .into_iter()
        .map(|(s, w)| format!("  {s}: {w}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Probe functions of each shape the path check must report, and two it must
/// not.
const PATH_PROBES: &str = r#"
CREATE FUNCTION public.t134_probe_invoker_no_temp() RETURNS integer
    LANGUAGE sql SET search_path = pg_catalog, public AS $$ SELECT 1 $$;
CREATE FUNCTION public.t134_probe_invoker_catalog_only() RETURNS integer
    LANGUAGE sql SET search_path = pg_catalog AS $$ SELECT 1 $$;
CREATE FUNCTION public.t134_probe_invoker_temp_first() RETURNS integer
    LANGUAGE sql SET search_path = pg_temp, public AS $$ SELECT 1 $$;
CREATE FUNCTION public.t134_probe_invoker_empty() RETURNS integer
    LANGUAGE sql SET search_path = '' AS $$ SELECT 1 $$;
CREATE FUNCTION public.t134_probe_trigger_no_temp() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$ BEGIN RETURN NEW; END $$;
CREATE FUNCTION public.t134_probe_invoker_temp_last() RETURNS integer
    LANGUAGE sql SET search_path = pg_catalog, public, pg_temp AS $$ SELECT 1 $$;
CREATE FUNCTION public.t134_probe_invoker_unpinned() RETURNS integer
    LANGUAGE sql AS $$ SELECT 1 $$;
"#;

/// Store `path` on `sig` VERBATIM, as `ALTER FUNCTION .. SET search_path FROM
/// CURRENT` stores the session's value (a `CREATE FUNCTION .. SET` clause
/// would normalise the spelling), and check it was.
async fn store_path_verbatim(pool: &PgPool, sig: &str, path: &str) {
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SELECT pg_catalog.set_config('search_path', $1, false)")
        .bind(path)
        .execute(&mut *conn)
        .await
        .expect("the session takes the path");
    sqlx::raw_sql(&format!(
        "ALTER FUNCTION {sig} SET search_path FROM CURRENT; RESET search_path"
    ))
    .execute(&mut *conn)
    .await
    .expect("store it on the function");
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT (SELECT pg_catalog.substr(c, 13) FROM pg_catalog.unnest(p.proconfig) c \
                  WHERE c LIKE 'search_path=%' LIMIT 1) \
           FROM pg_catalog.pg_proc p WHERE p.oid = pg_catalog.to_regprocedure($1)",
    )
    .bind(sig)
    .fetch_one(&mut *conn)
    .await
    .expect("read the stored path");
    assert_eq!(
        stored.as_deref(),
        Some(path),
        "CALIBRATION: {sig}'s path is stored verbatim"
    );
}

/// Probes whose spelling only `FROM CURRENT` stores: an upper-case `PG_TEMP`
/// is `pg_temp` to PostgreSQL, so listing it first is reported and listing
/// it last is not.
const VERBATIM_PATH_PROBES: &[(&str, &str)] = &[
    (
        "public.t134_probe_invoker_upper_temp_first()",
        "PG_TEMP, public, pg_temp",
    ),
    (
        "public.t134_probe_invoker_upper_temp_last()",
        "pg_catalog, public, PG_TEMP",
    ),
];

async fn create_verbatim_probes(pool: &PgPool, probes: &[(&str, &str)]) {
    for (sig, path) in probes {
        sqlx::raw_sql(&format!(
            "CREATE FUNCTION {sig} RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$"
        ))
        .execute(pool)
        .await
        .expect("a probe function");
        store_path_verbatim(pool, sig, path).await;
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_function_that_pins_a_search_path_lists_pg_temp_last(pool: PgPool) {
    let at_head = routines_of(&pool).await;
    let invokers_pinned = at_head
        .values()
        .filter(|r| !r.secdef && r.path.is_some())
        .count();
    assert!(
        at_head.len() > 200 && invokers_pinned > 10,
        "CALIBRATION: the scan sees the schema's functions ({}) and invokers that pin a \
         path ({invokers_pinned})",
        at_head.len()
    );
    assert!(
        at_head
            .get("public.epigraph_mass_function_retract_guard()")
            .is_some_and(|r| !r.secdef && r.trigger),
        "CALIBRATION: the scan sees 184's retract guard, an INVOKER trigger"
    );
    let bad = temp_shadowable(&at_head);

    sqlx::raw_sql(PATH_PROBES)
        .execute(&pool)
        .await
        .expect("probes");
    create_verbatim_probes(&pool, VERBATIM_PATH_PROBES).await;
    let with_probes = temp_shadowable(&routines_of(&pool).await);
    let probed: BTreeSet<&str> = with_probes
        .keys()
        .filter(|k| !bad.contains_key(*k))
        .map(String::as_str)
        .collect();
    assert_eq!(
        probed,
        BTreeSet::from([
            "public.t134_probe_invoker_catalog_only()",
            "public.t134_probe_invoker_empty()",
            "public.t134_probe_invoker_no_temp()",
            "public.t134_probe_invoker_temp_first()",
            "public.t134_probe_invoker_upper_temp_first()",
            "public.t134_probe_trigger_no_temp()",
        ]),
        "CALIBRATION: exactly the invoker probes whose path omits pg_temp, lists it first \
         (in any letter case) or is empty are reported (not the temp-last ones, in either \
         case, or the unpinned one)"
    );

    assert!(
        bad.is_empty(),
        "{} function(s) pin a search_path that does not list pg_temp exactly once, LAST. A \
         SECURITY INVOKER body runs as its caller, which inside a definer is the definer's \
         owner, and a path without pg_temp searches the caller's temporary schema first. \
         Append `, pg_temp`:\n{}",
        bad.len(),
        listing(bad.iter().map(|(s, w)| (s, w.clone())))
    );
}

/// Probe trigger functions: unpinned (reported, attached or not), pinned (not
/// reported), and an unpinned non-trigger invoker (not reported).
const TRIGGER_PROBES: &str = r#"
CREATE TABLE public.t134_probe_table (x integer);
CREATE FUNCTION public.t134_probe_trg_unpinned_attached() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
CREATE TRIGGER t134_probe BEFORE INSERT ON public.t134_probe_table
    FOR EACH ROW EXECUTE FUNCTION public.t134_probe_trg_unpinned_attached();
CREATE FUNCTION public.t134_probe_trg_unpinned_loose() RETURNS trigger
    LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
CREATE FUNCTION public.t134_probe_trg_pinned() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp
    AS $$ BEGIN RETURN NEW; END $$;
CREATE FUNCTION public.t134_probe_plain_unpinned() RETURNS integer
    LANGUAGE sql AS $$ SELECT 1 $$;
"#;

#[sqlx::test(migrations = "../../migrations")]
async fn every_trigger_function_pins_a_search_path(pool: PgPool) {
    let at_head = routines_of(&pool).await;
    let triggers = at_head.values().filter(|r| r.trigger).count();
    assert!(
        triggers > 50,
        "CALIBRATION: the scan sees the schema's trigger functions ({triggers})"
    );
    let bad = unpinned_triggers(&at_head);

    sqlx::raw_sql(TRIGGER_PROBES)
        .execute(&pool)
        .await
        .expect("probes");
    let with_probes = unpinned_triggers(&routines_of(&pool).await);
    let probed: BTreeSet<&str> = with_probes
        .iter()
        .filter(|k| !bad.contains(*k))
        .map(String::as_str)
        .collect();
    assert_eq!(
        probed,
        BTreeSet::from([
            "public.t134_probe_trg_unpinned_attached()",
            "public.t134_probe_trg_unpinned_loose()",
        ]),
        "CALIBRATION: exactly the unpinned trigger functions are reported"
    );

    assert!(
        bad.is_empty(),
        "{} trigger function(s) pin no search_path, so a row trigger a foreign-key action \
         fires runs as the referencing table's owner on the SESSION's path. Pin \
         `SET search_path = pg_catalog, public, pg_temp`:\n{}",
        bad.len(),
        bad.iter()
            .map(|s| format!("  {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ---------------------------------------------------------------------------
// The behavioural proof, on real logins
// ---------------------------------------------------------------------------

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// A REAL application login: `LOGIN NOSUPERUSER NOBYPASSRLS INHERIT`, a member
/// of `epigraph_app` and of nothing else (as `docs/deploy.md` provisions the
/// API's), and ONE fresh connection of its own, so no function body has been
/// planned on that backend yet.
async fn app_login(pool: &PgPool) -> (String, PgConnection) {
    let role = format!("t134_app_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB INHERIT \
         PASSWORD 'probe-only' IN ROLE epigraph_app"
    ))
    .execute(pool)
    .await
    .expect("create the application login");
    let url = fixture::database_url_for(pool).await;
    let conn = PgConnectOptions::from_str(&url)
        .expect("parse the test DSN")
        .username(&role)
        .password("probe-only")
        .connect()
        .await
        .expect("connect as the application login");
    (role, conn)
}

/// Drop the probe login once its backend has gone. `close()` returns when the
/// Terminate message is sent; the backend then drops its temporary objects
/// (the trap's table, function and domain, which the login owns) on its way
/// out, and until it has, DROP ROLE fails with 2BP01. Wait for the login's
/// session to leave `pg_stat_activity` (it does after the temp cleanup) first.
async fn drop_login(pool: &PgPool, role: &str) {
    for _ in 0..200 {
        let live: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename = $1")
                .bind(role)
                .fetch_one(pool)
                .await
                .expect("read the login's sessions");
        if live == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(pool)
        .await
        .expect("drop the login");
}

/// The session's trap: a temporary table it owns and lets anyone append to,
/// and a temporary domain `text` whose CHECK appends `current_user` to it.
/// Every name in the trap itself is qualified, so it does not recurse.
const TRAP: &str = r#"
CREATE TEMP TABLE t134_ran (ran_as pg_catalog.text NOT NULL);
GRANT INSERT, SELECT ON pg_temp.t134_ran TO PUBLIC;
CREATE FUNCTION pg_temp.t134_probe(v pg_catalog.text) RETURNS pg_catalog.bool
LANGUAGE plpgsql AS $f$
BEGIN
    INSERT INTO pg_temp.t134_ran (ran_as) VALUES (current_user::pg_catalog.text);
    RETURN true;
END $f$;
CREATE DOMAIN pg_temp.text AS pg_catalog.text CHECK (pg_temp.t134_probe(VALUE));
"#;

async fn trap_log(conn: &mut PgConnection) -> Vec<String> {
    sqlx::query_scalar("SELECT ran_as FROM pg_temp.t134_ran ORDER BY ran_as")
        .fetch_all(&mut *conn)
        .await
        .expect("read the trap's log")
}

/// Backlog eff4aaf5. An application login plants a temporary `text` domain,
/// then un-retracts a mass function through 184's definer (owned by the
/// NOSUPERUSER `epigraph_maintenance`, EXECUTE granted to `epigraph_app`).
/// The definer's UPDATE fires 184's INVOKER retract guard, whose clear arm
/// casts `OLD.id::text`. Below 271 the guard pinned `pg_catalog, public`, so
/// the cast resolved the session's `pg_temp.text` first and the session's own
/// function ran as `epigraph_maintenance`. On 271's path it resolves
/// `pg_catalog.text`, and the trap runs for no role but the login itself.
#[sqlx::test(migrations = "../../migrations")]
async fn an_application_login_cannot_run_its_own_type_as_the_definer_owner(pool: PgPool) {
    let head: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("read the migration head");
    assert!(
        head >= 271,
        "CALIBRATION: the embedded migrations include 271 (head {head}); touch this file if \
         the build is stale"
    );
    let (owner_role, owner_super, app_exec): (String, bool, bool) = sqlx::query_as(
        "SELECT pg_get_userbyid(p.proowner)::text, r.rolsuper, \
                has_function_privilege('epigraph_app', p.oid, 'EXECUTE') \
           FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
          WHERE p.oid = 'public.epigraph_unretract_mass_function(uuid, text, uuid, uuid)'\
                        ::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("the un-retract definer");
    assert_eq!(
        (owner_role.as_str(), owner_super, app_exec),
        ("epigraph_maintenance", false, true),
        "CALIBRATION: the definer runs as the NOSUPERUSER maintenance role and the \
         application role may call it"
    );

    // A retracted BBA of the owner's, made on the harness's own connections
    // (184's definer as epigraph_app), never on the attacking backend.
    let (owner, group) = fixture::seed_agent_with_group(&pool, "t134-owner").await;
    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 't134 probe claim', $2, 0.5, $3, true, 'public', $4)",
    )
    .bind(claim)
    .bind(&hash)
    .bind(owner)
    .bind(group)
    .execute(&pool)
    .await
    .expect("a public claim the owner's group owns");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("t134-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed a frame");
    let viewer = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    let groups = csv(viewer.group_bind().expect("a scoped viewer"));
    let writable = csv(viewer.writable_groups());
    let (g, w) = (groups.clone(), writable.clone());
    let bba = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.group_ids', $1, false), \
                    set_config('epigraph.writable_group_ids', $2, false), \
                    set_config('epigraph.principal_id', $3, false)",
        )
        .bind(&g)
        .bind(&w)
        .bind(owner.to_string())
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let masses = serde_json::json!({"0": 0.8, "0,1": 0.2});
        let id = MassFunctionRepository::store_with_perspective(
            &mut *conn,
            claim,
            frame,
            Some(owner),
            None,
            &masses,
            None,
            None,
            Some(1.0),
            None,
            "unknown",
            None,
        )
        .await
        .expect("store the owner's BBA");
        sqlx::query(
            "SELECT set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false), \
                    set_config('epigraph.principal_id', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("clear the stamp");
        (conn, id)
    })
    .await;
    retracted::retract_through_definer(&pool, bba).await;

    let (role, mut app) = app_login(&pool).await;
    let (session, superuser): (String, bool) = sqlx::query_as(
        "SELECT session_user::pg_catalog.text, r.rolsuper \
           FROM pg_catalog.pg_roles r WHERE r.rolname = current_user",
    )
    .fetch_one(&mut app)
    .await
    .expect("the login's identity");
    assert_eq!(
        (session.as_str(), superuser),
        (role.as_str(), false),
        "CALIBRATION: the session is the NOSUPERUSER login itself"
    );
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(&groups)
    .bind(&writable)
    .bind(owner.to_string())
    .execute(&mut app)
    .await
    .expect("stamp the login as the owner");
    sqlx::raw_sql(TRAP)
        .execute(&mut app)
        .await
        .expect("the application login arms the trap");

    // CALIBRATION: the trap is live. On the session's own path (pg_temp
    // unlisted, so searched first) `text` is the planted domain, and its check
    // runs as the login.
    sqlx::raw_sql("SELECT 'calibration'::text")
        .execute(&mut app)
        .await
        .expect("the session resolves its own domain");
    assert_eq!(
        trap_log(&mut app).await,
        vec![role.clone()],
        "CALIBRATION: the planted domain's check runs on the session's own path"
    );
    sqlx::raw_sql("DELETE FROM pg_temp.t134_ran")
        .execute(&mut app)
        .await
        .expect("clear the log");

    let out: serde_json::Value = sqlx::query_scalar(
        "SELECT public.epigraph_unretract_mass_function($1, 'eff4aaf5 probe', NULL, NULL)",
    )
    .bind(bba)
    .fetch_one(&mut app)
    .await
    .expect("the owner un-retracts through the definer");
    let ran_as = trap_log(&mut app).await;
    app.close().await.expect("close the login");
    drop_login(&pool, &role).await;

    let live: bool =
        sqlx::query_scalar("SELECT retracted_at IS NULL FROM mass_functions WHERE id = $1")
            .bind(bba)
            .fetch_one(&pool)
            .await
            .expect("re-read the row");
    assert!(
        live,
        "CALIBRATION: the un-retraction went through ({out}), so the guard's clear arm ran"
    );
    assert!(
        ran_as.iter().all(|r| *r == role),
        "the application login's own code ran as {ran_as:?} inside the un-retract definer \
         (a role it does not hold): an INVOKER body on the definer's write resolved the \
         session's temporary type"
    );
}

// ---------------------------------------------------------------------------
// Migration 271 itself
// ---------------------------------------------------------------------------

fn below(version: i64) -> Migrator {
    Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < version)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

async fn migrate(pool: &PgPool, migrator: &Migrator) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await.expect("acquire");
    let r = migrator.run(&mut *conn).await.map_err(sqlx::Error::from);
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    r
}

fn sqlstate<T>(r: &Result<T, sqlx::Error>) -> Option<String> {
    match r.as_ref().err() {
        Some(sqlx::Error::Migrate(m)) => match m.as_ref() {
            sqlx::migrate::MigrateError::Execute(e)
            | sqlx::migrate::MigrateError::ExecuteMigration(e, _) => e
                .as_database_error()
                .and_then(|d| d.code())
                .map(|c| c.into_owned()),
            _ => None,
        },
        Some(e) => e
            .as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.into_owned()),
        None => None,
    }
}

async fn applied(pool: &PgPool, version: i64) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1)")
        .bind(version)
        .fetch_one(pool)
        .await
        .expect("read _sqlx_migrations")
}

fn other_config(r: &Routine) -> Vec<String> {
    r.config
        .iter()
        .filter(|c| !c.starts_with("search_path="))
        .cloned()
        .collect()
}

/// 271 changes the `search_path` entry only, and only of functions listed in
/// [`CHANGED_BY_271`]. A path without `pg_temp` gets `, pg_temp` appended, an
/// unpinned trigger function gets `pg_catalog, <schema>, pg_temp`. No body,
/// owner, ACL, volatility, security mode or other config entry moves, and no
/// function appears or disappears.
#[sqlx::test(migrations = false)]
async fn migration_271_changes_only_search_paths(pool: PgPool) {
    migrate(&pool, &below(271))
        .await
        .expect("migrate below 271");
    let before = routines_of(&pool).await;
    migrate(&pool, &below(272)).await.expect("migrate to 271");
    let after = routines_of(&pool).await;
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "271 adds or drops no function"
    );
    let known: BTreeSet<&str> = CHANGED_BY_271.iter().copied().collect();
    let mut changed = BTreeSet::new();
    for (sig, b) in &before {
        let a = &after[sig];
        assert_eq!(
            (
                &a.src_md5,
                &a.owner,
                &a.acl,
                &a.volatile,
                a.secdef,
                other_config(a)
            ),
            (
                &b.src_md5,
                &b.owner,
                &b.acl,
                &b.volatile,
                b.secdef,
                other_config(b)
            ),
            "{sig}: body, owner, ACL, volatility, security and other config unchanged"
        );
        if a.path == b.path {
            continue;
        }
        changed.insert(sig.clone());
        assert!(
            known.contains(sig.as_str()),
            "{sig}: 271 changed a function it was not written for ({:?} -> {:?})",
            b.path,
            a.path
        );
        let want = match &b.path {
            Some(p) => format!("{p}, pg_temp"),
            None => {
                assert!(
                    b.trigger,
                    "{sig}: only an unpinned TRIGGER function is pinned"
                );
                let schema = sig.split('.').next().expect("schema");
                format!("pg_catalog, {schema}, pg_temp")
            }
        };
        assert_eq!(a.path.as_deref(), Some(want.as_str()), "{sig}");
    }
    // Neither is re-stated by any other change, so both still reach 271.
    assert!(
        changed.contains("public.epigraph_lockdown_privileged()")
            && changed.contains("public.trigger_validate_edge_refs()"),
        "CALIBRATION: 271 changed a pinned invoker and an unpinned trigger: {changed:?}"
    );
    assert!(
        temp_shadowable(&after).is_empty() && unpinned_triggers(&after).is_empty(),
        "nothing is left for either rule after 271"
    );
}

/// 271 refuses (55000, nothing changed) a function whose path lists
/// `pg_temp` before another schema: appending cannot fix that order.
/// POSITIVE CONTROL: with that function's path fixed, 271 applies.
#[sqlx::test(migrations = false)]
async fn migration_271_refuses_pg_temp_before_another_schema(pool: PgPool) {
    migrate(&pool, &below(271))
        .await
        .expect("migrate below 271");
    sqlx::raw_sql(
        "CREATE FUNCTION public.t134_temp_first() RETURNS integer LANGUAGE sql \
         SET search_path = pg_temp, public AS $$ SELECT 1 $$",
    )
    .execute(&pool)
    .await
    .expect("a temp-first function");
    let before = routines_of(&pool).await;
    let r = migrate(&pool, &below(272)).await;
    assert_eq!(sqlstate(&r).as_deref(), Some("55000"), "271 refuses: {r:?}");
    assert!(
        format!("{:?}", r.as_ref().err()).contains("t134_temp_first"),
        "the refusal names the function: {r:?}"
    );
    assert!(!applied(&pool, 271).await, "271 is not recorded");
    assert_eq!(routines_of(&pool).await, before, "nothing was changed");

    sqlx::raw_sql("ALTER FUNCTION public.t134_temp_first() SET search_path = public, pg_temp")
        .execute(&pool)
        .await
        .expect("fix the path");
    migrate(&pool, &below(272))
        .await
        .expect("POSITIVE CONTROL: 271 applies once the path is fixed");
    assert!(applied(&pool, 271).await);
}

/// The two branches a database at main's head does not exercise: an empty
/// path (`search_path = ''`, which searches `pg_temp` first) becomes
/// `pg_catalog, pg_temp`, and an unpinned trigger function in a schema other
/// than `public` is pinned on its own schema. A procedure is swept too
/// (`ALTER ROUTINE`).
#[sqlx::test(migrations = false)]
async fn migration_271_pins_an_empty_path_and_an_unpinned_trigger_in_any_schema(pool: PgPool) {
    migrate(&pool, &below(271))
        .await
        .expect("migrate below 271");
    sqlx::raw_sql(
        "CREATE SCHEMA t134_other; \
         CREATE FUNCTION public.t134_empty() RETURNS integer LANGUAGE sql \
             SET search_path = '' AS $$ SELECT 1 $$; \
         CREATE FUNCTION t134_other.t134_trg() RETURNS trigger LANGUAGE plpgsql \
             AS $$ BEGIN RETURN NEW; END $$; \
         CREATE PROCEDURE public.t134_proc() LANGUAGE sql \
             SET search_path = pg_catalog, public AS $$ SELECT 1 $$;",
    )
    .execute(&pool)
    .await
    .expect("fixtures");
    migrate(&pool, &below(272)).await.expect("migrate to 271");
    let after = routines_of(&pool).await;
    for (sig, want) in [
        ("public.t134_empty()", "pg_catalog, pg_temp"),
        ("t134_other.t134_trg()", "pg_catalog, t134_other, pg_temp"),
        ("public.t134_proc()", "pg_catalog, public, pg_temp"),
    ] {
        assert_eq!(after[sig].path.as_deref(), Some(want), "{sig}");
    }
}

/// A function's OWNER controls the text of its stored path: `ALTER FUNCTION
/// .. SET search_path FROM CURRENT` stores the session's value verbatim, and
/// a list item that is not quoted may hold any character but a comma or
/// whitespace. 271 builds a statement from that path and runs it as the
/// migrating role, so it must validate every item and rebuild the path, never
/// splice the stored text. A non-superuser owner stores a path whose items
/// are SQL; 271 refuses (55000) naming the function, and none of the SQL runs
/// (the table it would create stays absent).
#[sqlx::test(migrations = false)]
async fn migration_271_refuses_a_crafted_stored_path_and_runs_none_of_it(pool: PgPool) {
    migrate(&pool, &below(271))
        .await
        .expect("migrate below 271");
    let role = format!("t134_owner_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS; \
         CREATE FUNCTION public.t134_crafted() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$; \
         ALTER FUNCTION public.t134_crafted() OWNER TO {role};"
    ))
    .execute(&pool)
    .await
    .expect("a function owned by a non-superuser role");
    // Statements with no whitespace (comments stand in for spaces); the last
    // one re-paths the function so a migration that ran them would still
    // pass its own postcondition and commit.
    const PAYLOAD: &str = "public;create/**/table/**/public.t134_pwned(x/**/int);\
                           alter/**/function/**/public.t134_crafted()/**/set/**/\
                           search_path=public,pg_temp;--";
    {
        let mut conn = pool.acquire().await.expect("acquire");
        sqlx::raw_sql(&format!("SET ROLE {role}"))
            .execute(&mut *conn)
            .await
            .expect("act as the owner");
        sqlx::query("SELECT pg_catalog.set_config('search_path', $1, false)")
            .bind(PAYLOAD)
            .execute(&mut *conn)
            .await
            .expect("the session takes the crafted path");
        sqlx::raw_sql(
            "ALTER FUNCTION public.t134_crafted() SET search_path FROM CURRENT; \
             RESET ROLE; RESET search_path",
        )
        .execute(&mut *conn)
        .await
        .expect("the owner stores it");
    }
    let stored: Vec<String> = sqlx::query_scalar(
        "SELECT pg_catalog.unnest(proconfig) FROM pg_catalog.pg_proc \
          WHERE oid = 'public.t134_crafted()'::regprocedure",
    )
    .fetch_all(&pool)
    .await
    .expect("the stored config");
    assert_eq!(
        stored,
        vec![format!("search_path={PAYLOAD}")],
        "CALIBRATION: the owner's path is stored verbatim"
    );

    let r = migrate(&pool, &below(272)).await;
    assert_eq!(
        sqlstate(&r).as_deref(),
        Some("55000"),
        "271 refuses the crafted path: {r:?}"
    );
    assert!(
        format!("{:?}", r.as_ref().err()).contains("t134_crafted"),
        "the refusal names the function: {r:?}"
    );
    let pwned: bool = sqlx::query_scalar("SELECT to_regclass('public.t134_pwned') IS NOT NULL")
        .fetch_one(&pool)
        .await
        .expect("look for the marker table");
    assert!(!pwned, "271 ran SQL from a stored search_path");
    assert!(!applied(&pool, 271).await, "271 is not recorded");

    sqlx::raw_sql(&format!(
        "DROP TABLE IF EXISTS public.t134_pwned; DROP FUNCTION public.t134_crafted(); \
         DROP ROLE {role};"
    ))
    .execute(&pool)
    .await
    .expect("clean up the cluster-wide role");
}

/// 271 reads each path item as PostgreSQL does: an unquoted item ASCII
/// lower-cased, a quoted one with its quotes stripped. A stored `PG_TEMP`
/// (only `SET search_path FROM CURRENT` stores that spelling) IS `pg_temp`,
/// so listing it first is refused (55000, nothing changed) even though the
/// path also ends in `pg_temp`, and a path that ends in `PG_TEMP` or
/// `"pg_temp"` already lists it last and is left as stored.
#[sqlx::test(migrations = false)]
async fn migration_271_reads_path_items_as_postgres_does(pool: PgPool) {
    migrate(&pool, &below(271))
        .await
        .expect("migrate below 271");
    let kept = [
        (
            "public.t134_upper_temp_last()",
            "pg_catalog, public, PG_TEMP",
        ),
        (
            "public.t134_quoted_temp_last()",
            "pg_catalog, public, \"pg_temp\"",
        ),
    ];
    create_verbatim_probes(
        &pool,
        &[("public.t134_upper_temp_first()", "PG_TEMP, public, pg_temp")],
    )
    .await;
    create_verbatim_probes(&pool, &kept).await;
    let before = routines_of(&pool).await;

    let r = migrate(&pool, &below(272)).await;
    assert_eq!(
        sqlstate(&r).as_deref(),
        Some("55000"),
        "271 refuses a path listing PG_TEMP (pg_temp) before another schema: {r:?}"
    );
    assert!(
        format!("{:?}", r.as_ref().err()).contains("t134_upper_temp_first"),
        "the refusal names the function: {r:?}"
    );
    assert!(!applied(&pool, 271).await, "271 is not recorded");
    assert_eq!(routines_of(&pool).await, before, "nothing was changed");

    sqlx::raw_sql("DROP FUNCTION public.t134_upper_temp_first()")
        .execute(&pool)
        .await
        .expect("drop the refused function");
    migrate(&pool, &below(272)).await.expect(
        "POSITIVE CONTROL: 271 applies; a path ending in PG_TEMP or \"pg_temp\" already lists \
         pg_temp last",
    );
    let after = routines_of(&pool).await;
    for (sig, path) in kept {
        assert_eq!(
            after[sig].path.as_deref(),
            Some(path),
            "271 leaves {sig} as stored"
        );
    }
}

/// Runs `docs/runbooks/271-precheck.sql` and returns `function -> reason`.
async fn precheck(pool: &PgPool) -> BTreeMap<String, String> {
    let sql = repo_text("docs/runbooks/271-precheck.sql");
    let rows: Vec<(String, String, String)> = sqlx::query_as(&format!(
        "SELECT pg_catalog.regexp_replace(q.function::pg_catalog.text, '^public\\.', ''), \
                q.setting, q.reason \
           FROM ({}\n) AS q",
        sql.trim_end().trim_end_matches(';')
    ))
    .fetch_all(pool)
    .await
    .expect("the precheck runs");
    rows.into_iter().map(|(f, _, why)| (f, why)).collect()
}

/// `docs/runbooks/271-precheck.sql` lists exactly the functions 271's sweep
/// refuses, reading each `proconfig` entry on its own. The one-liner the
/// deploy row used to give joined a function's settings into one string, so
/// it reported 184's un-retract definer (`search_path` followed by a second
/// setting) on every database, a function 271 accepts.
#[sqlx::test(migrations = false)]
async fn the_271_precheck_lists_exactly_what_271_refuses(pool: PgPool) {
    migrate(&pool, &below(271))
        .await
        .expect("migrate below 271");
    let old_hits: Vec<String> = sqlx::query_scalar(
        "SELECT oid::regprocedure::text FROM pg_proc \
          WHERE array_to_string(proconfig, ',') ~ 'search_path=.*pg_temp *,'",
    )
    .fetch_all(&pool)
    .await
    .expect("the old one-liner");
    assert!(
        old_hits
            .iter()
            .any(|f| f.contains("epigraph_unretract_mass_function(")),
        "CALIBRATION: the old one-liner reports the un-retract definer ({old_hits:?})"
    );
    assert_eq!(
        precheck(&pool).await,
        BTreeMap::new(),
        "below 271 nothing would be refused, the un-retract definer included"
    );

    sqlx::raw_sql(
        "CREATE FUNCTION public.t134_pc_temp_first() RETURNS integer LANGUAGE sql \
             SET search_path = pg_temp, public AS $$ SELECT 1 $$; \
         CREATE FUNCTION public.t134_pc_append() RETURNS integer LANGUAGE sql \
             SET search_path = pg_catalog, public AS $$ SELECT 1 $$; \
         CREATE FUNCTION public.t134_pc_empty() RETURNS integer LANGUAGE sql \
             SET search_path = '' AS $$ SELECT 1 $$; \
         CREATE FUNCTION public.t134_pc_multi() RETURNS integer LANGUAGE sql \
             SET search_path = pg_catalog, public, pg_temp SET work_mem = '64kB' \
             AS $$ SELECT 1 $$;",
    )
    .execute(&pool)
    .await
    .expect("fixtures");
    create_verbatim_probes(
        &pool,
        &[
            ("public.t134_pc_upper_first()", "PG_TEMP, public, pg_temp"),
            ("public.t134_pc_quoted_item()", "pg_catalog, \"Public\""),
            (
                "public.t134_pc_quoted_temp_last()",
                "pg_catalog, \"pg_temp\"",
            ),
        ],
    )
    .await;
    let first = "lists pg_temp before another schema".to_string();
    let item = "an item is not a plain lower-case schema name or \"$user\"".to_string();
    let listed = precheck(&pool).await;
    assert_eq!(
        listed,
        BTreeMap::from([
            ("t134_pc_quoted_item()".to_string(), item),
            ("t134_pc_temp_first()".to_string(), first.clone()),
            ("t134_pc_upper_first()".to_string(), first),
        ]),
        "the precheck lists the temp-first paths (in any letter case) and the path with an \
         item 271 cannot rebuild, and not a path 271 appends to, an empty one, a quoted \
         pg_temp last, or a function with a second setting"
    );

    // The precheck and the sweep agree: 271 refuses while any listed
    // function remains, and applies once they are gone.
    let r = migrate(&pool, &below(272)).await;
    assert_eq!(sqlstate(&r).as_deref(), Some("55000"), "271 refuses: {r:?}");
    let refusal = format!("{:?}", r.as_ref().err());
    assert!(
        listed
            .keys()
            .any(|f| refusal.contains(f.trim_end_matches("()"))),
        "271 refuses a function the precheck listed: {refusal}"
    );
    sqlx::raw_sql(
        "DROP FUNCTION public.t134_pc_temp_first(); DROP FUNCTION public.t134_pc_upper_first(); \
         DROP FUNCTION public.t134_pc_quoted_item();",
    )
    .execute(&pool)
    .await
    .expect("drop the listed functions");
    assert_eq!(precheck(&pool).await, BTreeMap::new());
    migrate(&pool, &below(272))
        .await
        .expect("POSITIVE CONTROL: 271 applies once the precheck lists nothing");
}

// ---------------------------------------------------------------------------
// Production order: a lower-numbered migration applied after 271
// ---------------------------------------------------------------------------

/// The highest migration on main when 271 was written. Production applies 271
/// on a database at about that head; a migration numbered between it and 271
/// that merges later is applied AFTER 271 (sqlx applies a missing lower
/// version), and 271 does not sweep it.
const HEAD_WHEN_271_WRITTEN: i64 = 235;

fn migrator_of(migrations: Vec<Migration>) -> Migrator {
    Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

/// Everything up to [`HEAD_WHEN_271_WRITTEN`], then 271: production's state
/// right after 271 is deployed.
fn up_to_head_then_271() -> Migrator {
    migrator_of(
        MIGRATOR
            .migrations
            .iter()
            .filter(|m| m.version <= HEAD_WHEN_271_WRITTEN || m.version == 271)
            .cloned()
            .collect(),
    )
}

/// What a lower-numbered migration could do that 271 then never sees: reset
/// 184's retract guard to its pre-271 path (as a `CREATE OR REPLACE` with the
/// old `SET` clause would) and add an unpinned trigger function.
const BAD_LOWER_MIGRATION: &str = "\
ALTER FUNCTION public.epigraph_mass_function_retract_guard() SET search_path = pg_catalog, public;
CREATE FUNCTION public.t134_late_trigger() RETURNS trigger LANGUAGE plpgsql
    AS $$ BEGIN RETURN NEW; END $$;
";

/// `MIGRATOR` plus [`BAD_LOWER_MIGRATION`] at the highest version below 271
/// that no real migration takes.
fn with_bad_lower_migration() -> (Migrator, i64) {
    let taken: BTreeSet<i64> = MIGRATOR.migrations.iter().map(|m| m.version).collect();
    let version = (1..271)
        .rev()
        .find(|v| !taken.contains(v))
        .expect("a free version below 271");
    let mut all: Vec<Migration> = MIGRATOR.migrations.to_vec();
    all.push(Migration::new(
        version,
        Cow::Borrowed("t134 bad lower migration"),
        MigrationType::Simple,
        Cow::Borrowed(BAD_LOWER_MIGRATION),
        false,
    ));
    all.sort_by_key(|m| m.version);
    (migrator_of(all), version)
}

fn rule_breaks(fns: &BTreeMap<String, Routine>) -> (BTreeSet<String>, BTreeSet<String>) {
    (
        temp_shadowable(fns).into_keys().collect(),
        unpinned_triggers(fns),
    )
}

/// Both rules hold when the migrations numbered between
/// [`HEAD_WHEN_271_WRITTEN`] and 271 are applied AFTER 271, as production
/// applies one that merges after 271 deployed. A test database applies them
/// in version order, where 271 sweeps them and masks a path one of them got
/// wrong ([`in_version_order_271_masks_a_bad_lower_migration`]); here nothing
/// sweeps them. CALIBRATION: a synthetic lower migration that resets a path
/// and adds an unpinned trigger, applied the same way, is reported.
#[sqlx::test(migrations = false)]
async fn a_lower_migration_applied_after_271_keeps_both_rules(pool: PgPool) {
    migrate(&pool, &up_to_head_then_271())
        .await
        .expect("migrate to the head 271 was written on, then 271");
    let deployed = routines_of(&pool).await;
    assert!(
        applied(&pool, 271).await
            && deployed["public.epigraph_mass_function_retract_guard()"]
                .path
                .as_deref()
                == Some("pg_catalog, public, pg_temp"),
        "CALIBRATION: 271 ran on the older head and swept the retract guard"
    );

    let late: Vec<i64> = MIGRATOR
        .migrations
        .iter()
        .map(|m| m.version)
        .filter(|v| *v > HEAD_WHEN_271_WRITTEN && *v < 271)
        .collect();
    migrate(&pool, &MIGRATOR).await.unwrap_or_else(|e| {
        panic!(
            "applying migration(s) {late:?} AFTER 271, as production does, fails: {e}. A \
             lower migration's precondition must accept the paths 271 sets"
        )
    });
    let (bad, unpinned) = rule_breaks(&routines_of(&pool).await);
    assert!(
        bad.is_empty() && unpinned.is_empty(),
        "applied after 271 (production's order), migration(s) {late:?} leave functions that \
         pin a path without pg_temp last: {bad:?}, and unpinned trigger functions: \
         {unpinned:?}. 271 does not sweep a migration applied after it: state `pg_temp` last \
         on every path and pin every trigger function in the migration itself"
    );

    let (with_bad, version) = with_bad_lower_migration();
    migrate(&pool, &with_bad)
        .await
        .expect("the synthetic lower migration applies after 271");
    assert_eq!(
        rule_breaks(&routines_of(&pool).await),
        (
            BTreeSet::from(["public.epigraph_mass_function_retract_guard()".to_string()]),
            BTreeSet::from(["public.t134_late_trigger()".to_string()]),
        ),
        "CALIBRATION: a lower migration ({version}) applied after 271 that resets a path and \
         adds an unpinned trigger is reported"
    );
}

/// Why [`a_lower_migration_applied_after_271_keeps_both_rules`] exists: in
/// version order the same synthetic lower migration runs BEFORE 271, 271
/// sweeps it, and both rules hold, so the catalog ratchets above cannot see
/// what it would leave in production.
#[sqlx::test(migrations = false)]
async fn in_version_order_271_masks_a_bad_lower_migration(pool: PgPool) {
    let (with_bad, version) = with_bad_lower_migration();
    migrate(&pool, &with_bad)
        .await
        .expect("migrate in version order");
    assert!(
        applied(&pool, version).await && applied(&pool, 271).await,
        "CALIBRATION: both the synthetic {version} and 271 applied"
    );
    let fns = routines_of(&pool).await;
    assert_eq!(
        fns["public.t134_late_trigger()"].path.as_deref(),
        Some("pg_catalog, public, pg_temp"),
        "271 swept the synthetic migration's trigger function"
    );
    assert_eq!(
        rule_breaks(&fns),
        (BTreeSet::new(), BTreeSet::new()),
        "in version order both rules hold, masking the synthetic migration"
    );
}

fn repo_text(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// `docs/runbooks/271-undo.sql` returns every function to its state below
/// 271, twice over, and leaves a function whose body a later migration
/// re-stated (a different `prosrc`) on whatever path it has.
#[sqlx::test(migrations = false)]
async fn the_271_undo_restores_the_paths_below_271(pool: PgPool) {
    let undo = repo_text("docs/runbooks/271-undo.sql");
    migrate(&pool, &below(271))
        .await
        .expect("migrate below 271");
    let before = routines_of(&pool).await;
    migrate(&pool, &below(272)).await.expect("migrate to 271");
    assert_ne!(
        routines_of(&pool).await,
        before,
        "CALIBRATION: 271 changed the catalog"
    );
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        assert_eq!(
            routines_of(&pool).await,
            before,
            "the {run} run returns every function to its state below 271"
        );
    }

    // A later re-statement keeps its path. Re-apply 271 (its row is still
    // recorded: the undo leaves it), then re-body one function and run the
    // undo again.
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 271")
        .execute(&pool)
        .await
        .expect("forget 271");
    migrate(&pool, &below(272)).await.expect("re-apply 271");
    sqlx::raw_sql(
        "CREATE OR REPLACE FUNCTION public.epigraph_edges_repoint_unsign() RETURNS trigger \
             LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, pg_temp \
             AS $$ BEGIN RETURN NEW; END $$;",
    )
    .execute(&pool)
    .await
    .expect("a later re-statement");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("the undo applies over a re-stated body");
    let after = routines_of(&pool).await;
    assert_eq!(
        after["public.epigraph_edges_repoint_unsign()"]
            .path
            .as_deref(),
        Some("pg_catalog, public, pg_temp"),
        "the undo leaves a re-stated body's path alone"
    );
    assert_eq!(
        after["public.epigraph_lockdown_privileged()"].path,
        before["public.epigraph_lockdown_privileged()"].path,
        "CONTROL: an unchanged body on 271's path is reverted in the same run"
    );
}
