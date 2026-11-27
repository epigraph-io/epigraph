//! Migration 354 dropped the five harvester tables (backlog a6e3dba2; the
//! test 81809c45 asks for). This file pins the result and the migration's
//! own refusals:
//!
//! * at head no function body, policy, trigger or relation names a harvester
//!   table, and no `crates/*/src` file does either (the Rust half of the same
//!   change: a binary that still named one would fail on a 354 database);
//! * 354 refuses (55000, nothing changed) while any of the five tables has a
//!   row, naming it, and over a shared body it does not re-state;
//! * `docs/runbooks/354-undo.sql` puts the catalog back exactly as it was
//!   below 354, twice over, refuses over a foreign body, and 354 then applies
//!   again (apply, undo, apply).

use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// The five tables 354 drops.
const TABLES: [&str; 5] = [
    "harvester_audit_reports",
    "harvester_claim_provenance",
    "harvester_enriched_concepts",
    "harvester_fragments",
    "harvester_sources",
];

/// The same names as one POSIX regex, for the catalog reads.
const TABLES_RE: &str =
    "harvester_(fragments|sources|claim_provenance|enriched_concepts|audit_reports)";

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

async fn migrate(pool: &PgPool, migrator: &Migrator) -> Result<(), String> {
    let mut conn = pool.acquire().await.expect("acquire");
    let r = migrator.run(&mut *conn).await.map_err(|e| e.to_string());
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    r
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repo_text(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn migration_354() -> String {
    repo_text("migrations/354_drop_harvester_tables.sql")
}

fn sqlstate<T>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref()
        .err()
        .and_then(|e| e.as_database_error())
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

/// Every catalog object that names a harvester table, as sorted text lines.
async fn live_references(pool: &PgPool) -> Vec<String> {
    let mut out: Vec<String> = sqlx::query_scalar(
        "SELECT 'function ' || p.oid::regprocedure::text FROM pg_proc p \
          WHERE p.prosrc ~ $1 \
         UNION ALL \
         SELECT 'policy ' || tablename || '.' || policyname FROM pg_policies \
          WHERE tablename ~ $1 OR qual ~ $1 OR with_check ~ $1 \
         UNION ALL \
         SELECT 'trigger ' || t.tgrelid::regclass::text || '.' || t.tgname FROM pg_trigger t \
          WHERE NOT t.tgisinternal AND (t.tgrelid::regclass::text ~ $1 OR t.tgname ~ $1) \
         UNION ALL \
         SELECT 'relation ' || c.relname FROM pg_class c \
           JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND c.relname ~ $1 \
         UNION ALL \
         SELECT 'progress row ' || entity FROM tenancy_backfill_progress WHERE entity ~ $1",
    )
    .bind(TABLES_RE)
    .fetch_all(pool)
    .await
    .expect("read the catalog");
    out.sort();
    out
}

/// At head nothing in the catalog names a harvester table.
#[sqlx::test(migrations = "../../migrations")]
async fn no_live_object_names_a_harvester_table(pool: PgPool) {
    assert_eq!(live_references(&pool).await, Vec::<String>::new());
    for t in TABLES {
        let gone: bool = sqlx::query_scalar("SELECT to_regclass('public.' || $1) IS NULL")
            .bind(t)
            .fetch_one(&pool)
            .await
            .expect("to_regclass");
        assert!(gone, "{t} still exists");
    }
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// No crate's `src/` names a harvester table: the operator CLI's table model,
/// the backfill, the boot assertion and the seal stopped reading them in the
/// same change as the drop. The scan is calibrated: it must see this crate's
/// own sources, or a wrong root would make it pass on nothing.
#[test]
fn no_crate_source_names_a_harvester_table() {
    let crates = repo_root().join("crates");
    let mut files = Vec::new();
    for c in std::fs::read_dir(&crates).expect("crates/").flatten() {
        rust_files(&c.path().join("src"), &mut files);
    }
    assert!(
        files
            .iter()
            .any(|f| f.ends_with("epigraph-db/src/repos/privatization.rs")),
        "CALIBRATION: the scan must reach crates/*/src ({} files)",
        files.len()
    );
    let mut hits = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).expect("read source");
        for (i, line) in text.lines().enumerate() {
            if TABLES.iter().any(|t| line.contains(t)) {
                hits.push(format!("{}:{}: {}", f.display(), i + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "crate sources still name a dropped harvester table:\n{}",
        hits.join("\n")
    );
}

const WORLD: &str = "00000000-0000-0000-0000-000000000000";

/// One row in `table` alone. The case runs with `session_replication_role =
/// replica` (superuser, transaction-local), so no foreign key or stamping
/// trigger asks for the rows a real one would hang off: each case makes
/// exactly one of the five tables non-empty.
fn seed_for(table: &str) -> String {
    let cols = match table {
        "harvester_sources" => "content_hash, modality",
        "harvester_fragments" => "source_id, content_hash, content_text",
        "harvester_audit_reports" => "fragment_id, extraction_id",
        "harvester_claim_provenance" => "claim_id, fragment_id",
        "harvester_enriched_concepts" => "concept_name",
        other => panic!("no seed for {other}"),
    };
    let vals = match table {
        "harvester_sources" => "'\\x01'::bytea, 'text'",
        "harvester_fragments" => "gen_random_uuid(), '\\x02'::bytea, 'text'",
        "harvester_audit_reports" | "harvester_claim_provenance" => {
            "gen_random_uuid(), gen_random_uuid()"
        }
        _ => "'a concept'",
    };
    format!(
        "INSERT INTO public.{table} ({cols}, owner_group_id, visibility) \
         VALUES ({vals}, '{WORLD}', 'public')"
    )
}

/// 354 never drops a row: over ANY one non-empty harvester table it raises
/// 55000 naming that table and changes nothing. Each case seeds and runs the
/// file in one transaction and rolls it back. POSITIVE CONTROL: over the five
/// empty tables, the migrator applies 354.
#[sqlx::test(migrations = false)]
async fn migration_354_refuses_while_a_harvester_table_has_a_row(pool: PgPool) {
    migrate(&pool, &below(354))
        .await
        .expect("migrate below 354");
    let sql = migration_354();
    let before = live_references(&pool).await;
    assert!(
        !before.is_empty(),
        "CALIBRATION: below 354 the tables exist"
    );
    for table in TABLES {
        let mut tx = pool.begin().await.expect("begin");
        sqlx::raw_sql("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .expect("replica role");
        let seed = seed_for(table);
        sqlx::raw_sql(&seed)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("seed {table}: {e}\n{seed}"));
        let r = sqlx::raw_sql(&sql).execute(&mut *tx).await;
        assert_eq!(sqlstate(&r).as_deref(), Some("55000"), "{table}: {r:?}");
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains(&format!("public.{table} has rows")),
            "the refusal names {table}: {msg}"
        );
        drop(tx);
    }
    assert_eq!(
        live_references(&pool).await,
        before,
        "CALIBRATION: every case rolled back"
    );
    migrate(&pool, &below(355))
        .await
        .expect("POSITIVE CONTROL: over empty tables, 354 applies");
    assert_eq!(live_references(&pool).await, Vec::<String>::new());
}

/// The body of `epigraph_record_elevated_access` with `suffix` appended, as a
/// CREATE OR REPLACE statement.
async fn elevated_access_with(pool: &PgPool, suffix: &str) -> String {
    let def: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('public.epigraph_record_elevated_access(text, jsonb, \
         integer, uuid[])'::regprocedure)",
    )
    .fetch_one(pool)
    .await
    .expect("functiondef");
    let end = def.rfind("$function$").expect("closing quote");
    format!("{}{suffix}{}", &def[..end], &def[end..])
}

async fn elevated_access_src(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc WHERE oid = 'public.epigraph_record_elevated_access(text, \
         jsonb, integer, uuid[])'::regprocedure",
    )
    .fetch_one(pool)
    .await
    .expect("prosrc")
}

/// 354 re-states four bodies whole, so it refuses to apply over any other
/// body and changes nothing. POSITIVE CONTROL: restored, it applies.
#[sqlx::test(migrations = false)]
async fn migration_354_refuses_to_apply_over_another_body(pool: PgPool) {
    migrate(&pool, &below(354))
        .await
        .expect("migrate below 354");
    let original = elevated_access_src(&pool).await;
    let rebody = elevated_access_with(&pool, "-- a later migration's delta\n").await;
    sqlx::raw_sql(&rebody)
        .execute(&pool)
        .await
        .expect("re-body");
    let before = live_references(&pool).await;
    let err = migrate(&pool, &below(355))
        .await
        .expect_err("354 over another body");
    assert!(
        err.contains("is not the body 354 re-states"),
        "the refusal names the reason: {err}"
    );
    let applied: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 354)")
            .fetch_one(&pool)
            .await
            .expect("probe");
    assert!(!applied, "a refused 354 is not recorded");
    assert_eq!(
        live_references(&pool).await,
        before,
        "a refused 354 changes nothing"
    );

    let restore = elevated_access_with(&pool, "").await;
    let restore = restore.replacen("-- a later migration's delta\n", "", 1);
    sqlx::raw_sql(&restore)
        .execute(&pool)
        .await
        .expect("restore");
    assert_eq!(elevated_access_src(&pool).await, original, "CALIBRATION");
    migrate(&pool, &below(355))
        .await
        .expect("POSITIVE CONTROL: over 127's body, 354 applies");
}

/// Everything the undo has to put back, as sorted text lines: the five
/// tables' columns, constraints, indexes, triggers, row-security flags,
/// policies and grants; the seven functions' bodies (md5), owners, ACLs,
/// paths and definer flags; the two progress rows.
async fn harvester_catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'col ' || c.relname || '.' || a.attname || ' ' \
                || format_type(a.atttypid, a.atttypmod) || ' ' || a.attnotnull::text || ' ' \
                || COALESCE(pg_get_expr(d.adbin, d.adrelid), '-') \
           FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid \
           LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum \
          WHERE c.relname = ANY($1) AND a.attnum > 0 AND NOT a.attisdropped \
         UNION ALL \
         SELECT 'con ' || k.conrelid::regclass::text || ' ' || k.conname || ' ' \
                || pg_get_constraintdef(k.oid) \
           FROM pg_constraint k WHERE k.conrelid::regclass::text = ANY($1) \
         UNION ALL \
         SELECT 'idx ' || pg_get_indexdef(i.indexrelid) \
           FROM pg_index i WHERE i.indrelid::regclass::text = ANY($1) \
         UNION ALL \
         SELECT 'tg ' || pg_get_triggerdef(t.oid) || ' ' || t.tgenabled::text \
           FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgrelid::regclass::text = ANY($1) \
         UNION ALL \
         SELECT 'rls ' || c.relname || ' ' || c.relrowsecurity::text || ' ' \
                || c.relforcerowsecurity::text \
           FROM pg_class c WHERE c.relname = ANY($1) AND c.relkind = 'r' \
         UNION ALL \
         SELECT 'pol ' || tablename || ' ' || policyname || ' ' || permissive || ' ' \
                || roles::text || ' ' || cmd || ' ' || COALESCE(qual, '-') || ' ' \
                || COALESCE(with_check, '-') \
           FROM pg_policies WHERE tablename = ANY($1) \
         UNION ALL \
         SELECT 'acl ' || c.relname || ' ' || x.grantee::regrole::text || ' ' \
                || x.privilege_type \
           FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) x \
          WHERE c.relname = ANY($1) AND c.relkind = 'r' \
         UNION ALL \
         SELECT 'fn ' || p.oid::regprocedure::text || ' ' || md5(p.prosrc) || ' ' \
                || pg_get_userbyid(p.proowner) || ' ' || COALESCE(p.proacl::text, '-') || ' ' \
                || COALESCE(p.proconfig::text, '-') || ' ' || p.prosecdef::text \
           FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
          WHERE n.nspname = 'public' AND p.proname = ANY(ARRAY[ \
                'epigraph_propagate_tenancy', 'epigraph_record_elevated_access', \
                'epigraph_publicize_claims', 'epigraph_share_claims_with_team', \
                'epigraph_inherit_fragment_tenancy_stmt', \
                'epigraph_audit_report_inherit_tenancy', \
                'epigraph_fragment_audit_reports_follow']) \
         UNION ALL \
         SELECT 'progress ' || entity FROM tenancy_backfill_progress WHERE entity = ANY($1)",
    )
    .bind(TABLES.iter().map(|t| (*t).to_string()).collect::<Vec<_>>())
    .fetch_all(pool)
    .await
    .expect("read the harvester catalog");
    rows.into_iter().collect()
}

/// Apply, undo, apply. The undo returns every object 354 touched to its state
/// below 354 (tables empty), twice over; it refuses (55000, nothing changed)
/// over a body that is neither 354's nor the one below; and with 354's
/// bookkeeping row removed the migrator applies 354 again.
#[sqlx::test(migrations = false)]
async fn the_354_undo_restores_the_catalog_and_354_applies_again(pool: PgPool) {
    let undo = repo_text("docs/runbooks/354-undo.sql");
    migrate(&pool, &below(354))
        .await
        .expect("migrate below 354");
    let before = harvester_catalog(&pool).await;
    assert!(
        before.iter().filter(|l| l.starts_with("pol ")).count() == 18
            && before.iter().filter(|l| l.starts_with("tg ")).count() == 15,
        "CALIBRATION: below 354 the five tables carry 18 policies and 15 triggers"
    );
    migrate(&pool, &below(355)).await.expect("migrate to 354");
    assert_ne!(
        harvester_catalog(&pool).await,
        before,
        "CALIBRATION: 354 changed the catalog"
    );

    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("the undo applies");
    let after = harvester_catalog(&pool).await;
    assert_eq!(
        after.symmetric_difference(&before).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "the undo restores the catalog below 354"
    );
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("a second run applies");
    assert_eq!(harvester_catalog(&pool).await, before, "idempotent");

    // A foreign body: the undo refuses and leaves it.
    let foreign = elevated_access_with(&pool, "-- someone else's delta\n").await;
    sqlx::raw_sql(&foreign)
        .execute(&pool)
        .await
        .expect("re-body");
    let src = elevated_access_src(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let r = sqlx::raw_sql(&undo).execute(&mut *conn).await;
    assert_eq!(
        sqlstate(&r).as_deref(),
        Some("55000"),
        "the undo over a foreign body: {r:?}"
    );
    sqlx::raw_sql("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("end the undo's transaction");
    drop(conn);
    assert_eq!(
        elevated_access_src(&pool).await,
        src,
        "left the foreign body"
    );
    let restore =
        elevated_access_with(&pool, "")
            .await
            .replacen("-- someone else's delta\n", "", 1);
    sqlx::raw_sql(&restore)
        .execute(&pool)
        .await
        .expect("restore");
    assert_eq!(harvester_catalog(&pool).await, before, "CALIBRATION");

    // Apply again.
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 354")
        .execute(&pool)
        .await
        .expect("forget 354");
    migrate(&pool, &MIGRATOR)
        .await
        .expect("354 applies over the undone catalog");
    assert_eq!(live_references(&pool).await, Vec::<String>::new());
}
