//! Migration 354 (backlog a6e3dba2, c7752f07): the five harvester tables are
//! dropped, and so is every function body that named them.
//!
//! [`no_harvester_table_or_body_survives_at_head`]: on a database migrated to
//! head, no relation named `harvester_*` exists, the three trigger functions
//! only those tables ran are gone, and no surviving function body names one of
//! the five tables. `DROP TABLE` does not touch a function body, so a body left
//! naming a dropped table would fail only when called (42P01); the body check
//! is what catches that at migrate time.
//!
//! The four bodies 354 re-states are exercised at head by the suites that
//! already pin them (`declared_edge_remeet.rs`: publicize, share and the
//! propagation trigger; `elevated_access.rs`: the recorder;
//! `epigraph-mcp/tests/claim_visibility_cascade_app_role.rs`), where a body
//! still naming a dropped table would raise 42P01 when called.
//!
//! [`the_354_undo_returns_the_catalog_below_354`]: `docs/runbooks/354-undo.sql`
//! applied after 354 returns the `public` catalog (relations with owner, ACL,
//! row-security flags and comment; columns; functions by whole definition,
//! owner and ACL; policies with their expressions; triggers, constraints and
//! indexes by definition) to exactly what it was below 354, and a second run
//! changes nothing.
//!
//! [`migration_354_refuses_a_harvester_row`],
//! [`migration_354_refuses_a_body_it_was_not_written_from`] and
//! [`migration_354_refuses_a_session_that_cannot_read_every_row`]: 354's three
//! guards, each refusing with nothing changed.

use sqlx::PgPool;
use std::collections::BTreeSet;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const TABLES: [&str; 5] = [
    "harvester_audit_reports",
    "harvester_claim_provenance",
    "harvester_enriched_concepts",
    "harvester_fragments",
    "harvester_sources",
];

const DROPPED_FNS: [&str; 3] = [
    "epigraph_inherit_fragment_tenancy_stmt",
    "epigraph_audit_report_inherit_tenancy",
    "epigraph_fragment_audit_reports_follow",
];

/// Every migration strictly below `version`.
fn below(version: i64) -> sqlx::migrate::Migrator {
    through(version - 1)
}

fn through(max: i64) -> sqlx::migrate::Migrator {
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
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) -> Result<(), String> {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = migrator.run(&mut *conn).await.map_err(|e| format!("{e:?}"));
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    out
}

/// The `public` catalog, by definition where a definition exists. A
/// recreate-from-scratch undo must match the dropped objects in shape, not
/// only by name, so this is stricter than the name-only catalogs of the
/// re-statement undos.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text || ' ' \
                || pg_get_userbyid(c.relowner) || ' ' \
                || c.relrowsecurity::text || '/' || c.relforcerowsecurity::text || ' ' \
                || COALESCE((SELECT string_agg(a::text, ',' ORDER BY a::text) \
                               FROM unnest(c.relacl) a), '-') || ' ' \
                || COALESCE(obj_description(c.oid, 'pg_class'), '-') \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'col ' || c.relname || '.' || a.attname || ' ' \
                || format_type(a.atttypid, a.atttypmod) || ' ' || a.attnotnull::text || ' ' \
                || COALESCE(pg_get_expr(d.adbin, d.adrelid), '-') \
           FROM pg_attribute a \
           JOIN pg_class c ON c.oid = a.attrelid \
           LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum \
          WHERE c.relnamespace = 'public'::regnamespace AND a.attnum > 0 \
            AND NOT a.attisdropped \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname || ' ' || pol.polcmd::text || ' ' \
                || pol.polpermissive::text || ' ' || pol.polroles::text || ' ' \
                || COALESCE(pg_get_expr(pol.polqual, pol.polrelid), '-') || ' ' \
                || COALESCE(pg_get_expr(pol.polwithcheck, pol.polrelid), '-') \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname || ' ' || t.tgenabled::text || ' ' \
                || pg_get_triggerdef(t.oid) \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname || ' ' || k.convalidated::text || ' ' \
                || pg_get_constraintdef(k.oid) \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'idx ' || i.indexrelid::regclass::text || ' ' || pg_get_indexdef(i.indexrelid) \
           FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid \
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

/// The functions, in any non-system schema, whose body names one of the five
/// tables as a whole word.
async fn bodies_naming_a_table(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT p.oid::regprocedure::text FROM pg_proc p \
          WHERE p.pronamespace NOT IN ('pg_catalog'::regnamespace, \
                                       'information_schema'::regnamespace) \
            AND p.prosrc ~ '\\mharvester_(audit_reports|claim_provenance|enriched_concepts\
|fragments|sources)\\M' \
          ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .expect("bodies")
}

async fn harvester_relations(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c \
          WHERE c.relname LIKE 'harvester\\_%' ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .expect("relations")
}

async fn dropped_functions_present(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT p.proname::text FROM pg_proc p \
          WHERE p.pronamespace = 'public'::regnamespace AND p.proname = ANY($1) ORDER BY 1",
    )
    .bind(DROPPED_FNS.map(str::to_string).to_vec())
    .fetch_all(pool)
    .await
    .expect("functions")
}

/// At head: no harvester relation, none of the three harvester-only trigger
/// functions, and no function body naming one of the five tables.
///
/// Fails before 354: the five tables (and their indexes), the three functions
/// and seven bodies (the three, plus propagate, publicize, share and the
/// elevated-access recorder) are all present.
#[sqlx::test(migrations = "../../migrations")]
async fn no_harvester_table_or_body_survives_at_head(pool: PgPool) {
    assert_eq!(harvester_relations(&pool).await, Vec::<String>::new());
    assert_eq!(dropped_functions_present(&pool).await, Vec::<String>::new());
    assert_eq!(bodies_naming_a_table(&pool).await, Vec::<String>::new());
}

/// Calibration for the body check: below 354 it names exactly the seven
/// bodies that read or write the tables, so the empty answer at head is not
/// a query that matches nothing.
#[sqlx::test(migrations = false)]
async fn the_body_check_finds_the_seven_bodies_below_354(pool: PgPool) {
    migrate(&pool, &below(354)).await.expect("below 354");
    let mut bodies = bodies_naming_a_table(&pool).await;
    bodies.sort();
    assert_eq!(
        bodies,
        vec![
            "epigraph_audit_report_inherit_tenancy()".to_string(),
            "epigraph_fragment_audit_reports_follow()".to_string(),
            "epigraph_inherit_fragment_tenancy_stmt()".to_string(),
            "epigraph_propagate_tenancy()".to_string(),
            "epigraph_publicize_claims(uuid[],text)".to_string(),
            "epigraph_record_elevated_access(text,jsonb,integer,uuid[])".to_string(),
            "epigraph_share_claims_with_team(uuid[],uuid,text)".to_string(),
        ]
    );
    let mut rels = harvester_relations(&pool).await;
    rels.retain(|r| TABLES.contains(&r.as_str()));
    rels.sort();
    assert_eq!(rels, TABLES.map(str::to_string).to_vec());
}

/// The undo returns the catalog to what it was below 354, and is idempotent.
/// Mutation: one table's policy, trigger, grant, index or column dropped from
/// the undo, or one of the restored bodies edited -> that entry is named in
/// the diff.
#[sqlx::test(migrations = false)]
async fn the_354_undo_returns_the_catalog_below_354(pool: PgPool) {
    migrate(&pool, &below(354)).await.expect("below 354");
    let before = catalog(&pool).await;
    migrate(&pool, &through(354)).await.expect("through 354");
    let through_354 = catalog(&pool).await;
    assert!(
        !through_354.iter().any(|e| e.contains("harvester_")),
        "CALIBRATION: 354 leaves no catalog entry naming a harvester object"
    );
    let removed: BTreeSet<&String> = before.difference(&through_354).collect();
    for t in TABLES {
        assert!(
            removed.iter().any(|e| e.starts_with(&format!("rel {t} r "))),
            "CALIBRATION: 354 drops {t}"
        );
    }
    let undo = repo_file("docs/runbooks/354-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 354"
        );
    }
}

/// 354 refuses, with 55000 and nothing changed, while a harvester table holds
/// a row: it archives nothing. Mutation: guard (c) removed -> 354 applies and
/// drops the row with its table.
#[sqlx::test(migrations = false)]
async fn migration_354_refuses_a_harvester_row(pool: PgPool) {
    migrate(&pool, &below(354)).await.expect("below 354");
    sqlx::query(
        "INSERT INTO harvester_sources (content_hash, modality, owner_group_id, visibility) \
         VALUES ('\\x01'::bytea, 'text', '00000000-0000-0000-0000-000000000000', 'public')",
    )
    .execute(&pool)
    .await
    .expect("a harvester source");
    let before = catalog(&pool).await;
    let err = migrate(&pool, &through(354))
        .await
        .expect_err("354 must refuse a harvester row");
    assert!(err.contains("harvester_sources (1)"), "{err}");
    assert!(err.contains("55000"), "{err}");
    assert_eq!(
        catalog(&pool).await.symmetric_difference(&before).count(),
        0,
        "nothing was changed"
    );
}

/// 354 refuses to apply over a publicize body other than 284's, with 55000,
/// and changes nothing. Mutation: guard (a) removed -> 354 applies and the
/// re-bodied publicize is silently replaced.
#[sqlx::test(migrations = false)]
async fn migration_354_refuses_a_body_it_was_not_written_from(pool: PgPool) {
    migrate(&pool, &below(354)).await.expect("below 354");
    let def: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('public.epigraph_publicize_claims(uuid[], text)'::regprocedure)",
    )
    .fetch_one(&pool)
    .await
    .expect("publicize definition");
    let rebodied = def.replacen("VIS01: publicize needs", "VIS01: publicize  needs", 1);
    assert_ne!(rebodied, def, "PREMISE: the body changed");
    sqlx::raw_sql(&rebodied)
        .execute(&pool)
        .await
        .expect("re-body publicize");
    let before = catalog(&pool).await;
    let err = migrate(&pool, &through(354))
        .await
        .expect_err("354 must refuse a publicize body it was not written from");
    assert!(
        err.contains("is not the body 354 re-states"),
        "{err}"
    );
    assert!(err.contains("55000"), "{err}");
    assert_eq!(
        catalog(&pool).await.symmetric_difference(&before).count(),
        0,
        "nothing was changed"
    );
}

/// 354 refuses (42501) a login that cannot read every harvester row: the
/// tables are FORCEd, so such a session would count only the rows its policies
/// admit and pass the emptiness guard over rows it cannot see. The login is a
/// real one (a `SET ROLE` from the superuser keeps `session_user`, which
/// `epigraph_bypass()` admits), a member of `epigraph_app` and of nothing else.
/// Mutation: guard (b) removed -> the refusal is a privilege error from the
/// row count (the policies call `epigraph_definer_bypass()`), not this one.
#[sqlx::test(migrations = false)]
async fn migration_354_refuses_a_session_that_cannot_read_every_row(pool: PgPool) {
    use sqlx::{ConnectOptions, Connection};
    migrate(&pool, &below(354)).await.expect("below 354");
    let file = repo_file("migrations/354_drop_harvester_tables.sql");
    // Roles are cluster-wide: a name of this run's own, dropped at the end.
    let role = format!("h354_app_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB INHERIT \
         PASSWORD 'probe-only' IN ROLE epigraph_app"
    ))
    .execute(&pool)
    .await
    .expect("create the application login");
    let mut conn = (*pool.connect_options())
        .clone()
        .username(&role)
        .password("probe-only")
        .connect()
        .await
        .expect("connect as the application login");
    let mut tx = conn.begin().await.expect("begin");
    let err = sqlx::raw_sql(&file)
        .execute(&mut *tx)
        .await
        .expect_err("354 must refuse a session that cannot read every row");
    let db = err.as_database_error().expect("a database error");
    assert_eq!(db.code().as_deref(), Some("42501"), "{err}");
    assert!(
        db.message().contains("cannot read every harvester row"),
        "{err}"
    );
    tx.rollback().await.expect("rollback");
    conn.close().await.expect("close");
    assert!(
        harvester_relations(&pool).await.len() >= TABLES.len(),
        "nothing was dropped"
    );
    for _ in 0..200 {
        let live: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename = $1")
                .bind(&role)
                .fetch_one(&pool)
                .await
                .expect("the login's sessions");
        if live == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&pool)
        .await
        .expect("drop the login");
}
