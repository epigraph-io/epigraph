//! `docs/runbooks/255-undo.sql`, the rollback of migration 255
//! (`papers.licence` set by the operator only, backlog 9ee6799d).
//!
//! [`the_255_undo_returns_the_catalog_below_255`]: on a database migrated
//! through 255, the undo leaves the `public` catalog it touches (functions
//! with their whole definition, owner and ACL; the table and column ACLs of
//! `papers`; the policies on `security_events`; the comment on
//! `papers.licence`) exactly as it was below 255, and a second run changes
//! nothing.
//!
//! ACLs are compared as sets of entries: granting back what a REVOKE took
//! leaves the same privileges in a different array order, which is not a
//! difference anyone can observe.

use sqlx::PgPool;
use std::collections::BTreeSet;

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

async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE((SELECT string_agg(x::text, ',' ORDER BY x::text) \
                               FROM unnest(COALESCE(p.proacl, acldefault('f', p.proowner))) x), \
                            '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'acl papers ' || COALESCE((SELECT string_agg(x::text, ',' ORDER BY x::text) \
                                             FROM unnest(c.relacl) x), '-') \
           FROM pg_class c WHERE c.oid = 'public.papers'::regclass \
         UNION ALL \
         SELECT 'colacl papers.' || a.attname || ' ' || \
                (SELECT string_agg(x::text, ',' ORDER BY x::text) FROM unnest(a.attacl) x) \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.papers'::regclass AND a.attnum > 0 \
            AND NOT a.attisdropped AND cardinality(a.attacl) > 0 \
         UNION ALL \
         SELECT 'policy security_events.' || pol.polname || ' ' || pol.polpermissive::text \
                || ' ' || COALESCE(pg_get_expr(pol.polwithcheck, pol.polrelid), '-') \
           FROM pg_policy pol WHERE pol.polrelid = 'public.security_events'::regclass \
         UNION ALL \
         SELECT 'comment papers.licence ' || \
                COALESCE(col_description('public.papers'::regclass, a.attnum), '-') \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.papers'::regclass AND a.attname = 'licence'",
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

/// The undo returns the catalog to what it was below 255, and is idempotent.
/// Mutation: the undo's GRANT dropped -> the `papers` ACL differs; its
/// comment restatement dropped -> the comment entry differs.
#[sqlx::test(migrations = false)]
async fn the_255_undo_returns_the_catalog_below_255(pool: PgPool) {
    migrate(&pool, &up_to(254)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(255)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    assert!(
        added
            .iter()
            .any(|e| e.starts_with("fn epigraph_set_paper_licence(")),
        "CALIBRATION: 255 adds the operator definer: {added:?}"
    );
    assert!(
        added
            .iter()
            .any(|e| e
                .starts_with("policy security_events.security_events_paper_licence_privileged ")),
        "CALIBRATION: 255 adds the reserved-prefix policy: {added:?}"
    );
    assert!(
        added
            .iter()
            .any(|e| e.starts_with("colacl papers.doi ") && e.contains("epigraph_app=aw/")),
        "CALIBRATION: 255 grants epigraph_app column INSERT and UPDATE: {added:?}"
    );
    assert!(
        added
            .iter()
            .any(|e| e.starts_with("comment papers.licence ")),
        "CALIBRATION: 255 re-states the column comment: {added:?}"
    );

    let undo = repo_file("docs/runbooks/255-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 255"
        );
    }
}
