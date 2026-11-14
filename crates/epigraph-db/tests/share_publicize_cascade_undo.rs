//! `docs/runbooks/215-undo.sql`, the rollback of migration 215 (share and
//! publicize carry evidence-endpoint edges, harvester sources and the stale
//! scoped folds).
//!
//! [`the_215_undo_returns_the_catalog_below_215`]: on a database migrated
//! through 215, the undo leaves the `public` catalog (relations, columns,
//! functions with body, owner and ACL, policies, triggers, constraints)
//! exactly as it was below 215, and a second run changes nothing. Because the
//! catalog compares whole function definitions by md5, this pins that the
//! undo restores 206's `epigraph_publicize_claims` and
//! `epigraph_share_claims_with_team` byte for byte. It also pins the one
//! privilege 215 adds, `epigraph_maintenance`'s DELETE on
//! `ds_bayesian_divergence`, which the catalog does not list: absent below
//! 215, present through it, absent after the undo.

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

/// The `public` catalog by name: relations, `agents` columns, functions (body,
/// owner and ACL), policies, triggers and constraints. A function is hashed
/// by its whole definition (`pg_get_functiondef`: SECURITY DEFINER, the pinned
/// `search_path`, volatility and body), not its body alone, so an undo that
/// restored 206's body without its definer attributes would be caught.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'col agents.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.agents'::regclass AND a.attnum > 0 AND NOT a.attisdropped \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE(p.proacl::text, '-') \
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

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Whether `epigraph_maintenance` may DELETE from `ds_bayesian_divergence`.
async fn maintenance_deletes_divergence(pool: &PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT has_table_privilege('epigraph_maintenance', 'public.ds_bayesian_divergence', \
                                    'DELETE')",
    )
    .fetch_one(pool)
    .await
    .expect("privilege")
}

/// The undo returns the catalog to what it was below 215, and the DELETE
/// grant with it, and is idempotent. Mutation: either re-statement dropped
/// from the undo, or edited by one character -> that function's md5 differs
/// from the one below 215 and is named in the diff; the REVOKE dropped -> the
/// privilege check fails.
#[sqlx::test(migrations = false)]
async fn the_215_undo_returns_the_catalog_below_215(pool: PgPool) {
    migrate(&pool, &up_to(214)).await;
    let before = catalog(&pool).await;
    assert!(
        !maintenance_deletes_divergence(&pool).await,
        "CALIBRATION: below 215 maintenance holds no DELETE on ds_bayesian_divergence"
    );
    migrate(&pool, &up_to(215)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    assert_eq!(
        added.len(),
        2,
        "CALIBRATION: 215 re-states exactly 206's two widening acts: {added:?}"
    );
    for name in [
        "fn epigraph_publicize_claims(p_claim_ids uuid[], p_reason text)",
        "fn epigraph_share_claims_with_team(p_claim_ids uuid[], p_group_id uuid, p_reason text)",
    ] {
        assert!(
            added.iter().any(|e| e.starts_with(name)),
            "CALIBRATION: 215 re-states {name}: {added:?}"
        );
    }
    assert_eq!(removed.len(), 2, "CALIBRATION: {removed:?}");
    assert!(
        maintenance_deletes_divergence(&pool).await,
        "CALIBRATION: 215 grants maintenance DELETE on ds_bayesian_divergence"
    );
    let undo = repo_file("docs/runbooks/215-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 215"
        );
        assert!(
            !maintenance_deletes_divergence(&pool).await,
            "after the {run} run maintenance holds no DELETE on ds_bayesian_divergence"
        );
    }
}
