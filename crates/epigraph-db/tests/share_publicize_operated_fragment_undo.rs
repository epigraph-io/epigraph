//! `docs/runbooks/242-undo.sql`, the rollback of migration 242 (share and
//! publicize refuse an operated agent), and 242's md5 precondition.
//!
//! [`the_242_undo_returns_the_catalog_below_242`]: on a database migrated
//! through 242, the undo leaves the `public` catalog (relations, functions
//! with whole definition, owner and ACL, policies, triggers, constraints)
//! exactly as it was below 242, and a second run changes nothing. The catalog
//! hashes whole function definitions, so this pins that the undo restores
//! 215's `epigraph_publicize_claims` and `epigraph_share_claims_with_team`
//! byte for byte.
//!
//! [`migration_242_refuses_a_body_it_was_not_written_from`]: 242 re-states
//! both bodies whole, so it must not silently drop a delta another migration
//! made to either. Over a re-bodied `epigraph_publicize_claims` it refuses
//! (55000) and changes nothing.
//!
//! The behaviour 242 adds is pinned on the application role in
//! `epigraph-mcp/tests/claim_visibility_cascade_app_role.rs`.

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
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) -> Result<(), String> {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = migrator.run(&mut *conn).await.map_err(|e| format!("{e:?}"));
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    out
}

/// The `public` catalog by name: relations, functions (whole definition,
/// owner and ACL), policies, triggers and constraints.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
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

const PUBLICIZE: &str = "fn epigraph_publicize_claims(p_claim_ids uuid[], p_reason text)";
const SHARE: &str =
    "fn epigraph_share_claims_with_team(p_claim_ids uuid[], p_group_id uuid, p_reason text)";

/// The undo returns the catalog to what it was below 242, and is idempotent.
/// Mutation: either re-statement dropped from the undo, or edited by one
/// character -> that function's md5 differs from the one below 242 and is
/// named in the diff.
#[sqlx::test(migrations = false)]
async fn the_242_undo_returns_the_catalog_below_242(pool: PgPool) {
    migrate(&pool, &up_to(241)).await.expect("below 242");
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(242)).await.expect("through 242");
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    assert_eq!(
        added.len(),
        2,
        "CALIBRATION: 242 re-states exactly 215's two widening acts: {added:?}"
    );
    for name in [PUBLICIZE, SHARE] {
        assert!(
            added.iter().any(|e| e.starts_with(name)),
            "CALIBRATION: 242 re-states {name}: {added:?}"
        );
    }
    assert_eq!(removed.len(), 2, "CALIBRATION: {removed:?}");
    let undo = repo_file("docs/runbooks/242-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 242"
        );
    }
}

/// 242 refuses to apply over a publicize body other than 215's, with 55000,
/// and changes nothing (the share body is still the one below 242). Mutation:
/// the precondition block removed -> 242 applies and the share body changes.
#[sqlx::test(migrations = false)]
async fn migration_242_refuses_a_body_it_was_not_written_from(pool: PgPool) {
    migrate(&pool, &up_to(241)).await.expect("below 242");
    // Another migration's delta: the same function with one character more in
    // its body.
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

    let err = migrate(&pool, &up_to(242))
        .await
        .expect_err("242 must refuse a publicize body it was not written from");
    assert!(
        err.contains("242: epigraph_publicize_claims is not the body 242 re-states"),
        "{err}"
    );
    assert!(err.contains("55000"), "{err}");
    assert_eq!(
        catalog(&pool).await.symmetric_difference(&before).count(),
        0,
        "nothing was changed"
    );
}
