//! `docs/runbooks/258-undo.sql`, the rollback of migration 258 (a frame,
//! context, perspective or community endpoint contributes its own tenancy to
//! an edge's meet, backlog a07c25c0).
//!
//! [`the_258_undo_returns_the_catalog_below_258`]: on a database migrated
//! through 258, the undo leaves the `public` catalog (relations, columns,
//! functions with their whole definition, owner and ACL, policies, triggers,
//! constraints) exactly as it was below 258, and a second run changes nothing.
//! Because functions are compared by the md5 of `pg_get_functiondef`, this
//! pins that the undo restores 246's `epigraph_node_tenancy` and
//! `epigraph_propagate_tenancy` byte for byte (body, SECURITY DEFINER, pinned
//! `search_path`), with their owner and ACL.
//!
//! [`migration_258_refuses_over_a_restated_propagation_body`] and
//! [`the_258_undo_refuses_over_a_later_restatement`]: 258 and its undo each
//! re-state SHARED bodies (other migrations re-state them too), so each
//! refuses, changing nothing, unless the functions hold exactly the bodies it
//! was written against. Without that, whichever re-statement applied later
//! would silently revert the other.

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
/// owner and ACL), policies, triggers and constraints (the shape of
/// `agent_default_private_undo.rs`). A function is hashed
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

/// The undo returns the catalog to what it was below 258, and is idempotent.
/// Mutation: one character of the undo's re-statement of 246's propagation
/// body changed -> that function's md5 differs from the one below 258 and is
/// named in the diff.
#[sqlx::test(migrations = false)]
async fn the_258_undo_returns_the_catalog_below_258(pool: PgPool) {
    migrate(&pool, &up_to(257)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(258)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    assert_eq!(
        added.len(),
        2,
        "CALIBRATION: 258 re-states two functions and adds nothing: {added:?}"
    );
    for name in [
        "fn epigraph_node_tenancy(",
        "fn epigraph_propagate_tenancy(",
    ] {
        assert!(
            added.iter().any(|e| e.starts_with(name)),
            "CALIBRATION: 258 changes {name}: {added:?}"
        );
    }
    assert_eq!(
        removed.len(),
        2,
        "CALIBRATION: the only entries 258 changes are the two re-stated bodies: {removed:?}"
    );

    let undo = repo_file("docs/runbooks/258-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 258"
        );
    }
}

/// The propagation body re-stated with one added comment, as a migration that
/// re-states it would leave it; returns the marker it carries.
async fn restate_propagation(pool: &PgPool) -> &'static str {
    const MARK: &str = "-- re-stated by a later migration";
    let def: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('public.epigraph_propagate_tenancy()'::regprocedure)",
    )
    .fetch_one(pool)
    .await
    .expect("the propagation's definition");
    assert!(
        def.contains("\nBEGIN\n"),
        "CALIBRATION: a plpgsql body: {def}"
    );
    let restated = def.replacen("\nBEGIN\n", &format!("\nBEGIN\n    {MARK}\n"), 1);
    sqlx::raw_sql(&restated)
        .execute(pool)
        .await
        .expect("re-state the propagation");
    MARK
}

async fn propagation_src(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE proname = 'epigraph_propagate_tenancy'")
        .fetch_one(pool)
        .await
        .expect("prosrc")
}

/// 258 over a propagation body that is not 246's (a migration before it
/// re-stated the function) refuses, and applies nothing: the re-statement
/// survives and the oracle keeps 246's body. Mutation: the guard removed ->
/// 258 applies and puts 246's body (plus the joins) back over the change.
#[sqlx::test(migrations = false)]
async fn migration_258_refuses_over_a_restated_propagation_body(pool: PgPool) {
    migrate(&pool, &up_to(257)).await;
    let mark = restate_propagation(&pool).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let err = up_to(258)
        .run(&mut *conn)
        .await
        .expect_err("258 refuses over a body it was not written against");
    drop(conn);
    let text = format!("{err:?}");
    assert!(
        text.contains("is not the body 258 builds on"),
        "the refusal says why: {text}"
    );
    assert!(
        propagation_src(&pool).await.contains(mark),
        "the earlier re-statement survives"
    );
    let oracle: String = sqlx::query_scalar(
        "SELECT md5(prosrc) FROM pg_proc \
          WHERE oid = 'public.epigraph_node_tenancy(uuid, text)'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("oracle probe");
    assert_eq!(
        oracle, "25a0585c8da9141741a55e2f2f72259c",
        "nothing of 258 was applied: the oracle keeps 246's body"
    );
}

/// The undo over a propagation body that is neither 258's nor 246's (a later
/// migration re-stated it) refuses and changes nothing. Mutation: the undo's
/// guard removed -> it re-states 246's body and the later change is lost.
#[sqlx::test(migrations = false)]
async fn the_258_undo_refuses_over_a_later_restatement(pool: PgPool) {
    migrate(&pool, &up_to(258)).await;
    let mark = restate_propagation(&pool).await;
    let before = catalog(&pool).await;

    let undo = repo_file("docs/runbooks/258-undo.sql");
    let mut conn = pool.acquire().await.expect("acquire");
    let err = sqlx::raw_sql(&undo)
        .execute(&mut *conn)
        .await
        .expect_err("the undo refuses over a later re-statement");
    sqlx::query("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("end the aborted undo transaction");
    drop(conn);
    let text = format!("{err:?}");
    assert!(
        text.contains("neither 258's body"),
        "the refusal says why: {text}"
    );
    assert!(
        propagation_src(&pool).await.contains(mark),
        "the later re-statement survives"
    );
    assert_eq!(
        catalog(&pool)
            .await
            .symmetric_difference(&before)
            .collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "the refused undo changed nothing"
    );
}
