//! Migration 246 (backlog 34864fb5): a `papers` row carries the tenancy of the
//! ingest that wrote it.
//!
//! * The backfill makes every existing row ('public', world): what every reader
//!   saw before. Two rows of one document cannot exist before 246, and 246
//!   refuses to apply while a unique key over `doi` it does not drop survives.
//! * The columns have 062's tier-A shape, the row security is ENABLEd and
//!   FORCEd, a write must declare its tenancy, and nobody but a maintenance
//!   session re-tenants a row.
//! * One row per document per SCOPE (`PaperRepository::get_or_create` on
//!   stamped transactions as the application role): every public writer of a
//!   document converges on one public row whatever its group; two groups'
//!   private writes of it give two rows, neither visible to the other group;
//!   a stranger cannot write into a group it does not write.
//! * `epigraph_node_tenancy` meets a paper endpoint with its own row: an
//!   `authored` edge from a (public) agent onto a group paper is a group edge,
//!   invisible to a stranger; and re-tenanting a claim that a group paper
//!   asserts never re-meets that edge as if the paper were public.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::TenancyDecl;
use epigraph_db::visibility::Viewer;
use epigraph_db::{PaperRepository, ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();

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

async fn tenancy(pool: &PgPool, paper: Uuid) -> (String, Uuid) {
    sqlx::query_as("SELECT visibility::text, owner_group_id FROM papers WHERE id = $1")
        .bind(paper)
        .fetch_one(pool)
        .await
        .expect("row tenancy")
}

/// Every row written before 246 is public and world-owned afterwards.
#[sqlx::test(migrations = false)]
async fn migration_246_backfills_every_paper_public(pool: PgPool) {
    migrate(&pool, &up_to(245)).await;
    let a: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.5555/legacy-a', 'A') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("legacy row");
    let b: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi) VALUES ('urn:epigraph:doc:legacy-b') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("legacy row");

    migrate(&pool, &MIGRATOR).await;

    assert_eq!(tenancy(&pool, a).await, ("public".into(), WORLD));
    assert_eq!(tenancy(&pool, b).await, ("public".into(), WORLD));
}

/// 246 drops 001's two `UNIQUE (doi)` constraints by name. A unique key over
/// `doi` under any other name would survive those DROPs and refuse every group
/// copy of a document that already has a public row (23505), so 246 refuses to
/// apply over one; with it gone, 246 applies.
#[sqlx::test(migrations = false)]
async fn migration_246_refuses_a_surviving_unique_doi_key(pool: PgPool) {
    migrate(&pool, &up_to(245)).await;
    sqlx::query("ALTER TABLE papers ADD CONSTRAINT papers_doi_renamed UNIQUE (doi)")
        .execute(&pool)
        .await
        .expect("a unique key under a name 246 does not drop");

    let mut conn = pool.acquire().await.expect("acquire");
    let err = MIGRATOR
        .run(&mut *conn)
        .await
        .expect_err("246 must refuse while a unique key over doi survives its DROPs");
    drop(conn);
    let msg = format!("{err:?}");
    assert!(
        msg.contains("still has a unique index over doi") && msg.contains("papers_doi_renamed"),
        "refused for the surviving key, naming it: {msg}"
    );
    let applied: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 246)")
            .fetch_one(&pool)
            .await
            .expect("ledger");
    assert!(!applied, "the refused 246 left nothing behind");

    sqlx::query("ALTER TABLE papers DROP CONSTRAINT papers_doi_renamed")
        .execute(&pool)
        .await
        .expect("drop the surviving key");
    migrate(&pool, &MIGRATOR).await;
}

/// 062's tier-A shape, FORCEd row security, the three triggers, and the
/// per-scope unique key in place of 001's `UNIQUE (doi)`.
#[sqlx::test(migrations = "../../migrations")]
async fn paper_rows_carry_the_tier_a_shape(pool: PgPool) {
    let cols: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT column_name::text, is_nullable::text, column_default::text \
           FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'papers' \
            AND column_name IN ('owner_group_id', 'visibility') ORDER BY column_name",
    )
    .fetch_all(&pool)
    .await
    .expect("columns");
    assert_eq!(
        cols,
        vec![
            ("owner_group_id".into(), "NO".into(), None),
            ("visibility".into(), "NO".into(), None),
        ]
    );
    let (rls, force): (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
          WHERE oid = 'public.papers'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("pg_class");
    assert!(rls && force, "row security ENABLEd and FORCEd");
    let armed: Vec<String> = sqlx::query_scalar(
        "SELECT tgname::text FROM pg_trigger \
          WHERE tgrelid = 'public.papers'::regclass AND NOT tgisinternal \
            AND tgenabled = 'O' AND tgname IN ('papers_require_tenancy', \
                'papers_owner_immutable', 'papers_visibility_immutable') \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("triggers");
    assert_eq!(
        armed,
        [
            "papers_owner_immutable",
            "papers_require_tenancy",
            "papers_visibility_immutable"
        ]
    );
    let doi_only: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint \
          WHERE conrelid = 'public.papers'::regclass AND contype = 'u'",
    )
    .fetch_one(&pool)
    .await
    .expect("unique constraints");
    assert_eq!(doi_only, 0, "001's UNIQUE (doi) constraints are gone");
}

/// The application-role world: members `a` (group `g`) and `b` (group `h`),
/// and a stranger `s`, each with its own personal group.
struct AppWorld {
    scoped: ScopedPool,
    plain: PgPool,
    a: Viewer,
    b: Viewer,
    s: Viewer,
    g: Uuid,
    h: Uuid,
}

async fn app_world(pool: &PgPool) -> AppWorld {
    let (a, g) = fixture::seed_agent_with_group(pool, "paper-a").await;
    let (b, h) = fixture::seed_agent_with_group(pool, "paper-b").await;
    let (s, _) = fixture::seed_agent_with_group(pool, "paper-stranger").await;
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    AppWorld {
        scoped,
        plain: fixture::downgraded_pool(pool, "epigraph_app").await,
        a: Viewer::resolve(pool, a).await.expect("viewer a"),
        b: Viewer::resolve(pool, b).await.expect("viewer b"),
        s: Viewer::resolve(pool, s).await.expect("viewer s"),
        g,
        h,
    }
}

/// `get_or_create` as `viewer`, on its own committed stamped transaction.
async fn register(
    w: &AppWorld,
    viewer: &Viewer,
    doi: &str,
    decl: TenancyDecl,
) -> Result<Uuid, epigraph_db::DbError> {
    let mut tx = w.scoped.begin_as(viewer).await.expect("stamped tx");
    let id = PaperRepository::get_or_create(&mut *tx, doi, Some("a title"), None, decl).await?;
    tx.commit().await.expect("commit");
    Ok(id)
}

/// The ids of `doi`'s rows `viewer` reads, through the repository read and
/// through the row security alone (they must agree).
async fn visible(w: &AppWorld, viewer: &Viewer, doi: &str) -> Vec<Uuid> {
    let mut read = w.scoped.read_as(viewer).await.expect("stamped read");
    let repo: Vec<Uuid> = PaperRepository::visible_by_document_key(&mut read, viewer, doi)
        .await
        .expect("visible_by_document_key")
        .into_iter()
        .map(|p| p.id)
        .collect();
    let mut policy: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM papers WHERE doi = $1")
        .bind(doi)
        .fetch_all(&mut *read)
        .await
        .expect("policy read");
    read.commit().await.expect("close read");
    let mut sorted = repo.clone();
    sorted.sort();
    policy.sort();
    assert_eq!(
        sorted, policy,
        "the spliced predicate and the row security agree"
    );
    repo
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_groups_private_copies_are_two_rows_neither_visible_to_the_other(pool: PgPool) {
    let w = app_world(&pool).await;
    let doi = "10.5555/confidential";
    let pa = register(&w, &w.a, doi, TenancyDecl::group(w.g))
        .await
        .expect("a's private paper");
    let pb = register(&w, &w.b, doi, TenancyDecl::group(w.h))
        .await
        .expect("b's private paper");
    assert_ne!(
        pa, pb,
        "one row per group: b's ingest does not land on a's row"
    );
    assert_eq!(tenancy(&pool, pa).await, ("group".into(), w.g));
    assert_eq!(tenancy(&pool, pb).await, ("group".into(), w.h));
    assert_eq!(visible(&w, &w.a, doi).await, vec![pa]);
    assert_eq!(visible(&w, &w.b, doi).await, vec![pb]);
    assert!(
        visible(&w, &w.s, doi).await.is_empty(),
        "a stranger finds no row of a document only two groups hold privately"
    );
    let unstamped: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM papers WHERE doi = $1")
        .bind(doi)
        .fetch_all(&w.plain)
        .await
        .expect("unstamped read");
    assert!(
        unstamped.is_empty(),
        "an unstamped session reads public rows only"
    );
    // Idempotent per scope: a's second ingest reuses a's row.
    assert_eq!(
        register(&w, &w.a, doi, TenancyDecl::group(w.g))
            .await
            .expect("a again"),
        pa
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_public_writer_converges_on_one_public_row(pool: PgPool) {
    let w = app_world(&pool).await;
    let doi = "10.5555/published";
    let first = register(&w, &w.a, doi, TenancyDecl::public(w.g))
        .await
        .expect("a's public paper");
    let second = register(
        &w,
        &w.b,
        &format!("https://doi.org/{doi}"),
        TenancyDecl::public(w.h),
    )
    .await
    .expect("b's public paper");
    assert_eq!(
        first, second,
        "two groups' public ingests of one document share its one public row"
    );
    // A private copy beside the public row is its own row, seen by its group
    // first and by nobody else.
    let private = register(&w, &w.a, doi, TenancyDecl::group(w.g))
        .await
        .expect("a's private copy");
    assert_ne!(private, first);
    assert_eq!(visible(&w, &w.a, doi).await, vec![private, first]);
    assert_eq!(visible(&w, &w.s, doi).await, vec![first]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_a_writer_of_the_group_writes_and_nobody_retenants(pool: PgPool) {
    let w = app_world(&pool).await;
    let refused = register(&w, &w.s, "10.5555/not-yours", TenancyDecl::group(w.g)).await;
    assert!(
        matches!(
            refused,
            Err(epigraph_db::DbError::QueryFailed { source: sqlx::Error::Database(ref d) })
                if d.code().as_deref() == Some("42501")
        ),
        "a stranger cannot write a paper into a group it does not write: {refused:?}"
    );
    let mut tx = w.scoped.begin_as(&w.a).await.expect("stamped tx");
    let undeclared = sqlx::query("INSERT INTO papers (doi) VALUES ('10.5555/undeclared')")
        .execute(&mut *tx)
        .await
        .map(|_| ())
        .map_err(|e| {
            e.as_database_error()
                .and_then(|d| d.code().map(|c| c.to_string()))
                .unwrap_or_default()
        });
    drop(tx);
    assert_eq!(
        undeclared,
        Err("23502".into()),
        "an undeclared paper is refused, never defaulted"
    );
    let pa = register(&w, &w.a, "10.5555/kept", TenancyDecl::group(w.g))
        .await
        .expect("a's private paper");
    for sql in [
        "UPDATE papers SET visibility = 'public' WHERE id = $1",
        "UPDATE papers SET owner_group_id = $2 WHERE id = $1",
    ] {
        let mut tx = w.scoped.begin_as(&w.a).await.expect("stamped tx");
        let r = sqlx::query(sql)
            .bind(pa)
            .bind(w.h)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                e.as_database_error()
                    .and_then(|d| d.code().map(|c| c.to_string()))
                    .unwrap_or_default()
            });
        drop(tx);
        assert_eq!(r.map(|r| r.rows_affected()), Err("42501".into()), "{sql}");
    }
    let mut tx = w.scoped.begin_as(&w.a).await.expect("stamped tx");
    let deleted = sqlx::query("DELETE FROM papers WHERE id = $1")
        .bind(pa)
        .execute(&mut *tx)
        .await
        .map(|r| r.rows_affected());
    drop(tx);
    assert!(
        !matches!(deleted, Ok(n) if n > 0),
        "no application session deletes a paper"
    );
    assert_eq!(tenancy(&pool, pa).await, ("group".into(), w.g));
}

/// `(owner_group_id, visibility, co_owner_group_id)` of one edge.
async fn edge_tenancy(pool: &PgPool, edge: Uuid) -> (Uuid, String, Option<Uuid>) {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(edge)
    .fetch_one(pool)
    .await
    .expect("edge tenancy")
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_onto_a_group_paper_takes_the_papers_tenancy(pool: PgPool) {
    let w = app_world(&pool).await;
    let paper = register(&w, &w.a, "10.5555/edges", TenancyDecl::group(w.g))
        .await
        .expect("a's private paper");
    let author = w.a.principal().expect("a");
    let authored: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'agent', $2, 'paper', 'authored') RETURNING id",
    )
    .bind(author)
    .bind(paper)
    .fetch_one(&pool)
    .await
    .expect("authored edge");
    assert_eq!(
        edge_tenancy(&pool, authored).await,
        (w.g, "group".into(), None),
        "agent (public) -> group paper meets to the paper's group, not ('public', world)"
    );
    let mut read = w.scoped.read_as(&w.s).await.expect("stranger read");
    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE target_id = $1")
        .bind(paper)
        .fetch_one(&mut *read)
        .await
        .expect("stranger edge read");
    read.commit().await.expect("close");
    assert_eq!(
        seen, 0,
        "a stranger sees no edge onto another group's private paper"
    );

    // The paper asserts a PUBLIC claim (an atom the walk converged onto): the
    // edge is the paper's group's. When the claim is then made private to
    // ANOTHER group, the propagation re-meets the edge with the paper's own
    // row: it becomes co-owned (readable by members of both), never owned by
    // the claim's group alone (which would show h's members a's paper id).
    let claim = fixture::seed_public_claim(&pool, author, "an atom a's paper asserts").await;
    let asserts: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'paper', $2, 'claim', 'asserts') RETURNING id",
    )
    .bind(paper)
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("asserts edge");
    assert_eq!(
        edge_tenancy(&pool, asserts).await,
        (w.g, "group".into(), None)
    );
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(w.h)
        .execute(&pool)
        .await
        .expect("privatize the claim into h");
    assert_eq!(
        edge_tenancy(&pool, asserts).await,
        (w.g, "group".into(), Some(w.h)),
        "the re-meet keeps the paper's group as an owner"
    );
}

// =====================================================================
// docs/runbooks/246-undo.sql
// =====================================================================

/// The `public` catalog by name: relations, `papers` columns and row-security
/// flags, functions (whole definition, owner and ACL), policies, triggers and
/// constraints (the shape of `workflow_endpoint_tenancy_undo.rs`).
async fn catalog(pool: &PgPool) -> std::collections::BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'col papers.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) \
                || ' ' || a.attnotnull::text \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.papers'::regclass AND a.attnum > 0 AND NOT a.attisdropped \
         UNION ALL \
         SELECT 'rls papers ' || c.relrowsecurity::text || ' ' || c.relforcerowsecurity::text \
           FROM pg_class c WHERE c.oid = 'public.papers'::regclass \
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
         SELECT 'con ' || c.relname || '.' || k.conname || ' ' || pg_get_constraintdef(k.oid) \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

fn undo_sql() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/246-undo.sql"),
    )
    .expect("246-undo.sql")
}

/// On a database migrated through 246 with only public papers, the undo
/// leaves the catalog exactly as it was below 246 (219's two function bodies
/// byte for byte, 001's `UNIQUE (doi)` constraints, row security off), and a
/// second run changes nothing.
#[sqlx::test(migrations = false)]
async fn the_246_undo_returns_the_catalog_below_246(pool: PgPool) {
    migrate(&pool, &up_to(245)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &MIGRATOR).await;
    let through = catalog(&pool).await;
    assert!(
        through
            .difference(&before)
            .any(|e| e.starts_with("fn epigraph_node_tenancy(")),
        "CALIBRATION: 246 re-states the oracle"
    );
    sqlx::query(
        "INSERT INTO papers (doi, visibility, owner_group_id) \
         VALUES ('10.5555/kept-public', 'public', '00000000-0000-0000-0000-000000000000')",
    )
    .execute(&pool)
    .await
    .expect("a public paper survives the undo");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo_sql())
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 246"
        );
    }
    let kept: i64 =
        sqlx::query_scalar("SELECT count(*) FROM papers WHERE doi = '10.5555/kept-public'")
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(kept, 1);
}

/// A group-private paper, or two rows of one document, refuse the undo and
/// change nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_246_undo_refuses_while_a_paper_is_private(pool: PgPool) {
    let (_, g) = fixture::seed_agent_with_group(&pool, "undo-owner").await;
    sqlx::query(
        "INSERT INTO papers (doi, visibility, owner_group_id) \
         VALUES ('10.5555/private', 'group', $1)",
    )
    .bind(g)
    .execute(&pool)
    .await
    .expect("a private paper");
    let before = catalog(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let err = sqlx::raw_sql(&undo_sql())
        .execute(&mut *conn)
        .await
        .expect_err("the undo refuses over a private paper");
    sqlx::query("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("end the failed undo transaction");
    drop(conn);
    assert!(
        err.to_string().contains("group-private paper"),
        "the refusal names the reason: {err}"
    );
    assert_eq!(catalog(&pool).await, before, "nothing was changed");
}
