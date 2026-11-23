//! Migration 255 (backlog 9ee6799d): `papers.licence`, which decides whether
//! document ingest may keep a verbatim publisher passage in evidence, is
//! written only by the operator, through the audited maintenance definer
//! `epigraph_set_paper_licence`. Before 255 the application role held
//! table-level INSERT and UPDATE on the registry table `papers`, so any
//! application session could mark a paper open-licensed, either by writing
//! `licence` or by moving an open-licensed row's `doi` onto a paywalled DOI
//! (ingest finds the paper by DOI, then reads that row's licence).
//!
//! Every application write here runs on a pool whose connections are
//! `SET SESSION AUTHORIZATION epigraph_app` and stamped (session scope) as a
//! seeded agent writing its own group, the operator's on one that is
//! `SET SESSION AUTHORIZATION epigraph_maintenance`. Fixtures are seeded and
//! read back on the superuser pool.
//!
//! Since migration 246 (backlog 34864fb5) `papers` carries tenancy under
//! FORCEd row security, so an unstamped application session can write no row
//! at all: every refusal below would be 42501 for that reason alone. The
//! stamp makes the row security ADMIT each write (a public row is readable,
//! and the application's own rows are written into its group), so the 42501s
//! measured here are 255's column privileges. Upserts name 246's conflict
//! target (`papers_document_key_scope_key`: the document key and its scope).
//!
//! # Verified to fail
//!
//! Each mutation of migration 255 applied alone, then restored. The first
//! three also drop section 8 (the end-state check), which otherwise refuses
//! the mutated migration itself: with section 4 removed and section 8 kept,
//! every test fails at migrate time with `LIC09` (measured).
//!
//! Without 255 at all, every test here fails except the positive control
//! `the_app_role_still_registers_and_fills_papers`.
//!
//! * section 4 (the REVOKE and column re-grant) removed: fails
//!   `the_app_role_cannot_write_a_paper_licence` (the UPDATE succeeds),
//!   `the_app_role_cannot_repoint_a_licensed_paper_onto_another_doi` and
//!   `the_app_role_writes_only_the_allowlisted_paper_columns`.
//! * section 4 revoking UPDATE only (table-level INSERT kept): fails
//!   `the_app_role_cannot_write_a_paper_licence` (the INSERT naming
//!   `licence` succeeds) and the catalog ratchet.
//! * `licence` left in the re-granted column list: fails both, as above.
//! * UPDATE granted on every column but `licence` (the first form of 255,
//!   which a review refuted), with section 8 reduced to its `licence` arm:
//!   fails `the_app_role_cannot_repoint_a_licensed_paper_onto_another_doi`
//!   (the application's `UPDATE papers SET doi` succeeds) and the catalog
//!   ratchet (measured). With section 8 kept whole, 255 refuses at migrate
//!   time with `LIC09` naming `UPDATE (created_at), UPDATE (doi), UPDATE (id)`.
//! * EXECUTE on the definer granted to `epigraph_app`: fails
//!   `the_app_role_cannot_write_a_paper_licence`.
//! * section 6 (the reserved `paper.licence` prefix) removed: fails
//!   `the_app_role_cannot_forge_a_licence_audit_row`.
//! * the definer's audit INSERT removed: fails
//!   `the_operator_definer_sets_clears_and_audits_a_licence`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::PaperRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// 246's unique index on a paper's document key per scope, as an upsert's
/// conflict target (`PaperRepository::get_or_create` names the same).
const SCOPE_CONFLICT: &str = "(doi, (CASE WHEN visibility = 'public' \
     THEN '00000000-0000-0000-0000-000000000000'::uuid ELSE owner_group_id END))";

/// An `epigraph_app` pool stamped, for the whole session, as a seeded agent
/// that reads and writes its own group (the five GUCs `ScopedPool` stamps).
/// Returns the pool and that group.
async fn app_pool(pool: &PgPool) -> (PgPool, Uuid) {
    use sqlx::Executor;
    let (agent, group) = fixture::seed_agent_with_group(pool, "t67-app").await;
    let url = fixture::database_url_for(pool).await;
    let app = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_app")
                    .await?;
                sqlx::query(
                    "SELECT set_config('epigraph.group_ids', $1, false), \
                            set_config('epigraph.writable_group_ids', $1, false), \
                            set_config('epigraph.principal_id', $2, false), \
                            set_config('epigraph.elevation_id', '', false), \
                            set_config('epigraph.family_id', '', false)",
                )
                .bind(group.to_string())
                .bind(agent.to_string())
                .execute(&mut *conn)
                .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("stamped app pool");
    (app, group)
}

/// A pool whose connections are `SET SESSION AUTHORIZATION <role>` (a
/// test-local literal).
async fn role_pool(pool: &PgPool, role: &'static str) -> PgPool {
    use sqlx::Executor;
    let url = fixture::database_url_for(pool).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                conn.execute(format!("SET SESSION AUTHORIZATION {role}").as_str())
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("role pool")
}

fn sqlstate<T: std::fmt::Debug>(r: Result<T, sqlx::Error>) -> Option<String> {
    match r {
        Ok(v) => panic!("expected a database error, got Ok({v:?})"),
        Err(e) => e
            .as_database_error()
            .and_then(|d| d.code().map(|c| c.to_string())),
    }
}

async fn seed_paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, 'Seeded') RETURNING id")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("seed paper")
}

async fn licence_of(pool: &PgPool, doi: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT licence FROM papers WHERE doi = $1")
        .bind(doi)
        .fetch_optional(pool)
        .await
        .expect("licence read")
        .flatten()
}

async fn licence_events(pool: &PgPool) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE lower(btrim(event_type)) LIKE 'paper.licence%' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("audit read")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_write_a_paper_licence(pool: PgPool) {
    let existing = seed_paper(&pool, "10.9999/t67-existing").await;
    let (app, group) = app_pool(&pool).await;

    // An existing paper's licence.
    let r = sqlx::query("UPDATE papers SET licence = 'CC0-1.0' WHERE id = $1")
        .bind(existing)
        .execute(&app)
        .await;
    assert_eq!(sqlstate(r).as_deref(), Some("42501"), "UPDATE licence");

    // A not-yet-ingested DOI pre-registered as open.
    let r = sqlx::query(
        "INSERT INTO papers (doi, title, licence, visibility, owner_group_id) \
         VALUES ($1, 't', 'CC0-1.0', 'public', $2)",
    )
    .bind("10.9999/t67-preregistered")
    .bind(group)
    .execute(&app)
    .await;
    assert_eq!(
        sqlstate(r).as_deref(),
        Some("42501"),
        "INSERT naming licence"
    );

    // An upsert whose conflict arm sets it.
    let r = sqlx::query(&format!(
        "INSERT INTO papers (doi, title, visibility, owner_group_id) \
         VALUES ($1, 't', 'public', $2) \
         ON CONFLICT {SCOPE_CONFLICT} DO UPDATE SET licence = 'CC-BY-4.0'"
    ))
    .bind("10.9999/t67-existing")
    .bind(group)
    .execute(&app)
    .await;
    assert_eq!(
        sqlstate(r).as_deref(),
        Some("42501"),
        "ON CONFLICT DO UPDATE SET licence"
    );

    // The operator definer.
    let r = sqlx::query("SELECT epigraph_set_paper_licence($1, 'CC0-1.0', 'app attempt')")
        .bind(existing)
        .execute(&app)
        .await;
    assert_eq!(sqlstate(r).as_deref(), Some("42501"), "EXECUTE the definer");

    assert_eq!(licence_of(&pool, "10.9999/t67-existing").await, None);
    assert_eq!(licence_of(&pool, "10.9999/t67-preregistered").await, None);
    assert!(licence_events(&pool).await.is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_forge_a_licence_audit_row(pool: PgPool) {
    let app = role_pool(&pool, "epigraph_app").await;
    for event_type in ["paper.licence_set", " Paper.Licence_set", "PAPER.LICENCE"] {
        let r = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ($1, NULL, true, '{}'::jsonb)",
        )
        .bind(event_type)
        .execute(&app)
        .await;
        assert_eq!(sqlstate(r).as_deref(), Some("42501"), "{event_type:?}");
    }
    assert!(licence_events(&pool).await.is_empty());

    // CONTROL: the application still appends its own unattributed events
    // (077's anti-suppression arm), including a look-alike that is not the
    // reserved prefix.
    for event_type in ["paper_licence_probe", "paper.title_filled"] {
        sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ($1, NULL, true, '{}'::jsonb)",
        )
        .bind(event_type)
        .execute(&app)
        .await
        .unwrap_or_else(|e| panic!("{event_type}: {e}"));
    }
}

/// The application's own paper writes keep working on the application role:
/// `PaperRepository::get_or_create` (both arms; `POST /api/v1/papers` calls
/// it too since migration 246), and a fill-only UPDATE and a scope upsert in
/// the shape of get_or_create's own statements.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_still_registers_and_fills_papers(pool: PgPool) {
    let (app, group) = app_pool(&pool).await;
    let decl = epigraph_core::TenancyDecl::public(group);

    // get_or_create: a new paper (the INSERT arm) ...
    let new_id =
        PaperRepository::get_or_create(&app, "10.9999/t67-new", Some("New"), Some("J"), decl)
            .await
            .expect("get_or_create inserts on the application role");
    // ... and an existing row whose NULL title it fills (the UPDATE arm).
    let bare: Uuid = sqlx::query_scalar("INSERT INTO papers (doi) VALUES ($1) RETURNING id")
        .bind("10.9999/t67-bare")
        .fetch_one(&pool)
        .await
        .expect("seed bare paper");
    let hit = PaperRepository::get_or_create(&app, "10.9999/t67-bare", Some("Filled"), None, decl)
        .await
        .expect("get_or_create fills on the application role");
    assert_eq!(hit, bare);
    let title: Option<String> = sqlx::query_scalar("SELECT title FROM papers WHERE id = $1")
        .bind(bare)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(title.as_deref(), Some("Filled"));

    // A fill-only UPDATE and a scope upsert, the shapes get_or_create runs.
    sqlx::query(
        r#"UPDATE papers
                   SET title   = COALESCE(title, $2),
                       journal = COALESCE(journal, $3)
                   WHERE id = $1"#,
    )
    .bind(new_id)
    .bind(Some("ignored"))
    .bind(Some("ignored"))
    .execute(&app)
    .await
    .expect("a fill-only UPDATE on the application role");
    let row: (Uuid,) = sqlx::query_as(&format!(
        r#"INSERT INTO papers (doi, title, journal, visibility, owner_group_id)
               VALUES ($1, $2, $3, 'public', $4)
               ON CONFLICT {SCOPE_CONFLICT} DO UPDATE SET
                   title   = COALESCE(papers.title, EXCLUDED.title),
                   journal = COALESCE(papers.journal, EXCLUDED.journal)
               RETURNING id"#
    ))
    .bind("10.9999/t67-new")
    .bind(Some("Other"))
    .bind(None::<String>)
    .bind(group)
    .fetch_one(&app)
    .await
    .expect("a scope upsert on the application role");
    assert_eq!(row.0, new_id);

    // The read the ingest writers make still works, and reads NULL.
    assert_eq!(
        PaperRepository::licence(&app, new_id)
            .await
            .expect("licence read"),
        None
    );
}

/// The re-point route: with UPDATE on `doi`, an application session could
/// move a paper that carries an open licence onto a paywalled DOI, and the
/// next ingest of that DOI (`get_or_create` by DOI, then `licence` of the row
/// found) would keep its publisher text. Neither `doi` nor `id` may move.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_repoint_a_licensed_paper_onto_another_doi(pool: PgPool) {
    let open_doi = "10.9999/t67-open";
    let paywalled_doi = "10.9999/t67-paywalled";
    let open = seed_paper(&pool, open_doi).await;
    let maint = role_pool(&pool, "epigraph_maintenance").await;
    sqlx::query("SELECT epigraph_set_paper_licence($1, 'CC-BY-4.0', 'publisher page')")
        .bind(open)
        .execute(&maint)
        .await
        .expect("operator sets the open licence");
    let (app, group) = app_pool(&pool).await;

    // Move the open row onto a paywalled DOI not yet registered.
    let r = sqlx::query("UPDATE papers SET doi = $2 WHERE id = $1")
        .bind(open)
        .bind(paywalled_doi)
        .execute(&app)
        .await;
    assert_eq!(sqlstate(r).as_deref(), Some("42501"), "UPDATE doi");

    // The same through an upsert's conflict arm.
    let r = sqlx::query(&format!(
        "INSERT INTO papers (doi, title, visibility, owner_group_id) \
         VALUES ($1, 't', 'public', $3) \
         ON CONFLICT {SCOPE_CONFLICT} DO UPDATE SET doi = $2"
    ))
    .bind(open_doi)
    .bind(paywalled_doi)
    .bind(group)
    .execute(&app)
    .await;
    assert_eq!(
        sqlstate(r).as_deref(),
        Some("42501"),
        "ON CONFLICT DO UPDATE SET doi"
    );

    // Swap ids with a paywalled row already registered.
    let paywalled = seed_paper(&pool, paywalled_doi).await;
    let r = sqlx::query("UPDATE papers SET id = gen_random_uuid() WHERE id = $1")
        .bind(paywalled)
        .execute(&app)
        .await;
    assert_eq!(sqlstate(r).as_deref(), Some("42501"), "UPDATE id");

    // What ingest reads for the paywalled DOI: its own row, no licence.
    let found = PaperRepository::get_or_create(
        &app,
        paywalled_doi,
        None,
        None,
        epigraph_core::TenancyDecl::public(group),
    )
    .await
    .expect("get_or_create on the application role");
    assert_eq!(
        found, paywalled,
        "the paywalled DOI resolves to its own row"
    );
    assert_eq!(
        PaperRepository::licence(&app, found)
            .await
            .expect("licence read"),
        None,
        "the paywalled DOI must not read as open-licensed"
    );
    // And the open row is where the operator left it.
    let (doi, licence): (String, Option<String>) =
        sqlx::query_as("SELECT doi, licence FROM papers WHERE id = $1")
            .bind(open)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(doi, open_doi);
    assert_eq!(licence.as_deref(), Some("CC-BY-4.0"));
}

/// CATALOG RATCHET: the application role holds INSERT on every `papers`
/// column except `licence`, UPDATE on `title` and `journal` only (an
/// allowlist: `doi` and `id` are what ingest finds a paper and its licence
/// by), neither on `licence`, and nothing table-level. A migration that
/// adds a `papers` column the request path UPDATEs must grant it by name and
/// extend the allowlist here and in 255's section 8 deliberately; one that
/// re-grants table-level INSERT or UPDATE re-opens the licence and fails here.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_writes_only_the_allowlisted_paper_columns(pool: PgPool) {
    let rows: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT a.attname::text, \
                has_column_privilege('epigraph_app', 'public.papers'::regclass, a.attnum, 'INSERT'), \
                has_column_privilege('epigraph_app', 'public.papers'::regclass, a.attnum, 'UPDATE') \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.papers'::regclass AND a.attnum > 0 AND NOT a.attisdropped \
          ORDER BY a.attnum",
    )
    .fetch_all(&pool)
    .await
    .expect("privilege read");
    assert!(
        rows.iter().any(|(c, _, _)| c == "licence"),
        "papers.licence is missing: {rows:?}"
    );
    const UPDATABLE: [&str; 2] = ["title", "journal"];
    for (col, ins, upd) in &rows {
        if col == "licence" {
            assert!(
                !ins && !upd,
                "epigraph_app can write papers.licence (INSERT {ins}, UPDATE {upd}); only \
                 epigraph_set_paper_licence on the maintenance DSN may"
            );
            continue;
        }
        assert!(
            *ins,
            "epigraph_app lacks INSERT on papers.{col}; grant it column-level (never \
             table-level, which re-opens papers.licence)"
        );
        assert_eq!(
            *upd,
            UPDATABLE.contains(&col.as_str()),
            "epigraph_app UPDATE on papers.{col} is {upd}; only {UPDATABLE:?} may be updated \
             (UPDATE of doi or id re-points a licensed row onto another DOI)"
        );
    }
    for col in ["id", "doi"] {
        assert!(
            rows.iter().any(|(c, _, _)| c == col),
            "papers.{col} is missing: {rows:?}"
        );
    }
    let table_level: (bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege('epigraph_app', 'public.papers', 'INSERT'), \
                has_table_privilege('epigraph_app', 'public.papers', 'UPDATE')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        table_level,
        (false, false),
        "table-level INSERT/UPDATE on papers"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_definer_sets_clears_and_audits_a_licence(pool: PgPool) {
    let doi = "10.9999/t67-operator";
    let paper = seed_paper(&pool, doi).await;
    let maint = role_pool(&pool, "epigraph_maintenance").await;

    let prev: Option<String> =
        sqlx::query_scalar("SELECT epigraph_set_paper_licence($1, 'CC-BY-4.0', 'publisher page')")
            .bind(paper)
            .fetch_one(&maint)
            .await
            .expect("operator sets a licence");
    assert_eq!(prev, None);
    assert_eq!(licence_of(&pool, doi).await.as_deref(), Some("CC-BY-4.0"));

    let prev: Option<String> =
        sqlx::query_scalar("SELECT epigraph_set_paper_licence($1, NULL, 'withdrawn')")
            .bind(paper)
            .fetch_one(&maint)
            .await
            .expect("operator clears a licence");
    assert_eq!(prev.as_deref(), Some("CC-BY-4.0"));
    assert_eq!(licence_of(&pool, doi).await, None);

    let events = licence_events(&pool).await;
    assert_eq!(events.len(), 2, "one audit row per set: {events:#?}");
    let paper_s = paper.to_string();
    assert_eq!(events[0]["paper_id"], paper_s.as_str());
    assert_eq!(events[0]["doi"], doi);
    assert_eq!(events[0]["previous"], serde_json::Value::Null);
    assert_eq!(events[0]["licence"], "CC-BY-4.0");
    assert_eq!(events[0]["reason"], "publisher page");
    assert_eq!(events[0]["session_user"], "epigraph_maintenance");
    assert_eq!(events[1]["previous"], "CC-BY-4.0");
    assert_eq!(events[1]["licence"], serde_json::Value::Null);
    assert_eq!(events[1]["reason"], "withdrawn");

    // Refusals change nothing and write no audit row.
    for (args, want) in [
        ("$1, 'CC0-1.0', '  '", "22023"),               // blank reason
        ("$1, 'CC0-1.0', NULL", "22023"),               // no reason
        ("gen_random_uuid(), 'CC0-1.0', 'x'", "22023"), // unknown paper
        ("$1, ' CC0-1.0', 'padded'", "23514"),          // 226's CHECK
    ] {
        let sql = format!("SELECT epigraph_set_paper_licence({args})");
        let mut q = sqlx::query(&sql);
        if args.starts_with("$1") {
            q = q.bind(paper);
        }
        let r = q.execute(&maint).await;
        assert_eq!(sqlstate(r).as_deref(), Some(want), "{args}");
    }
    assert_eq!(licence_of(&pool, doi).await, None);
    assert_eq!(licence_events(&pool).await.len(), 2);
}
