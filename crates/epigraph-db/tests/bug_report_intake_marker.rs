//! Migration 265: the bug-report intake's write-time marker
//! (`bug_report_intake_marks`, backlog e690866c), across an UPGRADE.
//!
//! `bug_report_intake.rs` pins the behaviour at head (a moved report and one
//! filed under a replaced intake group stay in the reporter's list). This file
//! pins what only a database that ran 207-211 BEFORE 265 can show:
//!
//! * `the_265_backfill_keeps_every_earlier_report_listed`: reports filed on
//!   the pre-265 body (no marker written) get one marker each from their
//!   `bug_report.submitted` audit row, so every report its reporter listed
//!   before the upgrade it still lists after it, a report triage had already
//!   moved out of the intake group included (which 207's list had lost). A
//!   claim the reporter authored by another path gets no marker, even when
//!   an audit row names it, and neither does an audit row whose claim is gone
//!   or is no longer the reporter's. The filed labels are rebuilt from the
//!   audit row exactly as the write composed them.
//! * `the_265_marker_backfill_runbook_marks_a_report_filed_without_one`:
//!   `docs/runbooks/265-marker-backfill.sql` (265's backfill, for a report a
//!   call that started during the migration filed on the old body) marks it,
//!   and a second run changes nothing.
//! * `the_265_undo_returns_the_catalog_below_265`: `docs/runbooks/265-undo.sql`
//!   leaves the `public` catalog exactly as it was below 265 (function bodies
//!   compared by `pg_get_functiondef` md5, so 211's write and 207's list are
//!   restored byte for byte), and a second run changes nothing.
//!
//! Verified to fail: with 265's backfill INSERT removed, the first test's
//! post-upgrade list is empty; with the backfill's `properties ? 'bug_report'`
//! condition dropped, the first test sees a marker for the claim authored by
//! another path; with the undo's re-statement of 207's list dropped, the
//! undo test names `epigraph_my_bug_reports` in the diff. The runbook test's
//! calibration shows the report out of the list before the run, and a
//! runbook that drifts from 265's backfill fails its verbatim check.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{
    BugReportInput, BugReportReceipt, BugReportRepository, ScopedPool, SessionGucMode,
};
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

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

async fn team_group(pool: &PgPool, admin: Uuid, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, $2, 'did:test:team:' || $1::text, $3, 'team', $4)",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .bind(admin)
    .execute(pool)
    .await
    .expect("team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(id)
    .bind(admin)
    .execute(pool)
    .await
    .expect("membership");
    id
}

async fn linked_agent(pool: &PgPool, human: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("live link");
    agent
}

async fn app(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

fn report(title: &str) -> BugReportInput {
    BugReportInput {
        title: title.to_string(),
        description: format!("{title}: what happened"),
        severity: None,
        component: None,
        repro: None,
        evidence: None,
        embedding: None,
    }
}

async fn submit_as(pool: &PgPool, agent: Uuid, title: &str) -> BugReportReceipt {
    submit_input(pool, agent, &report(title)).await
}

async fn submit_input(pool: &PgPool, agent: Uuid, input: &BugReportInput) -> BugReportReceipt {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let scoped = app(pool).await;
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped");
    let r = BugReportRepository::submit_conn(&mut tx, input)
        .await
        .expect("filed");
    tx.commit().await.expect("commit");
    r
}

async fn labels_of(pool: &PgPool, claim: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("labels")
}

async fn list_as(pool: &PgPool, agent: Uuid) -> Vec<Uuid> {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let scoped = app(pool).await;
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped");
    let rows = BugReportRepository::list_mine_conn(&mut tx, 50)
        .await
        .expect("list");
    tx.rollback().await.expect("rollback");
    rows.into_iter().map(|r| r.claim_id).collect()
}

#[sqlx::test(migrations = false)]
async fn the_265_backfill_keeps_every_earlier_report_listed(pool: PgPool) {
    migrate(&pool, &up_to(264)).await;
    let marks_exist: bool =
        sqlx::query_scalar("SELECT to_regclass('public.bug_report_intake_marks') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .expect("catalog");
    assert!(!marks_exist, "CALIBRATION: the database is below 265");

    let (ops, _) = fixture::seed_human_operator(&pool, "brm-ops").await;
    let intake = team_group(&pool, ops, "brm-intake").await;
    let triaged = team_group(&pool, ops, "brm-triaged").await;
    let (human, home) = fixture::seed_human_operator(&pool, "brm-human").await;
    let reporter = linked_agent(&pool, human, "brm-reporter").await;
    let (other_human, _) = fixture::seed_human_operator(&pool, "brm-other-human").await;
    let other = linked_agent(&pool, other_human, "brm-other").await;
    sqlx::query("INSERT INTO bug_report_intake_settings (intake_group_id) VALUES ($1)")
        .bind(intake)
        .execute(&pool)
        .await
        .expect("configure");
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(&pool)
        .await
        .expect("arm");

    let first = submit_as(&pool, reporter, "first").await;
    let mut graded = report("second");
    graded.severity = Some("minor".into());
    graded.component = Some("theme-scripts".into());
    let second = submit_input(&pool, reporter, &graded).await;
    let second_filed = labels_of(&pool, second.claim_id).await;
    let theirs = submit_as(&pool, other, "theirs").await;
    let own = fixture::seed_group_claim(&pool, reporter, home, "not a report").await;
    // An audit row naming a claim the reporter authored by another path (only
    // a privileged session can write one since 207; the backfill must still
    // not take it for a report).
    sqlx::query(
        "INSERT INTO security_events (event_type, agent_id, success, details) \
         VALUES ('bug_report.submitted', $1, true, \
                 jsonb_build_object('claim_id', $2::uuid, 'intake_group_id', $3::uuid))",
    )
    .bind(reporter)
    .bind(own)
    .bind(intake)
    .execute(&pool)
    .await
    .expect("an audit row naming a non-report");
    // Triage moves the first report before the upgrade: 207's list loses it.
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(first.claim_id)
        .bind(triaged)
        .execute(&pool)
        .await
        .expect("triage moves a report");
    assert_eq!(
        list_as(&pool, reporter).await,
        vec![second.claim_id],
        "CALIBRATION: before 265 the moved report is out of the list"
    );

    migrate(&pool, &MIGRATOR).await;

    let marks: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(
        "SELECT claim_id, reporter_id, intake_group_id FROM bug_report_intake_marks \
          ORDER BY submitted_at",
    )
    .fetch_all(&pool)
    .await
    .expect("markers");
    assert_eq!(
        marks,
        vec![
            (first.claim_id, reporter, intake),
            (second.claim_id, reporter, intake),
            (theirs.claim_id, other, intake),
        ],
        "one marker per filed report, from its audit row (the claim authored by another path, \
         {own}, has none although an audit row names it)"
    );
    let filed: Vec<(Uuid, Option<String>, Vec<String>)> = sqlx::query_as(
        "SELECT claim_id, title, filed_labels FROM bug_report_intake_marks ORDER BY submitted_at",
    )
    .fetch_all(&pool)
    .await
    .expect("filed columns");
    let plain: Vec<String> = ["backlog", "bug-report", "intake"]
        .iter()
        .map(|l| (*l).to_string())
        .collect();
    assert_eq!(
        filed,
        vec![
            (first.claim_id, Some("first".into()), plain.clone()),
            (second.claim_id, Some("second".into()), second_filed.clone()),
            (theirs.claim_id, Some("theirs".into()), plain),
        ],
        "title and labels as filed, severity and component rebuilt from the audit row"
    );
    assert_eq!(
        second_filed.len(),
        5,
        "CALIBRATION: the graded report carries severity and component: {second_filed:?}"
    );
    assert_eq!(
        list_as(&pool, reporter).await,
        vec![second.claim_id, first.claim_id],
        "after 265 both reports are listed, the moved one included"
    );
    assert_eq!(list_as(&pool, other).await, vec![theirs.claim_id]);

    // A report filed after the upgrade is marked by the write itself.
    let third = submit_as(&pool, reporter, "third").await;
    assert_eq!(
        list_as(&pool, reporter).await,
        vec![third.claim_id, second.claim_id, first.claim_id]
    );
}

/// The `public` catalog by name: relations, functions (whole definition by
/// md5, owner and ACL), policies, triggers, constraints and indexes.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text || ' ' \
                || COALESCE(c.relacl::text, '-') \
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

#[sqlx::test(migrations = false)]
async fn the_265_undo_returns_the_catalog_below_265(pool: PgPool) {
    migrate(&pool, &up_to(264)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(265)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    for name in [
        "rel bug_report_intake_marks r",
        "fn epigraph_submit_bug_report(",
        "fn epigraph_my_bug_reports(",
    ] {
        assert!(
            added.iter().any(|e| e.starts_with(name)),
            "CALIBRATION: 265 adds or re-states {name}: {added:?}"
        );
    }
    assert_eq!(
        removed.len(),
        2,
        "CALIBRATION: the only entries 265 changes are the two function bodies: {removed:?}"
    );

    let undo = repo_file("docs/runbooks/265-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 265"
        );
    }
}

/// A report filed on the OLD body after 265's backfill (a write definer call
/// that started while 265 held its lock resumes on 211's body once 265
/// commits) has no marker; `docs/runbooks/265-marker-backfill.sql` gives it
/// the one the backfill would have, and a second run changes nothing. The
/// runbook is 265's own backfill statement, verbatim.
#[sqlx::test(migrations = false)]
async fn the_265_marker_backfill_runbook_marks_a_report_filed_without_one(pool: PgPool) {
    let runbook = repo_file("docs/runbooks/265-marker-backfill.sql");
    let migration = repo_file("migrations/265_bug_report_intake_marker.sql");
    let start = runbook.find("DO $$").expect("the runbook's DO block");
    let end = runbook[start..].find("END $$;").expect("its end") + start + "END $$;".len();
    assert!(
        migration.contains(&runbook[start..end]),
        "the runbook's backfill is 265's, verbatim"
    );

    migrate(&pool, &MIGRATOR).await;
    let (ops, _) = fixture::seed_human_operator(&pool, "brb-ops").await;
    let intake = team_group(&pool, ops, "brb-intake").await;
    let triaged = team_group(&pool, ops, "brb-triaged").await;
    let (human, _) = fixture::seed_human_operator(&pool, "brb-human").await;
    let reporter = linked_agent(&pool, human, "brb-reporter").await;
    sqlx::query("INSERT INTO bug_report_intake_settings (intake_group_id) VALUES ($1)")
        .bind(intake)
        .execute(&pool)
        .await
        .expect("configure");
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(&pool)
        .await
        .expect("arm");

    let raced = submit_as(&pool, reporter, "raced").await;
    let kept = submit_as(&pool, reporter, "kept").await;
    let written: (Uuid, Uuid, Option<String>, Vec<String>) = sqlx::query_as(
        "SELECT reporter_id, intake_group_id, title, filed_labels \
           FROM bug_report_intake_marks WHERE claim_id = $1",
    )
    .bind(raced.claim_id)
    .fetch_one(&pool)
    .await
    .expect("the write's marker");
    // What the old body leaves: the report and its audit row, no marker.
    sqlx::query("DELETE FROM bug_report_intake_marks WHERE claim_id = $1")
        .bind(raced.claim_id)
        .execute(&pool)
        .await
        .expect("as if filed on the old body");
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(raced.claim_id)
        .bind(triaged)
        .execute(&pool)
        .await
        .expect("triage moves it");
    assert_eq!(
        list_as(&pool, reporter).await,
        vec![kept.claim_id],
        "CALIBRATION: a moved report with no marker is out of the list"
    );

    for run in ["first", "second"] {
        sqlx::raw_sql(&runbook)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the runbook applies: {e}"));
        assert_eq!(
            list_as(&pool, reporter).await,
            vec![kept.claim_id, raced.claim_id],
            "after the {run} run the moved report is listed again"
        );
        let rebuilt: (Uuid, Uuid, Option<String>, Vec<String>) = sqlx::query_as(
            "SELECT reporter_id, intake_group_id, title, filed_labels \
               FROM bug_report_intake_marks WHERE claim_id = $1",
        )
        .bind(raced.claim_id)
        .fetch_one(&pool)
        .await
        .expect("the rebuilt marker");
        assert_eq!(rebuilt, written, "the marker the write would have written");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM bug_report_intake_marks")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(n, 2, "after the {run} run: one marker per report, no more");
    }
}
