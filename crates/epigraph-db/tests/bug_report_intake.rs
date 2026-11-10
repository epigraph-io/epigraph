//! Migration 207: the write-only bug-report intake, on the APPLICATION ROLE.
//!
//! Every call runs on an `epigraph_app` transaction stamped from the caller's
//! viewer exactly as the request path stamps it (`ScopedPool::begin_as`), on a
//! database ARMED for operator binding (122). On an unarmed database the
//! claims trigger checks no writer scope, so a definer that inserted straight
//! into the intake group would pass there and fail in production; every
//! fixture here arms first.
//!
//! Pinned:
//! * a reporter that is not a member of the intake group files a report; the
//!   row lands in the intake group, group-private, authored by the reporter,
//!   with exactly the intake labels (never `bug`), its trace and evidence
//!   owned the same way, and one `bug_report.submitted` audit row;
//! * the reporter cannot read any of it back (row security, the viewer
//!   predicate of the nearest-neighbour read the novelty gate uses);
//! * the reporter's list holds only its own intake reports, not a claim it
//!   authored in the intake group by another path;
//! * the per-hour and per-day limits;
//! * an unconfigured intake (or one whose group is suspended) refuses;
//! * session temporary objects named like the definer's relations change
//!   nothing;
//! * a system agent, an unbound agent and a session with no principal are
//!   refused;
//! * the application role cannot write a `bug_report.` audit row itself;
//! * empty, whitespace-only and oversized input is refused with nothing
//!   written.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::{
    BugReportInput, BugReportReceipt, BugReportRepository, ClaimRepository, DbError, RefusalKind,
    ScopedPool, SessionGucMode,
};
use sqlx::PgPool;
use uuid::Uuid;

// ─── fixtures ───────────────────────────────────────────────────────────

async fn arm(pool: &PgPool) {
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
}

/// A team group (not a personal one), with `admin` as its live admin.
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
    add_member(pool, id, admin, "admin").await;
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("membership");
}

async fn configure(pool: &PgPool, group: Uuid, per_hour: i32, per_day: i32) {
    sqlx::query(
        "INSERT INTO bug_report_intake_settings (intake_group_id, per_hour, per_day) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (singleton) DO UPDATE SET intake_group_id = EXCLUDED.intake_group_id, \
             per_hour = EXCLUDED.per_hour, per_day = EXCLUDED.per_day",
    )
    .bind(group)
    .bind(per_hour)
    .bind(per_day)
    .execute(pool)
    .await
    .expect("configure the intake");
}

/// An agent with its own personal group, linked live to `human`.
async fn linked_agent(pool: &PgPool, human: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("live link");
    agent
}

struct World {
    /// The human who runs the intake group (its admin).
    ops: Uuid,
    intake: Uuid,
    /// The reporter's human and its personal group (the reporter's home).
    human: Uuid,
    home: Uuid,
    /// An agent linked to `human`; NOT a member of `intake`.
    reporter: Uuid,
}

/// The intake group, a reporter that is not a member of it, NOT configured
/// and NOT armed yet.
async fn bare_world(pool: &PgPool) -> World {
    let (ops, _) = fixture::seed_human_operator(pool, "bri-ops").await;
    let intake = team_group(pool, ops, "bri-intake").await;
    let (human, home) = fixture::seed_human_operator(pool, "bri-human").await;
    let reporter = linked_agent(pool, human, "bri-reporter").await;
    World {
        ops,
        intake,
        human,
        home,
        reporter,
    }
}

/// [`bare_world`], configured at the default limits, then armed.
async fn world(pool: &PgPool) -> World {
    let w = bare_world(pool).await;
    configure(pool, w.intake, 20, 200).await;
    arm(pool).await;
    w
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
        description: format!("{title}: what happened, and what should have"),
        severity: Some("major".into()),
        component: Some("mcp".into()),
        repro: Some("1. call the tool\n2. observe".into()),
        evidence: Some("log line".into()),
        embedding: None,
    }
}

/// File `input` as `agent` on a stamped application transaction; commit on
/// success, roll back on refusal.
async fn submit_as(
    pool: &PgPool,
    agent: Uuid,
    input: &BugReportInput,
) -> Result<BugReportReceipt, DbError> {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let scoped = app(pool).await;
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped transaction");
    match BugReportRepository::submit_conn(&mut tx, input).await {
        Ok(r) => {
            tx.commit().await.expect("commit");
            Ok(r)
        }
        Err(e) => {
            tx.rollback().await.expect("rollback");
            Err(e)
        }
    }
}

async fn list_as(pool: &PgPool, agent: Uuid) -> Result<Vec<epigraph_db::BugReportRow>, DbError> {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let scoped = app(pool).await;
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped transaction");
    let out = BugReportRepository::list_mine_conn(&mut tx, 50).await;
    tx.rollback().await.expect("rollback");
    out
}

/// The refusal's code and message, or a panic naming what came back.
fn refused<T: std::fmt::Debug>(r: Result<T, DbError>) -> (RefusalKind, String) {
    match r {
        Err(DbError::Refused { kind, message }) => (kind, message),
        other => panic!("expected a coded refusal, got {other:?}"),
    }
}

async fn claims_by(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE agent_id = $1")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("count claims")
}

async fn markers_of(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE agent_id = $1 AND event_type = 'bug_report.submitted'",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("count markers")
}

async fn is_member(pool: &PgPool, group: Uuid, agent: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM public.epigraph_live_memberships($2) m \
                         WHERE m.group_id = $1)",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("membership read")
}

fn unit_vector(at: usize) -> String {
    let v: Vec<&str> = (0..1536).map(|i| if i == at { "1" } else { "0" }).collect();
    format!("[{}]", v.join(","))
}

// ─── the write ──────────────────────────────────────────────────────────

/// `(agent_id, owner_group_id, visibility, labels, content, content_hash,
/// trace_id, is_current)` of one claim.
type ClaimRow = (
    Uuid,
    Uuid,
    String,
    Vec<String>,
    String,
    Vec<u8>,
    Option<Uuid>,
    bool,
);

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_files_into_the_intake_group_privately_as_itself(pool: PgPool) {
    let w = world(&pool).await;
    assert!(
        !is_member(&pool, w.intake, w.reporter).await && !is_member(&pool, w.intake, w.human).await,
        "CALIBRATION: neither the reporter nor its human is a member of the intake group"
    );

    let input = report("tool X drops labels");
    let r = submit_as(&pool, w.reporter, &input)
        .await
        .expect("a bound non-member files a report");

    let (agent, owner, vis, labels, content, hash, trace, current): ClaimRow = sqlx::query_as(
        "SELECT agent_id, owner_group_id, visibility::text, labels, content, content_hash, \
                trace_id, is_current FROM claims WHERE id = $1",
    )
    .bind(r.claim_id)
    .fetch_one(&pool)
    .await
    .expect("the report's claim");
    assert_eq!(agent, w.reporter, "authored by the caller");
    assert_eq!(owner, w.intake, "owned by the intake group");
    assert_eq!(vis, "group", "group-private");
    assert!(current);
    assert_eq!(
        labels,
        vec![
            "backlog",
            "bug-report",
            "intake",
            "severity:major",
            "component:mcp"
        ],
        "exactly the intake labels; never `bug`"
    );
    assert_eq!(content, input.content());
    assert_eq!(
        hash,
        epigraph_crypto::ContentHasher::hash(content.as_bytes()).to_vec()
    );

    let trace = trace.expect("the claim names its trace");
    let (t_claim, t_owner, t_vis): (Uuid, Uuid, String) = sqlx::query_as(
        "SELECT claim_id, owner_group_id, visibility::text FROM reasoning_traces WHERE id = $1",
    )
    .bind(trace)
    .fetch_one(&pool)
    .await
    .expect("the trace");
    assert_eq!(
        (t_claim, t_owner, t_vis.as_str()),
        (r.claim_id, w.intake, "group")
    );
    let ev: Vec<(Uuid, String, String, Option<String>)> = sqlx::query_as(
        "SELECT owner_group_id, visibility::text, evidence_type::text, raw_content \
           FROM evidence WHERE claim_id = $1",
    )
    .bind(r.claim_id)
    .fetch_all(&pool)
    .await
    .expect("the evidence");
    assert_eq!(
        ev,
        vec![(
            w.intake,
            "group".to_string(),
            "testimony".to_string(),
            Some("log line".to_string())
        )]
    );

    let marker: (Uuid, String, String) = sqlx::query_as(
        "SELECT agent_id, details->>'claim_id', details->>'intake_group_id' \
           FROM security_events WHERE event_type = 'bug_report.submitted'",
    )
    .fetch_one(&pool)
    .await
    .expect("exactly one marker");
    assert_eq!(
        marker,
        (w.reporter, r.claim_id.to_string(), w.intake.to_string())
    );
    assert_eq!(
        claims_by(&pool, w.reporter).await,
        1,
        "nothing staged is left behind in the home group"
    );
}

/// The same report twice is two rows: no dedup, and the receipt has the same
/// shape either way.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repeated_report_is_a_new_row(pool: PgPool) {
    let w = world(&pool).await;
    let a = submit_as(&pool, w.reporter, &report("same words"))
        .await
        .expect("first");
    let b = submit_as(&pool, w.reporter, &report("same words"))
        .await
        .expect("second");
    assert_ne!(a.claim_id, b.claim_id);
    assert_eq!(claims_by(&pool, w.reporter).await, 2);
}

// ─── the read side ──────────────────────────────────────────────────────

/// The reporter reads nothing of its report: not the claim, its trace or its
/// evidence under row security, not the claim through the repository's
/// viewer-filtered read, and not through the nearest-neighbour read the
/// novelty gate runs. A member of the intake group reads all of it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_reporter_cannot_read_its_report_back(pool: PgPool) {
    let w = world(&pool).await;
    let mut input = report("private to ops");
    input.embedding = Some(unit_vector(7));
    let r = submit_as(&pool, w.reporter, &input).await.expect("filed");

    let stored: bool = sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(r.claim_id)
        .fetch_one(&pool)
        .await
        .expect("embedding");
    assert!(stored, "the embedding is stored for operations search");

    for (who, expect) in [(w.reporter, 0_i64), (w.ops, 1_i64)] {
        let viewer = Viewer::resolve(&pool, who).await.expect("resolve");
        let scoped = app(&pool).await;
        let mut tx = scoped.begin_as(&viewer).await.expect("stamped");
        for table in [
            "claims WHERE id",
            "evidence WHERE claim_id",
            "reasoning_traces WHERE claim_id",
        ] {
            let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table} = $1"))
                .bind(r.claim_id)
                .fetch_one(&mut *tx)
                .await
                .expect("row-security read");
            assert_eq!(n, expect, "{who} reading {table}");
        }
        let got = ClaimRepository::get_by_id(&mut *tx, &viewer, ClaimId::from_uuid(r.claim_id))
            .await
            .expect("get_by_id");
        assert_eq!(got.is_some(), expect == 1, "{who}: get_by_id");
        tx.rollback().await.expect("rollback");

        let near = ClaimRepository::nearest_by_embedding(&pool, &viewer, &unit_vector(7), 50)
            .await
            .expect("nearest");
        assert_eq!(
            near.iter().any(|h| h.claim_id == r.claim_id),
            expect == 1,
            "{who}: the nearest-neighbour read"
        );
    }
}

/// Only the caller's intake rows: not another reporter's, not a claim the
/// caller authored in its home group, and not a claim a MEMBER of the intake
/// group wrote straight into it. Labels are read live (triage status).
#[sqlx::test(migrations = "../../migrations")]
async fn the_list_holds_only_the_callers_intake_reports(pool: PgPool) {
    let w = world(&pool).await;
    let (other_human, _) = fixture::seed_human_operator(&pool, "bri-other-human").await;
    let other = linked_agent(&pool, other_human, "bri-other").await;

    let a = submit_as(&pool, w.reporter, &report("first"))
        .await
        .expect("a");
    let b = submit_as(&pool, w.reporter, &report("second"))
        .await
        .expect("b");
    let c = submit_as(&pool, other, &report("theirs")).await.expect("c");
    fixture::seed_group_claim(&pool, w.reporter, w.home, "the reporter's own claim").await;

    // The ops human: a member of the intake group, with one claim written
    // into it directly and one report filed through the intake.
    let direct = fixture::seed_group_claim(&pool, w.ops, w.intake, "written directly").await;
    let o = submit_as(&pool, w.ops, &report("ops files one too"))
        .await
        .expect("a member may file too");

    sqlx::query("UPDATE claims SET labels = labels || ARRAY['bug'] WHERE id = $1")
        .bind(a.claim_id)
        .execute(&pool)
        .await
        .expect("triage promotes a");
    sqlx::query("UPDATE claims SET labels = labels || ARRAY['resolved'] WHERE id = $1")
        .bind(b.claim_id)
        .execute(&pool)
        .await
        .expect("triage resolves b");

    let mine = list_as(&pool, w.reporter).await.expect("list");
    let ids: Vec<Uuid> = mine.iter().map(|r| r.claim_id).collect();
    assert_eq!(ids, vec![b.claim_id, a.claim_id], "newest first, only mine");
    assert_eq!(mine[0].title.as_deref(), Some("second"));
    assert!(mine[0].resolved && mine[0].is_current);
    assert!(mine[1].labels.contains(&"bug".to_string()) && !mine[1].resolved);

    let theirs: Vec<Uuid> = list_as(&pool, other)
        .await
        .expect("list")
        .iter()
        .map(|r| r.claim_id)
        .collect();
    assert_eq!(theirs, vec![c.claim_id]);

    let ops: Vec<Uuid> = list_as(&pool, w.ops)
        .await
        .expect("list")
        .iter()
        .map(|r| r.claim_id)
        .collect();
    assert_eq!(
        ops,
        vec![o.claim_id],
        "a claim the member wrote into the group directly ({direct}) is not an intake report"
    );
}

/// The application role cannot write the intake's marker, in any spelling,
/// while it can still write its own ordinary audit rows.
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_role_cannot_forge_a_marker(pool: PgPool) {
    let w = world(&pool).await;
    let viewer = Viewer::resolve(&pool, w.reporter).await.expect("resolve");
    let scoped = app(&pool).await;
    for (event_type, admitted) in [
        ("bug_report.submitted", false),
        ("BUG_REPORT.submitted", false),
        ("  bug_report.intake_configured", false),
        ("bri.calibration", true),
    ] {
        let mut tx = scoped.begin_as(&viewer).await.expect("stamped");
        let r = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ($1, $2, true, jsonb_build_object('claim_id', $3::uuid))",
        )
        .bind(event_type)
        .bind(w.reporter)
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await;
        assert_eq!(r.is_ok(), admitted, "{event_type:?}: {r:?}");
        tx.rollback().await.expect("rollback");
    }
}

// ─── limits, configuration, callers ─────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn the_rate_limits_hold(pool: PgPool) {
    let w = world(&pool).await;
    configure(&pool, w.intake, 2, 200).await;
    for i in 0..2 {
        submit_as(&pool, w.reporter, &report(&format!("hour {i}")))
            .await
            .expect("under the hourly limit");
    }
    let (kind, msg) = refused(submit_as(&pool, w.reporter, &report("one too many")).await);
    assert_eq!(kind, RefusalKind::State);
    assert!(msg.starts_with("BUG08:"), "{msg}");
    assert_eq!(claims_by(&pool, w.reporter).await, 2, "nothing written");
    assert_eq!(markers_of(&pool, w.reporter).await, 2);

    // The day: an hourly limit that no longer binds, a daily one that does.
    configure(&pool, w.intake, 100, 3).await;
    submit_as(&pool, w.reporter, &report("third today"))
        .await
        .expect("under the daily limit");
    let (_, msg) = refused(submit_as(&pool, w.reporter, &report("fourth today")).await);
    assert!(msg.starts_with("BUG08:"), "{msg}");
    assert_eq!(claims_by(&pool, w.reporter).await, 3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unconfigured_intake_refuses(pool: PgPool) {
    let w = bare_world(&pool).await;
    arm(&pool).await;
    let (kind, msg) = refused(submit_as(&pool, w.reporter, &report("nowhere to go")).await);
    assert_eq!(kind, RefusalKind::State);
    assert!(
        msg.starts_with("BUG03:") && msg.contains("bug intake is not configured"),
        "{msg}"
    );
    let (_, msg) = refused(list_as(&pool, w.reporter).await);
    assert!(msg.starts_with("BUG03:"), "{msg}");

    // Configured, but the group is suspended: the same refusal.
    configure(&pool, w.intake, 20, 200).await;
    sqlx::query("UPDATE groups SET status = 'suspended' WHERE id = $1")
        .bind(w.intake)
        .execute(&pool)
        .await
        .expect("suspend");
    let (_, msg) = refused(submit_as(&pool, w.reporter, &report("suspended")).await);
    assert!(msg.starts_with("BUG03:"), "{msg}");
    assert_eq!(claims_by(&pool, w.reporter).await, 0);
    assert_eq!(markers_of(&pool, w.reporter).await, 0);
}

/// A session's temporary relations named like every relation the definer
/// touches, holding a configuration that points at the reporter's own group
/// and carrying triggers that log who ran them, change nothing: the report
/// lands in the configured intake group, no temporary relation gains a row,
/// and no logging trigger runs.
#[sqlx::test(migrations = "../../migrations")]
async fn session_temporary_relations_do_not_reach_the_definer(pool: PgPool) {
    let w = world(&pool).await;
    let viewer = Viewer::resolve(&pool, w.reporter).await.expect("resolve");
    let scoped = app(&pool).await;
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped");
    let shadowed = [
        "claims",
        "evidence",
        "reasoning_traces",
        "security_events",
        "groups",
        "group_memberships",
        "system_agents",
        "operator_links",
        "bug_report_intake_settings",
    ];
    sqlx::query("CREATE TEMP TABLE shadow_log (who text, tbl text)")
        .execute(&mut *tx)
        .await
        .expect("log table");
    sqlx::query(
        "CREATE FUNCTION pg_temp.shadow_log() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN INSERT INTO pg_temp.shadow_log VALUES (current_user, TG_TABLE_NAME); \
         RETURN NEW; END $$",
    )
    .execute(&mut *tx)
    .await
    .expect("log function");
    sqlx::query("GRANT ALL ON pg_temp.shadow_log TO epigraph_maintenance")
        .execute(&mut *tx)
        .await
        .expect("grant log");
    for t in shadowed {
        sqlx::query(&format!(
            "CREATE TEMP TABLE {t} (LIKE public.{t} INCLUDING DEFAULTS)"
        ))
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("shadow {t}: {e}"));
        sqlx::query(&format!("GRANT ALL ON pg_temp.{t} TO epigraph_maintenance"))
            .execute(&mut *tx)
            .await
            .expect("grant");
        sqlx::query(&format!(
            "CREATE TRIGGER shadow BEFORE INSERT OR UPDATE ON pg_temp.{t} \
             FOR EACH ROW EXECUTE FUNCTION pg_temp.shadow_log()"
        ))
        .execute(&mut *tx)
        .await
        .expect("trigger");
    }
    sqlx::query(
        "INSERT INTO pg_temp.bug_report_intake_settings (intake_group_id, per_hour, per_day) \
         VALUES ($1, 10000, 100000)",
    )
    .bind(w.home)
    .execute(&mut *tx)
    .await
    .expect("a shadow configuration");
    sqlx::query("TRUNCATE pg_temp.shadow_log")
        .execute(&mut *tx)
        .await
        .expect("reset the log");

    let r = BugReportRepository::submit_conn(&mut tx, &report("shadowed"))
        .await
        .expect("the report is filed");
    let logged: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_temp.shadow_log")
        .fetch_one(&mut *tx)
        .await
        .expect("log");
    assert_eq!(logged, 0, "no shadow trigger ran");
    for t in shadowed {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM pg_temp.{t}"))
            .fetch_one(&mut *tx)
            .await
            .expect("shadow count");
        let expect = i64::from(t == "bug_report_intake_settings");
        assert_eq!(n, expect, "pg_temp.{t} was not written");
    }
    tx.commit().await.expect("commit");

    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(r.claim_id)
        .fetch_one(&pool)
        .await
        .expect("the report");
    assert_eq!(owner, w.intake, "the real configuration decided the owner");
}

#[sqlx::test(migrations = "../../migrations")]
async fn system_unbound_and_principal_less_callers_are_refused(pool: PgPool) {
    let w = world(&pool).await;

    // A registered system agent, bound (live link) so only the registry can
    // be what refuses it.
    let (system, _) = fixture::seed_agent_with_group(&pool, "bri-system").await;
    assert!(fixture::register_system_agent(&pool, system).await);
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, system, w.human)
            .await
            .expect("the system agent's live link");
    }
    let (kind, msg) = refused(submit_as(&pool, system, &report("from a system agent")).await);
    assert_eq!(kind, RefusalKind::Authority);
    assert!(msg.starts_with("BUG06:"), "{msg}");

    let (unbound, _) = fixture::seed_agent_with_group(&pool, "bri-unbound").await;
    let (_, msg) = refused(submit_as(&pool, unbound, &report("from nobody's agent")).await);
    assert!(msg.starts_with("BUG07:"), "{msg}");

    // No principal at all: an unstamped application connection.
    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let mut conn = plain.acquire().await.expect("acquire");
    let (_, msg) = refused(BugReportRepository::submit_conn(&mut conn, &report("anon")).await);
    assert!(msg.starts_with("BUG01:"), "{msg}");
    let (_, msg) = refused(BugReportRepository::list_mine_conn(&mut conn, 10).await);
    assert!(msg.starts_with("BUG01:"), "{msg}");

    for agent in [system, unbound] {
        assert_eq!(claims_by(&pool, agent).await, 0);
    }
    let markers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'bug_report.submitted'",
    )
    .fetch_one(&pool)
    .await
    .expect("markers");
    assert_eq!(markers, 0, "no refused call left a marker");
}

#[sqlx::test(migrations = "../../migrations")]
async fn malformed_input_is_refused_with_nothing_written(pool: PgPool) {
    let w = world(&pool).await;
    let base = report("valid");
    let cases: Vec<(&str, BugReportInput)> = vec![
        (
            "empty title",
            BugReportInput {
                title: String::new(),
                ..base.clone()
            },
        ),
        (
            "blank title",
            BugReportInput {
                title: " \t\n".into(),
                ..base.clone()
            },
        ),
        (
            "blank description",
            BugReportInput {
                description: "   ".into(),
                ..base.clone()
            },
        ),
        (
            "long title",
            BugReportInput {
                title: "t".repeat(201),
                ..base.clone()
            },
        ),
        (
            "long description",
            BugReportInput {
                description: "d".repeat(20_481),
                ..base.clone()
            },
        ),
        (
            "long repro",
            BugReportInput {
                repro: Some("r".repeat(20_481)),
                ..base.clone()
            },
        ),
        (
            "long evidence",
            BugReportInput {
                evidence: Some("e".repeat(51_201)),
                ..base.clone()
            },
        ),
        (
            "bad severity",
            BugReportInput {
                severity: Some("critical".into()),
                ..base.clone()
            },
        ),
        (
            "bad component",
            BugReportInput {
                component: Some("Not A Slug".into()),
                ..base.clone()
            },
        ),
    ];
    for (what, input) in cases {
        let r = submit_as(&pool, w.reporter, &input).await;
        assert!(r.is_err(), "{what}: admitted {r:?}");
        let (kind, msg) = refused(r);
        assert_eq!(kind, RefusalKind::Input, "{what}");
        assert!(msg.starts_with("BUG04:"), "{what}: {msg}");
    }
    // Limits are inclusive.
    submit_as(
        &pool,
        w.reporter,
        &BugReportInput {
            title: "t".repeat(200),
            description: "d".repeat(20_480),
            evidence: Some("e".repeat(51_200)),
            ..base.clone()
        },
    )
    .await
    .expect("at the limits");
    assert_eq!(claims_by(&pool, w.reporter).await, 1);
    assert_eq!(markers_of(&pool, w.reporter).await, 1);

    // Content that is not the composition of the fields: BUG05.
    let viewer = Viewer::resolve(&pool, w.reporter).await.expect("resolve");
    let scoped = app(&pool).await;
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped");
    let r = sqlx::query(
        "SELECT * FROM public.epigraph_submit_bug_report('t', 'd', NULL, NULL, NULL, NULL, \
             'something else', $1, $1, NULL)",
    )
    .bind(vec![0_u8; 32])
    .execute(&mut *tx)
    .await;
    let msg = r.expect_err("refused").to_string();
    assert!(msg.contains("BUG05:"), "{msg}");
}
