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
//! * the per-hour and per-day limits, counted per reporter;
//! * an agent bound by a client allowance (149) files, with no membership of
//!   any group; a linked agent whose acting row was revoked is refused;
//! * the preflight answers what the write answers for every caller state and
//!   writes nothing; only it, not the gate it shares with the write, is
//!   app-callable;
//! * a role-attached reporter (166) is refused ROL01 by the preflight and by
//!   the write alike while its own human does not hold the role, and files
//!   once it does;
//! * an unconfigured intake (or one whose group is suspended) refuses;
//! * session temporary objects named like the definer's relations change
//!   nothing;
//! * a system agent, an unbound agent and a session with no principal are
//!   refused;
//! * the application role cannot write a `bug_report.` audit row itself;
//! * empty, whitespace-only, invisible-only (format and control characters)
//!   and oversized input is refused with nothing written.

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

/// Both ends of every range of characters the intake treats as invisible
/// (Unicode 15.0: White_Space, Cc without U+0000, Cf). Listed here by value,
/// independently of the definer's bracket and of the MCP pre-check's table,
/// so a range dropped from either is caught.
const INVISIBLE_ENDPOINTS: &[u32] = &[
    0x01, 0x1F, 0x20, 0x7F, 0x85, 0x9F, 0xA0, 0xAD, 0x600, 0x605, 0x61C, 0x6DD, 0x70F, 0x890,
    0x891, 0x8E2, 0x1680, 0x180E, 0x2000, 0x200A, 0x200B, 0x200F, 0x2028, 0x2029, 0x202A, 0x202E,
    0x202F, 0x205F, 0x2060, 0x2064, 0x2066, 0x206F, 0x3000, 0xFEFF, 0xFFF9, 0xFFFB, 0x110BD,
    0x110CD, 0x13430, 0x1343F, 0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A, 0xE0001, 0xE0020, 0xE007F,
];

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

/// The limit is the REPORTER's: one reporter at its limit leaves another free
/// to file, and each one's BUG08 counts only its own filings.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rate_limit_is_per_reporter(pool: PgPool) {
    let w = world(&pool).await;
    let (other_human, _) = fixture::seed_human_operator(&pool, "bri-b-human").await;
    let b = linked_agent(&pool, other_human, "bri-b").await;
    configure(&pool, w.intake, 2, 200).await;

    for i in 0..2 {
        submit_as(&pool, w.reporter, &report(&format!("a {i}")))
            .await
            .expect("A under its limit");
    }
    let (_, msg) = refused(submit_as(&pool, w.reporter, &report("a over")).await);
    assert!(
        msg.starts_with("BUG08:")
            && msg.contains("filed 2 bug reports in the last hour and 2 in the last day"),
        "{msg}"
    );

    for i in 0..2 {
        submit_as(&pool, b, &report(&format!("b {i}")))
            .await
            .expect("B files while A is at its limit");
    }
    let (_, msg) = refused(submit_as(&pool, b, &report("b over")).await);
    assert!(
        msg.starts_with("BUG08:")
            && msg.contains("filed 2 bug reports in the last hour and 2 in the last day"),
        "B's refusal counts B's filings only: {msg}"
    );
    assert_eq!(claims_by(&pool, w.reporter).await, 2);
    assert_eq!(claims_by(&pool, b).await, 2);
}

/// On a maintenance session: allow `agent`'s only OAuth client (a service
/// client) for the human `operator` (149's client allowance).
async fn allow_client(pool: &PgPool, agent: Uuid, operator: Uuid) -> Uuid {
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'bug intake allowance fixture', 'service', ARRAY['claims:write'], \
                 'active', $2, 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("bug-intake-allowance-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("service client");
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let now: bool = sqlx::query_scalar(
            "SELECT allowed_now FROM public.epigraph_allow_author_binding_client($1, $2, $3)",
        )
        .bind(client)
        .bind(operator)
        .bind("bug intake test")
        .fetch_one(&mut *conn)
        .await
        .expect("allow the client for the operator");
        (conn, now)
    })
    .await;
    client
}

async fn binding_of(pool: &PgPool, agent: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT public.epigraph_author_binding($1)")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("binding")
}

/// An agent bound by a client ALLOWANCE (149), with no membership of any
/// group its human writes, files a report: it is staged in its human's
/// personal group (the claims trigger admits the agent's own write there) and
/// lands in the intake group, authored by the agent. Revoking the allowance
/// unbinds it, and it is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_agent_files_a_report(pool: PgPool) {
    let w = world(&pool).await;
    let (agent, own) = fixture::seed_agent_with_group(&pool, "bri-allowlisted").await;
    let client = allow_client(&pool, agent, w.human).await;
    assert_eq!(
        binding_of(&pool, agent).await.as_deref(),
        Some("client_allowlist"),
        "PREMISE: bound by the allowance alone"
    );
    assert!(
        !is_member(&pool, w.home, agent).await && !is_member(&pool, w.intake, agent).await,
        "PREMISE: no membership of its human's group or of the intake group"
    );

    let r = submit_as(&pool, agent, &report("from an allowlisted agent"))
        .await
        .expect("an allowlisted agent files");
    let (author, owner, vis): (Uuid, Uuid, String) = sqlx::query_as(
        "SELECT agent_id, owner_group_id, visibility::text FROM claims WHERE id = $1",
    )
    .bind(r.claim_id)
    .fetch_one(&pool)
    .await
    .expect("the report");
    assert_eq!((author, owner, vis.as_str()), (agent, w.intake, "group"));
    let listed: Vec<Uuid> = list_as(&pool, agent)
        .await
        .expect("list")
        .iter()
        .map(|r| r.claim_id)
        .collect();
    assert_eq!(listed, vec![r.claim_id]);
    let staged_elsewhere: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE agent_id = $1 AND owner_group_id IN ($2, $3)",
    )
    .bind(agent)
    .bind(w.home)
    .bind(own)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(staged_elsewhere, 0, "nothing is left in a staging group");

    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, $2)",
        )
        .bind(client)
        .bind("bug intake test")
        .fetch_one(&mut *conn)
        .await
        .expect("revoke the allowance");
        (conn, r)
    })
    .await;
    let (_, msg) = refused(submit_as(&pool, agent, &report("after the revoke")).await);
    assert!(msg.starts_with("BUG07:"), "{msg}");
    assert_eq!(claims_by(&pool, agent).await, 1);
}

/// A linked agent whose acting row in its operator's group was revoked (the
/// deactivation lever: a live link is never retired in place) is refused,
/// although its link is live. Its sibling on the same link files.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deactivated_linked_agent_is_refused(pool: PgPool) {
    let w = world(&pool).await;
    let sibling = linked_agent(&pool, w.human, "bri-sibling").await;
    submit_as(&pool, w.reporter, &report("before"))
        .await
        .expect("CALIBRATION: the reporter files while active");

    let (home, reporter) = (w.home, w.reporter);
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let n = sqlx::query(
            "UPDATE group_memberships SET revoked_at = now() \
              WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
        )
        .bind(home)
        .bind(reporter)
        .execute(&mut *conn)
        .await
        .expect("revoke the acting row")
        .rows_affected();
        assert_eq!(n, 1, "PREMISE: one acting row");
        (conn, ())
    })
    .await;
    assert_eq!(
        binding_of(&pool, w.reporter).await.as_deref(),
        Some("live_link"),
        "PREMISE: the link is still live"
    );

    let (_, msg) = refused(submit_as(&pool, w.reporter, &report("after")).await);
    assert!(msg.starts_with("BUG07:"), "{msg}");
    submit_as(&pool, sibling, &report("the sibling"))
        .await
        .expect("the active sibling files");
    assert_eq!(claims_by(&pool, w.reporter).await, 1);
}

async fn preflight_as(pool: &PgPool, agent: Uuid) -> Result<(), DbError> {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let scoped = app(pool).await;
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped transaction");
    let out = BugReportRepository::preflight_conn(&mut tx).await;
    tx.rollback().await.expect("rollback");
    out
}

/// The refusal code (`BUGnn`, or 166's `ROL01`) of a result, or `ok`.
fn code<T: std::fmt::Debug>(r: Result<T, DbError>) -> String {
    match r {
        Ok(_) => "ok".to_string(),
        Err(DbError::RoleHolderRequired { message }) => {
            assert!(message.starts_with("ROL01:"), "{message}");
            "ROL01".to_string()
        }
        Err(e) => refused::<T>(Err(e)).1[..5].to_string(),
    }
}

/// The preflight answers, for every caller state, exactly what the write
/// answers for a valid report (BUG03, BUG06, BUG07, BUG08, a pass), and
/// writes nothing. A reporter at its limit does not fail another reporter's
/// preflight.
#[sqlx::test(migrations = "../../migrations")]
async fn the_preflight_refuses_what_the_write_refuses_and_writes_nothing(pool: PgPool) {
    let w = bare_world(&pool).await;
    arm(&pool).await;
    let (system, _) = fixture::seed_agent_with_group(&pool, "bri-pf-system").await;
    assert!(fixture::register_system_agent(&pool, system).await);
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, system, w.human)
            .await
            .expect("the system agent's live link");
    }
    let (unbound, _) = fixture::seed_agent_with_group(&pool, "bri-pf-unbound").await;
    let (other_human, _) = fixture::seed_human_operator(&pool, "bri-pf-b-human").await;
    let b = linked_agent(&pool, other_human, "bri-pf-b").await;

    let pf = code(preflight_as(&pool, w.reporter).await);
    assert_eq!(pf, "BUG03");
    assert_eq!(code(submit_as(&pool, w.reporter, &report("x")).await), pf);

    configure(&pool, w.intake, 1, 200).await;
    for _ in 0..2 {
        assert_eq!(code(preflight_as(&pool, w.reporter).await), "ok");
    }
    assert_eq!(
        claims_by(&pool, w.reporter).await,
        0,
        "a preflight writes no claim"
    );
    assert_eq!(markers_of(&pool, w.reporter).await, 0, "and no marker");
    submit_as(&pool, w.reporter, &report("the one this hour"))
        .await
        .expect("filed");

    for (who, agent, want) in [
        ("over its limit", w.reporter, "BUG08"),
        ("system agent", system, "BUG06"),
        ("unbound", unbound, "BUG07"),
        ("another reporter", b, "ok"),
    ] {
        assert_eq!(
            code(preflight_as(&pool, agent).await),
            want,
            "preflight: {who}"
        );
    }
    for (who, agent, want) in [
        ("over its limit", w.reporter, "BUG08"),
        ("system agent", system, "BUG06"),
        ("unbound", unbound, "BUG07"),
    ] {
        assert_eq!(
            code(submit_as(&pool, agent, &report("y")).await),
            want,
            "write: {who}"
        );
    }

    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let mut conn = plain.acquire().await.expect("acquire");
    let (_, msg) = refused(BugReportRepository::preflight_conn(&mut conn).await);
    assert!(msg.starts_with("BUG01:"), "{msg}");
}

// ─── a role-attached reporter (166) ─────────────────────────────────────

const ROLE: &str = "role:bri-curator";

/// A synthetic catalog role, with the role node 123 requires for every role.
async fn seed_role(pool: &PgPool, key: &str) {
    let node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type, role, labels) \
         VALUES ($1, uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), $2, 'role', \
                 'custom', ARRAY['role'])",
    )
    .bind(node)
    .bind(key)
    .execute(pool)
    .await
    .expect("role node");
    sqlx::query(
        "INSERT INTO platform_roles (key, elevates, reads_audit, role_node_id, description) \
         VALUES ($1, false, false, $2, 'test role')",
    )
    .bind(key)
    .bind(node)
    .execute(pool)
    .await
    .expect("platform role");
}

/// Grant `role` to `holder`, live from a few seconds ago, open-ended.
async fn grant(pool: &PgPool, role: &str, holder: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now() - interval '5 seconds', NULL, NULL, \
                'test grant')",
    )
    .bind(role)
    .bind(holder)
    .fetch_one(pool)
    .await
    .expect("grant role")
}

async fn end_assignment(pool: &PgPool, assignment: Uuid) {
    let ended: bool = sqlx::query_scalar(
        "SELECT public.epigraph_end_role_assignment($1, 'test handover', NULL::uuid)",
    )
    .bind(assignment)
    .fetch_one(pool)
    .await
    .expect("end assignment");
    assert!(ended);
}

/// Attach `agent` to `role` through the maintenance definer.
async fn attach(pool: &PgPool, role: &str, agent: Uuid) {
    let role = role.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let _: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_attach_agent_to_role($1, $2, now() - interval '5 seconds', \
                                                         NULL, 'test attach')",
        )
        .bind(&role)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("the maintenance role attaches");
        (conn, ())
    })
    .await;
}

/// A role-attached agent writes only while its own linked human holds the
/// role (166's ROL01). The preflight refuses it exactly as the write does, so
/// such a caller never reaches the embedding call, and neither writes
/// anything: no holder, then a holder who is another human. CALIBRATION:
/// once the reporter's own human holds the role, both pass and the report
/// files.
#[sqlx::test(migrations = "../../migrations")]
async fn the_preflight_refuses_a_role_agent_its_holder_does_not_cover(pool: PgPool) {
    let w = world(&pool).await;
    seed_role(&pool, ROLE).await;
    attach(&pool, ROLE, w.reporter).await;
    let (stranger, _) = fixture::seed_human_operator(&pool, "bri-rol-stranger").await;

    // No holder.
    assert_eq!(code(preflight_as(&pool, w.reporter).await), "ROL01");
    assert_eq!(code(submit_as(&pool, w.reporter, &report("x")).await), "ROL01");
    // Held, by a human the reporter is not linked to.
    let theirs = grant(&pool, ROLE, stranger).await;
    assert_eq!(code(preflight_as(&pool, w.reporter).await), "ROL01");
    assert_eq!(code(submit_as(&pool, w.reporter, &report("y")).await), "ROL01");
    assert_eq!(claims_by(&pool, w.reporter).await, 0, "nothing was filed");
    assert_eq!(markers_of(&pool, w.reporter).await, 0, "and no marker");

    end_assignment(&pool, theirs).await;
    grant(&pool, ROLE, w.human).await;
    assert_eq!(code(preflight_as(&pool, w.reporter).await), "ok");
    submit_as(&pool, w.reporter, &report("held by its own human"))
        .await
        .expect("CALIBRATION: the holder's own agent files");
    assert_eq!(claims_by(&pool, w.reporter).await, 1);
}

/// `(owner, security definer, app may execute, PUBLIC may execute)`.
type FnCatalog = (String, bool, bool, bool);

/// The preflight is the application's; the gate it shares with the write
/// takes a principal as an argument and is NOT (it would answer any agent's
/// binding and filing counts).
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_preflight_is_app_callable(pool: PgPool) {
    for (sig, app_may) in [
        ("public.epigraph_bug_report_preflight()", true),
        (
            "public.epigraph_bug_report_gate(uuid, integer, integer, boolean)",
            false,
        ),
    ] {
        let row: FnCatalog = sqlx::query_as(
            "SELECT pg_get_userbyid(p.proowner)::text, p.prosecdef, \
                    has_function_privilege('epigraph_app', p.oid, 'EXECUTE'), \
                    EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, \
                                                acldefault('f', p.proowner))) a \
                             WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') \
               FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
        )
        .bind(sig)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{sig}: {e}"));
        assert_eq!(
            row,
            ("epigraph_maintenance".to_string(), true, app_may, false),
            "{sig}"
        );
    }
    // Through the real role: the gate is refused to the application.
    let plain = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let r = sqlx::query("SELECT public.epigraph_bug_report_gate($1, 100, 100, false)")
        .bind(Uuid::new_v4())
        .execute(&plain)
        .await;
    let e = r.expect_err("the gate is not the application's");
    assert_eq!(
        e.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("42501"),
        "{e}"
    );
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
    // Nothing visible: zero-width, joiner, BOM, separator and bidi
    // characters alone, then every endpoint of the invisible ranges at once
    // (any endpoint the check misses leaves a character, and is admitted).
    let mut cases = cases;
    let endpoints: String = INVISIBLE_ENDPOINTS
        .iter()
        .map(|&c| char::from_u32(c).expect("a scalar value"))
        .collect();
    for (what, text) in [
        ("zero-width space", "\u{200B}".to_string()),
        ("zero-width joiners", "\u{200B}\u{200C}\u{200D}".to_string()),
        ("word joiner and BOM", "\u{2060}\u{FEFF}".to_string()),
        ("information separator", "\u{1C}".to_string()),
        ("bidi controls", "\u{202E}\u{2066}\u{200F}".to_string()),
        ("tag characters", "\u{E0001}\u{E0020}\u{E007F}".to_string()),
        ("soft hyphen among spaces", " \u{AD}\t\u{3000}".to_string()),
        ("every range endpoint", endpoints),
    ] {
        cases.push((
            what,
            BugReportInput {
                title: text.clone(),
                ..base.clone()
            },
        ));
        cases.push((
            what,
            BugReportInput {
                description: text,
                ..base.clone()
            },
        ));
    }
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
    // A visible character next to invisible ones is a title (CALIBRATION for
    // the invisible-only refusals above).
    submit_as(
        &pool,
        w.reporter,
        &BugReportInput {
            title: "a\u{200B}".into(),
            description: "\u{FEFF}x".into(),
            ..base.clone()
        },
    )
    .await
    .expect("a visible character among invisible ones");
    assert_eq!(claims_by(&pool, w.reporter).await, 2);
    assert_eq!(markers_of(&pool, w.reporter).await, 2);

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
