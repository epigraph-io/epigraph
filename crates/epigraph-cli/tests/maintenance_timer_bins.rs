//! The two maintenance binaries batch W12a (operator decision D9) changes or
//! adds, driven as real processes on real LOGIN roles:
//!
//! * `replay_deferred_cascades`: the existing unset-variable refusal is kept;
//!   a run takes the replay's advisory lock and does nothing when it is held;
//!   `--report-only` prints the backlog and writes nothing, and takes no lock.
//! * `sweep_semantic_duplicates` (new): `--acting-agent` is required and must
//!   exist; the default is a dry run that writes nothing; `--apply` collapses
//!   through the audited administrative cascade; the sweep's own lock.
//! * `unmark_duplicate` (backlog e8113079): the only shipped process that can
//!   un-mark a duplicate, since a request-serving server holds no maintenance
//!   connection and an un-mark has no deferred form. A mark the sweep made is
//!   restored exactly (the moved edge back on the duplicate, the identity edge
//!   retracted) and audited as `undedup` naming the acting operator; every
//!   refusal, the dry run and a held replay lock write nothing; a label-dedup
//!   apply's marks are preflighted as a whole before any is un-marked.
//!
//! The logins are created per test (roles are cluster-global, so each name is
//! unique) and dropped at the end; neither is a superuser. The superuser
//! fixture pool only seeds rows and reads results.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::process::Command;

use sqlx::PgPool;
use uuid::Uuid;

const REPLAY: &str = env!("CARGO_BIN_EXE_replay_deferred_cascades");
const SWEEP: &str = env!("CARGO_BIN_EXE_sweep_semantic_duplicates");
const UNMARK: &str = env!("CARGO_BIN_EXE_unmark_duplicate");
const DIM: usize = 1536;

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("w12a_{}_{}", parent, Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' IN ROLE {parent}"
    ))
    .execute(pool)
    .await
    .expect("create the login");
    let base = viewer_fixture::database_url_for(pool).await;
    let scheme_end = base.find("://").expect("a scheme") + 3;
    let host_path = &base[base.find('@').expect("credentials in the DSN") + 1..];
    let url = format!("{}{role}:{password}@{host_path}", &base[..scheme_end]);
    (role, url)
}

async fn drop_login(pool: &PgPool, role: &str) {
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(pool)
        .await;
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(bin: &str, args: &[&str], database_url: &str, maintenance_url: Option<&str>) -> Run {
    let mut cmd = Command::new(bin);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", database_url)
        .env("RUST_LOG", "warn")
        .args(args)
        .current_dir(std::env::temp_dir());
    if let Some(m) = maintenance_url {
        cmd.env("MAINTENANCE_DATABASE_URL", m);
    }
    let out = cmd.output().expect("run the binary");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'w12a-bin', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A committed supersede act (new -> old, old retired) and the
/// `cascade.deferred` row a request-serving process records for it.
async fn deferred_supersede(pool: &PgPool, agent: Uuid) -> (Uuid, Uuid) {
    let old: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ('w12a old ' || gen_random_uuid(), sha256(gen_random_uuid()::text::bytea), 0.5, \
                 $1, false) RETURNING id",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("old claim");
    let new: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, supersedes) \
         VALUES ('w12a new ' || gen_random_uuid(), sha256(gen_random_uuid()::text::bytea), 0.6, \
                 $1, true, $2) RETURNING id",
    )
    .bind(agent)
    .bind(old)
    .fetch_one(pool)
    .await
    .expect("new claim");
    sqlx::query(
        "INSERT INTO security_events (event_type, agent_id, success, details) \
         VALUES ('cascade.deferred', $1, false, jsonb_build_object( \
             'cause', 'supersede', 'migration', 117, 'reason', 'test', \
             'trigger', jsonb_build_object('agent_id', $1, 'subject_id', $2, 'object_id', $3)))",
    )
    .bind(agent)
    .bind(old)
    .bind(new)
    .execute(pool)
    .await
    .expect("the deferral row");
    (old, new)
}

async fn hold_lock(pool: &PgPool, key: i64) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let mut conn = pool.acquire().await.expect("a lock-holding connection");
    assert!(
        epigraph_db::repos::maintenance_lock::try_take(&mut conn, key)
            .await
            .expect("take the lock"),
        "CALIBRATION: the lock was already held"
    );
    conn
}

/// Release a lock [`hold_lock`] took. Explicit: a session advisory lock lives
/// as long as its CONNECTION, and dropping a pooled connection returns it to
/// the pool still holding the lock.
async fn release_lock(mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>, key: i64) {
    assert!(
        epigraph_db::repos::maintenance_lock::release(&mut conn, key)
            .await
            .expect("release the lock"),
        "the lock was not held by this connection"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_replay_refuses_the_fallback_reports_read_only_and_yields_to_its_lock(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let agent = seed_agent(&pool).await;
    deferred_supersede(&pool, agent).await;
    let applied = "SELECT count(*) FROM security_events WHERE event_type = 'cascade.admin_applied'";
    let events = "SELECT count(*) FROM security_events";

    // The existing refusal: no configured maintenance DSN.
    let r = run(REPLAY, &[], &maint_url, None);
    assert_ne!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr
            .contains("runs only on an explicitly configured MAINTENANCE_DATABASE_URL"),
        "{}",
        r.stderr
    );

    // --report-only: the backlog, and nothing written.
    let before = count(&pool, events).await;
    let r = run(REPLAY, &["--report-only"], &app_url, Some(&maint_url));
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    let summary: serde_json::Value = serde_json::from_str(r.stdout.trim()).expect("JSON");
    assert_eq!(summary["pending"], 1, "{summary}");
    assert_eq!(summary["stuck"], 0, "{summary}");
    assert!(
        summary["oldest_age_s"].as_i64().is_some_and(|s| s >= 0),
        "{summary}"
    );
    assert_eq!(
        count(&pool, events).await,
        before,
        "--report-only wrote a row"
    );

    // Another run holds the replay lock: this one does nothing, and
    // --report-only still reports (it takes no lock).
    let holder = hold_lock(&pool, epigraph_db::repos::maintenance_lock::REPLAY_LOCK_KEY).await;
    let r = run(REPLAY, &[], &app_url, Some(&maint_url));
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    let out: serde_json::Value = serde_json::from_str(r.stdout.trim()).expect("JSON");
    assert_eq!(out["locked"], true, "{out}");
    assert_eq!(count(&pool, applied).await, 0, "a locked-out run replayed");
    let r = run(REPLAY, &["--report-only"], &app_url, Some(&maint_url));
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stdout.contains("\"pending\":1"), "{}", r.stdout);
    release_lock(
        holder,
        epigraph_db::repos::maintenance_lock::REPLAY_LOCK_KEY,
    )
    .await;

    // Free: the replay applies the deferral.
    let r = run(REPLAY, &[], &app_url, Some(&maint_url));
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    assert_eq!(count(&pool, applied).await, 1);
    let r = run(REPLAY, &["--report-only"], &app_url, Some(&maint_url));
    let summary: serde_json::Value = serde_json::from_str(r.stdout.trim()).expect("JSON");
    assert_eq!(summary["pending"], 0, "{summary}");
    assert!(summary["oldest_age_s"].is_null(), "{summary}");

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}

/// Migration 120's one-shot legacy sweep, on the real binary and a
/// non-superuser maintenance login: it refuses without an acting operator or a
/// reason, and with both it removes the BBAs of an edge withdrawn before
/// withdrawals recorded deferrals, audited as `edge_retract` naming the acting
/// operator. The engine arm (`epigraph-mcp/tests/edge_retract_bba_cleanup.rs`)
/// pins that a genuine perspective's BBA is never a candidate.
#[sqlx::test(migrations = "../../migrations")]
async fn the_withdrawn_edge_bba_sweep_needs_an_actor_and_a_reason_and_audits_them(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let operator = seed_agent(&pool).await;
    let a = viewer_fixture::seed_public_claim(&pool, operator, "w12b cli sweep a").await;
    let b = viewer_fixture::seed_public_claim(&pool, operator, "w12b cli sweep b").await;
    let edge = viewer_fixture::seed_edge(&pool, a, b).await;
    sqlx::query(
        "INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, 'w12b', 'edge')",
    )
    .bind(edge)
    .execute(&pool)
    .await
    .expect("edge-factor perspective");
    let frame = epigraph_db::FrameRepository::create(
        &pool,
        "binary_truth",
        Some("w12b"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;
    let bba = epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        b,
        frame,
        Some(operator),
        Some(edge),
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("test"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("a BBA keyed on the edge");
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(edge)
        .execute(&pool)
        .await
        .expect("retract (privileged)");
    let bba_left = format!("SELECT count(*) FROM mass_functions WHERE id = '{bba}'");

    let r = run(
        REPLAY,
        &["--sweep-withdrawn-edge-bbas", "--reason", "w12b"],
        &app_url,
        Some(&maint_url),
    );
    assert_ne!(r.code, Some(0), "{}", r.stdout);
    assert!(r.stderr.contains("--acting-agent"), "{}", r.stderr);
    let operator_arg = operator.to_string();
    let r = run(
        REPLAY,
        &[
            "--sweep-withdrawn-edge-bbas",
            "--acting-agent",
            &operator_arg,
        ],
        &app_url,
        Some(&maint_url),
    );
    assert_ne!(r.code, Some(0), "{}", r.stdout);
    assert!(r.stderr.contains("--reason"), "{}", r.stderr);
    assert_eq!(
        count(&pool, &bba_left).await,
        1,
        "a refused sweep removed nothing"
    );

    let r = run(
        REPLAY,
        &[
            "--sweep-withdrawn-edge-bbas",
            "--acting-agent",
            &operator_arg,
            "--reason",
            "w12b legacy sweep",
        ],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let out: serde_json::Value = serde_json::from_str(r.stdout.trim()).expect("JSON");
    assert_eq!(
        (out["swept"].clone(), out["failed"].clone()),
        (serde_json::json!(1), serde_json::json!(0)),
        "{out}"
    );
    assert_eq!(count(&pool, &bba_left).await, 0, "the sweep removed it");
    let audit: (Option<Uuid>, serde_json::Value) = sqlx::query_as(
        "SELECT agent_id, details FROM security_events \
          WHERE event_type = 'cascade.admin_applied' AND details->>'cause' = 'edge_retract'",
    )
    .fetch_one(&pool)
    .await
    .expect("the sweep's audit row");
    assert_eq!(audit.0, Some(operator), "names the acting operator");
    assert_eq!(audit.1["touched"]["sweep_reason"], "w12b legacy sweep");

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}

fn pgvec(axis: usize, tilt: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    v[axis] = 1.0;
    v[axis + 1] = tilt;
    let s: Vec<String> = v.iter().map(ToString::to_string).collect();
    format!("[{}]", s.join(","))
}

async fn seed_embedded(pool: &PgPool, agent: Uuid, content: &str, truth: f64, v: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, embedding) \
         VALUES ($1, sha256($1::bytea), $2, $3, true, $4::vector) RETURNING id",
    )
    .bind(content)
    .bind(truth)
    .bind(agent)
    .bind(v)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_sweep_cli_is_a_dry_run_by_default_and_audits_each_applied_collapse(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let (a1, a2, operator) = (
        seed_agent(&pool).await,
        seed_agent(&pool).await,
        seed_agent(&pool).await,
    );
    let strong = seed_embedded(&pool, a1, "said twice", 0.9, &pgvec(0, 0.0)).await;
    let weak = seed_embedded(&pool, a2, "said twice", 0.4, &pgvec(0, 0.001)).await;
    let op = operator.to_string();
    let current =
        format!("SELECT count(*) FROM claims WHERE is_current AND id IN ('{strong}', '{weak}')");
    let events = "SELECT count(*) FROM security_events";

    // --acting-agent is required, and must be an agent.
    let r = run(SWEEP, &[], &app_url, Some(&maint_url));
    assert_ne!(r.code, Some(0));
    assert!(r.stderr.contains("--acting-agent"), "{}", r.stderr);
    let stranger = Uuid::new_v4().to_string();
    let r = run(
        SWEEP,
        &["--acting-agent", &stranger, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stderr.contains("is not an agent"), "{}", r.stderr);
    assert_eq!(
        count(&pool, &current).await,
        2,
        "a refused run collapsed a pair"
    );

    // The default is a dry run: the cluster is listed, nothing is written.
    let before = count(&pool, events).await;
    let r = run(SWEEP, &["--acting-agent", &op], &app_url, Some(&maint_url));
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let report: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    assert_eq!(report["dry_run"], true, "{report}");
    assert_eq!(
        report["clusters"].as_array().map(Vec::len),
        Some(1),
        "{report}"
    );
    assert_eq!(report["pairs_marked"], 0, "{report}");
    assert_eq!(
        count(&pool, &current).await,
        2,
        "the dry run collapsed a pair"
    );
    assert_eq!(
        count(&pool, events).await,
        before,
        "the dry run wrote an audit row"
    );

    // The sweep's own lock.
    let holder = hold_lock(&pool, epigraph_db::repos::maintenance_lock::SWEEP_LOCK_KEY).await;
    let r = run(
        SWEEP,
        &["--acting-agent", &op, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stdout.contains("\"locked\":true"), "{}", r.stdout);
    assert_eq!(
        count(&pool, &current).await,
        2,
        "a locked-out run collapsed a pair"
    );
    release_lock(holder, epigraph_db::repos::maintenance_lock::SWEEP_LOCK_KEY).await;

    // --apply: collapsed through the administrative cascade, audited under the
    // acting agent with cause dedup.
    let r = run(
        SWEEP,
        &["--acting-agent", &op, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let report: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    assert_eq!(report["pairs_marked"], 1, "{report}");
    let supersedes: Option<Uuid> =
        sqlx::query_scalar("SELECT supersedes FROM claims WHERE id = $1")
            .bind(weak)
            .fetch_one(&pool)
            .await
            .expect("weak");
    assert_eq!(supersedes, Some(strong));
    let (who, cause): (Option<Uuid>, String) = sqlx::query_as(
        "SELECT agent_id, details->>'cause' FROM security_events \
          WHERE event_type = 'cascade.admin_applied' \
            AND details#>>'{trigger,subject_id}' = $1::text",
    )
    .bind(weak)
    .fetch_one(&pool)
    .await
    .expect("exactly one applied row for the pair");
    assert_eq!((who, cause.as_str()), (Some(operator), "dedup"));

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}

// ── unmark_duplicate (backlog e8113079) ─────────────────────────────────────

/// Two identical claims on their own embedding axis (so each pair is its own
/// cluster), a third claim's `supports` edge into the weaker one, and the
/// sweep's `--apply` collapsing the pair through the real act and repair (the
/// repair the replay timer runs in production). Returns
/// `(strong, weak, third, identity_edge)`.
async fn swept_pair(
    pool: &PgPool,
    app_url: &str,
    maint_url: &str,
    operator: Uuid,
    content: &str,
    axis: usize,
) -> (Uuid, Uuid, Uuid, Uuid) {
    let (a1, a2) = (seed_agent(pool).await, seed_agent(pool).await);
    let strong = seed_embedded(pool, a1, content, 0.9, &pgvec(axis, 0.0)).await;
    let weak = seed_embedded(pool, a2, content, 0.4, &pgvec(axis, 0.001)).await;
    let third = viewer_fixture::seed_public_claim(pool, a1, &format!("{content}: support")).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports')",
    )
    .bind(third)
    .bind(weak)
    .execute(pool)
    .await
    .expect("the edge into the duplicate");
    let op = operator.to_string();
    let r = run(
        SWEEP,
        &["--acting-agent", &op, "--apply"],
        app_url,
        Some(maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let edge = identity_edge(pool, weak)
        .await
        .expect("CALIBRATION: the sweep marked the pair");
    assert_eq!(
        supports_into(pool, third).await,
        vec![strong],
        "CALIBRATION: the dedup repair re-pointed the edge onto the canonical"
    );
    (strong, weak, third, edge)
}

/// The in-force dedup identity edge out of `dup`.
async fn identity_edge(pool: &PgPool, dup: Uuid) -> Option<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND relationship = 'same_as' \
            AND properties ? 'dedup' AND valid_to IS NULL",
    )
    .bind(dup)
    .fetch_optional(pool)
    .await
    .expect("identity edge")
}

/// Every claim `source`'s in-force `supports` edges point at.
async fn supports_into(pool: &PgPool, source: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'supports' \
            AND valid_to IS NULL ORDER BY target_id",
    )
    .bind(source)
    .fetch_all(pool)
    .await
    .expect("supports edges")
}

/// `(is_current, supersedes)` of `id`.
async fn claim_state(pool: &PgPool, id: Uuid) -> (bool, Option<Uuid>) {
    sqlx::query_as("SELECT COALESCE(is_current, true), supersedes FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("claim state")
}

/// The `cascade.admin_applied` rows of cause `undedup` whose subject is `dup`.
async fn undedup_rows(pool: &PgPool, dup: Uuid) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT agent_id, details FROM security_events \
          WHERE event_type = 'cascade.admin_applied' AND details->>'cause' = 'undedup' \
            AND details#>>'{trigger,subject_id}' = $1::text",
    )
    .bind(dup)
    .fetch_all(pool)
    .await
    .expect("undedup rows")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_unmark_cli_restores_a_swept_duplicate_exactly_and_audits_it(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let operator = seed_agent(&pool).await;
    let (strong, weak, third, edge) =
        swept_pair(&pool, &app_url, &maint_url, operator, "un-mark me", 0).await;
    let (op, dup, canon, edge_s) = (
        operator.to_string(),
        weak.to_string(),
        strong.to_string(),
        edge.to_string(),
    );

    let r = run(
        UNMARK,
        &[
            "--acting-agent",
            &op,
            "--claim-id",
            &dup,
            "--canonical",
            &canon,
            "--identity-edge",
            &edge_s,
            "--apply",
        ],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let report: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    assert_eq!(report["status"], "reverted", "{report}");
    let step = &report["steps"][0];
    assert_eq!(step["ok"], true, "{report}");
    assert_eq!(step["result"]["canonical_id"], canon, "{report}");
    assert_eq!(step["result"]["current_canonical_id"], canon, "{report}");
    assert_eq!(step["result"]["cascade"]["status"], "applied", "{report}");
    // No provider in the child's environment: nothing to embed with, said.
    assert_eq!(step["result"]["embedded"], false, "{report}");

    // The duplicate is current again, its mark gone, and the edge the repair
    // moved onto the canonical is back on it.
    assert_eq!(claim_state(&pool, weak).await, (true, None));
    assert_eq!(claim_state(&pool, strong).await, (true, None));
    assert_eq!(
        identity_edge(&pool, weak).await,
        None,
        "identity edge in force"
    );
    let retired: bool = sqlx::query_scalar("SELECT valid_to IS NOT NULL FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(&pool)
        .await
        .expect("the identity edge row");
    assert!(
        retired,
        "the identity edge was deleted rather than retracted"
    );
    assert_eq!(supports_into(&pool, third).await, vec![weak]);

    // Audited once, as cause `undedup`, naming the acting operator, reversed
    // from the record the sweep's repair kept.
    let rows = undedup_rows(&pool, weak).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (who, details) = &rows[0];
    assert_eq!(*who, Some(operator));
    assert!(details["reversed_event_id"].is_string(), "{details}");
    assert_eq!(details["touched"]["edges_retargeted_back"], 1, "{details}");

    // A second run finds no mark: refused, nothing written.
    let events = "SELECT count(*) FROM security_events";
    let before = count(&pool, events).await;
    let r = run(
        UNMARK,
        &["--acting-agent", &op, "--claim-id", &dup, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(1), "{}\n{}", r.stdout, r.stderr);
    assert!(
        r.stdout.contains("is not a marked duplicate"),
        "{}",
        r.stdout
    );
    assert_eq!(count(&pool, events).await, before);

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_unmark_cli_refuses_and_dry_runs_with_nothing_written(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let operator = seed_agent(&pool).await;
    let (strong, weak, third, edge) =
        swept_pair(&pool, &app_url, &maint_url, operator, "keep me marked", 0).await;
    let (op, dup, canon) = (operator.to_string(), weak.to_string(), strong.to_string());
    let stranger = Uuid::new_v4().to_string();
    let events = "SELECT count(*) FROM security_events";
    let before = count(&pool, events).await;
    let still_marked = |pool: PgPool| async move {
        assert_eq!(claim_state(&pool, weak).await, (false, Some(strong)));
        assert_eq!(identity_edge(&pool, weak).await, Some(edge));
        assert_eq!(supports_into(&pool, third).await, vec![strong]);
        assert_eq!(
            count(&pool, events).await,
            before,
            "a refused run wrote a row"
        );
    };

    // No configured maintenance DSN: refused even when DATABASE_URL itself
    // could bypass row security, so the application DSN never runs it.
    let r = run(
        UNMARK,
        &["--acting-agent", &op, "--claim-id", &dup, "--apply"],
        &maint_url,
        None,
    );
    assert_ne!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stderr
            .contains("runs only on an explicitly configured MAINTENANCE_DATABASE_URL"),
        "{}",
        r.stderr
    );
    still_marked(pool.clone()).await;

    // --acting-agent is required, and must be an agent.
    let r = run(UNMARK, &["--claim-id", &dup], &app_url, Some(&maint_url));
    assert_ne!(r.code, Some(0));
    assert!(r.stderr.contains("--acting-agent"), "{}", r.stderr);
    let r = run(
        UNMARK,
        &["--acting-agent", &stranger, "--claim-id", &dup, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stderr.contains("is not an agent"), "{}", r.stderr);
    still_marked(pool.clone()).await;

    // Refusals of the target, each read-only: not a marked duplicate, marked
    // onto another canonical than expected, carrying another identity edge.
    for (args, why) in [
        (
            vec!["--claim-id", canon.as_str()],
            "is not a marked duplicate",
        ),
        (
            vec!["--claim-id", dup.as_str(), "--canonical", stranger.as_str()],
            "not of",
        ),
        (
            vec![
                "--claim-id",
                dup.as_str(),
                "--identity-edge",
                stranger.as_str(),
            ],
            "no longer carries the mark",
        ),
    ] {
        let mut argv = vec!["--acting-agent", op.as_str(), "--apply"];
        argv.extend(args);
        let r = run(UNMARK, &argv, &app_url, Some(&maint_url));
        assert_eq!(r.code, Some(1), "{argv:?}\n{}\n{}", r.stdout, r.stderr);
        let report: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
        assert_eq!(report["admissible"], false, "{report}");
        assert!(
            report["unmarks"][0]["reason"]
                .as_str()
                .is_some_and(|s| s.contains(why)),
            "{argv:?}: {report}"
        );
        still_marked(pool.clone()).await;
    }

    // The default is a dry run: the plan, admissible, and nothing written.
    let r = run(
        UNMARK,
        &["--acting-agent", &op, "--claim-id", &dup],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let report: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    assert_eq!(report["dry_run"], true, "{report}");
    assert_eq!(report["admissible"], true, "{report}");
    assert_eq!(report["unmarks"][0]["canonical_id"], canon, "{report}");
    assert_eq!(
        report["unmarks"][0]["chain"],
        serde_json::json!([canon]),
        "{report}"
    );
    still_marked(pool.clone()).await;

    // A replay run holds its lock: the un-mark is not applied beside it.
    let holder = hold_lock(&pool, epigraph_db::repos::maintenance_lock::REPLAY_LOCK_KEY).await;
    let r = run(
        UNMARK,
        &["--acting-agent", &op, "--claim-id", &dup, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(1), "{}\n{}", r.stdout, r.stderr);
    assert!(r.stderr.contains("replay"), "{}", r.stderr);
    still_marked(pool.clone()).await;
    release_lock(
        holder,
        epigraph_db::repos::maintenance_lock::REPLAY_LOCK_KEY,
    )
    .await;

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}

/// The marks half of a label-dedup revert (`revert_label_dedup`, which a
/// request-serving server refuses when it carries marks): every mark of the
/// apply's `applied_marks` is proved admissible before any is un-marked, so
/// one stale mark leaves all of them in place; a sound file un-marks each.
///
/// The stale mark is the FIRST file entry, which `revert_marks` (newest first)
/// checks and un-marks LAST: a run that checked and applied each target in
/// turn would already have un-marked the sound second entry by the time it
/// reached the stale one, so only a whole-run preflight leaves both in place.
#[sqlx::test(migrations = "../../migrations")]
async fn the_unmark_cli_reverts_an_applys_marks_all_or_nothing(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let operator = seed_agent(&pool).await;
    let (s1, w1, t1, e1) = swept_pair(&pool, &app_url, &maint_url, operator, "pair one", 0).await;
    let (s2, w2, t2, e2) = swept_pair(&pool, &app_url, &maint_url, operator, "pair two", 10).await;
    let op = operator.to_string();
    let marks = |first_edge: Uuid| {
        serde_json::json!({
            "status": "applied",
            "applied_marks": [
                {"unit": "cluster:one", "dup": w1, "canonical": s1, "rule": "strong_id",
                 "matched_on": "id-1", "identity_edge": first_edge},
                {"unit": "cluster:two", "dup": w2, "canonical": s2, "rule": "strong_id",
                 "matched_on": "id-2", "identity_edge": e2},
            ],
        })
    };
    let mut written = Vec::new();
    let mut write = |name: &str, v: &serde_json::Value| {
        let p = std::env::temp_dir().join(format!("unmark-{}-{name}", Uuid::new_v4().simple()));
        std::fs::write(&p, v.to_string()).expect("write the marks file");
        written.push(p.clone());
        p.to_string_lossy().into_owned()
    };
    let events = "SELECT count(*) FROM security_events";
    let before = count(&pool, events).await;

    // The FIRST mark names an identity edge its claim no longer carries:
    // nothing is un-marked, not even the sound second one, which is checked
    // (and would be un-marked) first.
    let stale_edge = Uuid::new_v4();
    let stale = write("stale.json", &marks(stale_edge));
    let r = run(
        UNMARK,
        &["--acting-agent", &op, "--applied-marks", &stale, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(1), "{}\n{}", r.stdout, r.stderr);
    let plan: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON plan");
    assert_eq!(plan["admissible"], false, "{plan}");
    let unmarks = plan["unmarks"].as_array().expect("unmarks");
    assert_eq!(unmarks.len(), 2, "{plan}");
    // CALIBRATION: the sound mark is the one checked first, and admissible,
    // so this run is the case an interleaved check-then-apply gets wrong.
    assert_eq!(unmarks[0]["claim_id"], w2.to_string(), "{plan}");
    assert_eq!(unmarks[0]["admissible"], true, "{plan}");
    assert_eq!(unmarks[1]["claim_id"], w1.to_string(), "{plan}");
    assert_eq!(unmarks[1]["admissible"], false, "{plan}");
    assert!(
        unmarks[1]["reason"].as_str().is_some_and(|s| {
            s.contains("no longer carries the mark") && s.contains(&stale_edge.to_string())
        }),
        "{plan}"
    );
    for (s, w, t, e) in [(s1, w1, t1, e1), (s2, w2, t2, e2)] {
        assert_eq!(
            claim_state(&pool, w).await,
            (false, Some(s)),
            "{w} un-marked"
        );
        assert_eq!(
            identity_edge(&pool, w).await,
            Some(e),
            "{w}'s identity edge"
        );
        assert_eq!(
            supports_into(&pool, t).await,
            vec![s],
            "{w}'s edge moved back"
        );
        assert!(undedup_rows(&pool, w).await.is_empty(), "{w} audited");
    }
    assert_eq!(
        count(&pool, events).await,
        before,
        "a refused run wrote a row"
    );

    let sound = write("sound.json", &marks(e1));
    let r = run(
        UNMARK,
        &["--acting-agent", &op, "--applied-marks", &sound, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let report: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    assert_eq!(report["status"], "reverted", "{report}");
    // Newest first, as revert_label_dedup un-marks.
    assert_eq!(report["steps"][0]["claim_id"], w2.to_string(), "{report}");
    assert_eq!(report["steps"][1]["claim_id"], w1.to_string(), "{report}");
    assert_eq!(claim_state(&pool, w1).await, (true, None));
    assert_eq!(claim_state(&pool, w2).await, (true, None));
    assert_eq!(supports_into(&pool, t1).await, vec![w1]);
    assert_eq!(supports_into(&pool, t2).await, vec![w2]);
    assert_eq!(undedup_rows(&pool, w1).await.len(), 1);
    assert_eq!(undedup_rows(&pool, w2).await.len(), 1);

    for p in written {
        let _ = std::fs::remove_file(p);
    }
    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}

/// A dedup chain (Y marked onto X, then X onto W; two sweeps build it): Y
/// alone is refused, since its canonical is itself a marked duplicate, and an
/// apply's marks listing both un-mark X first (newest first) and then Y,
/// whose canonical the same run made current again (`revert_label_dedup`'s
/// preflight rule).
#[sqlx::test(migrations = "../../migrations")]
async fn the_unmark_cli_unmarks_a_chain_from_the_canonical_end_in_one_run(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let operator = seed_agent(&pool).await;
    let op = operator.to_string();
    let (a1, a2, a3) = (
        seed_agent(&pool).await,
        seed_agent(&pool).await,
        seed_agent(&pool).await,
    );
    let content = "chained restatement";
    let x = seed_embedded(&pool, a1, content, 0.9, &pgvec(0, 0.0)).await;
    let y = seed_embedded(&pool, a2, content, 0.4, &pgvec(0, 0.001)).await;
    let r = run(
        SWEEP,
        &["--acting-agent", &op, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let w = seed_embedded(&pool, a3, content, 0.95, &pgvec(0, 0.0005)).await;
    let r = run(
        SWEEP,
        &["--acting-agent", &op, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    assert_eq!(
        claim_state(&pool, y).await,
        (false, Some(x)),
        "CALIBRATION: Y onto X"
    );
    assert_eq!(
        claim_state(&pool, x).await,
        (false, Some(w)),
        "CALIBRATION: X onto W"
    );
    let ey = identity_edge(&pool, y).await.expect("Y's identity edge");
    let ex = identity_edge(&pool, x).await.expect("X's identity edge");
    let events = "SELECT count(*) FROM security_events";
    let before = count(&pool, events).await;

    // Y alone: its canonical is still a marked duplicate.
    let yid = y.to_string();
    let r = run(
        UNMARK,
        &["--acting-agent", &op, "--claim-id", &yid, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(1), "{}\n{}", r.stdout, r.stderr);
    let report: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    let why = report["unmarks"][0]["reason"].as_str().unwrap_or_default();
    assert!(
        why.contains("itself retired") && why.contains(&format!("un-mark {x} first")),
        "{report}"
    );
    assert_eq!(
        count(&pool, events).await,
        before,
        "a refused run wrote a row"
    );

    // Both marks, in apply order: X is un-marked first, then Y.
    let file = std::env::temp_dir().join(format!("unmark-chain-{}.json", Uuid::new_v4().simple()));
    std::fs::write(
        &file,
        serde_json::json!({"applied_marks": [
            {"unit": "u1", "dup": y, "canonical": x, "rule": "strong_id", "matched_on": "a",
             "identity_edge": ey},
            {"unit": "u2", "dup": x, "canonical": w, "rule": "strong_id", "matched_on": "a",
             "identity_edge": ex},
        ]})
        .to_string(),
    )
    .expect("write the marks file");
    let path = file.to_string_lossy().into_owned();
    let r = run(
        UNMARK,
        &["--acting-agent", &op, "--applied-marks", &path, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let report: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    assert_eq!(report["status"], "reverted", "{report}");
    assert_eq!(report["steps"][0]["claim_id"], x.to_string(), "{report}");
    assert_eq!(report["steps"][1]["claim_id"], y.to_string(), "{report}");
    assert_eq!(claim_state(&pool, x).await, (true, None));
    assert_eq!(claim_state(&pool, y).await, (true, None));
    assert_eq!(claim_state(&pool, w).await, (true, None));

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}

/// Operator ruling R-11 at the CLI: a duplicate whose canonical was
/// SUPERSEDED after the mark is un-marked against the canonical's current
/// replacement. The mark it must find is still the RECORDED one (`--canonical`
/// names the canonical the claim was marked onto, as MCP `unmark_duplicate`'s
/// gate compares it), the plan shows the chain from that canonical to its
/// replacement, and the edge the dedup repair moved (and the supersede then
/// carried on to the replacement) comes back to the duplicate, while the
/// supersede itself stands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_unmark_cli_follows_a_superseded_canonical(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let operator = seed_agent(&pool).await;
    let (strong, weak, third, _) =
        swept_pair(&pool, &app_url, &maint_url, operator, "revised later", 0).await;

    // The canonical is superseded after the mark, as the supersede routes do
    // it: the act, then its edges carried on to the replacement.
    let replacement = {
        let mut conn = pool.acquire().await.expect("acquire");
        let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(strong)
            .fetch_one(&mut *conn)
            .await
            .expect("the canonical's author");
        let (replacement, _) = epigraph_db::ClaimRepository::supersede_act_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(strong),
            &format!("revised later, revised {}", Uuid::new_v4()),
            epigraph_core::TruthValue::clamped(0.5),
            "revision",
            epigraph_db::SupersedeActor::new(author, epigraph_db::SupersedeTool::SupersedeClaim),
        )
        .await
        .expect("supersede act");
        epigraph_db::ClaimRepository::migrate_superseded_edges_conn(&mut conn, strong, replacement)
            .await
            .expect("edge migration");
        replacement
    };
    assert_eq!(
        claim_state(&pool, weak).await,
        (false, Some(strong)),
        "CALIBRATION: still marked onto the recorded canonical"
    );
    assert!(
        !claim_state(&pool, strong).await.0,
        "CALIBRATION: the canonical is retired"
    );
    assert_eq!(
        supports_into(&pool, third).await,
        vec![replacement],
        "CALIBRATION: the moved edge followed the canonical to its replacement"
    );
    let (op, dup, canon, repl) = (
        operator.to_string(),
        weak.to_string(),
        strong.to_string(),
        replacement.to_string(),
    );
    let events = "SELECT count(*) FROM security_events";
    let before = count(&pool, events).await;

    // The dry run names the recorded canonical and follows it to the
    // replacement.
    let r = run(
        UNMARK,
        &[
            "--acting-agent",
            &op,
            "--claim-id",
            &dup,
            "--canonical",
            &canon,
        ],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let plan: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON plan");
    assert_eq!(plan["admissible"], true, "{plan}");
    assert_eq!(plan["unmarks"][0]["canonical_id"], canon, "{plan}");
    assert_eq!(
        plan["unmarks"][0]["chain"],
        serde_json::json!([canon, repl]),
        "{plan}"
    );

    // The replacement is not the canonical the claim was marked onto.
    let r = run(
        UNMARK,
        &[
            "--acting-agent",
            &op,
            "--claim-id",
            &dup,
            "--canonical",
            &repl,
            "--apply",
        ],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(1), "{}\n{}", r.stdout, r.stderr);
    let plan: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON plan");
    assert!(
        plan["unmarks"][0]["reason"]
            .as_str()
            .is_some_and(|s| s.contains(&format!("duplicate of {canon}, not of {repl}"))),
        "{plan}"
    );
    assert_eq!(claim_state(&pool, weak).await, (false, Some(strong)));
    assert_eq!(
        count(&pool, events).await,
        before,
        "a dry run or refused run wrote a row"
    );

    let r = run(
        UNMARK,
        &[
            "--acting-agent",
            &op,
            "--claim-id",
            &dup,
            "--canonical",
            &canon,
            "--apply",
        ],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stdout, r.stderr);
    let report: serde_json::Value = serde_json::from_str(&r.stdout).expect("JSON report");
    assert_eq!(report["status"], "reverted", "{report}");
    let result = &report["steps"][0]["result"];
    assert_eq!(result["canonical_id"], canon, "{report}");
    assert_eq!(result["current_canonical_id"], repl, "{report}");
    assert_eq!(claim_state(&pool, weak).await, (true, None));
    assert_eq!(
        identity_edge(&pool, weak).await,
        None,
        "identity edge in force"
    );
    assert_eq!(supports_into(&pool, third).await, vec![weak]);
    // The supersede stands: the canonical stays retired, its replacement
    // current.
    assert!(
        !claim_state(&pool, strong).await.0,
        "the supersede was undone"
    );
    assert_eq!(claim_state(&pool, replacement).await, (true, Some(strong)));
    assert_eq!(undedup_rows(&pool, weak).await.len(), 1);

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}
