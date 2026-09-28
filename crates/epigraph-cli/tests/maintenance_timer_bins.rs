//! The two maintenance binaries batch W12a (operator decision D9) changes or
//! adds, driven as real processes on real LOGIN roles:
//!
//! * `replay_deferred_cascades`: the existing unset-variable refusal is kept;
//!   a run takes the replay's advisory lock and does nothing when it is held;
//!   `--report-only` prints the backlog and writes nothing, and takes no lock.
//! * `sweep_semantic_duplicates` (new): `--acting-agent` is required and must
//!   exist; the default is a dry run that writes nothing; `--apply` collapses
//!   through the audited administrative cascade; the sweep's own lock.
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
