//! The job queue's drain on the maintenance login (operator decision D9, batch
//! W12a; migration 119).
//!
//! Before D9 the API `server` ran the queue in-process on whatever DSN it had,
//! a superuser in every deployment so far, so a missing grant on the
//! maintenance role was invisible. The drain now runs as a non-superuser LOGIN
//! in `epigraph_maintenance`, and these tests run it that way:
//!
//! * the LIBRARY arms (`jobs_drain::drain`) on a `ScopedPool` downgraded to
//!   `epigraph_maintenance` with `SET SESSION AUTHORIZATION` (not a
//!   superuser; `epigraph_bypass()` is true through `session_user`), so every
//!   handler's statements meet the real grants and policies;
//! * the BINARY arms (`drain_jobs`, spawned) on real LOGIN roles created for
//!   the test, one in `epigraph_maintenance` and one in `epigraph_app`, so the
//!   refusals are measured on the process an operator runs.
//!
//! The superuser fixture pool only SEEDS rows and READS results.

#[path = "privatization_fixture.rs"]
mod fx;

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use epigraph_api::embedding_restore::EmbeddingProviderKind;
use epigraph_api::jobs_drain;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_jobs::{EpiGraphJob, JobQueue, PostgresJobQueue};
use fx::viewer_fixture;
use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_drain_jobs");

/// A `ScopedPool` whose every connection runs as `epigraph_maintenance`.
async fn maintenance_scoped(pool: &PgPool) -> Arc<ScopedPool> {
    let url = viewer_fixture::database_url_for(pool).await;
    Arc::new(
        ScopedPool::connect_downgraded_for_tests(
            &url,
            SessionGucMode::Session,
            "epigraph_maintenance",
        )
        .await
        .expect("a ScopedPool downgraded to epigraph_maintenance"),
    )
}

/// Calibration: the drain's connection is NOT a superuser and IS privileged.
async fn assert_maintenance_posture(scoped: &ScopedPool) {
    let (is_super, bypass): (bool, bool) = sqlx::query_as(
        "SELECT r.rolsuper, public.epigraph_bypass() FROM pg_roles r \
          WHERE r.rolname = session_user",
    )
    .fetch_one(scoped.inner())
    .await
    .expect("read the drain connection's posture");
    assert!(
        !is_super,
        "CALIBRATION: the drain runs as a superuser, so no grant is exercised"
    );
    assert!(
        bypass,
        "CALIBRATION: epigraph_bypass() is false on the maintenance login"
    );
}

fn mock_embedder() -> Arc<dyn epigraph_embeddings::EmbeddingService> {
    Arc::new(epigraph_embeddings::MockProvider::new(
        epigraph_embeddings::EmbeddingConfig::openai(1536),
    ))
}

/// The drain, built exactly as `drain_jobs` builds it, on `scoped`.
fn runner_on(
    scoped: &Arc<ScopedPool>,
    provider: EmbeddingProviderKind,
) -> (epigraph_jobs::JobRunner, PostgresJobQueue) {
    let queue = PostgresJobQueue::new(scoped.inner().clone());
    let runner = jobs_drain::build_job_runner(
        Arc::clone(scoped),
        Arc::new(queue.clone()),
        mock_embedder(),
        provider,
    );
    (runner, queue)
}

async fn enqueue(pool: &PgPool, job: EpiGraphJob) -> Uuid {
    let job = job.into_job().expect("serialise the job");
    let id: Uuid = job.id.into();
    PostgresJobQueue::new(pool.clone())
        .enqueue(job)
        .await
        .expect("seed the job as the superuser");
    id
}

async fn job_state(pool: &PgPool, id: Uuid) -> (String, Option<String>) {
    sqlx::query_as("SELECT state, error_message FROM jobs WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("the job row")
}

/// Claims with cluster-biased 1536-d embeddings, so the theme rebuild has
/// work to do (and so wipes the existing theme set, a DELETE on `claim_themes`).
async fn seed_embedded_claims(pool: &PgPool, agent: Uuid, n: usize) {
    for i in 0..n {
        let cluster = i % 3;
        let v: Vec<String> = (0..1536)
            .map(|j| {
                let bias = if j == cluster { 1.0 } else { 0.0 };
                format!("{}", bias + ((i + j) as f32) * 1e-7)
            })
            .collect();
        let content = format!("drain fixture {i} {}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) \
             VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector)",
        )
        .bind(&content)
        .bind(agent)
        .bind(format!("[{}]", v.join(",")))
        .execute(pool)
        .await
        .expect("seed an embedded claim");
    }
}

/// Every job type the drain timer inherits from `server`, drained once on the
/// maintenance login: a graph clustering run (its retention sweep DELETEs from
/// the four clustering tables), a theme rebuild (it wipes `claim_themes`) and a
/// privatization apply (the real lifecycle: world, plan, dispatch). Any grant
/// 119 missed fails its job with `permission denied`, and the report says so.
/// A second run then does nothing and exits 0.
#[sqlx::test(migrations = "../../migrations")]
async fn the_drain_runs_every_job_type_on_the_maintenance_login(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "drain apply seed").await;
    let (plan, _) = fx::create_plan(&pool, &world, &[claim]).await;
    let correlation = fx::dispatch(&pool, &world, plan, "applying").await;
    seed_embedded_claims(&pool, world.actor, 12).await;
    sqlx::query(
        "INSERT INTO claim_themes (label, description, claim_count) VALUES ('old', 'x', 0)",
    )
    .execute(&pool)
    .await
    .expect("seed a theme the rebuild must wipe");
    // A previous clustering run, so the retention sweep (retain_runs = 1)
    // deletes a run row and not only zero rows.
    let old_run = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, completed_at, cluster_count) \
         VALUES ($1, now() - interval '1 day', 0)",
    )
    .bind(old_run)
    .execute(&pool)
    .await
    .expect("seed an old clustering run");

    let cluster = enqueue(
        &pool,
        EpiGraphJob::ClusterGraph {
            resolution: 1.0,
            retain_runs: 1,
        },
    )
    .await;
    let theme = enqueue(
        &pool,
        EpiGraphJob::ThemeClusterRebuild {
            max_themes: 4,
            min_claims_per_theme: 1,
            skip_if_unchanged: false,
        },
    )
    .await;
    let apply = {
        let job = fx::apply_job(plan, world.actor, &correlation);
        let id: Uuid = job.id.into();
        PostgresJobQueue::new(pool.clone())
            .enqueue(job)
            .await
            .expect("seed the apply job");
        id
    };

    let scoped = maintenance_scoped(&pool).await;
    assert_maintenance_posture(&scoped).await;
    let (runner, queue) = runner_on(&scoped, EmbeddingProviderKind::Mock);
    let report = jobs_drain::drain(&runner, &queue, Duration::from_secs(600))
        .await
        .expect("the drain ran");

    assert!(
        report.failures.is_empty(),
        "a job failed on the maintenance login (a missing grant names its table here): {:?}",
        report.failures
    );
    for (name, id) in [
        ("cluster_graph", cluster),
        ("theme_cluster_rebuild", theme),
        ("privatization_apply", apply),
    ] {
        assert_eq!(
            job_state(&pool, id).await,
            ("completed".to_string(), None),
            "{name} did not complete"
        );
    }
    assert_eq!(report.exit_code(), 0);
    assert!(!report.out_of_time);
    // What the jobs did, not only that they returned Ok.
    assert_eq!(fx::plan_state(&pool, plan).await, "applied");
    assert_eq!(
        fx::tenancy(&pool, claim).await,
        ("group".to_string(), world.target_group),
        "the apply job ran but the plan's claim did not move"
    );
    let old_themes: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claim_themes WHERE label = 'old'")
            .fetch_one(&pool)
            .await
            .expect("count old themes");
    assert_eq!(old_themes, 0, "the theme rebuild did not wipe the old set");
    // The theme rebuild enqueues a follow-up clustering run, which this drain
    // also runs; so count the OLD run, not the total.
    let old_left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM graph_cluster_runs WHERE run_id = $1")
            .bind(old_run)
            .fetch_one(&pool)
            .await
            .expect("count the old run");
    assert_eq!(
        old_left, 0,
        "retain_runs = 1: the old run should have been deleted by the retention sweep"
    );

    // A second run: nothing left, nothing done, exit 0. (The theme rebuild's
    // follow-up enqueue, if it made one, was drained in the first run.)
    let again = jobs_drain::drain(&runner, &queue, Duration::from_secs(600))
        .await
        .expect("the second drain ran");
    assert_eq!(
        (again.completed, again.failures.len(), again.recovered_stale),
        (0, 0, 0),
        "{again:?}"
    );
    assert_eq!(again.exit_code(), 0);
}

/// A job left `running` by a crashed run (older than the 90-minute bound) is
/// reset and drained; a `running` job younger than that is left alone, since it
/// may still be running.
#[sqlx::test(migrations = "../../migrations")]
async fn the_drain_reaps_a_stale_running_job_and_leaves_a_fresh_one(pool: PgPool) {
    let stale = enqueue(
        &pool,
        EpiGraphJob::ClusterGraph {
            resolution: 1.0,
            retain_runs: 5,
        },
    )
    .await;
    let fresh = enqueue(
        &pool,
        EpiGraphJob::ClusterGraph {
            resolution: 1.0,
            retain_runs: 5,
        },
    )
    .await;
    sqlx::query(
        "UPDATE jobs SET state = 'running', started_at = now() - interval '2 hours' WHERE id = $1",
    )
    .bind(stale)
    .execute(&pool)
    .await
    .expect("age the stale job");
    sqlx::query(
        "UPDATE jobs SET state = 'running', started_at = now() - interval '5 minutes' WHERE id = $1",
    )
    .bind(fresh)
    .execute(&pool)
    .await
    .expect("mark the fresh job running");

    let scoped = maintenance_scoped(&pool).await;
    assert_maintenance_posture(&scoped).await;
    let (runner, queue) = runner_on(&scoped, EmbeddingProviderKind::Mock);
    let report = jobs_drain::drain(&runner, &queue, Duration::from_secs(600))
        .await
        .expect("the drain ran");

    assert_eq!(report.recovered_stale, 1, "{report:?}");
    assert_eq!(report.completed, 1, "{report:?}");
    assert_eq!(job_state(&pool, stale).await.0, "completed");
    assert_eq!(
        job_state(&pool, fresh).await.0,
        "running",
        "a job younger than the stale bound was reset out from under its runner"
    );
}

/// The provider gate on `embedding_generation`, and why the drain filters by
/// registered type: with a provider that may not write `claims.embedding` the
/// handler is not registered, and a pending `embedding_generation` job at the
/// HEAD of the queue neither wedges the run nor is touched; the job behind it
/// runs. With the owning provider the handler is registered.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unregistered_job_type_at_the_head_of_the_queue_does_not_wedge_the_drain(pool: PgPool) {
    let head = enqueue(
        &pool,
        EpiGraphJob::EmbeddingGeneration {
            claim_id: Uuid::new_v4(),
        },
    )
    .await;
    let behind = enqueue(
        &pool,
        EpiGraphJob::ClusterGraph {
            resolution: 1.0,
            retain_runs: 5,
        },
    )
    .await;

    let scoped = maintenance_scoped(&pool).await;
    let (mock_runner, queue) = runner_on(&scoped, EmbeddingProviderKind::Mock);
    assert!(
        !mock_runner
            .registered_job_types()
            .contains(&"embedding_generation".to_string()),
        "a mock provider was allowed to write claims.embedding"
    );
    let (owning_runner, _) = runner_on(&scoped, EmbeddingProviderKind::OpenAi);
    assert!(
        owning_runner
            .registered_job_types()
            .contains(&"embedding_generation".to_string()),
        "the owning provider's embedding handler is not registered"
    );

    let report = jobs_drain::drain(&mock_runner, &queue, Duration::from_secs(600))
        .await
        .expect("the drain ran");
    assert_eq!(report.completed, 1, "{report:?}");
    assert_eq!(job_state(&pool, behind).await.0, "completed");
    assert_eq!(
        job_state(&pool, head).await,
        ("pending".to_string(), None),
        "the drain claimed a job it has no handler for"
    );
}

/// A job whose handler fails is put back to `pending` with the retry counted,
/// and not retried in the same run (the next run is the backoff); when its
/// retries are used up it is `failed` and the run exits 1.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failing_job_is_retried_next_run_then_fails_terminally(pool: PgPool) {
    // A privatization apply for a plan that does not exist: the handler
    // refuses it.
    let id = {
        let job = fx::apply_job(Uuid::new_v4(), Uuid::new_v4(), "no-such-dispatch");
        let id: Uuid = job.id.into();
        PostgresJobQueue::new(pool.clone())
            .enqueue(job)
            .await
            .expect("seed");
        id
    };
    let max_retries: i32 = sqlx::query_scalar("SELECT max_retries FROM jobs WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("max_retries");

    let scoped = maintenance_scoped(&pool).await;
    let (runner, queue) = runner_on(&scoped, EmbeddingProviderKind::Mock);
    let first = jobs_drain::drain(&runner, &queue, Duration::from_secs(600))
        .await
        .expect("drain");
    assert_eq!(first.failures.len(), 1, "{first:?}");
    let (state, err) = job_state(&pool, id).await;
    if first.failures[0].terminal {
        // A permanent refusal uses up the retries at once.
        assert_eq!(state, "failed");
        assert_eq!(first.exit_code(), 1);
    } else {
        assert_eq!(
            state, "pending",
            "a retryable failure must go back to pending"
        );
        assert!(err.is_some(), "the failure's error was not recorded");
        assert_eq!(
            first.exit_code(),
            0,
            "a retry still pending is not a failed run"
        );
        let mut last = first;
        for _ in 0..max_retries {
            last = jobs_drain::drain(&runner, &queue, Duration::from_secs(600))
                .await
                .expect("drain");
            if last.failures.iter().any(|f| f.terminal) {
                break;
            }
        }
        assert_eq!(job_state(&pool, id).await.0, "failed");
        assert_eq!(last.exit_code(), 1);
    }
}

// ---------------------------------------------------------------------------
// The binary, on real LOGIN roles.
// ---------------------------------------------------------------------------

/// A LOGIN role in `parent`, and the database URL that logs in as it. The
/// role is dropped by [`drop_login`]. Its name is unique per test run; roles
/// are cluster-global.
async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("drain_{}_{}", parent, Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' IN ROLE {parent}"
    ))
    .execute(pool)
    .await
    .expect("create the login");
    let base = viewer_fixture::database_url_for(pool).await;
    let (scheme_rest, _) = base.split_once('@').expect("the DSN carries credentials");
    let scheme = &scheme_rest[..scheme_rest.find("://").expect("a scheme") + 3];
    let host_path = &base[base.find('@').expect("@") + 1..];
    (
        role.clone(),
        format!("{scheme}{role}:{password}@{host_path}"),
    )
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

fn run_drain(database_url: &str, maintenance_url: Option<&str>) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", database_url)
        .env("RUST_LOG", "warn")
        .current_dir(std::env::temp_dir());
    if let Some(m) = maintenance_url {
        cmd.env("MAINTENANCE_DATABASE_URL", m);
    }
    let out = cmd.output().expect("run drain_jobs");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The binary's three refusals and its two successes, on real logins:
///
/// * unset `MAINTENANCE_DATABASE_URL` (the application login as
///   `DATABASE_URL`): refused, exit 1, nothing drained;
/// * set to the APPLICATION login (unprivileged): refused, exit 1, nothing
///   drained;
/// * set to the maintenance login while another run holds the drain lock:
///   `{"locked": true}`, exit 0, nothing drained;
/// * set to the maintenance login: the job is drained, exit 0.
#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_refuses_without_a_privileged_maintenance_login_and_yields_to_a_held_lock(
    pool: PgPool,
) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    viewer_fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let job = enqueue(
        &pool,
        EpiGraphJob::ClusterGraph {
            resolution: 1.0,
            retain_runs: 5,
        },
    )
    .await;

    // Unset, with a PRIVILEGED login as DATABASE_URL: the fallback would work,
    // which is exactly why it is refused (the refusal's own text, not the
    // resolver's WARN that also names the variable).
    let unset = run_drain(&maint_url, None);
    assert_eq!(unset.code, Some(1), "{}", unset.stderr);
    assert!(
        unset
            .stderr
            .contains("runs only on an explicitly configured maintenance DSN"),
        "{}",
        unset.stderr
    );
    assert_eq!(
        job_state(&pool, job).await.0,
        "pending",
        "the fallback to a privileged DATABASE_URL drained a job"
    );
    let unpriv = run_drain(&app_url, Some(&app_url));
    assert_eq!(unpriv.code, Some(1), "{}", unpriv.stderr);
    assert!(
        unpriv.stderr.contains("does not satisfy epigraph_bypass()"),
        "{}",
        unpriv.stderr
    );
    assert_eq!(
        job_state(&pool, job).await.0,
        "pending",
        "a refused run drained a job"
    );

    // Another run holds the drain lock (a session lock, on its own connection).
    let mut holder = pool.acquire().await.expect("a lock-holding connection");
    let held = epigraph_db::repos::maintenance_lock::try_take(
        &mut holder,
        epigraph_db::repos::maintenance_lock::DRAIN_LOCK_KEY,
    )
    .await
    .expect("take the drain lock");
    assert!(held, "CALIBRATION: the drain lock was already held");
    let locked = run_drain(&app_url, Some(&maint_url));
    assert_eq!(locked.code, Some(0), "{}", locked.stderr);
    let report: serde_json::Value =
        serde_json::from_str(locked.stdout.trim()).expect("a JSON report");
    assert_eq!(report["locked"], true, "{report}");
    assert_eq!(
        job_state(&pool, job).await.0,
        "pending",
        "a run that found the lock held drained a job"
    );
    epigraph_db::repos::maintenance_lock::release(
        &mut holder,
        epigraph_db::repos::maintenance_lock::DRAIN_LOCK_KEY,
    )
    .await
    .expect("release the drain lock");
    drop(holder);

    let ok = run_drain(&app_url, Some(&maint_url));
    assert_eq!(ok.code, Some(0), "{}\n{}", ok.stdout, ok.stderr);
    let report: serde_json::Value = serde_json::from_str(ok.stdout.trim()).expect("a JSON report");
    assert_eq!(report["locked"], false, "{report}");
    assert_eq!(report["completed"], 1, "{report}");
    assert_eq!(job_state(&pool, job).await.0, "completed");

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}
