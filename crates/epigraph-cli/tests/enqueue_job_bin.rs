//! `enqueue_job` (backlog batch B99), driven as the real process an operator
//! or a timer runs, on real non-superuser LOGIN roles: an `epigraph_app` login
//! as `DATABASE_URL` and an `epigraph_maintenance` login as
//! `MAINTENANCE_DATABASE_URL`, as on a deployment.
//!
//! The contract pinned here, each on a fresh database:
//!
//! * a valid `ClusterGraph` is enqueued, and the row is exactly the row the
//!   queue writes for that job (`EpiGraphJob::into_job`): type, payload,
//!   state, attempt budget, no start/finish/error, and the printed id;
//! * `--unique` twice leaves one pending row; the second run exits 0 and
//!   reports `already_pending`;
//! * the retired `ThemeClusterRebuild`, a misspelled kind, a stray field and a
//!   privatization kind are refused, with nothing written;
//! * `--dry-run` writes nothing, even with a working maintenance DSN;
//! * no configured `MAINTENANCE_DATABASE_URL`: refused, nothing written;
//! * the job can come on stdin.
//!
//! The process environment is CLEARED (and the working directory is the temp
//! dir): the binary loads a `.env`, and an inherited `MAINTENANCE_DATABASE_URL`
//! would point it elsewhere or mask the refusal.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::io::Write as _;
use std::process::{Command, Stdio};

use epigraph_jobs::EpiGraphJob;
use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_enqueue_job");
const CLUSTER: &str = r#"{"ClusterGraph":{"resolution":1.0,"retain_runs":3}}"#;

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("enq_{}_{}", parent, Uuid::new_v4().simple());
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

struct Logins {
    app: (String, String),
    maint: (String, String),
}

impl Logins {
    async fn new(pool: &PgPool) -> Self {
        Self {
            app: create_login(pool, "epigraph_app").await,
            maint: create_login(pool, "epigraph_maintenance").await,
        }
    }

    fn run(&self, args: &[&str]) -> Run {
        run(args, &self.app.1, Some(&self.maint.1), None)
    }

    async fn drop(self, pool: &PgPool) {
        for role in [&self.app.0, &self.maint.0] {
            let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
                .execute(pool)
                .await;
        }
    }
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn report(&self) -> serde_json::Value {
        assert_eq!(self.code, Some(0), "the run failed: {}", self.stderr);
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("stdout is not the JSON report ({e}): {}", self.stdout))
    }

    fn refused(&self, text: &str) {
        assert_ne!(
            self.code,
            Some(0),
            "must be refused; stdout: {}",
            self.stdout
        );
        assert!(
            self.stderr.contains(text),
            "refused for the wrong reason (wanted {text:?}): {}",
            self.stderr
        );
        assert!(self.stdout.trim().is_empty(), "a refusal printed a report");
    }
}

fn run(
    args: &[&str],
    database_url: &str,
    maintenance_url: Option<&str>,
    stdin: Option<&str>,
) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", database_url)
        .env("RUST_LOG", "warn")
        .args(args)
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(m) = maintenance_url {
        cmd.env("MAINTENANCE_DATABASE_URL", m);
    }
    let mut child = cmd.spawn().expect("run the binary");
    {
        let mut pipe = child.stdin.take().expect("stdin");
        if let Some(text) = stdin {
            pipe.write_all(text.as_bytes()).expect("write stdin");
        }
    }
    let out = child.wait_with_output().expect("wait for the binary");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn jobs(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(pool)
        .await
        .expect("count jobs")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_valid_job_is_the_row_the_queue_would_write(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let report = logins.run(&["--job", CLUSTER]).report();
    assert_eq!(report["outcome"], "enqueued");
    let id: Uuid = report["job_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no job id in {report}"));

    let expected = serde_json::from_str::<EpiGraphJob>(CLUSTER)
        .expect("ClusterGraph")
        .into_job()
        .expect("into_job");
    type Row = (
        String,
        serde_json::Value,
        String,
        i32,
        i32,
        i32,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    );
    let row: Row = sqlx::query_as(
        "SELECT job_type, payload, state, retry_count, max_retries, redelivery_count, \
         started_at, completed_at, error_message FROM jobs WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .expect("the printed id names the row");
    assert_eq!(
        row,
        (
            expected.job_type.clone(),
            expected.payload.clone(),
            "pending".to_string(),
            0,
            i32::try_from(expected.max_retries).expect("fits"),
            0,
            None,
            None,
            None,
        )
    );
    assert_eq!(report["job_type"], "cluster_graph");
    assert_eq!(report["payload"], expected.payload);
    assert_eq!(jobs(&pool).await, 1);

    // The same job on stdin.
    let r = run(&[], &logins.app.1, Some(&logins.maint.1), Some(CLUSTER));
    assert_eq!(r.report()["outcome"], "enqueued");
    assert_eq!(jobs(&pool).await, 2);
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn unique_twice_leaves_one_pending_job(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let first = logins.run(&["--job", CLUSTER, "--unique"]).report();
    assert_eq!(first["outcome"], "enqueued");
    let second = logins.run(&["--job", CLUSTER, "--unique"]).report();
    assert_eq!(second["outcome"], "already_pending");
    assert!(second["job_id"].is_null());
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM jobs WHERE job_type = 'cluster_graph' AND state = 'pending'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(pending, 1);
    assert_eq!(jobs(&pool).await, 1);
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_job_writes_nothing(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let ids = r#""plan_id":"00000000-0000-0000-0000-000000000001","dispatched_by":"00000000-0000-0000-0000-000000000002","correlation_id":"c""#;
    let apply = format!("{{\"PrivatizationApply\":{{{ids}}}}}");
    for (job, why) in [
        (
            r#"{"ThemeClusterRebuild":{"max_themes":16,"min_claims_per_theme":5,"skip_if_unchanged":true}}"#,
            "not an EpiGraphJob",
        ),
        (
            r#"{"ClusterGrpah":{"resolution":1.0,"retain_runs":3}}"#,
            "not an EpiGraphJob",
        ),
        (
            r#"{"ClusterGraph":{"resolution":1.0,"retain_runs":3,"keep":9}}"#,
            "has no field",
        ),
        (apply.as_str(), "enqueue_job refuses them"),
        ("not json", "not JSON"),
    ] {
        logins.run(&["--job", job]).refused(why);
        logins.run(&["--job", job, "--unique"]).refused(why);
    }
    assert_eq!(jobs(&pool).await, 0);
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn dry_run_and_an_unset_maintenance_dsn_write_nothing(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let report = logins.run(&["--job", CLUSTER, "--dry-run"]).report();
    assert_eq!(report["outcome"], "dry_run");
    assert!(report["job_id"].is_null());
    assert_eq!(report["job_type"], "cluster_graph");
    let report = logins
        .run(&["--job", CLUSTER, "--dry-run", "--unique"])
        .report();
    assert_eq!(report["outcome"], "dry_run");
    assert_eq!(jobs(&pool).await, 0);

    // No MAINTENANCE_DATABASE_URL: the application DSN is never used.
    run(&["--job", CLUSTER], &logins.app.1, None, None)
        .refused("runs only on an explicitly configured MAINTENANCE_DATABASE_URL");
    assert_eq!(jobs(&pool).await, 0);
    logins.drop(&pool).await;
}
