//! `drain_jobs`: drain the job queue once, on the maintenance DSN (operator
//! decision D9, batch W12a). Run by `epigraph-jobs-drain.timer`.
//!
//! Before D9 the API `server` ran the queue forever in-process, on a job pool
//! built from the maintenance DSN. D9 takes that DSN out of every
//! request-serving process, so the queue is drained here instead:
//!
//! 1. refuse unless `MAINTENANCE_DATABASE_URL` is SET (the documented fallback
//!    to `DATABASE_URL` is refused, so the application DSN never runs
//!    maintenance work) and names the same database as `DATABASE_URL`;
//! 2. build one pool on it (45-minute statement timeout, overridable with
//!    `EPIGRAPH_JOB_STATEMENT_TIMEOUT_MS`) and take a dedicated connection;
//! 3. refuse unless that connection satisfies `epigraph_bypass()` (a
//!    non-superuser LOGIN in `epigraph_maintenance` does), whether or not row
//!    security is active yet: a job's bypass viewer on an unprivileged
//!    connection reads and writes nothing, with no error;
//! 4. take the drain's advisory lock on that connection; when another run
//!    holds it, print `{"locked": true}` and exit 0;
//! 5. reap `running` rows older than 90 minutes (a counted attempt: back to
//!    `pending`, or `failed` once the attempts are used up; a one-attempt row,
//!    `max_retries <= 1`, is reset uncounted and re-delivered at most
//!    `MAX_CRASH_REDELIVERIES` times, then failed, see
//!    `PostgresJobQueue::reap_stale_jobs_counting_attempts`), then run
//!    the oldest pending job of a registered type, one at a time, until none
//!    is left or `--max-runtime` (default 50min) has elapsed.
//!
//! Exit codes: 0 drained (or locked); 1 a job failed in this run (retryable
//! or terminal; a failure outranks every other code), or the run could not
//! start; 4 pending jobs of a type this run has no handler for are waiting
//! (`pending_unregistered` in the report, per type; for example
//! `embedding_generation` on an instance whose provider may not write
//! `claims.embedding`; it outranks 3); 3 out of time with work still pending.
//! The report is JSON on stdout. It writes no audit event of its own.
//!
//! An instance that will never register a type clears its exit 4 with
//! `--cancel-pending <TYPE>` (repeatable): the run sets that type's pending
//! jobs `cancelled` (`cancelled_unregistered` in the report) before draining.
//! It refuses, exit 1 with no write, a type this run has a handler for.
//!
//! Usage: `drain_jobs [--max-runtime <DURATION>] [--cancel-pending <TYPE>]...`,
//! where DURATION is seconds or a number with `s`, `m`/`min` or `h`. `DATABASE_URL` and
//! `MAINTENANCE_DATABASE_URL` come from the environment (the unit's 0600
//! EnvironmentFile); neither is ever printed.

use std::sync::Arc;
use std::time::Duration;

use epigraph_api::jobs_drain::{self, DrainReport};

fn usage() -> ! {
    eprintln!(
        "usage: drain_jobs [--max-runtime <DURATION>] [--cancel-pending <TYPE>]...\n\
         Drains the job queue once on MAINTENANCE_DATABASE_URL (which must be set).\n\
         DURATION: seconds, or a number with s, m/min or h (default 50min).\n\
         --cancel-pending: cancel the pending jobs of TYPE first; refused for a type\n\
         this run has a handler for."
    );
    std::process::exit(1);
}

/// `3000`, `3000s`, `50m`, `50min`, `2h`.
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (n, unit) = s.split_at(split);
    let n: u64 = n.parse().ok()?;
    let secs = match unit {
        "" | "s" => n,
        "m" | "min" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        _ => return None,
    };
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// The parsed command line: `--max-runtime` and every `--cancel-pending` type.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    max_runtime: Duration,
    cancel_pending: Vec<String>,
}

/// `None` on any unknown flag, a missing value, or an unparseable duration.
fn parse_args(mut args: impl Iterator<Item = String>) -> Option<Args> {
    let mut parsed = Args {
        max_runtime: jobs_drain::DEFAULT_MAX_RUNTIME,
        cancel_pending: Vec::new(),
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--max-runtime" => parsed.max_runtime = parse_duration(&args.next()?)?,
            "--cancel-pending" => {
                let t = args.next()?;
                if t.trim().is_empty() || t.starts_with("--") {
                    return None;
                }
                if !parsed.cancel_pending.contains(&t) {
                    parsed.cancel_pending.push(t);
                }
            }
            _ => return None,
        }
    }
    Some(parsed)
}

fn fail(msg: &str) -> ! {
    eprintln!("ERROR: drain_jobs: {msg}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let Args {
        max_runtime,
        cancel_pending,
    } = parse_args(std::env::args().skip(1)).unwrap_or_else(|| usage());

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        fail("DATABASE_URL is not set (it names the database the maintenance DSN must match)")
    });
    // The resolver checks the two DSNs name the same database. A fallback to
    // the application DSN is refused: D9 keeps maintenance work off it.
    let (maintenance_url, source) = epigraph_db::maintenance_database_url(&database_url)
        .unwrap_or_else(|e| fail(&format!("the maintenance DSN is unusable: {e}")));
    if source != epigraph_db::MaintenanceDsnSource::Configured {
        fail(
            "MAINTENANCE_DATABASE_URL is not set. drain_jobs runs every job with maintenance \
             authority, so it runs only on an explicitly configured maintenance DSN; the \
             application DSN is never used for this",
        );
    }

    let statement_timeout = std::env::var("EPIGRAPH_JOB_STATEMENT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(jobs_drain::DEFAULT_STATEMENT_TIMEOUT, Duration::from_millis);
    let guc_mode = epigraph_db::SessionGucMode::from_env(
        std::env::var("EPIGRAPH_SESSION_GUC_MODE")
            .unwrap_or_default()
            .as_str(),
    );
    let scoped = epigraph_db::ScopedPool::connect_with_options(
        &maintenance_url,
        guc_mode,
        epigraph_db::ScopedPoolOptions {
            max_connections: 4,
            statement_timeout: Some(statement_timeout),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|e| fail(&format!("could not connect the maintenance pool: {e}")));

    // The dedicated connection: privilege check and lock, held for the run.
    let mut lock_conn = scoped
        .inner()
        .acquire()
        .await
        .unwrap_or_else(|e| fail(&format!("could not acquire a maintenance connection: {e}")))
        .detach();
    let privilege = epigraph_db::probe_maintenance_privilege_conn(&mut lock_conn)
        .await
        .unwrap_or_else(|e| fail(&format!("could not probe the maintenance connection: {e}")));
    if !privilege.bypass {
        fail(
            "the maintenance connection does not satisfy epigraph_bypass() (its login is not a \
             member of epigraph_maintenance); every job would read and write nothing. Refusing",
        );
    }
    let locked = epigraph_db::repos::maintenance_lock::try_take(
        &mut lock_conn,
        epigraph_db::repos::maintenance_lock::DRAIN_LOCK_KEY,
    )
    .await
    .unwrap_or_else(|e| fail(&format!("could not take the drain lock: {e}")));
    if !locked {
        let report = DrainReport {
            locked: true,
            ..DrainReport::default()
        };
        println!(
            "{}",
            serde_json::to_string(&report).unwrap_or_else(|_| "{\"locked\":true}".into())
        );
        return;
    }

    let scoped = Arc::new(scoped);
    let queue = epigraph_jobs::PostgresJobQueue::new(scoped.inner().clone());
    let (embedder, provider) = epigraph_api::embedding_restore::embedding_service_from_env();
    let runner = jobs_drain::build_job_runner(
        Arc::clone(&scoped),
        Arc::new(queue.clone()),
        embedder,
        provider,
    );
    let report = jobs_drain::drain_cancelling(&runner, &queue, max_runtime, &cancel_pending)
        .await
        .unwrap_or_else(|e| fail(&format!("the drain stopped: {e}")));
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    );
    // The lock is released when `lock_conn` closes, at exit.
    drop(lock_conn);
    std::process::exit(report.exit_code());
}

#[cfg(test)]
mod tests {
    use super::{parse_args, parse_duration, Args};
    use std::time::Duration;

    fn args(v: &[&str]) -> Option<Args> {
        parse_args(v.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn cancel_pending_is_repeatable_and_needs_a_type() {
        assert_eq!(
            args(&[
                "--cancel-pending",
                "embedding_generation",
                "--max-runtime",
                "10m",
                "--cancel-pending",
                "legacy_type",
                "--cancel-pending",
                "embedding_generation",
            ]),
            Some(Args {
                max_runtime: Duration::from_secs(600),
                cancel_pending: vec!["embedding_generation".into(), "legacy_type".into()],
            })
        );
        assert_eq!(
            args(&[]).map(|a| a.cancel_pending),
            Some(Vec::<String>::new())
        );
        for bad in [
            &["--cancel-pending"][..],
            &["--cancel-pending", ""],
            &["--cancel-pending", "--max-runtime", "10m"],
            &["--max-runtime"],
            &["--cancel"],
        ] {
            assert_eq!(args(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn max_runtime_accepts_the_unit_file_spellings() {
        assert_eq!(parse_duration("50min"), Some(Duration::from_secs(3000)));
        assert_eq!(parse_duration("50m"), Some(Duration::from_secs(3000)));
        assert_eq!(parse_duration("3000"), Some(Duration::from_secs(3000)));
        assert_eq!(parse_duration("3000s"), Some(Duration::from_secs(3000)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        for bad in ["", "0", "0min", "50 min", "min", "5d", "-5"] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }
    }
}
