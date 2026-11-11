//! `backfill-ingest-markers` at production scale: the census, the apply and
//! the reversal each finish within a stated budget on a production-shaped
//! legacy corpus (`tests/fixtures/backfill_ingest_markers_scale.sql`: ~1.25M
//! edges, ~345k agent assertions from ~4.6k agents with one heavy author,
//! ~135k paper assertions, ~5.6k authorships, the production edge indexes,
//! ANALYZEd).
//!
//! Why: on a deployment of that size the planner sizes the legacy chains at
//! one row. The census's chain statement self-joined a chain CTE, planned as
//! a nested loop over two CTE scans, O(n^2) over ~10^5 rows: it never
//! finished. Each apply batch of agent assertions computed and sorted EVERY
//! candidate, then re-ran the per-paper principal aggregate for every row of
//! the batch (~13 s a batch, ~160 batches). These tests are the red line for
//! that class of plan: each statement's plan may not re-run a scan, an
//! aggregate or a CTE per outer row of a nested loop.
//!
//! The production-scale tests are too slow for every CI run, so they are
//! `#[ignore]`d AND gated by an environment variable (a bare `--ignored` run
//! skips them):
//!
//! ```text
//! EPIGRAPH_BACKFILL_SCALE=1 cargo test -p epigraph-cli --locked \
//!     --test operator_backfill_ingest_markers_scale -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `EPIGRAPH_BACKFILL_SCALE` is the corpus scale (`1` = production size; a
//! fraction samples it). Each statement's EXPLAIN, and each phase's wall
//! time, is printed.
//!
//! Two tests are not gated and run in CI on a sampled tenth of the corpus:
//! the one-pass chain census against the pre-rewrite self-join, and the
//! rewritten apply batches' principals against the pre-rewrite `pp` join.

mod viewer_fixture;

use epigraph_cli::operator::backfill_markers::{
    batch_statement, census_statements, Bind, Frame, Kind, Statement,
};
use serde_json::Value;
use sqlx::{Connection, PgPool};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const SCALE_ENV: &str = "EPIGRAPH_BACKFILL_SCALE";
const FIXTURE: &str = include_str!("fixtures/backfill_ingest_markers_scale.sql");

/// The whole read-only census (every statement together).
const CENSUS_BUDGET: Duration = Duration::from_secs(120);
/// One census statement.
const STATEMENT_BUDGET: Duration = Duration::from_secs(60);
/// One apply batch's locking SELECT (default batch size).
const BATCH_BUDGET: Duration = Duration::from_secs(3);
/// The default `--batch-size`.
const BATCH_SIZE: i64 = 2000;
/// The `--apply` run, census included, at the default batch size. It is
/// bounded by its writes, not its reads: ~136k ingest records written one
/// at a time (~2 ms each) and ~460k stamps (2,000-row UPDATEs through the
/// edge triggers); about 6.5 minutes on a build host.
const APPLY_BUDGET: Duration = Duration::from_secs(600);
/// The reversal of that run (`--apply`).
const REVERSE_BUDGET: Duration = Duration::from_secs(120);

fn scale() -> Option<String> {
    let s = std::env::var(SCALE_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty());
    if s.is_none() {
        eprintln!("skipped: set {SCALE_ENV}=1 to run the production-scale backfill tests");
    }
    s
}

/// The corpus, ANALYZEd; returns the run's cutoff (after every legacy edge).
async fn seed(pool: &PgPool, scale: &str) -> String {
    let t = Instant::now();
    let mut conn = pool.acquire().await.expect("conn");
    sqlx::query("SELECT set_config('fx.scale', $1, false)")
        .bind(scale)
        .execute(&mut *conn)
        .await
        .expect("scale");
    sqlx::raw_sql(FIXTURE)
        .execute(&mut *conn)
        .await
        .expect("fixture");
    let shape: Vec<(String, i64)> = sqlx::query_as(
        "SELECT e.source_type || ' -' || e.relationship || '-> ' || e.target_type, count(*) \
           FROM edges e GROUP BY 1 ORDER BY 2 DESC",
    )
    .fetch_all(&mut *conn)
    .await
    .expect("shape");
    let total: i64 = shape.iter().map(|r| r.1).sum();
    eprintln!(
        "FIXTURE\tscale={scale}\tedges={total}\tseeded_in={:?}",
        t.elapsed()
    );
    for (k, n) in &shape {
        eprintln!("FIXTURE-SHAPE\t{k}\t{n}");
    }
    let top: Vec<i64> = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_type = 'agent' AND relationship = 'asserts' \
            AND target_type = 'claim' GROUP BY source_id ORDER BY 1 DESC LIMIT 5",
    )
    .fetch_all(&mut *conn)
    .await
    .expect("top");
    eprintln!("FIXTURE-SHAPE\tagent asserts per agent, top 5: {top:?}");
    sqlx::query_scalar(
        "SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("cutoff")
}

/// The fixture's signers (md5-derived ids): ingest signers 1..3, the
/// attestation identity 4.
async fn signers(pool: &PgPool) -> (Vec<Uuid>, Vec<Uuid>) {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT md5('bf-signer-' || i)::uuid FROM generate_series(1, 4) i ORDER BY i",
    )
    .fetch_all(pool)
    .await
    .expect("signers");
    (ids[..3].to_vec(), ids[3..].to_vec())
}

/// The node types whose re-execution per outer row is a scan or a pass over
/// a set: on a `Nested Loop`'s inner side they make the loop O(outer x
/// set). An inner index lookup is the linear kind, and a `Materialize` or
/// `Memoize` is computed once.
const RESCANNED: [&str; 9] = [
    "Aggregate",
    "Sort",
    "Incremental Sort",
    "WindowAgg",
    "Gather",
    "Gather Merge",
    "Seq Scan",
    "Hash Join",
    "Merge Join",
];

/// The node types of `plan`'s subtree that run again on every rescan of it
/// (not below a `Materialize` / `Memoize`).
fn rerun_types(plan: &Value, out: &mut Vec<String>) {
    let t = plan.get("Node Type").and_then(Value::as_str).unwrap_or("");
    if t == "Materialize" || t == "Memoize" {
        return;
    }
    out.push(t.to_string());
    for k in plan
        .get("Plans")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        rerun_types(k, out);
    }
}

/// Every `Nested Loop` in a JSON plan that scans a CTE as its inner side
/// (the production plan: a nested loop over two CTE scans, O(n^2)) or
/// re-runs a [`RESCANNED`] node per outer row (one re-running an aggregate
/// per row). Both came from a rows=1 estimate and never finished on a
/// production corpus.
fn nested_loop_rescans(plan: &Value, out: &mut Vec<String>) {
    let kids: Vec<Value> = plan
        .get("Plans")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if plan.get("Node Type").and_then(Value::as_str) == Some("Nested Loop") {
        for k in &kids {
            if k.get("Parent Relationship").and_then(Value::as_str) != Some("Inner") {
                continue;
            }
            if k.get("Node Type").and_then(Value::as_str) == Some("CTE Scan") {
                out.push("Nested Loop over a CTE Scan".to_string());
            }
            let mut types = Vec::new();
            rerun_types(k, &mut types);
            for t in types.iter().filter(|t| RESCANNED.contains(&t.as_str())) {
                out.push(format!("Nested Loop re-runs a {t} per outer row"));
            }
        }
    }
    for k in &kids {
        nested_loop_rescans(k, out);
    }
}

fn bind<'q>(
    mut q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    binds: &[Bind],
    legacy: Uuid,
    ingest: &'q [Uuid],
    attest: &'q [Uuid],
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    for b in binds {
        q = match b {
            Bind::Legacy => q.bind(legacy),
            Bind::Ingest => q.bind(ingest),
            Bind::Attestation => q.bind(attest),
            Bind::After => q.bind(Uuid::nil()),
            Bind::Limit => q.bind(BATCH_SIZE),
        };
    }
    q
}

/// `st`'s plan, printed; returns its [`nested_loop_rescans`] (none
/// expected). With `analyze` it runs, and the actual rows and times print.
async fn explain(
    tx: &mut sqlx::PgConnection,
    st: &Statement,
    analyze: bool,
    legacy: Uuid,
    ingest: &[Uuid],
    attest: &[Uuid],
) -> Vec<String> {
    let plan: Value = {
        let sql = format!("EXPLAIN (FORMAT JSON) {}", st.sql);
        let row = bind(sqlx::query(&sql), st.binds, legacy, ingest, attest)
            .fetch_one(&mut *tx)
            .await
            .expect("explain");
        sqlx::Row::get(&row, 0)
    };
    let mut bad = Vec::new();
    nested_loop_rescans(&plan[0]["Plan"], &mut bad);
    let sql = format!(
        "EXPLAIN ({}) {}",
        if analyze {
            "ANALYZE, BUFFERS OFF"
        } else {
            "COSTS ON"
        },
        st.sql
    );
    eprintln!("EXPLAIN\t{}", st.name);
    for r in bind(sqlx::query(&sql), st.binds, legacy, ingest, attest)
        .fetch_all(&mut *tx)
        .await
        .expect("explain text")
    {
        eprintln!("  {}", sqlx::Row::get::<String, _>(&r, 0));
    }
    bad
}

/// Each census statement on its own, read-only under its own
/// `statement_timeout`: its EXPLAIN (no nested loop re-running a scan, an
/// aggregate or a CTE per row), then its wall time (within
/// [`STATEMENT_BUDGET`]); then one apply batch of each kind, analyzed and
/// rolled back (within [`BATCH_BUDGET`], same plan rule); then the census as
/// the binary runs it (within [`CENSUS_BUDGET`]).
#[ignore = "production scale: set EPIGRAPH_BACKFILL_SCALE=1 and pass --ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn every_census_statement_finishes_at_production_scale(pool: PgPool) {
    let Some(scale) = scale() else { return };
    let cutoff = seed(&pool, &scale).await;
    let written_before =
        epigraph_cli::operator::backfill_markers::parse_written_before(&cutoff).expect("cutoff");
    let frame = Frame::new(Some(&written_before));
    let url = fixture::database_url_for(&pool).await;
    let mut conn = sqlx::PgConnection::connect(&url).await.expect("connect");
    let (ingest, attest) = signers(&pool).await;
    let legacy = Uuid::nil();
    let budget = format!("{}s", STATEMENT_BUDGET.as_secs());
    let mut failures = Vec::new();
    for st in census_statements(&frame) {
        let mut tx = conn.begin().await.expect("begin");
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await
            .expect("read only");
        sqlx::query("SELECT set_config('statement_timeout', $1, true)")
            .bind(&budget)
            .execute(&mut *tx)
            .await
            .expect("timeout");
        let bad = explain(&mut tx, &st, false, legacy, &ingest, &attest).await;
        let t = Instant::now();
        let ran = bind(sqlx::query(&st.sql), st.binds, legacy, &ingest, &attest)
            .fetch_all(&mut *tx)
            .await;
        let took = t.elapsed();
        tx.rollback().await.ok();
        match ran {
            Ok(_) => eprintln!("STATEMENT\t{}\t{took:?}", st.name),
            Err(e) => {
                eprintln!("STATEMENT\t{}\tFAILED after {took:?}: {e}", st.name);
                failures.push(format!("{} failed after {took:?}: {e}", st.name));
            }
        }
        if took > STATEMENT_BUDGET {
            failures.push(format!("{} took {took:?} > {STATEMENT_BUDGET:?}", st.name));
        }
        for b in bad {
            failures.push(format!("{}: {b}", st.name));
        }
    }
    // One apply batch of each kind, locked and rolled back (in the order a
    // run reaches them, so each kind's candidates are as the run finds them).
    for kind in Kind::ALL {
        let st = batch_statement(&frame, kind);
        let mut tx = conn.begin().await.expect("begin");
        sqlx::query("SELECT set_config('statement_timeout', $1, true)")
            .bind(&budget)
            .execute(&mut *tx)
            .await
            .expect("timeout");
        let t = Instant::now();
        let bad = explain(&mut tx, &st, true, legacy, &ingest, &attest).await;
        let took = t.elapsed();
        tx.rollback().await.ok();
        eprintln!("BATCH\t{}\t{took:?} (plan, then the analyzed run)", st.name);
        if took > BATCH_BUDGET {
            failures.push(format!("{} took {took:?} > {BATCH_BUDGET:?}", st.name));
        }
        for b in bad {
            failures.push(format!("{}: {b}", st.name));
        }
    }
    // The census as the binary runs it.
    let classes = classify(&ingest, &attest);
    let t = Instant::now();
    let r = run_op(
        &url,
        &dry_run_args(&cutoff, &format!("{}s", CENSUS_BUDGET.as_secs()), &classes),
    );
    let took = t.elapsed();
    eprintln!("CENSUS\t{took:?}\texit={}", r.0);
    for l in r.1.lines() {
        eprintln!("  {l}");
    }
    if r.0 != 0 || took > CENSUS_BUDGET {
        failures.push(format!("census exit {} after {took:?}: {}", r.0, r.2));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

fn classify(ingest: &[Uuid], attest: &[Uuid]) -> Vec<String> {
    let mut v = Vec::new();
    for s in ingest {
        v.extend(["--ingest-signer".to_string(), s.to_string()]);
    }
    for s in attest {
        v.extend(["--attestation-signer".to_string(), s.to_string()]);
    }
    v
}

fn dry_run_args(cutoff: &str, timeout: &str, classes: &[String]) -> Vec<String> {
    let mut v: Vec<String> = [
        "backfill-ingest-markers",
        "--written-before",
        cutoff,
        "--statement-timeout",
        timeout,
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    v.extend(classes.iter().cloned());
    v
}

/// (exit code, stdout, stderr)
fn run_op(url: &str, args: &[String]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, url)
        .output()
        .expect("spawn epigraph-operator");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn field(stdout: &str, prefix: &str) -> u64 {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(prefix))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("no {prefix} line in:\n{stdout}"))
}

fn register_legacy(url: &str) {
    let reg = run_op(
        url,
        &[
            "register-system-agent",
            "--role",
            "legacy-ingest",
            "--create-agent",
            "--reason",
            "the legacy ingest-marker backfill principal",
            "--apply",
        ]
        .map(String::from),
    );
    assert_eq!(reg.0, 0, "{}\n{}", reg.1, reg.2);
}

/// `backfill-ingest-markers --apply` of `total` edges under `cutoff`.
fn apply_args(
    cutoff: &str,
    classes: &[String],
    total: u64,
    manifest: &std::path::Path,
) -> Vec<String> {
    let mut args = dry_run_args(cutoff, &format!("{}s", CENSUS_BUDGET.as_secs()), classes);
    args.extend(
        [
            "--apply",
            "--confirm-count",
            &total.to_string(),
            "--manifest-out",
            manifest.to_str().expect("utf-8 path"),
            "--ruling",
            "scale test",
            "--reason",
            "scale test",
        ]
        .map(String::from),
    );
    args
}

/// The edges a run reports stamped, every kind.
fn stamped_of(stdout: &str) -> u64 {
    stdout
        .lines()
        .filter_map(|l| l.strip_prefix("STAMPED\t"))
        .map(|l| l.rsplit('\t').next().unwrap().parse::<u64>().unwrap())
        .sum()
}

fn scratch_manifest() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("operator-backfill-scale-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("scratch");
    dir.join("manifest.jsonl")
}

/// The census (dry run), the apply in default-size batches and the
/// reversal, each through the binary and within its budget; the apply stamps
/// exactly the census's total and the reversal leaves no stamp and no record.
#[ignore = "production scale: set EPIGRAPH_BACKFILL_SCALE=1 and pass --ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_backfill_and_its_reversal_finish_at_production_scale(pool: PgPool) {
    let Some(scale) = scale() else { return };
    let cutoff = seed(&pool, &scale).await;
    let url = fixture::database_url_for(&pool).await;
    let (ingest, attest) = signers(&pool).await;
    let classes = classify(&ingest, &attest);
    register_legacy(&url);

    let t = Instant::now();
    let dry = run_op(
        &url,
        &dry_run_args(&cutoff, &format!("{}s", CENSUS_BUDGET.as_secs()), &classes),
    );
    let took = t.elapsed();
    eprintln!("DRY-RUN\t{took:?}\texit={}\n{}", dry.0, dry.1);
    assert_eq!(dry.0, 0, "{}\n{}", dry.1, dry.2);
    assert!(took < CENSUS_BUDGET, "dry run took {took:?}");
    let total = field(&dry.1, "TOTAL\tedges_to_stamp=");
    assert!(total > 0);

    let manifest = scratch_manifest();
    let args = apply_args(&cutoff, &classes, total, &manifest);
    let t = Instant::now();
    let applied = run_op(&url, &args);
    let took = t.elapsed();
    eprintln!("APPLY\t{took:?}\texit={}\n{}", applied.0, applied.1);
    assert_eq!(applied.0, 0, "{}\n{}", applied.1, applied.2);
    assert!(took < APPLY_BUDGET, "apply took {took:?}");
    assert_eq!(stamped_of(&applied.1), total, "{}", applied.1);
    let records = field(&applied.1, "CREATION-RECORDS-WRITTEN\t")
        + field(&applied.1, "NON-CREATION-RECORDS-WRITTEN\t");
    let in_db: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE labels @> ARRAY['epigraph:ingest_written']",
    )
    .fetch_one(&pool)
    .await
    .expect("stamped");
    assert_eq!(u64::try_from(in_db).unwrap(), total);

    let t = Instant::now();
    let rev = run_op(
        &url,
        &[
            "reverse-ingest-markers",
            "--manifest",
            manifest.to_str().unwrap(),
            "--apply",
        ]
        .map(String::from),
    );
    let took = t.elapsed();
    eprintln!("REVERSE\t{took:?}\texit={}\n{}", rev.0, rev.1);
    assert_eq!(rev.0, 0, "{}\n{}", rev.1, rev.2);
    assert!(took < REVERSE_BUDGET, "reversal took {took:?}");
    assert!(
        rev.1.contains(&format!(
            "REVERSED\tedges_restored={total}\tedges_held=0\trecords_deleted={records}\trecords_held=0"
        )),
        "{}",
        rev.1
    );
    let left: (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE labels @> ARRAY['epigraph:ingest_written']), \
                count(*) FILTER (WHERE relationship = $1) FROM edges",
    )
    .bind(epigraph_db::INGEST_RECORD_RELATIONSHIP)
    .fetch_one(&pool)
    .await
    .expect("left");
    assert_eq!(left, (0, 0));
}

/// The pre-rewrite SQL fragments under cutoff `cut` (the oracles' own
/// copy: `legacy(x)`, `authored(x)`, `paper_asserts(x)`, the `pp` CTE over
/// the ingest signers `$2`).
struct Old {
    cut: String,
}

impl Old {
    fn legacy(&self, x: &str) -> String {
        format!(
            "NOT ({x}.properties ? '{}') AND {x}.created_at < '{}'::timestamptz",
            epigraph_db::ingest_written::INGEST_WRITTEN_PROPERTY,
            self.cut
        )
    }

    fn au(x: &str) -> String {
        format!(
            "{x}.source_type = 'agent' AND {x}.relationship = 'authored' \
             AND {x}.target_type = 'paper'"
        )
    }

    fn pas(x: &str) -> String {
        format!(
            "{x}.source_type = 'paper' AND {x}.relationship = 'asserts' \
             AND {x}.target_type = 'claim'"
        )
    }

    fn pp(&self) -> String {
        format!(
            "pp AS (SELECT x.paper, count(DISTINCT x.sid) AS n, \
                           array_agg(DISTINCT x.sid ORDER BY x.sid) AS sids \
                      FROM (SELECT s.source_id AS paper, s.signer_id AS sid FROM edges s \
                             WHERE {} AND {} AND s.signer_id = ANY($2::uuid[]) \
                            UNION ALL \
                            SELECT s.target_id, s.signer_id FROM edges s \
                             WHERE {} AND {} AND s.signer_id = ANY($2::uuid[])) x \
                     GROUP BY x.paper)",
            Self::pas("s"),
            self.legacy("s"),
            Self::au("s"),
            self.legacy("s"),
        )
    }

    /// `FROM ... WHERE ...` of the legacy chains agent assertion `e` closes.
    fn chain_from(&self) -> String {
        format!(
            "FROM edges ea JOIN edges pa ON pa.source_id = ea.target_id \
              WHERE ea.source_id = e.source_id AND {} AND {} \
                AND {} AND {} AND pa.target_id = e.target_id",
            Self::au("ea"),
            self.legacy("ea"),
            Self::pas("pa"),
            self.legacy("pa"),
        )
    }
}

const OLD_CHAIN_ORDER: &str = "((ea.valid_to IS NULL OR ea.valid_to > now()) \
                               AND (pa.valid_to IS NULL OR pa.valid_to > now())) DESC, \
                              pa.created_at, pa.id, ea.created_at, ea.id";

/// The chain census as it was before the one-pass rewrite: `pr` (every
/// chain with its principal) joined with its own first chains (`ch`), and
/// grouped by agent assertion. Kept here only as the oracle; the test runs
/// it with nested loops off, the plan that makes it finish.
fn self_join_chains(cut: &str) -> String {
    use epigraph_db::ingest_written::INGEST_WRITTEN_LABEL;
    let old = Old {
        cut: cut.to_string(),
    };
    let pp = old.pp();
    let cand = format!(
        "(e.source_type = 'agent' AND e.relationship = 'asserts' AND e.target_type = 'claim' \
          AND COALESCE(e.properties ->> 'source', '') <> 'workflow_attribution' \
          AND EXISTS (SELECT 1 {}) \
          AND {} AND NOT (e.labels @> ARRAY['{INGEST_WRITTEN_LABEL}']::text[]))",
        old.chain_from(),
        old.legacy("e"),
    );
    let legacy = |x: &str| old.legacy(x);
    let au = Old::au;
    let pas = Old::pas;
    let order = OLD_CHAIN_ORDER;
    format!(
        "WITH {pp}, \
         tri AS (SELECT e.id AS e, ea.target_id AS paper, \
                        row_number() OVER (PARTITION BY e.id ORDER BY {order}) AS k \
                   FROM edges e JOIN edges ea ON ea.source_id = e.source_id \
                   JOIN edges pa ON pa.source_id = ea.target_id AND pa.target_id = e.target_id \
                  WHERE {cand} AND {} AND {} AND {} AND {}), \
         pr AS (SELECT tri.e, tri.k, \
                       COALESCE(CASE WHEN pp.n = 1 THEN pp.sids[1] END, $1::uuid) AS principal \
                  FROM tri LEFT JOIN pp ON pp.paper = tri.paper), \
         ch AS (SELECT pr.e, pr.principal FROM pr WHERE pr.k = 1) \
         SELECT (SELECT count(*) FROM pr), \
                (SELECT count(*) FROM pr JOIN ch ON ch.e = pr.e \
                  WHERE pr.principal <> ch.principal), \
                (SELECT count(*) FROM (SELECT pr.e FROM pr GROUP BY pr.e \
                                        HAVING count(DISTINCT pr.principal) > 1) m)",
        au("ea"),
        legacy("ea"),
        pas("pa"),
        legacy("pa"),
    )
}

/// The one-pass chain census counts exactly what the self-join counted, on
/// a sampled production-shaped corpus (a tenth: every paper size, heavy and
/// shared-claim chains, conflicting and retracted legs) where agent
/// assertions close chains of two principals. Not gated: it runs in CI.
#[sqlx::test(migrations = "../../migrations")]
async fn the_one_pass_chain_census_counts_what_the_self_join_counted(pool: PgPool) {
    use epigraph_cli::operator::backfill_markers::{census, parse_written_before, Options};
    let cutoff = seed(&pool, "0.1").await;
    let (ingest, attest) = signers(&pool).await;
    let url = fixture::database_url_for(&pool).await;
    let mut conn = sqlx::PgConnection::connect(&url).await.expect("connect");
    let written_before = parse_written_before(&cutoff).expect("cutoff");
    let o = Options {
        apply: false,
        confirm_count: None,
        written_before: Some(written_before),
        ruling: String::new(),
        reason: String::new(),
        manifest_out: None,
        attestation_signers: attest.clone(),
        ingest_signers: ingest.clone(),
        batch_size: 2000,
        max_batches: None,
        lock_timeout: "5s".into(),
        statement_timeout: "5min".into(),
        creation_records: true,
    };
    let c = census(&mut conn, &o).await.expect("census");
    let cut = epigraph_cli::operator::backfill_markers::cutoff_text(&written_before);
    let mut tx = conn.begin().await.expect("begin");
    sqlx::query("SET LOCAL enable_nestloop = off")
        .execute(&mut *tx)
        .await
        .expect("oracle plan");
    let oracle: (i64, i64, i64) = sqlx::query_as(&self_join_chains(&cut))
        .bind(c.legacy_principal.unwrap_or(Uuid::nil()))
        .bind(&ingest)
        .fetch_one(&mut *tx)
        .await
        .expect("oracle");
    tx.rollback().await.expect("rollback");
    eprintln!(
        "CHAINS one-pass=({}, {}, {}) self-join={oracle:?}",
        c.chains, c.chains_on_another_principal, c.agent_asserts_multi_principal
    );
    assert!(
        oracle.0 > 10_000 && oracle.1 > 0 && oracle.2 > 0,
        "the sample must hold chains on another principal: {oracle:?}"
    );
    assert_eq!(
        (
            c.chains,
            c.chains_on_another_principal,
            c.agent_asserts_multi_principal
        ),
        oracle
    );
}

/// Every stamped edge's `by` against the pre-rewrite principal: the `pp`
/// principal of the edge's paper (its own, or for an agent assertion the
/// paper of its first chain by the chain order), legacy `$1`. One row:
/// (stamped edges, those whose `by` differs).
fn pre_rewrite_principals(cut: &str) -> String {
    use epigraph_db::ingest_written::INGEST_WRITTEN_BY_LABEL_PREFIX;
    let old = Old {
        cut: cut.to_string(),
    };
    format!(
        "WITH {pp}, \
         s AS (SELECT e.id, substr(l.l, {skip}) AS by, \
                      CASE WHEN e.relationship = 'authored' THEN e.target_id \
                           WHEN e.source_type = 'paper' THEN e.source_id \
                           ELSE (SELECT ea.target_id {chain} \
                                  ORDER BY {OLD_CHAIN_ORDER} LIMIT 1) END AS paper \
                 FROM edges e CROSS JOIN LATERAL unnest(e.labels) l(l) \
                WHERE e.relationship IN ('authored', 'asserts') \
                  AND l.l LIKE '{INGEST_WRITTEN_BY_LABEL_PREFIX}%') \
         SELECT count(*), \
                count(*) FILTER (WHERE s.by <> \
                    COALESCE(CASE WHEN pp.n = 1 THEN pp.sids[1] END, $1::uuid)::text) \
           FROM s LEFT JOIN pp ON pp.paper = s.paper",
        pp = old.pp(),
        skip = INGEST_WRITTEN_BY_LABEL_PREFIX.len() + 1,
        chain = old.chain_from(),
    )
}

/// The rewritten apply batches (the principal by a window over the batch,
/// the chain test as a per-row lookup) stamp every edge of the sampled
/// production-shaped corpus with the principal the pre-rewrite formula
/// gives it: its paper's `pp` principal, an agent assertion's through its
/// first chain (the sample holds agent assertions closing chains of two
/// principals). Not gated: it runs in CI.
#[sqlx::test(migrations = "../../migrations")]
async fn the_rewritten_batches_stamp_what_the_pp_join_stamped(pool: PgPool) {
    let cutoff = seed(&pool, "0.1").await;
    let (ingest, attest) = signers(&pool).await;
    let classes = classify(&ingest, &attest);
    let url = fixture::database_url_for(&pool).await;
    register_legacy(&url);
    let dry = run_op(&url, &dry_run_args(&cutoff, "5min", &classes));
    assert_eq!(dry.0, 0, "{}\n{}", dry.1, dry.2);
    let total = field(&dry.1, "TOTAL\tedges_to_stamp=");
    let applied = run_op(
        &url,
        &apply_args(&cutoff, &classes, total, &scratch_manifest()),
    );
    assert_eq!(applied.0, 0, "{}\n{}", applied.1, applied.2);
    assert_eq!(stamped_of(&applied.1), total, "{}", applied.1);
    let legacy: Uuid =
        sqlx::query_scalar("SELECT agent_id FROM system_agents WHERE role = 'legacy-ingest'")
            .fetch_one(&pool)
            .await
            .expect("legacy principal");
    let written_before =
        epigraph_cli::operator::backfill_markers::parse_written_before(&cutoff).expect("cutoff");
    let cut = epigraph_cli::operator::backfill_markers::cutoff_text(&written_before);
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL enable_nestloop = off")
        .execute(&mut *tx)
        .await
        .expect("oracle plan");
    let (n, wrong): (i64, i64) = sqlx::query_as(&pre_rewrite_principals(&cut))
        .bind(legacy)
        .bind(&ingest)
        .fetch_one(&mut *tx)
        .await
        .expect("oracle");
    tx.rollback().await.expect("rollback");
    eprintln!("PRINCIPALS stamped={n} differing={wrong} (of {total})");
    assert_eq!((u64::try_from(n).unwrap(), wrong), (total, 0));
}
