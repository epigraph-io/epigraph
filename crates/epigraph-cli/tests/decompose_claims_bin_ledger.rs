//! `decompose_claims --singleton-ledger`, driven as the real binary (U040,
//! backlog 68d03c24).
//!
//! The library half of the ledger is covered in `decompose_priority_plan.rs`.
//! These tests cover the binary's own wiring, which the schedule runs: that
//! a normal run and `--apply-plan` hand the ledger to the persist path, that
//! `--plan` and `--dry-run` only read it, that selection is given it unless
//! `--include-judged-atomic` is passed, and the `selection:` line the
//! schedule's prompt reads (`skipped_judged_atomic=`, `eligible=`).
//!
//! No API server is needed: a singleton line submits nothing, so the token
//! (`EPIGRAPH_TOKEN`) is never presented, and the `fixture` provider answers
//! the one parent the tests decompose. Seed migrations may add rows to the
//! undecomposed population, so every assertion is by claim id or is a
//! difference between two runs over the same database.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::path::{Path, PathBuf};
use std::process::Command;

use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_decompose_claims");

/// Two sentences, so the `looks_atomic` filter does not skip it: only a
/// recorded verdict can.
const S_TEXT: &str =
    "The bin-test rotor arm turns freely. Its friction coefficient is about 4e-22 N m s.";

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    #[track_caller]
    fn ok(self) -> Self {
        assert_eq!(
            self.code,
            Some(0),
            "decompose_claims failed\nstdout:\n{}\nstderr:\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    /// Claim ids `--dry-run` listed on stdout (`<id>\t<content>` lines).
    fn listed(&self) -> Vec<Uuid> {
        self.stdout
            .lines()
            .filter_map(|l| l.split('\t').next())
            .filter_map(|id| Uuid::parse_str(id).ok())
            .collect()
    }

    /// The integer after `key=` on stderr's `selection:` lines (`>=` allowed).
    #[track_caller]
    fn selection_count(&self, key: &str) -> usize {
        let line = self
            .stderr
            .lines()
            .filter(|l| l.starts_with("selection:"))
            .find(|l| l.contains(&format!(" {key}=")))
            .unwrap_or_else(|| panic!("no `{key}=` on a selection: line:\n{}", self.stderr));
        let rest = &line[line.find(&format!(" {key}=")).unwrap() + key.len() + 2..];
        rest.trim_start_matches(">=")
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or_else(|e| panic!("`{key}=` is not a count ({e}): {line}"))
    }
}

async fn run(pool: &PgPool, args: &[&str], fixture: Option<&Path>) -> Run {
    let url = viewer_fixture::database_url_for(pool).await;
    let mut cmd = Command::new(BIN);
    // A clean environment: an inherited OPENAI_API_KEY, EPIGRAPH_* or
    // MAINTENANCE_DATABASE_URL would change what the binary does.
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", &url)
        .env("MAINTENANCE_DATABASE_URL", &url)
        .env("RUST_LOG", "warn")
        // Never presented: a singleton line submits nothing.
        .env("EPIGRAPH_TOKEN", "unused-by-singleton-lines")
        .args(args)
        .current_dir(std::env::temp_dir());
    if let Some(f) = fixture {
        cmd.env("DECOMPOSE_FIXTURE_PATH", f);
    }
    let out = cmd.output().expect("run decompose_claims");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn temp_path(stem: &str, ext: &str) -> PathBuf {
    std::env::temp_dir().join(format!("u040-{stem}-{}.{ext}", Uuid::new_v4()))
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'u040-bin-test') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
         VALUES ($1, $2, $3, 0.5) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// A fixture that answers `S_TEXT` with itself: one atom, "already atomic".
fn singleton_fixture() -> PathBuf {
    let path = temp_path("fixture", "json");
    let body = serde_json::json!({ S_TEXT: {"atoms": [S_TEXT], "generality": [0]} });
    std::fs::write(&path, body.to_string()).unwrap();
    path
}

fn ids_file(ids: &[Uuid]) -> PathBuf {
    let path = temp_path("ids", "txt");
    let body: Vec<String> = ids.iter().map(Uuid::to_string).collect();
    std::fs::write(&path, body.join("\n") + "\n").unwrap();
    path
}

/// The ledger holds exactly one verdict, for `id` on exactly `S_TEXT`.
#[track_caller]
fn assert_ledger_holds_only_s(ledger: &Path, id: Uuid) {
    let raw = std::fs::read_to_string(ledger)
        .unwrap_or_else(|e| panic!("no ledger at {}: {e}", ledger.display()));
    let lines: Vec<serde_json::Value> = raw
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 1, "{raw}");
    assert_eq!(lines[0]["kind"], "judged_atomic", "{raw}");
    assert_eq!(lines[0]["claim_id"], id.to_string(), "{raw}");
    assert_eq!(
        lines[0]["content_blake3"],
        blake3::hash(S_TEXT.as_bytes()).to_hex().to_string(),
        "the verdict is keyed on the judged text: {raw}"
    );
}

/// A scheduled run records the model's one-atom verdict in the ledger file;
/// the next run's selection reads that file and passes the parent over, says
/// so on the `selection:` line, and writes nothing to the ledger;
/// `--include-judged-atomic` asks again.
#[sqlx::test(migrations = "../../migrations")]
async fn a_run_records_the_verdict_and_the_next_selection_skips_it(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s_id = seed_claim(&pool, agent, S_TEXT).await;
    let u_id = seed_claim(
        &pool,
        agent,
        "Claim u040-bin has a first part. Claim u040-bin also has a second part.",
    )
    .await;
    let fixture = singleton_fixture();
    let ids = ids_file(&[s_id]);
    let ledger = temp_path("ledger", "jsonl");

    // The decomposing run (only `s` is named, so nothing else reaches the
    // fixture or the API).
    let r = run(
        &pool,
        &[
            "--provider",
            "fixture",
            "--ids-file",
            s(&ids),
            "--singleton-ledger",
            s(&ledger),
        ],
        Some(&fixture),
    )
    .await
    .ok();
    assert!(r.stderr.contains("decompose complete"), "{}", r.stderr);
    assert_ledger_holds_only_s(&ledger, s_id);
    let recorded = std::fs::read(&ledger).unwrap();

    // The next run's selection, as the schedule runs it, plus the count.
    let next = run(
        &pool,
        &[
            "--dry-run",
            "--priority",
            "oldest",
            "--limit",
            "10000",
            "--count-eligible",
            "--singleton-ledger",
            s(&ledger),
        ],
        None,
    )
    .await
    .ok();
    assert!(
        next.listed().contains(&u_id),
        "the untouched compound is still selected:\n{}",
        next.stdout
    );
    assert!(
        !next.listed().contains(&s_id),
        "a parent the model judged atomic was re-selected; it would cost an LLM call every \
         run:\n{}\n{}",
        next.stdout,
        next.stderr
    );
    assert_eq!(next.selection_count("skipped_judged_atomic"), 1);
    assert_eq!(
        std::fs::read(&ledger).unwrap(),
        recorded,
        "--dry-run only reads the ledger"
    );

    // --include-judged-atomic: the same population, the verdict ignored.
    let again = run(
        &pool,
        &[
            "--dry-run",
            "--priority",
            "oldest",
            "--limit",
            "10000",
            "--count-eligible",
            "--singleton-ledger",
            s(&ledger),
            "--include-judged-atomic",
        ],
        None,
    )
    .await
    .ok();
    assert!(again.listed().contains(&s_id), "{}", again.stdout);
    assert_eq!(again.selection_count("skipped_judged_atomic"), 0);
    // The judged parent moved from `skipped_judged_atomic` to `eligible`, and
    // no other column changed: it was never counted as "looks atomic".
    assert_eq!(
        again.selection_count("eligible"),
        next.selection_count("eligible") + 1,
        "{}\n{}",
        next.stderr,
        again.stderr
    );
    assert_eq!(
        again.selection_count("skipped_looks_atomic"),
        next.selection_count("skipped_looks_atomic"),
        "{}\n{}",
        next.stderr,
        again.stderr
    );
    assert!(
        next.stderr.contains("selection: eligible="),
        "{}",
        next.stderr
    );
    assert_eq!(std::fs::read(&ledger).unwrap(), recorded);

    // `--count-eligible` does not change which parents a run processes.
    let plain = run(
        &pool,
        &["--dry-run", "--priority", "oldest", "--limit", "1"],
        None,
    )
    .await
    .ok();
    let counted = run(
        &pool,
        &[
            "--dry-run",
            "--priority",
            "oldest",
            "--limit",
            "1",
            "--count-eligible",
        ],
        None,
    )
    .await
    .ok();
    assert_eq!(plain.stdout, counted.stdout);
    assert_eq!(counted.listed().len(), 1, "{}", counted.stdout);

    for p in [&fixture, &ids, &ledger] {
        std::fs::remove_file(p).ok();
    }
}

/// `--plan` asks the model but records nothing, not even the file; applying
/// the reviewed plan is where the singleton verdict is recorded.
#[sqlx::test(migrations = "../../migrations")]
async fn plan_records_nothing_and_apply_plan_records_the_singleton(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let s_id = seed_claim(&pool, agent, S_TEXT).await;
    let fixture = singleton_fixture();
    let ids = ids_file(&[s_id]);
    let ledger = temp_path("ledger", "jsonl");
    let plan = temp_path("plan", "jsonl");

    let r = run(
        &pool,
        &[
            "--provider",
            "fixture",
            "--ids-file",
            s(&ids),
            "--plan",
            s(&plan),
            "--singleton-ledger",
            s(&ledger),
        ],
        Some(&fixture),
    )
    .await
    .ok();
    let planned = std::fs::read_to_string(&plan).unwrap();
    assert!(
        planned.contains(&s_id.to_string()),
        "the plan carries the singleton line: {planned}\n{}",
        r.stderr
    );
    assert!(
        !ledger.exists(),
        "--plan wrote the ledger before anything was applied"
    );

    run(
        &pool,
        &["--apply-plan", s(&plan), "--singleton-ledger", s(&ledger)],
        None,
    )
    .await
    .ok();
    assert_ledger_holds_only_s(&ledger, s_id);

    let next = run(
        &pool,
        &[
            "--dry-run",
            "--priority",
            "oldest",
            "--limit",
            "10000",
            "--singleton-ledger",
            s(&ledger),
        ],
        None,
    )
    .await
    .ok();
    assert!(!next.listed().contains(&s_id), "{}", next.stdout);

    for p in [&fixture, &ids, &ledger, &plan] {
        std::fs::remove_file(p).ok();
    }
}
