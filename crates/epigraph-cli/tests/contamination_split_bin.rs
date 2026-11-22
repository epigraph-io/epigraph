//! ea6eb305: `contamination_split` runs the protocol's post-sweep split
//! (`tests/cross_source/prompts_v1.md` §2 step 3) from the command line.
//!
//! The binary tests run the REAL executable on fixture files with both DSN
//! variables removed, so file mode is pinned as never touching a database.
//! The DB test pins `--run-id`'s read of one run's `match_candidates` rows.

#![cfg(feature = "db")]

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use uuid::Uuid;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_contamination_split"))
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("contamination-split-bin-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .output()
        .expect("spawn contamination_split")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The ledger snapshot shape `calibrate_matcher --contamination-ledger`
/// writes: header fields plus `entries` in canonical `claim_a < claim_b`
/// order.
fn ledger_fixture(dir: &Path, decided: &[(Uuid, Uuid)]) -> PathBuf {
    let entries: Vec<Value> = decided
        .iter()
        .map(|&(a, b)| {
            json!({
                "claim_a": a.min(b), "claim_b": a.max(b),
                "status": "rejected", "verifier_verdict": "distinct",
                "decided_at": null, "reason": "verifier_verdict",
            })
        })
        .collect();
    let path = dir.join("contamination_ledger.json");
    let snapshot = json!({
        "protocol": "tests/cross_source/prompts_v1.md",
        "generated_at": "2026-11-22T00:00:00Z",
        "rule": "fixture",
        "contaminated": entries.len(),
        "entries": entries,
    });
    std::fs::write(&path, snapshot.to_string()).unwrap();
    path
}

/// A sweep of three pairs against a one-entry ledger: the decided pair is
/// listed REVERSED (claim_b first), so a split that compared orientation
/// literally would call it clean. Rows keep their extra fields, the counts go
/// to stdout and `split_counts.json`, and a re-run into the same directory is
/// refused without touching the archived result.
#[test]
fn splits_fixture_files_without_a_database() {
    let dir = scratch_dir();
    let (x, y, z, w) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let ledger = ledger_fixture(&dir, &[(x, y)]);
    let decided_reversed = json!({
        "claim_a": x.max(y), "claim_b": x.min(y),
        "status": "rejected", "verifier_verdict": "distinct", "score": 0.7,
    });
    let clean_answered = json!({
        "claim_a": x, "claim_b": z,
        "status": "pending", "verifier_verdict": "same", "score": 0.8,
    });
    let clean_unanswered = json!({
        "claim_a": z, "claim_b": w,
        "status": "pending", "verifier_verdict": null, "score": 0.6,
    });
    let pairs = dir.join("run_pairs.json");
    std::fs::write(
        &pairs,
        json!([clean_answered, decided_reversed, clean_unanswered]).to_string(),
    )
    .unwrap();
    let out_dir = dir.join("split");
    let args = [
        "--ledger",
        ledger.to_str().unwrap(),
        "--pairs",
        pairs.to_str().unwrap(),
        "--out-dir",
        out_dir.to_str().unwrap(),
    ];

    let out = run(&args);
    assert!(
        out.status.success(),
        "exit {:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let expected_counts = json!({
        "ledger_entries": 1, "pairs": 3, "clean": 2, "contaminated": 1,
        "clean_with_verifier_verdict": 1,
    });
    let stdout: Value = serde_json::from_slice(&out.stdout).expect("one JSON line on stdout");
    assert_eq!(stdout, expected_counts);
    assert_eq!(
        read_json(&out_dir.join("split_counts.json")),
        expected_counts
    );
    assert_eq!(
        read_json(&out_dir.join("contaminated_pairs.json")),
        json!([decided_reversed])
    );
    assert_eq!(
        read_json(&out_dir.join("clean_pairs.json")),
        json!([clean_answered, clean_unanswered])
    );

    let before = std::fs::read_to_string(out_dir.join("clean_pairs.json")).unwrap();
    let rerun = run(&args);
    assert!(!rerun.status.success(), "a re-run must not overwrite");
    assert_eq!(
        std::fs::read_to_string(out_dir.join("clean_pairs.json")).unwrap(),
        before
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Exactly one pair source: neither, or both, is a usage error, reported
/// before any file or database is touched.
#[test]
fn requires_exactly_one_of_pairs_or_run_id() {
    let dir = scratch_dir();
    let ledger = ledger_fixture(&dir, &[]);
    let out_dir = dir.join("split");
    let neither = run(&[
        "--ledger",
        ledger.to_str().unwrap(),
        "--out-dir",
        out_dir.to_str().unwrap(),
    ]);
    assert!(!neither.status.success());
    let both = run(&[
        "--ledger",
        ledger.to_str().unwrap(),
        "--pairs",
        "p.json",
        "--run-id",
        &Uuid::new_v4().to_string(),
        "--out-dir",
        out_dir.to_str().unwrap(),
    ]);
    assert!(!both.status.success());
    assert!(!out_dir.exists(), "a usage error must write nothing");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `--run-id` into a directory that already holds a split is refused BEFORE
/// any database work, so it never adds a run_pairs.json to an archived split.
/// Both DSN variables are removed: a binary that fetched first would fail on
/// the connection instead of naming the existing file.
#[test]
fn run_id_into_an_existing_split_is_refused_before_the_fetch() {
    let dir = scratch_dir();
    let ledger = ledger_fixture(&dir, &[]);
    let out_dir = dir.join("split");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("clean_pairs.json"), "[]").unwrap();
    let out = run(&[
        "--ledger",
        ledger.to_str().unwrap(),
        "--run-id",
        &Uuid::new_v4().to_string(),
        "--out-dir",
        out_dir.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("already exists"),
        "expected the overwrite refusal, got: {err}"
    );
    assert!(!out_dir.join("run_pairs.json").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `--run-id` reads exactly the rows stamped with that run, with the fields
/// §2 step 4 needs, and nothing from another run.
#[sqlx::test(migrations = "../../migrations")]
async fn fetch_run_pairs_reads_only_the_runs_rows(pool: sqlx::PgPool) {
    use epigraph_cli::contamination_split::fetch_run_pairs;

    let agent = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(agent)
    .execute(&pool)
    .await
    .expect("insert agent");
    let mut claims = Vec::new();
    for _ in 0..4 {
        let id = Uuid::new_v4();
        let content = format!("claim {id}");
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
             VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
        )
        .bind(id)
        .bind(&content)
        .bind(agent)
        .execute(&pool)
        .await
        .expect("insert claim");
        claims.push(id);
    }
    let (run, other_run) = (Uuid::new_v4(), Uuid::new_v4());
    let rows = [
        (claims[0], claims[1], run, "rejected", Some("distinct")),
        (claims[1], claims[2], run, "pending", None),
        (claims[2], claims[3], other_run, "rejected", Some("same")),
    ];
    for (a, b, r, status, verdict) in rows {
        sqlx::query(
            "INSERT INTO match_candidates
                 (claim_a, claim_b, score, features, verifier_verdict, status, matcher_run_id)
             VALUES ($1, $2, 0.5, '{}'::jsonb, $3, $4, $5)",
        )
        .bind(a.min(b))
        .bind(a.max(b))
        .bind(verdict)
        .bind(status)
        .bind(r)
        .execute(&pool)
        .await
        .expect("insert candidate");
    }

    let got = fetch_run_pairs(&pool, run).await.expect("fetch");
    let mut want: Vec<(Uuid, Uuid, Value, Value)> = vec![
        (
            claims[0].min(claims[1]),
            claims[0].max(claims[1]),
            json!("rejected"),
            json!("distinct"),
        ),
        (
            claims[1].min(claims[2]),
            claims[1].max(claims[2]),
            json!("pending"),
            Value::Null,
        ),
    ];
    want.sort_by_key(|w| (w.0, w.1));
    let got: Vec<(Uuid, Uuid, Value, Value)> = got
        .into_iter()
        .map(|p| {
            (
                p.claim_a,
                p.claim_b,
                p.rest["status"].clone(),
                p.rest["verifier_verdict"].clone(),
            )
        })
        .collect();
    assert_eq!(got, want);
}
