//! `epigraph-operator set-workflow-submitter` and its `--reverse` (backlog
//! 47ebd69a), driven through the real binary against a `#[sqlx::test]`
//! database migrated 001 -> head, on a REAL `NOSUPERUSER` maintenance login
//! (so `workflows`' row security, migration 183, is what a real run meets:
//! a group-private workflow must be selected and written too).
//!
//! What is pinned: the selectors (ids, every generation of a lineage, every
//! row with no submitter); a dry run writes nothing; `--apply` writes exactly
//! the eligible rows in `record_submitter`'s shape (a JSON `null` metadata
//! becomes an object), holds another submitter unless `--force-reassign`,
//! writes the manifest and one audit row; the reversal puts every row back
//! byte for byte (a removed key, a restored prior submitter, a restored JSON
//! `null`), holds a row another writer changed since, and is idempotent;
//! `reown-reverse` refuses the manifest and names this verb; and the
//! refusals write nothing.

mod viewer_fixture;

use sqlx::PgPool;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const KEY: &str = "epigraph_submitted_by";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn show(&self) -> String {
        format!(
            "exit={}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

fn run_with(args: &[&str], dsn: &str) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, dsn)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("wfsub_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    (role.clone(), format!("{scheme}://{role}:probe-only@{host}"))
}

async fn drop_login(pool: &PgPool, role: &str) {
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(pool)
        .await
        .expect("drop role");
}

fn scratch_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("operator-wf-submitter-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

fn lines_file(dir: &Path, name: &str, lines: &[String]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, lines.join("\n")).expect("write list");
    p
}

/// A workflow row with exactly `metadata`.
async fn workflow(
    pool: &PgPool,
    name: &str,
    generation: i32,
    metadata: serde_json::Value,
    owner: Uuid,
    visibility: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, metadata, \
                                owner_group_id, visibility) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(name)
    .bind(generation)
    .bind(format!("goal of {name}"))
    .bind(metadata)
    .bind(owner)
    .bind(visibility)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn metadata(pool: &PgPool, id: Uuid) -> serde_json::Value {
    sqlx::query_scalar("SELECT metadata FROM workflows WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("metadata")
}

async fn all_metadata(pool: &PgPool) -> Vec<(Uuid, serde_json::Value)> {
    sqlx::query_as("SELECT id, metadata FROM workflows ORDER BY id")
        .fetch_all(pool)
        .await
        .expect("all metadata")
}

async fn audit(pool: &PgPool, event: &str) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = $1 ORDER BY created_at, id",
    )
    .bind(event)
    .fetch_all(pool)
    .await
    .expect("audit")
}

struct Fx {
    operator: Uuid,
    submitter: Uuid,
    other: Uuid,
    /// `{}`, group-private: lineage alpha gen 0.
    w_empty: Uuid,
    /// JSON `null` metadata: lineage alpha gen 1.
    w_null: Uuid,
    /// Another submitter recorded, plus another key: lineage beta.
    w_other: Uuid,
    /// Already the submitter: lineage gamma.
    w_same: Uuid,
}

async fn seed(pool: &PgPool) -> Fx {
    let (operator, op_group) = fixture::seed_human_operator(pool, "wfsub-operator").await;
    let (submitter, _) = fixture::seed_agent_with_group(pool, "wfsub-submitter").await;
    let (other, _) = fixture::seed_agent_with_group(pool, "wfsub-other").await;
    let world = Uuid::nil();
    let w_empty = workflow(pool, "alpha", 0, serde_json::json!({}), op_group, "group").await;
    let w_null = workflow(pool, "alpha", 1, serde_json::Value::Null, world, "public").await;
    let w_other = workflow(
        pool,
        "beta",
        0,
        serde_json::json!({ KEY: other.to_string(), "x": 1 }),
        world,
        "public",
    )
    .await;
    let w_same = workflow(
        pool,
        "gamma",
        0,
        serde_json::json!({ KEY: submitter.to_string() }),
        world,
        "public",
    )
    .await;
    Fx {
        operator,
        submitter,
        other,
        w_empty,
        w_null,
        w_other,
        w_same,
    }
}

fn set_args<'a>(
    selector: &[&'a str],
    submitter: &'a str,
    operator: &'a str,
    extra: &[&'a str],
) -> Vec<&'a str> {
    let mut a = vec!["set-workflow-submitter"];
    a.extend_from_slice(selector);
    a.extend(["--submitter", submitter, "--operator", operator]);
    a.extend_from_slice(extra);
    a
}

fn apply_flags<'a>(count: &'a str, manifest: &'a str) -> Vec<&'a str> {
    vec![
        "--apply",
        "--confirm-count",
        count,
        "--manifest-out",
        manifest,
        "--ruling",
        "test ruling",
        "--reason",
        "test",
    ]
}

#[sqlx::test(migrations = "../../migrations")]
async fn apply_and_reverse_restore_every_shape_exactly(pool: PgPool) {
    let fx = seed(&pool).await;
    let (login, dsn) = maintenance_login(&pool).await;
    let dir = scratch_dir();
    let (s, op) = (fx.submitter.to_string(), fx.operator.to_string());
    let before = all_metadata(&pool).await;

    // A lineage selects every generation.
    let names = lines_file(&dir, "names.txt", &["alpha".to_string()]);
    let lineage = run_with(
        &set_args(
            &["--canonical-names-file", names.to_str().unwrap()],
            &s,
            &op,
            &[],
        ),
        &dsn,
    );
    assert_eq!(lineage.code, 0, "{}", lineage.show());
    for w in [fx.w_empty, fx.w_null] {
        assert!(
            lineage.stdout.contains(&format!("WRITE\tworkflow={w}")),
            "{}",
            lineage.show()
        );
    }

    // --without-submitter: the group-private row and the null row; the
    // others record one. A dry run writes nothing.
    let dry = run_with(&set_args(&["--without-submitter"], &s, &op, &[]), &dsn);
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t2"),
        "{}",
        dry.show()
    );
    assert_eq!(
        all_metadata(&pool).await,
        before,
        "a dry run writes nothing"
    );
    assert!(audit(&pool, "operator.workflow_submitter_set")
        .await
        .is_empty());

    let m1 = dir.join("m1.jsonl");
    let mut args = set_args(&["--without-submitter"], &s, &op, &[]);
    args.extend(apply_flags("2", m1.to_str().unwrap()));
    let applied = run_with(&args, &dsn);
    assert_eq!(applied.code, 0, "{}", applied.show());
    for w in [fx.w_empty, fx.w_null] {
        assert_eq!(
            metadata(&pool, w).await,
            serde_json::json!({ KEY: s }),
            "record_submitter's shape"
        );
    }
    let rows = audit(&pool, "operator.workflow_submitter_set").await;
    assert_eq!(rows.len(), 1, "one audit row per run");
    assert_eq!(rows[0]["counts"]["written"], 2);
    assert_eq!(rows[0]["ruling"], "test ruling");
    assert!(m1.exists());

    // Another submitter is HELD; already-set is ALREADY.
    let ids = lines_file(
        &dir,
        "ids.txt",
        &[fx.w_other.to_string(), fx.w_same.to_string()],
    );
    let ids_sel = ["--ids-file", ids.to_str().unwrap()];
    let held = run_with(&set_args(&ids_sel, &s, &op, &[]), &dsn);
    assert_eq!(held.code, 0, "{}", held.show());
    assert!(
        held.stdout
            .contains(&format!("HELD\tworkflow={}", fx.w_other))
            && held
                .stdout
                .contains(&format!("ALREADY\tworkflow={}", fx.w_same))
            && held.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t0"),
        "{}",
        held.show()
    );
    let m2 = dir.join("m2.jsonl");
    let mut args = set_args(&ids_sel, &s, &op, &["--force-reassign"]);
    args.extend(apply_flags("1", m2.to_str().unwrap()));
    let reassigned = run_with(&args, &dsn);
    assert_eq!(reassigned.code, 0, "{}", reassigned.show());
    assert_eq!(
        metadata(&pool, fx.w_other).await,
        serde_json::json!({ KEY: s, "x": 1 })
    );

    // reown-reverse refuses it and names this verb.
    let rr = run_with(&["reown-reverse", "--manifest", m2.to_str().unwrap()], &dsn);
    assert_eq!(rr.code, 1, "{}", rr.show());
    assert!(
        rr.stderr.contains("set-workflow-submitter --reverse"),
        "{}",
        rr.show()
    );

    // Reverse both: dry first, then applied, newest first.
    let rev = |m: &Path, apply: bool| {
        let mut a = vec!["set-workflow-submitter", "--reverse", m.to_str().unwrap()];
        if apply {
            a.extend(["--apply", "--reason", "test undo"]);
        }
        run_with(&a, &dsn)
    };
    let dry_rev = rev(&m2, false);
    assert_eq!(dry_rev.code, 0, "{}", dry_rev.show());
    assert!(
        dry_rev.stdout.contains("RESTORE-COUNT\t1"),
        "{}",
        dry_rev.show()
    );
    assert_eq!(
        metadata(&pool, fx.w_other).await,
        serde_json::json!({ KEY: s, "x": 1 }),
        "a dry reversal writes nothing"
    );
    for m in [&m2, &m1] {
        let r = rev(m, true);
        assert_eq!(r.code, 0, "{}", r.show());
    }
    assert_eq!(
        all_metadata(&pool).await,
        before,
        "every row back byte for byte: the key removed, the prior submitter, the JSON null"
    );
    assert_eq!(
        audit(&pool, "operator.workflow_submitter_reversed")
            .await
            .len(),
        2
    );
    let again = rev(&m1, true);
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(
        again.stdout.contains("ALREADY-COUNT\t2"),
        "{}",
        again.show()
    );
    assert_eq!(
        audit(&pool, "operator.workflow_submitter_reversed")
            .await
            .len(),
        2,
        "a reversal with nothing to restore writes no audit row"
    );
    let _ = fx.other;
    drop_login(&pool, &login).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_row_changed_since_the_run_is_held_by_the_reversal(pool: PgPool) {
    let fx = seed(&pool).await;
    let (login, dsn) = maintenance_login(&pool).await;
    let dir = scratch_dir();
    let (s, op) = (fx.submitter.to_string(), fx.operator.to_string());
    let m = dir.join("m.jsonl");
    let mut args = set_args(&["--without-submitter"], &s, &op, &[]);
    args.extend(apply_flags("2", m.to_str().unwrap()));
    let r = run_with(&args, &dsn);
    assert_eq!(r.code, 0, "{}", r.show());
    // Another writer re-records w_empty's submitter after the run.
    let later = serde_json::json!({ KEY: fx.other.to_string() });
    sqlx::query("UPDATE workflows SET metadata = $2 WHERE id = $1")
        .bind(fx.w_empty)
        .bind(&later)
        .execute(&pool)
        .await
        .expect("a later write");
    let rev = run_with(
        &[
            "set-workflow-submitter",
            "--reverse",
            m.to_str().unwrap(),
            "--apply",
            "--reason",
            "undo",
        ],
        &dsn,
    );
    assert_eq!(rev.code, 3, "a held row exits 3: {}", rev.show());
    assert!(
        rev.stdout
            .contains(&format!("HELD\tworkflow={}", fx.w_empty)),
        "{}",
        rev.show()
    );
    assert_eq!(metadata(&pool, fx.w_empty).await, later, "left as found");
    assert_eq!(
        metadata(&pool, fx.w_null).await,
        serde_json::Value::Null,
        "the other row is restored"
    );
    drop_login(&pool, &login).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn refusals_write_nothing(pool: PgPool) {
    let fx = seed(&pool).await;
    let (login, dsn) = maintenance_login(&pool).await;
    let dir = scratch_dir();
    let (s, op) = (fx.submitter.to_string(), fx.operator.to_string());
    let before = all_metadata(&pool).await;
    let m = dir.join("m.jsonl");
    let ms = m.to_str().unwrap();

    // A count that is not the plan's.
    let mut args = set_args(&["--without-submitter"], &s, &op, &[]);
    args.extend(apply_flags("5", ms));
    let r = run_with(&args, &dsn);
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("--confirm-count 5"), "{}", r.show());
    assert!(!m.exists(), "no manifest for a refused run");

    // No ruling.
    let r = run_with(
        &set_args(
            &["--without-submitter"],
            &s,
            &op,
            &[
                "--apply",
                "--confirm-count",
                "2",
                "--manifest-out",
                ms,
                "--reason",
                "r",
            ],
        ),
        &dsn,
    );
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("--ruling"), "{}", r.show());

    // A submitter that is not an agent; an operator that is not a human one.
    let ghost = Uuid::new_v4().to_string();
    let r = run_with(&set_args(&["--without-submitter"], &ghost, &op, &[]), &dsn);
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("is not an agent"), "{}", r.show());
    let r = run_with(&set_args(&["--without-submitter"], &s, &s, &[]), &dsn);
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("human operator"), "{}", r.show());

    // Two selectors.
    let ids = lines_file(&dir, "ids.txt", &[fx.w_empty.to_string()]);
    let r = run_with(
        &set_args(
            &["--without-submitter", "--ids-file", ids.to_str().unwrap()],
            &s,
            &op,
            &[],
        ),
        &dsn,
    );
    assert_ne!(r.code, 0, "{}", r.show());

    assert_eq!(all_metadata(&pool).await, before);
    assert!(audit(&pool, "operator.workflow_submitter_set")
        .await
        .is_empty());
    let _ = (fx.w_null, fx.w_other, fx.w_same);
    drop_login(&pool, &login).await;
}
