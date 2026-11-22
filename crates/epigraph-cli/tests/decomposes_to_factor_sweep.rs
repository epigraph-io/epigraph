//! `decomposes_to_factor_sweep` (backlog 444b1f4a; atom-level belief SPEC
//! §6.2, D3): the export-and-delete of the BP factors of `decomposes_to`
//! edges, the structural close of `bp_readable_factor_sql`'s legacy-arm
//! residual.
//!
//! THE RED TEST (`a_stranger_reads_no_decomposition_factor_after_the_sweep`):
//! a caller who cannot see a group-private decomposition, on a stamped
//! `epigraph_app` session (row security on), reads its LEGACY factor through
//! the BP predicate before the sweep (calibration: the known gap) and reads
//! no such factor after it. The fixture also holds the rows the sweep must not
//! touch: an ordinary keyed `supports` factor, an unkeyed
//! `directional_support` row on a pair that is no decomposition, a legacy
//! row on a RETRACTED decomposition, and an unkeyed `evidential_support` row
//! on an in-force decomposition pair. The library runs on the test's
//! superuser pool (`epigraph_bypass()` true); the binary is driven on real
//! NOSUPERUSER logins as an operator runs it.
//!
//! Since migration 262 the trigger mints no `decomposes_to` factor, so the
//! fixture seeds the rows a database migrated before 262 holds.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::collections::BTreeSet;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::Command;

use epigraph_cli::decomposes_to_factor_sweep::{self as sweep, SweepError, MANIFEST_KIND};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{seed_agent_with_group, seed_group_claim};

const BIN: &str = env!("CARGO_BIN_EXE_decomposes_to_factor_sweep");

// ---------------------------------------------------------------- fixture

async fn edge(pool: &PgPool, s: Uuid, t: Uuid, rel: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(s)
    .bind(t)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("insert edge")
}

/// A factor row as given (the shapes the pre-262 trigger and older writers
/// left).
async fn factor(
    pool: &PgPool,
    factor_type: &str,
    vars: &[Uuid],
    properties: serde_json::Value,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO factors (factor_type, variable_ids, potential, description, properties) \
         VALUES ($1, $2, $3, 'seeded', $4) RETURNING id",
    )
    .bind(factor_type)
    .bind(vars.to_vec())
    .bind(json!({"forward_strength": 0.0, "reverse_strength": 0.6}))
    .bind(properties)
    .fetch_one(pool)
    .await
    .expect("seed factor")
}

fn sorted(a: Uuid, b: Uuid) -> Vec<Uuid> {
    vec![a.min(b), a.max(b)]
}

struct World {
    owner: Uuid,
    stranger: Uuid,
    /// Legacy row on the group-private in-force decomposition `k -> a`.
    legacy: Uuid,
    /// Keyed `decomposes_to` row on `k -> a2`, whose pair also carries a
    /// `supports` edge left factorless by the slot conflict.
    keyed: Uuid,
    /// Rows the sweep must keep.
    keep: Vec<Uuid>,
}

async fn world(pool: &PgPool) -> World {
    let (owner, group) = seed_agent_with_group(pool, "dtfs-owner").await;
    let (stranger, _) = seed_agent_with_group(pool, "dtfs-stranger").await;
    let c = |s: &'static str| seed_group_claim(pool, owner, group, s);
    let (k, a, a2, x, y, r, ra, s, t) = (
        c("dtfs compound").await,
        c("dtfs atom").await,
        c("dtfs atom 2").await,
        c("dtfs x").await,
        c("dtfs y").await,
        c("dtfs retracted compound").await,
        c("dtfs retracted atom").await,
        c("dtfs supporter").await,
        c("dtfs supported").await,
    );

    // The private decomposition and its LEGACY row (unsorted on purpose: the
    // predicate matches either order).
    edge(pool, k, a, "decomposes_to").await;
    let legacy = factor(
        pool,
        "directional_support",
        &[a.max(k), a.min(k)],
        json!({}),
    )
    .await;

    // A keyed row on a second decomposition; a supports edge on the same pair
    // created after it finds the slot held (ON CONFLICT DO NOTHING).
    let dec2 = edge(pool, k, a2, "decomposes_to").await;
    let keyed = factor(
        pool,
        "directional_support",
        &sorted(k, a2),
        json!({"relationship": "decomposes_to", "source_edge_id": dec2}),
    )
    .await;
    let parallel = edge(pool, a2, k, "supports").await;
    let parallel_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM factors WHERE properties->>'source_edge_id' = $1")
            .bind(parallel.to_string())
            .fetch_one(pool)
            .await
            .expect("count");
    assert_eq!(
        parallel_rows, 0,
        "calibration: the keyed row holds the slot the parallel edge would use"
    );

    // Keep: the trigger's ordinary keyed factor of a supports edge.
    let sup = edge(pool, s, t, "supports").await;
    let ordinary: Uuid =
        sqlx::query_scalar("SELECT id FROM factors WHERE properties->>'source_edge_id' = $1")
            .bind(sup.to_string())
            .fetch_one(pool)
            .await
            .expect("control: the trigger minted the supports factor");
    // Keep: an unkeyed directional row on a pair that is no decomposition.
    let unrelated = factor(pool, "directional_support", &sorted(x, y), json!({})).await;
    // Keep: a legacy row on a RETRACTED decomposition (the predicate reads it
    // as an ordinary factor again, for every viewer).
    let retracted_edge = edge(pool, r, ra, "decomposes_to").await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(retracted_edge)
        .execute(pool)
        .await
        .expect("retract");
    let on_retracted = factor(pool, "directional_support", &sorted(r, ra), json!({})).await;
    // Keep: an unkeyed evidential row on the in-force decomposition pair (the
    // legacy arm matches directional_support only).
    let evidential = factor(pool, "evidential_support", &sorted(k, a), json!({})).await;

    // A BP message on the legacy row, removed with it by the FK cascade.
    sqlx::query(
        "INSERT INTO bp_messages (factor_id, variable_id, direction, message, iteration) \
         VALUES ($1, $2, 'factor_to_var', '{}', 0)",
    )
    .bind(legacy)
    .bind(k)
    .execute(pool)
    .await
    .expect("seed a bp message");

    World {
        owner,
        stranger,
        legacy,
        keyed,
        keep: vec![ordinary, unrelated, on_retracted, evidential],
    }
}

/// The ids BP may read on `agent`'s stamped connection, downgraded to
/// `epigraph_app` so row security filters `edges` as on a request.
async fn bp_readable_as(pool: &PgPool, agent: Uuid) -> BTreeSet<Uuid> {
    use sqlx::Executor;
    let scoped =
        viewer_fixture::scoped_pool_with_mode(pool, epigraph_db::SessionGucMode::Transaction).await;
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve the viewer on the superuser pool");
    let mut r = scoped.read_as(&viewer).await.expect("read_as");
    r.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *r)
        .await
        .expect("bypass");
    assert!(!bypass, "CALIBRATION: the stamped session must be filtered");
    let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT f.id FROM factors f WHERE {}",
        epigraph_db::repos::factor::bp_readable_factor_sql()
    ))
    .fetch_all(&mut *r)
    .await
    .expect("BP's factor read");
    r.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    r.commit().await.expect("commit");
    ids.into_iter().collect()
}

async fn all_factors(pool: &PgPool) -> BTreeSet<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM factors")
        .fetch_all(pool)
        .await
        .expect("factors")
        .into_iter()
        .collect()
}

async fn full_rows(pool: &PgPool, ids: &[Uuid]) -> Vec<String> {
    sqlx::query_scalar("SELECT to_jsonb(f)::text FROM factors f WHERE id = ANY($1) ORDER BY id")
        .bind(ids)
        .fetch_all(pool)
        .await
        .expect("rows")
}

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("dtfs-{}", Uuid::new_v4().simple()));
        std::fs::create_dir(&p).expect("temp dir");
        Self(p)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `apply`: the reviewed dry run's ids, or `None` for a dry run.
async fn run_lib(
    pool: &PgPool,
    out: &Path,
    apply: Option<&[Uuid]>,
) -> Result<sweep::SweepReport, SweepError> {
    let mut file = std::fs::File::create(out).expect("manifest file");
    let mut conn = pool.acquire().await.expect("acquire");
    sweep::run(&mut conn, &mut file, apply, None).await
}

fn manifest(path: &Path) -> (sweep::ManifestHeader, Vec<sweep::ManifestRow>) {
    sweep::read_manifest(BufReader::new(
        std::fs::File::open(path).expect("open manifest"),
    ))
    .expect("the manifest parses")
}

// ---------------------------------------------------------------- library

#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_reads_no_decomposition_factor_after_the_sweep(pool: PgPool) {
    let w = world(&pool).await;
    let dir = Dir::new();

    // Calibration, the residual this closes: the owner's stamped session sees
    // the decomposition and excludes its legacy row; the stranger's cannot.
    let owner_before = bp_readable_as(&pool, w.owner).await;
    assert!(
        !owner_before.contains(&w.legacy),
        "calibration: the owner's BP read excludes the legacy row"
    );
    let before = bp_readable_as(&pool, w.stranger).await;
    assert!(
        before.contains(&w.legacy),
        "calibration (the known gap): a caller who cannot see the decomposition reads its \
         legacy factor before the sweep"
    );
    for id in &w.keep {
        assert!(before.contains(id), "calibration: control {id} is readable");
    }

    // Dry run: the manifest is the export, and nothing changes.
    let all_before = all_factors(&pool).await;
    let dry = run_lib(&pool, &dir.path("dry.jsonl"), None)
        .await
        .expect("dry run");
    assert!(!dry.applied);
    let mut want = vec![w.legacy, w.keyed];
    want.sort();
    assert_eq!(
        dry.ids, want,
        "the sweep selects the keyed and the legacy row only"
    );
    assert_eq!(
        all_factors(&pool).await,
        all_before,
        "a dry run deletes nothing"
    );
    let (h, rows) = manifest(&dir.path("dry.jsonl"));
    assert_eq!(h.kind, MANIFEST_KIND);
    assert_eq!(
        (h.mode.as_str(), h.rows, h.keyed, h.legacy),
        ("dry_run", 2, 1, 1)
    );
    assert_eq!(h.bp_messages, 1, "the legacy row's bp message is counted");
    let keyed_row = rows.iter().find(|r| r.id == w.keyed).expect("keyed row");
    assert_eq!(
        keyed_row.parallel_unfactored_edges, 1,
        "the supports edge whose slot the keyed row holds is counted"
    );
    assert_eq!(
        rows.iter()
            .find(|r| r.id == w.legacy)
            .map(|r| r.arm.as_str()),
        Some("legacy")
    );

    // Apply: exactly the reviewed manifest is deleted, the rest is kept.
    let snapshot = full_rows(&pool, &want).await;
    let applied = run_lib(&pool, &dir.path("apply.jsonl"), Some(&dry.ids))
        .await
        .expect("apply");
    assert!(applied.applied);
    assert_eq!(applied.ids, want);
    let all_after = all_factors(&pool).await;
    let expected: BTreeSet<Uuid> = all_before
        .difference(&want.iter().copied().collect())
        .copied()
        .collect();
    assert_eq!(
        all_after, expected,
        "the apply deleted exactly the manifest's rows"
    );
    let msgs: i64 = sqlx::query_scalar("SELECT count(*) FROM bp_messages WHERE factor_id = $1")
        .bind(w.legacy)
        .fetch_one(&pool)
        .await
        .expect("bp messages");
    assert_eq!(msgs, 0, "the cascade removed the legacy row's bp message");

    // THE RED ASSERTION: the stranger reads no decomposition factor now.
    let after = bp_readable_as(&pool, w.stranger).await;
    assert!(
        !after.contains(&w.legacy) && !after.contains(&w.keyed),
        "after the sweep a caller without visibility of the decomposition reads none of its \
         factors: {after:?}"
    );
    for id in &w.keep {
        assert!(
            after.contains(id),
            "control {id} is still readable after the sweep"
        );
    }
    let mut conn = pool.acquire().await.expect("acquire");
    assert_eq!(
        sweep::remaining(&mut conn, None).await.expect("remaining"),
        0
    );
    drop(conn);

    // A re-run with nothing to do selects and deletes nothing.
    let none = run_lib(&pool, &dir.path("again.jsonl"), Some(&[]))
        .await
        .expect("idempotent re-run");
    assert!(none.ids.is_empty(), "nothing left to sweep");

    // Restore: a dry run inserts nothing; an apply puts the rows back as they
    // were, column for column.
    let (_, apply_rows) = manifest(&dir.path("apply.jsonl"));
    let mut conn = pool.acquire().await.expect("acquire");
    let dry_restore = sweep::restore(&mut conn, &apply_rows, true)
        .await
        .expect("dry restore");
    assert_eq!(dry_restore.restored, want);
    assert_eq!(
        all_factors(&pool).await,
        all_after,
        "a dry restore inserts nothing"
    );
    let restored = sweep::restore(&mut conn, &apply_rows, false)
        .await
        .expect("restore");
    assert_eq!(
        (restored.restored.clone(), restored.skipped.len()),
        (want.clone(), 0)
    );
    assert_eq!(
        full_rows(&pool, &want).await,
        snapshot,
        "the restore re-inserts every column as it was"
    );
    let again = sweep::restore(&mut conn, &apply_rows, false)
        .await
        .expect("restore again");
    assert_eq!(again.skipped, want, "a held id is skipped, not duplicated");
    drop(conn);

    // The sweep for rows minted later: a dry run finds the restored rows, and
    // an apply of that dry run removes them again.
    let later = run_lib(&pool, &dir.path("later-dry.jsonl"), None)
        .await
        .expect("dry run over the restored rows");
    assert_eq!(later.ids, want, "a re-run finds rows that appeared since");
    let swept = run_lib(&pool, &dir.path("later.jsonl"), Some(&later.ids))
        .await
        .expect("sweep the restored rows");
    assert_eq!(swept.ids, want, "and deletes them");
}

/// An apply deletes only the set the operator reviewed: a row that matches
/// since the dry run (here a new keyed row) makes it refuse, writing nothing
/// to the database or the manifest.
#[sqlx::test(migrations = "../../migrations")]
async fn an_apply_refuses_a_selection_that_changed_since_the_dry_run(pool: PgPool) {
    let w = world(&pool).await;
    let dir = Dir::new();
    let dry = run_lib(&pool, &dir.path("dry.jsonl"), None)
        .await
        .expect("dry run");
    let (agent, group) = seed_agent_with_group(&pool, "dtfs-late").await;
    let p = seed_group_claim(&pool, agent, group, "dtfs late compound").await;
    let q = seed_group_claim(&pool, agent, group, "dtfs late atom").await;
    let late = factor(
        &pool,
        "directional_support",
        &sorted(p, q),
        json!({"relationship": "decomposes_to"}),
    )
    .await;

    let out = dir.path("apply.jsonl");
    let err = run_lib(&pool, &out, Some(&dry.ids))
        .await
        .expect_err("the live selection gained a row the operator never reviewed");
    assert!(
        matches!(
            err,
            SweepError::PlanChanged {
                added: 1,
                missing: 0
            }
        ),
        "{err}"
    );
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM factors WHERE id = ANY($1)")
        .bind(vec![w.legacy, w.keyed, late])
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(left, 3, "nothing was deleted");
    assert_eq!(
        std::fs::metadata(&out).expect("file").len(),
        0,
        "no manifest is written for a refused apply"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_sweep_refuses_a_session_under_row_security(pool: PgPool) {
    use sqlx::Executor;
    let w = world(&pool).await;
    let dir = Dir::new();
    let out = dir.path("refused.jsonl");
    let mut file = std::fs::File::create(&out).expect("manifest file");
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("downgrade");
    let err = sweep::run(&mut conn, &mut file, Some(&[]), None)
        .await
        .expect_err("an application session would see only its own decompositions");
    assert!(matches!(err, SweepError::NotPrivileged), "{err}");
    let err = sweep::restore(&mut conn, &[], false)
        .await
        .expect_err("restore is refused the same way");
    assert!(matches!(err, SweepError::NotPrivileged), "{err}");
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    drop(conn);
    assert_eq!(
        std::fs::metadata(&out).expect("file").len(),
        0,
        "nothing is exported before the privilege check"
    );
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM factors WHERE id = ANY($1)")
        .bind(vec![w.legacy, w.keyed])
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(left, 2, "nothing was deleted");
}

// ---------------------------------------------------------------- binary

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("dtfs_{}_{}", parent, Uuid::new_v4().simple());
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
    (
        role.clone(),
        format!("{}{role}:{password}@{host_path}", &base[..scheme_end]),
    )
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_bin(dir: &Path, args: &[&str], database_url: &str, maintenance_url: Option<&str>) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", database_url)
        .env("RUST_LOG", "warn")
        .args(args)
        .current_dir(dir);
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

#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_exports_then_deletes_on_the_maintenance_login(pool: PgPool) {
    let w = world(&pool).await;
    let dir = Dir::new();
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let all_before = all_factors(&pool).await;

    // No configured MAINTENANCE_DATABASE_URL: refused, no file, nothing deleted.
    let dry = dir.path("dry.jsonl");
    let dry_s = dry.to_string_lossy().into_owned();
    let refused = run_bin(&dir.0, &["--manifest-out", &dry_s], &maint_url, None);
    assert_eq!(
        refused.code,
        Some(1),
        "{}\n{}",
        refused.stderr,
        refused.stdout
    );
    assert!(
        refused
            .stderr
            .contains("runs only on an explicitly configured MAINTENANCE_DATABASE_URL"),
        "{}",
        refused.stderr
    );
    assert!(!dry.exists(), "a refused run leaves no manifest");

    // Dry run on the maintenance login.
    let r = run_bin(
        &dir.0,
        &["--manifest-out", &dry_s],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stderr, r.stdout);
    assert!(r.stdout.contains("DRY RUN"), "{}", r.stdout);
    assert_eq!(
        all_factors(&pool).await,
        all_before,
        "the dry run deletes nothing"
    );
    let (h, _) = manifest(&dry);
    assert_eq!((h.rows, h.keyed, h.legacy), (2, 1, 1));

    // An existing output is refused before connecting.
    let again = run_bin(
        &dir.0,
        &["--manifest-out", &dry_s],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(again.code, Some(1), "{}", again.stderr);

    // An apply without the reviewed dry run is refused before connecting.
    let applied = dir.path("apply.jsonl");
    let applied_s = applied.to_string_lossy().into_owned();
    let r = run_bin(
        &dir.0,
        &["--manifest-out", &applied_s, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(1), "{}\n{}", r.stderr, r.stdout);
    assert!(r.stderr.contains("--expect"), "{}", r.stderr);
    assert!(!applied.exists(), "the refused apply leaves no manifest");
    assert_eq!(all_factors(&pool).await, all_before, "and deletes nothing");

    // Apply the reviewed dry run, then measure.
    let r = run_bin(
        &dir.0,
        &["--manifest-out", &applied_s, "--apply", "--expect", &dry_s],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}\n{}", r.stderr, r.stdout);
    let gone: i64 = sqlx::query_scalar("SELECT count(*) FROM factors WHERE id = ANY($1)")
        .bind(vec![w.legacy, w.keyed])
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(gone, 0, "the apply deleted both rows");
    let r = run_bin(&dir.0, &["--remaining"], &app_url, Some(&maint_url));
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(
        r.stdout.contains("decomposes_to factors remaining: 0"),
        "{}",
        r.stdout
    );

    // Restore from the apply's manifest (dry, then for real).
    let r = run_bin(
        &dir.0,
        &["--restore", &applied_s],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert!(r.stdout.contains("restored=2"), "{}", r.stdout);
    assert_eq!(
        all_factors(&pool).await.len(),
        all_before.len() - 2,
        "a dry restore inserts nothing"
    );
    let r = run_bin(
        &dir.0,
        &["--restore", &applied_s, "--apply"],
        &app_url,
        Some(&maint_url),
    );
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert_eq!(
        all_factors(&pool).await,
        all_before,
        "the restore puts both rows back"
    );

    for role in [app_role, maint_role] {
        let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
            .execute(&pool)
            .await;
    }
}
