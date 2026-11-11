//! `atlas_layout` (Atlas P3a, migration 197), driven as the real process an
//! operator runs, on real non-superuser LOGIN roles: an `epigraph_app` login
//! as `DATABASE_URL` and an `epigraph_maintenance` login as
//! `MAINTENANCE_DATABASE_URL`, as on a deployment.
//!
//! The operator contract this file pins:
//!
//! * no configured `MAINTENANCE_DATABASE_URL`: refused, nothing written;
//! * no flag: a report and nothing written;
//! * `--apply`: one run built from PUBLIC rows only (a private-only theme has
//!   no row, a private claim moves no position and adds no link), at the
//!   epoch of its snapshot; `--keep 1` keeps one run;
//! * a second run while the advisory lock is held is refused.
//!
//! The private rows are GROUP-private in a group the maintenance login has no
//! part in, so a build that leaked them would show them here: the login
//! bypasses row security.
//!
//! The process environment is CLEARED (and the working directory is the temp
//! dir): the binary loads a `.env`, and an inherited `MAINTENANCE_DATABASE_URL`
//! would point it elsewhere or mask the refusal.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::process::Command;

use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_atlas_layout");
const REFUSAL: &str = "runs only on an explicitly configured MAINTENANCE_DATABASE_URL";
const DIM: usize = 1536;

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("atlas_{}_{}", parent, Uuid::new_v4().simple());
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
}

fn run(args: &[&str], database_url: &str, maintenance_url: Option<&str>) -> Run {
    let mut cmd = Command::new(BIN);
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

fn basis(axis: usize, tilt: f64) -> String {
    let mut v = vec!["0".to_string(); DIM];
    v[axis] = "1".to_string();
    v[axis + 1] = format!("{tilt}");
    format!("[{}]", v.join(","))
}

async fn seed_theme(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ($1) RETURNING id")
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("seed theme")
}

async fn claim_in(
    pool: &PgPool,
    agent: Uuid,
    group: Option<Uuid>,
    theme: Uuid,
    embedding: &str,
) -> Uuid {
    let content = format!("atlas bin claim {}", Uuid::new_v4());
    let id = match group {
        None => viewer_fixture::seed_public_claim(pool, agent, &content).await,
        Some(g) => viewer_fixture::seed_group_claim(pool, agent, g, &content).await,
    };
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(id)
        .bind(theme)
        .execute(pool)
        .await
        .expect("assign theme");
    viewer_fixture::set_claim_embedding(pool, id, embedding).await;
    id
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
}

struct World {
    t1: Uuid,
    t3: Uuid,
    x: Uuid,
}

/// Public themes T1 (two claims), T2 and T4, with a public `supports` edge
/// T1 -> T2; private-only T3; and group-private X in T1 (an embedding far
/// from T1's) with `contradicts` to T2.
async fn world(pool: &PgPool) -> World {
    let (agent, group) = viewer_fixture::seed_agent_with_group(pool, "atlas-bin").await;
    let t1 = seed_theme(pool, "Electrode double layers").await;
    let t2 = seed_theme(pool, "Stern capacitance").await;
    let t3 = seed_theme(pool, "Private lab notes").await;
    let t4 = seed_theme(pool, "Ion transport").await;
    let p1 = claim_in(pool, agent, None, t1, &basis(0, 0.1)).await;
    claim_in(pool, agent, None, t1, &basis(0, 0.2)).await;
    let p2 = claim_in(pool, agent, None, t2, &basis(4, 0.1)).await;
    claim_in(pool, agent, None, t4, &basis(8, 0.1)).await;
    claim_in(pool, agent, Some(group), t3, &basis(12, 0.1)).await;
    let x = claim_in(pool, agent, Some(group), t1, &basis(20, 0.5)).await;
    edge(pool, p1, p2, "supports").await;
    edge(pool, x, p2, "contradicts").await;
    World { t1, t3, x }
}

async fn run_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM atlas_layout_runs")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn position(pool: &PgPool, theme: Uuid) -> Option<(f64, f64)> {
    sqlx::query_as(
        "SELECT lt.x, lt.y FROM atlas_layout_themes lt \
         JOIN atlas_layout_runs r ON r.id = lt.run_id \
         WHERE lt.theme_id = $1 ORDER BY r.completed_at DESC LIMIT 1",
    )
    .bind(theme)
    .fetch_optional(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn refuses_without_a_configured_maintenance_dsn(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    world(&pool).await;
    for args in [&[][..], &["--apply"][..]] {
        let r = run(args, &logins.maint.1, None);
        assert_eq!(r.code, Some(1), "{args:?}: {}", r.stdout);
        assert!(r.stderr.contains(REFUSAL), "{args:?}: {}", r.stderr);
    }
    assert_eq!(run_count(&pool).await, 0, "a refused run wrote");
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn dry_run_writes_nothing(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    world(&pool).await;
    for args in [&[][..], &["--dry-run"][..]] {
        let report = run(args, &logins.app.1, Some(&logins.maint.1)).report();
        assert_eq!(report["applied"], false, "{report}");
        assert_eq!(report["themes"]["placed"], 3, "{report}");
        assert!(report.get("run_id").is_none(), "{report}");
    }
    let both = run(
        &["--apply", "--dry-run"],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    assert_eq!(both.code, Some(2), "{}", both.stdout);
    assert_eq!(run_count(&pool).await, 0, "a dry run wrote");
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn apply_builds_from_public_claims_only(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let w = world(&pool).await;
    let epoch: i64 = sqlx::query_scalar("SELECT n FROM atlas_layout_epoch")
        .fetch_one(&pool)
        .await
        .unwrap();
    let report = run(&["--apply"], &logins.app.1, Some(&logins.maint.1)).report();
    assert_eq!(report["applied"], true, "{report}");
    assert_eq!(report["visibility_epoch"], epoch, "{report}");
    let text = report.to_string();
    assert!(!text.contains("Private lab notes"), "{text}");
    assert!(!text.contains(&w.x.to_string()), "{text}");

    let (run_epoch, digest): (i64, String) =
        sqlx::query_as("SELECT visibility_epoch, theme_set_digest FROM atlas_layout_runs")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(run_epoch, epoch);
    assert_eq!(digest.len(), 64);
    assert!(
        position(&pool, w.t3).await.is_none(),
        "a private-only theme was placed"
    );
    let rels: Vec<String> =
        sqlx::query_scalar("SELECT relationship FROM atlas_layout_theme_links ORDER BY 1")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        rels,
        vec!["supports".to_string()],
        "only the public edge is counted"
    );

    // The private claim moves nothing: without it the build is the same.
    let before = position(&pool, w.t1).await.expect("T1 placed");
    sqlx::query("DELETE FROM edges WHERE source_id = $1")
        .bind(w.x)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM claims WHERE id = $1")
        .bind(w.x)
        .execute(&pool)
        .await
        .unwrap();
    run(&["--apply"], &logins.app.1, Some(&logins.maint.1)).report();
    assert_eq!(position(&pool, w.t1).await, Some(before));
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn apply_with_keep_1_twice_leaves_one_run(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    world(&pool).await;
    for _ in 0..2 {
        run(
            &["--apply", "--keep", "1"],
            &logins.app.1,
            Some(&logins.maint.1),
        )
        .report();
    }
    assert_eq!(run_count(&pool).await, 1);
    let bad = run(
        &["--apply", "--keep", "0"],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    assert_eq!(bad.code, Some(2), "--keep 0 is an argument error");
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_second_run_is_refused_while_the_lock_is_held(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    world(&pool).await;
    let mut holder = pool.acquire().await.unwrap();
    let took: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(epigraph_db::repos::maintenance_lock::ATLAS_LAYOUT_LOCK_KEY)
        .fetch_one(&mut *holder)
        .await
        .unwrap();
    assert!(took);
    let r = run(&["--apply"], &logins.app.1, Some(&logins.maint.1));
    assert_eq!(r.code, Some(1), "{}", r.stdout);
    assert!(r.stderr.contains("holds the lock"), "{}", r.stderr);
    assert_eq!(run_count(&pool).await, 0);
    drop(holder);
    logins.drop(&pool).await;
}
