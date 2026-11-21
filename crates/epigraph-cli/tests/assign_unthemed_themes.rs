//! `assign_unthemed_themes` (backlog d5f9829a) driven as a real process on
//! real LOGIN roles, in the deployed shape: `DATABASE_URL` is an
//! `epigraph_app` login and `MAINTENANCE_DATABASE_URL` an
//! `epigraph_maintenance` login. Neither is a superuser; the superuser fixture
//! pool only seeds rows and reads results, and every assertion about what was
//! written is measured on it, not taken from the binary's summary.
//!
//! The defect: `POST /api/v1/themes/assign-unthemed` runs
//! `ClaimThemeRepository::assign_unthemed_batch` on the caller's connection,
//! where row security refuses (or hides) every claim the caller cannot write,
//! so no token could place another team's claims (prod, 2026-11-21: 34,547
//! embedded claims unthemed). The binary runs the same statement on the
//! maintenance connection, as `atlas_nightly`'s theme step does.
//!
//! What is pinned:
//!
//! * `--apply` places BOTH teams' group-private claims, each on its nearest
//!   theme, and leaves an already-themed claim alone;
//! * the dry run (the default) writes nothing, and its per-theme preview is
//!   exactly what an `--apply` then does;
//! * `--max-batches 1` stops after one batch;
//! * without `MAINTENANCE_DATABASE_URL` it refuses and writes nothing, even
//!   when `DATABASE_URL` is a login that could write everything.
//!
//! # Verified to fail
//!
//! Each test was run against a mutated binary (PR for backlog d5f9829a):
//! assignment on an application connection, a dry run that assigns, a loop
//! that ignores `--max-batches`, and no `MAINTENANCE_DATABASE_URL` check.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::collections::BTreeMap;
use std::process::Command;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_assign_unthemed_themes");
const DIM: usize = 1536;
const WORLD: Uuid = Uuid::nil();
const AXIS_A: usize = 0;
const AXIS_B: usize = 700;

// ── logins and the process ──────────────────────────────────────────────────

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("d5f9_{}_{}", parent, Uuid::new_v4().simple());
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

impl Run {
    fn summary(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout is not one JSON object ({e})\nstdout: {}\nstderr: {}",
                self.stdout, self.stderr
            )
        })
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
    let out = cmd.output().expect("run assign_unthemed_themes");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Run the binary in the deployed shape (an application `DATABASE_URL`, a
/// maintenance `MAINTENANCE_DATABASE_URL`), dropping both logins before the
/// caller asserts anything.
async fn run_deployed(pool: &PgPool, args: &[&str]) -> Run {
    let (maint_role, maint_url) = create_login(pool, "epigraph_maintenance").await;
    let (app_role, app_url) = create_login(pool, "epigraph_app").await;
    let r = run(args, &app_url, Some(&maint_url));
    drop_login(pool, &maint_role).await;
    drop_login(pool, &app_role).await;
    r
}

// ── seeding ─────────────────────────────────────────────────────────────────

async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, display_name) \
         VALUES ($1, $2, 'system', 'd5f9829a filer')",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

/// A 1536-d vector on axis `axis`, jittered by `jitter`.
fn vector(axis: usize, jitter: usize) -> String {
    let mut v = vec![0.0_f32; DIM];
    v[axis % DIM] = 1.0;
    v[(axis + 7 + jitter) % DIM] = 0.01;
    let parts: Vec<String> = v.iter().map(|x| format!("{x}")).collect();
    format!("[{}]", parts.join(","))
}

async fn theme(pool: &PgPool, label: &str, axis: usize) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, centroid) VALUES ($1, $2::vector) RETURNING id",
    )
    .bind(label)
    .bind(vector(axis, 0))
    .fetch_one(pool)
    .await
    .expect("seed theme")
}

/// `n` embedded claims near `axis`, owned by `owner` (`None`: public),
/// carrying `theme` (`None`: unthemed).
async fn claims(
    pool: &PgPool,
    filer: Uuid,
    owner: Option<Uuid>,
    theme: Option<Uuid>,
    axis: usize,
    n: usize,
) -> Vec<Uuid> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id, theme_id, embedding, updated_at) \
             VALUES (gen_random_uuid(), 'd5f9829a claim ' || gen_random_uuid()::text, \
                     decode(md5(random()::text) || md5(random()::text), 'hex'), 0.6, $1, true, \
                     CASE WHEN $2::uuid IS NULL THEN 'public' ELSE 'group' END, \
                     COALESCE($2, $5), $3, $4::vector, '2020-01-01T00:00:00Z') \
             RETURNING id",
        )
        .bind(filer)
        .bind(owner)
        .bind(theme)
        .bind(vector(axis, i + 1))
        .bind(WORLD)
        .fetch_one(pool)
        .await
        .expect("seed claim");
        out.push(id);
    }
    out
}

/// Two teams, two themes, and four kinds of claim.
struct World {
    theme_a: Uuid,
    theme_b: Uuid,
    /// Team A's group-private unthemed claims, nearest `theme_a`.
    team_a: Vec<Uuid>,
    /// Team B's group-private unthemed claims, nearest `theme_b`.
    team_b: Vec<Uuid>,
    /// One public unthemed claim, nearest `theme_a`.
    public: Vec<Uuid>,
    /// Team A's claim already filed on `theme_b` though nearest `theme_a`.
    themed: Uuid,
}

impl World {
    fn unthemed(&self) -> Vec<Uuid> {
        self.team_a
            .iter()
            .chain(&self.team_b)
            .chain(&self.public)
            .copied()
            .collect()
    }
}

async fn world(pool: &PgPool) -> World {
    let filer = agent(pool).await;
    let a = team(pool, "d5f9829a team A").await;
    let b = team(pool, "d5f9829a team B").await;
    let theme_a = theme(pool, "d5f9829a theme A", AXIS_A).await;
    let theme_b = theme(pool, "d5f9829a theme B", AXIS_B).await;
    let w = World {
        theme_a,
        theme_b,
        team_a: claims(pool, filer, Some(a), None, AXIS_A, 3).await,
        team_b: claims(pool, filer, Some(b), None, AXIS_B, 3).await,
        public: claims(pool, filer, None, None, AXIS_A, 1).await,
        themed: claims(pool, filer, Some(a), Some(theme_b), AXIS_A, 1).await[0],
    };
    // Calibration: the seeds are what the tests say they are.
    let group_private: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::int8 FROM claims WHERE id = ANY($1) AND visibility = 'group'",
    )
    .bind(
        w.team_a
            .iter()
            .chain(&w.team_b)
            .copied()
            .collect::<Vec<_>>(),
    )
    .fetch_one(pool)
    .await
    .expect("count group-private seeds");
    assert_eq!(
        group_private, 6,
        "CALIBRATION: both teams' claims must be group-private"
    );
    w
}

/// `(theme_id, updated_at)` of each claim, read on the superuser pool.
async fn state(pool: &PgPool, ids: &[Uuid]) -> BTreeMap<Uuid, (Option<Uuid>, String)> {
    sqlx::query_as::<_, (Uuid, Option<Uuid>, String)>(
        "SELECT id, theme_id, updated_at::text FROM claims WHERE id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(pool)
    .await
    .expect("read claims")
    .into_iter()
    .map(|(id, t, u)| (id, (t, u)))
    .collect()
}

async fn theme_of(pool: &PgPool, id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT theme_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read theme_id")
}

async fn unthemed_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*)::int8 FROM claims WHERE theme_id IS NULL AND embedding IS NOT NULL",
    )
    .fetch_one(pool)
    .await
    .expect("count unthemed")
}

fn assert_ok(r: &Run, what: &str) {
    assert_eq!(
        r.code,
        Some(0),
        "{what} failed\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
}

// ── tests ───────────────────────────────────────────────────────────────────

/// The defect's fix: on the maintenance connection BOTH teams' private claims
/// are assigned, each to its nearest theme. On an application connection the
/// statement cannot see (or write) them, which is how the route fails.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_on_the_maintenance_connection_assigns_both_teams_claims(pool: PgPool) {
    let w = world(&pool).await;
    let before = unthemed_count(&pool).await;
    assert_eq!(before, 7, "CALIBRATION: 3 + 3 + 1 unthemed embedded claims");
    let themed_before = state(&pool, &[w.themed]).await;

    let r = run_deployed(&pool, &["--apply", "--batch-size", "2"]).await;
    assert_ok(&r, "--apply on the maintenance connection");

    for &id in &w.team_a {
        assert_eq!(
            theme_of(&pool, id).await,
            Some(w.theme_a),
            "team A's private claim {id} was not placed on its nearest theme\nstdout: {}",
            r.stdout
        );
    }
    for &id in &w.team_b {
        assert_eq!(
            theme_of(&pool, id).await,
            Some(w.theme_b),
            "team B's private claim {id} was not placed on its nearest theme\nstdout: {}",
            r.stdout
        );
    }
    assert_eq!(theme_of(&pool, w.public[0]).await, Some(w.theme_a));
    assert_eq!(
        state(&pool, &[w.themed]).await,
        themed_before,
        "an already-themed claim was re-assigned or touched"
    );
    assert_eq!(unthemed_count(&pool).await, 0);

    let s = r.summary();
    assert_eq!(s["applied"], true);
    assert_eq!(s["unthemed_before"], 7);
    assert_eq!(s["assigned"], 7);
    assert_eq!(s["unthemed_after"], 0);
    // 7 claims in batches of 2: 2 + 2 + 2 + 1.
    assert_eq!(s["batches"], 4);
}

/// The default is a dry run: nothing changes (not a theme, not a timestamp),
/// and the per-theme preview is exactly what an `--apply` then does.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dry_run_writes_nothing_and_previews_what_apply_does(pool: PgPool) {
    let w = world(&pool).await;
    let mut every = w.unthemed();
    every.push(w.themed);
    let before = state(&pool, &every).await;

    let dry = run_deployed(&pool, &[]).await;
    assert_ok(&dry, "the dry run");
    assert_eq!(
        state(&pool, &every).await,
        before,
        "the dry run changed a claim's theme or updated_at\nstdout: {}",
        dry.stdout
    );
    let s = dry.summary();
    assert_eq!(s["applied"], false);
    assert_eq!(s["unthemed_before"], 7);
    assert_eq!(s["assigned"], 0);
    assert_eq!(s["unthemed_after"], 7);
    assert_eq!(s["batches"], 0);
    let preview: BTreeMap<String, i64> = s["would_assign"]
        .as_array()
        .unwrap_or_else(|| panic!("no would_assign in the dry run: {}", dry.stdout))
        .iter()
        .map(|row| {
            (
                row["theme_id"].as_str().expect("a theme id").to_string(),
                row["claims"].as_i64().expect("a count"),
            )
        })
        .collect();
    let expected: BTreeMap<String, i64> =
        BTreeMap::from([(w.theme_a.to_string(), 4), (w.theme_b.to_string(), 3)]);
    assert_eq!(
        preview, expected,
        "the preview is not team A + public on A, team B on B"
    );

    // The preview is a promise about --apply: measure it.
    let apply = run_deployed(&pool, &["--apply"]).await;
    assert_ok(&apply, "--apply after the dry run");
    let placed: BTreeMap<String, i64> = sqlx::query_as::<_, (Uuid, i64)>(
        "SELECT theme_id, COUNT(*)::int8 FROM claims WHERE id = ANY($1) GROUP BY theme_id",
    )
    .bind(w.unthemed())
    .fetch_all(&pool)
    .await
    .expect("count placements")
    .into_iter()
    .map(|(t, n)| (t.to_string(), n))
    .collect();
    assert_eq!(
        placed, preview,
        "--apply placed claims other than the dry run said"
    );
}

/// `--max-batches 1` runs one batch and stops, with the rest still unthemed.
#[sqlx::test(migrations = "../../migrations")]
async fn max_batches_one_stops_after_one_batch(pool: PgPool) {
    let w = world(&pool).await;

    let r = run_deployed(
        &pool,
        &["--apply", "--max-batches", "1", "--batch-size", "2"],
    )
    .await;
    assert_ok(&r, "--apply --max-batches 1");

    let after = state(&pool, &w.unthemed()).await;
    let placed = after.values().filter(|(t, _)| t.is_some()).count();
    assert_eq!(
        placed, 2,
        "one batch of 2 must place exactly 2 claims\nstdout: {}",
        r.stdout
    );
    assert_eq!(unthemed_count(&pool).await, 5);
    let s = r.summary();
    assert_eq!(s["batches"], 1);
    assert_eq!(s["assigned"], 2);
    assert_eq!(s["unthemed_before"], 7);
    assert_eq!(s["unthemed_after"], 5);
}

/// Without `MAINTENANCE_DATABASE_URL` the binary refuses before it writes,
/// even when `DATABASE_URL` is a login that could write every claim (the
/// superuser fixture): the application DSN is never used for this.
#[sqlx::test(migrations = "../../migrations")]
async fn it_refuses_without_a_maintenance_database_url(pool: PgPool) {
    let w = world(&pool).await;
    let su_url = viewer_fixture::database_url_for(&pool).await;

    let r = run(&["--apply"], &su_url, None);

    assert_eq!(
        unthemed_count(&pool).await,
        7,
        "a refused run assigned claims\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert_eq!(theme_of(&pool, w.team_b[0]).await, None);
    assert_ne!(r.code, Some(0), "the run was not refused: {}", r.stdout);
    assert!(
        r.stderr
            .contains("runs only on an explicitly configured MAINTENANCE_DATABASE_URL"),
        "the refusal does not name the missing variable: {}",
        r.stderr
    );
}
