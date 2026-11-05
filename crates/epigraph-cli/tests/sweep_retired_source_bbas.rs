//! The retroactive K10(3) sweep (`sweep_retired_source_bbas`; supersede SPEC
//! §11 K10(3), OD-10; rulings R-178(2), R-179), driven as the real processes
//! an operator runs, on real LOGIN roles.
//!
//! * The ORACLE is the read-only delta binary the operator accepted
//!   (`supersede_belief_delta --items k10-retro`): its report is the sweep's
//!   `--expect`, the sweep deletes exactly the rows it counted, and every
//!   holder's cache after the apply is the value it predicted.
//! * The fixture holds rows the sweep must NOT touch: a RETRACTED row from the
//!   retired source (kept), a live row keyed on one of the retired source's
//!   edges but held by a RETIRED claim (not measured, so not deleted, though
//!   a per-edge delete would take it), and a bystander. One holder is
//!   group-private (the sweep reads and deletes every group's rows).
//! * The dry run writes nothing. A second apply is a no-op with a fresh
//!   measurement and refused with the stale one.
//! * The undo puts every row back bit-identical and every cache back by
//!   compare-and-set; a cache or key written since the sweep is left alone;
//!   a dry-run undo writes nothing.
//! * Every guard refuses with nothing written: no configured maintenance DSN,
//!   an unprivileged login, a missing agent, an empty reason, a held replay
//!   lock, an existing snapshot path, a plan that differs from the
//!   measurement, and a belief-mode skew (exit 3).
//!
//! The logins are created per test (roles are cluster-global, so each name is
//! unique) and dropped at the end; neither is a superuser. The superuser
//! fixture pool only seeds rows and reads results.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::path::{Path, PathBuf};
use std::process::Command;

use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_engine::edge_factor::{auto_wire_ds_for_edge, ensure_binary_frame, EdgeFactorOutcome};
use uuid::Uuid;

const SWEEP: &str = env!("CARGO_BIN_EXE_sweep_retired_source_bbas");
const DELTA: &str = env!("CARGO_BIN_EXE_supersede_belief_delta");
const NOTHING_ANSWERS: &str = "http://127.0.0.1:9";

// ── processes and logins ───────────────────────────────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("k10-retro-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).expect("create a temp dir");
        Self(dir)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("k10r_{}_{}", parent, Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' IN ROLE {parent}"
    ))
    .execute(pool)
    .await
    .expect("create the login");
    let base = fixture::database_url_for(pool).await;
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

struct Logins {
    app_role: String,
    app: String,
    maint_role: String,
    maint: String,
}

impl Logins {
    async fn new(pool: &PgPool) -> Self {
        let (app_role, app) = create_login(pool, "epigraph_app").await;
        let (maint_role, maint) = create_login(pool, "epigraph_maintenance").await;
        Self {
            app_role,
            app,
            maint_role,
            maint,
        }
    }
    async fn drop(self, pool: &PgPool) {
        drop_login(pool, &self.app_role).await;
        drop_login(pool, &self.maint_role).await;
    }
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn ok(&self) -> bool {
        self.code == Some(0)
    }
    fn says(&self, needle: &str) -> bool {
        self.stderr.contains(needle) || self.stdout.contains(needle)
    }
}

impl std::fmt::Display for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exit {:?}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// Run `bin` in `dir` with a cleared environment: the binaries load a `.env`,
/// and an inherited DSN would change what they do.
fn run(bin: &str, dir: &Path, args: &[&str], app: &str, maint: Option<&str>) -> Run {
    let mut cmd = Command::new(bin);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", app)
        .env("EPIGRAPH_API", NOTHING_ANSWERS)
        .env("RUST_LOG", "warn")
        .args(args)
        .current_dir(dir);
    if let Some(m) = maint {
        cmd.env("MAINTENANCE_DATABASE_URL", m);
    }
    let out = cmd.output().expect("run the binary");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The accepted measurement: the delta binary's report, as the operator's
/// S1 pre-count writes it.
fn measure(dir: &TempDir, name: &str, l: &Logins) -> (PathBuf, serde_json::Value) {
    let out = dir.path(name);
    let r = run(
        DELTA,
        &dir.0,
        &["--items", "k10-retro", "--json", out.to_str().unwrap()],
        &l.app,
        Some(&l.maint),
    );
    assert!(r.ok(), "the measurement runs: {r}");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("the report")).expect("JSON");
    (out, v)
}

fn apply_args<'a>(expect: &'a Path, snapshot: &'a Path, agent: &'a str) -> Vec<&'a str> {
    vec![
        "--apply",
        "--expect",
        expect.to_str().unwrap(),
        "--snapshot",
        snapshot.to_str().unwrap(),
        "--acting-agent",
        agent,
        "--reason",
        "k10 retro sweep test",
        "--allow-mode-skew",
    ]
}

// ── the world ──────────────────────────────────────────────────────────────

struct World {
    _scoped: epigraph_db::ScopedPool,
    owner: Uuid,
    /// Refuted by the retired claim AND supported by a current one: re-folded.
    refuted: Uuid,
    /// Contradicted by the retired claim alone: left unbacked.
    lonely: Uuid,
    /// A group-private holder of a row from the retired claim: unbacked.
    private_holder: Uuid,
    /// Its row from the retired claim was RETRACTED by its owner: kept.
    kept_row: Uuid,
    /// A live row keyed on the retired claim's edge to `refuted`, held by a
    /// RETIRED claim: not measured, so never deleted.
    stray_row: Uuid,
    bystander: Uuid,
}

async fn believed(pool: &PgPool, agent: Uuid, tag: &str, bel: f64, pl: f64) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, tag).await;
    sqlx::query("UPDATE claims SET belief = $2, plausibility = $3 WHERE id = $1")
        .bind(id)
        .bind(bel)
        .bind(pl)
        .execute(pool)
        .await
        .expect("plant an interval");
    id
}

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

async fn wire(pool: &PgPool, viewer: &Viewer, agent: Uuid, s: Uuid, t: Uuid, rel: &str) -> Uuid {
    let e = edge(pool, s, t, rel).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = auto_wire_ds_for_edge(&mut conn, viewer, e, agent, s, t, rel)
        .await
        .expect("auto-wire");
    assert_eq!(
        out,
        EdgeFactorOutcome::Wired,
        "PREMISE: {rel} {s}->{t} wires"
    );
    e
}

async fn stamp(conn: &mut sqlx::PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let csv = |g: &[Uuid]| g.iter().map(Uuid::to_string).collect::<Vec<_>>().join(",");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(csv(v.group_bind().expect("scoped viewer")))
    .bind(csv(v.writable_groups()))
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp the session");
}

async fn owned_claim(pool: &PgPool, owner: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(tag)
    .bind(&hash)
    .bind(owner)
    .bind(group)
    .execute(pool)
    .await
    .expect("a public claim owned by the owner's group");
    id
}

async fn row_on(pool: &PgPool, edge: Uuid, holder: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM mass_functions WHERE perspective_id = $1 AND claim_id = $2")
        .bind(edge)
        .bind(holder)
        .fetch_one(pool)
        .await
        .expect("the edge row")
}

async fn retire(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
          WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("retire by a plain flip");
}

async fn world(pool: &PgPool) -> World {
    let (scoped, bypass) = fixture::bypass(pool).await;
    let public = fixture::public_viewer(pool).await;
    let (agent, _) = fixture::seed_agent_with_group(pool, "k10r-author").await;
    let (owner, group) = fixture::seed_agent_with_group(pool, "k10r-owner").await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary frame");

    let retired = believed(pool, agent, "k10r refuter", 0.9, 0.95).await;
    let supporter = believed(pool, agent, "k10r supporter", 0.6, 0.7).await;
    let refuted = fixture::seed_public_claim(pool, agent, "k10r refuted").await;
    let lonely = fixture::seed_public_claim(pool, agent, "k10r lonely").await;
    let kept_holder = owned_claim(pool, owner, group, "k10r kept holder").await;
    let refuting = wire(pool, &public, agent, retired, refuted, "refutes").await;
    wire(pool, &public, agent, supporter, refuted, "supports").await;
    wire(pool, &public, agent, retired, lonely, "contradicts").await;
    let kept_edge = wire(pool, &public, agent, retired, kept_holder, "contradicts").await;
    let (pagent, pgroup) = fixture::seed_agent_with_group(pool, "k10r-private").await;
    let private_holder = fixture::seed_group_claim(pool, pagent, pgroup, "k10r private").await;
    wire(pool, &bypass, agent, retired, private_holder, "refutes").await;

    // The owner retracts its row through the real repository path: kept.
    let kept_row = row_on(pool, kept_edge, kept_holder).await;
    let p = pool.clone();
    let retracted = fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let r =
            MassFunctionRepository::retract_conn(&mut conn, kept_row, "k10r fixture", None).await;
        (conn, r)
    })
    .await
    .expect("the owner retracts the row");
    assert_eq!(retracted.status.as_str(), "retracted", "PREMISE");

    // A live row keyed on the refuting edge, held by a claim that is then
    // retired: on the retired source's edge, but not measured.
    let stray_holder = fixture::seed_public_claim(pool, agent, "k10r stray holder").await;
    let mut conn = pool.acquire().await.expect("acquire");
    PerspectiveRepository::ensure_edge_perspective(&mut *conn, refuting, Some(agent))
        .await
        .expect("edge perspective");
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        stray_holder,
        frame,
        Some(agent),
        Some(refuting),
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("edge_factor"),
        Some(0.9),
        Some("contradicts"),
        "cross",
        None,
    )
    .await
    .expect("the stray row");
    drop(conn);
    let stray_row = row_on(pool, refuting, stray_holder).await;
    retire(pool, stray_holder).await;

    // The retirement the K10(2) arm never saw.
    retire(pool, retired).await;

    // A bystander no selection touches.
    let s2 = believed(pool, agent, "k10r bystander supporter", 0.8, 0.9).await;
    let bystander = fixture::seed_public_claim(pool, agent, "k10r bystander").await;
    wire(pool, &public, agent, s2, bystander, "supports").await;

    World {
        _scoped: scoped,
        owner,
        refuted,
        lonely,
        private_holder,
        kept_row,
        stray_row,
        bystander,
    }
}

// ── reads ──────────────────────────────────────────────────────────────────

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

/// Everything a run could write: every BBA row exactly, every cache exactly
/// (float8 text is exact), and the audit table's size.
async fn footprint(pool: &PgPool) -> (String, String, i64) {
    let rows: String = sqlx::query_scalar(
        "SELECT COALESCE(md5(string_agg(to_jsonb(m.*)::text, '|' ORDER BY m.id)), '') \
           FROM mass_functions m",
    )
    .fetch_one(pool)
    .await
    .expect("rows");
    let caches: String = sqlx::query_scalar(
        "SELECT COALESCE(md5(string_agg(concat_ws(',', id, belief, plausibility, \
                pignistic_prob, mass_on_empty, mass_on_missing, belief_frame_id, classification), \
                '|' ORDER BY id)), '') FROM claims",
    )
    .fetch_one(pool)
    .await
    .expect("caches");
    let events = count(pool, "SELECT count(*) FROM security_events").await;
    (rows, caches, events)
}

async fn exists(pool: &PgPool, row: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1)")
        .bind(row)
        .fetch_one(pool)
        .await
        .expect("exists")
}

type Cache = (Option<f64>, Option<f64>, Option<f64>);

async fn cache(pool: &PgPool, id: Uuid) -> Cache {
    sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read cache")
}

fn close(a: Option<f64>, b: Option<f64>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => (x - y).abs() < 1e-12,
        (None, None) => true,
        _ => false,
    }
}

fn block(report: &serde_json::Value) -> &serde_json::Value {
    &report["k10_retro"]
}

fn claim(report: &serde_json::Value, id: Uuid) -> &serde_json::Value {
    block(report)["delta"]["claims"]
        .as_array()
        .expect("claims")
        .iter()
        .find(|c| c["id"] == id.to_string())
        .unwrap_or_else(|| panic!("{id} is in the measurement: {report}"))
}

fn f(v: &serde_json::Value) -> Option<f64> {
    v.as_f64()
}

/// The ids the selection names, read straight from the database.
async fn selected(pool: &PgPool) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = epigraph_engine::supersede_delta::retired_source_edge_bbas(
        &mut pool.acquire().await.expect("acquire"),
        None,
    )
    .await
    .expect("the selection")
    .into_iter()
    .map(|r| r.mass_function_id)
    .collect();
    ids.sort();
    ids
}

// ── tests ──────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn the_sweep_applies_exactly_the_measured_rows_and_the_undo_puts_them_back(pool: PgPool) {
    let w = world(&pool).await;
    let l = Logins::new(&pool).await;
    let dir = TempDir::new();
    let agent = w.owner.to_string();

    let planned = selected(&pool).await;
    assert_eq!(
        planned.len(),
        3,
        "PREMISE: refuted, lonely and the private holder"
    );
    assert!(
        !planned.contains(&w.kept_row) && !planned.contains(&w.stray_row),
        "PREMISE"
    );
    let (k0, report) = measure(&dir, "k0.json", &l);
    assert_eq!(block(&report)["live_rows"], 3, "{report}");
    assert_eq!(
        claim(&report, w.refuted)["outcome"],
        "recomputed",
        "PREMISE"
    );
    assert_eq!(claim(&report, w.lonely)["outcome"], "unbacked", "PREMISE");
    assert_eq!(
        claim(&report, w.private_holder)["outcome"],
        "unbacked",
        "PREMISE"
    );
    let start = footprint(&pool).await;
    let bystander = cache(&pool, w.bystander).await;

    // The dry run: the exact rows, the measurement's own block, nothing written.
    let r = run(
        SWEEP,
        &dir.0,
        &["--expect", k0.to_str().unwrap()],
        &l.app,
        Some(&l.maint),
    );
    assert!(r.ok(), "{r}");
    let plan: serde_json::Value = serde_json::from_str(&r.stdout).expect("the plan is JSON");
    assert_eq!(plan["dry_run"], true);
    assert_eq!(plan["matches_expect"], true, "{plan}");
    let mut rows: Vec<Uuid> = plan["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| r["mass_function_id"].as_str().unwrap().parse().unwrap())
        .collect();
    rows.sort();
    assert_eq!(
        rows, planned,
        "the dry run prints exactly the measured rows"
    );
    assert_eq!(footprint(&pool).await, start, "the dry run wrote something");

    // The apply.
    let snap = dir.path("snap.json");
    let cascade_rows = "SELECT count(*) FROM security_events WHERE event_type LIKE 'cascade.%'";
    let cascade_before = count(&pool, cascade_rows).await;
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&k0, &snap, &agent),
        &l.app,
        Some(&l.maint),
    );
    assert!(r.ok(), "{r}");
    for id in &planned {
        assert!(
            !exists(&pool, *id).await,
            "{id} was measured and is still there"
        );
    }
    assert!(
        exists(&pool, w.kept_row).await,
        "the retracted row was deleted"
    );
    assert!(
        exists(&pool, w.stray_row).await,
        "a row the measurement did not select (held by a retired claim) was deleted"
    );
    for id in [w.refuted, w.lonely, w.private_holder] {
        let new = &claim(&report, id)["new"];
        let (b, pl, p) = cache(&pool, id).await;
        assert!(
            close(b, f(&new["belief"]))
                && close(pl, f(&new["plausibility"]))
                && close(p, f(&new["betp"])),
            "{id}: the sweep wrote ({b:?}, {pl:?}, {p:?}); the measurement predicted {new}"
        );
    }
    assert_eq!(
        cache(&pool, w.bystander).await,
        bystander,
        "the bystander moved"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM security_events WHERE event_type = 'k10_retro.sweep_applied' \
              AND agent_id IS NULL"
        )
        .await,
        1,
        "one agent-less audit row"
    );
    assert_eq!(
        count(&pool, cascade_rows).await,
        cascade_before,
        "the sweep wrote a cascade.* row, which the replay would read"
    );
    let snapshot: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&snap).expect("the snapshot")).unwrap();
    assert_eq!(
        snapshot["deleted"].as_array().unwrap().len(),
        3,
        "{snapshot}"
    );
    assert_eq!(
        snapshot["caches"].as_array().unwrap().len(),
        3,
        "{snapshot}"
    );
    assert_eq!(snapshot["acting_agent"], agent);
    let (_, after) = measure(&dir, "k0-after.json", &l);
    assert_eq!(block(&after)["live_rows"], 0, "{after}");
    let swept = footprint(&pool).await;

    // Again: refused with the stale measurement, a no-op with a fresh one.
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&k0, &dir.path("snap-stale.json"), &agent),
        &l.app,
        Some(&l.maint),
    );
    assert!(!r.ok(), "a stale measurement was accepted: {r}");
    assert!(r.says("differs from the accepted measurement"), "{r}");
    assert!(
        !dir.path("snap-stale.json").exists(),
        "a refused run left its snapshot"
    );
    assert_eq!(footprint(&pool).await, swept);
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&dir.path("k0-after.json"), &dir.path("snap-2.json"), &agent),
        &l.app,
        Some(&l.maint),
    );
    assert!(r.ok(), "{r}");
    assert_eq!(
        footprint(&pool).await,
        swept,
        "a second apply wrote something"
    );

    // A dry-run undo writes nothing.
    let r = run(
        SWEEP,
        &dir.0,
        &["--undo", snap.to_str().unwrap(), "--dry-run"],
        &l.app,
        Some(&l.maint),
    );
    assert!(r.ok(), "{r}");
    assert!(
        r.says("restored=3"),
        "the dry run reports what it would restore: {r}"
    );
    assert_eq!(
        footprint(&pool).await,
        swept,
        "the dry-run undo wrote something"
    );

    // The undo: every row bit-identical, every cache exact.
    let r = run(
        SWEEP,
        &dir.0,
        &[
            "--undo",
            snap.to_str().unwrap(),
            "--acting-agent",
            &agent,
            "--reason",
            "k10 retro undo test",
            "--allow-mode-skew",
        ],
        &l.app,
        Some(&l.maint),
    );
    assert!(r.ok(), "{r}");
    let (rows, caches, _) = footprint(&pool).await;
    assert_eq!(
        (rows, caches),
        (start.0.clone(), start.1.clone()),
        "the undo is not exact"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM security_events WHERE event_type = 'k10_retro.sweep_undone'"
        )
        .await,
        1
    );
    // And the measurement is the accepted one again.
    let r = run(
        SWEEP,
        &dir.0,
        &["--expect", k0.to_str().unwrap()],
        &l.app,
        Some(&l.maint),
    );
    assert!(r.ok(), "{r}");
    l.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_undo_leaves_what_was_written_since_the_sweep_alone(pool: PgPool) {
    let w = world(&pool).await;
    let l = Logins::new(&pool).await;
    let dir = TempDir::new();
    let agent = w.owner.to_string();
    let (k0, _) = measure(&dir, "k0.json", &l);
    let snap = dir.path("snap.json");
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&k0, &snap, &agent),
        &l.app,
        Some(&l.maint),
    );
    assert!(r.ok(), "{r}");
    assert!(snap.exists(), "the apply wrote no snapshot: {r}");
    let snapshot: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&snap).unwrap()).unwrap();
    let deleted = |holder: Uuid| -> serde_json::Value {
        snapshot["deleted"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["holder_id"] == holder.to_string())
            .cloned()
            .expect("a deleted row of the holder")
    };

    // Since the sweep: another writer re-folded `lonely`'s cache, and a new
    // row took the private holder's deleted row's key.
    sqlx::query("UPDATE claims SET belief = 0.25, plausibility = 0.5 WHERE id = $1")
        .bind(w.lonely)
        .execute(&pool)
        .await
        .unwrap();
    let image: String = deleted(w.private_holder)["row"]
        .as_str()
        .unwrap()
        .to_string();
    let new_row: Uuid = sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, masses) \
         SELECT r.claim_id, r.frame_id, r.source_agent_id, r.perspective_id, \
                '{\"0,1\": 1.0}'::jsonb \
           FROM jsonb_populate_record(NULL::mass_functions, $1::jsonb) r RETURNING id",
    )
    .bind(&image)
    .fetch_one(&pool)
    .await
    .expect("a row at the deleted row's key");
    let private_cache = cache(&pool, w.private_holder).await;

    let report = dir.path("undo.json");
    let r = run(
        SWEEP,
        &dir.0,
        &[
            "--undo",
            snap.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            "--acting-agent",
            &agent,
            "--reason",
            "k10 retro undo test",
            "--allow-mode-skew",
        ],
        &l.app,
        Some(&l.maint),
    );
    assert!(r.ok(), "{r}");
    let out: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    let ids = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    };
    let private_row = deleted(w.private_holder)["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        ids(&out["rows"]["superseded_since_sweep"]),
        vec![private_row.clone()],
        "{out}"
    );
    assert_eq!(
        out["rows"]["restored"].as_array().unwrap().len(),
        2,
        "{out}"
    );
    assert!(
        !exists(&pool, private_row.parse().unwrap()).await,
        "the deleted row came back over a newer row at its key"
    );
    assert!(exists(&pool, new_row).await, "the newer row was removed");
    assert_eq!(
        ids(&out["caches_held_back"]),
        vec![w.private_holder.to_string()],
        "a holder whose row did not come back keeps its cache: {out}"
    );
    assert_eq!(cache(&pool, w.private_holder).await, private_cache);
    assert_eq!(
        ids(&out["caches"]["superseded_since_wave"]),
        vec![w.lonely.to_string()],
        "{out}"
    );
    let (b, pl, _) = cache(&pool, w.lonely).await;
    assert_eq!(
        (b, pl),
        (Some(0.25), Some(0.5)),
        "a cache written since was overwritten"
    );
    assert_eq!(
        ids(&out["caches"]["restored"]),
        vec![w.refuted.to_string()],
        "{out}"
    );
    l.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_sweep_refuses_without_a_configured_privileged_maintenance_login(pool: PgPool) {
    let w = world(&pool).await;
    let l = Logins::new(&pool).await;
    let dir = TempDir::new();
    let agent = w.owner.to_string();
    let (k0, _) = measure(&dir, "k0.json", &l);
    let start = footprint(&pool).await;
    let snap = dir.path("snap.json");

    // No MAINTENANCE_DATABASE_URL: the application DSN is never used.
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&k0, &snap, &agent),
        &l.maint,
        None,
    );
    assert!(!r.ok(), "{r}");
    assert!(
        r.says("runs only on an explicitly configured MAINTENANCE_DATABASE_URL"),
        "{r}"
    );
    // The dry run reads every group's rows, so it refuses the same way.
    let r = run(SWEEP, &dir.0, &[], &l.maint, None);
    assert!(!r.ok(), "{r}");
    assert!(
        r.says("explicitly configured MAINTENANCE_DATABASE_URL"),
        "{r}"
    );

    // A login that cannot bypass row security, as the maintenance DSN.
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&k0, &snap, &agent),
        &l.app,
        Some(&l.app),
    );
    assert!(!r.ok(), "{r}");
    assert!(r.says("does not satisfy epigraph_bypass()"), "{r}");

    assert_eq!(
        footprint(&pool).await,
        start,
        "a refused run wrote something"
    );
    assert!(!snap.exists(), "a refused run left its snapshot");
    l.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_apply_refuses_every_missing_precondition_and_writes_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let l = Logins::new(&pool).await;
    let dir = TempDir::new();
    let agent = w.owner.to_string();
    let (k0, report) = measure(&dir, "k0.json", &l);
    let start = footprint(&pool).await;
    let maint = Some(l.maint.as_str());
    let snap = dir.path("snap.json");

    // No --expect: clap refuses before anything runs.
    let r = run(
        SWEEP,
        &dir.0,
        &[
            "--apply",
            "--snapshot",
            snap.to_str().unwrap(),
            "--acting-agent",
            &agent,
            "--reason",
            "x",
            "--allow-mode-skew",
        ],
        &l.app,
        maint,
    );
    assert!(!r.ok(), "{r}");
    assert!(r.says("--expect"), "{r}");

    // An agent that does not exist.
    let ghost = Uuid::new_v4().to_string();
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&k0, &snap, &ghost),
        &l.app,
        maint,
    );
    assert!(!r.ok(), "{r}");
    assert!(r.says("is not an agent"), "{r}");
    assert!(!snap.exists(), "a refused run left its snapshot");

    // An empty reason.
    let mut args = apply_args(&k0, &snap, &agent);
    let at = args.iter().position(|a| *a == "--reason").unwrap();
    args[at + 1] = "  ";
    let r = run(SWEEP, &dir.0, &args, &l.app, maint);
    assert!(!r.ok(), "{r}");
    assert!(r.says("non-empty --reason"), "{r}");

    // A snapshot path that already exists: refused before the database.
    std::fs::write(&snap, "keep me").unwrap();
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&k0, &snap, &agent),
        &l.app,
        maint,
    );
    assert!(!r.ok(), "{r}");
    assert_eq!(
        std::fs::read_to_string(&snap).unwrap(),
        "keep me",
        "overwritten"
    );
    std::fs::remove_file(&snap).unwrap();

    // Another maintenance run holds the replay lock.
    let mut holder = pool.acquire().await.unwrap();
    let key = epigraph_db::repos::maintenance_lock::REPLAY_LOCK_KEY;
    assert!(
        epigraph_db::repos::maintenance_lock::try_take(&mut holder, key)
            .await
            .unwrap()
    );
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&k0, &snap, &agent),
        &l.app,
        maint,
    );
    assert!(
        epigraph_db::repos::maintenance_lock::release(&mut holder, key)
            .await
            .unwrap()
    );
    drop(holder);
    assert!(!r.ok(), "{r}");
    assert!(r.says("holds its lock"), "{r}");
    assert!(!snap.exists(), "a refused run left its snapshot");

    // A measurement the plan differs from: a count, then one served value.
    let mut drifted = report.clone();
    drifted["k10_retro"]["live_rows"] = serde_json::json!(4);
    let bad = dir.path("k0-count.json");
    std::fs::write(&bad, drifted.to_string()).unwrap();
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&bad, &snap, &agent),
        &l.app,
        maint,
    );
    assert!(!r.ok(), "{r}");
    assert!(
        r.says("k10_retro.live_rows"),
        "the difference is named: {r}"
    );
    assert!(!snap.exists(), "a refused run left its snapshot");
    let mut drifted = report.clone();
    let claims = drifted["k10_retro"]["delta"]["claims"]
        .as_array_mut()
        .unwrap();
    let old = claims[0]["old"]["betp"].as_f64().unwrap_or(0.5);
    claims[0]["old"]["betp"] = serde_json::json!(old + 1e-6);
    let bad = dir.path("k0-value.json");
    std::fs::write(&bad, drifted.to_string()).unwrap();
    let r = run(
        SWEEP,
        &dir.0,
        &apply_args(&bad, &snap, &agent),
        &l.app,
        maint,
    );
    assert!(!r.ok(), "{r}");
    assert!(r.says("old.betp"), "the difference is named: {r}");
    // The same drift fails the dry run's comparison too (exit 1).
    let r = run(
        SWEEP,
        &dir.0,
        &["--expect", bad.to_str().unwrap()],
        &l.app,
        maint,
    );
    assert!(!r.ok(), "{r}");
    assert!(r.says("\"matches_expect\": false"), "{r}");

    // A belief-mode skew (nothing answers at EPIGRAPH_API): exit 3.
    let mut args = apply_args(&k0, &snap, &agent);
    args.retain(|a| *a != "--allow-mode-skew");
    let r = run(SWEEP, &dir.0, &args, &l.app, maint);
    assert_eq!(r.code, Some(3), "{r}");

    assert_eq!(
        footprint(&pool).await,
        start,
        "a refused run wrote something"
    );
    assert!(!snap.exists(), "a refused run left its snapshot");
    // Every refusal above left the measured rows in place.
    assert_eq!(selected(&pool).await.len(), 3);
    l.drop(&pool).await;
}
