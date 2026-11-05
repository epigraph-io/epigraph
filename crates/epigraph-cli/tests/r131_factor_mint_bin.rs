//! `r131_factor_mint` (ruling R-131, backlog 5094766c), driven as the real
//! process an operator runs, on real NOSUPERUSER logins: an `epigraph_app`
//! login and an `epigraph_maintenance` login, as on a deployment.
//!
//! The ORACLE is the measurement the operator accepted, read on the same
//! database: `epigraph_engine::supersede_delta::r131_factorless_edges` and
//! `slots_minted` (what `supersede_belief_delta --items r131` reports). The
//! tool must plan exactly that set, mint exactly its slots, and leave the
//! measurement with nothing to fill.
//!
//! The fixture holds, beside the edges the mint must fill (a symmetric
//! `corroborates` pair sharing one slot, a `refutes` edge, and an edge
//! between GROUP-private claims an unprivileged session could not see), the
//! rows it must not touch: a factorless edge whose slot another edge's factor
//! holds; one whose slot only a FRAME-scoped factor holds (the measurement
//! counts it held, but the per-frame unique index would let a careless mint
//! add a frame-less twin); a withdrawn edge; an edge to a retired claim; and a
//! factorless `supports` edge (not an R-131 relationship).
//!
//! Guards pinned here, each with nothing written: no configured
//! `MAINTENANCE_DATABASE_URL` (every mode); an application login as the
//! maintenance DSN; an existing output file; a plan the live set no longer
//! equals (including re-applying an applied plan); a held mint lock; and the
//! undo's compare-and-set (a factor changed or removed since the mint is kept
//! or reported, and nothing it did not mint is deleted, while a column added
//! to `factors` since, or another session time zone, does not block it). The
//! library's own privileged-session check is pinned on an application session
//! directly (the binary's app-login refusal above is the maintenance pool's).
//! BP only: no mass function and no claim column changes across an apply.
//!
//! The process environment is CLEARED (and the working directory is a temp
//! dir): the binary loads a `.env`, and an inherited `MAINTENANCE_DATABASE_URL`
//! would point it elsewhere or mask the refusal.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use epigraph_cli::r131_factor_mint::{
    self, read_record, write_record, MintError, MintPlan, RecordHeader, MINT_LOCK_NAME, RECORD_KIND,
};
use epigraph_engine::supersede_delta::{r131_factorless_edges, slots_minted, FactorlessEdge};
use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_r131_factor_mint");
const REFUSAL: &str = "runs only on an explicitly configured MAINTENANCE_DATABASE_URL";
/// `epigraph_db::pool::maintenance_verdict`'s REFUSAL arm (row security is
/// on and the login is not in `epigraph_maintenance`), reached through
/// `MaintenancePool::connect`. Both fragments are absent from its
/// non-refusing arm and from the privileged log line.
const APP_LOGIN_REFUSAL: [&str; 2] = [
    "session_user is not a member of epigraph_maintenance",
    "Refusing to run",
];

// ---------------------------------------------------------------- logins

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("r131_{}_{}", parent, Uuid::new_v4().simple());
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
        for role in [self.app.0, self.maint.0] {
            let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
                .execute(pool)
                .await;
        }
    }
}

// ---------------------------------------------------------------- process

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn ok(self) -> Self {
        assert_eq!(
            self.code,
            Some(0),
            "the run failed: {}\n{}",
            self.stderr,
            self.stdout
        );
        self
    }
}

fn run(dir: &Path, args: &[&str], database_url: &str, maintenance_url: Option<&str>) -> Run {
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

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("r131-mint-{}", Uuid::new_v4().simple()));
        std::fs::create_dir(&p).expect("temp dir");
        Self(p)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn read_plan(path: &str) -> MintPlan {
    serde_json::from_str(&std::fs::read_to_string(path).expect("read the plan"))
        .expect("the plan parses")
}

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

/// Drop the trigger's factor of `e` (the state a past cascade's re-pointing
/// UPDATE left: the trigger fires on INSERT only).
async fn strip(pool: &PgPool, e: Uuid) {
    sqlx::query("DELETE FROM factors WHERE properties->>'source_edge_id' = $1")
        .bind(e.to_string())
        .execute(pool)
        .await
        .expect("strip the factor");
}

async fn factorless(pool: &PgPool, s: Uuid, t: Uuid, rel: &str) -> Uuid {
    let e = edge(pool, s, t, rel).await;
    strip(pool, e).await;
    e
}

/// Factors on the `(type, pair)` slot of `a`, `b`, as (id, frame-less).
async fn on_slot(pool: &PgPool, ft: &str, a: Uuid, b: Uuid) -> Vec<(Uuid, bool, Option<String>)> {
    sqlx::query_as(
        "SELECT id, frame_id IS NULL, properties->>'source_edge_id' FROM factors \
          WHERE factor_type = $1 \
            AND variable_ids = CASE WHEN $2::uuid < $3::uuid THEN ARRAY[$2::uuid, $3::uuid] \
                                    ELSE ARRAY[$3::uuid, $2::uuid] END \
          ORDER BY id",
    )
    .bind(ft)
    .bind(a)
    .bind(b)
    .fetch_all(pool)
    .await
    .expect("factors on the slot")
}

struct World {
    /// The symmetric pair's first edge (earlier) and second.
    pair: (Uuid, Uuid),
    pair_ends: (Uuid, Uuid),
    refutes: Uuid,
    refutes_ends: (Uuid, Uuid),
    private_edge: Uuid,
    /// Factorless; its slot is held by `holder`'s factor.
    held_by_other: Uuid,
    held_by_other_ends: (Uuid, Uuid),
    holder: Uuid,
    /// Factorless; its slot is held only by a frame-scoped factor.
    held_on_frame: Uuid,
    held_on_frame_ends: (Uuid, Uuid),
    /// Never selected.
    withdrawn: Uuid,
    to_retired: Uuid,
    supports: Uuid,
}

async fn world(pool: &PgPool) -> World {
    let (agent, _) = viewer_fixture::seed_agent_with_group(pool, "r131-author").await;
    let (pagent, pgroup) = viewer_fixture::seed_agent_with_group(pool, "r131-private").await;
    let c = |tag: &'static str| viewer_fixture::seed_public_claim(pool, agent, tag);

    let (a, b) = (c("r131 a").await, c("r131 b").await);
    let first = factorless(pool, a, b, "corroborates").await;
    let second = factorless(pool, b, a, "corroborates").await;

    let (rc, rd) = (c("r131 c").await, c("r131 d").await);
    let refutes = factorless(pool, rc, rd, "refutes").await;

    let p = viewer_fixture::seed_group_claim(pool, pagent, pgroup, "r131 private p").await;
    let q = viewer_fixture::seed_group_claim(pool, pagent, pgroup, "r131 private q").await;
    let private_edge = factorless(pool, p, q, "corroborates").await;

    let (e, f) = (c("r131 e").await, c("r131 f").await);
    let held_by_other = factorless(pool, e, f, "corroborates").await;
    // The reverse edge's INSERT trigger fills the shared slot.
    let holder = edge(pool, f, e, "corroborates").await;
    assert_eq!(
        on_slot(pool, "evidential_support", e, f).await.len(),
        1,
        "PREMISE: the holder's trigger factor holds the slot"
    );

    let (g, h) = (c("r131 g").await, c("r131 h").await);
    let held_on_frame = factorless(pool, g, h, "corroborates").await;
    let public = viewer_fixture::public_viewer(pool).await;
    let frame = epigraph_engine::edge_factor::ensure_binary_frame(
        &mut pool.acquire().await.expect("acquire"),
        &public,
    )
    .await
    .expect("binary frame");
    sqlx::query(
        "INSERT INTO factors (factor_type, variable_ids, potential, frame_id, properties) \
         VALUES ('evidential_support', \
                 CASE WHEN $1::uuid < $2::uuid THEN ARRAY[$1::uuid, $2::uuid] \
                      ELSE ARRAY[$2::uuid, $1::uuid] END, \
                 '{\"strength\": 0.85}', $3, '{\"fixture\": \"frame-scoped holder\"}')",
    )
    .bind(g)
    .bind(h)
    .bind(frame)
    .execute(pool)
    .await
    .expect("a frame-scoped factor on the slot");

    let (i, j) = (c("r131 i").await, c("r131 j").await);
    let withdrawn = factorless(pool, i, j, "corroborates").await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(withdrawn)
        .execute(pool)
        .await
        .expect("withdraw");

    let (k, l) = (c("r131 k").await, c("r131 l").await);
    let to_retired = factorless(pool, k, l, "corroborates").await;
    sqlx::query(
        "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
          WHERE id = $1",
    )
    .bind(l)
    .execute(pool)
    .await
    .expect("retire");

    let (m, n) = (c("r131 m").await, c("r131 n").await);
    let supports = factorless(pool, m, n, "supports").await;

    World {
        pair: (first, second),
        pair_ends: (a, b),
        refutes,
        refutes_ends: (rc, rd),
        private_edge,
        held_by_other,
        held_by_other_ends: (e, f),
        holder,
        held_on_frame,
        held_on_frame_ends: (g, h),
        withdrawn,
        to_retired,
        supports,
    }
}

/// The accepted measurement, on the same database.
async fn measure(pool: &PgPool) -> (Vec<FactorlessEdge>, Vec<String>) {
    let mut conn = pool.acquire().await.expect("acquire");
    let edges = r131_factorless_edges(&mut conn).await.expect("measure");
    let slots = slots_minted(&edges);
    (edges, slots)
}

/// Every factor row, as `to_jsonb` text by id.
async fn factor_rows(pool: &PgPool) -> BTreeMap<Uuid, String> {
    sqlx::query_as::<_, (Uuid, String)>("SELECT id, to_jsonb(f)::text FROM factors f")
        .fetch_all(pool)
        .await
        .expect("factor rows")
        .into_iter()
        .collect()
}

/// A digest of every mass function row and every claim's belief columns.
async fn ds_state(pool: &PgPool) -> (Option<String>, Option<String>) {
    sqlx::query_as(
        "SELECT (SELECT md5(string_agg(to_jsonb(m)::text, '|' ORDER BY m.id)) \
                   FROM mass_functions m), \
                (SELECT md5(string_agg(concat_ws(',', c.id, c.belief, c.plausibility, \
                                                 c.pignistic_prob, c.truth_value, c.updated_at), \
                                       '|' ORDER BY c.id)) FROM claims c)",
    )
    .fetch_one(pool)
    .await
    .expect("ds state")
}

fn counts_line(prefix: &str, edges: &[FactorlessEdge], slots: usize) -> String {
    format!(
        "{prefix}: {} factorless edges, {slots} slots a mint would fill, {} on held slots",
        edges.len(),
        edges.iter().filter(|e| e.slot_held).count()
    )
}

fn dry_run(dir: &Dir, logins: &Logins, name: &str) -> (Run, String) {
    let path = dir.path(name);
    let r = run(
        &dir.0,
        &["--plan-out", &path],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    (r, path)
}

// ---------------------------------------------------------------- tests

#[sqlx::test(migrations = "../../migrations")]
async fn every_mode_refuses_without_a_configured_maintenance_dsn(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let _w = world(&pool).await;
    let dir = Dir::new();
    // A valid plan and an (empty) valid record, so each mode reaches its
    // connection before it can refuse.
    let mut conn = pool.acquire().await.expect("acquire");
    let plan = epigraph_cli::r131_factor_mint::dry_run(&mut conn, None)
        .await
        .expect("plan on the superuser pool");
    drop(conn);
    assert!(
        !plan.slots.is_empty(),
        "PREMISE: there is something to mint"
    );
    let plan_file = dir.path("plan.json");
    std::fs::write(&plan_file, serde_json::to_vec(&plan).expect("json")).expect("write plan");
    let empty_record = dir.path("empty.jsonl");
    let mut f = std::fs::File::create(&empty_record).expect("record");
    write_record(
        &mut f,
        &RecordHeader {
            kind: RECORD_KIND.into(),
            plan_sha256: plan.sha256(),
            minted: 0,
        },
        &[],
    )
    .expect("write record");
    let before = factor_rows(&pool).await;

    let plan_out = dir.path("refused-plan.json");
    let record = dir.path("refused-record.jsonl");
    let cases: [Vec<&str>; 4] = [
        vec!["--plan-out", &plan_out],
        vec!["--apply", "--plan", &plan_file, "--record", &record],
        vec!["--undo", &empty_record],
        vec!["--undo", &empty_record, "--apply"],
    ];
    for args in &cases {
        // The maintenance login itself as DATABASE_URL: a privileged DSN that
        // reaches the binary only through the fallback is still refused.
        let r = run(&dir.0, args, &logins.maint.1, None);
        assert_ne!(r.code, Some(0), "{args:?} ran: {}", r.stdout);
        assert!(r.stderr.contains(REFUSAL), "{args:?}: {}", r.stderr);
    }
    assert!(
        !Path::new(&plan_out).exists(),
        "a refused dry run left its plan"
    );
    assert!(
        !Path::new(&record).exists(),
        "a refused apply left a record"
    );
    assert_eq!(factor_rows(&pool).await, before, "a refused run wrote");
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_application_login_as_the_maintenance_dsn_is_refused(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let w = world(&pool).await;
    let dir = Dir::new();
    let plan_out = dir.path("plan.json");
    let before = factor_rows(&pool).await;

    let r = run(
        &dir.0,
        &["--plan-out", &plan_out],
        &logins.app.1,
        Some(&logins.app.1),
    );
    assert_ne!(r.code, Some(0), "an app-login dry run ran: {}", r.stdout);
    for text in APP_LOGIN_REFUSAL {
        assert!(r.stderr.contains(text), "dry run: {}", r.stderr);
    }
    assert!(
        !Path::new(&plan_out).exists(),
        "a refused dry run left its plan"
    );

    // A plan the maintenance login made, applied through an app login.
    let (ok, plan_file) = dry_run(&dir, &logins, "good-plan.json");
    ok.ok();
    assert!(
        read_plan(&plan_file)
            .slots
            .iter()
            .any(|s| s.source_edge_id == w.private_edge),
        "PREMISE: the maintenance plan sees the group-private edge"
    );
    let record = dir.path("record.jsonl");
    let r = run(
        &dir.0,
        &["--apply", "--plan", &plan_file, "--record", &record],
        &logins.app.1,
        Some(&logins.app.1),
    );
    assert_ne!(r.code, Some(0), "an app-login apply ran: {}", r.stdout);
    for text in APP_LOGIN_REFUSAL {
        assert!(r.stderr.contains(text), "apply: {}", r.stderr);
    }
    assert!(
        !Path::new(&record).exists(),
        "a refused apply left a record"
    );
    assert_eq!(factor_rows(&pool).await, before, "a refused run wrote");
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_dry_run_plans_exactly_the_measured_set_and_writes_nothing(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let w = world(&pool).await;
    let dir = Dir::new();
    let before = factor_rows(&pool).await;
    let ds_before = ds_state(&pool).await;
    let (edges, slots) = measure(&pool).await;

    let (r, path) = dry_run(&dir, &logins, "plan.json");
    let r = r.ok();
    assert!(
        r.stdout.contains(&counts_line("r131", &edges, slots.len())),
        "the dry run's counts are the measurement's: {}",
        r.stdout
    );
    let plan = read_plan(&path);

    // The measurement's set, exactly.
    assert_eq!(
        plan.slots
            .iter()
            .map(|s| s.slot.clone())
            .collect::<Vec<_>>(),
        slots,
        "the plan fills exactly the slots the measurement says a mint would fill"
    );
    assert_eq!(plan.edges, edges.len());
    let mut held: Vec<Uuid> = edges
        .iter()
        .filter(|e| e.slot_held)
        .map(|e| e.edge_id)
        .collect();
    held.sort_unstable();
    assert_eq!(
        plan.held_edges, held,
        "held edges are listed, never planned"
    );
    for s in &plan.slots {
        let on: BTreeSet<Uuid> = edges
            .iter()
            .filter(|e| e.slot == s.slot)
            .map(|e| e.edge_id)
            .collect();
        assert_eq!(
            s.edges.iter().copied().collect::<BTreeSet<_>>(),
            on,
            "{}: every measured edge on the slot",
            s.slot
        );
        let earliest: Uuid = sqlx::query_scalar(
            "SELECT id FROM edges WHERE id = ANY($1) ORDER BY created_at, id LIMIT 1",
        )
        .bind(&s.edges)
        .fetch_one(&pool)
        .await
        .expect("earliest");
        assert_eq!(s.source_edge_id, earliest, "{}: the trigger's pick", s.slot);
    }

    // The fixture, by name.
    let slot_of = |e: Uuid| plan.slots.iter().find(|s| s.edges.contains(&e));
    let pair = slot_of(w.pair.0).expect("the symmetric pair's slot is planned");
    assert_eq!(
        pair.source_edge_id, w.pair.0,
        "the earlier edge of the pair wins"
    );
    assert_eq!(pair.edges, vec![w.pair.0, w.pair.1]);
    let (a, b) = w.pair_ends;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    assert_eq!(pair.slot, format!("evidential_support:{lo},{hi}"));
    assert_eq!(
        slot_of(w.refutes).map(|s| s.factor_type.as_str()),
        Some("mutual_exclusion")
    );
    assert!(
        slot_of(w.private_edge).is_some(),
        "the group-private edge is planned (the maintenance login sees it)"
    );
    for e in [w.held_by_other, w.held_on_frame] {
        assert!(
            slot_of(e).is_none() && plan.held_edges.contains(&e),
            "{e} is held"
        );
    }
    let named: BTreeSet<Uuid> = plan
        .slots
        .iter()
        .flat_map(|s| s.edges.iter().copied())
        .chain(plan.held_edges.iter().copied())
        .collect();
    for e in [w.withdrawn, w.to_retired, w.supports, w.holder] {
        assert!(!named.contains(&e), "{e} is not in the R-131 set");
    }

    // Nothing written; a second dry run is byte-identical.
    assert_eq!(
        factor_rows(&pool).await,
        before,
        "the dry run wrote a factor"
    );
    assert_eq!(
        ds_state(&pool).await,
        ds_before,
        "the dry run wrote DS state"
    );
    let (r2, path2) = dry_run(&dir, &logins, "plan2.json");
    r2.ok();
    assert_eq!(
        std::fs::read(&path).expect("read"),
        std::fs::read(&path2).expect("read"),
        "two dry runs on one state differ"
    );

    // An existing plan file is refused and kept; --apply with --dry-run and
    // --apply without a plan are refused.
    let r = run(
        &dir.0,
        &["--plan-out", &path],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    assert_ne!(r.code, Some(0), "an existing plan file was overwritten");
    assert_eq!(read_plan(&path), plan, "the existing plan was changed");
    let r = run(
        &dir.0,
        &[
            "--apply",
            "--dry-run",
            "--plan",
            &path,
            "--record",
            &dir.path("r"),
        ],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    assert_ne!(r.code, Some(0), "--apply with --dry-run ran: {}", r.stdout);
    assert!(r.stderr.contains("cannot be used with"), "{}", r.stderr);
    let r = run(&dir.0, &["--apply"], &logins.app.1, Some(&logins.maint.1));
    assert_ne!(r.code, Some(0), "--apply without a plan ran: {}", r.stdout);
    assert!(r.stderr.contains("--plan"), "{}", r.stderr);
    assert_eq!(factor_rows(&pool).await, before, "a refused run wrote");
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn apply_mints_exactly_the_planned_slots_bp_only_and_once(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let w = world(&pool).await;
    let dir = Dir::new();
    let (r, plan_file) = dry_run(&dir, &logins, "plan.json");
    r.ok();
    let plan = read_plan(&plan_file);
    let before = factor_rows(&pool).await;
    let ds_before = ds_state(&pool).await;
    let record = dir.path("record.jsonl");

    let r = run(
        &dir.0,
        &["--apply", "--plan", &plan_file, "--record", &record],
        &logins.app.1,
        Some(&logins.maint.1),
    )
    .ok();
    assert!(
        r.stdout
            .contains(&format!("r131 apply: minted {} factors", plan.slots.len())),
        "{}",
        r.stdout
    );

    // Exactly the planned factors were added; nothing else changed.
    let after = factor_rows(&pool).await;
    for (id, row) in &before {
        assert_eq!(after.get(id), Some(row), "pre-existing factor {id} changed");
    }
    let added: Vec<Uuid> = after
        .keys()
        .filter(|id| !before.contains_key(id))
        .copied()
        .collect();
    let minted: BTreeSet<(String, String, bool)> = sqlx::query_as(
        "SELECT factor_type || ':' || array_to_string(variable_ids, ','), \
                properties->>'source_edge_id', frame_id IS NULL \
           FROM factors WHERE id = ANY($1)",
    )
    .bind(&added)
    .fetch_all(&pool)
    .await
    .expect("the added rows")
    .into_iter()
    .collect();
    let planned: BTreeSet<(String, String, bool)> = plan
        .slots
        .iter()
        .map(|s| (s.slot.clone(), s.source_edge_id.to_string(), true))
        .collect();
    assert_eq!(
        minted, planned,
        "the minted factors are the plan's, frame-less"
    );
    assert_eq!(added.len(), plan.slots.len(), "one factor per slot");
    let (g, h) = w.held_on_frame_ends;
    assert_eq!(
        on_slot(&pool, "evidential_support", g, h).await.len(),
        1,
        "no frame-less twin of the frame-held slot"
    );
    let (e, f) = w.held_by_other_ends;
    assert_eq!(
        on_slot(&pool, "evidential_support", e, f).await,
        vec![(
            before
                .keys()
                .copied()
                .find(|id| before[id].contains(&w.holder.to_string()))
                .expect("the holder's factor"),
            true,
            Some(w.holder.to_string())
        )],
        "the held slot keeps only the holder's factor"
    );
    let (rc, rd) = w.refutes_ends;
    assert_eq!(on_slot(&pool, "mutual_exclusion", rc, rd).await.len(), 1);
    assert_eq!(ds_state(&pool).await, ds_before, "the mint wrote DS state");

    // The measurement now has nothing to fill: the minted edges left it,
    // their slot-mates and the held edges stay, on held slots.
    let (edges_after, slots_after) = measure(&pool).await;
    assert!(slots_after.is_empty(), "slots left: {slots_after:?}");
    assert_eq!(edges_after.len(), plan.edges - plan.slots.len());
    assert!(edges_after.iter().all(|e| e.slot_held));
    assert!(
        r.stdout
            .contains(&counts_line("r131 after", &edges_after, 0)),
        "{}",
        r.stdout
    );
    assert!(edges_after.iter().any(|e| e.edge_id == w.pair.1));

    // The record names exactly the added rows.
    let rec = read_record(std::io::BufReader::new(
        std::fs::File::open(&record).expect("open record"),
    ))
    .expect("the record parses");
    assert_eq!(rec.header.plan_sha256, plan.sha256());
    let recorded: BTreeSet<Uuid> = rec.factors.iter().map(|f| f.factor_id).collect();
    assert_eq!(recorded, added.iter().copied().collect::<BTreeSet<_>>());

    // Re-applying the applied plan is refused (the live set changed) and
    // writes nothing; a fresh plan is empty and its apply mints nothing.
    let r = run(
        &dir.0,
        &[
            "--apply",
            "--plan",
            &plan_file,
            "--record",
            &dir.path("again.jsonl"),
        ],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    assert_ne!(r.code, Some(0), "an applied plan was applied again");
    assert!(
        r.stderr.contains("no longer equals the plan"),
        "{}",
        r.stderr
    );
    assert!(!Path::new(&dir.path("again.jsonl")).exists());
    let (r, plan2) = dry_run(&dir, &logins, "plan2.json");
    r.ok();
    assert!(read_plan(&plan2).slots.is_empty(), "a second plan mints");
    let r = run(
        &dir.0,
        &[
            "--apply",
            "--plan",
            &plan2,
            "--record",
            &dir.path("r2.jsonl"),
        ],
        &logins.app.1,
        Some(&logins.maint.1),
    )
    .ok();
    assert!(
        r.stdout.contains("r131 apply: minted 0 factors"),
        "{}",
        r.stdout
    );
    assert_eq!(factor_rows(&pool).await, after, "the second apply wrote");
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn apply_refuses_a_drifted_plan_an_existing_record_and_a_held_lock(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let w = world(&pool).await;
    let dir = Dir::new();
    let (r, plan_file) = dry_run(&dir, &logins, "plan.json");
    r.ok();

    // An existing record file: refused, kept as it was.
    let existing = dir.path("existing.jsonl");
    std::fs::write(&existing, "keep").expect("write");
    let before = factor_rows(&pool).await;
    let r = run(
        &dir.0,
        &["--apply", "--plan", &plan_file, "--record", &existing],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    assert_ne!(r.code, Some(0), "an existing record was overwritten");
    assert_eq!(std::fs::read_to_string(&existing).expect("read"), "keep");
    assert_eq!(factor_rows(&pool).await, before);

    // Another run holds the mint lock: refused.
    let mut holder = pool.acquire().await.expect("acquire");
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
        .bind(MINT_LOCK_NAME)
        .execute(&mut *holder)
        .await
        .expect("hold the lock");
    let record = dir.path("locked.jsonl");
    let r = run(
        &dir.0,
        &["--apply", "--plan", &plan_file, "--record", &record],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    assert_ne!(r.code, Some(0), "an apply ran under a held lock");
    assert!(r.stderr.contains("holds the mint lock"), "{}", r.stderr);
    assert!(
        !Path::new(&record).exists(),
        "a refused apply left a record"
    );
    sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
        .bind(MINT_LOCK_NAME)
        .execute(&mut *holder)
        .await
        .expect("release");
    drop(holder);
    assert_eq!(factor_rows(&pool).await, before);

    // A drift that keeps every count: the pair's second edge is withdrawn and
    // a third factorless edge joins the same slot. Same edges, slots and held
    // counts, a different set: refused, and the message tells the plans apart.
    let plan = read_plan(&plan_file);
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(w.pair.1)
        .execute(&pool)
        .await
        .expect("withdraw");
    let (a, b) = w.pair_ends;
    let third = factorless(&pool, a, b, "corroborates").await;
    let (edges_now, slots_now) = measure(&pool).await;
    assert_eq!(
        (
            edges_now.len(),
            slots_now.len(),
            edges_now.iter().filter(|e| e.slot_held).count()
        ),
        (plan.edges, plan.slots_minted, plan.edges_on_held_slots),
        "PREMISE: the drift keeps every count"
    );
    assert!(edges_now.iter().any(|e| e.edge_id == third), "PREMISE");
    let before = factor_rows(&pool).await;
    let record = dir.path("same-counts.jsonl");
    let r = run(
        &dir.0,
        &["--apply", "--plan", &plan_file, "--record", &record],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    assert_eq!(
        r.code,
        Some(1),
        "a same-counts drift was applied: {}",
        r.stdout
    );
    assert!(
        r.stderr.contains("no longer equals the plan"),
        "{}",
        r.stderr
    );
    assert!(
        r.stderr.contains(&format!("sha256 {}", plan.sha256())),
        "the refusal names the reviewed plan's sha256: {}",
        r.stderr
    );
    assert!(
        !Path::new(&record).exists(),
        "a refused apply left a record"
    );
    assert_eq!(factor_rows(&pool).await, before, "a refused apply wrote");

    // The live set gained a factorless edge since the plan: refused.
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "r131-drift").await;
    let x = viewer_fixture::seed_public_claim(&pool, agent, "r131 x").await;
    let y = viewer_fixture::seed_public_claim(&pool, agent, "r131 y").await;
    factorless(&pool, x, y, "corroborates").await;
    let before = factor_rows(&pool).await;
    let record = dir.path("drift.jsonl");
    let r = run(
        &dir.0,
        &["--apply", "--plan", &plan_file, "--record", &record],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    assert_ne!(r.code, Some(0), "a drifted plan was applied");
    assert!(
        r.stderr.contains("no longer equals the plan"),
        "{}",
        r.stderr
    );
    assert!(
        !Path::new(&record).exists(),
        "a refused apply left a record"
    );
    assert_eq!(factor_rows(&pool).await, before, "a refused apply wrote");
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn undo_deletes_by_compare_and_set_only_what_the_mint_wrote(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let w = world(&pool).await;
    let dir = Dir::new();
    let (r, plan_file) = dry_run(&dir, &logins, "plan.json");
    r.ok();
    let before = factor_rows(&pool).await;
    let record = dir.path("record.jsonl");
    run(
        &dir.0,
        &["--apply", "--plan", &plan_file, "--record", &record],
        &logins.app.1,
        Some(&logins.maint.1),
    )
    .ok();
    let rec = read_record(std::io::BufReader::new(
        std::fs::File::open(&record).expect("open"),
    ))
    .expect("record");
    let of = |e: Uuid| {
        rec.factors
            .iter()
            .find(|f| f.source_edge_id == e)
            .map(|f| f.factor_id)
            .expect("minted")
    };
    let (kept_whole, changed, gone) = (of(w.pair.0), of(w.refutes), of(w.private_edge));
    assert!(rec.factors.len() >= 3, "PREMISE");

    // Since the mint: one factor patched, one removed, and a BP message
    // written against an untouched one.
    sqlx::query("UPDATE factors SET potential = '{\"patched\": true}' WHERE id = $1")
        .bind(changed)
        .execute(&pool)
        .await
        .expect("patch");
    sqlx::query("DELETE FROM factors WHERE id = $1")
        .bind(gone)
        .execute(&pool)
        .await
        .expect("remove");
    sqlx::query(
        "INSERT INTO bp_messages (direction, factor_id, variable_id, message) \
         VALUES ('factor_to_var', $1, $2, '{}')",
    )
    .bind(kept_whole)
    .bind(w.pair_ends.0)
    .execute(&pool)
    .await
    .expect("a bp message");
    let state = factor_rows(&pool).await;
    let others = rec.factors.len() - 3;

    // Dry run: executes and rolls back.
    let r = run(
        &dir.0,
        &["--undo", &record],
        &logins.app.1,
        Some(&logins.maint.1),
    )
    .ok();
    assert!(
        r.stdout.contains(&format!(
            "r131 undo (dry run: rolled back): deleted={} absent=1 changed_since=1 \
             bp_messages_removed=1",
            1 + others
        )),
        "{}",
        r.stdout
    );
    assert_eq!(factor_rows(&pool).await, state, "the undo dry run deleted");

    let r = run(
        &dir.0,
        &["--undo", &record, "--apply"],
        &logins.app.1,
        Some(&logins.maint.1),
    )
    .ok();
    assert!(
        r.stdout.contains(&format!(
            "r131 undo: deleted={} absent=1 changed_since=1 bp_messages_removed=1",
            1 + others
        )),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains(&format!("changed_since {changed}")),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains(&format!("absent {gone}")), "{}", r.stdout);
    let end = factor_rows(&pool).await;
    // Back to the pre-mint factors, plus the patched one the undo kept.
    let mut expected = before.clone();
    expected.insert(changed, state[&changed].clone());
    assert_eq!(
        end, expected,
        "the undo deleted a factor it did not mint, or left one"
    );
    let bp: i64 = sqlx::query_scalar("SELECT count(*) FROM bp_messages WHERE factor_id = $1")
        .bind(kept_whole)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(bp, 0);

    // A second undo deletes nothing more.
    let r = run(
        &dir.0,
        &["--undo", &record, "--apply"],
        &logins.app.1,
        Some(&logins.maint.1),
    )
    .ok();
    assert!(
        r.stdout.contains(&format!(
            "r131 undo: deleted=0 absent={} changed_since=1",
            2 + others
        )),
        "{}",
        r.stdout
    );
    assert_eq!(factor_rows(&pool).await, end);
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_library_refuses_an_application_session_before_any_write(pool: PgPool) {
    let _w = world(&pool).await;
    let dir = Dir::new();
    let mut conn = pool.acquire().await.expect("acquire");
    let plan = r131_factor_mint::dry_run(&mut conn, None)
        .await
        .expect("plan on the superuser pool");
    drop(conn);
    assert!(
        !plan.slots.is_empty(),
        "PREMISE: there is something to mint"
    );
    let before = factor_rows(&pool).await;

    // apply, on an application session: refused before any statement.
    let path = dir.path("app-record.jsonl");
    let mut file = std::fs::File::create(&path).expect("record file");
    let p = plan.clone();
    let r = viewer_fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = r131_factor_mint::apply(&mut conn, &p, &mut file, None).await;
        (conn, r)
    })
    .await;
    assert!(matches!(r, Err(MintError::NotPrivileged)), "apply: {r:?}");
    assert_eq!(factor_rows(&pool).await, before, "a refused apply wrote");
    assert_eq!(
        std::fs::metadata(&path).expect("stat").len(),
        0,
        "a refused apply wrote its record"
    );

    // A real mint (superuser), then its undo on an application session.
    let real = dir.path("record.jsonl");
    let mut file = std::fs::File::create(&real).expect("record file");
    let mut conn = pool.acquire().await.expect("acquire");
    let report = r131_factor_mint::apply(&mut conn, &plan, &mut file, None)
        .await
        .expect("the superuser mint");
    drop(conn);
    assert_eq!(report.minted, plan.slots.len(), "PREMISE");
    let record = read_record(std::io::BufReader::new(
        std::fs::File::open(&real).expect("open"),
    ))
    .expect("record");
    let minted = factor_rows(&pool).await;
    for dry_run in [true, false] {
        let rec = record.clone();
        let r = viewer_fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let r = r131_factor_mint::undo(&mut conn, &rec, dry_run).await;
            (conn, r)
        })
        .await;
        assert!(
            matches!(r, Err(MintError::NotPrivileged)),
            "undo (dry_run {dry_run}): {r:?}"
        );
    }
    assert_eq!(factor_rows(&pool).await, minted, "a refused undo deleted");
}

#[sqlx::test(migrations = "../../migrations")]
async fn undo_still_matches_after_a_factors_column_is_added_and_in_another_time_zone(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let _w = world(&pool).await;
    let dir = Dir::new();
    let (r, plan_file) = dry_run(&dir, &logins, "plan.json");
    r.ok();
    let before: BTreeSet<Uuid> = factor_rows(&pool).await.into_keys().collect();
    let record = dir.path("record.jsonl");
    run(
        &dir.0,
        &["--apply", "--plan", &plan_file, "--record", &record],
        &logins.app.1,
        Some(&logins.maint.1),
    )
    .ok();
    let rec = read_record(std::io::BufReader::new(
        std::fs::File::open(&record).expect("open"),
    ))
    .expect("record");
    assert!(!rec.factors.is_empty(), "PREMISE: the mint wrote factors");

    // Since the mint: a release adds a column to `factors`, and the undo's
    // login renders timestamps in another zone. Neither changes a factor.
    sqlx::query("ALTER TABLE factors ADD COLUMN r131_probe integer")
        .execute(&pool)
        .await
        .expect("add a column");
    sqlx::query(&format!(
        "ALTER ROLE {} SET timezone = 'Pacific/Chatham'",
        logins.maint.0
    ))
    .execute(&pool)
    .await
    .expect("set the login's time zone");

    let r = run(
        &dir.0,
        &["--undo", &record, "--apply"],
        &logins.app.1,
        Some(&logins.maint.1),
    )
    .ok();
    assert!(
        r.stdout.contains(&format!(
            "r131 undo: deleted={} absent=0 changed_since=0",
            rec.factors.len()
        )),
        "{}",
        r.stdout
    );
    let after: BTreeSet<Uuid> = factor_rows(&pool).await.into_keys().collect();
    assert_eq!(
        after, before,
        "the undo left a minted factor or deleted another"
    );
    logins.drop(&pool).await;
}
