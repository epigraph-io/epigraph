//! `epigraph-operator reown-workflows` and its reversal through
//! `reown-reverse`, driven through the real binary against a `#[sqlx::test]`
//! database migrated 001 → head.
//!
//! # The fixture
//!
//! A human operator whose personal group SRC owns the plans, and a system
//! ingest agent LIVE-linked to the operator. Every workflow row, plan claim
//! and edge is inserted on a transaction STAMPED as that agent, so the edges'
//! tenancy is whatever the real edges trigger (migrations 072 and 120)
//! computes for an ingest, never a value this test forces. The fixture's first
//! assertion records what it computed: the claim-to-claim plan edges are
//! owned by SRC (the writer's group), and every edge with a workflow or agent
//! endpoint (`executes`, `variant_of`, `asserts`) is `('public', world)`.
//!
//! Lineages:
//!
//! * `alpha` (listed, moves): generations 0 and 1. It executes thesis T,
//!   phase P, steps S1, S2, S3, atom A1, the SHARED step X (also executed by
//!   another team's `gamma`, so it must be left on SRC and reported) and Z,
//!   a claim another group owns (left: not SRC's). S1N is S1's evolved
//!   successor (same step lineage, `supersedes` S1), executed by no workflow:
//!   it moves with its lineage.
//! * `beta` (listed, moves): one generation executing TB.
//! * `foreign` (listed): owned by another team. Held.
//! * `private` (listed): SRC's but `group`-visible. Held (a re-own keeps
//!   visibility, and moving a private row changes who reads it).
//! * `missing` (listed): no such lineage. Held.
//! * `gamma` (NOT listed): the other team's, executes X and GC.
//!
//! Attached rows: SRC's own evidence on S1 (follows the claim), a STRANGER's
//! writer-owned BBA on S2 (migration 114: stays the stranger's), and an edge
//! S1 -> Y owned by SRC that is not a plan edge (Y is an unrelated SRC claim):
//! it stays.
//!
//! # What a snapshot is
//!
//! Every row of every table the run could reach, as `to_jsonb(row)::text`,
//! sorted, with `claims.updated_at` stripped (migration 001's trigger stamps
//! it and no tool can put it back). `security_events` is compared on its own:
//! an applied run and an applied reversal each add exactly one row there.

mod viewer_fixture;

use sqlx::PgPool;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const WORLD: Uuid = Uuid::nil();
const RULING: &str = "test ruling: move the team's science workflows into the team";

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

async fn run_op(pool: &PgPool, args: &[&str]) -> Run {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, &url)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn scratch_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("operator-reown-wf-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

fn h32(seed: Uuid) -> Vec<u8> {
    seed.as_bytes().iter().copied().cycle().take(32).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct Fx {
    operator: Uuid,
    src: Uuid,
    target: Uuid,
    other_team: Uuid,
    not_admin_team: Uuid,
    stranger_group: Uuid,
    w_a0: Uuid,
    w_a1: Uuid,
    w_b0: Uuid,
    w_f: Uuid,
    w_p: Uuid,
    w_g: Uuid,
    w_d0: Uuid,
    w_d1: Uuid,
    t: Uuid,
    p: Uuid,
    s1: Uuid,
    s1n: Uuid,
    s2: Uuid,
    s3: Uuid,
    a1: Uuid,
    x: Uuid,
    z: Uuid,
    tb: Uuid,
    fc: Uuid,
    pc: Uuid,
    gc: Uuid,
    y: Uuid,
    ev_s1: Uuid,
    mf_s2: Uuid,
    /// S4 (alpha) and S4B (gamma) share a step lineage: S4B is shared, so S4
    /// must be LEFT with it.
    s4: Uuid,
    s4b: Uuid,
    /// S5 and S6 (alpha) are the provenance of one fragment; S6 has an edge to
    /// the private thesis PC, so it stays, and S5 must stay with it (the
    /// cascaded-row fixpoint).
    s5: Uuid,
    s6: Uuid,
    frag56: Uuid,
    /// author -> alpha generation 0 `AUTHORED`: structural, world-owned.
    e_authored: Uuid,
    /// alpha generation 0 `executes` S4, S5, S6 (three LEFT claims).
    e_exec_left: Vec<Uuid>,
    /// Claim-to-claim plan edges between moving claims (or to X): SRC's.
    plan_edges: Vec<Uuid>,
    /// `executes`, `variant_of`, `asserts`: world.
    structural_edges: Vec<Uuid>,
    /// S1 -> Y `supports`: SRC's, not a plan edge.
    e_s1_y: Uuid,
    /// The held private plan's `executes` edge: ('group', SRC).
    e_private: Uuid,
}

async fn team_group(pool: &PgPool, label: &str, admin: Uuid, role: &str) -> Uuid {
    let g: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, 'did:epigraph:group:' || gen_random_uuid()::text, ''::bytea, 'team', $2) \
         RETURNING id",
    )
    .bind(label)
    .bind(admin)
    .fetch_one(pool)
    .await
    .expect("seed team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(g)
    .bind(admin)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed team membership");
    g
}

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// A connection stamped as `agent` (its own viewer's read and write sets and
/// principal), the way the ingest system agent's transaction is stamped.
async fn stamped(pool: &PgPool, agent: Uuid) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let v = epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve the agent");
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(csv(v.group_bind().expect("scoped")))
    .bind(csv(v.writable_groups()))
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp");
    conn
}

async fn unstamp(conn: &mut sqlx::PgConnection) {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', '', false), \
                set_config('epigraph.writable_group_ids', '', false), \
                set_config('epigraph.principal_id', '', false)",
    )
    .execute(&mut *conn)
    .await
    .expect("unstamp");
}

async fn workflow(
    conn: &mut sqlx::PgConnection,
    name: &str,
    generation: i32,
    parent: Option<Uuid>,
    owner: Uuid,
    visibility: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, parent_id, \
                                owner_group_id, visibility) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(name)
    .bind(generation)
    .bind(format!("goal of {name}"))
    .bind(parent)
    .bind(owner)
    .bind(visibility)
    .execute(&mut *conn)
    .await
    .expect("seed workflow");
    id
}

async fn claim(
    conn: &mut sqlx::PgConnection,
    author: Uuid,
    owner: Uuid,
    visibility: &str,
    level: i32,
    content: &str,
) -> Uuid {
    claim_in_lineage(conn, author, owner, visibility, level, content, None).await
}

async fn claim_in_lineage(
    conn: &mut sqlx::PgConnection,
    author: Uuid,
    owner: Uuid,
    visibility: &str,
    level: i32,
    content: &str,
    step_lineage: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, properties, step_lineage_id) \
         VALUES ($1, $2, $3, 0.7, $4, true, $5, $6, jsonb_build_object('level', $7), $8)",
    )
    .bind(id)
    .bind(content)
    .bind(h32(id))
    .bind(author)
    .bind(visibility)
    .bind(owner)
    .bind(level)
    .bind(step_lineage)
    .execute(&mut *conn)
    .await
    .expect("seed claim");
    id
}

async fn edge(
    conn: &mut sqlx::PgConnection,
    source: (Uuid, &str),
    target: (Uuid, &str),
    relationship: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(source.0)
    .bind(source.1)
    .bind(target.0)
    .bind(target.1)
    .bind(relationship)
    .fetch_one(&mut *conn)
    .await
    .unwrap_or_else(|e| panic!("seed edge {relationship}: {e}"))
}

async fn seed(pool: &PgPool) -> Fx {
    let (operator, src) = fixture::seed_human_operator(pool, "operator").await;
    let (ingest, _) = fixture::seed_agent_with_group(pool, "workflow-ingest").await;
    let (author, _) = fixture::seed_agent_with_group(pool, "author").await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(pool, "stranger").await;
    let (other_admin, _) = fixture::seed_agent_with_group(pool, "other-admin").await;
    sqlx::query("SELECT * FROM epigraph_link_operator($1, $2)")
        .bind(ingest)
        .bind(operator)
        .execute(pool)
        .await
        .expect("link the ingest agent to the operator");

    let target = team_group(pool, "target team", operator, "admin").await;
    let other_team = team_group(pool, "other team", other_admin, "admin").await;
    let not_admin_team =
        team_group(pool, "a team the operator only writes", operator, "writer").await;
    // The operator ADMINISTERS the stranger's personal group: so a refusal of
    // it as a target can only come from its kind, not from the admin check.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(stranger_group)
    .bind(operator)
    .execute(pool)
    .await
    .expect("operator admin of a personal group");

    let mut c = stamped(pool, ingest).await;
    let w_a0 = workflow(&mut c, "alpha", 0, None, src, "public").await;
    let w_a1 = workflow(&mut c, "alpha", 1, Some(w_a0), src, "public").await;
    let w_b0 = workflow(&mut c, "beta", 0, None, src, "public").await;
    let w_f = workflow(&mut c, "foreign", 0, None, other_team, "public").await;
    let w_p = workflow(&mut c, "private", 0, None, src, "group").await;
    let w_g = workflow(&mut c, "gamma", 0, None, other_team, "public").await;
    // `delta`: generation 0 the target's already, generation 1 SRC's.
    let w_d0 = workflow(&mut c, "delta", 0, None, target, "public").await;
    let w_d1 = workflow(&mut c, "delta", 1, Some(w_d0), src, "public").await;

    let t = claim(&mut c, ingest, src, "public", 0, "alpha thesis").await;
    let p = claim(&mut c, ingest, src, "public", 1, "alpha phase").await;
    let step_lineage = Uuid::new_v4();
    let s1 = claim_in_lineage(
        &mut c,
        ingest,
        src,
        "public",
        2,
        "alpha step one",
        Some(step_lineage),
    )
    .await;
    // S1's evolved successor (evolve_step): executed by no workflow, reached
    // through its step lineage.
    let s1n = claim_in_lineage(
        &mut c,
        ingest,
        src,
        "public",
        2,
        "alpha step one, evolved",
        Some(step_lineage),
    )
    .await;
    let s2 = claim(&mut c, ingest, src, "public", 2, "alpha step two").await;
    let s3 = claim(&mut c, ingest, src, "public", 2, "alpha step three (gen 1)").await;
    let a1 = claim(&mut c, ingest, src, "public", 3, "alpha atom").await;
    let x = claim(&mut c, ingest, src, "public", 2, "a step two plans share").await;
    let z = claim(
        &mut c,
        ingest,
        other_team,
        "public",
        2,
        "another team's step",
    )
    .await;
    let tb = claim(&mut c, ingest, src, "public", 0, "beta thesis").await;
    let fc = claim(&mut c, ingest, other_team, "public", 0, "foreign thesis").await;
    let pc = claim(&mut c, ingest, src, "group", 0, "private thesis").await;
    let gc = claim(&mut c, ingest, other_team, "public", 0, "gamma thesis").await;
    let y = claim(
        &mut c,
        ingest,
        src,
        "public",
        0,
        "an unrelated claim of the operator",
    )
    .await;

    let step_lineage_2 = Uuid::new_v4();
    let s4 = claim_in_lineage(
        &mut c,
        ingest,
        src,
        "public",
        2,
        "alpha step four",
        Some(step_lineage_2),
    )
    .await;
    let s4b = claim_in_lineage(
        &mut c,
        ingest,
        src,
        "public",
        2,
        "step four as gamma runs it",
        Some(step_lineage_2),
    )
    .await;
    let s5 = claim(&mut c, ingest, src, "public", 2, "alpha step five").await;
    let s6 = claim(&mut c, ingest, src, "public", 2, "alpha step six").await;

    let mut structural = Vec::new();
    for (w, cl) in [
        (w_a0, t),
        (w_a0, p),
        (w_a0, s1),
        (w_a0, s2),
        (w_a0, a1),
        (w_a0, x),
        (w_a0, z),
        (w_a1, t),
        (w_a1, p),
        (w_a1, s1),
        (w_a1, s3),
        (w_a1, a1),
        (w_b0, tb),
        (w_f, fc),
        (w_g, x),
        (w_g, gc),
        (w_g, s4b),
    ] {
        structural.push(edge(&mut c, (w, "workflow"), (cl, "claim"), "executes").await);
    }
    let mut e_exec_left = Vec::new();
    for cl in [s4, s5, s6] {
        let e = edge(&mut c, (w_a0, "workflow"), (cl, "claim"), "executes").await;
        structural.push(e);
        e_exec_left.push(e);
    }
    let e_authored = edge(&mut c, (author, "agent"), (w_a0, "workflow"), "AUTHORED").await;
    structural.push(e_authored);
    structural.push(edge(&mut c, (w_a1, "workflow"), (w_a0, "workflow"), "variant_of").await);
    // The private plan's `executes` edge takes the meet of a private endpoint:
    // ('group', SRC). Its lineage is held, so it never moves.
    let e_private = edge(&mut c, (w_p, "workflow"), (pc, "claim"), "executes").await;
    structural.push(edge(&mut c, (author, "agent"), (t, "claim"), "asserts").await);

    let mut plan_edges = Vec::new();
    for (s, tg, rel) in [
        (t, p, "decomposes_to"),
        (p, s1, "decomposes_to"),
        (p, s2, "decomposes_to"),
        (p, s3, "decomposes_to"),
        (p, x, "decomposes_to"),
        (s1, a1, "decomposes_to"),
        (s1, s2, "step_follows"),
        (s1, s2, "refines"),
        (s1n, s1, "supersedes"),
    ] {
        plan_edges.push(edge(&mut c, (s, "claim"), (tg, "claim"), rel).await);
    }
    let e_s1_y = edge(&mut c, (s1, "claim"), (y, "claim"), "supports").await;
    // S6 -> the private thesis: a non-public endpoint, so S6 stays.
    edge(&mut c, (s6, "claim"), (pc, "claim"), "refines").await;
    unstamp(&mut c).await;
    drop(c);

    // One fragment, the provenance of S5 and S6, owned like the plan.
    let hsource: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_sources (content_hash, modality) VALUES ($1, 'text') RETURNING id",
    )
    .bind(h32(Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed harvester source");
    let frag56: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_fragments (source_id, content_hash, content_text, owner_group_id, \
                                          visibility) \
         VALUES ($1, $2, 'shared fragment', $3, 'public') RETURNING id",
    )
    .bind(hsource)
    .bind(h32(Uuid::new_v4()))
    .bind(src)
    .fetch_one(pool)
    .await
    .expect("seed fragment");
    for cl in [s5, s6] {
        sqlx::query(
            "INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)",
        )
        .bind(cl)
        .bind(frag56)
        .execute(pool)
        .await
        .expect("seed provenance");
    }

    let ev_s1: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, 'document', $2, 'evidence of step one') RETURNING id",
    )
    .bind(s1)
    .bind(h32(Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed evidence");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, owner_group_id, visibility) \
         VALUES ('reown-wf-frame', ARRAY['a','b'], $1, 'public') RETURNING id",
    )
    .bind(WORLD)
    .fetch_one(pool)
    .await
    .expect("seed frame");
    let mf_s2: Uuid = sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"a\": 1.0}') RETURNING id",
    )
    .bind(s2)
    .bind(frame)
    .bind(stranger)
    .fetch_one(pool)
    .await
    .expect("seed mass function");
    // The stranger's BBA is WRITER-OWNED (migration 114). LAST: 070's insert
    // arm re-syncs every row of a table to its claim on each new insert.
    sqlx::query(
        "UPDATE mass_functions SET owner_group_id = $2, visibility = 'public', \
                writer_owned = true WHERE id = $1",
    )
    .bind(mf_s2)
    .bind(stranger_group)
    .execute(pool)
    .await
    .expect("make a writer-owned row");

    Fx {
        operator,
        src,
        target,
        other_team,
        not_admin_team,
        stranger_group,
        w_a0,
        w_a1,
        w_b0,
        w_f,
        w_p,
        w_g,
        w_d0,
        w_d1,
        t,
        p,
        s1,
        s1n,
        s2,
        s3,
        a1,
        x,
        z,
        tb,
        fc,
        pc,
        gc,
        y,
        ev_s1,
        mf_s2,
        s4,
        s4b,
        s5,
        s6,
        frag56,
        e_authored,
        e_exec_left,
        plan_edges,
        structural_edges: structural,
        e_s1_y,
        e_private,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reads
// ─────────────────────────────────────────────────────────────────────────────

const SNAPSHOT_TABLES: &[&str] = &[
    "workflows",
    "claims",
    "edges",
    "evidence",
    "mass_functions",
    "groups",
    "group_memberships",
    "operator_links",
    "harvester_fragments",
    "harvester_claim_provenance",
    "atlas_layout_epoch",
];

async fn snapshot(pool: &PgPool) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for t in SNAPSHOT_TABLES {
        let strip = if *t == "claims" {
            " - 'updated_at'"
        } else {
            ""
        };
        let rows: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT (to_jsonb(x){strip})::text FROM {t} x ORDER BY 1"
        ))
        .fetch_all(pool)
        .await
        .unwrap_or_else(|e| panic!("snapshot {t}: {e}"));
        out.insert((*t).to_string(), rows);
    }
    out
}

async fn security_events(pool: &PgPool, event_type: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type = $1")
        .bind(event_type)
        .fetch_one(pool)
        .await
        .expect("count security events")
}

async fn tenancy(pool: &PgPool, table: &str, id: Uuid) -> (Uuid, String) {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, visibility::text FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("tenancy of {table} {id}: {e}"))
}

async fn edge_writer(pool: &PgPool, id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT writer_group_id FROM edges WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("edge writer")
}

async fn epoch(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT n FROM atlas_layout_epoch")
        .fetch_one(pool)
        .await
        .expect("atlas epoch")
}

/// `(table, id, visibility)` of every row in the snapshot tables that carries
/// a visibility column.
async fn visibilities(pool: &PgPool) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for t in ["workflows", "claims", "edges", "evidence", "mass_functions"] {
        let rows: Vec<(String, String)> = sqlx::query_as(&format!(
            "SELECT id::text, visibility::text FROM {t} ORDER BY 1"
        ))
        .fetch_all(pool)
        .await
        .expect("visibilities");
        out.extend(rows.into_iter().map(|(i, v)| (t.to_string(), i, v)));
    }
    out
}

fn names_file(dir: &Path, names: &[&str]) -> PathBuf {
    let p = dir.join("lineages.txt");
    let mut text = String::from("# lineages to move\n\n");
    for n in names {
        text.push_str(n);
        text.push('\n');
    }
    std::fs::write(&p, text).expect("write names file");
    p
}

const LISTED: &[&str] = &[
    "alpha", "beta", "foreign", "private", "missing", "delta", "alpha",
];

async fn apply(pool: &PgPool, fx: &Fx, dir: &Path, manifest: &Path) -> Run {
    apply_to(pool, fx, dir, manifest, fx.target, None).await
}

/// An `--apply` run into `target`, with `--visibility <v>` when given.
async fn apply_to(
    pool: &PgPool,
    fx: &Fx,
    dir: &Path,
    manifest: &Path,
    target: Uuid,
    visibility: Option<&str>,
) -> Run {
    let names = names_file(dir, LISTED);
    let target = target.to_string();
    let operator = fx.operator.to_string();
    let mut args = vec![
        "reown-workflows",
        "--canonical-names-file",
        names.to_str().unwrap(),
        "--target-group",
        &target,
        "--operator",
        &operator,
        "--manifest-out",
        manifest.to_str().unwrap(),
        "--apply",
        "--confirm-count",
        "3",
        "--ruling",
        RULING,
        "--reason",
        "the team evolves these plans",
    ];
    if let Some(v) = visibility {
        args.push("--visibility");
        args.push(v);
    }
    run_op(pool, &args).await
}

// ─────────────────────────────────────────────────────────────────────────────
// The fixture is what an ingest stamp writes
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn the_fixture_edges_carry_the_triggers_tenancy(pool: PgPool) {
    let fx = seed(&pool).await;
    for e in &fx.plan_edges {
        assert_eq!(
            tenancy(&pool, "edges", *e).await,
            (fx.src, "public".to_string()),
            "a claim-to-claim plan edge written on the ingest stamp is owned by its writer's \
             group, the operator's (migration 120)"
        );
        assert_eq!(edge_writer(&pool, *e).await, Some(fx.src));
    }
    for e in &fx.structural_edges {
        assert_eq!(
            tenancy(&pool, "edges", *e).await,
            (WORLD, "public".to_string()),
            "an edge with a workflow or agent endpoint is structural: (public, world)"
        );
    }
    assert_eq!(
        tenancy(&pool, "edges", fx.e_private).await,
        (fx.src, "group".to_string()),
        "an edge to a private claim takes the meet"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Dry run
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_writes_nothing_and_reports_the_plan(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let names = names_file(&dir, LISTED);
    let manifest = dir.join("m.jsonl");
    let before = snapshot(&pool).await;
    let audits = security_events(&pool, "operator.workflows_reowned").await;

    let r = run_op(
        &pool,
        &[
            "reown-workflows",
            "--canonical-names-file",
            names.to_str().unwrap(),
            "--target-group",
            &fx.target.to_string(),
            "--operator",
            &fx.operator.to_string(),
            "--manifest-out",
            manifest.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(
        snapshot(&pool).await,
        before,
        "a dry run wrote: {}",
        r.show()
    );
    assert_eq!(
        security_events(&pool, "operator.workflows_reowned").await,
        audits
    );
    assert!(!manifest.exists(), "a dry run must not write a manifest");
    assert!(
        r.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t3"),
        "{}",
        r.show()
    );
    for (name, why) in [
        ("foreign", "owned by"),
        ("private", "visibility"),
        ("missing", "no workflow row"),
        ("delta", "partly the target's"),
    ] {
        assert!(
            r.stdout
                .lines()
                .any(|l| l.starts_with("HELD-LINEAGE\t") && l.contains(name) && l.contains(why)),
            "lineage {name} must be held ({why}): {}",
            r.show()
        );
    }
    assert!(
        r.stdout.lines().any(|l| l.starts_with("LEFT-CLAIM\t")
            && l.contains(&fx.x.to_string())
            && l.contains("SHARED")),
        "the shared step must be reported and left: {}",
        r.show()
    );
    assert!(
        r.stdout
            .lines()
            .any(|l| l.starts_with("LEFT-CLAIM\t") && l.contains(&fx.z.to_string())),
        "a step another group owns must be reported and left: {}",
        r.show()
    );
    assert!(
        r.stdout.lines().any(|l| l.starts_with("LEFT-CLAIM\t")
            && l.contains(&fx.s4.to_string())
            && l.contains("step lineage")),
        "a step whose lineage has a shared member is left whole: {}",
        r.show()
    );
    assert!(
        r.stdout.lines().any(|l| l.starts_with("LEFT-CLAIM\t")
            && l.contains(&fx.s5.to_string())
            && l.contains("shared with a plan claim that stays")),
        "a step sharing a cascaded row with a step that stays, stays (the fixpoint): {}",
        r.show()
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply
// ─────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn apply_moves_only_the_source_groups_rows_and_keeps_visibility(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let vis_before = visibilities(&pool).await;
    let epoch_before = epoch(&pool).await;
    let audits = security_events(&pool, "operator.workflows_reowned").await;
    let writers_before: Vec<Option<Uuid>> = {
        let mut v = Vec::new();
        for e in &fx.plan_edges {
            v.push(edge_writer(&pool, *e).await);
        }
        v
    };

    let r = apply(&pool, &fx, &dir, &manifest).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(manifest.exists(), "{}", r.show());

    let moved = (fx.target, "public".to_string());
    for w in [fx.w_a0, fx.w_a1, fx.w_b0] {
        assert_eq!(tenancy(&pool, "workflows", w).await, moved, "workflow {w}");
    }
    assert_eq!(
        tenancy(&pool, "workflows", fx.w_f).await,
        (fx.other_team, "public".into())
    );
    assert_eq!(
        tenancy(&pool, "workflows", fx.w_p).await,
        (fx.src, "group".into())
    );
    assert_eq!(
        tenancy(&pool, "workflows", fx.w_g).await,
        (fx.other_team, "public".into())
    );
    assert_eq!(
        tenancy(&pool, "workflows", fx.w_d1).await,
        (fx.src, "public".into()),
        "a lineage partly the target's already is held whole"
    );
    for c in [fx.t, fx.p, fx.s1, fx.s1n, fx.s2, fx.s3, fx.a1, fx.tb] {
        assert_eq!(tenancy(&pool, "claims", c).await, moved, "claim {c}");
    }
    assert_eq!(
        tenancy(&pool, "claims", fx.x).await,
        (fx.src, "public".into()),
        "the shared step stays on the source group"
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.z).await,
        (fx.other_team, "public".into()),
        "another group's step is not taken"
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.y).await,
        (fx.src, "public".into())
    );
    for c in [fx.s4, fx.s4b, fx.s5, fx.s6] {
        assert_eq!(
            tenancy(&pool, "claims", c).await,
            (fx.src, "public".into()),
            "a left step stays on the source: {c}"
        );
    }
    assert_eq!(
        tenancy(&pool, "harvester_fragments", fx.frag56).await,
        (fx.src, "public".into()),
        "a fragment shared with a step that stays does not move"
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.pc).await,
        (fx.src, "group".into())
    );
    assert_eq!(tenancy(&pool, "evidence", fx.ev_s1).await, moved);
    assert_eq!(
        tenancy(&pool, "mass_functions", fx.mf_s2).await,
        (fx.stranger_group, "public".into()),
        "a writer-owned row stays its writer's"
    );
    for (i, e) in fx.plan_edges.iter().enumerate() {
        assert_eq!(tenancy(&pool, "edges", *e).await, moved, "plan edge {e}");
        assert_eq!(
            edge_writer(&pool, *e).await,
            writers_before[i],
            "writer_group_id is the author record and is not rewritten"
        );
    }
    for e in &fx.structural_edges {
        assert_eq!(
            tenancy(&pool, "edges", *e).await,
            (WORLD, "public".into()),
            "a structural world edge is not the source group's and stays"
        );
    }
    assert_eq!(
        tenancy(&pool, "edges", fx.e_s1_y).await,
        (fx.src, "public".into()),
        "a source-owned edge that is not a plan edge stays"
    );

    assert_eq!(
        visibilities(&pool).await,
        vis_before,
        "no row's visibility changed"
    );
    assert_eq!(
        epoch(&pool).await,
        epoch_before,
        "a public-to-public move must not bump the atlas epoch (migration 197)"
    );
    assert_eq!(
        security_events(&pool, "operator.workflows_reowned").await,
        audits + 1
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn apply_requires_the_dry_runs_count_a_ruling_and_a_reason(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let names = names_file(&dir, LISTED);
    let manifest = dir.join("m.jsonl");
    let before = snapshot(&pool).await;
    let base = [
        "reown-workflows".to_string(),
        "--canonical-names-file".into(),
        names.to_str().unwrap().into(),
        "--target-group".into(),
        fx.target.to_string(),
        "--operator".into(),
        fx.operator.to_string(),
        "--manifest-out".into(),
        manifest.to_str().unwrap().into(),
        "--apply".into(),
    ];
    for extra in [
        vec!["--ruling", RULING, "--reason", "r"],
        vec!["--confirm-count", "2", "--ruling", RULING, "--reason", "r"],
        vec!["--confirm-count", "3", "--reason", "r"],
        vec!["--confirm-count", "3", "--ruling", RULING],
    ] {
        let mut args: Vec<&str> = base.iter().map(String::as_str).collect();
        args.extend(extra.iter().copied());
        let r = run_op(&pool, &args).await;
        assert_eq!(r.code, 1, "{extra:?} must be refused: {}", r.show());
        assert_eq!(snapshot(&pool).await, before, "{extra:?} wrote");
        assert!(!manifest.exists(), "{extra:?} wrote a manifest");
    }
    std::fs::remove_dir_all(&dir).ok();
}

// ─────────────────────────────────────────────────────────────────────────────
// Refusals of the groups
// ─────────────────────────────────────────────────────────────────────────────

/// Run with `target` (and `--from-group`), as a DRY RUN when `apply` is
/// false (so no `--confirm-count` can be what refuses it), else as an apply.
async fn refused_target(
    pool: &PgPool,
    fx: &Fx,
    target: Uuid,
    from: Option<Uuid>,
    apply: bool,
) -> Run {
    let dir = scratch_dir();
    let names = names_file(&dir, LISTED);
    let manifest = dir.join("m.jsonl");
    let before = snapshot(pool).await;
    let mut args = vec![
        "reown-workflows".to_string(),
        "--canonical-names-file".into(),
        names.to_str().unwrap().into(),
        "--target-group".into(),
        target.to_string(),
        "--operator".into(),
        fx.operator.to_string(),
        "--manifest-out".into(),
        manifest.to_str().unwrap().into(),
    ];
    if apply {
        for a in [
            "--apply",
            "--confirm-count",
            "3",
            "--ruling",
            RULING,
            "--reason",
            "r",
        ] {
            args.push(a.into());
        }
    }
    if let Some(g) = from {
        args.push("--from-group".into());
        args.push(g.to_string());
    }
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = run_op(pool, &a).await;
    assert_eq!(
        snapshot(pool).await,
        before,
        "a refused run wrote: {}",
        r.show()
    );
    assert!(!manifest.exists(), "a refused run wrote a manifest");
    std::fs::remove_dir_all(&dir).ok();
    r
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_target_the_operator_does_not_administer_is_refused(pool: PgPool) {
    let fx = seed(&pool).await;
    for apply in [false, true] {
        let r = refused_target(&pool, &fx, fx.not_admin_team, None, apply).await;
        assert_eq!(r.code, 1, "apply={apply}: {}", r.show());
        assert!(
            r.stderr.contains("not a live admin"),
            "apply={apply}: {}",
            r.show()
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_personal_target_is_refused_even_to_its_admin(pool: PgPool) {
    let fx = seed(&pool).await;
    for apply in [false, true] {
        let r = refused_target(&pool, &fx, fx.stranger_group, None, apply).await;
        assert_eq!(r.code, 1, "apply={apply}: {}", r.show());
        assert!(
            r.stderr.contains("not a team group"),
            "apply={apply}: {}",
            r.show()
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_source_group_the_operator_does_not_administer_is_refused(pool: PgPool) {
    let fx = seed(&pool).await;
    for apply in [false, true] {
        let r = refused_target(&pool, &fx, fx.target, Some(fx.other_team), apply).await;
        assert_eq!(r.code, 1, "apply={apply}: {}", r.show());
        assert!(
            r.stderr.contains("--from-group"),
            "apply={apply}: {}",
            r.show()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reversal
// ─────────────────────────────────────────────────────────────────────────────

async fn reverse(pool: &PgPool, manifest: &Path, apply: bool) -> Run {
    let mut args = vec!["reown-reverse", "--manifest", manifest.to_str().unwrap()];
    if apply {
        args.push("--apply");
    }
    run_op(pool, &args).await
}

#[sqlx::test(migrations = "../../migrations")]
async fn reverse_restores_every_row_exactly(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let before = snapshot(&pool).await;
    let r = apply(&pool, &fx, &dir, &manifest).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_ne!(snapshot(&pool).await, before, "the apply moved nothing");

    let after_apply = snapshot(&pool).await;
    let dry = reverse(&pool, &manifest, false).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert_eq!(snapshot(&pool).await, after_apply, "a dry reversal wrote");

    let rev = reverse(&pool, &manifest, true).await;
    assert_eq!(rev.code, 0, "{}", rev.show());
    assert_eq!(
        snapshot(&pool).await,
        before,
        "the reversal did not restore every row: {}",
        rev.show()
    );
    assert_eq!(
        security_events(&pool, "operator.workflows_reown_reversed").await,
        1
    );

    // Idempotent: a second reversal finds every row on its prior state.
    let again = reverse(&pool, &manifest, true).await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(
        security_events(&pool, "operator.workflows_reown_reversed").await,
        1,
        "a reversal that changes nothing writes no audit row"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn reverse_refuses_when_a_moved_row_changed_since(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let r = apply(&pool, &fx, &dir, &manifest).await;
    assert_eq!(r.code, 0, "{}", r.show());

    // Someone (a maintenance act) moved one of the moved steps on.
    sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(fx.s3)
        .bind(fx.other_team)
        .execute(&pool)
        .await
        .expect("move a step on");
    let changed = snapshot(&pool).await;

    let rev = reverse(&pool, &manifest, true).await;
    assert_eq!(rev.code, 3, "{}", rev.show());
    assert!(rev.stdout.contains(&fx.s3.to_string()), "{}", rev.show());
    assert_eq!(
        snapshot(&pool).await,
        changed,
        "a refused reversal must write nothing"
    );
    assert_eq!(
        security_events(&pool, "operator.workflows_reown_reversed").await,
        0
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn reverse_refuses_after_a_new_generation_joined_the_lineage(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let r = apply(&pool, &fx, &dir, &manifest).await;
    assert_eq!(r.code, 0, "{}", r.show());

    // The team evolved the plan after the move: generation 2, the team's.
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, parent_id, \
                                owner_group_id, visibility) \
         VALUES (gen_random_uuid(), 'alpha', 2, 'goal', $1, $2, 'public')",
    )
    .bind(fx.w_a1)
    .bind(fx.target)
    .execute(&pool)
    .await
    .expect("a new generation");
    let changed = snapshot(&pool).await;

    let rev = reverse(&pool, &manifest, true).await;
    assert_eq!(rev.code, 3, "{}", rev.show());
    assert!(rev.stdout.contains("alpha"), "{}", rev.show());
    assert_eq!(snapshot(&pool).await, changed, "a refused reversal wrote");
    std::fs::remove_dir_all(&dir).ok();
}

// ─────────────────────────────────────────────────────────────────────────────
// Growth since the move: the reversal refuses
// ─────────────────────────────────────────────────────────────────────────────

/// Apply (with `visibility`), grow the moved plan with `grow`, then reverse:
/// the reversal must refuse (exit 3), write nothing, name `expect`, and write
/// no reversal audit row.
async fn reverse_refuses_after(
    pool: &PgPool,
    visibility: Option<&str>,
    grow: &str,
    expect: impl Fn(&Fx) -> String,
) {
    let fx = seed(pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let r = apply_to(pool, &fx, &dir, &manifest, fx.target, visibility).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let vis = visibility.unwrap_or("public");
    match grow {
        // evolve_step: a successor in S1's step lineage, inheriting S1's
        // tenancy (the target's now), executed by no workflow.
        "evolved" => {
            sqlx::query(
                "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                                     is_current, visibility, owner_group_id, properties, \
                                     step_lineage_id) \
                 SELECT gen_random_uuid(), 'alpha step one, evolved by the team', \
                        decode(md5(random()::text) || md5(random()::text), 'hex'), 0.7, \
                        agent_id, true, $2, $3, properties, step_lineage_id \
                   FROM claims WHERE id = $1",
            )
            .bind(fx.s1)
            .bind(vis)
            .bind(fx.target)
            .execute(pool)
            .await
            .expect("an evolved successor");
        }
        // add_step: a new claim, executed by a moved generation.
        "add_step" => {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                                     is_current, visibility, owner_group_id, properties) \
                 SELECT gen_random_uuid(), 'a step the team added', \
                        decode(md5(random()::text) || md5(random()::text), 'hex'), 0.7, \
                        agent_id, true, $2, $3, properties \
                   FROM claims WHERE id = $1 RETURNING id",
            )
            .bind(fx.s2)
            .bind(vis)
            .bind(fx.target)
            .fetch_one(pool)
            .await
            .expect("an added step");
            sqlx::query(
                "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
                 VALUES ($1, 'workflow', $2, 'claim', 'executes')",
            )
            .bind(fx.w_a1)
            .bind(id)
            .execute(pool)
            .await
            .expect("its executes edge");
        }
        // A team member's evidence on a moved step.
        "evidence" => {
            sqlx::query(
                "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
                 VALUES ($1, 'document', $2, 'the team''s evidence')",
            )
            .bind(fx.s2)
            .bind(h32(Uuid::new_v4()))
            .execute(pool)
            .await
            .expect("new evidence");
        }
        // A new edge from a moved step.
        "edge" => {
            sqlx::query(
                "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
                 VALUES ($1, 'claim', $2, 'claim', 'supports')",
            )
            .bind(fx.s2)
            .bind(fx.s3)
            .execute(pool)
            .await
            .expect("new edge");
        }
        // evolve_step's supersede cascade re-points a moved plan edge onto the
        // successor (same tenancy, new endpoint).
        "repoint" => {
            sqlx::query("UPDATE edges SET source_id = $2 WHERE id = $1")
                .bind(fx.plan_edges[5])
                .bind(fx.s1n)
                .execute(pool)
                .await
                .expect("re-point a moved plan edge");
        }
        other => panic!("unknown growth {other}"),
    }
    let grown = snapshot(pool).await;
    let rev = reverse(pool, &manifest, true).await;
    assert_eq!(
        rev.code,
        3,
        "growth `{grow}` must refuse the reversal: {}",
        rev.show()
    );
    assert!(
        rev.stdout.contains(&expect(&fx)),
        "growth `{grow}`: the refusal must name {}: {}",
        expect(&fx),
        rev.show()
    );
    assert_eq!(snapshot(pool).await, grown, "a refused reversal wrote");
    assert_eq!(
        security_events(pool, "operator.workflows_reown_reversed").await,
        0
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn reverse_refuses_after_the_team_evolved_a_moved_step(pool: PgPool) {
    reverse_refuses_after(&pool, None, "evolved", |_| "step lineage".into()).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn reverse_refuses_after_the_team_added_a_step(pool: PgPool) {
    reverse_refuses_after(&pool, None, "add_step", |fx| fx.w_a1.to_string()).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn reverse_refuses_after_new_evidence_on_a_moved_step(pool: PgPool) {
    reverse_refuses_after(&pool, None, "evidence", |_| "evidence".into()).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn reverse_refuses_after_a_new_edge_on_a_moved_step(pool: PgPool) {
    reverse_refuses_after(&pool, None, "edge", |fx| fx.s2.to_string()).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn reverse_refuses_after_a_moved_edge_was_repointed(pool: PgPool) {
    reverse_refuses_after(&pool, None, "repoint", |fx| fx.plan_edges[5].to_string()).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_narrowing_reverse_refuses_after_the_team_evolved_a_moved_step(pool: PgPool) {
    reverse_refuses_after(&pool, Some("group"), "evolved", |_| "step lineage".into()).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Narrowing: --visibility group (into a team, or in place)
// ─────────────────────────────────────────────────────────────────────────────

async fn snapshot_sans_epoch(pool: &PgPool) -> BTreeMap<String, Vec<String>> {
    let mut s = snapshot(pool).await;
    s.remove("atlas_layout_epoch");
    s
}

/// Every edge with an endpoint among `ids`, with its full tenancy.
async fn edges_touching(pool: &PgPool, ids: &[Uuid]) -> Vec<(Uuid, Uuid, String, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT id, owner_group_id, visibility::text, co_owner_group_id FROM edges \
          WHERE source_id = ANY($1) OR target_id = ANY($1) ORDER BY id",
    )
    .bind(ids)
    .fetch_all(pool)
    .await
    .expect("edges touching")
}

async fn writer_owned(pool: &PgPool, table: &str, id: Uuid) -> bool {
    sqlx::query_scalar(&format!("SELECT writer_owned FROM {table} WHERE id = $1"))
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("writer_owned")
}

#[sqlx::test(migrations = "../../migrations")]
async fn group_apply_narrows_every_moved_row_into_the_target_and_bumps_the_epoch(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let epoch_before = epoch(&pool).await;
    let audits = security_events(&pool, "operator.workflows_reowned").await;
    let left_edges_before = edges_touching(&pool, &[fx.w_g, fx.w_f]).await;

    let r = apply_to(&pool, &fx, &dir, &manifest, fx.target, Some("group")).await;
    assert_eq!(r.code, 0, "{}", r.show());

    let narrowed = (fx.target, "group".to_string());
    let moved_wf = [fx.w_a0, fx.w_a1, fx.w_b0];
    let moved_claims = [fx.t, fx.p, fx.s1, fx.s1n, fx.s2, fx.s3, fx.a1, fx.tb];
    for w in moved_wf {
        assert_eq!(
            tenancy(&pool, "workflows", w).await,
            narrowed,
            "workflow {w}"
        );
    }
    for c in moved_claims {
        assert_eq!(tenancy(&pool, "claims", c).await, narrowed, "claim {c}");
    }
    assert_eq!(tenancy(&pool, "evidence", fx.ev_s1).await, narrowed);
    assert_eq!(
        tenancy(&pool, "mass_functions", fx.mf_s2).await,
        narrowed,
        "a writer-owned public row narrows with its claim (migration 114)"
    );
    assert!(!writer_owned(&pool, "mass_functions", fx.mf_s2).await);
    // Every edge touching a moved workflow or claim: no more visible than the
    // plan it belongs to. Claim endpoints: the cascade's meet. Workflow and
    // agent endpoints (`executes` into a left step, `variant_of`, `AUTHORED`):
    // narrowed by the tool.
    let all: Vec<Uuid> = moved_wf
        .iter()
        .chain(moved_claims.iter())
        .copied()
        .collect();
    for (e, o, v, co) in edges_touching(&pool, &all).await {
        assert_eq!(
            (o, v.clone(), co),
            (fx.target, "group".to_string(), None),
            "edge {e}"
        );
    }
    assert!(fx.e_exec_left.len() == 3);
    assert_eq!(tenancy(&pool, "edges", fx.e_authored).await, narrowed);
    assert_eq!(tenancy(&pool, "edges", fx.e_s1_y).await, narrowed);
    // What stays: left steps, other plans, their edges.
    for c in [fx.x, fx.s4, fx.s4b, fx.s5, fx.s6, fx.y] {
        assert_eq!(
            tenancy(&pool, "claims", c).await,
            (fx.src, "public".into()),
            "claim {c}"
        );
    }
    assert_eq!(
        tenancy(&pool, "claims", fx.z).await,
        (fx.other_team, "public".into())
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.pc).await,
        (fx.src, "group".into())
    );
    assert_eq!(
        tenancy(&pool, "harvester_fragments", fx.frag56).await,
        (fx.src, "public".into())
    );
    for (w, t) in [
        (fx.w_f, (fx.other_team, "public".to_string())),
        (fx.w_g, (fx.other_team, "public".to_string())),
        (fx.w_p, (fx.src, "group".to_string())),
        (fx.w_d0, (fx.target, "public".to_string())),
        (fx.w_d1, (fx.src, "public".to_string())),
    ] {
        assert_eq!(tenancy(&pool, "workflows", w).await, t, "workflow {w}");
    }
    assert_eq!(
        edges_touching(&pool, &[fx.w_g, fx.w_f]).await,
        left_edges_before,
        "another plan's edges are untouched"
    );
    assert_eq!(
        epoch(&pool).await,
        epoch_before + 1,
        "a narrowing must bump the atlas epoch (migration 197): {}",
        r.show()
    );
    assert_eq!(
        security_events(&pool, "operator.workflows_reowned").await,
        audits + 1
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn group_reverse_restores_every_row_and_its_visibility_exactly(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let before = snapshot_sans_epoch(&pool).await;
    let r = apply_to(&pool, &fx, &dir, &manifest, fx.target, Some("group")).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let after_apply = snapshot_sans_epoch(&pool).await;
    assert_ne!(after_apply, before, "the apply narrowed nothing");
    let epoch_after_apply = epoch(&pool).await;

    let dry = reverse(&pool, &manifest, false).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert_eq!(
        snapshot_sans_epoch(&pool).await,
        after_apply,
        "a dry reversal wrote"
    );

    let rev = reverse(&pool, &manifest, true).await;
    assert_eq!(rev.code, 0, "{}", rev.show());
    assert_eq!(
        snapshot_sans_epoch(&pool).await,
        before,
        "the reversal did not restore every row and its visibility: {}",
        rev.show()
    );
    assert_eq!(
        epoch(&pool).await,
        epoch_after_apply,
        "a widening never moves the atlas epoch, and nothing decrements it"
    );
    assert_eq!(
        security_events(&pool, "operator.workflows_reown_reversed").await,
        1
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn in_place_narrowing_keeps_every_owner_and_reverses_exactly(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let before = snapshot_sans_epoch(&pool).await;
    let epoch_before = epoch(&pool).await;

    let r = apply_to(&pool, &fx, &dir, &manifest, fx.src, Some("group")).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let in_place = (fx.src, "group".to_string());
    for w in [fx.w_a0, fx.w_a1, fx.w_b0] {
        assert_eq!(
            tenancy(&pool, "workflows", w).await,
            in_place,
            "workflow {w}"
        );
    }
    for c in [fx.t, fx.p, fx.s1, fx.s1n, fx.s2, fx.s3, fx.a1, fx.tb] {
        assert_eq!(tenancy(&pool, "claims", c).await, in_place, "claim {c}");
    }
    assert_eq!(tenancy(&pool, "evidence", fx.ev_s1).await, in_place);
    for e in &fx.plan_edges {
        assert_eq!(tenancy(&pool, "edges", *e).await, in_place, "plan edge {e}");
    }
    assert_eq!(
        tenancy(&pool, "workflows", fx.w_p).await,
        in_place,
        "the already-private lineage is untouched"
    );
    assert_eq!(epoch(&pool).await, epoch_before + 1, "{}", r.show());

    let rev = reverse(&pool, &manifest, true).await;
    assert_eq!(rev.code, 0, "{}", rev.show());
    assert_eq!(
        snapshot_sans_epoch(&pool).await,
        before,
        "the in-place reversal did not restore exactly: {}",
        rev.show()
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn in_place_needs_group_visibility(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let before = snapshot(&pool).await;
    for vis in [None, Some("keep")] {
        let r = apply_to(&pool, &fx, &dir, &manifest, fx.src, vis).await;
        assert_eq!(r.code, 1, "{vis:?}: {}", r.show());
        assert!(
            r.stderr.contains("--visibility group"),
            "{vis:?}: {}",
            r.show()
        );
        assert_eq!(snapshot(&pool).await, before);
        assert!(!manifest.exists());
    }
    std::fs::remove_dir_all(&dir).ok();
}
