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
//! The private neighbour PN: S6 `refines` PN, a group-visible note. Its group
//! is the fixture's one parameter ([`Neighbour`]): the SOURCE's by default
//! (in place it is the same group, so it never blocks; a move would make the
//! target the owner of that private edge, so the move holds the lineage), or
//! the TARGET's (a move meets it into the group it is already in).
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
    /// the private note PN. Under `keep` that non-public endpoint leaves S6,
    /// and S5 must stay with it (the cascaded-row fixpoint). A narrowing
    /// decides by the edge's meet instead (see [`Neighbour`]).
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
    /// The private note S6 refines, and that edge.
    pn: Uuid,
    e_s6_pn: Uuid,
}

/// Whose group the private note PN is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Neighbour {
    Source,
    Target,
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
    seed_with(pool, Neighbour::Source).await
}

async fn seed_with(pool: &PgPool, neighbour: Neighbour) -> Fx {
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
    unstamp(&mut c).await;
    drop(c);

    // S6 -> the private note PN: an edge with a non-public endpoint. Written
    // on the maintenance pool, so the edges trigger gives it the meet:
    // (PN's group, 'group').
    let pn_owner = match neighbour {
        Neighbour::Source => src,
        Neighbour::Target => target,
    };
    let (pn, e_s6_pn) = {
        let mut m = pool.acquire().await.expect("acquire");
        let pn = claim(&mut m, ingest, pn_owner, "group", 0, "a private note").await;
        let e = edge(&mut m, (s6, "claim"), (pn, "claim"), "refines").await;
        (pn, e)
    };

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
        pn,
        e_s6_pn,
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
    let mut extra = Vec::new();
    if let Some(v) = visibility {
        extra.extend(["--visibility", v]);
    }
    reown_run(pool, fx, dir, manifest, target, Some("3"), &extra).await
}

/// A run of the LISTED lineages into `target` with `extra` arguments: an
/// `--apply` confirming `confirm` when given, else a dry run.
async fn reown_run(
    pool: &PgPool,
    fx: &Fx,
    dir: &Path,
    manifest: &Path,
    target: Uuid,
    confirm: Option<&str>,
    extra: &[&str],
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
    ];
    if let Some(n) = confirm {
        args.extend([
            "--apply",
            "--confirm-count",
            n,
            "--ruling",
            RULING,
            "--reason",
            "the team evolves these plans",
        ]);
    }
    args.extend(extra.iter().copied());
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
    // A move that narrows meets S6's edge into the group PN is already in.
    let fx = if visibility == Some("group") {
        seed_with(pool, Neighbour::Target).await
    } else {
        seed(pool).await
    };
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

/// Another team evolving a step the run LEFT (S4B, shared with gamma, whose
/// lineage S4 stays with) is not growth of the moved plan: the reversal goes
/// ahead and restores exactly.
#[sqlx::test(migrations = "../../migrations")]
async fn reverse_ignores_growth_of_a_step_lineage_the_run_left(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let before = snapshot(&pool).await;
    let r = apply(&pool, &fx, &dir, &manifest).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let successor: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, properties, step_lineage_id) \
         SELECT gen_random_uuid(), 'step four, evolved by the other team', \
                decode(md5(random()::text) || md5(random()::text), 'hex'), 0.7, agent_id, \
                true, 'public', $2, properties, step_lineage_id \
           FROM claims WHERE id = $1 RETURNING id",
    )
    .bind(fx.s4b)
    .bind(fx.other_team)
    .fetch_one(&pool)
    .await
    .expect("the other team's successor of a left step");

    let rev = reverse(&pool, &manifest, true).await;
    assert_eq!(
        rev.code,
        0,
        "growth of a lineage the run left must not refuse the reversal: {}",
        rev.show()
    );
    let mut after = snapshot(&pool).await;
    let id = successor.to_string();
    after
        .get_mut("claims")
        .expect("claims")
        .retain(|row| !row.contains(&id));
    assert_eq!(after, before, "the reversal did not restore exactly");
    std::fs::remove_dir_all(&dir).ok();
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
    let fx = seed_with(&pool, Neighbour::Target).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let epoch_before = epoch(&pool).await;
    let audits = security_events(&pool, "operator.workflows_reowned").await;
    let left_edges_before = edges_touching(&pool, &[fx.w_g, fx.w_f]).await;

    let r = apply_to(&pool, &fx, &dir, &manifest, fx.target, Some("group")).await;
    assert_eq!(r.code, 0, "{}", r.show());

    let narrowed = (fx.target, "group".to_string());
    let moved_wf = [fx.w_a0, fx.w_a1, fx.w_b0];
    // S5 and S6 included: S6's edge to PN, already private to the target,
    // meets into the target unchanged, so nothing keeps either public.
    let moved_claims = [
        fx.t, fx.p, fx.s1, fx.s1n, fx.s2, fx.s3, fx.a1, fx.tb, fx.s5, fx.s6,
    ];
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
    assert_eq!(
        tenancy(&pool, "harvester_fragments", fx.frag56).await,
        narrowed,
        "a fragment whose every claim narrows narrows with them"
    );
    assert_eq!(
        tenancy(&pool, "edges", fx.e_s6_pn).await,
        narrowed,
        "an edge to a row already private to the target stays as it is"
    );
    // What stays: shared steps, other plans, their edges.
    for c in [fx.x, fx.s4, fx.s4b, fx.y] {
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
    let fx = seed_with(&pool, Neighbour::Target).await;
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

// ─────────────────────────────────────────────────────────────────────────────
// A narrowing leaves no unshared plan row public
// ─────────────────────────────────────────────────────────────────────────────

/// The contents of `ids` an UNSTAMPED `epigraph_app` session reads.
async fn app_reads_claims(pool: &PgPool, ids: &[Uuid]) -> Vec<String> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *tx)
        .await
        .expect("become epigraph_app");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', '', true), \
                set_config('epigraph.writable_group_ids', '', true), \
                set_config('epigraph.principal_id', '', true)",
    )
    .execute(&mut *tx)
    .await
    .expect("unstamp");
    let out: Vec<String> =
        sqlx::query_scalar("SELECT content FROM claims WHERE id = ANY($1) ORDER BY content")
            .bind(ids)
            .fetch_all(&mut *tx)
            .await
            .expect("app read");
    tx.rollback().await.expect("rollback");
    out
}

fn line_with(stdout: &str, prefix: &str, needles: &[&str]) -> bool {
    stdout
        .lines()
        .any(|l| l.starts_with(prefix) && needles.iter().all(|n| l.contains(n)))
}

const GROUP: &[&str] = &["--visibility", "group"];
const CATCH_UP: &[&str] = &["--visibility", "group", "--catch-up"];

/// `--catch-up` following the act whose manifest is `after`.
fn catch_up_after(after: &Path) -> Vec<&str> {
    let mut v = CATCH_UP.to_vec();
    v.extend(["--after-manifest", after.to_str().unwrap()]);
    v
}

/// In place, every unshared step of a plan narrows. S6's edge to a note that
/// is already private to the SAME group meets into exactly the tuple it has,
/// and S3's pinned evidence is already in the group's private state: neither
/// hands anything to anyone, so neither may keep its step (or, through the
/// fragment S5 shares with S6, its sibling) public. An edge on a step's
/// evidence narrows with the step instead of keeping it public. A recorded run
/// of the plan (`behavioral_executions`, no tenancy) is reported, not hidden.
#[sqlx::test(migrations = "../../migrations")]
async fn in_place_narrowing_leaves_no_unshared_plan_row_public(pool: PgPool) {
    let fx = seed(&pool).await;
    let ev_pinned: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, 'document', $2, 'pinned evidence of step three') RETURNING id",
    )
    .bind(fx.s3)
    .bind(h32(Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("evidence to pin");
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'kept private by its owner')",
    )
    .bind(ev_pinned)
    .bind(fx.operator)
    .execute(&pool)
    .await
    .expect("pin");
    sqlx::query("UPDATE evidence SET visibility = 'group' WHERE id = $1")
        .bind(ev_pinned)
        .execute(&pool)
        .await
        .expect("pinned row private");
    assert_eq!(
        tenancy(&pool, "evidence", ev_pinned).await,
        (fx.src, "group".to_string()),
        "PREMISE: the pinned row is already in the in-place target state"
    );
    let e_ev = {
        let mut m = pool.acquire().await.expect("acquire");
        edge(&mut m, (fx.ev_s1, "evidence"), (fx.y, "claim"), "supports").await
    };
    assert_eq!(tenancy(&pool, "edges", e_ev).await.1, "public", "PREMISE");
    sqlx::query(
        "INSERT INTO behavioral_executions (workflow_id, goal_text, success, step_claim_id) \
         VALUES ($1, 'PRIVATE GOAL of alpha', true, $2)",
    )
    .bind(fx.w_a0)
    .bind(fx.s2)
    .execute(&pool)
    .await
    .expect("a recorded run");

    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let before = snapshot_sans_epoch(&pool).await;
    let dry = reown_run(&pool, &fx, &dir, &manifest, fx.src, None, GROUP).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    for c in [fx.s3, fx.s5, fx.s6, fx.s1] {
        assert!(
            !line_with(&dry.stdout, "LEFT-CLAIM\t", &[&c.to_string()]),
            "unshared step {c} must not be left: {}",
            dry.show()
        );
    }
    assert!(
        line_with(
            &dry.stdout,
            "BEHAVIORAL-EXECUTIONS-TOTAL\t1",
            &["no row security"]
        ),
        "the recorded run must be counted: {}",
        dry.show()
    );

    let r = reown_run(&pool, &fx, &dir, &manifest, fx.src, Some("3"), GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let in_place = (fx.src, "group".to_string());
    let alpha = [fx.t, fx.p, fx.s1, fx.s1n, fx.s2, fx.s3, fx.a1, fx.s5, fx.s6];
    for c in alpha {
        assert_eq!(tenancy(&pool, "claims", c).await, in_place, "claim {c}");
    }
    assert_eq!(
        app_reads_claims(&pool, &alpha).await,
        Vec::<String>::new(),
        "an unstamped session still reads a narrowed plan's steps"
    );
    assert_eq!(
        tenancy(&pool, "harvester_fragments", fx.frag56).await,
        in_place
    );
    assert_eq!(tenancy(&pool, "evidence", ev_pinned).await, in_place);
    assert_eq!(tenancy(&pool, "edges", fx.e_s6_pn).await, in_place);
    assert_eq!(
        tenancy(&pool, "edges", e_ev).await,
        in_place,
        "an edge on a narrowed step's evidence narrows with it"
    );
    assert!(
        r.stdout.contains("BEHAVIORAL-EXECUTIONS-TOTAL\t1"),
        "{}",
        r.show()
    );

    let rev = reverse(&pool, &manifest, true).await;
    assert_eq!(rev.code, 0, "{}", rev.show());
    assert_eq!(
        snapshot_sans_epoch(&pool).await,
        before,
        "the reversal did not restore exactly: {}",
        rev.show()
    );
    assert_eq!(tenancy(&pool, "edges", e_ev).await.1, "public");
    std::fs::remove_dir_all(&dir).ok();
}

/// A move that narrows must not make the target the OWNER of a row another
/// group keeps private: S6's edge to the SOURCE's private note would be
/// re-met to ('group', target, co-owner source). The whole lineage stays and
/// nothing of it is written; the lineages it does not touch narrow; the apply
/// exits 3.
#[sqlx::test(migrations = "../../migrations")]
async fn a_move_holds_a_lineage_whose_narrowing_would_hand_a_private_row_to_the_target(
    pool: PgPool,
) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let dry = reown_run(&pool, &fx, &dir, &manifest, fx.target, None, GROUP).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        line_with(
            &dry.stdout,
            "HELD-LINEAGE\talpha\t",
            &[&fx.e_s6_pn.to_string()]
        ),
        "alpha must be held on the edge: {}",
        dry.show()
    );
    assert!(
        dry.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t1"),
        "{}",
        dry.show()
    );
    let alpha_wf = [fx.w_a0, fx.w_a1];
    let alpha = [fx.t, fx.p, fx.s1, fx.s1n, fx.s2, fx.s3, fx.a1, fx.s5, fx.s6];

    let r = reown_run(&pool, &fx, &dir, &manifest, fx.target, Some("1"), GROUP).await;
    assert_eq!(
        r.code,
        3,
        "an apply that held a lineage on a hand-off must exit 3: {}",
        r.show()
    );
    assert!(
        line_with(&r.stdout, "SHORTFALL", &["alpha"]),
        "{}",
        r.show()
    );
    let src_public = (fx.src, "public".to_string());
    for w in alpha_wf {
        assert_eq!(tenancy(&pool, "workflows", w).await, src_public, "{w}");
    }
    for c in alpha {
        assert_eq!(tenancy(&pool, "claims", c).await, src_public, "{c}");
    }
    assert_eq!(
        tenancy(&pool, "edges", fx.e_s6_pn).await,
        (fx.src, "group".to_string())
    );
    let narrowed = (fx.target, "group".to_string());
    assert_eq!(tenancy(&pool, "workflows", fx.w_b0).await, narrowed);
    assert_eq!(tenancy(&pool, "claims", fx.tb).await, narrowed);
    std::fs::remove_dir_all(&dir).ok();
}

// ─────────────────────────────────────────────────────────────────────────────
// Catch-up: a lineage re-ingested between runs
// ─────────────────────────────────────────────────────────────────────────────

async fn reverse_many(pool: &PgPool, manifests: &[&Path], apply: bool) -> Run {
    let mut args = vec!["reown-reverse"];
    for m in manifests {
        args.push("--manifest");
        args.push(m.to_str().unwrap());
    }
    if apply {
        args.push("--apply");
    }
    run_op(pool, &args).await
}

/// After a move, alpha is re-ingested: generation 2 lands in the SOURCE's
/// private state (neither the run's FROM nor its TO state), with a new step.
/// The main act holds it and names `--catch-up`; `--catch-up` moves ONLY that
/// generation and its new step into the target, audited, and its manifest
/// reverses exactly. The original manifest then refuses (a generation joined
/// after it).
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_moves_only_a_re_ingested_generation_and_reverses(pool: PgPool) {
    let fx = seed_with(&pool, Neighbour::Target).await;
    let dir = scratch_dir();
    let m1 = dir.join("m1.jsonl");
    let m2 = dir.join("m2.jsonl");

    let r = reown_run(&pool, &fx, &dir, &m2, fx.target, None, &["--catch-up"]).await;
    assert_eq!(r.code, 1, "--catch-up needs a narrowing: {}", r.show());
    assert!(r.stderr.contains("--visibility group"), "{}", r.show());

    let r = reown_run(&pool, &fx, &dir, &m2, fx.target, None, CATCH_UP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    for n in ["alpha", "beta"] {
        assert!(
            r.stdout
                .lines()
                .any(|l| l.starts_with(&format!("SKIPPED-LINEAGE\t{n}\t"))),
            "{n}: a lineage with no stray generation is the main act's: {}",
            r.show()
        );
    }
    assert!(
        r.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t0"),
        "{}",
        r.show()
    );

    let r = reown_run(&pool, &fx, &dir, &m1, fx.target, Some("3"), GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());

    let (w_a2, ns, e_exec, e_var, e_exec_t) = {
        let mut m = pool.acquire().await.expect("acquire");
        let w = workflow(&mut m, "alpha", 2, Some(fx.w_a1), fx.src, "group").await;
        let ns = claim(
            &mut m,
            fx.operator,
            fx.src,
            "group",
            2,
            "alpha step seven (generation 2)",
        )
        .await;
        let e1 = edge(&mut m, (w, "workflow"), (ns, "claim"), "executes").await;
        let e2 = edge(&mut m, (w, "workflow"), (fx.w_a1, "workflow"), "variant_of").await;
        let e3 = edge(&mut m, (w, "workflow"), (fx.t, "claim"), "executes").await;
        (w, ns, e1, e2, e3)
    };
    let stray = snapshot_sans_epoch(&pool).await;

    let m3 = dir.join("m3.jsonl");
    let r = reown_run(&pool, &fx, &dir, &m3, fx.target, None, GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(&r.stdout, "HELD-LINEAGE\talpha\t", &["--catch-up"]),
        "the main act holds the re-ingested lineage and names the remedy: {}",
        r.show()
    );

    let r = reown_run(&pool, &fx, &dir, &m2, fx.target, None, &catch_up_after(&m1)).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t1"),
        "{}",
        r.show()
    );
    assert!(
        r.stdout
            .lines()
            .any(|l| l.starts_with("ALREADY-LINEAGE\tbeta\t")),
        "{}",
        r.show()
    );
    let audits = security_events(&pool, "operator.workflows_reowned").await;
    let r = reown_run(
        &pool,
        &fx,
        &dir,
        &m2,
        fx.target,
        Some("1"),
        &catch_up_after(&m1),
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(
        security_events(&pool, "operator.workflows_reowned").await,
        audits + 1,
        "the catch-up is audited"
    );
    let narrowed = (fx.target, "group".to_string());
    assert_eq!(tenancy(&pool, "workflows", w_a2).await, narrowed);
    assert_eq!(tenancy(&pool, "claims", ns).await, narrowed);
    for e in [e_exec, e_var, e_exec_t] {
        assert_eq!(tenancy(&pool, "edges", e).await, narrowed, "edge {e}");
    }
    let mut after = snapshot_sans_epoch(&pool).await;
    let mut want = stray.clone();
    for s in [&mut after, &mut want] {
        for rows in s.values_mut() {
            rows.retain(|row| {
                ![w_a2, ns, e_exec, e_var]
                    .iter()
                    .any(|id| row.contains(&id.to_string()))
            });
        }
    }
    assert_eq!(
        after, want,
        "the catch-up changed something besides the stray generation"
    );

    // Both manifests in one reversal, newest first, as the operator script
    // passes them.
    let rev = reverse_many(&pool, &[&m1, &m2], true).await;
    assert_eq!(rev.code, 3, "{}", rev.show());
    assert!(rev.stdout.contains(&w_a2.to_string()), "{}", rev.show());
    assert_eq!(
        snapshot_sans_epoch(&pool).await,
        stray,
        "the catch-up's reversal must restore exactly the state it started from"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// After an in-place narrowing, a generation ingested PUBLIC (before the
/// private default) is the FROM state while the rest of its lineage is the TO
/// state. The main act holds it; `--catch-up` narrows only it and its step.
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_narrows_a_public_generation_ingested_after_an_in_place_narrowing(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let m1 = dir.join("m1.jsonl");
    let m2 = dir.join("m2.jsonl");
    let r = reown_run(&pool, &fx, &dir, &m1, fx.src, Some("3"), GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let (w_a2, np) = {
        let mut m = pool.acquire().await.expect("acquire");
        let w = workflow(&mut m, "alpha", 2, Some(fx.w_a1), fx.src, "public").await;
        let np = claim(&mut m, fx.operator, fx.src, "public", 2, "alpha step eight").await;
        edge(&mut m, (w, "workflow"), (np, "claim"), "executes").await;
        (w, np)
    };
    let r = reown_run(&pool, &fx, &dir, &m2, fx.src, None, GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(&r.stdout, "HELD-LINEAGE\talpha\t", &["--catch-up"]),
        "{}",
        r.show()
    );
    let r = reown_run(
        &pool,
        &fx,
        &dir,
        &m2,
        fx.src,
        Some("1"),
        &catch_up_after(&m1),
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let in_place = (fx.src, "group".to_string());
    assert_eq!(tenancy(&pool, "workflows", w_a2).await, in_place);
    assert_eq!(tenancy(&pool, "claims", np).await, in_place);
    assert_eq!(app_reads_claims(&pool, &[np]).await, Vec::<String>::new());
    std::fs::remove_dir_all(&dir).ok();
}

/// A step executed by a listed lineage AND by a source-owned public lineage
/// left off the list is shared, so this run never narrows it. Narrowing the
/// two lineages in separate runs would leave it public for good, so the dry
/// run names the split for the operator to rule on. A step sharing a
/// fragment with a shared step stays with it, reported SHARED (the cascade
/// would narrow the fragment for both).
#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_names_a_step_split_with_an_unlisted_source_lineage(pool: PgPool) {
    let fx = seed(&pool).await;
    {
        let mut m = pool.acquire().await.expect("acquire");
        let w = workflow(&mut m, "epsilon", 0, None, fx.src, "public").await;
        edge(&mut m, (w, "workflow"), (fx.s2, "claim"), "executes").await;
    }
    let hsource: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_sources (content_hash, modality) VALUES ($1, 'text') RETURNING id",
    )
    .bind(h32(Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed harvester source");
    let frag: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_fragments (source_id, content_hash, content_text, owner_group_id, \
                                          visibility) \
         VALUES ($1, $2, 'fragment of step three and the shared step', $3, 'public') \
         RETURNING id",
    )
    .bind(hsource)
    .bind(h32(Uuid::new_v4()))
    .bind(fx.src)
    .fetch_one(&pool)
    .await
    .expect("seed fragment");
    for cl in [fx.s3, fx.x] {
        sqlx::query(
            "INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)",
        )
        .bind(cl)
        .bind(frag)
        .execute(&pool)
        .await
        .expect("seed provenance");
    }
    let dir = scratch_dir();
    let manifest = dir.join("m.jsonl");
    let r = reown_run(&pool, &fx, &dir, &manifest, fx.src, None, GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(
            &r.stdout,
            "SHARED-SPLIT\t",
            &[&fx.s2.to_string(), "epsilon"]
        ),
        "{}",
        r.show()
    );
    assert!(
        !line_with(&r.stdout, "SHARED-SPLIT\t", &[&fx.x.to_string()]),
        "X is shared with another team's lineage, not split: {}",
        r.show()
    );
    assert!(
        line_with(
            &r.stdout,
            "LEFT-CLAIM\t",
            &[&fx.s3.to_string(), "SHARED", &frag.to_string()]
        ),
        "a step sharing a fragment with a shared step stays with it: {}",
        r.show()
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ─────────────────────────────────────────────────────────────────────────────
// Catch-up never widens anything but the stray generation's own rows
// ─────────────────────────────────────────────────────────────────────────────

/// An edge's full tenancy: `(owner, visibility, co-owner)`.
async fn edge_tenancy(pool: &PgPool, id: Uuid) -> (Uuid, String, Option<Uuid>) {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("tenancy of edge {id}: {e}"))
}

/// A private re-ingest of `alpha` after its move: generation 2 and its new
/// step NS in the SOURCE's private state, with the edges a real ingest writes
/// (`executes` to NS and to the moved thesis T, `variant_of` to generation 1,
/// phase P `decomposes_to` NS, the author's `AUTHORED` on NS).
struct Stray {
    w_a2: Uuid,
    ns: Uuid,
    edges: Vec<Uuid>,
}

async fn private_reingest(pool: &PgPool, fx: &Fx) -> Stray {
    let mut m = pool.acquire().await.expect("acquire");
    let w_a2 = workflow(&mut m, "alpha", 2, Some(fx.w_a1), fx.src, "group").await;
    let ns = claim(
        &mut m,
        fx.operator,
        fx.src,
        "group",
        2,
        "alpha step nine (a private re-ingest)",
    )
    .await;
    let edges = vec![
        edge(&mut m, (w_a2, "workflow"), (ns, "claim"), "executes").await,
        edge(&mut m, (w_a2, "workflow"), (fx.t, "claim"), "executes").await,
        edge(
            &mut m,
            (w_a2, "workflow"),
            (fx.w_a1, "workflow"),
            "variant_of",
        )
        .await,
        edge(&mut m, (fx.p, "claim"), (ns, "claim"), "decomposes_to").await,
        edge(&mut m, (fx.operator, "agent"), (ns, "claim"), "AUTHORED").await,
    ];
    Stray { w_a2, ns, edges }
}

/// The main move of the LISTED lineages into the target, `alpha` included
/// (the private note is the target's, so nothing holds it).
async fn main_move(pool: &PgPool, fx: &Fx, dir: &Path) {
    let r = reown_run(
        pool,
        fx,
        dir,
        &dir.join("main.jsonl"),
        fx.target,
        Some("3"),
        GROUP,
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(
        tenancy(pool, "claims", fx.p).await,
        (fx.target, "group".to_string()),
        "PREMISE: the main act moved alpha"
    );
}

/// A real private re-ingest after a move: every row of the stray generation
/// (its workflow row, the step only it executes, and that step's plan edges,
/// including the phase's `decomposes_to` met with the source and the author's
/// `AUTHORED`) lands exactly in the target state.
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_moves_every_own_row_of_a_private_re_ingest(pool: PgPool) {
    let fx = seed_with(&pool, Neighbour::Target).await;
    let dir = scratch_dir();
    main_move(&pool, &fx, &dir).await;
    let s = private_reingest(&pool, &fx).await;
    let src_private = (fx.src, "group".to_string(), None);
    assert_eq!(
        edge_tenancy(&pool, s.edges[0]).await,
        src_private,
        "PREMISE"
    );
    assert_eq!(
        edge_tenancy(&pool, s.edges[4]).await,
        src_private,
        "PREMISE"
    );
    assert_eq!(
        edge_tenancy(&pool, s.edges[3]).await,
        (fx.target, "group".to_string(), Some(fx.src)),
        "PREMISE: the phase's edge to the private step is co-owned by the source"
    );

    let m = dir.join("c.jsonl");
    let main = dir.join("main.jsonl");
    let r = reown_run(
        &pool,
        &fx,
        &dir,
        &m,
        fx.target,
        None,
        &catch_up_after(&main),
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t1"),
        "{}",
        r.show()
    );
    let r = reown_run(
        &pool,
        &fx,
        &dir,
        &m,
        fx.target,
        Some("1"),
        &catch_up_after(&main),
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let to = (fx.target, "group".to_string());
    assert_eq!(tenancy(&pool, "workflows", s.w_a2).await, to);
    assert_eq!(tenancy(&pool, "claims", s.ns).await, to);
    for e in &s.edges {
        assert_eq!(
            edge_tenancy(&pool, *e).await,
            (fx.target, "group".to_string(), None),
            "edge {e}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// `alpha` is held by the main act (the source's private evidence on S2), then
/// gets a private generation 2 with NO generation in the target state. That is
/// the main act's lineage, not a stray one: `--catch-up` takes none of it, and
/// the private evidence stays the source's. The evidence alone also holds
/// `alpha`, so this test pins the main act's hint; the stray rule's own red
/// line is
/// [`catch_up_never_takes_a_lineage_with_a_private_generation_and_none_in_the_target`].
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_takes_nothing_of_a_lineage_with_no_generation_in_the_target(pool: PgPool) {
    let fx = seed_with(&pool, Neighbour::Target).await;
    let ev: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, 'document', $2, 'a private note on step two') RETURNING id",
    )
    .bind(fx.s2)
    .bind(h32(Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("evidence");
    sqlx::query("UPDATE evidence SET visibility = 'group' WHERE id = $1")
        .bind(ev)
        .execute(&pool)
        .await
        .expect("private evidence");
    let src_private = (fx.src, "group".to_string());
    assert_eq!(tenancy(&pool, "evidence", ev).await, src_private, "PREMISE");
    let dir = scratch_dir();
    let m = dir.join("m.jsonl");
    let r = reown_run(&pool, &fx, &dir, &m, fx.target, None, GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(&r.stdout, "HELD-LINEAGE\talpha\t", &[&ev.to_string()]),
        "PREMISE: the main act holds alpha on the evidence: {}",
        r.show()
    );
    let w_a2 = {
        let mut c = pool.acquire().await.expect("acquire");
        let w = workflow(&mut c, "alpha", 2, Some(fx.w_a1), fx.src, "group").await;
        edge(&mut c, (w, "workflow"), (fx.t, "claim"), "executes").await;
        w
    };
    let before = snapshot_sans_epoch(&pool).await;

    let r = reown_run(&pool, &fx, &dir, &m, fx.target, None, GROUP).await;
    assert!(
        !line_with(&r.stdout, "HELD-LINEAGE\talpha\t", &["--catch-up"]),
        "a lineage with nothing in the target state is not a catch-up's: {}",
        r.show()
    );
    let r = reown_run(&pool, &fx, &dir, &m, fx.target, None, CATCH_UP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(&r.stdout, "HELD-LINEAGE\talpha\t", &[]),
        "{}",
        r.show()
    );
    assert!(
        r.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t0"),
        "{}",
        r.show()
    );
    let r = reown_run(&pool, &fx, &dir, &m, fx.target, Some("3"), CATCH_UP).await;
    assert_eq!(r.code, 1, "the old count must be refused: {}", r.show());
    assert_eq!(tenancy(&pool, "evidence", ev).await, src_private);
    assert_eq!(tenancy(&pool, "workflows", w_a2).await, src_private);
    assert_eq!(
        snapshot_sans_epoch(&pool).await,
        before,
        "nothing is written"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Run a catch-up of a stray generation that carries one more source-private
/// row (`extra`) outside its own rows: the dry run holds `alpha` naming it, the
/// apply exits 3, and nothing is written.
async fn catch_up_holds_on(pool: &PgPool, fx: &Fx, dir: &Path, s: &Stray, extra: Uuid) {
    let before = snapshot_sans_epoch(pool).await;
    let m = dir.join("c.jsonl");
    let main = dir.join("main.jsonl");
    let r = reown_run(pool, fx, dir, &m, fx.target, None, &catch_up_after(&main)).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(&r.stdout, "HELD-LINEAGE\talpha\t", &[&extra.to_string()]),
        "the catch-up must hold alpha on {extra}: {}",
        r.show()
    );
    assert!(
        r.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t0"),
        "{}",
        r.show()
    );
    let r = reown_run(
        pool,
        fx,
        dir,
        &m,
        fx.target,
        Some("0"),
        &catch_up_after(&main),
    )
    .await;
    assert_eq!(r.code, 3, "a held hand-off exits 3: {}", r.show());
    let src_private = (fx.src, "group".to_string());
    assert_eq!(tenancy(pool, "workflows", s.w_a2).await, src_private);
    assert_eq!(tenancy(pool, "claims", s.ns).await, src_private);
    assert_eq!(
        snapshot_sans_epoch(pool).await,
        before,
        "nothing is written"
    );
}

/// The source's private evidence on the stray step is not one of the stray
/// generation's own rows (a derived row): the catch-up must not hand it to the
/// target.
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_holds_a_stray_step_whose_private_evidence_would_go_to_the_target(pool: PgPool) {
    let fx = seed_with(&pool, Neighbour::Target).await;
    let dir = scratch_dir();
    main_move(&pool, &fx, &dir).await;
    let s = private_reingest(&pool, &fx).await;
    let ev: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, 'document', $2, 'a private note on the new step') RETURNING id",
    )
    .bind(s.ns)
    .bind(h32(Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("evidence");
    assert_eq!(
        tenancy(&pool, "evidence", ev).await,
        (fx.src, "group".to_string()),
        "PREMISE: the evidence follows its private claim"
    );
    catch_up_holds_on(&pool, &fx, &dir, &s, ev).await;
    std::fs::remove_dir_all(&dir).ok();
}

/// A source-private edge from the stray step to a row OUTSIDE the plans (Y, an
/// unrelated public claim of the operator): its narrowing meets to exactly the
/// target state, the shape the round-3 exemption let through, but it is not
/// the stray generation's own. The catch-up must hold it.
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_holds_a_stray_steps_private_edge_to_a_row_outside_the_plans(pool: PgPool) {
    let fx = seed_with(&pool, Neighbour::Target).await;
    let dir = scratch_dir();
    main_move(&pool, &fx, &dir).await;
    let s = private_reingest(&pool, &fx).await;
    let e = {
        let mut m = pool.acquire().await.expect("acquire");
        edge(&mut m, (s.ns, "claim"), (fx.y, "claim"), "supports").await
    };
    assert_eq!(
        tenancy(&pool, "claims", fx.y).await,
        (fx.src, "public".to_string()),
        "PREMISE"
    );
    assert_eq!(
        edge_tenancy(&pool, e).await,
        (fx.src, "group".to_string(), None),
        "PREMISE: the edge is the source's private row"
    );
    catch_up_holds_on(&pool, &fx, &dir, &s, e).await;
    std::fs::remove_dir_all(&dir).ok();
}

/// A private step the main act LEFT (an evolved member of S1's step lineage,
/// which the moved plan reaches through that lineage) and the stray
/// generation then executes is not the stray generation's alone: it stays the
/// source's, and nothing hands it to the target.
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_never_moves_a_private_step_the_main_act_left(pool: PgPool) {
    let fx = seed_with(&pool, Neighbour::Target).await;
    let lineage: Uuid = sqlx::query_scalar("SELECT step_lineage_id FROM claims WHERE id = $1")
        .bind(fx.s1)
        .fetch_one(&pool)
        .await
        .expect("S1's step lineage");
    let q = {
        let mut m = pool.acquire().await.expect("acquire");
        claim_in_lineage(
            &mut m,
            fx.operator,
            fx.src,
            "group",
            2,
            "alpha step one, evolved privately",
            Some(lineage),
        )
        .await
    };
    let dir = scratch_dir();
    main_move(&pool, &fx, &dir).await;
    let src_private = (fx.src, "group".to_string());
    assert_eq!(
        tenancy(&pool, "claims", q).await,
        src_private,
        "PREMISE: the main act left the private step"
    );
    let s = private_reingest(&pool, &fx).await;
    let e_q = {
        let mut m = pool.acquire().await.expect("acquire");
        edge(&mut m, (s.w_a2, "workflow"), (q, "claim"), "executes").await
    };
    // Q is the stray generation's only through this edge; the moved plan
    // reaches it through S1's lineage. Left, its private `executes` edge from
    // the moving generation would become the target's: the lineage holds.
    catch_up_holds_on(&pool, &fx, &dir, &s, e_q).await;
    assert_eq!(tenancy(&pool, "claims", q).await, src_private);
    std::fs::remove_dir_all(&dir).ok();
}

/// A private step the moved plan executes DIRECTLY (one with no step lineage,
/// added to generation 1 after the move and kept in the source's private
/// state) that the stray generation then executes too is not the stray
/// generation's alone: it stays the source's, and nothing hands it to the
/// target.
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_never_moves_a_private_step_the_moved_plan_executes(pool: PgPool) {
    let fx = seed_with(&pool, Neighbour::Target).await;
    let dir = scratch_dir();
    main_move(&pool, &fx, &dir).await;
    let s = private_reingest(&pool, &fx).await;
    let (k, e_k) = {
        let mut m = pool.acquire().await.expect("acquire");
        let k = claim(
            &mut m,
            fx.operator,
            fx.src,
            "group",
            2,
            "alpha step ten, kept private in the moved plan",
        )
        .await;
        edge(&mut m, (fx.w_a1, "workflow"), (k, "claim"), "executes").await;
        let e_k = edge(&mut m, (s.w_a2, "workflow"), (k, "claim"), "executes").await;
        (k, e_k)
    };
    let src_private = (fx.src, "group".to_string());
    assert_eq!(tenancy(&pool, "claims", k).await, src_private, "PREMISE");
    assert_eq!(
        tenancy(&pool, "workflows", fx.w_a1).await,
        (fx.target, "group".to_string()),
        "PREMISE: generation 1 is in the target state"
    );
    let step_lineage: Option<Uuid> =
        sqlx::query_scalar("SELECT step_lineage_id FROM claims WHERE id = $1")
            .bind(k)
            .fetch_one(&pool)
            .await
            .expect("step lineage");
    assert_eq!(step_lineage, None, "PREMISE: reached only directly");
    // K is executed by the target-state generation 1 as well, so it is not
    // the stray generation's own; its private `executes` edge from the moving
    // generation would become the target's: the lineage holds.
    catch_up_holds_on(&pool, &fx, &dir, &s, e_k).await;
    assert_eq!(tenancy(&pool, "claims", k).await, src_private);
    std::fs::remove_dir_all(&dir).ok();
}

/// A lineage with source generations and NONE in the target state is the main
/// act's, never a catch-up's, even when one of its generations is in the
/// source's private state: `--catch-up` takes nothing of it. The fixture has
/// no other reason to hold `alpha` (no private derived row, no edge to a row
/// outside the plans, the private note is the target's: the PREMISE shows the
/// main act would take it whole), so the stray rule alone decides.
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_never_takes_a_lineage_with_a_private_generation_and_none_in_the_target(
    pool: PgPool,
) {
    let fx = seed_with(&pool, Neighbour::Target).await;
    let dir = scratch_dir();
    let m = dir.join("c.jsonl");
    let r = reown_run(&pool, &fx, &dir, &m, fx.target, None, GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        !r.stdout.contains("HELD-LINEAGE\talpha\t")
            && line_with(&r.stdout, "WORKFLOW\t", &[&fx.w_a1.to_string()]),
        "PREMISE: nothing else holds alpha, the main act would take it: {}",
        r.show()
    );
    let w_a2 = {
        let mut c = pool.acquire().await.expect("acquire");
        let w = workflow(&mut c, "alpha", 2, Some(fx.w_a1), fx.src, "group").await;
        edge(&mut c, (w, "workflow"), (fx.t, "claim"), "executes").await;
        w
    };
    let before = snapshot_sans_epoch(&pool).await;

    let r = reown_run(&pool, &fx, &dir, &m, fx.target, None, CATCH_UP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(&r.stdout, "HELD-LINEAGE\talpha\t", &["visibility group"]),
        "the source's private generation holds the main act's lineage: {}",
        r.show()
    );
    assert!(
        r.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t0"),
        "{}",
        r.show()
    );
    let r = reown_run(&pool, &fx, &dir, &m, fx.target, Some("3"), CATCH_UP).await;
    assert_eq!(r.code, 1, "the main act's count is refused: {}", r.show());
    // A lineage held for its state is reported, not a hand-off: the apply of
    // the dry run's count exits 0 and writes nothing.
    let r = reown_run(&pool, &fx, &dir, &m, fx.target, Some("0"), CATCH_UP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let src_private = (fx.src, "group".to_string());
    let src_public = (fx.src, "public".to_string());
    assert_eq!(tenancy(&pool, "workflows", w_a2).await, src_private);
    assert_eq!(tenancy(&pool, "workflows", fx.w_a1).await, src_public);
    assert_eq!(tenancy(&pool, "claims", fx.p).await, src_public);
    assert_eq!(
        snapshot_sans_epoch(&pool).await,
        before,
        "nothing is written"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A catch-up takes a stray lineage only when an act on record moved it. After
/// the main move, `alpha` gets a private re-ingest (a stray generation beside
/// generations the main manifest moved), and `missing` appears with generation
/// 0 owned NATIVELY by the target, in exactly the target state, and generation
/// 1 in the source's private state executing a private step only it executes.
/// Neither carries another reason to hold it. With the main manifest passed,
/// the catch-up takes `alpha` and holds `missing`: the source's private rows
/// never go to a group because it owns a same-named generation. A manifest of
/// another act is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_holds_a_lineage_the_target_owns_natively(pool: PgPool) {
    let fx = seed_with(&pool, Neighbour::Target).await;
    let dir = scratch_dir();
    main_move(&pool, &fx, &dir).await;
    let main = dir.join("main.jsonl");
    let s = private_reingest(&pool, &fx).await;
    let (n0, n1, nc, e) = {
        let mut c = pool.acquire().await.expect("acquire");
        let n0 = workflow(&mut c, "missing", 0, None, fx.target, "group").await;
        let n1 = workflow(&mut c, "missing", 1, Some(n0), fx.src, "group").await;
        let nc = claim(
            &mut c,
            fx.operator,
            fx.src,
            "group",
            2,
            "a private step of the source's generation",
        )
        .await;
        let e = edge(&mut c, (n1, "workflow"), (nc, "claim"), "executes").await;
        (n0, n1, nc, e)
    };
    let to = (fx.target, "group".to_string());
    let src_private = (fx.src, "group".to_string());
    assert_eq!(tenancy(&pool, "workflows", n0).await, to, "PREMISE");
    assert_eq!(
        edge_tenancy(&pool, e).await,
        (fx.src, "group".to_string(), None),
        "PREMISE: the edge is the source's private row, like a stray step's"
    );

    // Another act's manifest (another target) is refused.
    let other = dir.join("other.jsonl");
    let text = std::fs::read_to_string(&main).expect("read the main manifest");
    std::fs::write(
        &other,
        text.replacen(&fx.target.to_string(), &fx.other_team.to_string(), 1),
    )
    .expect("write");
    let m = dir.join("c.jsonl");
    let r = reown_run(
        &pool,
        &fx,
        &dir,
        &m,
        fx.target,
        None,
        &catch_up_after(&other),
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("not this run's"), "{}", r.show());

    let before = snapshot_sans_epoch(&pool).await;
    let r = reown_run(
        &pool,
        &fx,
        &dir,
        &m,
        fx.target,
        None,
        &catch_up_after(&main),
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(
            &r.stdout,
            "HELD-LINEAGE\tmissing\t",
            &["not moved there by any --after-manifest"]
        ),
        "the target's own lineage is no catch-up's: {}",
        r.show()
    );
    assert!(
        line_with(&r.stdout, "WORKFLOW\t", &[&s.w_a2.to_string()]),
        "the act's lineage is: {}",
        r.show()
    );
    assert!(
        r.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t1"),
        "{}",
        r.show()
    );
    let r = reown_run(
        &pool,
        &fx,
        &dir,
        &m,
        fx.target,
        Some("1"),
        &catch_up_after(&main),
    )
    .await;
    assert_eq!(r.code, 0, "a held lineage is not a hand-off: {}", r.show());
    assert_eq!(tenancy(&pool, "workflows", s.w_a2).await, to);
    assert_eq!(tenancy(&pool, "workflows", n1).await, src_private);
    assert_eq!(tenancy(&pool, "claims", nc).await, src_private);
    assert_eq!(
        edge_tenancy(&pool, e).await,
        (fx.src, "group".to_string(), None)
    );
    let mut after = snapshot_sans_epoch(&pool).await;
    let mut want = before;
    let mut moved: Vec<Uuid> = vec![s.w_a2, s.ns];
    moved.extend(&s.edges);
    for snap in [&mut after, &mut want] {
        for rows in snap.values_mut() {
            rows.retain(|row| !moved.iter().any(|id| row.contains(&id.to_string())));
        }
    }
    assert_eq!(after, want, "the catch-up changed the target's lineage");
    std::fs::remove_dir_all(&dir).ok();
}

/// `missing` with generation 0 natively in `owner`'s private state (no act
/// moved it there) and generation 1 in SRC's public state, executing a public
/// step only it executes: (generation 0, generation 1, the step).
async fn native_beside_public(pool: &PgPool, fx: &Fx, owner: Uuid) -> (Uuid, Uuid, Uuid) {
    let mut c = pool.acquire().await.expect("acquire");
    let n0 = workflow(&mut c, "missing", 0, None, owner, "group").await;
    let n1 = workflow(&mut c, "missing", 1, Some(n0), fx.src, "public").await;
    let np = claim(
        &mut c,
        fx.operator,
        fx.src,
        "public",
        2,
        "missing public step",
    )
    .await;
    edge(&mut c, (n1, "workflow"), (np, "claim"), "executes").await;
    (n0, n1, np)
}

/// In place the target IS the source, so a catch-up can only narrow the
/// source's own public rows into its own private state: no act need be on
/// record. A personal lineage with a natively private generation beside a
/// public one is held by the main in-place act, whose hint names plain
/// `--catch-up` (no act moved generation 0, so there is no manifest to name);
/// a plain `--catch-up` then narrows generation 1 and its step, leaves
/// generation 0 as it is, leaves nothing of the lineage public, exits 0, and
/// its reversal restores exactly the state it found.
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_in_place_narrows_a_public_generation_beside_a_native_private_one(pool: PgPool) {
    let fx = seed(&pool).await;
    let (n0, n1, np) = native_beside_public(&pool, &fx, fx.src).await;
    let in_place = (fx.src, "group".to_string());
    let src_public = (fx.src, "public".to_string());
    let dir = scratch_dir();
    let m1 = dir.join("m1.jsonl");
    let r = reown_run(&pool, &fx, &dir, &m1, fx.src, None, GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(
            &r.stdout,
            "HELD-LINEAGE\tmissing\t",
            &["partly the target's", "--catch-up"]
        ) && !line_with(&r.stdout, "HELD-LINEAGE\tmissing\t", &["--after-manifest"]),
        "in place the hint names plain --catch-up, never a manifest no act wrote: {}",
        r.show()
    );
    let r = reown_run(&pool, &fx, &dir, &m1, fx.src, Some("3"), GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(
        tenancy(&pool, "workflows", n1).await,
        src_public,
        "PREMISE: the main act holds the lineage"
    );

    let m2 = dir.join("m2.jsonl");
    let before = snapshot_sans_epoch(&pool).await;
    let r = reown_run(&pool, &fx, &dir, &m2, fx.src, None, CATCH_UP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        !r.stdout.contains("HELD-LINEAGE\tmissing\t")
            && line_with(&r.stdout, "WORKFLOW\t", &[&n1.to_string()])
            && r.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t1"),
        "an in-place catch-up takes the public generation: {}",
        r.show()
    );
    let r = reown_run(&pool, &fx, &dir, &m2, fx.src, Some("1"), CATCH_UP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(tenancy(&pool, "workflows", n0).await, in_place);
    assert_eq!(tenancy(&pool, "workflows", n1).await, in_place);
    assert_eq!(tenancy(&pool, "claims", np).await, in_place);
    assert_eq!(
        app_reads_claims(&pool, &[np]).await,
        Vec::<String>::new(),
        "an unstamped session still reads the narrowed step"
    );
    let public: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflows WHERE canonical_name = 'missing' \
            AND visibility = 'public'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(public, 0, "a generation of the lineage stayed public");

    let rev = reverse(&pool, &m2, true).await;
    assert_eq!(rev.code, 0, "{}", rev.show());
    assert_eq!(
        snapshot_sans_epoch(&pool).await,
        before,
        "the catch-up's reversal must restore exactly the state it found: {}",
        rev.show()
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The same shape in a MOVE: generation 0 natively in the TARGET's private
/// state, generation 1 in SRC's public state. No act moved generation 0, so a
/// catch-up must never take generation 1 into the target on a shared name: it
/// is held, by design, even with the main manifest passed, and nothing is
/// written. The main act's hint says so, and never sends the operator to "the
/// manifest of the act that moved them" when no act did.
#[sqlx::test(migrations = "../../migrations")]
async fn catch_up_in_a_move_holds_a_public_generation_beside_a_native_target_one(pool: PgPool) {
    let fx = seed_with(&pool, Neighbour::Target).await;
    let dir = scratch_dir();
    main_move(&pool, &fx, &dir).await;
    let main = dir.join("main.jsonl");
    let (n0, n1, np) = native_beside_public(&pool, &fx, fx.target).await;
    let src_public = (fx.src, "public".to_string());

    let m = dir.join("c.jsonl");
    let r = reown_run(&pool, &fx, &dir, &m, fx.target, None, GROUP).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(
            &r.stdout,
            "HELD-LINEAGE\tmissing\t",
            &["partly the target's", "held by design"]
        ) && !r.stdout.contains("the manifest of the act that moved them"),
        "a move's hint names the held-by-design case: {}",
        r.show()
    );

    let before = snapshot_sans_epoch(&pool).await;
    let r = reown_run(
        &pool,
        &fx,
        &dir,
        &m,
        fx.target,
        None,
        &catch_up_after(&main),
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        line_with(
            &r.stdout,
            "HELD-LINEAGE\tmissing\t",
            &["not moved there by any --after-manifest", "held by design"]
        ) && r.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t0"),
        "the target's own lineage is no catch-up's: {}",
        r.show()
    );
    let r = reown_run(
        &pool,
        &fx,
        &dir,
        &m,
        fx.target,
        Some("0"),
        &catch_up_after(&main),
    )
    .await;
    assert_eq!(r.code, 0, "a held lineage is not a hand-off: {}", r.show());
    assert_eq!(
        tenancy(&pool, "workflows", n0).await,
        (fx.target, "group".to_string())
    );
    assert_eq!(tenancy(&pool, "workflows", n1).await, src_public);
    assert_eq!(tenancy(&pool, "claims", np).await, src_public);
    assert_eq!(
        snapshot_sans_epoch(&pool).await,
        before,
        "nothing is written"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ─────────────────────────────────────────────────────────────────────────────
// A private move: ('group', source) -> ('group', target)
// ─────────────────────────────────────────────────────────────────────────────

const PRIVATE: &[&str] = &["--from-visibility", "group", "--visibility", "group"];

/// A run of `names` with `extra` arguments into `target`: an `--apply`
/// confirming `confirm` when given, else a dry run. `from` is `--from-group`
/// (the operator's personal group when `None`).
#[allow(clippy::too_many_arguments)]
async fn run_names(
    pool: &PgPool,
    fx: &Fx,
    dir: &Path,
    manifest: &Path,
    names: &[&str],
    target: Uuid,
    from: Option<Uuid>,
    confirm: Option<&str>,
    extra: &[&str],
) -> Run {
    let file = names_file(dir, names);
    let target = target.to_string();
    let operator = fx.operator.to_string();
    let from = from.map(|g| g.to_string());
    let mut args = vec![
        "reown-workflows",
        "--canonical-names-file",
        file.to_str().unwrap(),
        "--target-group",
        &target,
        "--operator",
        &operator,
        "--manifest-out",
        manifest.to_str().unwrap(),
    ];
    if let Some(g) = from.as_deref() {
        args.extend(["--from-group", g]);
    }
    if let Some(n) = confirm {
        args.extend([
            "--apply",
            "--confirm-count",
            n,
            "--ruling",
            RULING,
            "--reason",
            "the plans move with the team that runs them",
        ]);
    }
    args.extend(extra.iter().copied());
    run_op(pool, &args).await
}

/// The setup every private-move test starts from: alpha and beta narrowed IN
/// PLACE by the real narrowing act, so their generations, plan claims, rows
/// and plan edges are in the source's private state exactly as that act
/// leaves them (nothing hand-forged).
async fn narrowed(pool: &PgPool, fx: &Fx, dir: &Path) {
    let m = dir.join("narrow-in-place.jsonl");
    let r = run_names(
        pool,
        fx,
        dir,
        &m,
        &["alpha", "beta"],
        fx.src,
        None,
        Some("3"),
        GROUP,
    )
    .await;
    assert_eq!(r.code, 0, "the in-place narrowing: {}", r.show());
    let private = (fx.src, "group".to_string());
    for w in [fx.w_a0, fx.w_a1, fx.w_b0] {
        assert_eq!(tenancy(pool, "workflows", w).await, private);
    }
    assert_eq!(tenancy(pool, "claims", fx.s2).await, private);
}

/// The ids among `ids` of `table` an `epigraph_app` session whose read set
/// is exactly `groups` reads.
async fn reads_as(pool: &PgPool, groups: &[Uuid], table: &str, ids: &[Uuid]) -> Vec<Uuid> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *tx)
        .await
        .expect("become epigraph_app");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, true), \
                set_config('epigraph.writable_group_ids', '', true), \
                set_config('epigraph.principal_id', '', true)",
    )
    .bind(csv(groups))
    .execute(&mut *tx)
    .await
    .expect("stamp");
    let mut out: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM {table} WHERE id = ANY($1) ORDER BY id"
    ))
    .bind(ids)
    .fetch_all(&mut *tx)
    .await
    .expect("read as epigraph_app");
    tx.rollback().await.expect("rollback");
    out.sort();
    out
}

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort();
    v
}

/// A self-contained private plan moves between groups and back: alpha and
/// beta, narrowed in place in the operator's personal group, move to a team
/// (the default source), then from that team to a second team
/// (`--from-group`), then from the second team into the operator's OWN
/// personal group. Each hop moves every generation, plan claim, row and plan
/// edge from `('group', source)` to `('group', target)`, never touches a
/// public row (the shared step X stays public), keeps the edge to the private
/// note PN co-owned with PN's group, never moves the atlas epoch, and is
/// readable by exactly the target's members. Reversing the three manifests
/// (newest first) restores every row exactly.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_carries_a_narrowed_plan_between_groups_and_reverses_exactly(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    narrowed(&pool, &fx, &dir).await;
    let team2 = team_group(&pool, "second team", fx.operator, "admin").await;
    let before = snapshot(&pool).await;
    let epoch_before = epoch(&pool).await;
    let names = ["alpha", "beta"];
    let moved_claims = [
        fx.t, fx.p, fx.s1, fx.s1n, fx.s2, fx.s3, fx.a1, fx.tb, fx.s5, fx.s6,
    ];

    // Dry run: the plan, nothing written.
    let m1 = dir.join("private-1.jsonl");
    let dry = run_names(
        &pool, &fx, &dir, &m1, &names, fx.target, None, None, PRIVATE,
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.contains("act=PRIVATE-MOVE"), "{}", dry.show());
    assert!(
        dry.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t3"),
        "{}",
        dry.show()
    );
    assert!(
        line_with(&dry.stdout, "CO-OWNED-EDGE\t", &[&fx.e_s6_pn.to_string()]),
        "the edge to the note that stays in the source is reported: {}",
        dry.show()
    );
    assert_eq!(snapshot(&pool).await, before, "a dry run wrote");
    assert!(!m1.exists());

    // Hop 1: the operator's personal group -> the target team.
    let r1 = run_names(
        &pool,
        &fx,
        &dir,
        &m1,
        &names,
        fx.target,
        None,
        Some("3"),
        PRIVATE,
    )
    .await;
    assert_eq!(r1.code, 0, "{}", r1.show());
    let in_target = (fx.target, "group".to_string());
    for w in [fx.w_a0, fx.w_a1, fx.w_b0] {
        assert_eq!(tenancy(&pool, "workflows", w).await, in_target, "wf {w}");
    }
    for c in moved_claims {
        assert_eq!(tenancy(&pool, "claims", c).await, in_target, "claim {c}");
    }
    assert_eq!(tenancy(&pool, "evidence", fx.ev_s1).await, in_target);
    assert_eq!(tenancy(&pool, "mass_functions", fx.mf_s2).await, in_target);
    assert_eq!(
        tenancy(&pool, "harvester_fragments", fx.frag56).await,
        in_target
    );
    for e in &fx.plan_edges {
        assert_eq!(edge_tenancy(&pool, *e).await.0, fx.target, "plan edge {e}");
    }
    assert_eq!(
        tenancy(&pool, "claims", fx.x).await,
        (fx.src, "public".to_string()),
        "the shared public step is never touched"
    );
    assert_eq!(
        edge_tenancy(&pool, fx.e_s6_pn).await,
        (fx.target, "group".to_string(), Some(fx.src)),
        "an edge to the note that stays in the source is co-owned by both"
    );
    assert_eq!(epoch(&pool).await, epoch_before, "nothing public narrowed");
    assert_eq!(
        reads_as(&pool, &[fx.target], "claims", &moved_claims).await,
        sorted(moved_claims.to_vec())
    );
    assert!(reads_as(&pool, &[fx.src], "claims", &moved_claims)
        .await
        .is_empty());
    assert!(
        reads_as(&pool, &[fx.src], "workflows", &[fx.w_a0, fx.w_a1, fx.w_b0])
            .await
            .is_empty()
    );
    let body = std::fs::read_to_string(&m1).expect("manifest");
    let header: serde_json::Value =
        serde_json::from_str(body.lines().next().unwrap()).expect("header");
    assert_eq!(header["from_visibility"], "group");
    assert_eq!(header["act"], "PRIVATE-MOVE");

    // Hop 2: the target team -> a second team (`--from-group`).
    let m2 = dir.join("private-2.jsonl");
    let r2 = run_names(
        &pool,
        &fx,
        &dir,
        &m2,
        &names,
        team2,
        Some(fx.target),
        Some("3"),
        PRIVATE,
    )
    .await;
    assert_eq!(r2.code, 0, "{}", r2.show());
    for c in moved_claims {
        assert_eq!(
            tenancy(&pool, "claims", c).await,
            (team2, "group".to_string())
        );
    }
    assert_eq!(
        edge_tenancy(&pool, fx.e_s6_pn).await,
        (team2, "group".to_string(), Some(fx.src)),
        "the co-owner the note requires is kept"
    );

    // Hop 3: the second team -> the operator's OWN personal group.
    let m3 = dir.join("private-3.jsonl");
    let r3 = run_names(
        &pool,
        &fx,
        &dir,
        &m3,
        &names,
        fx.src,
        Some(team2),
        Some("3"),
        PRIVATE,
    )
    .await;
    assert_eq!(r3.code, 0, "{}", r3.show());
    for c in moved_claims {
        assert_eq!(
            tenancy(&pool, "claims", c).await,
            (fx.src, "group".to_string())
        );
    }
    assert_eq!(epoch(&pool).await, epoch_before);
    assert_eq!(
        security_events(&pool, "operator.workflows_reowned").await,
        4,
        "the narrowing and three moves: one audit row each"
    );

    let rev = reverse_many(&pool, &[&m1, &m2, &m3], true).await;
    assert_eq!(rev.code, 0, "{}", rev.show());
    assert_eq!(
        snapshot(&pool).await,
        before,
        "the reversals did not restore every row: {}",
        rev.show()
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A plan claim alpha shares with a lineage the list omits (epsilon, also
/// narrowed in the source) is LEFT where it is, reported as SHARED and as a
/// SHARED-SPLIT naming epsilon, and the edges from alpha's moved claims to it
/// become co-owned by both groups. The rest of alpha moves.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_leaves_a_shared_plan_claim_where_it_is_and_reports_the_split(pool: PgPool) {
    let fx = seed(&pool).await;
    {
        let mut m = pool.acquire().await.expect("acquire");
        let w = workflow(&mut m, "epsilon", 0, None, fx.src, "public").await;
        edge(&mut m, (w, "workflow"), (fx.s2, "claim"), "executes").await;
    }
    let dir = scratch_dir();
    let m0 = dir.join("narrow.jsonl");
    let r0 = run_names(
        &pool,
        &fx,
        &dir,
        &m0,
        &["alpha", "epsilon"],
        fx.src,
        None,
        Some("3"),
        GROUP,
    )
    .await;
    assert_eq!(r0.code, 0, "{}", r0.show());
    assert_eq!(
        tenancy(&pool, "claims", fx.s2).await,
        (fx.src, "group".to_string())
    );
    let m = dir.join("private.jsonl");
    let dry = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha"],
        fx.target,
        None,
        None,
        PRIVATE,
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        line_with(&dry.stdout, "LEFT-CLAIM\t", &[&fx.s2.to_string(), "SHARED"]),
        "{}",
        dry.show()
    );
    assert!(
        line_with(
            &dry.stdout,
            "SHARED-SPLIT\t",
            &[&fx.s2.to_string(), "epsilon"]
        ),
        "{}",
        dry.show()
    );
    let r = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha"],
        fx.target,
        None,
        Some("2"),
        PRIVATE,
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(
        tenancy(&pool, "claims", fx.s2).await,
        (fx.src, "group".to_string()),
        "the shared claim stays"
    );
    assert_eq!(
        tenancy(&pool, "mass_functions", fx.mf_s2).await,
        (fx.src, "group".to_string()),
        "and so does every row it carries"
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.s1).await,
        (fx.target, "group".to_string())
    );
    // plan_edges[2] is P -decomposes_to-> S2.
    assert_eq!(
        edge_tenancy(&pool, fx.plan_edges[2]).await,
        (fx.target, "group".to_string(), Some(fx.src))
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// A row of a private plan owned by a third group (another person's evidence
/// on S1) would be handed to the target: the whole lineage is HELD, nothing of
/// it moves, and an `--apply` that moves the rest exits 3.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_holds_a_lineage_carrying_a_third_groups_row(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    narrowed(&pool, &fx, &dir).await;
    sqlx::query("UPDATE evidence SET owner_group_id = $2 WHERE id = $1")
        .bind(fx.ev_s1)
        .bind(fx.stranger_group)
        .execute(&pool)
        .await
        .expect("a third group's evidence");
    let before = snapshot(&pool).await;
    let m = dir.join("private.jsonl");
    let dry = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        None,
        None,
        PRIVATE,
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        line_with(
            &dry.stdout,
            "HELD-LINEAGE\talpha\t",
            &[&fx.ev_s1.to_string()]
        ),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t1"),
        "{}",
        dry.show()
    );
    let r = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        None,
        Some("1"),
        PRIVATE,
    )
    .await;
    assert_eq!(r.code, 3, "{}", r.show());
    assert_eq!(
        tenancy(&pool, "workflows", fx.w_b0).await,
        (fx.target, "group".to_string())
    );
    for w in [fx.w_a0, fx.w_a1] {
        assert_eq!(
            tenancy(&pool, "workflows", w).await,
            (fx.src, "group".to_string())
        );
    }
    assert_eq!(
        tenancy(&pool, "evidence", fx.ev_s1).await,
        (fx.stranger_group, "group".to_string())
    );
    let rev = reverse(&pool, &m, true).await;
    assert_eq!(rev.code, 0, "{}", rev.show());
    assert_eq!(snapshot(&pool).await, before);
    std::fs::remove_dir_all(&dir).ok();
}

/// Where a sealed row sits on alpha's plan.
#[derive(Clone, Copy, Debug)]
enum Seal {
    /// `claim_encryption` on the step S2.
    Claim,
    /// `evidence_encryption` on S1's evidence.
    Evidence,
    /// `edge_encryption` on the plan edge P -> S2.
    Edge,
    /// `claim_version_encryption` on a version of S2.
    ClaimVersion,
}

/// Seal one row of alpha's plan under the source's key epoch 0; returns the
/// id the hold must name and the (table, row) whose tuple must not change.
async fn seal(pool: &PgPool, fx: &Fx, how: Seal) -> (Uuid, &'static str, Uuid) {
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(fx.src)
    .execute(pool)
    .await
    .expect("the source's key epoch");
    match how {
        Seal::Claim => {
            sqlx::query(
                "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                               encrypted_content) \
                 VALUES ($1, $2, 0, 'fully_private', ''::bytea)",
            )
            .bind(fx.s2)
            .bind(fx.src)
            .execute(pool)
            .await
            .expect("seal S2");
            (fx.s2, "claims", fx.s2)
        }
        Seal::Evidence => {
            sqlx::query(
                "INSERT INTO evidence_encryption (evidence_id, group_id, epoch, privacy_tier, \
                                                  encrypted_content) \
                 VALUES ($1, $2, 0, 'fully_private', ''::bytea)",
            )
            .bind(fx.ev_s1)
            .bind(fx.src)
            .execute(pool)
            .await
            .expect("seal S1's evidence");
            (fx.ev_s1, "evidence", fx.ev_s1)
        }
        Seal::Edge => {
            let e = fx.plan_edges[2];
            sqlx::query(
                "INSERT INTO edge_encryption (edge_id, group_id, epoch, privacy_tier, \
                                              encrypted_labels) \
                 VALUES ($1, $2, 0, 'fully_private', ''::bytea)",
            )
            .bind(e)
            .bind(fx.src)
            .execute(pool)
            .await
            .expect("seal the edge P -> S2");
            (e, "edges", e)
        }
        Seal::ClaimVersion => {
            let v: Uuid = sqlx::query_scalar(
                "INSERT INTO claim_versions (claim_id, version_number, content, truth_value) \
                 VALUES ($1, 1, 'alpha step two, version 1', 0.7) RETURNING id",
            )
            .bind(fx.s2)
            .fetch_one(pool)
            .await
            .expect("a version of S2");
            sqlx::query(
                "INSERT INTO claim_version_encryption (claim_version_id, claim_id, group_id, \
                                                       epoch, encrypted_content) \
                 VALUES ($1, $2, $3, 0, ''::bytea)",
            )
            .bind(v)
            .bind(fx.s2)
            .bind(fx.src)
            .execute(pool)
            .await
            .expect("seal S2's version");
            (fx.s2, "claims", fx.s2)
        }
    }
}

/// A sealed row on a moving plan: its ciphertext is keyed to the SOURCE, and
/// the move would not re-key it, so the target's members would get rows they
/// cannot decrypt (and the reversal would refuse it for good). The dry run
/// HOLDS the lineage and names the sealed row; nothing of alpha moves, an
/// `--apply` with the dry run's count moves beta only and exits 3, and the
/// reversal restores every row exactly.
async fn a_private_move_holds_a_sealed(pool: PgPool, how: Seal) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    narrowed(&pool, &fx, &dir).await;
    let (named, table, row) = seal(&pool, &fx, how).await;
    let private = (fx.src, "group".to_string());
    assert_eq!(tenancy(&pool, table, row).await, private, "{how:?}");
    let before = snapshot(&pool).await;
    let m = dir.join("private.jsonl");
    let dry = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        None,
        None,
        PRIVATE,
    )
    .await;
    assert_eq!(dry.code, 0, "{how:?}: {}", dry.show());
    assert!(
        line_with(
            &dry.stdout,
            "HELD-LINEAGE\talpha\t",
            &[&named.to_string(), "sealed"]
        ),
        "{how:?}: {}",
        dry.show()
    );
    assert!(
        dry.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t1"),
        "{how:?}: {}",
        dry.show()
    );
    assert_eq!(snapshot(&pool).await, before, "a dry run writes nothing");
    let r = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        None,
        Some("1"),
        PRIVATE,
    )
    .await;
    assert_eq!(r.code, 3, "{how:?}: {}", r.show());
    assert!(
        line_with(&r.stdout, "SHORTFALL\theld\talpha", &[]),
        "{how:?}: {}",
        r.show()
    );
    for w in [fx.w_a0, fx.w_a1] {
        assert_eq!(tenancy(&pool, "workflows", w).await, private, "{how:?}");
    }
    assert_eq!(tenancy(&pool, table, row).await, private, "{how:?}");
    assert_eq!(
        tenancy(&pool, "workflows", fx.w_b0).await,
        (fx.target, "group".to_string())
    );
    let rev = reverse(&pool, &m, true).await;
    assert_eq!(rev.code, 0, "{how:?}: {}", rev.show());
    assert_eq!(snapshot(&pool).await, before, "{how:?}");
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_holds_a_lineage_with_a_sealed_plan_claim(pool: PgPool) {
    a_private_move_holds_a_sealed(pool, Seal::Claim).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_holds_a_lineage_with_sealed_evidence(pool: PgPool) {
    a_private_move_holds_a_sealed(pool, Seal::Evidence).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_holds_a_lineage_with_a_sealed_plan_edge(pool: PgPool) {
    a_private_move_holds_a_sealed(pool, Seal::Edge).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_holds_a_lineage_with_a_sealed_claim_version(pool: PgPool) {
    a_private_move_holds_a_sealed(pool, Seal::ClaimVersion).await;
}

/// A row sealed under the TARGET's key after a private move cannot go back
/// to the source: the reversal refuses the whole manifest, naming the row,
/// and writes nothing. A sealed plan edge and a sealed claim version are
/// held as a sealed claim and sealed evidence are. (The version exists
/// before the move, so the run records it and only its seal is new.)
async fn a_private_move_reversal_refuses_a_row_sealed_since(pool: PgPool, how: Seal) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    narrowed(&pool, &fx, &dir).await;
    let version: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value) \
         VALUES ($1, 1, 'alpha step two, version 1', 0.7) RETURNING id",
    )
    .bind(fx.s2)
    .fetch_one(&pool)
    .await
    .expect("a version of S2");
    let m = dir.join("private.jsonl");
    let r = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        None,
        Some("3"),
        PRIVATE,
    )
    .await;
    assert_eq!(r.code, 0, "{how:?}: {}", r.show());
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(fx.target)
    .execute(&pool)
    .await
    .expect("the target's key epoch");
    let named = match how {
        Seal::Edge => {
            let e = fx.plan_edges[2];
            sqlx::query(
                "INSERT INTO edge_encryption (edge_id, group_id, epoch, privacy_tier, \
                                              encrypted_labels) \
                 VALUES ($1, $2, 0, 'fully_private', ''::bytea)",
            )
            .bind(e)
            .bind(fx.target)
            .execute(&pool)
            .await
            .expect("seal the moved edge P -> S2");
            e
        }
        Seal::ClaimVersion => {
            assert_eq!(
                tenancy(&pool, "claim_versions", version).await,
                (fx.target, "group".to_string()),
                "the version moved with S2"
            );
            sqlx::query(
                "INSERT INTO claim_version_encryption (claim_version_id, claim_id, group_id, \
                                                       epoch, encrypted_content) \
                 VALUES ($1, $2, $3, 0, ''::bytea)",
            )
            .bind(version)
            .bind(fx.s2)
            .bind(fx.target)
            .execute(&pool)
            .await
            .expect("seal S2's version");
            fx.s2
        }
        other => panic!("{other:?}: covered by the claim and evidence reversal checks"),
    };
    let sealed = snapshot(&pool).await;
    let rev = reverse(&pool, &m, true).await;
    assert_eq!(rev.code, 3, "{how:?}: {}", rev.show());
    assert!(
        rev.stdout
            .lines()
            .any(|l| l.contains(&named.to_string()) && l.contains("sealed since the run")),
        "{how:?}: {}",
        rev.show()
    );
    assert_eq!(
        snapshot(&pool).await,
        sealed,
        "a refused reversal writes nothing"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_reversal_refuses_an_edge_sealed_since(pool: PgPool) {
    a_private_move_reversal_refuses_a_row_sealed_since(pool, Seal::Edge).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_reversal_refuses_a_claim_version_sealed_since(pool: PgPool) {
    a_private_move_reversal_refuses_a_row_sealed_since(pool, Seal::ClaimVersion).await;
}

/// A private lineage `name`, one generation executing one claim, both
/// `('group', g)`, written on the maintenance pool. Returns (workflow, claim).
async fn private_lineage(pool: &PgPool, author: Uuid, g: Uuid, name: &str) -> (Uuid, Uuid) {
    let mut m = pool.acquire().await.expect("acquire");
    let w = workflow(&mut m, name, 0, None, g, "group").await;
    let c = claim(&mut m, author, g, "group", 0, &format!("{name} thesis")).await;
    edge(&mut m, (w, "workflow"), (c, "claim"), "executes").await;
    (w, c)
}

async fn make_admin(pool: &PgPool, g: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(g)
    .bind(agent)
    .execute(pool)
    .await
    .expect("make the operator an admin");
}

/// A private move takes rows only out of an active team or community group
/// the operator administers, or out of the operator's OWN personal group:
/// another person's personal group and an operated agent's are refused as
/// `--from-group` even though the operator administers both (so the refusal
/// comes from the kind, not the admin check), and nothing is written. The
/// operator's own personal group named explicitly is accepted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_refuses_another_persons_or_an_agents_personal_group_as_source(
    pool: PgPool,
) {
    let fx = seed(&pool).await;
    let (person, person_group) = fixture::seed_human_operator(&pool, "another person").await;
    make_admin(&pool, person_group, fx.operator).await;
    let (agent, agent_group) = fixture::seed_agent_with_group(&pool, "operated agent").await;
    sqlx::query("SELECT * FROM epigraph_link_operator($1, $2)")
        .bind(agent)
        .bind(fx.operator)
        .execute(&pool)
        .await
        .expect("link the agent to the operator");
    make_admin(&pool, agent_group, fx.operator).await;
    private_lineage(&pool, person, person_group, "zeta-person").await;
    private_lineage(&pool, agent, agent_group, "zeta-agent").await;
    let dir = scratch_dir();
    let before = snapshot(&pool).await;
    for (i, (g, name)) in [(person_group, "zeta-person"), (agent_group, "zeta-agent")]
        .into_iter()
        .enumerate()
    {
        let m = dir.join(format!("m{i}.jsonl"));
        let r = run_names(
            &pool,
            &fx,
            &dir,
            &m,
            &[name],
            fx.target,
            Some(g),
            Some("1"),
            PRIVATE,
        )
        .await;
        assert_eq!(r.code, 1, "case {i}: {}", r.show());
        assert!(
            r.stderr.contains("--from-group")
                && r.stderr.contains("not the operator's own personal group"),
            "case {i}: {}",
            r.show()
        );
        assert!(!m.exists(), "case {i}");
    }
    assert_eq!(snapshot(&pool).await, before, "nothing is written");
    // The operated agent as --operator, with no --from-group: the default
    // source is the agent's own personal group, which is not a registered
    // human operator's own group, so it is refused just the same.
    make_admin(&pool, fx.target, agent).await;
    let before = snapshot(&pool).await;
    let file = names_file(&dir, &["zeta-agent"]);
    let m = dir.join("agent.jsonl");
    let (target, agent_s) = (fx.target.to_string(), agent.to_string());
    let mut args = vec![
        "reown-workflows",
        "--canonical-names-file",
        file.to_str().unwrap(),
        "--target-group",
        &target,
        "--operator",
        &agent_s,
        "--manifest-out",
        m.to_str().unwrap(),
        "--apply",
        "--confirm-count",
        "1",
        "--ruling",
        RULING,
        "--reason",
        "an operated agent moving its own group's private rows",
    ];
    args.extend(PRIVATE.iter().copied());
    let r = run_op(&pool, &args).await;
    assert_eq!(r.code, 1, "default source: {}", r.show());
    assert!(
        r.stderr.contains("not the operator's own personal group"),
        "default source: {}",
        r.show()
    );
    assert!(!m.exists());
    assert_eq!(snapshot(&pool).await, before, "nothing is written");
    // The operator's own personal group, named explicitly, is a source.
    narrowed(&pool, &fx, &dir).await;
    let m = dir.join("own.jsonl");
    let dry = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        Some(fx.src),
        None,
        PRIVATE,
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t3"),
        "{}",
        dry.show()
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The hand-off rule lets a private row change hands only when the SOURCE (or
/// the target) owns it. A third group's private claim K with an edge to the
/// moving step S1: the edge is K's group's, co-owned by the source, and the
/// move would make it (K's group, co-owner target), a tuple that still
/// requires every group the old one did with the source replaced by the
/// target. Only the source-owner guard holds it, since the owner is K's group:
/// the lineage is HELD naming the edge, and the edge is untouched.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_holds_a_third_groups_edge_even_when_its_image_is_kept(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    narrowed(&pool, &fx, &dir).await;
    let e = {
        let mut m = pool.acquire().await.expect("acquire");
        let k = claim(
            &mut m,
            fx.operator,
            fx.stranger_group,
            "group",
            0,
            "a third group's note",
        )
        .await;
        edge(&mut m, (k, "claim"), (fx.s1, "claim"), "supports").await
    };
    let prior = (fx.stranger_group, "group".to_string(), Some(fx.src));
    assert_eq!(edge_tenancy(&pool, e).await, prior, "the trigger's meet");
    let before = snapshot(&pool).await;
    let m = dir.join("private.jsonl");
    let dry = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        None,
        None,
        PRIVATE,
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        line_with(&dry.stdout, "HELD-LINEAGE\talpha\t", &[&e.to_string()]),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t1"),
        "{}",
        dry.show()
    );
    let r = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        None,
        Some("1"),
        PRIVATE,
    )
    .await;
    assert_eq!(r.code, 3, "{}", r.show());
    assert_eq!(edge_tenancy(&pool, e).await, prior);
    for w in [fx.w_a0, fx.w_a1] {
        assert_eq!(
            tenancy(&pool, "workflows", w).await,
            (fx.src, "group".to_string())
        );
    }
    let rev = reverse(&pool, &m, true).await;
    assert_eq!(rev.code, 0, "{}", rev.show());
    assert_eq!(snapshot(&pool).await, before);
    std::fs::remove_dir_all(&dir).ok();
}

/// Public input is reown-workflows' public act, never a private move's: a
/// public lineage is HELD (`public`), and so is a private lineage whose
/// unshared plan claim is public (the plan would split). Nothing is written,
/// and an `--apply` with the dry run's count exits 3 on the claim hold.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_refuses_public_input(pool: PgPool) {
    let fx = seed(&pool).await;
    let pubc = {
        let mut m = pool.acquire().await.expect("acquire");
        let w = workflow(&mut m, "zeta", 0, None, fx.src, "group").await;
        let c = claim(&mut m, fx.operator, fx.src, "public", 0, "zeta thesis").await;
        edge(&mut m, (w, "workflow"), (c, "claim"), "executes").await;
        c
    };
    let dir = scratch_dir();
    let before = snapshot(&pool).await;
    let m = dir.join("private.jsonl");
    let dry = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "zeta"],
        fx.target,
        None,
        None,
        PRIVATE,
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        line_with(&dry.stdout, "HELD-LINEAGE\talpha\t", &["public"]),
        "{}",
        dry.show()
    );
    assert!(
        line_with(
            &dry.stdout,
            "HELD-LINEAGE\tzeta\t",
            &[&pubc.to_string(), "public"]
        ),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t0"),
        "{}",
        dry.show()
    );
    let r = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "zeta"],
        fx.target,
        None,
        Some("0"),
        PRIVATE,
    )
    .await;
    assert_eq!(r.code, 3, "{}", r.show());
    assert_eq!(snapshot(&pool).await, before, "nothing is written");
    assert!(!m.exists());
    std::fs::remove_dir_all(&dir).ok();
}

/// `--confirm-count` must repeat the dry run's count: a mismatch is refused
/// before any write, with no manifest and no audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_refuses_a_confirm_count_mismatch(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    narrowed(&pool, &fx, &dir).await;
    let before = snapshot(&pool).await;
    let audits = security_events(&pool, "operator.workflows_reowned").await;
    let m = dir.join("private.jsonl");
    let r = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        None,
        Some("2"),
        PRIVATE,
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("does not match"), "{}", r.show());
    assert_eq!(snapshot(&pool).await, before);
    assert!(!m.exists());
    assert_eq!(
        security_events(&pool, "operator.workflows_reowned").await,
        audits
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The targets and flags a private move refuses before writing: another
/// person's personal group (even administered by the operator), a team the
/// operator only writes, the source itself, and the flag combinations that do
/// not describe a private move.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_refuses_bad_targets_and_flags(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    narrowed(&pool, &fx, &dir).await;
    let before = snapshot(&pool).await;
    let catch_up: Vec<&str> = PRIVATE.iter().copied().chain(["--catch-up"]).collect();
    let cases: Vec<(Uuid, &[&str], &str)> = vec![
        (
            fx.stranger_group,
            PRIVATE,
            "not the operator's own personal group",
        ),
        (fx.not_admin_team, PRIVATE, "not a live admin"),
        (fx.src, PRIVATE, "moves between two groups"),
        (
            fx.target,
            &["--from-visibility", "group"],
            "--from-visibility group needs --visibility group",
        ),
        (fx.target, &catch_up, "--catch-up"),
        (
            fx.target,
            &["--from-visibility", "private", "--visibility", "group"],
            "--from-visibility must be public or group",
        ),
    ];
    for (i, (target, extra, needle)) in cases.into_iter().enumerate() {
        let m = dir.join(format!("m{i}.jsonl"));
        let r = run_names(
            &pool,
            &fx,
            &dir,
            &m,
            &["alpha"],
            target,
            None,
            Some("2"),
            extra,
        )
        .await;
        assert_eq!(r.code, 1, "case {i}: {}", r.show());
        assert!(r.stderr.contains(needle), "case {i}: {}", r.show());
        assert!(!m.exists());
    }
    assert_eq!(snapshot(&pool).await, before);
    std::fs::remove_dir_all(&dir).ok();
}

/// An edge from a plan claim to a frame that is private to the SOURCE and
/// does not move: the cascade counts the frame as public, so moving the step
/// would put the edge in the target while it names a frame the target's
/// members cannot read. The lineage is HELD (the edge is named) and nothing
/// of it moves. A PUBLIC frame contributes nothing, so its edge moves with
/// the plan.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_move_holds_a_lineage_with_an_edge_to_a_private_node_that_stays(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    narrowed(&pool, &fx, &dir).await;
    let frame = |owner: Uuid, visibility: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO frames (name, hypotheses, owner_group_id, visibility) \
                 VALUES ('frame-' || gen_random_uuid()::text, ARRAY['a','b'], $1, $2) \
                 RETURNING id",
            )
            .bind(owner)
            .bind(visibility)
            .fetch_one(&pool)
            .await
            .expect("seed frame")
        }
    };
    let link = |a: Uuid, f: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
                 VALUES ($1, 'claim', $2, 'frame', 'relates_to') RETURNING id",
            )
            .bind(a)
            .bind(f)
            .fetch_one(&pool)
            .await
            .expect("seed claim -> frame edge")
        }
    };
    let private_frame = frame(fx.src, "group").await;
    let public_frame = frame(WORLD, "public").await;
    let e_private = link(fx.s1, private_frame).await;
    let e_public = link(fx.tb, public_frame).await;
    let before = snapshot(&pool).await;
    let m = dir.join("private.jsonl");
    let dry = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        None,
        None,
        PRIVATE,
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        line_with(
            &dry.stdout,
            "HELD-LINEAGE\talpha\t",
            &[&e_private.to_string(), "group-private node"]
        ),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout.contains("ELIGIBLE-WORKFLOW-ROWS\t1"),
        "{}",
        dry.show()
    );
    assert_eq!(snapshot(&pool).await, before);
    let r = run_names(
        &pool,
        &fx,
        &dir,
        &m,
        &["alpha", "beta"],
        fx.target,
        None,
        Some("1"),
        PRIVATE,
    )
    .await;
    assert_eq!(r.code, 3, "{}", r.show());
    assert_eq!(
        tenancy(&pool, "claims", fx.s1).await,
        (fx.src, "group".to_string())
    );
    assert_eq!(
        edge_tenancy(&pool, e_private).await,
        (fx.src, "group".to_string(), None)
    );
    assert_eq!(
        edge_tenancy(&pool, e_public).await,
        (fx.target, "group".to_string(), None),
        "beta's edge to a public frame moves with beta"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The operator sequence for legacy claims a team holds (operator ruling,
/// 2026-11-12): alpha's thesis supersedes a legacy flat workflow claim L that
/// is group-private in a science team. Narrowing alpha in place in the
/// operator's personal group would hand the team's private edge to the
/// operator's group, so the narrowing HOLDS alpha (exit 3). `regroup-claims`
/// moves L into the operator's OWN personal group; the same narrowing then
/// takes alpha whole, and the edge ends private to the operator's group.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_claim_regrouped_into_the_personal_group_lets_its_superseder_narrow(pool: PgPool) {
    let fx = seed(&pool).await;
    let science = team_group(&pool, "science team", fx.operator, "admin").await;
    let (legacy, e_sup) = {
        let mut m = pool.acquire().await.expect("acquire");
        let l = claim(
            &mut m,
            fx.operator,
            science,
            "group",
            0,
            "a legacy flat workflow",
        )
        .await;
        let e = edge(&mut m, (fx.t, "claim"), (l, "claim"), "supersedes").await;
        (l, e)
    };
    assert_eq!(
        edge_tenancy(&pool, e_sup).await,
        (science, "group".to_string(), None)
    );
    let dir = scratch_dir();
    let held = run_names(
        &pool,
        &fx,
        &dir,
        &dir.join("narrow-held.jsonl"),
        &["alpha"],
        fx.src,
        None,
        Some("0"),
        GROUP,
    )
    .await;
    assert_eq!(held.code, 3, "{}", held.show());
    assert!(
        line_with(&held.stdout, "HELD-LINEAGE\talpha\t", &[&e_sup.to_string()]),
        "{}",
        held.show()
    );

    let ids = dir.join("legacy.txt");
    std::fs::write(&ids, format!("{legacy}\n")).expect("ids file");
    let (science_s, src_s, op_s) = (
        science.to_string(),
        fx.src.to_string(),
        fx.operator.to_string(),
    );
    let regroup_manifest = dir.join("regroup.jsonl");
    let rg = run_op(
        &pool,
        &[
            "regroup-claims",
            "--claims-file",
            ids.to_str().unwrap(),
            "--source-group",
            &science_s,
            "--target-group",
            &src_s,
            "--operator",
            &op_s,
            "--manifest-out",
            regroup_manifest.to_str().unwrap(),
            "--apply",
            "--confirm-count",
            "1",
            "--ruling",
            RULING,
            "--reason",
            "the legacy claims go private to the operator",
        ],
    )
    .await;
    assert_eq!(rg.code, 0, "{}", rg.show());
    assert_eq!(
        tenancy(&pool, "claims", legacy).await,
        (fx.src, "group".to_string())
    );

    let narrow = run_names(
        &pool,
        &fx,
        &dir,
        &dir.join("narrow.jsonl"),
        &["alpha"],
        fx.src,
        None,
        Some("2"),
        GROUP,
    )
    .await;
    assert_eq!(narrow.code, 0, "{}", narrow.show());
    for w in [fx.w_a0, fx.w_a1] {
        assert_eq!(
            tenancy(&pool, "workflows", w).await,
            (fx.src, "group".to_string())
        );
    }
    assert_eq!(
        edge_tenancy(&pool, e_sup).await,
        (fx.src, "group".to_string(), None)
    );
    std::fs::remove_dir_all(&dir).ok();
}
