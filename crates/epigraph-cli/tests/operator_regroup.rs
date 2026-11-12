//! `epigraph-operator regroup-claims` and its reversal through
//! `reown-reverse`, driven through the real binary against a `#[sqlx::test]`
//! database migrated 001 -> head.
//!
//! # The fixture
//!
//! Two team groups, SRC and DST, both administered by a registered human
//! operator, and a third group H that is not part of the act.
//!
//! * A: `('group', SRC)`, self-contained: its evidence, a reasoning trace, a
//!   BBA, a claim version, a frame assignment and a harvester fragment it is
//!   the only provenance of. Everything it carries moves with it.
//! * B: `('group', SRC)`, linked to S (`('group', SRC)`, NOT listed, so it
//!   stays) by a claim edge and by an evidence edge (B's evidence -> S's
//!   evidence), to a public claim P, and from a group-private workflow in SRC
//!   (`executes`). B moves; the edges to S become co-owned `(DST, group,
//!   co-owner SRC)`, readable only by a member of both, and so does the edge
//!   from the workflow, which the tool meets with the workflow's own tuple
//!   (`(SRC, group, co-owner DST)`) where the trigger would count it public.
//! * The holds: N is `('group', H)` (not the source's); Q is sealed; R carries
//!   an evidence row owned by H; V carries a PUBLIC evidence row; W carries
//!   PINNED evidence; E carries an edge to P DECLARED co-owned by H (the move's
//!   meet would drop H); U is a public claim (refused input).
//!
//! # What a snapshot is
//!
//! Every row of every table the run could reach, plus the control tables, as
//! `to_jsonb(row)::text`, sorted. `claims.updated_at` is stripped only in the
//! comparisons that span an apply (migration 001's trigger stamps it, and no
//! tool can put it back). `security_events` is compared on its own.

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
const RULING: &str = "test ruling: regroup between two team groups";

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
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, &url);
    let out = cmd.output().expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn scratch_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("operator-regroup-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

fn h32(seed: Uuid) -> Vec<u8> {
    seed.as_bytes().iter().copied().cycle().take(32).collect()
}

async fn exec(pool: &PgPool, sql: &str, ids: &[Uuid]) {
    let mut q = sqlx::query(sql);
    for id in ids {
        q = q.bind(*id);
    }
    q.execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct Fx {
    operator: Uuid,
    operator_group: Uuid,
    src: Uuid,
    dst: Uuid,
    h_group: Uuid,
    frame: Uuid,
    a: Uuid,
    ev_a: Uuid,
    trace_a: Uuid,
    mf_a: Uuid,
    cv_a: Uuid,
    frag_a: Uuid,
    b: Uuid,
    ev_b: Uuid,
    s: Uuid,
    ev_s: Uuid,
    p: Uuid,
    e_bs: Uuid,
    e_bp: Uuid,
    e_ev_bs: Uuid,
    wf: Uuid,
    e_wf_b: Uuid,
    n: Uuid,
    q: Uuid,
    r: Uuid,
    ev_r_h: Uuid,
    v: Uuid,
    w: Uuid,
    e: Uuid,
    e_ep_declared: Uuid,
    u: Uuid,
}

async fn team_group(pool: &PgPool, label: &str, admin: Uuid) -> Uuid {
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
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(g)
    .bind(admin)
    .execute(pool)
    .await
    .expect("seed team membership");
    g
}

/// Make `agent` a live admin of `group` (a row the fixture adds directly).
async fn admin_of(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed admin membership");
}

async fn evidence(pool: &PgPool, claim: Uuid, text: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, $2, 'document', $3, $4)",
    )
    .bind(id)
    .bind(claim)
    .bind(h32(id))
    .bind(text)
    .execute(pool)
    .await
    .expect("seed evidence");
    id
}

/// An edge between two evidence rows, forced to `(owner, 'group')`.
async fn evidence_edge(pool: &PgPool, from: Uuid, to: Uuid, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'evidence', $3, 'evidence', 'supports')",
    )
    .bind(id)
    .bind(from)
    .bind(to)
    .execute(pool)
    .await
    .expect("seed evidence edge");
    exec(
        pool,
        "UPDATE edges SET owner_group_id = $2, visibility = 'group', co_owner_group_id = NULL \
          WHERE id = $1",
        &[id, owner],
    )
    .await;
    id
}

async fn seed(pool: &PgPool) -> Fx {
    let (operator, operator_group) = fixture::seed_human_operator(pool, "operator").await;
    let (h_agent, h_group) = fixture::seed_agent_with_group(pool, "h").await;
    let src = team_group(pool, "SRC team", operator).await;
    let dst = team_group(pool, "DST team", operator).await;
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active')")
        .bind(src)
        .execute(pool)
        .await
        .expect("seed SRC key epoch");

    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, owner_group_id, visibility) \
         VALUES ('regroup-frame', ARRAY['a','b'], $1, 'public') RETURNING id",
    )
    .bind(WORLD)
    .fetch_one(pool)
    .await
    .expect("seed frame");

    let gc = |content: &'static str| fixture::seed_group_claim(pool, operator, src, content);
    let a = gc("A: SRC, self-contained, moves").await;
    let b = gc("B: SRC, linked to S, moves").await;
    let s = gc("S: SRC, not listed, stays").await;
    let q = gc("Q: SRC, sealed").await;
    let r = gc("R: SRC, carries H's evidence").await;
    let v = gc("V: SRC, carries a public evidence row").await;
    let w = gc("W: SRC, carries pinned evidence").await;
    let e = gc("E: SRC, carries an edge declared co-owned by H").await;
    let n = fixture::seed_group_claim(pool, h_agent, h_group, "N: H's claim").await;
    let p = fixture::seed_public_claim(pool, operator, "P: public").await;
    let u = fixture::seed_public_claim(pool, operator, "U: public, listed").await;

    // A's own rows.
    let ev_a = evidence(pool, a, "A's evidence").await;
    let trace_a = fixture::seed_reasoning_trace(pool, a, "deductive").await;
    let mf_a: Uuid = sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"a\": 1.0}') RETURNING id",
    )
    .bind(a)
    .bind(frame)
    .bind(operator)
    .fetch_one(pool)
    .await
    .expect("seed mass function");
    let cv_a: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, created_by) \
         VALUES ($1, 1, 'v1', 0.5, $2) RETURNING id",
    )
    .bind(a)
    .bind(operator)
    .fetch_one(pool)
    .await
    .expect("seed claim version");
    exec(
        pool,
        "INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2)",
        &[a, frame],
    )
    .await;
    let source: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_sources (content_hash, modality) VALUES ($1, 'text') RETURNING id",
    )
    .bind(h32(Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed harvester source");
    let frag_a: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_fragments (source_id, content_hash, content_text, owner_group_id, \
                                          visibility) \
         VALUES ($1, $2, 'A fragment', $3, 'group') RETURNING id",
    )
    .bind(source)
    .bind(h32(Uuid::new_v4()))
    .bind(src)
    .fetch_one(pool)
    .await
    .expect("seed fragment");
    exec(
        pool,
        "INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)",
        &[a, frag_a],
    )
    .await;

    // B, S, P and their edges.
    let ev_b = evidence(pool, b, "B's evidence").await;
    let ev_s = evidence(pool, s, "S's evidence").await;
    let e_bs = fixture::seed_edge(pool, b, s).await;
    let e_bp = fixture::seed_edge(pool, b, p).await;
    let e_ev_bs = evidence_edge(pool, ev_b, ev_s, src).await;
    // A group-private workflow in SRC that executes B. The edges arm (and
    // `epigraph_node_tenancy`) count a workflow endpoint as public, so the
    // trigger stamps B's tuple, (SRC, group). Once B moves, the tool writes
    // the exact meet, (SRC, group, co-owner DST); the workflow row itself is a
    // node and is not touched.
    let wf = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, owner_group_id, visibility) \
         VALUES ($1, 'regroup-fixture-wf', 0, 'goal', $2, 'group')",
    )
    .bind(wf)
    .bind(src)
    .execute(pool)
    .await
    .expect("seed workflow");
    let e_wf_b = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'workflow', $3, 'claim', 'executes')",
    )
    .bind(e_wf_b)
    .bind(wf)
    .bind(b)
    .execute(pool)
    .await
    .expect("seed executes edge");

    // The holds.
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', ''::bytea)",
    )
    .bind(q)
    .bind(src)
    .execute(pool)
    .await
    .expect("seal Q");
    let ev_r_h = evidence(pool, r, "H's evidence on R").await;
    let ev_v = evidence(pool, v, "a public evidence row on V").await;
    let ev_w = evidence(pool, w, "pinned evidence on W").await;
    // E -> P (public), DECLARED narrower than its meet: co-owned by H. The
    // move's meet would be (DST, group), dropping H.
    let e_ep_declared = fixture::seed_edge(pool, e, p).await;
    exec(
        pool,
        "UPDATE edges SET owner_group_id = $2, visibility = 'group', co_owner_group_id = $3 \
          WHERE id = $1",
        &[e_ep_declared, src, h_group],
    )
    .await;
    // LAST: 070's insert arm re-syncs a table's rows to their claim on each
    // new insert for that claim.
    exec(
        pool,
        "UPDATE evidence SET owner_group_id = $2 WHERE id = $1",
        &[ev_r_h, h_group],
    )
    .await;
    exec(
        pool,
        "UPDATE evidence SET owner_group_id = $2, visibility = 'public' WHERE id = $1",
        &[ev_v, WORLD],
    )
    .await;
    exec(
        pool,
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'regroup fixture pin')",
        &[ev_w, operator],
    )
    .await;

    Fx {
        operator,
        operator_group,
        src,
        dst,
        h_group,
        frame,
        a,
        ev_a,
        trace_a,
        mf_a,
        cv_a,
        frag_a,
        b,
        ev_b,
        s,
        ev_s,
        p,
        e_bs,
        e_bp,
        e_ev_bs,
        wf,
        e_wf_b,
        n,
        q,
        r,
        ev_r_h,
        v,
        w,
        e,
        e_ep_declared,
        u,
    }
}

fn ids_file(dir: &Path, name: &str, ids: &[Uuid]) -> PathBuf {
    let p = dir.join(name);
    let body: Vec<String> = ids.iter().map(ToString::to_string).collect();
    std::fs::write(&p, format!("# regroup fixture\n{}\n", body.join("\n"))).expect("ids file");
    p
}

const SNAP_TABLES: &[&str] = &[
    "claims",
    "evidence",
    "reasoning_traces",
    "mass_functions",
    "claim_versions",
    "challenges",
    "claim_frames",
    "triples",
    "entity_mentions",
    "ds_combined_beliefs",
    "ds_bayesian_divergence",
    "harvester_claim_provenance",
    "experiment_triples",
    "experiment_entity_mentions",
    "claim_clusters",
    "claim_cluster_membership",
    "claim_neighborhood_membership",
    "claim_signature_revocations",
    "harvester_fragments",
    "harvester_sources",
    "edges",
    "factors",
    "evidence_visibility_pins",
    "claim_encryption",
    "workflows",
    "groups",
    "group_memberships",
    "agents",
    "frames",
];

async fn snapshot(pool: &PgPool, strip_updated_at: bool) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for t in SNAP_TABLES {
        let expr = if *t == "claims" && strip_updated_at {
            "(to_jsonb(t) - 'updated_at')::text"
        } else {
            "to_jsonb(t)::text"
        };
        let sql = format!("SELECT {expr} FROM {t} t ORDER BY 1");
        let rows: Vec<String> = sqlx::query_scalar(&sql)
            .fetch_all(pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
        out.insert((*t).to_string(), rows);
    }
    out
}

fn assert_same(a: &BTreeMap<String, Vec<String>>, b: &BTreeMap<String, Vec<String>>, what: &str) {
    for (t, rows) in a {
        let other = &b[t];
        if rows != other {
            let gone: Vec<_> = rows.iter().filter(|r| !other.contains(r)).collect();
            let new: Vec<_> = other.iter().filter(|r| !rows.contains(r)).collect();
            panic!("{what}: table {t} differs\n  before-only: {gone:#?}\n  after-only: {new:#?}");
        }
    }
}

async fn audit_rows(pool: &PgPool) -> Vec<(String, Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT event_type::text, agent_id, details FROM security_events \
          WHERE event_type LIKE 'privatization.cli_regroup%' ORDER BY created_at, event_type",
    )
    .fetch_all(pool)
    .await
    .expect("read security_events")
}

/// `(owner, visibility, co_owner)` of an edge.
async fn edge(pool: &PgPool, id: Uuid) -> (Uuid, String, Option<Uuid>) {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("edge")
}

/// `(owner, visibility)` of a row by id.
async fn row(pool: &PgPool, table: &str, id: Uuid) -> (Uuid, String) {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, visibility::text FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} {id}: {e}"))
}

fn grp(g: Uuid) -> (Uuid, String) {
    (g, "group".into())
}

/// The ids among `ids` of `table` an `epigraph_app` session whose read set is
/// exactly `groups` can read (the tenancy policies read `epigraph.group_ids`).
async fn reads_as(pool: &PgPool, groups: &[Uuid], table: &str, ids: &[Uuid]) -> Vec<Uuid> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *tx)
        .await
        .expect("become epigraph_app");
    let csv = groups
        .iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, true), \
                set_config('epigraph.writable_group_ids', '', true), \
                set_config('epigraph.principal_id', '', true)",
    )
    .bind(csv)
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

struct Regroup<'a> {
    ids: &'a Path,
    src: Uuid,
    dst: Uuid,
    operator: Uuid,
    manifest: &'a Path,
    apply_count: Option<usize>,
    extra: &'a [&'a str],
}

async fn regroup(pool: &PgPool, r: Regroup<'_>) -> Run {
    let src = r.src.to_string();
    let dst = r.dst.to_string();
    let op = r.operator.to_string();
    let count = r.apply_count.map(|n| n.to_string());
    let mut args = vec![
        "regroup-claims",
        "--claims-file",
        r.ids.to_str().unwrap(),
        "--source-group",
        &src,
        "--target-group",
        &dst,
        "--operator",
        &op,
        "--manifest-out",
        r.manifest.to_str().unwrap(),
    ];
    if let Some(c) = count.as_deref() {
        args.extend([
            "--apply",
            "--confirm-count",
            c,
            "--ruling",
            RULING,
            "--reason",
            "test",
        ]);
    }
    args.extend_from_slice(r.extra);
    run_op(pool, &args).await
}

async fn reverse(pool: &PgPool, manifests: &[&Path], extra: &[&str], apply: bool) -> Run {
    let mut args = vec!["reown-reverse"];
    for m in manifests {
        args.push("--manifest");
        args.push(m.to_str().unwrap());
    }
    args.extend_from_slice(extra);
    if apply {
        args.push("--apply");
    }
    run_op(pool, &args).await
}

fn has_line(stdout: &str, prefix: &str, needles: &[&str]) -> bool {
    stdout
        .lines()
        .any(|l| l.starts_with(prefix) && needles.iter().all(|n| l.contains(n)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Dry run
// ─────────────────────────────────────────────────────────────────────────────

/// A dry run executes every batch and rolls it back: every row is
/// byte-identical afterwards, no manifest and no audit row exist. The plan's
/// eligible count already excludes the row-level holds, every hold names its
/// reason, and every edge that becomes co-owned is reported with its other
/// end.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_writes_nothing_and_reports_holds_and_co_owned_edges(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(
        &dir,
        "ids.txt",
        &[fx.a, fx.b, fx.n, fx.q, fx.r, fx.v, fx.w, fx.e, fx.u],
    );
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, false).await;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: None,
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_same(&before, &snapshot(&pool, false).await, "dry run");
    assert!(!mf.exists(), "a dry run must not write a manifest");
    assert!(
        audit_rows(&pool).await.is_empty(),
        "a dry run writes no audit row"
    );
    assert!(
        r.stdout
            .contains("PLAN: 9 requested, 2 eligible, 7 held, 0 already ('group', target)"),
        "{}",
        r.show()
    );
    for (id, needle) in [
        (fx.n, "not-in-source"),
        (fx.q, "sealed"),
        (fx.r, "third-group"),
        (fx.v, "public-row"),
        (fx.w, "pinned"),
        (fx.e, "edge-would-widen"),
        (fx.u, "public-claim"),
    ] {
        assert!(
            has_line(&r.stdout, "HELD\t", &[&id.to_string(), needle]),
            "no HELD line for {id} ({needle})\n{}",
            r.show()
        );
    }
    // Both edges from B to S's side become co-owned with SRC; the edge to the
    // public claim P does not.
    for e in [fx.e_bs, fx.e_ev_bs] {
        assert!(
            has_line(
                &r.stdout,
                "CO-OWNED-EDGE\t",
                &[&e.to_string(), &fx.src.to_string(), "source group"]
            ),
            "no CO-OWNED-EDGE line for {e}\n{}",
            r.show()
        );
    }
    assert!(
        !r.stdout.contains(&format!("CO-OWNED-EDGE\t{}", fx.e_bp)),
        "{}",
        r.show()
    );
    assert!(r.stdout.contains("co-owned edges: 2"), "{}", r.show());
    // The edge from SRC's workflow is reported on its own line.
    assert!(
        has_line(
            &r.stdout,
            "SOURCE-NODE-EDGE\t",
            &[
                &fx.e_wf_b.to_string(),
                "workflow",
                &fx.wf.to_string(),
                "source group"
            ]
        ),
        "no SOURCE-NODE-EDGE line for the workflow edge\n{}",
        r.show()
    );
    assert!(r.stdout.contains("source-node edges: 1"), "{}", r.show());
    assert!(r.stdout.contains("claims moved: 2"), "{}", r.show());
    assert!(
        r.stdout.contains("audit row: none (dry run)"),
        "{}",
        r.show()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply
// ─────────────────────────────────────────────────────────────────────────────

/// A self-contained claim moves with every row that follows it, keeping
/// `group` visibility; SRC's members lose it and DST's gain it; nothing else
/// changes; one audit row names the act; the manifest records every prior.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_moves_a_self_contained_claim_and_everything_that_follows(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let g = fx.dst;
    assert_eq!(row(&pool, "claims", fx.a).await, grp(g));
    for (t, id) in [
        ("evidence", fx.ev_a),
        ("reasoning_traces", fx.trace_a),
        ("mass_functions", fx.mf_a),
        ("claim_versions", fx.cv_a),
        ("harvester_fragments", fx.frag_a),
    ] {
        assert_eq!(row(&pool, t, id).await, grp(g), "{t} {id}");
    }
    let cf: (Uuid, String) = sqlx::query_as(
        "SELECT owner_group_id, visibility::text FROM claim_frames WHERE claim_id = $1",
    )
    .bind(fx.a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cf, grp(g));
    // Nothing else moved.
    let after = snapshot(&pool, true).await;
    for t in [
        "groups",
        "group_memberships",
        "agents",
        "frames",
        "harvester_sources",
    ] {
        assert_eq!(before[t], after[t], "{t} changed");
    }
    for c in [fx.b, fx.s, fx.r, fx.v, fx.w, fx.q] {
        assert_eq!(row(&pool, "claims", c).await, grp(fx.src), "{c} moved");
    }
    // Readability: SRC's members lost A and its evidence; DST's gained them.
    assert!(reads_as(&pool, &[fx.src], "claims", &[fx.a])
        .await
        .is_empty());
    assert!(reads_as(&pool, &[fx.src], "evidence", &[fx.ev_a])
        .await
        .is_empty());
    assert_eq!(
        reads_as(&pool, &[fx.dst], "claims", &[fx.a]).await,
        vec![fx.a]
    );
    assert_eq!(
        reads_as(&pool, &[fx.dst], "evidence", &[fx.ev_a]).await,
        vec![fx.ev_a]
    );
    assert!(reads_as(&pool, &[], "claims", &[fx.a]).await.is_empty());
    // One audit row naming the act; the manifest records the priors.
    let audit = audit_rows(&pool).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].0, "privatization.cli_regroup");
    assert_eq!(audit[0].1, Some(fx.operator));
    assert_eq!(audit[0].2["ruling"], RULING);
    assert_eq!(audit[0].2["source_group_id"], fx.src.to_string());
    assert_eq!(audit[0].2["target_group_id"], fx.dst.to_string());
    let body = std::fs::read_to_string(&mf).expect("manifest");
    let header: serde_json::Value =
        serde_json::from_str(body.lines().next().unwrap()).expect("header");
    assert_eq!(header["operation"], "regroup-claims");
    assert_eq!(header["source_group_id"], fx.src.to_string());
    for id in [fx.a, fx.ev_a, fx.trace_a, fx.mf_a, fx.cv_a, fx.frag_a] {
        assert!(
            body.lines().any(|l| l.contains(&id.to_string())
                && l.contains(&fx.src.to_string())
                && !l.contains("\"after\"")),
            "no prior record for {id}"
        );
    }
}

/// B moves; its edges to S, which stays in SRC, take the meet: owned by DST
/// and co-owned by SRC, so only a reader in BOTH groups reads them. A SRC-only
/// reader still reads S and no longer reads B; a DST-only reader reads B and
/// not S. The evidence-endpoint edge (which the trigger does not re-meet) ends
/// on the same tuple. The edge to the public claim P is DST's alone.
#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_to_a_claim_that_stays_in_source_becomes_co_owned(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.b]);
    let mf = dir.join("m.jsonl");
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let co = (fx.dst, "group".to_string(), Some(fx.src));
    assert_eq!(edge(&pool, fx.e_bs).await, co);
    assert_eq!(edge(&pool, fx.e_ev_bs).await, co);
    assert_eq!(
        edge(&pool, fx.e_bp).await,
        (fx.dst, "group".to_string(), None)
    );
    assert_eq!(
        edge(&pool, fx.e_wf_b).await,
        (fx.src, "group".to_string(), Some(fx.dst)),
        "the edge from SRC's workflow takes the exact meet (the workflow is its source end)"
    );
    assert!(
        has_line(
            &r.stdout,
            "SOURCE-NODE-EDGE\t",
            &[&fx.e_wf_b.to_string(), "workflow", "source group"]
        ),
        "{}",
        r.show()
    );
    assert!(r.stdout.contains("source-node edges: 1"), "{}", r.show());
    assert!(reads_as(&pool, &[fx.src], "edges", &[fx.e_wf_b])
        .await
        .is_empty());
    assert!(reads_as(&pool, &[fx.dst], "edges", &[fx.e_wf_b])
        .await
        .is_empty());
    assert_eq!(
        reads_as(&pool, &[fx.src, fx.dst], "edges", &[fx.e_wf_b]).await,
        vec![fx.e_wf_b]
    );
    assert_eq!(row(&pool, "workflows", fx.wf).await, grp(fx.src));
    assert_eq!(row(&pool, "claims", fx.s).await, grp(fx.src));
    assert_eq!(row(&pool, "evidence", fx.ev_s).await, grp(fx.src));
    assert_eq!(row(&pool, "evidence", fx.ev_b).await, grp(fx.dst));

    let claims = [fx.b, fx.s];
    let edges = [fx.e_bs, fx.e_ev_bs];
    assert_eq!(
        reads_as(&pool, &[fx.src], "claims", &claims).await,
        vec![fx.s]
    );
    assert!(reads_as(&pool, &[fx.src], "edges", &edges).await.is_empty());
    assert_eq!(
        reads_as(&pool, &[fx.dst], "claims", &claims).await,
        vec![fx.b]
    );
    assert!(reads_as(&pool, &[fx.dst], "edges", &edges).await.is_empty());
    assert_eq!(
        reads_as(&pool, &[fx.src, fx.dst], "claims", &claims).await,
        sorted(claims.to_vec())
    );
    assert_eq!(
        reads_as(&pool, &[fx.src, fx.dst], "edges", &edges).await,
        sorted(edges.to_vec())
    );
    assert!(reads_as(&pool, &[], "edges", &edges).await.is_empty());
    assert!(r.stdout.contains("co-owned edges: 2"), "{}", r.show());
}

/// A claim held for a row-level reason is held WHOLE: none of its rows moves,
/// the listed claim beside it moves, and `--apply` exits 3 because the list
/// was not fully moved.
#[sqlx::test(migrations = "../../migrations")]
async fn a_held_claim_is_held_whole_and_apply_exits_3(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, fx.r, fx.w, fx.q, fx.n, fx.e]);
    let mf = dir.join("m.jsonl");
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 3, "{}", r.show());
    assert_eq!(row(&pool, "claims", fx.a).await, grp(fx.dst));
    for c in [fx.r, fx.w, fx.q, fx.e] {
        assert_eq!(row(&pool, "claims", c).await, grp(fx.src), "{c}");
    }
    assert_eq!(
        edge(&pool, fx.e_ep_declared).await,
        (fx.src, "group".to_string(), Some(fx.h_group))
    );
    assert_eq!(row(&pool, "claims", fx.n).await, grp(fx.h_group));
    assert_eq!(row(&pool, "evidence", fx.ev_r_h).await, grp(fx.h_group));
    let r_own: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT owner_group_id, visibility::text FROM evidence WHERE claim_id = $1 AND id <> $2",
    )
    .bind(fx.r)
    .bind(fx.ev_r_h)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(r_own.iter().all(|t| *t == grp(fx.src)), "{r_own:?}");
}

/// Public input is refused and never touched: a public claim and a claim
/// carrying a public row are HELD, and an `--apply` with nothing eligible
/// writes nothing (no manifest, no audit row).
#[sqlx::test(migrations = "../../migrations")]
async fn public_input_is_refused_and_never_touched(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.u, fx.v]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, false).await;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(0),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 3, "{}", r.show());
    assert!(
        r.stdout.contains("PLAN: 2 requested, 0 eligible, 2 held"),
        "{}",
        r.show()
    );
    assert!(has_line(
        &r.stdout,
        "HELD\t",
        &[&fx.u.to_string(), "public-claim"]
    ));
    assert!(has_line(
        &r.stdout,
        "HELD\t",
        &[&fx.v.to_string(), "public-row"]
    ));
    assert_same(&before, &snapshot(&pool, false).await, "public input");
    assert!(!mf.exists());
    assert!(audit_rows(&pool).await.is_empty());
}

/// `--apply` with a `--confirm-count` that is not the dry run's eligible count
/// is refused before anything is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_confirm_count_mismatch_is_refused_and_nothing_is_written(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, fx.b]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, false).await;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(3),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("--confirm-count 3"), "{}", r.show());
    assert_same(&before, &snapshot(&pool, false).await, "confirm mismatch");
    assert!(!mf.exists());
    assert!(audit_rows(&pool).await.is_empty());
}

/// The groups and the operator are checked before anything is written: the
/// same group twice, a target that is not a team or community group, an
/// operator who does not administer the source, and one who is not a
/// registered human operator.
#[sqlx::test(migrations = "../../migrations")]
async fn bad_groups_and_unauthorized_operators_are_refused(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let before = snapshot(&pool, false).await;
    let stranger_team = {
        let (agent, _) = fixture::seed_human_operator(&pool, "stranger").await;
        team_group(&pool, "stranger team", agent).await
    };
    // Another person's personal group, which the operator ADMINISTERS: so its
    // refusal can only come from whose group it is, not from the admin check.
    let (_, stranger_personal) = fixture::seed_human_operator(&pool, "stranger person").await;
    admin_of(&pool, stranger_personal, fx.operator).await;
    let (robot, _) = fixture::seed_agent_with_group(&pool, "robot").await;
    let robot_src = team_group(&pool, "robot src", robot).await;
    let robot_dst = team_group(&pool, "robot dst", robot).await;
    let cases: Vec<(Uuid, Uuid, Uuid, &str)> = vec![
        (fx.src, fx.src, fx.operator, "is the source group"),
        (
            fx.src,
            stranger_personal,
            fx.operator,
            "not the operator's own personal group",
        ),
        (
            stranger_team,
            fx.dst,
            fx.operator,
            "not a live admin of --source-group",
        ),
        (
            robot_src,
            robot_dst,
            robot,
            "not a registered human operator",
        ),
    ];
    for (i, (src, dst, op, needle)) in cases.into_iter().enumerate() {
        let mf = dir.join(format!("m{i}.jsonl"));
        let r = regroup(
            &pool,
            Regroup {
                ids: &ids,
                src,
                dst,
                operator: op,
                manifest: &mf,
                apply_count: Some(1),
                extra: &[],
            },
        )
        .await;
        assert_eq!(r.code, 1, "case {i}: {}", r.show());
        assert!(r.stderr.contains(needle), "case {i}: {}", r.show());
        assert!(!mf.exists());
    }
    let mut after = snapshot(&pool, false).await;
    for t in ["groups", "group_memberships", "agents"] {
        after.insert(t.into(), before[t].clone());
    }
    assert_same(&before, &after, "refusals");
    assert!(audit_rows(&pool).await.is_empty());
}

/// The operator's OWN personal group is a target (operator ruling,
/// 2026-11-12: legacy workflow claims a team holds go private to the person
/// whose lineages supersede them). A and B move into it with everything that
/// follows them; B's edge to S, which stays in SRC, is co-owned by both; a
/// reader of the personal group reads them and a SRC-only reader does not;
/// the reversal puts every row back byte for byte.
#[sqlx::test(migrations = "../../migrations")]
async fn the_operators_own_personal_group_is_a_target_and_the_move_reverses_exactly(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, fx.b]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let g = fx.operator_group;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: g,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(2),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains(&format!("target_group={g} (personal)")),
        "{}",
        r.show()
    );
    for c in [fx.a, fx.b] {
        assert_eq!(row(&pool, "claims", c).await, grp(g), "claim {c}");
    }
    for (t, id) in [
        ("evidence", fx.ev_a),
        ("reasoning_traces", fx.trace_a),
        ("mass_functions", fx.mf_a),
        ("claim_versions", fx.cv_a),
        ("harvester_fragments", fx.frag_a),
        ("evidence", fx.ev_b),
    ] {
        assert_eq!(row(&pool, t, id).await, grp(g), "{t} {id}");
    }
    assert_eq!(
        edge(&pool, fx.e_bs).await,
        (g, "group".to_string(), Some(fx.src)),
        "an edge to a claim that stays in SRC is co-owned by both groups"
    );
    assert_eq!(
        reads_as(&pool, &[g], "claims", &[fx.a, fx.b]).await,
        sorted(vec![fx.a, fx.b])
    );
    assert!(reads_as(&pool, &[fx.src], "claims", &[fx.a, fx.b])
        .await
        .is_empty());
    assert!(reads_as(&pool, &[], "claims", &[fx.a, fx.b])
        .await
        .is_empty());
    let audit = audit_rows(&pool).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].2["target_group_id"], g.to_string());
    assert_eq!(audit[0].2["target_group_kind"], "personal");

    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "a move into the operator's personal group, then its reversal",
    );
}

/// A run into a personal group that is not the operator's own.
async fn refused_personal_target(pool: &PgPool, fx: &Fx, target: Uuid) {
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let before = snapshot(pool, false).await;
    for apply_count in [None, Some(1)] {
        let mf = dir.join(format!("m-{apply_count:?}.jsonl"));
        let r = regroup(
            pool,
            Regroup {
                ids: &ids,
                src: fx.src,
                dst: target,
                operator: fx.operator,
                manifest: &mf,
                apply_count,
                extra: &[],
            },
        )
        .await;
        assert_eq!(r.code, 1, "{}", r.show());
        assert!(
            r.stderr.contains("not the operator's own personal group"),
            "{}",
            r.show()
        );
        assert!(!mf.exists());
    }
    assert_same(&before, &snapshot(pool, false).await, "a refused target");
    assert!(audit_rows(pool).await.is_empty());
}

/// Another person's personal group is refused, even though the operator is
/// a live admin of it: a regroup never puts claims in a group that is someone
/// else's own.
#[sqlx::test(migrations = "../../migrations")]
async fn another_persons_personal_group_is_refused_even_to_its_admin(pool: PgPool) {
    let fx = seed(&pool).await;
    let (_, theirs) = fixture::seed_human_operator(&pool, "another person").await;
    admin_of(&pool, theirs, fx.operator).await;
    refused_personal_target(&pool, &fx, theirs).await;
}

/// An agent the operator OPERATES (a live operator link) has its own personal
/// group, and the operator is made a live admin of it: still refused. That
/// group is the agent's, where the agent's own writes land and which the
/// agent administers; migration 107's ownership model moves an operated
/// agent's claims OUT of it into the operator's group (`reown-linked`), never
/// into it. "The operator's own personal group" is the one carrying the
/// operator's personal did_key, created by the operator.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agents_personal_group_is_refused_even_to_its_operator(pool: PgPool) {
    let fx = seed(&pool).await;
    let (agent, agents_group) = fixture::seed_agent_with_group(&pool, "operated agent").await;
    sqlx::query("SELECT * FROM epigraph_link_operator($1, $2)")
        .bind(agent)
        .bind(fx.operator)
        .execute(&pool)
        .await
        .expect("link the agent to the operator");
    admin_of(&pool, agents_group, fx.operator).await;
    refused_personal_target(&pool, &fx, agents_group).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Reverse and re-run
// ─────────────────────────────────────────────────────────────────────────────

/// Apply then reverse puts every row back byte for byte (`claims.updated_at`
/// aside); the dry reverse changes nothing; a second reverse finds every claim
/// already restored and changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_then_reverse_restores_every_row_byte_for_byte(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, fx.b]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(2),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let moved = snapshot(&pool, true).await;
    assert_ne!(moved["edges"], before["edges"], "the apply moved nothing");

    let dry = reverse(&pool, &[&mf], &[], false).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert_same(&moved, &snapshot(&pool, true).await, "dry reverse");

    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert!(rv.stdout.contains("claims restored: 2"), "{}", rv.show());
    assert!(
        rv.stdout
            .contains("regroup manifests: 1 audit row(s) written"),
        "{}",
        rv.show()
    );
    assert_same(&before, &snapshot(&pool, true).await, "apply then reverse");
    let audit = audit_rows(&pool).await;
    assert_eq!(
        audit.iter().map(|a| a.0.as_str()).collect::<Vec<_>>(),
        vec![
            "privatization.cli_regroup",
            "privatization.cli_regroup_reverse"
        ]
    );

    let again = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(
        again
            .stdout
            .contains("claims already on their recorded owner: 2"),
        "{}",
        again.show()
    );
    assert_same(&before, &snapshot(&pool, true).await, "second reverse");
    assert_eq!(audit_rows(&pool).await.len(), 2);
}

/// Two linked claims moved and reversed one per batch: the edge between them
/// passes through the co-owned meet between batches and ends exactly where it
/// started, in both directions.
#[sqlx::test(migrations = "../../migrations")]
async fn linked_claims_across_batches_move_and_reverse_exactly(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.b, fx.s]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(2),
            extra: &["--batch-size", "1"],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let only_dst = (fx.dst, "group".to_string(), None);
    assert_eq!(edge(&pool, fx.e_bs).await, only_dst);
    assert_eq!(edge(&pool, fx.e_ev_bs).await, only_dst);
    let rv = reverse(&pool, &[&mf], &["--batch-size", "1"], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "batch-size 1 reverse",
    );
}

/// A re-run of the same list finds every claim already moved: nothing is
/// eligible, an `--apply` with `--confirm-count 0` writes nothing (no
/// manifest, no second audit row) and exits 0.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rerun_is_idempotent(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, fx.b]);
    let mf1 = dir.join("m1.jsonl");
    fn mk<'a>(fx: &Fx, ids: &'a Path, mf: &'a Path, n: Option<usize>) -> Regroup<'a> {
        Regroup {
            ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: mf,
            apply_count: n,
            extra: &[],
        }
    }
    let r = regroup(&pool, mk(&fx, &ids, &mf1, Some(2))).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let moved = snapshot(&pool, false).await;
    let mf2 = dir.join("m2.jsonl");
    let dry = regroup(&pool, mk(&fx, &ids, &mf2, None)).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout
            .contains("PLAN: 2 requested, 0 eligible, 0 held, 2 already ('group', target)"),
        "{}",
        dry.show()
    );
    let again = regroup(&pool, mk(&fx, &ids, &mf2, Some(0))).await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert_same(&moved, &snapshot(&pool, false).await, "re-run");
    assert!(!mf2.exists());
    assert_eq!(audit_rows(&pool).await.len(), 1);
}

/// The reversal is a compare-and-swap: a claim something else moved since is
/// HELD (exit 3), and so is one that gained a row after the act (the trigger
/// would carry that row into the source group); the other claim is restored.
#[sqlx::test(migrations = "../../migrations")]
async fn the_reversal_holds_a_claim_moved_since_or_grown_since(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, fx.b, fx.v]);
    // V is held by the apply; make it movable first so three claims move.
    exec(
        &pool,
        "UPDATE evidence SET owner_group_id = $2, visibility = 'group' WHERE claim_id = $1",
        &[fx.v, fx.src],
    )
    .await;
    let mf = dir.join("m.jsonl");
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(3),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    // A moves on to H; B gains a row after the act; V is untouched since.
    exec(
        &pool,
        "UPDATE claims SET owner_group_id = $2 WHERE id = $1",
        &[fx.a, fx.h_group],
    )
    .await;
    let late = evidence(&pool, fx.b, "written after the regroup").await;
    assert_eq!(row(&pool, "evidence", late).await, grp(fx.dst));
    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 3, "{}", rv.show());
    assert!(has_line(
        &rv.stdout,
        "HELD\t",
        &[&fx.a.to_string(), "moved it since"]
    ));
    assert!(has_line(
        &rv.stdout,
        "HELD\t",
        &[&fx.b.to_string(), &late.to_string(), "written after"]
    ));
    assert_eq!(row(&pool, "claims", fx.a).await, grp(fx.h_group));
    assert_eq!(row(&pool, "claims", fx.b).await, grp(fx.dst));
    assert_eq!(row(&pool, "evidence", late).await, grp(fx.dst));
    assert_eq!(row(&pool, "claims", fx.v).await, grp(fx.src));
}

/// The shapes a `restrict-claims` run leaves (the case this verb exists for:
/// claims an earlier restriction put in the wrong team group). Two public
/// claims X and Y carrying an outsider's public challenge, another writer's
/// evidence, a fragment X shares with a public claim P, and edges X->Y, X->P,
/// are restricted into SRC, then regrouped to DST: nothing is held (the
/// outsider's challenge and the shared fragment are left as they are, the
/// writer's evidence follows), nothing becomes public, SRC's members lose
/// everything and DST's gain it. One `reown-reverse` call over both manifests
/// (newest first) puts every row back byte for byte.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_a_restriction_put_in_source_regroup_and_both_acts_reverse(pool: PgPool) {
    let fx = seed(&pool).await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let x = fixture::seed_public_claim(&pool, fx.operator, "X: public, restricted").await;
    let y = fixture::seed_public_claim(&pool, fx.operator, "Y: public, restricted").await;
    let ev_x = evidence(&pool, x, "X's evidence").await;
    let ev_w = evidence(&pool, x, "the stranger's evidence on X").await;
    let ch: Uuid = sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation) \
         VALUES ($1, $2, 'factual_error', 'the outsider objects') RETURNING id",
    )
    .bind(x)
    .bind(stranger)
    .fetch_one(&pool)
    .await
    .expect("seed the outsider's challenge");
    let source: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_sources (content_hash, modality) VALUES ($1, 'text') RETURNING id",
    )
    .bind(h32(Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed harvester source");
    let frag: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_fragments (source_id, content_hash, content_text, owner_group_id, \
                                          visibility) \
         VALUES ($1, $2, 'shared fragment', $3, 'public') RETURNING id",
    )
    .bind(source)
    .bind(h32(Uuid::new_v4()))
    .bind(WORLD)
    .fetch_one(&pool)
    .await
    .expect("seed fragment");
    for c in [x, fx.p] {
        exec(
            &pool,
            "INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)",
            &[c, frag],
        )
        .await;
    }
    let e_xy = fixture::seed_edge(&pool, x, y).await;
    let e_xp = fixture::seed_edge(&pool, x, fx.p).await;
    exec(
        &pool,
        "UPDATE evidence SET owner_group_id = $2, visibility = 'public', writer_owned = true \
          WHERE id = $1",
        &[ev_w, stranger_group],
    )
    .await;
    exec(
        &pool,
        "UPDATE challenges SET owner_group_id = $2, visibility = 'public', writer_owned = true \
          WHERE id = $1",
        &[ch, stranger_group],
    )
    .await;

    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[x, y]);
    let before = snapshot(&pool, true).await;
    let m_restrict = dir.join("restrict.jsonl");
    let (target, op) = (fx.src.to_string(), fx.operator.to_string());
    let rs = run_op(
        &pool,
        &[
            "restrict-claims",
            "--claims-file",
            ids.to_str().unwrap(),
            "--target-group",
            &target,
            "--operator",
            &op,
            "--manifest-out",
            m_restrict.to_str().unwrap(),
            "--apply",
            "--confirm-count",
            "2",
            "--ruling",
            RULING,
            "--reason",
            "the earlier act",
        ],
    )
    .await;
    assert_eq!(rs.code, 0, "{}", rs.show());
    assert_eq!(row(&pool, "claims", x).await, grp(fx.src));
    assert_eq!(
        row(&pool, "harvester_fragments", frag).await,
        (WORLD, "public".into())
    );

    let m_regroup = dir.join("regroup.jsonl");
    let rg = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &m_regroup,
            apply_count: Some(2),
            extra: &[],
        },
    )
    .await;
    assert_eq!(rg.code, 0, "{}", rg.show());
    for c in [x, y] {
        assert_eq!(row(&pool, "claims", c).await, grp(fx.dst));
    }
    for e in [ev_x, ev_w] {
        assert_eq!(row(&pool, "evidence", e).await, grp(fx.dst));
    }
    assert_eq!(
        row(&pool, "challenges", ch).await,
        (stranger_group, "public".into()),
        "the outsider's challenge is the challenger's"
    );
    assert_eq!(
        row(&pool, "harvester_fragments", frag).await,
        (WORLD, "public".into()),
        "a fragment shared with a claim that stays is a node"
    );
    assert_eq!(edge(&pool, e_xy).await, (fx.dst, "group".into(), None));
    assert_eq!(edge(&pool, e_xp).await, (fx.dst, "group".into(), None));
    assert!(reads_as(&pool, &[fx.src], "claims", &[x, y])
        .await
        .is_empty());
    assert!(reads_as(&pool, &[fx.src], "challenges", &[ch])
        .await
        .is_empty());
    assert_eq!(
        reads_as(&pool, &[fx.dst], "challenges", &[ch]).await,
        vec![ch]
    );
    assert!(reads_as(&pool, &[], "claims", &[x, y]).await.is_empty());

    let rv = reverse(&pool, &[&m_restrict, &m_regroup], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(&before, &snapshot(&pool, true).await, "both acts reversed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Edges to nodes with their own tenancy (workflow, frame, context,
// perspective, community)
// ─────────────────────────────────────────────────────────────────────────────

/// Insert a node of entity type `ty` owned by `(owner, visibility)`.
async fn seed_node(pool: &PgPool, ty: &str, owner: Uuid, visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    let name = format!("regroup-node-{id}");
    let sql = match ty {
        "workflow" => {
            "INSERT INTO workflows (id, canonical_name, generation, goal, owner_group_id, \
                                    visibility) VALUES ($1, $2, 0, 'goal', $3, $4)"
        }
        "frame" => {
            "INSERT INTO frames (id, name, hypotheses, owner_group_id, visibility) \
             VALUES ($1, $2, ARRAY['a','b'], $3, $4)"
        }
        "context" => {
            "INSERT INTO contexts (id, name, context_type, owner_group_id, visibility) \
             VALUES ($1, $2, 'domain', $3, $4)"
        }
        "perspective" => {
            "INSERT INTO perspectives (id, name, owner_group_id, visibility) \
             VALUES ($1, $2, $3, $4)"
        }
        "community" => {
            "INSERT INTO communities (id, name, owner_group_id, visibility) \
             VALUES ($1, $2, $3, $4)"
        }
        other => panic!("no seeder for node type {other}"),
    };
    sqlx::query(sql)
        .bind(id)
        .bind(&name)
        .bind(owner)
        .bind(visibility)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed {ty}: {e}"));
    id
}

/// An edge between `(a, a_ty)` and `(b, b_ty)`, stamped by the trigger.
async fn typed_edge(pool: &PgPool, a: Uuid, a_ty: &str, b: Uuid, b_ty: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5, 'relates_to')",
    )
    .bind(id)
    .bind(a)
    .bind(a_ty)
    .bind(b)
    .bind(b_ty)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {a_ty} -> {b_ty} edge: {e}"));
    id
}

/// A fresh SRC claim C linked to a SRC-private node of type `ty` (the node is
/// the edge's source end when `node_first`). The trigger counts the node as
/// public, so the edge starts on C's tuple. Regrouping C writes the EXACT meet
/// (co-owned by SRC through the node), reports it as a SOURCE-NODE-EDGE, and
/// neither a SRC-only nor a DST-only reader reads it; reversing puts every
/// row back byte for byte.
async fn a_source_node_edge_is_co_owned_and_reported(pool: PgPool, ty: &str, node_first: bool) {
    let fx = seed(&pool).await;
    let c = fixture::seed_group_claim(&pool, fx.operator, fx.src, "C: SRC, linked to a node").await;
    let table = row_table(ty);
    let node = seed_node(&pool, ty, fx.src, "group").await;
    let e = if node_first {
        typed_edge(&pool, node, ty, c, "claim").await
    } else {
        typed_edge(&pool, c, "claim", node, ty).await
    };
    assert_eq!(
        edge(&pool, e).await,
        (fx.src, "group".to_string(), None),
        "the trigger counts the {ty} as public"
    );
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[c]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let want = if node_first {
        (fx.src, "group".to_string(), Some(fx.dst))
    } else {
        (fx.dst, "group".to_string(), Some(fx.src))
    };
    assert_eq!(edge(&pool, e).await, want, "{ty} edge\n{}", r.show());
    assert!(
        has_line(
            &r.stdout,
            "SOURCE-NODE-EDGE\t",
            &[&e.to_string(), ty, &node.to_string(), "source group"]
        ),
        "no SOURCE-NODE-EDGE line for the {ty} edge\n{}",
        r.show()
    );
    assert!(r.stdout.contains("source-node edges: 1"), "{}", r.show());
    assert!(r.stdout.contains("co-owned edges: 0"), "{}", r.show());
    assert!(r.stdout.contains("irreversible edges: 0 "), "{}", r.show());
    assert!(reads_as(&pool, &[fx.src], "edges", &[e]).await.is_empty());
    assert!(reads_as(&pool, &[fx.dst], "edges", &[e]).await.is_empty());
    assert_eq!(
        reads_as(&pool, &[fx.src, fx.dst], "edges", &[e]).await,
        vec![e]
    );
    assert_eq!(row(&pool, table, node).await, grp(fx.src), "the node moved");
    assert_eq!(row(&pool, "claims", c).await, grp(fx.dst));

    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(&before, &snapshot(&pool, true).await, "node edge reversed");
    assert_eq!(edge(&pool, e).await, (fx.src, "group".to_string(), None));
}

/// The dry run and the apply both name edge `e` as IRREVERSIBLE-EDGE, with
/// claim `c`, and count it: the reversal will hold `c`.
fn assert_irreversible(r: &Run, e: Uuid, c: Uuid) {
    assert!(
        has_line(
            &r.stdout,
            "IRREVERSIBLE-EDGE\t",
            &[
                &e.to_string(),
                &format!("claim {c}"),
                "will not be reversible"
            ]
        ),
        "no IRREVERSIBLE-EDGE line for edge {e}\n{}",
        r.show()
    );
    assert!(r.stdout.contains("irreversible edges: 1 "), "{}", r.show());
}

fn row_table(ty: &str) -> &'static str {
    match ty {
        "workflow" => "workflows",
        "frame" => "frames",
        "context" => "contexts",
        "perspective" => "perspectives",
        "community" => "communities",
        other => panic!("no table for {other}"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_edge_takes_the_exact_meet(pool: PgPool) {
    a_source_node_edge_is_co_owned_and_reported(pool, "workflow", true).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_frame_edge_takes_the_exact_meet(pool: PgPool) {
    a_source_node_edge_is_co_owned_and_reported(pool, "frame", false).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_context_edge_takes_the_exact_meet(pool: PgPool) {
    a_source_node_edge_is_co_owned_and_reported(pool, "context", true).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_perspective_edge_takes_the_exact_meet(pool: PgPool) {
    a_source_node_edge_is_co_owned_and_reported(pool, "perspective", false).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_community_edge_takes_the_exact_meet(pool: PgPool) {
    a_source_node_edge_is_co_owned_and_reported(pool, "community", true).await;
}

/// A reasoning trace is an entity type with its own tenancy that FOLLOWS its
/// claim. An edge from C to C's own trace ends on the target alone (both ends
/// move, and nothing is reported); an edge from the trace of S2, which stays
/// in SRC, to C is co-owned and reported. The reversal puts both back byte
/// for byte: C's trace comes back with C, so the first edge's recorded tuple
/// is no wider than its endpoints.
#[sqlx::test(migrations = "../../migrations")]
async fn a_trace_edge_takes_the_exact_meet(pool: PgPool) {
    let fx = seed(&pool).await;
    let c = fixture::seed_group_claim(&pool, fx.operator, fx.src, "C: SRC, with a trace").await;
    let s2 = fixture::seed_group_claim(&pool, fx.operator, fx.src, "S2: SRC, stays").await;
    let trace_c = fixture::seed_reasoning_trace(&pool, c, "deductive").await;
    let trace_s2 = fixture::seed_reasoning_trace(&pool, s2, "deductive").await;
    let e_own = typed_edge(&pool, c, "claim", trace_c, "trace").await;
    let e_other = typed_edge(&pool, trace_s2, "trace", c, "claim").await;
    for e in [e_own, e_other] {
        assert_eq!(edge(&pool, e).await, (fx.src, "group".to_string(), None));
    }
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[c]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(row(&pool, "reasoning_traces", trace_c).await, grp(fx.dst));
    assert_eq!(row(&pool, "reasoning_traces", trace_s2).await, grp(fx.src));
    assert_eq!(
        edge(&pool, e_own).await,
        (fx.dst, "group".to_string(), None)
    );
    assert_eq!(
        edge(&pool, e_other).await,
        (fx.src, "group".to_string(), Some(fx.dst))
    );
    assert!(
        has_line(
            &r.stdout,
            "SOURCE-NODE-EDGE\t",
            &[
                &e_other.to_string(),
                "trace",
                &trace_s2.to_string(),
                "source group"
            ]
        ),
        "{}",
        r.show()
    );
    assert!(r.stdout.contains("source-node edges: 1"), "{}", r.show());
    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "trace edges reversed",
    );
}

/// An edge from C1 to the reasoning trace of C2, both listed, moved one per
/// batch. C1's batch meets the edge with C2's trace still in SRC; C2's batch
/// reaches the edge through the trace (as it reaches an evidence edge through
/// the evidence) and settles it on DST alone, so no SOURCE-NODE-EDGE line
/// survives. The reversal, one per batch too, passes through the interim meet
/// and ends byte for byte where it started.
#[sqlx::test(migrations = "../../migrations")]
async fn a_trace_edge_across_batches_is_settled_by_the_later_batch(pool: PgPool) {
    let fx = seed(&pool).await;
    let c1 =
        fixture::seed_group_claim(&pool, fx.operator, fx.src, "C1: SRC, cites C2's trace").await;
    let c2 = fixture::seed_group_claim(&pool, fx.operator, fx.src, "C2: SRC, with a trace").await;
    let trace_c2 = fixture::seed_reasoning_trace(&pool, c2, "deductive").await;
    let e = typed_edge(&pool, c1, "claim", trace_c2, "trace").await;
    assert_eq!(edge(&pool, e).await, (fx.src, "group".to_string(), None));
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[c1, c2]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(2),
            extra: &["--batch-size", "1"],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(row(&pool, "reasoning_traces", trace_c2).await, grp(fx.dst));
    assert_eq!(
        edge(&pool, e).await,
        (fx.dst, "group".to_string(), None),
        "{}",
        r.show()
    );
    assert!(
        !r.stdout
            .lines()
            .any(|l| l.starts_with("SOURCE-NODE-EDGE\t")),
        "{}",
        r.show()
    );
    assert!(r.stdout.contains("source-node edges: 0"), "{}", r.show());
    assert!(
        r.stdout.contains("irreversible edges: 0 "),
        "C1, moved by the first batch, comes back to SRC too\n{}",
        r.show()
    );
    assert_eq!(
        reads_as(&pool, &[fx.dst], "edges", &[e]).await,
        vec![e],
        "a DST-only reader reads the settled edge"
    );
    let rv = reverse(&pool, &[&mf], &["--batch-size", "1"], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert!(
        rv.stdout
            .contains("BATCH 2/2\tOK\t1 claim(s) restored, 0 edge(s)"),
        "{}",
        rv.show()
    );
    assert!(
        !rv.stdout.contains("not restored (held)"),
        "nothing was held, so no edge may be blamed on a held endpoint\n{}",
        rv.show()
    );
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "trace edge across batches reversed",
    );
}

/// An edge from the trace of a moving claim C to S, a SRC claim that is not
/// listed and stays. The trace follows C to DST, so the edge takes the exact
/// meet of the trace and S: co-owned by both groups, reported as a
/// CO-OWNED-EDGE whose other end is S (the trace, its source end, moved). The
/// reversal brings the trace back with C and the edge back on its recorded
/// tuple, byte for byte.
#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_from_an_unlisted_claim_to_a_moving_trace_is_co_owned(pool: PgPool) {
    let fx = seed(&pool).await;
    let c = fixture::seed_group_claim(&pool, fx.operator, fx.src, "C: SRC, with a trace").await;
    let s = fixture::seed_group_claim(&pool, fx.operator, fx.src, "S: SRC, stays").await;
    let trace_c = fixture::seed_reasoning_trace(&pool, c, "deductive").await;
    let e = typed_edge(&pool, trace_c, "trace", s, "claim").await;
    assert_eq!(edge(&pool, e).await, (fx.src, "group".to_string(), None));
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[c]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(row(&pool, "reasoning_traces", trace_c).await, grp(fx.dst));
    assert_eq!(
        edge(&pool, e).await,
        (fx.dst, "group".to_string(), Some(fx.src)),
        "{}",
        r.show()
    );
    assert!(
        has_line(
            &r.stdout,
            "CO-OWNED-EDGE\t",
            &[
                &e.to_string(),
                &format!("other end claim {s}"),
                "source group"
            ]
        ),
        "{}",
        r.show()
    );
    assert!(r.stdout.contains("co-owned edges: 1"), "{}", r.show());
    assert!(r.stdout.contains("source-node edges: 0"), "{}", r.show());
    assert!(reads_as(&pool, &[fx.src], "edges", &[e]).await.is_empty());
    assert!(reads_as(&pool, &[fx.dst], "edges", &[e]).await.is_empty());
    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "unlisted claim's trace edge reversed",
    );
}

/// An edge from a moving claim's reasoning trace to a PUBLIC frame. The
/// trigger counts both ends as public, so the edge is a public row; read
/// through the trace, it holds its claim whole (`public-row`), as a public
/// evidence edge does: this tool never touches a public row. The plan's
/// eligible count leaves the claim out.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_edge_from_a_moving_trace_holds_its_claim(pool: PgPool) {
    let fx = seed(&pool).await;
    let c = fixture::seed_group_claim(&pool, fx.operator, fx.src, "C: SRC, with a trace").await;
    let trace_c = fixture::seed_reasoning_trace(&pool, c, "deductive").await;
    let e = typed_edge(&pool, trace_c, "trace", fx.frame, "frame").await;
    assert_eq!(
        edge(&pool, e).await.1,
        "public",
        "both ends count as public"
    );
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[c]);
    let mf = dir.join("m.jsonl");
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: None,
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout
            .contains("PLAN: 1 requested, 0 eligible, 1 held, 0 already"),
        "{}",
        r.show()
    );
    assert!(
        has_line(
            &r.stdout,
            "HELD\t",
            &[&c.to_string(), "public-row", &format!("edges {e}")]
        ),
        "{}",
        r.show()
    );
    assert_eq!(row(&pool, "claims", c).await, grp(fx.src));
}

/// The node types the tool meets by their own row are exactly the entity
/// types (other than claim and evidence) whose table has tenancy columns at
/// head, and every one of them has a test above. A type that gains tenancy
/// columns fails here until it is covered.
#[sqlx::test(migrations = "../../migrations")]
async fn the_node_types_are_every_tenanted_entity_type(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let mf = dir.join("m.jsonl");
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: None,
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.lines().any(|l| l.starts_with(
            "NODE-TYPES\tcommunity=communities,context=contexts,frame=frames,\
             perspective=perspectives,trace=reasoning_traces,workflow=workflows\t"
        )),
        "{}",
        r.show()
    );
}

/// An edge to a PUBLIC node goes to the target alone (the node requires no
/// group) and is not reported.
#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_to_a_public_node_goes_to_the_target(pool: PgPool) {
    let fx = seed(&pool).await;
    let c =
        fixture::seed_group_claim(&pool, fx.operator, fx.src, "C: SRC, linked to a frame").await;
    let e = typed_edge(&pool, c, "claim", fx.frame, "frame").await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[c]);
    let mf = dir.join("m.jsonl");
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(edge(&pool, e).await, (fx.dst, "group".to_string(), None));
    assert!(
        !r.stdout
            .lines()
            .any(|l| l.starts_with("SOURCE-NODE-EDGE\t")),
        "{}",
        r.show()
    );
    assert!(r.stdout.contains("source-node edges: 0"), "{}", r.show());
}

/// An edge to a node of a THIRD group is met with that group (it keeps
/// requiring it) and reported. Its recorded prior, the claim's tuple alone,
/// was already wider than the node: the reversal will not write it back and
/// holds the claim instead, which the dry run and the apply both report
/// (IRREVERSIBLE-EDGE and its count).
#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_to_a_third_group_node_is_reported_and_its_reversal_holds(pool: PgPool) {
    let fx = seed(&pool).await;
    let c =
        fixture::seed_group_claim(&pool, fx.operator, fx.src, "C: SRC, run by H's workflow").await;
    let wf = seed_node(&pool, "workflow", fx.h_group, "group").await;
    let e = typed_edge(&pool, wf, "workflow", c, "claim").await;
    assert_eq!(edge(&pool, e).await, (fx.src, "group".to_string(), None));
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[c]);
    let mf = dir.join("m.jsonl");
    let dry = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: None,
            extra: &[],
        },
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert_irreversible(&dry, e, c);
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(
        edge(&pool, e).await,
        (fx.h_group, "group".to_string(), Some(fx.dst))
    );
    assert!(
        has_line(
            &r.stdout,
            "SOURCE-NODE-EDGE\t",
            &[&e.to_string(), &format!("group {}", fx.h_group)]
        ),
        "{}",
        r.show()
    );
    assert_irreversible(&r, e, c);
    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 3, "{}", rv.show());
    assert!(
        has_line(
            &rv.stdout,
            "HELD\t",
            &[&c.to_string(), &e.to_string(), "widen"]
        ),
        "{}",
        rv.show()
    );
    assert_eq!(row(&pool, "claims", c).await, grp(fx.dst));
    assert_eq!(
        edge(&pool, e).await,
        (fx.h_group, "group".to_string(), Some(fx.dst))
    );
}

/// An edge from a workflow that is already in the TARGET goes to the target
/// alone (the node requires nothing beyond the target) and is not a
/// SOURCE-NODE-EDGE. Its recorded prior, the claim's tuple alone, was wider
/// than the node (a SOURCE-only reader read an edge naming a TARGET-private
/// workflow), so the reversal will not write it back and holds the claim
/// instead. The dry run and the apply both say so up front (IRREVERSIBLE-EDGE
/// and its count).
#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_from_a_target_node_goes_to_the_target_and_its_reversal_holds(pool: PgPool) {
    let fx = seed(&pool).await;
    let c = fixture::seed_group_claim(&pool, fx.operator, fx.src, "C: SRC, run by DST's workflow")
        .await;
    let wf = seed_node(&pool, "workflow", fx.dst, "group").await;
    let e = typed_edge(&pool, wf, "workflow", c, "claim").await;
    assert_eq!(edge(&pool, e).await, (fx.src, "group".to_string(), None));
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[c]);
    let mf = dir.join("m.jsonl");
    let dry = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: None,
            extra: &[],
        },
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert_irreversible(&dry, e, c);
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(edge(&pool, e).await, (fx.dst, "group".to_string(), None));
    assert!(
        !r.stdout
            .lines()
            .any(|l| l.starts_with("SOURCE-NODE-EDGE\t")),
        "{}",
        r.show()
    );
    assert_irreversible(&r, e, c);
    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 3, "{}", rv.show());
    assert!(
        has_line(
            &rv.stdout,
            "HELD\t",
            &[&c.to_string(), &e.to_string(), "widen"]
        ),
        "{}",
        rv.show()
    );
    assert_eq!(row(&pool, "claims", c).await, grp(fx.dst));
    assert_eq!(edge(&pool, e).await, (fx.dst, "group".to_string(), None));
}

// ─────────────────────────────────────────────────────────────────────────────
// Sealed evidence, a moved evidence endpoint, a concurrent edge insert
// ─────────────────────────────────────────────────────────────────────────────

async fn seal_evidence(pool: &PgPool, ev: Uuid, group: Uuid) {
    exec(
        pool,
        "INSERT INTO evidence_encryption (evidence_id, group_id, epoch, privacy_tier, \
                                          encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', ''::bytea)",
        &[ev, group],
    )
    .await;
}

/// Evidence sealed under the source group holds its claim WHOLE (the plan
/// excludes it, the apply exits 3); evidence sealed after the act holds the
/// claim in the reversal.
#[sqlx::test(migrations = "../../migrations")]
async fn sealed_evidence_holds_its_claim_in_the_move_and_in_the_reversal(pool: PgPool) {
    let fx = seed(&pool).await;
    seal_evidence(&pool, fx.ev_a, fx.src).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, fx.b]);
    let dry = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &dir.join("dry.jsonl"),
            apply_count: None,
            extra: &[],
        },
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout
            .contains("PLAN: 2 requested, 1 eligible, 1 held, 0 already ('group', target)"),
        "{}",
        dry.show()
    );
    assert!(
        has_line(
            &dry.stdout,
            "HELD\t",
            &[&fx.a.to_string(), "sealed-evidence", &fx.ev_a.to_string()]
        ),
        "{}",
        dry.show()
    );
    let mf = dir.join("m.jsonl");
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 3, "{}", r.show());
    assert_eq!(row(&pool, "claims", fx.a).await, grp(fx.src));
    assert_eq!(row(&pool, "evidence", fx.ev_a).await, grp(fx.src));
    assert_eq!(row(&pool, "claims", fx.b).await, grp(fx.dst));

    // B's evidence is sealed under DST after the act: the reversal holds B.
    exec(
        &pool,
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active')",
        &[fx.dst],
    )
    .await;
    seal_evidence(&pool, fx.ev_b, fx.dst).await;
    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 3, "{}", rv.show());
    assert!(
        has_line(
            &rv.stdout,
            "HELD\t",
            &[&fx.b.to_string(), &fx.ev_b.to_string(), "sealed since"]
        ),
        "{}",
        rv.show()
    );
    assert_eq!(row(&pool, "claims", fx.b).await, grp(fx.dst));
    assert_eq!(row(&pool, "evidence", fx.ev_b).await, grp(fx.dst));
}

/// An evidence edge from B's evidence to the evidence of a claim S2 that is
/// not in the manifest: the neighbour watch sees only claim endpoints, so S2
/// moving on to H after the act is invisible to it, and the edge itself is
/// still on its post tuple. Writing its recorded `(SRC, group)` back would let
/// SRC-only members read an edge to H-private evidence; the reversal checks
/// the recorded tuple against the meet of the endpoints after the restore and
/// holds B.
#[sqlx::test(migrations = "../../migrations")]
async fn the_reversal_holds_an_edge_whose_evidence_endpoint_moved_since(pool: PgPool) {
    let fx = seed(&pool).await;
    let s2 = fixture::seed_group_claim(&pool, fx.operator, fx.src, "S2: SRC, not listed").await;
    let ev_s2 = evidence(&pool, s2, "S2's evidence").await;
    let e = evidence_edge(&pool, fx.ev_b, ev_s2, fx.src).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.b]);
    let mf = dir.join("m.jsonl");
    let r = regroup(
        &pool,
        Regroup {
            ids: &ids,
            src: fx.src,
            dst: fx.dst,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let post = (fx.dst, "group".to_string(), Some(fx.src));
    assert_eq!(edge(&pool, e).await, post);
    exec(
        &pool,
        "UPDATE claims SET owner_group_id = $2 WHERE id = $1",
        &[s2, fx.h_group],
    )
    .await;
    assert_eq!(row(&pool, "evidence", ev_s2).await, grp(fx.h_group));
    assert_eq!(
        edge(&pool, e).await,
        post,
        "the trigger does not re-meet it"
    );

    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 3, "{}", rv.show());
    assert!(
        has_line(
            &rv.stdout,
            "HELD\t",
            &[&fx.b.to_string(), &e.to_string(), "widen"]
        ),
        "{}",
        rv.show()
    );
    assert_eq!(row(&pool, "claims", fx.b).await, grp(fx.dst));
    assert_eq!(edge(&pool, e).await, post);
    assert!(reads_as(&pool, &[fx.src], "edges", &[e]).await.is_empty());
}

/// A concurrent edge INSERT on a moving claim, open (uncommitted) when the
/// regroup starts: its trigger stamped the claim's SOURCE tuple. The batch
/// waits for it (it locks `edges`), then sees the committed edge and moves
/// it. Without the lock the batch would commit past the invisible row, which
/// would then commit on the source tuple of a claim now in the target.
#[sqlx::test(migrations = "../../migrations")]
async fn a_concurrent_edge_insert_on_a_moving_claim_is_waited_for_and_moved(pool: PgPool) {
    let fx = seed(&pool).await;
    let c = fixture::seed_group_claim(&pool, fx.operator, fx.src, "C: SRC, gains an edge").await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[c]);
    let mf = dir.join("m.jsonl");

    let mut tx = pool.begin().await.expect("begin");
    let late = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports')",
    )
    .bind(late)
    .bind(c)
    .bind(fx.p)
    .execute(&mut *tx)
    .await
    .expect("concurrent edge insert");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .expect("pid");

    let url = fixture::database_url_for(&pool).await;
    let (src, dst, op) = (
        fx.src.to_string(),
        fx.dst.to_string(),
        fx.operator.to_string(),
    );
    let mut child = Command::new(BIN)
        .args([
            "regroup-claims",
            "--claims-file",
            ids.to_str().unwrap(),
            "--source-group",
            &src,
            "--target-group",
            &dst,
            "--operator",
            &op,
            "--manifest-out",
            mf.to_str().unwrap(),
            "--apply",
            "--confirm-count",
            "1",
            "--ruling",
            RULING,
            "--reason",
            "test",
            "--lock-timeout",
            "60s",
        ])
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, &url)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn epigraph-operator");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            let out = child.wait_with_output().expect("output");
            panic!(
                "the regroup finished ({status}) without waiting for the open edge insert\n\
                 --- stdout\n{}\n--- stderr\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                             WHERE $1 = ANY (pg_blocking_pids(pid)))",
        )
        .bind(pid)
        .fetch_one(&pool)
        .await
        .expect("pg_blocking_pids");
        if blocked {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the regroup never blocked on the open insert"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    tx.commit().await.expect("commit the concurrent insert");
    let out = child.wait_with_output().expect("output");
    let run = Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    assert_eq!(run.code, 0, "{}", run.show());
    assert_eq!(row(&pool, "claims", c).await, grp(fx.dst));
    assert_eq!(
        edge(&pool, late).await,
        (fx.dst, "group".to_string(), None),
        "the edge committed during the batch was moved with its claim\n{}",
        run.show()
    );
}
