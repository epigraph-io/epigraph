//! `epigraph-operator restrict-claims` and its reversal through
//! `reown-reverse`, driven through the real binary against a `#[sqlx::test]`
//! database migrated 001 → head.
//!
//! # The fixture
//!
//! A world-owned public claim A (the one that moves) carrying: its own
//! evidence, a reasoning trace, a claim version, a challenge, a frame
//! assignment, a harvester fragment shared with a claim B that is not listed,
//! and ANOTHER WRITER's attachments (writer-owned evidence and a writer-owned
//! BBA, migration 114). Edges from A: a public edge to B owned by its writer's
//! group (D8), an edge to a group claim D in group K (meet `('group', K)`), and
//! an edge to B DECLARED `('group', target)` (the F2 shape that must come back
//! exactly). A second public claim H carries an edge to B declared
//! `('group', other)`: moving H would move another group's edge into the
//! target, so H must be held with nothing written.
//!
//! # What a snapshot is
//!
//! Every row of every table the run could reach, plus the control tables, as
//! `to_jsonb(row)::text`, sorted. `claims.updated_at` is stripped only in the
//! comparisons that span an apply (migration 001's trigger stamps it, and no
//! tool can put it back). `security_events` is compared on its own: an applied
//! run and an applied reversal each add exactly one row there.

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
const RULING: &str = "test ruling: four-eyes suspended, audited CLI act";

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
    let d = std::env::temp_dir().join(format!("operator-restrict-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

fn h32(seed: Uuid) -> Vec<u8> {
    seed.as_bytes().iter().copied().cycle().take(32).collect()
}

async fn exec(pool: &PgPool, sql: &str) {
    sqlx::query(sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct Fx {
    operator: Uuid,
    target: Uuid,
    stranger: Uuid,
    stranger_group: Uuid,
    other_group: Uuid,
    k_group: Uuid,
    frame: Uuid,
    a: Uuid,
    b: Uuid,
    d: Uuid,
    h: Uuid,
    ev_a: Uuid,
    ev_w: Uuid,
    trace: Uuid,
    mf_w: Uuid,
    cv: Uuid,
    challenge: Uuid,
    frag: Uuid,
    e_ab_writer: Uuid,
    e_ad: Uuid,
    e_ab_declared: Uuid,
    e_hb_other: Uuid,
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

async fn seed(pool: &PgPool) -> Fx {
    let (operator, target) = fixture::seed_human_operator(pool, "operator").await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(pool, "stranger").await;
    let (other, other_group) = fixture::seed_agent_with_group(pool, "other").await;
    let (k_agent, k_group) = fixture::seed_agent_with_group(pool, "k").await;

    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, owner_group_id, visibility) \
         VALUES ('restrict-frame', ARRAY['a','b'], $1, 'public') RETURNING id",
    )
    .bind(WORLD)
    .fetch_one(pool)
    .await
    .expect("seed frame");

    let a = fixture::seed_public_claim(pool, operator, "A: world-owned, moves").await;
    let b = fixture::seed_public_claim(pool, other, "B: world-owned, not listed").await;
    let d = fixture::seed_group_claim(pool, k_agent, k_group, "D: group K").await;
    let h = fixture::seed_public_claim(pool, other, "H: world-owned, carries H's edge").await;

    let ev_a = evidence(pool, a, "A's own evidence").await;
    let ev_w = evidence(pool, a, "the stranger's evidence on A").await;
    let trace = fixture::seed_reasoning_trace(pool, a, "deductive").await;
    let mf_w: Uuid = sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"a\": 1.0}') RETURNING id",
    )
    .bind(a)
    .bind(frame)
    .bind(stranger)
    .fetch_one(pool)
    .await
    .expect("seed mass function");
    let cv: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, created_by) \
         VALUES ($1, 1, 'v1', 0.5, $2) RETURNING id",
    )
    .bind(a)
    .bind(stranger)
    .fetch_one(pool)
    .await
    .expect("seed claim version");
    let challenge: Uuid = sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation) \
         VALUES ($1, $2, 'factual', 'disputed') RETURNING id",
    )
    .bind(a)
    .bind(stranger)
    .fetch_one(pool)
    .await
    .expect("seed challenge");
    sqlx::query("INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2)")
        .bind(a)
        .bind(frame)
        .execute(pool)
        .await
        .expect("seed claim frame");

    let source: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_sources (content_hash, modality) VALUES ($1, 'text') RETURNING id",
    )
    .bind(h32(Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed harvester source");
    let frag: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_fragments (source_id, content_hash, content_text, owner_group_id, \
                                          visibility) \
         VALUES ($1, $2, 'fragment text', $3, 'public') RETURNING id",
    )
    .bind(source)
    .bind(h32(Uuid::new_v4()))
    .bind(WORLD)
    .fetch_one(pool)
    .await
    .expect("seed fragment");
    for c in [a, b] {
        sqlx::query(
            "INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)",
        )
        .bind(c)
        .bind(frag)
        .execute(pool)
        .await
        .expect("seed provenance");
    }

    let e_ab_writer = fixture::seed_edge_owned_by(pool, a, b, "public", stranger_group).await;
    let e_ad = fixture::seed_edge(pool, a, d).await;
    let e_ab_declared = fixture::seed_edge_owned_by(pool, a, b, "group", target).await;
    let e_hb_other = fixture::seed_edge_owned_by(pool, h, b, "group", other_group).await;

    // The stranger's attachments are WRITER-OWNED (migration 114): its group,
    // public, flagged. LAST, on purpose: 070's insert arm re-syncs every row of
    // a table to its claim on each new insert for that claim.
    for (t, id) in [("evidence", ev_w), ("mass_functions", mf_w)] {
        sqlx::query(&format!(
            "UPDATE {t} SET owner_group_id = $2, visibility = 'public', writer_owned = true \
              WHERE id = $1"
        ))
        .bind(id)
        .bind(stranger_group)
        .execute(pool)
        .await
        .expect("make a writer-owned row");
    }

    Fx {
        operator,
        target,
        stranger,
        stranger_group,
        other_group,
        k_group,
        frame,
        a,
        b,
        d,
        h,
        ev_a,
        ev_w,
        trace,
        mf_w,
        cv,
        challenge,
        frag,
        e_ab_writer,
        e_ad,
        e_ab_declared,
        e_hb_other,
    }
}

fn ids_file(dir: &Path, name: &str, ids: &[Uuid]) -> PathBuf {
    let p = dir.join(name);
    let body: Vec<String> = ids.iter().map(ToString::to_string).collect();
    std::fs::write(&p, format!("# restrict fixture\n{}\n", body.join("\n"))).expect("ids file");
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
          WHERE event_type LIKE 'privatization.cli_restrict%' ORDER BY created_at, event_type",
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

async fn writer_owned(pool: &PgPool, table: &str, id: Uuid) -> bool {
    sqlx::query_scalar(&format!("SELECT writer_owned FROM {table} WHERE id = $1"))
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{table} {id}: {e}"))
}

fn grp(g: Uuid) -> (Uuid, String) {
    (g, "group".into())
}

fn publ(g: Uuid) -> (Uuid, String) {
    (g, "public".into())
}

struct Restrict<'a> {
    ids: &'a Path,
    target: Uuid,
    operator: Uuid,
    manifest: &'a Path,
    apply_count: Option<usize>,
    extra: &'a [&'a str],
}

async fn restrict(pool: &PgPool, r: Restrict<'_>) -> Run {
    let target = r.target.to_string();
    let op = r.operator.to_string();
    let count = r.apply_count.map(|n| n.to_string());
    let mut args = vec![
        "restrict-claims",
        "--claims-file",
        r.ids.to_str().unwrap(),
        "--target-group",
        &target,
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

/// A legacy permissive policy shape on claims, evidence and edges: PERMISSIVE,
/// TO public, FOR ALL, no WITH CHECK, USING a function TRUE for every row that
/// has no `fully_private` encryption row.
async fn seed_legacy_permissive_policies(pool: &PgPool) {
    exec(
        pool,
        "DO $$ BEGIN
           IF to_regprocedure('public.epigraph_current_group_id()') IS NULL THEN
             EXECUTE 'CREATE FUNCTION public.epigraph_current_group_id() RETURNS uuid \
                      LANGUAGE sql STABLE AS ''SELECT NULL::uuid''';
           END IF;
         END $$",
    )
    .await;
    exec(
        pool,
        "CREATE OR REPLACE FUNCTION public.epigraph_is_visible_to_group(p_entity_id uuid, p_table text)
          RETURNS boolean LANGUAGE plpgsql STABLE AS $f$
         DECLARE gid uuid := epigraph_current_group_id(); found boolean;
         BEGIN
           IF p_table = 'claim' THEN
             SELECT EXISTS(SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = p_entity_id
                             AND ce.privacy_tier = 'fully_private'
                             AND (gid IS NULL OR ce.group_id != gid)) INTO found;
           ELSIF p_table = 'evidence' THEN
             SELECT EXISTS(SELECT 1 FROM evidence_encryption ee WHERE ee.evidence_id = p_entity_id
                             AND ee.privacy_tier = 'fully_private'
                             AND (gid IS NULL OR ee.group_id != gid)) INTO found;
           ELSE found := false;
           END IF;
           RETURN NOT found;
         END; $f$",
    )
    .await;
    for sql in [
        "CREATE POLICY claims_privacy ON public.claims AS PERMISSIVE FOR ALL TO public \
           USING (epigraph_is_visible_to_group(id, 'claim'::text))",
        "CREATE POLICY evidence_privacy ON public.evidence AS PERMISSIVE FOR ALL TO public \
           USING (epigraph_is_visible_to_group(id, 'evidence'::text))",
        "CREATE POLICY edges_privacy ON public.edges AS PERMISSIVE FOR ALL TO public \
           USING (epigraph_is_visible_to_group(source_id, 'claim'::text) \
             AND epigraph_is_visible_to_group(source_id, 'evidence'::text) \
             AND epigraph_is_visible_to_group(target_id, 'claim'::text) \
             AND epigraph_is_visible_to_group(target_id, 'evidence'::text))",
    ] {
        exec(pool, sql).await;
    }
    // Assert the shape, so the test cannot pass on a different policy.
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policies p \
          WHERE p.schemaname = 'public' AND p.policyname = p.tablename || '_privacy' \
            AND p.tablename IN ('claims', 'evidence', 'edges') \
            AND p.permissive = 'PERMISSIVE' AND p.cmd = 'ALL' \
            AND p.roles::text[] = ARRAY['public']::text[] AND p.with_check IS NULL",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(n, 3, "the legacy policies are not in the intended shape");
}

// ─────────────────────────────────────────────────────────────────────────────
// Dry run
// ─────────────────────────────────────────────────────────────────────────────

/// A dry run executes every batch and rolls it back: every row of every table
/// is byte-identical afterwards (`updated_at` included), no manifest and no
/// audit row exist, and the report names the plan, per-table counts and a
/// sample. On a clean schema it reports ENFORCED.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_writes_nothing_and_reports_the_plan(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, fx.h, fx.d]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, false).await;
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
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
    for needle in [
        "PLAN: 3 requested, 2 eligible, 1 held, 0 already",
        &format!("HELD\t{}\tclaim is ({}, group)", fx.d, fx.k_group),
        "ENFORCEMENT: ENFORCED",
        &format!("SAMPLE\t{}\tclaims\t{}", fx.a, fx.a),
        &format!("SAMPLE\t{}\tedges\t{}", fx.a, fx.e_ab_declared),
        &format!("HELD-UNDER-LOCK\t{}\tedges {}", fx.h, fx.e_hb_other),
        "claims moved: 1",
        "evidence: rows moved: 2",
        "edges: rows moved: 2",
        "audit row: none (dry run)",
    ] {
        assert!(
            r.stdout.contains(needle),
            "missing {needle:?}\n{}",
            r.show()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply
// ─────────────────────────────────────────────────────────────────────────────

/// Every row that follows A is in the target, with the exact tuple the
/// cascade gives it; another writer's attachments follow too and lose their
/// writer-owned flag; the edges are their endpoints' meet; the declared target
/// edge is unchanged; nothing of B, D or H moved.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_moves_the_claim_and_everything_that_follows(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let mf = dir.join("m.jsonl");
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let g = fx.target;
    assert_eq!(row(&pool, "claims", fx.a).await, grp(g));
    for (t, id) in [
        ("evidence", fx.ev_a),
        ("evidence", fx.ev_w),
        ("reasoning_traces", fx.trace),
        ("mass_functions", fx.mf_w),
        ("claim_versions", fx.cv),
        ("challenges", fx.challenge),
    ] {
        assert_eq!(row(&pool, t, id).await, grp(g), "{t} {id}");
    }
    assert_eq!(
        row(&pool, "harvester_fragments", fx.frag).await,
        publ(WORLD),
        "a fragment that is also B's provenance is a shared NODE: it does not narrow"
    );
    assert!(!writer_owned(&pool, "evidence", fx.ev_w).await);
    assert!(!writer_owned(&pool, "mass_functions", fx.mf_w).await);
    let cf: (Uuid, String) = sqlx::query_as(
        "SELECT owner_group_id, visibility::text FROM claim_frames WHERE claim_id = $1",
    )
    .bind(fx.a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cf, grp(g));
    assert_eq!(
        edge(&pool, fx.e_ab_writer).await,
        (g, "group".into(), None),
        "A public, B public before; A now in the target: the meet is ('group', target)"
    );
    assert_eq!(
        edge(&pool, fx.e_ad).await,
        (g, "group".into(), Some(fx.k_group)),
        "A in the target and D in K: owned by both, readable by neither alone"
    );
    assert_eq!(
        edge(&pool, fx.e_ab_declared).await,
        (g, "group".into(), None)
    );
    assert_eq!(row(&pool, "claims", fx.b).await, publ(WORLD));
    assert_eq!(row(&pool, "claims", fx.d).await, grp(fx.k_group));
    assert_eq!(row(&pool, "claims", fx.h).await, publ(WORLD));
    assert_eq!(
        edge(&pool, fx.e_hb_other).await,
        (fx.other_group, "group".into(), None)
    );
    assert!(r.stdout.contains("claims moved: 1"), "{}", r.show());
}

// ─────────────────────────────────────────────────────────────────────────────
// Reverse
// ─────────────────────────────────────────────────────────────────────────────

/// Apply then reverse puts every tenancy column of every row back byte for
/// byte (owner, visibility, co-owner, `writer_owned`, `writer_group_id`; all
/// other columns too): the full-row snapshot matches, `claims.updated_at`
/// aside. A second reverse changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_then_reverse_restores_every_row_byte_for_byte(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let moved = snapshot(&pool, true).await;
    assert_ne!(
        moved["evidence"], before["evidence"],
        "the apply moved nothing"
    );

    let dry = reverse(&pool, &[&mf], &[], false).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert_same(&moved, &snapshot(&pool, true).await, "dry reverse");

    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(&before, &snapshot(&pool, true).await, "apply then reverse");
    assert!(writer_owned(&pool, "evidence", fx.ev_w).await);
    assert_eq!(
        row(&pool, "evidence", fx.ev_w).await,
        publ(fx.stranger_group)
    );

    let again = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(
        again
            .stdout
            .contains("claims already on their recorded owner: 1"),
        "{}",
        again.show()
    );
    assert_same(&before, &snapshot(&pool, true).await, "second reverse");
}

/// Migration 168 (ruling R-CH1): an OUTSIDER's challenge on A (the stranger's,
/// owned by the stranger's group, public, writer-owned) is not dragged into the
/// target when A is restricted: the cascade leaves it exactly as it was, the
/// run's prediction must agree (or its invariants roll the batch back), and the
/// claim-owned challenge on A (the fixture's) still follows. Reverse puts
/// every row back byte for byte, the outsider's included.
#[sqlx::test(migrations = "../../migrations")]
async fn an_outsiders_challenge_is_not_dragged_into_the_target(pool: PgPool) {
    let fx = seed(&pool).await;
    let outsiders: Uuid = sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation) \
         VALUES ($1, $2, 'factual_error', 'the outsider objects') RETURNING id",
    )
    .bind(fx.a)
    .bind(fx.stranger)
    .fetch_one(&pool)
    .await
    .expect("seed the outsider's challenge");
    // The shape 168's attach rule gives it (the harness is privileged, so it
    // inherited; set it as the fixture sets the stranger's other rows).
    sqlx::query(
        "UPDATE challenges SET owner_group_id = $2, visibility = 'public', writer_owned = true \
          WHERE id = $1",
    )
    .bind(outsiders)
    .bind(fx.stranger_group)
    .execute(&pool)
    .await
    .expect("make the challenge outsider-owned");

    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(row(&pool, "claims", fx.a).await, grp(fx.target));
    assert_eq!(
        row(&pool, "challenges", outsiders).await,
        publ(fx.stranger_group),
        "the outsider's challenge keeps its owner and visibility"
    );
    assert!(writer_owned(&pool, "challenges", outsiders).await);
    assert_eq!(
        row(&pool, "challenges", fx.challenge).await,
        grp(fx.target),
        "control: the claim-owned challenge follows A"
    );

    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(&before, &snapshot(&pool, true).await, "apply then reverse");
}

/// See `PrivatizationRepository::recompute_boundary_meet_conn` ("an edge DECLARED
/// ('group', H) between two public claims widens on revert"). An edge DECLARED `('group', target)` between two public claims
/// keeps exactly that tuple through apply AND reverse. A reverse that recomputed
/// the edge from its (both public again) endpoints would make it PUBLIC.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_group_edge_keeps_its_exact_tuple_through_apply_and_reverse(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let mf = dir.join("m.jsonl");
    let declared = (fx.target, "group".to_string(), None);
    assert_eq!(edge(&pool, fx.e_ab_declared).await, declared);
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(edge(&pool, fx.e_ab_declared).await, declared);
    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_eq!(row(&pool, "claims", fx.a).await, publ(WORLD));
    assert_eq!(
        edge(&pool, fx.e_ab_declared).await,
        declared,
        "F2: the declared group edge came back as something else (widened?)"
    );
}

/// A claim carrying ANOTHER group's declared edge is held: moving it would
/// move that group's edge into the target. Nothing at all is written, read
/// back from the database, and no audit row exists.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_whose_row_would_widen_into_the_target_is_held(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.h]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, false).await;
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains(&format!(
            "HELD-UNDER-LOCK\t{}\tedges {}",
            fx.h, fx.e_hb_other
        )),
        "{}",
        r.show()
    );
    assert!(r.stdout.contains("claims moved: 0"), "{}", r.show());
    assert_same(&before, &snapshot(&pool, false).await, "held claim");
    assert!(
        audit_rows(&pool).await.is_empty(),
        "nothing changed, so no audit row"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Refusals
// ─────────────────────────────────────────────────────────────────────────────

/// A public claim owned by a group other than the world group is held (only
/// the world-owned corpus moves), and nothing is written; with
/// `--allow-non-world-owner` it moves.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_world_owned_claim_is_held_unless_allowed(pool: PgPool) {
    let fx = seed(&pool).await;
    let personal = fixture::seed_public_claim(&pool, fx.stranger, "personal-owned").await;
    exec(
        &pool,
        &format!(
            "UPDATE claims SET owner_group_id = '{}' WHERE id = '{personal}'",
            fx.stranger_group
        ),
    )
    .await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[personal]);
    let before = snapshot(&pool, false).await;
    let mf = dir.join("m.jsonl");
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(0),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains(&format!(
            "HELD\t{personal}\tpublic but owned by group {}",
            fx.stranger_group
        )),
        "{}",
        r.show()
    );
    assert_same(&before, &snapshot(&pool, false).await, "non-world claim");
    assert!(!mf.exists());
    assert!(audit_rows(&pool).await.is_empty());

    let mf2 = dir.join("m2.jsonl");
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf2,
            apply_count: Some(1),
            extra: &["--allow-non-world-owner"],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(row(&pool, "claims", personal).await, grp(fx.target));
}

/// A target that does not exist, is not active, or that the operator does not
/// administer is refused before anything is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bad_target_is_refused_and_nothing_is_written(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let before = snapshot(&pool, false).await;
    let cases: [(Uuid, &str); 3] = [
        (Uuid::new_v4(), "no such group"),
        (fx.k_group, "is not a live admin"),
        (WORLD, "world or seed"),
    ];
    for (target, needle) in cases {
        let mf = dir.join(format!("m-{target}.jsonl"));
        let r = restrict(
            &pool,
            Restrict {
                ids: &ids,
                target,
                operator: fx.operator,
                manifest: &mf,
                apply_count: Some(1),
                extra: &[],
            },
        )
        .await;
        assert_eq!(r.code, 1, "{}", r.show());
        assert!(r.stderr.contains(needle), "{needle}: {}", r.show());
        assert!(!mf.exists());
    }
    assert_same(&before, &snapshot(&pool, false).await, "refused targets");
    exec(
        &pool,
        &format!(
            "UPDATE groups SET status = 'suspended' WHERE id = '{}'",
            fx.target
        ),
    )
    .await;
    let suspended = snapshot(&pool, false).await;
    let mf = dir.join("m-suspended.jsonl");
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("not active"), "{}", r.show());
    assert!(!mf.exists());
    assert_same(
        &suspended,
        &snapshot(&pool, false).await,
        "suspended target",
    );
    assert!(audit_rows(&pool).await.is_empty());
}

/// With legacy permissive policies present, `--apply` refuses
/// and writes nothing (read back from the database, no manifest, no audit
/// row). With `--accept-unenforced` it moves the claim and says UNENFORCED in
/// its report and its audit row, and the reversal still restores everything.
#[sqlx::test(migrations = "../../migrations")]
async fn legacy_permissive_policies_refuse_apply_unless_accepted_and_the_run_says_unenforced(
    pool: PgPool,
) {
    let fx = seed(&pool).await;
    seed_legacy_permissive_policies(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let before = snapshot(&pool, false).await;
    let before_stripped = snapshot(&pool, true).await;
    let mf = dir.join("m.jsonl");
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stdout.contains("WARNING: UNENFORCED"), "{}", r.show());
    assert!(
        r.stderr.contains("--accept-unenforced") && r.stderr.contains("claims_privacy"),
        "{}",
        r.show()
    );
    assert_same(
        &before,
        &snapshot(&pool, false).await,
        "refused unenforced run",
    );
    assert!(!mf.exists());
    assert!(audit_rows(&pool).await.is_empty());

    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &["--accept-unenforced"],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(row(&pool, "claims", fx.a).await, grp(fx.target));
    assert!(r.stdout.contains("enforcement: UNENFORCED"), "{}", r.show());
    let audit = audit_rows(&pool).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].2["enforcement"]["state"], "UNENFORCED");
    assert!(audit[0].2["enforcement"]["by"]["claims"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p == "claims_privacy"));

    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(
        &before_stripped,
        &snapshot(&pool, true).await,
        "unenforced apply then reverse",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit
// ─────────────────────────────────────────────────────────────────────────────

/// One `security_events` row per applied run and one per applied reversal,
/// attributed to the operator, naming the ruling, the target, the counts, the
/// operator login, and binding the manifest by digest (header line on apply,
/// the whole file on reverse) and the id file by digest.
#[sqlx::test(migrations = "../../migrations")]
async fn the_audit_rows_name_the_act(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let mf = dir.join("m.jsonl");
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let rows = audit_rows(&pool).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (ty, agent, d) = &rows[0];
    assert_eq!(ty, "privatization.cli_restrict");
    assert_eq!(*agent, Some(fx.operator));
    let session_user: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&pool)
        .await
        .unwrap();
    let text = std::fs::read_to_string(&mf).unwrap();
    let header_line = text.lines().next().unwrap();
    let sha = |b: &[u8]| epigraph_cli::operator::restrict::sha256_hex(b);
    assert_eq!(d["ruling"], RULING);
    assert_eq!(d["reason"], "test");
    assert_eq!(d["target_group_id"], fx.target.to_string());
    assert_eq!(d["operator"]["session_user"], session_user);
    assert_eq!(d["manifest_header_sha256"], sha(header_line.as_bytes()));
    assert_eq!(d["claims_file_sha256"], sha(&std::fs::read(&ids).unwrap()));
    assert_eq!(d["planned"]["eligible"], 1);
    assert_eq!(d["planned"]["requested"], 1);
    assert_eq!(d["first_batch"]["claims_moved"], 1);
    assert_eq!(d["enforcement"]["state"], "ENFORCED");

    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    let rows = audit_rows(&pool).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let (ty, agent, d) = &rows[1];
    assert_eq!(ty, "privatization.cli_restrict_reverse");
    assert_eq!(*agent, Some(fx.operator));
    assert_eq!(
        d["manifest_sha256"],
        sha(&std::fs::read(&mf).unwrap()),
        "the reverse row binds the whole manifest file"
    );
    assert_eq!(d["ruling"], RULING);
    assert_eq!(d["first_batch"]["claims_restored"], 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Durability, resumability, cross-batch edges
// ─────────────────────────────────────────────────────────────────────────────

/// The manifest holds every row's prior BEFORE the write: a batch whose claims
/// UPDATE fails (a test trigger raises) leaves the database unchanged, no
/// audit row, and a manifest that already records the claim and each of its
/// rows with their exact prior tuples.
#[sqlx::test(migrations = "../../migrations")]
async fn the_manifest_is_on_disk_before_the_write(pool: PgPool) {
    let fx = seed(&pool).await;
    exec(
        &pool,
        &format!(
            "CREATE FUNCTION test_refuse_claim_update() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.id = '{}' THEN RAISE EXCEPTION 'test: refuse this write'; END IF; \
             RETURN NEW; END $$",
            fx.a
        ),
    )
    .await;
    exec(
        &pool,
        "CREATE TRIGGER test_refuse_claim_update BEFORE UPDATE ON claims \
         FOR EACH ROW EXECUTE FUNCTION test_refuse_claim_update()",
    )
    .await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, false).await;
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 2, "{}", r.show());
    assert!(r.stdout.contains("test: refuse this write"), "{}", r.show());
    assert_same(&before, &snapshot(&pool, false).await, "failed batch");
    assert!(audit_rows(&pool).await.is_empty());
    let m = epigraph_cli::operator::manifest::read(&mf).expect("manifest");
    let prior: BTreeMap<(String, String), &epigraph_cli::operator::manifest::Record> = m
        .records
        .iter()
        .filter(|r| !r.after)
        .map(|r| ((r.table.clone(), r.id.to_string()), r))
        .collect();
    let q = |id: Uuid| format!("\"{id}\"");
    let rec = |t: &str, id: Uuid| prior.get(&(t.to_string(), q(id))).copied();
    let c = rec("claims", fx.a).expect("the claim's prior");
    assert_eq!((c.owner_group_id, c.visibility.as_str()), (WORLD, "public"));
    let w = rec("evidence", fx.ev_w).expect("the writer-owned row's prior");
    assert_eq!(
        (w.owner_group_id, w.visibility.as_str(), w.writer_owned),
        (fx.stranger_group, "public", Some(true))
    );
    let e = rec("edges", fx.e_ab_declared).expect("the declared edge's prior");
    assert_eq!(
        (e.owner_group_id, e.visibility.as_str(), e.co_owner_group_id),
        (fx.target, "group", Some(None))
    );
    let e = rec("edges", fx.e_ad).expect("the A-D edge's prior");
    assert_eq!(
        (e.owner_group_id, e.visibility.as_str()),
        (fx.k_group, "group")
    );
    assert!(
        m.records.iter().all(|r| !r.after),
        "no post record may exist for a batch that did not commit"
    );
}

/// An interrupted run (stopped by `--max-batches`) resumes: a re-run with a new
/// manifest moves exactly what is left, and both manifests in one reverse
/// restore every row byte for byte.
#[sqlx::test(migrations = "../../migrations")]
async fn an_interrupted_run_resumes_and_both_manifests_reverse(pool: PgPool) {
    let fx = seed(&pool).await;
    let c2 = fixture::seed_public_claim(&pool, fx.operator, "second").await;
    let c3 = fixture::seed_public_claim(&pool, fx.operator, "third").await;
    let _e23 = fixture::seed_edge(&pool, c2, c3).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, c2, c3]);
    let before = snapshot(&pool, true).await;
    let m1 = dir.join("m1.jsonl");
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &m1,
            apply_count: Some(3),
            extra: &["--batch-size", "1", "--max-batches", "1"],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains("STOPPED by --max-batches"),
        "{}",
        r.show()
    );
    assert_eq!(row(&pool, "claims", fx.a).await, grp(fx.target));
    assert_eq!(row(&pool, "claims", c2).await, publ(WORLD));

    let m2 = dir.join("m2.jsonl");
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &m2,
            apply_count: Some(2),
            extra: &["--batch-size", "1"],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout
            .contains("PLAN: 3 requested, 2 eligible, 0 held, 1 already"),
        "{}",
        r.show()
    );
    for c in [fx.a, c2, c3] {
        assert_eq!(row(&pool, "claims", c).await, grp(fx.target));
    }
    assert_eq!(audit_rows(&pool).await.len(), 2, "one row per applied run");

    let rv = reverse(&pool, &[&m1, &m2], &["--batch-size", "1"], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "resumed run reversed",
    );
}

/// An edge between two claims the run moved is not put back on its recorded
/// PUBLIC tuple while one of them is still restricted (held by the reversal):
/// it keeps the narrow meet. Once that claim is reversible and reversed, the
/// edge is restored exactly.
#[sqlx::test(migrations = "../../migrations")]
async fn an_edge_is_not_widened_while_its_other_moved_endpoint_is_held(pool: PgPool) {
    let fx = seed(&pool).await;
    let c2 = fixture::seed_public_claim(&pool, fx.operator, "second").await;
    let e = fixture::seed_edge_owned_by(&pool, fx.a, c2, "public", fx.stranger_group).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, c2]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(2),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(edge(&pool, e).await, (fx.target, "group".into(), None));
    // A row written on c2 after the restriction is group-private and unrecorded:
    // restoring c2 would widen it, so the reversal must HOLD c2.
    let late = evidence(&pool, c2, "written after the restriction").await;
    assert_eq!(row(&pool, "evidence", late).await, grp(fx.target));
    let rv = reverse(&pool, &[&mf], &["--batch-size", "1"], true).await;
    assert_eq!(rv.code, 3, "{}", rv.show());
    assert!(rv.stdout.contains(&format!("HELD\t{c2}")), "{}", rv.show());
    assert_eq!(row(&pool, "claims", fx.a).await, publ(WORLD));
    assert_eq!(row(&pool, "claims", c2).await, grp(fx.target));
    assert_eq!(
        edge(&pool, e).await,
        (fx.target, "group".into(), None),
        "the edge must keep the meet of A (public again) and c2 (still in the target), not its \
         recorded public tuple"
    );
    assert!(
        rv.stdout.contains("1 edge(s) left on their narrow meet"),
        "{}",
        rv.show()
    );
    // The late row goes; the reversal then finishes and restores the edge.
    exec(&pool, &format!("DELETE FROM evidence WHERE id = '{late}'")).await;
    let rv = reverse(&pool, &[&mf], &["--batch-size", "1"], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(&before, &snapshot(&pool, true).await, "held then finished");
}

// ─────────────────────────────────────────────────────────────────────────────
// Edges with an EVIDENCE endpoint: the narrowest of their endpoints
// ─────────────────────────────────────────────────────────────────────────────

/// An edge between any two nodes (`claim` or `evidence`), stamped by the
/// tenancy trigger from its endpoints; with `force`, its tenancy is then set
/// to exactly `(visibility, owner, co_owner)`.
async fn node_edge(
    pool: &PgPool,
    (src, src_ty): (Uuid, &str),
    (tgt, tgt_ty): (Uuid, &str),
    force: Option<(&str, Uuid, Option<Uuid>)>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5, 'supports')",
    )
    .bind(id)
    .bind(src)
    .bind(src_ty)
    .bind(tgt)
    .bind(tgt_ty)
    .execute(pool)
    .await
    .expect("seed node edge");
    if let Some((v, o, co)) = force {
        sqlx::query(
            "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = $4 \
              WHERE id = $1",
        )
        .bind(id)
        .bind(v)
        .bind(o)
        .bind(co)
        .execute(pool)
        .await
        .expect("force edge tenancy");
    }
    id
}

/// Edges touching `claims` or their evidence that are PUBLIC while one of their
/// endpoints is not: the shape the operator's rule forbids ("an edge goes
/// invisible if one endpoint is invisible").
async fn visible_edges_with_an_invisible_endpoint(pool: &PgPool, claims: &[Uuid]) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT e.id FROM edges e \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.source_id, e.source_type) s \
           CROSS JOIN LATERAL public.epigraph_node_tenancy(e.target_id, e.target_type) t \
          WHERE e.visibility = 'public' AND (s.v <> 'public' OR t.v <> 'public') \
            AND (e.source_id = ANY($1) OR e.target_id = ANY($1) \
                 OR e.source_id IN (SELECT id FROM evidence WHERE claim_id = ANY($1)) \
                 OR e.target_id IN (SELECT id FROM evidence WHERE claim_id = ANY($1))) \
          ORDER BY 1",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("visible edges with an invisible endpoint")
}

/// claim->evidence and evidence->evidence edges whose evidence endpoint moves
/// with its claim narrow to the narrowest of their endpoints, exactly as a
/// claim-endpoint edge does; an edge already narrower than that keeps its
/// tuple; no visible edge is left with an invisible endpoint; the dry run
/// reports the count; and the reversal restores every one byte for byte.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_endpoint_edges_narrow_on_apply_and_restore_exactly(pool: PgPool) {
    let fx = seed(&pool).await;
    let ev_b = evidence(&pool, fx.b, "B's evidence").await;
    let x_ce = node_edge(&pool, (fx.b, "claim"), (fx.ev_a, "evidence"), None).await;
    let x_ee = node_edge(&pool, (fx.ev_a, "evidence"), (ev_b, "evidence"), None).await;
    let x_narrow = node_edge(
        &pool,
        (fx.ev_a, "evidence"),
        (ev_b, "evidence"),
        Some(("group", fx.target, Some(fx.k_group))),
    )
    .await;
    assert_eq!(edge(&pool, x_ce).await, (WORLD, "public".into(), None));
    assert_eq!(edge(&pool, x_ee).await, (WORLD, "public".into(), None));
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let before = snapshot(&pool, true).await;

    let dry = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &dir.join("dry.jsonl"),
            apply_count: None,
            extra: &[],
        },
    )
    .await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains("EVIDENCE-ENDPOINT-EDGES\t3\t") && dry.stdout.contains("narrowed"),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout.contains("edges: rows moved: 4"),
        "{}",
        dry.show()
    );

    let mf = dir.join("m.jsonl");
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let g = fx.target;
    assert_eq!(row(&pool, "evidence", fx.ev_a).await, grp(g));
    assert_eq!(
        edge(&pool, x_ce).await,
        (g, "group".into(), None),
        "claim(public) -> evidence(now in the target): the narrow tuple, as for a claim endpoint"
    );
    assert_eq!(
        edge(&pool, x_ee).await,
        (g, "group".into(), None),
        "evidence(now in the target) -> evidence(public): the narrow tuple"
    );
    assert_eq!(
        edge(&pool, x_narrow).await,
        (g, "group".into(), Some(fx.k_group)),
        "an edge already narrower than its endpoints keeps its tuple"
    );
    assert_eq!(
        visible_edges_with_an_invisible_endpoint(&pool, &[fx.a]).await,
        Vec::<Uuid>::new()
    );

    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "evidence edges reversed",
    );
}

/// An evidence->evidence edge between two claims the run moved is not put back
/// on its recorded PUBLIC tuple while the other claim is still restricted
/// (held by the reversal); once that claim is reversed, the edge is restored
/// exactly.
#[sqlx::test(migrations = "../../migrations")]
async fn an_evidence_edge_is_not_widened_while_its_other_moved_endpoint_is_held(pool: PgPool) {
    let fx = seed(&pool).await;
    let c2 = fixture::seed_public_claim(&pool, fx.operator, "second").await;
    let ev_c2 = evidence(&pool, c2, "c2's evidence").await;
    let x = node_edge(&pool, (fx.ev_a, "evidence"), (ev_c2, "evidence"), None).await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a, c2]);
    let mf = dir.join("m.jsonl");
    let before = snapshot(&pool, true).await;
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(2),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(edge(&pool, x).await, (fx.target, "group".into(), None));
    let late = evidence(&pool, c2, "written after the restriction").await;
    let rv = reverse(&pool, &[&mf], &["--batch-size", "1"], true).await;
    assert_eq!(rv.code, 3, "{}", rv.show());
    assert_eq!(row(&pool, "evidence", fx.ev_a).await, publ(WORLD));
    assert_eq!(row(&pool, "evidence", ev_c2).await, grp(fx.target));
    assert_eq!(
        edge(&pool, x).await,
        (fx.target, "group".into(), None),
        "the edge must stay narrow while its other moved endpoint is still restricted"
    );
    assert_eq!(
        visible_edges_with_an_invisible_endpoint(&pool, &[fx.a, c2]).await,
        Vec::<Uuid>::new()
    );
    exec(&pool, &format!("DELETE FROM evidence WHERE id = '{late}'")).await;
    let rv = reverse(&pool, &[&mf], &["--batch-size", "1"], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(&before, &snapshot(&pool, true).await, "held then finished");
}

/// A claim whose EVIDENCE carries another group's declared edge is held:
/// narrowing that edge into the target would make it readable to the target's
/// members. Nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_whose_evidence_edge_would_widen_is_held(pool: PgPool) {
    let fx = seed(&pool).await;
    let h2 = fixture::seed_public_claim(&pool, fx.operator, "carries H's evidence edge").await;
    let ev_h2 = evidence(&pool, h2, "h2's evidence").await;
    let x = node_edge(
        &pool,
        (ev_h2, "evidence"),
        (fx.b, "claim"),
        Some(("group", fx.other_group, None)),
    )
    .await;
    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[h2]);
    let before = snapshot(&pool, false).await;
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: fx.target,
            operator: fx.operator,
            manifest: &dir.join("m.jsonl"),
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout
            .contains(&format!("HELD-UNDER-LOCK\t{h2}\tedges {x}")),
        "{}",
        r.show()
    );
    assert_same(
        &before,
        &snapshot(&pool, false).await,
        "held evidence-edge claim",
    );
    assert!(audit_rows(&pool).await.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Nodes stay; only this claim's dependent and link rows narrow
// ─────────────────────────────────────────────────────────────────────────────

/// The classification of every table a restriction touches: DEPENDENT rows
/// (the claim's own) and LINK rows (an association of the claim with another
/// node) narrow; harvester fragments are NODES and narrow only when every
/// claim they are the provenance of is restricted with them. A table the
/// cascade gains without a decision here fails this test.
#[sqlx::test(migrations = "../../migrations")]
async fn every_touched_table_is_classified_node_link_or_dependent(pool: PgPool) {
    use epigraph_cli::operator::restrict::{role_of, Role};
    let mut conn = pool.acquire().await.unwrap();
    let specs = epigraph_cli::operator::tables::propagated_tables(&mut conn)
        .await
        .expect("propagated tables");
    let mut got: Vec<(String, Role)> = specs
        .iter()
        .map(|s| {
            (
                s.name.clone(),
                role_of(&s.name).expect("unclassified table"),
            )
        })
        .collect();
    got.sort_by(|a, b| a.0.cmp(&b.0));
    let want: Vec<(String, Role)> = [
        ("challenges", Role::Dependent),
        ("claim_cluster_membership", Role::Link),
        ("claim_clusters", Role::Link),
        ("claim_frames", Role::Link),
        ("claim_neighborhood_membership", Role::Link),
        ("claim_signature_revocations", Role::Dependent),
        ("claim_versions", Role::Dependent),
        ("claims", Role::Dependent),
        ("ds_bayesian_divergence", Role::Dependent),
        ("ds_combined_beliefs", Role::Dependent),
        ("edges", Role::Link),
        ("entity_mentions", Role::Link),
        ("evidence", Role::Dependent),
        ("experiment_entity_mentions", Role::Link),
        ("experiment_triples", Role::Dependent),
        ("harvester_claim_provenance", Role::Link),
        ("harvester_fragments", Role::SharedNode),
        ("mass_functions", Role::Dependent),
        ("reasoning_traces", Role::Dependent),
        ("triples", Role::Dependent),
    ]
    .into_iter()
    .map(|(t, r)| (t.to_string(), r))
    .collect();
    assert_eq!(got, want);
}

/// A cluster, a frame, a shared fragment and the far-end claim and evidence
/// of A's edges are NODES: after restricting A they are byte-identical, the
/// other member's link rows are unchanged, and only A's own link rows (graph
/// cluster membership, k-means assignment, frame assignment, provenance) and
/// A's edges narrow. A fragment that is A's alone narrows with A. The reversal
/// restores every row.
#[sqlx::test(migrations = "../../migrations")]
async fn connected_nodes_stay_and_only_this_claims_links_narrow(pool: PgPool) {
    let fx = seed(&pool).await;
    let g = fx.target;
    let run = Uuid::new_v4();
    let gc = Uuid::new_v4();
    exec(
        &pool,
        &format!(
            "INSERT INTO graph_clusters (id, run_id, label, size) VALUES ('{gc}', '{run}', 'c', 2)"
        ),
    )
    .await;
    for c in [fx.a, fx.b] {
        exec(
            &pool,
            &format!(
                "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) \
                 VALUES ('{c}', '{gc}', '{run}')"
            ),
        )
        .await;
        exec(
            &pool,
            &format!(
                "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, \
                   second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id) \
                 VALUES ('{c}', 7, 0.1, 0.2, 0.5, 0.3, '{run}')"
            ),
        )
        .await;
    }
    exec(
        &pool,
        &format!(
            "INSERT INTO claim_frames (claim_id, frame_id) VALUES ('{}', '{}')",
            fx.b, fx.frame
        ),
    )
    .await;
    let ev_b = evidence(&pool, fx.b, "B's evidence").await;
    let x_ee = node_edge(&pool, (fx.ev_a, "evidence"), (ev_b, "evidence"), None).await;
    let src: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_sources (content_hash, modality) VALUES ($1, 'text') RETURNING id",
    )
    .bind(h32(Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .unwrap();
    let frag_a: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_fragments (source_id, content_hash, content_text, owner_group_id, \
                                          visibility) \
         VALUES ($1, $2, 'A only', $3, 'public') RETURNING id",
    )
    .bind(src)
    .bind(h32(Uuid::new_v4()))
    .bind(WORLD)
    .fetch_one(&pool)
    .await
    .unwrap();
    exec(
        &pool,
        &format!(
            "INSERT INTO harvester_claim_provenance (claim_id, fragment_id) \
             VALUES ('{}', '{frag_a}')",
            fx.a
        ),
    )
    .await;

    let node_rows = |t: &'static str, cond: String| {
        let pool = pool.clone();
        async move {
            let rows: Vec<String> = sqlx::query_scalar(&format!(
                "SELECT to_jsonb(t)::text FROM {t} t WHERE {cond} ORDER BY 1"
            ))
            .fetch_all(&pool)
            .await
            .unwrap();
            rows
        }
    };
    let b_links = |pool: PgPool, b: Uuid| async move {
        let mut out = Vec::new();
        for t in [
            "claim_cluster_membership",
            "claim_clusters",
            "claim_frames",
            "harvester_claim_provenance",
            "evidence",
        ] {
            let rows: Vec<String> = sqlx::query_scalar(&format!(
                "SELECT to_jsonb(t)::text FROM {t} t WHERE claim_id = $1 ORDER BY 1"
            ))
            .bind(b)
            .fetch_all(&pool)
            .await
            .unwrap();
            out.push((t, rows));
        }
        out
    };
    let nodes_before = (
        node_rows("graph_clusters", format!("id = '{gc}'")).await,
        node_rows("frames", format!("id = '{}'", fx.frame)).await,
        node_rows("harvester_fragments", format!("id = '{}'", fx.frag)).await,
        node_rows("claims", format!("id = '{}'", fx.b)).await,
    );
    let b_before = b_links(pool.clone(), fx.b).await;
    let before = snapshot(&pool, true).await;

    let dir = scratch_dir();
    let ids = ids_file(&dir, "ids.txt", &[fx.a]);
    let mf = dir.join("m.jsonl");
    let r = restrict(
        &pool,
        Restrict {
            ids: &ids,
            target: g,
            operator: fx.operator,
            manifest: &mf,
            apply_count: Some(1),
            extra: &[],
        },
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());

    let nodes_after = (
        node_rows("graph_clusters", format!("id = '{gc}'")).await,
        node_rows("frames", format!("id = '{}'", fx.frame)).await,
        node_rows("harvester_fragments", format!("id = '{}'", fx.frag)).await,
        node_rows("claims", format!("id = '{}'", fx.b)).await,
    );
    assert_eq!(nodes_before, nodes_after, "a connected NODE changed");
    assert_eq!(
        b_before,
        b_links(pool.clone(), fx.b).await,
        "B's own rows changed"
    );
    for t in [
        "claim_cluster_membership",
        "claim_clusters",
        "claim_frames",
        "harvester_claim_provenance",
    ] {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(&format!(
            "SELECT owner_group_id, visibility::text FROM {t} WHERE claim_id = $1"
        ))
        .bind(fx.a)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(!rows.is_empty(), "{t}: A has no row");
        assert!(
            rows.iter().all(|r| *r == grp(g)),
            "{t}: A's link rows {rows:?}"
        );
    }
    assert_eq!(row(&pool, "harvester_fragments", frag_a).await, grp(g));
    assert_eq!(edge(&pool, x_ee).await, (g, "group".into(), None));
    assert_eq!(row(&pool, "evidence", ev_b).await, publ(WORLD));

    let rv = reverse(&pool, &[&mf], &[], true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "nodes and links reversed",
    );
}
