//! `epigraph-operator`: `link-retired`, `reown-claims` and `reown-reverse`,
//! driven through the real binary against a `#[sqlx::test]` database migrated
//! 001 → head.
//!
//! # The fixture reproduces every hazard the brief names
//!
//! * world-owned public claims by a RETIRED-linked author, and one by an
//!   ACTOR-linked author;
//! * a claim owned by its author's own personal group;
//! * a listed claim owned by a third group (must be held);
//! * a listed claim by an UNLINKED author (must be held);
//! * a listed claim that does not exist (must be held);
//! * a public claim carrying a GROUP-PRIVATE evidence row (must be held, and
//!   nothing of it written — the operator's 2026-09-23 directive);
//! * derived rows written by the linked author AND by a non-linked agent, in
//!   `evidence`, `mass_functions`, `claim_versions` and `challenges`, plus
//!   writer-less rows (`reasoning_traces`, `claim_frames` — a composite key —
//!   `harvester_claim_provenance`), a harvester fragment shared with a held
//!   claim, and edges (one signed by the non-linked agent, one whose prior
//!   owner differs from both endpoints');
//! * a derived row whose prior owner DIFFERS from its claim's, so reversal must
//!   restore that row's own owner rather than re-propagate the claim's;
//! * a `recall_events` row, which is principal-scoped and must stay untouched.
//!
//! # What a snapshot is
//!
//! Every row of every table the re-own could reach, plus the control tables,
//! as `to_jsonb(row)::text`, sorted. `claims.updated_at` is removed from the
//! claims rows ONLY in the comparisons that span an apply: the
//! `claims_updated_at` trigger (migration 001) stamps `now()` on every claims
//! UPDATE, which neither the re-own nor its reversal can prevent. Every other
//! column of every row is compared byte for byte.

mod viewer_fixture;

use sqlx::PgPool;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const WORLD: Uuid = Uuid::nil();

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

/// Run the binary with ONLY the dedicated DSN variable pointing at `pool`'s
/// database. `DATABASE_URL` and `MAINTENANCE_DATABASE_URL` are removed, so a
/// run that succeeds did not reach the database through either of them.
async fn run_op(pool: &PgPool, args: &[&str]) -> Run {
    let url = fixture::database_url_for(pool).await;
    run_with_env(
        args,
        &[(DSN_ENV, url.as_str())],
        &["DATABASE_URL", "MAINTENANCE_DATABASE_URL"],
    )
}

fn run_with_env(args: &[&str], set: &[(&str, &str)], remove: &[&str]) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env("RUST_LOG", "warn");
    for r in remove {
        cmd.env_remove(r);
    }
    for (k, v) in set {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn scratch_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("operator-reown-{}", Uuid::new_v4()));
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
    target: Uuid,
    retired: Uuid,
    retired_group: Uuid,
    actor: Uuid,
    actor_group: Uuid,
    stranger: Uuid,
    stranger_group: Uuid,
    unlinked: Uuid,
    third_group: Uuid,
    frame: Uuid,
    c_world: Uuid,
    c_personal: Uuid,
    c_actor: Uuid,
    c_third: Uuid,
    c_unlinked: Uuid,
    c_private: Uuid,
    missing: Uuid,
    ev_r: Uuid,
    ev_w: Uuid,
    ev_null: Uuid,
    ev_personal: Uuid,
    ev_private: Uuid,
    trace: Uuid,
    mf_w: Uuid,
    mf_r: Uuid,
    mf_w_personal: Uuid,
    cv_w: Uuid,
    challenge_w: Uuid,
    frag: Uuid,
    edge_plain: Uuid,
    edge_w: Uuid,
    edge_prior: Uuid,
    recall: Uuid,
}

async fn exec(pool: &PgPool, sql: &str) {
    sqlx::query(sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

async fn claim(pool: &PgPool, author: Uuid, owner: Uuid, text: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             owner_group_id, visibility) \
         VALUES ($1, $2, $3, 0.7, $4, true, $5, 'public')",
    )
    .bind(id)
    .bind(text)
    .bind(h32(id))
    .bind(author)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn evidence(pool: &PgPool, claim: Uuid, signer: Option<Uuid>, text: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, claim_id, evidence_type, content_hash, raw_content, \
                               signer_id, signature) \
         VALUES ($1, $2, 'document', $3, $4, $5, CASE WHEN $5::uuid IS NULL THEN NULL \
                 ELSE decode(repeat('ab', 64), 'hex') END)",
    )
    .bind(id)
    .bind(claim)
    .bind(h32(id))
    .bind(text)
    .bind(signer)
    .execute(pool)
    .await
    .expect("seed evidence");
    id
}

async fn mass_function(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"a\": 1.0}') RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed mass function")
}

async fn signed_edge(pool: &PgPool, source: Uuid, target: Uuid, signer: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            signer_id, signature) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports', $4, decode(repeat('cd', 64), 'hex'))",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(signer)
    .execute(pool)
    .await
    .expect("seed signed edge");
    id
}

async fn seed(pool: &PgPool) -> Fx {
    let (operator, target) = fixture::seed_agent_with_group(pool, "operator").await;
    let (retired, retired_group) = fixture::seed_agent_with_group(pool, "retired").await;
    let (actor, actor_group) = fixture::seed_agent_with_group(pool, "actor").await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(pool, "stranger").await;
    let (unlinked, _) = fixture::seed_agent_with_group(pool, "unlinked").await;
    let (_, third_group) = fixture::seed_agent_with_group(pool, "third").await;

    sqlx::query("SELECT * FROM epigraph_link_retired_agent($1, $2)")
        .bind(retired)
        .bind(operator)
        .execute(pool)
        .await
        .expect("retired link");
    sqlx::query("SELECT * FROM epigraph_link_operator($1, $2)")
        .bind(actor)
        .bind(operator)
        .execute(pool)
        .await
        .expect("actor link");

    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, owner_group_id, visibility) \
         VALUES ('reown-frame', ARRAY['a','b'], $1, 'public') RETURNING id",
    )
    .bind(WORLD)
    .fetch_one(pool)
    .await
    .expect("seed frame");

    let c_world = claim(pool, retired, WORLD, "retired author, world-owned").await;
    let c_personal = claim(pool, retired, retired_group, "retired author, own group").await;
    let c_actor = claim(pool, actor, actor_group, "actor author, own group").await;
    let c_third = claim(pool, retired, third_group, "retired author, third group").await;
    let c_unlinked = claim(pool, unlinked, WORLD, "unlinked author").await;
    let c_private = claim(pool, retired, WORLD, "public claim, private evidence").await;
    let missing = Uuid::new_v4();

    let ev_r = evidence(
        pool,
        c_world,
        Some(retired),
        "evidence signed by the retired author",
    )
    .await;
    let ev_w = evidence(
        pool,
        c_world,
        Some(stranger),
        "evidence signed by a stranger",
    )
    .await;
    let ev_null = evidence(pool, c_world, None, "unsigned evidence").await;
    let ev_personal = evidence(
        pool,
        c_personal,
        Some(retired),
        "evidence on the personal claim",
    )
    .await;
    let ev_private = evidence(pool, c_private, None, "group-private evidence").await;
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(ev_private)
        .bind(retired_group)
        .execute(pool)
        .await
        .expect("make ev_private group-private");

    let trace = fixture::seed_reasoning_trace(pool, c_world, "deductive").await;
    let mf_w = mass_function(pool, c_world, frame, stranger).await;
    let mf_r = mass_function(pool, c_personal, frame, retired).await;
    let mf_w_personal = mass_function(pool, c_personal, frame, stranger).await;
    let cv_w: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, created_by) \
         VALUES ($1, 1, 'v1', 0.5, $2) RETURNING id",
    )
    .bind(c_world)
    .bind(stranger)
    .fetch_one(pool)
    .await
    .expect("seed claim version");
    let challenge_w: Uuid = sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation) \
         VALUES ($1, $2, 'factual', 'a stranger disputes it') RETURNING id",
    )
    .bind(c_world)
    .bind(stranger)
    .fetch_one(pool)
    .await
    .expect("seed challenge");
    sqlx::query("INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2)")
        .bind(c_world)
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
    for c in [c_world, c_unlinked] {
        sqlx::query(
            "INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)",
        )
        .bind(c)
        .bind(frag)
        .execute(pool)
        .await
        .expect("seed provenance");
    }

    let edge_plain = fixture::seed_edge(pool, c_world, c_personal).await;
    let edge_w = signed_edge(pool, c_world, c_actor, stranger).await;
    let edge_prior =
        fixture::seed_edge_owned_by(pool, c_world, c_third, "public", retired_group).await;

    let recall: Uuid = sqlx::query_scalar(
        "INSERT INTO recall_events (agent_id, tool, query_text, returned_claim_ids, \
                                    owner_group_id, visibility) \
         VALUES ($1, 'recall', 'what did I say', ARRAY[$2]::uuid[], $3, 'group') RETURNING id",
    )
    .bind(retired)
    .bind(c_world)
    .bind(retired_group)
    .fetch_one(pool)
    .await
    .expect("seed recall event");

    // A derived row whose prior owner differs from its claim's: reversal must
    // give it THIS owner back, not the claim's. LAST, on purpose: migration
    // 070's insert arm re-syncs EVERY evidence row of a claim to the claim on
    // each new evidence insert for it, so an earlier divergence would already
    // have been undone by the inserts above.
    sqlx::query("UPDATE evidence SET owner_group_id = $2 WHERE id = $1")
        .bind(ev_w)
        .bind(stranger_group)
        .execute(pool)
        .await
        .expect("diverge ev_w");

    Fx {
        operator,
        target,
        retired,
        retired_group,
        actor,
        actor_group,
        stranger,
        stranger_group,
        unlinked,
        third_group,
        frame,
        c_world,
        c_personal,
        c_actor,
        c_third,
        c_unlinked,
        c_private,
        missing,
        ev_r,
        ev_w,
        ev_null,
        ev_personal,
        ev_private,
        trace,
        mf_w,
        mf_r,
        mf_w_personal,
        cv_w,
        challenge_w,
        frag,
        edge_plain,
        edge_w,
        edge_prior,
        recall,
    }
}

fn claims_file(dir: &std::path::Path, fx: &Fx) -> PathBuf {
    let p = dir.join("claims.txt");
    let body = [
        fx.c_world,
        fx.c_personal,
        fx.c_actor,
        fx.c_third,
        fx.c_unlinked,
        fx.c_private,
        fx.missing,
    ]
    .iter()
    .map(ToString::to_string)
    .collect::<Vec<_>>()
    .join("\n");
    std::fs::write(&p, format!("# reown fixture\n{body}\n")).expect("claims file");
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
    "recall_events",
    "groups",
    "group_memberships",
    "operator_links",
    "agents",
    "frames",
];

/// Every row of [`SNAP_TABLES`]. With `strip_updated_at`, `claims.updated_at`
/// is removed from claims rows (see the module doc); nothing else ever is.
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

async fn tenancy(pool: &PgPool, table: &str, id: Uuid) -> (Uuid, String) {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, visibility::text FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} {id}: {e}"))
}

async fn tenancy_where(pool: &PgPool, table: &str, cond: &str, id: Uuid) -> (Uuid, String) {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, visibility::text FROM {table} WHERE {cond}"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} where {cond}: {e}"))
}

fn public(g: Uuid) -> (Uuid, String) {
    (g, "public".to_string())
}

async fn reown(
    pool: &PgPool,
    dir: &std::path::Path,
    fx: &Fx,
    derived: &str,
    manifest: &str,
    apply: bool,
) -> Run {
    let cf = claims_file(dir, fx);
    let mf = dir.join(manifest);
    let op = fx.operator.to_string();
    let mut args = vec![
        "reown-claims",
        "--claims-file",
        cf.to_str().unwrap(),
        "--operator",
        &op,
        "--derived",
        derived,
        "--manifest-out",
        mf.to_str().unwrap(),
        "--batch-size",
        "2",
    ];
    if apply {
        args.push("--apply");
    }
    run_op(pool, &args).await
}

async fn reverse(pool: &PgPool, manifest: &std::path::Path, apply: bool) -> Run {
    let mut args = vec![
        "reown-reverse",
        "--manifest",
        manifest.to_str().unwrap(),
        "--batch-size",
        "2",
    ];
    if apply {
        args.push("--apply");
    }
    run_op(pool, &args).await
}

/// The held claims and everything of theirs that must never be written.
async fn assert_held_untouched(pool: &PgPool, fx: &Fx) {
    assert_eq!(
        tenancy(pool, "claims", fx.c_third).await,
        public(fx.third_group)
    );
    assert_eq!(tenancy(pool, "claims", fx.c_unlinked).await, public(WORLD));
    assert_eq!(tenancy(pool, "claims", fx.c_private).await, public(WORLD));
    assert_eq!(
        tenancy(pool, "evidence", fx.ev_private).await,
        (fx.retired_group, "group".to_string()),
        "the group-private evidence row must stay exactly where it was"
    );
    assert_eq!(
        tenancy(pool, "recall_events", fx.recall).await,
        (fx.retired_group, "group".to_string()),
        "recall_events is principal-scoped and must stay untouched"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The derived-table list cannot drift
// ─────────────────────────────────────────────────────────────────────────────

/// The tables `epigraph_propagate_tenancy` cascades to, parsed from the live
/// function body, are EXACTLY the tables `WRITER_COLUMNS` attributes. A
/// migration that adds a table to the trigger fails here until the new table's
/// writer rule is decided; one that removes a table fails here until the stale
/// entry is removed.
#[sqlx::test(migrations = "../../migrations")]
async fn every_propagated_table_has_a_writer_rule(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let specs = epigraph_cli::operator::tables::propagated_tables(&mut conn)
        .await
        .expect("the live cascade is fully attributed");
    let derived: std::collections::BTreeSet<String> = specs
        .iter()
        .filter(|s| s.kind == epigraph_cli::operator::tables::Kind::Derived)
        .map(|s| s.name.clone())
        .collect();
    let ruled: std::collections::BTreeSet<String> = epigraph_cli::operator::tables::WRITER_COLUMNS
        .iter()
        .map(|(t, _)| (*t).to_string())
        .collect();
    assert_eq!(derived, ruled);
    assert!(specs.iter().any(|s| s.name == "harvester_fragments"));
    assert!(specs.iter().any(|s| s.name == "edges"));
    let cf = specs.iter().find(|s| s.name == "claim_frames").unwrap();
    assert_eq!(
        cf.pk,
        vec!["claim_id", "frame_id"],
        "composite keys are read, not assumed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// reown-claims
// ─────────────────────────────────────────────────────────────────────────────

/// A dry run changes nothing, not even `claims.updated_at`, and creates no
/// manifest; it prints the plan, the held list with reasons, the spill and the
/// per-table "rows moved, all public before and after" lines.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_writes_nothing_and_reports_the_plan(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let before = snapshot(&pool, false).await;
    let r = reown(&pool, &dir, &fx, "follow-claim", "m.jsonl", false).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_same(&before, &snapshot(&pool, false).await, "dry run");
    assert!(
        !dir.join("m.jsonl").exists(),
        "a dry run writes no manifest"
    );

    let o = &r.stdout;
    assert!(
        o.contains("PLAN: 7 requested, 3 eligible, 4 held"),
        "{}",
        r.show()
    );
    assert!(
        o.contains(&format!("HELD\t{}\tnot found", fx.missing)),
        "{o}"
    );
    assert!(
        o.contains(&format!(
            "HELD\t{}\towned by group {}",
            fx.c_third, fx.third_group
        )),
        "{o}"
    );
    assert!(
        o.contains(&format!(
            "HELD\t{}\tauthor {} has no operator link",
            fx.c_unlinked, fx.unlinked
        )),
        "{o}"
    );
    assert!(
        o.contains(&format!(
            "HELD\t{}\tnon-public rows would move with it: evidence=1",
            fx.c_private
        )),
        "{o}"
    );
    assert!(o.contains(&format!("SPILL-WRITER\t{}", fx.stranger)), "{o}");
    assert!(o.contains("SHARED-FRAGMENTS\t1"), "{o}");
    assert!(
        o.contains("evidence: rows moved: 4, all public before and after"),
        "{o}"
    );
    assert!(o.contains("invariants: all held in every batch"), "{o}");
    assert!(o.contains("DRY RUN"), "{o}");
}

/// `--derived follow-claim`: every eligible claim and every row it carries
/// lands exactly where the plan says, visibility never changes, and nothing
/// held is touched.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_follow_claim_gives_exact_owners(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let r = reown(&pool, &dir, &fx, "follow-claim", "m.jsonl", true).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let t = fx.target;
    for c in [fx.c_world, fx.c_personal, fx.c_actor] {
        assert_eq!(tenancy(&pool, "claims", c).await, public(t));
    }
    for e in [fx.ev_r, fx.ev_w, fx.ev_null, fx.ev_personal] {
        assert_eq!(tenancy(&pool, "evidence", e).await, public(t));
    }
    for m in [fx.mf_w, fx.mf_r, fx.mf_w_personal] {
        assert_eq!(tenancy(&pool, "mass_functions", m).await, public(t));
    }
    assert_eq!(tenancy(&pool, "claim_versions", fx.cv_w).await, public(t));
    assert_eq!(
        tenancy(&pool, "challenges", fx.challenge_w).await,
        public(t)
    );
    assert_eq!(
        tenancy(&pool, "reasoning_traces", fx.trace).await,
        public(t)
    );
    assert_eq!(
        tenancy(&pool, "harvester_fragments", fx.frag).await,
        public(t)
    );
    assert_eq!(
        tenancy_where(&pool, "claim_frames", "claim_id = $1", fx.c_world).await,
        public(t)
    );
    // The held claim's provenance row of the SHARED fragment stays its own.
    assert_eq!(
        tenancy_where(
            &pool,
            "harvester_claim_provenance",
            "claim_id = $1",
            fx.c_unlinked
        )
        .await,
        public(WORLD)
    );
    // Edges take the trigger's meet: two public endpoints => world.
    for e in [fx.edge_plain, fx.edge_w, fx.edge_prior] {
        assert_eq!(tenancy(&pool, "edges", e).await, public(WORLD));
    }
    assert_held_untouched(&pool, &fx).await;
    assert!(r.stdout.contains("claims moved: 3"), "{}", r.show());
}

/// `--derived keep-writer`: rows written by the non-linked stranger keep their
/// prior owners (including one that differed from its claim's); rows by the
/// linked author, and writer-less rows, follow the claim.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_keep_writer_keeps_non_linked_rows(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let r = reown(&pool, &dir, &fx, "keep-writer", "m.jsonl", true).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let t = fx.target;
    assert_eq!(tenancy(&pool, "claims", fx.c_world).await, public(t));
    // Stranger-written: kept.
    assert_eq!(
        tenancy(&pool, "evidence", fx.ev_w).await,
        public(fx.stranger_group)
    );
    assert_eq!(
        tenancy(&pool, "mass_functions", fx.mf_w).await,
        public(WORLD)
    );
    assert_eq!(
        tenancy(&pool, "mass_functions", fx.mf_w_personal).await,
        public(fx.retired_group)
    );
    assert_eq!(
        tenancy(&pool, "claim_versions", fx.cv_w).await,
        public(WORLD)
    );
    assert_eq!(
        tenancy(&pool, "challenges", fx.challenge_w).await,
        public(WORLD)
    );
    // Linked-author and writer-less rows: follow.
    assert_eq!(tenancy(&pool, "evidence", fx.ev_r).await, public(t));
    assert_eq!(tenancy(&pool, "evidence", fx.ev_null).await, public(t));
    assert_eq!(tenancy(&pool, "evidence", fx.ev_personal).await, public(t));
    assert_eq!(tenancy(&pool, "mass_functions", fx.mf_r).await, public(t));
    assert_eq!(
        tenancy(&pool, "reasoning_traces", fx.trace).await,
        public(t)
    );
    // The stranger-signed edge's prior owner was world, which the meet also gives.
    assert_eq!(tenancy(&pool, "edges", fx.edge_w).await, public(WORLD));
    assert_held_untouched(&pool, &fx).await;
    assert!(
        r.stdout
            .contains("evidence: rows moved: 3, all public before and after (1 kept"),
        "{}",
        r.show()
    );
}

async fn apply_then_reverse_is_byte_for_byte(pool: PgPool, derived: &str) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let before = snapshot(&pool, true).await;
    let r = reown(&pool, &dir, &fx, derived, "m.jsonl", true).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let moved = snapshot(&pool, true).await;
    assert_ne!(
        moved["claims"], before["claims"],
        "the apply must have moved something"
    );

    let rv = reverse(&pool, &dir.join("m.jsonl"), true).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert!(rv.stdout.contains("claims restored: 3"), "{}", rv.show());
    assert_same(&before, &snapshot(&pool, true).await, "apply then reverse");

    // A second reversal is a no-op: nothing changes, not even updated_at.
    let settled = snapshot(&pool, false).await;
    let rv2 = reverse(&pool, &dir.join("m.jsonl"), true).await;
    assert_eq!(rv2.code, 0, "{}", rv2.show());
    assert!(rv2.stdout.contains("claims restored: 0"), "{}", rv2.show());
    assert_same(&settled, &snapshot(&pool, false).await, "second reverse");
}

/// `follow-claim` → reverse restores every row byte for byte, including the
/// evidence row whose prior owner differed from its claim's and the edge whose
/// prior owner was neither endpoint's.
#[sqlx::test(migrations = "../../migrations")]
async fn follow_claim_apply_then_reverse_restores_every_row(pool: PgPool) {
    apply_then_reverse_is_byte_for_byte(pool, "follow-claim").await;
}

/// The same for `keep-writer`.
#[sqlx::test(migrations = "../../migrations")]
async fn keep_writer_apply_then_reverse_restores_every_row(pool: PgPool) {
    apply_then_reverse_is_byte_for_byte(pool, "keep-writer").await;
}

/// A dry-run reversal changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_reverse_writes_nothing(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let r = reown(&pool, &dir, &fx, "follow-claim", "m.jsonl", true).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let moved = snapshot(&pool, false).await;
    let rv = reverse(&pool, &dir.join("m.jsonl"), false).await;
    assert_eq!(rv.code, 0, "{}", rv.show());
    assert!(rv.stdout.contains("claims restored: 3"), "{}", rv.show());
    assert_same(&moved, &snapshot(&pool, false).await, "dry-run reverse");
}

/// A second apply moves nothing, and a manifest is never overwritten.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rerun_is_a_noop(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let r = reown(&pool, &dir, &fx, "follow-claim", "m1.jsonl", true).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let first = std::fs::read_to_string(dir.join("m1.jsonl")).unwrap();
    let settled = snapshot(&pool, false).await;

    let again = reown(&pool, &dir, &fx, "follow-claim", "m1.jsonl", true).await;
    assert_eq!(
        again.code,
        1,
        "an existing manifest must be refused: {}",
        again.show()
    );
    assert!(again.stderr.contains("must not exist"), "{}", again.show());
    assert_eq!(
        std::fs::read_to_string(dir.join("m1.jsonl")).unwrap(),
        first
    );

    let r2 = reown(&pool, &dir, &fx, "follow-claim", "m2.jsonl", true).await;
    assert_eq!(r2.code, 0, "{}", r2.show());
    assert!(r2.stdout.contains("0 eligible"), "{}", r2.show());
    assert!(
        r2.stdout.contains("3 already owned by the target"),
        "{}",
        r2.show()
    );
    assert!(r2.stdout.contains("claims moved: 0"), "{}", r2.show());
    assert_same(&settled, &snapshot(&pool, false).await, "re-run");
}

/// The manifest is written before the first write and holds one record per
/// claim and per derived row, each with ITS OWN prior tenancy.
#[sqlx::test(migrations = "../../migrations")]
async fn the_manifest_records_each_rows_own_prior_owner(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let r = reown(&pool, &dir, &fx, "follow-claim", "m.jsonl", true).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let text = std::fs::read_to_string(dir.join("m.jsonl")).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(lines[0].get("manifest").is_some(), "header first");
    let find = |table: &str, id: Uuid| {
        lines
            .iter()
            .find(|v| v["table"] == table && v["id"] == id.to_string())
            .unwrap_or_else(|| panic!("no record for {table} {id}"))
            .clone()
    };
    assert_eq!(
        find("claims", fx.c_world)["owner_group_id"],
        WORLD.to_string()
    );
    assert_eq!(
        find("claims", fx.c_personal)["owner_group_id"],
        fx.retired_group.to_string()
    );
    assert_eq!(
        find("evidence", fx.ev_w)["owner_group_id"],
        fx.stranger_group.to_string()
    );
    let edge = find("edges", fx.edge_prior);
    assert_eq!(edge["owner_group_id"], fx.retired_group.to_string());
    assert!(edge["co_owner_group_id"].is_null());
    assert!(find("evidence", fx.ev_r).get("co_owner_group_id").is_none());
    let cf = lines
        .iter()
        .find(|v| v["table"] == "claim_frames")
        .expect("composite-key record");
    assert_eq!(cf["id"]["claim_id"], fx.c_world.to_string());
    assert_eq!(cf["id"]["frame_id"], fx.frame.to_string());
    for v in &lines[1..] {
        assert_ne!(v["table"], "recall_events");
        if v["neighbour"] == true {
            // A NEIGHBOUR record observes the state of a claim that shares a
            // row with a moved one; it moves nothing and restores nothing.
            assert_eq!(v["after"], true, "{v}");
            continue;
        }
        for held in [fx.c_third, fx.c_unlinked, fx.c_private] {
            assert_ne!(
                v["claim_id"],
                held.to_string(),
                "a held claim was recorded: {v}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Invariant violations roll the batch back
// ─────────────────────────────────────────────────────────────────────────────

async fn assert_batch_rolls_back(pool: &PgPool, fx: &Fx, needle: &str) {
    let dir = scratch_dir();
    let before = snapshot(pool, false).await;
    let r = reown(pool, &dir, fx, "follow-claim", "m.jsonl", true).await;
    assert_eq!(r.code, 2, "{}", r.show());
    assert!(r.stdout.contains("ROLLED BACK"), "{}", r.show());
    assert!(r.stdout.contains(needle), "{}", r.show());
    assert!(r.stdout.contains("STOPPED"), "{}", r.show());
    assert_same(&before, &snapshot(pool, false).await, "rolled-back batch");
    assert!(
        dir.join("m.jsonl").exists(),
        "the manifest is written before the first write"
    );
}

/// A trigger that narrows evidence to `group` whenever its owner changes: the
/// visibility invariant must catch it and the batch must roll back whole.
#[sqlx::test(migrations = "../../migrations")]
async fn a_visibility_change_rolls_back_its_batch(pool: PgPool) {
    let fx = seed(&pool).await;
    exec(
        &pool,
        "CREATE FUNCTION test_narrow_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.owner_group_id IS DISTINCT FROM OLD.owner_group_id THEN \
         NEW.visibility := 'group'; END IF; RETURN NEW; END $$",
    )
    .await;
    exec(
        &pool,
        "CREATE TRIGGER test_narrow_evidence BEFORE UPDATE ON evidence \
         FOR EACH ROW EXECUTE FUNCTION test_narrow_evidence()",
    )
    .await;
    assert_batch_rolls_back(&pool, &fx, "visibility changed public -> group").await;
}

/// A trigger that writes a row OUTSIDE the eligible set — a principal-scoped
/// `recall_events` row — on every claims UPDATE: the transaction's row census
/// must catch it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_write_outside_the_set_rolls_back_its_batch(pool: PgPool) {
    let fx = seed(&pool).await;
    exec(
        &pool,
        "CREATE FUNCTION test_touch_recall() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN UPDATE recall_events SET query_text = query_text || '!'; RETURN NULL; END $$",
    )
    .await;
    exec(
        &pool,
        "CREATE TRIGGER test_touch_recall AFTER UPDATE ON claims \
         FOR EACH STATEMENT EXECUTE FUNCTION test_touch_recall()",
    )
    .await;
    assert_batch_rolls_back(&pool, &fx, "table recall_events").await;
}

/// The batch's `SELECT ... FOR UPDATE` is what excludes a concurrent derived
/// INSERT: that INSERT takes `FOR KEY SHARE` on its parent claim through the
/// foreign key, and the re-own's own `UPDATE claims SET owner_group_id` takes
/// only `FOR NO KEY UPDATE`, which does NOT conflict with it. So a second
/// transaction holding `FOR KEY SHARE` on a claim (exactly what an in-flight
/// evidence INSERT holds) must make the batch wait, hit `--lock-timeout`, and
/// roll back — which also proves the lock timeout is wired.
#[sqlx::test(migrations = "../../migrations")]
async fn a_concurrent_derived_insert_lock_blocks_the_batch(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let before = snapshot(&pool, false).await;
    let mut holder = pool.begin().await.expect("holder tx");
    sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR KEY SHARE")
        .bind(fx.c_world)
        .execute(&mut *holder)
        .await
        .expect("hold FOR KEY SHARE");
    let cf = claims_file(&dir, &fx);
    let mf = dir.join("m.jsonl");
    let op = fx.operator.to_string();
    let r = run_op(
        &pool,
        &[
            "reown-claims",
            "--claims-file",
            cf.to_str().unwrap(),
            "--operator",
            &op,
            "--derived",
            "follow-claim",
            "--manifest-out",
            mf.to_str().unwrap(),
            "--lock-timeout",
            "500ms",
            "--batch-size",
            "10",
            "--apply",
        ],
    )
    .await;
    holder.rollback().await.expect("release");
    assert_eq!(r.code, 2, "{}", r.show());
    assert!(r.stdout.contains("lock timeout"), "{}", r.show());
    assert!(r.stdout.contains("ROLLED BACK"), "{}", r.show());
    assert_same(
        &before,
        &snapshot(&pool, false).await,
        "lock-timed-out batch",
    );
}

/// An IN-FLIGHT insert into a cascade table with NO foreign key to `claims`
/// excludes the batch too (review finding: `FOR UPDATE` alone does not).
///
/// `claim_versions` has no key on `claim_id`, so its INSERT takes no lock on
/// the parent claim, and `FOR UPDATE` does not see it. Review measured the
/// consequence with a concurrent INSERT against a batch holding the claim: the
/// new row landed on the claim's OLD owner, and (with a divergent sibling row)
/// its statement-level inherit trigger rewrote a row the batch had moved and
/// verified, after the batch committed. The batch now takes SHARE ROW
/// EXCLUSIVE on every such table, so an uncommitted insert there makes it wait,
/// hit `--lock-timeout` and roll back; the insert then commits against a claim
/// that never moved, and the state is consistent.
#[sqlx::test(migrations = "../../migrations")]
async fn an_in_flight_insert_into_an_unkeyed_table_blocks_the_batch(pool: PgPool) {
    let fx = seed(&pool).await;
    let keyed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint \
          WHERE conrelid = 'public.claim_versions'::regclass AND contype = 'f' \
            AND confrelid = 'public.claims'::regclass)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !keyed,
        "PREMISE: claim_versions has no foreign key to claims; if it gains one, pick another \
         unkeyed table for this test"
    );
    let dir = scratch_dir();
    let cf = dir.join("one.txt");
    std::fs::write(&cf, format!("{}\n", fx.c_world)).unwrap();
    let mf = dir.join("m.jsonl");
    let op = fx.operator.to_string();

    let mut holder = pool.begin().await.expect("holder tx");
    let in_flight: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, created_by) \
         VALUES ($1, 7, 'in-flight v7', 0.5, $2) RETURNING id",
    )
    .bind(fx.c_world)
    .bind(fx.stranger)
    .fetch_one(&mut *holder)
    .await
    .expect("an uncommitted claim_versions insert");
    let r = run_op(
        &pool,
        &[
            "reown-claims",
            "--claims-file",
            cf.to_str().unwrap(),
            "--operator",
            &op,
            "--derived",
            "follow-claim",
            "--manifest-out",
            mf.to_str().unwrap(),
            "--lock-timeout",
            "500ms",
            "--apply",
        ],
    )
    .await;
    holder
        .commit()
        .await
        .expect("the writer commits after the batch");

    assert_eq!(
        r.code,
        2,
        "the batch ran while a claim_versions insert for its claim was in flight: that row lands \
         on the claim's OLD owner and is never moved: {}",
        r.show()
    );
    assert!(r.stdout.contains("lock timeout"), "{}", r.show());
    assert!(r.stdout.contains("LOCKED-PER-BATCH\t"), "{}", r.show());
    assert_eq!(
        tenancy(&pool, "claims", fx.c_world).await,
        public(WORLD),
        "the rolled-back batch moved nothing"
    );
    assert_eq!(
        tenancy(&pool, "claim_versions", in_flight).await,
        public(WORLD),
        "the committed insert agrees with its (unmoved) claim"
    );
}

/// A dry run holds no lock past its own batch (review finding: one transaction
/// with savepoints kept every batch's `FOR UPDATE` until the whole run ended,
/// because `RELEASE SAVEPOINT` keeps locks, so a large dry run against
/// production blocked application writers to every claim it had visited).
///
/// Batch 1 is `c_world`, batch 2 is `c_personal`. A second transaction holds
/// `FOR KEY SHARE` on `c_personal`, so the dry run's batch 2 waits on it. While
/// it waits, `c_world` — batch 1's claim — must be lockable `FOR UPDATE NOWAIT`
/// from outside: batch 1's transaction is already gone.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_holds_no_lock_past_its_batch(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let cf = dir.join("two.txt");
    std::fs::write(&cf, format!("{}\n{}\n", fx.c_world, fx.c_personal)).unwrap();
    let mf = dir.join("m.jsonl");
    let op = fx.operator.to_string();
    let url = fixture::database_url_for(&pool).await;

    let mut holder = pool.begin().await.expect("holder tx");
    sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR KEY SHARE")
        .bind(fx.c_personal)
        .execute(&mut *holder)
        .await
        .expect("hold batch 2's claim");
    let args: Vec<String> = [
        "reown-claims",
        "--claims-file",
        cf.to_str().unwrap(),
        "--operator",
        &op,
        "--derived",
        "follow-claim",
        "--manifest-out",
        mf.to_str().unwrap(),
        "--batch-size",
        "1",
        "--lock-timeout",
        "8s",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let run = tokio::task::spawn_blocking(move || {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        run_with_env(
            &a,
            &[(DSN_ENV, url.as_str())],
            &["DATABASE_URL", "MAINTENANCE_DATABASE_URL"],
        )
    });

    // Wait until the dry run is blocked in batch 2 on the holder.
    let mut waiting = false;
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
              WHERE datname = current_database() AND wait_event_type = 'Lock' \
                AND query ILIKE '%FOR UPDATE%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if n > 0 {
            waiting = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        waiting,
        "PREMISE: the dry run's batch 2 waits on the held claim"
    );

    let mut probe = pool.begin().await.expect("probe tx");
    let batch1 = sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR UPDATE NOWAIT")
        .bind(fx.c_world)
        .execute(&mut *probe)
        .await;
    probe.rollback().await.ok();
    holder.rollback().await.expect("release batch 2");
    let r = run.await.expect("join");

    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        batch1.is_ok(),
        "while the dry run sat in batch 2, batch 1's claim was still locked by it: {:?}",
        batch1.err()
    );
    assert!(
        r.stdout
            .contains("each batch above ran in its own transaction"),
        "{}",
        r.show()
    );
    assert!(!mf.exists(), "a dry run writes no manifest");
}

/// Two claims in two batches that SHARE rows: a fragment (provenance of both)
/// and an edge between them, whose tenancy batch 1 changes. The shared rows
/// are the review's P1 shape.
async fn shared_rows_fixture(pool: &PgPool) -> (Fx, Uuid) {
    let fx = seed(pool).await;
    sqlx::query("INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)")
        .bind(fx.c_personal)
        .bind(fx.frag)
        .execute(pool)
        .await
        .expect("share the fragment with c_personal");
    let e =
        fixture::seed_edge_owned_by(pool, fx.c_world, fx.c_personal, "public", fx.retired_group)
            .await;
    (fx, e)
}

fn ids_file(dir: &std::path::Path, name: &str, ids: &[Uuid]) -> PathBuf {
    let p = dir.join(name);
    let body: Vec<String> = ids.iter().map(ToString::to_string).collect();
    std::fs::write(&p, body.join("\n") + "\n").expect("ids file");
    p
}

async fn reown_ids(
    pool: &PgPool,
    fx: &Fx,
    claims: &std::path::Path,
    manifest: &std::path::Path,
    extra: &[&str],
) -> Run {
    let op = fx.operator.to_string();
    let mut args = vec![
        "reown-claims",
        "--claims-file",
        claims.to_str().unwrap(),
        "--operator",
        &op,
        "--derived",
        "follow-claim",
        "--manifest-out",
        manifest.to_str().unwrap(),
        "--batch-size",
        "1",
        "--apply",
    ];
    args.extend_from_slice(extra);
    run_op(pool, &args).await
}

/// A row ANOTHER writer changes between the plan and its batch holds the claim
/// (review finding: the manifest de-duplicates by key, so the row kept its
/// stale plan-time record, and a reversal would have restored the stale owner).
///
/// The run is made to wait in batch 2 on a `FOR KEY SHARE` held by a second
/// transaction, which meanwhile re-owns `ev_personal` (a row of batch 2's
/// claim) and commits. Batch 2 must then HOLD `c_personal` with "changed since
/// the plan", and leave the row where the other writer put it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_row_changed_by_another_writer_since_the_plan_holds_its_claim(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let cf = ids_file(&dir, "two.txt", &[fx.c_world, fx.c_personal]);
    let mf = dir.join("m.jsonl");
    let url = fixture::database_url_for(&pool).await;
    let op = fx.operator.to_string();

    let mut holder = pool.begin().await.expect("holder tx");
    sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR KEY SHARE")
        .bind(fx.c_personal)
        .execute(&mut *holder)
        .await
        .expect("hold batch 2's claim");
    let args: Vec<String> = [
        "reown-claims",
        "--claims-file",
        cf.to_str().unwrap(),
        "--operator",
        &op,
        "--derived",
        "follow-claim",
        "--manifest-out",
        mf.to_str().unwrap(),
        "--batch-size",
        "1",
        "--lock-timeout",
        "8s",
        "--apply",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let run = tokio::task::spawn_blocking(move || {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        run_with_env(
            &a,
            &[(DSN_ENV, url.as_str())],
            &["DATABASE_URL", "MAINTENANCE_DATABASE_URL"],
        )
    });
    let mut waiting = false;
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
              WHERE datname = current_database() AND wait_event_type = 'Lock' \
                AND query ILIKE '%FOR UPDATE%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if n > 0 {
            waiting = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(waiting, "PREMISE: the run waits in batch 2, after the plan");
    sqlx::query("UPDATE evidence SET owner_group_id = $2 WHERE id = $1")
        .bind(fx.ev_personal)
        .bind(fx.stranger_group)
        .execute(&mut *holder)
        .await
        .expect("another writer re-owns a row of batch 2's claim");
    holder.commit().await.expect("the other writer commits");
    let r = run.await.expect("join");

    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains(&format!(
            "HELD-UNDER-LOCK\t{}\tevidence {} changed since the plan",
            fx.c_personal, fx.ev_personal
        )),
        "a claim whose row changed since the plan must be held, not moved with a stale record: \
         {}",
        r.show()
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.c_personal).await,
        public(fx.retired_group),
        "the held claim did not move"
    );
    assert_eq!(
        tenancy(&pool, "evidence", fx.ev_personal).await,
        public(fx.stranger_group),
        "the other writer's change stands"
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.c_world).await,
        public(fx.target),
        "batch 1 was unaffected"
    );
}

/// The other direction: a shared row THIS run changed in an earlier batch is
/// expected, not "changed since the plan". Batch 1 (`c_world`) moves the shared
/// fragment and recomputes the shared edge's meet; batch 2 (`c_personal`) must
/// still move, and a reversal must restore every row byte-for-byte.
#[sqlx::test(migrations = "../../migrations")]
async fn a_row_this_run_moved_in_an_earlier_batch_is_not_a_false_hold(pool: PgPool) {
    let (fx, e) = shared_rows_fixture(&pool).await;
    let dir = scratch_dir();
    let before = snapshot(&pool, true).await;
    let prior_edge = tenancy(&pool, "edges", e).await;
    let mf = dir.join("m.jsonl");
    let r = reown_ids(
        &pool,
        &fx,
        &ids_file(&dir, "two.txt", &[fx.c_world, fx.c_personal]),
        &mf,
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        !r.stdout.contains("HELD-UNDER-LOCK"),
        "a row this run moved in batch 1 was mistaken for another writer's change: {}",
        r.show()
    );
    assert!(r.stdout.contains("claims moved: 2"), "{}", r.show());
    assert_ne!(
        tenancy(&pool, "edges", e).await,
        prior_edge,
        "PREMISE: the shared edge's tenancy changed during the run"
    );
    let r = reverse(&pool, &mf, true).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "reverse after two batches",
    );
}

async fn reverse_many(pool: &PgPool, manifests: &[&std::path::Path], apply: bool) -> Run {
    let mut args = vec!["reown-reverse", "--batch-size", "2"];
    for m in manifests {
        args.push("--manifest");
        args.push(m.to_str().unwrap());
    }
    if apply {
        args.push("--apply");
    }
    run_op(pool, &args).await
}

async fn manifests_in_one_reverse_restore_byte_for_byte(pool: PgPool, oldest_first_argv: bool) {
    let dir = scratch_dir();
    let (fx, _e) = shared_rows_fixture(&pool).await;
    let before = snapshot(&pool, true).await;
    let m1 = dir.join("m1.jsonl");
    let m2 = dir.join("m2.jsonl");
    let r = reown_ids(
        &pool,
        &fx,
        &ids_file(&dir, "a.txt", &[fx.c_world]),
        &m1,
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let r = reown_ids(
        &pool,
        &fx,
        &ids_file(&dir, "b.txt", &[fx.c_personal]),
        &m2,
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    let argv: [&std::path::Path; 2] = if oldest_first_argv {
        [&m1, &m2]
    } else {
        [&m2, &m1]
    };
    let r = reverse_many(&pool, &argv, true).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(!r.stdout.contains("HELD\t"), "{}", r.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "two manifests reversed in one invocation",
    );
}

/// Both manifests in ONE `reown-reverse`, given OLDEST first on the command
/// line: the tool orders them newest-first by header `created_at`, so the
/// shared rows come back byte-for-byte (review finding: in that order, as two
/// invocations, the fragment ended on the target and the edge on world, where
/// both had been on the retired author's group).
#[sqlx::test(migrations = "../../migrations")]
async fn two_manifests_in_one_reverse_restore_when_given_oldest_first(pool: PgPool) {
    manifests_in_one_reverse_restore_byte_for_byte(pool, true).await;
}

/// The same, given newest first.
#[sqlx::test(migrations = "../../migrations")]
async fn two_manifests_in_one_reverse_restore_when_given_newest_first(pool: PgPool) {
    manifests_in_one_reverse_restore_byte_for_byte(pool, false).await;
}

/// Reversing the OLDER manifest on its own, while a newer run's changes to
/// shared rows stand, HOLDS instead of restoring stale state: exit 3, the hold
/// names the cause, and nothing at all is written. Then the right order (M2,
/// then M1, as two invocations) restores everything byte-for-byte.
#[sqlx::test(migrations = "../../migrations")]
async fn reversing_an_older_manifest_alone_holds_and_writes_nothing(pool: PgPool) {
    let dir = scratch_dir();
    let (fx, _e) = shared_rows_fixture(&pool).await;
    let before = snapshot(&pool, true).await;
    let m1 = dir.join("m1.jsonl");
    let m2 = dir.join("m2.jsonl");
    assert_eq!(
        reown_ids(
            &pool,
            &fx,
            &ids_file(&dir, "a.txt", &[fx.c_world]),
            &m1,
            &[]
        )
        .await
        .code,
        0
    );
    assert_eq!(
        reown_ids(
            &pool,
            &fx,
            &ids_file(&dir, "b.txt", &[fx.c_personal]),
            &m2,
            &[]
        )
        .await
        .code,
        0
    );
    let moved = snapshot(&pool, false).await;

    let r = reverse(&pool, &m1, true).await;
    assert_eq!(
        r.code,
        3,
        "reversing M1 alone must HOLD, not restore rows a newer run moved: {}",
        r.show()
    );
    assert!(
        r.stdout.contains(&format!("HELD\t{}\t", fx.c_world))
            && r.stdout.contains("reverse that manifest first"),
        "{}",
        r.show()
    );
    assert_same(
        &moved,
        &snapshot(&pool, false).await,
        "a held reversal writes nothing, not even updated_at",
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.c_world).await,
        public(fx.target)
    );

    for m in [&m2, &m1] {
        let r = reverse(&pool, m, true).await;
        assert_eq!(r.code, 0, "{}", r.show());
    }
    assert_same(&before, &snapshot(&pool, true).await, "M2 then M1");
}

/// A STOPPED run and its resume (review probe P6). Batch 2 of run 1 times out on
/// a held `FOR KEY SHARE`, so M1's plan records BOTH claims while only
/// `c_world` moved; the resume moves `c_personal` into M2. M1 reversed alone
/// must neither touch `c_personal` (M1 never moved it) nor restore `c_world`
/// over the resumed run's shared rows; both manifests in one invocation, in
/// either argv order, restore byte-for-byte.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stopped_run_and_its_resume_reverse_safely(pool: PgPool) {
    let (fx, _e) = shared_rows_fixture(&pool).await;
    let dir = scratch_dir();
    let before = snapshot(&pool, true).await;
    let cf = ids_file(&dir, "ab.txt", &[fx.c_world, fx.c_personal]);
    let m1 = dir.join("m1.jsonl");
    let m2 = dir.join("m2.jsonl");
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR KEY SHARE")
        .bind(fx.c_personal)
        .execute(&mut *holder)
        .await
        .unwrap();
    let r = reown_ids(&pool, &fx, &cf, &m1, &["--lock-timeout", "500ms"]).await;
    holder.rollback().await.unwrap();
    assert_eq!(r.code, 2, "PREMISE: run 1 stops at batch 2: {}", r.show());
    let text = std::fs::read_to_string(&m1).unwrap();
    let priors = text
        .lines()
        .filter(|l| l.contains("\"table\":\"claims\"") && !l.contains("\"after\""))
        .count();
    let posts = text
        .lines()
        .filter(|l| {
            l.contains("\"table\":\"claims\"")
                && l.contains("\"after\"")
                && !l.contains("\"neighbour\"")
        })
        .count();
    assert_eq!(
        (priors, posts),
        (2, 1),
        "PREMISE: M1's plan records both claims, and its post records only the one it moved"
    );
    let r = reown_ids(&pool, &fx, &cf, &m2, &[]).await;
    assert_eq!(r.code, 0, "the resume: {}", r.show());
    let moved = snapshot(&pool, false).await;

    let r = reverse(&pool, &m1, true).await;
    assert_eq!(r.code, 3, "{}", r.show());
    assert!(
        r.stdout
            .contains("claims planned but never moved by their run (untouched): 1"),
        "{}",
        r.show()
    );
    assert_same(&moved, &snapshot(&pool, false).await, "M1 alone");

    let r = reverse_many(&pool, &[&m1, &m2], true).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "M1 + M2 in one reverse",
    );
}

/// A row can become unreadable to an unstamped application session without
/// its visibility column changing — here a RESTRICTIVE policy that hides rows
/// owned by the target group from `epigraph_app`. The readability census, taken
/// under `SET LOCAL SESSION AUTHORIZATION epigraph_app`, must catch it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_readability_loss_rolls_back_its_batch(pool: PgPool) {
    let fx = seed(&pool).await;
    exec(
        &pool,
        &format!(
            "CREATE POLICY test_hide_target ON evidence AS RESTRICTIVE FOR SELECT \
             TO epigraph_app USING (owner_group_id <> '{}')",
            fx.target
        ),
    )
    .await;
    assert_batch_rolls_back(
        &pool,
        &fx,
        "an unstamped epigraph_app session can read changed",
    )
    .await;
}

/// The operator's 2026-09-23 directive, alone: a public claim whose evidence
/// row is GROUP-private is held, and nothing at all is written — not the
/// claim, not the row, not a manifest record.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_private_evidence_row_holds_its_claim_and_nothing_is_written(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let cf = dir.join("one.txt");
    std::fs::write(&cf, format!("{}\n", fx.c_private)).unwrap();
    let mf = dir.join("m.jsonl");
    let op = fx.operator.to_string();
    let before = snapshot(&pool, false).await;
    let r = run_op(
        &pool,
        &[
            "reown-claims",
            "--claims-file",
            cf.to_str().unwrap(),
            "--operator",
            &op,
            "--derived",
            "follow-claim",
            "--manifest-out",
            mf.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains(&format!(
            "HELD\t{}\tnon-public rows would move with it: evidence=1",
            fx.c_private
        )),
        "{}",
        r.show()
    );
    assert!(r.stdout.contains("claims moved: 0"), "{}", r.show());
    assert_same(&before, &snapshot(&pool, false).await, "held claim");
    let recorded = std::fs::read_to_string(&mf).unwrap();
    assert_eq!(recorded.lines().count(), 1, "header only: {recorded}");
}

// ─────────────────────────────────────────────────────────────────────────────
// The connection
// ─────────────────────────────────────────────────────────────────────────────

fn with_user(url: &str, user: &str, pass: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials in DATABASE_URL");
    format!("{scheme}://{user}:{pass}@{host}")
}

/// Without the dedicated variable the tool refuses — even with `DATABASE_URL`
/// and `MAINTENANCE_DATABASE_URL` both pointing at a maintenance-capable
/// database — and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn it_never_falls_back_to_database_url(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let url = fixture::database_url_for(&pool).await;
    let before = snapshot(&pool, false).await;
    let cf = claims_file(&dir, &fx);
    let mf = dir.join("m.jsonl");
    let op = fx.operator.to_string();
    let r = run_with_env(
        &[
            "reown-claims",
            "--claims-file",
            cf.to_str().unwrap(),
            "--operator",
            &op,
            "--derived",
            "follow-claim",
            "--manifest-out",
            mf.to_str().unwrap(),
            "--apply",
        ],
        &[("DATABASE_URL", &url), ("MAINTENANCE_DATABASE_URL", &url)],
        &[DSN_ENV],
    );
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(
        r.stderr
            .contains("EPIGRAPH_OPERATOR_MAINTENANCE_DSN is not set"),
        "{}",
        r.show()
    );
    assert_same(&before, &snapshot(&pool, false).await, "refused run");
    assert!(!mf.exists());
}

/// A LOGIN role that is not a member of `epigraph_maintenance` is refused
/// before anything is read or written. Calibration: the SAME role, once
/// granted membership, gets past the check (and `reown-claims` then refuses
/// for the next reason — it cannot switch `session_user` for the readability
/// check — also before writing anything).
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_maintenance_role_is_refused(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let role = format!("reown_probe_{}", Uuid::new_v4().simple());
    exec(
        &pool,
        &format!("CREATE ROLE {role} LOGIN PASSWORD 'probe-only'"),
    )
    .await;
    let url = with_user(&fixture::database_url_for(&pool).await, &role, "probe-only");
    let agents = dir.join("agents.txt");
    std::fs::write(&agents, format!("{}\n", fx.stranger)).unwrap();
    let op = fx.operator.to_string();
    let link_args = [
        "link-retired",
        "--agents-file",
        agents.to_str().unwrap(),
        "--operator",
        &op,
        "--apply",
    ];
    let before = snapshot(&pool, false).await;

    let r = run_with_env(&link_args, &[(DSN_ENV, &url)], &["DATABASE_URL"]);
    let refused = r.code == 1 && r.stderr.contains("is not a member of epigraph_maintenance");

    exec(&pool, &format!("GRANT epigraph_maintenance TO {role}")).await;
    let dry = [
        "link-retired",
        "--agents-file",
        agents.to_str().unwrap(),
        "--operator",
        &op,
    ];
    let calibrated = run_with_env(&dry, &[(DSN_ENV, &url)], &["DATABASE_URL"]);
    let cf = claims_file(&dir, &fx);
    let mf = dir.join("m.jsonl");
    let no_switch = run_with_env(
        &[
            "reown-claims",
            "--claims-file",
            cf.to_str().unwrap(),
            "--operator",
            &op,
            "--derived",
            "follow-claim",
            "--manifest-out",
            mf.to_str().unwrap(),
            "--apply",
        ],
        &[(DSN_ENV, &url)],
        &["DATABASE_URL"],
    );
    exec(&pool, &format!("REVOKE epigraph_maintenance FROM {role}")).await;
    exec(&pool, &format!("DROP ROLE {role}")).await;

    assert!(refused, "{}", r.show());
    assert_eq!(calibrated.code, 0, "{}", calibrated.show());
    assert!(
        calibrated.stdout.contains("LINKED-RETIRED"),
        "{}",
        calibrated.show()
    );
    assert_eq!(no_switch.code, 1, "{}", no_switch.show());
    assert!(
        no_switch.stderr.contains("SESSION AUTHORIZATION"),
        "{}",
        no_switch.show()
    );
    assert!(!mf.exists(), "refused before the manifest");
    assert_same(&before, &snapshot(&pool, false).await, "refused runs");
}

// ─────────────────────────────────────────────────────────────────────────────
// link-retired
// ─────────────────────────────────────────────────────────────────────────────

/// Dry run: the function's real outcome per id, rolled back. Apply: a retired
/// row and no membership; a second apply is ALREADY-RETIRED; a self-link is
/// refused with the function's own message and exit code 3.
#[sqlx::test(migrations = "../../migrations")]
async fn link_retired_dry_run_apply_and_refusal(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let (fresh, _) = fixture::seed_agent_with_group(&pool, "fresh-retiree").await;
    let agents = dir.join("agents.txt");
    std::fs::write(&agents, format!("{fresh}\n{}\n", fx.operator)).unwrap();
    let op = fx.operator.to_string();
    let args = |apply: bool| {
        let mut a = vec![
            "link-retired".to_string(),
            "--agents-file".into(),
            agents.to_str().unwrap().into(),
            "--operator".into(),
            op.clone(),
        ];
        if apply {
            a.push("--apply".into());
        }
        a
    };
    let before = snapshot(&pool, false).await;
    let dry_args = args(false);
    let dry = run_op(
        &pool,
        &dry_args.iter().map(String::as_str).collect::<Vec<_>>(),
    )
    .await;
    assert_eq!(dry.code, 3, "{}", dry.show());
    assert!(
        dry.stdout.contains(&format!("{fresh}\tLINKED-RETIRED")),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout.contains("cannot be its own operator"),
        "{}",
        dry.show()
    );
    assert_same(
        &before,
        &snapshot(&pool, false).await,
        "link-retired dry run",
    );

    let apply_args = args(true);
    let apply_args: Vec<&str> = apply_args.iter().map(String::as_str).collect();
    let r = run_op(&pool, &apply_args).await;
    assert_eq!(r.code, 3, "{}", r.show());
    let row: (Uuid, bool) =
        sqlx::query_as("SELECT operator_id, retired FROM operator_links WHERE agent_id = $1")
            .bind(fresh)
            .fetch_one(&pool)
            .await
            .expect("retired row");
    assert_eq!(row, (fx.operator, true));
    let memberships: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(fx.target)
    .bind(fresh)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(memberships, 0, "a retired link creates no membership");

    let again = run_op(&pool, &apply_args).await;
    assert!(
        again.stdout.contains(&format!("{fresh}\tALREADY-RETIRED")),
        "{}",
        again.show()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Opt-in evidence hiding (Amendment 2): selectors, preview and refusals
// ─────────────────────────────────────────────────────────────────────────────

async fn evidence_typed(pool: &PgPool, claim: Uuid, ty: &str, labels: &[&str], text: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, claim_id, evidence_type, content_hash, raw_content, labels) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(claim)
    .bind(ty)
    .bind(h32(id))
    .bind(text)
    .bind(labels.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    .execute(pool)
    .await
    .expect("seed typed evidence");
    id
}

struct HideFx {
    fx: Fx,
    ev_testimony: Uuid,
    ev_labelled: Uuid,
    stray: Uuid,
    dir: PathBuf,
    claims: PathBuf,
    ids: PathBuf,
}

const LONG_TESTIMONY: &str = "A witness statement that runs well past eighty characters,\n\
                              with a line break inside it, so the preview must cut and flatten it.";

async fn hide_fixture(pool: &PgPool) -> HideFx {
    let fx = seed(pool).await;
    let ev_testimony = evidence_typed(pool, fx.c_world, "testimony", &[], LONG_TESTIMONY).await;
    let ev_labelled = evidence_typed(
        pool,
        fx.c_personal,
        "document",
        &["private"],
        "labelled private",
    )
    .await;
    let stray = Uuid::new_v4();
    let dir = scratch_dir();
    let claims = dir.join("hide-claims.txt");
    std::fs::write(
        &claims,
        format!(
            "{}\n{}\n{}\n{}\n",
            fx.c_world, fx.c_personal, fx.c_unlinked, fx.c_private
        ),
    )
    .unwrap();
    let ids = dir.join("hide-ids.txt");
    // ev_private is already group-private: selected, and left as it is.
    std::fs::write(&ids, format!("{}\n{stray}\n", fx.ev_private)).unwrap();
    HideFx {
        fx,
        ev_testimony,
        ev_labelled,
        stray,
        dir,
        claims,
        ids,
    }
}

async fn hide_run(pool: &PgPool, h: &HideFx, extra: &[&str]) -> Run {
    let op = h.fx.operator.to_string();
    let mut args = vec![
        "hide-evidence",
        "--claims-file",
        h.claims.to_str().unwrap(),
        "--operator",
        &op,
        "--hide-evidence-type",
        "testimony",
        "--hide-evidence-label",
        "private",
        "--hide-evidence-ids",
        h.ids.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run_op(pool, &args).await
}

/// The dry run of `hide-evidence` reports per-type and per-claim counts and an
/// 80-character, single-line preview of every selected row; selectors are a
/// union; an id outside scope and a claim that is not the operator's are
/// reported; and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn hide_evidence_dry_run_previews_and_writes_nothing(pool: PgPool) {
    let h = hide_fixture(&pool).await;
    let before = snapshot(&pool, false).await;
    let r = hide_run(&pool, &h, &[]).await;
    assert_eq!(r.code, 0, "{}", r.show());
    let o = &r.stdout;
    assert!(
        o.contains("HIDE-PLAN: 2 evidence row(s) would become visibility=group")
            && o.contains("(1 selected row(s) already not public"),
        "{}",
        r.show()
    );
    assert!(o.contains("HIDE-TYPE\ttestimony\t1"), "{o}");
    assert!(o.contains("HIDE-TYPE\tdocument\t1"), "{o}");
    assert!(
        o.contains(&format!("HIDE-CLAIM\t{}\t1", h.fx.c_world)),
        "{o}"
    );
    assert!(
        o.contains(&format!("HIDE-CLAIM\t{}\t1", h.fx.c_personal)),
        "{o}"
    );
    let flat: String = LONG_TESTIMONY
        .chars()
        .take(80)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    assert!(
        o.contains(&format!(
            "HIDE\t{}\t{}\ttestimony\t{flat}\n",
            h.ev_testimony, h.fx.c_world
        )),
        "{o}"
    );
    assert!(o.contains(&format!("HIDE\t{}\t", h.ev_labelled)), "{o}");
    assert!(
        o.contains(&format!("HIDE-OUT-OF-SCOPE\t{}", h.stray)),
        "{o}"
    );
    assert!(
        o.contains(&format!("HELD\t{}\tneither owned", h.fx.c_unlinked)),
        "{o}"
    );
    assert!(o.contains("DRY RUN: nothing was written"), "{o}");
    assert!(!o.contains("HIDING WILL NOT BE ENFORCED"), "{o}");
    assert_same(&before, &snapshot(&pool, false).await, "hide dry run");
}

/// `--apply` needs `--confirm-hide <N>` equal to the planned count, and then
/// refuses because the kernel guard that keeps a hidden row hidden is absent
/// from this schema. Nothing is written on any of the three.
#[sqlx::test(migrations = "../../migrations")]
async fn hide_apply_requires_the_confirm_count_and_the_kernel_guard(pool: PgPool) {
    let h = hide_fixture(&pool).await;
    let before = snapshot(&pool, false).await;
    let none = hide_run(&pool, &h, &["--apply"]).await;
    assert_eq!(none.code, 1, "{}", none.show());
    assert!(
        none.stderr.contains("requires --confirm-hide 2"),
        "{}",
        none.show()
    );
    let wrong = hide_run(&pool, &h, &["--apply", "--confirm-hide", "3"]).await;
    assert_eq!(wrong.code, 1, "{}", wrong.show());
    assert!(
        wrong
            .stderr
            .contains("does not match the planned hidden-row count 2"),
        "{}",
        wrong.show()
    );
    let right = hide_run(&pool, &h, &["--apply", "--confirm-hide", "2"]).await;
    assert_eq!(right.code, 1, "{}", right.show());
    assert!(
        right
            .stderr
            .contains("kernel guard that keeps a hidden row hidden"),
        "{}",
        right.show()
    );
    assert_same(&before, &snapshot(&pool, false).await, "refused hides");
}

/// Can an UNSTAMPED `epigraph_app` session read evidence row `ev`?
async fn app_reads_evidence(pool: &PgPool, ev: Uuid) -> i64 {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL SESSION AUTHORIZATION epigraph_app")
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence WHERE id = $1")
        .bind(ev)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    n
}

/// B-H4. A stand-in for production's orphan `evidence_privacy`: a PERMISSIVE
/// always-true SELECT policy. First the measurement that makes it matter — an
/// unstamped `epigraph_app` session reads the group-private evidence row with
/// it and not without it. Then: the dry run warns loudly, `--apply` refuses
/// without `--accept-unenforced-hide`, and with it gets past that check to the
/// next refusal.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unenforced_hide_is_detected_warned_and_refused(pool: PgPool) {
    let h = hide_fixture(&pool).await;
    assert_eq!(app_reads_evidence(&pool, h.fx.ev_private).await, 0);
    exec(
        &pool,
        "CREATE POLICY evidence_privacy ON evidence AS PERMISSIVE FOR SELECT USING (true)",
    )
    .await;
    assert_eq!(
        app_reads_evidence(&pool, h.fx.ev_private).await,
        1,
        "the stand-in must defeat group visibility, or this test proves nothing"
    );

    let before = snapshot(&pool, false).await;
    let dry = hide_run(&pool, &h, &[]).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains("WARNING: HIDING WILL NOT BE ENFORCED")
            && dry.stdout.contains("evidence_privacy"),
        "{}",
        dry.show()
    );
    let refused = hide_run(&pool, &h, &["--apply", "--confirm-hide", "2"]).await;
    assert_eq!(refused.code, 1, "{}", refused.show());
    assert!(
        refused.stderr.contains("--accept-unenforced-hide"),
        "{}",
        refused.show()
    );
    let accepted = hide_run(
        &pool,
        &h,
        &["--apply", "--confirm-hide", "2", "--accept-unenforced-hide"],
    )
    .await;
    assert_eq!(accepted.code, 1, "{}", accepted.show());
    assert!(
        accepted.stderr.contains("kernel guard")
            && !accepted.stderr.contains("--accept-unenforced-hide"),
        "past the policy check, the guard refuses: {}",
        accepted.show()
    );
    assert_same(&before, &snapshot(&pool, false).await, "unenforced hide");
}

/// `reown-claims` with a hide selector: the dry run prints the hide plan and
/// still runs the re-own (without the hide); `--apply` refuses BEFORE the
/// manifest and before any write, so it never runs half of what it was asked.
#[sqlx::test(migrations = "../../migrations")]
async fn reown_with_hide_flags_previews_and_refuses_apply_before_writing(pool: PgPool) {
    let h = hide_fixture(&pool).await;
    let cf = claims_file(&h.dir, &h.fx);
    let mf = h.dir.join("m.jsonl");
    let op = h.fx.operator.to_string();
    let base = [
        "reown-claims",
        "--claims-file",
        cf.to_str().unwrap(),
        "--operator",
        &op,
        "--derived",
        "follow-claim",
        "--manifest-out",
        mf.to_str().unwrap(),
        "--hide-evidence-type",
        "testimony",
    ];
    let before = snapshot(&pool, false).await;
    let dry = run_op(&pool, &base).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains("HIDE-PLAN: 1 evidence row(s)"),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout.contains(&format!("HIDE\t{}", h.ev_testimony)),
        "{}",
        dry.show()
    );
    assert!(dry.stdout.contains("HIDE: not simulated"), "{}", dry.show());
    assert!(dry.stdout.contains("claims moved: 3"), "{}", dry.show());

    let mut apply: Vec<&str> = base.to_vec();
    apply.extend_from_slice(&["--apply", "--confirm-hide", "1"]);
    let r = run_op(&pool, &apply).await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("kernel guard"), "{}", r.show());
    assert!(!mf.exists(), "refused before the manifest");
    assert_same(
        &before,
        &snapshot(&pool, false).await,
        "refused hide re-own",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// reown-reverse checks itself too, and the target group must be the operator's
// ─────────────────────────────────────────────────────────────────────────────

/// `reown-reverse` runs its own copy of the batch invariants. A trigger that
/// writes a principal-scoped `recall_events` row on every claims UPDATE — a
/// row outside the set — must make the reversal's census fail and roll the
/// batch back, leaving the post-apply state exactly as it was.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reverse_that_writes_outside_the_set_rolls_back(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    let r = reown(&pool, &dir, &fx, "follow-claim", "m.jsonl", true).await;
    assert_eq!(r.code, 0, "{}", r.show());
    exec(
        &pool,
        "CREATE FUNCTION test_touch_recall() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN UPDATE recall_events SET query_text = query_text || '!'; RETURN NULL; END $$",
    )
    .await;
    exec(
        &pool,
        "CREATE TRIGGER test_touch_recall AFTER UPDATE ON claims \
         FOR EACH STATEMENT EXECUTE FUNCTION test_touch_recall()",
    )
    .await;
    let moved = snapshot(&pool, false).await;
    let rv = reverse(&pool, &dir.join("m.jsonl"), true).await;
    assert_eq!(rv.code, 2, "{}", rv.show());
    assert!(rv.stdout.contains("ROLLED BACK"), "{}", rv.show());
    assert!(rv.stdout.contains("table recall_events"), "{}", rv.show());
    assert!(rv.stdout.contains("STOPPED"), "{}", rv.show());
    assert_same(&moved, &snapshot(&pool, false).await, "rolled-back reverse");
}

/// The target is refused unless it is a `personal` group the operator itself
/// created — the creator test branch A applies to operator groups. A group
/// carrying the operator's did_key but created by someone else is a squat, and
/// nothing is written: no manifest, no row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_squatted_target_group_is_refused(pool: PgPool) {
    let fx = seed(&pool).await;
    let dir = scratch_dir();
    sqlx::query("UPDATE groups SET created_by_agent_id = $2 WHERE id = $1")
        .bind(fx.target)
        .bind(fx.stranger)
        .execute(&pool)
        .await
        .expect("make the target a squat (superuser: 103 admits a maintenance session)");
    let before = snapshot(&pool, false).await;
    let r = reown(&pool, &dir, &fx, "follow-claim", "m.jsonl", true).await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(
        r.stderr
            .contains("not a personal group created by the operator"),
        "{}",
        r.show()
    );
    assert!(!dir.join("m.jsonl").exists(), "refused before the manifest");
    assert_same(&before, &snapshot(&pool, false).await, "squatted target");
}
