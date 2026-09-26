//! `epigraph-operator reown-seed` (backlog 0512ca33) and `strip-label` /
//! `strip-label-reverse` (backlog f6310444), driven through the real binary
//! against a `#[sqlx::test]` database migrated 001 → head.
//!
//! # The reown-seed fixture
//!
//! Claims owned by migration 074's seed group, as the superuser-DSN escape
//! hatch left them (declared explicitly here, so the fixture does not depend
//! on whether the harness role holds a grant of `epigraph_seed`), with every
//! owner derivation the tool distinguishes:
//!
//! * an author with its own personal group → that group, and the claim's
//!   evidence (seed-owned by inheritance) follows it;
//! * an ACTING operated author and a RETIRED one → the operator's group;
//! * an author whose personal-group row is revoked → HELD;
//! * an author with NO personal group → HELD, and nothing is provisioned;
//! * a listed claim NOT owned by the seed group → HELD;
//! * an edge between two seed claims whose derived owners differ, so the two
//!   per-target manifests share a row and must reverse together;
//! * a seed-owned ROOT row (a frame) no claim carries → counted, untouched.

mod viewer_fixture;

use sqlx::PgPool;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const SEED: Uuid = Uuid::from_u128(0xdead);
const BAD_LABEL: &str = "group:$EPICLAW_GROUP_ID";

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
        .env(DSN_ENV, url)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn scratch_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("operator-repair-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

fn h32(seed: Uuid) -> Vec<u8> {
    seed.as_bytes().iter().copied().cycle().take(32).collect()
}

async fn claim_owned(pool: &PgPool, author: Uuid, owner: Uuid, labels: &[&str]) -> Uuid {
    let id = Uuid::new_v4();
    let labels: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             owner_group_id, visibility, labels) \
         VALUES ($1, $2, $3, 0.6, $4, true, $5, 'public', $6)",
    )
    .bind(id)
    .bind(format!("claim {id}"))
    .bind(h32(id))
    .bind(author)
    .bind(owner)
    .bind(&labels)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn evidence(pool: &PgPool, claim: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, $2, 'document', $3, 'evidence text')",
    )
    .bind(id)
    .bind(claim)
    .bind(h32(id))
    .execute(pool)
    .await
    .expect("seed evidence");
    id
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

fn public(g: Uuid) -> (Uuid, String) {
    (g, "public".to_string())
}

const SNAP_TABLES: &[&str] = &[
    "claims",
    "evidence",
    "edges",
    "frames",
    "groups",
    "group_memberships",
    "operator_links",
    "agents",
];

/// Every row of [`SNAP_TABLES`] as `to_jsonb(row)::text`, sorted.
/// `claims.updated_at` is removed only where a comparison spans a write: the
/// `claims_updated_at` trigger stamps it on every claims UPDATE.
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

// ─────────────────────────────────────────────────────────────────────────────
// reown-seed
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct Fx {
    plain_group: Uuid,
    operator_group: Uuid,
    c_plain: Uuid,
    ev_plain: Uuid,
    c_actor: Uuid,
    c_retired: Uuid,
    c_revoked: Uuid,
    c_orphan: Uuid,
    orphan: Uuid,
    c_not_seed: Uuid,
    edge: Uuid,
    frame: Uuid,
}

async fn seed_fixture(pool: &PgPool) -> Fx {
    let (plain, plain_group) = fixture::seed_agent_with_group(pool, "plain").await;
    let (operator, operator_group) = fixture::seed_agent_with_group(pool, "operator").await;
    let (actor, _) = fixture::seed_agent_with_group(pool, "actor").await;
    let (retired, _) = fixture::seed_agent_with_group(pool, "retired").await;
    let (revoked, _) = fixture::seed_agent_with_group(pool, "revoked").await;
    sqlx::query("SELECT * FROM epigraph_link_operator($1, $2)")
        .bind(actor)
        .bind(operator)
        .execute(pool)
        .await
        .expect("actor link");
    sqlx::query("SELECT * FROM epigraph_link_retired_agent($1, $2)")
        .bind(retired)
        .bind(operator)
        .execute(pool)
        .await
        .expect("retired link");
    sqlx::query("UPDATE group_memberships SET revoked_at = now() WHERE agent_id = $1")
        .bind(revoked)
        .execute(pool)
        .await
        .expect("revoke");
    let orphan = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(orphan)
        .bind(h32(orphan))
        .execute(pool)
        .await
        .expect("orphan agent (no personal group)");

    let c_plain = claim_owned(pool, plain, SEED, &[]).await;
    let ev_plain = evidence(pool, c_plain).await;
    let c_actor = claim_owned(pool, actor, SEED, &[]).await;
    let c_retired = claim_owned(pool, retired, SEED, &[]).await;
    let c_revoked = claim_owned(pool, revoked, SEED, &[]).await;
    let c_orphan = claim_owned(pool, orphan, SEED, &[]).await;
    let c_not_seed = claim_owned(pool, plain, plain_group, &[]).await;
    let edge = fixture::seed_edge(pool, c_plain, c_actor).await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, owner_group_id, visibility) \
         VALUES ('seed-owned root', ARRAY['a','b'], $1, 'public') RETURNING id",
    )
    .bind(SEED)
    .fetch_one(pool)
    .await
    .expect("seed-owned frame");

    Fx {
        plain_group,
        operator_group,
        c_plain,
        ev_plain,
        c_actor,
        c_retired,
        c_revoked,
        c_orphan,
        orphan,
        c_not_seed,
        edge,
        frame,
    }
}

async fn reown_seed(pool: &PgPool, dir: &Path, claims: Option<&Path>, apply: bool) -> Run {
    let d = dir.to_str().unwrap().to_string();
    let mut args = vec![
        "reown-seed",
        "--manifest-dir",
        d.as_str(),
        "--batch-size",
        "2",
    ];
    let cf;
    if let Some(p) = claims {
        cf = p.to_str().unwrap().to_string();
        args.push("--claims-file");
        args.push(cf.as_str());
    }
    if apply {
        args.push("--apply");
    }
    run_op(pool, &args).await
}

fn manifests_in(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    v.sort();
    v
}

#[sqlx::test(migrations = "../../migrations")]
async fn reown_seed_dry_run_writes_nothing_and_reports_the_plan(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    let dir = scratch_dir();
    let before = snapshot(&pool, false).await;
    let r = reown_seed(&pool, &dir, None, false).await;
    assert_eq!(r.code, 3, "held claims make the exit code 3\n{}", r.show());
    assert_same(&before, &snapshot(&pool, false).await, "a dry run");
    assert!(
        manifests_in(&dir).is_empty(),
        "a dry run writes no manifest"
    );
    for want in [
        "DRY-RUN".to_string(),
        "SEED-OWNED\tclaims\t5".to_string(),
        "SEED-OWNED\tevidence\t1".to_string(),
        "SEED-OWNED\tframes\t1".to_string(),
        format!("TARGET\t{}\t1 claim(s)", fx.plain_group),
        format!("TARGET\t{}\t2 claim(s)", fx.operator_group),
        format!("HELD\t{}", fx.c_revoked),
        format!("HELD\t{}", fx.c_orphan),
    ] {
        assert!(
            r.stdout.contains(&want),
            "stdout lacks {want:?}\n{}",
            r.show()
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn reown_seed_apply_moves_each_claim_to_its_derived_owner(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    let dir = scratch_dir();
    let groups_before: i64 = sqlx::query_scalar("SELECT count(*) FROM groups")
        .fetch_one(&pool)
        .await
        .unwrap();
    let members_before: i64 = sqlx::query_scalar("SELECT count(*) FROM group_memberships")
        .fetch_one(&pool)
        .await
        .unwrap();

    let r = reown_seed(&pool, &dir, None, true).await;
    assert_eq!(r.code, 3, "two claims are held\n{}", r.show());
    assert!(r.stdout.contains("invariants: all held"), "{}", r.show());

    assert_eq!(
        tenancy(&pool, "claims", fx.c_plain).await,
        public(fx.plain_group)
    );
    assert_eq!(
        tenancy(&pool, "evidence", fx.ev_plain).await,
        public(fx.plain_group),
        "the evidence inherited the seed group from its claim and must follow it"
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.c_actor).await,
        public(fx.operator_group)
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.c_retired).await,
        public(fx.operator_group),
        "a RETIRED author's claims are its operator's (the ownership read)"
    );
    assert_eq!(tenancy(&pool, "claims", fx.c_revoked).await, public(SEED));
    assert_eq!(tenancy(&pool, "claims", fx.c_orphan).await, public(SEED));
    assert_eq!(
        tenancy(&pool, "frames", fx.frame).await,
        public(SEED),
        "a seed-owned root no claim carries is counted, never moved"
    );
    let groups_after: i64 = sqlx::query_scalar("SELECT count(*) FROM groups")
        .fetch_one(&pool)
        .await
        .unwrap();
    let members_after: i64 = sqlx::query_scalar("SELECT count(*) FROM group_memberships")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        (groups_after, members_after),
        (groups_before, members_before),
        "reown-seed must never provision a group or a membership (the orphan author has none)"
    );
    assert_eq!(manifests_in(&dir).len(), 2, "one manifest per target group");
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn reown_seed_then_reverse_restores_every_row(pool: PgPool) {
    let _fx = seed_fixture(&pool).await;
    let dir = scratch_dir();
    let before = snapshot(&pool, true).await;
    let r = reown_seed(&pool, &dir, None, true).await;
    assert_eq!(r.code, 3, "{}", r.show());
    let ms = manifests_in(&dir);
    assert_eq!(ms.len(), 2);
    let mut args = vec!["reown-reverse".to_string()];
    for m in &ms {
        args.push("--manifest".into());
        args.push(m.to_str().unwrap().into());
    }
    args.push("--apply".into());
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let rr = run_op(&pool, &argv).await;
    assert_eq!(rr.code, 0, "{}", rr.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "reown-seed then reown-reverse over both manifests",
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn reown_seed_holds_a_listed_claim_the_seed_group_does_not_own(pool: PgPool) {
    let fx = seed_fixture(&pool).await;
    let dir = scratch_dir();
    let cf = dir.join("claims.txt");
    std::fs::write(&cf, format!("{}\n{}\n", fx.c_not_seed, fx.c_plain)).unwrap();
    let mdir = dir.join("m");
    std::fs::create_dir_all(&mdir).unwrap();
    let r = reown_seed(&pool, &mdir, Some(&cf), true).await;
    assert_eq!(r.code, 3, "{}", r.show());
    assert!(
        r.stdout.contains(&format!(
            "HELD\t{}\towned by group {}",
            fx.c_not_seed, fx.plain_group
        )),
        "{}",
        r.show()
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.c_plain).await,
        public(fx.plain_group)
    );
    assert_eq!(
        tenancy(&pool, "claims", fx.c_actor).await,
        public(SEED),
        "an unlisted claim is not touched when a list is given"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ─────────────────────────────────────────────────────────────────────────────
// strip-label
// ─────────────────────────────────────────────────────────────────────────────

async fn labels_of(pool: &PgPool, id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn owned(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| (*s).to_string()).collect()
}

struct LabelFx {
    both: Uuid,
    once: Uuid,
    clean: Uuid,
}

async fn label_fixture(pool: &PgPool) -> LabelFx {
    let (agent, group) = fixture::seed_agent_with_group(pool, "labels").await;
    // Out of alphabetical order and with the bad value twice, so a sort or a
    // de-duplication of the array (what update_labels does) is visible.
    let both = claim_owned(
        pool,
        agent,
        group,
        &["zeta", BAD_LABEL, "alpha", BAD_LABEL, "mu"],
    )
    .await;
    let once = claim_owned(pool, agent, group, &[BAD_LABEL, "b", "b"]).await;
    let clean = claim_owned(pool, agent, group, &["zeta", "alpha"]).await;
    LabelFx { both, once, clean }
}

#[sqlx::test(migrations = "../../migrations")]
async fn strip_label_dry_run_writes_nothing(pool: PgPool) {
    let fx = label_fixture(&pool).await;
    let dir = scratch_dir();
    let mf = dir.join("strip.jsonl");
    let before = snapshot(&pool, false).await;
    let r = run_op(
        &pool,
        &["strip-label", "--manifest-out", mf.to_str().unwrap()],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains("PLAN: 2 claim(s) carry it"),
        "{}",
        r.show()
    );
    assert!(r.stdout.contains(&fx.both.to_string()), "{}", r.show());
    assert_same(
        &before,
        &snapshot(&pool, false).await,
        "a strip-label dry run",
    );
    assert!(!mf.exists(), "a dry run writes no manifest");
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn strip_label_removes_only_that_value_and_reverses_exactly(pool: PgPool) {
    let fx = label_fixture(&pool).await;
    let dir = scratch_dir();
    let mf = dir.join("strip.jsonl");
    let before = snapshot(&pool, true).await;

    let r = run_op(
        &pool,
        &[
            "strip-label",
            "--manifest-out",
            mf.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert_eq!(
        labels_of(&pool, fx.both).await,
        owned(&["zeta", "alpha", "mu"]),
        "every occurrence goes, every other label keeps its place (no sort, no de-dup)"
    );
    assert_eq!(labels_of(&pool, fx.once).await, owned(&["b", "b"]));
    assert_eq!(labels_of(&pool, fx.clean).await, owned(&["zeta", "alpha"]));
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE $1 = ANY(labels)")
        .bind(BAD_LABEL)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);

    let rr = run_op(
        &pool,
        &[
            "strip-label-reverse",
            "--manifest",
            mf.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(rr.code, 0, "{}", rr.show());
    assert_same(
        &before,
        &snapshot(&pool, true).await,
        "strip-label then strip-label-reverse",
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn strip_label_reverse_holds_a_claim_changed_since(pool: PgPool) {
    let fx = label_fixture(&pool).await;
    let dir = scratch_dir();
    let mf = dir.join("strip.jsonl");
    let r = run_op(
        &pool,
        &[
            "strip-label",
            "--manifest-out",
            mf.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.show());
    sqlx::query("UPDATE claims SET labels = array_append(labels, 'later') WHERE id = $1")
        .bind(fx.once)
        .execute(&pool)
        .await
        .unwrap();
    let rr = run_op(
        &pool,
        &[
            "strip-label-reverse",
            "--manifest",
            mf.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(
        rr.code,
        3,
        "a held claim makes the exit code 3\n{}",
        rr.show()
    );
    assert!(
        rr.stdout.contains(&format!("HELD\t{}", fx.once)),
        "{}",
        rr.show()
    );
    assert_eq!(labels_of(&pool, fx.once).await, owned(&["b", "b", "later"]));
    assert_eq!(
        labels_of(&pool, fx.both).await,
        owned(&["zeta", BAD_LABEL, "alpha", BAD_LABEL, "mu"]),
        "the untouched claim is still restored"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn strip_label_refuses_a_label_the_write_path_accepts(pool: PgPool) {
    let fx = label_fixture(&pool).await;
    let dir = scratch_dir();
    let mf = dir.join("strip.jsonl");
    let r = run_op(
        &pool,
        &[
            "strip-label",
            "--label",
            "zeta",
            "--manifest-out",
            mf.to_str().unwrap(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("refusing"), "{}", r.show());
    assert_eq!(labels_of(&pool, fx.clean).await, owned(&["zeta", "alpha"]));
    assert!(!mf.exists());
    std::fs::remove_dir_all(&dir).ok();
}
