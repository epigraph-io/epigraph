//! `recompute_betp` cohort v2: reviewed waves over evidenced atoms, with a
//! mandatory snapshot, a disk gate before every batch, a drift decomposition
//! from snapshot S0, and an accepted-vacate path (atom-level belief program,
//! SPEC §10.3 order of operations, §10.4 gates and drift decomposition, §10.5
//! residue and vacate path, §10.7 the held apply, §10.8 rollback).
//!
//! Every test drives the real binary as a separate process with a cleared
//! environment, against a fixture `/health` (SPEC §10.2 mode check), exactly
//! as an operator runs a wave. Claim caches are compared against sentinels no
//! fold here can produce, or against what a real run actually left in the
//! database, never against a value this file computes by the fold's own
//! formula.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::belief_cache::{read_cache_columns, read_snapshot, read_wave};

const RECOMPUTE_BETP: &str = env!("CARGO_BIN_EXE_recompute_betp");
const SNAPSHOT: &str = env!("CARGO_BIN_EXE_belief_snapshot");
const RESTORE: &str = env!("CARGO_BIN_EXE_restore_belief_cache");

// ── processes ──────────────────────────────────────────────────────────────

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn ok(&self, what: &str) {
        assert_eq!(
            self.code,
            Some(0),
            "{what}: expected exit 0\nstdout: {}\nstderr: {}",
            self.stdout,
            self.stderr
        );
    }
}

/// Run `bin` with ONLY the given environment (plus `PATH`), from `cwd`.
fn run(bin: &str, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(bin);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "warn")
        .args(args)
        .current_dir(cwd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run the binary");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn scratch_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("recompute-betp-wave-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

fn s(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

/// The modes a server reports, with `atom_fold` set to `fold`.
fn modes(fold: &str) -> serde_json::Value {
    serde_json::json!({
        "atom_fold": fold,
        "compound_belief": "legacy",
        "compound_write_guard": "warn",
        "compound_source_edges": "frozen",
        "atom_cache_mode": "display",
        "inference": "off",
        "bp_apply": "off",
    })
}

/// Serve a `/health` reporting `modes(fold)` on a loopback port, forever.
fn fixture_health(fold: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let addr = listener.local_addr().expect("fixture address");
    let payload = serde_json::json!({
        "status": "healthy",
        "version": "0.0.0-fixture",
        "timestamp": "2026-01-01T00:00:00Z",
        "belief_modes": modes(fold),
    })
    .to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let mut head = Vec::new();
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

/// The environment of a writing run whose modes agree with the server's:
/// both run `fold`.
struct WaveEnv {
    db: String,
    api: String,
    fold: &'static str,
}

impl WaveEnv {
    async fn new(pool: &PgPool, fold: &'static str) -> Self {
        Self {
            db: fixture::database_url_for(pool).await,
            api: fixture_health(fold),
            fold,
        }
    }

    fn vars(&self) -> Vec<(&str, &str)> {
        vec![
            ("DATABASE_URL", self.db.as_str()),
            ("EPIGRAPH_API_URL", self.api.as_str()),
            ("EPIGRAPH_ATOM_FOLD", self.fold),
        ]
    }
}

/// The flags every real wave run carries apart from the one under test.
fn real_run_args<'a>(role: &'a str, wave_file: &'a str, dir: &'a str) -> Vec<&'a str> {
    vec![
        "--role",
        role,
        "--snapshot",
        wave_file,
        "--wave",
        "test-wave",
        "--disk-path",
        dir,
        "--min-free-gb",
        "0",
        "--disk-check-cmd",
        "true",
    ]
}

// ── seeding ────────────────────────────────────────────────────────────────

async fn agent(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test']) \
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// An agent registered as the `workflow-ingest` system agent (migration 148):
/// the only author whose `source_type: workflow` root stamp makes a tree
/// procedural (the property alone is caller-set). Planted with triggers off
/// (one per test database: the role is the registry's primary key).
async fn workflow_ingest_agent(pool: &PgPool, name: &str) -> Uuid {
    let id = agent(pool, name).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    sqlx::query(
        "INSERT INTO public.system_agents (role, agent_id, registered_public_key, reason) \
         SELECT 'workflow-ingest', a.id, a.public_key, 'cohort-v2 test plant' \
           FROM public.agents a WHERE a.id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("plant the workflow-ingest system agent");
    tx.commit().await.expect("commit");
    id
}

/// Get-or-create a two-hypothesis frame by name (`frames.name` is UNIQUE).
async fn frame(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query(
        "INSERT INTO frames (name, description, hypotheses) \
         VALUES ($1, 'cohort v2 test frame', ARRAY['TRUE', 'FALSE']) \
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(name)
    .execute(pool)
    .await
    .expect("insert frame");
    sqlx::query_scalar("SELECT id FROM frames WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("frame by name")
}

async fn claim(pool: &PgPool, owner: Uuid, what: &str) -> Uuid {
    let content = format!("{what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(&content)
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// An evidence row on `claim`, with an optional DOI in its properties.
async fn evidence(pool: &PgPool, claim: Uuid, doi: Option<&str>) -> Uuid {
    let props = match doi {
        Some(d) => serde_json::json!({ "doi": d }),
        None => serde_json::json!({}),
    };
    sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, properties) \
         VALUES ($1, 'observation', sha256(gen_random_uuid()::text::bytea), $2) RETURNING id",
    )
    .bind(claim)
    .bind(props)
    .fetch_one(pool)
    .await
    .expect("seed evidence")
}

/// One BBA row, shaped by its stored columns only.
struct Row<'a> {
    frame: Uuid,
    source: Option<Uuid>,
    masses: serde_json::Value,
    method: Option<&'a str>,
    source_strength: Option<f64>,
    evidence_type: Option<&'a str>,
    evidence_id: Option<Uuid>,
    perspective_id: Option<Uuid>,
}

async fn insert_row(pool: &PgPool, claim: Uuid, row: &Row<'_>) -> Uuid {
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) \
         VALUES ($1, $2, 0) ON CONFLICT DO NOTHING",
    )
    .bind(claim)
    .bind(row.frame)
    .execute(pool)
    .await
    .expect("assign claim to frame");
    sqlx::query_scalar(
        "INSERT INTO mass_functions \
           (claim_id, frame_id, source_agent_id, masses, conflict_k, combination_method, \
            source_strength, evidence_type, locality_tag, evidence_id, perspective_id) \
         VALUES ($1, $2, $3, $4, 0.0, $5, $6, $7, 'unknown', $8, $9) RETURNING id",
    )
    .bind(claim)
    .bind(row.frame)
    .bind(row.source)
    .bind(&row.masses)
    .bind(row.method)
    .bind(row.source_strength)
    .bind(row.evidence_type)
    .bind(row.evidence_id)
    .bind(row.perspective_id)
    .fetch_one(pool)
    .await
    .expect("insert BBA")
}

/// A substantive, support-leaning evidence row.
fn evidence_row(frame: Uuid, source: Uuid, support: f64, evidence: Option<Uuid>) -> Row<'static> {
    Row {
        frame,
        source: Some(source),
        masses: serde_json::json!({ "0": support, "0,1": 1.0 - support }),
        method: Some("auto_wire"),
        source_strength: Some(0.9),
        evidence_type: Some("empirical"),
        evidence_id: evidence,
        perspective_id: None,
    }
}

/// The ingest template's shape (SPEC §10.5 residue): `research_validity`, no
/// combination method, source strength 0.3, 0.9 of the mass on the frame.
fn template_row(research_validity: Uuid, ingest: Uuid) -> Row<'static> {
    Row {
        frame: research_validity,
        source: Some(ingest),
        masses: serde_json::json!({ "0": 0.1, "0,1": 0.9 }),
        method: None,
        source_strength: Some(0.3),
        evidence_type: None,
        evidence_id: None,
        perspective_id: None,
    }
}

async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '2 days')",
    )
    .bind(parent)
    .bind(child)
    .execute(pool)
    .await
    .expect("seed decomposes_to edge");
}

/// Every cache column a writer owns on `claims`.
#[derive(Debug, Clone, PartialEq)]
struct Cache {
    belief: Option<f64>,
    plausibility: Option<f64>,
    pignistic_prob: Option<f64>,
    mass_on_empty: Option<f64>,
    mass_on_missing: Option<f64>,
    belief_frame_id: Option<Uuid>,
    classification: Option<String>,
}

async fn cache(pool: &PgPool, claim: Uuid) -> Cache {
    use sqlx::Row as _;
    let r = sqlx::query(
        "SELECT belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing, \
                belief_frame_id, classification \
           FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the claim's cache");
    Cache {
        belief: r.get("belief"),
        plausibility: r.get("plausibility"),
        pignistic_prob: r.get("pignistic_prob"),
        mass_on_empty: r.get("mass_on_empty"),
        mass_on_missing: r.get("mass_on_missing"),
        belief_frame_id: r.get("belief_frame_id"),
        classification: r.get("classification"),
    }
}

/// Put a cache on `claim` that no fold here can produce, recorded on `frame`.
/// `nudge` keeps sentinels of different claims apart.
async fn set_sentinel(pool: &PgPool, claim: Uuid, frame: Uuid, nudge: f64) -> Cache {
    sqlx::query(
        "UPDATE claims SET belief = 0.213 + $3, plausibility = 0.887 - $3, \
                pignistic_prob = 0.641 + $3, mass_on_empty = 0.017, mass_on_missing = 0.029, \
                belief_frame_id = $2, classification = 'sentinel' \
          WHERE id = $1",
    )
    .bind(claim)
    .bind(frame)
    .bind(nudge)
    .execute(pool)
    .await
    .expect("set the sentinel cache");
    cache(pool, claim).await
}

/// A fingerprint of every belief-bearing row a wave could write.
async fn belief_state(pool: &PgPool) -> (String, String, String) {
    let one = |sql: &'static str| async move {
        sqlx::query_scalar::<_, Option<String>>(sql)
            .fetch_one(pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .unwrap_or_default()
    };
    (
        one(
            "SELECT md5(string_agg(concat_ws('|', id, belief, plausibility, mass_on_empty, \
             pignistic_prob, mass_on_missing, open_world_mass, belief_frame_id, classification), \
             ',' ORDER BY id)) FROM claims",
        )
        .await,
        one("SELECT md5(string_agg(t::text, ',' ORDER BY t::text)) FROM mass_functions t").await,
        one("SELECT md5(string_agg(t::text, ',' ORDER BY t::text)) FROM ds_combined_beliefs t")
            .await,
    )
}

async fn binary_truth_id(pool: &PgPool) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM frames WHERE name = 'binary_truth'")
        .fetch_optional(pool)
        .await
        .expect("binary_truth by name")
}

/// The claim ids of a dry-run report (one JSON object per line).
fn report_lines(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("report line {l}: {e}")))
        .collect()
}

fn report_ids(path: &Path) -> HashSet<Uuid> {
    report_lines(path)
        .iter()
        .map(|v| {
            v["claim_id"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("claim_id in {v}"))
        })
        .collect()
}

/// Take a snapshot with the `belief_snapshot` binary.
fn take_snapshot(db: &str, dir: &Path, name: &str) -> PathBuf {
    let out = dir.join(name);
    let r = run(SNAPSHOT, dir, &["--out", s(&out)], &[("DATABASE_URL", db)]);
    r.ok("belief_snapshot");
    out
}

/// A dry wave run of `role` under `target`, from `s0`, into a report file.
fn dry_wave(db: &str, dir: &Path, role: &str, target: &str, s0: &Path) -> PathBuf {
    let report = dir.join(format!("report-{role}-{}.jsonl", Uuid::new_v4()));
    let r = run(
        RECOMPUTE_BETP,
        dir,
        &[
            "--dry-run",
            "--role",
            role,
            "--target-fold",
            target,
            "--s0",
            s(s0),
            "--report",
            s(&report),
        ],
        &[("DATABASE_URL", db)],
    );
    r.ok(&format!("dry wave --role {role} --target-fold {target}"));
    report
}

// ── (1) the wave cohort ─────────────────────────────────────────────────────

/// SPEC §10.7: the wave cohort is current, non-compound, non-procedural
/// claims with a non-empty AEF input (P1). A claim whose only input is the
/// ingest template has no AEF input, so it is never in a wave, for either
/// role; the evidenced claims of the same role are (the control). Each of
/// the other predicates keeps out a claim that HAS AEF input: a superseded
/// claim, a procedural root, a top-level and a mid-level compound.
#[sqlx::test(migrations = "../../migrations")]
async fn a_template_only_atom_is_never_in_the_wave_cohort(pool: PgPool) {
    let dir = scratch_dir();
    let db = fixture::database_url_for(&pool).await;
    let owner = agent(&pool, "cohort-owner").await;
    let ingest = agent(&pool, "cohort-ingest").await;
    let source = agent(&pool, "cohort-source").await;
    let rv = frame(&pool, "research_validity").await;
    let bin = frame(&pool, "cohort_v2_binary").await;

    let template_standalone = claim(&pool, owner, "template-only standalone").await;
    insert_row(&pool, template_standalone, &template_row(rv, ingest)).await;
    set_sentinel(&pool, template_standalone, rv, 0.0).await;
    let evidenced_standalone = claim(&pool, owner, "evidenced standalone").await;
    insert_row(
        &pool,
        evidenced_standalone,
        &evidence_row(bin, source, 0.7, None),
    )
    .await;

    let parent = claim(&pool, owner, "compound").await;
    let template_leaf = claim(&pool, owner, "template-only leaf").await;
    let evidenced_leaf = claim(&pool, owner, "evidenced leaf").await;
    decomposes_to(&pool, parent, template_leaf).await;
    decomposes_to(&pool, parent, evidenced_leaf).await;
    insert_row(&pool, template_leaf, &template_row(rv, ingest)).await;
    set_sentinel(&pool, template_leaf, rv, 0.01).await;
    insert_row(&pool, evidenced_leaf, &evidence_row(bin, source, 0.6, None)).await;
    // The compound carries its own BBA: it is not in any cohort either.
    insert_row(&pool, parent, &evidence_row(bin, source, 0.8, None)).await;

    // Evidenced claims the cohort's other predicates keep out: a superseded
    // claim, a procedural root (a workflow tree's thesis), and a MID-level
    // compound (decomposed from a parent, and decomposing into a leaf).
    let superseded = claim(&pool, owner, "evidenced but superseded").await;
    insert_row(&pool, superseded, &evidence_row(bin, source, 0.7, None)).await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(superseded)
        .execute(&pool)
        .await
        .expect("supersede");
    // A workflow root is procedural only when the registered workflow-ingest
    // system agent authored it; the stamp alone is caller-set.
    let workflow_ingest = workflow_ingest_agent(&pool, "cohort-workflow-ingest").await;
    let procedural = claim(&pool, workflow_ingest, "evidenced workflow thesis").await;
    insert_row(&pool, procedural, &evidence_row(bin, source, 0.7, None)).await;
    sqlx::query(
        "UPDATE claims SET properties = '{\"source_type\": \"workflow\"}'::jsonb WHERE id = $1",
    )
    .bind(procedural)
    .execute(&pool)
    .await
    .expect("stamp the workflow root");
    let top = claim(&pool, owner, "top compound").await;
    let mid = claim(&pool, owner, "evidenced mid-level compound").await;
    let deep_leaf = claim(&pool, owner, "evidenced leaf under the mid compound").await;
    decomposes_to(&pool, top, mid).await;
    decomposes_to(&pool, mid, deep_leaf).await;
    insert_row(&pool, mid, &evidence_row(bin, source, 0.7, None)).await;
    insert_row(&pool, deep_leaf, &evidence_row(bin, source, 0.65, None)).await;

    let s0 = take_snapshot(&db, &dir, "s0.jsonl");
    let standalone = report_ids(&dry_wave(&db, &dir, "standalone", "aef_standalone", &s0));
    let leaf = report_ids(&dry_wave(&db, &dir, "leaf", "aef", &s0));

    assert!(
        standalone.contains(&evidenced_standalone),
        "the evidenced standalone is in the standalone wave: {standalone:?}"
    );
    assert!(
        leaf.contains(&evidenced_leaf) && leaf.contains(&deep_leaf),
        "the evidenced leaves are in the leaf wave: {leaf:?}"
    );
    for (wave, ids) in [("standalone", &standalone), ("leaf", &leaf)] {
        for (what, id) in [
            ("template-only standalone", template_standalone),
            ("template-only leaf", template_leaf),
            ("compound", parent),
            ("superseded claim", superseded),
            ("procedural root", procedural),
            ("mid-level compound", mid),
        ] {
            assert!(
                !ids.contains(&id),
                "the {what} is in the {wave} wave cohort: {ids:?}"
            );
        }
    }
    assert!(
        !standalone.contains(&evidenced_leaf),
        "a leaf is not a standalone"
    );
    assert!(
        !leaf.contains(&evidenced_standalone),
        "a standalone is not a leaf"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── (2) and (3) the accepted-vacate path ────────────────────────────────────

struct VacateFixture {
    listed_residue: Uuid,
    unlisted_residue: Uuid,
    listed_evidenced: Uuid,
    listed_compound: Uuid,
    before: HashMap<Uuid, Cache>,
}

/// Two template-only standalones (the residue), one listed and one not; an
/// evidenced standalone and a compound, both listed. Every one has a sentinel
/// cache.
async fn seed_vacate_fixture(pool: &PgPool) -> VacateFixture {
    let owner = agent(pool, "vacate-owner").await;
    let ingest = agent(pool, "vacate-ingest").await;
    let source = agent(pool, "vacate-source").await;
    let rv = frame(pool, "research_validity").await;
    let bin = frame(pool, "cohort_v2_binary").await;

    let listed_residue = claim(pool, owner, "listed residue").await;
    insert_row(pool, listed_residue, &template_row(rv, ingest)).await;
    let unlisted_residue = claim(pool, owner, "unlisted residue").await;
    insert_row(pool, unlisted_residue, &template_row(rv, ingest)).await;
    let listed_evidenced = claim(pool, owner, "listed but evidenced").await;
    insert_row(
        pool,
        listed_evidenced,
        &evidence_row(bin, source, 0.7, None),
    )
    .await;
    let listed_compound = claim(pool, owner, "listed compound").await;
    let child = claim(pool, owner, "the compound's leaf").await;
    decomposes_to(pool, listed_compound, child).await;
    insert_row(pool, listed_compound, &template_row(rv, ingest)).await;

    let mut before = HashMap::new();
    for (i, id) in [
        listed_residue,
        unlisted_residue,
        listed_evidenced,
        listed_compound,
    ]
    .into_iter()
    .enumerate()
    {
        #[allow(clippy::cast_precision_loss)]
        let c = set_sentinel(pool, id, rv, 0.01 * i as f64).await;
        before.insert(id, c);
    }
    VacateFixture {
        listed_residue,
        unlisted_residue,
        listed_evidenced,
        listed_compound,
        before,
    }
}

fn write_accept_list(dir: &Path, ids: &[Uuid]) -> PathBuf {
    let path = dir.join("accept-vacate.jsonl");
    let mut text = String::from(
        "{\"rule\": \"test class: template-only standalones with no recall exposure\"}\n",
    );
    for id in ids {
        text.push_str(&format!("{{\"claim_id\": \"{id}\"}}\n"));
    }
    std::fs::write(&path, text).expect("write the accept list");
    path
}

fn vacate_args<'a>(list: &'a str, wave_file: &'a str, dir: &'a str) -> Vec<&'a str> {
    vec![
        "--accept-vacate",
        list,
        "--snapshot",
        wave_file,
        "--wave",
        "test-vacate",
        "--disk-path",
        dir,
        "--min-free-gb",
        "0",
        "--disk-check-cmd",
        "true",
    ]
}

/// SPEC §10.5: `--accept-vacate` writes an explicit vacuous cache ONLY for the
/// listed ids. An unlisted residue claim keeps its cache exactly, and so does
/// a listed claim that has AEF input (vacating it would erase evidence) and a
/// listed compound. The listed residue claim IS vacated: the control that
/// shows the run did write.
#[sqlx::test(migrations = "../../migrations")]
async fn an_id_not_on_the_accept_list_is_never_vacated(pool: PgPool) {
    let dir = scratch_dir();
    let f = seed_vacate_fixture(&pool).await;
    let env = WaveEnv::new(&pool, "legacy").await;
    let list = write_accept_list(
        &dir,
        &[f.listed_residue, f.listed_evidenced, f.listed_compound],
    );
    let wave_file = dir.join("vacate-wave.jsonl");

    let r = run(
        RECOMPUTE_BETP,
        &dir,
        &vacate_args(s(&list), s(&wave_file), s(&dir)),
        &env.vars(),
    );
    r.ok("accept-vacate run");

    assert_eq!(
        cache(&pool, f.unlisted_residue).await,
        f.before[&f.unlisted_residue],
        "an id not on the accept list was rewritten"
    );
    assert_eq!(
        cache(&pool, f.listed_evidenced).await,
        f.before[&f.listed_evidenced],
        "a listed atom with AEF input was vacated"
    );
    assert_eq!(
        cache(&pool, f.listed_compound).await,
        f.before[&f.listed_compound],
        "a listed compound was written"
    );
    assert_ne!(
        cache(&pool, f.listed_residue).await,
        f.before[&f.listed_residue],
        "control: the listed residue claim must be vacated"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// SPEC §10.5: a vacated atom reads back as `unproven`: its cache is the
/// explicit vacuous value (Bel 0, Pl 1, BetP .5, no conflict, no open-world
/// mass) on `binary_truth`, never NULL, and re-classified, so no column of
/// the sentinel survives. The accept list is stored with the batch, named by
/// its SHA-256, and the batch's records name that hash, so a vacate batch
/// traces back to the class rule it was accepted under. The wave file holds
/// the record a compare-and-swap restore needs (`written` is the row as
/// stored).
///
/// `basis: unproven` itself is read through `BeliefView`, which this stack
/// does not have yet (PR-6); this test asserts what that basis is computed
/// from.
#[sqlx::test(migrations = "../../migrations")]
async fn a_vacated_atom_reads_back_unproven_with_a_non_null_cache(pool: PgPool) {
    use sha2::Digest as _;

    let dir = scratch_dir();
    let f = seed_vacate_fixture(&pool).await;
    let env = WaveEnv::new(&pool, "legacy").await;
    let list = write_accept_list(&dir, &[f.listed_residue]);
    let wave_file = dir.join("vacate-wave.jsonl");

    run(
        RECOMPUTE_BETP,
        &dir,
        &vacate_args(s(&list), s(&wave_file), s(&dir)),
        &env.vars(),
    )
    .ok("accept-vacate run");

    let after = cache(&pool, f.listed_residue).await;
    assert_eq!(after.belief, Some(0.0), "{after:?}");
    assert_eq!(after.plausibility, Some(1.0), "{after:?}");
    assert_eq!(after.pignistic_prob, Some(0.5), "{after:?}");
    assert_eq!(after.mass_on_empty, Some(0.0), "no conflict: {after:?}");
    assert_eq!(
        after.mass_on_missing,
        Some(0.0),
        "no open-world mass: {after:?}"
    );
    assert!(
        after.classification.is_some() && after.classification.as_deref() != Some("sentinel"),
        "the vacuous cache is re-classified: {after:?}"
    );
    assert!(
        after.belief_frame_id.is_some() && after.belief_frame_id == binary_truth_id(&pool).await,
        "the vacuous cache is stamped binary_truth: {after:?}"
    );

    let list_bytes = std::fs::read(&list).expect("the accept list");
    let h = hex::encode(sha2::Sha256::digest(&list_bytes));
    let h = &h[..16];
    let stored = {
        let mut p = wave_file.as_os_str().to_owned();
        p.push(format!(".accept-vacate.{h}.jsonl"));
        PathBuf::from(p)
    };
    assert_eq!(
        std::fs::read(&stored).unwrap_or_else(|e| panic!("{}: {e}", stored.display())),
        list_bytes,
        "the accept list is stored with the batch, byte for byte"
    );

    let records = read_wave(std::io::BufReader::new(
        std::fs::File::open(&wave_file).expect("the wave file exists"),
    ))
    .expect("parse the wave file");
    let mine: Vec<_> = records
        .iter()
        .filter(|r| r.claim_id == f.listed_residue)
        .collect();
    assert_eq!(
        mine.len(),
        1,
        "one record for the vacated claim: {records:?}"
    );
    let stored = read_cache_columns(&pool, &[f.listed_residue])
        .await
        .expect("read cache columns");
    assert_eq!(
        mine[0].written, stored[&f.listed_residue],
        "the record's `written` is the row as stored, so a CAS restore matches it"
    );
    assert_eq!(
        mine[0].before.pignistic_prob, f.before[&f.listed_residue].pignistic_prob,
        "the record's `before` is the sentinel"
    );
    assert!(
        mine[0].wave.ends_with(&format!(":vacate:{h}")),
        "the record names the accept list's hash: {}",
        mine[0].wave
    );
    assert_eq!(records.len(), 1, "nothing else was written: {records:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The verdict a dry run prints for each listed id (`{"claim_id", "vacate"}`
/// lines).
fn dry_vacate_verdicts(stdout: &str) -> HashMap<Uuid, String> {
    stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| {
            Some((
                v.get("claim_id")?.as_str()?.parse().ok()?,
                v.get("vacate")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

/// SPEC §10.5 vacates residue ATOMS, and an atom is a current claim
/// (`select_wave_cohort` reads `is_current` too). A superseded claim on an
/// accept list (lists are generated from a class rule, so one can be) is
/// never vacated: its cache keeps its sentinel and nothing is recorded. The
/// dry run's verdict for every listed id is the apply's own outcome: an id
/// the dry run says it would vacate is the one the apply records, and every
/// other id is reported skipped with the same key by both.
#[sqlx::test(migrations = "../../migrations")]
async fn a_listed_superseded_claim_is_never_vacated_and_the_dry_run_agrees(pool: PgPool) {
    let dir = scratch_dir();
    let f = seed_vacate_fixture(&pool).await;
    let owner = agent(&pool, "superseded-owner").await;
    let ingest = agent(&pool, "superseded-ingest").await;
    let rv = frame(&pool, "research_validity").await;
    let superseded = claim(&pool, owner, "superseded residue").await;
    insert_row(&pool, superseded, &template_row(rv, ingest)).await;
    let superseded_before = set_sentinel(&pool, superseded, rv, 0.05).await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(superseded)
        .execute(&pool)
        .await
        .expect("supersede");
    let env = WaveEnv::new(&pool, "legacy").await;
    let listed = [
        f.listed_residue,
        superseded,
        f.listed_evidenced,
        f.listed_compound,
    ];
    let list = write_accept_list(&dir, &listed);

    let dry = run(
        RECOMPUTE_BETP,
        &dir,
        &["--dry-run", "--accept-vacate", s(&list)],
        &[("DATABASE_URL", env.db.as_str())],
    );
    dry.ok("dry accept-vacate");
    let verdicts = dry_vacate_verdicts(&dry.stdout);
    assert_eq!(
        verdicts.len(),
        listed.len(),
        "one verdict per listed id: {}",
        dry.stdout
    );

    let wave_file = dir.join("vacate-wave.jsonl");
    let real = run(
        RECOMPUTE_BETP,
        &dir,
        &vacate_args(s(&list), s(&wave_file), s(&dir)),
        &env.vars(),
    );
    real.ok("accept-vacate run");

    assert_eq!(
        cache(&pool, superseded).await,
        superseded_before,
        "a superseded claim on the accept list was vacated"
    );
    assert_ne!(
        cache(&pool, f.listed_residue).await,
        f.before[&f.listed_residue],
        "control: the current listed residue claim is vacated"
    );
    let recorded: HashSet<Uuid> = read_wave(std::io::BufReader::new(
        std::fs::File::open(&wave_file).expect("the wave file exists"),
    ))
    .expect("parse the wave file")
    .into_iter()
    .map(|r| r.claim_id)
    .collect();
    for id in listed {
        let verdict = &verdicts[&id];
        if verdict == "would_vacate" {
            assert!(
                recorded.contains(&id),
                "{id}: the dry run said would_vacate, the apply did not vacate it"
            );
        } else {
            assert!(
                !recorded.contains(&id),
                "{id}: the dry run said {verdict}, the apply vacated it"
            );
            assert!(
                real.stdout.contains(&format!("{id}: {verdict}")),
                "{id}: the apply must report the dry run's {verdict}\nstdout: {}",
                real.stdout
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── (4) compounds ───────────────────────────────────────────────────────────

/// A compound is never written: not by a leaf wave, not by a standalone wave,
/// and not when it is on the accept list. Its leaf in the leaf wave is (the
/// control).
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_is_never_written(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "compound-owner").await;
    let source = agent(&pool, "compound-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let compound = claim(&pool, owner, "compound with its own BBA").await;
    let leaf = claim(&pool, owner, "evidenced leaf").await;
    decomposes_to(&pool, compound, leaf).await;
    insert_row(&pool, compound, &evidence_row(bin, source, 0.9, None)).await;
    insert_row(&pool, leaf, &evidence_row(bin, source, 0.7, None)).await;
    let compound_before = set_sentinel(&pool, compound, bin, 0.0).await;
    let leaf_before = set_sentinel(&pool, leaf, bin, 0.02).await;

    let env = WaveEnv::new(&pool, "aef").await;
    for role in ["leaf", "standalone"] {
        let wave_file = dir.join(format!("wave-{role}.jsonl"));
        run(
            RECOMPUTE_BETP,
            &dir,
            &real_run_args(role, s(&wave_file), s(&dir)),
            &env.vars(),
        )
        .ok(&format!("{role} wave"));
        assert_eq!(
            cache(&pool, compound).await,
            compound_before,
            "the {role} wave wrote a compound's cache"
        );
    }
    // The accept list, in a vacate run of its own (its own wave file).
    let list = write_accept_list(&dir, &[compound]);
    let vacate_file = dir.join("vacate.jsonl");
    run(
        RECOMPUTE_BETP,
        &dir,
        &vacate_args(s(&list), s(&vacate_file), s(&dir)),
        &env.vars(),
    )
    .ok("accept-vacate run");
    assert_eq!(
        cache(&pool, compound).await,
        compound_before,
        "a listed compound was vacated"
    );
    assert_ne!(
        cache(&pool, leaf).await,
        leaf_before,
        "control: the leaf wave must rewrite the evidenced leaf"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── (5) the snapshot is mandatory ───────────────────────────────────────────

/// SPEC §10.7: `--snapshot` is mandatory for a real run. Without it the run
/// refuses, names the flag, and writes nothing; the same run with it writes
/// (the control), and its wave file stamps every record with one `at`. The
/// cohort-v1 apply (a writing run with no wave) is gone too.
#[sqlx::test(migrations = "../../migrations")]
async fn a_real_run_without_snapshot_refuses(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "snapshot-owner").await;
    let source = agent(&pool, "snapshot-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let atom = claim(&pool, owner, "evidenced standalone").await;
    insert_row(&pool, atom, &evidence_row(bin, source, 0.8, None)).await;
    let other = claim(&pool, owner, "second evidenced standalone").await;
    insert_row(&pool, other, &evidence_row(bin, source, 0.6, None)).await;
    let sentinel = set_sentinel(&pool, atom, bin, 0.0).await;
    set_sentinel(&pool, other, bin, 0.03).await;
    let env = WaveEnv::new(&pool, "aef_standalone").await;
    let state = belief_state(&pool).await;

    let no_snapshot = run(
        RECOMPUTE_BETP,
        &dir,
        &[
            "--role",
            "standalone",
            "--wave",
            "test-wave",
            "--disk-path",
            s(&dir),
            "--min-free-gb",
            "0",
            "--disk-check-cmd",
            "true",
        ],
        &env.vars(),
    );
    assert!(
        no_snapshot.code.is_some_and(|c| c != 0),
        "a real run without --snapshot must refuse; got {:?}\nstdout: {}",
        no_snapshot.code,
        no_snapshot.stdout
    );
    assert!(
        no_snapshot.stderr.contains("--snapshot"),
        "the refusal must name --snapshot\nstderr: {}",
        no_snapshot.stderr
    );
    assert_eq!(
        belief_state(&pool).await,
        state,
        "a refused run writes nothing"
    );

    let v1_apply = run(RECOMPUTE_BETP, &dir, &[], &env.vars());
    assert!(
        v1_apply.code.is_some_and(|c| c != 0) && v1_apply.stderr.contains("--role"),
        "a writing run with no wave (the cohort-v1 apply) must refuse, naming --role; \
         got {:?}\nstderr: {}",
        v1_apply.code,
        v1_apply.stderr
    );
    assert_eq!(
        belief_state(&pool).await,
        state,
        "a refused run writes nothing"
    );

    let wave_file = dir.join("wave.jsonl");
    run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &env.vars(),
    )
    .ok("control: the same run with --snapshot");
    assert_ne!(cache(&pool, atom).await, sentinel, "control: the run wrote");
    let records = read_wave(std::io::BufReader::new(
        std::fs::File::open(&wave_file).expect("the wave file exists"),
    ))
    .expect("parse the wave file");
    let ids: HashSet<Uuid> = records.iter().map(|r| r.claim_id).collect();
    assert!(
        ids.contains(&atom) && ids.contains(&other),
        "every write is recorded: {records:?}"
    );
    let stamps: HashSet<_> = records.iter().map(|r| r.at).collect();
    assert_eq!(stamps.len(), 1, "one wave_at for the whole run: {stamps:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// SPEC §10.8 restores a wave, and §10.5 a vacate batch, from the run's own
/// wave file. So one wave file holds one run: a real run refuses a wave file
/// that already holds records (it would mix two runs, and a restore of either
/// would undo both), and a wave and a vacate batch never share a run. Both
/// refusals are usage refusals (exit 2) that write and record nothing; the
/// first run into the fresh file is the control.
#[sqlx::test(migrations = "../../migrations")]
async fn a_real_run_refuses_a_wave_file_that_already_holds_records(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "one-run-owner").await;
    let source = agent(&pool, "one-run-source").await;
    let ingest = agent(&pool, "one-run-ingest").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let rv = frame(&pool, "research_validity").await;
    let atom = claim(&pool, owner, "evidenced standalone").await;
    insert_row(&pool, atom, &evidence_row(bin, source, 0.8, None)).await;
    let residue = claim(&pool, owner, "residue").await;
    insert_row(&pool, residue, &template_row(rv, ingest)).await;
    set_sentinel(&pool, residue, rv, 0.02).await;
    let sentinel = set_sentinel(&pool, atom, bin, 0.0).await;
    let env = WaveEnv::new(&pool, "aef_standalone").await;

    let wave_file = dir.join("wave.jsonl");
    run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &env.vars(),
    )
    .ok("control: the first run into a fresh wave file");
    assert_ne!(cache(&pool, atom).await, sentinel, "control: the run wrote");
    let recorded = std::fs::read(&wave_file).expect("the wave file exists");
    assert!(!recorded.is_empty(), "control: the run recorded its write");

    // The same atom moves again, so a second run WOULD write and record.
    set_sentinel(&pool, atom, bin, 0.0).await;
    let state = belief_state(&pool).await;
    let again = run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &env.vars(),
    );
    assert_eq!(
        again.code,
        Some(2),
        "a real run into a wave file that already holds records must refuse (exit 2)\n\
         stdout: {}\nstderr: {}",
        again.stdout,
        again.stderr
    );
    assert!(
        again.stderr.contains(s(&wave_file)),
        "the refusal must name the wave file\nstderr: {}",
        again.stderr
    );
    assert_eq!(
        belief_state(&pool).await,
        state,
        "a refused run writes nothing"
    );
    assert_eq!(
        std::fs::read(&wave_file).expect("the wave file"),
        recorded,
        "a refused run appends nothing to the wave file"
    );

    // A wave and a vacate batch in one run: refused, into a fresh file.
    let list = write_accept_list(&dir, &[residue]);
    let mixed_file = dir.join("mixed.jsonl");
    let mut mixed_args = real_run_args("standalone", s(&mixed_file), s(&dir));
    mixed_args.extend(["--accept-vacate", s(&list)]);
    let mixed = run(RECOMPUTE_BETP, &dir, &mixed_args, &env.vars());
    assert_eq!(
        mixed.code,
        Some(2),
        "a wave and a vacate batch in one run must refuse (exit 2)\nstdout: {}\nstderr: {}",
        mixed.stdout,
        mixed.stderr
    );
    assert!(
        mixed.stderr.contains("--accept-vacate") && mixed.stderr.contains("--role"),
        "the refusal must name both flags\nstderr: {}",
        mixed.stderr
    );
    assert_eq!(
        belief_state(&pool).await,
        state,
        "a refused run writes nothing"
    );
    assert!(
        std::fs::read(&mixed_file).unwrap_or_default().is_empty(),
        "a refused run records nothing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── (6) the drift decomposition ─────────────────────────────────────────────

fn component(line: &serde_json::Value, key: &str) -> Option<f64> {
    let c = &line["components"];
    assert!(
        c.get(key).is_some(),
        "component {key:?} missing from {line}"
    );
    c[key].as_f64()
}

/// SPEC §10.4: the dry run's per-atom drift decomposition starts at S0 (the
/// snapshot), and its components telescope to what the wave then writes. So
/// for every cohort atom, S0 (from the snapshot file) plus the components
/// equals the cache a real run under the target fold leaves in `claims`
/// (read back from the database), and each named component is nonzero
/// exactly where its cause is seeded:
///
/// * (0b) organic: a cache rewritten after S0;
/// * (0c) clamp residue: a BetP held up by `ds_auto`'s monotonicity clamp;
/// * (2) the template drop: an ingest template beside real evidence;
/// * (3c) paper-key grouping: two agents' rows citing one DOI (and not two
///   agents' rows citing two DOIs, the negative control);
/// * (4) attribution: an `attributed_v1` row.
///
/// Two stages are also pinned to independent writers, through TWIN claims:
/// (2) of the templated atom is what the legacy writer caches for a twin
/// holding only its evidence row, and (3c) of the one-paper atom is what the
/// wave caches for a twin holding one of its two rows.
#[sqlx::test(migrations = "../../migrations")]
async fn the_drift_components_sum_to_the_change_the_wave_writes(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "drift-owner").await;
    let ingest = agent(&pool, "drift-ingest").await;
    let source = agent(&pool, "drift-source").await;
    let other_source = agent(&pool, "drift-other-source").await;
    let rv = frame(&pool, "research_validity").await;
    let bin = frame(&pool, "cohort_v2_binary").await;

    // (0b) an atom whose cache is rewritten after S0.
    let organic = claim(&pool, owner, "organic").await;
    insert_row(&pool, organic, &evidence_row(bin, source, 0.7, None)).await;
    set_sentinel(&pool, organic, bin, 0.0).await;

    // (0c) the clamp: a high prior, then a weak supporting update. The
    // writer keeps the fold's Bel/Pl and holds BetP at the prior.
    let clamped = claim(&pool, owner, "clamped").await;
    sqlx::query(
        "UPDATE claims SET belief = 0.05, plausibility = 0.99, pignistic_prob = 0.97 \
          WHERE id = $1",
    )
    .bind(clamped)
    .execute(&pool)
    .await
    .expect("set the clamp's prior");
    let clamp_evidence = evidence(&pool, clamped, None).await;
    let viewer = fixture::public_viewer(&pool).await;
    epigraph_mcp::tools::ds_auto::auto_wire_ds_update(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
        clamped,
        source,
        0.3,  // confidence
        1.0,  // weight
        true, // supports
        Some("empirical"),
        Some(clamp_evidence),
        false,
    )
    .await
    .expect("auto_wire_ds_update");
    let held = cache(&pool, clamped).await;
    assert_eq!(
        held.pignistic_prob,
        Some(0.97),
        "fixture: the clamp must hold BetP at the prior: {held:?}"
    );

    // (2) the ingest template beside real evidence, on the owner frame.
    let templated = claim(&pool, owner, "template plus evidence").await;
    insert_row(&pool, templated, &template_row(rv, ingest)).await;
    insert_row(&pool, templated, &evidence_row(rv, source, 0.6, None)).await;
    set_sentinel(&pool, templated, rv, 0.01).await;

    // (3c) two agents' rows citing one paper (one DOI, two evidence rows).
    let one_paper = claim(&pool, owner, "one paper, two agents").await;
    let ev_a = evidence(&pool, one_paper, Some("10.1000/one-paper")).await;
    let ev_b = evidence(&pool, one_paper, Some("10.1000/one-paper")).await;
    insert_row(
        &pool,
        one_paper,
        &evidence_row(bin, source, 0.7, Some(ev_a)),
    )
    .await;
    insert_row(
        &pool,
        one_paper,
        &evidence_row(bin, other_source, 0.7, Some(ev_b)),
    )
    .await;
    set_sentinel(&pool, one_paper, bin, 0.02).await;

    // The negative control: two agents' rows citing two DOIs.
    let two_papers = claim(&pool, owner, "two papers, two agents").await;
    let ev_c = evidence(&pool, two_papers, Some("10.1000/paper-c")).await;
    let ev_d = evidence(&pool, two_papers, Some("10.1000/paper-d")).await;
    insert_row(
        &pool,
        two_papers,
        &evidence_row(bin, source, 0.7, Some(ev_c)),
    )
    .await;
    insert_row(
        &pool,
        two_papers,
        &evidence_row(bin, other_source, 0.7, Some(ev_d)),
    )
    .await;
    set_sentinel(&pool, two_papers, bin, 0.04).await;

    // The twins. The template twin's legacy value is read now, before the
    // wave rewrites it, with explicit legacy settings.
    let template_twin = claim(&pool, owner, "twin: the evidence row alone").await;
    insert_row(&pool, template_twin, &evidence_row(rv, source, 0.6, None)).await;
    epigraph_engine::edge_factor::recompute_atom_cache_with(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
        template_twin,
        epigraph_engine::edge_factor::CacheWriteCause::Organic,
        epigraph_engine::edge_factor::LegacyFold::OwnerFrame,
        epigraph_engine::edge_factor::AtomCacheSettings {
            fold: epigraph_engine::atom_items::AtomFoldMode::Legacy,
            compound_source_edges: epigraph_engine::atom_items::CompoundSourceEdges::Frozen,
            vacate_on_evidence_removal: true,
        },
    )
    .await
    .expect("the legacy writer");
    let template_twin_legacy = cache(&pool, template_twin)
        .await
        .pignistic_prob
        .expect("the legacy writer cached the twin");
    let paper_twin = claim(&pool, owner, "twin: one row of the paper").await;
    let ev_twin = evidence(&pool, paper_twin, Some("10.1000/one-paper")).await;
    insert_row(
        &pool,
        paper_twin,
        &evidence_row(bin, source, 0.7, Some(ev_twin)),
    )
    .await;

    // (4) an attributed_v1 row beside ordinary evidence.
    let attributed = claim(&pool, owner, "attributed").await;
    insert_row(&pool, attributed, &evidence_row(bin, source, 0.6, None)).await;
    let attr_ev = evidence(&pool, attributed, None).await;
    insert_row(
        &pool,
        attributed,
        &Row {
            method: Some("attributed_v1"),
            ..evidence_row(bin, other_source, 0.8, Some(attr_ev))
        },
    )
    .await;
    set_sentinel(&pool, attributed, bin, 0.03).await;

    let env = WaveEnv::new(&pool, "aef_standalone").await;
    let s0_path = take_snapshot(&env.db, &dir, "s0.jsonl");
    let s0: HashMap<Uuid, Option<f64>> = read_snapshot(std::io::BufReader::new(
        std::fs::File::open(&s0_path).expect("open S0"),
    ))
    .expect("parse S0")
    .into_iter()
    .map(|r| (r.claim_id, r.pignistic_prob))
    .collect();

    // The organic move after S0.
    sqlx::query(
        "UPDATE claims SET belief = 0.111, plausibility = 0.777, pignistic_prob = 0.444 \
          WHERE id = $1",
    )
    .bind(organic)
    .execute(&pool)
    .await
    .expect("organic move");

    let report = dry_wave(&env.db, &dir, "standalone", "aef_standalone", &s0_path);
    let lines = report_lines(&report);

    let wave_file = dir.join("wave.jsonl");
    run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &env.vars(),
    )
    .ok("the real wave");

    let seeded = [
        organic, clamped, templated, one_paper, two_papers, attributed,
    ];
    let mut seen = HashSet::new();
    for line in &lines {
        let id: Uuid = line["claim_id"].as_str().unwrap().parse().unwrap();
        if !seeded.contains(&id) {
            continue;
        }
        seen.insert(id);
        let start = s0[&id].expect("every seeded claim has an S0 value");
        let sum: f64 = line["components"]
            .as_object()
            .expect("components object")
            .values()
            .filter_map(serde_json::Value::as_f64)
            .sum();
        let written = cache(&pool, id)
            .await
            .pignistic_prob
            .expect("the wave wrote a value");
        assert!(
            (start + sum - written).abs() < 1e-9,
            "{id}: S0 {start} + components {sum} != written {written}\n{line}"
        );
    }
    assert_eq!(seen.len(), seeded.len(), "every seeded atom is reported");

    let by_id: HashMap<Uuid, &serde_json::Value> = lines
        .iter()
        .map(|l| (l["claim_id"].as_str().unwrap().parse().unwrap(), l))
        .collect();
    for (key, cause) in [
        ("0b", organic),
        ("0c", clamped),
        ("2", templated),
        ("3c", one_paper),
        ("4", attributed),
    ] {
        for id in seeded {
            let v = component(by_id[&id], key).unwrap_or(0.0);
            if id == cause {
                assert!(
                    v.abs() > 1e-9,
                    "({key}) must be nonzero where its cause is: {}",
                    by_id[&id]
                );
            } else {
                assert!(
                    v.abs() <= 1e-9,
                    "({key}) must be zero without its cause: {}",
                    by_id[&id]
                );
            }
        }
    }

    // The stage pins.
    let stage = |id: Uuid, key: &str| {
        by_id[&id]["stages"][key]
            .as_f64()
            .unwrap_or_else(|| panic!("stage ({key}) of {id}: {}", by_id[&id]))
    };
    assert!(
        (stage(templated, "2") - template_twin_legacy).abs() < 1e-12,
        "(2) is the legacy owner fold without the template: {} vs the twin's {}",
        stage(templated, "2"),
        template_twin_legacy
    );
    let paper_twin_aef = cache(&pool, paper_twin)
        .await
        .pignistic_prob
        .expect("the wave wrote the twin");
    assert!(
        (stage(one_paper, "3c") - paper_twin_aef).abs() < 1e-12,
        "(3c) folds the two rows of one paper as ONE item: {} vs the one-row twin's {}",
        stage(one_paper, "3c"),
        paper_twin_aef
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A wave's dry run is exempt from the mode check, so the setting it reads
/// for compound-source edges (SPEC §6.3) can differ from the server's that
/// the apply is checked against; stages (3b) to (4) and the cohort depend on
/// it. So every report line names the setting it was computed under: the
/// process's `EPIGRAPH_COMPOUND_SOURCE_EDGES`, `frozen` when unset, unless
/// `--target-compound-source-edges` names the setting the review is for.
#[sqlx::test(migrations = "../../migrations")]
async fn a_drift_report_names_the_compound_source_edges_setting_it_read(pool: PgPool) {
    let dir = scratch_dir();
    let db = fixture::database_url_for(&pool).await;
    let owner = agent(&pool, "cse-owner").await;
    let source = agent(&pool, "cse-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let atom = claim(&pool, owner, "evidenced standalone").await;
    insert_row(&pool, atom, &evidence_row(bin, source, 0.7, None)).await;
    let s0 = take_snapshot(&db, &dir, "s0.jsonl");

    for (env_value, flag, want) in [
        (None, None, "frozen"),
        (Some("excluded"), None, "excluded"),
        (None, Some("excluded"), "excluded"),
        (Some("excluded"), Some("frozen"), "frozen"),
    ] {
        let report = dir.join(format!("report-{}.jsonl", Uuid::new_v4()));
        let mut env = vec![("DATABASE_URL", db.as_str())];
        if let Some(v) = env_value {
            env.push(("EPIGRAPH_COMPOUND_SOURCE_EDGES", v));
        }
        let mut args = vec![
            "--dry-run",
            "--role",
            "standalone",
            "--target-fold",
            "aef_standalone",
            "--s0",
            s(&s0),
            "--report",
            s(&report),
        ];
        if let Some(f) = flag {
            args.extend(["--target-compound-source-edges", f]);
        }
        run(RECOMPUTE_BETP, &dir, &args, &env)
            .ok(&format!("dry run, env {env_value:?}, flag {flag:?}"));
        let lines = report_lines(&report);
        assert!(!lines.is_empty(), "control: the atom is reported");
        for line in &lines {
            assert_eq!(
                line["compound_source_edges"], want,
                "the line names the setting it was computed under: {line}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A wave dry run into a report file, with `extra` flags.
fn dry_report(
    db: &str,
    dir: &Path,
    role: &str,
    target: &str,
    s0: &Path,
    extra: &[&str],
) -> Vec<serde_json::Value> {
    let report = dir.join(format!("report-{role}-{}.jsonl", Uuid::new_v4()));
    let mut args = vec![
        "--dry-run",
        "--role",
        role,
        "--target-fold",
        target,
        "--s0",
        s(s0),
        "--report",
        s(&report),
    ];
    args.extend_from_slice(extra);
    run(RECOMPUTE_BETP, dir, &args, &[("DATABASE_URL", db)]).ok(&format!("dry run {args:?}"));
    report_lines(&report)
}

fn line_for(lines: &[serde_json::Value], id: Uuid) -> &serde_json::Value {
    lines
        .iter()
        .find(|l| l["claim_id"].as_str() == Some(id.to_string().as_str()))
        .unwrap_or_else(|| panic!("{id} is not reported: {lines:?}"))
}

/// S0 plus a line's components equals what the wave wrote (read back).
async fn assert_sums_to_written(pool: &PgPool, line: &serde_json::Value, s0: f64, id: Uuid) {
    let sum: f64 = line["components"]
        .as_object()
        .expect("components")
        .values()
        .filter_map(serde_json::Value::as_f64)
        .sum();
    let written = cache(pool, id).await.pignistic_prob.expect("written");
    assert!(
        (s0 + sum - written).abs() < 1e-9,
        "{id}: S0 {s0} + components {sum} != written {written}\n{line}"
    );
}

/// SPEC §10.4, the components the first drift test does not seed:
///
/// * (1') the α change: nonzero exactly on the atom whose row is in the
///   `--alpha-manifest` (its `evidence_type` set after S0), `null` (not
///   separable) on every line of a run without a manifest;
/// * (3a) the one-sided read of a compound-source positive edge-factor row
///   with m(F): positive (m(F) moves to Theta) exactly on the standalone that
///   is that edge's target, already in the standalone wave;
/// * (3b) compound-source rows excluded: zero under `frozen`, nonzero on that
///   standalone under `excluded`;
/// * a leaf wave under `aef` decomposes to what the real leaf wave writes;
///   under a target that does not fold leaves (`aef_standalone`) it stops at
///   (1').
///
/// Sums are checked against what real waves then write.
#[sqlx::test(migrations = "../../migrations")]
async fn the_drift_decomposition_separates_alpha_and_compound_source_reads(pool: PgPool) {
    let dir = scratch_dir();
    let db = fixture::database_url_for(&pool).await;
    let owner = agent(&pool, "drift2-owner").await;
    let source = agent(&pool, "drift2-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;

    // A compound and its evidenced leaf.
    let compound = claim(&pool, owner, "compound").await;
    let leaf = claim(&pool, owner, "evidenced leaf").await;
    decomposes_to(&pool, compound, leaf).await;
    insert_row(&pool, leaf, &evidence_row(bin, source, 0.7, None)).await;
    set_sentinel(&pool, leaf, bin, 0.0).await;

    // A standalone the compound supports, through an edge-factor row with
    // disbelief mass (stored, as the edge auto-wire stores it, keyed by the
    // edge's own perspective).
    let target = claim(&pool, owner, "target of a compound-source edge").await;
    insert_row(&pool, target, &evidence_row(bin, source, 0.6, None)).await;
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'supports', \
                 now() - interval '2 days') RETURNING id",
    )
    .bind(compound)
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("seed the supports edge");
    sqlx::query(
        "INSERT INTO perspectives (id, name, owner_agent_id, perspective_type) \
         VALUES ($1, 'edge_factor', $2, 'edge')",
    )
    .bind(edge)
    .bind(owner)
    .execute(&pool)
    .await
    .expect("the edge's perspective");
    insert_row(
        &pool,
        target,
        &Row {
            frame: bin,
            source: Some(owner),
            masses: serde_json::json!({ "0": 0.5, "1": 0.2, "0,1": 0.3 }),
            method: Some("edge_factor"),
            source_strength: Some(0.8),
            evidence_type: None,
            evidence_id: None,
            perspective_id: Some(edge),
        },
    )
    .await;
    set_sentinel(&pool, target, bin, 0.01).await;

    // A standalone whose row a type backfill set after S0: in the manifest.
    let typed = claim(&pool, owner, "typed after S0").await;
    let typed_row = insert_row(
        &pool,
        typed,
        &Row {
            source_strength: Some(0.4),
            ..evidence_row(bin, source, 0.7, None)
        },
    )
    .await;
    set_sentinel(&pool, typed, bin, 0.02).await;
    let manifest = dir.join("alpha-manifest.txt");
    std::fs::write(&manifest, format!("{typed_row}\n")).expect("manifest");

    let s0_path = take_snapshot(&db, &dir, "s0.jsonl");
    let s0: HashMap<Uuid, f64> = read_snapshot(std::io::BufReader::new(
        std::fs::File::open(&s0_path).expect("open S0"),
    ))
    .expect("parse S0")
    .into_iter()
    .filter_map(|r| r.pignistic_prob.map(|p| (r.claim_id, p)))
    .collect();

    let c = |line: &serde_json::Value, key: &str| component(line, key);
    let with_manifest = ["--alpha-manifest", s(&manifest)];
    let frozen = dry_report(
        &db,
        &dir,
        "standalone",
        "aef_standalone",
        &s0_path,
        &with_manifest,
    );
    let excluded = dry_report(
        &db,
        &dir,
        "standalone",
        "aef_standalone",
        &s0_path,
        &[
            "--alpha-manifest",
            s(&manifest),
            "--target-compound-source-edges",
            "excluded",
        ],
    );
    let no_manifest = dry_report(&db, &dir, "standalone", "aef_standalone", &s0_path, &[]);

    // (1'): only with a manifest, and only where it names a row.
    let alpha = c(line_for(&frozen, typed), "1'").expect("(1') is separable with a manifest");
    assert!(
        alpha.abs() > 1e-9,
        "(1') moves the typed atom: {}",
        line_for(&frozen, typed)
    );
    assert_eq!(
        c(line_for(&frozen, target), "1'"),
        Some(0.0),
        "(1') is zero where the manifest names no row"
    );
    for line in &no_manifest {
        assert_eq!(
            c(line, "1'"),
            None,
            "(1') is null without a manifest: {line}"
        );
    }
    // (3a) and (3b).
    for (lines, setting) in [(&frozen, "frozen"), (&excluded, "excluded")] {
        let t = line_for(lines, target);
        assert!(
            c(t, "3a").unwrap() > 1e-9,
            "(3a) RAISES the compound-source edge's target under {setting} (the one-sided \
             read moves the row's m(F) to Theta): {t}"
        );
        assert!(
            c(line_for(lines, typed), "3a").unwrap().abs() <= 1e-9,
            "(3a) is zero without a compound-source row ({setting})"
        );
        assert!(
            c(line_for(lines, typed), "3b").unwrap().abs() <= 1e-9,
            "(3b) is zero without a compound-source row ({setting})"
        );
    }
    assert!(
        c(line_for(&frozen, target), "3b").unwrap().abs() <= 1e-9,
        "(3b) is zero under frozen: {}",
        line_for(&frozen, target)
    );
    assert!(
        c(line_for(&excluded, target), "3b").unwrap().abs() > 1e-9,
        "(3b) moves the target under excluded: {}",
        line_for(&excluded, target)
    );

    // The leaf: under a target that does not fold leaves, the decomposition
    // stops at (1').
    let not_folded = dry_report(&db, &dir, "leaf", "aef_standalone", &s0_path, &[]);
    let keys: HashSet<&str> = line_for(&not_folded, leaf)["components"]
        .as_object()
        .expect("components")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        HashSet::from(["0b", "0c", "1", "1'"]),
        "a leaf under aef_standalone stops at (1')"
    );
    let leaf_aef = dry_report(&db, &dir, "leaf", "aef", &s0_path, &[]);

    // The real waves: standalones under aef_standalone (frozen, as the
    // fixture server), then leaves under aef.
    let standalone_env = WaveEnv::new(&pool, "aef_standalone").await;
    let wave_file = dir.join("standalone-wave.jsonl");
    run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &standalone_env.vars(),
    )
    .ok("the standalone wave");
    for id in [target, typed] {
        assert_sums_to_written(&pool, line_for(&frozen, id), s0[&id], id).await;
    }
    let leaf_env = WaveEnv::new(&pool, "aef").await;
    let leaf_file = dir.join("leaf-wave.jsonl");
    run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("leaf", s(&leaf_file), s(&dir)),
        &leaf_env.vars(),
    )
    .ok("the leaf wave");
    assert_sums_to_written(&pool, line_for(&leaf_aef, leaf), s0[&leaf], leaf).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ── (7) the disk gate ───────────────────────────────────────────────────────

/// The real-run flags of a standalone wave with everything but the disk gate:
/// the caller adds the gate's flags.
fn gate_args<'a>(wave_file: &'a str, dir: &'a str) -> Vec<&'a str> {
    vec![
        "--role",
        "standalone",
        "--snapshot",
        wave_file,
        "--wave",
        "test-wave",
        "--disk-path",
        dir,
    ]
}

/// SPEC §10.4 disk gate: checked before every batch, a failure aborts before
/// the batch writes (exit 4). A run whose first check fails, on free space or
/// on the check command, writes nothing and records nothing; the same run
/// with a passing check writes (the control).
#[sqlx::test(migrations = "../../migrations")]
async fn a_run_whose_disk_check_fails_writes_nothing(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "disk-owner").await;
    let source = agent(&pool, "disk-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let atom = claim(&pool, owner, "evidenced standalone").await;
    insert_row(&pool, atom, &evidence_row(bin, source, 0.8, None)).await;
    let sentinel = set_sentinel(&pool, atom, bin, 0.0).await;
    let env = WaveEnv::new(&pool, "aef_standalone").await;
    let state = belief_state(&pool).await;

    let wave_file = dir.join("wave.jsonl");
    let failing = run(
        RECOMPUTE_BETP,
        &dir,
        &{
            let mut a = gate_args(s(&wave_file), s(&dir));
            // No volume has this much free space.
            a.extend(["--min-free-gb", "1000000000", "--disk-check-cmd", "true"]);
            a
        },
        &env.vars(),
    );
    assert_eq!(
        failing.code,
        Some(4),
        "a failed disk check must abort the run (exit 4)\nstdout: {}\nstderr: {}",
        failing.stdout,
        failing.stderr
    );
    assert!(
        failing.stderr.contains("disk check failed"),
        "the abort must say the disk check failed\nstderr: {}",
        failing.stderr
    );
    assert_eq!(
        belief_state(&pool).await,
        state,
        "a failed disk check writes nothing"
    );
    let recorded = std::fs::read_to_string(&wave_file).unwrap_or_default();
    assert!(
        recorded.trim().is_empty(),
        "a failed disk check records nothing: {recorded}"
    );

    let failing_cmd = run(
        RECOMPUTE_BETP,
        &dir,
        &{
            let mut a = gate_args(s(&wave_file), s(&dir));
            a.extend(["--min-free-gb", "0", "--disk-check-cmd", "exit 7"]);
            a
        },
        &env.vars(),
    );
    assert_eq!(
        failing_cmd.code,
        Some(4),
        "a failing --disk-check-cmd aborts the run (exit 4)\nstdout: {}\nstderr: {}",
        failing_cmd.stdout,
        failing_cmd.stderr
    );
    assert!(
        failing_cmd.stderr.contains("disk check command"),
        "the abort must name the failed check command\nstderr: {}",
        failing_cmd.stderr
    );
    assert_eq!(
        belief_state(&pool).await,
        state,
        "a failed disk check writes nothing"
    );

    run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &env.vars(),
    )
    .ok("control: a passing disk check");
    assert_ne!(cache(&pool, atom).await, sentinel, "control: the run wrote");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A check command that passes the first time and fails every time after:
/// it leaves a marker file the first time.
fn passes_once(marker: &Path) -> String {
    format!("test ! -e '{0}' && touch '{0}'", marker.display())
}

/// SPEC §10.4: the disk gate runs before EVERY batch, not once per run, on the
/// wave path and on the vacate path. With one claim per batch and a check
/// that passes once, the first batch is written and recorded, the second
/// check aborts the run (exit 4), and the second claim keeps its cache with
/// no record. A wave's cohort is in id order; a vacate list in list order.
#[sqlx::test(migrations = "../../migrations")]
async fn the_disk_gate_is_checked_before_every_batch(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "batches-owner").await;
    let source = agent(&pool, "batches-source").await;
    let ingest = agent(&pool, "batches-ingest").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let rv = frame(&pool, "research_validity").await;
    let env = WaveEnv::new(&pool, "aef_standalone").await;

    // The wave path.
    let mut atoms = Vec::new();
    for (i, support) in [0.8, 0.6].into_iter().enumerate() {
        let atom = claim(&pool, owner, "evidenced standalone").await;
        insert_row(&pool, atom, &evidence_row(bin, source, support, None)).await;
        #[allow(clippy::cast_precision_loss)]
        let before = set_sentinel(&pool, atom, bin, 0.01 * i as f64).await;
        atoms.push((atom, before));
    }
    atoms.sort_by_key(|(id, _)| *id);
    let wave_file = dir.join("wave.jsonl");
    let check = passes_once(&dir.join("wave-gate-used"));
    let mut args = gate_args(s(&wave_file), s(&dir));
    args.extend([
        "--min-free-gb",
        "0",
        "--disk-check-cmd",
        &check,
        "--batch-size",
        "1",
    ]);
    let r = run(RECOMPUTE_BETP, &dir, &args, &env.vars());
    assert_eq!(
        r.code,
        Some(4),
        "the second batch's failed check aborts the wave (exit 4)\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert!(
        r.stderr.contains("before wave batch 2"),
        "the abort names the batch\nstderr: {}",
        r.stderr
    );
    let recorded = |path: &Path| -> HashSet<Uuid> {
        read_wave(std::io::BufReader::new(
            std::fs::File::open(path).expect("the wave file exists"),
        ))
        .expect("parse the wave file")
        .into_iter()
        .map(|r| r.claim_id)
        .collect()
    };
    let (first, first_before) = &atoms[0];
    let (second, second_before) = &atoms[1];
    assert_ne!(
        &cache(&pool, *first).await,
        first_before,
        "batch 1 was written"
    );
    assert_eq!(
        &cache(&pool, *second).await,
        second_before,
        "batch 2 was written after its disk check failed"
    );
    assert_eq!(
        recorded(&wave_file),
        HashSet::from([*first]),
        "only batch 1 is recorded"
    );

    // The vacate path, in list order.
    let residue_a = claim(&pool, owner, "residue listed first").await;
    insert_row(&pool, residue_a, &template_row(rv, ingest)).await;
    let a_before = set_sentinel(&pool, residue_a, rv, 0.02).await;
    let residue_b = claim(&pool, owner, "residue listed second").await;
    insert_row(&pool, residue_b, &template_row(rv, ingest)).await;
    let b_before = set_sentinel(&pool, residue_b, rv, 0.03).await;
    let list = write_accept_list(&dir, &[residue_a, residue_b]);
    let vacate_file = dir.join("vacate.jsonl");
    let check = passes_once(&dir.join("vacate-gate-used"));
    let args = vec![
        "--accept-vacate",
        s(&list),
        "--snapshot",
        s(&vacate_file),
        "--wave",
        "test-vacate",
        "--disk-path",
        s(&dir),
        "--min-free-gb",
        "0",
        "--disk-check-cmd",
        &check,
        "--batch-size",
        "1",
    ];
    let r = run(RECOMPUTE_BETP, &dir, &args, &env.vars());
    assert_eq!(
        r.code,
        Some(4),
        "the second batch's failed check aborts the vacate (exit 4)\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert!(
        r.stderr.contains("before vacate batch 2"),
        "the abort names the batch\nstderr: {}",
        r.stderr
    );
    assert_ne!(
        cache(&pool, residue_a).await,
        a_before,
        "vacate batch 1 was written"
    );
    assert_eq!(
        cache(&pool, residue_b).await,
        b_before,
        "vacate batch 2 was written after its disk check failed"
    );
    assert_eq!(
        recorded(&vacate_file),
        HashSet::from([residue_a]),
        "only vacate batch 1 is recorded"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// SPEC §10.4: the disk gate is free space AND backup health (`pgbackrest
/// check` green, a full backup recent enough for expire to run). Free space
/// is measured by the tool; backup health only by the operator's check
/// command. So a real run without `--disk-check-cmd` refuses (exit 2), names
/// the flag, and writes and records nothing, unless the operator opts out
/// explicitly. The same run with a check command writes (the control).
#[sqlx::test(migrations = "../../migrations")]
async fn a_real_run_without_a_backup_check_refuses(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "backup-owner").await;
    let source = agent(&pool, "backup-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let atom = claim(&pool, owner, "evidenced standalone").await;
    insert_row(&pool, atom, &evidence_row(bin, source, 0.8, None)).await;
    let sentinel = set_sentinel(&pool, atom, bin, 0.0).await;
    let env = WaveEnv::new(&pool, "aef_standalone").await;
    let state = belief_state(&pool).await;

    let wave_file = dir.join("wave.jsonl");
    let unchecked = run(
        RECOMPUTE_BETP,
        &dir,
        &{
            let mut a = gate_args(s(&wave_file), s(&dir));
            a.extend(["--min-free-gb", "0"]);
            a
        },
        &env.vars(),
    );
    assert_eq!(
        unchecked.code,
        Some(2),
        "a real run with no backup check must refuse (exit 2)\nstdout: {}\nstderr: {}",
        unchecked.stdout,
        unchecked.stderr
    );
    assert!(
        unchecked.stderr.contains("--disk-check-cmd"),
        "the refusal must name --disk-check-cmd\nstderr: {}",
        unchecked.stderr
    );
    assert_eq!(
        belief_state(&pool).await,
        state,
        "a refused run writes nothing"
    );
    assert!(
        std::fs::read(&wave_file).unwrap_or_default().is_empty(),
        "a refused run records nothing"
    );

    run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &env.vars(),
    )
    .ok("control: the same run with a check command");
    assert_ne!(cache(&pool, atom).await, sentinel, "control: the run wrote");
    let record = run_record(&wave_file);
    assert_eq!(
        record["disk_gate"]["backup_check"]["command"], "true",
        "the run record names the check command: {record}"
    );

    // The explicit opt-out proceeds, says so, and is recorded.
    set_sentinel(&pool, atom, bin, 0.0).await;
    let opted_file = dir.join("opted-out.jsonl");
    let opted = run(
        RECOMPUTE_BETP,
        &dir,
        &{
            let mut a = gate_args(s(&opted_file), s(&dir));
            a.extend(["--min-free-gb", "0", "--no-backup-check"]);
            a
        },
        &env.vars(),
    );
    opted.ok("--no-backup-check");
    assert!(
        opted.stdout.contains("NO backup check"),
        "the opt-out is printed\nstdout: {}",
        opted.stdout
    );
    assert_ne!(
        cache(&pool, atom).await,
        sentinel,
        "the opted-out run wrote"
    );
    let record = run_record(&opted_file);
    assert_eq!(
        record["disk_gate"]["backup_check"]["no_backup_check"], true,
        "the opt-out is recorded: {record}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `<wave file>.run.json`, the run's own record of its modes and gate.
fn run_record(wave_file: &Path) -> serde_json::Value {
    let mut p = wave_file.as_os_str().to_owned();
    p.push(".run.json");
    let text = std::fs::read_to_string(PathBuf::from(p)).expect("the run record exists");
    serde_json::from_str(&text).expect("the run record is JSON")
}

/// A claim whose write fails does not stop the wave: the other claims are
/// written, the failed one is left and unrecorded (its transaction rolled
/// back), and the run exits 5, distinct from a usage refusal (2), a mode
/// refusal (3) and a disk-gate abort (4), so a wrapper can tell them apart.
/// The failure is a database trigger refusing that one claim's cache write.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_whose_write_fails_exits_5_and_the_others_are_written(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "errors-owner").await;
    let source = agent(&pool, "errors-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let failing = claim(&pool, owner, "a write the database refuses").await;
    insert_row(&pool, failing, &evidence_row(bin, source, 0.8, None)).await;
    let fine = claim(&pool, owner, "a write that lands").await;
    insert_row(&pool, fine, &evidence_row(bin, source, 0.6, None)).await;
    let failing_before = set_sentinel(&pool, failing, bin, 0.0).await;
    let fine_before = set_sentinel(&pool, fine, bin, 0.03).await;
    sqlx::query(&format!(
        "CREATE FUNCTION test_refuse_one_claim() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.id = '{failing}' THEN RAISE EXCEPTION 'test: refused write'; END IF; \
         RETURN NEW; END $$"
    ))
    .execute(&pool)
    .await
    .expect("trigger function");
    sqlx::query(
        "CREATE TRIGGER test_refuse_one_claim BEFORE UPDATE ON claims \
         FOR EACH ROW EXECUTE FUNCTION test_refuse_one_claim()",
    )
    .execute(&pool)
    .await
    .expect("trigger");
    let env = WaveEnv::new(&pool, "aef_standalone").await;

    let wave_file = dir.join("wave.jsonl");
    let r = run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &env.vars(),
    );
    assert_eq!(
        r.code,
        Some(5),
        "a run with a failed claim exits 5\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert_eq!(
        cache(&pool, failing).await,
        failing_before,
        "the failed claim is left"
    );
    assert_ne!(
        cache(&pool, fine).await,
        fine_before,
        "the other claim is written"
    );
    let recorded: HashSet<Uuid> = read_wave(std::io::BufReader::new(
        std::fs::File::open(&wave_file).expect("the wave file exists"),
    ))
    .expect("parse the wave file")
    .into_iter()
    .map(|r| r.claim_id)
    .collect();
    assert_eq!(
        recorded,
        HashSet::from([fine]),
        "only the committed write is recorded"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── the per-scope rows the wave resyncs ─────────────────────────────────────

/// SPEC §7.2: a wave resyncs the atom's existing `ds_combined_beliefs` rows
/// from the atom fold: the global row to the atom's fold, a perspective row
/// to the fold of that perspective's rows (checked against a TWIN claim that
/// carries only that perspective's row). Their `before` and `written` are
/// recorded, and `restore_belief_cache` puts the claim's cache AND those rows
/// back. No scoped row is created.
#[sqlx::test(migrations = "../../migrations")]
async fn a_wave_resyncs_existing_scoped_rows_and_a_restore_puts_them_back(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "scoped-owner").await;
    let source = agent(&pool, "scoped-source").await;
    let other_source = agent(&pool, "scoped-other-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("scoped resync {}", Uuid::new_v4()))
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("seed perspective");

    let atom = claim(&pool, owner, "atom with scoped rows").await;
    insert_row(&pool, atom, &evidence_row(bin, source, 0.8, None)).await;
    insert_row(
        &pool,
        atom,
        &Row {
            perspective_id: Some(perspective),
            ..evidence_row(bin, other_source, 0.55, None)
        },
    )
    .await;
    // The twin carries only the perspective's row.
    let twin = claim(&pool, owner, "twin with only the perspective's row").await;
    insert_row(
        &pool,
        twin,
        &Row {
            perspective_id: Some(perspective),
            ..evidence_row(bin, other_source, 0.55, None)
        },
    )
    .await;
    let atom_before = set_sentinel(&pool, atom, bin, 0.0).await;
    set_sentinel(&pool, twin, bin, 0.04).await;
    for (scope, scope_id, b) in [
        ("global", None, 0.123),
        ("perspective", Some(perspective), 0.321),
    ] {
        sqlx::query(
            "INSERT INTO ds_combined_beliefs (frame_id, claim_id, scope_type, scope_id, belief, \
                 plausibility, mass_on_empty, mass_on_missing, pignistic_prob) \
             VALUES ($1, $2, $3, $4, $5, 0.9, 0.0, 0.0, 0.5)",
        )
        .bind(bin)
        .bind(atom)
        .bind(scope)
        .bind(scope_id)
        .bind(b)
        .execute(&pool)
        .await
        .expect("seed scoped row");
    }
    let scoped_before = scoped_full(&pool, atom).await;
    let rows_before: i64 = sqlx::query_scalar("SELECT count(*) FROM ds_combined_beliefs")
        .fetch_one(&pool)
        .await
        .unwrap();

    let env = WaveEnv::new(&pool, "aef_standalone").await;
    let wave_file = dir.join("wave.jsonl");
    run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &env.vars(),
    )
    .ok("the wave");

    let after = cache(&pool, atom).await;
    let twin_after = cache(&pool, twin).await;
    let rows: HashMap<String, (f64, f64, Option<f64>)> = scoped(&pool, atom)
        .await
        .into_iter()
        .map(|(k, b, p, bp)| (k, (b, p, bp)))
        .collect();
    assert_eq!(
        rows["global"],
        (
            after.belief.unwrap(),
            after.plausibility.unwrap(),
            after.pignistic_prob
        ),
        "the global row is the atom's fold"
    );
    let (p_bel, p_pl, p_betp) = rows["perspective"];
    for (got, want, what) in [
        (p_bel, twin_after.belief.unwrap(), "belief"),
        (p_pl, twin_after.plausibility.unwrap(), "plausibility"),
        (
            p_betp.expect("pignistic_prob"),
            twin_after.pignistic_prob.unwrap(),
            "pignistic_prob",
        ),
    ] {
        assert!(
            (got - want).abs() < 1e-12,
            "the perspective row's {what} is the fold of that perspective's rows alone: \
             {got} vs the twin's {want}"
        );
    }
    assert!(
        (p_bel - after.belief.unwrap()).abs() > 1e-6,
        "fixture: the perspective's fold must differ from the atom's whole fold"
    );
    let rows_after: i64 = sqlx::query_scalar("SELECT count(*) FROM ds_combined_beliefs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows_after, rows_before, "a wave creates no scoped row");

    let restore = run(
        RESTORE,
        &dir,
        &["--from", s(&wave_file)],
        &[("DATABASE_URL", env.db.as_str())],
    );
    restore.ok("restore_belief_cache");
    assert_eq!(
        cache(&pool, atom).await,
        atom_before,
        "the claim cache is restored"
    );
    assert_eq!(
        scoped_full(&pool, atom).await,
        scoped_before,
        "the scoped rows are restored, every value column"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `(scope_type, scope_id, every value column)` of the claim's scoped rows,
/// in scope order.
async fn scoped_full(pool: &PgPool, claim: Uuid) -> Vec<(String, Option<Uuid>, ScopedRow)> {
    use sqlx::Row as _;
    sqlx::query(
        "SELECT scope_type, scope_id, belief, plausibility, mass_on_empty, mass_on_missing, \
                conflict_k, strategy_used, pignistic_prob \
           FROM ds_combined_beliefs WHERE claim_id = $1 ORDER BY scope_type, scope_id",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read scoped rows")
    .into_iter()
    .map(|r| {
        (
            r.get("scope_type"),
            r.get("scope_id"),
            ScopedRow {
                belief: r.get("belief"),
                plausibility: r.get("plausibility"),
                mass_on_empty: r.get("mass_on_empty"),
                mass_on_missing: r.get("mass_on_missing"),
                conflict_k: r.get("conflict_k"),
                strategy_used: r.get("strategy_used"),
                pignistic_prob: r.get("pignistic_prob"),
            },
        )
    })
    .collect()
}

/// SPEC §10.8's restore is compare-and-swap for the scoped rows too: a row
/// written after the wave (a later `ScopedBeliefRepository::upsert`, say) is
/// left as that later write and reported `scoped_superseded_since_wave`,
/// while the wave's other rows go back. `--claims` limits the scoped restore
/// as it does the claim restore: a row of an unlisted claim keeps the wave's
/// value until a run that covers it, which then restores it and reports the
/// earlier rows `already_restored` (or still superseded).
#[sqlx::test(migrations = "../../migrations")]
async fn a_scoped_restore_leaves_a_row_written_after_the_wave_and_honours_claims(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "cas-owner").await;
    let source = agent(&pool, "cas-source").await;
    let other_source = agent(&pool, "cas-other-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let p = perspective(&pool, owner, "cas").await;
    let a = claim(&pool, owner, "listed atom").await;
    insert_row(&pool, a, &evidence_row(bin, source, 0.8, None)).await;
    insert_row(
        &pool,
        a,
        &Row {
            perspective_id: Some(p),
            ..evidence_row(bin, other_source, 0.55, None)
        },
    )
    .await;
    let b = claim(&pool, owner, "unlisted atom").await;
    insert_row(&pool, b, &evidence_row(bin, source, 0.6, None)).await;
    seed_scoped_row(&pool, a, bin, ("global", None), 0.111, "seeded").await;
    seed_scoped_row(&pool, a, bin, ("perspective", Some(p)), 0.222, "seeded").await;
    seed_scoped_row(&pool, b, bin, ("global", None), 0.333, "seeded").await;
    let a_global_before = scoped_row(&pool, a, bin, ("global", None)).await;
    let b_global_before = scoped_row(&pool, b, bin, ("global", None)).await;

    let env = WaveEnv::new(&pool, "aef_standalone").await;
    let wave_file = dir.join("wave.jsonl");
    run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &env.vars(),
    )
    .ok("the wave");
    let b_global_wave = scoped_row(&pool, b, bin, ("global", None)).await;
    assert_ne!(
        b_global_wave, b_global_before,
        "control: the wave resynced B's row"
    );

    // A later write to A's perspective row.
    sqlx::query(
        "UPDATE ds_combined_beliefs SET belief = 0.444, strategy_used = 'Dempster' \
          WHERE claim_id = $1 AND scope_type = 'perspective'",
    )
    .bind(a)
    .execute(&pool)
    .await
    .expect("the later write");
    let a_later = scoped_row(&pool, a, bin, ("perspective", Some(p))).await;

    let claims_file = dir.join("claims.txt");
    std::fs::write(&claims_file, format!("{a}\n")).expect("claims file");
    let restore = |extra: Vec<String>, tag: &str| {
        let mut args = vec![
            "--from".to_string(),
            s(&wave_file).to_string(),
            "--outcomes-out".to_string(),
            s(&dir.join(format!("outcomes-{tag}.jsonl"))).to_string(),
            "--downstream-out".to_string(),
            s(&dir.join(format!("downstream-{tag}.jsonl"))).to_string(),
        ];
        args.extend(extra);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = run(RESTORE, &dir, &args, &[("DATABASE_URL", env.db.as_str())]);
        r.ok(&format!("restore {tag}"));
        r.stdout
    };

    let out = restore(
        vec!["--claims".into(), s(&claims_file).to_string()],
        "listed",
    );
    for line in [
        "scoped_restored: 1",
        "scoped_superseded_since_wave: 1",
        "scoped_already_restored: 0",
    ] {
        assert!(out.contains(line), "expected {line:?}\nstdout: {out}");
    }
    assert_eq!(
        scoped_row(&pool, a, bin, ("global", None)).await,
        a_global_before,
        "the listed atom's untouched row is restored"
    );
    assert_eq!(
        scoped_row(&pool, a, bin, ("perspective", Some(p))).await,
        a_later,
        "a row written after the wave keeps the later write"
    );
    assert_eq!(
        scoped_row(&pool, b, bin, ("global", None)).await,
        b_global_wave,
        "--claims leaves an unlisted claim's scoped row alone"
    );

    let out = restore(Vec::new(), "all");
    for line in [
        "scoped_restored: 1",
        "scoped_already_restored: 1",
        "scoped_superseded_since_wave: 1",
    ] {
        assert!(out.contains(line), "expected {line:?}\nstdout: {out}");
    }
    assert_eq!(
        scoped_row(&pool, b, bin, ("global", None)).await,
        b_global_before,
        "a run that covers B restores its row"
    );
    assert_eq!(
        scoped_row(&pool, a, bin, ("perspective", Some(p))).await,
        a_later,
        "the later write still stands"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `restore_scoped` over a row recorded by more than one wave (records in
/// any order): a CHAINED run of records (each `before` the previous
/// `written`) restores to the chain's first `before`; where the chain is
/// broken (a write landed between two waves), only the records after the
/// break are undone, to that later write.
#[sqlx::test(migrations = "../../migrations")]
async fn a_scoped_restore_follows_a_chain_of_waves_to_its_start(pool: PgPool) {
    use epigraph_cli::belief_cache::{
        restore_scoped, RestoreOptions, ScopedColumns, ScopedWaveRecord,
    };

    let owner = agent(&pool, "chain-owner").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let col = |b: f64| ScopedColumns {
        belief: Some(b),
        plausibility: Some(0.9),
        mass_on_empty: Some(0.0),
        mass_on_missing: Some(0.0),
        conflict_k: None,
        strategy_used: Some("atom_fold".into()),
        pignistic_prob: Some(0.5),
    };
    let t0 = chrono::Utc::now();
    let mut records = Vec::new();
    let mut rows = Vec::new();
    // (chained: A -> B, B -> C) restores to A; (broken: A -> B, D -> C) to D.
    for (what, first_before, second_before, want) in
        [("chained", 0.1, 0.2, 0.1), ("broken", 0.1, 0.4, 0.4)]
    {
        let c = claim(&pool, owner, what).await;
        seed_scoped_row(&pool, c, bin, ("global", None), 0.3, "atom_fold").await;
        sqlx::query(
            "UPDATE ds_combined_beliefs SET plausibility = 0.9, mass_on_empty = 0.0, \
                    mass_on_missing = 0.0, conflict_k = NULL, pignistic_prob = 0.5 \
              WHERE claim_id = $1",
        )
        .bind(c)
        .execute(&pool)
        .await
        .expect("hold the second wave's written");
        let row_id: Uuid =
            sqlx::query_scalar("SELECT id FROM ds_combined_beliefs WHERE claim_id = $1")
                .bind(c)
                .fetch_one(&pool)
                .await
                .expect("row id");
        let rec = |before: f64, written: f64, secs: i64| ScopedWaveRecord {
            row_id,
            claim_id: c,
            frame_id: bin,
            scope_type: "global".into(),
            scope_id: None,
            before: col(before),
            written: col(written),
            wave: format!("wave-{secs}"),
            at: t0 + chrono::Duration::seconds(secs),
        };
        // The later wave first: the restore orders by `at`, not file order.
        records.push(rec(second_before, 0.3, 2));
        records.push(rec(first_before, 0.2, 1));
        rows.push((c, want));
    }
    let report = restore_scoped(&pool, &records, &RestoreOptions::default())
        .await
        .expect("restore_scoped");
    assert_eq!(report.restored.len(), 2, "{report:?}");
    for (c, want) in rows {
        let got: Option<f64> =
            sqlx::query_scalar("SELECT belief FROM ds_combined_beliefs WHERE claim_id = $1")
                .bind(c)
                .fetch_one(&pool)
                .await
                .expect("belief");
        assert_eq!(
            got,
            Some(want),
            "restored to the start of the trailing chain"
        );
    }
}

/// `(scope_type, belief, plausibility, pignistic_prob)` of the claim's scoped
/// rows, in scope order.
async fn scoped(pool: &PgPool, claim: Uuid) -> Vec<(String, f64, f64, Option<f64>)> {
    sqlx::query_as(
        "SELECT scope_type, belief, plausibility, pignistic_prob FROM ds_combined_beliefs \
          WHERE claim_id = $1 ORDER BY scope_type",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read scoped rows")
}

/// Every value column of one `ds_combined_beliefs` row.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
struct ScopedRow {
    belief: Option<f64>,
    plausibility: Option<f64>,
    mass_on_empty: Option<f64>,
    mass_on_missing: Option<f64>,
    conflict_k: Option<f64>,
    strategy_used: Option<String>,
    pignistic_prob: Option<f64>,
}

async fn seed_scoped_row(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    scope: (&str, Option<Uuid>),
    belief: f64,
    strategy: &str,
) {
    sqlx::query(
        "INSERT INTO ds_combined_beliefs (frame_id, claim_id, scope_type, scope_id, belief, \
             plausibility, mass_on_empty, mass_on_missing, conflict_k, strategy_used, \
             pignistic_prob) \
         VALUES ($1, $2, $3, $4, $5, 0.913, 0.007, 0.011, 0.019, $6, 0.517)",
    )
    .bind(frame)
    .bind(claim)
    .bind(scope.0)
    .bind(scope.1)
    .bind(belief)
    .bind(strategy)
    .execute(pool)
    .await
    .expect("seed scoped row");
}

async fn scoped_row(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    scope: (&str, Option<Uuid>),
) -> ScopedRow {
    sqlx::query_as(
        "SELECT belief, plausibility, mass_on_empty, mass_on_missing, conflict_k, \
                strategy_used, pignistic_prob \
           FROM ds_combined_beliefs \
          WHERE claim_id = $1 AND frame_id = $2 AND scope_type = $3 \
            AND scope_id IS NOT DISTINCT FROM $4",
    )
    .bind(claim)
    .bind(frame)
    .bind(scope.0)
    .bind(scope.1)
    .fetch_one(pool)
    .await
    .expect("read scoped row")
}

async fn perspective(pool: &PgPool, owner: Uuid, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("{name} {}", Uuid::new_v4()))
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("seed perspective")
}

async fn community(pool: &PgPool, name: &str, members: &[Uuid]) -> Uuid {
    let id: Uuid = sqlx::query_scalar("INSERT INTO communities (name) VALUES ($1) RETURNING id")
        .bind(format!("{name} {}", Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("seed community");
    for m in members {
        sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
            .bind(id)
            .bind(m)
            .execute(pool)
            .await
            .expect("seed community member");
    }
    id
}

fn assert_row_is_fold(row: &ScopedRow, twin: &Cache, what: &str) {
    for (got, want, col) in [
        (row.belief, twin.belief, "belief"),
        (row.plausibility, twin.plausibility, "plausibility"),
        (row.pignistic_prob, twin.pignistic_prob, "pignistic_prob"),
        (row.mass_on_missing, twin.mass_on_missing, "mass_on_missing"),
    ] {
        let (got, want) = (got.expect(col), want.expect(col));
        assert!(
            (got - want).abs() < 1e-12,
            "{what}: {col} {got} is not the twin's fold {want}\nrow: {row:?}\ntwin: {twin:?}"
        );
    }
    assert_eq!(
        row.strategy_used.as_deref(),
        Some("atom_fold"),
        "{what}: a resynced row is marked atom_fold: {row:?}"
    );
}

/// SPEC §7.2 per-frame rows: `ds_combined_beliefs` holds one row per (frame,
/// scope), each the fold of that frame's rows in that scope
/// (`routes/belief.rs::submit_evidence`). A wave resyncs a row on a
/// 2-hypothesis frame from the AEF fold of the atom's rows on THAT frame in
/// THAT scope, each checked against a TWIN claim holding only those rows. It
/// leaves alone every row the AEF does not fold, compared column for column:
/// a row on a frame of more than two hypotheses (its Bel/Pl are of one
/// hypothesis of that frame, not of the coarsened TRUE), a perspective row on
/// a frame where that perspective has no row, a perspective with no row at
/// all, and a community `override` row. A community row is the fold of its
/// member perspectives' rows.
#[sqlx::test(migrations = "../../migrations")]
async fn scoped_rows_resync_per_frame_and_keep_what_the_aef_does_not_fold(pool: PgPool) {
    let dir = scratch_dir();
    let owner = agent(&pool, "frames-owner").await;
    let source = agent(&pool, "frames-source").await;
    let other_source = agent(&pool, "frames-other-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let bin2 = frame(&pool, "cohort_v2_binary_two").await;
    let tri: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, description, hypotheses) \
         VALUES ('cohort_v2_three', 'cohort v2 test frame', ARRAY['A', 'B', 'C']) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("three-hypothesis frame");
    let p = perspective(&pool, owner, "with rows").await;
    let q = perspective(&pool, owner, "without rows").await;
    let members = community(&pool, "members", &[p]).await;
    let overridden = community(&pool, "override", &[p]).await;

    let bin_plain = evidence_row(bin, source, 0.8, None);
    let bin_p = || Row {
        perspective_id: Some(p),
        ..evidence_row(bin, other_source, 0.55, None)
    };
    let bin2_plain = evidence_row(bin2, source, 0.3, None);

    let atom = claim(&pool, owner, "atom on two frames").await;
    insert_row(&pool, atom, &bin_plain).await;
    insert_row(&pool, atom, &bin_p()).await;
    insert_row(&pool, atom, &bin2_plain).await;
    // The twins: each holds only the rows one scoped row folds.
    let twin_bin = claim(&pool, owner, "twin: the binary frame's rows").await;
    insert_row(&pool, twin_bin, &bin_plain).await;
    insert_row(&pool, twin_bin, &bin_p()).await;
    let twin_bin2 = claim(&pool, owner, "twin: the second frame's row").await;
    insert_row(&pool, twin_bin2, &bin2_plain).await;
    let twin_p = claim(&pool, owner, "twin: the perspective's row").await;
    insert_row(&pool, twin_p, &bin_p()).await;
    set_sentinel(&pool, atom, bin, 0.0).await;

    let rewritten = [
        (
            "global on the binary frame",
            bin,
            ("global", None),
            twin_bin,
        ),
        (
            "global on the second frame",
            bin2,
            ("global", None),
            twin_bin2,
        ),
        (
            "perspective on the binary frame",
            bin,
            ("perspective", Some(p)),
            twin_p,
        ),
        (
            "community of the perspective",
            bin,
            ("community", Some(members)),
            twin_p,
        ),
    ];
    let kept = [
        (
            "global on a three-hypothesis frame",
            tri,
            ("global", None),
            "seeded",
        ),
        (
            "perspective on a frame it has no row on",
            bin2,
            ("perspective", Some(p)),
            "seeded",
        ),
        (
            "perspective with no row",
            bin,
            ("perspective", Some(q)),
            "seeded",
        ),
        (
            "community override",
            bin,
            ("community", Some(overridden)),
            "override",
        ),
    ];
    for (i, (_, f, scope, _)) in rewritten.iter().enumerate() {
        #[allow(clippy::cast_precision_loss)]
        seed_scoped_row(&pool, atom, *f, *scope, 0.101 + 0.01 * i as f64, "seeded").await;
    }
    let mut kept_before = Vec::new();
    for (i, (_, f, scope, strategy)) in kept.iter().enumerate() {
        #[allow(clippy::cast_precision_loss)]
        seed_scoped_row(&pool, atom, *f, *scope, 0.201 + 0.01 * i as f64, strategy).await;
        kept_before.push(scoped_row(&pool, atom, *f, *scope).await);
    }

    let env = WaveEnv::new(&pool, "aef_standalone").await;
    let wave_file = dir.join("wave.jsonl");
    run(
        RECOMPUTE_BETP,
        &dir,
        &real_run_args("standalone", s(&wave_file), s(&dir)),
        &env.vars(),
    )
    .ok("the wave");

    for (what, f, scope, twin) in rewritten {
        let row = scoped_row(&pool, atom, f, scope).await;
        assert_row_is_fold(&row, &cache(&pool, twin).await, what);
    }
    for ((what, f, scope, _), before) in kept.iter().zip(&kept_before) {
        assert_eq!(
            &scoped_row(&pool, atom, *f, *scope).await,
            before,
            "the wave rewrote a row the AEF does not fold: {what}"
        );
    }
    // The fixture: each frame's fold differs from the atom's whole fold, so
    // a row given the whole fold fails above.
    let whole = cache(&pool, atom).await;
    for twin in [twin_bin, twin_bin2] {
        let t = cache(&pool, twin).await;
        assert!(
            (t.belief.unwrap() - whole.belief.unwrap()).abs() > 1e-6,
            "fixture: one frame's fold must differ from the whole fold: {t:?} vs {whole:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── a claim whose role changed after the cohort was selected ───────────────

/// A wave writes only claims of its own role (SPEC §10.7: the standalone and
/// leaf waves are reviewed and applied separately). A claim selected as a
/// standalone that is a leaf by the time its write runs (a decomposition
/// landed in between) is skipped: written neither with the legacy owner fold
/// (under `aef_standalone`, which does not fold leaves) nor with the AEF
/// (under `aef`, in a wave nobody reviewed it in), and nothing is recorded.
/// The same claim in a leaf wave under `aef` is written (the control).
#[sqlx::test(migrations = "../../migrations")]
async fn a_wave_write_skips_a_claim_whose_role_changed(pool: PgPool) {
    use epigraph_cli::recompute_betp::{write_wave_claim, WaveLog, WaveRole};
    use epigraph_engine::atom_items::{AtomFoldMode, CompoundSourceEdges};
    use epigraph_engine::edge_factor::AtomCacheSettings;

    let dir = scratch_dir();
    let owner = agent(&pool, "role-owner").await;
    let source = agent(&pool, "role-source").await;
    let bin = frame(&pool, "cohort_v2_binary").await;
    let parent = claim(&pool, owner, "the decomposition that landed").await;
    let leaf = claim(&pool, owner, "selected as a standalone, now a leaf").await;
    decomposes_to(&pool, parent, leaf).await;
    insert_row(&pool, leaf, &evidence_row(bin, source, 0.7, None)).await;
    let before = set_sentinel(&pool, leaf, bin, 0.0).await;
    let viewer = fixture::public_viewer(&pool).await;
    let settings = |fold| AtomCacheSettings {
        fold,
        compound_source_edges: CompoundSourceEdges::Frozen,
        vacate_on_evidence_removal: true,
    };
    let wave_file = dir.join("wave.jsonl");
    let log = WaveLog::open(&wave_file, "test-wave", chrono::Utc::now()).expect("open the log");

    for fold in [AtomFoldMode::AefStandalone, AtomFoldMode::Aef] {
        let o = write_wave_claim(
            &pool,
            &viewer,
            leaf,
            WaveRole::Standalone,
            settings(fold),
            &log,
        )
        .await
        .expect("write_wave_claim");
        assert!(
            !o.changed,
            "a standalone wave under {fold:?} changed a leaf: {o:?}"
        );
        assert_eq!(
            cache(&pool, leaf).await,
            before,
            "a standalone wave under {fold:?} wrote a leaf's cache"
        );
    }
    assert!(
        std::fs::read(&wave_file).unwrap_or_default().is_empty(),
        "a skipped claim is not recorded"
    );

    let o = write_wave_claim(
        &pool,
        &viewer,
        leaf,
        WaveRole::Leaf,
        settings(AtomFoldMode::Aef),
        &log,
    )
    .await
    .expect("write_wave_claim");
    assert!(o.changed, "control: the leaf wave writes the leaf: {o:?}");
    assert_ne!(
        cache(&pool, leaf).await,
        before,
        "control: the leaf wave wrote"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
