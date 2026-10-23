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
    let r = run(
        SNAPSHOT,
        dir,
        &["--out", s(&out)],
        &[("DATABASE_URL", db)],
    );
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
/// role; the evidenced claims of the same role are (the control).
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
    insert_row(&pool, evidenced_standalone, &evidence_row(bin, source, 0.7, None)).await;

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

    let s0 = take_snapshot(&db, &dir, "s0.jsonl");
    let standalone = report_ids(&dry_wave(&db, &dir, "standalone", "aef_standalone", &s0));
    let leaf = report_ids(&dry_wave(&db, &dir, "leaf", "aef", &s0));

    assert!(
        standalone.contains(&evidenced_standalone),
        "the evidenced standalone is in the standalone wave: {standalone:?}"
    );
    assert!(
        leaf.contains(&evidenced_leaf),
        "the evidenced leaf is in the leaf wave: {leaf:?}"
    );
    for (wave, ids) in [("standalone", &standalone), ("leaf", &leaf)] {
        for (what, id) in [
            ("template-only standalone", template_standalone),
            ("template-only leaf", template_leaf),
            ("compound", parent),
        ] {
            assert!(
                !ids.contains(&id),
                "the {what} is in the {wave} wave cohort: {ids:?}"
            );
        }
    }
    assert!(!standalone.contains(&evidenced_leaf), "a leaf is not a standalone");
    assert!(!leaf.contains(&evidenced_standalone), "a standalone is not a leaf");
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
    insert_row(pool, listed_evidenced, &evidence_row(bin, source, 0.7, None)).await;
    let listed_compound = claim(pool, owner, "listed compound").await;
    let child = claim(pool, owner, "the compound's leaf").await;
    decomposes_to(pool, listed_compound, child).await;
    insert_row(pool, listed_compound, &template_row(rv, ingest)).await;

    let mut before = HashMap::new();
    for (i, id) in [listed_residue, unlisted_residue, listed_evidenced, listed_compound]
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
/// explicit vacuous value (Bel 0, Pl 1, BetP .5) on `binary_truth`, never
/// NULL, it is not in any wave cohort (not P1), and the wave file holds the
/// record a compare-and-swap restore needs (`written` is the row as stored).
#[sqlx::test(migrations = "../../migrations")]
async fn a_vacated_atom_reads_back_unproven_with_a_non_null_cache(pool: PgPool) {
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
    assert!(
        after.belief_frame_id.is_some() && after.belief_frame_id == binary_truth_id(&pool).await,
        "the vacuous cache is stamped binary_truth: {after:?}"
    );

    let s0 = take_snapshot(&env.db, &dir, "after-vacate.jsonl");
    let cohort = report_ids(&dry_wave(&env.db, &dir, "standalone", "aef_standalone", &s0));
    assert!(
        !cohort.contains(&f.listed_residue),
        "a vacated atom has no AEF input, so it is not in a wave: {cohort:?}"
    );

    let records = read_wave(std::io::BufReader::new(
        std::fs::File::open(&wave_file).expect("the wave file exists"),
    ))
    .expect("parse the wave file");
    let mine: Vec<_> = records
        .iter()
        .filter(|r| r.claim_id == f.listed_residue)
        .collect();
    assert_eq!(mine.len(), 1, "one record for the vacated claim: {records:?}");
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
    assert_eq!(records.len(), 1, "nothing else was written: {records:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ── (4) compounds ───────────────────────────────────────────────────────────

/// A compound is never written: not by a leaf wave, not by a standalone wave,
/// and not when it is on the accept list. Its leaf in the same run is (the
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
    let list = write_accept_list(&dir, &[compound]);
    for role in ["leaf", "standalone"] {
        let wave_file = dir.join(format!("wave-{role}.jsonl"));
        let mut args = real_run_args(role, s(&wave_file), s(&dir));
        args.extend(["--accept-vacate", s(&list)]);
        run(RECOMPUTE_BETP, &dir, &args, &env.vars()).ok(&format!("{role} wave"));
        assert_eq!(
            cache(&pool, compound).await,
            compound_before,
            "the {role} wave wrote a compound's cache"
        );
    }
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
    assert_eq!(belief_state(&pool).await, state, "a refused run writes nothing");

    let v1_apply = run(RECOMPUTE_BETP, &dir, &[], &env.vars());
    assert!(
        v1_apply.code.is_some_and(|c| c != 0) && v1_apply.stderr.contains("--role"),
        "a writing run with no wave (the cohort-v1 apply) must refuse, naming --role; \
         got {:?}\nstderr: {}",
        v1_apply.code,
        v1_apply.stderr
    );
    assert_eq!(belief_state(&pool).await, state, "a refused run writes nothing");

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
/// * (3c) paper-key grouping: two agents' rows citing one DOI;
/// * (4) attribution: an `attributed_v1` row.
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
    insert_row(&pool, one_paper, &evidence_row(bin, source, 0.7, Some(ev_a))).await;
    insert_row(&pool, one_paper, &evidence_row(bin, other_source, 0.7, Some(ev_b))).await;
    set_sentinel(&pool, one_paper, bin, 0.02).await;

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

    let seeded = [organic, clamped, templated, one_paper, attributed];
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
                assert!(v.abs() > 1e-9, "({key}) must be nonzero where its cause is: {}", by_id[&id]);
            } else {
                assert!(v.abs() <= 1e-9, "({key}) must be zero without its cause: {}", by_id[&id]);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── (7) the disk gate ───────────────────────────────────────────────────────

/// SPEC §10.4 disk gate: checked before every batch, a failure aborts before
/// the batch writes. A run whose first check fails writes nothing and records
/// nothing; the same run with a passing check writes (the control).
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
        &[
            "--role",
            "standalone",
            "--snapshot",
            s(&wave_file),
            "--wave",
            "test-wave",
            "--disk-path",
            s(&dir),
            // No volume has this much free space.
            "--min-free-gb",
            "1000000000",
        ],
        &env.vars(),
    );
    assert!(
        failing.code.is_some_and(|c| c != 0),
        "a failed disk check must stop the run with a non-zero exit; got {:?}\nstdout: {}",
        failing.code,
        failing.stdout
    );
    assert!(
        failing.stderr.contains("disk"),
        "the abort must say the disk check failed\nstderr: {}",
        failing.stderr
    );
    assert_eq!(belief_state(&pool).await, state, "a failed disk check writes nothing");
    let recorded = std::fs::read_to_string(&wave_file).unwrap_or_default();
    assert!(
        recorded.trim().is_empty(),
        "a failed disk check records nothing: {recorded}"
    );

    let failing_cmd = run(
        RECOMPUTE_BETP,
        &dir,
        &{
            let mut a = real_run_args("standalone", s(&wave_file), s(&dir));
            a.extend(["--disk-check-cmd", "exit 7"]);
            a
        },
        &env.vars(),
    );
    assert!(
        failing_cmd.code.is_some_and(|c| c != 0) && failing_cmd.stderr.contains("disk"),
        "a failing --disk-check-cmd stops the run; got {:?}\nstderr: {}",
        failing_cmd.code,
        failing_cmd.stderr
    );
    assert_eq!(belief_state(&pool).await, state, "a failed disk check writes nothing");

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
    for (scope, scope_id, b) in [("global", None, 0.123), ("perspective", Some(perspective), 0.321)] {
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
    let scoped_before: Vec<(String, f64, f64, Option<f64>)> = scoped(&pool, atom).await;
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
        (after.belief.unwrap(), after.plausibility.unwrap(), after.pignistic_prob),
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
    assert_eq!(cache(&pool, atom).await, atom_before, "the claim cache is restored");
    assert_eq!(
        scoped(&pool, atom).await,
        scoped_before,
        "the scoped rows are restored"
    );
    let _ = std::fs::remove_dir_all(&dir);
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
