//! `recompute_claim_belief --snapshot <wave file>`: every cache write the
//! recompute makes is recorded as a `belief_cache::WaveRecord`, so
//! `restore_belief_cache --from <wave file>` can undo exactly that run by
//! compare-and-swap (R-176 apply prerequisite; calibration-recompute plan
//! §4.5 (1a), OD-2).
//!
//! Both binaries run as real processes with a cleared environment, as an
//! operator runs them. Claim caches start on a SENTINEL no fold produces and
//! every claim carries a real BBA on its owner frame, so each test first
//! proves the recompute MOVED the cache (a recompute that wrote nothing would
//! otherwise read as a restore that "worked"). Restored values are compared
//! with what the database held before the run, never with a value this file
//! computes.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::belief_cache::{read_cache_columns, read_wave, CacheColumns, WaveRecord};

const RECOMPUTE: &str = env!("CARGO_BIN_EXE_recompute_claim_belief");
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

    fn count(&self, key: &str) -> usize {
        self.stdout
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}: ")))
            .unwrap_or_else(|| panic!("no `{key}:` line in stdout:\n{}", self.stdout))
            .trim()
            .parse()
            .expect("a count")
    }
}

/// Run `bin` with only `DATABASE_URL` (plus `PATH`), from `cwd`.
fn run(bin: &str, cwd: &Path, db: &str, args: &[&str]) -> Run {
    let out = Command::new(bin)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "warn")
        .env("DATABASE_URL", db)
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("run the binary");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn scratch_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("recompute-claim-snapshot-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

fn s(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

fn write_ids(dir: &Path, ids: &[Uuid]) -> PathBuf {
    let p = dir.join("ids.txt");
    let body: String = ids.iter().map(|id| format!("{id}\n")).collect();
    std::fs::write(&p, body).expect("write the id list");
    p
}

/// The wave file's records; an absent file reads as none.
fn wave_records(path: &Path) -> Vec<WaveRecord> {
    match std::fs::File::open(path) {
        Ok(f) => read_wave(std::io::BufReader::new(f)).expect("parse the wave file"),
        Err(_) => Vec::new(),
    }
}

// ── seeding ────────────────────────────────────────────────────────────────

async fn agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'recompute-snapshot-test', 'system', \
                 ARRAY['test']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A two-hypothesis frame of its own, so the claims' only input frame is
/// their owner frame.
async fn frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, description, hypotheses) \
         VALUES ($1, 'recompute snapshot test frame', ARRAY['TRUE', 'FALSE']) RETURNING id",
    )
    .bind(format!("recompute_snapshot_{}", Uuid::new_v4().simple()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

async fn claim(pool: &PgPool, owner: Uuid) -> Uuid {
    let content = format!("recompute snapshot claim {}", Uuid::new_v4());
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

/// One substantive support-leaning BBA of `claim` on `frame`.
async fn bba(pool: &PgPool, claim: Uuid, frame: Uuid, source: Uuid, support: f64) {
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) \
         VALUES ($1, $2, 0) ON CONFLICT DO NOTHING",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("assign claim to frame");
    sqlx::query(
        "INSERT INTO mass_functions \
           (claim_id, frame_id, source_agent_id, masses, conflict_k, combination_method, \
            source_strength, evidence_type, locality_tag) \
         VALUES ($1, $2, $3, $4, 0.0, 'auto_wire', 0.9, 'empirical', 'unknown')",
    )
    .bind(claim)
    .bind(frame)
    .bind(source)
    .bind(serde_json::json!({ "0": support, "0,1": 1.0 - support }))
    .execute(pool)
    .await
    .expect("insert BBA");
}

/// Put a cache on `claim` that no fold produces, recorded on `frame`; `nudge`
/// keeps the sentinels of different claims apart.
async fn set_sentinel(pool: &PgPool, claim: Uuid, frame: Uuid, nudge: f64) -> CacheColumns {
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

async fn cache(pool: &PgPool, claim: Uuid) -> CacheColumns {
    read_cache_columns(pool, &[claim])
        .await
        .expect("read cache")
        .remove(&claim)
        .expect("claim exists")
}

/// A fingerprint of every claim's cache columns.
async fn cache_state(pool: &PgPool) -> String {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT md5(string_agg(concat_ws('|', id, belief, plausibility, mass_on_empty, \
         pignistic_prob, mass_on_missing, belief_frame_id, classification, updated_at), \
         ',' ORDER BY id)) FROM claims",
    )
    .fetch_one(pool)
    .await
    .expect("cache fingerprint")
    .unwrap_or_default()
}

/// `n` claims with a BBA on one fresh frame and a distinct sentinel each.
async fn seeded(pool: &PgPool, n: usize) -> (Vec<Uuid>, Vec<CacheColumns>) {
    let owner = agent(pool).await;
    let f = frame(pool).await;
    let mut ids = Vec::new();
    let mut sentinels = Vec::new();
    for i in 0..n {
        let id = claim(pool, owner).await;
        bba(pool, id, f, owner, 0.6 + 0.05 * i as f64).await;
        sentinels.push(set_sentinel(pool, id, f, 0.01 * i as f64).await);
        ids.push(id);
    }
    (ids, sentinels)
}

/// The wave file's raw bytes split into lines, each with its `\n`; a cut
/// line (no `\n`) is the last element.
fn raw_lines(path: &Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(path).expect("read the wave file");
    bytes
        .split_inclusive(|b| *b == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

// ── tests ──────────────────────────────────────────────────────────────────

/// The round trip the R-176 apply's rollback rests on: each claim the run
/// changed has one record whose `before` is the cache it found and whose
/// `written` is what it left; a claim with no input is neither written nor
/// recorded; and the restore puts back exactly the prior cache, all seven
/// columns.
#[sqlx::test(migrations = "../../migrations")]
async fn a_snapshot_run_then_restore_puts_back_the_exact_prior_cache(pool: PgPool) {
    let db = fixture::database_url_for(&pool).await;
    let dir = scratch_dir();
    let (ids, sentinels) = seeded(&pool, 2).await;
    // A claim with no BBA: the recompute leaves its cache as it was.
    let no_input = claim(&pool, agent(&pool).await).await;
    let no_input_frame = frame(&pool).await;
    let no_input_cache = set_sentinel(&pool, no_input, no_input_frame, 0.05).await;

    let wave = dir.join("wave.jsonl");
    let list = write_ids(&dir, &[ids[0], ids[1], no_input]);
    let r = run(
        RECOMPUTE,
        &dir,
        &db,
        &[
            "--input",
            s(&list),
            "--snapshot",
            s(&wave),
            "--wave",
            "cal2-test",
        ],
    );
    r.ok("recompute --snapshot");

    // The recompute moved both caches (else the restore below proves nothing).
    let mut written = Vec::new();
    for (id, sentinel) in ids.iter().zip(&sentinels) {
        let now = cache(&pool, *id).await;
        assert_ne!(&now, sentinel, "the recompute did not write claim {id}");
        written.push(now);
    }
    assert_eq!(
        cache(&pool, no_input).await,
        no_input_cache,
        "a claim with no input was written"
    );

    let records = wave_records(&wave);
    assert_eq!(
        records.len(),
        2,
        "one record per changed claim, none for the claim with no input: {records:?}"
    );
    for (i, id) in ids.iter().enumerate() {
        let rec = records
            .iter()
            .find(|r| r.claim_id == *id)
            .unwrap_or_else(|| panic!("no record for claim {id}"));
        assert_eq!(
            rec.before, sentinels[i],
            "`before` is not the cache the run found"
        );
        assert_eq!(
            rec.written, written[i],
            "`written` is not what the run left"
        );
        assert_eq!(rec.wave, "cal2-test");
    }
    let stamps: HashSet<_> = records.iter().map(|r| r.at).collect();
    assert_eq!(stamps.len(), 1, "one `at` per run");

    let r = run(RESTORE, &dir, &db, &["--from", s(&wave)]);
    r.ok("restore --from");
    assert_eq!(r.count("restored"), 2);
    for (id, sentinel) in ids.iter().zip(&sentinels) {
        assert_eq!(
            &cache(&pool, *id).await,
            sentinel,
            "the restore did not put back claim {id}'s exact prior cache"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A claim whose cache a later writer changed after the run is NOT rolled
/// back (compare-and-swap): the restore reports it `superseded_since_wave`
/// and leaves the later value, while the untouched claim is restored.
#[sqlx::test(migrations = "../../migrations")]
async fn a_restore_after_a_concurrent_change_refuses_that_claim(pool: PgPool) {
    let db = fixture::database_url_for(&pool).await;
    let dir = scratch_dir();
    let (ids, sentinels) = seeded(&pool, 2).await;

    let wave = dir.join("wave.jsonl");
    let list = write_ids(&dir, &ids);
    run(
        RECOMPUTE,
        &dir,
        &db,
        &["--input", s(&list), "--snapshot", s(&wave)],
    )
    .ok("recompute --snapshot");
    assert_eq!(wave_records(&wave).len(), 2, "both writes recorded");
    for (id, sentinel) in ids.iter().zip(&sentinels) {
        assert_ne!(&cache(&pool, *id).await, sentinel, "claim {id} not written");
    }

    // Another writer lands on the second claim after the run.
    let other_frame = frame(&pool).await;
    let later = set_sentinel(&pool, ids[1], other_frame, 0.07).await;

    let r = run(RESTORE, &dir, &db, &["--from", s(&wave)]);
    r.ok("restore --from");
    assert_eq!(r.count("restored"), 1);
    assert_eq!(r.count("superseded_since_wave"), 1);
    assert_eq!(
        cache(&pool, ids[0]).await,
        sentinels[0],
        "untouched claim restored"
    );
    assert_eq!(
        cache(&pool, ids[1]).await,
        later,
        "the restore overwrote a write that landed after the run"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A wave file the run cannot open, or one that already holds a run's
/// records, is refused before any claim is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_snapshot_that_cannot_be_opened_refuses_before_any_write(pool: PgPool) {
    let db = fixture::database_url_for(&pool).await;
    let dir = scratch_dir();
    let (ids, _) = seeded(&pool, 2).await;
    let list = write_ids(&dir, &ids);
    let state = cache_state(&pool).await;

    let unopenable = dir.join("no-such-dir").join("wave.jsonl");
    let r = run(
        RECOMPUTE,
        &dir,
        &db,
        &["--input", s(&list), "--snapshot", s(&unopenable)],
    );
    assert_ne!(
        r.code,
        Some(0),
        "an unopenable wave file must be refused\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert!(
        r.stderr.contains(s(&unopenable)),
        "refused for the wrong reason: {}",
        r.stderr
    );
    assert_eq!(
        cache_state(&pool).await,
        state,
        "the refused run wrote a cache"
    );

    let used = dir.join("used.jsonl");
    std::fs::write(&used, "{\"an earlier run\":1}\n").expect("seed a used wave file");
    let r = run(
        RECOMPUTE,
        &dir,
        &db,
        &["--input", s(&list), "--snapshot", s(&used)],
    );
    assert_ne!(
        r.code,
        Some(0),
        "a wave file holding records must be refused\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert!(
        r.stderr.contains("already holds records"),
        "refused for the wrong reason: {}",
        r.stderr
    );
    assert_eq!(
        std::fs::read_to_string(&used).unwrap(),
        "{\"an earlier run\":1}\n",
        "the earlier run's records were touched"
    );
    assert_eq!(
        cache_state(&pool).await,
        state,
        "the refused run wrote a cache"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A record that cannot be written (the device is full) means that claim's
/// write is never committed, and the run stops rather than writing claims it
/// can no longer record: no claim leaves its sentinel.
#[sqlx::test(migrations = "../../migrations")]
async fn a_record_that_cannot_be_written_leaves_the_claim_unwritten_and_stops_the_run(
    pool: PgPool,
) {
    assert!(
        Path::new("/dev/full").exists(),
        "this test needs /dev/full to make every wave-file write fail"
    );
    let db = fixture::database_url_for(&pool).await;
    let dir = scratch_dir();
    let (ids, sentinels) = seeded(&pool, 3).await;
    let list = write_ids(&dir, &ids);
    // Opens fine (append to a character device); every write fails ENOSPC.
    let wave = dir.join("wave.jsonl");
    std::os::unix::fs::symlink("/dev/full", &wave).expect("symlink the wave file to /dev/full");

    let r = run(
        RECOMPUTE,
        &dir,
        &db,
        &[
            "--input",
            s(&list),
            "--snapshot",
            s(&wave),
            "--concurrency",
            "1",
        ],
    );
    assert_ne!(
        r.code,
        Some(0),
        "a run whose records cannot be written must fail\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    for (id, sentinel) in ids.iter().zip(&sentinels) {
        assert_eq!(
            &cache(&pool, *id).await,
            sentinel,
            "claim {id} was written without a record of its prior cache"
        );
    }
    assert!(
        r.stderr.contains("wave file"),
        "failed for the wrong reason: {}",
        r.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The volume fills up PART-WAY through a record (a short write, then
/// `EFBIG`): the cut line is taken back off the wave file, so the file still
/// parses and `restore_belief_cache --from` (the restore the STOP message
/// points at) undoes the one write that committed. A cut line left in place
/// would make the restore refuse the whole file.
///
/// The fill is a file-size limit (`ulimit -f`, 512-byte blocks, `SIGXFSZ`
/// ignored so the write fails instead of killing the run) placed inside the
/// second record. Where it falls is measured, not guessed: a first run of
/// identically shaped claims gives the record length, and the `--wave` name
/// pads each record so the limit lands a third of the way into record 2.
#[sqlx::test(migrations = "../../migrations")]
async fn a_record_cut_short_by_a_full_volume_leaves_a_wave_file_the_restore_reads(pool: PgPool) {
    let db = fixture::database_url_for(&pool).await;
    let dir = scratch_dir();
    const WAVE: &str = "cal2-straddle";

    // Calibration: the same values on other claims, into a throwaway file.
    let (cal_ids, _) = seeded(&pool, 3).await;
    let cal_wave = dir.join("calibration.jsonl");
    let cal_list = write_ids(&dir, &cal_ids);
    run(
        RECOMPUTE,
        &dir,
        &db,
        &[
            "--input",
            s(&cal_list),
            "--snapshot",
            s(&cal_wave),
            "--wave",
            WAVE,
            "--concurrency",
            "1",
        ],
    )
    .ok("calibration run");
    let cal = raw_lines(&cal_wave);
    assert_eq!(cal.len(), 3, "calibration: one record per claim");
    let first = cal[0].len();
    let longest = cal.iter().map(Vec::len).max().expect("a record");
    // The smallest block count whose two-thirds point lies past every
    // record; pad record 1 to end exactly there.
    let blocks = (1..)
        .find(|k| 1024 * k / 3 >= longest)
        .expect("a block count");
    let limit = 512 * blocks;
    let pad = 1024 * blocks / 3 - first;
    let wave_name = format!("{WAVE}{}", "x".repeat(pad));
    let line_len = |i: usize| cal[i].len() + pad;
    assert!(
        line_len(0) < limit && limit < line_len(0) + line_len(1),
        "the limit ({limit} bytes) does not fall inside record 2 ({} .. {})",
        line_len(0),
        line_len(0) + line_len(1)
    );

    let (ids, sentinels) = seeded(&pool, 3).await;
    let wave = dir.join("wave.jsonl");
    let list = write_ids(&dir, &ids);
    let blocks_arg = blocks.to_string();
    let r = run(
        "/bin/sh",
        &dir,
        &db,
        &[
            "-c",
            r#"trap "" XFSZ; ulimit -f "$1" || exit 99; shift; exec "$@""#,
            "sh",
            &blocks_arg,
            RECOMPUTE,
            "--input",
            s(&list),
            "--snapshot",
            s(&wave),
            "--wave",
            &wave_name,
            "--concurrency",
            "1",
        ],
    );
    assert_eq!(
        r.code,
        Some(3),
        "the run must STOP on the cut record (exit 3)\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert_eq!(r.count("recorded"), 1, "claim 1 recorded, claim 2 not");
    assert!(
        r.stderr.contains("1 claims were not attempted"),
        "claim 3 was attempted: {}",
        r.stderr
    );
    let written_1 = cache(&pool, ids[0]).await;
    assert_ne!(written_1, sentinels[0], "claim 1 was not written");
    for i in 1..3 {
        assert_eq!(
            cache(&pool, ids[i]).await,
            sentinels[i],
            "claim {} was written without a record",
            i + 1
        );
    }

    let lines = raw_lines(&wave);
    let tail = lines
        .last()
        .filter(|l| !l.ends_with(b"\n"))
        .map_or(0, Vec::len);
    let r = run(RESTORE, &dir, &db, &["--from", s(&wave)]);
    assert_eq!(
        r.code,
        Some(0),
        "the restore refused the wave file a full volume left ({tail} bytes of a cut record \
         after the last whole line)\nstdout: {}\nstderr: {}",
        r.stdout,
        r.stderr
    );
    assert_eq!(tail, 0, "a cut record was left in the wave file");
    assert_eq!(lines.len(), 1, "the wave file holds one whole record");
    assert_eq!(r.count("restored"), 1);
    assert_eq!(
        cache(&pool, ids[0]).await,
        sentinels[0],
        "the restore did not put back claim 1's exact prior cache"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
