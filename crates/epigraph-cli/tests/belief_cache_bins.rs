//! The `belief_snapshot` and `restore_belief_cache` binaries as real
//! processes: argument wiring, the no-overwrite rule for a snapshot, the
//! `--claims` filter, `--dry-run` rolling back, and the output files. The
//! properties of the operations themselves are pinned in
//! `belief_cache_restore.rs`.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::belief_cache::{
    read_cache_columns, read_snapshot, write_wave_record, CacheColumns, WaveRecord,
};

const SNAPSHOT: &str = env!("CARGO_BIN_EXE_belief_snapshot");
const RESTORE: &str = env!("CARGO_BIN_EXE_restore_belief_cache");

fn scratch_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("belief-cache-bins-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

/// A cleared environment (no operator DSN leaks in) and a cwd with no `.env`.
fn run(bin: &str, cwd: &Path, database_url: Option<&str>, args: &[&str]) -> Output {
    let mut c = Command::new(bin);
    c.env_clear().current_dir(cwd).args(args);
    if let Some(url) = database_url {
        c.env("DATABASE_URL", url);
    }
    c.output().expect("spawn")
}

fn stdout_count(out: &Output, key: &str) -> usize {
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")))
        .unwrap_or_else(|| panic!("no `{key}:` line in stdout"))
        .trim()
        .parse()
        .expect("a count")
}

#[test]
fn belief_snapshot_never_overwrites_an_existing_out() {
    let dir = scratch_dir();
    let out = dir.join("s0.jsonl");
    std::fs::write(&out, "baseline\n").expect("seed existing file");

    // No DATABASE_URL: the refusal must come before any connection attempt.
    let o = run(SNAPSHOT, &dir, None, &["--out", out.to_str().unwrap()]);
    assert!(!o.status.success(), "an existing --out must be refused");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("already exists"),
        "refused for the wrong reason"
    );
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "baseline\n");
    assert!(!dir.join("s0.jsonl.partial").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

async fn seed_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let content = format!("belief cache bins claim {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn set_cache(pool: &PgPool, id: Uuid, v: f64, class: Option<&str>) {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $2, pignistic_prob = $2, \
                mass_on_empty = 0.0, mass_on_missing = 0.0, classification = $3 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(v)
    .bind(class)
    .execute(pool)
    .await
    .expect("set cache");
}

async fn cache_of(pool: &PgPool, id: Uuid) -> CacheColumns {
    read_cache_columns(pool, &[id])
        .await
        .expect("read")
        .remove(&id)
        .expect("exists")
}

#[sqlx::test(migrations = "../../migrations")]
async fn snapshot_then_dry_run_then_restore_through_the_binaries(pool: PgPool) {
    let url = viewer_fixture::database_url_for(&pool).await;
    let dir = scratch_dir();
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'belief-cache-bins-test', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed agent");

    let ids = [
        seed_claim(&pool, agent).await,
        seed_claim(&pool, agent).await,
        seed_claim(&pool, agent).await,
    ];
    for (i, &id) in ids.iter().enumerate() {
        set_cache(&pool, id, 0.1 + 0.1 * i as f64, None).await;
    }

    // Snapshot S0 through the binary.
    let s0 = dir.join("s0.jsonl");
    let o = run(
        SNAPSHOT,
        &dir,
        Some(&url),
        &["--out", s0.to_str().unwrap(), "--page-size", "2"],
    );
    assert!(o.status.success(), "belief_snapshot failed");
    let rows = read_snapshot(std::io::BufReader::new(std::fs::File::open(&s0).unwrap()))
        .expect("read snapshot");
    assert_eq!(stdout_count(&o, "rows"), rows.len());
    for &id in &ids {
        let row = rows
            .iter()
            .find(|r| r.claim_id == id)
            .expect("seeded claim in S0");
        assert_eq!(row.cache(), cache_of(&pool, id).await);
    }

    // A wave over all three; then a later write on the third.
    let at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut befores = Vec::new();
    let mut wave = Vec::new();
    for &id in &ids {
        let before = cache_of(&pool, id).await;
        set_cache(&pool, id, 0.9, Some("supported")).await;
        let written = cache_of(&pool, id).await;
        write_wave_record(
            &mut wave,
            &WaveRecord {
                claim_id: id,
                before: before.clone(),
                written,
                wave: "bins-test".into(),
                at,
            },
        )
        .unwrap();
        befores.push(before);
    }
    // A fourth claim written by two runs with an organic write between them
    // (a broken chain): the restore puts back the organic write's value.
    let gapped = seed_claim(&pool, agent).await;
    set_cache(&pool, gapped, 0.2, None).await;
    for (run, (organic, wave_value)) in [(0.3, 0.8), (0.4, 0.85)].into_iter().enumerate() {
        let before = cache_of(&pool, gapped).await;
        set_cache(&pool, gapped, wave_value, Some("supported")).await;
        write_wave_record(
            &mut wave,
            &WaveRecord {
                claim_id: gapped,
                before,
                written: cache_of(&pool, gapped).await,
                wave: "bins-test".into(),
                at: at + chrono::Duration::seconds(run as i64),
            },
        )
        .unwrap();
        if run == 0 {
            set_cache(&pool, gapped, organic, None).await;
        }
    }
    let intervening = CacheColumns {
        belief: Some(0.3),
        plausibility: Some(0.3),
        pignistic_prob: Some(0.3),
        mass_on_empty: Some(0.0),
        mass_on_missing: Some(0.0),
        belief_frame_id: None,
        classification: None,
    };
    let wave_path = dir.join("wave.jsonl");
    std::fs::write(&wave_path, &wave).unwrap();
    // One edge a wave claim sources after the wave: the downstream file's line.
    let target = seed_claim(&pool, agent).await;
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(ids[0])
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("post-wave edge");
    set_cache(&pool, ids[2], 0.95, Some("supported")).await;
    let later = cache_of(&pool, ids[2]).await;

    let unknown = Uuid::new_v4();
    let claims_path = dir.join("claims.txt");
    std::fs::write(
        &claims_path,
        format!(
            "# subset\n{}\n\n{}\n{}\n{gapped}\n{unknown}\n",
            ids[0], ids[1], ids[2]
        ),
    )
    .unwrap();

    // Dry run: reports what it would do, writes nothing.
    let o = run(
        RESTORE,
        &dir,
        Some(&url),
        &[
            "--from",
            wave_path.to_str().unwrap(),
            "--claims",
            claims_path.to_str().unwrap(),
            "--batch-size",
            "2",
            "--dry-run",
        ],
    );
    assert!(o.status.success(), "dry run failed");
    assert_eq!(stdout_count(&o, "restored"), 2);
    assert_eq!(stdout_count(&o, "restored_partial"), 1);
    assert_eq!(stdout_count(&o, "superseded_since_wave"), 1);
    assert_eq!(stdout_count(&o, "not_in_wave"), 1);
    for &id in &ids[..2] {
        assert_eq!(cache_of(&pool, id).await.belief, Some(0.9), "dry run wrote");
    }

    // Real run with explicit output paths.
    let outcomes = dir.join("outcomes.jsonl");
    let downstream = dir.join("downstream.jsonl");
    let real_args = [
        "--from",
        wave_path.to_str().unwrap(),
        "--claims",
        claims_path.to_str().unwrap(),
        "--batch-size",
        "2",
        "--outcomes-out",
        outcomes.to_str().unwrap(),
        "--downstream-out",
        downstream.to_str().unwrap(),
    ];
    let o = run(RESTORE, &dir, Some(&url), &real_args);
    assert!(o.status.success(), "restore failed");
    assert_eq!(stdout_count(&o, "restored"), 2);
    for (i, &id) in ids.iter().enumerate().take(2) {
        assert_eq!(cache_of(&pool, id).await, befores[i]);
    }
    assert_eq!(cache_of(&pool, ids[2]).await, later, "later write survived");
    assert_eq!(
        cache_of(&pool, gapped).await,
        intervening,
        "a broken chain restores to the intervening write"
    );

    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&outcomes)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let pairs: HashSet<(String, String)> = lines
        .iter()
        .map(|v| {
            (
                v["claim_id"].as_str().unwrap().to_string(),
                v["outcome"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let want: HashSet<(String, String)> = [
        (ids[0].to_string(), "restored".to_string()),
        (ids[1].to_string(), "restored".to_string()),
        (ids[2].to_string(), "superseded_since_wave".to_string()),
        (gapped.to_string(), "restored_partial".to_string()),
        (unknown.to_string(), "not_in_wave".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(pairs, want);
    assert_eq!(lines.len(), want.len());
    assert_eq!(
        edge_ids(&downstream),
        vec![edge],
        "the downstream file lists exactly the post-wave edge"
    );

    // Outputs are never overwritten: the same explicit paths refuse a re-run,
    // BEFORE the database is touched. Put the wave's value back on ids[0] so a
    // re-run that reached the database would visibly restore it again.
    set_cache(&pool, ids[0], 0.9, Some("supported")).await;
    let rewaved = cache_of(&pool, ids[0]).await;
    let outcomes_before = std::fs::read(&outcomes).unwrap();
    let o = run(RESTORE, &dir, Some(&url), &real_args);
    assert!(
        !o.status.success(),
        "an existing outcomes file must be refused"
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains(outcomes.to_str().unwrap()) && err.contains("exists"),
        "refused for the wrong reason"
    );
    assert_eq!(
        cache_of(&pool, ids[0]).await,
        rewaved,
        "the refused run touched the database"
    );
    assert_eq!(
        std::fs::read(&outcomes).unwrap(),
        outcomes_before,
        "the refused run rewrote the outcomes file"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn edge_ids(path: &Path) -> Vec<Uuid> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["edge_id"].as_str().unwrap().parse().unwrap()
        })
        .collect()
}

fn outcome_pairs(path: &Path) -> HashSet<(String, String)> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            (
                v["claim_id"].as_str().unwrap().to_string(),
                v["outcome"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// A batch that fails after earlier batches committed: the committed claims
/// ARE restored, so the operator must still get their outcomes and the
/// downstream edges to re-wire, not two empty files and a non-zero exit.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_batch_still_leaves_the_committed_batches_outcomes_and_downstream(pool: PgPool) {
    let url = viewer_fixture::database_url_for(&pool).await;
    let dir = scratch_dir();
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'belief-cache-bins-test', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed agent");

    let mut ids = Vec::new();
    for i in 0..4 {
        let id = seed_claim(&pool, agent).await;
        set_cache(&pool, id, 0.1 + 0.1 * f64::from(i), None).await;
        ids.push(id);
    }
    let target = seed_claim(&pool, agent).await;

    let at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut befores = Vec::new();
    let mut wave = Vec::new();
    for &id in &ids {
        let before = cache_of(&pool, id).await;
        set_cache(&pool, id, 0.9, Some("supported")).await;
        write_wave_record(
            &mut wave,
            &WaveRecord {
                claim_id: id,
                before: before.clone(),
                written: cache_of(&pool, id).await,
                wave: "bins-test".into(),
                at,
            },
        )
        .unwrap();
        befores.push(before);
    }
    let wave_path = dir.join("wave.jsonl");
    std::fs::write(&wave_path, &wave).unwrap();
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(ids[0])
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("post-wave edge");

    // Batch 2 (ids[2], ids[3] at --batch-size 2) fails on ids[2].
    sqlx::query(&format!(
        "CREATE FUNCTION belief_cache_bins_fail() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.id = '{}'::uuid THEN RAISE EXCEPTION 'injected restore failure'; END IF; \
         RETURN NEW; END $$",
        ids[2]
    ))
    .execute(&pool)
    .await
    .expect("failure trigger function");
    sqlx::query(
        "CREATE TRIGGER belief_cache_bins_fail BEFORE UPDATE ON claims \
         FOR EACH ROW EXECUTE FUNCTION belief_cache_bins_fail()",
    )
    .execute(&pool)
    .await
    .expect("failure trigger");

    let outcomes = dir.join("outcomes.jsonl");
    let downstream = dir.join("downstream.jsonl");
    let o = run(
        RESTORE,
        &dir,
        Some(&url),
        &[
            "--from",
            wave_path.to_str().unwrap(),
            "--batch-size",
            "2",
            "--outcomes-out",
            outcomes.to_str().unwrap(),
            "--downstream-out",
            downstream.to_str().unwrap(),
        ],
    );
    assert!(!o.status.success(), "a failed batch must fail the run");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("injected restore failure"),
        "failed for the wrong reason"
    );

    // Batch 1 committed; batch 2 rolled back.
    assert_eq!(cache_of(&pool, ids[0]).await, befores[0]);
    assert_eq!(cache_of(&pool, ids[1]).await, befores[1]);
    assert_eq!(cache_of(&pool, ids[3]).await.belief, Some(0.9));

    let want: HashSet<(String, String)> = [
        (ids[0].to_string(), "restored".to_string()),
        (ids[1].to_string(), "restored".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        outcome_pairs(&outcomes),
        want,
        "the committed batch's outcomes, and only those, are on file"
    );
    assert_eq!(
        edge_ids(&downstream),
        vec![edge],
        "the downstream list is written even though the run failed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
