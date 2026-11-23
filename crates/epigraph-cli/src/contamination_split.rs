//! Post-sweep contamination split for the cross-source verifier adjudication
//! protocol (`tests/cross_source/prompts_v1.md` §2 step 3 and §5; backlog
//! ea6eb305).
//!
//! The protocol snapshots the contamination ledger BEFORE the sweep
//! (`calibrate_matcher --contamination-ledger`), runs the sweep, and then
//! splits the run's candidate pairs into a **clean** set (no verdict existed
//! before the sweep: the only pairs the headline precision figure may use)
//! and a **contaminated** set (reported as a count only). The split itself is
//! [`partition_by_ledger`]; this module reads the archived snapshot and the
//! run's pairs, calls it, and writes the two sets plus their counts, so the
//! step is a command rather than a hand-written script.
//!
//! Nothing here writes to the database. The `contamination_split` binary
//! reads `match_candidates` only when it is given `--run-id`, and never with
//! `--pairs`.
//!
//! Every file involved (the ledger snapshot, the run's pairs, both output
//! sets) lists claim ids from every tenant: archive them privately, never in
//! the public repository.

use anyhow::Context;
use epigraph_engine::matching::contamination::{partition_by_ledger, ClaimPair, LedgerEntry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// One candidate pair of the sweep. `claim_a` / `claim_b` are what the split
/// keys on (in either orientation); every other field of the input row
/// (`status`, `verifier_verdict`, `score`, ...) is carried through unchanged,
/// because §2 step 4 reads the clean rows' `verifier_verdict` afterwards.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SweepPair {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// The counts the protocol's report (§7) records, with what they were
/// computed from: a counts file that does not name its ledger snapshot and
/// its pairs cannot be audited (a stale ledger, or a mistyped run id, would
/// leave no trace in it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SplitCounts {
    /// SHA-256 (hex) of the ledger snapshot file exactly as read.
    pub ledger_sha256: String,
    /// The snapshot's own `generated_at` header (`None` when absent). It must
    /// predate the sweep: a later snapshot counts this run's own verdicts as
    /// contamination, an earlier one lets pairs decided in between count as
    /// clean.
    pub ledger_generated_at: Option<String>,
    /// SHA-256 (hex) of the pairs that were split: the `--pairs` file as read,
    /// or the `run_pairs.json` written next to the split.
    pub pairs_sha256: String,
    /// The `matcher_run_id` the pairs were read for (`None` with `--pairs`).
    pub run_id: Option<Uuid>,
    /// Entries in the ledger snapshot.
    pub ledger_entries: usize,
    /// Pairs read from the sweep.
    pub pairs: usize,
    pub clean: usize,
    pub contaminated: usize,
    /// Clean pairs carrying a non-null `verifier_verdict`: this run's verifier
    /// answers (§2 step 4). Contaminated rows are deliberately not counted
    /// this way: their stored verdict may predate the run.
    pub clean_with_verifier_verdict: usize,
}

/// The ledger file `calibrate_matcher --contamination-ledger` writes. Only
/// `entries` and `generated_at` are read; the other header fields are for the
/// archive.
#[derive(Deserialize)]
struct LedgerSnapshot {
    entries: Vec<LedgerEntry>,
    #[serde(default)]
    generated_at: Option<String>,
}

/// A ledger snapshot as read, with the identity [`SplitCounts`] records.
#[derive(Debug, Clone)]
pub struct Ledger {
    pub entries: Vec<LedgerEntry>,
    pub generated_at: Option<String>,
    pub sha256: String,
}

/// The pairs to split, with their identity for [`SplitCounts`].
#[derive(Debug, Clone)]
pub struct SweepPairs {
    pub pairs: Vec<SweepPair>,
    pub sha256: String,
    pub run_id: Option<Uuid>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Read a ledger snapshot written by `calibrate_matcher
/// --contamination-ledger`. A file without an `entries` array is refused
/// rather than read as an empty ledger: an empty ledger would mark every pair
/// clean.
pub fn read_ledger(path: &Path) -> anyhow::Result<Ledger> {
    let bytes = std::fs::read(path).with_context(|| format!("open ledger {}", path.display()))?;
    let snap: LedgerSnapshot = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse ledger {} (expected an `entries` array)",
            path.display()
        )
    })?;
    Ok(Ledger {
        entries: snap.entries,
        generated_at: snap.generated_at,
        sha256: sha256_hex(&bytes),
    })
}

/// Read a sweep's pairs: a JSON array of objects, each with `claim_a` and
/// `claim_b` (the shape [`fetch_run_pairs`] writes as `run_pairs.json`).
pub fn read_pairs(path: &Path) -> anyhow::Result<SweepPairs> {
    let bytes = std::fs::read(path).with_context(|| format!("open pairs {}", path.display()))?;
    let pairs = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse pairs {} (expected a JSON array of objects with claim_a and claim_b)",
            path.display()
        )
    })?;
    Ok(SweepPairs {
        pairs,
        sha256: sha256_hex(&bytes),
        run_id: None,
    })
}

/// Pretty JSON bytes, as every output file is written.
pub fn to_json_bytes<T: Serialize + ?Sized>(value: &T) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(value)?)
}

/// Split `pairs` into `(clean, contaminated, counts)` against `ledger` with
/// [`partition_by_ledger`], keeping each row whole and in input order.
pub fn split(
    pairs: SweepPairs,
    ledger: &Ledger,
) -> (Vec<SweepPair>, Vec<SweepPair>, SplitCounts) {
    let SweepPairs {
        pairs,
        sha256: pairs_sha256,
        run_id,
    } = pairs;
    let keys: Vec<ClaimPair> = pairs.iter().map(|p| (p.claim_a, p.claim_b)).collect();
    let (_, dirty) = partition_by_ledger(&keys, &ledger.entries);
    // `partition_by_ledger` returns pairs exactly as given, so a row is
    // contaminated iff its own (claim_a, claim_b) is among them.
    let dirty: HashSet<ClaimPair> = dirty.into_iter().collect();
    let total = pairs.len();
    let (contaminated, clean): (Vec<SweepPair>, Vec<SweepPair>) = pairs
        .into_iter()
        .partition(|p| dirty.contains(&(p.claim_a, p.claim_b)));
    let clean_with_verifier_verdict = clean
        .iter()
        .filter(|p| p.rest.get("verifier_verdict").is_some_and(|v| !v.is_null()))
        .count();
    let counts = SplitCounts {
        ledger_sha256: ledger.sha256.clone(),
        ledger_generated_at: ledger.generated_at.clone(),
        pairs_sha256,
        run_id,
        ledger_entries: ledger.entries.len(),
        pairs: total,
        clean: clean.len(),
        contaminated: contaminated.len(),
        clean_with_verifier_verdict,
    };
    (clean, contaminated, counts)
}

/// File names written under the output directory.
pub const CLEAN_FILE: &str = "clean_pairs.json";
pub const CONTAMINATED_FILE: &str = "contaminated_pairs.json";
pub const COUNTS_FILE: &str = "split_counts.json";
/// Written only by `--run-id`: the pairs as fetched, so the archive holds
/// exactly what was split even after a later sweep re-stamps the rows.
pub const RUN_PAIRS_FILE: &str = "run_pairs.json";

/// Write every `(name, bytes)` under `dir` as ONE all-or-nothing batch: each
/// file is created with `create_new` (a re-run never replaces an archived
/// result), written in full and synced, and if any step fails every file
/// THIS call created is removed again, so a failed run (disk full, a name
/// that appeared meanwhile) leaves no partial archive that would then make
/// every re-run refuse. Files that existed before the call are never touched.
pub fn write_files(dir: &Path, files: &[(&str, Vec<u8>)]) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let mut created: Vec<PathBuf> = Vec::new();
    let result = (|| -> anyhow::Result<()> {
        for (name, bytes) in files {
            let path = dir.join(name);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| format!("create {} (refusing to overwrite)", path.display()))?;
            created.push(path.clone());
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .with_context(|| format!("write {}", path.display()))?;
        }
        Ok(())
    })();
    if result.is_err() {
        for path in &created {
            let _ = std::fs::remove_file(path);
        }
    }
    result
}

/// Refuse when any of `names` already exists under `dir`, so a refused run
/// leaves no partial archive behind.
pub fn ensure_absent(dir: &Path, names: &[&str]) -> anyhow::Result<()> {
    for name in names {
        let path = dir.join(name);
        anyhow::ensure!(
            !path.exists(),
            "{} already exists; refusing to overwrite an archived split",
            path.display()
        );
    }
    Ok(())
}

/// Write the clean set, the contaminated set and the counts under `dir`,
/// plus `run_pairs` (the fetched pairs, as already serialized for their hash)
/// when given, as one batch through [`write_files`].
pub fn write_split(
    dir: &Path,
    run_pairs: Option<Vec<u8>>,
    clean: &[SweepPair],
    contaminated: &[SweepPair],
    counts: &SplitCounts,
) -> anyhow::Result<()> {
    let mut files: Vec<(&str, Vec<u8>)> = Vec::new();
    if let Some(bytes) = run_pairs {
        files.push((RUN_PAIRS_FILE, bytes));
    }
    files.push((CLEAN_FILE, to_json_bytes(clean)?));
    files.push((CONTAMINATED_FILE, to_json_bytes(contaminated)?));
    files.push((COUNTS_FILE, to_json_bytes(counts)?));
    let names: Vec<&str> = files.iter().map(|(n, _)| *n).collect();
    ensure_absent(dir, &names)?;
    write_files(dir, &files)
}

/// [`fetch_run_pairs`], refusing a run id that matches no row. A mistyped
/// `--run-id` (or one whose rows a later sweep already re-stamped) would
/// otherwise archive an all-zero split and exit 0. Returns the pairs and the
/// exact `run_pairs.json` bytes their `sha256` was computed over.
#[cfg(feature = "db")]
pub async fn fetch_run_pairs_nonempty(
    pool: &sqlx::PgPool,
    run_id: Uuid,
) -> anyhow::Result<(SweepPairs, Vec<u8>)> {
    let pairs = fetch_run_pairs(pool, run_id).await?;
    anyhow::ensure!(
        !pairs.is_empty(),
        "no match_candidates row carries matcher_run_id {run_id}: check the run id \
         (a later sweep re-stamps the rows it touches); nothing written"
    );
    let bytes = to_json_bytes(&pairs)?;
    let pairs = SweepPairs {
        pairs,
        sha256: sha256_hex(&bytes),
        run_id: Some(run_id),
    };
    Ok((pairs, bytes))
}

/// The `match_candidates` rows stamped with `run_id` (§2 step 3), read-only.
///
/// The upsert re-stamps `matcher_run_id` on rows a later sweep touches, so this
/// set is only the run's pairs until the next sweep: run the split before it.
#[cfg(feature = "db")]
pub async fn fetch_run_pairs(
    pool: &sqlx::PgPool,
    run_id: Uuid,
) -> Result<Vec<SweepPair>, sqlx::Error> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT claim_a, claim_b, status, verifier_verdict, score::float8 AS score, decided_at
         FROM match_candidates
         WHERE matcher_run_id = $1
         ORDER BY claim_a, claim_b",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let mut rest = serde_json::Map::new();
            rest.insert("status".into(), row.try_get::<String, _>("status")?.into());
            rest.insert(
                "verifier_verdict".into(),
                row.try_get::<Option<String>, _>("verifier_verdict")?.into(),
            );
            rest.insert("score".into(), row.try_get::<f64, _>("score")?.into());
            rest.insert(
                "decided_at".into(),
                serde_json::to_value(
                    row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("decided_at")?,
                )
                .unwrap_or(serde_json::Value::Null),
            );
            Ok(SweepPair {
                claim_a: row.try_get("claim_a")?,
                claim_b: row.try_get("claim_b")?,
                rest,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(a: Uuid, b: Uuid) -> LedgerEntry {
        LedgerEntry {
            claim_a: a.min(b),
            claim_b: a.max(b),
            status: "rejected".into(),
            verifier_verdict: Some("distinct".into()),
            decided_at: None,
            reason: "verifier_verdict".into(),
        }
    }

    fn ledger(entries: Vec<LedgerEntry>) -> Ledger {
        Ledger {
            entries,
            generated_at: Some("2026-11-22T00:00:00Z".into()),
            sha256: "ledger-hash".into(),
        }
    }

    fn pairs(pairs: Vec<SweepPair>) -> SweepPairs {
        SweepPairs {
            pairs,
            sha256: "pairs-hash".into(),
            run_id: None,
        }
    }

    fn pair(a: Uuid, b: Uuid, verdict: Option<&str>) -> SweepPair {
        let mut rest = serde_json::Map::new();
        rest.insert("status".into(), json!("rejected"));
        rest.insert("verifier_verdict".into(), json!(verdict));
        SweepPair {
            claim_a: a,
            claim_b: b,
            rest,
        }
    }

    /// A pair given against the ledger's canonical order is contaminated, the
    /// rows keep their extra fields, and only clean rows with a verdict count
    /// as this run's verifier answers.
    #[test]
    fn split_keeps_rows_whole_and_matches_either_orientation() {
        let (x, y, z, w) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let ledger = ledger(vec![entry(x, y)]);
        let reversed = pair(x.max(y), x.min(y), Some("same"));
        let clean_answered = pair(x, z, Some("paraphrase"));
        let clean_unanswered = pair(z, w, None);
        let (clean, dirty, counts) = split(
            pairs(vec![
                clean_answered.clone(),
                reversed.clone(),
                clean_unanswered.clone(),
            ]),
            &ledger,
        );
        assert_eq!(dirty, vec![reversed]);
        assert_eq!(clean, vec![clean_answered, clean_unanswered]);
        assert_eq!(
            counts,
            SplitCounts {
                ledger_sha256: "ledger-hash".into(),
                ledger_generated_at: Some("2026-11-22T00:00:00Z".into()),
                pairs_sha256: "pairs-hash".into(),
                run_id: None,
                ledger_entries: 1,
                pairs: 3,
                clean: 2,
                contaminated: 1,
                clean_with_verifier_verdict: 1,
            }
        );
    }

    /// A ledger file without `entries` is refused, not read as "nothing is
    /// contaminated" (which would mark every pair clean).
    #[test]
    fn a_ledger_without_entries_is_refused() {
        let dir = std::env::temp_dir().join(format!("contamination-split-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.json");
        std::fs::write(&path, r#"{"contaminated": 0}"#).unwrap();
        assert!(read_ledger(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A second split into the same directory is refused and leaves the first
    /// result untouched.
    #[test]
    fn write_split_refuses_to_overwrite() {
        let dir = std::env::temp_dir().join(format!("contamination-split-{}", Uuid::new_v4()));
        let p = pair(Uuid::new_v4(), Uuid::new_v4(), None);
        let (clean, dirty, counts) = split(pairs(vec![p]), &ledger(vec![]));
        write_split(&dir, None, &clean, &dirty, &counts).expect("first write");
        let before = std::fs::read_to_string(dir.join(CLEAN_FILE)).unwrap();
        assert!(write_split(&dir, None, &[], &[], &counts).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join(CLEAN_FILE)).unwrap(),
            before
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A batch that fails part-way removes the files it created and leaves a
    /// file that was already there untouched, so a failed run never leaves a
    /// partial archive that makes every re-run refuse (T95 review). The third
    /// name exists already, so its `create_new` fails after two files were
    /// written. (Mutation: drop the cleanup and the first two stay behind.)
    #[test]
    fn a_failed_batch_leaves_no_partial_archive() {
        let dir = std::env::temp_dir().join(format!("contamination-split-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(COUNTS_FILE), "keep").unwrap();
        let err = write_files(
            &dir,
            &[
                (CLEAN_FILE, b"[]".to_vec()),
                (CONTAMINATED_FILE, b"[]".to_vec()),
                (COUNTS_FILE, b"{}".to_vec()),
            ],
        );
        assert!(err.is_err());
        assert!(!dir.join(CLEAN_FILE).exists());
        assert!(!dir.join(CONTAMINATED_FILE).exists());
        assert_eq!(
            std::fs::read_to_string(dir.join(COUNTS_FILE)).unwrap(),
            "keep"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The ledger's hash and `generated_at` are read from the file itself,
    /// so the counts name exactly the snapshot they were computed against.
    #[test]
    fn read_ledger_records_the_snapshot_identity() {
        let dir = std::env::temp_dir().join(format!("contamination-split-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.json");
        let body = r#"{"generated_at": "2026-11-21T12:00:00Z", "entries": []}"#;
        std::fs::write(&path, body).unwrap();
        let ledger = read_ledger(&path).unwrap();
        assert_eq!(ledger.generated_at.as_deref(), Some("2026-11-21T12:00:00Z"));
        assert_eq!(ledger.sha256, hex::encode(Sha256::digest(body.as_bytes())));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
