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
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter};
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

/// The counts the protocol's report (§7) records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SplitCounts {
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
/// `entries` is read; the header fields are for the archive.
#[derive(Deserialize)]
struct LedgerSnapshot {
    entries: Vec<LedgerEntry>,
}

/// Read a ledger snapshot written by `calibrate_matcher
/// --contamination-ledger`. A file without an `entries` array is refused
/// rather than read as an empty ledger: an empty ledger would mark every pair
/// clean.
pub fn read_ledger(path: &Path) -> anyhow::Result<Vec<LedgerEntry>> {
    let file = File::open(path).with_context(|| format!("open ledger {}", path.display()))?;
    let snap: LedgerSnapshot =
        serde_json::from_reader(BufReader::new(file)).with_context(|| {
            format!(
                "parse ledger {} (expected an `entries` array)",
                path.display()
            )
        })?;
    Ok(snap.entries)
}

/// Read a sweep's pairs: a JSON array of objects, each with `claim_a` and
/// `claim_b` (the shape [`fetch_run_pairs`] writes as `run_pairs.json`).
pub fn read_pairs(path: &Path) -> anyhow::Result<Vec<SweepPair>> {
    let file = File::open(path).with_context(|| format!("open pairs {}", path.display()))?;
    serde_json::from_reader(BufReader::new(file)).with_context(|| {
        format!(
            "parse pairs {} (expected a JSON array of objects with claim_a and claim_b)",
            path.display()
        )
    })
}

/// Split `pairs` into `(clean, contaminated, counts)` against `ledger` with
/// [`partition_by_ledger`], keeping each row whole and in input order.
pub fn split(
    pairs: Vec<SweepPair>,
    ledger: &[LedgerEntry],
) -> (Vec<SweepPair>, Vec<SweepPair>, SplitCounts) {
    let keys: Vec<ClaimPair> = pairs.iter().map(|p| (p.claim_a, p.claim_b)).collect();
    let (_, dirty) = partition_by_ledger(&keys, ledger);
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
        ledger_entries: ledger.len(),
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

/// Write `value` as pretty JSON to `dir/name`, refusing to overwrite an
/// existing file (a re-run must not silently replace an archived result).
pub fn write_new_json<T: Serialize>(dir: &Path, name: &str, value: &T) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(name);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("create {} (refusing to overwrite)", path.display()))?;
    serde_json::to_writer_pretty(BufWriter::new(file), value)?;
    Ok(path)
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

/// Write the clean set, the contaminated set and the counts under `dir`.
pub fn write_split(
    dir: &Path,
    clean: &[SweepPair],
    contaminated: &[SweepPair],
    counts: &SplitCounts,
) -> anyhow::Result<()> {
    ensure_absent(dir, &[CLEAN_FILE, CONTAMINATED_FILE, COUNTS_FILE])?;
    write_new_json(dir, CLEAN_FILE, &clean)?;
    write_new_json(dir, CONTAMINATED_FILE, &contaminated)?;
    write_new_json(dir, COUNTS_FILE, counts)?;
    Ok(())
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
        let ledger = vec![entry(x, y)];
        let reversed = pair(x.max(y), x.min(y), Some("same"));
        let clean_answered = pair(x, z, Some("paraphrase"));
        let clean_unanswered = pair(z, w, None);
        let (clean, dirty, counts) = split(
            vec![
                clean_answered.clone(),
                reversed.clone(),
                clean_unanswered.clone(),
            ],
            &ledger,
        );
        assert_eq!(dirty, vec![reversed]);
        assert_eq!(clean, vec![clean_answered, clean_unanswered]);
        assert_eq!(
            counts,
            SplitCounts {
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
        let (clean, dirty, counts) = split(vec![p], &[]);
        write_split(&dir, &clean, &dirty, &counts).expect("first write");
        let before = std::fs::read_to_string(dir.join(CLEAN_FILE)).unwrap();
        assert!(write_split(&dir, &[], &[], &counts).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join(CLEAN_FILE)).unwrap(),
            before
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
