//! The re-own manifest: the undo record, written before the first write.
//!
//! # Format
//!
//! JSON Lines. The first line is a header object carrying a `manifest` key;
//! every other line is one ROW record:
//!
//! ```json
//! {"table":"claims","id":"<uuid>","owner_group_id":"<uuid>","visibility":"public","claim_id":"<uuid>"}
//! {"table":"edges","id":"<uuid>","owner_group_id":"<uuid>","visibility":"public","co_owner_group_id":null,"claim_id":"<uuid>"}
//! {"table":"claim_frames","id":{"claim_id":"<uuid>","frame_id":"<uuid>"},"owner_group_id":"<uuid>","visibility":"public","claim_id":"<uuid>"}
//! ```
//!
//! `id` is the row's primary key: the bare value for a one-column key, an
//! object for a composite one. `claim_id` is the claim the row was reached
//! through. `co_owner_group_id` is present on `edges` records only, the one
//! table that carries it.
//!
//! Each PRIOR record holds THAT ROW's own tenancy before the re-own. Reversal
//! restores every row to its own record, never by re-propagating its claim's
//! prior owner: a derived row whose owner differed from its claim's before the
//! re-own gets its own owner back.
//!
//! # Post-state records (version 2)
//!
//! A record carrying `"after": true` is the state a COMMITTED batch left that
//! row (or claim) in. Each batch appends one for every claim it moved and
//! every row it checked, under its locks and `fsync`ed BEFORE its commit. A
//! row shared by several batches gets one per batch; the LAST one is the state
//! this run left it in. If the commit then fails, the post records describe a
//! state that never happened, and the rows are still at their prior records,
//! which reversal treats as "nothing to undo".
//!
//! A post record carrying `"neighbour": true` is the `(owner, visibility)` of a
//! NEIGHBOUR claim at that batch: a claim the batch did NOT move that shares a
//! checked row (a fragment's other provenance claim, an edge's other claim
//! endpoint, or a claim of the batch that was held) with one it did.
//!
//! Reversal uses them as a COMPARE-AND-SWAP (`reverse.rs`). A claim is reversed
//! only if it HAS a post record (so a claim the plan recorded but no batch
//! moved is never touched), only while it is still in that post state, only
//! while each recorded row is in its post or prior state, and only while every
//! recorded NEIGHBOUR of its rows is still in the state recorded here. The
//! neighbour test is the one that makes reversal order-safe. Review measured
//! two manifests M1, M2 whose runs shared rows, reversed oldest-first,
//! silently leaving those rows on neither their original owner nor anything
//! the operator chose; the rows' own post states could not tell the two runs
//! apart (a public–public edge is `(world, public)` after either, and the
//! shared fragment was already on the target before M2 ran). What does tell
//! them apart is that M2 moved a claim M1 recorded as a neighbour. So M1
//! reversed on its own HOLDS, and `reown-reverse` applies several manifests
//! newest-first by header `created_at`.
//!
//! # Durability
//!
//! The file is opened `create_new`, so a re-run can never truncate the record
//! of a run that already wrote: a resumed or repeated run takes a NEW path.
//! The plan's prior records are written before the first batch and cover every
//! PLANNED claim, including claims a batch then held or never reached, so a
//! manifest's prior records are NOT a list of what its run moved; its post
//! records are. Every append is flushed and `fsync`ed, and the directory is
//! `fsync`ed after creation, BEFORE the write the records describe.

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The manifest format version this build writes and reads.
pub const VERSION: i64 = 2;

/// One row's prior tenancy, or (with `after`) its post-batch tenancy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub table: String,
    pub id: Value,
    pub owner_group_id: Uuid,
    pub visibility: String,
    /// `Some(..)` on `edges` only (the inner `None` is a recorded NULL).
    pub co_owner_group_id: Option<Option<Uuid>>,
    pub claim_id: Uuid,
    /// The row was HIDDEN by this run (evidence only): reversal restores its
    /// visibility too, and removes its pin.
    pub hidden: bool,
    /// A POST-state record (see the module doc), not a prior one.
    pub after: bool,
    /// With `after`: a NEIGHBOUR claim's state — a claim this batch did not
    /// move that shares a row with one it did (see the module doc).
    pub neighbour: bool,
    /// `Some(..)` only on a row of a table that carries migration 114's
    /// `writer_owned` flag, and only in a `restrict-claims` or
    /// `regroup-claims` manifest: the act's cascade clears the flag (the row
    /// follows the claim), so its reversal must put the recorded value back.
    /// `None` (absent) everywhere else.
    pub writer_owned: Option<bool>,
}

impl Record {
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "table": self.table,
            "id": self.id,
            "owner_group_id": self.owner_group_id,
            "visibility": self.visibility,
            "claim_id": self.claim_id,
        });
        if let Some(co) = self.co_owner_group_id {
            v["co_owner_group_id"] = json!(co);
        }
        if self.hidden {
            v["hidden"] = json!(true);
        }
        if self.after {
            v["after"] = json!(true);
        }
        if self.neighbour {
            v["neighbour"] = json!(true);
        }
        if let Some(w) = self.writer_owned {
            v["writer_owned"] = json!(w);
        }
        v
    }

    /// # Errors
    /// A field is missing or malformed.
    pub fn from_json(v: &Value) -> anyhow::Result<Self> {
        let s = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("record lacks string field {k}: {v}"))
        };
        let u = |k: &str| -> anyhow::Result<Uuid> {
            Uuid::parse_str(s(k)?).with_context(|| format!("field {k} is not a uuid"))
        };
        let co_owner_group_id = match v.get("co_owner_group_id") {
            None => None,
            Some(Value::Null) => Some(None),
            Some(Value::String(x)) => Some(Some(Uuid::parse_str(x)?)),
            Some(other) => bail!("co_owner_group_id is {other}"),
        };
        Ok(Self {
            table: s("table")?.to_string(),
            id: v
                .get("id")
                .cloned()
                .ok_or_else(|| anyhow!("record lacks id: {v}"))?,
            owner_group_id: u("owner_group_id")?,
            visibility: s("visibility")?.to_string(),
            co_owner_group_id,
            claim_id: u("claim_id")?,
            hidden: v.get("hidden").and_then(Value::as_bool).unwrap_or(false),
            after: v.get("after").and_then(Value::as_bool).unwrap_or(false),
            neighbour: v.get("neighbour").and_then(Value::as_bool).unwrap_or(false),
            writer_owned: match v.get("writer_owned") {
                None => None,
                Some(Value::Bool(b)) => Some(*b),
                Some(other) => bail!("writer_owned is {other}"),
            },
        })
    }

    /// `(table, id as compact JSON)`, for de-duplication.
    #[must_use]
    pub fn dedup_key(&self) -> (String, String) {
        (self.table.clone(), self.id.to_string())
    }
}

/// Where records go: a durable file under `--apply`, memory under a dry run.
pub enum Sink {
    File(Writer),
    Memory(HashSet<(String, String)>, usize),
}

impl Sink {
    /// Record every row not already recorded. Returns how many were new.
    ///
    /// # Errors
    /// A write or `fsync` fails.
    pub fn record(&mut self, recs: &[Record]) -> anyhow::Result<usize> {
        match self {
            Sink::File(w) => w.append(recs),
            Sink::Memory(seen, n) => {
                let mut added = 0;
                for r in recs {
                    if seen.insert(r.dedup_key()) {
                        added += 1;
                    }
                }
                *n += added;
                Ok(added)
            }
        }
    }

    /// Record POST-state records, every one: never de-duplicated, because a
    /// row a later batch changes again needs its later state too.
    ///
    /// # Errors
    /// A write or `fsync` fails.
    pub fn record_post(&mut self, recs: &[Record]) -> anyhow::Result<usize> {
        match self {
            Sink::File(w) => w.append_post(recs),
            Sink::Memory(..) => Ok(recs.len()),
        }
    }

    /// Total prior rows recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Sink::File(w) => w.recorded.len(),
            Sink::Memory(_, n) => *n,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A `create_new` JSONL file, fsynced on every append.
pub struct Writer {
    file: File,
    pub path: PathBuf,
    recorded: HashSet<(String, String)>,
}

impl Writer {
    /// Create the file (refusing one that exists) and write the header.
    ///
    /// # Errors
    /// The file exists, or a write or `fsync` fails.
    pub fn create_new(path: &Path, header: &Value) -> anyhow::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| {
                format!(
                    "creating manifest {} (it must not exist: a manifest is never overwritten, \
                     so a resumed run needs a new path)",
                    path.display()
                )
            })?;
        let mut w = Self {
            file,
            path: path.to_path_buf(),
            recorded: HashSet::new(),
        };
        w.write_line(header)?;
        w.sync()?;
        if let Some(dir) = path.parent() {
            let dir = if dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                dir
            };
            File::open(dir)
                .and_then(|d| d.sync_all())
                .with_context(|| format!("fsync of {}", dir.display()))?;
        }
        Ok(w)
    }

    fn write_line(&mut self, v: &Value) -> anyhow::Result<()> {
        let mut line = serde_json::to_string(v)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        Ok(())
    }

    fn sync(&mut self) -> anyhow::Result<()> {
        self.file.flush()?;
        self.file
            .sync_all()
            .with_context(|| format!("fsync of {}", self.path.display()))
    }

    /// Append every record not already in the file, then flush and `fsync`.
    ///
    /// # Errors
    /// A write or `fsync` fails.
    pub fn append(&mut self, recs: &[Record]) -> anyhow::Result<usize> {
        let mut added = 0;
        for r in recs {
            if self.recorded.insert(r.dedup_key()) {
                self.write_line(&r.to_json())?;
                added += 1;
            }
        }
        if added > 0 {
            self.sync()?;
        }
        Ok(added)
    }
}

impl Writer {
    /// Append POST-state records unconditionally, then flush and `fsync`.
    ///
    /// # Errors
    /// A write or `fsync` fails.
    pub fn append_post(&mut self, recs: &[Record]) -> anyhow::Result<usize> {
        for r in recs {
            debug_assert!(r.after);
            self.write_line(&r.to_json())?;
        }
        if !recs.is_empty() {
            self.sync()?;
        }
        Ok(recs.len())
    }
}

/// A manifest read back: its header and its row records, in file order.
pub struct Manifest {
    pub header: Value,
    pub records: Vec<Record>,
    /// The torn last line [`read_tolerating_truncated_tail`] dropped, if any.
    /// Always `None` from [`read`].
    pub truncated_tail: Option<TruncatedTail>,
}

/// A final line a crash cut short, dropped by
/// [`read_tolerating_truncated_tail`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TruncatedTail {
    /// Its 1-based line number.
    pub line: usize,
    /// How many bytes it held.
    pub bytes: usize,
}

/// Read a manifest, strictly: every non-empty line must be a JSON record or
/// the one header.
///
/// # Errors
/// The file cannot be read, has no header, or a line is malformed.
pub fn read(path: &Path) -> anyhow::Result<Manifest> {
    read_inner(path, false)
}

/// Read a manifest whose run may have crashed mid-append: as [`read`], except
/// that ONE unparseable FINAL line with NO trailing newline, after the header,
/// is dropped and reported in [`Manifest::truncated_tail`] instead of
/// refusing the whole file.
///
/// That is the one shape a crash leaves: every record is written as one
/// `write_all` of its JSON and its `\n`, then `fsync`ed, before the write it
/// describes, so a line without its newline is a record whose `fsync` never
/// returned, and the batch it belongs to never committed from this run. The
/// reader cannot prove that from the file alone; the operator proves the
/// batch rolled back from the database before reversing with it.
///
/// A malformed line anywhere else, a malformed final line that DOES end in a
/// newline, or a file whose only line is a torn header, is still an error.
///
/// # Errors
/// As [`read`], for anything but that one tail.
pub fn read_tolerating_truncated_tail(path: &Path) -> anyhow::Result<Manifest> {
    read_inner(path, true)
}

fn read_inner(path: &Path, allow_truncated_tail: bool) -> anyhow::Result<Manifest> {
    // Split the raw bytes, not `BufRead::lines()`: a crash can cut a line
    // inside a multi-byte character, which `lines()` reports as an I/O error
    // before the line could be recognised as the torn tail.
    let bytes = std::fs::read(path).with_context(|| format!("opening {}", path.display()))?;
    let ends_with_newline = bytes.last() == Some(&b'\n');
    let segments: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    // `split` yields an empty last segment after a final newline.
    let last = if ends_with_newline {
        None
    } else {
        Some(segments.len() - 1)
    };
    let mut header = None;
    let mut records = Vec::new();
    let mut truncated_tail = None;
    for (n, raw) in segments.iter().enumerate() {
        let parsed = std::str::from_utf8(raw)
            .map_err(anyhow::Error::from)
            .and_then(|line| {
                if line.trim().is_empty() {
                    Ok(None)
                } else {
                    serde_json::from_str::<Value>(line)
                        .map(Some)
                        .map_err(anyhow::Error::from)
                }
            });
        let v = match parsed {
            Ok(None) => continue,
            Ok(Some(v)) => v,
            Err(e) => {
                if allow_truncated_tail && Some(n) == last && header.is_some() {
                    truncated_tail = Some(TruncatedTail {
                        line: n + 1,
                        bytes: raw.len(),
                    });
                    continue;
                }
                return Err(e).with_context(|| {
                    format!(
                        "{}:{}: not JSON{}",
                        path.display(),
                        n + 1,
                        if Some(n) == last && header.is_some() {
                            " (the final line has no newline: a run that crashed mid-write \
                             leaves this; --allow-truncated-tail drops it once the batch it \
                             belongs to is proven rolled back)"
                        } else {
                            ""
                        }
                    )
                });
            }
        };
        if v.get("manifest").is_some() {
            if header.is_some() {
                bail!("{}:{}: a second header", path.display(), n + 1);
            }
            header = Some(v);
        } else {
            records.push(
                Record::from_json(&v).with_context(|| format!("{}:{}", path.display(), n + 1))?,
            );
        }
    }
    let header = header.ok_or_else(|| anyhow!("{} has no header line", path.display()))?;
    Ok(Manifest {
        header,
        records,
        truncated_tail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_and_the_co_owner_is_edges_only() {
        let edge = Record {
            table: "edges".into(),
            id: json!(Uuid::nil().to_string()),
            owner_group_id: Uuid::nil(),
            visibility: "public".into(),
            co_owner_group_id: Some(None),
            claim_id: Uuid::nil(),
            hidden: false,
            after: false,
            neighbour: false,
            writer_owned: None,
        };
        let j = edge.to_json();
        assert!(j.get("co_owner_group_id").is_some_and(Value::is_null));
        assert_eq!(Record::from_json(&j).unwrap(), edge);
        let ev = Record {
            table: "evidence".into(),
            co_owner_group_id: None,
            hidden: true,
            ..edge
        };
        let j = ev.to_json();
        assert!(j.get("co_owner_group_id").is_none());
        assert!(j.get("writer_owned").is_none());
        assert_eq!(Record::from_json(&j).unwrap(), ev);
        let wo = Record {
            writer_owned: Some(true),
            ..ev
        };
        let j = wo.to_json();
        assert_eq!(j.get("writer_owned"), Some(&json!(true)));
        assert_eq!(Record::from_json(&j).unwrap(), wo);
    }

    #[test]
    fn a_manifest_is_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("opmanifest-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("m.jsonl");
        let mut w = Writer::create_new(&p, &json!({"manifest": "t"})).unwrap();
        let r = Record {
            table: "claims".into(),
            id: json!("x"),
            owner_group_id: Uuid::nil(),
            visibility: "public".into(),
            co_owner_group_id: None,
            claim_id: Uuid::nil(),
            hidden: false,
            after: false,
            neighbour: false,
            writer_owned: None,
        };
        assert_eq!(w.append(&[r.clone(), r.clone()]).unwrap(), 1);
        assert_eq!(w.append(&[r]).unwrap(), 0);
        assert!(Writer::create_new(&p, &json!({"manifest": "t"})).is_err());
        let m = read(&p).unwrap();
        assert_eq!(m.records.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn rec_line(id: &str) -> String {
        let r = Record {
            table: "claims".into(),
            id: json!(id),
            owner_group_id: Uuid::nil(),
            visibility: "public".into(),
            co_owner_group_id: None,
            claim_id: Uuid::nil(),
            hidden: false,
            after: false,
            neighbour: false,
            writer_owned: None,
        };
        serde_json::to_string(&r.to_json()).unwrap()
    }

    /// A file holding `body` exactly; returns `(dir, path)`.
    fn file_with(body: &[u8]) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("opmanifest-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("m.jsonl");
        std::fs::write(&p, body).unwrap();
        (dir, p)
    }

    /// The header, two whole records, and the first `cut` bytes of a third
    /// with no newline: what a crash during the third `write_all` leaves.
    fn torn(cut: usize) -> Vec<u8> {
        let mut body = format!(
            "{}\n{}\n{}\n",
            json!({"manifest": "t"}),
            rec_line("a"),
            rec_line("b")
        )
        .into_bytes();
        body.extend_from_slice(&rec_line("c").as_bytes()[..cut]);
        body
    }

    #[test]
    fn a_torn_final_line_is_dropped_only_when_allowed_and_reported() {
        let (dir, p) = file_with(&torn(20));
        let err = read(&p).err().expect("the strict reader refuses a torn tail");
        assert!(format!("{err:#}").contains(":4: not JSON"), "{err:#}");
        let m = read_tolerating_truncated_tail(&p).expect("the tail is tolerated");
        assert_eq!(m.records.len(), 2, "the two whole records are kept");
        assert_eq!(
            m.truncated_tail,
            Some(TruncatedTail { line: 4, bytes: 20 })
        );
        assert!(read(&p).is_err(), "tolerating once changes nothing on disk");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_tail_torn_inside_a_multibyte_character_is_the_same_tail() {
        let mut body = torn(0);
        body.extend_from_slice("{\"table\":\"claims\",\"note\":\"\u{e9}".as_bytes());
        body.pop(); // half of the two-byte character
        let (dir, p) = file_with(&body);
        assert!(read(&p).is_err());
        let m = read_tolerating_truncated_tail(&p).expect("a torn UTF-8 tail is tolerated");
        assert_eq!(m.records.len(), 2);
        assert_eq!(m.truncated_tail.map(|t| t.line), Some(4));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_whole_manifest_reads_the_same_either_way() {
        let (dir, p) = file_with(&torn(0));
        let strict = read(&p).unwrap();
        let lenient = read_tolerating_truncated_tail(&p).unwrap();
        assert_eq!(strict.records, lenient.records);
        assert_eq!(lenient.truncated_tail, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_other_bad_line_is_still_refused_when_tails_are_allowed() {
        let h = json!({"manifest": "t"}).to_string();
        let (a, b) = (rec_line("a"), rec_line("b"));
        for (what, body) in [
            ("a bad line mid-file", format!("{h}\n{a}\n{{\"tab\n{b}\n")),
            ("a bad line mid-file, no final newline", format!("{h}\n{{\"tab\n{b}")),
            ("a bad final line WITH its newline", format!("{h}\n{a}\n{{\"tab\n")),
            ("a torn header, nothing before it", "{\"manifest\": \"t".to_string()),
            ("two torn lines", format!("{h}\n{a}\n{{\"x\n{{\"tab")),
        ] {
            let (dir, p) = file_with(body.as_bytes());
            assert!(
                read_tolerating_truncated_tail(&p).is_err(),
                "{what} must still be refused"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}
