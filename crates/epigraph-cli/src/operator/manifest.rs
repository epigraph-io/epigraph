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
//! Each record holds THAT ROW's own prior tenancy. Reversal restores every row
//! to its own record, never by re-propagating its claim's prior owner: a
//! derived row whose owner differed from its claim's before the re-own gets its
//! own owner back.
//!
//! # Durability
//!
//! The file is opened `create_new`, so a re-run can never truncate the record
//! of a run that already wrote (a resumed run takes a new path; the claims the
//! first run moved are skipped, so each manifest records only what its own run
//! moved). Every append is flushed and `fsync`ed, and the directory is
//! `fsync`ed after creation, BEFORE the write the records describe.

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// One row's prior tenancy.
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

    /// Total rows recorded.
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

/// A manifest read back: its header and its row records, in file order.
pub struct Manifest {
    pub header: Value,
    pub records: Vec<Record>,
}

/// # Errors
/// The file cannot be read, has no header, or a line is malformed.
pub fn read(path: &Path) -> anyhow::Result<Manifest> {
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut header = None;
    let mut records = Vec::new();
    for (n, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line)
            .with_context(|| format!("{}:{}: not JSON", path.display(), n + 1))?;
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
    Ok(Manifest { header, records })
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
        assert_eq!(Record::from_json(&j).unwrap(), ev);
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
        };
        assert_eq!(w.append(&[r.clone(), r.clone()]).unwrap(), 1);
        assert_eq!(w.append(&[r]).unwrap(), 0);
        assert!(Writer::create_new(&p, &json!({"manifest": "t"})).is_err());
        let m = read(&p).unwrap();
        assert_eq!(m.records.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
