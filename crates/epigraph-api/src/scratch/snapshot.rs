//! Durable snapshots of the scratch graph (DESIGN §4.2 "Durability").
//!
//! # Format
//!
//! One line of compact JSON and a newline:
//!
//! ```text
//! {"format":1,"scope":..,"epoch":..,"applied_turns":[..],"atoms":[..],"edges":[..],"built_at":..,"sha256":"<64 hex>"}
//! ```
//!
//! Atoms and edges are in id order and applied turns ascend, so the bytes are
//! a function of the graph's content alone. `sha256` is the SHA-256 of the
//! same object WITHOUT its `sha256` member, taken over the raw bytes in the
//! file. Verification never re-serializes parsed values, so it cannot depend
//! on how a float parses back.
//!
//! # Writing
//!
//! [`write_atomic`] writes `graph.json.tmp`, fsyncs it, renames `graph.json`
//! to `graph.json.prev`, renames the tmp file into place and fsyncs the
//! directory. A crash at any point leaves `graph.json` or `graph.json.prev`
//! (or both) whole. The first write after a restore from `.prev` uses
//! [`write_atomic_keeping_prev`] instead, so a damaged `graph.json` is never
//! rotated over the good `.prev`.
//!
//! # Restoring
//!
//! [`restore`] tries `graph.json`, then `graph.json.prev`, and otherwise
//! starts empty, reporting which it used. The tmp file is never read: a torn
//! tmp left by a crash is ignored and overwritten by the next write.
//!
//! A snapshot that is intact but belongs to another scope or epoch is never
//! skipped over: restore refuses ([`RestoreError::Foreign`]). Starting empty
//! there would let the next write rename that snapshot over `.prev` and lose
//! another epoch's graph. The runner archives the directory when the epoch
//! changes (DESIGN §2), so a foreign snapshot means the caller is wrong.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::store::{ScratchAtom, ScratchEdge, ScratchStore};

/// The snapshot format version this build reads and writes.
///
/// Still 1 after E2 replaced a seed's `supported` with `confidence` and
/// `reliability`: no format-1 snapshot existed outside tests when it did. A
/// snapshot of the older shape fails to decode, restore falls back to `.prev`
/// or empty, and the runner backfills from its kept atoms (DESIGN §4.2).
pub const FORMAT: u32 = 1;

/// `,"sha256":"` — the member that closes every snapshot object.
const SHA_MEMBER: &[u8] = b",\"sha256\":\"";
/// Bytes from the start of [`SHA_MEMBER`] to the end of the object.
const SHA_TAIL_LEN: usize = SHA_MEMBER.len() + 64 + 2;

#[derive(Serialize)]
struct BodyOut<'a> {
    format: u32,
    scope: &'a str,
    epoch: u64,
    applied_turns: Vec<u64>,
    atoms: Vec<&'a ScratchAtom>,
    edges: Vec<&'a ScratchEdge>,
    built_at: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIn {
    format: u32,
    scope: String,
    epoch: u64,
    applied_turns: Vec<u64>,
    atoms: Vec<ScratchAtom>,
    edges: Vec<ScratchEdge>,
    built_at: String,
    sha256: String,
}

/// Why a snapshot file could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not a complete snapshot object (torn, truncated or not JSON).
    Malformed,
    /// The recorded hash does not match the content.
    HashMismatch,
    /// A format version this build does not read.
    UnsupportedFormat(u32),
    /// Parsed, but the graph inside breaks an invariant; names which.
    Invalid(&'static str),
}

impl DecodeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::HashMismatch => "hash_mismatch",
            Self::UnsupportedFormat(_) => "unsupported_format",
            Self::Invalid(_) => "invalid",
        }
    }
}

/// Serialize `store` to snapshot bytes.
pub fn encode(store: &ScratchStore) -> Vec<u8> {
    let body = BodyOut {
        format: FORMAT,
        scope: store.scope(),
        epoch: store.epoch(),
        applied_turns: store.applied_turns().collect(),
        atoms: store.atoms().collect(),
        edges: store.edges().collect(),
        built_at: store.built_at(),
    };
    // Serializing plain structs, strings, integers and finite floats into a
    // Vec cannot fail; a failure here is a bug, not an I/O condition.
    let mut bytes = serde_json::to_vec(&body).expect("snapshot body serializes");
    let digest = hex::encode(Sha256::digest(&bytes));
    bytes.pop(); // the body's closing brace
    bytes.extend_from_slice(SHA_MEMBER);
    bytes.extend_from_slice(digest.as_bytes());
    bytes.extend_from_slice(b"\"}\n");
    bytes
}

/// Parse and verify snapshot bytes. Scope and epoch are NOT checked here;
/// [`restore`] does that.
pub fn decode(bytes: &[u8]) -> Result<ScratchStore, DecodeError> {
    let object = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if object.len() < SHA_TAIL_LEN + 2 || !object.ends_with(b"\"}") {
        return Err(DecodeError::Malformed);
    }
    let tail_start = object.len() - SHA_TAIL_LEN;
    let (head, tail) = object.split_at(tail_start);
    if !tail.starts_with(SHA_MEMBER) {
        return Err(DecodeError::Malformed);
    }
    let recorded = &tail[SHA_MEMBER.len()..SHA_MEMBER.len() + 64];
    let mut body = head.to_vec();
    body.push(b'}');
    let actual = hex::encode(Sha256::digest(&body));
    if actual.as_bytes() != recorded {
        return Err(DecodeError::HashMismatch);
    }
    let file: FileIn = serde_json::from_slice(object).map_err(|_| DecodeError::Malformed)?;
    if file.sha256.as_bytes() != recorded {
        // A second `sha256` member earlier in the object would make the
        // parsed value differ from the tail we hashed against.
        return Err(DecodeError::Malformed);
    }
    if file.format != FORMAT {
        return Err(DecodeError::UnsupportedFormat(file.format));
    }
    ScratchStore::from_parts(
        file.scope,
        file.epoch,
        file.applied_turns,
        file.atoms,
        file.edges,
        file.built_at,
    )
    .map_err(DecodeError::Invalid)
}

/// `<path>.prev`.
pub fn prev_path(path: &Path) -> PathBuf {
    sibling(path, ".prev")
}

/// `<path>.tmp`.
pub fn tmp_path(path: &Path) -> PathBuf {
    sibling(path, ".tmp")
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Write `bytes` to `path` atomically, keeping the previous file as
/// `<path>.prev` (see the module docs for the sequence).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_inner(path, bytes, true)
}

/// Write `bytes` to `path` atomically WITHOUT rotating: `<path>.prev` is
/// left as it is and the tmp file replaces `path` directly.
///
/// For the first write after a restore from `.prev`: `path` then holds a
/// damaged file (or none), and rotating would rename that damage over the
/// only good copy. A crash before the rename leaves the damaged file and the
/// good `.prev` (the next restore still reports it); a crash after leaves the
/// new snapshot and the good `.prev`.
pub fn write_atomic_keeping_prev(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_inner(path, bytes, false)
}

fn write_inner(path: &Path, bytes: &[u8], rotate: bool) -> io::Result<()> {
    let tmp = tmp_path(path);
    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if rotate {
        match fs::rename(path, prev_path(path)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Where a restored graph came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoredFrom {
    /// `graph.json`.
    Snapshot,
    /// `graph.json.prev`, because `graph.json` was missing or unusable.
    Prev,
    /// Neither file was usable (or neither existed): an empty graph.
    Empty,
}

impl RestoredFrom {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Prev => "prev",
            Self::Empty => "empty",
        }
    }
}

/// What [`restore`] found in each file. `None` means the file was used or
/// was not consulted; `Some(code)` says why it was skipped (`missing`,
/// `unreadable`, or a [`DecodeError::code`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub from: RestoredFrom,
    pub snapshot_problem: Option<&'static str>,
    pub prev_problem: Option<&'static str>,
}

impl RestoreReport {
    /// True when some snapshot file existed but could not be used, so the
    /// runner must backfill turns the graph does not list as applied.
    ///
    /// `false` does NOT prove the graph holds every acknowledged write: a
    /// `graph.json` deleted outside a crash window restores from an older
    /// `.prev`, and both files deleted restores empty. The runner reconciles
    /// its own ledger against `stats.applied_turns` on every spawn and
    /// replays any written turn the graph does not list.
    pub fn degraded(&self) -> bool {
        let real = |p: Option<&'static str>| p.is_some_and(|code| code != "missing");
        real(self.snapshot_problem) || real(self.prev_problem)
    }
}

/// Restore was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError {
    /// An intact snapshot belongs to another scope or epoch.
    Foreign { which: RestoredFrom },
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Foreign { which } => write!(
                f,
                "the {} file holds an intact graph for another scope or epoch",
                which.as_str()
            ),
        }
    }
}

impl std::error::Error for RestoreError {}

enum Attempt {
    Usable(ScratchStore),
    Skip(&'static str),
    Foreign,
}

fn attempt(path: &Path, scope: &str, epoch: u64) -> Attempt {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Attempt::Skip("missing"),
        Err(_) => return Attempt::Skip("unreadable"),
    };
    match decode(&bytes) {
        Ok(store) if store.scope() == scope && store.epoch() == epoch => Attempt::Usable(store),
        Ok(_) => Attempt::Foreign,
        Err(e) => Attempt::Skip(e.code()),
    }
}

/// Restore the graph for `scope`/`epoch` from `path`, then `<path>.prev`,
/// else start empty at `now`.
pub fn restore(
    path: &Path,
    scope: &str,
    epoch: u64,
    now: DateTime<Utc>,
) -> Result<(ScratchStore, RestoreReport), RestoreError> {
    let snapshot_problem = match attempt(path, scope, epoch) {
        Attempt::Usable(store) => {
            return Ok((
                store,
                RestoreReport {
                    from: RestoredFrom::Snapshot,
                    snapshot_problem: None,
                    prev_problem: None,
                },
            ))
        }
        Attempt::Foreign => {
            return Err(RestoreError::Foreign {
                which: RestoredFrom::Snapshot,
            })
        }
        Attempt::Skip(code) => code,
    };
    match attempt(&prev_path(path), scope, epoch) {
        Attempt::Usable(store) => Ok((
            store,
            RestoreReport {
                from: RestoredFrom::Prev,
                snapshot_problem: Some(snapshot_problem),
                prev_problem: None,
            },
        )),
        Attempt::Foreign => Err(RestoreError::Foreign {
            which: RestoredFrom::Prev,
        }),
        Attempt::Skip(code) => Ok((
            ScratchStore::new(scope, epoch, now),
            RestoreReport {
                from: RestoredFrom::Empty,
                snapshot_problem: Some(snapshot_problem),
                prev_problem: Some(code),
            },
        )),
    }
}
