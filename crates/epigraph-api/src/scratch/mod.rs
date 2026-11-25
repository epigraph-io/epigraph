//! A throwaway belief graph with no database (`scratch` feature).
//!
//! The `epigraph-scratch` binary holds one chat's belief graph in memory and
//! persists it to a single snapshot file. It is a stdio child of the EpiClaw
//! agent-runner and speaks the JSON-lines protocol in [`protocol`].
//!
//! # No database, no network, no environment
//!
//! Operator ruling 9854c563 asked for "Epigraph API without DB" for temporary
//! throwaway belief graphs. This module is that carve-out from R-39, which
//! still holds for `server`: `server`, `epigraph-migrate` and `drain_jobs`
//! keep `required-features = ["db"]`, and nothing here is reachable from
//! them.
//!
//! * No `feature = "db"` code is used: no route table, no pool, no DSN.
//! * epigraph-db is linked (epigraph-engine depends on it unconditionally) and
//!   the feature names it for its plain types only. No connection is made.
//! * Nothing here reads an environment variable. The runner starts the child
//!   with `PATH` alone; `tests/scratch_no_db.rs` starts it with a database
//!   address that would be dialled if anything tried, and checks the child
//!   holds no socket.
//!
//! # Usage
//!
//! ```text
//! epigraph-scratch --snapshot <dir>/graph.json --scope <hex> --epoch <n>
//! ```
//!
//! `--scope` is opaque lower-case hex, 12 to 64 characters (DESIGN §1 uses a
//! 12-hex prefix of a SHA-256; critic finding X17 may make it a longer HMAC).
//! The snapshot's directory must exist. Exit status: 0 at end of input, 2 for
//! a usage error, 3 when the snapshot belongs to another scope or epoch
//! ([`snapshot::RestoreError::Foreign`]), 1 when stdout fails. Diagnostics on
//! stderr are fixed phrases with no paths and no chat text.

pub mod belief;
pub mod bm25;
pub mod protocol;
pub mod snapshot;
pub mod store;

use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

/// Exit status for a usage error.
pub const EXIT_USAGE: i32 = 2;
/// Exit status when restore is refused.
pub const EXIT_FOREIGN_SNAPSHOT: i32 = 3;
/// Exit status when stdout or stdin fails.
pub const EXIT_IO: i32 = 1;

/// Parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub snapshot: PathBuf,
    pub scope: String,
    pub epoch: u64,
}

fn valid_scope(scope: &str) -> bool {
    (12..=64).contains(&scope.len())
        && scope
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Args {
    /// Parse `--snapshot P --scope S --epoch N` (any order, each once).
    pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Self, &'static str> {
        let (mut snapshot, mut scope, mut epoch) = (None, None, None);
        let mut it = args.into_iter();
        while let Some(flag) = it.next() {
            let slot = match flag.as_str() {
                "--snapshot" => &mut snapshot,
                "--scope" => &mut scope,
                "--epoch" => &mut epoch,
                _ => return Err("unknown argument"),
            };
            if slot.is_some() {
                return Err("an argument was given twice");
            }
            *slot = Some(it.next().ok_or("an argument is missing its value")?);
        }
        let snapshot = PathBuf::from(snapshot.ok_or("--snapshot is required")?);
        let scope = scope.ok_or("--scope is required")?;
        if !valid_scope(&scope) {
            return Err("--scope must be 12 to 64 lower-case hex characters");
        }
        let epoch = epoch
            .ok_or("--epoch is required")?
            .parse::<u64>()
            .map_err(|_| "--epoch must be a non-negative integer")?;
        if snapshot.file_name().is_none() {
            return Err("--snapshot must name a file");
        }
        Ok(Self {
            snapshot,
            scope,
            epoch,
        })
    }
}

/// The whole program: parse arguments, restore, serve stdin to stdout.
/// Returns the process exit status.
pub fn run<I: IntoIterator<Item = String>>(args: I) -> i32 {
    let stderr = std::io::stderr();
    let args = match Args::parse(args) {
        Ok(a) => a,
        Err(msg) => {
            let _ = writeln!(
                stderr.lock(),
                "epigraph-scratch: {msg}\nusage: epigraph-scratch --snapshot <file> --scope <hex> --epoch <n>"
            );
            return EXIT_USAGE;
        }
    };
    let dir_ok = match args.snapshot.parent() {
        Some(p) if p.as_os_str().is_empty() => true,
        Some(p) => p.is_dir(),
        None => false,
    };
    if !dir_ok {
        let _ = writeln!(
            stderr.lock(),
            "epigraph-scratch: the snapshot's directory does not exist"
        );
        return EXIT_USAGE;
    }
    let mut session = match protocol::Session::open(args.snapshot, &args.scope, args.epoch) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr.lock(), "epigraph-scratch: refusing to start: {e}");
            return EXIT_FOREIGN_SNAPSHOT;
        }
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match protocol::serve(
        &mut session,
        BufReader::new(stdin.lock()),
        BufWriter::new(stdout.lock()),
    ) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(
                stderr.lock(),
                "epigraph-scratch: stdio failed: {:?}",
                e.kind()
            );
            EXIT_IO
        }
    }
}
