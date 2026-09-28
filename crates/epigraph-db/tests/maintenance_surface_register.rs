//! Operator decision D9 (batch W12a): the maintenance DSN lives only in timers
//! and operator CLIs, never in a request-serving process. This is the static
//! register that keeps it there, in the style of `no_unscoped_pool.rs`.
//!
//! # What it pins
//!
//! Over `crates/epigraph-api/src` and `crates/epigraph-mcp/src` (the two crates
//! that build the request-serving binaries `server` and `epigraph-mcp-full`),
//! comment-stripped, with `#[cfg(test)]` modules removed:
//!
//! * the four spellings that ACQUIRE maintenance authority or run the job
//!   queue -- `maintenance_database_url(`, `with_maintenance_pool(`,
//!   `JobRunner::new`, `PostgresJobQueue::new` -- appear only at the sites in
//!   [`ALLOWED`], at exactly the counts recorded there: the `drain_jobs` timer
//!   binary, the one job-registration function it calls, and the test-only
//!   `build_app_for_tests_with_admin_cascade` helper;
//! * the environment variable is READ only by the two boot refusals (the
//!   `server` and `epigraph-mcp-full` mains), each of which hands it straight to
//!   the D9 predicate;
//! * `DbReputationService` (epigraph-jobs), a maintenance-pool consumer with no
//!   constructor anywhere, is not wired into either crate: if it is ever wired,
//!   it belongs in the drain timer, not a request binary.
//!
//! The set is asserted in BOTH directions: a new site fails, and a site that
//! is removed but left in [`ALLOWED`] fails too, so the table cannot turn into
//! folklore.
//!
//! # Known limits
//!
//! A token inside a string literal counts (none does today). A whole-line `//`
//! comment is skipped; a trailing comment after code is not (none carries a
//! token). `#[cfg(test)]` removal is by brace span from the attribute's `mod`
//! item, which is how every in-source test module here is written.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const TOKENS: &[&str] = &[
    "maintenance_database_url(",
    "with_maintenance_pool(",
    "JobRunner::new",
    "PostgresJobQueue::new",
];

/// `(repo-relative file, token, count)`: every permitted site.
const ALLOWED: &[(&str, &str, usize)] = &[
    // The drain timer resolves the maintenance DSN (refusing the fallback) and
    // builds the queue on the pool it connects there.
    (
        "crates/epigraph-api/src/bin/drain_jobs.rs",
        "maintenance_database_url(",
        1,
    ),
    (
        "crates/epigraph-api/src/bin/drain_jobs.rs",
        "PostgresJobQueue::new",
        1,
    ),
    // The ONE registration of the job handlers, called only by drain_jobs.
    ("crates/epigraph-api/src/jobs_drain.rs", "JobRunner::new", 1),
    // `build_app_for_tests_with_admin_cascade`: a test harness that exercises
    // the in-process administrative cascade (no binary calls it).
    (
        "crates/epigraph-api/src/lib.rs",
        "with_maintenance_pool(",
        1,
    ),
];

/// The only files that may read the environment variable, and why: each is a
/// request-serving `main` that refuses to start when it is set.
const ENV_READERS: &[&str] = &[
    "crates/epigraph-api/src/bin/server.rs",
    "crates/epigraph-mcp/src/main.rs",
];

const ROOTS: &[&str] = &["crates/epigraph-api/src", "crates/epigraph-mcp/src"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/epigraph-db has two ancestors")
        .to_path_buf()
}

fn collect(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `src` with every `#[cfg(test)]` / `#[cfg(all(test, ...))]` module removed
/// (by brace span) and every whole-line `//` comment dropped.
fn production_code(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        let is_test_attr = t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(all(test");
        if is_test_attr {
            // Find the item the attribute applies to; skip it if it is a module.
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim_start().starts_with("#[") {
                j += 1;
            }
            let item = lines.get(j).map_or("", |l| l.trim_start());
            if item.starts_with("mod ") || item.starts_with("pub mod ") {
                let mut depth: i64 = 0;
                let mut seen_open = false;
                let mut k = j;
                while k < lines.len() {
                    for c in lines[k].chars() {
                        if c == '{' {
                            depth += 1;
                            seen_open = true;
                        } else if c == '}' {
                            depth -= 1;
                        }
                    }
                    k += 1;
                    if seen_open && depth == 0 {
                        break;
                    }
                }
                i = k;
                continue;
            }
        }
        if !t.starts_with("//") {
            out.push_str(lines[i]);
            out.push('\n');
        }
        i += 1;
    }
    out
}

fn sources() -> Vec<(String, String)> {
    let root = repo_root();
    let mut files = Vec::new();
    for r in ROOTS {
        collect(&root.join(r), &mut files);
    }
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&p).expect("read source");
            (rel, production_code(&src))
        })
        .collect()
}

#[test]
fn the_scan_reads_both_crates_and_strips_test_modules() {
    let srcs = sources();
    assert!(
        srcs.len() > 100,
        "expected >100 source files under {ROOTS:?}, found {}: a silently empty scan \
         certifies nothing",
        srcs.len()
    );
    // Calibration of the test-module stripping: epigraph-mcp's maintenance
    // module attaches a maintenance pool in its #[cfg(test)] module only.
    let raw = std::fs::read_to_string(repo_root().join("crates/epigraph-mcp/src/maintenance.rs"))
        .expect("read maintenance.rs");
    assert!(
        raw.contains("with_maintenance_pool("),
        "CALIBRATION: the test module no longer attaches a pool, so the stripping is \
         unmeasured"
    );
    assert!(
        !production_code(&raw).contains("with_maintenance_pool("),
        "the #[cfg(test)] module was not stripped"
    );
}

#[test]
fn only_the_drain_timer_and_its_registration_acquire_maintenance_authority() {
    let mut found: BTreeMap<(String, &str), usize> = BTreeMap::new();
    for (rel, code) in sources() {
        for tok in TOKENS {
            let n = code.matches(tok).count();
            if n > 0 {
                found.insert((rel.clone(), tok), n);
            }
        }
    }
    let want: BTreeMap<(String, &str), usize> = ALLOWED
        .iter()
        .map(|(f, t, n)| (((*f).to_string(), *t), *n))
        .collect();
    assert_eq!(
        found, want,
        "\n\nA request-serving crate acquires maintenance authority or runs the job queue \
         somewhere new (or an allowed site went away). Under operator decision D9 the \
         maintenance DSN lives only in timers and operator CLIs: `server` and \
         `epigraph-mcp-full` hold none, and the job queue is the drain_jobs timer's. Move the \
         work to a timer or CLI, or, if the site is the drain's own, update ALLOWED with the \
         reason."
    );
}

#[test]
fn only_the_two_boot_refusals_read_the_variable() {
    let mut readers: Vec<String> = Vec::new();
    for (rel, code) in sources() {
        let reads = code
            .matches("env::var(epigraph_db::MAINTENANCE_DATABASE_URL)")
            .count()
            + code
                .matches("env::var(\"MAINTENANCE_DATABASE_URL\")")
                .count()
            + code
                .matches("env::var_os(\"MAINTENANCE_DATABASE_URL\")")
                .count()
            + code
                .matches("env::var_os(epigraph_db::MAINTENANCE_DATABASE_URL)")
                .count();
        if reads == 0 {
            continue;
        }
        assert_eq!(
            reads, 1,
            "{rel} reads MAINTENANCE_DATABASE_URL {reads} times"
        );
        // The read feeds the D9 predicate, and nothing else, in the same statement.
        let at = code
            .find("MAINTENANCE_DATABASE_URL)")
            .expect("the read is there");
        let before = &code[at.saturating_sub(400)..at];
        assert!(
            before.contains("request_unit_may_start(")
                || before.contains("request_unit_maintenance_dsn_check("),
            "{rel} reads MAINTENANCE_DATABASE_URL for something other than the D9 boot refusal"
        );
        readers.push(rel);
    }
    readers.sort();
    let mut want: Vec<String> = ENV_READERS.iter().map(ToString::to_string).collect();
    want.sort();
    assert_eq!(readers, want);
}

#[test]
fn the_unwired_reputation_service_stays_out_of_the_request_crates() {
    for (rel, code) in sources() {
        assert!(
            !code.contains("DbReputationService"),
            "{rel} wires epigraph-jobs' DbReputationService, a maintenance-pool consumer; under \
             D9 it belongs in the drain timer, never in a request-serving binary"
        );
    }
}
