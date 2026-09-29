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
//! * the spellings that ACQUIRE maintenance authority or run the job queue
//!   ([`TOKENS`]) appear only at the sites in [`ALLOWED`], at exactly the
//!   counts recorded there. Two families:
//!   - resolving or attaching the maintenance DSN, and running the queue:
//!     `maintenance_database_url(`, `resolve_maintenance_url(`,
//!     `with_maintenance_pool(`, `JobRunner::new`, `PostgresJobQueue::new`
//!     (the `drain_jobs` timer binary, the one job-registration function it
//!     calls, and the test-only `build_app_for_tests_with_admin_cascade`
//!     helper);
//!   - leasing a maintenance connection from a `ScopedPool`:
//!     `maintenance_session(`, `unscoped_for_maintenance(`,
//!     `maintenance_inner(`. `ScopedPool` falls back to the APPLICATION pool
//!     when no maintenance pool is attached (the operator CLI fleet relies on
//!     that), so in a request binary such a call is a bypass on the
//!     application DSN: on a privileged application DSN, the very surface D9
//!     removed. The permitted sites are the two gated `maintenance_viewer`s
//!     (each refuses first when no maintenance pool is attached) and the
//!     embedding job handler, which only the drain registers;
//! * the environment variable is READ only by the two boot refusals (the
//!   `server` and `epigraph-mcp-full` mains), each of which hands it straight to
//!   the D9 predicate; and its NAME appears in production code only there and
//!   in the drain timer's own messages ([`VARIABLE_NAMED`]), which catches a
//!   read that does not go through `std::env::var` (a clap `env = ...`
//!   binding, a scan of `std::env::vars()` that compares names);
//! * `DbReputationService` (epigraph-jobs), a maintenance-pool consumer with no
//!   constructor anywhere, is not wired into either crate: if it is ever wired,
//!   it belongs in the drain timer, not a request binary.
//!
//! The set is asserted in BOTH directions: a new site fails, and a site that
//! is removed but left in [`ALLOWED`] fails too, so the table cannot turn into
//! folklore.
//!
//! A function token (one spelled `name(`) is counted by its BARE IDENTIFIER as
//! a whole word, so a path to the function item
//! (`let f = ScopedPool::maintenance_session;`) and a renaming import
//! (`use epigraph_db::resolve_maintenance_url as r;`) count like a call
//! (review W12a-D4). The two queue types are not counted bare (they are named
//! legitimately as types), so renaming either of them (`use ... as`, a `type`
//! alias) is refused outright.
//!
//! # Known limits
//!
//! * Only [`ROOTS`] is scanned. A helper in a LINKED crate (epigraph-engine,
//!   an epigraph-db repo) that leases `maintenance_session` and is called from
//!   a route is not seen here: the lease happens outside both crates. None
//!   exists today (the sites outside the two crates are the operator CLIs in
//!   epigraph-cli and the drain-only job handlers in epigraph-jobs); a new one
//!   is a review question, not something this scan can answer.
//! * A name assembled at run time (`concat!`, `format!` of two halves) or
//!   produced by a macro is not caught; nor is a DSN handed over under another
//!   variable name, nor a queue type reached through a generic parameter.
//! * A token inside a string literal counts (none does today). A whole-line
//!   `//` comment is skipped; a trailing comment after code is not (none
//!   carries a token). `#[cfg(test)]` removal is by brace span from the
//!   attribute's `mod` item, which is how every in-source test module here is
//!   written.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const TOKENS: &[&str] = &[
    "maintenance_database_url(",
    "resolve_maintenance_url(",
    "with_maintenance_pool(",
    "JobRunner::new",
    "PostgresJobQueue::new",
    "maintenance_session(",
    "unscoped_for_maintenance(",
    "maintenance_inner(",
];

/// The [`TOKENS`] that name a `ScopedPool` / `epigraph_db` function, each of
/// which must still be DEFINED in `epigraph-db/src/pool.rs` under that name: a
/// token that matches nothing anywhere certifies nothing.
const POOL_FNS: &[&str] = &[
    "maintenance_database_url(",
    "resolve_maintenance_url(",
    "with_maintenance_pool(",
    "maintenance_session(",
    "unscoped_for_maintenance(",
    "maintenance_inner(",
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
    // `AppState::maintenance_viewer`: refuses with `NotServed` first when no
    // maintenance pool is attached, so the application-pool fallback is never
    // reached on a request unit.
    (
        "crates/epigraph-api/src/state.rs",
        "maintenance_session(",
        1,
    ),
    // `epigraph-mcp`'s `maintenance_viewer`: the same gate, then the lease.
    (
        "crates/epigraph-mcp/src/maintenance.rs",
        "maintenance_session(",
        1,
    ),
    // `ClaimEmbeddingJobService`, the `embedding_generation` handler: only
    // `jobs_drain::build_job_runner` (the drain timer) registers it.
    (
        "crates/epigraph-api/src/embedding_restore.rs",
        "unscoped_for_maintenance(",
        2,
    ),
];

/// `(repo-relative file, count)`: every production-code occurrence of the
/// variable's NAME, `MAINTENANCE_DATABASE_URL` (the `epigraph_db` constant's
/// name is the same text, so a use of the constant counts too).
const VARIABLE_NAMED: &[(&str, usize)] = &[
    // The boot refusal's one read.
    ("crates/epigraph-api/src/bin/server.rs", 1),
    ("crates/epigraph-mcp/src/main.rs", 1),
    // The drain timer's usage text and its unset-variable refusal.
    ("crates/epigraph-api/src/bin/drain_jobs.rs", 2),
];

/// The only files that may read the environment variable, and why: each is a
/// request-serving `main` that refuses to start when it is set.
const ENV_READERS: &[&str] = &[
    "crates/epigraph-api/src/bin/server.rs",
    "crates/epigraph-mcp/src/main.rs",
];

const ROOTS: &[&str] = &["crates/epigraph-api/src", "crates/epigraph-mcp/src"];

/// Occurrences of `tok` in `code`.
///
/// A token ending in `(` names a FUNCTION, and is counted by its bare
/// identifier as a whole word, not by its call spelling: a call is one use,
/// and so is a path to the function item (`let f = ScopedPool::maintenance_session;`)
/// or a renaming import (`use epigraph_db::resolve_maintenance_url as r;`),
/// neither of which contains `name(` (review W12a-D4). Other tokens
/// (`JobRunner::new`, `PostgresJobQueue::new`) are counted as written; their
/// types' renaming is refused by [`no_register_type_is_renamed`].
fn token_count(code: &str, tok: &str) -> usize {
    match tok.strip_suffix('(') {
        Some(ident) => ident_count(code, ident),
        None => code.matches(tok).count(),
    }
}

/// Whole-word occurrences of the identifier `ident` in `code`.
fn ident_count(code: &str, ident: &str) -> usize {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    code.match_indices(ident)
        .filter(|(at, _)| {
            let before = code[..*at].chars().next_back();
            let after = code[at + ident.len()..].chars().next();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .count()
}

/// The two queue types whose constructor is a [`TOKENS`] entry. Renamed (a
/// `use ... as` or a `type` alias), `Alias::new` would not match the token.
const REGISTER_TYPES: &[&str] = &["JobRunner", "PostgresJobQueue"];

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
            let n = token_count(&code, tok);
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

#[test]
fn every_pool_token_still_names_a_function_epigraph_db_defines() {
    let pool = std::fs::read_to_string(repo_root().join("crates/epigraph-db/src/pool.rs"))
        .expect("read pool.rs");
    for tok in POOL_FNS {
        assert!(
            pool.contains(&format!("fn {tok}")),
            "`{tok}` is no longer defined in epigraph-db/src/pool.rs: the register would scan \
             for a name nothing can call. Rename the token with the function"
        );
    }
}

#[test]
fn the_variable_is_named_only_by_the_boot_refusals_and_the_drain_timer() {
    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    for (rel, code) in sources() {
        let n = code.matches("MAINTENANCE_DATABASE_URL").count();
        if n > 0 {
            found.insert(rel, n);
        }
    }
    let want: BTreeMap<String, usize> = VARIABLE_NAMED
        .iter()
        .map(|(f, n)| ((*f).to_string(), *n))
        .collect();
    assert_eq!(
        found, want,
        "\n\nA request-serving crate names MAINTENANCE_DATABASE_URL somewhere new (or a \
         recorded site went away). Under operator decision D9 only the two boot refusals may \
         read it, and a clap `env = ...` binding or a scan of the environment reads it without \
         `std::env::var`. If the new site is the drain timer's own, update VARIABLE_NAMED with \
         the reason."
    );
}

#[test]
fn no_register_type_is_renamed() {
    for (rel, code) in sources() {
        for ty in REGISTER_TYPES {
            for renamed in [format!("{ty} as "), format!("= {ty};"), format!("= {ty}<")] {
                assert!(
                    !code.contains(&renamed),
                    "{rel} renames `{ty}` (`{renamed}`): `<alias>::new` would then escape the \
                     D9 register's `{ty}::new` token. Use the type by its own name"
                );
            }
        }
    }
}

#[test]
fn the_identifier_count_sees_paths_and_renames_but_not_longer_names() {
    // Calibration of `token_count` on the shapes review W12a-D4 used to bypass
    // the call spelling, and on the near-misses it must not count.
    let t = "maintenance_session(";
    assert_eq!(token_count("s.maintenance_session(r)", t), 1);
    assert_eq!(
        token_count("let f = epigraph_db::ScopedPool::maintenance_session;", t),
        1
    );
    assert_eq!(
        token_count(
            "use epigraph_db::resolve_maintenance_url as r;",
            "resolve_maintenance_url("
        ),
        1
    );
    assert_eq!(token_count("fn maintenance_session_privilege() {}", t), 0);
    assert_eq!(token_count("self.xmaintenance_session(", t), 0);
    assert_eq!(token_count("JobRunner::new(q)", "JobRunner::new"), 1);
}
