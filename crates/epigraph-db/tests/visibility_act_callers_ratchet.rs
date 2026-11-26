//! Only the engine's visibility act may call the two raw widening acts.
//!
//! `ClaimRepository::publicize_conn` and `ClaimRepository::share_with_team_conn`
//! run the migration 215 definers, which widen a claim's audience (group to
//! public, home group to a team). They do NOT refold the moved claim's cached
//! belief: the fold runs in Rust, so `epigraph_engine::visibility_act` calls
//! the definer and then refolds every moved claim for its new audience, in the
//! same transaction. A direct call from anywhere else widens the audience and
//! serves it a value folded from sources it cannot read (backlog 31285392,
//! follow-up b20387e9).
//!
//! Narrowing the two functions to `pub(crate)` is not possible, because the
//! caller lives in another crate, so this ratchet fails instead when any Rust
//! source under `crates/` or the workspace's `tests/` other than the places
//! below names either function in a code line:
//!
//! * `epigraph-db/src/repos/claim_visibility.rs`, which defines them;
//! * `epigraph-engine/src/visibility_act.rs`, the one sanctioned caller;
//! * `epigraph-db/tests/`, whose tests drive the definers directly;
//! * the exact lines in [`REGISTER_DATA`], which name a function as register
//!   DATA (the callee string a viewer-call scanner measured in the sanctioned
//!   caller), not as a call. Only those lines of that file: a call anywhere in
//!   the same file is still reported.
//!
//! It also fails when a non-test source outside the defining file calls either
//! definer in SQL (`epigraph_publicize_claims($…` /
//! `epigraph_share_claims_with_team($…`, matched with whitespace removed, so
//! `( $1` counts), the same bypass one layer down. A call whose SQL text is
//! split across lines or assembled at run time is not seen; the database still
//! lets any application session execute the definers.
//!
//! A new caller must go through `epigraph_engine::visibility_act` instead.
//! Static: no database.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The Rust functions that must not be called outside [`ALLOWED`].
const FUNCTIONS: &[&str] = &["publicize_conn", "share_with_team_conn"];

/// The SQL calls of the two definers, as a caller would bind them.
const SQL_CALLS: &[&str] = &[
    "epigraph_publicize_claims($",
    "epigraph_share_claims_with_team($",
];

/// Files (repo-relative, `/`-separated) that may name the functions.
const ALLOWED: &[&str] = &[
    "crates/epigraph-db/src/repos/claim_visibility.rs",
    "crates/epigraph-engine/src/visibility_act.rs",
];

/// A directory prefix whose files may name the functions and the SQL.
const ALLOWED_TEST_DIR: &str = "crates/epigraph-db/tests/";

/// `(file, trimmed line)` pairs that name one of [`FUNCTIONS`] as register
/// data, not as a call. Matched on the WHOLE trimmed line, so a call, or the
/// same text with anything added, on any other line of the file is still
/// reported. Each entry must still be in the tree (see
/// `every_register_data_line_is_still_in_the_tree`).
///
/// The engine's viewer-call register (backlog 37e68f5b) records, for
/// `visibility_act.rs::{publicize_claims, share_claims_with_team}`, the one
/// callee its scanner measures in each: the sanctioned raw widening act.
const REGISTER_DATA: &[(&str, &str)] = &[
    (
        "crates/epigraph-engine/tests/viewer_calls_register.rs",
        "&[\"ClaimRepository::publicize_conn\"],",
    ),
    (
        "crates/epigraph-engine/tests/viewer_calls_register.rs",
        "&[\"ClaimRepository::share_with_team_conn\"],",
    ),
];

/// The sanctioned caller, and how many call sites of each function it has.
const CALLER: &str = "crates/epigraph-engine/src/visibility_act.rs";

/// Repo root: `CARGO_MANIFEST_DIR` is `crates/epigraph-db`.
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
            // Build output is not source.
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Lines that are not whole-line comments, numbered from 1.
fn code_lines(src: &str) -> impl Iterator<Item = (usize, &str)> {
    src.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
}

/// Whether `line` names `ident` as a whole identifier (not as part of a
/// longer one such as `publicize_conn_v2`).
fn names_ident(line: &str, ident: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(ident).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + ident.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// Every Rust source under `crates/` and `tests/`, repo-relative, with its
/// text.
fn sources() -> BTreeMap<String, String> {
    let root = repo_root();
    let mut files = Vec::new();
    // The two roots are named outside a `join(` so the CI shard planner
    // reads them as the Rust globs this file declares in its WALKERS entry
    // (`.github/scripts/test-shard.py`), not as every file under `tests/`.
    for top in ["crates", "tests"] {
        collect(&root.join(top), &mut files);
    }
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .expect("under the repo root")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {rel}: {e}"));
            (rel, src)
        })
        .collect()
}

/// `file:line: text` for every code line naming one of [`FUNCTIONS`] outside
/// the allowed places, and every non-test source line outside the defining
/// file that calls one of [`SQL_CALLS`].
fn violations(files: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for (rel, src) in files {
        let allowed = ALLOWED.contains(&rel.as_str()) || rel.starts_with(ALLOWED_TEST_DIR);
        let is_test = rel.starts_with("tests/") || rel.contains("/tests/");
        for (n, line) in code_lines(src) {
            let data = REGISTER_DATA
                .iter()
                .any(|(f, l)| *f == rel.as_str() && *l == line.trim());
            if !allowed && !data && FUNCTIONS.iter().any(|f| names_ident(line, f)) {
                out.push(format!("{rel}:{n}: {}", line.trim()));
            }
            let squeezed: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            if !allowed && !is_test && SQL_CALLS.iter().any(|s| squeezed.contains(s)) {
                out.push(format!("{rel}:{n}: {}", line.trim()));
            }
        }
    }
    out
}

#[test]
fn only_the_visibility_act_calls_the_raw_widening_acts() {
    let files = sources();
    let found = violations(&files);
    assert!(
        found.is_empty(),
        "these lines call a raw widening act (publicize_conn / share_with_team_conn, or their \
         definers in SQL) outside epigraph_engine::visibility_act, which would widen a claim's \
         audience without refolding its cached belief for it. Call \
         epigraph_engine::visibility_act::{{publicize_claims, share_claims_with_team}} \
         instead:\n{}",
        found.join("\n")
    );
}

/// The scan sees the tree: the sanctioned caller is found and calls each
/// function exactly once, and the defining file defines both.
#[test]
fn the_scan_is_not_vacuous() {
    let files = sources();
    assert!(
        files.len() > 100,
        "only {} sources under crates/",
        files.len()
    );
    assert!(
        files.keys().any(|k| k.starts_with("tests/")),
        "no source under the workspace's tests/ was scanned"
    );
    let caller = files
        .get(CALLER)
        .unwrap_or_else(|| panic!("{CALLER} not found: the ratchet must move with it"));
    for f in FUNCTIONS {
        let sites = code_lines(caller)
            .filter(|(_, l)| names_ident(l, f))
            .count();
        assert_eq!(sites, 1, "{CALLER} calls {f} {sites} times");
    }
    let defining = &files[ALLOWED[0]];
    for f in FUNCTIONS {
        assert!(
            defining.contains(&format!("pub async fn {f}(")),
            "{} no longer defines {f}",
            ALLOWED[0]
        );
    }
}

/// The detector reports a call from an unlisted file, in either form, and
/// ignores comments and longer identifiers.
#[test]
fn the_detector_reports_a_direct_call() {
    let mut files = BTreeMap::new();
    files.insert(
        "crates/epigraph-mcp/src/tools/visibility.rs".to_string(),
        "// publicize_conn is not called here\n\
         let o = ClaimRepository::publicize_conn(&mut tx, &ids, r).await?;\n\
         let p = share_with_team_conn_v2(x);\n"
            .to_string(),
    );
    files.insert(
        "crates/epigraph-api/src/routes/x.rs".to_string(),
        "sqlx::query(\"SELECT * FROM public.epigraph_share_claims_with_team($1, $2, $3)\")\n"
            .to_string(),
    );
    files.insert(
        "crates/epigraph-cli/src/bin/tenancy_backfill.rs".to_string(),
        "(\"epigraph_publicize_claims\", \"public.epigraph_publicize_claims(uuid[], text)\"),\n"
            .to_string(),
    );
    files.insert(
        "crates/epigraph-cli/src/bin/spaced.rs".to_string(),
        "sqlx::query(\"SELECT * FROM epigraph_publicize_claims ( $1, $2 )\")\n".to_string(),
    );
    files.insert(
        "tests/engine-integration/src/lib.rs".to_string(),
        "sqlx::query(\"SELECT * FROM epigraph_publicize_claims($1, $2)\")\n\
         ClaimRepository::share_with_team_conn(&mut c, &ids, g, r).await?;\n"
            .to_string(),
    );
    files.insert(
        "crates/epigraph-api/tests/t.rs".to_string(),
        "sqlx::query(\"SELECT * FROM epigraph_publicize_claims($1, $2)\")\n".to_string(),
    );
    let found = violations(&files);
    assert_eq!(
        found,
        vec![
            "crates/epigraph-api/src/routes/x.rs:1: sqlx::query(\"SELECT * FROM \
             public.epigraph_share_claims_with_team($1, $2, $3)\")"
                .to_string(),
            "crates/epigraph-cli/src/bin/spaced.rs:1: sqlx::query(\"SELECT * FROM \
             epigraph_publicize_claims ( $1, $2 )\")"
                .to_string(),
            "crates/epigraph-mcp/src/tools/visibility.rs:2: let o = \
             ClaimRepository::publicize_conn(&mut tx, &ids, r).await?;"
                .to_string(),
            "tests/engine-integration/src/lib.rs:2: \
             ClaimRepository::share_with_team_conn(&mut c, &ids, g, r).await?;"
                .to_string(),
        ]
    );
}

/// The register-data exemption admits only its exact lines of its file: a
/// call in the same file, a longer line naming the same callee, and the same
/// line in another file are all still reported.
#[test]
fn the_register_data_exemption_admits_only_its_exact_lines() {
    let mut files = BTreeMap::new();
    files.insert(
        "crates/epigraph-engine/tests/viewer_calls_register.rs".to_string(),
        "        &[\"ClaimRepository::publicize_conn\"],\n\
         &[\"ClaimRepository::share_with_team_conn\"],\n\
         let o = ClaimRepository::publicize_conn(&mut tx, &ids, r).await?;\n\
         &[\"ClaimRepository::share_with_team_conn\", \"sqlx::query(X).execute\"],\n"
            .to_string(),
    );
    files.insert(
        "crates/epigraph-mcp/tests/viewer_calls_register.rs".to_string(),
        "&[\"ClaimRepository::publicize_conn\"],\n".to_string(),
    );
    let found = violations(&files);
    assert_eq!(
        found,
        vec![
            "crates/epigraph-engine/tests/viewer_calls_register.rs:3: let o = \
             ClaimRepository::publicize_conn(&mut tx, &ids, r).await?;"
                .to_string(),
            "crates/epigraph-engine/tests/viewer_calls_register.rs:4: \
             &[\"ClaimRepository::share_with_team_conn\", \"sqlx::query(X).execute\"],"
                .to_string(),
            "crates/epigraph-mcp/tests/viewer_calls_register.rs:1: \
             &[\"ClaimRepository::publicize_conn\"],"
                .to_string(),
        ]
    );
}

/// Every [`REGISTER_DATA`] line is still in its file, so a stale exemption
/// cannot linger after the register changes.
#[test]
fn every_register_data_line_is_still_in_the_tree() {
    let files = sources();
    for (file, line) in REGISTER_DATA {
        let src = files
            .get(*file)
            .unwrap_or_else(|| panic!("{file} not found: remove its REGISTER_DATA entries"));
        assert!(
            src.lines().any(|l| l.trim() == *line),
            "{file} no longer has the line {line}: remove the stale REGISTER_DATA entry"
        );
    }
}
