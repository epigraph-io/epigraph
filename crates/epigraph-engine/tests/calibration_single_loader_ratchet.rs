//! Ratchet: the evidence-type calibration is resolved in ONE place,
//! `crates/epigraph-engine/src/calibration.rs` (`CalibrationConfig::cached`:
//! the `CALIBRATION_PATH` file when it loads, else the copy compiled into the
//! binary). No other production source reads a calibration file by path
//! (backlog d83b998a).
//!
//! Three private `load_evidence_type_weight` copies (MCP `tools/claims.rs`,
//! `tools/workflows.rs`, CLI `bin/backfill_factors.rs`) read the file
//! `CALIBRATION_PATH` named, else `calibration.toml` in the cwd, and returned
//! 0.7 on any failure, so a process started outside a checkout baked 0.7 into
//! BBAs the served calibration weights at 1.0. This test scans the code of
//! every `crates/*/src` file and `crates/*/build.rs` (comments and
//! `#[cfg(test)] mod` blocks excluded; string literals KEPT, since the
//! needles are literals) for:
//!
//! - `"CALIBRATION_PATH"`: reading the override variable outside the resolver;
//! - `CalibrationConfig::load(`: a path-based read of the calibration;
//! - a string literal ending in `calibration.toml"`: naming the file as a path
//!   (cwd-relative `"calibration.toml"`, or an `include_str!` copy).
//!
//! The exemption is the resolver's file by its FULL path (a file-name match
//! would also exempt `matching/calibration.rs`). Any other exception is an
//! entry in [`ALLOWED`] with its reason; an entry that matches nothing fails,
//! so the list cannot rot.
//!
//! Plain text processing (no syn), so it runs everywhere the suite runs.

use std::path::{Path, PathBuf};

/// The one module allowed to resolve the calibration from a path.
const RESOLVER: &str = "crates/epigraph-engine/src/calibration.rs";

/// `(workspace-relative file, fragment of the offending code line, reason)`.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "crates/epigraph-cli/src/bin/backfill_evidence_type.rs",
        "CalibrationConfig::load(&cli.calibration)",
        "an explicit, REQUIRED `--calibration <PATH>` operator argument that refuses an \
         empty [evidence_type_weights]; not an implicit env or cwd read",
    ),
    (
        "crates/epigraph-engine/src/belief_profile.rs",
        "p.overlaid(\"calibration.toml\", over)",
        "a provenance label for the profile overlay, not a path",
    ),
    (
        "crates/epigraph-engine/src/matching/calibration.rs",
        "Self::load_from(Path::new(\"calibration.toml\"))",
        "MatcherConfig ([matcher] section, cross-source matcher), a separate loader that \
         fails loudly instead of falling back; not the evidence-type calibration",
    ),
];

const NEEDLES: &[&str] = &[
    "\"CALIBRATION_PATH\"",
    "CalibrationConfig::load(",
    "calibration.toml\"",
];

#[derive(Debug, Clone, PartialEq)]
struct Hit {
    file: String,
    line: usize,
    text: String,
}

/// Two views of `src`, char-aligned with it (newlines kept):
/// `.0` with comments blanked (string literals kept), `.1` with comments AND
/// string/char literals blanked (for brace matching).
fn lex(src: &str) -> (Vec<char>, Vec<char>) {
    let b: Vec<char> = src.chars().collect();
    let mut keep = b.clone();
    let mut code = b.clone();
    let blank = |v: &mut Vec<char>, k: usize| {
        if v[k] != '\n' {
            v[k] = ' ';
        }
    };
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                blank(&mut keep, i);
                blank(&mut code, i);
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    for k in i..i + 2 {
                        blank(&mut keep, k);
                        blank(&mut code, k);
                    }
                    i += 2;
                    continue;
                }
                if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    for k in i..i + 2 {
                        blank(&mut keep, k);
                        blank(&mut code, k);
                    }
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                blank(&mut keep, i);
                blank(&mut code, i);
                i += 1;
            }
            continue;
        }
        // Raw string r"…", r#"…"#, br#"…"#: blanked in `code` only.
        let prev_ident = i > 0 && (b[i - 1].is_alphanumeric() || b[i - 1] == '_');
        if !prev_ident && (c == 'r' || (c == 'b' && next == Some('r'))) {
            let mut j = if c == 'b' { i + 2 } else { i + 1 };
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&'"') {
                let start = i;
                j += 1;
                while j < b.len() {
                    if b[j] == '"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&'#')) {
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                for k in start..j.min(b.len()) {
                    blank(&mut code, k);
                }
                i = j;
                continue;
            }
        }
        if c == '"' {
            let start = i;
            i += 1;
            while i < b.len() {
                if b[i] == '\\' {
                    i += 2;
                    continue;
                }
                if b[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            for k in start..i.min(b.len()) {
                blank(&mut code, k);
            }
            continue;
        }
        // Char literal 'x' / '\n' (a lifetime has no closing quote).
        if c == '\'' {
            let close = if next == Some('\\') {
                (i + 3..(i + 12).min(b.len())).find(|&k| b[k] == '\'')
            } else if b.get(i + 2) == Some(&'\'') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(end) = close {
                for k in i..=end {
                    blank(&mut code, k);
                }
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    (keep, code)
}

/// `src` with comments and every `#[cfg(test)] mod … { … }` block blanked,
/// string literals kept, line structure preserved.
fn production_code(src: &str) -> String {
    let (mut keep, code) = lex(src);
    let pat: Vec<char> = "#[cfg(test)]".chars().collect();
    let mut i = 0;
    while i + pat.len() <= code.len() {
        if code[i..i + pat.len()] != pat[..] {
            i += 1;
            continue;
        }
        let mut j = i + pat.len();
        while j < code.len() && code[j].is_whitespace() {
            j += 1;
        }
        let rest: String = code[j..code.len().min(j + 4)].iter().collect();
        if rest != "mod " {
            i += 1;
            continue;
        }
        let Some(open) = (j..code.len()).find(|&k| code[k] == '{' || code[k] == ';') else {
            break;
        };
        if code[open] == ';' {
            i = open + 1;
            continue;
        }
        let mut depth = 0;
        let mut end = code.len() - 1;
        for (k, ch) in code.iter().enumerate().skip(open) {
            if *ch == '{' {
                depth += 1;
            } else if *ch == '}' {
                depth -= 1;
                if depth == 0 {
                    end = k;
                    break;
                }
            }
        }
        for ch in keep.iter_mut().take(end + 1).skip(i) {
            if *ch != '\n' {
                *ch = ' ';
            }
        }
        i = end + 1;
    }
    keep.into_iter().collect()
}

/// Every needle hit in one file's production code.
fn scan(file: &str, src: &str) -> Vec<Hit> {
    production_code(src)
        .lines()
        .enumerate()
        .filter(|(_, l)| NEEDLES.iter().any(|n| l.contains(n)))
        .map(|(n, l)| Hit {
            file: file.to_string(),
            line: n + 1,
            text: l.trim().to_string(),
        })
        .collect()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Production sources: every `crates/<crate>/src/**/*.rs` and `build.rs`.
fn production_sources(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for krate in std::fs::read_dir(root.join("crates"))
        .expect("crates/")
        .flatten()
    {
        rs_files(&krate.path().join("src"), &mut files);
        let build = krate.path().join("build.rs");
        if build.is_file() {
            files.push(build);
        }
    }
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(root)
                .expect("under the workspace")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&p).expect("read source");
            (rel, src)
        })
        .collect()
}

fn is_allowed(hit: &Hit) -> bool {
    ALLOWED
        .iter()
        .any(|(f, frag, _)| hit.file == *f && hit.text.contains(frag))
}

#[test]
fn no_path_based_calibration_read_outside_the_resolver() {
    let root = workspace_root();
    let sources = production_sources(&root);
    assert!(
        sources.iter().any(|(f, _)| f == RESOLVER),
        "the resolver {RESOLVER} must exist (did it move? update this ratchet)"
    );
    let hits: Vec<Hit> = sources
        .iter()
        .filter(|(f, _)| f != RESOLVER)
        .flat_map(|(f, s)| scan(f, s))
        .collect();

    let offending: Vec<&Hit> = hits.iter().filter(|h| !is_allowed(h)).collect();
    assert!(
        offending.is_empty(),
        "path-based calibration reads outside {RESOLVER} (use \
         CalibrationConfig::cached(), which serves the CALIBRATION_PATH file or the \
         compiled-in copy; or add an ALLOWED entry with its reason):\n{}",
        offending
            .iter()
            .map(|h| format!("  {}:{}: {}", h.file, h.line, h.text))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let stale: Vec<&str> = ALLOWED
        .iter()
        .filter(|(f, frag, _)| !hits.iter().any(|h| h.file == *f && h.text.contains(frag)))
        .map(|(f, _, _)| *f)
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWED entries that exempt nothing (remove them): {stale:?}"
    );
}

/// The scanner itself: the three removed loader shapes are hits; the same
/// text in a comment, a doc comment or a `#[cfg(test)] mod` is not; an
/// `ALLOWED` fragment exempts only its own file.
#[test]
fn the_scanner_flags_the_removed_loader_shapes_and_nothing_in_comments_or_tests() {
    let removed = r#"
fn load_evidence_type_weight(evidence_type: &str) -> f64 {
    let path = std::env::var("CALIBRATION_PATH").unwrap_or_else(|_| "calibration.toml".to_string());
    epigraph_engine::calibration::CalibrationConfig::load(std::path::Path::new(&path))
        .ok()
        .map(|c| c.get_evidence_type_weight(evidence_type))
        .unwrap_or(0.7)
}
const COPY: &str = include_str!("../../../calibration.toml");
"#;
    let hits = scan("x.rs", removed);
    assert_eq!(
        hits.iter().map(|h| h.line).collect::<Vec<_>>(),
        vec![3, 4, 9],
        "env + cwd literal (line 3), path load (line 4), embedded copy (line 9): {hits:?}"
    );

    let quiet = r#"
//! Reads `CALIBRATION_PATH`: std::env::var("CALIBRATION_PATH")
/// `CalibrationConfig::load(Path::new("calibration.toml"))` was the old way.
fn served() -> f64 {
    // CalibrationConfig::load(&p) is forbidden here
    /* nested /* "calibration.toml" */ still a comment */
    let msg = "Failed to load calibration.toml: {e}";
    CalibrationConfig::cached().get_evidence_type_weight("empirical")
}
#[cfg(test)]
mod tests {
    fn path() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("calibration.toml") }
    fn load() { CalibrationConfig::load(&path()).unwrap(); }
}
fn after_tests() -> &'static str { "{" }
"#;
    assert_eq!(scan("y.rs", quiet), Vec::<Hit>::new());

    // Code after a test module (and a brace inside a string) is still scanned.
    let after = "#[cfg(test)]\nmod t { fn f() { let _ = \"}\"; } }\nfn g() { CalibrationConfig::load(&p); }\n";
    assert_eq!(scan("z.rs", after).len(), 1);

    let allowed_elsewhere = Hit {
        file: "crates/other/src/lib.rs".into(),
        line: 1,
        text: "CalibrationConfig::load(&cli.calibration)".into(),
    };
    assert!(
        !is_allowed(&allowed_elsewhere),
        "an ALLOWED fragment is per file"
    );
}
