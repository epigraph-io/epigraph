//! `--help` must never print the current value of an env-backed argument.
//!
//! clap renders every `#[arg(env = "X")]` as `[env: X=<current value>]` in
//! help output unless the argument sets `hide_env_values = true`. For this
//! binary that includes `DATABASE_URL` (a DSN carries a password),
//! `OPENAI_API_KEY` and `EPIGRAPH_JWT_SECRET`, so running `--help` in a shell
//! that has the service environment loaded writes those secrets to the
//! terminal, a log, or an agent transcript.
//!
//! Two tests, deliberately separate so a regression shows which one caught it:
//!
//! * `help_output_never_contains_an_env_value` runs the REAL binary's
//!   `--help` (and every subcommand's) with a sentinel in every env var the
//!   source declares, and asserts no sentinel reaches stdout or stderr. It also
//!   asserts the set of `[env: NAME]` annotations it saw equals the set the
//!   source declares, so it cannot pass vacuously on an exit-early error or on
//!   a scanner that found nothing.
//! * `every_env_backed_arg_hides_its_value` is the static lint: every
//!   `#[arg(...)]` / `#[clap(...)]` attribute under `src/` that names an env
//!   var spells the name explicitly and sets `hide_env_values = true` —
//!   including args that look harmless, because the next one added may not be.
//!
//! The child runs with a cleared environment and a cwd with no `.env` in any
//! ancestor (the binary may call `dotenvy::dotenv()`, which walks upward), and
//! a failure message names the binary, subcommand and env var only: it never
//! echoes help text, because test output is itself a disclosure surface.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every binary in this crate whose source declares an env-backed argument:
/// `(label, executable, source file relative to the crate root)`.
const BINS: &[(&str, &str, &str)] = &[(
    "epigraph-mcp-full",
    env!("CARGO_BIN_EXE_epigraph-mcp-full"),
    "src/main.rs",
)];

const SENTINEL_TAG: &str = "HELPLEAK";

fn sentinel(name: &str) -> String {
    format!("{SENTINEL_TAG}-{name}-5e4c")
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// One env-backed clap argument found in source.
struct EnvArg {
    file: PathBuf,
    line: usize,
    /// `None` for a bare `env` (the name is derived from the field), which the
    /// lint refuses because the runtime test could not set it.
    name: Option<String>,
    hidden: bool,
}

#[derive(Debug, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Eq,
    Other,
}

fn tokenize(body: &str) -> Vec<Tok> {
    let chars: Vec<char> = body.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            let mut s = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                }
                if i < chars.len() {
                    s.push(chars[i]);
                }
                i += 1;
            }
            toks.push(Tok::Str(s));
        } else if c.is_alphanumeric() || c == '_' {
            let mut s = String::new();
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                s.push(chars[i]);
                i += 1;
            }
            toks.push(Tok::Ident(s));
            continue;
        } else if c == '=' {
            toks.push(Tok::Eq);
        } else if !c.is_whitespace() {
            toks.push(Tok::Other);
        }
        i += 1;
    }
    toks
}

/// Byte index of the `)` closing an attribute body that starts at `start`
/// (just past its `(`), skipping string literals.
fn attr_body_end(b: &[u8], start: usize) -> usize {
    let (mut depth, mut i, mut in_str) = (1usize, start, false);
    while i < b.len() {
        let c = b[i];
        if in_str {
            if c == b'\\' {
                i += 1;
            } else if c == b'"' {
                in_str = false;
            }
        } else {
            match c {
                b'"' => in_str = true,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return i;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    panic!("unterminated attribute starting at byte {start}");
}

fn env_args_in(file: &Path) -> Vec<EnvArg> {
    let raw =
        std::fs::read_to_string(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
    // Blank out line comments (doc comments quote `#[arg(env = ...)]` in prose)
    // while keeping line numbers stable.
    let src: String = raw
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut out = Vec::new();
    for opener in ["#[arg(", "#[clap("] {
        let mut from = 0;
        while let Some(off) = src[from..].find(opener) {
            let start = from + off + opener.len();
            let end = attr_body_end(src.as_bytes(), start);
            let toks = tokenize(&src[start..end]);
            let line = src[..start].matches('\n').count() + 1;
            for (k, t) in toks.iter().enumerate() {
                if *t != Tok::Ident("env".into()) {
                    continue;
                }
                let name = match (toks.get(k + 1), toks.get(k + 2)) {
                    (Some(Tok::Eq), Some(Tok::Str(s))) => Some(s.clone()),
                    _ => None,
                };
                let hidden = toks.iter().enumerate().any(|(j, t)| {
                    *t == Tok::Ident("hide_env_values".into())
                        && !matches!(
                            (toks.get(j + 1), toks.get(j + 2)),
                            (Some(Tok::Eq), Some(Tok::Ident(v))) if v == "false"
                        )
                });
                out.push(EnvArg {
                    file: file.to_path_buf(),
                    line,
                    name,
                    hidden,
                });
            }
            from = end;
        }
    }
    out
}

fn rust_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files_under(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// A cwd for the child with no `.env` in it or any ancestor.
fn scrubbed_cwd() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("help-hides-env-values-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch cwd");
    for anc in dir.ancestors() {
        assert!(
            !anc.join(".env").exists(),
            "{} contains a .env that dotenvy would load into the child; point TMPDIR elsewhere",
            anc.display()
        );
    }
    dir
}

/// `[env: NAME]` / `[env: NAME=VALUE]` annotations: `(name, carries_a_value)`.
fn env_annotations(help: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut rest = help;
    while let Some(i) = rest.find("[env: ") {
        rest = &rest[i + "[env: ".len()..];
        let end = rest.find(']').unwrap_or(rest.len());
        let ann = &rest[..end];
        match ann.split_once('=') {
            Some((name, _)) => out.push((name.trim().to_string(), true)),
            None => out.push((ann.trim().to_string(), false)),
        }
    }
    out
}

/// Subcommand names listed under `Commands:`, minus clap's own `help`.
fn subcommands(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|l| l.trim_end() != "Commands:")
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .filter(|s| s != "help")
        .collect()
}

struct Walk<'a> {
    label: &'a str,
    exe: &'a str,
    envs: &'a BTreeSet<String>,
    cwd: &'a Path,
    seen: BTreeSet<String>,
    failures: Vec<String>,
}

impl Walk<'_> {
    fn help(&mut self, path: &[String]) {
        let at = std::iter::once(self.label.to_string())
            .chain(path.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ");
        let out = Command::new(self.exe)
            .args(path)
            .arg("--help")
            .env_clear()
            .envs(self.envs.iter().map(|n| (n.clone(), sentinel(n))))
            .current_dir(self.cwd)
            .output()
            .unwrap_or_else(|e| panic!("spawn {at}: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() || !stdout.contains("Usage:") {
            self.failures.push(format!(
                "`{at} --help` did not render help (exit {:?}); output withheld",
                out.status.code()
            ));
        }
        for name in self.envs {
            let s = sentinel(name);
            if stdout.contains(&s) || stderr.contains(&s) {
                self.failures
                    .push(format!("`{at} --help` printed the value of {name}"));
            }
        }
        if stdout.contains(SENTINEL_TAG) || stderr.contains(SENTINEL_TAG) {
            self.failures
                .push(format!("`{at} --help` printed a sentinel value"));
        }
        for (name, shown) in env_annotations(&stdout) {
            if shown {
                self.failures.push(format!(
                    "`{at} --help` renders [env: {name}=...] with a value"
                ));
            }
            self.seen.insert(name);
        }
        for sub in subcommands(&stdout) {
            let mut next = path.to_vec();
            next.push(sub);
            self.help(&next);
        }
    }
}

#[test]
fn help_output_never_contains_an_env_value() {
    let cwd = scrubbed_cwd();
    let mut failures = Vec::new();
    for (label, exe, file) in BINS {
        let expected: BTreeSet<String> = env_args_in(&crate_root().join(file))
            .into_iter()
            .filter_map(|a| a.name)
            .collect();
        assert!(
            !expected.is_empty(),
            "{file}: no env-backed args found; stale table?"
        );
        let mut walk = Walk {
            label,
            exe,
            envs: &expected,
            cwd: &cwd,
            seen: BTreeSet::new(),
            failures: Vec::new(),
        };
        walk.help(&[]);
        if walk.seen != expected {
            failures.push(format!(
                "{label}: help annotated env vars {:?}, source declares {:?}",
                walk.seen, expected
            ));
        }
        failures.extend(walk.failures);
    }
    let _ = std::fs::remove_dir(&cwd);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_env_backed_arg_hides_its_value() {
    let mut files = Vec::new();
    rust_files_under(&crate_root().join("src"), &mut files);
    let mut by_file: BTreeMap<PathBuf, Vec<EnvArg>> = BTreeMap::new();
    for f in &files {
        for a in env_args_in(f) {
            by_file.entry(a.file.clone()).or_default().push(a);
        }
    }
    assert!(
        !by_file.is_empty(),
        "scanner found no env-backed args at all"
    );
    let mut failures = Vec::new();
    for (file, args) in &by_file {
        let rel = file.strip_prefix(crate_root()).unwrap_or(file);
        for a in args {
            match &a.name {
                None => failures.push(format!(
                    "{}:{}: bare `env`; spell the name (`env = \"NAME\"`) so the help test can set it",
                    rel.display(),
                    a.line
                )),
                Some(n) if !a.hidden => failures.push(format!(
                    "{}:{}: env = \"{n}\" lacks `hide_env_values = true`; --help would print its value",
                    rel.display(),
                    a.line
                )),
                Some(_) => {}
            }
        }
        if !BINS
            .iter()
            .any(|(_, _, src)| crate_root().join(src) == *file)
        {
            failures.push(format!(
                "{} declares env-backed args but is not in BINS; add it so its --help is exercised",
                rel.display()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
