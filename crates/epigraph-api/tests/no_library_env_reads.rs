//! Library code in `epigraph-api` must not read the process environment.
//!
//! Backlog deed6549 (split 4/4 of 378ee0c0): configuration was read with
//! `std::env::var` at the point of use, in handlers and helpers as well as in
//! `bin/server.rs`. A read in a handler runs on every request, is invisible
//! to the binary's startup checks, and cannot be set by a test without
//! mutating the process environment. The settings pattern is:
//!
//! * a typed setting with a pure `parse(Option<&str>)` and a `from_env()` that
//!   feeds it the variable (`serving.rs`, `oauth/redirect.rs`,
//!   `oauth/run_token.rs`);
//! * `bin/server.rs` calls `from_env()` (or reads the variable) ONCE at
//!   startup and passes the value in: an `AppState` builder
//!   (`with_oauth_redirect_origins`, ...) or a function argument
//!   (`edge_signer::boot(pool, key_file)`).
//!
//! # What is scanned
//!
//! Every `.rs` file under `crates/epigraph-api/src`, except `src/bin/` (the
//! binaries are where the environment IS read). Items under `#[cfg(test)]` or
//! `#[cfg(all(test, ...))]` are cut (a test reading `DATABASE_URL` is fine);
//! `#[cfg(any(test, ...))]` is NOT cut, since it is compiled into a non-test
//! build too. Whole-line `//` comments are skipped. A site is a call of
//! `env::var(` or `env::var_os(` (so also `std::env::var(`).
//!
//! # The allowlist
//!
//! Each site is attributed to its enclosing `fn` (by indentation, see
//! [`enclosing_fn`]; a closure is attributed to the fn that holds it, and a
//! read outside any fn to none). A site whose `(file, fn)` is not in [`ALLOWED`] fails the
//! test with `file:line`. An entry is NOT required to still match a site: a
//! straggler item that removes its read leaves its entry inert, and the PR
//! that lands it deletes the entry (a "stale entry fails" rule would turn this
//! test red on whichever parallel PR lands first).
//!
//! # Known limits
//!
//! `use std::env::var; var("X")` and `std::env::vars()` are not seen; nor is a
//! read in another crate the library calls. This is a guard against the
//! common spelling, not a proof.

use std::path::{Path, PathBuf};

/// `(file relative to src/, enclosing fn, why)`.
const ALLOWED: &[(&str, &str, &str)] = &[
    // The settings pattern itself: a typed setting's `from_env`, called once
    // by bin/server.rs.
    ("serving.rs", "from_env", "settings pattern"),
    ("security/rate_limit.rs", "from_env", "settings pattern"),
    ("oauth/redirect.rs", "from_env", "settings pattern"),
    ("oauth/run_token.rs", "from_env", "settings pattern"),
    ("oauth/token_exchange.rs", "from_env", "settings pattern"),
    // AssertionV1Policy::from_env.
    ("oauth/assertion.rs", "from_env", "settings pattern"),
    // The migrate-on-boot settings, read by the binary and epigraph-migrate.
    ("migrate.rs", "migration_dsn_from_env", "settings pattern"),
    (
        "migrate.rs",
        "from_env",
        "MigrateOptions::from_env, settings pattern",
    ),
    (
        "migrate.rs",
        "grant_seed_to_self_requested",
        "settings pattern",
    ),
    // providers.toml names the VARIABLE holding each secret (`*_env` keys);
    // resolving that indirection is the point of these functions. In
    // google.rs and cloudflare_access.rs the read is a `resolve_env` closure
    // inside `from_config`.
    (
        "oauth/providers/config.rs",
        "resolve_env",
        "providers.toml env-name indirection",
    ),
    (
        "oauth/providers/google.rs",
        "from_config",
        "providers.toml env-name indirection",
    ),
    (
        "oauth/providers/cloudflare_access.rs",
        "from_config",
        "providers.toml env-name indirection",
    ),
    // Operator decision D9: the embedding service is built from the
    // environment by this one function.
    (
        "embedding_restore.rs",
        "embedding_service_from_env",
        "operator decision D9",
    ),
    // Owned by 70a92fc5 (the JWT secret's two readers).
    ("state.rs", "default_jwt_config", "owned by 70a92fc5"),
    (
        "routes/search.rs",
        "key_cursor_mac_key",
        "owned by 70a92fc5",
    ),
    // `AppState::new(config)`: the lazy-pool constructor documented to panic
    // without DATABASE_URL. No backlog item moves it yet (378ee0c0 names the
    // read); it belongs with the typed config.
    ("state.rs", "new", "378ee0c0: AppState::new's DATABASE_URL"),
    // TODO(e8e14178): read EPIGRAPH_LLM_PROVIDER once at boot, not per
    // request; delete this entry when it lands.
    (
        "routes/analyze.rs",
        "unconstrained_analysis",
        "TODO e8e14178",
    ),
    // TODO(b2017136): server.rs::main's env and config gates move into a
    // library `boot::check_env_gates()`. Narrow or delete this entry when
    // those reads move behind a settings type.
    ("boot.rs", "check_env_gates", "TODO b2017136"),
];

const NEEDLES: &[&str] = &["env::var(", "env::var_os("];

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
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

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn is_test_cfg(trimmed: &str) -> bool {
    trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[cfg(all(test")
}

/// `keep[i]` is false for every line of an item gated on a test cfg. rustfmt
/// layout is assumed: the item ends at the first line at the item's own
/// indentation that closes a block (`}`) or ends with `;` or `,`.
fn non_test_lines(lines: &[&str]) -> Vec<bool> {
    let mut keep = vec![true; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        if !is_test_cfg(lines[i].trim()) {
            i += 1;
            continue;
        }
        let first = i;
        // An item written on the cfg's own line (`#[cfg(test)] fn f() {}`)
        // starts there; otherwise skip further attributes and comments
        // between the cfg and its item.
        let same_line = lines[i].trim().split_once(")]").is_some_and(|(_, rest)| {
            let rest = rest.trim();
            !rest.is_empty() && !rest.starts_with("//")
        });
        let mut j = if same_line { i } else { i + 1 };
        while !same_line && j < lines.len() {
            let t = lines[j].trim();
            if t.starts_with("#[") || t.starts_with("//") || t.is_empty() {
                j += 1;
            } else {
                break;
            }
        }
        let item_indent = lines.get(j).map_or(0, |l| indent(l));
        let mut end = j;
        while end < lines.len() {
            let l = lines[end];
            let t = l.trim_end();
            if end > j && !t.trim().is_empty() && indent(l) < item_indent {
                // Left the enclosing block without finding the item's end.
                end -= 1;
                break;
            }
            let at_item_level = indent(l) == item_indent;
            let closes = end > j && t.trim_start().starts_with('}');
            // A one-line item (`fn helper() -> u8 { 1 }`, `struct S {}`) ends
            // on its own line; without this the cut would run on through the
            // next (production) item.
            let one_line =
                end == j && t.ends_with('}') && t.matches('{').count() == t.matches('}').count();
            if at_item_level && (t.ends_with(';') || t.ends_with(',') || closes || one_line) {
                break;
            }
            end += 1;
        }
        let last = end.min(lines.len() - 1);
        for k in keep.iter_mut().take(last + 1).skip(first) {
            *k = false;
        }
        i = last + 1;
    }
    keep
}

/// The fn name declared on `trimmed`, if it declares one.
fn declared_fn(trimmed: &str) -> Option<&str> {
    let mut rest = trimmed;
    loop {
        let (tok, tail) = rest.split_once(char::is_whitespace)?;
        let tail = tail.trim_start();
        if tok == "fn" {
            let end = tail
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(tail.len());
            return (end > 0).then(|| &tail[..end]);
        }
        let qualifier = tok == "pub"
            || tok.starts_with("pub(")
            || matches!(tok, "const" | "async" | "unsafe" | "extern" | "default")
            || tok.starts_with('"');
        if !qualifier {
            return None;
        }
        rest = tail;
    }
}

/// The fn enclosing a line indented `ind`, given the lines above it: walk up
/// the chain of opening lines (each indented less than the last), skipping a
/// multi-line signature's `) -> T {` / `where` tail, and stop at the first
/// `fn` declaration. A non-fn opener at column 0 (a `static`'s initializer,
/// say) ends the walk with `None`, so a module-level read is never pinned on
/// the fn above it.
fn enclosing_fn<'a>(above: &[&'a str], ind: usize) -> Option<&'a str> {
    let mut limit = ind;
    for l in above.iter().rev() {
        let t = l.trim();
        if t.is_empty() || t.starts_with("//") || indent(l) >= limit {
            continue;
        }
        if let Some(name) = declared_fn(t) {
            return Some(name);
        }
        let signature_tail = t.starts_with(')') || t.starts_with("->") || t.starts_with("where");
        limit = if signature_tail {
            indent(l) + 1
        } else {
            indent(l)
        };
        if limit == 0 {
            return None;
        }
    }
    None
}

#[derive(Debug)]
struct Site {
    file: String,
    line: usize,
    func: String,
    text: String,
}

/// The sites in one file's source.
fn scan(file: &str, src: &str) -> Vec<Site> {
    let lines: Vec<&str> = src.lines().collect();
    let keep = non_test_lines(&lines);
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if !keep[i] || t.starts_with("//") {
            continue;
        }
        let n: usize = NEEDLES.iter().map(|n| line.matches(n).count()).sum();
        if n == 0 {
            continue;
        }
        let func = declared_fn(t)
            .or_else(|| enclosing_fn(&lines[..i], indent(line)))
            .unwrap_or("<not in a fn>")
            .to_string();
        for _ in 0..n {
            out.push(Site {
                file: file.to_string(),
                line: i + 1,
                func: func.clone(),
                text: t.to_string(),
            });
        }
    }
    out
}

fn measure() -> Vec<Site> {
    let root = src_root();
    let mut files = Vec::new();
    collect(&root, &mut files);
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel.starts_with("bin/") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read source");
        out.extend(scan(&rel, &src));
    }
    out
}

fn allowed(site: &Site) -> bool {
    ALLOWED
        .iter()
        .any(|(f, func, _)| *f == site.file && *func == site.func)
}

#[test]
fn library_code_reads_no_environment_outside_the_allowlist() {
    let sites = measure();
    let offending: Vec<String> = sites
        .iter()
        .filter(|s| !allowed(s))
        .map(|s| format!("  src/{}:{} (in fn {}): {}", s.file, s.line, s.func, s.text))
        .collect();
    assert!(
        offending.is_empty(),
        "epigraph-api library code reads the process environment outside the \
         allowlist:\n{}\n\nRead the variable ONCE in bin/server.rs and pass the value in \
         (an AppState builder or a function argument). For a setting with rules, add a \
         typed setting with a pure `parse(Option<&str>)` and a `from_env()`, as \
         serving.rs and oauth/redirect.rs do, and call `from_env()` from the binary. A \
         deliberate exception needs an ALLOWED entry in this file with its reason.",
        offending.join("\n")
    );
}

/// Calibration: a green run must mean "no unlisted read", not "the scanner
/// saw nothing".
#[test]
fn the_scanner_is_not_vacuous() {
    let sample = "\
pub fn from_env() -> Self {
    let v = std::env::var(\"A\").ok();
    let w = env::var_os(\"B\");
    // let x = std::env::var(\"C\");
    let f = |n: &str| std::env::var(n).ok();
}

pub async fn handler(
    State(state): State<AppState>,
) -> Response {
    if std::env::var(\"X\").is_ok() {}
}

#[cfg(test)]
mod tests {
    fn t() {
        let url = std::env::var(\"DATABASE_URL\").unwrap();
    }
}

#[cfg(all(test, feature = \"db\"))]
mod db_tests {
    #[test]
    fn t() {
        let url = std::env::var(\"DATABASE_URL\").unwrap();
    }
}

#[cfg(any(test, feature = \"db\"))]
fn shared() -> String {
    std::env::var(\"Y\").unwrap()
}

static K: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| std::env::var(\"Z\").unwrap());
";
    let sites = scan("sample.rs", sample);
    let got: Vec<(usize, &str)> = sites.iter().map(|s| (s.line, s.func.as_str())).collect();
    assert_eq!(
        got,
        vec![
            (2, "from_env"),
            (3, "from_env"),
            (5, "from_env"),
            (11, "handler"),
            (31, "shared"),
            (35, "<not in a fn>"),
        ],
        "detected sites and their enclosing fns"
    );

    // A one-line test item, on its own line or on the cfg's line, hides
    // only itself: the production fns after it are still scanned.
    let one_liners = "\
#[cfg(test)]
fn helper() -> u8 { 1 }
pub fn after_helper() -> String {
    std::env::var(\"P\").unwrap()
}
#[cfg(test)] struct S {}
pub fn after_struct() -> String {
    std::env::var(\"Q\").unwrap()
}
#[cfg(test)] fn inline() -> u8 { 1 }
pub fn after_inline() -> String {
    std::env::var(\"R\").unwrap()
}
";
    let got: Vec<(usize, String)> = scan("sample.rs", one_liners)
        .into_iter()
        .map(|s| (s.line, s.func))
        .collect();
    assert_eq!(
        got,
        vec![
            (4, "after_helper".to_string()),
            (8, "after_struct".to_string()),
            (12, "after_inline".to_string()),
        ],
        "a one-line #[cfg(test)] item must not swallow the production item after it"
    );

    // The real tree: the allowlisted reads are seen and attributed.
    let real = measure();
    let listed = real.iter().filter(|s| allowed(s)).count();
    assert!(
        listed >= 15,
        "expected at least 15 allowlisted environment reads under src/, saw {listed}: \
         the scanner or its fn attribution has broken"
    );
    // ...and the test modules' DATABASE_URL reads (routes/claims.rs and
    // others) are cut, not attributed.
    assert!(
        !real
            .iter()
            .any(|s| s.file.starts_with("routes/") && s.text.contains("DATABASE_URL")),
        "a #[cfg(test)] module's DATABASE_URL read was scanned"
    );
}
