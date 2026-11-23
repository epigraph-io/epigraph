//! Ratchet: every environment variable a binary reads is documented
//! (backlog 649860a4, the lint half of e44193c7).
//!
//! An operator configures EpiGraph from the configuration reference
//! (`docs/deploy.md` section 3) and the other reader-facing docs. A variable
//! the code reads and no doc names is a switch nobody can find, and e44193c7
//! found 13 of them. The doc table that closed it does not stop the next one,
//! so this test scans every production source and fails on a variable named
//! in none of [`DOCS`].
//!
//! What counts as a read, in production code (comments and
//! `#[cfg(test)] mod` blocks or files excluded) under `crates/*/src` and
//! `services/*/src`:
//!
//! - `env::var("X")` and `env::var_os("X")`;
//! - an `env = "X"` argument: clap's `#[arg(env = "X")]` and the
//!   `belief_mode!` macro's `env = "X"`;
//! - `env::var(C)` or `env = path::C`, with `C` a `const C: &str = "X"`
//!   defined in a scanned source;
//! - any `const` whose name says it is a variable name (`ENV`, `ENV_*`,
//!   `*_ENV`, `*_ENV_*`) holding a literal: that is how the readers that go
//!   through a lookup closure (`from_lookup(|k| env::var(k).ok())`) name
//!   their variables.
//!
//! A read whose name is computed at run time cannot be resolved from the
//! text. Each file holding one is listed in [`DYNAMIC_READERS`] with where its
//! names come from, so a new one is a reviewed decision rather than a gap.
//! Build scripts are not scanned: their environment is Cargo's.
//!
//! A variable read only by a service under `services/<name>/` may instead be
//! documented in that service's own `README.md`; a standalone service ships
//! with its own runbook.
//!
//! Every allow-list entry must still be needed: an entry nothing reads, or a
//! dynamic-reader entry whose file no longer computes a name, fails.

#[allow(dead_code)] // `workspace_root`: this file finds the root itself.
#[path = "support/rust_sources.rs"]
mod rust_sources;

use rust_sources::{production_code, production_sources};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The reader-facing docs a variable may be documented in.
const DOCS: &[&str] = &[
    "README.md",
    "docs/deploy.md",
    "docs/intro/01-quickstart.md",
    "docs/tenancy.md",
];

/// The directory of the standalone services, each with its own README.
const SERVICES: &str = "services";

/// Variables production code reads that the operating system or the login
/// session sets, not EpiGraph's configuration: (name, reader and why).
const PLATFORM: &[(&str, &str)] = &[
    (
        "HOME",
        "atlas_naming::backend: the Claude CLI working directory's fallback base",
    ),
    (
        "XDG_RUNTIME_DIR",
        "atlas_naming::backend: the Claude CLI working directory's base",
    ),
];

/// Variables production code reads only for tests: (name, reader and why).
const TEST_ONLY: &[(&str, &str)] = &[(
    "EPIGRAPH_OPERATOR_TEST_CRASH_AT",
    "operator::backfill_markers::crash_point, a crash-injection hook compiled \
     into debug builds only, set by the resume tests",
)];

/// Files that read the environment through a name computed at run time:
/// (file, where the names come from).
const DYNAMIC_READERS: &[(&str, &str)] = &[
    (
        "crates/epigraph-api/src/oauth/providers/cloudflare_access.rs",
        "the `*_env` keys of providers.toml name the variables (docs/deploy.md step 7)",
    ),
    (
        "crates/epigraph-api/src/oauth/providers/config.rs",
        "the `*_env` keys of providers.toml name the variables (docs/deploy.md step 7)",
    ),
    (
        "crates/epigraph-api/src/oauth/providers/google.rs",
        "the `*_env` keys of providers.toml name the variables (docs/deploy.md step 7)",
    ),
    (
        "crates/epigraph-api/src/security/rate_limit.rs",
        "a `var` closure over the file's `*_ENV` constants",
    ),
    (
        "crates/epigraph-api/src/serving.rs",
        "a `var` closure over the file's `*_ENV` constants",
    ),
    (
        "crates/epigraph-cli/src/operator/client_scope.rs",
        "the OS user: SUDO_USER, USER, LOGNAME (platform variables)",
    ),
    (
        "crates/epigraph-engine/src/belief_modes.rs",
        "a lookup closure over each flag's `belief_mode!` `env = \"...\"`",
    ),
    (
        "crates/epigraph-mcp/src/tools/label_dedup.rs",
        "a lookup closure over the file's `*_ENV` constants",
    ),
    (
        "crates/epigraph-passkey/src/config.rs",
        "lookup closures over the file's `ENV_*` constants",
    ),
    (
        "services/explorer/src/config.rs",
        "a lookup closure over the file's `ENV_*` constants",
    ),
];

/// What the scan found.
#[derive(Debug, Default)]
struct Measured {
    /// Variable name -> the files that read it.
    names: BTreeMap<String, BTreeSet<String>>,
    /// File -> how many reads there compute their name at run time.
    dynamic: BTreeMap<String, usize>,
    /// (file, argument): a constant passed as a variable name that no
    /// scanned `const` defines.
    unresolved: Vec<(String, String)>,
}

/// The allow-lists [`findings`] checks against.
struct Registers<'a> {
    platform: &'a [(&'a str, &'a str)],
    test_only: &'a [(&'a str, &'a str)],
    dynamic: &'a [(&'a str, &'a str)],
}

const REGISTERS: Registers<'static> = Registers {
    platform: PLATFORM,
    test_only: TEST_ONLY,
    dynamic: DYNAMIC_READERS,
};

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// SCREAMING_CASE: the spelling of a constant.
fn is_screaming(s: &str) -> bool {
    !s.is_empty()
        && s.chars().any(|c| c.is_ascii_uppercase())
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// A constant name that says it holds a variable name.
fn is_env_name_const(name: &str) -> bool {
    name == "ENV" || name.starts_with("ENV_") || name.ends_with("_ENV") || name.contains("_ENV_")
}

/// What an argument naming a variable is.
#[derive(Debug, PartialEq)]
enum Arg {
    Literal(String),
    /// The last path segment of a SCREAMING_CASE constant reference.
    Const(String),
    Dynamic,
}

fn classify(arg: &str) -> Arg {
    let a = arg.trim().trim_start_matches('&').trim();
    if a.len() >= 2 && a.starts_with('"') && a.ends_with('"') {
        return Arg::Literal(a[1..a.len() - 1].to_string());
    }
    let is_path = !a.is_empty()
        && a.split("::")
            .all(|seg| !seg.is_empty() && seg.chars().all(is_ident_char));
    match a.rsplit("::").next() {
        Some(last) if is_path && is_screaming(last) => Arg::Const(last.to_string()),
        _ => Arg::Dynamic,
    }
}

/// The text between the `(` at `open` and its matching `)`, skipping string
/// literals.
fn call_argument(code: &str, open: usize) -> &str {
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for (k, c) in code[open..].char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &code[open + 1..open + k];
                }
            }
            _ => {}
        }
    }
    &code[open + 1..]
}

/// The arguments of every `env::var(…)` and `env::var_os(…)` call.
fn env_var_arguments(code: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for callee in ["env::var(", "env::var_os("] {
        let mut from = 0;
        while let Some(at) = code[from..].find(callee) {
            let start = from + at;
            from = start + callee.len();
            if code[..start].chars().next_back().is_some_and(is_ident_char) {
                continue;
            }
            out.push(call_argument(code, from - 1));
        }
    }
    out
}

/// The value of every `env = <value>` argument (`(` or `,` before `env`).
fn env_assignments(code: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find("env") {
        let start = from + at;
        from = start + 3;
        let before = code[..start].trim_end();
        if !(before.ends_with('(') || before.ends_with(',')) {
            continue;
        }
        let rest = code[from..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        if rest.starts_with('=') {
            continue;
        }
        let rest = rest.trim_start();
        let end = match rest.strip_prefix('"') {
            Some(inner) => inner.find('"').map_or(rest.len(), |k| k + 2),
            None => rest.find([',', ')', ']', '\n']).unwrap_or(rest.len()),
        };
        out.push(&rest[..end]);
    }
    out
}

/// Every `const NAME: &str = <value>;` (or `&'static str`): (name, value).
fn str_consts(code: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find("const ") {
        let start = from + at;
        from = start + "const ".len();
        if code[..start].chars().next_back().is_some_and(is_ident_char) {
            continue;
        }
        let rest = code[from..].trim_start();
        let name_len = rest.find(|c: char| !is_ident_char(c)).unwrap_or(rest.len());
        let (name, rest) = rest.split_at(name_len);
        let Some(rest) = rest.trim_start().strip_prefix(':') else {
            continue;
        };
        let Some(eq) = rest.find('=') else { continue };
        let ty: String = rest[..eq].split_whitespace().collect();
        if ty != "&str" && ty != "&'staticstr" {
            continue;
        }
        let value = &rest[eq + 1..];
        let value = value[..value.find(';').unwrap_or(value.len())].trim();
        out.push((name, value));
    }
    out
}

/// The files `#[cfg(test)] mod <name>;` declarations pull in, as path
/// prefixes: `<dir>/<name>.rs` and everything under `<dir>/<name>/`.
fn test_module_files(rel: &str, code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (dir, file) = rel.rsplit_once('/').unwrap_or(("", rel));
    let base = if matches!(file, "lib.rs" | "main.rs" | "mod.rs") {
        dir.to_string()
    } else {
        format!("{dir}/{}", file.trim_end_matches(".rs"))
    };
    let mut from = 0;
    while let Some(at) = code[from..].find("#[cfg(test)]") {
        from += at + "#[cfg(test)]".len();
        let mut rest = code[from..].trim_start();
        for vis in ["pub(crate) ", "pub(super) ", "pub "] {
            if let Some(r) = rest.strip_prefix(vis) {
                rest = r.trim_start();
            }
        }
        let Some(rest) = rest.strip_prefix("mod ") else {
            continue;
        };
        let rest = rest.trim_start();
        let len = rest.find(|c: char| !is_ident_char(c)).unwrap_or(rest.len());
        if rest[len..].trim_start().starts_with(';') {
            let name = &rest[..len];
            out.push(format!("{base}/{name}.rs"));
            out.push(format!("{base}/{name}/"));
        }
    }
    out
}

/// Scan `(repository-relative path, source)` pairs.
fn measure(sources: &[(String, String)]) -> Measured {
    let mut code: Vec<(String, String)> = sources
        .iter()
        .filter(|(rel, _)| !rel.ends_with("/build.rs") && rel != "build.rs")
        .map(|(rel, src)| (rel.clone(), production_code(src)))
        .collect();
    let test_files: Vec<String> = code
        .iter()
        .flat_map(|(rel, c)| test_module_files(rel, c))
        .collect();
    code.retain(|(rel, _)| {
        !test_files
            .iter()
            .any(|t| rel == t || (t.ends_with('/') && rel.starts_with(t.as_str())))
    });

    // Constants that hold a literal, and the names defined without one
    // (macro-built or aliases of another constant).
    let mut literal_consts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut other_consts: BTreeSet<String> = BTreeSet::new();
    let mut m = Measured::default();
    fn read(m: &mut Measured, name: &str, rel: &str) {
        m.names
            .entry(name.to_string())
            .or_default()
            .insert(rel.to_string());
    }
    for (rel, c) in &code {
        for (name, value) in str_consts(c) {
            match classify(value) {
                Arg::Literal(v) => {
                    if is_env_name_const(name) {
                        read(&mut m, &v, rel);
                    }
                    literal_consts
                        .entry(name.to_string())
                        .or_default()
                        .insert(v);
                }
                _ => {
                    other_consts.insert(name.to_string());
                }
            }
        }
    }
    for (rel, c) in &code {
        let calls = env_var_arguments(c).into_iter().map(|a| (a, true));
        let assigns = env_assignments(c).into_iter().map(|a| (a, false));
        for (arg, is_call) in calls.chain(assigns) {
            match classify(arg) {
                Arg::Literal(v) => read(&mut m, &v, rel),
                Arg::Const(k) => match literal_consts.get(&k) {
                    Some(values) => {
                        for v in values {
                            read(&mut m, v, rel);
                        }
                    }
                    None if other_consts.contains(&k) => {}
                    None => m.unresolved.push((rel.clone(), arg.trim().to_string())),
                },
                // `env = $env:literal` in a macro definition is not a read.
                Arg::Dynamic if is_call => *m.dynamic.entry(rel.clone()).or_default() += 1,
                Arg::Dynamic => {}
            }
        }
    }
    m
}

/// `word` appears in `text` with no identifier character on either side.
fn mentions(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        !text[..at].chars().next_back().is_some_and(is_ident_char)
            && !text[at + word.len()..]
                .chars()
                .next()
                .is_some_and(is_ident_char)
    })
}

/// The service directory (`services/<name>`) a file belongs to, if any.
fn service_of(rel: &str) -> Option<String> {
    let rest = rel.strip_prefix(SERVICES)?.strip_prefix('/')?;
    Some(format!("{SERVICES}/{}", rest.split('/').next()?))
}

/// Everything wrong with `m`: undocumented variables, unresolved
/// constants, unregistered dynamic readers and stale register entries.
/// `docs` is the text of [`DOCS`]; `service_docs` maps `services/<name>` to
/// that service's README.
fn findings(
    m: &Measured,
    docs: &str,
    service_docs: &BTreeMap<String, String>,
    reg: &Registers,
) -> Vec<String> {
    let mut out = Vec::new();
    let excused: BTreeSet<&str> = reg
        .platform
        .iter()
        .chain(reg.test_only)
        .map(|(n, _)| *n)
        .collect();
    for (name, files) in &m.names {
        if excused.contains(name.as_str()) || mentions(docs, name) {
            continue;
        }
        // A service's README counts only when that service is the one reader.
        let services: BTreeSet<Option<String>> = files.iter().map(|f| service_of(f)).collect();
        let only_service = match services.iter().collect::<Vec<_>>().as_slice() {
            [Some(svc)] => Some(svc.clone()),
            _ => None,
        };
        if only_service
            .and_then(|svc| service_docs.get(&svc))
            .is_some_and(|d| mentions(d, name))
        {
            continue;
        }
        out.push(format!(
            "{name} (read by {}) is in none of {}: document it in the configuration \
             reference (docs/deploy.md section 3)",
            files.iter().cloned().collect::<Vec<_>>().join(", "),
            DOCS.join(", ")
        ));
    }
    for (rel, arg) in &m.unresolved {
        out.push(format!(
            "{rel}: `{arg}` names a variable through a constant no scanned `const` defines"
        ));
    }
    let registered: BTreeSet<&str> = reg.dynamic.iter().map(|(f, _)| *f).collect();
    for (rel, n) in &m.dynamic {
        if !registered.contains(rel.as_str()) {
            out.push(format!(
                "{rel}: {n} environment read(s) with a name computed at run time; pass a \
                 literal or a `const`, or list the file in DYNAMIC_READERS with where \
                 its names come from (and make sure those are documented)"
            ));
        }
    }
    for f in &registered {
        if !m.dynamic.contains_key(*f) {
            out.push(format!(
                "{f} is listed in DYNAMIC_READERS but computes no variable name: remove it"
            ));
        }
    }
    for (n, _) in reg.platform.iter().chain(reg.test_only) {
        if !m.names.contains_key(*n) {
            out.push(format!(
                "{n} is allow-listed but no production code reads it: remove it"
            ));
        }
    }
    out
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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

/// `crates/*/src` (and build scripts, which [`measure`] skips) plus
/// `services/*/src`, and each service's README.
fn tree() -> (Vec<(String, String)>, BTreeMap<String, String>) {
    let root = repo_root().canonicalize().expect("repository root");
    let mut sources = production_sources(&root);
    let mut service_docs = BTreeMap::new();
    let services = root.join(SERVICES);
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&services)
        .unwrap_or_else(|e| panic!("read {}: {e}", services.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        let name = format!(
            "{SERVICES}/{}",
            dir.file_name().expect("a name").to_string_lossy()
        );
        if let Ok(readme) = std::fs::read_to_string(dir.join("README.md")) {
            service_docs.insert(name, readme);
        }
        let mut files = Vec::new();
        rs_files(&dir.join("src"), &mut files);
        files.sort();
        for p in files {
            let rel = p
                .strip_prefix(&root)
                .expect("under the root")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&p).expect("read source");
            sources.push((rel, src));
        }
    }
    (sources, service_docs)
}

fn docs_text() -> String {
    let root = repo_root();
    DOCS.iter()
        .map(|d| std::fs::read_to_string(root.join(d)).unwrap_or_else(|e| panic!("read {d}: {e}")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_environment_variable_the_code_reads_is_documented() {
    let (sources, service_docs) = tree();
    let m = measure(&sources);

    // Calibration: each kind of read was found in the real tree, so an empty
    // finding list means "documented", not "nothing was scanned".
    for (name, how) in [
        ("DATABASE_URL", "an env::var literal"),
        ("RECALL_EVENTS_RETENTION_DAYS", "a clap env literal"),
        ("EPIGRAPH_ATOM_FOLD", "a belief_mode! env literal"),
        ("EPIGRAPH_RUN_TOKENS", "a constant passed to env::var"),
        (
            "EPIGRAPH_WEBAUTHN_RP_ID",
            "an ENV_* constant behind a lookup closure",
        ),
        ("EPIGRAPH_EXPLORER_PORT", "a service's ENV_* constant"),
    ] {
        assert!(
            m.names.contains_key(name),
            "the scan missed {name} ({how}); it found {:?}",
            m.names.keys().collect::<Vec<_>>()
        );
    }
    assert!(m.names.len() > 50, "only {} names found", m.names.len());
    // A file declared `#[cfg(test)] mod tests;` is test code.
    assert!(
        !m.names.contains_key("ATLAS_CONTRACT_BLESS"),
        "a #[cfg(test)] module file was scanned as production code"
    );

    let f = findings(&m, &docs_text(), &service_docs, &REGISTERS);
    assert!(f.is_empty(), "{} finding(s):\n{}", f.len(), f.join("\n"));
}

// --- the rules, on synthetic sources --------------------------------------

fn src(files: &[(&str, &str)]) -> Vec<(String, String)> {
    files
        .iter()
        .map(|(p, s)| (p.to_string(), s.to_string()))
        .collect()
}

const NO_REGISTERS: Registers<'static> = Registers {
    platform: &[],
    test_only: &[],
    dynamic: &[],
};

fn names(m: &Measured) -> Vec<&str> {
    m.names.keys().map(String::as_str).collect()
}

#[test]
fn each_kind_of_read_is_found() {
    let m = measure(&src(&[
        (
            "crates/a/src/lib.rs",
            r#"
            const KEY_FILE: &str = "A_CONST_PASSED";
            pub const PORT_ENV: &str = "A_CONVENTION";
            const NOT_A_NAME: &str = "NOT_READ";
            fn f() {
                let _ = std::env::var("A_LITERAL");
                let _ = env::var_os("A_VAR_OS");
                let _ = std::env::var(KEY_FILE);
                // let _ = std::env::var("IN_A_COMMENT");
                let _ = option_env!("COMPILE_TIME");
                let env = "NOT_AN_ATTRIBUTE";
            }
            #[derive(Parser)]
            struct Cli {
                #[arg(long, env = "A_CLAP", hide_env_values = true)]
                a: String,
                #[arg(long, env = crate::B_CONST)]
                b: String,
            }
            "#,
        ),
        (
            "crates/b/src/lib.rs",
            r#"pub const B_CONST: &'static str = "B_CLAP_CONST";"#,
        ),
    ]));
    assert_eq!(
        names(&m),
        [
            "A_CLAP",
            "A_CONST_PASSED",
            "A_CONVENTION",
            "A_LITERAL",
            "A_VAR_OS",
            "B_CLAP_CONST"
        ]
    );
    assert!(m.dynamic.is_empty() && m.unresolved.is_empty(), "{m:?}");
}

#[test]
fn test_code_and_build_scripts_are_not_production_reads() {
    let m = measure(&src(&[
        (
            "crates/a/src/lib.rs",
            "#[cfg(test)]\nmod tests;\n#[cfg(test)]\nmod inline { fn t() { std::env::var(\"INLINE\"); } }\n",
        ),
        ("crates/a/src/tests.rs", "fn t() { std::env::var(\"TEST_FILE\"); }"),
        ("crates/a/src/routes/mod.rs", "#[cfg(test)]\nmod neg;\n"),
        ("crates/a/src/routes/neg.rs", "fn t() { std::env::var(\"NEG\"); }"),
        ("crates/a/src/routes/other.rs", "fn p() { std::env::var(\"PROD\"); }"),
        ("crates/a/build.rs", "fn main() { std::env::var(\"OUT_DIR\"); }"),
    ]));
    assert_eq!(names(&m), ["PROD"]);
}

#[test]
fn an_undocumented_variable_fails_and_a_documented_one_passes() {
    let m = measure(&src(&[(
        "crates/a/src/lib.rs",
        r#"fn f() { std::env::var("EPIGRAPH_DOCUMENTED"); std::env::var("EPIGRAPH_NEW"); }"#,
    )]));
    let docs = "| `EPIGRAPH_DOCUMENTED` | ... |\nEPIGRAPH_NEWER is a different word";
    let f = findings(&m, docs, &BTreeMap::new(), &NO_REGISTERS);
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(
        f[0].starts_with("EPIGRAPH_NEW (read by crates/a/src/lib.rs)"),
        "{f:?}"
    );
}

#[test]
fn a_service_readme_documents_only_that_services_variables() {
    let m = measure(&src(&[
        (
            "services/svc/src/config.rs",
            r#"const ENV_PORT: &str = "SVC_PORT"; const ENV_SHARED: &str = "SHARED";"#,
        ),
        (
            "crates/a/src/lib.rs",
            r#"fn f() { std::env::var("SHARED"); }"#,
        ),
    ]));
    let readme = BTreeMap::from([(
        "services/svc".to_string(),
        "SVC_PORT and SHARED".to_string(),
    )]);
    let f = findings(&m, "", &readme, &NO_REGISTERS);
    // SHARED is also read by a crate, so the service's README is not enough.
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f[0].starts_with("SHARED "), "{f:?}");
}

#[test]
fn a_computed_name_needs_a_register_entry_and_an_unknown_constant_fails() {
    let m = measure(&src(&[(
        "crates/a/src/lib.rs",
        "fn f(k: &str) { std::env::var(k); std::env::var(other::MISSING_CONST); }",
    )]));
    assert_eq!(m.dynamic.get("crates/a/src/lib.rs"), Some(&1));
    let f = findings(&m, "", &BTreeMap::new(), &NO_REGISTERS);
    assert_eq!(f.len(), 2, "{f:?}");
    assert!(
        f.iter().any(|x| x.contains("computed at run time")),
        "{f:?}"
    );
    assert!(
        f.iter().any(|x| x.contains("`other::MISSING_CONST`")),
        "{f:?}"
    );

    let reg = Registers {
        dynamic: &[("crates/a/src/lib.rs", "why")],
        ..NO_REGISTERS
    };
    let f = findings(&m, "", &BTreeMap::new(), &reg);
    assert_eq!(f.len(), 1, "{f:?}");
}

#[test]
fn a_stale_register_entry_fails() {
    let m = measure(&src(&[("crates/a/src/lib.rs", "fn f() {}")]));
    let reg = Registers {
        platform: &[("HOME", "why")],
        test_only: &[("A_TEST_HOOK", "why")],
        dynamic: &[("crates/a/src/lib.rs", "why")],
    };
    let f = findings(&m, "", &BTreeMap::new(), &reg);
    assert_eq!(f.len(), 3, "{f:?}");
}

#[test]
fn an_allow_listed_variable_needs_no_doc() {
    let m = measure(&src(&[(
        "crates/a/src/lib.rs",
        r#"fn f() { std::env::var_os("HOME"); std::env::var("A_TEST_HOOK"); }"#,
    )]));
    let reg = Registers {
        platform: &[("HOME", "why")],
        test_only: &[("A_TEST_HOOK", "why")],
        dynamic: &[],
    };
    assert_eq!(
        findings(&m, "", &BTreeMap::new(), &reg),
        Vec::<String>::new()
    );
    assert_eq!(findings(&m, "", &BTreeMap::new(), &NO_REGISTERS).len(), 2);
}
