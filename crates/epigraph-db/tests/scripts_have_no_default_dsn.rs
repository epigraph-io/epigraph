//! The operator scripts carry no database credentials and have no default database.
//!
//! Deferred-commitment screen key `script-hardcoded-prod-dsn` (PR-15
//! `explicitly_not_done` item 3 in `docs/tenancy/progress.json`). Twenty-one
//! Python files under `scripts/` fell back to a credentialed DSN for the live
//! `epigraph` database whenever the environment named none. That was four role and
//! password pairs, the admin role's among them, in a pushed repository. Worse, it
//! meant a forgotten `export` silently ran a writing script against production.
//! PR-15 added `MAINTENANCE_DATABASE_URL` ahead of those defaults and deliberately
//! left the defaults in place. They are gone now, and these two rules keep them
//! gone:
//!
//! 1. **No credential literal anywhere under `scripts/`.** A `postgres://` or
//!    `postgresql://` URL whose user-info carries a password is a finding unless
//!    the password is a placeholder: a shell expansion (`$VAR`, `${VAR}`), an
//!    angle-bracket slot (`<...>`), `...`, or the literal words `PASS` /
//!    `PASSWORD`. Every file type is scanned, not only `.py`, because a usage
//!    line in a shell script or README leaks a password just as well.
//! 2. **Every script that opens a driver connection routes its DSN through
//!    `require_dsn(`.** Removing the literal is not enough on its own. Handing
//!    `None` or `""` to psycopg2 does not raise. libpq falls back to the PG*
//!    variables, `~/.pgpass`, the local socket and a database named after the OS
//!    user, which can be a local `epigraph`. `scripts/maintenance_dsn.py::require_dsn`
//!    is the one place that turns "no DSN" into an exit.
//!
//! # Known limits, so nobody over-claims
//!
//! * Rule 2 is per-FILE and substring-based, like the Python half of
//!   `no_unmaintained_dsn.rs`. It proves the file calls `require_dsn(`
//!   somewhere, not that every connect site is downstream of it. The behavioural
//!   proof is `scripts/tests/test_no_default_database.py`. It runs every
//!   connecting script with the driver stubbed and no DSN in the environment, and
//!   asserts each one refuses before it reaches connect. CI has no Python step,
//!   so that suite is run by hand, with Python 3.11 or newer.
//! * Rule 1 sees URL-form DSNs only. A key=value DSN (`password=...`) is not
//!   matched. None exists under `scripts/` today; add a spelling here before
//!   introducing one.
//! * The scope is `scripts/`. Several crate test files and historical plan
//!   documents also spell DSNs. The admin, read-only and dev role passwords are
//!   redacted from them in the same series, but they are not held here.

use std::path::{Path, PathBuf};

const SCRIPTS: &str = "scripts";

/// The connect spelling rule 2 keys on, and the helper it requires.
const DRIVER_CONNECT: &str = "psycopg2.connect(";
const REQUIRE_DSN: &str = "require_dsn(";

/// Password spellings that are placeholders, not credentials.
const PLACEHOLDER_PASSWORDS: &[&str] = &["PASS", "PASSWORD", "..."];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/epigraph-db has two ancestors")
        .to_path_buf()
}

/// Every regular file under `root`, skipping bytecode caches.
fn collect_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "__pycache__") {
                continue;
            }
            collect_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_placeholder(password: &str) -> bool {
    password.starts_with('$')
        || password.starts_with('<')
        || PLACEHOLDER_PASSWORDS.contains(&password)
}

/// The credentialed DSNs on one line, as `user:password@` fragments.
///
/// The authority is everything after the scheme up to the first `/`,
/// whitespace, quote or backslash. The user-info is what precedes its LAST `@`,
/// and the password is what follows the user-info's first `:`.
fn credentialed_dsns(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    // Neither scheme is a substring of the other (`postgresql://` never contains
    // `postgres://`), so one URL is never counted twice.
    for scheme in ["postgresql://", "postgres://"] {
        let mut rest = line;
        while let Some(at) = rest.find(scheme) {
            let after = &rest[at + scheme.len()..];
            let end = after
                .find(|c: char| c == '/' || c.is_whitespace() || "\"'`\\".contains(c))
                .unwrap_or(after.len());
            let authority = &after[..end];
            if let Some(userinfo_end) = authority.rfind('@') {
                let userinfo = &authority[..userinfo_end];
                if let Some((user, password)) = userinfo.split_once(':') {
                    if !password.is_empty() && !is_placeholder(password) {
                        found.push(format!("{user}:{password}@"));
                    }
                }
            }
            rest = &after[end..];
        }
    }
    found
}

/// Lines that are not whole-line `#` comments. Docstrings count as code, which
/// errs toward reporting a connect site rather than missing one.
fn python_code_lines(src: &str) -> impl Iterator<Item = &str> {
    src.lines().filter(|l| !l.trim_start().starts_with('#'))
}

fn script_files() -> (PathBuf, Vec<PathBuf>) {
    let root = repo_root();
    let mut files = Vec::new();
    collect_files(&root.join(SCRIPTS), &mut files);
    files.sort();
    assert!(
        files.len() > 30,
        "expected >30 files under scripts/; found {}. A silently-empty scan is how \
         this lint would certify a tree it never read.",
        files.len()
    );
    (root, files)
}

#[test]
fn no_file_under_scripts_carries_a_database_credential() {
    let (root, files) = script_files();
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in &files {
        // Binary files (none are tracked today) are skipped, not failed.
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        scanned += 1;
        for (i, line) in src.lines().enumerate() {
            for hit in credentialed_dsns(line) {
                findings.push(format!("  {}:{}  {hit}", rel(&root, path), i + 1));
            }
        }
    }
    assert!(
        scanned > 30,
        "read only {scanned} text files under scripts/"
    );
    assert!(
        findings.is_empty(),
        "{} credentialed DSN(s) under scripts/. A script must not carry a database \
         password, and must not have a default database at all. Read the DSN from \
         the environment or a flag and pass it through `require_dsn`. In a usage \
         line, write the password as PASS, $VAR or <...>:\n{}",
        findings.len(),
        findings.join("\n")
    );
}

#[test]
fn every_script_that_connects_refuses_without_a_dsn() {
    let (root, files) = script_files();
    let mut connecting = 0usize;
    let mut findings = Vec::new();
    for path in files
        .iter()
        .filter(|p| p.extension().is_some_and(|x| x == "py"))
    {
        let src = std::fs::read_to_string(path).expect("read script");
        if !python_code_lines(&src).any(|l| l.contains(DRIVER_CONNECT)) {
            continue;
        }
        connecting += 1;
        if !python_code_lines(&src).any(|l| l.contains(REQUIRE_DSN)) {
            findings.push(format!("  {}", rel(&root, path)));
        }
    }
    assert!(
        connecting > 20,
        "expected >20 scripts that open a connection; found {connecting}"
    );
    assert!(
        findings.is_empty(),
        "{} script(s) open a driver connection without passing the DSN through \
         `require_dsn` (scripts/maintenance_dsn.py). psycopg2 given None or \"\" does \
         not raise: libpq fills the gap from PG* variables, ~/.pgpass and the OS user \
         name, which can silently be a local `epigraph`:\n{}",
        findings.len(),
        findings.join("\n")
    );
}

/// Calibration: the scanner fires on every shape it claims to, and on nothing
/// it claims to allow. Without this, a green run means "found nothing" rather
/// than "there is nothing".
#[test]
fn the_credential_scanner_is_not_vacuous() {
    for (line, want) in [
        (
            r#"DEFAULT_DATABASE_URL = "postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph""#,
            "epigraph_admin:epigraph_admin@",
        ),
        (
            "    \"postgres://epigraph:epigraph@127.0.0.1:5432/epigraph\"",
            "epigraph:epigraph@",
        ),
        (
            "default='postgresql://epigraph_ro:epigraph_ro@db:5432'",
            "epigraph_ro:epigraph_ro@",
        ),
        (
            "#   DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/<testdb> ./x.sh",
            "epigraph:epigraph@",
        ),
        (
            "psql postgres://u:s3cr3t@host/db -c 'select 1'",
            "u:s3cr3t@",
        ),
    ] {
        assert_eq!(
            credentialed_dsns(line),
            vec![want.to_string()],
            "the scanner must report exactly one credential in: {line}"
        );
    }
    for allowed in [
        "    DATABASE_URL=postgres://USER:PASS@HOST:5432/DB \\",
        "    DATABASE_URL=postgres://epigraph_ro:PASS@HOST:5432/DB \\",
        "    DATABASE_URL=postgres://... python3 scripts/audit_mixed_bbas.py",
        r#"URL="postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}""#,
        "postgres://someone@127.0.0.1:1/scratch",
        "postgres://user:<password>@host/db",
        "if parts.scheme not in (\"postgres\", \"postgresql\"):",
    ] {
        assert!(
            credentialed_dsns(allowed).is_empty(),
            "a placeholder must not be a finding: {allowed}"
        );
    }
}

#[test]
fn rule_two_reads_code_not_comments() {
    let commented = "# conn = psycopg2.connect(url)\n";
    assert!(!python_code_lines(commented).any(|l| l.contains(DRIVER_CONNECT)));
    let real = "    conn = psycopg2.connect(args.database_url)\n";
    assert!(python_code_lines(real).any(|l| l.contains(DRIVER_CONNECT)));
    // A comment naming the helper is not a call to it.
    let described = "# see require_dsn(\nconn = psycopg2.connect(url)\n";
    assert!(!python_code_lines(described).any(|l| l.contains(REQUIRE_DSN)));
}
