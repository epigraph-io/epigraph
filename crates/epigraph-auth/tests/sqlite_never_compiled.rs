//! Ratchet for the accepted RUSTSEC-2026-0459 (`libsqlite3-sys` < 0.39, whose
//! bundled SQLite can return uninitialized page-cache memory on a crafted
//! `-wal` file). `.cargo/audit.toml` ignores that advisory (operator ruling,
//! 2026-11-10) on one condition: SQLite is NEVER COMPILED into this workspace.
//! `libsqlite3-sys` is locked, not activated, as an optional dependency of
//! `sqlx-sqlite`, which no crate enables; enabling it adds further lock
//! entries. So a `--locked` build already refuses an SQLite enable that has
//! not been re-locked, and this test catches one that has.
//!
//! Once the advisory is ignored, `cargo audit` says nothing if that condition
//! breaks, and the audit CI job is advisory anyway. This test is the blocking
//! check. It fails when:
//!
//! - any workspace manifest (the root and every `workspace.members` entry)
//!   depends on `rusqlite`, `libsqlite3-sys` or `sqlx-sqlite`, under any
//!   dependency table (normal, dev, build, `[target.*]`, or
//!   `[workspace.dependencies]`), optional or not, renamed or not;
//! - any manifest asks an `sqlx*` dependency for a feature that compiles
//!   SQLite: one whose name contains `sqlite` (`sqlite`, `sqlite-unbundled`,
//!   `sqlite-preupdate-hook`, `_sqlite`) or `all-databases`, either on the
//!   dependency itself or from a `[features]` entry (`sqlx/sqlite`,
//!   `sqlx?/sqlite`, or `dep:` on one of the three crates);
//! - `Cargo.lock` gains `rusqlite`, or a package other than `sqlx-sqlite`
//!   depending on `libsqlite3-sys`, or one other than `sqlx` /
//!   `sqlx-macros-core` depending on `sqlx-sqlite`. That catches a third-party
//!   crate that starts pulling SQLite in on its own.
//!
//! Why a manifest scan and not `cargo metadata` resolved features: `cargo
//! metadata` reads the manifest of every package in its resolve, including
//! locked packages no build compiles, and without `--offline` a blocking test
//! would depend on the network. `cargo metadata --all-features --locked
//! --offline` exits 101 even on a long-lived cache: it wants crates built only
//! for other targets. With `--filter-platform <host>` it can run offline on
//! such a cache, but on a fresh `CARGO_HOME` after building this crate it exits
//! 101 ("failed to download"). Its resolve still holds the locked but inactive
//! `sqlx-sqlite` and `libsqlite3-sys`, which no build downloads, so a CI runner
//! whose cache misses would fail the check for a reason unrelated to SQLite.
//!
//! Blind spot: a third-party crate that enables `sqlx/sqlite` through its OWN
//! manifest is invisible to both scans (the lockfile records no features).
//! When a dependency that itself depends on sqlx is added or bumped, re-run
//! `cargo tree -i libsqlite3-sys -e normal --all-features --target all
//! --workspace`, which must print nothing.

use std::path::{Path, PathBuf};

use toml::Value;

/// Crates whose presence in any dependency table means SQLite is compiled
/// (or is one feature away from it).
const SQLITE_CRATES: &[&str] = &["rusqlite", "libsqlite3-sys", "sqlx-sqlite"];

/// The dependency tables a manifest can hold, at the top level or under
/// `[target.<cfg>]`.
const DEP_TABLES: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Whether an `sqlx*` feature compiles SQLite (sqlx 0.8.6's feature table:
/// `sqlite`, `sqlite-unbundled` and `sqlite-preupdate-hook` enable
/// `sqlx-sqlite`, and `all-databases` enables `sqlite`).
fn sqlite_feature(feature: &str) -> bool {
    feature.contains("sqlite") || feature == "all-databases"
}

fn is_sqlx(package: &str) -> bool {
    package == "sqlx" || package.starts_with("sqlx-")
}

/// Every dependency table in `manifest`, as (where, table).
fn dependency_tables(manifest: &Value) -> Vec<(String, &toml::Table)> {
    let mut tables = Vec::new();
    for kind in DEP_TABLES {
        if let Some(t) = manifest.get(*kind).and_then(Value::as_table) {
            tables.push(((*kind).to_string(), t));
        }
    }
    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for (cfg, target) in targets {
            for kind in DEP_TABLES {
                if let Some(t) = target.get(*kind).and_then(Value::as_table) {
                    tables.push((format!("target.{cfg}.{kind}"), t));
                }
            }
        }
    }
    if let Some(t) = manifest
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(Value::as_table)
    {
        tables.push(("workspace.dependencies".to_string(), t));
    }
    tables
}

/// The package a dependency entry names: its `package =` rename, else its key.
fn package_of<'a>(key: &'a str, spec: &'a Value) -> &'a str {
    spec.get("package").and_then(Value::as_str).unwrap_or(key)
}

/// Every way `manifest` (read from `label`) compiles SQLite, one line each.
fn sqlite_violations(label: &str, manifest: &str) -> Vec<String> {
    let manifest: Value =
        toml::from_str(manifest).unwrap_or_else(|e| panic!("parse {label} as TOML: {e}"));
    let mut violations = Vec::new();
    // dependency key -> package, for resolving `<key>/<feature>` strings below.
    let mut key_to_package = std::collections::BTreeMap::new();

    for (table_name, table) in dependency_tables(&manifest) {
        for (key, spec) in table {
            let package = package_of(key, spec);
            key_to_package.insert(key.clone(), package.to_string());
            if SQLITE_CRATES.contains(&package) {
                violations.push(format!("{label} [{table_name}] depends on {package}"));
            }
            if is_sqlx(package) {
                for feature in spec
                    .get("features")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .filter(|f| sqlite_feature(f))
                {
                    violations.push(format!(
                        "{label} [{table_name}] enables {package}'s `{feature}` feature"
                    ));
                }
            }
        }
    }

    if let Some(features) = manifest.get("features").and_then(Value::as_table) {
        for (name, implied) in features {
            for entry in implied
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if let Some(dep) = entry.strip_prefix("dep:") {
                    let package = key_to_package.get(dep).map_or(dep, String::as_str);
                    if SQLITE_CRATES.contains(&package) {
                        violations.push(format!(
                            "{label} [features] {name} enables `{entry}` ({package})"
                        ));
                    }
                } else if let Some((dep, feature)) = entry.split_once('/') {
                    let dep = dep.trim_end_matches('?');
                    let package = key_to_package.get(dep).map_or(dep, String::as_str);
                    if is_sqlx(package) && sqlite_feature(feature) {
                        violations.push(format!(
                            "{label} [features] {name} enables `{entry}` ({package})"
                        ));
                    }
                }
            }
        }
    }
    violations
}

/// The `name` of every `[[package]]` in `lock` whose `dependencies` include
/// `target` (an entry is `"name"` or `"name <version>"`).
fn lock_dependants(lock: &str, target: &str) -> Vec<String> {
    let mut dependants = Vec::new();
    for entry in lock.split("[[package]]").skip(1) {
        let name = entry
            .lines()
            .find_map(|l| l.trim().strip_prefix("name = \""))
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("lockfile entry without a name: {entry}"));
        let depends = entry
            .split_once("dependencies = [")
            .map(|(_, rest)| rest.split(']').next().unwrap_or(""))
            .unwrap_or("")
            .split(',')
            .filter_map(|d| d.trim().strip_prefix('"')?.strip_suffix('"'))
            .any(|d| d.split(' ').next() == Some(target));
        if depends {
            dependants.push(name.to_string());
        }
    }
    dependants
}

/// Every way `lock` shows SQLite being pulled in other than the one optional
/// sqlx path this workspace already locks.
fn lock_violations(lock: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if lock.lines().any(|l| l.trim() == "name = \"rusqlite\"") {
        violations.push("Cargo.lock contains rusqlite".to_string());
    }
    for (target, allowed) in [
        ("libsqlite3-sys", &["sqlx-sqlite"][..]),
        ("sqlx-sqlite", &["sqlx", "sqlx-macros-core"][..]),
    ] {
        for dependant in lock_dependants(lock, target) {
            if !allowed.contains(&dependant.as_str()) {
                violations.push(format!("Cargo.lock: {dependant} depends on {target}"));
            }
        }
    }
    violations
}

/// The root manifest and every `workspace.members` manifest, as (label, text).
fn workspace_manifests() -> Vec<(String, String)> {
    let root = workspace_root();
    let root_text = read(&root.join("Cargo.toml"));
    let root_toml: Value = toml::from_str(&root_text).expect("parse the root Cargo.toml");
    let members: Vec<&str> = root_toml
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(Value::as_array)
        .expect("the root Cargo.toml lists workspace.members")
        .iter()
        .map(|m| m.as_str().expect("a workspace member is a string"))
        .collect();
    assert!(
        members.iter().all(|m| !m.contains('*')),
        "workspace.members uses a glob; expand it here so no member is skipped"
    );
    let mut manifests = vec![("Cargo.toml".to_string(), root_text)];
    for member in &members {
        let label = format!("{member}/Cargo.toml");
        manifests.push((label.clone(), read(&root.join(&label))));
    }
    assert_eq!(manifests.len(), members.len() + 1);
    manifests
}

#[test]
fn no_workspace_manifest_compiles_sqlite() {
    let manifests = workspace_manifests();
    // Non-vacuity: the scan must see the workspace's own sqlx line, with the
    // postgres feature, or it is reading the wrong files.
    let root: Value = toml::from_str(&manifests[0].1).unwrap();
    let sqlx_features: Vec<&str> = root["workspace"]["dependencies"]["sqlx"]["features"]
        .as_array()
        .expect("workspace.dependencies.sqlx has a features list")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(sqlx_features.contains(&"postgres"), "{sqlx_features:?}");

    let violations: Vec<String> = manifests
        .iter()
        .flat_map(|(label, text)| sqlite_violations(label, text))
        .collect();
    assert!(
        violations.is_empty(),
        "RUSTSEC-2026-0459 is ignored in .cargo/audit.toml only while SQLite is never \
         compiled; remove the ignore entry (and re-triage the advisory) before adding: {}",
        violations.join("; ")
    );
}

#[test]
fn lockfile_pulls_sqlite_only_through_the_optional_sqlx_path() {
    let lock = read(&workspace_root().join("Cargo.lock"));
    // Non-vacuity: the dependant scan must find the known optional edges.
    assert_eq!(lock_dependants(&lock, "libsqlite3-sys"), ["sqlx-sqlite"]);
    let violations = lock_violations(&lock);
    assert!(
        violations.is_empty(),
        "RUSTSEC-2026-0459 is ignored in .cargo/audit.toml only while SQLite is never \
         compiled; a new path to it needs that entry re-triaged: {}",
        violations.join("; ")
    );
}

// ── The scan itself, on synthetic manifests ───────────────────────────────

const CLEAN: &str = r#"
[package]
name = "x"

[dependencies]
sqlx = { workspace = true }
serde = "1"

[features]
db = ["dep:sqlx", "sqlx/postgres"]
"#;

#[test]
fn a_postgres_only_manifest_passes() {
    assert_eq!(sqlite_violations("x", CLEAN), Vec::<String>::new());
}

#[test]
fn each_way_of_compiling_sqlite_is_caught() {
    let cases: &[(&str, &str)] = &[
        (
            "direct feature",
            r#"[dependencies]
sqlx = { version = "0.8", features = ["postgres", "sqlite"] }"#,
        ),
        (
            "inherited dep, added feature",
            r#"[dependencies]
sqlx = { workspace = true, features = ["sqlite-unbundled"] }"#,
        ),
        (
            "workspace.dependencies",
            r#"[workspace.dependencies]
sqlx = { version = "0.8", default-features = false, features = ["all-databases"] }"#,
        ),
        (
            "sqlx-macros feature",
            r#"[dev-dependencies]
sqlx-macros = { version = "0.8", features = ["sqlite"] }"#,
        ),
        (
            "[features] strong",
            r#"[dependencies]
sqlx = { workspace = true }
[features]
local = ["sqlx/sqlite"]"#,
        ),
        (
            "[features] weak",
            r#"[dependencies]
sqlx = { workspace = true, optional = true }
[features]
local = ["sqlx?/sqlite-preupdate-hook"]"#,
        ),
        (
            "renamed sqlx",
            r#"[dependencies]
db = { package = "sqlx", version = "0.8" }
[features]
local = ["db/sqlite"]"#,
        ),
        (
            "rusqlite under a target dev table",
            r#"[target.'cfg(unix)'.dev-dependencies]
rusqlite = "0.32""#,
        ),
        (
            "renamed libsqlite3-sys, optional",
            r#"[build-dependencies]
sq = { package = "libsqlite3-sys", version = "0.30", optional = true }"#,
        ),
    ];
    for (case, manifest) in cases {
        assert!(
            !sqlite_violations(case, manifest).is_empty(),
            "{case}: not caught:\n{manifest}"
        );
    }
}

/// A synthetic lockfile with one `[[package]]` per (name, dependencies).
fn synthetic_lock(packages: &[(&str, &[&str])]) -> String {
    let mut lock = String::from("version = 4\n");
    for (name, deps) in packages {
        lock.push_str(&format!(
            "\n[[package]]\nname = \"{name}\"\nversion = \"1.0.0\"\n"
        ));
        if !deps.is_empty() {
            lock.push_str("dependencies = [\n");
            for d in *deps {
                lock.push_str(&format!(" \"{d}\",\n"));
            }
            lock.push_str("]\n");
        }
    }
    lock
}

#[test]
fn the_lockfile_scan_allows_the_optional_sqlx_path_and_nothing_else() {
    let base: &[(&str, &[&str])] = &[
        ("sqlx", &["sqlx-core", "sqlx-sqlite"]),
        ("sqlx-macros-core", &["sqlx-sqlite"]),
        ("sqlx-sqlite", &["libsqlite3-sys"]),
        ("libsqlite3-sys", &["pkg-config"]),
    ];
    assert_eq!(lock_violations(&synthetic_lock(base)), Vec::<String>::new());

    let mut with_third_party = base.to_vec();
    with_third_party.push(("some-cache", &["libsqlite3-sys 0.30.1"]));
    assert_eq!(
        lock_violations(&synthetic_lock(&with_third_party)),
        ["Cargo.lock: some-cache depends on libsqlite3-sys"]
    );

    let mut with_rusqlite = base.to_vec();
    with_rusqlite.push(("rusqlite", &["libsqlite3-sys"]));
    assert_eq!(
        lock_violations(&synthetic_lock(&with_rusqlite)),
        [
            "Cargo.lock contains rusqlite",
            "Cargo.lock: rusqlite depends on libsqlite3-sys"
        ]
    );
}
