//! Ratchet for the crate-layering rule (backlog 6ffcb138, 93e01896): the three
//! front ends, `epigraph-api` (HTTP), `epigraph-mcp` (MCP) and `epigraph-cli`
//! (operator binaries), are peers over a shared service layer
//! (`epigraph-service`) and must not grow new dependencies on each other.
//!
//! Today they are not peers yet. The API's `db` feature pulls in the MCP
//! crate and its `genai` feature the CLI crate, and the CLI depends on the MCP
//! crate (and, for its tests, on the API). The 93e01896 wave moves the shared
//! operations into `epigraph-service` one module at a time; each step lowers
//! the lists below, and its last step (2c0d2ea9) takes them to zero apart from
//! a named test-only exception. Until then this test holds the line: it fails
//! on anything the lists do not already allow, so the coupling can only shrink.
//!
//! It fails when:
//!
//! 1. **A new dependency edge appears among the three front ends**, or from
//!    `epigraph-service` to any of them. Every dependency table is read
//!    (normal, dev, build, and each under `[target.<cfg>]`). A dependency is
//!    identified by the package it names (its `package =` rename, or that of
//!    the `[workspace.dependencies]` entry a `workspace = true` line inherits),
//!    so renaming the key does not hide an edge. An allowed edge is keyed on
//!    (from, to, table, optional), so turning an optional edge into an
//!    unconditional one, or moving a dev edge into `[dependencies]`, also
//!    fails. A feature can only enable a dependency its manifest declares, so
//!    the tables are the whole edge set.
//! 2. **A front end's source names another front end's crate more often than
//!    its ceiling.** The test counts occurrences of `epigraph_mcp::`,
//!    `epigraph_cli::` and `epigraph_api::` in each `.rs` file under a front
//!    end's `src/`, counting only the OTHER front ends' names. The CLI's
//!    binaries naming `epigraph_cli::`, their own library, are not coupling.
//!    `epigraph-service/src` has a ceiling of zero for all three. Comments and
//!    `#[cfg(test)]` modules COUNT. A doc comment that points at another front
//!    end's item is coupling the wave must remove too (2c0d2ea9 deletes the
//!    comment-only references), and a plain substring count cannot be fooled
//!    by an `#[cfg]` it fails to parse. Files under `tests/` are not counted,
//!    because test-only composition is the documented exception. A file with
//!    no entry has a ceiling of zero.
//!
//! 3. **A front-end dependency is renamed, or a front end's crate is aliased
//!    in source.** The count in 2 reads the crate's own name, so a
//!    `mcp = { package = "epigraph-mcp", .. }` key (whose references read
//!    `mcp::`) or a `use epigraph_mcp as m;` (whose calls read `m::`) would
//!    take the count to zero or freeze it while the coupling grows. Both are
//!    refused outright: a front end names another front end only by its own
//!    crate name, so every reference is one the count sees. An item imported
//!    by name (`use epigraph_mcp::{a, b};`) counts once per import, not per
//!    use; the count is a proxy for the import surface, not a call graph.
//!
//! A count BELOW its ceiling, or a ceiling whose file is gone, does not fail.
//! It prints "lower the ceiling" so the step that removed a reference
//! lowers the number in the same change.
//!
//! The checks are pure functions over manifest text and file text, so
//! [`an_extra_mcp_to_api_edge_fails`], [`a_raised_reference_count_fails`] and
//! [`a_renamed_or_aliased_front_end_fails`] feed them synthetic input and prove
//! that each kind of violation is caught.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use toml::Value;

/// The front ends: no new edge among them.
const FRONT_ENDS: &[&str] = &["epigraph-api", "epigraph-mcp", "epigraph-cli"];

/// The service crate: no edge from it to any front end, ever.
const SERVICE: &str = "epigraph-service";

/// The dependency tables a manifest can hold, at the top level or under
/// `[target.<cfg>]`.
const DEP_TABLES: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

/// One front-end dependency edge: `from` depends on `to` in `table`
/// (`dependencies`, `dev-dependencies`, `build-dependencies`, or
/// `target.<cfg>.<kind>`), `optional` or not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Edge {
    from: String,
    to: String,
    table: String,
    optional: bool,
}

/// The edges among the front ends as they are today (backlog e08daaec). Each
/// is removed by a step of the 93e01896 wave; none may be added.
const ALLOWED_EDGES: &[(&str, &str, &str, bool)] = &[
    // The `db` feature (`dep:epigraph-mcp`): the MCP twins, the tool catalog
    // route and the workflow warnings. Removed by 2c0d2ea9.
    ("epigraph-api", "epigraph-mcp", "dependencies", true),
    // The `genai` feature (`dep:epigraph-cli`): the LLM client factory.
    // Removed by 365f85a4.
    ("epigraph-api", "epigraph-cli", "dependencies", true),
    // The operator binaries drive MCP tool functions directly. Removed by
    // ac09c8d7.
    ("epigraph-cli", "epigraph-mcp", "dependencies", false),
    // The CLI's tests oneshot the real API handlers: test-only composition.
    ("epigraph-cli", "epigraph-api", "dev-dependencies", false),
];

/// Per-file ceilings on the references a front end's source makes to another
/// front end's crate (see the module doc for what counts). Measured on the
/// tree that added this test; lower an entry when a move removes references,
/// and delete it at zero.
const REFERENCE_CEILINGS: &[(&str, usize)] = &[
    ("crates/epigraph-api/src/errors.rs", 1),
    ("crates/epigraph-api/src/routes/analyze.rs", 2),
    ("crates/epigraph-api/src/routes/claims.rs", 1),
    ("crates/epigraph-api/src/routes/mcp_tools.rs", 3),
    ("crates/epigraph-api/src/routes/mcp_twins.rs", 17),
    ("crates/epigraph-api/src/routes/workflows.rs", 3),
    ("crates/epigraph-cli/src/beta_replay.rs", 2),
    ("crates/epigraph-cli/src/bin/backfill_factors.rs", 1),
    ("crates/epigraph-cli/src/bin/ingest_document.rs", 5),
    ("crates/epigraph-cli/src/bin/ingest_git.rs", 1),
    ("crates/epigraph-cli/src/bin/ingest_literature.rs", 1),
    ("crates/epigraph-cli/src/bin/privatize.rs", 1),
    (
        "crates/epigraph-cli/src/bin/sweep_semantic_duplicates.rs",
        3,
    ),
    ("crates/epigraph-cli/src/cache_owner_audit.rs", 1),
    ("crates/epigraph-cli/src/evidence_type_backfill.rs", 1),
    ("crates/epigraph-cli/src/lib.rs", 1),
    ("crates/epigraph-cli/src/operator/bind.rs", 1),
    ("crates/epigraph-cli/src/operator/link.rs", 1),
    ("crates/epigraph-cli/src/operator/privatization.rs", 1),
    ("crates/epigraph-mcp/src/server.rs", 2),
    ("crates/epigraph-mcp/src/tools/claims.rs", 1),
    ("crates/epigraph-mcp/src/tools/link_hierarchical.rs", 1),
    ("crates/epigraph-mcp/src/tools/supersede.rs", 1),
];

/// The crate path a crate's source uses for a package (`epigraph-mcp` ->
/// `epigraph_mcp::`).
fn path_prefix(package: &str) -> String {
    format!("{}::", package.replace('-', "_"))
}

/// The source roots counted, each with the crate it belongs to.
fn source_roots() -> Vec<(&'static str, PathBuf)> {
    let root = workspace_root();
    FRONT_ENDS
        .iter()
        .chain(std::iter::once(&SERVICE))
        .map(|c| (*c, root.join("crates").join(c).join("src")))
        .collect()
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
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
    tables
}

/// The package a dependency entry names: its own `package =` rename; else, for
/// `workspace = true`, the rename of the `[workspace.dependencies]` entry it
/// inherits; else its key.
fn package_of(key: &str, spec: &Value, workspace_deps: &toml::Table) -> String {
    if let Some(p) = spec.get("package").and_then(Value::as_str) {
        return p.to_string();
    }
    if spec.get("workspace").and_then(Value::as_bool) == Some(true) {
        if let Some(p) = workspace_deps
            .get(key)
            .and_then(|w| w.get("package"))
            .and_then(Value::as_str)
        {
            return p.to_string();
        }
    }
    key.to_string()
}

/// The `[workspace.dependencies]` table of the root manifest `root`.
fn workspace_dependencies(root: &str) -> toml::Table {
    let root: Value = toml::from_str(root).expect("parse the root Cargo.toml");
    root.get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default()
}

/// Every front-end edge declared by `manifest`, the manifest of `from`.
fn front_end_edges(from: &str, manifest: &str, workspace_deps: &toml::Table) -> Vec<Edge> {
    let manifest: Value =
        toml::from_str(manifest).unwrap_or_else(|e| panic!("parse {from}'s Cargo.toml: {e}"));
    let mut edges = Vec::new();
    for (table, deps) in dependency_tables(&manifest) {
        for (key, spec) in deps {
            let to = package_of(key, spec, workspace_deps);
            if FRONT_ENDS.contains(&to.as_str()) && to != from {
                edges.push(Edge {
                    from: from.to_string(),
                    to,
                    table: table.clone(),
                    optional: spec.get("optional").and_then(Value::as_bool) == Some(true),
                });
            }
        }
    }
    edges
}

/// Every edge in `manifests` (crate name, manifest text) that `allowed` does
/// not list, one line each. `epigraph-service` has no allowed edge.
fn edge_violations(
    manifests: &[(&str, String)],
    workspace_deps: &toml::Table,
    allowed: &[(&str, &str, &str, bool)],
) -> Vec<String> {
    let mut violations = Vec::new();
    for (from, manifest) in manifests {
        for edge in front_end_edges(from, manifest, workspace_deps) {
            let listed = allowed.iter().any(|(f, t, table, optional)| {
                *f == edge.from
                    && *t == edge.to
                    && *table == edge.table
                    && *optional == edge.optional
            });
            if !listed {
                violations.push(format!(
                    "{} -> {} [{}{}]: a dependency edge the layering rule does not allow. \
                     Shared code belongs in epigraph-service, which every front end may \
                     depend on (backlog 93e01896).",
                    edge.from,
                    edge.to,
                    edge.table,
                    if edge.optional { ", optional" } else { "" }
                ));
            }
        }
    }
    violations
}

/// Every front-end dependency in `manifests` declared under a key that is not
/// the package's own name (check 3), one line each. A `workspace = true` entry
/// inherits its rename, so a renamed `[workspace.dependencies]` key counts too.
fn rename_violations(manifests: &[(&str, String)], workspace_deps: &toml::Table) -> Vec<String> {
    let mut violations = Vec::new();
    for (from, manifest) in manifests {
        let parsed: Value =
            toml::from_str(manifest).unwrap_or_else(|e| panic!("parse {from}'s Cargo.toml: {e}"));
        for (table, deps) in dependency_tables(&parsed) {
            for (key, spec) in deps {
                let to = package_of(key, spec, workspace_deps);
                if FRONT_ENDS.contains(&to.as_str()) && to != *from && key != &to {
                    violations.push(format!(
                        "{from} -> {to} [{table}] is declared under the key `{key}`: its \
                         source would name the crate `{}::`, which the reference count does \
                         not see. Declare it under its own name.",
                        key.replace('-', "_")
                    ));
                }
            }
        }
    }
    violations
}

/// The aliases `text`, a source file of `owner`, gives the OTHER front ends'
/// crates (`use epigraph_mcp as m;`, `extern crate epigraph_mcp as m;`,
/// `use epigraph_mcp::{self as m};`), one line each (check 3).
fn alias_violations(owner: &str, text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for c in FRONT_ENDS.iter().filter(|c| **c != owner) {
        let name = c.replace('-', "_");
        for pattern in [
            format!("{name} as "),
            format!("{name}::{{self as "),
            format!("{name}::self as "),
        ] {
            if text.contains(&pattern) {
                found.push(format!(
                    "`{}`: an alias for another front end's crate, whose uses the \
                     reference count does not see. Name the crate by its own name.",
                    pattern.trim_end()
                ));
            }
        }
    }
    found
}

/// The references `text`, a source file of `owner`, makes to the OTHER front
/// ends' crates.
fn foreign_references(owner: &str, text: &str) -> usize {
    FRONT_ENDS
        .iter()
        .filter(|c| **c != owner)
        .map(|c| text.matches(&path_prefix(c)).count())
        .sum()
}

/// What the reference count of `files` (path, owning crate, text) says against
/// `ceilings`: (violations, which fail; "lower the ceiling" notes, which only
/// print).
fn reference_findings(
    files: &[(String, &str, String)],
    ceilings: &[(&str, usize)],
) -> (Vec<String>, Vec<String>) {
    let ceiling: BTreeMap<&str, usize> = ceilings.iter().copied().collect();
    let mut violations = Vec::new();
    let mut lower = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (path, owner, text) in files {
        for alias in alias_violations(owner, text) {
            violations.push(format!("{path}: {alias}"));
        }
        let count = foreign_references(owner, text);
        let max = ceiling.get(path.as_str()).copied().unwrap_or(0);
        seen.insert(path.as_str());
        if count > max {
            violations.push(format!(
                "{path}: {count} reference(s) to another front end's crate, ceiling {max}. \
                 Reach the shared code through epigraph-service instead (backlog 93e01896)."
            ));
        } else if count < max {
            lower.push(format!(
                "{path}: {count} reference(s), ceiling {max}: lower the ceiling"
            ));
        }
    }
    for (path, max) in ceilings {
        if !seen.contains(path) && *max > 0 {
            lower.push(format!(
                "{path}: file gone, ceiling {max}: lower the ceiling (delete the entry)"
            ));
        }
    }
    (violations, lower)
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The workspace's real manifests for the front ends and the service crate.
fn real_manifests() -> Vec<(&'static str, String)> {
    let root = workspace_root();
    FRONT_ENDS
        .iter()
        .chain(std::iter::once(&SERVICE))
        .map(|c| (*c, read(&root.join("crates").join(c).join("Cargo.toml"))))
        .collect()
}

#[test]
fn no_new_dependency_edge_among_the_front_ends() {
    let root = workspace_root();
    let workspace_deps = workspace_dependencies(&read(&root.join("Cargo.toml")));
    let manifests = real_manifests();

    let violations = edge_violations(&manifests, &workspace_deps, ALLOWED_EDGES);
    assert!(
        violations.is_empty(),
        "crate layering (backlog 6ffcb138):\n{}",
        violations.join("\n")
    );

    // An allowed edge that is gone is a removal to record: shrink the list.
    let present: Vec<Edge> = manifests
        .iter()
        .flat_map(|(from, m)| front_end_edges(from, m, &workspace_deps))
        .collect();
    for (f, t, table, optional) in ALLOWED_EDGES {
        let still = present
            .iter()
            .any(|e| e.from == *f && e.to == *t && e.table == *table && e.optional == *optional);
        if !still {
            eprintln!(
                "{f} -> {t} [{table}] is gone: lower the ceiling (delete it from ALLOWED_EDGES)"
            );
        }
    }
}

#[test]
fn no_front_end_dependency_is_renamed() {
    let root = workspace_root();
    let workspace_deps = workspace_dependencies(&read(&root.join("Cargo.toml")));
    let violations = rename_violations(&real_manifests(), &workspace_deps);
    assert!(
        violations.is_empty(),
        "crate layering (backlog 6ffcb138):\n{}",
        violations.join("\n")
    );
}

#[test]
fn front_end_references_stay_at_or_below_their_ceilings() {
    let root = workspace_root();
    let mut files = Vec::new();
    for (owner, dir) in source_roots() {
        let mut paths = Vec::new();
        rust_files(&dir, &mut paths);
        for p in paths {
            let rel = p
                .strip_prefix(&root)
                .expect("under the workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            files.push((rel, owner, read(&p)));
        }
    }
    assert!(
        files.len() > 100,
        "the scan found only {} source files; the roots are wrong",
        files.len()
    );

    let (violations, lower) = reference_findings(&files, REFERENCE_CEILINGS);
    for note in &lower {
        eprintln!("{note}");
    }
    assert!(
        violations.is_empty(),
        "crate layering (backlog 6ffcb138):\n{}",
        violations.join("\n")
    );
}

/// The edge check catches an added edge: a synthetic MCP manifest that
/// depends on the API fails, and so does that dependency hidden behind a
/// renamed key, under a target table, or inherited through a renamed
/// workspace entry. So do an allowed edge made unconditional, and any edge
/// from the service crate.
#[test]
fn an_extra_mcp_to_api_edge_fails() {
    let workspace_deps = workspace_dependencies(
        r#"
        [workspace.dependencies]
        epigraph-api = { path = "crates/epigraph-api" }
        http-front = { path = "crates/epigraph-api", package = "epigraph-api" }
        "#,
    );
    let cases = [
        ("epigraph-mcp", "[dependencies]\nepigraph-api = { workspace = true }\n"),
        ("epigraph-mcp", "[dev-dependencies]\nfront = { path = \"../epigraph-api\", package = \"epigraph-api\" }\n"),
        ("epigraph-mcp", "[target.'cfg(unix)'.dependencies]\nepigraph-api = { workspace = true }\n"),
        ("epigraph-mcp", "[build-dependencies]\nhttp-front = { workspace = true }\n"),
        // An allowed edge, made unconditional.
        ("epigraph-api", "[dependencies]\nepigraph-mcp = { workspace = true }\n"),
        ("epigraph-service", "[dependencies]\nepigraph-cli = { workspace = true, optional = true }\n"),
    ];
    for (from, manifest) in cases {
        let violations = edge_violations(
            &[(from, manifest.to_string())],
            &workspace_deps,
            ALLOWED_EDGES,
        );
        assert_eq!(violations.len(), 1, "{from}: {manifest}\n{violations:?}");
    }

    // The allowed edges themselves pass, and a kernel dependency is no edge.
    let allowed = "[dependencies]\nepigraph-mcp = { workspace = true, optional = true }\n\
                   epigraph-cli = { workspace = true, optional = true }\n\
                   epigraph-db = { workspace = true }\n";
    assert!(edge_violations(
        &[("epigraph-api", allowed.to_string())],
        &workspace_deps,
        ALLOWED_EDGES
    )
    .is_empty());
}

/// The reference check catches a raised count, a new file, and a service-crate
/// reference; it only prints for a lowered one; and a crate naming itself is
/// not counted.
#[test]
fn a_raised_reference_count_fails() {
    let ceilings = &[("crates/epigraph-api/src/a.rs", 1)];
    let file =
        |path: &str, owner: &'static str, text: &str| (path.to_string(), owner, text.to_string());

    let (v, _) = reference_findings(
        &[file(
            "crates/epigraph-api/src/a.rs",
            "epigraph-api",
            "use epigraph_mcp::x;\n// epigraph_cli::y\n",
        )],
        ceilings,
    );
    assert_eq!(v.len(), 1, "{v:?}");

    let (v, _) = reference_findings(
        &[file(
            "crates/epigraph-api/src/b.rs",
            "epigraph-api",
            "epigraph_mcp::z()",
        )],
        ceilings,
    );
    assert_eq!(v.len(), 1, "a file with no entry has ceiling 0: {v:?}");

    let (v, _) = reference_findings(
        &[file(
            "crates/epigraph-service/src/c.rs",
            "epigraph-service",
            "/// see epigraph_mcp::errors",
        )],
        ceilings,
    );
    assert_eq!(v.len(), 1, "the service crate has ceiling 0: {v:?}");

    let (v, lower) = reference_findings(
        &[file(
            "crates/epigraph-api/src/a.rs",
            "epigraph-api",
            "nothing here",
        )],
        ceilings,
    );
    assert!(v.is_empty());
    assert_eq!(lower.len(), 1, "{lower:?}");

    let (v, lower) = reference_findings(
        &[file(
            "crates/epigraph-cli/src/bin/x.rs",
            "epigraph-cli",
            "use epigraph_cli::lib;",
        )],
        ceilings,
    );
    assert!(v.is_empty(), "a crate naming itself is not coupling: {v:?}");
    assert_eq!(
        lower.len(),
        1,
        "the ceiling whose file is absent is reported: {lower:?}"
    );
}

/// Check 3 catches the two ways to hide references from the count: the
/// allowed API -> MCP edge declared under a renamed key (directly or through a
/// renamed workspace entry), and an alias for the MCP crate in API source. A
/// plain declaration and a plain reference are not flagged.
#[test]
fn a_renamed_or_aliased_front_end_fails() {
    let workspace_deps = workspace_dependencies(
        r#"
        [workspace.dependencies]
        epigraph-mcp = { path = "crates/epigraph-mcp" }
        mcp-front = { path = "crates/epigraph-mcp", package = "epigraph-mcp" }
        "#,
    );
    for manifest in [
        "[dependencies]\nmcp = { path = \"../epigraph-mcp\", package = \"epigraph-mcp\", optional = true }\n",
        "[dependencies]\nmcp-front = { workspace = true, optional = true }\n",
    ] {
        let manifests = [("epigraph-api", manifest.to_string())];
        assert!(
            edge_violations(&manifests, &workspace_deps, ALLOWED_EDGES).is_empty(),
            "the edge itself is the allowed one: {manifest}"
        );
        assert_eq!(
            rename_violations(&manifests, &workspace_deps).len(),
            1,
            "{manifest}"
        );
    }
    assert!(rename_violations(
        &[(
            "epigraph-api",
            "[dependencies]\nepigraph-mcp = { workspace = true, optional = true }\n\
             db = { package = \"epigraph-db\", path = \"../epigraph-db\" }\n"
                .to_string()
        )],
        &workspace_deps
    )
    .is_empty());

    let ceilings = &[("crates/epigraph-api/src/a.rs", 5)];
    for text in [
        "use epigraph_mcp as m;\nm::a(); m::b(); m::c(); m::d(); m::e(); m::f();\n",
        "extern crate epigraph_mcp as m;\n",
        "use epigraph_mcp::{self as m, errors};\n",
    ] {
        let (v, _) = reference_findings(
            &[(
                "crates/epigraph-api/src/a.rs".to_string(),
                "epigraph-api",
                text.to_string(),
            )],
            ceilings,
        );
        assert_eq!(v.len(), 1, "{text}\n{v:?}");
    }
    let (v, _) = reference_findings(
        &[(
            "crates/epigraph-cli/src/bin/x.rs".to_string(),
            "epigraph-cli",
            "use epigraph_cli as cli;\n".to_string(),
        )],
        ceilings,
    );
    assert!(
        v.is_empty(),
        "a crate aliasing itself is not coupling: {v:?}"
    );
}
