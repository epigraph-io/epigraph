//! Source lint: the write gate is **called**, and by exactly the sites reviewed.
//!
//! # The gap this closes
//!
//! Before PR-11, `AppState.policy_gate` was a trait object that was constructed
//! six times, stored, made swappable — and consulted **zero** times.
//! `git grep -l policy_gate -- crates/` returned one file, `state.rs`. Nothing
//! in the tree could have detected that: a policy gate nobody calls has no
//! observable behaviour, so no behavioural test fails, and the field looks like
//! a control in a grep and in a threat model.
//!
//! The read side has three ratchets for the analogous property
//! (`epigraph-db/tests/visibility_lint.rs`,
//! `epigraph-mcp/tests/tool_viewer_is_spent.rs`,
//! `epigraph-mcp/tests/tool_viewer_coverage.rs`). The write side had none. This
//! is the write-side equivalent, and it is written as an **exact set** for the
//! same reason those are: a count can be satisfied by moving a call, and an
//! `assert!(> 0)` cannot notice a gate being deleted from one of two twins.
//!
//! # What this CANNOT tell you
//!
//! That the gate's *verdict* is honoured — a handler could call `authorize` and
//! ignore the `Decision`. This file is the *acquisition* half, exactly as
//! `tool_viewer_coverage.rs` is on the read side.
//!
//! The verdict half is covered by two **behavioural** files, and by nothing
//! else:
//!
//! * `epigraph-api/tests/write_gate_denies_at_the_route.rs` — real HTTP round
//!   trips through `spawn_app`, asserting 403 for a non-owner and 200/201 for
//!   the owner at both gated routes.
//! * `epigraph-mcp/tests/write_gate_denies_at_the_tool.rs` — the same matrix
//!   driven at the MCP tool functions with a `Viewer::resolve`d principal.
//!
//! An earlier revision of this comment cited `routes/negative_tests.rs`
//! instead. **That citation was wrong**: its only ownership cases
//! (`assign_ownership_wrong_scope_with_malformed_body_returns_403_not_422` and
//! its `update_partition` sibling) assert extractor *ordering* — wrong-scope
//! 403-vs-422 — and `RequireScopeAdmin` rejects those requests before
//! `require_declassify_authority` is ever reached. A ratchet that names its own
//! coverage boundary must name it correctly, so the two files above were
//! written rather than the claim restated.
//!
//! # What is deliberately NOT asserted: coverage of all write paths
//!
//! PR-11 does not gate all 60 HTTP write registrations or all 45 mutating MCP
//! tools, and this lint does not pretend otherwise. The blast radius of a
//! fleet-wide fail-closed gate is what **PR-15** (`give every background writer
//! a maintenance DSN`) exists to make survivable, and it lands four PRs later.
//! PR-11 gates the declassification surface — the one the PR title names and
//! the one §9's leak table rates *blocker* — and builds the mechanism the rest
//! will use.

use std::path::{Path, PathBuf};

/// The exact set of production call sites that consult the write gate, as
/// measured on **2026-09-03**.
///
/// `(file, function)`. Removing a name here without removing the call is a
/// visible diff a reviewer can check; removing the call without the name fails
/// this test.
const EXPECTED_GATED_WRITES: &[(&str, &str)] = &[
    // HTTP. `claims:admin` is necessary and no longer sufficient: the scope
    // says the client may reach the route, the gate says the principal may
    // touch the node.
    ("epigraph-api/src/routes/ownership.rs", "assign_ownership"),
    ("epigraph-api/src/routes/ownership.rs", "update_partition"),
    // MCP. `assign_ownership` is `claims:write` in `scope_map.rs` while its
    // sibling `update_partition` is `claims:admin` — and on the stdio
    // transport `enforce_tool_scope` does not run at all, so for stdio callers
    // this gate is the only authorization there is.
    ("epigraph-mcp/src/tools/perspectives.rs", "assign_ownership"),
    ("epigraph-mcp/src/tools/perspectives.rs", "update_partition"),
];

/// The one spelling of "this write asked the gate". Shared by the two helpers
/// (`routes/ownership.rs` and `tools/perspectives.rs` each define one) so the
/// lint and the code cannot drift to two different spellings, the same
/// discipline `VISIBILITY_MARKER_PREFIX` applies on the read side.
const GATE_CALL: &str = "require_declassify_authority(";

/// The *other* way a write could reach the gate: calling
/// [`PolicyGate::authorize`] directly instead of going through a reviewed
/// helper. Detected so that "add a gated write without telling the lint" needs
/// two mistakes rather than one.
const DIRECT_GATE_CALL: &str = ".authorize(";

/// Files where a direct `.authorize(` is expected and is **not** a write call
/// site: the trait's own default method, the gate implementation, and the
/// `#[cfg(test)]` blocks that exercise the default `AppState` installs. Measured
/// 2026-09-03 — `grep -rn '\.authorize(' crates/*/src/` returns exactly these
/// three plus the two reviewed helpers (excluded by name below).
const DIRECT_CALL_EXPECTED_IN: &[&str] = &[
    "epigraph-interfaces/src/policy.rs",
    "epigraph-authz/src/lib.rs",
    "epigraph-api/src/state.rs",
];

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("crates/ is the parent of epigraph-api")
}

/// Every `.rs` under `crates/*/src/`, as paths relative to `crates/`.
///
/// The discovery half of the exact-set assertion. Sorted so a failure message is
/// stable.
fn workspace_src_files() -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                if let Ok(rel) = path.strip_prefix(root) {
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }

    let root = crates_dir();
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&root)
        .expect("crates/ is readable")
        .flatten()
    {
        let src = entry.path().join("src");
        if src.is_dir() {
            walk(&src, &root, &mut out);
        }
    }
    assert!(
        out.len() > 100,
        "the workspace walk found only {} source files — the scan root is wrong, \
         and a vacuous scan would make the exact-set assertion pass by finding \
         nothing",
        out.len()
    );
    out.sort();
    out
}

fn read(rel: &str) -> String {
    let path = crates_dir().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// **Every** body of `fn <name>` in `src`, brace-balanced, comments and string
/// literals skipped.
///
/// Plural on purpose. `routes/ownership.rs` defines `assign_ownership` and
/// `update_partition` **twice** each, under `#[cfg(feature = "db")]` and
/// `#[cfg(not(feature = "db"))]`. A first-match lookup would inspect the `db`
/// arm twice and never see the no-db twin at all — so the lint would appear to
/// check a property it could not observe. Returning both makes the two
/// assertions below mean what their names say: `every_reviewed_write_site…`
/// requires the gate in *at least one* arm (the no-db stubs persist nothing and
/// are deliberately ungated — see the rationale at the stubs), and the exact-set
/// test dedups by `(file, name)` so a twin pair counts once.
fn fn_bodies<'a>(src: &'a str, name: &str) -> Vec<&'a str> {
    let needle = format!("fn {name}(");
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(&needle) {
        let at = from + rel;
        from = at + needle.len();
        // `fn foo(` must not be the tail of `some_fn foo(`.
        if at > 0 {
            let prev = src.as_bytes()[at - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                continue;
            }
        }
        let Some(off) = src[at..].find('{') else {
            continue;
        };
        out.push(balanced(src, at + off));
    }
    out
}

fn balanced(src: &str, start: usize) -> &str {
    let b = src.as_bytes();
    let n = src.len();
    let mut j = start;
    let mut depth = 0usize;
    while j < n {
        match b[j] {
            b'"' => {
                let mut k = j + 1;
                while k < n {
                    if b[k] == b'\\' {
                        k += 2;
                        continue;
                    }
                    if b[k] == b'"' {
                        break;
                    }
                    k += 1;
                }
                j = k + 1;
                continue;
            }
            b'/' if j + 1 < n && b[j + 1] == b'/' => {
                j = src[j..].find('\n').map_or(n, |e| j + e + 1);
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let mut e = j + 1;
                    while e < n && !src.is_char_boundary(e) {
                        e += 1;
                    }
                    return &src[start..e];
                }
            }
            _ => {}
        }
        j += 1;
    }
    &src[start..]
}

/// Every named site really does call the gate.
#[test]
fn every_reviewed_write_site_consults_the_gate() {
    let mut missing = Vec::new();
    for (file, func) in EXPECTED_GATED_WRITES {
        let src = read(file);
        let bodies = fn_bodies(&src, func);
        assert!(
            !bodies.is_empty(),
            "{file} no longer defines `fn {func}(` — update this lint"
        );
        if !bodies.iter().any(|b| b.contains(GATE_CALL)) {
            missing.push(format!("  {file}::{func}"));
        }
    }
    assert!(
        missing.is_empty(),
        "\n\nThese write paths no longer consult the policy gate:\n{}\n\n\
         A gate that is constructed, stored and never called is exactly the \
         state PR-11 found `AppState.policy_gate` in. If the site was \
         deliberately un-gated, remove it from EXPECTED_GATED_WRITES in the \
         same commit and say why in the PR body.\n",
        missing.join("\n")
    );
}

/// Nothing else calls it, and nothing calls it and is unlisted.
///
/// The direction that matters is the second one: a *new* gated write is good
/// news, but it must be reviewed, because the argument it passes as the owner
/// of record is the whole decision.
///
/// # Scan root, and the one thing this still cannot see
///
/// The scan walks **every `crates/*/src/**/*.rs` in the workspace**, not the two
/// files the expected set names. An earlier revision iterated the two-element
/// list, which made the "nothing calls it and is unlisted" half vacuous: a
/// gated write added in `routes/crud.rs` would have been invisible to exactly
/// the direction the doc says matters. The list is now the *allowlist* and the
/// walk is the *discovery*.
///
/// What remains uncovered is the **spelling**: detection is `GATE_CALL` plus a
/// direct `.authorize(` on a `PolicyGate`, so a site that reached the trait some
/// third way would still slip through. That is the same class as
/// `F-fail-open-ratchet-single-spelling` already open in
/// `docs/tenancy/progress.json`, and it is stated here rather than left to be
/// discovered.
#[test]
fn the_set_of_gated_write_sites_is_exactly_what_was_reviewed() {
    let mut found: Vec<(String, String)> = Vec::new();

    for rel in workspace_src_files() {
        let rel = rel.as_str();
        let src = read(rel);
        let direct_expected = DIRECT_CALL_EXPECTED_IN.contains(&rel);
        let interesting =
            src.contains(GATE_CALL) || (!direct_expected && src.contains(DIRECT_GATE_CALL));
        if !interesting {
            continue;
        }
        // Walk `pub async fn` / `async fn` / `fn` declarations and record the
        // ones whose body calls the gate. The helper that DEFINES the call is
        // excluded by name — it is the callee, not a call site.
        let mut from = 0usize;
        while let Some(rel_at) = src[from..].find("fn ") {
            let at = from + rel_at;
            from = at + 3;
            if at > 0 {
                let prev = src.as_bytes()[at - 1];
                if prev.is_ascii_alphanumeric() || prev == b'_' {
                    continue;
                }
            }
            let after = &src[at + 3..];
            let end = after
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(after.len());
            if end == 0 {
                continue;
            }
            let name = after[..end].to_string();
            if name == "require_declassify_authority" {
                continue;
            }
            let bodies = fn_bodies(&src, &name);
            if bodies.iter().any(|b| {
                b.contains(GATE_CALL) || (!direct_expected && b.contains(DIRECT_GATE_CALL))
            }) {
                found.push((rel.to_string(), name));
            }
        }
    }
    found.sort();
    found.dedup();

    let mut expected: Vec<(String, String)> = EXPECTED_GATED_WRITES
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect();
    expected.sort();

    assert_eq!(
        found, expected,
        "\n\nThe set of write paths consulting the policy gate changed.\n\
         If you gated a new write: add it here in the same commit, and check \
         the value it passes as the owner of record against the contract the \
         two existing helpers document — the owner comes from the DATABASE \
         when a row exists; when none exists, the ONLY request-derived value \
         that may reach the gate's owner slot is the caller's own principal \
         (a self-claim), and anything else must leave the ResourceRef \
         undeclared so the gate refuses it.\n\
         A text lint cannot check that. It is stated here because this is \
         where a contributor adding a site will read it.\n"
    );
}

/// The scan root is not vacuous.
///
/// Both files must exist and must define the shared helper; if either is
/// renamed or deleted (PR-14 deletes `routes/ownership.rs` outright) this test
/// says so instead of passing over an empty set.
#[test]
fn the_scanned_files_still_exist_and_define_the_helper() {
    for rel in [
        "epigraph-api/src/routes/ownership.rs",
        "epigraph-mcp/src/tools/perspectives.rs",
    ] {
        let src = read(rel);
        assert!(
            src.contains("async fn require_declassify_authority("),
            "{rel} no longer defines the shared gate helper. PR-14 deletes \
             `routes/ownership.rs` and the MCP ownership tools; when it does, \
             this lint must move to whatever PR-16 gates instead, not be \
             deleted."
        );
    }
}
