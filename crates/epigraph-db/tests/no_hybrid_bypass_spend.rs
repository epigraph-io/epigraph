//! The HYBRID SHAPE: mint a bypass `Viewer`, then spend it on a pool that is
//! not the maintenance one.
//!
//! Recorded as `D-PR17-hybrid-shape-lint`, and named as a known limit by
//! `no_unmaintained_dsn.rs`'s own module doc.
//!
//! # Why a third key was needed
//!
//! Three lints already exist over this surface and none of them can see this
//! shape:
//!
//! * `no_unmaintained_dsn.rs` is keyed on pool **CONSTRUCTION**. It proves a
//!   scanned file builds no unmaintained pool. A file that takes an injected
//!   `PgPool` constructs nothing and passes green — its own doc says so.
//! * `no_unscoped_pool.rs` is keyed on the `state.db_pool` **FIELD ACCESS**
//!   count, as a monotone ratchet. It measures how much of the request path is
//!   unconverted, not whether a bypass viewer is spent somewhere it cannot work.
//! * `no_bypass_in_handlers.rs` is keyed on a handler **MINTING** a bypass at
//!   all. It has nothing to say about where a legitimately-minted one is spent.
//!
//! What determines whether a statement is filtered is the pool it RUNS on. A
//! bypass `Viewer` emits no SQL predicate; from plan §9.2 step 11d on, the
//! database policy still filters. So a bypass viewer spent on an ordinary
//! application connection returns **zero** rows rather than all of them — a
//! wrong answer with no error, which plan §4.3's R2 calls the worse failure
//! because *"fail-closed regressions look like data loss, not errors."*
//!
//! # What this lint checks, stated precisely
//!
//! Two passes over the production text of every file under [`SCAN_ROOTS`].
//!
//! **1. Same region.** The source is split into function-sized regions. A
//! region that MINTS a bypass ([`MINTS`], or a call to a derived [`Wrapper`] —
//! a function that returns a `MaintenanceSession`, or a `Viewer` it minted) or
//! HOLDS one it was handed ([`HOLDS`] — the `MaintenanceSession` type) must
//! name no FOREIGN POOL HANDLE ([`FOREIGN_POOLS`]).
//!
//! **2. Across calls.** From every such region the bypass is FOLLOWED: through
//! each call whose arguments carry it — a local bound from a mint, the viewer
//! half of `session.split()`, `session.viewer()`, or a parameter that arrived
//! carrying it — into the callee, mapped to the parameter it lands in, up to
//! [`MAX_HOPS`] calls, across files and crates. A function the bypass reaches
//! that names a [`FOREIGN_POOLS`] spelling is a finding, keyed by the function
//! where the pool is NAMED, and the failure prints the chain back to the mint.
//! See [`analyse_sources`] for the rules and known limit (d) for what they do
//! not follow.
//!
//! The granularity is the FUNCTION and that is an over-approximation, the same
//! one `visibility_lint.rs` states for `no_spliced_statement_binds_the_unconditional_group_array`:
//! a function that mints a bypass for one statement and legitimately uses an
//! application pool for an unrelated one is flagged. That is deliberate — the
//! two things being adjacent in one body is itself the review signal. The
//! cross-function pass applies the same rule at the far end of a call.
//!
//! # COMMENTS ARE STRIPPED BEFORE MATCHING, and this is NOT a re-litigation of
//! `lint_robustness_repos_is_not_a_stripping_root`
//!
//! That decision refused comment-stripping for `visibility_lint.rs`, and the
//! reason was specific: *"the VISIBILITY-EXEMPT convention is carried in
//! COMMENTS BY DESIGN"*, so stripping there deletes the very thing the lint
//! reads. Nothing this lint matches on is a convention — [`MINTS`] and
//! [`FOREIGN_POOLS`] are both CODE spellings. Measured on the tree before the
//! stripper existed: two false positives, both prose. `state.rs::maintenance_viewer`
//! and `routes/claims.rs::find_claims_needing_embeddings` each carry a doc
//! comment explaining why the statement must NOT run on `state.db_pool` — the
//! correct reasoning, flagged as the defect it warns against. A lint that
//! punishes a call site for documenting its own hazard is worse than no lint.
//!
//! The stripper tracks string and char literals so a `"postgres://…"` DSN is
//! not mistaken for a line comment; `the_stripper_does_not_eat_code` pins that.
//!
//! `#[cfg(test)]` MODULES are removed too, by brace matching rather than by
//! truncating at the first occurrence — see `strip_cfg_test_modules` for the
//! measurement that forced that, and `the_cfg_test_strip_keeps_production_code`
//! for the pin.
//!
//! # KNOWN LIMITS, measured rather than assumed
//!
//! **(a) `maint.pool()` is not foreign.** The eleven `epigraph-cli` binaries
//! pass `maint.pool()` into their repo calls and are **not** hybrids:
//! `MaintenancePool::connect_to` builds its `ScopedPool` from the MAINTENANCE
//! DSN and attaches no separate pool, so `pool()` is `scoped.inner()` is the
//! privileged pool. If a future revision of `MaintenancePool` ever attaches a
//! second pool, that assumption dies and this paragraph is the thing to
//! re-measure. `MaintenancePool::viewer` IS derived as a [`Wrapper`] since
//! 2026-09-22, so every binary is now a seed and the cross-function pass follows
//! its bypass into their helpers and the engine; re-measured with that wider
//! reach, none of them names a foreign pool.
//!
//! **(b) A BARE `&Viewer` HANDED ACROSS A FUNCTION OR FILE BOUNDARY — CLOSED
//! 2026-09-22.** The same-region pass keys on one region containing BOTH halves,
//! so a function that mints and hands a `&Viewer` to a callee that runs the
//! statement elsewhere matched neither half anywhere — and `Viewer` is also the
//! type of every REQUEST viewer, so it cannot be keyed on by name. The measured
//! instance was `epigraph-mcp/src/server.rs`'s three maintenance tools: they
//! minted through `maintenance_viewer(` and handed the bare `&Viewer` into
//! `crates/epigraph-mcp/src/tools/`, whose statements ran on `server.pool`, and
//! the `"server.pool"` entry in [`FOREIGN_POOLS`] contributed ZERO detections.
//! The cross-function pass follows the viewer by VALUE instead of by type: only
//! locals bound from a mint and parameters that received one are tainted.
//! Measured by running this binary against the tree at `ba6f6d68`, before those
//! tools were fixed: it reports exactly the three tool functions, each reached
//! from its `server.rs` method, and nothing else in the eight scan roots — where
//! the previous revision passed green. `the_pre_fix_mcp_shape_is_detected_across_files`
//! keeps that as a fixture and `a_bare_viewer_hand_off_on_the_real_mcp_surface_is_detected`
//! re-creates it in the real tree. (The tools themselves now take the session
//! and are clean; `the_mcp_maintenance_tools_are_in_reach_and_clean`.)
//!
//! **(c) Passing a `MaintenanceSession` into a callee — CLOSED.** A helper
//! taking `&mut MaintenanceSession` and a pool handle used to contain no
//! [`MINTS`] spelling in its own region. [`HOLDS`] counts naming the session
//! type as holding a bypass, so such a helper is scanned exactly like a
//! function that mints. A function that RETURNS a session is a [`Wrapper`], and
//! its callers are scanned as minting — `routes/privatization.rs`'s private
//! `maintenance(state)` has ten, none of which spells a mint of its own.
//!
//! **(d) WHAT THE CROSS-FUNCTION PASS DOES NOT FOLLOW.** Stated so (b) is not
//! read as "every flow". It is a text scan, not a type checker:
//!
//! * the RECEIVER of a method call (`bypass.f()`, `session.f()`): those methods
//!   live in `epigraph-db`, and `MaintenanceSession::pool` names `self.pool`
//!   legitimately — it is the maintenance pool;
//! * a bypass stored in a struct field, captured by a closure that is stored or
//!   returned, sent over a channel, or returned from a function that is not a
//!   [`Wrapper`];
//! * a call through a type parameter (`T::f(`) or a qualified path
//!   (`<T as Trait>::f(`), and anything behind a turbofish;
//! * a bare call to a function `use`d from ANOTHER crate — cross-crate calls
//!   resolve only through an explicit `epigraph_x::` path or a method name;
//! * arguments inside macros that are not call syntax (`sqlx::query!(.., v)`);
//! * more than [`MAX_HOPS`] calls from the mint, and THROUGH [`SINK_CRATES`]:
//!   an `epigraph-db` function is checked when the bypass reaches it, not
//!   followed further;
//! * a helper handed only the maintenance CONNECTION — deliberately, since it
//!   holds no bypass.
//!
//! Two approximations run the other way, toward findings: a method call
//! `expr.f(..)` resolves to EVERY method named `f` in the scanned crates
//! (recorded in [`Analysis::ambiguous`] and printed beside any finding reached
//! through one), and a name, once tainted, stays tainted for the rest of its
//! function (shadowing is not modelled).
//!
//! # A RATCHET WITH A NAMED RESIDUE, not an invariant
//!
//! [`EXPECTED_HYBRIDS`] is asserted as an EXACT SET in both directions **over
//! what these two passes key on**: an unregistered hybrid — same-region or
//! reached across calls — fails the build, and a registered one that has been
//! fixed also fails, so the register cannot rot into a licence. Same shape as
//! `no_inline_sql_in_tools.rs`'s `EXPECTED_INLINE_SQL`. It is not a statement
//! about hybrids in general — limit (d) above bounds it.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Spellings that mint a bypass `Viewer` in a production body.
///
/// `ScopedPool::maintenance_session` is the single mint inside `epigraph-db`
/// and the three wrappers route through it, so keying on the wrapper names plus
/// the raw `Viewer::system(` covers every production site that can hold one.
const MINTS: &[&str] = &[
    "Viewer::system(",
    "maintenance_viewer(",
    "maintenance_session(",
];

/// Spellings by which a region HOLDS a bypass it did not mint: naming the
/// session type, whether as a parameter, a return type or a local annotation.
///
/// Kept apart from [`MINTS`] because the claim is different — a region here
/// may never call a mint, yet the `&Viewer` it can reach through
/// `MaintenanceSession::viewer` / `::split` is just as unrestricted. Known
/// limit (c) is what this closes. `GatedMaintenanceSession`
/// (`epigraph-mcp/src/maintenance.rs`) contains the spelling and is meant to.
const HOLDS: &[&str] = &["MaintenanceSession"];

/// Does this region hold a bypass viewer, by minting one or by being handed one?
fn holds_a_bypass(body: &str) -> bool {
    MINTS.iter().any(|m| body.contains(m)) || HOLDS.iter().any(|h| body.contains(h))
}

/// Pool handles that are NOT derived from a maintenance connection.
///
/// Each is a field or accessor on a long-lived application object. A
/// `MaintenanceConn`, a `MaintenanceSession`, a `ScopedTx` begun on one, and
/// `maint.pool()` are all absent from this list on purpose — see the module
/// doc's known limit (a).
///
/// Every entry is proven able to fire across a call by
/// `every_foreign_pool_spelling_fires_across_a_call`, so none is the dead weight
/// `"server.pool"` was while known limit (b) stood. `"app.db_pool"` names no
/// production site today (measured 2026-09-22); it is a guard on the spelling,
/// not a count.
const FOREIGN_POOLS: &[&str] = &[
    "self.pool",
    "self.db_pool",
    "state.db_pool",
    "server.pool",
    "app.db_pool",
];

/// Crates whose `src/` is scanned. `epigraph-db` itself is included: the mint
/// lives there, and a repo module that minted and spent one would be the worst
/// version of this.
const SCAN_ROOTS: &[&str] = &[
    "../epigraph-api/src",
    "../epigraph-cli/src",
    "../epigraph-db/src",
    "../epigraph-embeddings/src",
    "../epigraph-engine/src",
    "../epigraph-ingest-executor/src",
    "../epigraph-jobs/src",
    "../epigraph-mcp/src",
];

/// The hybrids that exist today, as `(path suffix, function name)` of the
/// function that NAMES the foreign pool — for a cross-function hybrid that is
/// the callee, and the failure message prints the chain from the mint.
///
/// `db_reputation_service.rs::get_claim_outcomes` mints a bypass viewer from
/// the privileged pool and then runs the read on an injected `PgPool`. It has
/// no production constructor — `DbReputationService::new` and
/// `::with_scoped_pool` have no caller outside their own file — which is the
/// only reason it is a register entry rather than a live defect. Owner:
/// `D-PR17-hybrid-shape-lint`, re-owned by PR-17 to the `acquire_as`
/// conversion PR.
///
/// Fixing it means routing the read onto the maintenance connection, which is a
/// signature change to a public struct and therefore not this batch's to make.
const EXPECTED_HYBRIDS: &[(&str, &str)] = &[(
    "epigraph-jobs/src/db_reputation_service.rs",
    "get_claim_outcomes",
)];

/// Remove comments, leaving code positions otherwise intact.
///
/// Line and block comments both go. String and char literals are tracked so a
/// DSN like `"postgres://host/db"` does not read as a line comment and take the
/// rest of the line with it — which would silently delete real matches.
fn strip_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    let mut in_str = false;
    let mut in_char = false;
    let mut block_depth = 0usize;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if block_depth > 0 {
            if c == '/' && next == Some('*') {
                block_depth += 1;
                i += 2;
                continue;
            }
            if c == '*' && next == Some('/') {
                block_depth -= 1;
                i += 2;
                continue;
            }
            if c == '\n' {
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if in_str {
            out.push(c);
            if c == '\\' {
                if let Some(n) = next {
                    out.push(n);
                }
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if in_char {
            out.push(c);
            if c == '\\' {
                if let Some(n) = next {
                    out.push(n);
                }
                i += 2;
                continue;
            }
            if c == '\'' {
                in_char = false;
            }
            i += 1;
            continue;
        }
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            block_depth = 1;
            i += 2;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        // A lifetime (`'a`) is not a char literal. Only treat `'` as opening one
        // when the character two ahead closes it or an escape follows.
        if c == '\'' && (b.get(i + 2) == Some(&'\'') || next == Some('\\')) {
            in_char = true;
            out.push(c);
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Remove `#[cfg(test)]` MODULES, and only those.
///
/// # Why not `src.split("#[cfg(test)]").next()`
///
/// That was the first version and it is wrong in the direction that certifies a
/// broken tree as clean: it keeps only the text BEFORE the first occurrence, so
/// a file whose `#[cfg(test)]` sits anywhere but the end loses all production
/// code after it. Measured across the eight scan roots: **125 files** carry a
/// `#[cfg(test)]` that is not in the final stretch, and
/// `epigraph-api/src/routes/agents.rs` carries one at 4% of the file — the
/// truncating version scanned 4% of it and reported a clean run.
///
/// This walks braces from the `mod NAME {` that follows the attribute and
/// removes exactly that block. A `#[cfg(test)]` on anything other than a module
/// — a helper fn, a field, an import — is deliberately LEFT IN the scan: over-
/// scanning can only produce a finding to triage, whereas under-scanning
/// produces silence.
fn strip_cfg_test_modules(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i..].starts_with(&['#', '[', 'c']) && src_at(&b, i, "#[cfg(test)]") {
            // Look ahead for `mod <name> {` with only whitespace, attributes and
            // visibility between. If it is not a module, fall through and keep it.
            if let Some(open) = module_open_brace(&b, i + "#[cfg(test)]".len()) {
                let mut depth = 0usize;
                let mut j = open;
                let mut in_str = false;
                while j < b.len() {
                    let c = b[j];
                    if in_str {
                        if c == '\\' {
                            j += 2;
                            continue;
                        }
                        if c == '"' {
                            in_str = false;
                        }
                    } else if c == '"' {
                        in_str = true;
                    } else if c == '{' {
                        depth += 1;
                    } else if c == '}' {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    j += 1;
                }
                // Preserve line structure so `regions` still splits sanely.
                for c in &b[i..j] {
                    if *c == '\n' {
                        out.push('\n');
                    }
                }
                i = j;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn src_at(b: &[char], i: usize, needle: &str) -> bool {
    let n: Vec<char> = needle.chars().collect();
    b.len() >= i + n.len() && b[i..i + n.len()] == n[..]
}

/// From just after a `#[cfg(test)]`, the index of the `{` that opens the module
/// it annotates — or `None` if it annotates something that is not a module.
fn module_open_brace(b: &[char], mut i: usize) -> Option<usize> {
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if src_at(b, i, "pub(crate) ") {
            i += "pub(crate) ".len();
            continue;
        }
        if src_at(b, i, "pub ") {
            i += "pub ".len();
            continue;
        }
        if src_at(b, i, "mod ") {
            let mut j = i + "mod ".len();
            while j < b.len() && b[j] != '{' && b[j] != ';' {
                j += 1;
            }
            return (b.get(j) == Some(&'{')).then_some(j);
        }
        return None;
    }
    None
}

/// A function-sized region of a source file: its name, and its body text.
struct Region {
    name: String,
    body: String,
}

/// Split a Rust source file into function-sized regions.
///
/// Text, not AST, and the module doc says why that is acceptable here. A region
/// runs from one `fn` header line to the next, so a nested `fn` starts a new
/// region and its enclosing tail is attributed to the nested one. That can only
/// SPLIT a body, never merge two — so it can lose a finding whose mint and
/// spend straddle a nested `fn`, and it cannot invent one.
fn regions(src: &str) -> Vec<Region> {
    let mut out: Vec<Region> = Vec::new();
    let mut current: Option<Region> = None;
    for line in src.lines() {
        if let Some(name) = fn_name(line) {
            if let Some(r) = current.take() {
                out.push(r);
            }
            current = Some(Region {
                name,
                body: String::new(),
            });
        }
        if let Some(r) = current.as_mut() {
            r.body.push_str(line);
            r.body.push('\n');
        }
    }
    if let Some(r) = current.take() {
        out.push(r);
    }
    out
}

/// The function name on a `fn` header line, if the line is one.
fn fn_name(line: &str) -> Option<String> {
    let t = line.trim_start();
    let rest = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub(super) "))
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    let rest = rest.strip_prefix("const ").unwrap_or(rest);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("unsafe ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn rust_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `crates/<crate>/src/...` suffix of a path, for stable register keys.
fn key_for(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    s.split_once("crates/").map_or_else(
        || s.trim_start_matches("../").to_string(),
        |(_, rest)| rest.to_string(),
    )
}

// ===========================================================================
// THE CROSS-FUNCTION PASS — what closed known limit (b)
// ===========================================================================
//
// Text, not a type checker, and every approximation below is chosen to fail
// toward a finding to triage rather than toward silence, except where the
// module doc's KNOWN LIMITS name the direction explicitly.

/// How many calls away from its mint a bypass is followed.
///
/// Four covers every chain in the tree today with room to spare: the longest
/// measured is two (`server.rs` tool method -> `tools/` function -> engine
/// helper). The bound exists so an over-approximated resolution cannot walk
/// the whole call graph; `the_hop_bound_is_the_documented_one` pins it.
const MAX_HOPS: usize = 4;

/// Crates a bypass is followed INTO but not THROUGH.
///
/// `epigraph-db`'s repo functions legitimately take `(executor, viewer)` — that
/// is the whole design of the viewer-spliced read path — so following a bypass
/// through them would only walk the repo layer's own internals. They are still
/// CHECKED on arrival: a repo method that names `self.pool` and is handed a
/// bypass is exactly the hybrid, one layer down.
const SINK_CRATES: &[&str] = &["epigraph-db"];

/// Call-shaped keywords, never functions.
const NOT_CALLS: &[&str] = &[
    "if", "while", "match", "for", "in", "return", "loop", "as", "move", "fn", "impl", "where",
    "let", "else", "mut", "ref", "unsafe", "async", "await", "dyn", "break", "continue",
];

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// If a string, raw-string, byte-string or char literal starts at `i`, the
/// index just past its end. A lifetime (`'a`) is not a literal.
fn literal_end(b: &[char], i: usize) -> Option<usize> {
    let prev_ident = i > 0 && is_ident(b[i - 1]);
    match b[i] {
        '"' => Some(quoted_end(b, i + 1)),
        'b' if !prev_ident && b.get(i + 1) == Some(&'"') => Some(quoted_end(b, i + 2)),
        'b' if !prev_ident && b.get(i + 1) == Some(&'\'') => char_end(b, i + 1),
        'b' if !prev_ident && b.get(i + 1) == Some(&'r') => raw_end(b, i + 2),
        'r' if !prev_ident => raw_end(b, i + 1),
        '\'' => char_end(b, i),
        _ => None,
    }
}

/// From just after an opening `"`, the index just past the closing one.
fn quoted_end(b: &[char], mut k: usize) -> usize {
    while k < b.len() {
        match b[k] {
            '\\' => k += 2,
            '"' => return k + 1,
            _ => k += 1,
        }
    }
    b.len()
}

/// From just after the `r` of a raw string, the index just past its end — or
/// `None` when no `#*"` follows, i.e. the `r` was an identifier (`r#type`).
fn raw_end(b: &[char], k: usize) -> Option<usize> {
    let mut h = 0;
    while b.get(k + h) == Some(&'#') {
        h += 1;
    }
    if b.get(k + h) != Some(&'"') {
        return None;
    }
    let mut j = k + h + 1;
    while j < b.len() {
        if b[j] == '"' && (1..=h).all(|n| b.get(j + n) == Some(&'#')) {
            return Some(j + 1 + h);
        }
        j += 1;
    }
    Some(b.len())
}

/// At a `'`: the index just past a char literal, or `None` for a lifetime.
fn char_end(b: &[char], i: usize) -> Option<usize> {
    if b.get(i + 1) == Some(&'\\') {
        let mut k = i + 3;
        while k < b.len() && b[k] != '\'' {
            k += 1;
        }
        return Some((k + 1).min(b.len()));
    }
    (b.get(i + 2) == Some(&'\'')).then_some(i + 3)
}

/// `src` with the CONTENTS of every literal blanked to spaces, newlines kept.
///
/// Call, `let` and brace parsing run on this, so a `{` in a format string or a
/// `"` inside a raw SQL string cannot move a block boundary, and an identifier
/// that only appears inside a message cannot look like an argument. Pool and
/// mint MATCHING still runs on the unblanked text, as it always has.
fn blank_literals(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = b.clone();
    let mut i = 0usize;
    while i < b.len() {
        match literal_end(&b, i) {
            Some(end) if end > i + 1 => {
                for k in i..end {
                    if b[k] != '\n' {
                        out[k] = ' ';
                    }
                }
                out[i] = '"';
                out[end - 1] = '"';
                i = end;
            }
            _ => i += 1,
        }
    }
    out.into_iter().collect()
}

/// The self type an `impl` (or `trait`) header line opens, if the line is one.
fn impl_header_type(line: &str) -> Option<String> {
    let t = line.trim_start();
    let t = t.strip_prefix("unsafe ").unwrap_or(t);
    if let Some(r) = t.strip_prefix("impl") {
        if !(r.starts_with('<') || r.starts_with(' ')) {
            return None;
        }
        let r = skip_leading_angle(r.trim_start());
        let head = r.split('{').next().unwrap_or(r);
        let head = head.split(" where").next().unwrap_or(head);
        let ty = top_level_for(head).map_or(head, |i| &head[i + " for ".len()..]);
        return type_name(ty);
    }
    let t = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    let name: String = t
        .strip_prefix("trait ")?
        .chars()
        .take_while(|c| is_ident(*c))
        .collect();
    (!name.is_empty()).then_some(name)
}

/// `s` without a leading balanced `<...>` (an `impl`'s own generics).
fn skip_leading_angle(s: &str) -> &str {
    if !s.starts_with('<') {
        return s;
    }
    let mut depth = 0i32;
    let mut prev = ' ';
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' if prev != '-' => {
                depth -= 1;
                if depth == 0 {
                    return &s[i + 1..];
                }
            }
            _ => {}
        }
        prev = c;
    }
    s
}

/// Byte offset of ` for ` outside any `<...>`, in an `impl` header.
fn top_level_for(head: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut prev = ' ';
    for (i, c) in head.char_indices() {
        match c {
            '<' => depth += 1,
            '>' if prev != '-' => depth -= 1,
            ' ' if depth == 0 && head[i..].starts_with(" for ") => return Some(i),
            _ => {}
        }
        prev = c;
    }
    None
}

/// The last path segment of a type, without generics or references.
fn type_name(ty: &str) -> Option<String> {
    let mut t = ty.trim();
    loop {
        let before = t;
        t = t.trim_start_matches('&').trim_start();
        if t.starts_with('\'') {
            t = t.split_once(' ').map_or("", |(_, r)| r).trim_start();
        }
        for kw in ["mut ", "dyn "] {
            t = t.strip_prefix(kw).unwrap_or(t).trim_start();
        }
        if t == before {
            break;
        }
    }
    let path: String = t
        .chars()
        .take_while(|c| is_ident(*c) || *c == ':')
        .collect();
    let last = path.rsplit("::").next().unwrap_or("").to_string();
    (!last.is_empty()).then_some(last)
}

/// For each line of literal-blanked `code`, the innermost `impl`/`trait` self
/// type open at that line's start. Brace depth, so an `impl` nested in a
/// function body and a free function after an `impl` block both come out right.
fn impl_context_by_line(code: &str) -> Vec<Option<String>> {
    let mut out = Vec::new();
    let mut stack: Vec<(String, usize)> = Vec::new();
    let mut depth = 0usize;
    let mut pending: Option<String> = None;
    for line in code.lines() {
        out.push(stack.last().map(|(t, _)| t.clone()));
        if let Some(t) = impl_header_type(line) {
            pending = Some(t);
        }
        for c in line.chars() {
            match c {
                '{' => {
                    if let Some(t) = pending.take() {
                        stack.push((t, depth));
                    }
                    depth += 1;
                }
                '}' => {
                    depth = depth.saturating_sub(1);
                    if stack.last().is_some_and(|(_, d)| *d == depth) {
                        stack.pop();
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Index of the bracket closing the one opened at `open`, counting all three
/// bracket kinds together (the input is literal-blanked).
fn match_close(c: &[char], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (k, ch) in c.iter().enumerate().skip(open) {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(k);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split on commas outside any bracket. `angle` also treats `<...>` as a
/// bracket, which is right for a parameter list and wrong for call arguments
/// (where `<` is a comparison).
fn split_top_level(text: &str, angle: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut prev = ' ';
    for c in text.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            '<' if angle => depth += 1,
            '>' if angle && prev != '-' => depth -= 1,
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
                prev = c;
                continue;
            }
            _ => {}
        }
        cur.push(c);
        prev = c;
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Byte offset of the first `:` that is not half of a `::`.
fn single_colon(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    (0..b.len())
        .find(|&i| b[i] == b':' && b.get(i + 1) != Some(&b':') && (i == 0 || b[i - 1] != b':'))
}

/// The identifiers a pattern binds: lowercase words that are not path
/// segments, keywords or `_`. `Parameters(params)` binds `params`;
/// `(mut conn, viewer)` binds `conn` and `viewer`.
fn pattern_idents(pat: &str) -> Vec<String> {
    let c: Vec<char> = pat.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < c.len() {
        if !is_ident(c[i]) || (i > 0 && is_ident(c[i - 1])) {
            i += 1;
            continue;
        }
        let s = i;
        while i < c.len() && is_ident(c[i]) {
            i += 1;
        }
        let w: String = c[s..i].iter().collect();
        let is_path = c.get(i) == Some(&':') && c.get(i + 1) == Some(&':');
        let lower = w.starts_with(|ch: char| ch.is_lowercase() || ch == '_');
        if lower && !is_path && !matches!(w.as_str(), "mut" | "ref" | "box" | "_") {
            out.push(w);
        }
    }
    out
}

#[derive(Debug, Clone)]
struct Param {
    names: Vec<String>,
    ty: String,
    is_self: bool,
}

fn parse_param(p: &str) -> Param {
    let p = p.trim();
    let (pat, ty) = single_colon(p).map_or((p, ""), |i| (&p[..i], p[i + 1..].trim()));
    let mut bare = pat.trim().trim_start_matches('&').trim_start();
    if bare.starts_with('\'') {
        bare = bare.split_once(' ').map_or("", |(_, r)| r).trim_start();
    }
    let bare = bare.strip_prefix("mut ").unwrap_or(bare).trim();
    Param {
        names: if bare == "self" {
            Vec::new()
        } else {
            pattern_idents(pat)
        },
        ty: ty.to_string(),
        is_self: bare == "self",
    }
}

/// A function's parameters and its return-type text, from its literal-blanked
/// region.
fn parse_signature(code: &str, name: &str) -> (Vec<Param>, String) {
    let c: Vec<char> = code.chars().collect();
    let needle: Vec<char> = format!("fn {name}").chars().collect();
    let Some(start) = (0..c.len()).find(|&i| c[i..].starts_with(&needle)) else {
        return (Vec::new(), String::new());
    };
    let mut j = start + needle.len();
    let after: String = c[j..].iter().collect();
    let skipped = skip_leading_angle(after.trim_start());
    j = c.len() - skipped.chars().count();
    while j < c.len() && c[j].is_whitespace() {
        j += 1;
    }
    if c.get(j) != Some(&'(') {
        return (Vec::new(), String::new());
    }
    let Some(close) = match_close(&c, j) else {
        return (Vec::new(), String::new());
    };
    let params: String = c[j + 1..close].iter().collect();
    let params = split_top_level(&params, true)
        .iter()
        .filter(|p| !p.trim().is_empty())
        .map(|p| parse_param(p))
        .collect();
    let tail: String = c[close + 1..]
        .iter()
        .take_while(|ch| **ch != '{' && **ch != ';')
        .collect();
    let ret = tail
        .trim()
        .strip_prefix("->")
        .unwrap_or("")
        .split("where")
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    (params, ret)
}

/// One production function, as the cross-function pass sees it.
#[derive(Debug)]
struct FnSite {
    /// Register key, e.g. `epigraph-mcp/src/tools/dedup_sweep.rs`.
    file: String,
    /// `epigraph-mcp`, or `epigraph-mcp:bin:main` for a binary's own root.
    krate: String,
    name: String,
    /// The `impl`/`trait` self type the function sits in, if any.
    impl_type: Option<String>,
    /// No `pub` of any kind: callable from its own file only, for our purposes.
    private: bool,
    params: Vec<Param>,
    ret: String,
    /// Comment- and test-module-stripped region text, exactly as [`regions`]
    /// produces it. Mints, holds and foreign pools match HERE.
    body: String,
    /// `body` with literal contents blanked: calls and `let`s parse HERE.
    code: String,
}

impl FnSite {
    fn key(&self) -> (String, String) {
        (self.file.clone(), self.name.clone())
    }
    fn label(&self) -> String {
        match &self.impl_type {
            Some(t) => format!("{}::{t}::{}", self.file, self.name),
            None => format!("{}::{}", self.file, self.name),
        }
    }
}

/// Which crate a file compiles into. A binary root (`src/main.rs`,
/// `src/bin/*.rs`) is its own crate, so a bare call in one binary never
/// resolves to a same-named helper in another.
fn crate_of(file: &str) -> String {
    let krate = file.split('/').next().unwrap_or_default();
    match file.split_once("/src/") {
        Some((_, "main.rs")) => format!("{krate}:bin:main"),
        Some((_, rest)) if rest.starts_with("bin/") => {
            let stem = rest["bin/".len()..].split('/').next().unwrap_or_default();
            format!("{krate}:bin:{}", stem.trim_end_matches(".rs"))
        }
        _ => krate.to_string(),
    }
}

/// The library a binary links, or the crate itself.
fn lib_crate(krate: &str) -> &str {
    krate.split(":bin:").next().unwrap_or(krate)
}

/// Split one file's production text into [`FnSite`]s, on the SAME header
/// lines [`regions`] uses, so a same-region finding keys identically here.
fn fn_sites(file: &str, prod: &str) -> Vec<FnSite> {
    let krate = crate_of(file);
    let code = blank_literals(prod);
    let ctx = impl_context_by_line(&code);
    let raw: Vec<&str> = prod.lines().collect();
    let blanked: Vec<&str> = code.lines().collect();
    let mut out = Vec::new();
    let mut open: Option<(usize, String)> = None;
    let close_at = |start: usize, end: usize, name: String, out: &mut Vec<FnSite>| {
        let body: String = raw[start..end].iter().map(|l| format!("{l}\n")).collect();
        let code: String = blanked
            .get(start..end.min(blanked.len()))
            .unwrap_or(&[])
            .iter()
            .map(|l| format!("{l}\n"))
            .collect();
        let (params, ret) = parse_signature(&code, &name);
        out.push(FnSite {
            file: file.to_string(),
            krate: krate.clone(),
            impl_type: ctx.get(start).cloned().flatten(),
            private: !raw[start].trim_start().starts_with("pub"),
            name,
            params,
            ret,
            body,
            code,
        });
    };
    for (n, line) in raw.iter().enumerate() {
        if let Some(name) = fn_name(line) {
            if let Some((start, prev)) = open.take() {
                close_at(start, n, prev, &mut out);
            }
            open = Some((n, name));
        }
    }
    if let Some((start, name)) = open.take() {
        close_at(start, raw.len(), name, &mut out);
    }
    out
}

/// A function that hands its caller a bypass: it returns a
/// `MaintenanceSession` (by any wrapper type), or returns a `Viewer` it minted.
/// Calling one is minting, wherever it is in scope.
///
/// Derived from the tree, never listed: `routes/privatization.rs`'s private
/// `maintenance(state)` and `epigraph-cli`'s `MaintenancePool::viewer` are the
/// two whose names are NOT already in [`MINTS`], and their callers contain no
/// mint spelling of their own.
struct Wrapper {
    name: String,
    file: String,
    krate: String,
    private: bool,
}

impl Wrapper {
    fn in_scope_for(&self, site: &FnSite) -> bool {
        if self.private {
            self.file == site.file
        } else {
            lib_crate(&site.krate) == lib_crate(&self.krate)
        }
    }
}

/// Does `text` call `name(` — at a word boundary, and not as its definition?
fn calls_name(text: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    text.match_indices(&needle).any(|(i, _)| {
        let before = &text[..i];
        let boundary = !before.chars().next_back().is_some_and(is_ident);
        boundary && !before.trim_end().ends_with("fn")
    })
}

/// Does `text` mention the local `ident` in a position that can carry the
/// bypass? Not as a field of something else (`x.viewer`), not as a path
/// segment (`viewer::`), and not through the two session accessors that hand
/// out something other than the viewer (`.pool()`, `.conn()`).
fn mentions(text: &str, ident: &str) -> bool {
    text.match_indices(ident).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let rest = &text[i + ident.len()..];
        let after = rest.chars().next();
        !before.is_some_and(|c| is_ident(c) || c == '.')
            && !after.is_some_and(is_ident)
            && !rest.starts_with("::")
            && !rest.trim_start().starts_with(".pool(")
            && !rest.trim_start().starts_with(".conn(")
    })
}

/// Every `let PATTERN = EXPR;` in a literal-blanked body, as `(pattern, expr)`.
fn let_statements(code: &str) -> Vec<(String, String)> {
    let c: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= c.len() {
        let at_let = c[i..].starts_with(&['l', 'e', 't', ' ']) && (i == 0 || !is_ident(c[i - 1]));
        if !at_let {
            i += 1;
            continue;
        }
        let mut j = i + 4;
        let mut depth = 0i32;
        let mut eq = None;
        while j < c.len() {
            match c[j] {
                '(' | '[' | '{' | '<' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                '>' if c[j - 1] != '-' => depth -= 1,
                '=' if depth == 0
                    && c.get(j + 1) != Some(&'=')
                    && c.get(j + 1) != Some(&'>')
                    && !"=!<>+-*/%&|^".contains(c[j - 1]) =>
                {
                    eq = Some(j);
                    break;
                }
                ';' => break,
                _ => {}
            }
            j += 1;
        }
        let Some(eq) = eq else {
            i += 4;
            continue;
        };
        let mut k = eq + 1;
        let mut depth = 0i32;
        while k < c.len() {
            match c[k] {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                }
                ';' if depth == 0 => break,
                _ => {}
            }
            k += 1;
        }
        let pat: String = c[i + 4..eq].iter().collect();
        let pat = single_colon(&pat).map_or(pat.clone(), |x| pat[..x].to_string());
        out.push((pat, c[eq + 1..k].iter().collect()));
        i = k;
    }
    out
}

/// How a call names its callee.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CallKind {
    /// `self.name(..)`
    SelfMethod,
    /// `expr.name(..)` — receiver type unknown to a text scan.
    Method,
    /// `Self::name(..)`
    SelfPath,
    /// `Type::name(..)`, keyed on the last type segment.
    TypePath(String),
    /// `module::path::name(..)`, segments before the name.
    ModPath(Vec<String>),
    /// `name(..)`
    Bare,
}

#[derive(Debug)]
struct Call {
    name: String,
    kind: CallKind,
    args: Vec<String>,
}

/// Every call in a literal-blanked body. Macros (`name!(`), tuple-struct and
/// variant constructors (uppercase names), keywords and the function's own
/// definition are skipped; so is anything behind a turbofish or a qualified
/// `<T as Trait>::` path, which text cannot resolve.
fn calls_in(code: &str) -> Vec<Call> {
    let c: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    for p in 0..c.len() {
        if c[p] != '(' {
            continue;
        }
        let mut s = p;
        while s > 0 && is_ident(c[s - 1]) {
            s -= 1;
        }
        if s == p {
            continue;
        }
        let name: String = c[s..p].iter().collect();
        if name.starts_with(|ch: char| ch.is_uppercase() || ch.is_ascii_digit())
            || NOT_CALLS.contains(&name.as_str())
        {
            continue;
        }
        let before: String = c[..s].iter().collect();
        if before.trim_end().ends_with("fn") && before.trim_end().len() < before.len() {
            continue;
        }
        let kind = if s > 0 && c[s - 1] == '.' {
            let mut rs = s - 1;
            while rs > 0 && is_ident(c[rs - 1]) {
                rs -= 1;
            }
            let recv: String = c[rs..s - 1].iter().collect();
            let prev = if rs > 0 { c[rs - 1] } else { ' ' };
            if recv == "self" && !is_ident(prev) && prev != '.' {
                CallKind::SelfMethod
            } else {
                CallKind::Method
            }
        } else if s >= 2 && c[s - 1] == ':' && c[s - 2] == ':' {
            let mut segs = Vec::new();
            let mut e = s - 2;
            loop {
                let mut b = e;
                while b > 0 && is_ident(c[b - 1]) {
                    b -= 1;
                }
                if b == e {
                    segs.clear();
                    break;
                }
                segs.push(c[b..e].iter().collect::<String>());
                if b >= 2 && c[b - 1] == ':' && c[b - 2] == ':' {
                    e = b - 2;
                } else {
                    break;
                }
            }
            let Some(last) = segs.first().cloned() else {
                continue;
            };
            segs.reverse();
            if last == "Self" {
                CallKind::SelfPath
            } else if last.starts_with(char::is_uppercase) {
                CallKind::TypePath(last)
            } else {
                CallKind::ModPath(segs)
            }
        } else {
            CallKind::Bare
        };
        let Some(close) = match_close(&c, p) else {
            continue;
        };
        let inner: String = c[p + 1..close].iter().collect();
        let args = if inner.trim().is_empty() {
            Vec::new()
        } else {
            split_top_level(&inner, false)
        };
        out.push(Call { name, kind, args });
    }
    out
}

/// Every production function in the scanned tree, with what resolution needs.
struct Index {
    sites: Vec<FnSite>,
    by_name: BTreeMap<String, Vec<usize>>,
    /// Module names per library crate, from its file layout.
    modules: BTreeMap<String, BTreeSet<String>>,
    wrappers: Vec<Wrapper>,
}

impl Index {
    /// `files` are `(register key, raw source)`; stripping happens here.
    fn build(files: &[(String, String)]) -> Self {
        let mut sites = Vec::new();
        let mut modules: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (file, src) in files {
            // `#[cfg(test)]` bodies are excluded: a test that stands a pool in
            // for a maintenance one is a fixture choice, not a production path.
            let prod = strip_cfg_test_modules(&strip_comments(src));
            if let Some((krate, rest)) = file.split_once("/src/") {
                for seg in rest.trim_end_matches(".rs").split('/') {
                    if !matches!(seg, "mod" | "lib" | "main") {
                        modules
                            .entry(krate.to_string())
                            .or_default()
                            .insert(seg.to_string());
                    }
                }
            }
            sites.extend(fn_sites(file, &prod));
        }
        let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, s) in sites.iter().enumerate() {
            by_name.entry(s.name.clone()).or_default().push(i);
        }
        let mut ix = Self {
            sites,
            by_name,
            modules,
            wrappers: Vec::new(),
        };
        ix.derive_wrappers();
        ix
    }

    /// Fixpoint: anything returning a session is a wrapper; anything returning
    /// a `Viewer` it minted (directly or through a wrapper) is one too.
    fn derive_wrappers(&mut self) {
        let mut is_wrapper: Vec<bool> = self
            .sites
            .iter()
            .map(|s| s.ret.contains("MaintenanceSession"))
            .collect();
        loop {
            self.wrappers = self
                .sites
                .iter()
                .zip(&is_wrapper)
                .filter(|(_, w)| **w)
                .map(|(s, _)| Wrapper {
                    name: s.name.clone(),
                    file: s.file.clone(),
                    krate: s.krate.clone(),
                    private: s.private,
                })
                .collect();
            let mut changed = false;
            for (s, w) in self.sites.iter().zip(is_wrapper.iter_mut()) {
                if !*w
                    && s.ret.contains("Viewer")
                    && !s.ret.trim_start().starts_with('&')
                    && self.mints_in(&s.body, s)
                {
                    *w = true;
                    changed = true;
                }
            }
            if !changed {
                return;
            }
        }
    }

    /// Does `text`, inside `site`, mint a bypass — by a [`MINTS`] spelling or
    /// by calling a wrapper in scope?
    fn mints_in(&self, text: &str, site: &FnSite) -> bool {
        MINTS.iter().any(|m| text.contains(m))
            || self
                .wrappers
                .iter()
                .any(|w| w.in_scope_for(site) && calls_name(text, &w.name))
    }

    fn is_seed(&self, site: &FnSite) -> bool {
        holds_a_bypass(&site.body) || self.mints_in(&site.body, site)
    }

    /// The locals of `site` that carry the bypass, given the parameters that
    /// arrived carrying it.
    ///
    /// Seeded from `init`, plus any parameter typed `MaintenanceSession`. A
    /// `let` taints its pattern when its initializer mints, or is a tainted
    /// local passed through `&`/`*`/`.clone()`/`.viewer()`/`.split()`. For
    /// `let (conn, viewer) = session.split()` only the VIEWER is tainted: the
    /// connection is the maintenance one, and a callee handed only that is not
    /// holding a bypass. A query RESULT is never tainted — `let rows =
    /// Repo::f(conn, viewer)` binds data, not a viewer.
    fn local_taint(&self, site: &FnSite, init: &BTreeSet<String>) -> BTreeSet<String> {
        let mut t = init.clone();
        for p in &site.params {
            if p.ty.contains("MaintenanceSession") {
                t.extend(p.names.iter().cloned());
            }
        }
        let lets = let_statements(&site.code);
        loop {
            let before = t.len();
            for (pat, expr) in &lets {
                let (carries, split) = self.carries_bypass(expr, &t, site);
                if !carries {
                    continue;
                }
                let names = pattern_idents(pat);
                if split && names.len() == 2 && pat.trim_start().starts_with('(') {
                    t.insert(names[1].clone());
                } else {
                    t.extend(names);
                }
            }
            if t.len() == before {
                return t;
            }
        }
    }

    /// `(does expr yield a bypass, is it a .split())`.
    fn carries_bypass(&self, expr: &str, t: &BTreeSet<String>, site: &FnSite) -> (bool, bool) {
        let mut e = expr.trim();
        let mut split = false;
        loop {
            let before = e;
            for suffix in [
                "?",
                ".await",
                ".clone()",
                ".as_ref()",
                ".viewer()",
                ".split()",
            ] {
                if let Some(x) = e.strip_suffix(suffix) {
                    split |= suffix == ".split()";
                    e = x.trim_end();
                }
            }
            e = e.trim_start_matches(['&', '*']).trim_start();
            e = e.strip_prefix("mut ").unwrap_or(e).trim_start();
            if e == before {
                break;
            }
        }
        if t.contains(e) {
            return (true, split);
        }
        (self.mints_in(expr, site), false)
    }

    fn arg_carries(&self, arg: &str, t: &BTreeSet<String>, site: &FnSite) -> bool {
        self.mints_in(arg, site) || t.iter().any(|v| mentions(arg, v))
    }

    fn is_module(&self, krate: &str, seg: &str) -> bool {
        self.modules
            .get(lib_crate(krate))
            .is_some_and(|m| m.contains(seg))
    }

    /// `epigraph_engine` -> `epigraph-engine`, if that crate is scanned.
    fn crate_for_ident(&self, seg: &str) -> Option<String> {
        let k = seg.replace('_', "-");
        self.modules.contains_key(&k).then_some(k)
    }

    /// The functions a call can reach, never the caller itself.
    ///
    /// Precise where the text says who the callee is (`Type::`, `Self::`,
    /// `self.`, a module path); by name within the caller's own file or crate
    /// for a bare call; and by name over EVERY method for `expr.name(..)`,
    /// because a text scan cannot type the receiver. That last rule
    /// over-approximates, which this lint's policy prefers to silence;
    /// [`Analysis::ambiguous`] records where it fanned out.
    fn resolve(&self, caller: usize, call: &Call) -> Vec<usize> {
        let me = &self.sites[caller];
        let named = |pred: &dyn Fn(&FnSite) -> bool| -> Vec<usize> {
            self.by_name
                .get(&call.name)
                .map(|v| {
                    v.iter()
                        .copied()
                        .filter(|&i| i != caller && pred(&self.sites[i]))
                        .collect()
                })
                .unwrap_or_default()
        };
        let own = |s: &FnSite| s.krate == me.krate || s.krate == lib_crate(&me.krate);
        match &call.kind {
            CallKind::SelfMethod | CallKind::SelfPath => match &me.impl_type {
                Some(t) => named(&|s| own(s) && s.impl_type.as_ref() == Some(t)),
                None => Vec::new(),
            },
            CallKind::TypePath(t) => named(&|s| s.impl_type.as_ref() == Some(t)),
            CallKind::Method => named(&|s| s.impl_type.is_some()),
            CallKind::ModPath(segs) => {
                let first = segs[0].as_str();
                let target = if matches!(first, "crate" | "self" | "super")
                    || self.is_module(&me.krate, first)
                {
                    None
                } else if let Some(k) = self.crate_for_ident(first) {
                    Some(k)
                } else {
                    // An external crate (`sqlx::`, `tokio::`, `std::`...).
                    return Vec::new();
                };
                let all = named(&|s| {
                    s.impl_type.is_none()
                        && target
                            .as_ref()
                            .map_or_else(|| own(s), |k| lib_crate(&s.krate) == k)
                });
                let last = segs.last().map(String::as_str).unwrap_or_default();
                let preferred: Vec<usize> = all
                    .iter()
                    .copied()
                    .filter(|&i| {
                        let f = &self.sites[i].file;
                        f.ends_with(&format!("/{last}.rs"))
                            || f.ends_with(&format!("/{last}/mod.rs"))
                    })
                    .collect();
                if preferred.is_empty() {
                    all
                } else {
                    preferred
                }
            }
            CallKind::Bare => {
                let same_file = named(&|s| s.file == me.file && s.impl_type.is_none());
                if same_file.is_empty() {
                    named(&|s| own(s) && s.impl_type.is_none())
                } else {
                    same_file
                }
            }
        }
    }
}

/// Which of the callee's parameters arrive carrying the bypass.
///
/// Positional when the argument count matches the parameter count (a method
/// call drops the `self` parameter; a path call keeps it, which is UFCS). When
/// it does not match — a closure argument with a top-level comma, a resolution
/// to a same-named function of another arity — every parameter typed `Viewer`
/// or `MaintenanceSession` is taken instead.
fn callee_taint(callee: &FnSite, call: &Call, carrying: &[usize]) -> BTreeSet<String> {
    let effective: Vec<&Param> = match call.kind {
        CallKind::Method | CallKind::SelfMethod => {
            callee.params.iter().filter(|p| !p.is_self).collect()
        }
        _ => callee.params.iter().collect(),
    };
    let mut out = BTreeSet::new();
    if effective.len() == call.args.len() {
        for &k in carrying {
            out.extend(effective[k].names.iter().cloned());
        }
    } else {
        for p in &callee.params {
            if p.ty.contains("Viewer") || p.ty.contains("MaintenanceSession") {
                out.extend(p.names.iter().cloned());
            }
        }
    }
    out
}

/// What one run of the lint found.
#[derive(Default)]
struct Analysis {
    /// Every hybrid, keyed `(file, fn)` where the foreign pool is NAMED, with
    /// the chain of `file::fn` labels from the mint to it (length 1 for a
    /// same-region hybrid).
    findings: BTreeMap<(String, String), Vec<String>>,
    /// Every function the bypass reached, with the chain that reached it.
    reached: BTreeMap<(String, String), Vec<String>>,
    /// Every call edge the pass followed, as `(caller, callee)` keys.
    edges: BTreeSet<((String, String), (String, String))>,
    /// Calls whose name resolved to more than one function: caller label ->
    /// callee labels. Over-approximation, recorded so a finding reached only
    /// through one can be triaged as such.
    ambiguous: BTreeMap<String, BTreeSet<String>>,
}

/// Run both passes over `(register key, raw source)` pairs.
///
/// SEEDS are every function the same-region lint always scanned (a [`MINTS`] or
/// [`HOLDS`] spelling), plus every caller of a derived [`Wrapper`]. From each
/// seed the bypass is followed through calls whose arguments carry it, up to
/// [`MAX_HOPS`], into [`SINK_CRATES`] but not through them. Any function the
/// bypass reaches that names a [`FOREIGN_POOLS`] spelling is a finding — the
/// same over-approximation at function granularity the module doc describes,
/// now applied at the far end of a call as well as at the mint.
fn analyse_sources(files: &[(String, String)]) -> Analysis {
    let ix = Index::build(files);
    let mut a = Analysis::default();
    let mut work: VecDeque<(usize, BTreeSet<String>, Vec<usize>)> = (0..ix.sites.len())
        .filter(|&i| ix.is_seed(&ix.sites[i]))
        .map(|i| (i, BTreeSet::new(), vec![i]))
        .collect();
    let mut seen: HashSet<(usize, BTreeSet<String>)> = HashSet::new();
    let labels =
        |chain: &[usize]| -> Vec<String> { chain.iter().map(|&i| ix.sites[i].label()).collect() };
    while let Some((i, init, chain)) = work.pop_front() {
        if !seen.insert((i, init.clone())) {
            continue;
        }
        let site = &ix.sites[i];
        a.reached
            .entry(site.key())
            .or_insert_with(|| labels(&chain));
        if FOREIGN_POOLS.iter().any(|p| site.body.contains(p)) {
            a.findings
                .entry(site.key())
                .or_insert_with(|| labels(&chain));
        }
        let is_sink = SINK_CRATES.contains(&lib_crate(&site.krate));
        if (is_sink && chain.len() > 1) || chain.len() > MAX_HOPS {
            continue;
        }
        let t = ix.local_taint(site, &init);
        for call in calls_in(&site.code) {
            let carrying: Vec<usize> = call
                .args
                .iter()
                .enumerate()
                .filter(|(_, arg)| ix.arg_carries(arg, &t, site))
                .map(|(k, _)| k)
                .collect();
            if carrying.is_empty() {
                continue;
            }
            let callees: Vec<usize> = ix
                .resolve(i, &call)
                .into_iter()
                .filter(|c| !chain.contains(c))
                .collect();
            if callees.len() > 1 {
                a.ambiguous
                    .entry(site.label())
                    .or_default()
                    .extend(callees.iter().map(|&c| ix.sites[c].label()));
            }
            for c in callees {
                a.edges.insert((site.key(), ix.sites[c].key()));
                let mut next = chain.clone();
                next.push(c);
                work.push_back((c, callee_taint(&ix.sites[c], &call, &carrying), next));
            }
        }
    }
    a
}

/// The production tree under [`SCAN_ROOTS`], as `(register key, raw source)`.
fn tree_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for root in SCAN_ROOTS {
        let mut files = Vec::new();
        rust_files(Path::new(root), &mut files);
        for f in files {
            out.push((
                key_for(&f),
                std::fs::read_to_string(&f).expect("read source"),
            ));
        }
    }
    out.sort();
    out
}

/// The real tree's analysis, computed once per test binary.
fn tree_analysis() -> &'static Analysis {
    static A: OnceLock<Analysis> = OnceLock::new();
    A.get_or_init(|| analyse_sources(&tree_sources()))
}

/// Every production function the bypass reaches that names a foreign pool
/// handle — same-region hybrids and cross-function ones alike.
fn scan() -> BTreeSet<(String, String)> {
    tree_analysis().findings.keys().cloned().collect()
}

/// No production function may mint a bypass viewer and spend it on a pool that
/// is not the maintenance one, except the registered residue.
#[test]
fn no_function_mints_a_bypass_and_names_a_foreign_pool() {
    let analysis = tree_analysis();
    let found = scan();
    let expected: BTreeSet<(String, String)> = EXPECTED_HYBRIDS
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect();

    let unregistered: Vec<String> = found
        .difference(&expected)
        .map(|k| {
            let chain = analysis.findings[k].join("\n      -> ");
            let fanned: Vec<&String> = analysis.findings[k]
                .iter()
                .filter(|l| analysis.ambiguous.contains_key(*l))
                .collect();
            format!(
                "\n  {}::{} names an application pool, reached by the bypass as:\n      {chain}{}",
                k.0,
                k.1,
                if fanned.is_empty() {
                    String::new()
                } else {
                    format!(
                        "\n    (through a call resolved BY NAME to several functions at \
                         {fanned:?} — check it is the one really called)"
                    )
                }
            )
        })
        .collect();
    assert!(
        unregistered.is_empty(),
        "these functions hold a bypass Viewer — minted in their own body or handed \
         to them down the chain shown — and also name an application pool handle. \
         A bypass viewer emits no SQL predicate, so once RLS is FORCEd it returns \
         ZERO rows on a connection the policy applies to — a wrong answer with no \
         error. Route the statement onto the maintenance connection \
         (`MaintenanceSession::split`; pass the session down, not the viewer), or \
         add a row to EXPECTED_HYBRIDS with an owner. Unregistered:{}",
        unregistered.concat()
    );

    let fixed: Vec<_> = expected.difference(&found).collect();
    assert!(
        fixed.is_empty(),
        "these rows are in EXPECTED_HYBRIDS but no longer scan as hybrids. If \
         they were fixed, DELETE the row in the same commit — a register that \
         keeps entries for code that no longer matches is how a ratchet decays \
         into a licence. Stale: {fixed:?}"
    );
}

/// The scanner is not vacuous, in BOTH directions.
///
/// A scanner that matched nothing would satisfy the test above perfectly, and a
/// scanner whose FOREIGN_POOLS list matched nothing in the tree would too. Each
/// arm below fails if the corresponding population empties out.
#[test]
fn the_scanner_is_not_vacuous() {
    let mut minting_regions = 0usize;
    let mut holding_regions = 0usize;
    let mut foreign_pool_regions = 0usize;
    let mut files_seen = 0usize;
    for root in SCAN_ROOTS {
        let mut files = Vec::new();
        rust_files(Path::new(root), &mut files);
        files_seen += files.len();
        for f in files {
            let src = strip_comments(&std::fs::read_to_string(&f).expect("read source"));
            let prod = strip_cfg_test_modules(&src);
            for r in regions(&prod) {
                if MINTS.iter().any(|m| r.body.contains(m)) {
                    minting_regions += 1;
                }
                if HOLDS.iter().any(|h| r.body.contains(h)) {
                    holding_regions += 1;
                }
                if FOREIGN_POOLS.iter().any(|p| r.body.contains(p)) {
                    foreign_pool_regions += 1;
                }
            }
        }
    }
    assert!(
        files_seen > 200,
        "the scan roots resolved to {files_seen} files; the lint is looking at \
         the wrong directory"
    );
    assert!(
        minting_regions >= 5,
        "only {minting_regions} regions mint a bypass. If the mint spellings in \
         MINTS ever go stale the whole lint passes by matching nothing."
    );
    // The three MCP maintenance tool functions take a session, so HOLDS must
    // match at least those; below that the spelling has gone stale and known
    // limit (c) is open again without anything saying so.
    assert!(
        holding_regions >= 3,
        "only {holding_regions} regions name MaintenanceSession. If HOLDS ever \
         goes stale, a function handed a session is invisible again."
    );
    // DELIBERATELY LOW, and not a ratchet. COMPLETION-PLAN 2.1's conversion tail
    // exists to drive `state.db_pool` uses toward zero, so a floor set at
    // today's count would fail a CORRECT tree partway through that work — the
    // failure mode the tenancy recon brief opens by warning about. Five is a
    // number the conversion cannot cross while any application pool handle
    // remains named anywhere, which is all this arm needs to establish.
    assert!(
        foreign_pool_regions >= 5,
        "only {foreign_pool_regions} regions name a foreign pool handle. If \
         FOREIGN_POOLS goes stale the lint passes by matching nothing on the \
         other side."
    );

    // THE CROSS-FUNCTION PASS MUST BE FOLLOWING SOMETHING. A call parser or a
    // resolver that silently stopped matching would leave every assertion
    // above green and put known limit (b) back exactly where it was. The floor
    // is the three `server.rs` -> `tools/` hand-offs, which
    // `the_mcp_maintenance_tools_are_in_reach_and_clean` also pins by name:
    // edges that leave their file and do not end in a sink crate.
    let analysis = tree_analysis();
    let cross_file: Vec<_> = analysis
        .edges
        .iter()
        .filter(|(from, to)| {
            from.0 != to.0
                && !SINK_CRATES
                    .iter()
                    .any(|c| to.0.starts_with(&format!("{c}/")))
        })
        .collect();
    assert!(
        cross_file.len() >= 3,
        "the cross-function pass followed only {} cross-file, non-sink edges: \
         {cross_file:?}. Below three it has lost the MCP maintenance hand-offs, \
         which is the shape known limit (b) was about.",
        cross_file.len()
    );
    assert!(
        analysis.reached.len() > analysis.findings.len() + 20,
        "the bypass reached only {} functions; the pass is not following calls",
        analysis.reached.len()
    );
}

/// THE POSITIVE CONTROL the obligation names, asserted by NAME rather than by
/// absence from a list.
///
/// `routes/claims.rs::find_claims_needing_embeddings` WAS an instance of this
/// shape and PR-15 fixed it; nothing would have caught the regression, because
/// `routes/` is an explicit non-root of the construction lint. It must stay
/// clean, and "it is not in `scan()`" is a weaker statement than it looks —
/// a broken scanner satisfies it too. So this asserts the two halves directly:
/// the function still mints, and it still spends on the maintenance connection.
#[test]
fn the_positive_control_is_still_clean() {
    let src = strip_comments(include_str!("../../epigraph-api/src/routes/claims.rs"));
    let region = regions(&src)
        .into_iter()
        .find(|r| r.name == "find_claims_needing_embeddings")
        .expect("routes/claims.rs must still define find_claims_needing_embeddings");
    assert!(
        MINTS.iter().any(|m| region.body.contains(m)),
        "CALIBRATION: the positive control must still MINT a bypass. If it \
         stopped, this test is passing for the wrong reason and the lint has no \
         clean case to calibrate against."
    );
    assert!(
        region.body.contains("session.split()"),
        "the positive control must spend its bypass on the maintenance \
         connection. `split` is the only accessor that yields the connection \
         and the viewer together."
    );
    assert!(
        !FOREIGN_POOLS.iter().any(|p| region.body.contains(p)),
        "the positive control has regressed to an application pool handle"
    );
    assert!(
        !scan().contains(&(
            "epigraph-api/src/routes/claims.rs".to_string(),
            "find_claims_needing_embeddings".to_string()
        )),
        "and the scanner agrees"
    );
}

/// THE NEGATIVE CONTROL the obligation names, asserted by NAME.
///
/// The register entry must correspond to a function the scanner actually finds.
/// A register row pointing at nothing is how this lint would quietly stop
/// having a calibration case at all.
#[test]
fn the_registered_hybrid_is_really_there() {
    let src = strip_comments(include_str!(
        "../../epigraph-jobs/src/db_reputation_service.rs"
    ));
    let region = regions(&src)
        .into_iter()
        .find(|r| r.name == "get_claim_outcomes")
        .expect("db_reputation_service.rs must still define get_claim_outcomes");
    assert!(
        MINTS.iter().any(|m| region.body.contains(m)),
        "CALIBRATION: the registered hybrid must still mint a bypass"
    );
    assert!(
        FOREIGN_POOLS.iter().any(|p| region.body.contains(p)),
        "CALIBRATION: the registered hybrid must still name a foreign pool \
         handle. If it does not, the row belongs in a DELETE, not here."
    );
}

/// The three MCP maintenance tools, asserted BY NAME: each is in the scanner's
/// reach TWICE OVER — its region names the session type, and the cross-function
/// pass follows the bypass into it from the `server.rs` method that minted it —
/// and each names no foreign pool.
///
/// This is known limit (b)'s measured instance, turned into a calibration
/// case. Before the tools took a `MaintenanceSession` they took a bare
/// `&Viewer` and queried `server.pool`, and this scanner could see neither half.
/// "Not in `scan()`" alone would be satisfied by a broken scanner, so both
/// halves are asserted directly — and the SAME predicate `scan` uses is shown to
/// fire on the regression, so the clean result is not a blind spot.
#[test]
fn the_mcp_maintenance_tools_are_in_reach_and_clean() {
    // The mint-to-spend edges, on the REAL tree. Each resolution has to get
    // past a same-named method in `server.rs` (the caller itself) and land on
    // the free function in the right `tools/` file.
    let edges = &tree_analysis().edges;
    for (tool_file, name) in [
        (
            "epigraph-mcp/src/tools/dedup_sweep.rs",
            "sweep_semantic_duplicates",
        ),
        (
            "epigraph-mcp/src/tools/embeddings.rs",
            "backfill_embeddings",
        ),
        (
            "epigraph-mcp/src/tools/cdst_maintenance.rs",
            "recompute_beliefs",
        ),
    ] {
        let edge = (
            ("epigraph-mcp/src/server.rs".to_string(), name.to_string()),
            (tool_file.to_string(), name.to_string()),
        );
        assert!(
            edges.contains(&edge),
            "the cross-function pass no longer follows the bypass from \
             server.rs::{name} into {tool_file}::{name}. That hand-off is the one \
             known limit (b) was measured on; without this edge a tool that went \
             back to a bare `&Viewer` would be invisible again."
        );
    }

    for (src, name) in [
        (
            include_str!("../../epigraph-mcp/src/tools/dedup_sweep.rs"),
            "sweep_semantic_duplicates",
        ),
        (
            include_str!("../../epigraph-mcp/src/tools/embeddings.rs"),
            "backfill_embeddings",
        ),
        (
            include_str!("../../epigraph-mcp/src/tools/cdst_maintenance.rs"),
            "recompute_beliefs",
        ),
    ] {
        let src = strip_cfg_test_modules(&strip_comments(src));
        let region = regions(&src)
            .into_iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("tools must still define {name}"));
        assert!(
            holds_a_bypass(&region.body),
            "{name} must take the maintenance session. A bare `&Viewer` is still \
             followed by the cross-function pass, but only the session lets the \
             tool run on the maintenance connection at all — which is the fix, \
             not just the visibility."
        );
        assert!(
            !FOREIGN_POOLS.iter().any(|p| region.body.contains(p)),
            "{name} names an application pool handle: its bypass viewer would read \
             zero rows there under row security"
        );
    }

    // The regression, as the scanner sees it.
    let regressed = r#"
pub async fn sweep_semantic_duplicates(
    _server: &EpiGraphMcpFull,
    session: &mut epigraph_db::MaintenanceSession<'_>,
) {
    let (_conn, viewer) = session.split();
    let _ = ClaimRepository::content_hashes_for(&server.pool, viewer, &[]).await;
}
"#;
    let region = regions(regressed)
        .into_iter()
        .next()
        .expect("sample has a region");
    assert!(
        holds_a_bypass(&region.body) && FOREIGN_POOLS.iter().any(|p| region.body.contains(p)),
        "CALIBRATION: a session-holding function that queries `server.pool` must \
         be a finding"
    );
}

// ---------------------------------------------------------------------------
// The cross-function pass, calibrated. Each fixture below ALSO asserts that the
// function-granular predicate alone finds nothing in it, so every one is a case
// the lint could not see before this pass existed.
// ---------------------------------------------------------------------------

fn fixture(files: &[(&str, &str)]) -> Analysis {
    let owned: Vec<(String, String)> = files
        .iter()
        .map(|(k, s)| ((*k).to_string(), (*s).to_string()))
        .collect();
    analyse_sources(&owned)
}

/// What the lint could see before the cross-function pass: one region holding
/// a bypass spelling and naming a foreign pool.
fn same_region_only(files: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for (key, src) in files {
        let prod = strip_cfg_test_modules(&strip_comments(src));
        for r in regions(&prod) {
            if holds_a_bypass(&r.body) && FOREIGN_POOLS.iter().any(|p| r.body.contains(p)) {
                out.insert(((*key).to_string(), r.name));
            }
        }
    }
    out
}

fn keys(pairs: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    pairs
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect()
}

/// The `epigraph-mcp` shape as it stood at `ba6f6d68`, reduced to the lines that
/// decide it: each `server.rs` tool method mints through `maintenance_viewer(`,
/// takes `session.viewer()`, and hands the bare `&Viewer` to a `tools/`
/// function whose statements run on `server.pool`. A request-path tool
/// (`embedding_neighborhood_density`) sits beside them as the control: same
/// file, same `server.pool`, a REQUEST viewer.
const PRE_FIX_MCP: &[(&str, &str)] = &[
    (
        "epigraph-mcp/src/server.rs",
        r#"
use crate::tools;

impl EpiGraphMcpFull {
    #[tool(description = "Sweep a page of the corpus for semantic near-duplicates.")]
    async fn sweep_semantic_duplicates(
        &self,
        Parameters(params): Parameters<crate::types::SweepSemanticDuplicatesParams>,
    ) -> Result<CallToolResult, McpError> {
        let session = crate::maintenance::maintenance_viewer(
            self,
            epigraph_db::visibility::SystemReason::DedupSweep,
        )
        .await?;
        let viewer = session.viewer();
        self.reject_if_read_only()?;
        tools::dedup_sweep::sweep_semantic_duplicates(self, viewer, params).await
    }

    async fn recompute_beliefs(
        &self,
        Parameters(params): Parameters<RecomputeBeliefsParams>,
    ) -> Result<CallToolResult, McpError> {
        let session = crate::maintenance::maintenance_viewer(
            self,
            epigraph_db::visibility::SystemReason::BeliefRecomputation,
        )
        .await?;
        let viewer = session.viewer();
        self.reject_if_read_only()?;
        tools::cdst_maintenance::recompute_beliefs(self, viewer, params).await
    }

    async fn embedding_neighborhood_density(
        &self,
        Parameters(params): Parameters<crate::tools::embeddings::DensityParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;
        crate::tools::embeddings::embedding_neighborhood_density(self, viewer, params).await
    }

    async fn backfill_embeddings(
        &self,
        Parameters(params): Parameters<crate::tools::embeddings::BackfillEmbeddingsParams>,
    ) -> Result<CallToolResult, McpError> {
        let session = crate::maintenance::maintenance_viewer(
            self,
            epigraph_db::visibility::SystemReason::EmbeddingBackfill,
        )
        .await?;
        let viewer = session.viewer();
        self.reject_if_read_only()?;
        crate::tools::embeddings::backfill_embeddings(self, viewer, params).await
    }
}
"#,
    ),
    (
        "epigraph-mcp/src/tools/dedup_sweep.rs",
        r#"
pub async fn sweep_semantic_duplicates(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SweepSemanticDuplicatesParams,
) -> Result<CallToolResult, McpError> {
    let candidates = ClaimRepository::enumerate_current_embedded(
        &server.pool,
        viewer,
        None,
        None,
        0,
        500,
    )
    .await
    .map_err(internal_error)?;
    let _ = (candidates, params);
    todo!()
}
"#,
    ),
    (
        "epigraph-mcp/src/tools/cdst_maintenance.rs",
        r#"
pub async fn recompute_beliefs(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: RecomputeBeliefsParams,
) -> Result<CallToolResult, McpError> {
    let pool = &server.pool;
    let ids = MassFunctionRepository::list_claim_ids(pool, viewer, 500, 0)
        .await
        .map_err(internal_error)?;
    let _ = (ids, params);
    todo!()
}
"#,
    ),
    (
        "epigraph-mcp/src/tools/embeddings.rs",
        r#"
pub async fn embedding_neighborhood_density(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: DensityParams,
) -> Result<CallToolResult, McpError> {
    let r = ClaimRepository::embedding_radius_breakdown(&server.pool, viewer, params.claim_id)
        .await
        .map_err(internal_error)?;
    let _ = r;
    todo!()
}

pub async fn backfill_embeddings(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: BackfillEmbeddingsParams,
) -> Result<CallToolResult, McpError> {
    let rows =
        epigraph_db::ClaimRepository::find_claims_needing_embeddings(&server.pool, viewer, 200)
            .await
            .map_err(internal_error)?;
    let _ = (rows, params);
    todo!()
}
"#,
    ),
];

/// THE DONE-STATE OF `hybrid-lint-cross-function-blind-spot`: the MCP
/// `server.rs` mint spent in `tools/` on `server.pool` is DETECTED, and the
/// `"server.pool"` [`FOREIGN_POOLS`] entry produces real detections — three
/// of them, each reached across a file boundary.
#[test]
fn the_pre_fix_mcp_shape_is_detected_across_files() {
    // BEFORE: the function-granular predicate saw none of it. This is the
    // measurement known limit (b) recorded as "zero detections".
    assert!(
        same_region_only(PRE_FIX_MCP).is_empty(),
        "the fixture must be invisible to the same-region predicate, or it does \
         not exercise the cross-function pass at all"
    );

    let a = fixture(PRE_FIX_MCP);
    assert_eq!(
        a.findings.keys().cloned().collect::<BTreeSet<_>>(),
        keys(&[
            (
                "epigraph-mcp/src/tools/cdst_maintenance.rs",
                "recompute_beliefs"
            ),
            (
                "epigraph-mcp/src/tools/dedup_sweep.rs",
                "sweep_semantic_duplicates"
            ),
            (
                "epigraph-mcp/src/tools/embeddings.rs",
                "backfill_embeddings"
            ),
        ]),
        "exactly the three maintenance tools, and NOT the request-path \
         embedding_neighborhood_density, which spends a request viewer on the \
         same pool"
    );
    for ((file, name), chain) in &a.findings {
        assert_eq!(
            chain,
            &vec![
                format!("epigraph-mcp/src/server.rs::EpiGraphMcpFull::{name}"),
                format!("{file}::{name}"),
            ],
            "each finding must be reached from the server.rs method that minted \
             the bypass, not from anywhere else"
        );
    }
    assert!(
        a.ambiguous.is_empty(),
        "module-path resolution must pick the tools/ function over the \
         same-named server.rs method: {:?}",
        a.ambiguous
    );
}

/// The same shape, reintroduced into the REAL tree: `server.rs`'s real
/// `sweep_semantic_duplicates` goes back to handing a bare `&Viewer` to a
/// `tools/dedup_sweep.rs` function that queries `server.pool`.
///
/// Where the fixture above proves the pass on a reduction, this proves it on
/// the code as it stands — the real `impl` blocks, the real `#[tool]`
/// attributes, the real sibling functions that could mis-resolve.
#[test]
fn a_bare_viewer_hand_off_on_the_real_mcp_surface_is_detected() {
    let mut files = tree_sources();
    let server = files
        .iter_mut()
        .find(|(k, _)| k == "epigraph-mcp/src/server.rs")
        .expect("the tree has epigraph-mcp/src/server.rs");
    let anchor = "tools::dedup_sweep::sweep_semantic_duplicates(self, &mut session, params).await";
    assert!(
        server.1.contains(anchor),
        "server.rs no longer contains `{anchor}`; update this regression to the \
         current hand-off"
    );
    server.1 = server.1.replacen(
        anchor,
        "{ let viewer = session.viewer(); \
         tools::dedup_sweep::regressed_sweep(self, viewer, params).await }",
        1,
    );
    let tool = files
        .iter_mut()
        .find(|(k, _)| k == "epigraph-mcp/src/tools/dedup_sweep.rs")
        .expect("the tree has epigraph-mcp/src/tools/dedup_sweep.rs");
    tool.1.push_str(
        "\npub async fn regressed_sweep(\n    server: &EpiGraphMcpFull,\n    \
         viewer: &epigraph_db::visibility::Viewer,\n    \
         params: SweepSemanticDuplicatesParams,\n) -> Result<CallToolResult, McpError> {\n    \
         let _ = ClaimRepository::content_hashes_for(&server.pool, viewer, &[]).await;\n    \
         todo!()\n}\n",
    );

    let a = analyse_sources(&files);
    let key = (
        "epigraph-mcp/src/tools/dedup_sweep.rs".to_string(),
        "regressed_sweep".to_string(),
    );
    assert_eq!(
        a.findings.get(&key),
        Some(&vec![
            "epigraph-mcp/src/server.rs::EpiGraphMcpFull::sweep_semantic_duplicates".to_string(),
            "epigraph-mcp/src/tools/dedup_sweep.rs::regressed_sweep".to_string(),
        ]),
        "the regressed hand-off must be a finding, reached from the real \
         server.rs mint"
    );
    let mut expected = scan();
    expected.insert(key);
    assert_eq!(
        a.findings.keys().cloned().collect::<BTreeSet<_>>(),
        expected,
        "and nothing else in the tree may change"
    );
}

/// A WRAPPER THAT RETURNS A SESSION is a mint for its callers.
/// `routes/privatization.rs`'s private `maintenance(state)` is the live
/// instance: its ten callers contain no [`MINTS`] or [`HOLDS`] spelling, so
/// before wrappers were derived an app-pool statement added to any of them was
/// invisible.
#[test]
fn a_session_returning_wrapper_is_a_mint_for_its_callers() {
    let files: &[(&str, &str)] = &[(
        "epigraph-api/src/routes/privatization.rs",
        r#"
async fn maintenance(state: &AppState) -> Result<epigraph_db::MaintenanceSession<'_>, ApiError> {
    state
        .maintenance_viewer(SystemReason::PrivatizationSelection)
        .await
        .map_err(|e| ApiError::InternalError { message: e.to_string() })
}

pub async fn approve_plan(
    State(state): State<AppState>,
    Path(plan_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut session = maintenance(&state).await?;
    let (_maint, bypass) = session.split();
    let rows = load_plan_rows(&state, bypass, plan_id).await?;
    Ok(Json(serde_json::json!({ "rows": rows })))
}

async fn load_plan_rows(
    state: &AppState,
    viewer: &Viewer,
    plan_id: Uuid,
) -> Result<Vec<PlanRow>, ApiError> {
    PrivatizationRepository::rows(&state.db_pool, viewer, plan_id)
        .await
        .map_err(Into::into)
}

pub async fn abort_plan(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let session = maintenance(&state).await?;
    let n = PrivatizationRepository::count(&state.db_pool, session.viewer()).await?;
    Ok(Json(serde_json::json!({ "n": n })))
}
"#,
    )];
    assert!(same_region_only(files).is_empty());
    let a = fixture(files);
    assert_eq!(
        a.findings.keys().cloned().collect::<BTreeSet<_>>(),
        keys(&[
            ("epigraph-api/src/routes/privatization.rs", "abort_plan"),
            ("epigraph-api/src/routes/privatization.rs", "load_plan_rows"),
        ]),
        "a caller of the wrapper that names the app pool itself (abort_plan) and \
         a helper it hands the bypass to (load_plan_rows) are both hybrids"
    );
}

/// What the pass must NOT follow, so it does not drown the register in noise.
///
/// * A REQUEST viewer. Every request-path function takes `viewer: &Viewer`
///   from its caller's own session; the type name alone says nothing.
/// * The maintenance CONNECTION. `split()` yields `(conn, viewer)`; a helper
///   handed only the connection holds no bypass.
/// * A query RESULT. `let rows = Repo::f(conn, bypass)` binds data.
/// * The session's `pool()`. It is the privileged pool the session came from.
#[test]
fn request_viewers_connections_and_results_are_not_followed() {
    let files: &[(&str, &str)] = &[
        (
            "epigraph-api/src/routes/things.rs",
            r#"
pub async fn list_things(
    State(state): State<AppState>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<Vec<Thing>>, ApiError> {
    let viewer = crate::viewer::request_viewer(&state, auth).await?;
    render(&state, &viewer).await
}

async fn render(state: &AppState, viewer: &Viewer) -> Result<Json<Vec<Thing>>, ApiError> {
    Ok(Json(ThingRepository::list(&state.db_pool, viewer).await?))
}

pub async fn repair(State(state): State<AppState>) -> Result<(), ApiError> {
    let mut session = state.maintenance_viewer(SystemReason::DedupSweep).await?;
    let maint_pool = session.pool();
    let (maint, bypass) = session.split();
    write_audit(&mut *maint).await?;
    let rows = ThingRepository::broken(&mut *maint, bypass).await?;
    summarise(&state, &rows).await?;
    reindex(maint_pool, &state).await
}

async fn write_audit(conn: &mut PgConnection) -> Result<(), ApiError> {
    let _ = &state.db_pool;
    Ok(())
}

async fn summarise(state: &AppState, rows: &[Thing]) -> Result<(), ApiError> {
    let _ = (&state.db_pool, rows);
    Ok(())
}

async fn reindex(pool: &PgPool, state: &AppState) -> Result<(), ApiError> {
    let _ = (pool, &state.db_pool);
    Ok(())
}
"#,
        ),
        (
            "epigraph-db/src/repos/thing.rs",
            r#"
impl ThingRepository {
    pub async fn broken(conn: &mut PgConnection, viewer: &Viewer) -> Result<Vec<Thing>, DbError> {
        todo!()
    }
}
"#,
        ),
    ];
    let a = fixture(files);
    assert!(
        a.findings.is_empty(),
        "none of these is a hybrid; found {:?}",
        a.findings
    );
    // And it is not clean because nothing was followed: the one hand-off that
    // DOES carry the bypass is an edge.
    assert!(a.edges.contains(&(
        (
            "epigraph-api/src/routes/things.rs".to_string(),
            "repair".to_string()
        ),
        (
            "epigraph-db/src/repos/thing.rs".to_string(),
            "broken".to_string()
        ),
    )));
    assert_eq!(a.edges.len(), 1, "only that edge: {:?}", a.edges);
}

/// Every [`FOREIGN_POOLS`] spelling fires at the far end of a cross-file call,
/// so no entry is dead weight the way `"server.pool"` was while known limit (b)
/// stood. A spelling that could not produce a finding here would fail this.
#[test]
fn every_foreign_pool_spelling_fires_across_a_call() {
    for spelling in FOREIGN_POOLS {
        let callee = format!(
            "pub async fn spend_it(viewer: &Viewer) -> Result<(), DbError> {{\n    \
             ClaimRepository::list(&{spelling}, viewer).await\n}}\n"
        );
        let files: Vec<(&str, &str)> = vec![
            (
                "epigraph-jobs/src/hand_off.rs",
                "pub async fn mint_and_hand_off(scoped: &ScopedPool) -> Result<(), DbError> {\n    \
                 let mut session = scoped.maintenance_session(SystemReason::DedupSweep).await?;\n    \
                 let (_conn, viewer) = session.split();\n    \
                 crate::spend::spend_it(viewer).await\n}\n",
            ),
            ("epigraph-jobs/src/spend.rs", &callee),
        ];
        assert!(same_region_only(&files).is_empty(), "{spelling}");
        let a = fixture(&files);
        assert_eq!(
            a.findings.keys().cloned().collect::<BTreeSet<_>>(),
            keys(&[("epigraph-jobs/src/spend.rs", "spend_it")]),
            "`{spelling}` did not fire across a call"
        );
    }
}

/// [`MAX_HOPS`] is exactly the reach the module doc states: a spend four calls
/// from the mint is found, five is not.
#[test]
fn the_hop_bound_is_the_documented_one() {
    let src = r#"
pub fn f0(scoped: &ScopedPool) {
    let session = scoped.maintenance_session(SystemReason::DedupSweep);
    let viewer = session.viewer();
    f1(viewer);
}
fn f1(viewer: &Viewer) { f2(viewer); }
fn f2(viewer: &Viewer) { f3(viewer); }
fn f3(viewer: &Viewer) { f4(viewer); }
fn f4(viewer: &Viewer) { let _ = &state.db_pool; f5(viewer); }
fn f5(viewer: &Viewer) { let _ = &state.db_pool; }
"#;
    assert_eq!(MAX_HOPS, 4, "the module doc and this test both say four");
    let a = fixture(&[("epigraph-jobs/src/chain.rs", src)]);
    assert_eq!(
        a.findings.keys().cloned().collect::<BTreeSet<_>>(),
        keys(&[("epigraph-jobs/src/chain.rs", "f4")])
    );
    assert_eq!(a.findings.values().next().map(Vec::len), Some(5));
}

/// The block tracker that attributes a function to its `impl` must not be
/// moved by braces or quotes inside literals — a `{` in a format string, a
/// `'}'`, a raw SQL string with embedded `"` — and must close an `impl` before
/// the free function after it. Resolution of `Type::f(` and `self.f(` depends
/// on it.
#[test]
fn the_impl_tracker_ignores_literals() {
    let src = r##"
impl<T: Into<String>> Store for Pg<T>
where
    T: Clone,
{
    fn a(&self) {
        let s = format!("{{ not a block {}", 1);
        let c = '}';
        let q = r#"SELECT "x" FROM t WHERE y = '}' AND z = '{'"#;
    }
    fn b(&self) {}
}

fn free() {}

impl Other {
    fn c(&self) {}
}
"##;
    let sites = fn_sites("epigraph-x/src/a.rs", src);
    let got: Vec<(String, Option<String>)> = sites
        .iter()
        .map(|s| (s.name.clone(), s.impl_type.clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("a".to_string(), Some("Pg".to_string())),
            ("b".to_string(), Some("Pg".to_string())),
            ("free".to_string(), None),
            ("c".to_string(), Some("Other".to_string())),
        ]
    );
    // And the blanker keeps line structure, which the per-line context needs.
    assert_eq!(blank_literals(src).lines().count(), src.lines().count());
}

/// The comment stripper must not eat code, and must not leave prose behind.
///
/// Both directions matter. A stripper that ate too much would delete real
/// matches and make the whole lint pass by seeing nothing; a stripper that ate
/// too little would reinstate the two prose false positives the module doc
/// records. The `postgres://` case is the one that motivates tracking string
/// literals at all: a naive `//` scan takes the rest of that line with it.
#[test]
fn the_stripper_does_not_eat_code() {
    let src = r#"
fn sample() {
    // self.pool must never be used here
    let dsn = "postgres://user@host/db"; let a = &self.pool;
    /* block: state.db_pool */
    let b = 'x';
    let _ = (dsn, a, b);
}
"#;
    let out = strip_comments(src);
    assert!(
        out.contains("&self.pool"),
        "the code occurrence survived stripping; got:\n{out}"
    );
    assert!(
        out.contains("postgres://user@host/db"),
        "a DSN inside a string literal must not be read as a line comment, or \
         everything after it on that line is silently deleted; got:\n{out}"
    );
    assert_eq!(
        out.matches("self.pool").count(),
        1,
        "the comment occurrence must be gone and the code one must remain; \
         got:\n{out}"
    );
    assert!(
        !out.contains("state.db_pool"),
        "a block comment must be stripped too; got:\n{out}"
    );
    assert!(
        out.lines().count() >= src.lines().count() - 1,
        "stripping must preserve line structure so a future line-numbered \
         report stays honest"
    );
}

/// The `#[cfg(test)]` strip must remove the test module and KEEP the production
/// code that follows it.
///
/// This is the pin on the measurement in `strip_cfg_test_modules`' own doc. The
/// first version of this lint truncated at the first `#[cfg(test)]`, and 125
/// files under the scan roots carry one that is not at the end — one of them at
/// 4% of the file. Under-scanning is invisible: the lint reports clean and the
/// non-vacuity floors still pass, because they count what survives the strip.
#[test]
fn the_cfg_test_strip_keeps_production_code() {
    let src = r#"
fn before() { let _ = &self.pool; }

#[cfg(test)]
mod tests {
    fn helper() { let _ = &self.pool; }
    fn nested() { if true { let _ = 1; } }
}

fn after() { Viewer::system(&lease, r); let _ = &state.db_pool; }
"#;
    let out = strip_cfg_test_modules(src);
    assert!(out.contains("fn before()"), "got:\n{out}");
    assert!(
        out.contains("fn after()") && out.contains("state.db_pool"),
        "PRODUCTION CODE AFTER THE TEST MODULE MUST SURVIVE. This is the whole \
         reason the strip is brace-matched instead of a truncating split; \
         got:\n{out}"
    );
    assert!(
        !out.contains("fn helper()") && !out.contains("fn nested()"),
        "the whole test module must go, nested braces included; got:\n{out}"
    );
    // And the region splitter still finds the function after it.
    assert!(
        regions(&out).iter().any(|r| r.name == "after"),
        "regions() must still see the post-module function"
    );

    // A `#[cfg(test)]` on something that is NOT a module is deliberately left
    // in: over-scanning yields a finding to triage, under-scanning yields
    // silence.
    let attr_on_fn = "#[cfg(test)]\nfn only_in_tests() { let _ = &self.pool; }\n";
    assert!(
        strip_cfg_test_modules(attr_on_fn).contains("only_in_tests"),
        "a non-module #[cfg(test)] must not swallow anything"
    );
}
