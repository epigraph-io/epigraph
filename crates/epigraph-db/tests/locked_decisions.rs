//! The locked decisions, checkable from one file (plan §0.2).
//!
//! # THIS FILE GROWS EACH PR
//!
//! Plan §0.2 fixes four decisions that the rest of the design rests on. They are
//! *locked*: a later PR does not get to relitigate one by quietly editing the
//! code it constrains. This file is where each becomes a machine-checked
//! predicate, and it is deliberately one file rather than four, so a reviewer can
//! read the whole contract in one screen.
//!
//! **A PR that changes an RLS policy, a route split, or a tenancy column and does
//! not touch this file is rejected in review.** If a change is genuinely outside
//! the four decisions, say so in the commit body; do not leave the reviewer to
//! infer it from an untouched test file.
//!
//! ## Status at PR-04
//!
//! * **D3 — no anonymous read authority.** Asserted below, in full.
//! * **D1 — tenancy is declared, never defaulted.** *Not yet assertable.*
//!   Migration 062 ships `DEFAULT 'public'` / `DEFAULT <world group>` on purpose:
//!   they are the transition artifacts that make the widening metadata-only on a
//!   live table. Asserting D1 today would fail by construction. See the
//!   placeholder comment in the D1 section below.
//! * **D4 — privatization is an explicit, audited administrative act.** Nothing
//!   to assert until the D4 surface exists. See the placeholder in the D4
//!   section.
//!
//! Both placeholders are *comments*, not `#[ignore]`d tests: an ignored test is
//! a red herring in `cargo test` output, and a parked `panic!` body is a trap for
//! whoever runs the suite with `--include-ignored`. PR-03 used the parked-test
//! form for one specific obligation with a silent failure mode; these two have
//! no such mode, so a comment naming the owning PR is the honest shape.
//!
//! ## Relationship to the other lint files
//!
//! `d3_viewer_has_no_infallible_constructor` overlaps
//! `crates/epigraph-db/tests/no_anonymous_viewer.rs`, and
//! `d3_anonymous_route_surface_is_the_allowlist` overlaps
//! `crates/epigraph-api/tests/public_router_allowlist.rs`. **That overlap is the
//! design**, not an oversight: §0.2 wants the locked decisions readable in one
//! place. The other two files remain **authoritative** — `public_router_allowlist.rs`
//! in particular also boots the app and proves every protected route really 401s,
//! and documents why axum 0.7.9 makes a runtime walk of "both variants"
//! impossible. What is here is the cheaper, structural half.

use std::collections::BTreeSet;

// ===========================================================================
// D3 — there is no anonymous read authority
// ===========================================================================

const VISIBILITY_RS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/visibility.rs");

/// Cross-crate source read. `locked_decisions.rs` lives in `epigraph-db` because
/// that is where §0.2 fixes its path, but D3's route half is a fact about
/// `epigraph-api`. Both crates are in this workspace and the path is stable.
const ROUTES_MOD_RS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../epigraph-api/src/routes/mod.rs"
);

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

/// Strip `//`-style comments so the prose explaining *why* a construct is banned
/// does not itself trip the ban. Block comments are not stripped; do not write
/// one containing a banned needle.
///
/// **This truncates at the first `//` on a line, including one inside a string
/// literal** — a URL in a doc example would silently delete the rest of that
/// line. Harmless in today's `visibility.rs`, which has none, but it matters
/// here in a way it would not in a normal linter: every assertion below is that
/// a needle is ABSENT, so over-deleting makes the lint quieter, never louder.
/// If a banned construct ever hides behind a `//` in a string, this scanner is
/// where to look.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// D3, half one: read authority cannot be materialised out of nothing.
///
/// Every needle below is a way to obtain a `Viewer` without proving who the
/// caller is. They are *absences*, so a text scan is the right instrument —
/// there is no type to assert against when the point is that the impl must not
/// exist.
#[test]
fn d3_viewer_has_no_infallible_constructor() {
    let code = strip_line_comments(&read(VISIBILITY_RS));

    const BANNED: &[(&str, &str)] = &[
        (
            "Anonymous",
            "D3 removes the anonymous shape entirely. A viewer that 'matches \
             nothing' is invisible to a test suite written as 'assert a stranger \
             CANNOT read': it passes every case while returning empty results \
             forever.",
        ),
        ("anonymous(", "the same, in constructor form"),
        (
            "impl Default for Viewer",
            "reachable by `..Default::default()` in a struct literal nobody reads",
        ),
        (
            "From<Option<Uuid>> for Viewer",
            "the anonymous shape wearing a different hat: `None` would have to \
             mean something, and every meaning is wrong",
        ),
        (
            "From<&AuthContext> for Viewer",
            "an infallible conversion cannot perform the membership round trip, \
             so it would have to invent a group set",
        ),
        (
            "fn unrestricted(",
            "the unrestricted shape must cost a MaintenanceLease",
        ),
    ];

    let violations: Vec<String> = BANNED
        .iter()
        .filter(|(needle, _)| code.contains(needle))
        .map(|(needle, why)| format!("  `{needle}` — {why}"))
        .collect();

    assert!(
        violations.is_empty(),
        "D3 is violated in src/visibility.rs:\n{}",
        violations.join("\n\n")
    );
}

/// D3, half two: the one unrestricted shape costs a lease, and the lease is
/// unforgeable outside this crate.
#[test]
fn d3_the_only_unrestricted_shape_costs_a_lease() {
    let code = strip_line_comments(&read(VISIBILITY_RS));

    assert!(
        code.contains("pub struct MaintenanceLease(pub(crate) ())"),
        "MaintenanceLease's field must stay `pub(crate)`. If it becomes `pub`, \
         any crate constructs one with `MaintenanceLease(())` and `Viewer::system` \
         stops being a type-level guarantee."
    );
    assert!(
        code.contains("pub const fn system(_lease: &MaintenanceLease, reason: SystemReason)")
            || code.contains("pub fn system(_lease: &MaintenanceLease, reason: SystemReason)"),
        "Viewer::system must take a `&MaintenanceLease`. Without the lease \
         parameter, 'unrestricted viewer' and 'maintenance connection' come apart \
         — and under FORCEd RLS that combination returns ZERO rows, not all rows."
    );
    assert!(
        !code.contains("pub const fn new() -> Self") || code.contains("pub(crate) const fn new()"),
        "MaintenanceLease::new must stay crate-private."
    );

    // There is deliberately no behavioural half here. Constructing a lease from
    // an integration test is IMPOSSIBLE — `MaintenanceLease::new` is
    // `pub(crate)` and this file links `epigraph-db` from outside — and that
    // impossibility IS the decision. The behaviour of a bypass viewer once it
    // exists is asserted in `qual_guc_coherence.rs`, which obtains its lease the
    // only way anything can: from `ScopedPool::unscoped_for_maintenance`.
}

/// D3, half three: the set of routes reachable with no `Authorization` header is
/// an allowlist of exactly two application routes, in **both** `create_router`
/// variants.
///
/// The `#[cfg(not(feature = "db"))]` variant is not built in any buildable
/// configuration, so a source lint is the only mechanism that covers it at all.
#[test]
fn d3_anonymous_route_surface_is_the_allowlist() {
    let src = read(ROUTES_MOD_RS);
    let expected: BTreeSet<&str> = ["/health", "/api/v1/openapi.json"].into_iter().collect();

    let chains: Vec<&str> = statement_starts(&src, "let public = Router::new()")
        .into_iter()
        .map(|start| statement_at(&src, start))
        .collect();

    assert_eq!(
        chains.len(),
        2,
        "expected exactly two `let public = Router::new()` chains — one per \
         create_router variant. Found {}. If a variant was added or removed, \
         this test must be updated deliberately.",
        chains.len()
    );

    for (i, chain) in chains.iter().enumerate() {
        let routes: BTreeSet<&str> = route_literals(chain).into_iter().collect();
        assert_eq!(
            routes, expected,
            "create_router variant #{i}: the anonymous surface is not the \
             allowlist. Registering a route on the `public` chain puts it back \
             on the unauthenticated internet — which under D3 is a decision that \
             belongs in review, not in a diff hunk. \
             (The authoritative, richer check, including the live 401 assertions, \
             is crates/epigraph-api/tests/public_router_allowlist.rs.)"
        );
    }
}

// ---------------------------------------------------------------------------
// A minimal, depth-aware Rust statement scanner.
//
// Line-based scanning has a silent-truncation mode: a `;` inside a route
// closure ends the scan early, and a truncation falling after the last expected
// route but before a newly added one passes the assertion while missing the new
// route. So `;` only terminates at depth zero.
// ---------------------------------------------------------------------------

fn statement_starts(src: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(needle) {
        out.push(from + rel);
        from += rel + needle.len();
    }
    out
}

fn statement_at(src: &str, start: usize) -> &str {
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b';' if depth == 0 => return &src[start..=i],
            b'"' => {
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i += 1,
                        b'"' => break,
                        _ => {}
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unterminated statement starting at byte {start} of routes/mod.rs");
}

/// Every `.route("<path>"` literal in a chain.
fn route_literals(chain: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = chain[from..].find(".route(") {
        let after = from + rel + ".route(".len();
        let rest = chain[after..].trim_start();
        let offset = after + (chain[after..].len() - rest.len());
        if let Some(stripped) = rest.strip_prefix('"') {
            if let Some(end) = stripped.find('"') {
                out.push(&chain[offset + 1..offset + 1 + end]);
            }
        }
        from = after;
    }
    out
}

// ===========================================================================
// D1 — tenancy is declared on write, never defaulted
// ===========================================================================
//
// PR-16: after migration 074 drops the DEFAULTs, assert here that no tier-A
// table has a `column_default` on `visibility` or `owner_group_id`, and that
// `count(*) FROM claims WHERE owner_group_id = <world>` is 0.
//
// It is NOT assertable at PR-04. Migration 062 ships
// `DEFAULT 'public'` and `DEFAULT '00000000-…-000000000000'::uuid` deliberately:
// they are what makes `ADD COLUMN` metadata-only on a live `claims` table, and
// dropping them is stage two, not stage one. An assertion written now would fail
// by construction and would be silenced rather than fixed.

// ===========================================================================
// D4 — privatization is an explicit, audited administrative act
// ===========================================================================
//
// PR-18: assert that every non-public row reachable through a privatization plan
// has a `tenancy_transcription_log` entry, that `privatization_audit` is
// append-only, and that the D4 HTTP surface is admin-only.
//
// Nothing to assert at PR-04: none of those objects exists yet. Migration 062
// creates `tenancy_transcription_log` as an empty ledger; `tenancy_migration_shape.rs`
// pins its shape.
