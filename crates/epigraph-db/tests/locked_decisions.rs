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
//! ## Status at PR-13
//!
//! **PR-13 DOES touch a locked decision.** It adds a tenancy column —
//! `edges.co_owner_group_id` (migration 072). "A tenancy column" is one of the
//! three things named above that make extending this file mandatory, so this
//! section is not optional.
//!
//! * **D1 (nothing is public by absence, omission, or default-on-error)** —
//!   preserved, and the *shape* of the new column is where it bites.
//!   `co_owner_group_id` is nullable **with no `DEFAULT`**, and NULL means
//!   "single owner", not "unknown". That reads like the implicit-public D1
//!   forbids, and it is not: the column is never the sole carrier of an
//!   authorization decision. `owner_group_id` (NOT NULL, CHECKed, stamped by a
//!   trigger) decides visibility; `co_owner_group_id` can only NARROW it.
//!   A NULL therefore fails toward the pre-072 behaviour, which is the
//!   single-owner predicate — never toward public. Pinned by
//!   [`d1_the_co_owner_column_has_no_default_and_cannot_widen`].
//! * **D3 (`public` = any authenticated agent; no anonymous shape)** —
//!   unchanged. PR-13 adds `Viewer::edge_predicate_fragment`, a second *method*
//!   on the existing type; it adds no shape, no constructor, no `SystemReason`,
//!   and `no_anonymous_viewer.rs`'s source lint over `visibility.rs` is
//!   unchanged and still passes.
//! * **No route moved**, and `public_router_allowlist.rs` is untouched.
//! * **No RLS policy, no `WITH CHECK`, no write-side SQL predicate.** Migration
//!   072 `CREATE OR REPLACE`s two *stamping* trigger arms and creates no policy.
//!   It also REMOVES a write-side membership test — arm (b)'s
//!   `sg = ANY(epigraph_session_groups()) AND tg = ANY(...)` hatch — and that
//!   direction is the one this bullet permits: it moves write authorization
//!   OUT of a stamping trigger and leaves it to PR-16, rather than pre-empting
//!   PR-16 by adding some. The hatch was unsatisfiable in production anyway
//!   (personal groups admit no principal in two of them, and every edge writer
//!   reaches the trigger on a bare `&PgPool` with no session GUCs), so nothing
//!   that ever fired was removed. Pinned by
//!   `tenancy_triggers.rs::arm_b_no_longer_raises_on_a_cross_group_edge`.
//! * **No `VALIDATE CONSTRAINT`, no `DROP DEFAULT`.** Both 072 constraints ship
//!   `NOT VALID`; validation is PR-16's 075/076.
//!   [`d1_the_stamping_trigger_is_still_the_transition_form`] still passes,
//!   i.e. `claims.owner_group_id` keeps its `column_default`.
//! * **No `FAIL_OPEN_SCOPE_SITES` row moved.**
//! * **The trigger inventory count is unchanged at 21.** 072 replaces two
//!   function BODIES with `CREATE OR REPLACE`, which does not re-create a
//!   trigger — [`d1_tenancy_stamping_triggers_are_armed`] would catch a
//!   replacement that silently dropped one.
//!
//! ## Status at PR-11
//!
//! **PR-11 DOES touch a locked decision.** It changes the kernel's *write*
//! authorization posture from allow-all to deny-by-default, which is D1 — not a
//! route split, not a tenancy column, not a migration (PR-11 adds none;
//! `migrations/README.md` reserves it no number), but the first of the four,
//! read on the write side.
//!
//! * **D1 (nothing is public by absence, omission, or default-on-error)** —
//!   extended from reads to writes. Three mechanisms, all in
//!   `crates/epigraph-interfaces/src/policy.rs` and
//!   `crates/epigraph-authz/src/lib.rs`:
//!   - The kernel's type-level floor is `DenyAllPolicyGate`. It replaces
//!     `NoOpPolicyGate`, whose `check()` returned `Ok(true)` unconditionally —
//!     *public by default*, one layer up from `access_control.rs:68`.
//!     **Say "floor", not "the default a deployment gets":**
//!     `DenyAllPolicyGate` has zero production install sites. All six
//!     `AppState` constructors and both `EpiGraphMcpFull` constructors install
//!     `epigraph_authz::GroupPolicyGate`, and the test that pins *that* is
//!     `epigraph-api/src/state.rs::the_default_gate_is_installed_at_every_constructor`.
//!     [`d1_the_kernel_write_gate_is_not_an_allow_all`] below is a source scan
//!     over `policy.rs`; it proves no allow-all is reachable in a production
//!     build, which is a weaker and different claim than "a running process
//!     denies by default". Both are needed; neither substitutes for the other.
//!   - `PolicyGate::authorize` maps `Err(_)` to `Decision::Deny` inside the
//!     trait, so no call site can spell *default-on-error*. This is the direct
//!     analogue of PR-10's three-branch `retain_visible_subscriptions`.
//!   - `GroupPolicyGate` denies a `ResourceRef` that names neither an owning
//!     group nor an owning agent — *absence* is a denial, not a pass.
//!
//!   Asserted by [`d1_the_kernel_write_gate_is_not_an_allow_all`].
//! * **D3 (`public` means any authenticated agent; no anonymous shape)** —
//!   unchanged. PR-11 adds no `Viewer` constructor and no `SystemReason`. Its
//!   two HTTP call sites take `middleware::bearer::ViewerExtractor`, which is
//!   the one production path, and its two MCP call sites take
//!   `tools::viewer::request_viewer`, which is the other. Neither invents a
//!   principal: a viewer with no principal is refused, not defaulted.
//! * **No route moved** between the `public` and `protected` chains, and no
//!   route was added or removed. `public_router_allowlist.rs` is untouched.
//! * **No RLS policy, no `WITH CHECK`, no write-side SQL predicate.** That half
//!   is PR-16/PR-17's and PR-11 deliberately does not pre-empt it — see the
//!   `-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate`
//!   markers in `repos/claim.rs`, which are unchanged.
//! * **No `FAIL_OPEN_SCOPE_SITES` row moved.** Locked decision Q7 assigns those
//!   35 sites to PR-16 and PR-11 spends its mechanism elsewhere.
//!
//! ## Status at PR-10
//!
//! **PR-10 adds a migration and does NOT touch any of the four.** Said
//! explicitly, because it adds one (085, `webhook_subscriptions`) and the
//! rejection trigger above is written to catch exactly the PR that adds a
//! migration and leaves this file alone.
//!
//! * **D1 (nothing is public by absence, omission, or default-on-error)** —
//!   reinforced, not changed. The new fan-out filter in
//!   `epigraph-api/src/routes/webhooks.rs::retain_visible_subscriptions` has
//!   three failure branches (no `agent_id`, `Viewer::resolve` errors,
//!   `hidden_claim_ids` errors) and all three DROP the delivery. A database
//!   outage stops webhooks; it does not broadcast every tenant's claims.
//! * **D3 (`public` means any authenticated agent; no anonymous shape)** —
//!   unchanged. PR-10 adds no `Viewer` constructor and no `SystemReason`. Its
//!   viewers come from `Viewer::resolve` over a subscription's `agent_id`,
//!   which is the one production path. `list_webhooks` / `get_webhook` gained
//!   `middleware::bearer::RequirePrincipal`, which enforces D3's two 401
//!   branches (no `AuthContext`, then no `agent_id`) and deliberately does NOT
//!   hand out a `Viewer` — there is no visibility predicate on a subscription
//!   row for one to be spent on, and an unspent viewer is a fail-open dressed
//!   as diligence.
//! * **Migration 085 is not a tenancy column change.** `webhook_subscriptions`
//!   has no `claim_id` and no foreign key onto `claims`, so it is outside the
//!   §2.4 protected set under both of `tenancy_coverage.rs::protected_set`'s
//!   generators, carries neither `visibility` nor `owner_group_id`, and gets no
//!   `tenancy_exempt` row (the registry is for relations the generators DO
//!   find; `migration_068_and_069_apply_twice` pins its cardinality at 12).
//! * **No route moved between the `public` and `protected` chains.** The four
//!   webhook routes were already on `protected` in both `create_router`
//!   variants and still are; `public_router_allowlist.rs` is untouched.
//! * **No RLS policy.** None exists yet (PR-17 owns 077/079).
//! * **No write-side tenancy predicate.** `register_webhook` now writes a row,
//!   which is disclosed on the handler itself, but it adds no
//!   `writable_bind()`, no `WITH CHECK` and no policy — that is PR-16's
//!   mechanism and it does not exist. Refusing when `AuthContext` is absent
//!   (`delete_webhook`) is authentication, not the PR-16 control.
//!
//! ## Status at PR-09
//!
//! **PR-09 DOES touch a locked decision, and this file grows accordingly.**
//! It changes how an MCP caller obtains read authority, which is D3 — not a
//! route split, not a tenancy column, but the third of the four. Two changes,
//! both in the direction D3 points:
//!
//! * `crates/epigraph-mcp/src/tools/viewer.rs::request_viewer` no longer
//!   flattens `agent_id.or(owner_id).unwrap_or(client_id)`. `owner_id` and
//!   `client_id` are `oauth_clients.id` values; feeding either to
//!   `Viewer::resolve` was a type confusion that produced the D3-correct answer
//!   (public only) *by accident*, because the membership lookup happened never
//!   to match. An HTTP `AuthContext` with no `agent_id` is now refused.
//!   Asserted by [`d3_mcp_viewer_acquisition_does_not_flatten_a_client_id`].
//! * `crates/epigraph-mcp/src/auth.rs::unauthenticated_context` now carries the
//!   server's own `agents.id`, so the `--allow-unauthenticated-http` listener
//!   resolves the server's viewer rather than a nil principal's. This is a
//!   **widening** of that listener's read authority, and it is the change plan
//!   §4.12 assigns to PR-09. It does not create an anonymous *shape* — there is
//!   still exactly one `Viewer::resolve` and it still requires a principal — so
//!   [`d3_viewer_has_no_infallible_constructor`] is unchanged and correct.
//!
//! Nothing else in PR-09 is one of the four: the rest is read-path filtering
//! (viewer predicates spliced into repo functions and into `recall.rs`'s
//! `sqlx::query!` macros), inline SQL moved to `crates/epigraph-db/src/repos/`,
//! and three new test files. No migration; no RLS policy; no route moved
//! between the `public` and `protected` chains.
//!
//! ## Status at PR-08
//!
//! PR-06, PR-07 and PR-08 leave every assertion below unchanged, and that is the
//! correct outcome rather than an omission: none changes an RLS policy, a
//! route split, or a tenancy column. PR-07 is a read-path refactor — it moves
//! statements from `crates/epigraph-api/src/routes/` into
//! `crates/epigraph-db/src/repos/` and splices `Viewer` predicates into them —
//! and it adds no migration. Recorded here explicitly because the rejection
//! trigger above asks for it to be said, not inferred.
//!
//! **PR-08 in particular does not move a route.** Its plan entry says
//! `/api/v1/structural-features/:owner_id` is registered on the `public` router
//! and must move to `protected`; it already is on `protected`, in BOTH
//! `create_router` variants. Which PR moved it is NOT attributable from the
//! history — an earlier revision of this comment credited PR-03, which is not
//! evidenced: `git log -S/-G 'structural-features' -- routes/mod.rs` returns
//! only the initial public release, because the registration line itself never
//! changed and only the enclosing `public`/`protected` block boundary moved.
//! `routes/mod.rs` is untouched by PR-08 and the anonymous→401 acceptance
//! criterion is *tested*
//! (`crates/epigraph-api/tests/structural_features_authz.rs::anonymous_is_401`)
//! rather than implemented. The rest of PR-08 — nine statements into
//! `repos/structural.rs` with spliced predicates, an `epsilon` default of 1.0
//! that is also the unprivileged ceiling, and a `claims:admin` gate on exact
//! counts — is a read path and a scope check, neither of which is one of the
//! four decisions.
//!
//! * **D3 — no anonymous read authority.** Asserted below, in full.
//! * **D1 — tenancy is declared, never defaulted.** *Half asserted.* PR-05's
//!   migration 069 adds `entity_types.tenancy_tier`, and — unusually for this
//!   series — drops its DEFAULT **in the same migration**, because a type that
//!   does not exist yet has no live table to widen metadata-only and therefore
//!   needs no transition DEFAULT at all. That makes one column, today, the first
//!   place D1 is a machine-checkable predicate rather than an intention:
//!   `d1_tenancy_tier_is_declared_never_defaulted` below.
//!
//!   The OTHER half — the tier-A `visibility` / `owner_group_id` DEFAULTs
//!   migration 062 ships on purpose — is still not assertable, and stays a
//!   comment in the D1 section until migration 074 drops them in PR-16.
//! * **D4 — privatization is an explicit, audited administrative act.** Nothing
//!   to assert until the D4 surface exists. See the placeholder in the D4
//!   section.
//!
//! The remaining placeholders are *comments*, not `#[ignore]`d tests: an ignored
//! test is a red herring in `cargo test` output, and a parked `panic!` body is a
//! trap for whoever runs the suite with `--include-ignored`. PR-03 used the
//! parked-test form for one specific obligation with a silent failure mode;
//! these have no such mode, so a comment naming the owning PR is the honest
//! shape.
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

use sqlx::PgPool;
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

/// D3's MCP half (PR-09). `crates/epigraph-mcp/src/tools/viewer.rs` is where a
/// tool call turns an `AuthContext` into read authority — the MCP counterpart of
/// `epigraph-api`'s `ViewerExtractor`, and therefore the other place D3 can be
/// violated. Same cross-crate rationale as [`ROUTES_MOD_RS`].
const MCP_VIEWER_RS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../epigraph-mcp/src/tools/viewer.rs"
);

/// D1's write half (PR-11). `crates/epigraph-interfaces/src/policy.rs` is
/// where the kernel decides what an unconfigured deployment permits. Same
/// cross-crate rationale as [`ROUTES_MOD_RS`].
const INTERFACES_POLICY_RS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../epigraph-interfaces/src/policy.rs"
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

/// D3, MCP half: read authority comes from an `agents.id` or it does not come
/// at all (PR-09).
///
/// `epigraph-api`'s side of this is the `ViewerExtractor`, which 401s a
/// principal-less token. MCP has no extractor — `tools/viewer.rs::request_viewer`
/// is the whole of it — and until PR-09 it flattened
/// `agent_id.or(owner_id).unwrap_or(client_id)` and resolved whatever came out.
///
/// Why that mattered even though the outcome was correct: `owner_id` and
/// `client_id` are `oauth_clients.id` values, so `Viewer::resolve` looked up
/// `group_memberships.agent_id = <a client id>`, matched nothing, and returned a
/// public-only viewer. Right answer, wrong reason — and a reason that stops
/// holding the moment those id spaces overlap, at which point the flatten is a
/// silent authority grant with no error and no metric. Plan §4.12 says so
/// directly, prescribing `None => Err(unauthorized(...))`.
///
/// This is a source-text assertion for the same reason
/// [`d3_viewer_has_no_infallible_constructor`] is: the property is "this
/// spelling does not appear", which no runtime test can establish.
#[test]
fn d3_mcp_viewer_acquisition_does_not_flatten_a_client_id() {
    let code = strip_line_comments(&read(MCP_VIEWER_RS));

    assert!(
        !code.contains("unwrap_or(a.client_id)") && !code.contains("or(a.owner_id)"),
        "D3 is violated in epigraph-mcp/src/tools/viewer.rs: request_viewer is \
         flattening an oauth_clients.id into an agents.id position again. A \
         token with no agent principal has no read authority; refuse it."
    );
    assert!(
        code.contains("a.agent_id.ok_or_else("),
        "request_viewer must refuse an AuthContext carrying no agent_id, not \
         substitute another id for it. If the refusal moved or changed shape, \
         update this assertion deliberately — it is the only mechanical record \
         that MCP's read authority is agent-derived."
    );
    assert!(
        code.contains("Viewer::resolve"),
        "request_viewer must still go through Viewer::resolve — the one \
         constructor a request path can reach. A second acquisition path is a \
         second place D3 can be violated."
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
// STILL A PLACEHOLDER, for the tier-A columns only:
//
// PR-16: after migration 074 drops the DEFAULTs, assert here that no tier-A
// table has a `column_default` on `visibility` or `owner_group_id`, and that
// `count(*) FROM claims WHERE owner_group_id = <world>` is 0.
//
// That half is NOT assertable at PR-05. Migration 062 ships
// `DEFAULT 'public'` and `DEFAULT '00000000-…-000000000000'::uuid` deliberately:
// they are what makes `ADD COLUMN` metadata-only on a live `claims` table, and
// dropping them is stage two, not stage one. An assertion written now would fail
// by construction and would be silenced rather than fixed.
//
// What IS assertable, as of PR-05, is below.

/// D1, the half that is live: **a tenancy column with no absence value.**
///
/// PR-05's migration 069 adds `entity_types.tenancy_tier` and drops its DEFAULT
/// in the same file. It can, where 062 could not: `entity_types` holds 23 rows,
/// not a live `claims` table, so there is no metadata-only widening to protect
/// and no two-stage rollout to sequence. The 23 existing rows are classified by
/// the migration itself and the DEFAULT is then removed, which is exactly the
/// end-state 074 will bring the tier-A columns to.
///
/// Two things together are what make D1 true here, and BOTH are asserted:
///
/// 1. **No DEFAULT.** An `INSERT` that omits the column raises 23502 rather than
///    silently landing on a value nobody chose. This is what makes
///    `EntityTypeRepository::upsert_non_core`'s `tenancy_tier` parameter
///    load-bearing rather than cosmetic.
/// 2. **No absence value inside the vocabulary.** `entity_types_no_unclassified`
///    forbids `'unclassified'` at rest, so "I did not decide" cannot be
///    laundered into a stored value. Without this, dropping the DEFAULT would
///    only move the silence from the schema into the caller.
///
/// A PR that reinstates either — a convenience DEFAULT, or dropping the CHECK so
/// a registration can park at `'unclassified'` — relitigates D1, and this is
/// where it is caught.
#[sqlx::test(migrations = "../../migrations")]
async fn d1_tenancy_tier_is_declared_never_defaulted(pool: PgPool) {
    // (1) No DEFAULT, read from the catalog rather than inferred from an error.
    let default: Option<String> = sqlx::query_scalar(
        "SELECT column_default FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'entity_types' \
            AND column_name = 'tenancy_tier'",
    )
    .fetch_one(&pool)
    .await
    .expect("column_default probe");
    assert_eq!(
        default, None,
        "entity_types.tenancy_tier must have NO column_default. A DEFAULT here is \
         D1 being relitigated: it would let a registration omit the field and land \
         on a tier nobody declared."
    );

    // And it is still NOT NULL, so "no default" means "you must say", not
    // "it can be blank".
    let nullable: String = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'entity_types' \
            AND column_name = 'tenancy_tier'",
    )
    .fetch_one(&pool)
    .await
    .expect("is_nullable probe");
    assert_eq!(
        nullable, "NO",
        "dropping the DEFAULT only declares tenancy if the column is also NOT NULL"
    );

    // (2) The absence value is not storable.
    let constraint_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_constraint \
                        WHERE conrelid = 'public.entity_types'::regclass \
                          AND conname = 'entity_types_no_unclassified')",
    )
    .fetch_one(&pool)
    .await
    .expect("constraint probe");
    assert!(
        constraint_exists,
        "entity_types_no_unclassified must exist. Without it, 'unclassified' is a \
         storable absence value and dropping the DEFAULT merely moves the silence \
         from the schema to the caller."
    );

    // CONRELID-QUALIFIED above on purpose: `pg_constraint.conname` is unique per
    // RELATION, not per database, so a bare name lookup would be satisfied by a
    // same-named constraint on any other table — the exact blind spot migration
    // 062's own comments call out.

    // And no row is parked at the absence value.
    let unclassified: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM entity_types WHERE tenancy_tier = 'unclassified'",
    )
    .fetch_one(&pool)
    .await
    .expect("unclassified count");
    assert_eq!(unclassified, 0);
}

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

// ===========================================================================
// D1 — nothing is authorized by absence, omission, or default-on-error
// ===========================================================================

/// D1, write half: the kernel's default write gate is a **denial**, and the
/// allow-all is not compiled into a production binary.
///
/// Before PR-11 the default was `NoOpPolicyGate`, whose `check()` returned
/// `Ok(true)` for every `(agent, action, resource)`. That is "public by
/// omission" for writes — the same defect D1 names at `access_control.rs:68`,
/// one layer up — and it went unnoticed for as long as it did precisely because
/// nothing ever called it, so no test could observe the verdict.
///
/// A text scan is the right instrument for the same reason as
/// [`d3_viewer_has_no_infallible_constructor`]: the assertions are about what
/// must be ABSENT, and there is no type to name when the point is that a
/// production build must not contain one.
#[test]
fn d1_the_kernel_write_gate_is_not_an_allow_all() {
    let raw = read(INTERFACES_POLICY_RS);
    let code = strip_line_comments(&raw);

    assert!(
        code.contains("pub struct DenyAllPolicyGate"),
        "the kernel default write gate must be a deny-all; if it was renamed, \
         update this assertion in the same commit and say in the PR body which \
         way the default now falls"
    );
    assert!(
        !code.contains("pub struct NoOpPolicyGate"),
        "`NoOpPolicyGate` returned Ok(true) unconditionally and was the \
         kernel default. It must not come back under that name or any other \
         un-cfg'd allow-all."
    );

    // The allow-all survives, and is reachable only under a cfg. The assertion
    // is on the ATTRIBUTE immediately preceding the definition, not merely on
    // the presence of the string somewhere in the file.
    let at = code
        .find("pub struct AllowAllPolicyGate")
        .expect("AllowAllPolicyGate must still exist — plan §2.7 keeps it for tests");
    let preceding = &code[..at];
    assert!(
        preceding
            .rfind("#[cfg(any(test, feature = \"insecure-allow-all\"))]")
            .is_some_and(|c| preceding[c..].matches('\n').count() <= 3),
        "`AllowAllPolicyGate` must be immediately preceded by \
         #[cfg(any(test, feature = \"insecure-allow-all\"))]"
    );

    // Nothing in the workspace may turn that feature on. A cargo feature CAN be
    // enabled from a dependent crate's build graph — the hazard
    // `Viewer::test_scoped` avoids by using `#[cfg(test)]` on its definition —
    // so the cfg alone is not the control; this is.
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let mut enablers = Vec::new();
    for entry in walk_manifests(std::path::Path::new(root)) {
        let text = read(entry.to_str().expect("utf-8 path"));
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            // The declaration in epigraph-interfaces' own [features] table is
            // the definition, not an enablement.
            if line.starts_with("insecure-allow-all = ") {
                continue;
            }
            if line.contains("insecure-allow-all") {
                enablers.push(format!("{}: {line}", entry.display()));
            }
        }
    }
    assert!(
        enablers.is_empty(),
        "\n\nA manifest in this workspace enables `insecure-allow-all`, which \
         compiles an allow-everything write gate:\n{}\n",
        enablers.join("\n")
    );
}

/// Every `Cargo.toml` under the workspace root, skipping `target/`.
fn walk_manifests(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name == "target" || name == ".git" || name.starts_with('.') {
                    continue;
                }
                stack.push(path);
            } else if name == "Cargo.toml" {
                out.push(path);
            }
        }
    }
    out.sort();
    assert!(
        out.len() > 10,
        "expected to find the workspace's manifests, found {}",
        out.len()
    );
    out
}

// =============================================================================
// D1 / D2 — PR-12: the stamping triggers are armed, and the transition form is
// still the transition form.
//
// Plan §0.2 requires every PR that touches a locked decision to extend this
// file. PR-12 arms the write-side stamping D1 depends on and performs the D2
// backfill, so both are locked here.
// =============================================================================

/// D1 — plan §8.2 acceptance **A5**: every tenancy trigger is `tgenabled = 'O'`.
///
/// D1 is "nothing is public by absence, omission, or default-on-error", and
/// after PR-12 the mechanism enforcing it on the write side is a set of
/// triggers. `ALTER TABLE … DISABLE TRIGGER` is a one-line, in-band way to
/// revert that whole decision with no diff and no migration — precisely the
/// shape this file exists to catch. A disabled stamping trigger is
/// indistinguishable from an absent one at the row level.
///
/// The count is pinned, not just the enabled-ness: an assertion that "no
/// tenancy trigger is disabled" passes vacuously on a database that has none.
#[sqlx::test(migrations = "../../migrations")]
async fn d1_tenancy_stamping_triggers_are_armed(pool: PgPool) {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT t.tgname, t.tgenabled::text FROM pg_trigger t \
          WHERE NOT t.tgisinternal \
            AND (t.tgname IN ('claims_require_tenancy', 'edges_tenancy', \
                              'claims_propagate_tenancy', 'ownership_transcribe') \
                 OR t.tgname LIKE '%\\_inherit\\_tenancy') \
          ORDER BY t.tgname",
    )
    .fetch_all(&pool)
    .await
    .expect("read pg_trigger");

    assert_eq!(
        rows.len(),
        21,
        "expected 21 tenancy triggers — 4 named (claims_require_tenancy, \
         edges_tenancy, claims_propagate_tenancy, ownership_transcribe) plus one \
         *_inherit_tenancy per claim-derived tier-A table (17). Found {}: {rows:?}. \
         A different count means migration 070 arm (c)'s table set moved, which \
         is a D1 change and needs a decision, not a silent edit.",
        rows.len()
    );

    let disabled: Vec<&(String, String)> = rows.iter().filter(|(_, e)| e != "O").collect();
    assert!(
        disabled.is_empty(),
        "plan §8.2 A5: every tenancy trigger must be ENABLED (tgenabled = 'O'). \
         These are not: {disabled:?}"
    );
}

/// D1 — migration 070 must ship the TRANSITION form, not 074's final form.
///
/// The distinction is the whole staging strategy. 070 arm (a) **warns and
/// counts**; migration 074 (PR-16) `CREATE OR REPLACE`s the same function with
/// the `RAISE`-terminated version in the same migration that drops 062's
/// DEFAULTs. Shipping the final form early turns thirteen production
/// `INSERT INTO claims` call sites and ~160 test statements into hard `23502`s
/// on the day PR-12 lands, months before PR-16's week-11a rollout.
///
/// Read from `pg_proc.prosrc` and the catalog rather than from the file, so a
/// database that has had the function replaced out of band also fails.
#[sqlx::test(migrations = "../../migrations")]
async fn d1_the_stamping_trigger_is_still_the_transition_form(pool: PgPool) {
    let src: String = sqlx::query_scalar(
        "SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
          WHERE n.nspname = 'public' AND p.proname = 'epigraph_claims_require_tenancy'",
    )
    .fetch_one(&pool)
    .await
    .expect("epigraph_claims_require_tenancy must exist after migration 070");

    assert!(
        src.contains("tenancy_undeclared_writes"),
        "arm (a) must COUNT undeclared writes — that counter is plan §9.2's \
         week-11b deploy gate, and without it PR-16 has no evidence to gate on"
    );
    assert!(
        src.contains("RAISE WARNING"),
        "arm (a) must WARN, not raise, while 062's DEFAULTs are still present"
    );

    // The transition form keys on "still equals the world default"; 074's final
    // form keys on IS NULL, which is only reachable once the DEFAULTs are gone.
    let default_present: bool = sqlx::query_scalar(
        "SELECT column_default IS NOT NULL FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'claims' \
            AND column_name = 'owner_group_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("read claims.owner_group_id default");
    assert!(
        default_present,
        "claims.owner_group_id lost its DEFAULT before migration 074. The \
         transition trigger keys on that default, so dropping it early makes arm \
         (a) silently stop recognising undeclared writes."
    );
}

/// D2 — the backfill's target is the author's personal group, and the seed
/// group is NOT it.
///
/// Both nil-flavoured groups must exist and must remain memberless, because
/// that is what makes `('group', world)` and `('group', seed)` black holes and
/// what migration 062's `<table>_group_needs_real_group` CHECK is protecting.
/// A PR that gives seed memberships changes what PR-16's migration 074 arm 4
/// means, and this is where that is caught.
#[sqlx::test(migrations = "../../migrations")]
async fn d2_world_and_seed_remain_memberless(pool: PgPool) {
    for kind in ["world", "seed"] {
        let group: uuid::Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE kind = $1")
            .bind(kind)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("migration 062 seeds the {kind} group: {e}"));

        let members: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM group_memberships WHERE group_id = $1 AND revoked_at IS NULL",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .expect("count memberships");

        assert_eq!(
            members, 0,
            "the {kind} group must stay memberless by design. It is a SHAPE \
             CONSTANT, not an owner; giving it members would make ('group', \
             {kind}) look readable and quietly relitigate D2's choice of the \
             author's personal group as the backfill target."
        );
    }
}

// =============================================================================
// D1 — PR-13: the co-ownership column narrows, and can never widen.
//
// Plan §0.2 requires every PR that adds a tenancy column to extend this file.
// `edges.co_owner_group_id` (migration 072) is one.
// =============================================================================

/// D1 — `edges.co_owner_group_id` has NO `DEFAULT`, and NULL cannot widen.
///
/// The nullable column is the part of PR-13 that most resembles the thing D1
/// forbids: "nothing is public by absence, by omission, or by
/// default-on-error". Three catalog facts are what make it not that, and all
/// three are one edit away from being untrue:
///
/// 1. **No `column_default`.** 062's DEFAULTs on `owner_group_id` /
///    `visibility` are the transition form PR-16's 074 removes; adding one here
///    would be a NEW implicit declaration, arriving after the decision to stop
///    making them. There is also nothing a default could sensibly say — a
///    co-owner is derived from two endpoints, never assumed.
/// 2. **`owner_group_id` is still NOT NULL.** Co-ownership adds a SECOND owner;
///    it never replaces the first. A row whose only ownership signal were a
///    nullable column would be exactly the absence-means-public shape.
/// 3. **`edges_co_owner_shape` requires `visibility = 'group'`.** A co-owner on
///    a `visibility = 'public'` row is rejected, so the column cannot be read as
///    a restriction on an otherwise-public edge — the read fragment's leading
///    `visibility = 'public'` disjunct short-circuits before the co-owner test,
///    and this CHECK is what stops those two facts from disagreeing.
///
/// Together: a NULL co-owner degrades to the pre-072 single-owner predicate,
/// which is strictly narrower than public. The behavioural half of this lives
/// in `privatization_boundary.rs`; this is the catalog half, which survives a
/// database whose column was altered out of band.
#[sqlx::test(migrations = "../../migrations")]
async fn d1_the_co_owner_column_has_no_default_and_cannot_widen(pool: PgPool) {
    let (nullable, default): (String, Option<String>) = sqlx::query_as(
        "SELECT is_nullable, column_default FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'edges' \
            AND column_name = 'co_owner_group_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("edges.co_owner_group_id must exist after migration 072");

    assert_eq!(
        nullable, "YES",
        "NULL is the single-owner case and must stay expressible; NOT NULL here \
         would force every edge to name a second group it does not have"
    );
    assert_eq!(
        default, None,
        "a DEFAULT on co_owner_group_id would be a new implicit tenancy \
         declaration, which is the D1 shape migration 074 exists to remove"
    );

    let owner_nullable: String = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'edges' \
            AND column_name = 'owner_group_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("edges.owner_group_id");
    assert_eq!(
        owner_nullable, "NO",
        "the FIRST owner stays NOT NULL: co-ownership adds an owner, it does \
         not make ownership optional"
    );

    // The shape CHECK exists, still NOT VALID (validation is PR-16's 075/076),
    // and still names both conjuncts.
    let (src, validated): (String, bool) = sqlx::query_as(
        "SELECT pg_get_constraintdef(oid), convalidated FROM pg_constraint \
          WHERE conrelid = 'public.edges'::regclass AND conname = 'edges_co_owner_shape'",
    )
    .fetch_one(&pool)
    .await
    .expect("edges_co_owner_shape must exist after migration 072");

    assert!(
        !validated,
        "edges_co_owner_shape must stay NOT VALID; VALIDATE CONSTRAINT is \
         PR-16's 075/076 and takes a full-table lock this migration does not \
         advertise"
    );
    assert!(
        src.contains("co_owner_group_id IS NULL"),
        "the single-owner case must be permitted: {src}"
    );
    assert!(
        src.contains("visibility)::text = 'group'::text") || src.contains("visibility = 'group'"),
        "a co-owner is only meaningful on a group-visible row; without this \
         conjunct a public edge could carry a co-owner the read fragment never \
         checks: {src}"
    );
    assert!(
        src.contains("co_owner_group_id <> owner_group_id"),
        "co_owner = owner is not co-ownership; permitting it would make the \
         read fragment test one group's membership twice: {src}"
    );
}
