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
