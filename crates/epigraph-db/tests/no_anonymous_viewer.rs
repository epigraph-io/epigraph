//! Source lint: the `Viewer` has exactly two shapes and no way to conjure one.
//!
//! Plan §4.13. This is the seed of PR-04's `viewer_ratchet.rs`.
//!
//! Two halves, deliberately different in kind:
//!
//! 1. A **text** scan of `src/visibility.rs`. The banned constructs are things
//!    that would let a caller materialise read authority out of nothing —
//!    `Default`, `From<Option<Uuid>>`, `From<&AuthContext>`, a zero-argument
//!    `unrestricted()` — plus any reintroduction of an `Anonymous` shape.
//!    A text scan is the right tool here precisely because these are *absences*:
//!    there is no type to assert against when the whole point is that the impl
//!    must not exist.
//!
//! 2. A **compiled** assertion over `SystemReason`. `ALL.len() == 10` alone is
//!    weak — someone could add a variant and bump the number. The exhaustive
//!    `match` below is the real check: adding a variant without also handling it
//!    here fails to *compile*, which forces the author past a review boundary.

use epigraph_db::SystemReason;

/// Constructs that must never appear in `visibility.rs`.
///
/// Each entry is `(needle, why)`. `why` is printed on failure so the next
/// person reads the reasoning rather than reverse-engineering it.
const BANNED: &[(&str, &str)] = &[
    (
        "Anonymous",
        "D3 removes the anonymous shape entirely: a caller with no agents.id \
         must be rejected by the extractor (401), never handed a Viewer that \
         'matches nothing'. An over-restricting viewer passes every \
         adversarial test while silently returning empty result sets.",
    ),
    ("anonymous(", "Same as above, in constructor form."),
    ("ViewerShape::Anonymous", "Same as above, in pattern form."),
    (
        "impl Default for Viewer",
        "A Default viewer is read authority from nothing, reachable by \
         `..Default::default()` in a struct literal nobody reviews.",
    ),
    (
        "From<Option<Uuid>> for Viewer",
        "This is the anonymous shape wearing a different hat: `None` would have \
         to mean something, and every meaning is wrong.",
    ),
    (
        "From<&AuthContext> for Viewer",
        "A Viewer requires a database round trip to resolve group membership. \
         An infallible conversion from a token cannot do that, so it would have \
         to invent an empty or unrestricted group set.",
    ),
    (
        "fn unrestricted(",
        "The unrestricted shape must cost a MaintenanceLease. A zero-argument \
         constructor decouples 'unrestricted viewer' from 'maintenance \
         connection', and under FORCEd RLS that combination returns zero rows \
         rather than all rows.",
    ),
];

fn visibility_source() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/visibility.rs");
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

/// Strip `//`-style comments so the doc block explaining *why* `Anonymous` is
/// banned does not itself trip the ban.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn visibility_module_has_no_anonymous_or_forgeable_viewer() {
    let code = strip_line_comments(&visibility_source());

    let mut violations = Vec::new();
    for (needle, why) in BANNED {
        if code.contains(needle) {
            violations.push(format!("  `{needle}` — {why}"));
        }
    }

    assert!(
        violations.is_empty(),
        "crates/epigraph-db/src/visibility.rs contains banned constructs:\n{}",
        violations.join("\n\n")
    );
}

#[test]
fn maintenance_lease_has_no_public_constructor() {
    let code = strip_line_comments(&visibility_source());
    assert!(
        code.contains("pub struct MaintenanceLease(pub(crate) ())"),
        "MaintenanceLease's field must stay `pub(crate)`. If it becomes `pub`, \
         any crate can construct a lease with `MaintenanceLease(())` and \
         `Viewer::system` stops being a type-level guarantee."
    );
    assert!(
        !code.contains("pub const fn new() -> Self")
            || code.contains("pub(crate) const fn new() -> Self"),
        "MaintenanceLease::new must stay crate-private."
    );
}

#[test]
fn system_reason_all_is_exhaustive_and_ten_long() {
    // The `match` is the load-bearing half: a new variant that is not handled
    // here fails to compile. Bumping the count without touching the match is
    // therefore impossible.
    for reason in SystemReason::ALL {
        let _label: &'static str = match reason {
            SystemReason::EmbeddingBackfill => "embedding_backfill",
            SystemReason::BeliefRecomputation => "belief_recomputation",
            SystemReason::DedupSweep => "dedup_sweep",
            SystemReason::ThemeClustering => "theme_clustering",
            SystemReason::TenancyBackfill => "tenancy_backfill",
            SystemReason::PrivatizationSelection => "privatization_selection",
            SystemReason::PrivatizationApply => "privatization_apply",
            SystemReason::PrivatizationReseal => "privatization_reseal",
            SystemReason::SchemaContractTest => "schema_contract_test",
            SystemReason::RlsCanaryProbe => "rls_canary_probe",
            // `SystemReason` is `#[non_exhaustive]`, so an out-of-crate match
            // needs a wildcard. Panicking here rather than returning a
            // placeholder is what makes this a ratchet: a new variant that
            // reaches this arm fails the test even though it compiles.
            other => panic!(
                "SystemReason::{other:?} is not handled by no_anonymous_viewer.rs. \
                 Adding a bypass reason is a security-relevant change: extend \
                 this match, extend SystemReason::ALL, and say in the commit \
                 body which job needs it and on which pool it runs."
            ),
        };
    }

    assert_eq!(
        SystemReason::ALL.len(),
        10,
        "SystemReason::ALL changed length. This is the bypass ratchet (plan \
         §4.13): it is expected to be monotone *decreasing* from here. Growing \
         it means a new code path reads the corpus unfiltered."
    );
}

/// PR-04 obligation, parked here as a tripwire rather than as prose.
///
/// Plan §4.3 specifies that a `Scoped` viewer's `group_ids` **always contains
/// the principal's personal group**, and that `Viewer::resolve` "always unions
/// in the principal's personal group". The shipped `resolve` does not, and
/// cannot: personal groups do not exist until PR-04 adds `ensure_personal_group`
/// and the world/seed groups. `visibility.rs` records the deferral in the
/// `ViewerShape::Scoped` doc.
///
/// The failure mode this guards is silent. If PR-04 lands the groups but not
/// the union, nothing errors — every `Scoped` viewer over a fresh principal
/// simply reads `visibility = 'public'` and nothing else, forever, and the
/// symptom looks like "the corpus is empty for new users" rather than like a
/// bug in `resolve`.
///
/// **PR-04: un-ignore this test and give it a body.** It should seed an agent,
/// call whatever provisions the personal group, and assert
/// `Viewer::resolve(...).group_bind()` contains it.
#[test]
#[ignore = "PR-04 obligation: un-ignore when ensure_personal_group lands"]
fn resolve_unions_in_the_principals_personal_group() {
    panic!(
        "Plan §4.3's personal-group invariant is not established yet. This test \
         is the ratchet on it: PR-04 must replace this panic with a real \
         assertion that Viewer::resolve's group_bind() contains the \
         principal's personal group, and remove the #[ignore]. Do not delete \
         the test — deleting it is how the invariant silently never holds."
    );
}
