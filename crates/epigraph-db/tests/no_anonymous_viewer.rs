//! Source lint: the `Viewer` has exactly two shapes and no way to conjure one.
//!
//! Plan §4.13. The seed of `viewer_ratchet.rs`, which PR-04 split out: the
//! **count** of `SystemReason` variants is a monotone-decreasing ratchet and
//! lives there; the compile-time exhaustiveness check and the source lint stay
//! here. An equality assertion on the count and a `<=` ratchet cannot both
//! survive the first removal of a bypass reason.
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
//! 2. A **compiled** assertion over `SystemReason`. A count alone is weak —
//!    someone could add a variant and bump the number. The exhaustive `match`
//!    below is the real check: adding a variant without also handling it here
//!    fails to *compile*, which forces the author past a review boundary.
//!
//! 3. Since PR-04, one live database test: plan §4.3's personal-group invariant,
//!    whose failure mode is silent and therefore cannot be left as prose.

use epigraph_db::{repos::AgentRepository, SystemReason, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

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
fn system_reason_all_is_exhaustive() {
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

    // The COUNT assertion deliberately does not live here. It is a
    // monotone-decreasing ratchet in `viewer_ratchet.rs`
    // (`bypass_count_is_monotone_decreasing_from_the_pr04_baseline`). An
    // `assert_eq!(…, 10)` here and a `<= PR04_BASELINE` there cannot both
    // survive the first legitimate REMOVAL of a bypass reason, and whoever hit
    // that would have to edit one of the two to keep the other green — which is
    // how a ratchet quietly stops ratcheting. This file keeps the half the
    // compiler enforces; that file keeps the number.
}

/// Plan §4.3's personal-group invariant, as a live tripwire.
///
/// A `Scoped` viewer's `group_ids` must **always** contain the principal's own
/// personal group. As of PR-02 that holds by provisioning rather than by
/// special-casing: `AgentRepository::ensure_personal_group` writes the agent a
/// `kind = 'personal'` group and a live `role = 'admin'` membership in it, and
/// `Viewer::resolve` reads that membership like any other. PR-03 parked this
/// test `#[ignore]`d with a `panic!` body on the belief that personal groups
/// arrived in PR-04; they had already arrived. PR-04 gives it a body.
///
/// **The failure mode is silent, which is the whole reason this exists.** If a
/// principal is provisioned without a personal group, nothing errors: the viewer
/// reads `visibility = 'public'` and nothing else, forever, and the symptom
/// presents as "the corpus is empty for new users" rather than as a bug in
/// `resolve`. Do not delete this test — deleting it is how the invariant
/// silently stops holding.
///
/// The GUC-side counterpart (the personal group actually reaching
/// `epigraph.group_ids`) is
/// `qual_guc_coherence.rs::the_personal_group_reaches_the_session_gucs`.
#[sqlx::test(migrations = "../../migrations")]
async fn resolve_unions_in_the_principals_personal_group(pool: PgPool) {
    // An agent inserted directly, as `oauth/token.rs` does before it calls
    // `ensure_for_client`.
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(&pool)
        .await
        .expect("seed agent");

    // Before provisioning: no groups at all. This is what the invariant is
    // protecting against becoming permanent.
    let before = Viewer::resolve(&pool, agent).await.expect("resolve");
    assert_eq!(
        before.group_bind(),
        Some(&[][..]),
        "precondition: an unprovisioned agent has no memberships"
    );

    let mut conn = pool.acquire().await.expect("acquire");
    let personal = AgentRepository::ensure_personal_group(&mut conn, agent)
        .await
        .expect("ensure_personal_group");
    drop(conn);

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");

    assert!(
        viewer
            .group_bind()
            .expect("a scoped viewer binds its groups")
            .contains(&personal),
        "Viewer::resolve must union in the principal's personal group"
    );
    assert!(
        viewer.writable_groups().contains(&personal),
        "the personal-group membership is role='admin', so the principal's own \
         group must also be WRITABLE — otherwise a new user can read their own \
         group and never write to it"
    );

    // Idempotent: a second provisioning call must not create a second group or
    // a duplicate membership.
    let mut conn = pool.acquire().await.expect("acquire");
    let again = AgentRepository::ensure_personal_group(&mut conn, agent)
        .await
        .expect("ensure_personal_group is idempotent");
    drop(conn);
    assert_eq!(again, personal);

    let after = Viewer::resolve(&pool, agent).await.expect("resolve");
    assert_eq!(
        after.group_bind(),
        Some(&[personal][..]),
        "exactly one group, exactly once"
    );
}
