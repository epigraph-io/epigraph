//! `Viewer::detach_scoped` — the one duplication a `Viewer` still permits, and
//! the two things that must be true of it.
//!
//! # Why this file exists at all
//!
//! `Viewer` is not `Clone`, so an owned `Viewer` can no longer be derived from
//! a borrowed one. The type-level half of that is proved where it belongs —
//! by the `compile_fail` doctests on `epigraph_db::MaintenanceSession`, because
//! a shape that is supposed to be UNREPRESENTABLE cannot be proved by a test
//! that runs.
//!
//! `detach_scoped` is the deliberate exception: three production call sites
//! need an owned copy of a REQUEST's own read authority, because a detached
//! `tokio::spawn` and an axum extractor both take their viewer by value. That
//! exception is a behavioural surface, so it gets behavioural coverage, and
//! both directions of it:
//!
//! * **Negative** — it refuses an unrestricted viewer. A duplication that could
//!   hand one back would reintroduce exactly the shape the missing `Clone`
//!   removes, and it would do so through a function whose name suggests it
//!   cannot.
//! * **Positive** — it preserves the principal's authority EXACTLY. This half
//!   is not decoration. A `detach_scoped` that returned an empty-group viewer
//!   would pass every "a stranger cannot read X" assertion in this repository
//!   while silently emptying the corpus for the caller it was supposed to
//!   serve, and the negative test above would still pass.
//!
//! Both assertions are on the EFFECT — which rows come back — not on the
//! shape of the value, because the shape is private and the rows are the point.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::{SystemReason, Viewer};
use epigraph_db::ClaimRepository;
use sqlx::PgPool;

/// The unrestricted viewer a [`epigraph_db::MaintenanceSession`] owns cannot be
/// copied out of it.
///
/// This is the arm a mutation has to kill: make `detach_scoped` rebuild the
/// unrestricted shape instead of refusing it and this `assert!` fails on its
/// own message, with nothing running inside an `.expect(...)`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unrestricted_viewer_cannot_be_detached(pool: PgPool) {
    let scoped = fixture::scoped_pool(&pool).await;
    let session = scoped
        .maintenance_session(SystemReason::SchemaContractTest)
        .await
        .expect("maintenance session");

    assert!(
        session.viewer().detach_scoped().is_none(),
        "an unrestricted viewer's authority is one half of a pair whose other \
         half is this session's privileged connection. Handing back an owned \
         copy would let the two come apart, which is the whole reason `Viewer` \
         is no longer `Clone`."
    );
}

/// The same refusal, reached through the other constructor that mints an
/// unrestricted viewer — so the property is about the SHAPE and not about
/// `MaintenanceSession`'s particular one.
#[sqlx::test(migrations = "../../migrations")]
async fn the_refusal_is_a_property_of_the_shape_not_of_one_constructor(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;

    assert!(
        bypass.detach_scoped().is_none(),
        "`detach_scoped` must refuse every unrestricted viewer, however it was \
         minted; a refusal keyed on one construction path is a refusal one \
         construction path away from being wrong"
    );
}

/// Class P, and the half that a refusal-only test cannot give you: a detached
/// viewer reads EXACTLY what the viewer it came from reads.
///
/// Asserted on rows, against a fixture that contains a `visibility = 'group'`
/// row — without one every viewer predicate matches every row and the whole
/// assertion is vacuous.
#[sqlx::test(migrations = "../../migrations")]
async fn a_detached_scoped_viewer_reads_exactly_what_its_original_reads(pool: PgPool) {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "detach-owner").await;
    let (stranger, _stranger_group) =
        fixture::seed_agent_with_group(&pool, "detach-stranger").await;

    let mine =
        fixture::seed_group_claim(&pool, owner, owner_group, "the owner's private row").await;

    let owner_viewer = Viewer::resolve(&pool, owner).await.expect("owner viewer");
    let stranger_viewer = Viewer::resolve(&pool, stranger)
        .await
        .expect("stranger viewer");

    let detached_owner = owner_viewer
        .detach_scoped()
        .expect("a scoped viewer detaches");
    let detached_stranger = stranger_viewer
        .detach_scoped()
        .expect("a scoped viewer detaches");

    let served = ClaimRepository::get_by_id(&pool, &detached_owner, mine.into())
        .await
        .expect("get_by_id");
    assert!(
        served.is_some(),
        "the DETACHED copy of the owner's viewer must still read the owner's \
         own group-private row. Without this arm, a `detach_scoped` that \
         returned an authority-free viewer would satisfy every negative \
         assertion in this repository while emptying the corpus for the caller \
         it exists to serve."
    );

    let withheld = ClaimRepository::get_by_id(&pool, &detached_stranger, mine.into())
        .await
        .expect("get_by_id");
    assert!(
        withheld.is_none(),
        "the DETACHED copy of a stranger's viewer must not widen: detaching is \
         a copy of one principal's authority, not a promotion"
    );
}
