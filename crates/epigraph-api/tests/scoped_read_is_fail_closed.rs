//! `AppState::read_as` refuses when no `ScopedPool` was built, and serves when
//! one was.
//!
//! # Why this file exists
//!
//! `AppState.scoped` is an `Option`, and of the thirteen `AppState`
//! constructors exactly ONE — `with_scoped_pool`, which `bin/server.rs`
//! calls — populates it. Every other constructor, including the ones this test
//! suite and `spawn_app` build state through, leaves it `None`.
//!
//! That asymmetry is what makes the obvious implementation of a scoped-read
//! accessor a trap. An accessor that fell back to `self.db_pool` when `scoped`
//! is `None` would take the fallback branch in *every test in the workspace*
//! and the stamped branch in *production only*, so no test could distinguish a
//! correctly plumbed request from an unstamped one, and the whole mechanism
//! would be inert exactly where it matters. Under FORCE that is worse than
//! inert: an unstamped connection makes the RLS policy and the in-query
//! predicate disagree, and rows vanish from their own owners with a 200 and no
//! log line.
//!
//! So the accessor refuses — and a refusal nobody has watched happen is the
//! same defect wearing the opposite mask. Both directions are asserted here:
//! the `None` constructor must ERROR, and the `with_scoped_pool` constructor
//! must SERVE and actually stamp the GUC the RLS policy reads. Without the
//! second half, an accessor that was simply broken would pass the first.

mod viewer_fixture;

use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::DbError;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{scoped_pool, seed_agent_with_group};

/// The `None` half: a state built through any non-scoped constructor must
/// refuse a scoped read rather than quietly serving it on the raw pool.
#[sqlx::test(migrations = "../../migrations")]
async fn read_as_refuses_when_no_scoped_pool_was_built(pool: PgPool) {
    let (agent, _group) = seed_agent_with_group(&pool, "fail-closed-none").await;
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("resolve");

    // `with_db` is the constructor the api test suite and `spawn_app` use. It
    // leaves `scoped` as `None`.
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    assert!(
        state.scoped.is_none(),
        "CALIBRATION: with_db must leave `scoped` unset, or this test is asserting nothing"
    );

    let err = state
        .read_as(&viewer)
        .await
        .expect_err("a state with no ScopedPool must REFUSE a scoped read, not fall back");

    match err {
        DbError::InvalidData { reason } => {
            assert!(
                reason.contains("with_scoped_pool"),
                "the refusal must name the constructor that fixes it; got: {reason}"
            );
            assert!(
                reason.contains("Refusing"),
                "the refusal must say it is refusing rather than degrading; got: {reason}"
            );
        }
        other => panic!("expected DbError::InvalidData, got {other:?}"),
    }
}

/// The other half, and the one that keeps the first honest: with a `ScopedPool`
/// attached the same call SERVES, and the connection it returns really does
/// carry the viewer's group set in `epigraph.group_ids` — the GUC migration
/// 077's policies read.
///
/// An accessor that always errored would satisfy the test above.
#[sqlx::test(migrations = "../../migrations")]
async fn read_as_serves_and_stamps_when_a_scoped_pool_was_built(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "fail-closed-some").await;
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("resolve");

    let state = AppState::with_scoped_pool(scoped_pool(&pool).await, ApiConfig::default());
    assert!(
        state.scoped.is_some(),
        "CALIBRATION: with_scoped_pool must populate `scoped`"
    );

    let mut r = state
        .read_as(&viewer)
        .await
        .expect("a state built from a ScopedPool must serve a scoped read");

    // A SECOND statement on the handle. This is what proves the stamp landed
    // and survived, rather than merely that the acquire succeeded.
    let (observed,): (Vec<Uuid>,) = sqlx::query_as("SELECT epigraph_session_groups()")
        .fetch_one(&mut *r)
        .await
        .expect("epigraph_session_groups()");

    assert!(
        observed.contains(&group),
        "the connection read_as returned must carry the viewer's group in \
         epigraph.group_ids — that GUC is what the RLS policies read, and a request served \
         without it is the fail-closed drift step 11d turns into an outage. \
         got {observed:?}, expected to contain {group}"
    );

    r.commit().await.expect("commit");
}

/// A bypass viewer must not reach an application connection through this door.
///
/// It emits no predicate and is still filtered by RLS, so it reads zero rows
/// rather than all rows. `ScopedPool` refuses it at both primitives; this pins
/// that routing through `AppState` does not launder it.
#[sqlx::test(migrations = "../../migrations")]
async fn read_as_refuses_a_bypass_viewer(pool: PgPool) {
    let (scoped, bypass) = viewer_fixture::bypass(&pool).await;
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());

    let err = state
        .read_as(&bypass)
        .await
        .expect_err("a bypass viewer must not be served on an application connection");

    match err {
        DbError::InvalidData { reason } => assert!(
            reason.contains("unscoped_for_maintenance"),
            "the refusal must name where a bypass belongs; got: {reason}"
        ),
        other => panic!("expected DbError::InvalidData, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The pilot conversion: `routes/conflicts.rs::classify_conflict`
// ---------------------------------------------------------------------------
//
// One handler is converted onto `AppState::read_as` in this PR, deliberately
// rather than none. A mechanism with zero production call sites is exactly the
// state `acquire_as` was already in — it is what
// `D-PR17-request-path-never-stamps-session-gucs` records as the open defect —
// so shipping a second unused entry point would reproduce the problem it exists
// to close. `classify_conflict` was chosen because it is a pure read, already
// carries a `ViewerExtractor`, and its repo method already has a
// connection-taking sibling that takes a `&Viewer` and splices the visibility
// marker from it, so the pilot needs no repo-layer change. ("Spends" would be
// the wrong verb: `Viewer::splice` takes `&self` and consumes nothing.)
//
// TWO THINGS THE PILOT ALSO ESTABLISHES AS THE TEMPLATE, both of which a shard
// should copy rather than re-derive:
//
// * `get_by_id_conn` is now FIELD-equivalent to `get_by_id`, not merely
//   visibility-equivalent. It used to project seven columns where its
//   pool-taking twin projects nine, so a superseded claim came back reporting
//   `is_current = true`. Harmless in this handler (it serialises only
//   `content` and `truth_value`) and invisible to every gate, because the
//   dropped fields default to plausible values rather than erroring. A `*_conn`
//   sibling is not automatically a drop-in: diff the projected columns as well
//   as the visibility marker.
// * The `read_as` refusal is LOGGED in full and answered with a short opaque
//   message. Its reason is a paragraph of internal design prose aimed at
//   whoever mis-built the `AppState`, and `errors.rs` serialises
//   `ApiError::InternalError { message }` verbatim into the response body.
//
// The handler is invoked directly rather than over HTTP: it is an ordinary
// async fn, and calling it here exercises the converted body without standing
// up bearer auth. `spawn_app` builds state through a NON-scoped constructor, so
// no HTTP fixture in this crate could reach a stamped read today — closing that
// is the natural first task of the conversion shards, and is called out in the
// PR body rather than half-done here.

use axum::extract::{Json as JsonBody, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::conflicts::{classify_conflict, ClassifyConflictRequest};
use viewer_fixture::{seed_group_claim, seed_public_claim};

/// The positive half: two claims the viewer may see come back through the
/// stamped connection.
#[sqlx::test(migrations = "../../migrations")]
async fn classify_conflict_serves_claims_the_viewer_can_see(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "pilot-visible").await;
    let a = seed_public_claim(&pool, agent, "pilot claim A").await;
    let b = seed_group_claim(&pool, agent, group, "pilot claim B").await;

    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("resolve");
    let state = AppState::with_scoped_pool(scoped_pool(&pool).await, ApiConfig::default());

    let out = classify_conflict(
        ViewerExtractor(viewer),
        State(state),
        JsonBody(ClassifyConflictRequest {
            claim_a_id: a,
            claim_b_id: b,
        }),
    )
    .await
    .expect("both claims are visible to this viewer");

    assert_eq!(
        out.0["claim_a"]["content"], "pilot claim A",
        "the converted handler must still return claim A's content"
    );
    assert_eq!(
        out.0["claim_b"]["content"], "pilot claim B",
        "a group-private claim the viewer IS a member of must remain readable — the \
         over-restricting direction is silent and permanent, so it needs its own assertion"
    );
}

/// The negative half, and the one the conversion is FOR: a group-private claim
/// owned by a group this viewer is not a member of is not served.
///
/// Note what this does and does not prove. `#[sqlx::test]` connects as
/// `epigraph`, which is superuser, `BYPASSRLS` and the table owner, so no RLS
/// policy filters anything here — the exclusion observed below is the in-query
/// `$V` predicate that `get_by_id_conn` splices, not the policy. That is still
/// the assertion worth making at this layer: the two filters are populated from
/// the same `Viewer`, and this pins the half that is observable on a superuser
/// session. The policy half is pinned on a genuinely filtered session in
/// `epigraph-db/tests/qual_guc_coherence.rs::read_as_agrees_with_the_policy_on_a_filtered_session_*`.
#[sqlx::test(migrations = "../../migrations")]
async fn classify_conflict_does_not_serve_a_claim_outside_the_viewers_groups(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "pilot-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "pilot-theirs").await;

    let mine = seed_group_claim(&pool, agent, group, "my claim").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "not my claim").await;

    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("resolve");
    let state = AppState::with_scoped_pool(scoped_pool(&pool).await, ApiConfig::default());

    // CALIBRATION: the same handler DOES serve the viewer's own group-private
    // claim, so the refusal below is about tenancy and not about the fixture.
    let _calibration = classify_conflict(
        ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, agent)
                .await
                .expect("resolve"),
        ),
        State(state.clone()),
        JsonBody(ClassifyConflictRequest {
            claim_a_id: mine,
            claim_b_id: mine,
        }),
    )
    .await
    .expect("CALIBRATION: the viewer's own group-private claim must be readable");

    let err = classify_conflict(
        ViewerExtractor(viewer),
        State(state),
        JsonBody(ClassifyConflictRequest {
            claim_a_id: mine,
            claim_b_id: theirs,
        }),
    )
    .await
    .expect_err("a claim owned by a group the viewer is not in must not be served");

    // A non-visible row is ABSENT, not blanked (PR-14).
    assert!(
        matches!(err, epigraph_api::ApiError::NotFound { .. }),
        "a claim outside the viewer's groups must read as absent; got {err:?}"
    );
}
