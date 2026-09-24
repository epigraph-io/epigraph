//! `routes/belief.rs`'s fourteen read-only handlers and `routes/computation.rs`'s
//! four each serve every statement of their request on ONE viewer-stamped
//! connection, and every read that has a viewer to spend suppresses on it.
//!
//! # What this file is, in the series
//!
//! Conversion shard 4 against `D-PR17-request-path-never-stamps-session-gucs`:
//! 19 sites across two route files. It copies the template PR-28 established in
//! `claims_query_scoped_read.rs` and PR-29 carried into
//! `search_voids_methods_scoped_read.rs` — direct `async fn` invocation, a
//! CALIBRATION arm on every negative assertion, and
//! `viewer_fixture::downgraded_pool` for `AppState.db_pool`.
//!
//! # THE AUTHORITY TRAP, AND WHAT THIS FILE DOES ABOUT IT
//!
//! `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` AND
//! the table owner, so **no RLS policy filters anything on the pool it hands
//! you**. Worse for a conversion shard: `AppState::with_scoped_pool` sets
//! `db_pool = scoped.inner().clone()`, so on that fixture the converted and the
//! unconverted arms are the SAME POOL and reverting a site to `&state.db_pool`
//! changes not one observable row.
//!
//! That matters more for shard 4 than for its predecessors, because shard 4 is
//! the first whose converted handlers have real HTTP coverage and it made
//! `epigraph_api::build_app_for_tests` build through `with_scoped_pool` so that
//! coverage keeps running. **Those HTTP tests are not a mutation proof and must
//! not be read as one** — they run on exactly the same-pool fixture the previous
//! paragraph describes. This file is the proof; that change is plumbing.
//!
//! So [`split_state`] gives `AppState.db_pool` its own pool whose every
//! connection is `SET SESSION AUTHORIZATION epigraph_app` in `after_connect`,
//! while `AppState.scoped` holds an ordinary `ScopedPool`. `db_pool !=
//! scoped.inner()`, the raw arm is FILTERED and unstamped, and reverting a
//! converted site is observable.
//!
//! # Coverage, stated as a fraction rather than implied
//!
//! Four arms drive 8 of the shard's 19 converted sites. That is not every site,
//! and the reason is a fixture gap rather than a judgement about which sites
//! matter: the remaining handlers read `mass_functions`, `ds_bayesian_divergence`
//! and `ds_combined_beliefs`, and **no seeder exists for any of those relations
//! in `epigraph-db/tests/viewer_fixture.rs`** — a grep for
//! `mass_function|divergence|scoped_belief` there returns nothing. Writing four
//! new seeders is a larger and separable piece of work than the conversion it
//! would cover. The sizing consequence is stated in the PR body: for this series
//! the unit that predicts test cost is *distinct relations needing a new
//! fixture*, not site count.
//!
//! | route | sites driven | arm |
//! |---|---|---|
//! | `belief.rs::frame_claims_sorted` | `FrameRepository::get_by_id`, `ClaimRepository::frame_claims_sorted` | [`frame_claims_sorted_serves_the_viewers_own_group_private_claim`] |
//! | `belief.rs::claims_by_belief` | `ClaimRepository::list_by_belief_bounds` | [`claims_by_belief_serves_the_viewers_own_group_private_claim`] |
//! | `belief.rs::get_frame` | `FrameRepository::get_by_id`, `::get_claims_in_frame` | [`get_frame_serves_a_group_private_frame_to_its_own_group`] |
//! | `computation.rs::belief_at_time` | `ClaimRepository::get_by_id`, `EvidenceRepository::provided_for_claim_as_of` | [`belief_at_time_replays_only_the_evidence_the_viewer_can_see`] |
//!
//! # What IS and is NOT proven here
//!
//! `ScopedPoolOptions` exposes no `after_connect`, so the SCOPED arm is still a
//! superuser session and the assertions below observe the in-query `$V`
//! predicate on the converted path, not migration 077's policies.
//!
//! **The policy half on the CONVERTED side is NOT pinned anywhere, and shard 4
//! is the first shard in the series to ship without pinning it.** An earlier
//! revision of this paragraph said it was "pinned on the repo primitives
//! elsewhere in `epigraph-db/tests/`", which does not survive measurement and is
//! corrected here rather than left to stop the next reader looking. What exists
//! for `mass_functions`, `ds_combined_beliefs` and `ds_bayesian_divergence` is
//! RELATION-level: membership in `rls_enforcement.rs`'s protected-relation list,
//! which asserts the relation is RLS-enabled and FORCEd. That is not a read
//! through these repo primitives on a downgraded stamped connection. Measured:
//! the three files under `epigraph-db/tests/` that use `downgraded_pool` or
//! `scoped_pool` name none of `MassFunctionRepository`, `DivergenceRepository`,
//! `ScopedBeliefRepository` or `FrameRepository` — the intersection is EMPTY.
//!
//! Each of the three preceding shards shipped a `_policy` sibling under
//! `epigraph-db/tests/` that does exactly this (`claims_query_scoped_read_policy`,
//! `lineage_scoped_read_policy`, `search_voids_methods_scoped_read_policy`).
//! Shard 4 shipped none, for the same fixture reason the coverage fraction above
//! gives. The gap is registered as `F-SHARD4-A4` with an owner; the mutation
//! proofs and the arms below stand regardless, because what they pin is the
//! executor, not the policy.
//!
//! **The UNCONVERTED side is proven here, and more sharply than the template
//! files this copies claim for themselves.** Reverting
//! `ClaimRepository::frame_claims_sorted`'s executor to `&state.db_pool`
//! makes [`frame_claims_sorted_serves_the_viewers_own_group_private_claim`]
//! fail with an EMPTY result — and the viewer's own group was bound into `$V`
//! on that same statement, so the in-query predicate would have returned the
//! row. Only a row-level policy can have removed it. That is the
//! non-bypass-role, principal-set, groups-deliberately-empty condition the
//! acceptance asks for, observed directly rather than deferred to a sibling
//! file: it is the FORCE differential itself, not a proxy for it.

mod common;
mod viewer_fixture;

use axum::extract::{Path, Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::belief::{
    claims_by_belief, frame_claims_sorted, get_frame, BeliefFilterQuery, FrameClaimsQuery,
};
use epigraph_api::routes::computation::{belief_at_time, BeliefAtQuery};
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    downgraded_pool, public_viewer, scoped_pool, seed_agent_with_group, seed_group_claim,
    seed_public_claim,
};

// ── The instrument ──

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped.
///
/// The asymmetry is the instrument: a converted site reads through `scoped` and
/// works; the same site reverted to `&state.db_pool` reads through a session the
/// RLS policies filter, with no `epigraph.group_ids` to admit the viewer's own
/// group, and loses the rows.
///
/// This is the sixth hand-copy of this body in `crates/epigraph-api/tests/`.
/// That duplication is real and is registered; it is copied here rather than
/// canonicalised because promoting it is a change to the shared fixture whose
/// reach is the subject of an open entry, and bundling that into a conversion
/// shard would put two unrelated decisions in one diff.
async fn split_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let scoped = scoped_pool(pool).await;

    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);

    // CALIBRATION: the two arms must really be different sessions, or every
    // assertion below is about one pool wearing two names.
    assert!(
        state.scoped.is_some(),
        "CALIBRATION: AppState.scoped must be populated, or read_as refuses and \
         the handler cannot serve at all"
    );
    let raw_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&state.db_pool)
        .await
        .expect("current_user on the raw pool");
    assert_eq!(
        raw_user, "epigraph_app",
        "CALIBRATION: AppState.db_pool must be DOWNGRADED, or reverting a converted \
         site to it is invisible and the mutation proof is vacuous"
    );
    let scoped_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(state.scoped.as_ref().expect("scoped").inner())
        .await
        .expect("current_user on the scoped pool");
    assert_ne!(
        scoped_user, raw_user,
        "CALIBRATION: the scoped and raw arms must not be the same session — that \
         sameness is exactly what makes with_scoped_pool useless as a conversion fixture"
    );

    state
}

/// Resolved on the SUPERUSER pool, never the downgraded one: `Viewer::resolve`
/// reads `group_memberships`, and on a filtered unstamped session it resolves to
/// an EMPTY group set — which would satisfy every "the viewer sees its own row"
/// assertion here for entirely the wrong reason, by making the viewer a stranger.
async fn viewer_for(pool: &PgPool, agent: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
}

// ── File-local seeding ──

/// `belief`/`plausibility` on a claim, so the belief-bounds predicate admits it.
///
/// `NULL >= 0.0` is falsy, so an unstamped claim never satisfies
/// `c.belief >= $min AND c.plausibility <= $max` and the arm would pass for a
/// reason unrelated to tenancy.
async fn set_belief(pool: &PgPool, claim: Uuid, belief: f64, plausibility: f64) {
    sqlx::query("UPDATE claims SET belief = $2, plausibility = $3 WHERE id = $1")
        .bind(claim)
        .bind(belief)
        .bind(plausibility)
        .execute(pool)
        .await
        .expect("set belief columns");
}

/// Move a seeded frame into `group`, so `frames`' own policy — not only the
/// `claim_frames` and `claims` policies downstream of it — is exercised.
async fn privatise_frame(pool: &PgPool, frame: Uuid, group: Uuid) {
    sqlx::query("UPDATE frames SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(frame)
        .bind(group)
        .execute(pool)
        .await
        .expect("privatise frame");
}

/// An evidence row plus the `provided_evidence` edge `belief_at_time` replays it
/// through. `seed_evidence` alone is not enough: the repo statement joins
/// `edges`, so an evidence row with no edge never appears on either arm.
///
/// `evidence_type` must be one of migration 001's `evidence_type_valid` set, and
/// `seed_evidence` derives `content_hash` from `(claim, evidence_type)` — so two
/// rows on one claim must differ in TYPE, not in a label.
async fn seed_belief_at_evidence(pool: &PgPool, claim: Uuid, evidence_type: &str) -> Uuid {
    let evidence = viewer_fixture::seed_evidence(pool, claim, evidence_type).await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'evidence', $3, 'claim', 'provided_evidence')",
    )
    .bind(Uuid::new_v4())
    .bind(evidence)
    .bind(claim)
    .execute(pool)
    .await
    .expect("seed provided_evidence edge");
    evidence
}

fn frame_claims_params() -> FrameClaimsQuery {
    FrameClaimsQuery {
        sort_by: "belief".to_string(),
        order: "desc".to_string(),
        limit: 1000,
        offset: 0,
        agent_id: None,
    }
}

// ── belief.rs ──

/// `GET /api/v1/frames/:id/claims` — the handler PR-07 found holding a `Viewer`
/// and never filtering on it, and now one of the two sites shard 4 converted in
/// the same body.
///
/// The over-suppression direction is the one that catches a reversion to the raw
/// pool: with the handler reading `&state.db_pool`, the filtered unstamped
/// session has no `epigraph.group_ids` to admit the viewer's own group, the
/// `claim_frames` row that migration 070 stamped from the private claim is gone,
/// and the claim silently disappears. That direction is permanent and looks like
/// data loss rather than like a leak, which is why it is asserted first.
#[sqlx::test(migrations = "../../migrations")]
async fn frame_claims_sorted_serves_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s4-fcs-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "s4-fcs-theirs").await;

    let mine = seed_group_claim(&pool, agent, group, "s4 fcs: my claim").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "s4 fcs: their claim").await;
    set_belief(&pool, mine, 0.7, 0.9).await;
    set_belief(&pool, theirs, 0.8, 0.95).await;

    let frame = common::seed_frame_with_claim(&pool, mine).await;
    sqlx::query("INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2)")
        .bind(theirs)
        .bind(frame)
        .execute(&pool)
        .await
        .expect("attach the stranger's claim to the same frame");

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = frame_claims_sorted(
        ViewerExtractor(viewer),
        State(state),
        Path(frame),
        Query(frame_claims_params()),
    )
    .await
    .expect(
        "the viewer is entitled to read its own group-private claim, so this must SERVE. \
         A failure here is the conversion itself: either `read_as` refused because the \
         AppState carries no ScopedPool, or a statement errored on the stamped connection",
    )
    .0;

    let got: Vec<Uuid> = out.iter().map(|r| r.claim_id).collect();
    assert!(
        got.contains(&mine),
        "CALIBRATION: a group-private claim the viewer is a MEMBER of must be served. \
         Absence here is the fail-closed drift that reads as data loss — and if the \
         handler is reading the raw pool instead of a stamped connection, this is where \
         it shows; got {got:?}"
    );
    assert!(
        !got.contains(&theirs),
        "a claim owned by a group the viewer is not in must be ABSENT from the frame's \
         claim list, not present with its content blanked; got {got:?}"
    );
    assert_eq!(
        got.len(),
        1,
        "exactly one of the two claims attached to this frame is readable by this viewer; \
         a different count means the predicate is admitting or dropping rows for a reason \
         this arm does not model. got {got:?}"
    );
}

/// `GET /api/v1/claims/by-belief` — an unbounded, caller-paginated corpus scan,
/// which is why its site is the one where an unstamped read is most costly.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_by_belief_serves_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s4-cbb-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "s4-cbb-theirs").await;

    let mine = seed_group_claim(&pool, agent, group, "s4 cbb: my claim").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "s4 cbb: their claim").await;
    set_belief(&pool, mine, 0.6, 0.9).await;
    set_belief(&pool, theirs, 0.6, 0.9).await;

    // Narrow to a private frame both claims sit in, so the assertion is about
    // these two rows and not about whatever else the page happens to contain.
    let frame = common::seed_frame_with_claim(&pool, mine).await;
    sqlx::query("INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2)")
        .bind(theirs)
        .bind(frame)
        .execute(&pool)
        .await
        .expect("attach the stranger's claim to the same frame");

    let state = split_state(&pool).await;
    let viewer = viewer_for(&pool, agent).await;

    let out = claims_by_belief(
        ViewerExtractor(viewer),
        State(state),
        Query(BeliefFilterQuery {
            min_belief: Some(0.0),
            max_plausibility: Some(1.0),
            frame_id: Some(frame),
            limit: 1000,
            offset: 0,
            agent_id: None,
        }),
    )
    .await
    .expect("claims_by_belief must serve on the stamped connection")
    .0;

    let got: Vec<Uuid> = out.iter().map(|r| r.id).collect();
    assert!(
        got.contains(&mine),
        "CALIBRATION: the viewer's own group-private claim must survive the belief scan. \
         Its absence is what a reversion to the raw pool produces; got {got:?}"
    );
    assert!(
        !got.contains(&theirs),
        "a claim owned by a group the viewer is not in must be ABSENT from the belief \
         scan; got {got:?}"
    );
    assert!(
        !out.iter().any(|r| r.content.contains("their claim")),
        "another group's claim CONTENT must not appear in the belief-scan body"
    );
}

/// `GET /api/v1/frames/:id` — the arm that exercises `frames`' own row-level
/// policy rather than only the `claims` policy downstream of it, and the one
/// that proves both of the handler's statements run on the SAME stamped handle.
///
/// The stranger direction here is an EXISTENCE assertion: a frame the caller
/// cannot see is a 404, not a 403, so the negative arm asserts the error rather
/// than an empty claim list — an empty list would mean the frame was disclosed
/// and only its contents withheld.
#[sqlx::test(migrations = "../../migrations")]
async fn get_frame_serves_a_group_private_frame_to_its_own_group(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s4-gf-mine").await;

    let mine = seed_group_claim(&pool, agent, group, "s4 gf: my claim").await;
    let frame = common::seed_frame_with_claim(&pool, mine).await;
    privatise_frame(&pool, frame, group).await;

    let state = split_state(&pool).await;

    let out = get_frame(
        ViewerExtractor(viewer_for(&pool, agent).await),
        State(state.clone()),
        Path(frame),
    )
    .await
    .expect(
        "a member of the frame's owning group must be served the frame AND its claims. \
         A NotFound here means the frames read lost the row — which is exactly what the \
         unstamped filtered session does",
    )
    .0;

    assert_eq!(
        out.claim_count, 1,
        "CALIBRATION: the frame's one claim must come back on the same stamped handle \
         that admitted the frame. A frame that resolves with an EMPTY claim list is the \
         signature of two statements on two different connections"
    );
    assert!(
        out.claims.iter().any(|c| c.claim_id == mine),
        "the seeded claim must be the one returned; got {:?}",
        out.claims.iter().map(|c| c.claim_id).collect::<Vec<_>>()
    );

    // A principal with no membership in the frame's group must not be able to
    // distinguish this frame from one that does not exist.
    let stranger_out = get_frame(
        ViewerExtractor(public_viewer(&pool).await),
        State(state),
        Path(frame),
    )
    .await;
    assert!(
        stranger_out.is_err(),
        "a group-private frame must be absent for a non-member — a 200 with an empty \
         claim list would confirm the frame exists"
    );
}

// ── computation.rs ──

/// `GET /api/v1/claims/:id/belief-at` — both of its sites on one stamped handle.
///
/// The CLAIM is public on purpose: a stranger passes the existence check and
/// gets a reply, which is the sharp case — the endpoint must withhold the
/// evidence rather than 404 the whole claim. `evidence_count` is the number this
/// arm asserts, because it is the only place the suppression is observable in
/// the response.
#[sqlx::test(migrations = "../../migrations")]
async fn belief_at_time_replays_only_the_evidence_the_viewer_can_see(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "s4-bat").await;
    let claim = seed_public_claim(&pool, agent, "s4 bat: public claim").await;
    let as_of = chrono::Utc::now() + chrono::Duration::days(1);

    let private_evidence = seed_belief_at_evidence(&pool, claim, "document").await;
    seed_belief_at_evidence(&pool, claim, "observation").await;

    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $1 WHERE id = $2")
        .bind(group)
        .bind(private_evidence)
        .execute(&pool)
        .await
        .expect("privatise one evidence row");

    let state = split_state(&pool).await;

    let owner = belief_at_time(
        ViewerExtractor(viewer_for(&pool, agent).await),
        State(state.clone()),
        Path(claim),
        Query(BeliefAtQuery { as_of }),
    )
    .await
    .expect(
        "the owner must be served on the stamped connection. A NotFound here means the \
         existence check lost a PUBLIC claim, which is the unstamped-session signature",
    )
    .0;
    assert_eq!(
        owner["evidence_count"], 2,
        "CALIBRATION: the owner replays BOTH evidence rows. A count of 1 here means the \
         group-private row was lost to the reader who owns it — the over-suppression \
         direction — and a count of 0 means the join broke rather than the filter working"
    );

    let stranger = belief_at_time(
        ViewerExtractor(public_viewer(&pool).await),
        State(state),
        Path(claim),
        Query(BeliefAtQuery { as_of }),
    )
    .await
    .expect("the claim is PUBLIC, so a stranger must still be served a reply")
    .0;
    assert_eq!(
        stranger["evidence_count"], 1,
        "a stranger replays only the public control row; the group-private evidence must \
         not contribute to the reconstructed belief"
    );
}
