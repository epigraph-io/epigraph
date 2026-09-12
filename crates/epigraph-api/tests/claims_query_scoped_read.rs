//! `routes/claims_query.rs::list_claims_query` serves every statement of
//! `GET /api/v1/claims` on ONE viewer-stamped connection, and both of its paths
//! suppress on the viewer.
//!
//! # What this file is, in the series
//!
//! PR-28 is conversion shard 2 against
//! `D-PR17-request-path-never-stamps-session-gucs`. It copies the template PR-26
//! established in `crates/epigraph-api/tests/lineage_scoped_read.rs`: direct
//! `async fn` invocation, a CALIBRATION arm on every negative assertion, and
//! `viewer_fixture::downgraded_pool` for `AppState.db_pool`.
//!
//! # THE AUTHORITY TRAP, AND WHAT THIS FILE DOES ABOUT IT
//!
//! `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` AND
//! the table owner, so **no RLS policy filters anything on the pool it hands
//! you**. Worse for a conversion shard: `AppState::with_scoped_pool` sets
//! `db_pool = scoped.inner().clone()`, so on that fixture the converted and the
//! unconverted arms are the SAME POOL and reverting a site to `&state.db_pool`
//! changes not one observable row. A mutation proof built that way reports a
//! false pass.
//!
//! So [`split_state`] gives `AppState.db_pool` its own pool whose every
//! connection is `SET SESSION AUTHORIZATION epigraph_app` in `after_connect`,
//! while `AppState.scoped` holds an ordinary `ScopedPool`. `db_pool !=
//! scoped.inner()`, the raw arm is FILTERED and unstamped, and reverting any of
//! the five converted sites is observable.
//!
//! # The five sites, and which arm below drives each
//!
//! `needs_in_memory_filters` decides the path, and it includes
//! `methodology.is_some() || evidence_type.is_some()` — so a fired prefetch
//! FORCES the slow path and `count` can never run alongside a prefetch. The
//! sites therefore partition:
//!
//! | site | driven by |
//! |---|---|
//! | `count` (no-search shape) | [`the_fast_path_serves_the_viewers_own_group_private_claim`] |
//! | `list` (no-search shape) | the same |
//! | `count` + `list` (ILIKE shapes) | [`the_fast_paths_search_shape_still_suppresses`] |
//! | `list` (slow path) | [`the_slow_path_serves_the_viewers_own_group_private_claim`] |
//! | `claim_ids_by_methodology` | [`the_methodology_prefetch_narrows_without_dropping_the_viewers_own_claim`] |
//! | `claim_ids_by_evidence_type` | [`the_evidence_type_prefetch_narrows_without_dropping_the_viewers_own_claim`] |
//!
//! Both `list` and `count` carry TWO SQL texts with their own marker, selected
//! by `content_contains`, and `visibility_lint.rs` checks a marker's SPELLING
//! rather than its presence per shape. Driving only one shape would leave the
//! other unpinned, which is why the search arm exists.
//!
//! `total == claims.len()` is asserted on the FAST arms only. There it
//! separates the two sites independently: reverting only `count` gives
//! `total < len`, reverting only `list` gives `total > len`. On the slow path the
//! same equality is a tautology — `total` is assigned `claims.len()` after
//! filtering and before pagination — so asserting it there would look like
//! evidence and be none.
//!
//! # What is still NOT proven here
//!
//! `ScopedPoolOptions` exposes no `after_connect`, so the SCOPED arm is still a
//! superuser session and the assertions below observe the in-query `$V`
//! predicate, not migration 077's policies. The policy half — that a STAMPED
//! connection and an UNSTAMPED one disagree about the viewer's OWN rows once the
//! session is filtered — is pinned on the repo primitives in
//! `epigraph-db/tests/claims_query_scoped_read_policy.rs`, on both
//! `SessionGucMode` arms. Neither file is sufficient alone.
//!
//! There is also still no HTTP-level fixture: `spawn_app` builds `AppState`
//! through a non-scoped constructor, so the handler is called directly. That gap
//! is recorded in `docs/tenancy/progress.json`'s `prs.next` with an owner, and
//! this shard does not close it.

mod viewer_fixture;

use axum::extract::{Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::claims_query::{list_claims_query, ClaimListResponse, ClaimQueryParams};
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    downgraded_pool, scoped_pool, seed_agent_with_group, seed_evidence, seed_group_claim,
    seed_reasoning_trace,
};

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped.
///
/// The asymmetry is the instrument: a converted site reads through `scoped` and
/// works; the same site reverted to `&state.db_pool` reads through a session the
/// RLS policies filter, with no `epigraph.group_ids` to admit the viewer's own
/// group, and loses the rows.
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

/// Every filter off: the shape that takes the FAST path and the no-search SQL.
fn base_params() -> ClaimQueryParams {
    ClaimQueryParams {
        limit: None,
        offset: None,
        truth_min: None,
        truth_max: None,
        agent_id: None,
        exclude_agent_id: None,
        is_current: None,
        created_after: None,
        created_before: None,
        sort_by: None,
        sort_order: None,
        content_contains: None,
        methodology: None,
        evidence_type: None,
    }
}

async fn list(
    pool: &PgPool,
    state: AppState,
    agent: Uuid,
    params: ClaimQueryParams,
) -> ClaimListResponse {
    // Resolved on the SUPERUSER pool, never the downgraded one: `Viewer::resolve`
    // reads `group_memberships`, and on a filtered unstamped session it resolves
    // to an EMPTY group set — which would satisfy every "a stranger is absent"
    // assertion here for entirely the wrong reason.
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve");

    list_claims_query(ViewerExtractor(viewer), State(state), Query(params))
        .await
        .expect(
            "the viewer is entitled to read its own group-private claim, so the listing \
             must SERVE. A failure here is the conversion itself: either `read_as` refused \
             because the AppState carries no ScopedPool, or a statement errored on the \
             stamped connection",
        )
        .0
}

fn ids(r: &ClaimListResponse) -> Vec<Uuid> {
    r.claims.iter().map(|c| c.id).collect()
}

/// THE FAST PATH, on the no-search shapes of BOTH `count` and `list`.
///
/// The over-suppression direction is the one that catches a reversion to the raw
/// pool: with the handler reading `&state.db_pool`, the filtered unstamped
/// session has no `epigraph.group_ids` to admit the viewer's own group and the
/// claim silently disappears. That direction is permanent and looks like data
/// loss rather than like a leak, and it is the one PR-24's Mutation B broke.
#[sqlx::test(migrations = "../../migrations")]
async fn the_fast_path_serves_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "cq-fast-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "cq-fast-theirs").await;

    let mine = seed_group_claim(&pool, agent, group, "fast path: my claim").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "fast path: their claim").await;

    let state = split_state(&pool).await;
    let out = list(&pool, state, agent, base_params()).await;

    let got = ids(&out);
    // CALIBRATION: the listing returns something, so the absence below is about
    // tenancy and not about an empty table or a refused read.
    assert!(
        got.contains(&mine),
        "CALIBRATION: a group-private claim the viewer is a MEMBER of must be served. \
         Absence here is the fail-closed drift that reads as data loss — and if the \
         handler is reading the raw pool instead of a stamped connection, this is where \
         it shows; got {got:?}"
    );
    assert!(
        !got.contains(&theirs),
        "a claim owned by a group the viewer is not in must be ABSENT from the listing, \
         not present with its content blanked; got {got:?}"
    );

    // `count` and `list` are SEPARATE statements. This equality is what
    // distinguishes them: reverting only `count` gives total < len, reverting
    // only `list` gives total > len. Both are seeded well under the default
    // limit of 20, so pagination cannot explain a difference.
    assert_eq!(
        out.total,
        out.claims.len(),
        "the fast path reports `total` from ClaimRepository::count and the rows from \
         ClaimRepository::list. Two statements that disagree about one viewer's corpus \
         mean one of them ran on a connection the other did not; got total={} len={}",
        out.total,
        out.claims.len()
    );
}

/// THE OTHER SQL SHAPE. `list` and `count` each carry two query texts with their
/// own marker, selected by `content_contains`; the arm above drives only the
/// no-search pair.
///
/// `content_contains` does NOT select the path — it is absent from
/// `needs_in_memory_filters` — so this stays on the fast path and the
/// `total == len` discrimination still applies.
#[sqlx::test(migrations = "../../migrations")]
async fn the_fast_paths_search_shape_still_suppresses(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "cq-ilike-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "cq-ilike-theirs").await;

    let mine = seed_group_claim(&pool, agent, group, "ilike: quarkonium is mine").await;
    let decoy = seed_group_claim(&pool, agent, group, "ilike: mine but unrelated").await;
    let theirs = seed_group_claim(
        &pool,
        stranger,
        stranger_group,
        "ilike: quarkonium is theirs",
    )
    .await;

    let state = split_state(&pool).await;
    let out = list(
        &pool,
        state,
        agent,
        ClaimQueryParams {
            content_contains: Some("quarkonium".to_string()),
            ..base_params()
        },
    )
    .await;

    let got = ids(&out);
    assert!(
        got.contains(&mine),
        "CALIBRATION: the viewer's own matching claim must survive the ILIKE shape; got {got:?}"
    );
    assert!(
        !got.contains(&decoy),
        "CALIBRATION: a claim of the viewer's own that does NOT match must be filtered out, \
         or the search predicate is not running and the assertion below proves nothing \
         about the ILIKE text; got {got:?}"
    );
    assert!(
        !got.contains(&theirs),
        "the ILIKE shape carries its own visibility marker at its own bind index. A \
         stranger's matching claim must be ABSENT; got {got:?}"
    );
    assert_eq!(
        out.total,
        out.claims.len(),
        "count's ILIKE shape and list's ILIKE shape must agree; got total={} len={}",
        out.total,
        out.claims.len()
    );
}

/// THE SLOW PATH, which is a different call site of `ClaimRepository::list`
/// (10_000 / 0, then filtered in memory) and never calls `count` at all.
///
/// `truth_min` is the selector: it is a term of `needs_in_memory_filters` and
/// nothing else about it touches tenancy.
#[sqlx::test(migrations = "../../migrations")]
async fn the_slow_path_serves_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "cq-slow-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "cq-slow-theirs").await;

    let mine = seed_group_claim(&pool, agent, group, "slow path: my claim").await;
    let theirs = seed_group_claim(&pool, stranger, stranger_group, "slow path: their claim").await;

    let state = split_state(&pool).await;
    let out = list(
        &pool,
        state,
        agent,
        ClaimQueryParams {
            // The fixture seeds truth_value 0.8, so this admits everything the
            // viewer may read and selects the path without also being the
            // reason a row is missing.
            truth_min: Some(0.1),
            ..base_params()
        },
    )
    .await;

    let got = ids(&out);
    assert!(
        got.contains(&mine),
        "CALIBRATION: the slow path's working-set read is a SECOND call site of \
         ClaimRepository::list and must serve the viewer's own group-private claim; \
         got {got:?}"
    );
    assert!(
        !got.contains(&theirs),
        "a stranger's group-private claim must be absent from the slow path's working \
         set too — the in-memory filters below it only ever NARROW, so anything the \
         read admits is served; got {got:?}"
    );
}

/// THE METHODOLOGY PREFETCH — `ClaimRepository::claim_ids_by_methodology`, whose
/// result is applied as `claims.retain(|c| ids.contains(..))`.
///
/// Because that application is an INTERSECTION, a prefetch reverted to the raw
/// pool returns an empty id set and the viewer's OWN claim vanishes. That is the
/// direction this arm asserts. It is also why the prefetch predicates are
/// defence in depth rather than the control: they can only narrow a set that
/// already came from the viewer-predicated `list`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_methodology_prefetch_narrows_without_dropping_the_viewers_own_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "cq-meth-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "cq-meth-theirs").await;

    let mine = seed_group_claim(&pool, agent, group, "methodology: my deductive claim").await;
    seed_reasoning_trace(&pool, mine, "deductive").await;

    let other_methodology =
        seed_group_claim(&pool, agent, group, "methodology: my inductive claim").await;
    seed_reasoning_trace(&pool, other_methodology, "inductive").await;

    let theirs = seed_group_claim(
        &pool,
        stranger,
        stranger_group,
        "methodology: their deductive claim",
    )
    .await;
    seed_reasoning_trace(&pool, theirs, "deductive").await;

    let state = split_state(&pool).await;
    let out = list(
        &pool,
        state,
        agent,
        ClaimQueryParams {
            methodology: Some("deductive".to_string()),
            ..base_params()
        },
    )
    .await;

    let got = ids(&out);
    assert!(
        got.contains(&mine),
        "CALIBRATION: the viewer's own deductive claim must survive the prefetch. The \
         prefetch result is INTERSECTED with the listing, so a prefetch that read an \
         unstamped connection returns an empty set and empties the response; got {got:?}"
    );
    assert!(
        !got.contains(&other_methodology),
        "CALIBRATION: the viewer's own INDUCTIVE claim must be filtered out, or the \
         prefetch is not narrowing at all and the assertion above is about the listing \
         alone; got {got:?}"
    );
    assert!(
        !got.contains(&theirs),
        "a stranger's deductive claim must be absent; got {got:?}"
    );
}

/// THE EVIDENCE-TYPE PREFETCH — `ClaimRepository::claim_ids_by_evidence_type`,
/// the second and structurally different one: the row it filters is not the row
/// it returns.
///
/// That asymmetry is safe here only because the application is an intersection
/// (see the handler's doc comment) — and, independently, because migration 070's
/// `evidence_inherit_tenancy` arm is UNCONDITIONAL: a derived row's
/// `(visibility, owner_group_id)` is overwritten from its parent claim's on
/// every insert, with no no-widening gate. A fixture with a visible claim and an
/// invisible evidence row is therefore not constructible, so this arm cannot
/// separate the evidence marker from the claim marker, and does not claim to.
#[sqlx::test(migrations = "../../migrations")]
async fn the_evidence_type_prefetch_narrows_without_dropping_the_viewers_own_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "cq-ev-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "cq-ev-theirs").await;

    let mine = seed_group_claim(&pool, agent, group, "evidence: my documented claim").await;
    seed_evidence(&pool, mine, "document").await;

    let other_type = seed_group_claim(&pool, agent, group, "evidence: my observed claim").await;
    seed_evidence(&pool, other_type, "observation").await;

    let theirs = seed_group_claim(
        &pool,
        stranger,
        stranger_group,
        "evidence: their documented claim",
    )
    .await;
    seed_evidence(&pool, theirs, "document").await;

    let state = split_state(&pool).await;
    let out = list(
        &pool,
        state,
        agent,
        ClaimQueryParams {
            evidence_type: Some("document".to_string()),
            ..base_params()
        },
    )
    .await;

    let got = ids(&out);
    assert!(
        got.contains(&mine),
        "CALIBRATION: the viewer's own claim with document evidence must survive the \
         prefetch intersection; got {got:?}"
    );
    assert!(
        !got.contains(&other_type),
        "CALIBRATION: the viewer's own claim whose evidence is an OBSERVATION must be \
         filtered out, or the prefetch is not narrowing; got {got:?}"
    );
    assert!(
        !got.contains(&theirs),
        "a stranger's claim with document evidence must be absent; got {got:?}"
    );
}

// ── The 500 body, which is a different property from any of the above ───────

/// A statement that FAILS on the viewer-stamped connection must answer with a
/// fixed, opaque message — not with the database's own error text.
///
/// # Why this arm exists at all
///
/// `list_claims_query`'s two PR-28 branches (`read_as`'s refusal and
/// `finish_scoped_read`'s) log the internal error and answer with a fixed
/// literal. Its five STATEMENT branches used to interpolate the `sqlx` error
/// into the body instead, and log nothing. Nothing in this tree asserted a 500
/// body from this handler, in either shape — so the inconsistency was invisible
/// to the gate, and this file is explicitly the template the remaining
/// conversion shards copy.
///
/// # The mutilation, and why it is this one
///
/// `ClaimRepository::claim_ids_by_methodology` is the only one of the five that
/// joins a table no other statement in the request touches, so renaming the
/// column it filters on fails exactly one branch and leaves the handler
/// otherwise intact. Renaming rather than dropping the table keeps the failure
/// a plain "column does not exist" rather than a cascade of unrelated ones.
/// The database is `#[sqlx::test]`'s throwaway, so nothing is restored.
///
/// # What this asserts, and what it does NOT
///
/// It asserts the BODY: the exact literal, and the absence of the identifier the
/// driver's message would have carried. It does NOT assert that the
/// `tracing::error!` half fired — `epigraph-api` carries no `tracing-test`
/// dev-dependency, and adding one to assert a log line was out of scope for this
/// change. The logging half is therefore covered by review only, and that is
/// stated rather than implied.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_statement_answers_with_an_opaque_body_not_the_driver_error(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "cq-opaque").await;
    let claim = seed_group_claim(&pool, agent, group, "opaque-body fixture claim").await;
    seed_reasoning_trace(&pool, claim, "deductive").await;

    // CALIBRATION: the same request SUCCEEDS before the mutilation, so the error
    // below is the mutilation and not a broken fixture. This also carries the
    // positive direction the acceptance asks for — the legitimate caller is
    // still served.
    let ok = list(&pool, split_state(&pool).await, agent, methodology_params()).await;
    assert!(
        ids(&ok).contains(&claim),
        "CALIBRATION: the methodology prefetch must serve the viewer's own claim \
         before the column is renamed"
    );

    sqlx::query("ALTER TABLE reasoning_traces RENAME COLUMN reasoning_type TO reasoning_type_gone")
        .execute(&pool)
        .await
        .expect("rename the column the methodology prefetch filters on");

    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("resolve");
    let err = list_claims_query(
        ViewerExtractor(viewer),
        State(split_state(&pool).await),
        Query(methodology_params()),
    )
    .await
    .expect_err("the methodology prefetch must fail once its column is gone");

    let message = match err {
        epigraph_api::errors::ApiError::InternalError { message } => message,
        other => panic!("expected InternalError, got {other:?}"),
    };

    assert_eq!(
        message, "Methodology filter query failed",
        "the 500 body must be the fixed literal the two PR-28 branches use. \
         `errors.rs` serialises `message` verbatim, so anything appended to it \
         is disclosed to the caller."
    );
    assert!(
        !message.contains("reasoning_type"),
        "the body carried the name of the object the failing statement touched. \
         The driver's error belongs in the log, not in the response body. \
         Body: {message}"
    );
}

/// `methodology = "deductive"` and nothing else — the shape that fires the
/// prefetch and therefore forces the slow path.
fn methodology_params() -> ClaimQueryParams {
    ClaimQueryParams {
        methodology: Some("deductive".to_string()),
        ..base_params()
    }
}
