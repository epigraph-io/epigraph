//! `routes/claims_query.rs::list_claims_query` serves every statement of
//! `GET /api/v1/claims` on ONE viewer-stamped connection, and every one of them
//! suppresses on the viewer.
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
//! # THE FAST/SLOW SPLIT IS GONE. The arm names below outlived it.
//!
//! PR-28 wrote this file against a handler with two paths: a `count` + `list`
//! fast path, and a slow path that read the 10,000 most-recent rows and filtered
//! them in Rust. Backlog `2265a67b` deleted the split — every predicate now runs
//! in SQL through `ClaimRepository::{count_filtered, list_filtered}`, because the
//! slow path's `total` was the length of a filtered slice of a capped window and
//! returned an empty set, indistinguishable from a true zero, for any filter
//! matching only older claims.
//!
//! **Every arm below still drives the handler and still asserts what it says it
//! asserts** — these are HTTP-level tests of `list_claims_query`, so they
//! followed the handler through the change. What the names no longer describe is
//! WHICH internal path they take: there is one. They are kept, rather than
//! renamed, because each still selects a distinct PARAMETER SHAPE, and the shape
//! is what the file is really covering:
//!
//! | parameter shape | driven by |
//! |---|---|
//! | no filters (the `FILTER_WHERE` all-`NULL` shape) | [`the_fast_path_serves_the_viewers_own_group_private_claim`] |
//! | `content_contains` (the `ILIKE` predicate) | [`the_fast_paths_search_shape_still_suppresses`] |
//! | `truth_min` (a bound predicate) | [`the_slow_path_serves_the_viewers_own_group_private_claim`] |
//! | `claim_ids_by_methodology` | [`the_methodology_prefetch_narrows_without_dropping_the_viewers_own_claim`] |
//! | `claim_ids_by_evidence_type` | [`the_evidence_type_prefetch_narrows_without_dropping_the_viewers_own_claim`] |
//!
//! `total == claims.len()` separates `count_filtered` from `list_filtered`
//! independently: reverting only the count gives `total != len` in one direction,
//! reverting only the list in the other. It is no longer a tautology on ANY arm —
//! under the old slow path `total` was assigned `claims.len()` after filtering,
//! so the equality there was evidence of nothing. It is now two SQL statements
//! agreeing, which is the property `2265a67b` is about.
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
        theme_id: None,
        include_links: None,
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

    let mine = seed_group_claim(&pool, agent, group, "no-filter shape: my claim").await;
    let theirs = seed_group_claim(
        &pool,
        stranger,
        stranger_group,
        "no-filter shape: their claim",
    )
    .await;

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

    // `count_filtered` and `list_filtered` are SEPARATE statements. This
    // equality is what distinguishes them: reverting only the count gives
    // total != len in one direction, reverting only the list in the other. Both
    // are seeded well under the default limit of 20, so pagination cannot
    // explain a difference.
    assert_eq!(
        out.total,
        out.claims.len(),
        "`total` comes from ClaimRepository::count_filtered and the rows from \
         ClaimRepository::list_filtered. Two statements that disagree about one viewer's corpus \
         mean one of them ran on a connection the other did not; got total={} len={}",
        out.total,
        out.claims.len()
    );
}

/// THE OTHER SQL SHAPE. `list` and `count` each carry two query texts with their
/// own marker, selected by `content_contains`; the arm above drives only the
/// no-search pair.
///
/// `content_contains` is `$1` of `FILTER_WHERE`, ANDed with the viewer
/// predicate in the same clause both statements share, so the `total == len`
/// discrimination applies here exactly as it does above.
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

/// A BOUND PREDICATE (`truth_min`) alongside the viewer's.
///
/// `truth_min` used to be the selector for the in-memory slow path; since
/// `2265a67b` it is `$2` of `FILTER_WHERE` and runs in SQL beside the viewer
/// predicate. The arm is kept because that is a different statement shape from
/// the all-`NULL` one above, and nothing else about `truth_min` touches
/// tenancy — so a row missing here is the viewer, not the bound.
#[sqlx::test(migrations = "../../migrations")]
async fn the_slow_path_serves_the_viewers_own_group_private_claim(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "cq-slow-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "cq-slow-theirs").await;

    let mine = seed_group_claim(&pool, agent, group, "bound shape: my claim").await;
    let theirs =
        seed_group_claim(&pool, stranger, stranger_group, "bound shape: their claim").await;

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
        "CALIBRATION: a bound predicate must not cost the viewer their own \
         group-private claim — the bound admits it and the viewer owns it; \
         got {got:?}"
    );
    assert!(
        !got.contains(&theirs),
        "a stranger's group-private claim must be absent under this shape too — \
         `FILTER_WHERE` ANDs the bound with the viewer predicate, so neither can \
         excuse the other; got {got:?}"
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
/// prefetch, whose resolved id set becomes the `ids` field of
/// `ClaimListFilter` (`$9`, `id = ANY(...)`) rather than an in-memory `retain`.
fn methodology_params() -> ClaimQueryParams {
    ClaimQueryParams {
        methodology: Some("deductive".to_string()),
        ..base_params()
    }
}

/// A `claim_themes` row; returns its id.
async fn seed_theme(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ($1) RETURNING id")
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("seed theme")
}

/// Assign `claim` to `theme` and give it a creation time `minutes` after a
/// fixed instant, so date order is the fixture's and not the insert's.
async fn place(pool: &PgPool, claim: Uuid, theme: Option<Uuid>, minutes: i32) {
    sqlx::query(
        "UPDATE claims SET theme_id = $2, \
                created_at = '2026-01-01T00:00:00Z'::timestamptz + make_interval(mins => $3) \
          WHERE id = $1",
    )
    .bind(claim)
    .bind(theme)
    .bind(minutes)
    .execute(pool)
    .await
    .expect("place the claim");
}

/// Backlog ea26d7aa: a theme's claims in date order with the links among them,
/// which is what a timeline of a theme needs.
///
/// * `theme_id` selects the theme's claims the viewer may read: the viewer's
///   own group claim is there, a stranger's group claim in the same theme is
///   not, and `total` counts what was selectable.
/// * `include_links=true` returns the in-force epistemic edges between two
///   claims ON THE PAGE that the viewer may read. An edge to a claim outside
///   the page, an edge private to another group between two readable claims, a
///   retracted edge and a structural (non-epistemic) edge are all absent.
/// * without `include_links` there is no `links` key at all.
#[sqlx::test(migrations = "../../migrations")]
async fn a_themes_claims_come_in_date_order_with_the_links_among_them(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "cq-theme-mine").await;
    let (stranger, stranger_group) = seed_agent_with_group(&pool, "cq-theme-theirs").await;
    let theme = seed_theme(&pool, "timeline theme").await;
    let other_theme = seed_theme(&pool, "another theme").await;

    let first = viewer_fixture::seed_public_claim(&pool, agent, "theme: first, public").await;
    let second = seed_group_claim(&pool, agent, group, "theme: second, mine").await;
    let third = viewer_fixture::seed_public_claim(&pool, stranger, "theme: third, public").await;
    let hidden = seed_group_claim(&pool, stranger, stranger_group, "theme: hidden, theirs").await;
    let elsewhere = viewer_fixture::seed_public_claim(&pool, agent, "other theme, public").await;
    place(&pool, first, Some(theme), 1).await;
    place(&pool, second, Some(theme), 2).await;
    place(&pool, third, Some(theme), 3).await;
    place(&pool, hidden, Some(theme), 4).await;
    place(&pool, elsewhere, Some(other_theme), 5).await;

    // On the page and readable: these two are the answer.
    let supports = viewer_fixture::seed_edge(&pool, first, third).await;
    let refutes: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'REFUTES') RETURNING id",
    )
    .bind(third)
    .bind(second)
    .fetch_one(&pool)
    .await
    .expect("upper-case refutes edge");
    // Absent, each for its own reason.
    let _to_outside_page = viewer_fixture::seed_edge(&pool, first, elsewhere).await;
    let _private_to_strangers =
        viewer_fixture::seed_edge_owned_by(&pool, third, first, "group", stranger_group).await;
    let retracted = viewer_fixture::seed_edge(&pool, second, first).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1")
        .bind(retracted)
        .execute(&pool)
        .await
        .expect("retract");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(first)
    .bind(second)
    .execute(&pool)
    .await
    .expect("structural edge");

    let state = split_state(&pool).await;
    let out = list(
        &pool,
        state.clone(),
        agent,
        ClaimQueryParams {
            theme_id: Some(theme),
            include_links: Some(true),
            sort_by: Some("created_at".to_string()),
            sort_order: Some("asc".to_string()),
            ..base_params()
        },
    )
    .await;

    assert_eq!(
        ids(&out),
        vec![first, second, third],
        "the theme's readable claims, oldest first; the stranger's group claim and the \
         other theme's claim are absent"
    );
    assert_eq!(out.total, 3, "total counts the same selectable set");
    let mut links: Vec<(Uuid, Uuid, Uuid, String)> = out
        .links
        .expect("include_links=true returns a links list")
        .into_iter()
        .map(|l| (l.id, l.source_id, l.target_id, l.relationship))
        .collect();
    links.sort();
    let mut want = vec![
        (supports, first, third, "supports".to_string()),
        (refutes, third, second, "refutes".to_string()),
    ];
    want.sort();
    assert_eq!(
        links, want,
        "exactly the in-force epistemic edges between two claims on the page that the \
         viewer may read, relationship lower-cased"
    );
    assert_eq!(out.links_truncated, Some(false));

    // A stranger reads its own group claim and not the viewer's; the link that
    // is private to its group is now on its page.
    let theirs = list(
        &pool,
        state.clone(),
        stranger,
        ClaimQueryParams {
            theme_id: Some(theme),
            include_links: Some(true),
            sort_by: Some("created_at".to_string()),
            sort_order: Some("asc".to_string()),
            ..base_params()
        },
    )
    .await;
    assert_eq!(ids(&theirs), vec![first, third, hidden]);
    let their_pairs: Vec<(Uuid, Uuid)> = theirs
        .links
        .expect("links")
        .into_iter()
        .map(|l| (l.source_id, l.target_id))
        .collect();
    assert!(their_pairs.contains(&(first, third)), "{their_pairs:?}");
    assert!(
        their_pairs.contains(&(third, first)),
        "the edge private to the stranger's group is readable by the stranger: {their_pairs:?}"
    );
    assert!(
        !their_pairs
            .iter()
            .any(|(s, t)| *s == second || *t == second),
        "no link names a claim the stranger cannot read: {their_pairs:?}"
    );

    // Without the flag there is no links key; an unknown theme selects nothing.
    let plain = list(
        &pool,
        state.clone(),
        agent,
        ClaimQueryParams {
            theme_id: Some(theme),
            ..base_params()
        },
    )
    .await;
    assert!(plain.links.is_none() && plain.links_truncated.is_none());
    let unknown = list(
        &pool,
        state,
        agent,
        ClaimQueryParams {
            theme_id: Some(Uuid::new_v4()),
            include_links: Some(true),
            ..base_params()
        },
    )
    .await;
    assert!(ids(&unknown).is_empty());
    assert_eq!(unknown.total, 0);
    assert_eq!(unknown.links.map(|l| l.len()), Some(0));
}
