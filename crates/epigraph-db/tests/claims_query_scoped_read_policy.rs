//! The POLICY half of PR-28: on a genuinely filtered session, each of the four
//! reads `GET /api/v1/claims` runs returns the viewer's own rows through a
//! viewer-stamped connection and NOTHING through an unstamped one.
//!
//! # Why this file exists separately from the api-crate one
//!
//! `crates/epigraph-api/tests/claims_query_scoped_read.rs` asserts the
//! SUPPRESSION properties of the converted handler, and says plainly that it
//! observes the in-query `$V` predicate rather than migration 077's policies:
//! its scoped arm is a superuser session, because `ScopedPoolOptions` has no
//! `after_connect` knob to downgrade it with.
//!
//! This file pins the other half, and it is the half the CONVERSION is for. The
//! two filters — the `$V` bind that `Viewer::splice` renders, and the
//! `epigraph.group_ids` GUC that 077's policies read — are populated by two
//! independent code paths. An unstamped connection has the first and not the
//! second, so under 079's `FORCE` they disagree and **rows vanish from their own
//! owners with a 200 and no log line**. That is the §9.2 step 11d outage
//! `D-PR17-request-path-never-stamps-session-gucs` blocks on, and it is
//! invisible to any assertion written as "a stranger cannot read".
//!
//! # The control arm IS the mutation
//!
//! Both arms below call the SAME repository function, with the same viewer, the
//! same seeded rows, and the same `SET SESSION AUTHORIZATION epigraph_app`
//! downgrade. Exactly one variable differs: whether the connection was stamped
//! by `ScopedPool::read_as` first. So no separate mutant is needed to show the
//! assertion is not tautological; the unstamped arm is an inline mutation of the
//! thing under test, and it is asserted to fail in the direction the conversion
//! fixes.
//!
//! Unlike PR-26, this shard authored NO new repo form to make that expressible.
//! PR-27 widened all four of these functions to `<'e, E: sqlx::PgExecutor<'e>>`,
//! so a `&mut ScopedRead` and a `&mut PgConnection` are both accepted by the one
//! body the handler calls — the arms genuinely execute the same SQL text rather
//! than two texts believed to match.
//!
//! # All FOUR reads, and both `SessionGucMode` arms
//!
//! Factored over [`Read`] as well as the mode. `count` and `list` are the fast
//! path; `list` is also the slow path's working-set read;
//! `claim_ids_by_methodology` and `claim_ids_by_evidence_type` are the two
//! prefetches. All four are RLS-relevant — `claims`, `reasoning_traces` and
//! `evidence` are all in 077's owned set and FORCEd by 079 — and the register's
//! rule is that one function being correct does not cover its siblings.
//!
//! `Session` alone would prove the half that already worked: in `Session` mode a
//! `ScopedRead` is a bare connection, so "these statements run in one
//! transaction" is simply false there, while the identical code in `Transaction`
//! mode is atomic. `ScopedPool::acquire_as` hard-refuses `Transaction`, so the
//! transaction arms are also what prove the converted handler is servable behind
//! the pooler `bin/server.rs` advertises to operators — the reason the
//! conversion targets `AppState::read_as` and not a literal `acquire_as`.
//!
//! # No `grant_app_privileges`
//!
//! Migration 077 issues the app-role grants itself. Re-granting here would paper
//! over a missing grant; a `42501` from these calls is a finding about the
//! migration, not a fixture bug.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, SessionGucMode};
use sqlx::{Executor, PgPool};
use uuid::Uuid;
use viewer_fixture::{
    scoped_pool_with_mode, seed_agent_with_group, seed_evidence, seed_group_claim,
    seed_reasoning_trace,
};

/// What one arm saw.
#[derive(Debug)]
struct Observation {
    /// How many rows this read reported for the viewer.
    visible: usize,
    /// `false` would make every assertion here pass vacuously.
    bypass: bool,
}

/// Which of the handler's four reads an arm drives.
///
/// A parameter and not a closure: the arms take `&mut ScopedRead` / `&mut
/// PgConnection` behind a generic `E: PgExecutor`, which a shared `Fn(..) ->
/// Fut` cannot thread without an HRTB fight, and the four differ in arity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Read {
    /// The fast path's `COUNT(*)`, whose differential is NUMERIC — `1` against
    /// `0` — rather than an empty vec. That is the sharpest available form of
    /// "rows vanish from their own owner with a 200".
    Count,
    /// The fast path's page read, and the slow path's 10_000-row working set.
    List,
    /// The methodology prefetch.
    Methodology,
    /// The evidence-type prefetch.
    EvidenceType,
}

impl Read {
    /// The number of rows this read reports for `viewer` on `conn`.
    ///
    /// Cardinality rather than ids because `count` has no ids to give, and the
    /// fixture seeds exactly one matching claim on a `#[sqlx::test]` database no
    /// migration puts a claim into — so `1` and `0` are exact, not thresholds.
    async fn run(
        self,
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
    ) -> Result<usize, epigraph_db::DbError> {
        Ok(match self {
            Read::Count => ClaimRepository::count(&mut *conn, viewer, None).await? as usize,
            Read::List => ClaimRepository::list(&mut *conn, viewer, 100, 0, None)
                .await?
                .len(),
            Read::Methodology => {
                ClaimRepository::claim_ids_by_methodology(&mut *conn, viewer, "deductive")
                    .await?
                    .len()
            }
            Read::EvidenceType => {
                ClaimRepository::claim_ids_by_evidence_type(&mut *conn, viewer, "document")
                    .await?
                    .len()
            }
        })
    }
}

/// One group-private claim owned by a group `agent` is an `admin` of, carrying
/// both a `deductive` reasoning trace and a `document` evidence row.
///
/// One claim serves all four reads, which is deliberate: the expected
/// cardinality is then the same `1` for every arm, and a differential cannot be
/// an artefact of one arm's fixture being richer than another's.
///
/// Neither derived row declares tenancy columns. Migration 070's
/// `epigraph_inherit_tenancy_stmt` arm (c) is unconditional and overwrites them
/// from the parent claim, so the trace and the evidence are private to the same
/// group as the claim — by construction, not by declaration.
async fn seed_corpus(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let (agent, group) = seed_agent_with_group(pool, label).await;
    let claim = seed_group_claim(pool, agent, group, "policy-half: the viewer's own claim").await;
    seed_reasoning_trace(pool, claim, "deductive").await;
    seed_evidence(pool, claim, "document").await;
    (agent, claim)
}

/// The read through a `read_as` connection, downgraded to `epigraph_app` AFTER
/// the stamp lands.
///
/// The stamp is issued by the superuser session `read_as` opens, then the role
/// is switched on that same connection — the only idiom that composes with
/// `AppState::read_as`, which acquires its own connection internally and offers
/// no seam a `viewer_fixture::as_role` closure could be routed through.
async fn stamped(pool: &PgPool, mode: SessionGucMode, read: Read, agent: Uuid) -> Observation {
    let scoped = scoped_pool_with_mode(pool, mode).await;
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");

    let mut r = scoped.read_as(&viewer).await.expect("read_as");
    assert_eq!(
        r.mode(),
        mode,
        "CALIBRATION: read_as must dispatch on the pool's mode, or the two arms of \
         this file are the same arm"
    );
    r.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("SET SESSION AUTHORIZATION requires a superuser connection");

    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *r)
        .await
        .expect("epigraph_bypass()");

    let visible = read
        .run(&mut r, &viewer)
        .await
        .expect("the stamped read must SERVE — a failure here is the outage, not the fix");

    r.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    // Explicit: `ScopedRead` has no `Drop` impl, so the transaction arm would
    // roll back silently on drop. The converted handler finishes the same way,
    // on both of its return paths.
    r.commit().await.expect("commit");

    Observation { visible, bypass }
}

/// The same read, the same viewer, the same function — on a connection nothing
/// stamped. This is the pre-conversion request path.
async fn unstamped(pool: &PgPool, read: Read, agent: Uuid) -> Observation {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("SET SESSION AUTHORIZATION");

    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_bypass()");

    let visible = read.run(&mut conn, &viewer).await.expect(
        "the unstamped read must not ERROR — it must return FEWER rows, which is \
         precisely why the defect is invisible",
    );

    // Mandatory: this pool has no `after_release` scrub, so a connection left as
    // `epigraph_app` would fail an unrelated later test somewhere else entirely.
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");

    Observation { visible, bypass }
}

/// The differential, over one read and one mode.
async fn coherence_case_for(pool: PgPool, mode: SessionGucMode, read: Read) {
    let (agent, _claim) = seed_corpus(&pool, &format!("cq-policy-{mode:?}-{read:?}")).await;

    let stamped = stamped(&pool, mode, read, agent).await;
    let unstamped = unstamped(&pool, read, agent).await;
    let arm = format!("{mode:?}/{read:?}");

    assert!(
        !stamped.bypass,
        "CALIBRATION ({arm}): the stamped session must NOT hold bypass, or the \
         policies filter nothing and this test passes vacuously"
    );
    assert!(
        !unstamped.bypass,
        "CALIBRATION ({arm}): the unstamped session must NOT hold bypass either — \
         if it did, the differential below would be an artifact of the role switch \
         rather than of the stamp"
    );

    assert_eq!(
        stamped.visible, 1,
        "COHERENCE ({arm}): the group whose id the read binds as $V is in the GUC \
         read_as stamped, so 077's policies must admit that group's private claim — and \
         the trace and evidence rows migration 070 stamped with the same group. A \
         missing row here is the fail-closed drift that is indistinguishable from data \
         loss."
    );

    assert_eq!(
        unstamped.visible, 0,
        "THE DIFFERENTIAL ({arm}): the identical call on an UNSTAMPED connection must \
         report nothing — the $V predicate admits the row and the policy, seeing no \
         epigraph.group_ids, does not. If this is non-zero the fixture is not filtering \
         and the assertion above proves nothing about the conversion."
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_count_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Session, Read::Count).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_count_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Transaction, Read::Count).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_list_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Session, Read::List).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_list_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Transaction, Read::List).await;
}

/// The methodology prefetch's own differential.
///
/// It joins `reasoning_traces`, a second FORCEd table with its own policy, so
/// `list` being correct does not cover it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_methodology_prefetch_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Session, Read::Methodology).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_methodology_prefetch_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Transaction, Read::Methodology).await;
}

/// The evidence-type prefetch's own differential.
///
/// This one reads `evidence` ALONE — it never mentions `claims` — so it is the
/// arm on which the `claims` policy cannot be doing the work.
#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_evidence_prefetch_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Session, Read::EvidenceType).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_evidence_prefetch_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Transaction, Read::EvidenceType).await;
}
