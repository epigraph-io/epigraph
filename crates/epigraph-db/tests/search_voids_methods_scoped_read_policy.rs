//! The POLICY half of PR-29: on a genuinely filtered session, each of the five
//! RLS-relevant reads the converted `search.rs` / `voids.rs` / `methods.rs`
//! handlers run returns the viewer's own rows through a viewer-stamped
//! connection and NOTHING through an unstamped one.
//!
//! # Why this file exists separately from the api-crate one
//!
//! `crates/epigraph-api/tests/search_voids_methods_scoped_read.rs` asserts the
//! SUPPRESSION properties of the three converted handlers, and says plainly that
//! it observes the in-query `$V` predicate rather than migration 077's policies:
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
//! # The FIVE reads, and the two that CANNOT appear here
//!
//! Every read below already took a `&Viewer` and was already generic over
//! `sqlx::PgExecutor` before this shard — PR-27 widened all five — so the arms
//! genuinely execute the one SQL text the handler calls, rather than two texts
//! believed to match.
//!
//! Two of the eleven converted sites are ABSENT from this file, and the absence
//! is a measurement rather than an oversight. `ClaimThemeRepository::
//! find_similar_themes_at_dim` reads `claim_themes` and `MethodRepository::get`
//! reads `methods`; both tables measure `relrowsecurity = f` /
//! `relforcerowsecurity = f` with no `visibility` and no `owner_group_id`
//! column, so neither function takes a `&Viewer` and neither has a policy for a
//! stamp to feed. A stamped-vs-unstamped arm over either would assert `1 == 1`.
//! Their reason for holding no viewer is recorded in
//! `visibility_lint.rs::EXECUTOR_WITHOUT_VIEWER`, and the plumbing property that
//! IS assertable about them — that the statement runs on the connection the
//! handler thinks it does — is pinned by the two GRANT arms in the api-crate
//! file. The remaining two of the eleven are inline `sqlx` statements in
//! `search.rs` with no repo function to drive here.
//!
//! # Both `SessionGucMode` arms
//!
//! `Session` alone would prove the half that already worked: in `Session` mode a
//! `ScopedRead` is a bare connection, so "these statements run in one
//! transaction" is simply false there, while the identical code in `Transaction`
//! mode is atomic. `ScopedPool::acquire_as` hard-refuses `Transaction`, so the
//! transaction arms are also what prove the converted handlers are servable
//! behind the pooler `bin/server.rs` advertises to operators — the reason the
//! conversion targets `AppState::read_as` and not a literal `acquire_as`.
//!
//! # No `grant_app_privileges`
//!
//! Migration 077 issues the app-role grants itself. Re-granting here would paper
//! over a missing grant; a `42501` from these calls is a finding about the
//! migration, not a fixture bug.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, ClaimThemeRepository, MethodRepository, SessionGucMode};
use sqlx::{Executor, PgPool};
use uuid::Uuid;
use viewer_fixture::{scoped_pool_with_mode, seed_agent_with_group, seed_edge, seed_group_claim};

/// The dimension every seeded vector uses; must match the `claims.embedding`
/// and `claim_themes.centroid` column widths or the inserts raise `22000`.
const DIM: usize = 1536;

/// A pgvector literal whose every component is equal, so any two vectors built
/// by this helper with the same sign are at cosine similarity 1.0.
///
/// Exact rather than approximate similarity is what lets every arm below expect
/// the cardinality `1` rather than a threshold: the seeded claim is at the probe
/// point, so it is admitted by any `min_similarity` the reads apply.
fn unit_vec() -> String {
    let component = 1.0f32 / (DIM as f32).sqrt();
    format!(
        "[{}]",
        std::iter::repeat_n(component.to_string(), DIM)
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// What one arm saw.
#[derive(Debug)]
struct Observation {
    /// How many rows this read reported for the viewer.
    visible: usize,
    /// `false` would make every assertion here pass vacuously.
    bypass: bool,
}

/// Which of the converted reads an arm drives.
///
/// A parameter and not a closure: the arms take `&mut ScopedRead` / `&mut
/// PgConnection` behind a generic `E: PgExecutor`, which a shared `Fn(..) ->
/// Fut` cannot thread without an HRTB fight, and the five differ in arity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Read {
    /// `search.rs`'s flat path and BOTH `voids.rs` handlers' nearest-claim
    /// lookup. Three of the eleven sites call this one function.
    SemanticFlat,
    /// `voids.rs::embedding_density`'s cardinality read, whose differential is
    /// NUMERIC — `1` against `0` — rather than an empty vec. That is the
    /// sharpest available form of "rows vanish from their own owner with a 200".
    DensityStats,
    /// `search.rs`'s diverse path: the graph-neighbour join, which reads the FAR
    /// side of an edge. The neighbour was never in the caller's id list, so the
    /// `claims` predicate is the only thing filtering it.
    GraphNeighbors,
    /// `search.rs`'s diverse path: the candidate pull, the only theme-side read
    /// that carries a viewer at all.
    ThemeCandidates,
    /// `methods.rs`'s evidence read, which reaches `claims` through
    /// `unnest(m.source_claim_ids)` rather than through a WHERE on `claims`.
    MethodEvidence,
}

/// Everything the five reads need, seeded once so that every arm's expected
/// cardinality is the same `1` and a differential cannot be an artefact of one
/// arm's fixture being richer than another's.
struct Corpus {
    agent: Uuid,
    /// The claim every read is expected to find, at the probe point.
    claim: Uuid,
    /// The far side of the edge `GraphNeighbors` walks to.
    neighbor: Uuid,
    theme: Uuid,
    method: Uuid,
}

async fn seed_corpus(pool: &PgPool, label: &str) -> Corpus {
    let vec = unit_vec();
    let (agent, group) = seed_agent_with_group(pool, label).await;

    let claim = seed_group_claim(pool, agent, group, "policy-half: the viewer's own claim").await;
    let neighbor =
        seed_group_claim(pool, agent, group, "policy-half: the viewer's neighbour").await;

    for c in [claim, neighbor] {
        sqlx::query("UPDATE claims SET embedding = $2::vector WHERE id = $1")
            .bind(c)
            .bind(&vec)
            .execute(pool)
            .await
            .expect("set embedding");
    }

    // The edge is left for migration 070's trigger to stamp, so it is visible to
    // whoever can see its endpoints. Forcing it public would let the EDGE
    // predicate satisfy the neighbour arm on its own and the `claims` predicate
    // could be deleted without failing it.
    seed_edge(pool, claim, neighbor).await;

    let theme: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("policy-half-{label}"))
    .bind("PR-29 policy fixture theme")
    .fetch_one(pool)
    .await
    .expect("insert theme");
    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(theme)
        .bind(&vec)
        .execute(pool)
        .await
        .expect("set centroid");
    // Only `claim` joins the theme: `neighbor` must stay out of it or the
    // candidate arm's expected cardinality becomes 2.
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("attach theme");

    let method = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO methods (id, name, canonical_name, technique_type, source_claim_ids) \
         VALUES ($1, $2, $3, 'measurement', $4)",
    )
    .bind(method)
    .bind(format!("policy-half method {label}"))
    .bind(format!("policy-half-method-{label}"))
    .bind(vec![claim])
    .execute(pool)
    .await
    .expect("insert method");

    Corpus {
        agent,
        claim,
        neighbor,
        theme,
        method,
    }
}

impl Read {
    /// The number of rows this read reports for `viewer` on `conn`.
    ///
    /// Cardinality rather than ids because `DensityStats` and `MethodEvidence`
    /// have no ids to give, and the fixture seeds exactly one matching row on a
    /// `#[sqlx::test]` database no migration puts a claim into — so `1` and `0`
    /// are exact, not thresholds.
    async fn run(
        self,
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        corpus: &Corpus,
    ) -> Result<usize, epigraph_db::DbError> {
        let vec = unit_vec();
        Ok(match self {
            Read::SemanticFlat => ClaimRepository::semantic_search_flat(
                &mut *conn, viewer, &vec,
                // The floor `voids.rs` passes: cosine similarity is bounded
                // below by -1, so it excludes nothing and the read is the
                // unbounded nearest-neighbour lookup both handlers want.
                -1.0, None, None, None, None, 100,
            )
            .await?
            .into_iter()
            // `neighbor` is also at the probe point; count only the claim every
            // other arm counts, so the expected cardinality is uniformly 1.
            .filter(|h| h.claim_id == corpus.claim)
            .count(),
            Read::DensityStats => {
                let (count, _avg) =
                    ClaimRepository::embedding_density_stats(&mut *conn, viewer, &vec, 0.60)
                        .await?;
                // Both seeded claims sit at the probe point, so the reader's
                // count is 2 when the policy admits them and 0 when it does not.
                // Halved so every arm shares one expected value.
                count as usize / 2
            }
            Read::GraphNeighbors => ClaimRepository::semantic_graph_neighbors(
                &mut *conn,
                viewer,
                "embedding",
                &vec,
                &[corpus.claim],
            )
            .await?
            .into_iter()
            .filter(|n| n.neighbor_id == corpus.neighbor)
            .count(),
            Read::ThemeCandidates => ClaimThemeRepository::claims_in_themes_at_dim_since(
                &mut *conn,
                viewer,
                &[corpus.theme],
                &vec,
                100,
                1536,
                false,
                None,
            )
            .await?
            .len(),
            Read::MethodEvidence => {
                MethodRepository::get_evidence_strength(&mut *conn, viewer, corpus.method)
                    .await
                    .map_err(epigraph_db::DbError::from)?
                    .claim_count as usize
            }
        })
    }
}

/// The read through a `read_as` connection, downgraded to `epigraph_app` AFTER
/// the stamp lands.
///
/// The stamp is issued by the superuser session `read_as` opens, then the role
/// is switched on that same connection — the only idiom that composes with
/// `AppState::read_as`, which acquires its own connection internally and offers
/// no seam a `viewer_fixture::as_role` closure could be routed through.
async fn stamped(pool: &PgPool, mode: SessionGucMode, read: Read, corpus: &Corpus) -> Observation {
    let scoped = scoped_pool_with_mode(pool, mode).await;
    let viewer = Viewer::resolve(pool, corpus.agent).await.expect("resolve");

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
        .run(&mut r, &viewer, corpus)
        .await
        .expect("the stamped read must SERVE — a failure here is the outage, not the fix");

    r.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset");
    // Explicit: `ScopedRead` has no `Drop` impl, so the transaction arm would
    // roll back silently on drop. The converted handlers finish the same way, on
    // every one of their five success paths.
    r.commit().await.expect("commit");

    Observation { visible, bypass }
}

/// The same read, the same viewer, the same function — on a connection nothing
/// stamped. This is the pre-conversion request path.
async fn unstamped(pool: &PgPool, read: Read, corpus: &Corpus) -> Observation {
    let viewer = Viewer::resolve(pool, corpus.agent).await.expect("resolve");
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("SET SESSION AUTHORIZATION");

    let bypass: bool = sqlx::query_scalar("SELECT epigraph_bypass()")
        .fetch_one(&mut *conn)
        .await
        .expect("epigraph_bypass()");

    let visible = read.run(&mut conn, &viewer, corpus).await.expect(
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
    let corpus = seed_corpus(&pool, &format!("svm-policy-{mode:?}-{read:?}")).await;

    let stamped = stamped(&pool, mode, read, &corpus).await;
    let unstamped = unstamped(&pool, read, &corpus).await;
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
         the edge migration 070 stamped from its endpoints. A missing row here is the \
         fail-closed drift that is indistinguishable from data loss."
    );

    assert_eq!(
        unstamped.visible, 0,
        "THE DIFFERENTIAL ({arm}): the identical call on an UNSTAMPED connection must \
         report nothing — the $V predicate admits the row and the policy, seeing no \
         epigraph.group_ids, does not. If this is non-zero the fixture is not filtering \
         and the assertion above proves nothing about the conversion."
    );
}

// ── `ClaimRepository::semantic_search_flat` — three of the eleven sites ──

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_semantic_flat_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Session, Read::SemanticFlat).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_semantic_flat_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Transaction, Read::SemanticFlat).await;
}

// ── `ClaimRepository::embedding_density_stats` ──

/// The cardinality oracle's own differential. It is a bare aggregate with no
/// row projection, so `semantic_search_flat` being correct does not cover it:
/// an aggregate over a filtered relation still returns a row, just a smaller
/// number, which is exactly the shape that hides.
#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_density_stats_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Session, Read::DensityStats).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_density_stats_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Transaction, Read::DensityStats).await;
}

// ── `ClaimRepository::semantic_graph_neighbors` ──

/// The neighbour join's own differential. The row it returns is the FAR side of
/// an edge — never in the caller's id list and never viewer-checked upstream —
/// so this is the one arm where the `claims` predicate is doing all of the work.
#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_graph_neighbors_serve_the_viewers_own_rows_and_the_unstamped_ones_do_not_in_session_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Session, Read::GraphNeighbors).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_graph_neighbors_serve_the_viewers_own_rows_and_the_unstamped_ones_do_not_in_transaction_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Transaction, Read::GraphNeighbors).await;
}

// ── `ClaimThemeRepository::claims_in_themes_at_dim_since` ──

/// The candidate pull's own differential. It filters `c.theme_id = ANY($1)`
/// rather than by id, and it is the read that makes the three sites downstream
/// of it in the diverse path safe by derivation — so if it stops filtering, the
/// `full_sql` fetch and the neighbour join inherit an unfiltered id list.
#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_theme_candidates_serve_the_viewers_own_rows_and_the_unstamped_ones_do_not_in_session_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Session, Read::ThemeCandidates).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_theme_candidates_serve_the_viewers_own_rows_and_the_unstamped_ones_do_not_in_transaction_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Transaction, Read::ThemeCandidates).await;
}

// ── `MethodRepository::get_evidence_strength` ──

/// The one read in `methods.rs` with a policy to answer to.
///
/// It reaches `claims` through `CROSS JOIN LATERAL unnest(m.source_claim_ids)`
/// from an UN-scoped table, which is a different join shape from every other arm
/// here: the outer relation is not policy-filtered at all, so the differential
/// can only come from the `claims` side.
#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_method_evidence_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_session_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Session, Read::MethodEvidence).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_stamped_method_evidence_serves_the_viewers_own_rows_and_the_unstamped_one_does_not_in_transaction_mode(
    pool: PgPool,
) {
    coherence_case_for(pool, SessionGucMode::Transaction, Read::MethodEvidence).await;
}
