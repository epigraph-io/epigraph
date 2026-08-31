//! Cascading belief repair downstream of `supersede_claim`
//! (backlog claim `20e9ed83-c5f1-4f26-bee5-d6eb105d2635`, PREREGISTRATION.md
//! criteria C2, C3, C6, C7).
//!
//! Every fixture drives the **real MCP call site**
//! (`epigraph_mcp::tools::supersede::supersede_claim`) rather than the engine
//! helper directly, so deleting the cascade call from the tool turns these
//! red — an engine-only test would stay green with the wiring removed.
//!
//! Edges are wired through the normal edge-write path (`do_link_epistemic`),
//! which is what materializes the `perspective_id = edge_id` edge-factor BBAs
//! whose staleness this feature exists to repair.
//!
//! No test body calls `recompute_beliefs`: the whole claim under test is that
//! retraction repairs downstream belief *without* a manual recompute.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{admin_auth, build_test_server, seed_claim, seed_claim_with_belief};
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::tools::supersede::supersede_claim;
use epigraph_mcp::types::{LinkEpistemicParams, SupersedeClaimParams};
use sqlx::PgPool;
use uuid::Uuid;

// ── fixture helpers ─────────────────────────────────────────────────────────

/// Cached DS scalars on `claims`, in the order
/// `(belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing)`.
type CachedScalars = (
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
);

async fn read_scalars(pool: &PgPool, claim_id: Uuid) -> CachedScalars {
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing \
         FROM claims WHERE id = $1",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .expect("read cached DS scalars")
}

async fn read_betp(pool: &PgPool, claim_id: Uuid) -> Option<f64> {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read pignistic_prob")
}

async fn wire_supports(
    pool: &PgPool,
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    s: Uuid,
    t: Uuid,
) {
    let viewer = fixture::public_viewer(pool).await;
    let result = do_link_epistemic(
        server, &viewer,
        LinkEpistemicParams {
            source_claim_id: s.to_string(),
            target_claim_id: t.to_string(),
            relationship: "supports".to_string(),
            properties: None,
        },
    )
    .await
    .expect("link_epistemic supports");
    let text = result
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text
        .clone();
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("link response json");
    assert_eq!(
        parsed["belief_wired"],
        serde_json::Value::Bool(true),
        "fixture precondition: {s} --supports--> {t} must materialize a BBA \
         (belief_wired=true), else the cascade has nothing to invalidate; raw={text}"
    );
    // The BBA must have landed on the TARGET keyed by the edge id.
    let bba_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions mf \
         JOIN edges e ON e.id = mf.perspective_id \
         WHERE mf.claim_id = $1 AND e.source_id = $2 AND e.target_id = $1",
    )
    .bind(t)
    .bind(s)
    .fetch_one(pool)
    .await
    .expect("count edge BBAs");
    assert_eq!(
        bba_count, 1,
        "expected exactly one edge-factor BBA for {s}->{t}"
    );
}

async fn supersede(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    old: Uuid,
) -> Result<rmcp::model::CallToolResult, epigraph_mcp::errors::McpError> {
    supersede_claim(
        server, &viewer,
        SupersedeClaimParams {
            claim_id: old.to_string(),
            content: format!("replacement for {old}"),
            truth_value: 0.5,
            reason: "retracted by cascade regression fixture".to_string(),
        },
        Some(&admin_auth()),
    )
    .await
}

/// The canonical combine pipeline's answer for `claim` on the binary frame,
/// computed WITHOUT writing. C2/C5 compare the cached scalar against this.
async fn preview_betp(pool: &PgPool, claim_id: Uuid) -> Option<f64> {
    let viewer = fixture::public_viewer(pool).await;
    let frame_id = epigraph_engine::edge_factor::ensure_binary_frame(pool, &viewer)
        .await
        .expect("binary frame");
    epigraph_engine::edge_factor::preview_claim_belief_on_frame(pool, &viewer, claim_id, frame_id)
        .await
        .expect("preview")
        .map(|p| p.pignistic_prob)
}

// ── C2 (ANCHOR) ─────────────────────────────────────────────────────────────

/// C2: superseding a supporter must move the downstream claim's *cached*
/// belief, and leave it coherent with what the canonical combine pipeline
/// produces from the BBAs that actually survive.
///
/// This is the criterion that separates a real repair from the naive
/// "enumerate targets → call `recompute_beliefs`" implementation: that one
/// re-combines the SAME stored `mass_functions.masses` rows and is a
/// bit-for-bit no-op (PREREGISTRATION F2 / BCH-EG-K02).
///
/// A and C carry deliberately different intervals so the observed move cannot
/// be a coincidence of two identical supporters cancelling out.
#[sqlx::test(migrations = "../../migrations")]
async fn downstream_cache_drops_retracted_supporter(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let a = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let c = seed_claim_with_belief(&pool, 0.6, 0.7, Some(0.65)).await;
    let b = seed_claim(&pool, "downstream claim B", 0.5).await;

    wire_supports(&pool, &server, a, b).await;
    wire_supports(&pool, &server, c, b).await;

    let betp_before = read_betp(&pool, b).await.expect("B has a cached BetP");

    supersede(&server, &viewer, a)
        .await
        .expect("supersede_claim succeeds");

    let betp_after = read_betp(&pool, b)
        .await
        .expect("B still has a cached BetP");

    assert!(
        (betp_after - betp_before).abs() > 1e-9,
        "retracting supporter A must move B's cached BetP; before={betp_before}, after={betp_after} \
         (a cascade that merely re-combines the stale edge BBAs is a numeric no-op)"
    );

    let coherent = preview_betp(&pool, b)
        .await
        .expect("B still has at least the C supporter");
    assert!(
        (betp_after - coherent).abs() < 1e-12,
        "B's cached BetP ({betp_after}) must equal the canonical combine of its \
         POST-cascade mass_functions set ({coherent})"
    );
}

// ── C3 (CONTROL) ────────────────────────────────────────────────────────────

/// C3: the cascade is surgical. The surviving supporter's BBA row must not be
/// re-derived (its calibration-owned columns are byte-identical), and a claim
/// with no relationship to the retraction must not be rewritten at all.
///
/// A cascade whose numbers shift on untouched rows is silently rewriting the
/// graph's calibration on every supersede, at which point "the cascade ran"
/// says nothing about whether the resulting number is right.
#[sqlx::test(migrations = "../../migrations")]
async fn cascade_does_not_touch_unrelated_bbas_or_claims(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let a = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let c = seed_claim_with_belief(&pool, 0.6, 0.7, Some(0.65)).await;
    let b = seed_claim(&pool, "downstream claim B", 0.5).await;
    // D: own BBA, no edge to A, B or C.
    let d_source = seed_claim_with_belief(&pool, 0.8, 0.85, Some(0.82)).await;
    let d = seed_claim(&pool, "unrelated claim D", 0.5).await;

    wire_supports(&pool, &server, a, b).await;
    wire_supports(&pool, &server, c, b).await;
    wire_supports(&pool, &server, d_source, d).await;

    type BbaRow = (
        serde_json::Value,
        Option<f64>,
        Option<String>,
        String,
        Option<Uuid>,
    );
    let read_c_bba = |pool: PgPool| async move {
        sqlx::query_as::<_, BbaRow>(
            "SELECT mf.masses, mf.source_strength, mf.evidence_type, mf.locality_tag, mf.perspective_id \
             FROM mass_functions mf JOIN edges e ON e.id = mf.perspective_id \
             WHERE e.source_id = $1 AND e.target_id = $2",
        )
        .bind(c)
        .bind(b)
        .fetch_one(&pool)
        .await
        .expect("read C->B BBA row")
    };

    let c_bba_before = read_c_bba(pool.clone()).await;
    let d_before = read_scalars(&pool, d).await;
    let d_updated_before: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT updated_at FROM claims WHERE id = $1")
            .bind(d)
            .fetch_one(&pool)
            .await
            .expect("read D updated_at");

    supersede(&server, &viewer, a)
        .await
        .expect("supersede_claim succeeds");

    let c_bba_after = read_c_bba(pool.clone()).await;
    assert_eq!(
        c_bba_before, c_bba_after,
        "the surviving C->B BBA must be byte-identical after the cascade — \
         re-deriving calibration-owned fields on an edge the retraction never \
         touched silently rewrites the graph's calibration"
    );

    let d_after = read_scalars(&pool, d).await;
    assert_eq!(
        d_before, d_after,
        "unrelated claim D's cached scalars must be bit-identical"
    );
    let d_updated_after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT updated_at FROM claims WHERE id = $1")
            .bind(d)
            .fetch_one(&pool)
            .await
            .expect("read D updated_at");
    assert_eq!(
        d_updated_before, d_updated_after,
        "unrelated claim D must not even be touched (updated_at moved)"
    );
}

// ── C6 ──────────────────────────────────────────────────────────────────────

/// C6: when the retracted supporter was the downstream claim's ONLY BBA, the
/// canonical recompute short-circuits on `all_rows.is_empty()` and writes
/// nothing — leaving B believed at its pre-retraction value with no evidence
/// backing it at all, while every "did the cascade run" assertion passes
/// (PREREGISTRATION F5 / BCH-EG-K04).
///
/// The implementation's documented choice is **(ii) explicit unbacked marker**:
/// the derived scalars are NULLed, which is exactly the state a claim carries
/// before it ever acquires a BBA (see `link_epistemic_smoke`'s "target must
/// start with NULL pignistic_prob"). A reader can then distinguish "unbacked"
/// from "believed at 0.79".
#[sqlx::test(migrations = "../../migrations")]
async fn sole_supporter_retraction_does_not_leave_frozen_belief(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let a = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let b = seed_claim(&pool, "sole-supported claim B", 0.5).await;

    wire_supports(&pool, &server, a, b).await;

    let betp_before = read_betp(&pool, b).await.expect("B has a cached BetP");
    let bba_count_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1")
            .bind(b)
            .fetch_one(&pool)
            .await
            .expect("count B BBAs");
    assert_eq!(bba_count_before, 1, "fixture: A->B must be B's only BBA");

    supersede(&server, &viewer, a)
        .await
        .expect("supersede_claim succeeds");

    let (bel, pl, betp, empty, missing) = read_scalars(&pool, b).await;
    assert!(
        betp != Some(betp_before),
        "B's belief ({betp:?}) must not survive the retraction of its sole \
         supporter unchanged at {betp_before} — 'nothing to recompute' is not \
         'nothing to change'; the cached scalars are a stale cache, not a view"
    );
    assert_eq!(
        (bel, pl, betp, empty, missing),
        (None, None, None, None, None),
        "documented semantics (ii): a claim with no surviving BBA is marked \
         unbacked (NULL scalars), not reset to a fabricated 0.5"
    );
    let classification: Option<String> =
        sqlx::query_scalar("SELECT classification FROM claims WHERE id = $1")
            .bind(b)
            .fetch_one(&pool)
            .await
            .expect("read classification");
    assert_eq!(
        classification, None,
        "the CDST classification is derived from the same evidence and must be \
         cleared with it — a surviving 'supported' label is an orphaned \
         derived record"
    );
}

// ── C7 ──────────────────────────────────────────────────────────────────────

/// C7.1 + C7.2: a mutually-supporting pair must not send the cascade round the
/// loop, and the walk must stop after one hop.
///
/// Naive reasoning here is that Dempster-Shafer combination is a contraction so
/// the propagation "settles" — it does not: each pass re-derives BBAs from
/// freshly written intervals, and the walk starves the pool or hangs. The bound
/// is structural (1 hop + a `visited` set), not numeric.
///
/// C is present so the coherence check has content: without a second supporter,
/// B ends up unbacked and the assertion would degenerate to `None == None`.
#[sqlx::test(migrations = "../../migrations")]
async fn cyclic_support_terminates(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let a = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let c = seed_claim_with_belief(&pool, 0.6, 0.7, Some(0.65)).await;
    let b = seed_claim(&pool, "cyclic partner B", 0.5).await;

    wire_supports(&pool, &server, a, b).await;
    wire_supports(&pool, &server, c, b).await;
    // B now carries an interval, so B --supports--> A wires too, closing the cycle.
    wire_supports(&pool, &server, b, a).await;

    // The reverse edge's BBA lives on A, keyed by that edge's id. If the walk
    // followed the cycle back from B it would invalidate this row.
    let reverse_edge: Uuid =
        sqlx::query_scalar("SELECT id FROM edges WHERE source_id = $1 AND target_id = $2")
            .bind(b)
            .bind(a)
            .fetch_one(&pool)
            .await
            .expect("read B->A edge id");

    let result = tokio::time::timeout(std::time::Duration::from_secs(30), supersede(&server, &viewer, a))
        .await
        .expect("cascade must terminate on a mutually-supporting pair, not loop");
    result.expect("supersede_claim succeeds on a cyclic fixture");

    // One hop forward: B was repaired and its cache is coherent with the C
    // supporter that survived.
    let b_betp = read_betp(&pool, b)
        .await
        .expect("B keeps a cached BetP — the C supporter survived");
    let coherent = preview_betp(&pool, b).await.expect("B still has a BBA");
    assert!(
        (b_betp - coherent).abs() < 1e-12,
        "B's cache ({b_betp}) must be coherent with its surviving BBAs ({coherent})"
    );

    // ...and no second hop: the reverse edge's BBA was not touched.
    let reverse_bba_survived: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mass_functions WHERE perspective_id = $1)",
    )
    .bind(reverse_edge)
    .fetch_one(&pool)
    .await
    .expect("check reverse BBA");
    assert!(
        reverse_bba_survived,
        "the B->A' edge is two hops from the retraction; invalidating it means \
         the walk followed the cycle back and the 1-hop bound is not real"
    );
}

/// C7.3 / BCH-EG-K06: the supersede transaction has already committed by the
/// time the cascade runs. A cascade failure must be swallowed — propagating it
/// hands the caller an error for a write that succeeded, and the retry gets
/// "Claim <uuid> has already been superseded": a wedged, unrecoverable state.
///
/// The failure is induced for real (not mocked): the surviving supporter's
/// stored BBA is corrupted so `parse_stored_bba` errors inside the combine
/// pipeline, which is exactly the shape of a live "belief subsystem cannot
/// run" fault.
#[sqlx::test(migrations = "../../migrations")]
async fn cascade_failure_does_not_fail_the_write(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let a = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let c = seed_claim_with_belief(&pool, 0.6, 0.7, Some(0.65)).await;
    let b = seed_claim(&pool, "downstream claim B", 0.5).await;

    wire_supports(&pool, &server, a, b).await;
    wire_supports(&pool, &server, c, b).await;

    // Corrupt the surviving supporter's BBA so it no longer deserializes as
    // a mass map: the combine pipeline then returns Err for B. (An unknown
    // focal-element KEY would not do — `from_json_masses` folds those into the
    // conflict element rather than failing.)
    sqlx::query(
        "UPDATE mass_functions SET masses = '{\"0\": \"not-a-number\"}'::jsonb \
         WHERE perspective_id = (SELECT id FROM edges WHERE source_id = $1 AND target_id = $2)",
    )
    .bind(c)
    .bind(b)
    .execute(&pool)
    .await
    .expect("corrupt surviving BBA");

    let result = supersede(&server, &viewer, a).await;
    assert!(
        result.is_ok(),
        "supersede must still report success when the belief subsystem cannot \
         run — the transaction already committed: {:?}",
        result.err()
    );

    let (is_current, superseded_by): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT is_current, (SELECT id FROM claims WHERE supersedes = $1) FROM claims WHERE id = $1",
    )
    .bind(a)
    .fetch_one(&pool)
    .await
    .expect("read A state");
    assert!(
        !is_current,
        "A must still be retired despite the cascade error"
    );
    assert!(
        superseded_by.is_some(),
        "the replacement claim must still exist despite the cascade error"
    );
}

/// C7.1 / BCH-EG-K05, stated without a cycle: on the chain
/// `A --supports--> B --supports--> C`, retracting `A` must repair `B` and
/// stop. `C` is two hops out and must be left completely alone.
///
/// This is the assertion `cyclic_support_terminates` cannot make. Its bound is
/// observed as "the walk did not come back", which a non-terminating
/// implementation would demonstrate by hanging rather than by failing an
/// assertion; and the 1-hop bound itself is structural (flat `for` loops over
/// one query result — there is no recursion in `retraction_cascade` to bound).
/// A straight chain turns the bound into something a future edit can actually
/// break: add transitive propagation and this goes red immediately, because
/// `B`'s BBA set changes and a second hop would invalidate `B --supports--> C`.
#[sqlx::test(migrations = "../../migrations")]
async fn second_hop_downstream_of_the_retraction_is_not_touched(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let a = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let b = seed_claim(&pool, "one hop out: B", 0.5).await;
    let c = seed_claim(&pool, "two hops out: C", 0.5).await;

    wire_supports(&pool, &server, a, b).await;
    // B now carries an interval of its own, so B --supports--> C wires.
    wire_supports(&pool, &server, b, c).await;

    let hop_two_edge: Uuid =
        sqlx::query_scalar("SELECT id FROM edges WHERE source_id = $1 AND target_id = $2")
            .bind(b)
            .bind(c)
            .fetch_one(&pool)
            .await
            .expect("read B->C edge id");
    let hop_two_masses_before: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT masses FROM mass_functions WHERE perspective_id = $1")
            .bind(hop_two_edge)
            .fetch_optional(&pool)
            .await
            .expect("read B->C BBA");
    assert!(
        hop_two_masses_before.is_some(),
        "fixture: the second hop must carry a BBA, else there is nothing to \
         observe being left alone"
    );
    let c_before = read_scalars(&pool, c).await;
    let c_updated_before: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT updated_at FROM claims WHERE id = $1")
            .bind(c)
            .fetch_one(&pool)
            .await
            .expect("read C updated_at");

    supersede(&server, &viewer, a)
        .await
        .expect("supersede_claim succeeds");

    let hop_two_masses_after: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT masses FROM mass_functions WHERE perspective_id = $1")
            .bind(hop_two_edge)
            .fetch_optional(&pool)
            .await
            .expect("read B->C BBA");
    assert_eq!(
        hop_two_masses_before, hop_two_masses_after,
        "the B->C edge factor is two hops from the retraction; invalidating or \
         re-deriving it means the walk did not stop at one hop"
    );
    assert_eq!(
        c_before,
        read_scalars(&pool, c).await,
        "C's cached scalars must be bit-identical two hops out"
    );
    let c_updated_after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT updated_at FROM claims WHERE id = $1")
            .bind(c)
            .fetch_one(&pool)
            .await
            .expect("read C updated_at");
    assert_eq!(
        c_updated_before, c_updated_after,
        "C must not even be written to"
    );
}
