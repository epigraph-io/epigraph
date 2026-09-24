//! Backlog `14b98adc`: `min_truth` gated on the stale `claims.truth_value`.
//!
//! `ClaimRepository::effective_belief_batch` is the scalar every `min_truth`
//! gate now compares against. It must be the exact SQL twin of
//! `belief_query::get_belief`'s UNFRAMED branch, because the two are the read
//! and the gate over the same state and a disagreement between them is the
//! class of defect this item is: two channels reporting different beliefs for
//! the same claim.
//!
//! The four selection cases below are that branch's four arms, and the
//! half-written arm is the one a "simplification" would delete: a bare
//! `COALESCE(pignistic_prob, belief, truth_value)` passes every OTHER case in
//! this file and reports a half-written DS row as authoritative. Migration 001's
//! `claims_bel_pl_order` explicitly permits `belief IS NOT NULL` with
//! `plausibility IS NULL`, so that row shape is reachable, not hypothetical.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// Overwrite a seeded claim's authored `truth_value`.
///
/// `fixture::seed_public_claim` hardcodes 0.8; every case here needs the
/// authored scalar to sit somewhere a DS-derived answer cannot coincidentally
/// match, so the assertions distinguish which column was read.
async fn set_truth(pool: &PgPool, claim: Uuid, truth: f64) {
    sqlx::query("UPDATE claims SET truth_value = $2 WHERE id = $1")
        .bind(claim)
        .bind(truth)
        .execute(pool)
        .await
        .expect("set truth_value");
}

async fn set_ds(
    pool: &PgPool,
    claim: Uuid,
    belief: Option<f64>,
    plausibility: Option<f64>,
    betp: Option<f64>,
) {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4 WHERE id = $1",
    )
    .bind(claim)
    .bind(belief)
    .bind(plausibility)
    .bind(betp)
    .execute(pool)
    .await
    .expect("set DS columns");
}

/// The production shape from the backlog item: claim `8f192373` carried
/// `truth_value` 1.0000 against a cached BetP of 0.1797, and every `min_truth`
/// gate in the system read the 1.0.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ds_cached_claim_reports_betp_not_the_authored_truth_value(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "ebb-betp").await;
    let claim = fixture::seed_public_claim(&pool, agent, "ebb: refuted but authored high").await;
    set_truth(&pool, claim, 1.0).await;
    set_ds(&pool, claim, Some(0.0), Some(0.3594), Some(0.1797)).await;

    let viewer = fixture::public_viewer(&pool).await;
    let got = ClaimRepository::effective_belief_batch(&pool, &viewer, &[claim])
        .await
        .expect("effective_belief_batch");

    let score = *got.get(&claim).expect("claim present");
    assert!(
        (score - 0.1797).abs() < 1e-9,
        "gate scalar must be the cached BetP, got {score}. A value of 1.0 is the \
         authored truth_value, which no DS write path refreshes — that is the \
         whole of backlog 14b98adc."
    );
}

/// `belief` written, `plausibility` still NULL — a half-written DS row.
///
/// `belief_query::get_belief` requires BOTH before treating the cache as
/// authoritative, so this must fall back to `truth_value`. A bare
/// `COALESCE(pignistic_prob, belief, truth_value)` returns 0.9 here and would
/// report a partial write as settled belief.
#[sqlx::test(migrations = "../../migrations")]
async fn a_half_written_ds_row_falls_back_to_truth_value(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "ebb-half").await;
    let claim = fixture::seed_public_claim(&pool, agent, "ebb: half-written DS row").await;
    set_truth(&pool, claim, 0.42).await;
    set_ds(&pool, claim, Some(0.9), None, None).await;

    let viewer = fixture::public_viewer(&pool).await;
    let got = ClaimRepository::effective_belief_batch(&pool, &viewer, &[claim])
        .await
        .expect("effective_belief_batch");

    let score = *got.get(&claim).expect("claim present");
    assert!(
        (score - 0.42).abs() < 1e-9,
        "a row with belief but no plausibility is half-written and must fall back \
         to truth_value, got {score}. 0.9 means the both-of-(belief, plausibility) \
         guard from belief_query.rs was dropped."
    );
}

/// Both bounds present but `pignistic_prob` still NULL (rows that predate the
/// column being populated). `belief_query::get_belief` falls back to `belief`
/// here, NOT to `truth_value` — that is the whole point of the read it mirrors.
#[sqlx::test(migrations = "../../migrations")]
async fn a_null_betp_with_both_bounds_falls_back_to_belief_not_truth_value(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "ebb-nullbetp").await;
    let claim = fixture::seed_public_claim(&pool, agent, "ebb: bounds without betp").await;
    set_truth(&pool, claim, 0.95).await;
    set_ds(&pool, claim, Some(0.31), Some(0.67), None).await;

    let viewer = fixture::public_viewer(&pool).await;
    let got = ClaimRepository::effective_belief_batch(&pool, &viewer, &[claim])
        .await
        .expect("effective_belief_batch");

    let score = *got.get(&claim).expect("claim present");
    assert!(
        (score - 0.31).abs() < 1e-9,
        "with both bounds written and BetP NULL the value must be `belief`, got \
         {score}. 0.95 would be truth_value — the scalar this read exists to stop \
         conflating with the DS state."
    );
}

/// A claim that has never had a DS write must gate exactly as it did before
/// this change. This is what makes the whole fix reviewable: every behaviour
/// change is attributable to a real DS cache.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_with_no_ds_state_reports_its_truth_value(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "ebb-none").await;
    let claim = fixture::seed_public_claim(&pool, agent, "ebb: no DS state at all").await;
    set_truth(&pool, claim, 0.73).await;

    let viewer = fixture::public_viewer(&pool).await;
    let got = ClaimRepository::effective_belief_batch(&pool, &viewer, &[claim])
        .await
        .expect("effective_belief_batch");

    let score = *got.get(&claim).expect("claim present");
    assert!(
        (score - 0.73).abs() < 1e-9,
        "with no DS columns written the gate must read truth_value, got {score}. \
         Reporting 0.0 would make an unassessed claim indistinguishable from a \
         refuted one, and would silently empty every default (min_truth=0.3) recall."
    );
}

/// The read is viewer-scoped, and both `Viewer` shapes must bind correctly.
///
/// Two properties in one test because they share a fixture and each is
/// meaningless without the other:
///
/// * **The predicate is live.** A group-private claim is absent for a
///   public-only viewer. Without this, the splice could be a no-op and every
///   other test here would still pass.
/// * **The bind arity is right for BOTH shapes.** `group_bind()` is `None` on a
///   bypass viewer, so the `$2` bind is conditional — an off-by-one is a runtime
///   error that a restricted-viewer-only test never reaches.
#[sqlx::test(migrations = "../../migrations")]
async fn the_read_is_viewer_scoped_under_both_viewer_shapes(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "ebb-scope").await;
    let open = fixture::seed_public_claim(&pool, agent, "ebb: public row").await;
    let shut = fixture::seed_group_claim(&pool, agent, group, "ebb: group-private row").await;
    set_truth(&pool, open, 0.61).await;
    set_truth(&pool, shut, 0.62).await;

    let public = fixture::public_viewer(&pool).await;
    let seen = ClaimRepository::effective_belief_batch(&pool, &public, &[open, shut])
        .await
        .expect("scoped read");
    assert!(
        seen.contains_key(&open),
        "the public claim must be visible to a public viewer; its absence would make \
         the negative assertion below vacuous"
    );
    assert!(
        !seen.contains_key(&shut),
        "a group-private claim leaked to a public-only viewer — the VISIBILITY marker \
         is spliced but not filtering"
    );

    // Bypass shape: no group bind at all. Hold the ScopedPool — dropping it
    // closes the pool the viewer was minted from.
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let all = ClaimRepository::effective_belief_batch(&pool, &bypass, &[open, shut])
        .await
        .expect("bypass read must not fail on bind arity");
    assert_eq!(
        all.len(),
        2,
        "a bypass viewer emits no predicate and must see both rows; got {all:?}"
    );
}

/// An empty id list must short-circuit rather than issue `= ANY('{}')`.
/// Every call site passes an empty slice on an empty page.
#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_id_list_returns_an_empty_map(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let got = ClaimRepository::effective_belief_batch(&pool, &viewer, &[])
        .await
        .expect("empty batch");
    assert!(got.is_empty(), "expected an empty map, got {got:?}");
}
