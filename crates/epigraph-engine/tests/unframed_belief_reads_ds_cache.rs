//! Backlog 152d9af6: unframed `get_belief` never read the DS cache.
//!
//! `belief_query::get_belief` called without a `frame_id` returned
//! `BeliefInterval::cached_from_truth(claim.truth_value)` — i.e. `{belief:
//! truth_value, plausibility: 1.0, pignistic_prob: truth_value}` — ignoring the
//! `claims.{belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing}`
//! columns entirely.
//!
//! Both the MCP tool schema ("If omitted, returns cached DS columns") and the
//! function's own doc comment ("returns the cached DS columns from the claim row")
//! described behaviour the code did not have.
//!
//! The practical consequence is that two read channels disagreed:
//! `link_epistemic`'s readback consults the cache via
//! `ClaimRepository::get_belief_columns`, while the unframed `get_belief` did not.
//! A claim whose belief had been moved by epistemic edges reported its pre-edge
//! `truth_value` through one channel and its edge-derived value through the other —
//! which is what made a recompute look like a clean revert in backlog 696d3a1c.

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use epigraph_engine::belief_query::get_belief;
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at) \
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

async fn insert_claim(pool: &PgPool, agent: Uuid, truth: f64) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("152d9af6 {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, sha256($2::bytea), $3, $4)",
    )
    .bind(id)
    .bind(&content)
    .bind(truth)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

/// A claim whose DS columns have been written must report THOSE values, not a
/// reconstruction from `truth_value`.
#[sqlx::test(migrations = "../../migrations")]
async fn unframed_get_belief_returns_the_persisted_ds_columns(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    // truth_value deliberately far from the DS state, so a reconstruction from it
    // cannot coincidentally match.
    let claim = insert_claim(&pool, agent, 0.6).await;

    sqlx::query(
        "UPDATE claims SET belief = 0.12, plausibility = 0.44, pignistic_prob = 0.28, \
         mass_on_empty = 0.07, mass_on_missing = 0.05 WHERE id = $1",
    )
    .bind(claim)
    .execute(&pool)
    .await
    .expect("seed DS columns");

    let got = get_belief(&pool, claim, None).await.expect("get_belief");

    assert!(
        (got.belief - 0.12).abs() < 1e-9,
        "belief must come from claims.belief, got {} — a value of 0.6 means it was \
         reconstructed from truth_value (backlog 152d9af6)",
        got.belief
    );
    assert!(
        (got.plausibility - 0.44).abs() < 1e-9,
        "plausibility must come from claims.plausibility, got {} — a value of 1.0 is \
         the hardcoded cached_from_truth signature",
        got.plausibility
    );
    assert!(
        (got.pignistic_prob - 0.28).abs() < 1e-9,
        "pignistic_prob must come from claims.pignistic_prob, got {}",
        got.pignistic_prob
    );
    assert!(
        (got.mass_on_conflict - 0.07).abs() < 1e-9,
        "mass_on_conflict must come from claims.mass_on_empty, got {}",
        got.mass_on_conflict
    );
    assert!(
        (got.mass_on_missing - 0.05).abs() < 1e-9,
        "mass_on_missing must come from claims.mass_on_missing, got {}",
        got.mass_on_missing
    );
    assert!(!got.framed, "the unframed path must not report framed=true");
}

/// The two read channels must agree. This is the disagreement that made a
/// recompute look like a clean revert in 696d3a1c.
#[sqlx::test(migrations = "../../migrations")]
async fn unframed_get_belief_agrees_with_get_belief_columns(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let claim = insert_claim(&pool, agent, 0.9).await;

    sqlx::query(
        "UPDATE claims SET belief = 0.31, plausibility = 0.67, pignistic_prob = 0.49, \
         mass_on_empty = 0.0, mass_on_missing = 0.0 WHERE id = $1",
    )
    .bind(claim)
    .execute(&pool)
    .await
    .expect("seed DS columns");

    let via_engine = get_belief(&pool, claim, None).await.expect("get_belief");
    let via_repo = ClaimRepository::get_belief_columns(&pool, ClaimId::from_uuid(claim))
        .await
        .expect("get_belief_columns")
        .expect("columns present");

    assert!(
        (via_engine.belief - via_repo.belief.unwrap()).abs() < 1e-9
            && (via_engine.plausibility - via_repo.plausibility.unwrap()).abs() < 1e-9
            && (via_engine.pignistic_prob - via_repo.pignistic_prob.unwrap()).abs() < 1e-9,
        "the two cached-read channels disagree — engine {:?} vs repo belief={:?} \
         plausibility={:?} betp={:?}. link_epistemic reads the repo channel, so a \
         disagreement means the same claim reports two different beliefs depending on \
         which tool asks.",
        via_engine,
        via_repo.belief,
        via_repo.plausibility,
        via_repo.pignistic_prob
    );
}

/// A claim that has never had a DS write still has NULL columns. It must fall back
/// to the truth_value reconstruction rather than reporting zeros, which would read
/// as "refuted" instead of "no DS state".
#[sqlx::test(migrations = "../../migrations")]
async fn unframed_get_belief_falls_back_when_no_ds_columns(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let claim = insert_claim(&pool, agent, 0.73).await;

    let got = get_belief(&pool, claim, None).await.expect("get_belief");

    assert!(
        (got.belief - 0.73).abs() < 1e-9 && (got.plausibility - 1.0).abs() < 1e-9,
        "with no DS columns written the unframed read must fall back to the \
         truth_value reconstruction, got belief={} plausibility={}. Reporting 0.0 \
         here would make an unassessed claim indistinguishable from a refuted one.",
        got.belief,
        got.plausibility
    );
    assert_eq!(
        got.source, "cached",
        "the fallback must still identify itself as a cached read"
    );
}
