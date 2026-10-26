#![cfg(feature = "db")]
//! The CDST seeds of `POST /api/v1/bp/propagate` (`propagate_beliefs`, mode
//! `cdst`): each claim's stored BBAs, combined, anchor that claim's BP value.
//!
//! * Ruling R-22 (backlog fef24216, generalised by the security review and
//!   confirmed as R-71): a read-only run (`apply_updates: false`, the default
//!   diagnostic) serves BetP values to its caller, so a claim's seed folds only
//!   the BBAs whose every source THAT caller can read; a run that writes
//!   caches seeds each claim with the BBAs its cache may hold.
//!
//! # What was wrong, measured before this file
//!
//! The read-only run seeded every visible BBA row, and a row on a public
//! claim is public whatever it was derived from: a stranger's BP value moved
//! with a BBA citing evidence narrowed to a group.
//!
//! # The oracle
//!
//! Components are isolated (one factor between a seeded claim and an unseeded
//! partner), so a claim's BP value depends only on its seed. Two claims whose
//! seeds must be equal therefore get equal BP values, and the values are
//! compared between such pairs, never to a hand-computed BP number.
//!
//! The handler runs on the `#[sqlx::test]` superuser pools (the viewer
//! predicates decide).

mod viewer_fixture;

use axum::extract::State;
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::computation::{propagate_beliefs, PropagateRequest};
use epigraph_api::state::{ApiConfig, AppState, BpApply};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{scoped_pool, seed_agent_with_group, seed_evidence, seed_public_claim};

async fn frame(pool: &PgPool, name: &str) -> Uuid {
    epigraph_db::FrameRepository::create(
        pool,
        name,
        None,
        &["supported".to_string(), "unsupported".to_string()],
    )
    .await
    .expect("frame")
    .id
}

async fn factor(pool: &PgPool, frame: Uuid, a: Uuid, b: Uuid) {
    sqlx::query(
        "INSERT INTO factors (id, factor_type, variable_ids, potential, frame_id) \
         VALUES ($1, 'evidential_support', $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(vec![a, b])
    .bind(serde_json::json!({"strength": 0.8}))
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed factor");
}

/// A stored BBA on `claim`: `t` on "supported", the rest on the frame.
async fn bba(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, evidence: Option<Uuid>, t: f64) {
    epigraph_db::MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        evidence,
        &serde_json::json!({"0": t, "0,1": 1.0 - t}),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        evidence,
    )
    .await
    .expect("store a BBA");
}

async fn run(
    pool: &PgPool,
    caller: Uuid,
    frame: Uuid,
    apply: bool,
    bp_apply: bool,
) -> serde_json::Value {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped_pool(pool).await);
    if bp_apply {
        state.bp_apply = BpApply::On;
    }
    let viewer = Viewer::resolve(pool, caller).await.expect("caller viewer");
    let request: PropagateRequest = serde_json::from_value(serde_json::json!({
        "frame_id": frame,
        "apply_updates": apply,
        "mode": "cdst",
        "max_iterations": 10,
    }))
    .expect("request");
    let Json(body) = propagate_beliefs(ViewerExtractor(viewer), State(state), Json(request))
        .await
        .unwrap_or_else(|e| panic!("propagate_beliefs failed: {e:?}"));
    body
}

fn served(body: &serde_json::Value, claim: Uuid) -> f64 {
    body["updated_beliefs"]
        .as_array()
        .expect("updated_beliefs")
        .iter()
        .find(|b| b["claim_id"].as_str() == Some(claim.to_string().as_str()))
        .and_then(|b| b["betp"].as_f64())
        .unwrap_or_else(|| panic!("no BP value for {claim}: {body}"))
}

async fn cached_betp(pool: &PgPool, claim: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read BetP")
}

/// A public claim with a public BBA and one citing evidence narrowed to the
/// member's group, in a component with a public partner. Returns
/// `(frame, target, member, stranger, public_only_served)` where the last is
/// the stranger's BP value for the target BEFORE the narrowed BBA existed.
async fn public_claim_with_a_narrowed_bba(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid, f64) {
    let (member, group) = seed_agent_with_group(pool, "r22-bp-seed-member").await;
    let (stranger, _) = seed_agent_with_group(pool, "r22-bp-seed-stranger").await;
    let frame = frame(pool, "r22_bp_seed_frame").await;
    // The member authors both claims so that an applying run may write them.
    let target = seed_public_claim(pool, member, "r22 bp seed target").await;
    let partner = seed_public_claim(pool, member, "r22 bp seed partner").await;
    factor(pool, frame, target, partner).await;

    let public_ev = seed_evidence(pool, target, "observation").await;
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(pool, public_ev, Some(member))
        .await
        .expect("evidence perspective");
    bba(pool, target, frame, member, Some(public_ev), 0.6).await;
    let public_only = served(&run(pool, stranger, frame, false, false).await, target);

    let hidden_ev = seed_evidence(pool, target, "document").await;
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(hidden_ev)
        .bind(group)
        .execute(pool)
        .await
        .expect("narrow the evidence to the group");
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(pool, hidden_ev, Some(member))
        .await
        .expect("evidence perspective");
    bba(pool, target, frame, member, Some(hidden_ev), 0.8).await;
    (frame, target, member, stranger, public_only)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_read_only_bp_run_serves_a_stranger_no_seed_from_narrowed_evidence(pool: PgPool) {
    let (frame, target, member, stranger, public_only) =
        public_claim_with_a_narrowed_bba(&pool).await;

    let mine = served(&run(&pool, member, frame, false, false).await, target);
    assert!(
        mine > public_only + 1e-3,
        "PREMISE: the narrowed BBA moves the member's BP value ({mine} vs {public_only})"
    );
    let theirs = served(&run(&pool, stranger, frame, false, false).await, target);
    assert!(
        (theirs - public_only).abs() < 1e-9,
        "a read-only BP run served a stranger a value moved by evidence narrowed to a group: \
         {public_only} -> {theirs}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_applying_cdst_run_seeds_a_public_claim_without_its_narrowed_bba(pool: PgPool) {
    let (frame, target, member, _stranger, public_only) =
        public_claim_with_a_narrowed_bba(&pool).await;

    // The member can read the narrowed evidence, but the claim's cache is read
    // by everyone: an applying run seeds it as its own recompute would.
    let body = run(&pool, member, frame, true, true).await;
    assert_eq!(
        body["skipped_less_readable_inputs"].as_u64(),
        Some(0),
        "PREMISE: an all-public component is applied: {body}"
    );
    let written = cached_betp(&pool, target)
        .await
        .expect("BP wrote the claim");
    assert!(
        (written - public_only).abs() < 1e-9,
        "BP apply seeded a public claim's cache from evidence narrowed to a group: \
         {public_only} -> {written} ({body})"
    );
}
