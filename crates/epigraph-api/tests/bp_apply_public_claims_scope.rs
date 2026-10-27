#![cfg(feature = "db")]
//! Ruling R-22 (backlog fef24216) on BP apply (`POST /api/v1/bp/propagate`
//! with `apply_updates: true`, available only under `EPIGRAPH_BP_APPLY=on`):
//! BP messages travel along factors, so a PUBLIC claim's BP value carries the
//! belief of every claim in its connected component. A run that names a
//! group-private claim beside a public one must not write the public claim's
//! cache from it.
//!
//! # What was wrong, measured at origin/main before this file
//!
//! `apply_bp_updates` wrote every visible, non-compound claim the run
//! computed, so a member of the group could run BP over a factor joining its
//! private claim to a public one and write the result into the public
//! claim's cache.
//!
//! The handler runs on the `#[sqlx::test]` superuser pools with BP apply on,
//! as the member; the factor graph and the claims are seeded directly.

mod viewer_fixture;

use axum::extract::State;
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::computation::{propagate_beliefs, PropagateRequest};
use epigraph_api::state::{ApiConfig, AppState, BpApply};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{scoped_pool, seed_agent_with_group, seed_group_claim, seed_public_claim};

async fn set_betp(pool: &PgPool, claim: Uuid, p: f64) {
    sqlx::query("UPDATE claims SET pignistic_prob = $2 WHERE id = $1")
        .bind(claim)
        .bind(p)
        .execute(pool)
        .await
        .expect("seed BetP");
}

async fn betp(pool: &PgPool, claim: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read BetP")
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

#[sqlx::test(migrations = "../../migrations")]
async fn bp_apply_never_writes_a_public_claim_from_a_private_neighbour(pool: PgPool) {
    let (member, group) = seed_agent_with_group(&pool, "r22-bp-member").await;
    let frame = epigraph_db::FrameRepository::create(
        &pool,
        "r22_bp_frame",
        None,
        &["supported".to_string(), "unsupported".to_string()],
    )
    .await
    .expect("frame")
    .id;

    // One component joins a group-private claim to a public one; another is
    // public on both ends.
    let private = seed_group_claim(&pool, member, group, "r22 bp private").await;
    let exposed = seed_public_claim(&pool, member, "r22 bp public beside private").await;
    let left = seed_public_claim(&pool, member, "r22 bp public left").await;
    let right = seed_public_claim(&pool, member, "r22 bp public right").await;
    for (c, p) in [(private, 0.95), (exposed, 0.3), (left, 0.9), (right, 0.3)] {
        set_betp(&pool, c, p).await;
    }
    factor(&pool, frame, private, exposed).await;
    factor(&pool, frame, left, right).await;

    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped_pool(&pool).await);
    state.bp_apply = BpApply::On;
    let viewer = Viewer::resolve(&pool, member).await.expect("member viewer");
    let request: PropagateRequest = serde_json::from_value(serde_json::json!({
        "frame_id": frame,
        "apply_updates": true,
        "mode": "scalar",
        "max_iterations": 10,
    }))
    .expect("request");
    let Json(body) = propagate_beliefs(ViewerExtractor(viewer), State(state), Json(request))
        .await
        .unwrap_or_else(|e| panic!("propagate_beliefs failed: {e:?}"));

    let computed: Vec<Uuid> = body["updated_beliefs"]
        .as_array()
        .expect("updated_beliefs")
        .iter()
        .filter_map(|b| b["claim_id"].as_str().and_then(|s| s.parse().ok()))
        .collect();
    assert!(
        computed.contains(&exposed),
        "PREMISE: BP computed a value for the public claim beside the private one: {body}"
    );
    assert_eq!(
        betp(&pool, exposed).await,
        Some(0.3),
        "BP apply wrote a public claim's cache from a group-private neighbour: {body}"
    );
    assert_eq!(
        body["skipped_less_readable_inputs"].as_u64(),
        Some(1),
        "the skip is reported: {body}"
    );
    // Controls. `applied_count >= 1` alone would hold if only the private
    // claim were written, so each claim that must be applied is checked: the
    // all-public component, and the group-private claim (a NARROWER claim may
    // be informed by a more readable one; its audience can read both).
    let served = |claim: Uuid| -> f64 {
        body["updated_beliefs"]
            .as_array()
            .expect("updated_beliefs")
            .iter()
            .find(|b| b["claim_id"].as_str() == Some(claim.to_string().as_str()))
            .and_then(|b| b["betp"].as_f64())
            .unwrap_or_else(|| panic!("no BP value for {claim}: {body}"))
    };
    let seeds = [(private, 0.95), (left, 0.9), (right, 0.3)];
    assert!(
        seeds.iter().any(|(c, p)| (served(*c) - p).abs() > 1e-6),
        "PREMISE: BP moved at least one of the claims that must be applied: {body}"
    );
    for (claim, _) in seeds {
        let cached = betp(&pool, claim).await.expect("cache");
        assert!(
            (cached - served(claim)).abs() < 1e-9,
            "claim {claim} must be applied (cache {cached}, BP {}): {body}",
            served(claim)
        );
    }
    assert_eq!(body["applied_count"].as_u64(), Some(3), "{body}");
}

async fn team_group(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind) \
         VALUES ($1, 'did:test:r22bp:' || gen_random_uuid(), decode(repeat('ab', 32), 'hex'), \
                 'team') RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("team group")
}

/// The security review's generalisation: a GROUP claim beside ANOTHER group's
/// claim in one component is not written either (each is less readable than
/// the other's audience), while a component of one group's claims is.
#[sqlx::test(migrations = "../../migrations")]
async fn bp_apply_never_writes_a_group_claim_from_another_groups_neighbour(pool: PgPool) {
    let (member, _) = seed_agent_with_group(&pool, "r22-bp-both").await;
    let group_a = team_group(&pool, "r22 bp A").await;
    let group_b = team_group(&pool, "r22 bp B").await;
    for g in [group_a, group_b] {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'admin')",
        )
        .bind(g)
        .bind(member)
        .execute(&pool)
        .await
        .expect("membership");
    }
    let frame = epigraph_db::FrameRepository::create(
        &pool,
        "r22_bp_groups_frame",
        None,
        &["supported".to_string(), "unsupported".to_string()],
    )
    .await
    .expect("frame")
    .id;
    let in_a = seed_group_claim(&pool, member, group_a, "r22 bp A beside B").await;
    let in_b = seed_group_claim(&pool, member, group_b, "r22 bp B beside A").await;
    let a_left = seed_group_claim(&pool, member, group_a, "r22 bp A left").await;
    let a_right = seed_group_claim(&pool, member, group_a, "r22 bp A right").await;
    for (c, p) in [(in_a, 0.3), (in_b, 0.95), (a_left, 0.9), (a_right, 0.3)] {
        set_betp(&pool, c, p).await;
    }
    factor(&pool, frame, in_b, in_a).await;
    factor(&pool, frame, a_left, a_right).await;

    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped_pool(&pool).await);
    state.bp_apply = BpApply::On;
    let viewer = Viewer::resolve(&pool, member).await.expect("member viewer");
    let request: PropagateRequest = serde_json::from_value(serde_json::json!({
        "frame_id": frame,
        "apply_updates": true,
        "mode": "scalar",
        "max_iterations": 10,
    }))
    .expect("request");
    let Json(body) = propagate_beliefs(ViewerExtractor(viewer), State(state), Json(request))
        .await
        .unwrap_or_else(|e| panic!("propagate_beliefs failed: {e:?}"));

    assert_eq!(
        betp(&pool, in_a).await,
        Some(0.3),
        "BP apply wrote group A's claim from group B's neighbour: {body}"
    );
    assert_eq!(
        betp(&pool, in_b).await,
        Some(0.95),
        "BP apply wrote group B's claim from group A's neighbour: {body}"
    );
    assert_eq!(
        body["skipped_less_readable_inputs"].as_u64(),
        Some(2),
        "both skips are reported: {body}"
    );
    assert!(
        body["applied_count"].as_u64().unwrap_or_default() >= 1,
        "the one-group component must still be applied: {body}"
    );
}
