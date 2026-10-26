#![cfg(feature = "db")]
//! The STORED scoped beliefs (`ds_combined_beliefs`) that
//! `POST /api/v1/frames/:id/evidence` writes: the claim's global row (from the
//! shared recompute's preview) and the perspective row of the submission's
//! perspective (`scoped_belief_write`, which community rows share).
//!
//! * Ruling R-22 (backlog fef24216; generalised to every claim, R-71): a
//!   stored belief is read by everyone who can read the claim, so it folds
//!   only BBAs whose every source is at least as widely readable as the claim.
//! * Ruling R-36 (backlog fe3ec493): agents of one human never aggregate.
//!
//! It also pins the stored-row semantics the rewrite set (mass_on_empty,
//! conflict_k, strategy_used) for a single BBA, two independent agreeing
//! BBAs, a contest, and a same-human sibling group.
//!
//! The handler runs on the `#[sqlx::test]` superuser pools (the fold rules are
//! under test, not row security).

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::belief::{submit_evidence, SubmitEvidenceRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{scoped_pool, seed_agent_with_group, seed_evidence, seed_public_claim};

const EPS: f64 = 1e-9;

async fn state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped_pool(pool).await);
    state
}

async fn frame(pool: &PgPool, name: &str) -> Uuid {
    epigraph_db::FrameRepository::create(pool, name, None, &["h0".to_string(), "h1".to_string()])
        .await
        .expect("frame")
        .id
}

async fn perspective(pool: &PgPool, owner: Uuid, frame: Uuid, name: &str) -> Uuid {
    epigraph_db::PerspectiveRepository::create(
        pool,
        name,
        None,
        Some(owner),
        None,
        &[frame],
        None,
        None,
    )
    .await
    .expect("perspective")
    .id
}

#[allow(clippy::too_many_arguments)]
async fn submit(
    state: &AppState,
    pool: &PgPool,
    caller: Uuid,
    claim: Uuid,
    frame: Uuid,
    perspective: Uuid,
    masses: serde_json::Value,
) {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let request: SubmitEvidenceRequest = serde_json::from_value(serde_json::json!({
        "claim_id": claim,
        "perspective_id": perspective,
        "reliability": 1.0,
        "masses": masses,
    }))
    .expect("request");
    let _created = submit_evidence(
        ViewerExtractor(viewer),
        State(state.clone()),
        Path(frame),
        Json(request),
    )
    .await
    .unwrap_or_else(|e| panic!("submit_evidence failed: {e:?}"));
}

fn support(t: f64) -> serde_json::Value {
    serde_json::json!({"0": t, "0,1": 1.0 - t})
}

/// One stored scoped belief.
#[derive(Debug, sqlx::FromRow)]
struct Stored {
    belief: f64,
    plausibility: f64,
    pignistic_prob: Option<f64>,
    mass_on_empty: f64,
    conflict_k: Option<f64>,
    strategy_used: Option<String>,
}

impl Stored {
    fn same_values(&self, other: &Stored) -> bool {
        (self.belief - other.belief).abs() < EPS
            && (self.plausibility - other.plausibility).abs() < EPS
            && match (self.pignistic_prob, other.pignistic_prob) {
                (Some(a), Some(b)) => (a - b).abs() < EPS,
                _ => false,
            }
            && (self.mass_on_empty - other.mass_on_empty).abs() < EPS
            && match (self.conflict_k, other.conflict_k) {
                (Some(a), Some(b)) => (a - b).abs() < EPS,
                (None, None) => true,
                _ => false,
            }
            && self.strategy_used == other.strategy_used
    }
}

async fn stored(pool: &PgPool, claim: Uuid, frame: Uuid, scope: Option<Uuid>) -> Stored {
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, mass_on_empty, conflict_k, strategy_used \
           FROM ds_combined_beliefs \
          WHERE claim_id = $1 AND frame_id = $2 \
            AND scope_id IS NOT DISTINCT FROM $3 \
            AND scope_type = CASE WHEN $3::uuid IS NULL THEN 'global' ELSE 'perspective' END",
    )
    .bind(claim)
    .bind(frame)
    .bind(scope)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("stored scoped belief for {claim} / {scope:?}: {e}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn stored_scoped_beliefs_never_fold_a_bba_citing_narrowed_evidence(pool: PgPool) {
    let state = state(&pool).await;
    let (member, group) = seed_agent_with_group(&pool, "r22-scoped-member").await;
    let (caller, _) = seed_agent_with_group(&pool, "r22-scoped-caller").await;
    let (author, _) = seed_agent_with_group(&pool, "r22-scoped-author").await;
    let frame = frame(&pool, "r22_scoped_rows").await;
    let p = perspective(&pool, author, frame, "r22 scoped perspective").await;
    let with_hidden = seed_public_claim(&pool, author, "r22 scoped: with a narrowed BBA").await;
    let control = seed_public_claim(&pool, author, "r22 scoped: control").await;

    // A member's BBA under the perspective, citing evidence narrowed to its
    // group (the row stays public with its claim).
    let hidden = seed_evidence(&pool, with_hidden, "document").await;
    // Pinned, as `epigraph-operator hide-evidence` pins it (migration 110):
    // without the pin the next evidence INSERT on the claim re-publishes it.
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden')",
    )
    .bind(hidden)
    .bind(member)
    .execute(&pool)
    .await
    .expect("pin the hidden evidence");
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(hidden)
        .bind(group)
        .execute(&pool)
        .await
        .expect("narrow the evidence");
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        with_hidden,
        frame,
        Some(member),
        Some(p),
        &support(0.8),
        None,
        Some("discount"),
        None,
        None,
        "unknown",
        Some(hidden),
    )
    .await
    .expect("store the narrowed BBA");

    for claim in [with_hidden, control] {
        submit(&state, &pool, caller, claim, frame, p, support(0.6)).await;
    }
    for scope in [None, Some(p)] {
        let (a, b) = (
            stored(&pool, with_hidden, frame, scope).await,
            stored(&pool, control, frame, scope).await,
        );
        assert!(
            a.same_values(&b),
            "the stored {scope:?} scoped belief folded a BBA citing narrowed evidence: \
             {a:?} vs {b:?}"
        );
    }
    // One admissible BBA: not folded, so no step, no strategy (as before).
    let single = stored(&pool, control, frame, Some(p)).await;
    assert_eq!(
        (single.conflict_k, single.strategy_used.as_deref()),
        (None, None),
        "{single:?}"
    );
    assert!(single.mass_on_empty.abs() < EPS, "{single:?}");
}
