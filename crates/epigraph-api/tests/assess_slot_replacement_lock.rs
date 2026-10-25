//! `POST /api/v1/claims/:id/assess` reports the owner's assessment it replaced
//! (`replaced_assessments`) from a read of the slot row. That read and the
//! slot upsert must be ONE serialized unit per slot (backlog 4a7f90f8, part 3).
//!
//! # What was wrong, measured at origin/main before this file
//!
//! `routes/assess.rs::assess_claim` read the slot row with
//! `MassFunctionRepository::get_for_claim_frame(pool, ..)` on the raw pool and
//! only then upserted it with `store_with_perspective(pool, ..)`, with no
//! transaction and no lock between the two. Two concurrent calls by the same
//! owner could both read "no row" before either upsert landed, so BOTH answered
//! `replaced_assessments: []` although the second one overwrote the first. The
//! stored row count stayed correct (the upsert is keyed); the REPORT was wrong.
//!
//! # How the interleave is made deterministic
//!
//! Not a `tokio::join!` race. A side connection X holds an UNCOMMITTED insert
//! of the slot row. Any upsert on that key then blocks until X ends, while a
//! plain read does not see X's row. The test starts both calls, waits until
//! two backends are blocked on a lock (`pg_stat_activity`, with a hard
//! deadline so a hang fails instead of stalling the run), and only then rolls
//! X back.
//!
//! * Unserialized code: both calls have already read "no row" and are blocked
//!   in their upserts. After the rollback one inserts and the other updates,
//!   and both report nothing replaced.
//! * Serialized code: the first call holds the slot lock and is blocked in its
//!   upsert; the second is blocked on the slot lock BEFORE its read. After the
//!   rollback the first inserts and commits, and the second then reads that
//!   row and reports it replaced.
//!
//! The handler runs on the `#[sqlx::test]` superuser pool, as in
//! `assess_canonical_frame.rs`: this pins the read/upsert serialization, not
//! tenancy, so an RLS refusal must not be able to decide the outcome.

#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::routes::assess::{assess_claim, AssessClaimRequest, AssessClaimResponse};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::time::{Duration, Instant};
use uuid::Uuid;
use viewer_fixture::{seed_agent_with_group, seed_public_claim};

fn request_on(frame: Uuid, supports: bool, confidence: f64) -> AssessClaimRequest {
    serde_json::from_value(serde_json::json!({
        "evidence_type": "empirical",
        "methodology": "instrumental",
        "confidence": confidence,
        "supports": supports,
        "frame_id": frame,
    }))
    .expect("AssessClaimRequest deserializes")
}

async fn assess(
    pool: PgPool,
    caller: Uuid,
    claim: Uuid,
    req: AssessClaimRequest,
) -> AssessClaimResponse {
    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    let Json(resp) = assess_claim(
        epigraph_api::middleware::bearer::ViewerExtractor(viewer),
        State(state),
        Path(claim),
        Json(req),
    )
    .await
    .unwrap_or_else(|e| panic!("assess_claim failed: {e:?}"));
    resp
}

/// Backends of this database, other than the caller, blocked on a lock.
async fn lock_waiters(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity \
         WHERE datname = current_database() AND wait_event_type = 'Lock' \
           AND pid <> pg_backend_pid()",
    )
    .fetch_one(pool)
    .await
    .expect("read pg_stat_activity")
}

#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_same_owner_calls_report_exactly_one_replacement(
    pool_opts: PgPoolOptions,
    conn_opts: PgConnectOptions,
) {
    // Room for X, two blocked calls and the poller at once.
    let pool = pool_opts
        .max_connections(12)
        .connect_with(conn_opts)
        .await
        .expect("test pool");
    let (caller, _group) = seed_agent_with_group(&pool, "assess-slot-lock").await;
    let claim = seed_public_claim(&pool, caller, "assess slot lock: concurrent replacement").await;
    let frame = epigraph_db::FrameRepository::create(
        &pool,
        "assess_slot_lock_frame",
        None,
        &["supported".to_string(), "refuted".to_string()],
    )
    .await
    .expect("create frame")
    .id;

    // The caller is bound to no human, so it owns its own slot. The slot's
    // perspective is created COMMITTED up front: an uncommitted one in X would
    // block both calls before their reads, which is not the interleave wanted.
    let owner = Some(caller);
    let slot = epigraph_db::repos::mass_function::assessment_slot_perspective(owner);
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(&pool, slot, owner)
        .await
        .expect("slot perspective");

    // X: an uncommitted slot row on exactly the key both calls upsert.
    let mut x = pool.begin().await.expect("begin X");
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &mut *x,
        claim,
        frame,
        owner,
        Some(slot),
        &serde_json::json!({"0": 0.5, "0,1": 0.5}),
        None,
        Some("discount"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("X holds the slot key");

    let first = tokio::spawn(assess(
        pool.clone(),
        caller,
        claim,
        request_on(frame, true, 0.9),
    ));
    let second = tokio::spawn(assess(
        pool.clone(),
        caller,
        claim,
        request_on(frame, true, 0.8),
    ));

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let waiting = lock_waiters(&pool).await;
        if waiting >= 2 {
            break;
        }
        assert!(
            !first.is_finished() && !second.is_finished(),
            "a call finished while X still held the slot key ({waiting} lock waiters): \
             the upsert did not wait on X"
        );
        assert!(
            Instant::now() < deadline,
            "CALIBRATION: both calls must block on a lock before X ends, saw {waiting}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    x.rollback().await.expect("rollback X");

    let a = tokio::time::timeout(Duration::from_secs(60), first)
        .await
        .expect("first call hung")
        .expect("first call panicked");
    let b = tokio::time::timeout(Duration::from_secs(60), second)
        .await
        .expect("second call hung")
        .expect("second call panicked");

    assert_eq!(
        a.mass_function_id, b.mass_function_id,
        "one owner, one slot row"
    );
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(claim)
    .bind(frame)
    .fetch_one(&pool)
    .await
    .expect("count rows");
    assert_eq!(rows, 1, "the keyed upsert keeps one row either way");

    let reports: Vec<&AssessClaimResponse> = [&a, &b]
        .into_iter()
        .filter(|r| !r.replaced_assessments.is_empty())
        .collect();
    assert_eq!(
        reports.len(),
        1,
        "exactly one of two serialized same-owner calls replaced the other's row; \
         got first={:?} second={:?}",
        a.replaced_assessments,
        b.replaced_assessments
    );
    let replaced = &reports[0].replaced_assessments;
    assert_eq!(replaced.len(), 1, "{replaced:?}");
    assert_eq!(replaced[0].mass_function_id, a.mass_function_id);
    assert_eq!(replaced[0].source_agent_id, owner);
    assert!(
        replaced[0].prior_pignistic_prob.is_some(),
        "the replaced row is the other call's committed assessment: {replaced:?}"
    );
}
