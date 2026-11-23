//! An un-mark (`admin_cascade::apply_unmark`) whose mark's repair bound a
//! frame onto the canonical removes that binding on a NOSUPERUSER
//! `epigraph_maintenance` session, the session the `unmark_duplicate` operator
//! CLI and the request paths run it on (backlog 8ca08222).
//!
//! The reversal's `DELETE FROM claim_frames` needs the DELETE privilege
//! migration 247 grants; without it the whole un-mark fails ("permission
//! denied for table claim_frames") and the duplicate stays marked. Every other
//! un-mark test either runs on the superuser pool (which holds every
//! privilege) or leaves the duplicate unbound so no binding is copied.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::repos::admin_cascade as audit;
use epigraph_db::{ClaimRepository, FrameRepository, MassFunctionRepository, PgPool};
use epigraph_engine::admin_cascade::{
    apply_after_dedup, apply_unmark, CascadeCause, CascadeTrigger,
};
use uuid::Uuid;

/// A pool whose every connection is `epigraph_maintenance`, asserted to be a
/// NOSUPERUSER privileged writer (as in `retracted_bba_cascade.rs`).
async fn maintenance(pool: &PgPool) -> PgPool {
    let m = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let (superuser, privileged): (bool, bool) = sqlx::query_as(
        "SELECT r.rolsuper, public.epigraph_session_is_privileged_writer() \
           FROM pg_roles r WHERE r.rolname = current_user",
    )
    .fetch_one(&m)
    .await
    .expect("read the maintenance session's role");
    assert!(!superuser && privileged, "a NOSUPERUSER privileged session");
    m
}

/// The `claim_frames` binding of `claim` on `frame` (its hypothesis index),
/// read on the superuser pool so row security cannot hide it.
async fn binding(pool: &PgPool, claim: Uuid, frame: Uuid) -> Option<Option<i32>> {
    sqlx::query_scalar(
        "SELECT hypothesis_index FROM claim_frames WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(claim)
    .bind(frame)
    .fetch_optional(pool)
    .await
    .expect("read the binding")
}

async fn is_current(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read is_current")
}

/// Two GROUP-private claims of a group the maintenance login is no member of
/// (so every read and write goes through the maintenance bypass, not a
/// membership). The duplicate is bound to a `binary_truth` frame at index 1
/// (FALSE) and holds a poolable input on it; the canonical is unbound. The
/// mark's repair copies the binding onto the canonical (same owner group, so
/// even the FALSE index is copied), and the un-mark must take it off again:
/// left behind, the canonical would read as FALSE on a frame it holds no
/// input on.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_unbinds_the_copied_frame_on_a_non_superuser_maintenance_login(pool: PgPool) {
    let maint = maintenance(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let (author, g) = fixture::seed_agent_with_group(&pool, "t44-unbind").await;
    let canonical = fixture::seed_group_claim(&pool, author, g, "t44 unbind canonical").await;
    let dup = fixture::seed_group_claim(&pool, author, g, "t44 unbind duplicate").await;
    let f = FrameRepository::create(
        &pool,
        "binary_truth",
        Some("t44-unbind"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;
    FrameRepository::assign_claim(&pool, dup, f, Some(1))
        .await
        .expect("bind the duplicate");
    let input = MassFunctionRepository::store_with_perspective(
        &pool,
        dup,
        f,
        Some(author),
        None,
        &serde_json::json!({"1": 0.6, "0,1": 0.4}),
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("the duplicate's own input");
    assert_eq!(
        binding(&pool, canonical, f).await,
        None,
        "calibration: the canonical starts unbound"
    );

    // The role already holds UPDATE on `claim_frames` (070): migration 247's
    // header rests its "no new reach" argument on that.
    let update: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('epigraph_maintenance', 'public.claim_frames', 'UPDATE')",
    )
    .fetch_one(&pool)
    .await
    .expect("read the role's privilege");
    assert!(
        update,
        "the maintenance role holds UPDATE on claim_frames (070)"
    );

    {
        let mut conn = pool.acquire().await.expect("acquire");
        ClaimRepository::mark_duplicate_act_conn(
            &mut conn,
            ClaimId::from_uuid(dup),
            ClaimId::from_uuid(canonical),
        )
        .await
        .expect("the dedup act");
    }
    let mut conn = maint.acquire().await.expect("acquire maintenance");
    let mark = CascadeTrigger::new(
        CascadeCause::Dedup,
        Some(author),
        None,
        dup,
        Some(canonical),
    );
    let (status, report) =
        apply_after_dedup(&mut conn, &viewer, &viewer, &mark, dup, canonical).await;
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(
        status.audit_event_id.is_some(),
        "calibration: the mark's repair applied on the maintenance login: {status:?}"
    );
    assert_eq!(
        binding(&pool, canonical, f).await,
        Some(Some(1)),
        "calibration: the repair bound the frame onto the canonical, FALSE index included"
    );
    let identity_edge: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND relationship = 'same_as'",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("identity edge");
    let (_, revert) = audit::dedup_revert_record(&pool, dup, identity_edge)
        .await
        .expect("lookup")
        .expect("the revert record is kept");
    assert_eq!(
        revert["copied_frames"],
        serde_json::json!([f]),
        "calibration: the record names the copied binding, so the un-mark must delete it"
    );
    let on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
        .bind(input)
        .fetch_one(&pool)
        .await
        .expect("the input");
    assert_eq!(on, canonical, "calibration: the mark pooled the input");

    let unmark = CascadeTrigger::new(CascadeCause::Undedup, Some(author), None, dup, None);
    let (outcome, report) = apply_unmark(&mut conn, &viewer, &viewer, &unmark, dup, canonical)
        .await
        .expect("the un-mark completes on a non-superuser maintenance login");
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(
        is_current(&pool, dup).await,
        "the duplicate is current again"
    );
    assert_eq!(
        binding(&pool, canonical, f).await,
        None,
        "the binding the repair added is gone from the canonical"
    );
    assert_eq!(
        binding(&pool, dup, f).await,
        Some(Some(1)),
        "the duplicate keeps its own binding"
    );
    let touched = outcome
        .cascade
        .touched
        .clone()
        .expect("the un-mark's counts");
    assert_eq!(
        (&touched["frames_unbound"], &touched["drifted"]),
        (&serde_json::json!(1), &serde_json::json!(0)),
        "the binding was deleted, not skipped as drift: {touched}"
    );
    let back: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
        .bind(input)
        .fetch_one(&pool)
        .await
        .expect("the input");
    assert_eq!(back, dup, "the input is back on the duplicate");
}

/// `docs/runbooks/247-undo.sql` takes the grant back, and runs twice
/// (idempotent), so an operator can roll 247 out without hand-written SQL.
#[sqlx::test(migrations = "../../migrations")]
async fn the_247_undo_runbook_revokes_the_grant_idempotently(pool: PgPool) {
    use sqlx::Executor;
    let held = |pool: PgPool| async move {
        sqlx::query_scalar::<_, bool>(
            "SELECT has_table_privilege('epigraph_maintenance', 'public.claim_frames', 'DELETE')",
        )
        .fetch_one(&pool)
        .await
        .expect("read the privilege")
    };
    assert!(held(pool.clone()).await, "calibration: 247 granted DELETE");
    let undo = include_str!("../../../docs/runbooks/247-undo.sql");
    for run in 1..=2 {
        pool.execute(undo)
            .await
            .unwrap_or_else(|e| panic!("undo run {run}: {e}"));
    }
    assert!(!held(pool.clone()).await, "the undo revoked DELETE");
}
