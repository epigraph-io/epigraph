//! SPEC §11 phase 1, K4a, at the administrative cascades: a RETRACTED mass
//! function (migration 184, rulings R-79 / R-103) survives the supersede
//! cascade's invalidate-and-rewire and the un-mark's reversal, and each
//! cascade completes and says what it kept.
//!
//! Every cascade runs on a NOSUPERUSER `epigraph_maintenance` session (SPEC
//! §12), the session the request paths and the replay timer use; every
//! retracted row is made by migration 184's definer on the application role.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/retracted_bba_fixture.rs"]
mod retracted;

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, FrameRepository, MassFunctionRepository, PgPool};
use epigraph_engine::admin_cascade::{
    apply_after_dedup, apply_after_supersede, apply_unmark, CascadeCause, CascadeTrigger,
};
use retracted::{retract_through_definer, row_state};
use uuid::Uuid;

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

async fn claim(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("k4a cascade fixture {tag} {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("seed edge");
    sqlx::query(
        "INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, 'edge_factor', 'edge')",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed the edge's perspective");
    id
}

#[allow(clippy::too_many_arguments)]
async fn bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Option<Uuid>,
    perspective: Option<Uuid>,
    method: Option<&str>,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        agent,
        perspective,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        method,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA")
}

/// Sites 1 and 8: the supersede cascade over three edges re-pointed onto the
/// replacement, on the privileged maintenance session:
///
/// * `e1` holds ONLY a retracted edge BBA: it is kept, nothing is re-wired;
/// * `e2` holds a retracted edge BBA AND another agent's live one: the live
///   one is invalidated, the retracted one is kept, and the re-wire is
///   skipped (the retracted row holds the edge; R-103), without an error;
/// * `e3` (control) holds a live one: invalidated as before.
///
/// The cascade completes with no error and both its report and its belief
/// audit row count the two retracted keys it kept.
#[sqlx::test(migrations = "../../migrations")]
async fn the_supersede_cascade_keeps_retracted_edge_bbas_and_counts_them(pool: PgPool) {
    let maint = maintenance(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let (author, g) = fixture::seed_agent_with_group(&pool, "k4a-s8-author").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "k4a-s8-other").await;
    let a = claim(&pool, author, g, "s8 supporter").await;
    let b = claim(&pool, author, g, "s8 downstream b").await;
    let c = claim(&pool, author, g, "s8 downstream c").await;
    let bf = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_engine::edge_factor::ensure_binary_frame(&mut conn, &viewer)
            .await
            .expect("binary frame")
    };
    let e1 = edge(&pool, a, b, "supports").await;
    // `corroborates`, not a weakening relationship: weakening edges stay on
    // the retired claim (`WEAKENING_RELATIONSHIPS`), so only a supporting
    // one is re-pointed and walked.
    let e2 = edge(&pool, a, b, "corroborates").await;
    let e3 = edge(&pool, a, c, "supports").await;
    let r1 = bba(&pool, b, bf, Some(author), Some(e1), Some("edge_factor")).await;
    let r2 = bba(&pool, b, bf, Some(author), Some(e2), Some("edge_factor")).await;
    let l2 = bba(&pool, b, bf, Some(other), Some(e2), Some("edge_factor")).await;
    let l3 = bba(&pool, c, bf, Some(author), Some(e3), Some("edge_factor")).await;
    retract_through_definer(&pool, r1).await;
    retract_through_definer(&pool, r2).await;

    let (new_id, old_id) = {
        let mut tx = pool.begin().await.expect("begin");
        let ids = ClaimRepository::supersede_act_conn(
            &mut tx,
            ClaimId::from_uuid(a),
            "k4a s8 replacement",
            epigraph_core::TruthValue::clamped(0.5),
            "k4a cascade fixture",
            epigraph_db::SupersedeActor::new(author, epigraph_db::SupersedeTool::SupersedeClaim),
        )
        .await
        .expect("the supersede act");
        tx.commit().await.expect("commit the act");
        ids
    };
    let trigger = CascadeTrigger::new(
        CascadeCause::Supersede,
        Some(author),
        None,
        old_id,
        Some(new_id),
    );
    let mut conn = maint.acquire().await.expect("acquire maintenance");
    let (status, report) =
        apply_after_supersede(&mut conn, &viewer, &viewer, &trigger, old_id, new_id).await;

    assert_eq!(
        row_state(&pool, r1).await,
        Some((b, true)),
        "a retracted edge BBA on an invalidated edge is kept for audit"
    );
    assert_eq!(
        row_state(&pool, r2).await,
        Some((b, true)),
        "a retracted edge BBA beside a live one is kept for audit"
    );
    assert!(
        report.errors.is_empty(),
        "the cascade completes: no RT07, no re-wire refused by the retracted holder; {:?}",
        report.errors
    );
    assert_eq!(
        row_state(&pool, l2).await,
        None,
        "the live BBA beside the retracted one is invalidated"
    );
    assert_eq!(
        row_state(&pool, l3).await,
        None,
        "calibration: a live edge BBA is invalidated"
    );
    assert_eq!(report.invalidated_bbas, 2, "{report:?}");
    assert_eq!(
        report.retracted_key_kept, 2,
        "both retracted keys are counted: {report:?}"
    );
    let belief_row = status
        .belief_audit_event_id
        .expect("the belief audit row of the applied cascade");
    let counted: serde_json::Value =
        sqlx::query_scalar("SELECT details->'belief' FROM security_events WHERE id = $1")
            .bind(belief_row)
            .fetch_one(&pool)
            .await
            .expect("the belief audit row");
    assert_eq!(
        counted["retracted_key_kept"], 2,
        "the audit row counts the kept retracted keys: {counted}"
    );
}

/// Site 3: an un-mark whose returning input's slot on the duplicate is now
/// held by a RETRACTED cached combination keeps that row (it is not the
/// derived cache the clear exists to make room past), reports the input as
/// drifted, and leaves it where the mark put it. The un-mark completes.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_over_a_retracted_key_keeps_it_and_reports_drift(pool: PgPool) {
    let maint = maintenance(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let (author, g) = fixture::seed_agent_with_group(&pool, "k4a-s3").await;
    let canonical = claim(&pool, author, g, "s3 canonical").await;
    let dup = claim(&pool, author, g, "s3 duplicate").await;
    let f = FrameRepository::create(
        &pool,
        "binary_truth",
        Some("k4a-s3"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;
    // The duplicate is NOT bound to the frame, so the repair binds none onto
    // the canonical and the un-mark has no frame binding to remove: the
    // maintenance role holds no DELETE on `claim_frames` (migration 158), which
    // is outside what this test measures.
    let input = bba(&pool, dup, f, None, None, None).await;

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
    let (status, _) = apply_after_dedup(&mut conn, &viewer, &viewer, &mark, dup, canonical).await;
    assert!(
        status.audit_event_id.is_some(),
        "calibration: the mark's repair applied: {status:?}"
    );
    assert_eq!(
        row_state(&pool, input).await,
        Some((canonical, false)),
        "calibration: the mark pooled the duplicate's input onto the canonical"
    );

    // The input's slot on the duplicate now holds a cached combination, which
    // a writer of the claim's group then retracted.
    let cached = bba(&pool, dup, f, None, None, Some("Dempster")).await;
    retract_through_definer(&pool, cached).await;

    let unmark = CascadeTrigger::new(CascadeCause::Undedup, Some(author), None, dup, None);
    let (outcome, report) = apply_unmark(&mut conn, &viewer, &viewer, &unmark, dup, canonical)
        .await
        .expect("the un-mark completes");
    assert_eq!(
        row_state(&pool, cached).await,
        Some((dup, true)),
        "the retracted row holding the slot is kept for audit"
    );
    assert_eq!(
        row_state(&pool, input).await,
        Some((canonical, false)),
        "the input whose slot a retracted row holds does not return"
    );
    let touched = outcome
        .cascade
        .touched
        .clone()
        .expect("the un-mark's counts");
    assert_eq!(
        (&touched["cached_rows_cleared"], &touched["bbas_returned"]),
        (&serde_json::json!(0), &serde_json::json!(0)),
        "nothing retracted is cleared and the blocked input does not return: {touched}"
    );
    assert!(
        touched["drifted"].as_u64().unwrap_or(0) >= 1,
        "the blocked input is reported drifted: {touched}"
    );
    assert!(report.errors.is_empty(), "{:?}", report.errors);
}
