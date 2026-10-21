//! The administrative un-mark (`admin_cascade::apply_unmark`): the dedup's
//! repair is reversed from the revert record its APPLIED audit row kept, in one
//! transaction with the un-mark's act, and both claims' belief is re-derived.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::repos::admin_cascade as audit;
use epigraph_db::{ClaimRepository, FrameRepository, MassFunctionRepository, PgPool};
use epigraph_engine::admin_cascade::{
    apply_after_dedup, apply_unmark, record_deferral, CascadeCause, CascadeTrigger, UnmarkRefusal,
};
use epigraph_engine::edge_factor::preview_claim_belief_on_frame;
use uuid::Uuid;

async fn new_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("agent")
}

async fn new_claim(pool: &PgPool, agent: Uuid, tag: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(format!("unmark cascade {tag} {}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("claim")
}

async fn frame(pool: &PgPool) -> Uuid {
    FrameRepository::create(
        pool,
        "binary_truth",
        None,
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id
}

async fn store(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Option<Uuid>,
    persp: Option<Uuid>,
    m: serde_json::Value,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        agent,
        persp,
        &m,
        None,
        None,
        None,
        Some("empirical"),
        "unknown",
        None,
    )
    .await
    .expect("store bba")
}

async fn current(pool: &PgPool, id: Uuid) -> (Option<Uuid>, bool) {
    sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("claim row")
}

fn trigger(cause: CascadeCause, agent: Uuid, dup: Uuid, canonical: Option<Uuid>) -> CascadeTrigger {
    CascadeTrigger::new(cause, Some(agent), None, dup, canonical)
}

/// Mark through the act and the administrative cascade (as the MCP tool and
/// the HTTP route do with a maintenance connection), then un-mark: the
/// duplicate's BBAs are back on it, its belief is re-derived from them, the
/// applied `undedup` row names the reversed dedup row, and nothing the caller
/// receives spells another writer's row id.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_reverses_the_recorded_repair_and_rederives_the_duplicate(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let f = frame(&pool).await;
    let (author, other) = (new_agent(&pool).await, new_agent(&pool).await);
    let canonical = new_claim(&pool, author, "canonical").await;
    let dup = new_claim(&pool, author, "duplicate").await;
    let supporter = new_claim(&pool, other, "supporter").await;
    FrameRepository::assign_claim(&pool, dup, f, Some(0))
        .await
        .expect("bind");
    let e: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(supporter)
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("edge");
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, 'edge')")
        .bind(e)
        .execute(&pool)
        .await
        .expect("perspective");
    let other_writers_bba = store(
        &pool,
        dup,
        f,
        Some(other),
        Some(e),
        serde_json::json!({"0": 0.7, "0,1": 0.3}),
    )
    .await;
    let own = store(
        &pool,
        dup,
        f,
        Some(author),
        None,
        serde_json::json!({"1": 0.4, "0,1": 0.6}),
    )
    .await;

    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("act");
    let t = trigger(CascadeCause::Dedup, author, dup, Some(canonical));
    let (status, _) = apply_after_dedup(&mut conn, &viewer, &viewer, &t, dup, canonical).await;
    let dedup_row = status.audit_event_id.expect("applied dedup row");
    let identity_edge: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND relationship = 'same_as'",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("identity edge");
    let (rec_applied, revert) = audit::dedup_revert_record(&mut *conn, dup, identity_edge)
        .await
        .expect("lookup")
        .expect("the revert record is kept");
    assert_eq!(
        rec_applied, dedup_row,
        "the record names the applied row it belongs to"
    );
    assert!(revert.get("moved_bbas").is_some(), "{revert}");

    // The record names other writers' rows, so the TRIGGERING principal, which
    // `security_events_read` lets read the applied row it is named on, must
    // not be able to read the record. Calibrated on the applied row itself.
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let (applied_visible, record_rows) =
        fixture::as_role(&pool, "epigraph_app", |mut c| async move {
            sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
                .bind(author.to_string())
                .execute(&mut *c)
                .await
                .expect("stamp principal");
            let applied: i64 =
                sqlx::query_scalar("SELECT count(*) FROM security_events WHERE id = $1")
                    .bind(dedup_row)
                    .fetch_one(&mut *c)
                    .await
                    .expect("read applied row");
            let records: i64 =
                sqlx::query_scalar("SELECT count(*) FROM security_events WHERE details ? 'revert'")
                    .fetch_one(&mut *c)
                    .await
                    .expect("read records");
            (c, (applied, records))
        })
        .await;
    assert_eq!(
        applied_visible, 1,
        "calibration: the triggering agent reads its applied row"
    );
    assert_eq!(
        record_rows, 0,
        "the triggering agent cannot read any revert record"
    );
    let caller_copy = serde_json::to_string(&status).expect("status");
    assert!(
        !caller_copy.contains(&other_writers_bba.to_string())
            && !caller_copy.contains(&e.to_string()),
        "the caller's copy of the dedup cascade carries counts only: {caller_copy}"
    );
    for id in [other_writers_bba, own] {
        let on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("bba");
        assert_eq!(on, canonical, "calibration: the mark moved {id}");
    }

    let ut = trigger(CascadeCause::Undedup, author, dup, None);
    let (outcome, report) = apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, canonical)
        .await
        .expect("unmark");
    assert_eq!(outcome.canonical_id, canonical);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(current(&pool, dup).await, (None, true));
    for id in [other_writers_bba, own] {
        let on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("bba");
        assert_eq!(on, dup, "{id} is back on the duplicate");
    }
    let expected = preview_claim_belief_on_frame(&mut conn, &viewer, dup, f)
        .await
        .expect("preview")
        .expect("dup has BBAs");
    let cached: Option<f64> = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(dup)
        .fetch_one(&pool)
        .await
        .expect("dup");
    assert!(
        (cached.expect("re-derived") - expected.pignistic_prob).abs() < 1e-9,
        "the duplicate's belief is re-derived from its returned BBAs"
    );
    let undedup: serde_json::Value =
        sqlx::query_scalar("SELECT details FROM security_events WHERE id = $1")
            .bind(outcome.cascade.audit_event_id.expect("undedup row"))
            .fetch_one(&pool)
            .await
            .expect("undedup row");
    assert_eq!(undedup["cause"], "undedup");
    assert_eq!(undedup["reversed_event_id"], serde_json::json!(dedup_row));
    let caller_copy = serde_json::to_string(&outcome).expect("outcome");
    assert!(
        !caller_copy.contains(&other_writers_bba.to_string())
            && !caller_copy.contains(&e.to_string()),
        "the caller's copy of the un-mark carries counts only: {caller_copy}"
    );
}

/// The mark's cascade never ran (deferred, as on a request path without the
/// maintenance connection): the un-mark puts the duplicate back and RETIRES
/// the pending cascade, so the replay does not later try to repair a claim
/// that is no longer a duplicate.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_of_a_deferred_mark_retires_its_pending_cascade(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let author = new_agent(&pool).await;
    let canonical = new_claim(&pool, author, "canonical").await;
    let dup = new_claim(&pool, author, "duplicate").await;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("act");
    let t = trigger(CascadeCause::Dedup, author, dup, Some(canonical));
    record_deferral(&mut *conn, &t, "test: no maintenance connection")
        .await
        .expect("deferral");
    assert_eq!(
        audit::open_dedup_cascades(&mut *conn, dup)
            .await
            .expect("open")
            .len(),
        1
    );

    let ut = trigger(CascadeCause::Undedup, author, dup, None);
    apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, canonical)
        .await
        .expect("unmark of a deferred mark");
    assert_eq!(current(&pool, dup).await, (None, true));
    assert!(
        audit::open_dedup_cascades(&mut *conn, dup)
            .await
            .expect("open")
            .is_empty(),
        "the pending cascade is retired"
    );
}

/// A mark with neither an applied repair record nor an open cascade (the
/// repository path, which writes no audit row) cannot be reversed exactly: the
/// un-mark is refused and the duplicate stays marked.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_without_a_record_is_refused_and_changes_nothing(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let author = new_agent(&pool).await;
    let canonical = new_claim(&pool, author, "canonical").await;
    let dup = new_claim(&pool, author, "duplicate").await;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_with_repair_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("repository mark, no audit row");
    let ut = trigger(CascadeCause::Undedup, author, dup, None);
    let err = apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, canonical)
        .await
        .expect_err("no record");
    assert_eq!(err, UnmarkRefusal::NoRecord);
    assert_eq!(
        current(&pool, dup).await,
        (Some(canonical), false),
        "nothing changed"
    );
    let edge_in_force: bool = sqlx::query_scalar(
        "SELECT valid_to IS NULL FROM edges WHERE source_id = $1 AND relationship = 'same_as'",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("identity edge");
    assert!(edge_in_force, "the identity edge is untouched");
}

/// The caller's authority was checked against the canonical it read. If the
/// duplicate has since been re-marked onto ANOTHER canonical, the un-mark must
/// refuse rather than reverse a mark the caller was never checked against.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_refuses_when_the_mark_is_not_the_one_authorized(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let author = new_agent(&pool).await;
    let checked = new_claim(
        &pool,
        author,
        "the canonical the caller was checked against",
    )
    .await;
    let other = new_claim(&pool, author, "the canonical it is marked onto now").await;
    let dup = new_claim(&pool, author, "duplicate").await;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(other),
    )
    .await
    .expect("act");
    let t = trigger(CascadeCause::Dedup, author, dup, Some(other));
    apply_after_dedup(&mut conn, &viewer, &viewer, &t, dup, other).await;

    let ut = trigger(CascadeCause::Undedup, author, dup, Some(checked));
    let err = apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, checked)
        .await
        .expect_err("a different mark");
    assert!(matches!(err, UnmarkRefusal::Act(_)), "{err:?}");
    assert_eq!(
        current(&pool, dup).await,
        (Some(other), false),
        "nothing changed"
    );
}

/// Two records for one identity edge (a stale replay that re-ran the repair
/// after the first one had already moved everything, and so recorded nothing):
/// the un-mark reverses from the FIRST record, which did the work.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_uses_the_first_record_of_its_identity_edge(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let f = frame(&pool).await;
    let author = new_agent(&pool).await;
    let canonical = new_claim(&pool, author, "canonical").await;
    let dup = new_claim(&pool, author, "duplicate").await;
    let own = store(
        &pool,
        dup,
        f,
        Some(author),
        None,
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("act");
    let t = trigger(CascadeCause::Dedup, author, dup, Some(canonical));
    let (status, _) = apply_after_dedup(&mut conn, &viewer, &viewer, &t, dup, canonical).await;
    let identity_edge: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND relationship = 'same_as'",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("identity edge");
    // The stale second repair found nothing left to move.
    audit::record_dedup_revert(
        &mut *conn,
        status.audit_event_id.expect("applied"),
        dup,
        &serde_json::json!({"identity_edge": identity_edge}),
    )
    .await
    .expect("second, empty record");

    let ut = trigger(CascadeCause::Undedup, author, dup, Some(canonical));
    apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, canonical)
        .await
        .expect("unmark");
    let on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
        .bind(own)
        .fetch_one(&pool)
        .await
        .expect("bba");
    assert_eq!(
        on, dup,
        "the pooled BBA came back: the first record was used"
    );
}
