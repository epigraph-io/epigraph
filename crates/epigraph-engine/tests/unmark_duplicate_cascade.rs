//! The administrative un-mark (`admin_cascade::apply_unmark`): the dedup's
//! repair is reversed from the revert record its APPLIED audit row kept, in one
//! transaction with the un-mark's act, and both claims' belief is re-derived.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::repos::admin_cascade as audit;
use epigraph_db::{ClaimRepository, FrameRepository, MassFunctionRepository, PgPool};
use epigraph_engine::admin_cascade::{
    apply_after_dedup, apply_unmark, apply_unmark_authorized, record_deferral, CascadeCause,
    CascadeTrigger, UnmarkRefusal,
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
            // No row it can read carries a revert record or names the other
            // writer's BBA (which only the record does).
            let records: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM security_events WHERE details ? 'revert' \
                    OR details::text LIKE '%' || $1 || '%'",
            )
            .bind(other_writers_bba.to_string())
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

/// A duplicate the legacy raw-SQL `fuzzy_dedup_claims` marked gets its
/// identity edge from the operator backfill (backlog d5781a48), and from then on
/// it is an ordinary dedup record (operator ruling R-7): the un-mark makes it
/// current again and retracts the backfilled edge. The legacy script kept no
/// repair record, so there is nothing to put back; the audit row and the
/// caller's copy say so (`legacy_mark`), rather than reading as a reversal.
#[sqlx::test(migrations = "../../migrations")]
async fn a_backfilled_legacy_mark_is_unmarked_as_an_ordinary_record(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let author = new_agent(&pool).await;
    let canonical = new_claim(&pool, author, "legacy canonical").await;
    let dup = new_claim(&pool, author, "legacy duplicate").await;
    sqlx::query(
        "UPDATE claims SET supersedes = $1, is_current = false, embedding = NULL, \
                           embedding_3072 = NULL, \
                           labels = COALESCE(labels, ARRAY[]::text[]) \
                                    || ARRAY['r18-kept', 'deduped'], \
                           properties = COALESCE(properties, '{}'::jsonb) \
                             || jsonb_build_object('deduped_into', $1::text, \
                                                   'deduped_by', 'fuzzy_dedup_claims', \
                                                   'deduped_at', now()::text, \
                                                   'r18_kept', true) \
          WHERE id = $2",
    )
    .bind(canonical)
    .bind(dup)
    .execute(&pool)
    .await
    .expect("legacy raw-SQL mark");
    let mut conn = pool.acquire().await.expect("acquire");
    let backfilled = ClaimRepository::backfill_legacy_dedup_identity_edges_conn(&mut conn, true)
        .await
        .expect("backfill");
    assert_eq!(backfilled.inserted, 1, "calibration: {backfilled:?}");
    let edge = backfilled.duplicates[0].identity_edge.expect("edge");

    let ut = trigger(CascadeCause::Undedup, author, dup, None);
    let (outcome, report) = apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, canonical)
        .await
        .expect("a backfilled legacy mark is un-markable");
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(outcome.canonical_id, canonical);
    assert_eq!(current(&pool, dup).await, (None, true), "current again");
    let edge_in_force: bool =
        sqlx::query_scalar("SELECT valid_to IS NULL FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&pool)
            .await
            .expect("identity edge");
    assert!(!edge_in_force, "the backfilled identity edge is retracted");

    let caller_copy = serde_json::to_value(&outcome).expect("outcome");
    assert_eq!(
        caller_copy["cascade"]["touched"]["legacy_mark"],
        serde_json::json!(true),
        "the caller is told this was a legacy mark with nothing to restore: {caller_copy}"
    );
    let undedup: serde_json::Value =
        sqlx::query_scalar("SELECT details FROM security_events WHERE id = $1")
            .bind(outcome.cascade.audit_event_id.expect("undedup row"))
            .fetch_one(&pool)
            .await
            .expect("undedup row");
    assert_eq!(undedup["outcome"], "applied", "{undedup}");
    assert_eq!(
        undedup["identity_edge"],
        serde_json::json!(edge),
        "{undedup}"
    );
    assert_eq!(undedup["legacy_mark"], serde_json::json!(true), "{undedup}");
    assert_eq!(
        undedup["reversed_event_id"],
        serde_json::Value::Null,
        "{undedup}"
    );

    // Operator ruling R-18 (backlog 0e013aa8): the restored claim no longer
    // carries what the legacy script wrote to say it was deduplicated: its
    // `deduped` label and `deduped_*` properties go, and the audit row records
    // what was stripped. Its other labels and properties stay.
    let (labels, properties): (Vec<String>, serde_json::Value) = sqlx::query_as(
        "SELECT COALESCE(labels, ARRAY[]::text[]), properties FROM claims WHERE id = $1",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("the restored claim");
    assert!(
        !labels.iter().any(|l| l == "deduped"),
        "the stale 'deduped' label is stripped: {labels:?}"
    );
    assert!(
        labels.iter().any(|l| l == "r18-kept"),
        "CALIBRATION: other labels stay: {labels:?}"
    );
    let left: Vec<&String> = properties
        .as_object()
        .map(|o| o.keys().filter(|k| k.starts_with("deduped_")).collect())
        .unwrap_or_default();
    assert!(
        left.is_empty(),
        "the stale deduped_* properties are stripped: {properties}"
    );
    assert_eq!(
        properties["r18_kept"],
        serde_json::json!(true),
        "CALIBRATION: other properties stay: {properties}"
    );
    let stripped = &undedup["legacy_stripped"];
    assert_eq!(
        stripped["labels"],
        serde_json::json!(["deduped"]),
        "the audit row names the stripped label: {undedup}"
    );
    assert_eq!(
        stripped["properties"]["deduped_into"],
        serde_json::json!(canonical.to_string()),
        "the audit row keeps the stripped properties' values: {undedup}"
    );
    assert_eq!(
        stripped["properties"]["deduped_by"],
        serde_json::json!("fuzzy_dedup_claims"),
        "{undedup}"
    );
    assert!(
        stripped["properties"]["deduped_at"].is_string(),
        "{undedup}"
    );
}

/// The legacy exemption keys on the identity EDGE the backfill wrote (its
/// reserved `properties.dedup`), never on the claim's own, application-patchable
/// `deduped_by`: a repository-path mark (no audit row, no record) whose claim
/// merely CARRIES the legacy marker is still refused as `NoRecord`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_marker_on_the_claim_alone_does_not_make_a_mark_unmarkable(pool: PgPool) {
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
    sqlx::query(
        "UPDATE claims SET labels = array_append(COALESCE(labels, ARRAY[]::text[]), 'deduped'), \
                           properties = COALESCE(properties, '{}'::jsonb) \
                             || jsonb_build_object('deduped_into', $1::text, \
                                                   'deduped_by', 'fuzzy_dedup_claims') \
          WHERE id = $2",
    )
    .bind(canonical)
    .bind(dup)
    .execute(&pool)
    .await
    .expect("forge the legacy marker on the claim");
    let ut = trigger(CascadeCause::Undedup, author, dup, None);
    let err = apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, canonical)
        .await
        .expect_err("no record");
    assert_eq!(err, UnmarkRefusal::NoRecord);
    assert_eq!(current(&pool, dup).await, (Some(canonical), false));
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

async fn betp(pool: &PgPool, id: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("claim")
}

async fn binary_frame(pool: &PgPool, viewer: &epigraph_db::visibility::Viewer) -> Uuid {
    epigraph_engine::edge_factor::ensure_binary_frame(
        &mut pool.acquire().await.expect("acquire"),
        viewer,
    )
    .await
    .expect("binary frame")
}

/// After an un-mark: the canonical's belief is re-derived without the rows it
/// gave back, the duplicate's from them, and an edge re-sourced back onto the
/// duplicate has its far-end BBA re-wired from the duplicate. The caller's copy
/// of the belief report names only claims the caller can read: the far end is
/// private to another group, and a public caller's report omits it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_rederives_both_claims_and_the_far_end_and_filters_the_report(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let caller = fixture::public_viewer(&pool).await;
    let f = binary_frame(&pool, &viewer).await;
    let (author, other) = (new_agent(&pool).await, new_agent(&pool).await);
    let (x, h) = fixture::seed_agent_with_group(&pool, "far-end owner").await;
    let canonical = new_claim(&pool, author, "canonical").await;
    let dup = new_claim(&pool, author, "duplicate").await;
    let far = fixture::seed_group_claim(&pool, x, h, "a private far end").await;
    for c in [canonical, dup, far] {
        FrameRepository::assign_claim(&pool, c, f, Some(0))
            .await
            .expect("bind");
    }
    store(
        &pool,
        canonical,
        f,
        Some(other),
        None,
        serde_json::json!({"0": 0.3, "0,1": 0.7}),
    )
    .await;
    store(
        &pool,
        dup,
        f,
        Some(author),
        None,
        serde_json::json!({"0": 0.8, "0,1": 0.2}),
    )
    .await;
    let e: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(dup)
    .bind(far)
    .fetch_one(&pool)
    .await
    .expect("edge");
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, 'edge')")
        .bind(e)
        .execute(&pool)
        .await
        .expect("perspective");
    let far_bba = store(
        &pool,
        far,
        f,
        Some(author),
        Some(e),
        serde_json::json!({"0": 0.5, "0,1": 0.5}),
    )
    .await;
    let far_edge_bba = |pool: PgPool| async move {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM mass_functions WHERE claim_id = $1 AND perspective_id = $2",
        )
        .bind(far)
        .bind(e)
        .fetch_optional(&pool)
        .await
        .expect("far bba")
    };

    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("act");
    let t = trigger(CascadeCause::Dedup, author, dup, Some(canonical));
    apply_after_dedup(&mut conn, &viewer, &viewer, &t, dup, canonical).await;
    let after_mark = far_edge_bba(pool.clone()).await;
    assert_ne!(
        after_mark,
        Some(far_bba),
        "calibration: the mark re-wired the far end"
    );

    let ut = trigger(CascadeCause::Undedup, author, dup, Some(canonical));
    let (_, report) = apply_unmark(&mut conn, &viewer, &caller, &ut, dup, canonical)
        .await
        .expect("unmark");
    for (what, id) in [("canonical", canonical), ("duplicate", dup)] {
        let expected = preview_claim_belief_on_frame(&mut conn, &viewer, id, f)
            .await
            .expect("preview")
            .expect("has BBAs")
            .pignistic_prob;
        let got = betp(&pool, id).await.expect("cached");
        assert!(
            (got - expected).abs() < 1e-9,
            "{what}: cached {got} vs preview {expected}"
        );
    }
    let after_unmark = far_edge_bba(pool.clone()).await;
    assert!(
        after_unmark.is_some(),
        "the far end's edge factor is re-wired"
    );
    assert_ne!(after_unmark, after_mark, "re-derived from the duplicate");
    assert!(
        !report.targets.contains(&far) && !report.recomputed.contains(&far),
        "a public caller's report omits the private far end: {report:?}"
    );
}

/// The un-mark is atomic: when the reversal fails after the act ran (here a
/// record that does not parse), nothing commits: the duplicate is still
/// marked, its identity edge in force, and no `undedup` row exists.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_that_fails_after_the_act_changes_nothing(pool: PgPool) {
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
    let identity_edge: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND relationship = 'same_as'",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("identity edge");
    sqlx::query(
        "INSERT INTO security_events (id, event_type, agent_id, success, details) \
         VALUES (gen_random_uuid(), 'cascade.dedup_revert_record', NULL, true, \
                 jsonb_build_object('cause', 'dedup', 'applied_event_id', gen_random_uuid(), \
                                    'subject_id', $1::text, 'identity_edge', $2::text, \
                                    'revert', jsonb_build_object('moved_bbas', 'not a list')))",
    )
    .bind(dup)
    .bind(identity_edge)
    .execute(&pool)
    .await
    .expect("a record that does not parse");

    let ut = trigger(CascadeCause::Undedup, author, dup, Some(canonical));
    let err = apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, canonical)
        .await
        .expect_err("the reversal fails");
    assert!(matches!(err, UnmarkRefusal::Failed(_)), "{err:?}");
    assert_eq!(
        current(&pool, dup).await,
        (Some(canonical), false),
        "the act rolled back"
    );
    let in_force: bool = sqlx::query_scalar("SELECT valid_to IS NULL FROM edges WHERE id = $1")
        .bind(identity_edge)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert!(in_force, "the identity edge is still in force");
    let undedup_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE details->>'cause' = 'undedup'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(undedup_rows, 0);
}

/// After the mark, a belief write on the retired duplicate (the evidence and
/// assess routes store their fold as a cached combination row) puts a cached
/// row in the (frame, no agent, no perspective) slot. The pooled assess row
/// returning to that slot clears that derived row, which the cascade
/// re-derives.
#[sqlx::test(migrations = "../../migrations")]
async fn a_returning_input_clears_the_duplicates_cached_row_from_its_slot(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let f = binary_frame(&pool, &viewer).await;
    let author = new_agent(&pool).await;
    let canonical = new_claim(&pool, author, "canonical").await;
    let dup = new_claim(&pool, author, "duplicate").await;
    for c in [canonical, dup] {
        FrameRepository::assign_claim(&pool, c, f, Some(0))
            .await
            .expect("bind");
    }
    store(
        &pool,
        canonical,
        f,
        Some(author),
        None,
        serde_json::json!({"0": 0.3, "0,1": 0.7}),
    )
    .await;
    // Kept on the duplicate: the canonical already holds the author's key.
    store(
        &pool,
        dup,
        f,
        Some(author),
        None,
        serde_json::json!({"0": 0.9, "0,1": 0.1}),
    )
    .await;
    let assess = epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        dup,
        f,
        None,
        None,
        &serde_json::json!({"1": 0.2, "0,1": 0.8}),
        None,
        Some("discount"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("assess row");
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_act_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("act");
    let t = trigger(CascadeCause::Dedup, author, dup, Some(canonical));
    apply_after_dedup(&mut conn, &viewer, &viewer, &t, dup, canonical).await;
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        dup,
        f,
        None,
        None,
        &serde_json::json!({"0": 0.9, "0,1": 0.1}),
        None,
        Some("Dempster"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("a later belief write's cached fold in the slot");

    let ut = trigger(CascadeCause::Undedup, author, dup, Some(canonical));
    let (outcome, _) = apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, canonical)
        .await
        .expect("unmark");
    assert_eq!(
        outcome
            .cascade
            .touched
            .as_ref()
            .map(|t| t["cached_rows_cleared"].clone()),
        Some(serde_json::json!(1)),
        "{:?}",
        outcome.cascade
    );
    let on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
        .bind(assess)
        .fetch_one(&pool)
        .await
        .expect("assess");
    assert_eq!(on, dup, "the assess row is back in its slot");
}

/// How a canonical is retired after the mark, for
/// [`an_unmark_follows_the_canonicals_replacement`].
#[derive(Clone, Copy, Debug)]
enum Retire {
    Supersede,
    Consolidate,
}

/// Un-marking a duplicate whose canonical was later SUPERSEDED or CONSOLIDATED
/// follows the chain to the current canonical and restores the duplicate
/// against it (operator ruling R-11; before it, the un-mark refused while the
/// canonical was retired). The rows the mark moved have since gone two ways:
/// the supersession / merge carried the dup's `supports` edge on to the
/// replacement, and left its claim-level BBA on the retired canonical. Both
/// come back and nothing is reported drifted.
async fn an_unmark_follows_the_canonicals_replacement(pool: PgPool, how: Retire) {
    let f = frame(&pool).await;
    {
        let (_scoped, viewer) = fixture::bypass(&pool).await;
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
        assert!(
            status.audit_event_id.is_some(),
            "{how:?}: applied dedup row"
        );

        let replacement = match how {
            Retire::Supersede => {
                let (replacement, _) = ClaimRepository::supersede_act_conn(
                    &mut conn,
                    ClaimId::from_uuid(canonical),
                    &format!("canonical, revised {}", Uuid::new_v4()),
                    epigraph_core::TruthValue::clamped(0.5),
                    "revision",
                )
                .await
                .expect("supersede act");
                ClaimRepository::migrate_superseded_edges_conn(&mut conn, canonical, replacement)
                    .await
                    .expect("edge migration");
                replacement
            }
            Retire::Consolidate => {
                let partner = new_claim(&pool, author, "consolidation partner").await;
                let merged = ClaimRepository::consolidate_act_conn(
                    &mut conn,
                    &[canonical, partner],
                    &format!("canonical and partner, merged {}", Uuid::new_v4()),
                    0.5,
                    epigraph_db::repos::claim::ConsolidateMode::Merge,
                    "merge",
                    author,
                )
                .await
                .expect("consolidate act")
                .merged_id;
                ClaimRepository::migrate_consolidated_edges_conn(
                    &mut conn,
                    merged,
                    &[canonical, partner],
                )
                .await
                .expect("edge migration");
                merged
            }
        };
        let edge_target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
            .bind(e)
            .fetch_one(&pool)
            .await
            .expect("edge");
        assert_eq!(
            edge_target, replacement,
            "{how:?}: calibration: the dup's edge followed the canonical to its replacement"
        );
        let bba_on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
            .bind(own)
            .fetch_one(&pool)
            .await
            .expect("bba");
        assert_eq!(
            bba_on, canonical,
            "{how:?}: calibration: the dup's BBA stayed on the retired canonical"
        );

        let ut = trigger(CascadeCause::Undedup, author, dup, None);
        let (outcome, report) = apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, canonical)
            .await
            .unwrap_or_else(|e| panic!("{how:?}: the un-mark follows the chain: {e}"));
        assert!(report.errors.is_empty(), "{how:?}: {:?}", report.errors);
        assert_eq!(current(&pool, dup).await, (None, true), "{how:?}");
        let edge_target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
            .bind(e)
            .fetch_one(&pool)
            .await
            .expect("edge");
        assert_eq!(
            edge_target, dup,
            "{how:?}: the edge is back on the duplicate"
        );
        let bba_on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
            .bind(own)
            .fetch_one(&pool)
            .await
            .expect("bba");
        assert_eq!(bba_on, dup, "{how:?}: the BBA is back on the duplicate");
        let out = serde_json::to_value(&outcome).expect("outcome");
        assert_eq!(
            out["canonical_id"],
            serde_json::json!(canonical),
            "{how:?}: {out}"
        );
        assert_eq!(
            out["current_canonical_id"],
            serde_json::json!(replacement),
            "{how:?}: restored against the current canonical: {out}"
        );
        assert_eq!(out["cascade"]["touched"]["drifted"], 0, "{how:?}: {out}");
        assert_eq!(
            out["cascade"]["touched"]["edges_retargeted_back"], 1,
            "{how:?}: {out}"
        );
        assert_eq!(
            out["cascade"]["touched"]["bbas_returned"], 1,
            "{how:?}: {out}"
        );
    }
}

/// [`an_unmark_follows_the_canonicals_replacement`] for a canonical SUPERSEDED
/// since the mark.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_follows_a_superseded_canonical(pool: PgPool) {
    an_unmark_follows_the_canonicals_replacement(pool, Retire::Supersede).await;
}

/// [`an_unmark_follows_the_canonicals_replacement`] for a canonical
/// CONSOLIDATED since the mark (its own arm, so each has its own red).
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_follows_a_consolidated_canonical(pool: PgPool) {
    an_unmark_follows_the_canonicals_replacement(pool, Retire::Consolidate).await;
}

/// Supersede `old` through the act and carry its edges on, as the supersede
/// routes do; returns the replacement.
async fn supersede(conn: &mut sqlx::PgConnection, old: Uuid) -> Uuid {
    let (replacement, _) = ClaimRepository::supersede_act_conn(
        conn,
        ClaimId::from_uuid(old),
        &format!("revised {old} {}", Uuid::new_v4()),
        epigraph_core::TruthValue::clamped(0.5),
        "revision",
    )
    .await
    .expect("supersede act");
    ClaimRepository::migrate_superseded_edges_conn(conn, old, replacement)
        .await
        .expect("edge migration");
    replacement
}

/// A request path checks the caller's authority over the canonical's chain
/// it read on the caller's own transaction, then the act re-reads the chain on
/// the maintenance connection. If the canonical was replaced again in between
/// (here: the caller was checked against `[C]`, and C has since been superseded
/// by N), the un-mark is refused and nothing changes. The refusal does not
/// name the claims the act read under the maintenance (bypass) viewer: N may
/// be private to another group, and the caller was never shown it. Likewise
/// when the chain the caller was checked against no longer leads to any
/// current canonical (N deprecated since).
#[sqlx::test(migrations = "../../migrations")]
async fn an_authorized_unmark_refuses_a_chain_that_changed_without_naming_it(pool: PgPool) {
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
    apply_after_dedup(&mut conn, &viewer, &viewer, &t, dup, canonical).await;
    let replacement = supersede(&mut conn, canonical).await;

    let undedup_rows = |pool: PgPool| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM security_events WHERE details->>'cause' = 'undedup'",
        )
        .fetch_one(&pool)
        .await
        .expect("count")
    };
    let ut = trigger(CascadeCause::Undedup, author, dup, Some(canonical));
    let err = apply_unmark_authorized(
        &mut conn,
        &viewer,
        &viewer,
        &ut,
        dup,
        canonical,
        Some(&[canonical]),
    )
    .await
    .expect_err("the chain changed since the caller was checked");
    let UnmarkRefusal::Act(msg) = &err else {
        panic!("an act refusal: {err:?}");
    };
    assert!(
        msg.contains("replaced again") && !msg.contains(&replacement.to_string()),
        "refused without naming the replacement the caller was never shown: {msg}"
    );
    assert_eq!(
        current(&pool, dup).await,
        (Some(canonical), false),
        "nothing changed"
    );
    assert_eq!(undedup_rows(pool.clone()).await, 0, "no audit row");

    // The chain the caller was checked against, [C, N], has since lost its
    // current canonical: N was deprecated. Refused the same way.
    sqlx::query(
        "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
          WHERE id = $1",
    )
    .bind(replacement)
    // On the un-mark's own connection: the refused act's rollback is flushed
    // by this statement, releasing the chain rows it held.
    .execute(&mut *conn)
    .await
    .expect("deprecate the replacement");
    let err = apply_unmark_authorized(
        &mut conn,
        &viewer,
        &viewer,
        &ut,
        dup,
        canonical,
        Some(&[canonical, replacement]),
    )
    .await
    .expect_err("no current canonical any more");
    let UnmarkRefusal::Act(msg) = &err else {
        panic!("an act refusal: {err:?}");
    };
    assert!(
        msg.contains("replaced again") && !msg.contains(&replacement.to_string()),
        "refused without naming the claims the act read: {msg}"
    );
    assert_eq!(
        current(&pool, dup).await,
        (Some(canonical), false),
        "nothing changed"
    );
    assert_eq!(undedup_rows(pool.clone()).await, 0, "no audit row");
}

/// A canonical replaced TWICE since the mark (C consolidated with a partner
/// into N1, then N1 superseded by N2): the un-mark follows the whole chain to
/// the current canonical N2, not one step to the retired N1 (operator ruling
/// R-11). The duplicate's `supports` edge rode both migrations on to N2 and
/// comes back from there; its BBA stayed on C and comes back from there;
/// nothing drifts; the audit row records the chain; the restored edge's BP
/// factor is minted on the duplicate, and no factor of it is left on C, N1 or
/// N2.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unmark_follows_a_chain_of_replacements_to_the_current_canonical(pool: PgPool) {
    let f = frame(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
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
    assert!(
        status.audit_event_id.is_some(),
        "calibration: applied dedup row"
    );

    let partner = new_claim(&pool, author, "consolidation partner").await;
    let n1 = ClaimRepository::consolidate_act_conn(
        &mut conn,
        &[canonical, partner],
        &format!("canonical and partner, merged {}", Uuid::new_v4()),
        0.5,
        epigraph_db::repos::claim::ConsolidateMode::Merge,
        "merge",
        author,
    )
    .await
    .expect("consolidate act")
    .merged_id;
    ClaimRepository::migrate_consolidated_edges_conn(&mut conn, n1, &[canonical, partner])
        .await
        .expect("edge migration");
    let n2 = supersede(&mut conn, n1).await;
    let edge_target = |pool: PgPool| async move {
        sqlx::query_scalar::<_, Uuid>("SELECT target_id FROM edges WHERE id = $1")
            .bind(e)
            .fetch_one(&pool)
            .await
            .expect("edge")
    };
    assert_eq!(
        edge_target(pool.clone()).await,
        n2,
        "calibration: the dup's edge rode both migrations on to N2"
    );
    let bba_on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
        .bind(own)
        .fetch_one(&pool)
        .await
        .expect("bba");
    assert_eq!(bba_on, canonical, "calibration: the dup's BBA stayed on C");
    let factors_of_e = |pool: PgPool| async move {
        sqlx::query_scalar::<_, Vec<Uuid>>(
            "SELECT variable_ids FROM factors WHERE properties->>'source_edge_id' = $1::text",
        )
        .bind(e)
        .fetch_all(&pool)
        .await
        .expect("factors")
    };
    let before = factors_of_e(pool.clone()).await;

    let ut = trigger(CascadeCause::Undedup, author, dup, None);
    let (outcome, report) = apply_unmark(&mut conn, &viewer, &viewer, &ut, dup, canonical)
        .await
        .expect("the un-mark follows the whole chain");
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let out = serde_json::to_value(&outcome).expect("outcome");
    assert_eq!(out["canonical_id"], serde_json::json!(canonical), "{out}");
    assert_eq!(
        out["current_canonical_id"],
        serde_json::json!(n2),
        "restored against the CURRENT canonical, two replacements on: {out}"
    );
    assert_eq!(out["cascade"]["touched"]["drifted"], 0, "{out}");
    assert_eq!(current(&pool, dup).await, (None, true));
    assert_eq!(
        edge_target(pool.clone()).await,
        dup,
        "the edge is back on the duplicate, taken from N2"
    );
    let bba_on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
        .bind(own)
        .fetch_one(&pool)
        .await
        .expect("bba");
    assert_eq!(
        bba_on, dup,
        "the BBA is back on the duplicate, taken from C"
    );
    let undedup: serde_json::Value =
        sqlx::query_scalar("SELECT details FROM security_events WHERE id = $1")
            .bind(outcome.cascade.audit_event_id.expect("undedup row"))
            .fetch_one(&pool)
            .await
            .expect("undedup row");
    assert_eq!(
        undedup["canonical_chain"],
        serde_json::json!([canonical, n1, n2]),
        "{undedup}"
    );
    let after = factors_of_e(pool.clone()).await;
    let mut want = vec![supporter, dup];
    want.sort();
    assert_eq!(
        after,
        vec![want],
        "the restored edge's factor is on the duplicate (before the un-mark: {before:?})"
    );
    for retired in [canonical, n1, n2] {
        assert!(
            !after.iter().flatten().any(|v| *v == retired),
            "no factor of the restored edge is left on {retired}: {after:?}"
        );
    }
}
