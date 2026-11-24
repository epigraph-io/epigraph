//! Every repair candidate of a belief cascade that holds a BBA or a cache lands
//! in exactly ONE report bucket (backlog 541d7104): `recomputed`, `unbacked`,
//! `unchanged` or `errors`.
//!
//! Before, a candidate that still held BBAs but whose refold wrote nothing was
//! silently absent from the report (`CascadeReport::targets` documented it as
//! absent), so the caller of a supersede or retraction, and the operator
//! reading the cascade audit, could not tell that a dependent claim kept a
//! cache folded with the retired evidence. Two ways the refold writes nothing
//! are pinned here:
//!
//! * EMPTIED: the claim's BBAs sit only on a frame other than the one the
//!   cascade repairs (`binary_truth`), so the refold finds nothing to fold and
//!   the BBAs elsewhere keep the cache from being cleared;
//! * DECLINED: the cascade runs on a session that does not own the public
//!   claim's cache, which is recorded on another frame, so migration 114 turns
//!   the write into a no-op.
//!
//! And a claim with no BBA left whose cache CLEAR the database declined, which
//! the clear's 0-row answer used to make indistinguishable from "there was no
//! cache" (review of backlog 541d7104):
//!
//! * CLEAR DECLINED (definer): a public claim with a cache recording no frame,
//!   cleared by a non-owner session; migration 114's definer refuses it.
//!
//! A clear that row-level security refuses (a group claim the session reads as
//! a `reader` member) raises an error rather than answering 0 rows, so that
//! claim is pinned in `errors`, again in exactly one bucket.
//!
//! A BBA-free, cache-free candidate (every `mark_duplicate` endpoint pair)
//! stays absent from every field.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, PgPool, ScopedPool, SessionGucMode};
use epigraph_engine::admin_cascade::report_for_caller;
use epigraph_engine::edge_factor::{ensure_binary_frame, resolve_claim_validity_frame};
use epigraph_engine::retraction_cascade::{cascade_after_edge_withdrawal, CascadeReport};
use uuid::Uuid;

/// A claim's cache: belief, plausibility, pignistic, the frame it records.
type Cache = (Option<f64>, Option<f64>, Option<f64>, Option<Uuid>);

async fn cache(pool: &PgPool, id: Uuid) -> Cache {
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, belief_frame_id FROM claims WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read the cache")
}

/// Plant a filled cache recorded on `frame`.
async fn plant(pool: &PgPool, id: Uuid, frame: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.7, plausibility = 0.9, pignistic_prob = 0.8, \
                           belief_frame_id = $2 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(frame)
    .execute(pool)
    .await
    .expect("plant a cache");
}

async fn store(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid) {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA");
}

async fn frames(pool: &PgPool) -> (Uuid, Uuid) {
    let public = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let binary = ensure_binary_frame(&mut conn, &public)
        .await
        .expect("binary frame");
    let validity = resolve_claim_validity_frame(&mut conn, &public)
        .await
        .expect("claim_validity frame");
    assert_ne!(binary, validity, "PREMISE: two distinct frames");
    (binary, validity)
}

/// Each candidate in exactly one bucket, and `targets` is exactly the union
/// of `recomputed`, `unbacked` and the claims named in `errors`.
fn assert_partition(report: &CascadeReport) {
    let mut buckets: Vec<Uuid> = report
        .recomputed
        .iter()
        .chain(&report.unbacked)
        .chain(&report.unchanged)
        .copied()
        .collect();
    let n = buckets.len();
    buckets.sort_unstable();
    buckets.dedup();
    assert_eq!(buckets.len(), n, "a candidate in two buckets: {report:?}");
    for id in &report.unchanged {
        assert!(
            !report.targets.contains(id),
            "an unchanged claim is not a target (nothing was written): {report:?}"
        );
    }
    let mut written: Vec<Uuid> = report
        .recomputed
        .iter()
        .chain(&report.unbacked)
        .copied()
        .collect();
    written.sort_unstable();
    let mut targets = report.targets.clone();
    targets.sort_unstable();
    assert_eq!(
        targets, written,
        "targets = recomputed + unbacked: {report:?}"
    );
}

/// EMPTIED: a cached claim whose only BBA sits on `claim_validity` is listed
/// under `unchanged` (its cache is left as it was), beside a recomputed
/// control and a BBA-free, cache-free candidate that stays absent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refold_that_empties_on_the_repaired_frame_is_reported_unchanged(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "unchanged-emptied").await;
    let (binary, validity) = frames(&pool).await;

    let elsewhere = fixture::seed_public_claim(&pool, agent, "backed on another frame").await;
    store(&pool, elsewhere, validity, agent).await;
    plant(&pool, elsewhere, validity).await;
    let control = fixture::seed_public_claim(&pool, agent, "backed on binary_truth").await;
    store(&pool, control, binary, agent).await;
    let bare = fixture::seed_public_claim(&pool, agent, "no BBA, no cache").await;
    let before = cache(&pool, elsewhere).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let report =
        cascade_after_edge_withdrawal(&mut conn, &bypass, &[elsewhere, control, bare], 0).await;

    assert!(report.errors.is_empty(), "{report:?}");
    assert_eq!(
        report.unchanged,
        vec![elsewhere],
        "a candidate whose refold wrote nothing is reported, not silently dropped: {report:?}"
    );
    assert_eq!(
        report.recomputed,
        vec![control],
        "CALIBRATION: a candidate backed on the repaired frame is recomputed: {report:?}"
    );
    assert!(report.unbacked.is_empty(), "{report:?}");
    assert!(
        !report.unchanged.contains(&bare) && !report.targets.contains(&bare),
        "a BBA-free, cache-free candidate stays absent: {report:?}"
    );
    assert_partition(&report);
    assert_eq!(
        cache(&pool, elsewhere).await,
        before,
        "the unchanged claim's cache is left as it was"
    );
}

/// DECLINED: a public claim owned by the world group, backed on
/// `binary_truth`, whose cache is recorded on `claim_validity`. The cascade on
/// an application-role session stamped as an agent that does not own the
/// claim refolds `binary_truth`, and migration 114 declines that write: the
/// claim is listed under `unchanged`. The same cascade on the privileged
/// connection writes it (the control), so the decline is the session's.
///
/// The claim also holds a BBA on `claim_validity`, the frame its cache
/// records: migration 243 lets a non-owner re-point a public claim's cache
/// off a recorded frame that holds NO cache-admissible input, so without that
/// BBA the stranger's write is accepted (as a re-point), not declined.
#[sqlx::test(migrations = "../../migrations")]
async fn a_write_migration_114_declines_is_reported_unchanged(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "unchanged-114-author").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "unchanged-114-stranger").await;
    let (binary, validity) = frames(&pool).await;

    let claim = fixture::seed_public_claim(&pool, author, "cache owned elsewhere").await;
    store(&pool, claim, binary, author).await;
    store(&pool, claim, validity, author).await;
    plant(&pool, claim, validity).await;
    let before = cache(&pool, claim).await;

    let url = fixture::database_url_for(&pool).await;
    let app =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let viewer = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve the stranger");
    let mut tx = app.begin_as(&viewer).await.expect("stamped app session");
    let report = cascade_after_edge_withdrawal(&mut tx, &viewer, &[claim], 0).await;
    tx.commit().await.expect("commit");

    assert!(report.errors.is_empty(), "{report:?}");
    assert_eq!(
        report.unchanged,
        vec![claim],
        "a refold migration 114 declined is reported, not silently dropped: {report:?}"
    );
    assert!(
        report.recomputed.is_empty() && report.unbacked.is_empty(),
        "{report:?}"
    );
    assert_partition(&report);
    assert_eq!(
        cache(&pool, claim).await,
        before,
        "the declined write leaves the cache as it was"
    );

    // Control: the privileged connection's write is not declined.
    let mut conn = pool.acquire().await.expect("acquire");
    let control = cascade_after_edge_withdrawal(&mut conn, &bypass, &[claim], 0).await;
    assert_eq!(
        control.recomputed,
        vec![claim],
        "CALIBRATION: the owner-class session writes the same refold: {control:?}"
    );
    assert!(control.unchanged.is_empty(), "{control:?}");
    assert_eq!(
        cache(&pool, claim).await.3,
        Some(binary),
        "re-pointed by the control"
    );
}

/// Run `cascade_after_edge_withdrawal` over `ids` on an application-role
/// session stamped as `agent`, committing it.
async fn cascade_as(pool: &PgPool, agent: Uuid, ids: &[Uuid]) -> CascadeReport {
    let url = fixture::database_url_for(pool).await;
    let app =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let viewer = Viewer::resolve(pool, agent)
        .await
        .expect("resolve the agent");
    let mut tx = app.begin_as(&viewer).await.expect("stamped app session");
    let report = cascade_after_edge_withdrawal(&mut tx, &viewer, ids, 0).await;
    tx.commit().await.expect("commit");
    report
}

/// Plant a filled cache that records NO frame.
async fn plant_frameless(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.7, plausibility = 0.9, pignistic_prob = 0.8, \
                           belief_frame_id = NULL \
          WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("plant a frameless cache");
}

/// CLEAR DECLINED (definer): a public, BBA-free claim with a cache recording
/// no frame. On a non-owner app-role session the clear goes through migration
/// 114's definer, which refuses a cache with no recorded frame and answers 0
/// rows. The claim is listed under `unchanged` with its cache kept, beside a
/// BBA-free, cache-free candidate that stays absent. The privileged control
/// clears the same cache and reports it `unbacked`, so the decline is the
/// session's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cache_clear_migration_114_declines_is_reported_unchanged(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "declined-clear-author").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "declined-clear-stranger").await;

    let claim = fixture::seed_public_claim(&pool, author, "frameless cache, no BBA").await;
    plant_frameless(&pool, claim).await;
    let bare = fixture::seed_public_claim(&pool, author, "no BBA, no cache").await;
    let before = cache(&pool, claim).await;
    assert!(before.0.is_some(), "PREMISE: the claim holds a cache");

    let report = cascade_as(&pool, stranger, &[claim, bare]).await;

    assert!(report.errors.is_empty(), "{report:?}");
    assert_eq!(
        report.unchanged,
        vec![claim],
        "a cache whose clear the database declined is reported, not silently dropped: \
         {report:?}"
    );
    assert!(
        report.unbacked.is_empty() && report.recomputed.is_empty() && report.targets.is_empty(),
        "{report:?}"
    );
    assert!(
        !report.unchanged.contains(&bare),
        "a BBA-free, cache-free candidate stays absent: {report:?}"
    );
    assert_partition(&report);
    assert_eq!(
        cache(&pool, claim).await,
        before,
        "the declined clear leaves the cache as it was"
    );

    // Control: the privileged connection clears it.
    let mut conn = pool.acquire().await.expect("acquire");
    let control = cascade_after_edge_withdrawal(&mut conn, &bypass, &[claim, bare], 0).await;
    assert_eq!(
        control.unbacked,
        vec![claim],
        "CALIBRATION: the owner-class session clears the same cache: {control:?}"
    );
    assert!(control.unchanged.is_empty(), "{control:?}");
    assert_eq!(cache(&pool, claim).await, (None, None, None, None));
}

/// CLEAR REFUSED (row-level security): a BBA-free group claim with a cache,
/// read by a `reader` member of its group. The session sees the claim but may
/// not write it: the clear's UPDATE fails row-level security's check and
/// raises, so the claim is reported in `errors` (and `targets`), in no other
/// bucket, with its cache kept. Its owner's session clears it (the control).
#[sqlx::test(migrations = "../../migrations")]
async fn a_cache_clear_row_security_refuses_is_reported_as_an_error(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "rls-clear-author").await;
    let (reader, _) = fixture::seed_agent_with_group(&pool, "rls-clear-reader").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(group)
    .bind(reader)
    .execute(&pool)
    .await
    .expect("seed the reader membership");

    let claim = fixture::seed_group_claim(&pool, author, group, "group cache, no BBA").await;
    let (_, validity) = frames(&pool).await;
    plant(&pool, claim, validity).await;
    let before = cache(&pool, claim).await;

    let report = cascade_as(&pool, reader, &[claim]).await;

    let id = claim.to_string();
    assert_eq!(
        report.errors.iter().filter(|e| e.contains(&id)).count(),
        1,
        "a cache the session can read but not clear is reported as one error: {report:?}"
    );
    assert_eq!(report.targets, vec![claim], "{report:?}");
    assert!(
        report.unbacked.is_empty() && report.recomputed.is_empty() && report.unchanged.is_empty(),
        "an errored candidate is in no other bucket: {report:?}"
    );
    assert_eq!(
        cache(&pool, claim).await,
        before,
        "the refused clear leaves the cache as it was"
    );

    // Control: the owner's own session clears it.
    let control = cascade_as(&pool, author, &[claim]).await;
    assert!(control.errors.is_empty(), "{control:?}");
    assert_eq!(
        control.unbacked,
        vec![claim],
        "CALIBRATION: the owner clears the same cache: {control:?}"
    );
}

/// The caller's copy of a report (`admin_cascade::report_for_caller`) drops
/// every claim id outside the caller's view from EVERY bucket, `unchanged`
/// included: that bucket carries claim ids to callers who may not be members
/// of the claims' groups. A public claim in each bucket stays; a group claim
/// of a group the caller is not in is dropped from each.
#[sqlx::test(migrations = "../../migrations")]
async fn the_callers_copy_drops_unchanged_claims_outside_its_view(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "caller-copy-author").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "caller-copy-stranger").await;
    let public = fixture::seed_public_claim(&pool, author, "readable by all").await;
    let hidden = fixture::seed_group_claim(&pool, author, group, "not the caller's").await;
    let both = vec![public, hidden];
    let report = CascadeReport {
        targets: both.clone(),
        recomputed: both.clone(),
        unbacked: both.clone(),
        unchanged: both.clone(),
        ..CascadeReport::default()
    };

    let url = fixture::database_url_for(&pool).await;
    let app =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let viewer = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve the stranger");
    let mut tx = app.begin_as(&viewer).await.expect("stamped app session");
    let copy = report_for_caller(&mut tx, &viewer, &report).await;
    tx.rollback().await.expect("rollback");

    assert_eq!(
        copy.unchanged,
        vec![public],
        "an unchanged claim outside the caller's view is dropped: {copy:?}"
    );
    for (name, bucket) in [
        ("targets", &copy.targets),
        ("recomputed", &copy.recomputed),
        ("unbacked", &copy.unbacked),
    ] {
        assert_eq!(
            bucket,
            &vec![public],
            "CALIBRATION: {name} is filtered the same way: {copy:?}"
        );
    }
}
