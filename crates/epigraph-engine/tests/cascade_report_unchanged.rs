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
//! A BBA-free, cache-free candidate (every `mark_duplicate` endpoint pair)
//! stays absent from every field.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{MassFunctionRepository, PgPool, ScopedPool, SessionGucMode};
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
#[sqlx::test(migrations = "../../migrations")]
async fn a_write_migration_114_declines_is_reported_unchanged(pool: PgPool) {
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "unchanged-114-author").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "unchanged-114-stranger").await;
    let (binary, validity) = frames(&pool).await;

    let claim = fixture::seed_public_claim(&pool, author, "cache owned elsewhere").await;
    store(&pool, claim, binary, author).await;
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
