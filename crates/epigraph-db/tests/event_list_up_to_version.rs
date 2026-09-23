//! `EventRepository::list_up_to_version`: the read behind
//! `GET /api/v1/graph/snapshot/:version`.
//!
//! Deferred-commitment screen key `graph-snapshot-scan-cost`
//! (`docs/tenancy/progress.json::F-graph-snapshot-scan-cost`). The snapshot
//! handler used to call `EventRepository::list(.., version + 1)` and drop rows
//! newer than `version` in Rust. `list` orders by `created_at DESC`, so the
//! limit took the NEWEST `version + 1` rows and the filter then discarded all
//! of them for any version below about half the log. The register had this as
//! a speed note; it was a wrong answer. These tests pin the three things the
//! replacement has to get right:
//!
//! * **Completeness.** Every event at or below the bound is returned, however
//!   many newer events exist. The fixture writes more than twice as many newer
//!   events as older ones, which is the shape the old code answered with
//!   nothing.
//! * **Order.** Oldest first, and a limit that binds keeps the oldest rows.
//! * **Tenancy is unchanged.** The same suppression predicate as `list`, with
//!   its viewer bound at index 3 rather than 4. An off-by-one there fails only
//!   for a `Scoped` viewer, so the member and stranger arms are resolved
//!   through `Viewer::resolve`, the way production builds them, and a `Bypass`
//!   arm covers the rendering that binds nothing.
//!
//! Every test runs on its own `#[sqlx::test]` database. `graph_version` is a
//! global counter, so on a shared corpus "every event at or below v" would be
//! whatever other binaries had left in `events`. Assertions are still by id,
//! because the fixture helpers may themselves write events.

use std::collections::HashSet;

use epigraph_db::repos::{EventRepository, EventRow};
use epigraph_db::Viewer;
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

async fn insert(pool: &PgPool, actor: Uuid, event_type: &str, payload: serde_json::Value) -> Uuid {
    EventRepository::insert(pool, event_type, Some(actor), &payload)
        .await
        .expect("insert event")
}

async fn version_of(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT graph_version FROM events WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("graph_version of a seeded event")
}

fn ids(rows: &[EventRow]) -> HashSet<Uuid> {
    rows.iter().map(|r| r.id).collect()
}

fn assert_ascending_and_bounded(rows: &[EventRow], bound: i64, who: &str) {
    assert!(
        rows.iter().all(|r| r.graph_version <= bound),
        "{who}: every row must be at or below graph_version {bound}; got {:?}",
        rows.iter().map(|r| r.graph_version).collect::<Vec<_>>()
    );
    assert!(
        rows.windows(2)
            .all(|w| w[0].graph_version < w[1].graph_version),
        "{who}: a snapshot is a replay and must come back oldest first; got {:?}",
        rows.iter().map(|r| r.graph_version).collect::<Vec<_>>()
    );
}

/// The regression. Three old events, then more than twice as many newer ones,
/// then a read at the third old event's version.
///
/// The old shape (`list(.., v + 1)` then `graph_version <= v` in Rust) returned
/// NONE of the three here. The newest `v + 1` rows are all newer than `v`.
#[sqlx::test(migrations = "../../migrations")]
async fn every_event_at_or_below_the_bound_is_returned_oldest_first(pool: PgPool) {
    let (member_agent, group) = fixture::seed_agent_with_group(&pool, "upto-member").await;
    let (stranger_agent, _) = fixture::seed_agent_with_group(&pool, "upto-stranger").await;
    let public_id = fixture::seed_public_claim(&pool, member_agent, "upto public claim").await;
    let private_id =
        fixture::seed_group_claim(&pool, member_agent, group, "upto private claim").await;

    let ev_public = insert(
        &pool,
        member_agent,
        "upto.names_public",
        serde_json::json!({ "claim_id": public_id }),
    )
    .await;
    let ev_private = insert(
        &pool,
        member_agent,
        "upto.names_private",
        serde_json::json!({ "claim_a_id": private_id, "claim_b_id": public_id }),
    )
    .await;
    let ev_plain = insert(
        &pool,
        member_agent,
        "upto.names_nothing",
        serde_json::json!({ "note": "no identifier in this payload" }),
    )
    .await;
    let bound = version_of(&pool, ev_plain).await;

    // More than 2x as many newer events as there are events at or below the
    // bound, fixture-written ones included.
    let mut newer = HashSet::new();
    for i in 0..(2 * bound + 5) {
        newer.insert(
            insert(
                &pool,
                member_agent,
                "upto.newer",
                serde_json::json!({ "i": i, "claim_id": public_id }),
            )
            .await,
        );
    }

    let at_or_below: i64 =
        sqlx::query_scalar("SELECT count(*) FROM events WHERE graph_version <= $1")
            .bind(bound)
            .fetch_one(&pool)
            .await
            .expect("count events at or below the bound");
    let above: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE graph_version > $1")
        .bind(bound)
        .fetch_one(&pool)
        .await
        .expect("count events above the bound");
    assert!(
        above > 2 * at_or_below,
        "PREMISE: the fixture must put more than twice as many events above the \
         bound as at or below it, or it does not reproduce the shape the old \
         code answered with nothing ({above} above, {at_or_below} at or below)"
    );

    let member = Viewer::resolve(&pool, member_agent)
        .await
        .expect("resolve member");
    let stranger = Viewer::resolve(&pool, stranger_agent)
        .await
        .expect("resolve stranger");
    assert!(
        member.group_bind().is_some_and(|g| g.contains(&group)),
        "PREMISE: the member viewer carries the owning group"
    );
    assert!(
        stranger.group_bind().is_some_and(|g| !g.contains(&group)),
        "PREMISE: the stranger viewer does not carry the owning group"
    );

    // ---- The member: everything at or below the bound, nothing above it.
    let rows = EventRepository::list_up_to_version(&pool, &member, bound, bound + 1)
        .await
        .expect("list_up_to_version as the member");
    assert_ascending_and_bounded(&rows, bound, "member");
    let seen = ids(&rows);
    assert!(
        seen.contains(&ev_public) && seen.contains(&ev_private) && seen.contains(&ev_plain),
        "member: every seeded event at or below graph_version {bound} must be \
         returned, however many newer events exist. The old shape returned none \
         of them. Got {} rows: {seen:?}",
        rows.len()
    );
    assert!(
        seen.is_disjoint(&newer),
        "member: no event newer than the bound may be returned"
    );
    assert_eq!(
        i64::try_from(rows.len()).expect("row count fits i64"),
        at_or_below,
        "member: nothing at or below the bound is hidden from a member of every \
         group that owns a claim named here, so the read must return all of them"
    );

    // ---- The stranger: the same rows minus the one naming the private claim.
    let rows = EventRepository::list_up_to_version(&pool, &stranger, bound, bound + 1)
        .await
        .expect("list_up_to_version as the stranger");
    assert_ascending_and_bounded(&rows, bound, "stranger");
    let seen = ids(&rows);
    assert!(
        !seen.contains(&ev_private),
        "stranger: an event naming a claim this viewer cannot read must be \
         suppressed, exactly as EventRepository::list suppresses it"
    );
    assert!(
        seen.contains(&ev_public) && seen.contains(&ev_plain),
        "stranger: suppression must not take the readable events with it. Got {seen:?}"
    );

    // ---- Bypass: renders no viewer predicate and binds no third parameter.
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let rows = EventRepository::list_up_to_version(&pool, &bypass, bound, bound + 1)
        .await
        .expect("list_up_to_version as a bypass viewer");
    assert_ascending_and_bounded(&rows, bound, "bypass");
    let seen = ids(&rows);
    assert!(
        seen.contains(&ev_public) && seen.contains(&ev_private) && seen.contains(&ev_plain),
        "bypass: every event at or below the bound. Got {seen:?}"
    );
}

/// A limit that binds keeps the OLDEST rows: a prefix of the replay, never the
/// newest rows below the bound. That is what lets `graph_snapshot` detect a
/// binding limit instead of returning a sample from the wrong end.
#[sqlx::test(migrations = "../../migrations")]
async fn a_binding_limit_keeps_the_oldest_rows(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "upto-limit").await;
    let mut seeded = Vec::new();
    for i in 0..6 {
        let id = insert(&pool, agent, "upto.limit", serde_json::json!({ "i": i })).await;
        seeded.push((version_of(&pool, id).await, id));
    }
    let bound = seeded.last().expect("seeded").0;

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");
    let all = EventRepository::list_up_to_version(&pool, &viewer, bound, bound + 1)
        .await
        .expect("unbounded read");
    let prefix = EventRepository::list_up_to_version(&pool, &viewer, bound, 2)
        .await
        .expect("limited read");

    assert_eq!(prefix.len(), 2, "the limit must bind here");
    assert_eq!(
        prefix.iter().map(|r| r.id).collect::<Vec<_>>(),
        all.iter().take(2).map(|r| r.id).collect::<Vec<_>>(),
        "a binding limit must return the first rows of the full replay"
    );
    assert!(
        all.iter().any(|r| r.id == seeded[0].1),
        "the unlimited read contains the oldest seeded event"
    );
}
