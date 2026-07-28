//! `prune_telemetry_events` — retention for the `events` table.
//!
//! The one property that matters here is what does NOT get deleted. `events`
//! holds the graph's provenance record (`claim.created` alone was 51k rows in
//! prod); a retention job that swept it would destroy history that cannot be
//! reconstructed from anything else. Pruning is therefore allowlisted to
//! telemetry types, and these tests pin that boundary.

use epigraph_db::{RecallEventRepository, PRUNABLE_EVENT_TYPES};
use sqlx::PgPool;

async fn seed_event(pool: &PgPool, event_type: &str, age_days: i32) {
    sqlx::query(
        "INSERT INTO events (event_type, payload, graph_version, created_at)
         VALUES ($1, '{}'::jsonb, 1, NOW() - make_interval(days => $2))",
    )
    .bind(event_type)
    .bind(age_days)
    .execute(pool)
    .await
    .expect("seed event");
}

async fn count_of(pool: &PgPool, event_type: &str) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events WHERE event_type = $1")
        .bind(event_type)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Provenance event types must survive pruning regardless of age. This is the
/// test that stands between a retention job and the loss of graph history.
#[sqlx::test(migrations = "../../migrations")]
async fn provenance_event_types_are_never_pruned(pool: PgPool) {
    // Every non-telemetry type observed in prod, all far past retention.
    let provenance = [
        "claim.created",
        "edge.added",
        "agent.registered",
        "claim.challenged",
        "conflict.detected",
        "conflict.resolved",
        "synthesis.complete",
        "workflow.created",
    ];
    for t in provenance {
        seed_event(&pool, t, 400).await;
    }
    seed_event(&pool, "tool.invoked", 400).await;

    let deleted = RecallEventRepository::prune_telemetry_events(&pool, 90)
        .await
        .expect("prune");

    assert_eq!(deleted, 1, "only the telemetry row is deleted");
    for t in provenance {
        assert_eq!(
            count_of(&pool, t).await,
            1,
            "{t} is provenance and must survive pruning at any age"
        );
    }
    assert_eq!(count_of(&pool, "tool.invoked").await, 0);
}

/// An event type nobody has classified yet must be LEFT ALONE. This is the
/// allowlist's whole purpose: a denylist would silently start deleting any
/// type added after the policy was written.
#[sqlx::test(migrations = "../../migrations")]
async fn unknown_future_event_types_are_left_alone(pool: PgPool) {
    seed_event(&pool, "some.future.event.type", 400).await;

    let deleted = RecallEventRepository::prune_telemetry_events(&pool, 90)
        .await
        .expect("prune");

    assert_eq!(deleted, 0);
    assert_eq!(
        count_of(&pool, "some.future.event.type").await,
        1,
        "an unclassified type is not swept — it is simply not on the allowlist"
    );
}

/// Retention boundary: telemetry inside the window survives.
#[sqlx::test(migrations = "../../migrations")]
async fn telemetry_inside_the_window_survives(pool: PgPool) {
    seed_event(&pool, "tool.invoked", 400).await; // expired
    seed_event(&pool, "tool.invoked", 30).await; // fresh

    let would = RecallEventRepository::count_prunable_events(&pool, 90)
        .await
        .expect("count");
    assert_eq!(would, 1, "dry-run count sees only the expired row");

    let deleted = RecallEventRepository::prune_telemetry_events(&pool, 90)
        .await
        .expect("prune");
    assert_eq!(deleted, 1);
    assert_eq!(
        count_of(&pool, "tool.invoked").await,
        1,
        "the fresh row remains"
    );
}

/// The allowlist is a deliberate policy artifact — assert its contents so
/// widening it requires editing a test that says why.
#[test]
fn allowlist_contains_only_telemetry() {
    assert_eq!(
        PRUNABLE_EVENT_TYPES,
        &["tool.invoked"],
        "adding a type here deletes production history — it needs an explicit decision, \
         not an incidental edit"
    );
}
