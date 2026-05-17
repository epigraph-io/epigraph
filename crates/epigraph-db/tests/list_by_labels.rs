//! Integration tests for [`ClaimRepository::list_by_labels`] after extension
//! with `exclude_labels` and `current_only` filters plus labels in the result
//! tuple (see plan `docs/superpowers/plans/2026-05-16-backlog-retirement.md`,
//! Task 1).
//!
//! Seeds three backlog claims directly via SQL: one current open, one current
//! resolved (extra label), and one superseded (`is_current = false` pointing
//! at the open one). Pins the cross-product of filters so future regressions
//! in label-containment, exclusion, or supersession-state filtering surface
//! here.

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn list_by_labels_returns_labels_is_current_supersedes(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    // Seed: one current backlog claim, one resolved backlog claim, one
    // superseded backlog claim. The superseded one references the open one as
    // its successor, so the supersedes FK resolves.
    let backlog_open = seed_claim(&pool, agent, &["backlog"], true, None).await;
    let backlog_resolved = seed_claim(&pool, agent, &["backlog", "resolved"], true, None).await;
    let backlog_superseded =
        seed_claim(&pool, agent, &["backlog"], false, Some(backlog_open)).await;

    // Default call: returns all three with labels populated
    let rows = ClaimRepository::list_by_labels(
        &pool,
        &["backlog".to_string()],
        &[],   // exclude_labels
        false, // current_only
        0.0,
        50,
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 3);
    let labels_for = |id: ClaimId| {
        rows.iter()
            .find(|(c, _)| c.id == id)
            .map(|(_, l)| l.clone())
            .unwrap()
    };
    assert_eq!(labels_for(backlog_open), vec!["backlog"]);
    assert!(labels_for(backlog_resolved).contains(&"resolved".to_string()));
    let superseded_row = rows
        .iter()
        .find(|(c, _)| c.id == backlog_superseded)
        .unwrap();
    assert!(!superseded_row.0.is_current);
    assert!(superseded_row.0.supersedes.is_some());

    // exclude_labels=["resolved"] drops the resolved one
    let filtered = ClaimRepository::list_by_labels(
        &pool,
        &["backlog".to_string()],
        &["resolved".to_string()],
        false,
        0.0,
        50,
    )
    .await
    .unwrap();
    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().all(|(c, _)| c.id != backlog_resolved));

    // current_only=true drops the superseded one
    let current =
        ClaimRepository::list_by_labels(&pool, &["backlog".to_string()], &[], true, 0.0, 50)
            .await
            .unwrap();
    assert_eq!(current.len(), 2);
    assert!(current.iter().all(|(c, _)| c.id != backlog_superseded));

    // Both filters combined: only the live open backlog claim
    let open = ClaimRepository::list_by_labels(
        &pool,
        &["backlog".to_string()],
        &["resolved".to_string()],
        true,
        0.0,
        50,
    )
    .await
    .unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].0.id, backlog_open);
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent_id: Uuid,
    labels: &[&str],
    is_current: bool,
    supersedes: Option<ClaimId>,
) -> ClaimId {
    let id = Uuid::new_v4();
    // Unique content_hash per row — content_hash has a btree index and some
    // dedup paths key on it; using the claim UUID padded to 32 bytes avoids
    // any collisions across calls within a single test.
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             labels, is_current, supersedes) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(format!("test claim {}", id))
    .bind(hash)
    .bind(agent_id)
    .bind(labels.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(is_current)
    .bind(supersedes.map(|s| s.as_uuid()))
    .execute(pool)
    .await
    .unwrap();
    ClaimId::from_uuid(id)
}
