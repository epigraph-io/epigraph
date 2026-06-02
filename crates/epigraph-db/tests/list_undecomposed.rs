//! Integration tests for `ClaimRepository::list_undecomposed` — the
//! 'never touched by decomposition' predicate (item 46aee550). Seeds the
//! cross-product of edge states (outgoing-only, incoming-only, none) plus the
//! two exclusion classes (telemetry, too-short) so a regression in ANY arm
//! of the WHERE clause surfaces here.

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, EdgeRepository};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2,'hex'))")
        .bind(id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    labels: &[&str],
    props: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, is_current, properties) VALUES ($1,$2,$3,0.5,$4,$5,true,$6)")
        .bind(id).bind(content).bind(hash).bind(agent)
        .bind(labels.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .bind(props)
        .execute(pool).await.unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_undecomposed_excludes_both_edge_directions_and_noise(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    let parent = seed_claim(
        &pool,
        agent,
        "a compound claim that was already decomposed",
        &[],
        serde_json::json!({}),
    )
    .await;
    let child = seed_claim(
        &pool,
        agent,
        "an atom child of the compound claim above",
        &[],
        serde_json::json!({}),
    )
    .await;
    EdgeRepository::create_if_not_exists(
        &pool,
        parent,
        "claim",
        child,
        "claim",
        "decomposes_to",
        None,
        None,
        None,
    )
    .await
    .unwrap();

    let standalone = seed_claim(
        &pool,
        agent,
        "a standalone compound claim never decomposed at all",
        &[],
        serde_json::json!({}),
    )
    .await;
    let telemetry = seed_claim(
        &pool,
        agent,
        "Agent sent message to container epiclaw worker",
        &["telemetry"],
        serde_json::json!({"event": "agent_output"}),
    )
    .await;
    let short = seed_claim(&pool, agent, "tiny", &[], serde_json::json!({})).await;

    let rows = ClaimRepository::list_undecomposed(&pool, 50, 0)
        .await
        .unwrap();
    let ids: std::collections::HashSet<Uuid> = rows.iter().map(|c| c.id.as_uuid()).collect();

    assert!(
        ids.contains(&standalone),
        "standalone claim (no decomposes_to edge either direction) must be returned"
    );
    assert!(
        !ids.contains(&parent),
        "parent of a decomposes_to edge (outgoing) must be excluded"
    );
    assert!(!ids.contains(&child), "child of a decomposes_to edge (incoming) must be excluded — outgoing-only predicate would wrongly include this atom");
    assert!(
        !ids.contains(&telemetry),
        "telemetry claim must be excluded"
    );
    assert!(
        !ids.contains(&short),
        "too-short (<=10 char) content must be excluded"
    );
    assert_eq!(
        rows.len(),
        1,
        "exactly the one standalone claim is undecomposed"
    );
    let _ = ClaimId::from_uuid(standalone);
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_undecomposed_orders_oldest_first_and_pages(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let mut seeded = Vec::new();
    for i in 0..3 {
        seeded.push(
            seed_claim(
                &pool,
                agent,
                &format!("standalone undecomposed claim number {i}"),
                &[],
                serde_json::json!({}),
            )
            .await,
        );
    }
    // created_at ASC => insertion order.
    let page1 = ClaimRepository::list_undecomposed(&pool, 2, 0)
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);
    assert_eq!(page1[0].id.as_uuid(), seeded[0], "oldest first");
    let page2 = ClaimRepository::list_undecomposed(&pool, 2, 2)
        .await
        .unwrap();
    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].id.as_uuid(), seeded[2]);
}
