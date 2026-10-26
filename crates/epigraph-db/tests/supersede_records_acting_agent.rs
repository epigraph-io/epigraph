//! A supersession records the agent that PERFORMED it (backlog 73085534,
//! operator ruling R-23).
//!
//! `ClaimRepository::supersede_act_conn` restates the retired claim under the
//! retired claim's author (`claims.agent_id`), the documented contract the
//! ruling keeps. Until this fix the acting agent appeared nowhere in the graph
//! (only in the cascade's `security_events` rows), so a successor written by
//! agent B read as agent A's work. The act now also writes ONE `AUTHORED` edge
//! from the acting agent to the successor, in the act's own transaction, with
//! the properties the workflow writes use for the same purpose (#600,
//! `epigraph_ingest_executor::record_caller_authorship`).

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::{ClaimRepository, SupersedeActor};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type) \
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system') RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, author: Uuid) -> Uuid {
    let text = format!("a claim to supersede {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(&text)
    .bind(author)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// Every `AUTHORED` edge INTO `claim`: `(source_id, source_type, properties)`.
async fn authored_into(pool: &PgPool, claim: Uuid) -> Vec<(Uuid, String, serde_json::Value)> {
    sqlx::query_as(
        "SELECT source_id, source_type, COALESCE(properties, '{}'::jsonb) FROM edges \
          WHERE relationship = 'AUTHORED' AND target_id = $1 AND target_type = 'claim' \
          ORDER BY source_id",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("read AUTHORED edges")
}

/// Agent B supersedes agent A's claim: the successor keeps A as its author
/// (the contract R-23 keeps) AND carries exactly one `AUTHORED` edge, from B,
/// with the #600 properties. A gets no edge from the act.
#[sqlx::test(migrations = "../../migrations")]
async fn the_successor_keeps_its_author_and_records_the_acting_agent(pool: PgPool) {
    let a = seed_agent(&pool, "author-a").await;
    let b = seed_agent(&pool, "actor-b").await;
    let old = seed_claim(&pool, a).await;

    let mut tx = pool.begin().await.expect("begin");
    let (new, returned_old) = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(old),
        "a correction written by B",
        TruthValue::clamped(0.6),
        "B corrects A",
        SupersedeActor::new(b, "supersede_claim"),
    )
    .await
    .expect("B's supersession lands");
    tx.commit().await.expect("commit");
    assert_eq!(returned_old, old);

    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(new)
        .fetch_one(&pool)
        .await
        .expect("the successor");
    assert_eq!(author, a, "the successor inherits the predecessor's author");

    assert_eq!(
        authored_into(&pool, new).await,
        vec![(
            b,
            "agent".to_string(),
            serde_json::json!({"tool": "supersede_claim", "was_created": true}),
        )],
        "exactly one AUTHORED edge, from the acting agent B, with the #600 properties"
    );
}

/// The edge is part of the ACT: an act that rolls back leaves no edge behind
/// and no successor, so a successor never exists without the record of who
/// wrote it and a record never names a write that did not happen.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rolled_back_act_leaves_no_authorship_edge(pool: PgPool) {
    let a = seed_agent(&pool, "author-a").await;
    let b = seed_agent(&pool, "actor-b").await;
    let old = seed_claim(&pool, a).await;

    let mut tx = pool.begin().await.expect("begin");
    let (new, _) = ClaimRepository::supersede_act_conn(
        &mut tx,
        ClaimId::from_uuid(old),
        "a correction that will be rolled back",
        TruthValue::clamped(0.6),
        "rolled back",
        SupersedeActor::new(b, "supersede_claim"),
    )
    .await
    .expect("the act runs");
    // Inside the act's own transaction the edge is already there ...
    let inside: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship = 'AUTHORED' \
            AND source_id = $1 AND target_id = $2",
    )
    .bind(b)
    .bind(new)
    .fetch_one(&mut *tx)
    .await
    .expect("count inside");
    assert_eq!(inside, 1, "the act writes the edge in its own transaction");
    tx.rollback().await.expect("rollback");

    // ... and it goes with the act.
    assert!(authored_into(&pool, new).await.is_empty());
    let current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .expect("the predecessor");
    assert!(current, "the rolled-back act retired nothing");
}
