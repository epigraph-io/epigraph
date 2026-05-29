//! Regression test for backlog bug `5c7fc645`: `decide_match_candidate`
//! wrote CORROBORATES edges without checking that both endpoints were still
//! current, so a near-duplicate that had since been superseded/marked-duplicate
//! could end up with a structural edge (e.g. a bidirectional support cycle on
//! near-identical content).
//!
//! The fix routes the check through `ClaimRepository::are_all_current`, which
//! this test pins: a superseded or missing endpoint must make the guard fail.

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

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
    is_current: bool,
    supersedes: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, supersedes) \
         VALUES ($1, $2, $3, 0.6, $4, $5, $6)",
    )
    .bind(id)
    .bind(format!("claim {id}"))
    .bind(hash)
    .bind(agent_id)
    .bind(is_current)
    .bind(supersedes)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn are_all_current_rejects_stale_or_missing(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let live_a = seed_claim(&pool, agent, true, None).await;
    let live_b = seed_claim(&pool, agent, true, None).await;
    // A superseded claim: is_current = false, pointing at live_a as its successor.
    let superseded = seed_claim(&pool, agent, false, Some(live_a)).await;
    let missing = Uuid::new_v4();

    // Two live claims → guard passes (a CORROBORATES edge would be allowed).
    assert!(ClaimRepository::are_all_current(&pool, &[live_a, live_b])
        .await
        .unwrap());

    // Any superseded endpoint → guard fails (the bug scenario).
    assert!(
        !ClaimRepository::are_all_current(&pool, &[live_a, superseded])
            .await
            .unwrap()
    );

    // A missing id → guard fails.
    assert!(!ClaimRepository::are_all_current(&pool, &[live_a, missing])
        .await
        .unwrap());

    // Empty set is vacuously true.
    assert!(ClaimRepository::are_all_current(&pool, &[]).await.unwrap());
}
