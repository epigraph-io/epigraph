//! Plan 2.5 — Server-side ingestion idempotency (TDD)
//!
//! These tests drive durable, cross-process idempotency for agent
//! registration and `POST /api/v1/submit/packet` claim insertion, so the
//! per-PR-process commit ingester can find-or-create repo/PR/commit nodes and
//! author/orchestrator agents without 500s on run 2+.
//!
//! # Running
//!
//! ```bash
//! DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
//!   cargo test -p epigraph-api --test idempotency_2p5_tests
//! ```

use epigraph_core::Agent;
use epigraph_db::{AgentRepository, PgPool};

/// Create an agent with a fixed (deterministic) 32-byte public key so two
/// calls collide on `agents_public_key_unique`.
fn fixed_agent(seed: u8, display_name: &str) -> Agent {
    let key = [seed; 32];
    Agent::new(key, Some(display_name.to_string()))
}

/// `create_or_get` is idempotent on `public_key`: the first call creates the
/// agent, the second returns the same row without inserting a duplicate.
#[sqlx::test(migrations = "../../migrations")]
async fn agent_create_or_get_is_idempotent_on_public_key(pool: PgPool) {
    let agent = fixed_agent(7, "idem-agent");

    let (first, created_first) = AgentRepository::create_or_get(&pool, &agent)
        .await
        .expect("first create_or_get should succeed");
    assert!(created_first, "first call must report a fresh creation");

    let (second, created_second) = AgentRepository::create_or_get(&pool, &agent)
        .await
        .expect("second create_or_get should succeed");
    assert!(!created_second, "second call must report find (not create)");

    assert_eq!(
        first.id, second.id,
        "both calls must resolve to the same agent id"
    );

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(agent.public_key.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count query should succeed");
    assert_eq!(count, 1, "exactly one agents row for the fixed public key");
}
