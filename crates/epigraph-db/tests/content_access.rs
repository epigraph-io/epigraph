//! Partition access checks (`epigraph_db::access_control`) against a real
//! schema.
//!
//! Each case gets its own `#[sqlx::test]` database, so the seeded ownership
//! rows are the only ones and a failure injected into one case (a renamed
//! table, a closed pool) cannot leak into another.

use epigraph_db::access_control::{check_content_access, ContentAccess};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .unwrap();
    id
}

/// `ownership.owner_id` is an FK to `agents`, so owners are seeded agents.
async fn seed_ownership(
    pool: &PgPool,
    node_id: Uuid,
    partition: &str,
    owner_id: Uuid,
    encryption_key_id: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, encryption_key_id) \
         VALUES ($1, 'claim', $2, $3, $4)",
    )
    .bind(node_id)
    .bind(partition)
    .bind(owner_id)
    .bind(encryption_key_id)
    .execute(pool)
    .await
    .unwrap();
}

// ── Fail closed ─────────────────────────────────────────────────────────────

/// A failed ownership lookup must redact. Before the fix the error was
/// swallowed into "no ownership row", which is read as public, so every node —
/// private ones included — came back `Full` to every requester.
#[sqlx::test(migrations = "../../migrations")]
async fn ownership_lookup_error_redacts_instead_of_serving_full(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let stranger = Uuid::new_v4();
    let private_node = Uuid::new_v4();
    let public_node = Uuid::new_v4();
    let bare_node = Uuid::new_v4(); // no ownership row
    seed_ownership(&pool, private_node, "private", owner, None).await;
    seed_ownership(&pool, public_node, "public", owner, None).await;

    // Baseline while the lookup works, so the post-failure assertions below are
    // about the failure and not about the fixtures.
    assert_eq!(
        check_content_access(&pool, private_node, Some(stranger)).await,
        ContentAccess::Redacted
    );
    assert_eq!(
        check_content_access(&pool, private_node, Some(owner)).await,
        ContentAccess::Full
    );
    assert_eq!(
        check_content_access(&pool, public_node, None).await,
        ContentAccess::Full
    );
    assert_eq!(
        check_content_access(&pool, bare_node, None).await,
        ContentAccess::Full
    );

    // Every ownership lookup now errors ("relation does not exist").
    sqlx::query("ALTER TABLE ownership RENAME TO ownership_unavailable")
        .execute(&pool)
        .await
        .unwrap();

    for node in [private_node, public_node, bare_node] {
        for requester in [None, Some(stranger), Some(owner)] {
            assert_eq!(
                check_content_access(&pool, node, requester).await,
                ContentAccess::Redacted,
                "node {node} requester {requester:?}: a lookup error must redact"
            );
        }
    }
}

/// The pool-exhaustion shape of the same failure: acquiring a connection
/// fails, the query never runs, and the private node stays redacted.
#[sqlx::test(migrations = "../../migrations")]
async fn closed_pool_redacts_a_private_node(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let stranger = Uuid::new_v4();
    let private_node = Uuid::new_v4();
    seed_ownership(&pool, private_node, "private", owner, None).await;

    pool.close().await;

    for requester in [None, Some(stranger), Some(owner)] {
        assert_eq!(
            check_content_access(&pool, private_node, requester).await,
            ContentAccess::Redacted,
            "requester {requester:?}: an unreachable database must redact"
        );
    }
}
