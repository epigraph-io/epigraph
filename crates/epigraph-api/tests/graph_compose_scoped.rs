//! `POST /api/v1/graph/compose` composes only over what the caller may read.
//!
//! Deferred-commitment screen key `f-shard4-a1-compose-subgraphs`, recorded on
//! register entry `F-SHARD4-A1`. Before the fix the handler took no `Viewer`
//! and ran all three of its statements (two recursive neighborhood walks and a
//! belief read) on the raw pool. So any bearer:
//!
//! * got neighborhood sizes, a shared boundary and a `consistent` verdict
//!   computed over claims and edges it cannot read;
//! * got a 200 for a center it cannot read, or one that names no claim at all,
//!   because the walk seeded the center as a bare literal and counted it.
//!
//! These tests go through the real router, so they run against the handler
//! whatever its signature. `build_app_for_tests` builds its state through
//! `with_scoped_pool` on the superuser `DATABASE_URL` pool, where no RLS
//! policy filters anything. So on the pre-fix handler the raw-pool reads see
//! every row, and both tests below fail. They were run against the pre-fix
//! handler and did. The executor half (a reversion to the raw pool) is pinned
//! separately, by `belief_computation_scoped_read.rs`'s `compose_subgraphs`
//! arms, which run on a downgraded raw pool.
//!
//! # Fixture shape
//!
//! `a -- h -- b`: two public centers joined only through `h`, a claim private
//! to the owner's personal group. The two `supports` edges are left to
//! migration 070's trigger, which stamps them private to the same group
//! because `h` is. Every claim and edge is fresh, so rows other tests left in
//! the shared `DATABASE_URL` database cannot join the walk.

#![cfg(feature = "db")]

use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

async fn test_pool() -> (String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to test DB");
    (url, pool)
}

/// An agent with a personal group it administers.
async fn seed_principal(pool: &PgPool) -> Uuid {
    let agent = common::seed_system_agent(pool).await;
    common::personal_group_of(pool, agent).await;
    agent
}

/// A claim authored by `author`, declared `(visibility, <author's personal
/// group>)`.
async fn seed_claim(pool: &PgPool, author: Uuid, visibility: &str) -> Uuid {
    let group = common::personal_group_of(pool, author).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             labels, visibility, owner_group_id, pignistic_prob) \
         VALUES ($1, $2, $3, $4, 0.5, true, ARRAY[]::text[], $5, $6, 0.7)",
    )
    .bind(id)
    .bind(format!("graph-compose-scoped claim {id}"))
    .bind(&hash)
    .bind(author)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A `supports` edge, tenancy left to the trigger.
async fn seed_supports(pool: &PgPool, source: Uuid, target: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports')",
    )
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("seed supports edge");
}

/// `(owner, stranger, [a, h, b])`.
async fn seed_graph(pool: &PgPool) -> (Uuid, Uuid, [Uuid; 3]) {
    let owner = seed_principal(pool).await;
    let stranger = seed_principal(pool).await;
    let a = seed_claim(pool, owner, "public").await;
    let h = seed_claim(pool, owner, "group").await;
    let b = seed_claim(pool, owner, "public").await;
    seed_supports(pool, a, h).await;
    seed_supports(pool, h, b).await;
    (owner, stranger, [a, h, b])
}

async fn compose(
    addr: std::net::SocketAddr,
    principal: Uuid,
    center_a: Uuid,
    center_b: Uuid,
) -> (u16, Value) {
    let token = common::test_bearer_token_for_principal(principal, &["graph:read"]);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/graph/compose"))
        .bearer_auth(token)
        .json(&json!({ "center_a": center_a, "center_b": center_b, "max_depth": 1 }))
        .send()
        .await
        .expect("POST /api/v1/graph/compose");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, json)
}

/// A stranger's two neighborhoods neither count nor meet at a claim it cannot
/// read. The owner's compose over the same centers meets at `h`, which is what
/// makes the stranger's empty boundary a filter and not an empty fixture.
#[tokio::test(flavor = "multi_thread")]
async fn a_strangers_compose_neither_counts_nor_meets_at_a_claim_it_cannot_read() {
    let (url, pool) = test_pool().await;
    let (owner, stranger, [a, _h, b]) = seed_graph(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (status, mine) = compose(addr, owner, a, b).await;
    assert_eq!(status, 200, "body={mine}");
    assert_eq!(
        (
            mine["left_boundary"].as_u64(),
            mine["shared_boundary_size"].as_u64(),
            mine["total_nodes"].as_u64()
        ),
        (Some(1), Some(1), Some(3)),
        "CALIBRATION: the owner's neighborhoods meet at its own private claim; body={mine}"
    );

    let (status, theirs) = compose(addr, stranger, a, b).await;
    assert_eq!(status, 200, "both centers are public; body={theirs}");
    assert_eq!(
        (
            theirs["left_boundary"].as_u64(),
            theirs["shared_boundary_size"].as_u64(),
            theirs["total_nodes"].as_u64()
        ),
        (Some(0), Some(0), Some(2)),
        "the stranger's compose must not count, or meet at, the owner's private claim; \
         body={theirs}"
    );
}

/// A center the caller cannot read is a 404, as is an id that names no claim.
/// Before the fix both were a 200 that counted the id as a node.
#[tokio::test(flavor = "multi_thread")]
async fn a_center_the_caller_cannot_read_is_404() {
    let (url, pool) = test_pool().await;
    let (owner, stranger, [a, h, _b]) = seed_graph(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (status, body) = compose(addr, stranger, h, a).await;
    assert_eq!(
        status, 404,
        "a stranger composing around the owner's private claim must get a 404; body={body}"
    );

    let (status, body) = compose(addr, owner, h, a).await;
    assert_eq!(
        status, 200,
        "CALIBRATION: the owner composing around its own private claim is served; \
         body={body}"
    );

    let (status, body) = compose(addr, owner, a, Uuid::new_v4()).await;
    assert_eq!(
        status, 404,
        "an id that names no claim must be the same 404; body={body}"
    );
}
