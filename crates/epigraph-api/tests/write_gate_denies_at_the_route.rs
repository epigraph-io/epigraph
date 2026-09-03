#![cfg(feature = "db")]
//! PR-11 — the write gate's **verdict** is honoured, at the route.
//!
//! # Why this file exists
//!
//! `write_gate_call_sites.rs` proves the gate is *called*; `epigraph-authz`'s
//! unit tests and `tests/fail_closed.rs` prove the gate *decides correctly*.
//! Neither proves the handler does anything with the answer. A handler that ran
//! `authorize(...)` and dropped the `Decision` on the floor passed every other
//! test PR-11 ships — which is precisely the failure mode PR-11 exists to fix,
//! one layer up: `AppState.policy_gate` was constructed, stored and never
//! consulted, and nothing in the tree noticed for the life of the field.
//!
//! An earlier revision of `write_gate_call_sites.rs` attributed this coverage to
//! `routes/negative_tests.rs`. It does not provide it: its two ownership cases
//! assert extractor *ordering* (wrong-scope 403 rather than 422), and
//! `RequireScopeAdmin` rejects those requests before `require_declassify_authority`
//! is reached — which is why they still pass unchanged across this PR.
//!
//! # Every denial here is paired with a positive control
//!
//! A 403 assertion on its own is satisfied by a route that is broken, missing,
//! or refusing for a completely different reason. Each case therefore drives the
//! **same request** twice — once with a token whose `agent_id` is the owner of
//! record and once with a stranger's — and asserts the owner succeeds. That is
//! what makes it evidence about the *gate* rather than about the route existing.
//!
//! Both tokens carry `claims:admin`, so the scope extractor is satisfied in both
//! runs and cannot be the thing that differs. The only variable is the principal.

mod common;

use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool_and_app() -> (
    sqlx::PgPool,
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool");
    let (addr, shutdown) = common::spawn_app(&url).await;
    (pool, addr, shutdown)
}

/// Seed an agent (via a throwaway claim, which creates the `agents` row) and
/// return its id.
async fn seed_agent(pool: &sqlx::PgPool, label: &str) -> Uuid {
    let agent = Uuid::new_v4();
    common::seed_claim_with_agent(pool, &format!("pr11 write-gate fixture {label}"), agent).await;
    agent
}

// ── PUT /api/v1/ownership/:node_id — the declassification primitive ─────────

/// The stranger is refused and the owner is not. Both hold `claims:admin`.
#[tokio::test]
async fn update_partition_denies_a_non_owner_and_allows_the_owner() {
    let (pool, addr, shutdown) = pool_and_app().await;

    let owner = seed_agent(&pool, "update-owner").await;
    let stranger = seed_agent(&pool, "update-stranger").await;
    let node = common::seed_claim_with_agent(&pool, "pr11 update_partition target", owner).await;
    common::seed_private_ownership(&pool, node, owner).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/ownership/{node}");

    // NEGATIVE — a claims:admin token for an agent who is not the owner.
    let resp = client
        .put(&url)
        .bearer_auth(common::mint_token_with_agent(&["claims:admin"], stranger))
        .json(&json!({ "partition_type": "public" }))
        .send()
        .await
        .expect("stranger update_partition");
    assert_eq!(
        resp.status(),
        403,
        "a claims:admin token whose principal is not the owner of record must be \
         refused BY THE GATE. Body: {}",
        resp.text().await.unwrap_or_default()
    );

    // The write must not have happened.
    let after: String =
        sqlx::query_scalar("SELECT partition_type FROM ownership WHERE node_id = $1")
            .bind(node)
            .fetch_one(&pool)
            .await
            .expect("read back partition");
    assert_eq!(
        after, "private",
        "the denial must be a refusal to write, not a 403 emitted after the write"
    );

    // POSITIVE CONTROL — the owner, same request, same scope.
    let resp = client
        .put(&url)
        .bearer_auth(common::mint_token_with_agent(&["claims:admin"], owner))
        .json(&json!({ "partition_type": "public" }))
        .send()
        .await
        .expect("owner update_partition");
    assert_eq!(
        resp.status(),
        200,
        "the owner of record must still be able to change the partition — without \
         this the 403 above would be evidence of nothing. Body: {}",
        resp.text().await.unwrap_or_default()
    );

    let after: String =
        sqlx::query_scalar("SELECT partition_type FROM ownership WHERE node_id = $1")
            .bind(node)
            .fetch_one(&pool)
            .await
            .expect("read back partition");
    assert_eq!(after, "public");

    let _ = shutdown.send(());
}

// ── POST /api/v1/ownership — reassignment and first assignment ──────────────

/// A node someone else already owns cannot be reassigned by a stranger.
#[tokio::test]
async fn assign_ownership_denies_reassignment_by_a_non_owner() {
    let (pool, addr, shutdown) = pool_and_app().await;

    let owner = seed_agent(&pool, "assign-owner").await;
    let stranger = seed_agent(&pool, "assign-stranger").await;
    let node = common::seed_claim_with_agent(&pool, "pr11 assign_ownership target", owner).await;
    common::seed_private_ownership(&pool, node, owner).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/ownership");
    let body = json!({
        "node_id": node,
        "node_type": "claim",
        "partition_type": "public",
        "owner_id": stranger,
    });

    let resp = client
        .post(&url)
        .bearer_auth(common::mint_token_with_agent(&["claims:admin"], stranger))
        .json(&body)
        .send()
        .await
        .expect("stranger assign_ownership");
    assert_eq!(
        resp.status(),
        403,
        "seizing a node that already has an owner must be refused. Body: {}",
        resp.text().await.unwrap_or_default()
    );

    let still: Uuid = sqlx::query_scalar("SELECT owner_id FROM ownership WHERE node_id = $1")
        .bind(node)
        .fetch_one(&pool)
        .await
        .expect("read back owner");
    assert_eq!(still, owner, "the owner of record must be unchanged");

    // POSITIVE CONTROL — the owner of record may reassign their own node.
    let resp = client
        .post(&url)
        .bearer_auth(common::mint_token_with_agent(&["claims:admin"], owner))
        .json(&body)
        .send()
        .await
        .expect("owner assign_ownership");
    assert_eq!(
        resp.status(),
        201,
        "the owner of record must still be able to reassign. Body: {}",
        resp.text().await.unwrap_or_default()
    );

    let _ = shutdown.send(());
}

/// The self-claim rule, both halves: an unowned node may be claimed **to
/// yourself** and to nobody else.
///
/// This is the case the gate's owner slot is most easily got wrong on — it is
/// the one branch where a *request-derived* value reaches the decision at all —
/// so both halves are asserted rather than only the permissive one.
#[tokio::test]
async fn assign_ownership_on_an_unclaimed_node_is_self_only() {
    let (pool, addr, shutdown) = pool_and_app().await;

    let claimant = seed_agent(&pool, "claimant").await;
    let third_party = seed_agent(&pool, "third-party").await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/ownership");

    // NEGATIVE — first assignment TO SOMEONE ELSE on an unowned node.
    let foreign_node =
        common::seed_claim_with_agent(&pool, "pr11 unclaimed foreign", claimant).await;
    let resp = client
        .post(&url)
        .bearer_auth(common::mint_token_with_agent(&["claims:admin"], claimant))
        .json(&json!({
            "node_id": foreign_node,
            "node_type": "claim",
            "partition_type": "public",
            "owner_id": third_party,
        }))
        .send()
        .await
        .expect("third-party first assignment");
    assert_eq!(
        resp.status(),
        403,
        "PR-11 narrows claims:admin: an unowned node may not be assigned to a \
         third party. This is a BREAKING CHANGE and is pinned deliberately. \
         Body: {}",
        resp.text().await.unwrap_or_default()
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM ownership WHERE node_id = $1")
        .bind(foreign_node)
        .fetch_one(&pool)
        .await
        .expect("count ownership rows");
    assert_eq!(
        rows, 0,
        "the refused assignment must not have written a row"
    );

    // POSITIVE — the same caller claiming the same shape of node for itself.
    let own_node = common::seed_claim_with_agent(&pool, "pr11 unclaimed self", claimant).await;
    let resp = client
        .post(&url)
        .bearer_auth(common::mint_token_with_agent(&["claims:admin"], claimant))
        .json(&json!({
            "node_id": own_node,
            "node_type": "claim",
            "partition_type": "public",
            "owner_id": claimant,
        }))
        .send()
        .await
        .expect("self first assignment");
    assert_eq!(
        resp.status(),
        201,
        "claiming an unowned node to yourself must remain possible, or \
         assign_ownership has no reachable success path at all. Body: {}",
        resp.text().await.unwrap_or_default()
    );

    let _ = shutdown.send(());
}
