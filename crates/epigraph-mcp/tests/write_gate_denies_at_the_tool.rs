//! PR-11 — the write gate's **verdict** is honoured at the MCP ownership tools,
//! and the tool's default owner is the CALLER rather than the server.
//!
//! # Why this file exists
//!
//! The HTTP twin of these assertions lives in
//! `epigraph-api/tests/write_gate_denies_at_the_route.rs`. This one is not a
//! duplicate of it: the MCP arm has a defect shape the HTTP arm structurally
//! cannot have, and it is the reason this file was written.
//!
//! `AssignOwnershipRequest.owner_id` is a **required** body field on HTTP, so
//! there is no default to get wrong. `AssignOwnershipParams.owner_id` is
//! **optional**, and PR-11's first pass defaulted it to
//! `EpiGraphMcpFull::agent_id()` — the server's own signing-key agent
//! (`server.rs::agent_id` → `AgentRepository::get_by_public_key(self.signer…)`),
//! not the requester. On stdio those are the same identity
//! (`tools/viewer.rs::request_viewer` resolves `server.agent_id()` when there is
//! no `AuthContext`), so a fully green suite saw nothing. On the HTTP transport
//! the principal is the caller's agent, so the gate compared the *server's* id
//! against the *caller's* and refused every first assignment by anyone but the
//! server. That is a false denial of the tool's most ordinary call.
//!
//! Every test below therefore resolves a viewer for an agent that is **not** the
//! server's agent — the HTTP-transport shape — which is exactly the condition
//! that made the defect invisible when it was absent.
//!
//! # Each denial is paired with a positive control
//!
//! A test that only asserts `is_err()` is satisfied by a tool that is broken for
//! any reason at all. Each case runs the same call twice, varying only the
//! principal, and asserts the authorized principal succeeds.

mod common;

use common::build_test_server;
use epigraph_db::visibility::Viewer;
use epigraph_mcp::tools::perspectives::{assign_ownership, update_partition};
use epigraph_mcp::types::{AssignOwnershipParams, UpdatePartitionParams};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(format!("pr11 mcp write-gate fixture {id}"))
    .bind(&hash)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn seed_ownership(pool: &PgPool, node: Uuid, owner: Uuid, partition: &str) {
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', $2, $3) \
         ON CONFLICT (node_id) DO UPDATE SET partition_type = $2, owner_id = $3",
    )
    .bind(node)
    .bind(partition)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed ownership");
}

fn assign_params(node: Uuid, owner: Option<Uuid>) -> AssignOwnershipParams {
    AssignOwnershipParams {
        node_id: node.to_string(),
        node_type: Some("claim".to_string()),
        partition_type: Some("public".to_string()),
        owner_id: owner.map(|o| o.to_string()),
        community_id: None,
    }
}

/// The declassification primitive refuses a principal who is not the owner of
/// record, and does not refuse the one who is.
#[sqlx::test(migrations = "../../migrations")]
async fn update_partition_denies_a_non_owner_and_allows_the_owner(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let owner = seed_agent(&pool).await;
    let stranger = seed_agent(&pool).await;
    let node = seed_claim(&pool, owner).await;
    seed_ownership(&pool, node, owner, "private").await;

    let params = || UpdatePartitionParams {
        node_id: node.to_string(),
        partition_type: "public".to_string(),
    };

    let stranger_viewer = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");
    let denied = update_partition(&server, &stranger_viewer, params()).await;
    assert!(
        denied.is_err(),
        "a principal who is not the owner of record must be refused; got {denied:?}"
    );

    let after: String =
        sqlx::query_scalar("SELECT partition_type FROM ownership WHERE node_id = $1")
            .bind(node)
            .fetch_one(&pool)
            .await
            .expect("read back partition");
    assert_eq!(
        after, "private",
        "the denial must be a refusal to write, not an error raised after the write"
    );

    let owner_viewer = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    update_partition(&server, &owner_viewer, params())
        .await
        .expect("the owner of record must still be able to declassify");

    let after: String =
        sqlx::query_scalar("SELECT partition_type FROM ownership WHERE node_id = $1")
            .bind(node)
            .fetch_one(&pool)
            .await
            .expect("read back partition");
    assert_eq!(after, "public");
}

/// A node with an owner may not be seized by anyone else.
#[sqlx::test(migrations = "../../migrations")]
async fn assign_ownership_denies_reassignment_by_a_non_owner(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let owner = seed_agent(&pool).await;
    let stranger = seed_agent(&pool).await;
    let node = seed_claim(&pool, owner).await;
    seed_ownership(&pool, node, owner, "private").await;

    let stranger_viewer = Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger");
    let denied = assign_ownership(
        &server,
        &stranger_viewer,
        assign_params(node, Some(stranger)),
    )
    .await;
    assert!(
        denied.is_err(),
        "reassigning an owned node must be refused; got {denied:?}"
    );

    let still: Uuid = sqlx::query_scalar("SELECT owner_id FROM ownership WHERE node_id = $1")
        .bind(node)
        .fetch_one(&pool)
        .await
        .expect("read back owner");
    assert_eq!(still, owner);

    let owner_viewer = Viewer::resolve(&pool, owner).await.expect("resolve owner");
    assign_ownership(&server, &owner_viewer, assign_params(node, Some(owner)))
        .await
        .expect("the owner of record must still be able to reassign");
}

/// **The regression this file exists for.** With `owner_id` omitted, the tool
/// must claim the node for the CALLER.
///
/// The viewer here is resolved for a freshly seeded agent, so
/// `viewer.principal() != server.agent_id()` — the HTTP-transport shape. Under
/// the old `server.agent_id()` default the gate compared the server's id against
/// the caller's and this call returned an error; under the fixed default it
/// succeeds and writes the CALLER as owner. Asserting the written `owner_id`
/// (not merely that the call returned `Ok`) is what makes this a test of *which
/// identity* was used rather than of the gate being permissive.
#[sqlx::test(migrations = "../../migrations")]
async fn assign_ownership_with_no_owner_id_claims_the_node_for_the_caller(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let caller = seed_agent(&pool).await;
    let node = seed_claim(&pool, caller).await;

    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");
    assign_ownership(&server, &viewer, assign_params(node, None))
        .await
        .expect("omitting owner_id must mean 'claim this for me', not 'give it to the server'");

    let written: Uuid = sqlx::query_scalar("SELECT owner_id FROM ownership WHERE node_id = $1")
        .bind(node)
        .fetch_one(&pool)
        .await
        .expect("read back owner");
    assert_eq!(
        written, caller,
        "an omitted owner_id must default to the requesting principal. It \
         previously defaulted to the server's own agent row, which is the same \
         identity on stdio and a different one on every HTTP call."
    );
}

/// The other half of the self-claim rule: an unowned node may not be handed to
/// a third party.
#[sqlx::test(migrations = "../../migrations")]
async fn assign_ownership_on_an_unclaimed_node_refuses_a_third_party(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let caller = seed_agent(&pool).await;
    let third_party = seed_agent(&pool).await;
    let node = seed_claim(&pool, caller).await;

    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");
    let denied = assign_ownership(&server, &viewer, assign_params(node, Some(third_party))).await;
    assert!(
        denied.is_err(),
        "an unowned node may be claimed only to yourself; got {denied:?}"
    );

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM ownership WHERE node_id = $1")
        .bind(node)
        .fetch_one(&pool)
        .await
        .expect("count ownership rows");
    assert_eq!(
        rows, 0,
        "the refused assignment must not have written a row"
    );
}

/// The gate that runs is the **installed** one, not a `GroupPolicyGate`
/// constructed inside the helper.
///
/// PR-11's first pass built `epigraph_authz::GroupPolicyGate::new()` inline in
/// `require_declassify_authority`, so `EpiGraphMcpFull` had no way to be given a
/// policy and `AppState::with_policy_gate` reached the HTTP surface only. This
/// installs a gate that denies everything and asserts the owner of record — who
/// the default gate allows — is now refused. Nothing else in the suite can tell
/// the two wirings apart.
#[sqlx::test(migrations = "../../migrations")]
async fn the_installed_gate_is_the_one_that_decides(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let node = seed_claim(&pool, owner).await;
    seed_ownership(&pool, node, owner, "private").await;
    let viewer = Viewer::resolve(&pool, owner).await.expect("resolve owner");

    let params = || UpdatePartitionParams {
        node_id: node.to_string(),
        partition_type: "public".to_string(),
    };

    // Baseline: the default gate allows the owner.
    let default_server = build_test_server(pool.clone());
    update_partition(&default_server, &viewer, params())
        .await
        .expect("the default gate allows the owner of record");
    seed_ownership(&pool, node, owner, "private").await;

    // Same call, same principal, deny-all gate installed.
    let strict_server = build_test_server(pool.clone()).with_policy_gate(std::sync::Arc::new(
        epigraph_interfaces::DenyAllPolicyGate::new(),
    ));
    let denied = update_partition(&strict_server, &viewer, params()).await;
    assert!(
        denied.is_err(),
        "with_policy_gate must reach the MCP surface: a deployment that installs \
         a stricter gate and gets it only on HTTP is a fail-open on the transport \
         where `enforce_tool_scope` does not run. Got {denied:?}"
    );

    let after: String =
        sqlx::query_scalar("SELECT partition_type FROM ownership WHERE node_id = $1")
            .bind(node)
            .fetch_one(&pool)
            .await
            .expect("read back partition");
    assert_eq!(after, "private");
}
