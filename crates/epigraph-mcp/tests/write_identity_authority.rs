//! Batch H-b, D1: an authenticated MCP write authors and stamps as the CALLER,
//! stdio keeps the server's own agent, and the ownership gate recognises the
//! caller's own claims by `agents.id`.
//!
//! # What a superuser `#[sqlx::test]` can and cannot see here
//!
//! This harness connects BYPASSRLS, so it cannot observe the `42501` a wrong
//! STAMP produces on a clean schema — `scripts/e2e/probe-batch-h.sh`'s
//! `caller_auth` arm measures that through the real binary as `epigraph_app`.
//! What IS data, and therefore visible to a superuser, is WHO the rows name:
//! `claims.agent_id`, `claims.owner_group_id` and `evidence.signer_id`. Before
//! D1 every one of those named the server signer whatever the transport, so the
//! authorship arms below fail on the unconverted tree regardless of role. The
//! gate arm is decided in Rust and is likewise role-independent.
//!
//! Load-bearing, verified by reverting:
//! * `write_identity`'s `Some(auth)` arm returning `self.agent_id()` fails
//!   `an_authenticated_submit_claim_is_authored_and_owned_by_the_caller` and
//!   `an_authenticated_memorize_is_authored_by_the_caller`;
//! * dropping `require_owner_or_admin`'s `caller_agent == target_agent_id` arm
//!   on the HTTP branch fails
//!   `the_callers_own_claim_passes_the_gate_by_agent_id_not_by_client_id`;
//! * naming the author on the evidence row fails
//!   `evidence_names_the_server_as_signer_not_the_caller`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::build_scoped_test_server;
use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_mcp::tools;
use epigraph_mcp::types::{
    MemorizeParams, PatchClaimParams, SubmitClaimParams, UpdateLabelsParams,
};
use sqlx::PgPool;
use uuid::Uuid;

/// A caller's token as `oauth/token.rs` mints it: `sub` / `owner_id` are
/// `oauth_clients` ids, and ONLY `agent_id` is an `agents.id`.
fn caller_token(agent: Uuid, scopes: &[&str]) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Agent,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
    }
}

fn submit(content: &str) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.to_string(),
        methodology: "extraction".to_string(),
        evidence_data: format!("evidence for {content}"),
        evidence_type: "empirical".to_string(),
        confidence: 0.7,
        source_url: None,
        reasoning: None,
        labels: vec![],
        novelty_threshold: Some(0.0),
    }
}

async fn row_of(pool: &PgPool, content: &str) -> (Uuid, Uuid, Uuid) {
    sqlx::query_as("SELECT id, agent_id, owner_group_id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("the submitted claim")
}

async fn claims_with(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_authenticated_submit_claim_is_authored_and_owned_by_the_caller(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = server.server_agent_id().await.expect("server agent");
    let (caller, caller_group) = fixture::seed_agent_with_group(&pool, "d1-caller").await;
    let viewer = Viewer::resolve(&pool, caller).await.expect("caller viewer");
    let token = caller_token(caller, &["claims:read", "claims:write"]);

    let content = "D1: a caller's submit_claim is the caller's claim";
    tools::claims::submit_claim(&server, &viewer, submit(content), Some(&token))
        .await
        .expect("submit as the caller");

    let (_, author, owner_group) = row_of(&pool, content).await;
    assert_ne!(caller, server_agent, "fixture: two distinct agents");
    assert_eq!(
        author, caller,
        "authored by the CALLER (auth.agent_id), not the shared server signer {server_agent}"
    );
    assert_eq!(
        owner_group, caller_group,
        "owned by the caller's personal group, not the server agent's"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn stdio_submit_claim_is_still_authored_by_the_server_agent(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = server.server_agent_id().await.expect("server agent");
    let viewer = Viewer::resolve(&pool, server_agent).await.expect("viewer");

    let content = "D1: stdio authors as the server agent, unchanged";
    tools::claims::submit_claim(&server, &viewer, submit(content), None)
        .await
        .expect("stdio submit");

    let (_, author, _) = row_of(&pool, content).await;
    assert_eq!(
        author, server_agent,
        "no AuthContext: the process is the principal"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn evidence_names_the_server_as_signer_not_the_caller(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = server.server_agent_id().await.expect("server agent");
    let (caller, _) = fixture::seed_agent_with_group(&pool, "d1-signer").await;
    let viewer = Viewer::resolve(&pool, caller).await.expect("caller viewer");
    let token = caller_token(caller, &["claims:write"]);

    let content = "D1: the server key signs the caller's evidence";
    tools::claims::submit_claim(&server, &viewer, submit(content), Some(&token))
        .await
        .expect("submit");
    let (claim, _, _) = row_of(&pool, content).await;

    let signer: Option<Uuid> =
        sqlx::query_scalar("SELECT signer_id FROM evidence WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("the submission's evidence row");
    assert_eq!(
        signer,
        Some(server_agent),
        "the evidence digest is signed with THIS SERVER's key, so its signer_id must name the \
         server agent; naming the caller would verify the signature against the wrong key"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_authenticated_memorize_is_authored_by_the_caller(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (caller, caller_group) = fixture::seed_agent_with_group(&pool, "d1-memo").await;
    let viewer = Viewer::resolve(&pool, caller).await.expect("caller viewer");
    let token = caller_token(caller, &["claims:write"]);

    let content = "D1: a caller's memory is the caller's";
    tools::memory::memorize(
        &server,
        &viewer,
        MemorizeParams {
            content: content.to_string(),
            confidence: None,
            tags: None,
            novelty_threshold: Some(0.0),
        },
        Some(&token),
    )
    .await
    .expect("memorize as the caller");

    let (_, author, owner_group) = row_of(&pool, content).await;
    assert_eq!(author, caller);
    assert_eq!(owner_group, caller_group);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_with_no_agent_principal_writes_nothing(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (caller, _) = fixture::seed_agent_with_group(&pool, "d1-noagent").await;
    let viewer = Viewer::resolve(&pool, caller).await.expect("viewer");
    let mut token = caller_token(caller, &["claims:write"]);
    token.agent_id = None;

    let content = "D1: no agent principal, no author";
    let err = tools::claims::submit_claim(&server, &viewer, submit(content), Some(&token))
        .await
        .expect_err("a token with no agents.id has no author");
    assert!(
        err.message.contains("no agent principal"),
        "named cause: {}",
        err.message
    );
    assert_eq!(claims_with(&pool, content).await, 0, "nothing written");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_viewer_for_another_principal_is_refused_and_writes_nothing(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (caller, _) = fixture::seed_agent_with_group(&pool, "d1-token").await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "d1-viewer").await;
    let others_viewer = Viewer::resolve(&pool, other).await.expect("viewer");
    let token = caller_token(caller, &["claims:write"]);

    let content = "D1: read and write principals must agree";
    let err = tools::claims::submit_claim(&server, &others_viewer, submit(content), Some(&token))
        .await
        .expect_err("a viewer resolved for another agent must not carry this token's write");
    assert!(
        err.message.contains("diverge"),
        "named cause: {}",
        err.message
    );
    assert_eq!(claims_with(&pool, content).await, 0, "nothing written");
}

/// The gate half of D1. The token's `client_id` / `owner_id` are
/// `oauth_clients` ids, so the legacy principal comparison can never match the
/// caller's own claim (authored as `auth.agent_id` since D1). Before the
/// `caller_agent == target` arm, `patch_claim` refused the caller's OWN claim
/// and `update_labels +resolved` refused its OWN backlog item.
#[sqlx::test(migrations = "../../migrations")]
async fn the_callers_own_claim_passes_the_gate_by_agent_id_not_by_client_id(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (caller, _) = fixture::seed_agent_with_group(&pool, "d1-gate").await;
    let viewer = Viewer::resolve(&pool, caller).await.expect("caller viewer");
    let token = caller_token(caller, &["claims:read", "claims:write"]);

    let content = "D1: the caller patches its own claim";
    tools::claims::submit_claim(&server, &viewer, submit(content), Some(&token))
        .await
        .expect("submit");
    let (claim, author, _) = row_of(&pool, content).await;
    assert_eq!(author, caller);

    tools::claims::patch_claim(
        &server,
        &viewer,
        PatchClaimParams {
            claim_id: claim.to_string(),
            trace_id: None,
            properties: Some(serde_json::json!({"d1": true})),
            add_labels: vec![],
            remove_labels: vec![],
        },
        Some(&token),
    )
    .await
    .expect("the author's own patch_claim must pass require_owner_or_admin");

    tools::claims::update_labels(
        &server,
        &viewer,
        UpdateLabelsParams {
            claim_id: claim.to_string(),
            add: vec!["resolved".to_string()],
            remove: vec![],
        },
        Some(&token),
    )
    .await
    .expect("the author may retire its own item");

    let (props, labels): (serde_json::Value, Vec<String>) =
        sqlx::query_as("SELECT properties, labels FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("re-read");
    assert_eq!(props["d1"], serde_json::json!(true), "patch landed");
    assert!(labels.iter().any(|l| l == "resolved"), "label landed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_foreign_claim_is_still_refused_over_http(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (caller, _) = fixture::seed_agent_with_group(&pool, "d1-stranger").await;
    let (owner, _) = fixture::seed_agent_with_group(&pool, "d1-owner").await;
    let claim = fixture::seed_public_claim(&pool, owner, "D1: someone else's claim").await;
    let viewer = Viewer::resolve(&pool, caller).await.expect("viewer");
    let token = caller_token(caller, &["claims:read", "claims:write"]);

    let err = tools::claims::patch_claim(
        &server,
        &viewer,
        PatchClaimParams {
            claim_id: claim.to_string(),
            trace_id: None,
            properties: Some(serde_json::json!({"d1": "foreign"})),
            add_labels: vec![],
            remove_labels: vec![],
        },
        Some(&token),
    )
    .await
    .expect_err("not the author, not its operator, no claims:admin");
    assert!(err.message.contains("cannot retire it"), "{}", err.message);
    let props: serde_json::Value =
        sqlx::query_scalar("SELECT COALESCE(properties, '{}'::jsonb) FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("re-read");
    assert!(props.get("d1").is_none(), "nothing written: {props}");
}
