//! Batch H-b, D1-sig: a claim AUTHORED by an authenticated caller and SIGNED by
//! the MCP server verifies.
//!
//! # The measurement that decided the design
//!
//! `verify_claim` checks the stored Ed25519 signature against
//! `claims.signer_id -> agents.public_key` (`ClaimRepository::get_by_id`'s
//! crypto post-fix), never against `claims.agent_id`'s key. And before this
//! change NO MCP write persisted a signature at all: `create_strict` inserted
//! neither `signature` nor `signer_id`, so every MCP-written claim reported
//! `signed: false`. The feared "mismatch" (a caller-authored claim checked
//! against the caller's keyless `derived` agent) therefore could not occur, but
//! "reports valid" was unreachable too.
//!
//! The resolution records the SIGNER apart from the author: the submission path
//! stores the server's signature with `signer_id` = the server's agent, and
//! `agent_id` stays the caller. Verification is unchanged and not weakened: it
//! still requires a signature that verifies under the recorded signer's key.
//!
//! Load-bearing, verified by reverting: `create_claim_idempotent` passing `None`
//! for the signer (the pre-H-b shape) fails every `signed` arm below.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_caller};
use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use epigraph_mcp::tools;
use epigraph_mcp::types::{SubmitClaimParams, VerifyClaimParams};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

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

async fn verify(server: &epigraph_mcp::EpiGraphMcpFull, viewer: &Viewer, claim: Uuid) -> Value {
    let out = tools::claims::verify_claim(
        server,
        viewer,
        VerifyClaimParams {
            claim_id: claim.to_string(),
        },
    )
    .await
    .expect("verify_claim");
    common::first_text(&out)
}

async fn author_and_signer(pool: &PgPool, content: &str) -> (Uuid, Uuid, Option<Uuid>) {
    sqlx::query_as("SELECT id, agent_id, signer_id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("the claim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_authored_claim_signed_by_the_server_verifies(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = server.server_agent_id().await.expect("server agent");
    let (caller, token, viewer) = seed_caller(&pool, &["claims:read", "claims:write"]).await;

    let content = "D1-sig: authored by the caller, signed by the server";
    tools::claims::submit_claim(&server, &viewer, submit(content), Some(&token))
        .await
        .expect("submit as the caller");
    let (claim, author, signer) = author_and_signer(&pool, content).await;

    assert_eq!(author, caller, "the AUTHOR is the caller");
    assert_eq!(
        signer,
        Some(server_agent),
        "the SIGNER is the server's agent"
    );

    let resp = verify(&server, &viewer, claim).await;
    assert_eq!(resp["signed"], Value::Bool(true), "{resp}");
    assert_eq!(
        resp["signature_valid"],
        Value::Bool(true),
        "a caller-authored claim must verify against its signer's key: {resp}"
    );
    assert_eq!(resp["hash_check"], "match", "{resp}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_claim_verifies_with_the_server_as_author_and_signer(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = server.server_agent_id().await.expect("server agent");
    let viewer = Viewer::resolve(&pool, server_agent).await.expect("viewer");

    let content = "D1-sig: a stdio claim is signed too";
    tools::claims::submit_claim(&server, &viewer, submit(content), None)
        .await
        .expect("stdio submit");
    let (claim, author, signer) = author_and_signer(&pool, content).await;
    assert_eq!((author, signer), (server_agent, Some(server_agent)));

    let resp = verify(&server, &viewer, claim).await;
    assert_eq!(resp["signed"], Value::Bool(true), "{resp}");
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
}

/// The repo refuses to store a signature it cannot verify: over a digest other
/// than the `blake3(content)` it stores, a stored signature would read as
/// tampering on every `verify_claim`. The row is still written, unsigned.
#[sqlx::test(migrations = "../../migrations")]
async fn a_signature_over_another_digest_is_not_stored(pool: PgPool) {
    let (author, _, _) = seed_caller(&pool, &[]).await;
    let signer = AgentSigner::from_bytes(&[0x3Cu8; 32]).expect("signer");
    let content = "D1-sig: signed over the wrong digest";
    let mut claim = Claim::new(
        content.to_string(),
        AgentId::from_uuid(author),
        signer.public_key(),
        TruthValue::clamped(0.5),
    );
    claim.content_hash = ContentHasher::hash(content.as_bytes());
    claim.signature = Some(signer.sign(&ContentHasher::hash(b"some other body")));

    let group = common::personal_group_of(&pool, author).await;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::create_strict_signed(
        &mut conn,
        &claim,
        epigraph_core::TenancyDecl::public(group),
        Some(author),
    )
    .await
    .expect("the claim itself is written");

    let (_, _, stored_signer) = author_and_signer(&pool, content).await;
    let sig: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT signature FROM claims WHERE content = $1")
            .bind(content)
            .fetch_one(&pool)
            .await
            .expect("signature column");
    assert_eq!(
        (sig, stored_signer),
        (None, None),
        "an unverifiable signature must not be stored"
    );
}
