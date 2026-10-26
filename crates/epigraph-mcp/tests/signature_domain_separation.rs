//! Ruling R-34 / backlog `1a79c4d9`: signatures are domain-separated by entity
//! type, and the claim verifier is versioned.
//!
//! Before v1 every writer signed the BARE content digest, so a signature over
//! an evidence row's hash `H` was, byte for byte, a valid claim signature over
//! any claim whose content hash is `H`. v1 signs
//! `b"epigraph-sig-v1:<claim|evidence|edge>:" || digest` instead; the verifier
//! tries v1 first and then the legacy bare digest, and says which verified.
//!
//! The rows here are written with raw SQL on purpose: a fixture written through
//! the MCP writers could only ever carry what those writers sign, and these
//! tests pin what the VERIFIER accepts.

mod common;

use common::build_test_server;
use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_crypto::{AgentSigner, ContentHasher, SignedEntity};
use epigraph_db::ClaimRepository;
use epigraph_mcp::tools::claims::verify_claim;
use epigraph_mcp::types::VerifyClaimParams;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// A claim signed under v1 (claim-tagged) verifies and reports `v1`.
///
/// RED before the versioned verifier: `bind_signature` checked the signature
/// over the bare digest only, so a v1 signature reported
/// `signature_valid: false` and no MCP writer could move to v1.
#[sqlx::test(migrations = "../../migrations")]
async fn a_v1_claim_signature_verifies_as_v1(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x61u8; 32]).expect("signer");
    let agent = seed_agent(&pool, &signer.public_key()).await;
    let content = "R-34: a claim signed under the tagged scheme.";
    let h = ContentHasher::hash(content.as_bytes());
    let sig = signer.sign_entity(SignedEntity::Claim, &h);
    let claim = insert_claim(&pool, agent, content, &h, Some(&sig), Some(agent)).await;

    let resp = run_verify(&pool, claim).await;
    assert_eq!(resp["signed"], Value::Bool(true), "{resp}");
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
    assert_eq!(resp["signature_scheme"], "v1", "{resp}");
    assert_eq!(resp["hash_check"], "match", "{resp}");
}

/// A row signed before v1 (bare digest) keeps verifying, reported `legacy`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_bare_digest_claim_signature_still_verifies_as_legacy(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x62u8; 32]).expect("signer");
    let agent = seed_agent(&pool, &signer.public_key()).await;
    let content = "R-34: a claim signed over the bare digest, before v1.";
    let h = ContentHasher::hash(content.as_bytes());
    let sig = signer.sign(&h);
    let claim = insert_claim(&pool, agent, content, &h, Some(&sig), Some(agent)).await;

    let resp = run_verify(&pool, claim).await;
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
    assert_eq!(resp["signature_scheme"], "legacy", "{resp}");
}

/// The cross-type substitution the backlog names: the signer's EVIDENCE
/// signature over `H`, copied onto a claim whose content hash is `H`, is not a
/// claim signature. It is present (`signed`) and rejected.
#[sqlx::test(migrations = "../../migrations")]
async fn an_evidence_signature_copied_onto_a_claim_does_not_verify(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x63u8; 32]).expect("signer");
    let agent = seed_agent(&pool, &signer.public_key()).await;
    let content = "R-34: the same text, once as evidence and once as a claim.";
    let h = ContentHasher::hash(content.as_bytes());
    let evidence_sig = signer.sign_entity(SignedEntity::Evidence, &h);
    let claim = insert_claim(&pool, agent, content, &h, Some(&evidence_sig), Some(agent)).await;

    let resp = run_verify(&pool, claim).await;
    assert_eq!(resp["signed"], Value::Bool(true), "{resp}");
    assert_eq!(
        resp["signature_valid"],
        Value::Bool(false),
        "an evidence-tagged signature verified a claim: {resp}"
    );
    assert_eq!(resp["signature_scheme"], Value::Null, "{resp}");
}

/// The write side: `create_strict_signed` stores a signature only when it
/// verifies as a CLAIM signature. A v1 claim signature is stored (RED before:
/// it checked the bare digest and silently dropped it), an evidence-tagged one
/// over the same digest is not.
#[sqlx::test(migrations = "../../migrations")]
async fn create_strict_signed_stores_only_claim_signatures(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x64u8; 32]).expect("signer");
    let author = seed_agent(&pool, &signer.public_key()).await;
    let group = common::personal_group_of(&pool, author).await;

    for (content, kind, stored) in [
        ("R-34: stored, claim-tagged.", SignedEntity::Claim, true),
        (
            "R-34: dropped, evidence-tagged.",
            SignedEntity::Evidence,
            false,
        ),
        ("R-34: dropped, edge-tagged.", SignedEntity::Edge, false),
    ] {
        let mut claim = Claim::new(
            content.to_string(),
            AgentId::from_uuid(author),
            signer.public_key(),
            TruthValue::clamped(0.5),
        );
        claim.content_hash = ContentHasher::hash(content.as_bytes());
        claim.signature = Some(signer.sign_entity(kind, &claim.content_hash));
        let mut conn = pool.acquire().await.expect("acquire");
        ClaimRepository::create_strict_signed(
            &mut conn,
            &claim,
            epigraph_core::TenancyDecl::public(group),
            Some(author),
        )
        .await
        .expect("the claim itself is written");

        let (sig, signer_id): (Option<Vec<u8>>, Option<Uuid>) =
            sqlx::query_as("SELECT signature, signer_id FROM claims WHERE content = $1")
                .bind(content)
                .fetch_one(&pool)
                .await
                .expect("row");
        assert_eq!(
            (sig.is_some(), signer_id.is_some()),
            (stored, stored),
            "{kind:?}-tagged signature stored = {stored} expected"
        );
    }
}

async fn run_verify(pool: &PgPool, claim_id: Uuid) -> Value {
    let (agent_id,): (Uuid,) = sqlx::query_as("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("fixture claim must exist");
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent_id)
        .await
        .expect("resolve author viewer");
    let server = build_test_server(pool.clone());
    let result = verify_claim(
        &server,
        &viewer,
        VerifyClaimParams {
            claim_id: claim_id.to_string(),
        },
    )
    .await
    .expect("verify_claim");
    common::first_text(&result)
}

async fn seed_agent(pool: &PgPool, public_key: &[u8; 32]) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(public_key.as_slice())
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn insert_claim(
    pool: &PgPool,
    agent_id: Uuid,
    content: &str,
    content_hash: &[u8],
    signature: Option<&[u8]>,
    signer_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             signature, signer_id, labels, is_current, properties) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, ARRAY[]::text[], true, '{}'::jsonb)",
    )
    .bind(id)
    .bind(content)
    .bind(content_hash)
    .bind(agent_id)
    .bind(signature)
    .bind(signer_id)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}
