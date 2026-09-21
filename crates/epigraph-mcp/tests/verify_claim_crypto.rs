//! Falsifiability regression for MCP `verify_claim` (backlog `49c17386`).
//!
//! Before this fix `verify_claim` was theatre in both halves:
//!
//! * `ClaimRepository::claim_from_row` RECOMPUTED `content_hash` from
//!   `content` instead of projecting `claims.content_hash`, so
//!   `computed_hash == claim.content_hash` compared a value against itself.
//!   `hash_matches` was structurally incapable of being `false`, which is
//!   exactly the property an integrity check exists to have.
//! * It hardcoded `public_key = [0u8; 32]` and `signature = None`, and
//!   `get_by_id`'s SELECT list projected neither `claims.signature` nor the
//!   signer's `agents.public_key`. `signature_valid` therefore took the
//!   `None => false` arm for every claim in the database.
//!
//! Every assertion below is chosen to FAIL against the pre-fix reader, and the
//! fixtures are inserted with raw SQL on purpose: `ClaimRepository::create`
//! derives `content_hash = BLAKE3(content)` itself, so a fixture written
//! through it can never exhibit a stored/computed mismatch and the tampering
//! test would pass over the unmodified code.

use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_mcp::tools::claims::verify_claim;
use epigraph_mcp::types::VerifyClaimParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

/// A claim whose body was mutated without rewriting its digest must FAIL the
/// hash check.
///
/// This is the backlog's headline symptom ("a tampered claim body verifies
/// clean"). `content` and `content_hash` are seeded deliberately inconsistent —
/// the digest is BLAKE3 of the *original* text, the body is the *tampered*
/// text. Pre-fix the reader recomputed the digest from the tampered body, so
/// both sides of the comparison were `BLAKE3(tampered)` and `hash_matches` came
/// back `true`.
#[sqlx::test(migrations = "../../migrations")]
async fn tampered_body_fails_the_hash_check(pool: PgPool) {
    let agent = seed_agent(&pool, &[0x11u8; 32]).await;

    let original = "Diamond mechanosynthesis requires positional control to 0.1 nm.";
    let tampered = "Diamond mechanosynthesis requires positional control to 100 nm.";
    let stored_hash = ContentHasher::hash(original.as_bytes());

    // Body says `tampered`, digest attests `original`.
    let claim_id = insert_claim(&pool, agent, tampered, &stored_hash, None, None).await;

    let resp = run_verify(&pool, claim_id).await;

    assert_eq!(
        resp["hash_matches"],
        Value::Bool(false),
        "a body that does not hash to the STORED content_hash must fail the \
         integrity check; `true` here means the reader recomputed the digest \
         from the tampered body and compared it against itself: {resp}"
    );
}

/// The converse, so the fix cannot be "return false": an untampered claim whose
/// stored digest really is BLAKE3 of its body must PASS.
///
/// Together with the test above this pins `hash_matches` to the row rather than
/// to a constant — it is `true` here and `false` there, over the same code path,
/// with only the stored digest differing.
#[sqlx::test(migrations = "../../migrations")]
async fn intact_body_passes_the_hash_check(pool: PgPool) {
    let agent = seed_agent(&pool, &[0x22u8; 32]).await;

    let content = "Positional assembly of adamantane from CH2 feedstock is exoergic.";
    let stored_hash = ContentHasher::hash(content.as_bytes());

    let claim_id = insert_claim(&pool, agent, content, &stored_hash, None, None).await;

    let resp = run_verify(&pool, claim_id).await;

    assert_eq!(
        resp["hash_matches"],
        Value::Bool(true),
        "an untampered claim must pass the integrity check: {resp}"
    );
}

/// A claim carrying a real Ed25519 signature over its stored digest, signed by
/// an agent whose `agents.public_key` is that signer's key, must verify.
///
/// This is the half the backlog called unpassable. It exercises the whole
/// resolution chain the fix added: `claims.signer_id` → `agents.public_key` →
/// `SignatureVerifier::verify(public_key, stored content_hash, stored
/// signature)`. Pre-fix `signature` was hardcoded `None` and `public_key`
/// hardcoded `[0u8; 32]`, so `signature_valid` was `false` no matter what the
/// row held.
#[sqlx::test(migrations = "../../migrations")]
async fn stored_signature_over_stored_hash_verifies(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x5Eu8; 32]).expect("deterministic signer");
    let public_key = signer.public_key();

    // The signing agent's registered key IS this signer's key.
    let signer_agent = seed_agent(&pool, &public_key).await;

    let content = "Scanning probe tip functionalization is the rate-limiting step.";
    let stored_hash = ContentHasher::hash(content.as_bytes());
    // Same message the production writers sign (`memory.rs`,
    // `ingestion.rs`: `signer.sign(&claim.content_hash)`).
    let signature = signer.sign(&stored_hash);

    let claim_id = insert_claim(
        &pool,
        signer_agent,
        content,
        &stored_hash,
        Some(&signature),
        Some(signer_agent),
    )
    .await;

    let resp = run_verify(&pool, claim_id).await;

    assert_eq!(
        resp["signed"],
        Value::Bool(true),
        "a claim with a non-NULL `claims.signature` must report signed: {resp}"
    );
    assert_eq!(
        resp["signature_valid"],
        Value::Bool(true),
        "a valid signature over the stored digest, by the agent named in \
         signer_id, must verify — `false` means the reader is not projecting \
         claims.signature and/or the signer's agents.public_key: {resp}"
    );
    assert_eq!(
        resp["hash_matches"],
        Value::Bool(true),
        "fixture body hashes to its stored digest: {resp}"
    );
}

/// A signature by the WRONG key must be REJECTED, and reported as
/// `signed: true, signature_valid: false`.
///
/// Without this, "project the signer's key" could be satisfied by projecting
/// any key (e.g. the author's, or a constant) and the passing test above would
/// still be green. Here `signer_id` points at an agent whose registered
/// `public_key` belongs to a different keypair than the one that produced the
/// signature, so verification must fail on key mismatch alone — the body,
/// digest and signature are internally consistent.
#[sqlx::test(migrations = "../../migrations")]
async fn signature_by_a_different_key_is_rejected(pool: PgPool) {
    let real_signer = AgentSigner::from_bytes(&[0x7Au8; 32]).expect("signer");
    let other_signer = AgentSigner::from_bytes(&[0x7Bu8; 32]).expect("other signer");
    assert_ne!(
        real_signer.public_key(),
        other_signer.public_key(),
        "fixture precondition: the two keypairs must differ"
    );

    // The agent registered in `signer_id` carries the OTHER key.
    let signer_agent = seed_agent(&pool, &other_signer.public_key()).await;

    let content = "Vacuum UHV conditions suppress unwanted surface reconstruction.";
    let stored_hash = ContentHasher::hash(content.as_bytes());
    let signature = real_signer.sign(&stored_hash);

    let claim_id = insert_claim(
        &pool,
        signer_agent,
        content,
        &stored_hash,
        Some(&signature),
        Some(signer_agent),
    )
    .await;

    let resp = run_verify(&pool, claim_id).await;

    assert_eq!(
        resp["signed"],
        Value::Bool(true),
        "the signature column is populated: {resp}"
    );
    assert_eq!(
        resp["signature_valid"],
        Value::Bool(false),
        "a signature that does not verify under the signer agent's registered \
         public_key must be rejected: {resp}"
    );
}

/// An unsigned claim must be reported as `signed: false`, not merely
/// `signature_valid: false`.
///
/// `signature_valid` alone conflates "no signature to check" with "signature
/// present and rejected", and while every claim inherited `signature = None`
/// there was no way to tell the two apart. Every row written by today's
/// `ClaimRepository::create*` methods is in this state — none of them insert
/// `signature`/`signer_id` — so this is the common case, and it must be
/// distinguishable from the rejection asserted above.
#[sqlx::test(migrations = "../../migrations")]
async fn unsigned_claim_reports_signed_false(pool: PgPool) {
    let agent = seed_agent(&pool, &[0x33u8; 32]).await;

    let content = "Unsigned claims are the norm on the current write path.";
    let stored_hash = ContentHasher::hash(content.as_bytes());

    let claim_id = insert_claim(&pool, agent, content, &stored_hash, None, None).await;

    let resp = run_verify(&pool, claim_id).await;

    assert_eq!(
        resp["signed"],
        Value::Bool(false),
        "no signature column value => signed: false: {resp}"
    );
    assert_eq!(
        resp["signature_valid"],
        Value::Bool(false),
        "nothing to verify => signature_valid: false: {resp}"
    );
}

async fn run_verify(pool: &PgPool, claim_id: Uuid) -> Value {
    let server = build_test_server(pool.clone());
    let result = verify_claim(
        &server,
        VerifyClaimParams {
            claim_id: claim_id.to_string(),
        },
    )
    .await
    .expect("verify_claim");
    parse_response(&result)
}

fn parse_response(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    serde_json::from_str(&text).expect("response is JSON")
}

async fn seed_agent(pool: &PgPool, public_key: &[u8; 32]) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system')",
    )
    .bind(id)
    .bind(public_key.as_slice())
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

/// Insert a claim row with FULL control over `content_hash`, `signature` and
/// `signer_id`.
///
/// Deliberately raw SQL. `ClaimRepository::create` recomputes
/// `content_hash = BLAKE3(content)` and never writes `signature`/`signer_id`,
/// so no repo method can produce any of the four fixtures above.
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
                             signature, signer_id, labels, is_current) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, ARRAY[]::text[], true)",
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
