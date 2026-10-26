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

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, build_test_server};
use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_crypto::{
    AgentSigner, ContentHasher, SignatureScheme, SignatureVerifier, SignedEntity,
};
use epigraph_db::ClaimRepository;
use epigraph_mcp::tools::claims::verify_claim;
use epigraph_mcp::types::{
    MemorizeParams, ReportWorkflowOutcomeParams, StepExecution, SubmitClaimParams,
    UpdateWithEvidenceParams, VerifyClaimParams,
};
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

/// The cross-type substitution the backlog names: the signer's v1 EVIDENCE
/// signature over `H`, copied onto a claim whose content hash is `H`, is not a
/// claim signature. It is present (`signed`) and rejected.
///
/// A REGRESSION GUARD, not a red: a v1-tagged signature verified nowhere before
/// this branch, so this also passes on the base. The substitution that DID
/// work on the base (a legacy bare-digest evidence signature) is the next test.
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

/// The ruled residual exposure (R-34: legacy stays verifiable): a LEGACY
/// evidence signature is a bare-digest signature, byte for byte the same as a
/// legacy claim signature over the same `H`, so copied onto a same-content
/// claim it still verifies. It must be reported `legacy`, never `v1`, so a
/// reader can see the row carries no type binding.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_evidence_signature_on_a_same_content_claim_reports_legacy(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x65u8; 32]).expect("signer");
    let agent = seed_agent(&pool, &signer.public_key()).await;
    let content = "R-34: a legacy evidence signature, copied onto a claim.";
    let h = ContentHasher::hash(content.as_bytes());
    let legacy_evidence_sig = signer.sign(&h);
    let claim = insert_claim(
        &pool,
        agent,
        content,
        &h,
        Some(&legacy_evidence_sig),
        Some(agent),
    )
    .await;

    let resp = run_verify(&pool, claim).await;
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
    assert_eq!(
        resp["signature_scheme"], "legacy",
        "a bare-digest signature must never read as type-bound: {resp}"
    );
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

/// The writers: a claim written through MCP `submit_claim` carries a v1 CLAIM
/// signature and its evidence row a v1 EVIDENCE signature, by the server key.
/// The evidence signature is not a valid claim signature over the same digest.
///
/// RED before the writer switch: both were signed over the bare digest
/// (`signature_scheme: legacy`, and the evidence signature verified as a claim
/// signature).
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_signs_the_claim_and_its_evidence_under_v1(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = server.server_agent_id().await.expect("server agent");
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, server_agent)
        .await
        .expect("viewer");
    let content = "R-34 writer: submit_claim signs under v1";
    let evidence_text = format!("evidence for {content}");
    epigraph_mcp::tools::claims::submit_claim(
        &server,
        &viewer,
        SubmitClaimParams {
            content: content.to_string(),
            methodology: "extraction".to_string(),
            evidence_data: evidence_text.clone(),
            evidence_type: "empirical".to_string(),
            confidence: 0.7,
            source_url: None,
            reasoning: None,
            labels: vec![],
            novelty_threshold: Some(0.0),
        },
        None,
    )
    .await
    .expect("stdio submit");
    let claim: Uuid = sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(&pool)
        .await
        .expect("claim");

    let resp = run_verify(&pool, claim).await;
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
    assert_eq!(resp["signature_scheme"], "v1", "{resp}");

    assert_evidence_signed_v1(&pool, claim, &evidence_text).await;
}

/// The same for `memorize` (its own sign sites in `tools/memory.rs`).
#[sqlx::test(migrations = "../../migrations")]
async fn memorize_signs_the_claim_and_its_evidence_under_v1(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let server_agent = server.server_agent_id().await.expect("server agent");
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, server_agent)
        .await
        .expect("viewer");
    let content = "R-34 writer: memorize signs under v1";
    epigraph_mcp::tools::memory::memorize(
        &server,
        &viewer,
        MemorizeParams {
            content: content.to_string(),
            confidence: Some(0.7),
            tags: None,
            novelty_threshold: Some(0.0),
        },
        None,
    )
    .await
    .expect("stdio memorize");
    let claim: Uuid = sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(&pool)
        .await
        .expect("claim");

    let resp = run_verify(&pool, claim).await;
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
    assert_eq!(resp["signature_scheme"], "v1", "{resp}");

    let (evidence_text,): (String,) = sqlx::query_as(
        "SELECT raw_content FROM evidence WHERE claim_id = $1 AND signature IS NOT NULL LIMIT 1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("a signed evidence row");
    assert_evidence_signed_v1(&pool, claim, &evidence_text).await;
}

/// The key every `build_scoped_test_server` signs with.
fn test_server_key() -> [u8; 32] {
    AgentSigner::from_bytes(&[0xA7u8; 32])
        .expect("signer")
        .public_key()
}

/// Every signed evidence row `sql` selects (`content_hash, signature`) is a v1
/// EVIDENCE signature by the server key, and no claim signature over the same
/// digest. At least one row, so the check cannot pass vacuously.
async fn assert_signed_evidence_rows_v1(
    pool: &PgPool,
    writer: &str,
    sql: &str,
    bind: Option<Uuid>,
) {
    let mut q = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(sql);
    if let Some(b) = bind {
        q = q.bind(b);
    }
    let rows = q.fetch_all(pool).await.expect("evidence rows");
    assert!(!rows.is_empty(), "{writer} wrote no signed evidence row");
    let key = test_server_key();
    for (hash, sig) in rows {
        let hash: [u8; 32] = hash.try_into().expect("32-byte hash");
        let sig: [u8; 64] = sig.try_into().expect("64-byte signature");
        assert_eq!(
            SignatureVerifier::verify_entity(&key, SignedEntity::Evidence, &hash, &sig).unwrap(),
            Some(SignatureScheme::V1),
            "{writer}: an evidence row is not signed as v1 evidence"
        );
        assert_eq!(
            SignatureVerifier::verify_entity(&key, SignedEntity::Claim, &hash, &sig).unwrap(),
            None,
            "{writer}: an evidence signature verifies as a claim signature"
        );
    }
}

fn ingest_extraction(tag: &str) -> epigraph_ingest::schema::DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {
            "title": format!("R-34 {tag}: Tagged Signatures for Ingested Documents"),
            "doi": format!("10.9999/r34-{tag}"),
            "source_type": "Paper",
            "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("R-34 {tag}: tagged signatures bind each row to its entity type."),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Methods",
            "paragraphs": [{
                "text": format!("R-34 {tag}: every evidence row is signed over a tagged message."),
                "atoms": [format!("R-34 {tag}: evidence rows carry v1 signatures.")],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        "relationships": []
    }))
    .expect("fixture parses")
}

const ALL_SIGNED_EVIDENCE: &str =
    "SELECT content_hash, signature FROM evidence WHERE signature IS NOT NULL";
const CLAIMS_SIGNED_EVIDENCE: &str =
    "SELECT content_hash, signature FROM evidence WHERE claim_id = $1 AND signature IS NOT NULL";

/// `ingest_document`'s evidence sign site (`do_ingest_document`). Its claim
/// sign site is guarded by `epigraph-crypto`'s `entity_signing_sites` ratchet
/// instead: the document walk's claim INSERTs
/// (`create_with_id_if_absent_conn`, `create_conn`) store no signature, so no
/// row shows it.
#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_signs_its_evidence_under_v1(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    epigraph_mcp::tools::ingestion::do_ingest_document(
        &server,
        &viewer,
        &ingest_extraction("document"),
        None,
    )
    .await
    .expect("document ingests");
    assert_signed_evidence_rows_v1(&pool, "ingest_document", ALL_SIGNED_EVIDENCE, None).await;
}

/// `ingest_document_spine`'s evidence sign site (`do_ingest_document_spine`);
/// its claim sign site as for `ingest_document`.
#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_spine_signs_its_evidence_under_v1(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    epigraph_mcp::tools::ingestion::do_ingest_document_spine(
        &server,
        &viewer,
        &ingest_extraction("spine"),
        None,
    )
    .await
    .expect("spine ingests");
    assert_signed_evidence_rows_v1(&pool, "ingest_document_spine", ALL_SIGNED_EVIDENCE, None).await;
}

/// `update_with_evidence`'s evidence sign site (`tools/claims.rs`).
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_signs_its_evidence_under_v1(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let claim_id = common::seed_claim(&pool, "R-34 writer: update_with_evidence", 0.5).await;
    epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".to_string(),
            evidence_data: "R-34: a measurement".to_string(),
            source_url: None,
            supports: true,
            strength: 0.8,
            labels: vec![],
        },
        None,
    )
    .await
    .expect("update_with_evidence");
    assert_signed_evidence_rows_v1(
        &pool,
        "update_with_evidence",
        CLAIMS_SIGNED_EVIDENCE,
        Some(claim_id),
    )
    .await;
}

/// `report_workflow_outcome`'s evidence sign site (`tools/workflows.rs`).
#[sqlx::test(migrations = "../../migrations")]
async fn report_workflow_outcome_signs_its_evidence_under_v1(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let workflow = common::seed_workflow_claim(&pool, "R-34 workflow outcome", &["s1"]).await;
    epigraph_mcp::tools::workflows::report_workflow_outcome(
        &server,
        &viewer,
        ReportWorkflowOutcomeParams {
            workflow_id: workflow.to_string(),
            success: true,
            execution_log: vec![StepExecution {
                step_index: 0,
                planned: "s1".to_string(),
                actual: "s1".to_string(),
                deviated: false,
                deviation_reason: None,
            }],
            outcome_details: "ran".to_string(),
            quality: Some(0.8),
            goal_text: None,
        },
        None,
    )
    .await
    .expect("report_workflow_outcome");
    assert_signed_evidence_rows_v1(
        &pool,
        "report_workflow_outcome",
        CLAIMS_SIGNED_EVIDENCE,
        Some(workflow),
    )
    .await;
}

/// The claim's signed evidence row: its signature verifies under the server
/// key as a v1 EVIDENCE signature over its stored hash, and NOT as a claim
/// signature over that hash under either rung.
async fn assert_evidence_signed_v1(pool: &PgPool, claim: Uuid, evidence_text: &str) {
    // The signer's registered key: these test servers sign with the key their
    // agent row carries.
    let (hash, sig, key): (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT e.content_hash, e.signature, a.public_key FROM evidence e \
           JOIN agents a ON a.id = e.signer_id \
          WHERE e.claim_id = $1 AND e.raw_content = $2 AND e.signature IS NOT NULL",
    )
    .bind(claim)
    .bind(evidence_text)
    .fetch_one(pool)
    .await
    .expect("the claim's signed evidence row");
    let hash: [u8; 32] = hash.try_into().expect("32-byte hash");
    let sig: [u8; 64] = sig.try_into().expect("64-byte signature");
    let key: [u8; 32] = key.try_into().expect("32-byte key");
    assert_eq!(
        SignatureVerifier::verify_entity(&key, SignedEntity::Evidence, &hash, &sig).unwrap(),
        Some(SignatureScheme::V1),
        "the evidence row is not signed as v1 evidence"
    );
    assert_eq!(
        SignatureVerifier::verify_entity(&key, SignedEntity::Claim, &hash, &sig).unwrap(),
        None,
        "the evidence signature verifies as a claim signature over the same digest"
    );
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
