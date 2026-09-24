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
//!
//! The `hash_check` cases at the bottom cover the *third* state. Making
//! `hash_matches` falsifiable is not enough on its own: the canonical Tier-1
//! document pipeline deliberately stores a digest that is NOT `blake3(content)`
//! on every thesis/section/paragraph row, so a two-valued answer turns those
//! rows into a confident false accusation. Those tests pin `not_applicable` to
//! exactly that class and `mismatch` to everything else.

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
    assert_eq!(
        resp["hash_check"],
        Value::String("mismatch".to_string()),
        "and the tri-state must name it as a mismatch, not as undecided: {resp}"
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
    assert_eq!(
        resp["hash_check"],
        Value::String("match".to_string()),
        "and the tri-state must name it a match: {resp}"
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

/// A document-scoped COMPOUND node, seeded byte-for-byte the way
/// `epigraph_ingest::document::builder` writes a thesis, must report
/// `hash_check: "not_applicable"` — NOT a mismatch.
///
/// This is the class the two-valued answer got confidently wrong. The builder
/// binds `compound_content_hash(blake3(text), artifact_seed)` at levels 0/1/2
/// (`plan.rs`: "the value a writer must store in `claims.content_hash` — NOT
/// necessarily `blake3(content)` ... writers must bind this value rather than
/// re-deriving from content") so that migration 013's
/// `UNIQUE (content_hash, agent_id)` cannot collapse paper A's and paper B's
/// "Introduction" rows. `blake3(content)` therefore never equals the stored
/// digest on an *untampered* structural row, and the artifact seed is not
/// recoverable from the claim, so the only honest answer is "this digest is not
/// derivable from the body — content-hash verification does not apply here".
///
/// Fixture is built with the production helpers (`content_hash`,
/// `compound_content_hash`, `compound_claim_id`) rather than hand-rolled bytes,
/// so it tracks the writer instead of a snapshot of it.
#[sqlx::test(migrations = "../../migrations")]
async fn compound_document_hash_reports_not_applicable(pool: PgPool) {
    use epigraph_ingest::common::ids::{compound_claim_id, compound_content_hash, content_hash};

    let agent = seed_agent(&pool, &[0x44u8; 32]).await;

    // Exactly `document::builder`'s thesis branch: seed = "{title}\u{1f}thesis".
    let doc_title = "Positional Assembly of Diamondoid Structures";
    let thesis_text = "Mechanosynthesis can be made reliable at cryogenic temperatures.";
    let plain = content_hash(thesis_text);
    let seed = format!("{doc_title}\u{1f}thesis");
    let stored_hash = compound_content_hash(&plain, &seed);
    let claim_id = compound_claim_id(&plain, &seed);

    assert_ne!(
        stored_hash, plain,
        "fixture precondition: a compound row's stored digest is not blake3(content)"
    );

    insert_claim_with_properties(
        &pool,
        claim_id,
        agent,
        thesis_text,
        &stored_hash,
        None,
        None,
        // `document::builder`'s level-0 properties, verbatim.
        serde_json::json!({
            "level": 0,
            "source_type": "Paper",
            "thesis_derivation": "TopDown",
        }),
    )
    .await;

    let resp = run_verify(&pool, claim_id).await;

    assert_eq!(
        resp["hash_check"],
        Value::String("not_applicable".to_string()),
        "an UNTAMPERED thesis node of an ingested document must report \
         not_applicable; `mismatch` here is a false tampering alarm over every \
         thesis/section/paragraph row written by ingest_document: {resp}"
    );
    assert_eq!(
        resp["hash_matches"],
        Value::Null,
        "hash_matches must be null (undecided), never `false`, for a digest \
         that is not blake3(content) by construction: {resp}"
    );
}

/// The converse that keeps the new state from becoming a blanket excuse: a
/// CONTENT-ADDRESSED row (level-3 atom, plain digest) whose body was mutated
/// must still report `mismatch`.
///
/// Without this, "return not_applicable" would satisfy the test above and the
/// tampering signal would be gone again — the opposite-sign version of the
/// always-true theatre this whole item exists to remove.
#[sqlx::test(migrations = "../../migrations")]
async fn tampered_atom_still_reports_mismatch(pool: PgPool) {
    use epigraph_ingest::common::ids::content_hash;

    let agent = seed_agent(&pool, &[0x55u8; 32]).await;

    let original = "Tip functionalization proceeds by hydrogen abstraction.";
    let tampered = "Tip functionalization proceeds by fluorine abstraction.";
    let stored_hash = content_hash(original);
    let claim_id = Uuid::new_v4();

    insert_claim_with_properties(
        &pool,
        claim_id,
        agent,
        tampered,
        &stored_hash,
        None,
        None,
        // `document::builder`'s level-3 (atom) properties: SAME source_type,
        // different level — so the classifier cannot key on source_type alone.
        serde_json::json!({
            "level": 3,
            "source_type": "Paper",
            "section": "Methods",
        }),
    )
    .await;

    let resp = run_verify(&pool, claim_id).await;

    assert_eq!(
        resp["hash_check"],
        Value::String("mismatch".to_string()),
        "an atom binds the PLAIN content hash, so a body that does not hash to \
         it is genuine tampering and must be reported as mismatch: {resp}"
    );
    assert_eq!(
        resp["hash_matches"],
        Value::Bool(false),
        "mismatch must still surface as hash_matches: false: {resp}"
    );
}

/// A level-2 row that is NOT document ingest output (no `source_type`) must
/// still report `mismatch` when its body disagrees with its digest.
///
/// `ClaimRepository::evolve_step` writes `properties = {"level": <n>,
/// "step_lineage_id": …}` with `content_hash = blake3(content)`, and the
/// workflow builder writes `source_type: "workflow"` with the plain hash too.
/// Both are level < 3, so a classifier keyed on `level` alone would excuse a
/// tampered body on either. This pins the predicate to the document-compound
/// class specifically.
#[sqlx::test(migrations = "../../migrations")]
async fn tampered_non_document_level_two_reports_mismatch(pool: PgPool) {
    use epigraph_ingest::common::ids::content_hash;

    let agent = seed_agent(&pool, &[0x66u8; 32]).await;

    let original = "Acquire the admin token from the canonical client secret.";
    let tampered = "Acquire the admin token from the attacker's client secret.";
    let stored_hash = content_hash(original);
    let claim_id = Uuid::new_v4();

    insert_claim_with_properties(
        &pool,
        claim_id,
        agent,
        tampered,
        &stored_hash,
        None,
        None,
        serde_json::json!({
            "level": 2,
            "step_lineage_id": Uuid::new_v4().to_string(),
        }),
    )
    .await;

    let resp = run_verify(&pool, claim_id).await;

    assert_eq!(
        resp["hash_check"],
        Value::String("mismatch".to_string()),
        "a level-2 step claim stores the plain content hash, so `level < 3` \
         alone must not excuse a body/digest disagreement: {resp}"
    );
}

/// Run `verify_claim` as the claim's OWN author.
///
/// A real `Viewer::resolve` on the authoring agent, not `Viewer::test_bypass`.
/// A bypass viewer renders no predicate at all, so every assertion below would
/// hold over a `get_by_id` that had silently lost its visibility marker — the
/// class `visibility.rs` exists to make unbuildable. Resolving the author is
/// also the only principal guaranteed to see the row regardless of what the
/// tenancy defaults make of a raw-SQL fixture.
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
    insert_claim_with_properties(
        pool,
        id,
        agent_id,
        content,
        content_hash,
        signature,
        signer_id,
        serde_json::json!({}),
    )
    .await;
    id
}

/// [`insert_claim`] plus control over the row `id` and `properties`.
///
/// The `hash_check` fixtures need both: a document-compound row is identified by
/// `claims.properties` (`level` + `source_type`), and its `id` is
/// `compound_claim_id(...)` over the same material as its stored digest, so
/// seeding a random id would make the fixture unlike anything ingest writes.
#[allow(clippy::too_many_arguments)]
async fn insert_claim_with_properties(
    pool: &PgPool,
    id: Uuid,
    agent_id: Uuid,
    content: &str,
    content_hash: &[u8],
    signature: Option<&[u8]>,
    signer_id: Option<Uuid>,
    properties: Value,
) {
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             signature, signer_id, labels, is_current, properties) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, ARRAY[]::text[], true, $7)",
    )
    .bind(id)
    .bind(content)
    .bind(content_hash)
    .bind(agent_id)
    .bind(signature)
    .bind(signer_id)
    .bind(properties)
    .execute(pool)
    .await
    .expect("seed claim");
}
