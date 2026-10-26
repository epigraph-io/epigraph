//! The separate-signing-key mode (agent identity lineage design D1, D2).
//!
//! The host gives a container its IDENTITY public key (the agent's
//! `agents.public_key`) and a random SIGNING private key registered for that
//! agent in `agent_keys`. `epigraph-mcp` then:
//!
//! * attributes every write to the agent found by the identity key, and
//! * signs every digest with the signing key, never with an identity key
//!   (whose private half it does not hold);
//! * refuses to start unless the signing key is an ACTIVE `signing` key of
//!   that agent.
//!
//! The identity is registered here exactly as the host does it: through
//! migration 161's `epigraph_register_agent_identity`, on the attestor role.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use epigraph_crypto::{AgentSigner, ContentHasher, SignatureVerifier};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentIdentityRepository, IdentityRegistration, PromptFile};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools;
use epigraph_mcp::types::{SubmitClaimParams, VerifyClaimParams};
use epigraph_mcp::EpiGraphMcpFull;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const ATTESTOR: &str = "epigraph_identity_attestor";

fn signer(byte: u8) -> AgentSigner {
    AgentSigner::from_bytes(&[byte; 32]).expect("signer")
}

/// Register `identity` with `signing` as its signing key, as the host does.
async fn register(pool: &PgPool, identity: [u8; 32], signing: [u8; 32], group: &str) -> Uuid {
    let reg = IdentityRegistration {
        identity_pubkey: identity,
        parent_agent_id: None,
        model: "test-model-s2".to_string(),
        prompt_hash: blake3::hash(&identity).to_hex().to_string(),
        group_folder: group.to_string(),
        signing_pubkey: Some(signing),
        identity_md: PromptFile::Absent,
        global_claude_md: PromptFile::Absent,
        group_claude_md: PromptFile::Stored(b"group rules\n".to_vec()),
        learned_md: PromptFile::Stored(b"a lesson\n".to_vec()),
        in_prompt: json!({"group_claude_md": true, "learned_md": true}),
        runner_version: Some("runner-test".to_string()),
        host_sha: None,
    };
    fixture::as_role(pool, ATTESTOR, |mut conn| async move {
        let r = AgentIdentityRepository::register(&mut conn, &reg).await;
        (conn, r)
    })
    .await
    .expect("the attestor registers the identity")
    .agent_id
}

fn server_signing_with(
    pool: &PgPool,
    scoped: epigraph_db::ScopedPool,
    key: AgentSigner,
) -> EpiGraphMcpFull {
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool.clone(), key, embedder, false).with_scoped_pool(scoped)
}

async fn agent_with_key(pool: &PgPool, key: &[u8; 32]) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_optional(pool)
        .await
        .expect("agent by key")
}

/// A server signing with the registered signing key and declaring the identity
/// key resolves to the IDENTITY agent; a claim it writes on stdio is authored
/// and signer-recorded as that agent, carries a signature that verifies under
/// the signing key and not under the identity key, and `verify_claim` reports
/// it valid, bound, kind `signing`. No agent row is ever keyed by the signing
/// key.
///
/// The contrast server (same signing key, no identity declared) resolves to a
/// DIFFERENT agent: the one keyed by the signing key, which is the legacy
/// behaviour. So the identity key is what selects the agent, not the signer.
#[sqlx::test(migrations = "../../migrations")]
async fn the_new_mode_signs_with_the_signing_key_and_attributes_to_the_identity(pool: PgPool) {
    let identity = signer(0x81).public_key();
    let signing = signer(0x82);
    let agent = register(&pool, identity, signing.public_key(), "g-s2-attr").await;

    let scoped = fixture::scoped_pool(&pool).await;
    let server =
        server_signing_with(&pool, scoped.clone(), signer(0x82)).with_identity_public_key(identity);
    assert_eq!(
        server.server_agent_id().await.expect("server agent"),
        agent,
        "the server's agent is the one registered under the identity key"
    );

    let viewer = Viewer::resolve(&pool, agent).await.expect("viewer");
    let content = "S2: written by the identity agent, signed by its signing key";
    tools::claims::submit_claim(
        &server,
        &viewer,
        SubmitClaimParams {
            content: content.to_string(),
            methodology: "extraction".to_string(),
            evidence_data: "evidence for the S2 attribution test".to_string(),
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

    let (claim, author, signer_id, signature): (Uuid, Uuid, Option<Uuid>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT id, agent_id, signer_id, signature FROM claims WHERE content = $1")
            .bind(content)
            .fetch_one(&pool)
            .await
            .expect("the claim");
    assert_eq!((author, signer_id), (agent, Some(agent)));
    let signature: [u8; 64] = signature
        .expect("the claim is signed")
        .try_into()
        .expect("64-byte signature");
    let digest = ContentHasher::hash(content.as_bytes());
    // Ruling R-34: the server signs the claim-tagged v1 message.
    assert_eq!(
        SignatureVerifier::verify_entity(
            &signing.public_key(),
            epigraph_crypto::SignedEntity::Claim,
            &digest,
            &signature
        )
        .unwrap(),
        Some(epigraph_crypto::SignatureScheme::V1),
        "the stored signature is the signing key's, over the v1 claim message"
    );
    assert_eq!(
        SignatureVerifier::verify_entity(
            &identity,
            epigraph_crypto::SignedEntity::Claim,
            &digest,
            &signature
        )
        .unwrap(),
        None,
        "and not an identity-key signature"
    );
    assert_eq!(
        agent_with_key(&pool, &signing.public_key()).await,
        None,
        "no agent is keyed by the signing key"
    );

    let out = tools::claims::verify_claim(
        &server,
        &viewer,
        VerifyClaimParams {
            claim_id: claim.to_string(),
        },
    )
    .await
    .expect("verify_claim");
    let resp: Value = common::first_text(&out);
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
    assert_eq!(resp["key_bound"], Value::Bool(true), "{resp}");
    assert_eq!(resp["key_kind"], Value::from("signing"), "{resp}");

    // Contrast: no identity declared -> the agent is keyed by the signer.
    let legacy = server_signing_with(&pool, scoped, signer(0x82));
    let legacy_agent = legacy.server_agent_id().await.expect("legacy agent");
    assert_ne!(legacy_agent, agent);
    assert_eq!(
        agent_with_key(&pool, &signing.public_key()).await,
        Some(legacy_agent)
    );
}

/// The boot check admits exactly an ACTIVE `signing` key of the identity's
/// agent, and refuses, without creating any agent row:
/// an identity no agent carries; a key registered for ANOTHER agent; a key
/// the agent holds only as `identity-legacy`; a signing key since revoked;
/// and a key registered nowhere.
#[sqlx::test(migrations = "../../migrations")]
async fn the_boot_check_admits_only_the_agents_active_signing_key(pool: PgPool) {
    use epigraph_mcp::signing_identity::check_signing_key;

    let identity = signer(0x91).public_key();
    let signing = signer(0x92).public_key();
    let agent = register(&pool, identity, signing, "g-s2-boot-a").await;

    // Positive control.
    assert_eq!(
        check_signing_key(&pool, &identity, &signing).await,
        Ok(agent),
        "the registered active signing key admits"
    );

    // A key registered nowhere.
    let stray = signer(0x93).public_key();
    assert!(check_signing_key(&pool, &identity, &stray).await.is_err());

    // A key registered for ANOTHER identity.
    let other_identity = signer(0x94).public_key();
    let other_signing = signer(0x95).public_key();
    register(&pool, other_identity, other_signing, "g-s2-boot-b").await;
    assert!(check_signing_key(&pool, &identity, &other_signing)
        .await
        .is_err());

    // The agent's identity-legacy key is not a signing key.
    let legacy = signer(0x96).public_key();
    sqlx::query(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status) \
         VALUES ($1, $2, 'identity-legacy', 'active')",
    )
    .bind(agent)
    .bind(legacy.as_slice())
    .execute(&pool)
    .await
    .expect("legacy key row");
    assert!(check_signing_key(&pool, &identity, &legacy).await.is_err());

    // An identity no agent carries: refused, and no row is created for it.
    let unknown = signer(0x97).public_key();
    let refusal = check_signing_key(&pool, &unknown, &signing)
        .await
        .expect_err("an unregistered identity is refused");
    assert!(!refusal.is_empty());
    assert_eq!(agent_with_key(&pool, &unknown).await, None);

    // Revoke the signing key (a maintenance act): refused from then on.
    sqlx::query(
        "UPDATE agent_keys SET status = 'revoked' \
          WHERE agent_id = $1 AND public_key = $2 AND key_type = 'signing'",
    )
    .bind(agent)
    .bind(signing.as_slice())
    .execute(&pool)
    .await
    .expect("revoke");
    assert!(check_signing_key(&pool, &identity, &signing).await.is_err());
}

/// The boot check reads `key_type` and `status` in the spelling migration
/// 161's guard compares (`lower(btrim(..))`, which trims SPACES only), so a
/// row the guard does not treat as attested never admits. `'signing\t'` is
/// not a signing key to the guard, so the application role can insert it for
/// any agent; were it admitted, the container would sign with a key that
/// `verify_claim` (same SQL spelling) never binds. Positive control: the same
/// agent's registered key, and a `' Signing '` spelling the guard does
/// attest, both admit.
#[sqlx::test(migrations = "../../migrations")]
async fn the_boot_check_normalises_as_the_guard_does(pool: PgPool) {
    use epigraph_mcp::signing_identity::check_signing_key;

    let identity = signer(0xA1).public_key();
    let signing = signer(0xA2).public_key();
    let agent = register(&pool, identity, signing, "g-s2-norm").await;
    assert_eq!(
        check_signing_key(&pool, &identity, &signing).await,
        Ok(agent),
        "positive control: the registered key admits"
    );

    let insert = |key: [u8; 32], key_type: &'static str, status: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO agent_keys (agent_id, public_key, key_type, status) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(agent)
            .bind(key.as_slice())
            .bind(key_type)
            .bind(status)
            .execute(&pool)
            .await
            .expect("key row");
        }
    };

    let spaced = signer(0xA3).public_key();
    insert(spaced, " Signing ", "active").await;
    assert_eq!(
        check_signing_key(&pool, &identity, &spaced).await,
        Ok(agent),
        "a space-padded, upper-case spelling is a signing key to the guard too"
    );

    for (byte, key_type, status) in [
        (0xA4, "signing\t", "active"),
        (0xA5, "signing\n", "active"),
        (0xA6, "signing", "active\t"),
    ] {
        let key = signer(byte).public_key();
        insert(key, key_type, status).await;
        let refusal = check_signing_key(&pool, &identity, &key)
            .await
            .expect_err("a spelling the guard does not attest never admits");
        assert!(
            refusal.contains("is not an active signing key of"),
            "{key_type:?}/{status:?}: {refusal}"
        );
    }
}

/// The boot check admits a signing key only inside its validity window, the
/// window `verify_claim` binds by: an ACTIVE row whose `valid_until` has
/// passed, or whose `valid_from` is still far ahead, would sign claims that
/// are never bound. Each window edit is a maintenance act (superuser here);
/// restoring the window admits again, so the refusals are the window.
#[sqlx::test(migrations = "../../migrations")]
async fn the_boot_check_admits_only_inside_the_keys_window(pool: PgPool) {
    use epigraph_mcp::signing_identity::check_signing_key;

    let identity = signer(0xB1).public_key();
    let signing = signer(0xB2).public_key();
    let agent = register(&pool, identity, signing, "g-s2-window").await;
    assert_eq!(
        check_signing_key(&pool, &identity, &signing).await,
        Ok(agent)
    );

    let set_window = |from: &'static str, until: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(&format!(
                "UPDATE agent_keys SET valid_from = {from}, valid_until = {until} \
                  WHERE agent_id = $1 AND public_key = $2"
            ))
            .bind(agent)
            .bind(signing.as_slice())
            .execute(&pool)
            .await
            .expect("window edit");
        }
    };

    set_window("now() - interval '10 days'", "now() - interval '1 day'").await;
    let closed = check_signing_key(&pool, &identity, &signing)
        .await
        .expect_err("an active key whose window has closed is refused");
    assert!(
        closed.contains("is not an active signing key of"),
        "{closed}"
    );

    set_window("now() + interval '1 day'", "NULL").await;
    let future = check_signing_key(&pool, &identity, &signing)
        .await
        .expect_err("an active key whose window has not opened is refused");
    assert!(
        future.contains("is not an active signing key of"),
        "{future}"
    );

    set_window("now()", "NULL").await;
    assert_eq!(
        check_signing_key(&pool, &identity, &signing).await,
        Ok(agent),
        "the open window admits again"
    );
}
