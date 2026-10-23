//! `verify_claim` key binding (agent identity lineage design D2).
//!
//! `signature_valid` alone says a signature verifies under SOME key the reader
//! resolved. Under the unkeyed identity scheme that key is a function of public
//! inputs, so a valid signature proves nothing about who wrote the claim. D2
//! adds `key_bound`: the key that verifies the signature is an attested
//! `agent_keys` key (`signing`, or `identity-legacy` from migration 161's
//! backfill) of the claim's AUTHOR, valid when the claim was created. And
//! `key_kind` names which kind of key verified it.
//!
//! In the separate-signing-key mode the signer agent's `agents.public_key` is
//! its IDENTITY key, which signs nothing, so the signature verifies only under
//! the agent's registered signing key: `signature_valid` must look there too.
//!
//! Fixtures are raw SQL on the privileged test pool: `agent_keys` rows of the
//! attested types are refused to the application role (migration 161 section
//! 7a), and the claim rows need a chosen `created_at`, `signature` and
//! `signer_id`.

mod common;

use chrono::{DateTime, Duration, Utc};
use common::build_test_server;
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_mcp::tools::claims::verify_claim;
use epigraph_mcp::types::VerifyClaimParams;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

fn signer(byte: u8) -> AgentSigner {
    AgentSigner::from_bytes(&[byte; 32]).expect("signer")
}

/// An agent whose `agents.public_key` is `public_key`, created at `created_at`.
async fn seed_agent(pool: &PgPool, public_key: &[u8; 32], created_at: DateTime<Utc>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, created_at) \
         VALUES ($1, $2, 'system', $3)",
    )
    .bind(id)
    .bind(public_key.as_slice())
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

/// One `agent_keys` row, written on the privileged pool.
async fn seed_key(
    pool: &PgPool,
    agent: Uuid,
    public_key: &[u8; 32],
    key_type: &str,
    status: &str,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
) {
    sqlx::query(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from, valid_until) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(agent)
    .bind(public_key.as_slice())
    .bind(key_type)
    .bind(status)
    .bind(valid_from)
    .bind(valid_until)
    .execute(pool)
    .await
    .expect("seed agent key");
}

/// A claim authored by `author`, recorded as signed by `signer_id`, signed by
/// `key` over BLAKE3(content), created at `created_at`.
async fn seed_signed_claim(
    pool: &PgPool,
    author: Uuid,
    signer_id: Uuid,
    key: &AgentSigner,
    content: &str,
    created_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash = ContentHasher::hash(content.as_bytes());
    let signature = key.sign(&hash);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, signature, \
                             signer_id, labels, is_current, properties, created_at, updated_at) \
         VALUES ($1, $2, $3, 0.5, $4, $5, $6, ARRAY[]::text[], true, '{}'::jsonb, $7, $7)",
    )
    .bind(id)
    .bind(content)
    .bind(hash.as_slice())
    .bind(author)
    .bind(signature.as_slice())
    .bind(signer_id)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn verify(pool: &PgPool, claim: Uuid) -> Value {
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim");
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, author)
        .await
        .expect("viewer");
    let server = build_test_server(pool.clone());
    let out = verify_claim(
        &server,
        &viewer,
        VerifyClaimParams {
            claim_id: claim.to_string(),
        },
    )
    .await
    .expect("verify_claim");
    common::first_text(&out)
}

fn bound(resp: &Value) -> (Value, Value, Value) {
    (
        resp["signature_valid"].clone(),
        resp["key_bound"].clone(),
        resp["key_kind"].clone(),
    )
}

/// The separate-signing-key shape: the agent's `agents.public_key` is its
/// identity key, the claim is signed by its registered ACTIVE signing key, and
/// author = signer. Valid, bound, kind `signing`.
///
/// Paired with the refusal below that differs only in the signing key's
/// status, so `key_bound` is a function of the key row, not a constant.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_signed_by_the_authors_active_signing_key_is_bound(pool: PgPool) {
    let t0 = Utc::now() - Duration::days(10);
    let identity = signer(0x11);
    let signing = signer(0x12);
    let agent = seed_agent(&pool, &identity.public_key(), t0).await;
    seed_key(
        &pool,
        agent,
        &signing.public_key(),
        "signing",
        "active",
        t0,
        None,
    )
    .await;
    let claim = seed_signed_claim(
        &pool,
        agent,
        agent,
        &signing,
        "D2: signed by the registered signing key",
        t0 + Duration::days(1),
    )
    .await;

    let resp = verify(&pool, claim).await;
    assert_eq!(
        bound(&resp),
        (Value::Bool(true), Value::Bool(true), Value::from("signing")),
        "{resp}"
    );
}

/// A REVOKED signing key binds nothing (revocation carries no timestamp, so a
/// revoked key is treated as compromised), though its signature still verifies.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_signing_key_verifies_but_is_not_bound(pool: PgPool) {
    let t0 = Utc::now() - Duration::days(10);
    let identity = signer(0x21);
    let signing = signer(0x22);
    let agent = seed_agent(&pool, &identity.public_key(), t0).await;
    seed_key(
        &pool,
        agent,
        &signing.public_key(),
        "signing",
        "revoked",
        t0,
        None,
    )
    .await;
    let claim = seed_signed_claim(
        &pool,
        agent,
        agent,
        &signing,
        "D2: signed by a key since revoked",
        t0 + Duration::days(1),
    )
    .await;

    let resp = verify(&pool, claim).await;
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
    assert_eq!(resp["key_bound"], Value::Bool(false), "{resp}");
}

/// A claim created BEFORE the signing key's `valid_from` is not bound by it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_older_than_the_signing_key_is_not_bound(pool: PgPool) {
    let t0 = Utc::now() - Duration::days(10);
    let identity = signer(0x31);
    let signing = signer(0x32);
    let agent = seed_agent(&pool, &identity.public_key(), t0).await;
    seed_key(
        &pool,
        agent,
        &signing.public_key(),
        "signing",
        "active",
        t0 + Duration::days(5),
        None,
    )
    .await;
    let claim = seed_signed_claim(
        &pool,
        agent,
        agent,
        &signing,
        "D2: dated before its key existed",
        t0 + Duration::days(1),
    )
    .await;

    let resp = verify(&pool, claim).await;
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
    assert_eq!(resp["key_bound"], Value::Bool(false), "{resp}");
}

/// The legacy identity key (161's backfill: `identity-legacy`, valid from the
/// agent's creation, `valid_until` set at cut-over). A claim signed with it
/// BEFORE the cut-over is bound and says so (`identity-legacy`); the same key
/// AFTER the cut-over still verifies but is no longer bound.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_identity_key_is_bound_before_the_cut_over_only(pool: PgPool) {
    let t0 = Utc::now() - Duration::days(30);
    let cut_over = t0 + Duration::days(20);
    let legacy = signer(0x41);
    let agent = seed_agent(&pool, &legacy.public_key(), t0).await;
    seed_key(
        &pool,
        agent,
        &legacy.public_key(),
        "identity-legacy",
        "active",
        t0,
        Some(cut_over),
    )
    .await;

    let before = seed_signed_claim(
        &pool,
        agent,
        agent,
        &legacy,
        "D2: legacy-signed before the cut-over",
        cut_over - Duration::days(1),
    )
    .await;
    let after = seed_signed_claim(
        &pool,
        agent,
        agent,
        &legacy,
        "D2: legacy-signed after the cut-over",
        cut_over + Duration::days(1),
    )
    .await;

    let resp = verify(&pool, before).await;
    assert_eq!(
        bound(&resp),
        (
            Value::Bool(true),
            Value::Bool(true),
            Value::from("identity-legacy")
        ),
        "{resp}"
    );
    let resp = verify(&pool, after).await;
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
    assert_eq!(resp["key_bound"], Value::Bool(false), "{resp}");
}

/// The HTTP shape: a caller AUTHORS, the server SIGNS with its own active
/// signing key. The signature is valid, but the key is the signer's, not the
/// author's, so it does not bind the claim to its author.
#[sqlx::test(migrations = "../../migrations")]
async fn a_key_of_the_signer_that_is_not_the_authors_is_not_bound(pool: PgPool) {
    let t0 = Utc::now() - Duration::days(10);
    let author_identity = signer(0x51);
    let server_identity = signer(0x52);
    let server_signing = signer(0x53);
    let author = seed_agent(&pool, &author_identity.public_key(), t0).await;
    let server = seed_agent(&pool, &server_identity.public_key(), t0).await;
    seed_key(
        &pool,
        server,
        &server_signing.public_key(),
        "signing",
        "active",
        t0,
        None,
    )
    .await;
    let claim = seed_signed_claim(
        &pool,
        author,
        server,
        &server_signing,
        "D2: authored by a caller, signed by the server",
        t0 + Duration::days(1),
    )
    .await;

    let resp = verify(&pool, claim).await;
    assert_eq!(resp["signature_valid"], Value::Bool(true), "{resp}");
    assert_eq!(resp["key_bound"], Value::Bool(false), "{resp}");
    assert_eq!(resp["key_kind"], Value::from("signing"), "{resp}");
}

/// Only ATTESTED key types widen `signature_valid`. An `encryption` row is
/// application-insertable (migration 161's guard covers `signing` and
/// `identity-legacy` only), so a key planted there must not make a signature
/// valid, let alone bound. Paired with the first test, which differs only in
/// the row's type.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unattested_key_type_neither_verifies_nor_binds(pool: PgPool) {
    let t0 = Utc::now() - Duration::days(10);
    let identity = signer(0x61);
    let planted = signer(0x62);
    let agent = seed_agent(&pool, &identity.public_key(), t0).await;
    seed_key(
        &pool,
        agent,
        &planted.public_key(),
        "encryption",
        "active",
        t0,
        None,
    )
    .await;
    let claim = seed_signed_claim(
        &pool,
        agent,
        agent,
        &planted,
        "D2: signed by a key planted under an unattested type",
        t0 + Duration::days(1),
    )
    .await;

    let resp = verify(&pool, claim).await;
    assert_eq!(resp["signed"], Value::Bool(true), "{resp}");
    assert_eq!(resp["signature_valid"], Value::Bool(false), "{resp}");
    assert_eq!(resp["key_bound"], Value::Bool(false), "{resp}");
    assert_eq!(resp["key_kind"], Value::Null, "{resp}");
}

/// A signature by a key the reader knows nothing about: invalid, unbound, no
/// kind — while the author does hold an active signing key (a different one).
#[sqlx::test(migrations = "../../migrations")]
async fn a_signature_by_an_unknown_key_is_invalid_and_unbound(pool: PgPool) {
    let t0 = Utc::now() - Duration::days(10);
    let identity = signer(0x71);
    let signing = signer(0x72);
    let stranger = signer(0x73);
    let agent = seed_agent(&pool, &identity.public_key(), t0).await;
    seed_key(
        &pool,
        agent,
        &signing.public_key(),
        "signing",
        "active",
        t0,
        None,
    )
    .await;
    let claim = seed_signed_claim(
        &pool,
        agent,
        agent,
        &stranger,
        "D2: signed by a stranger's key",
        t0 + Duration::days(1),
    )
    .await;

    let resp = verify(&pool, claim).await;
    assert_eq!(
        bound(&resp),
        (Value::Bool(false), Value::Bool(false), Value::Null),
        "{resp}"
    );
}
