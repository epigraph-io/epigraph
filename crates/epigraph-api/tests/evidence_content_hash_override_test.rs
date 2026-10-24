#![cfg(feature = "db")]
//! `POST /api/v1/evidence` must not store a caller-supplied `content_hash`
//! that disagrees with the `raw_content` it is stored beside.
//!
//! The evidence twin of `content_hash_override_verification_test.rs` (claims).
//! When `raw_content` is present the override must equal BLAKE3(raw_content),
//! or the request is refused with 400 before anything is written. When
//! `raw_content` is absent the evidence is external content the server cannot
//! hash, and the caller's hash is stored as given (the same contract as the
//! `/api/v1/submit` evidence path).

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
mod common;

const SCOPES: &[&str] = &["evidence:write", "claims:write"];

async fn connect() -> (String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    (url, pool)
}

fn document_type() -> serde_json::Value {
    serde_json::json!({
        "type": "document",
        "source_url": null,
        "mime_type": "text/plain",
        "checksum": null,
    })
}

async fn post_evidence(
    addr: std::net::SocketAddr,
    token: &str,
    body: &serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/evidence"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(serde_json::json!({ "raw": text }));
    (status, json)
}

async fn evidence_count_for_raw(pool: &PgPool, raw: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM evidence WHERE raw_content = $1")
        .bind(raw)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn mismatched_evidence_hash_with_raw_content_is_rejected() {
    let (url, pool) = connect().await;
    let agent = common::seed_system_agent(&pool).await;
    let claim = common::seed_claim(
        &pool,
        &format!("evidence hash claim {}", uuid::Uuid::new_v4()),
    )
    .await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, SCOPES).await;

    let raw = format!("evidence raw A-{}", uuid::Uuid::new_v4());
    // BLAKE3 of a DIFFERENT string: well-formed, 32 bytes, wrong.
    let wrong_hash = blake3::hash(b"B").to_hex().to_string();

    let (status, body) = post_evidence(
        addr,
        &token,
        &serde_json::json!({
            "agent_id": agent,
            "claim_id": claim,
            "raw_content": raw,
            "evidence_type": document_type(),
            "content_hash": wrong_hash,
        }),
    )
    .await;

    // The write half first: a mismatched digest must not be stored at all.
    assert_eq!(
        evidence_count_for_raw(&pool, &raw).await,
        0,
        "no evidence row may be written with a content_hash that does not match \
         its raw_content (status {status}, body {body})"
    );
    assert_eq!(status, 400, "expected 400, got {status} body={body}");
    assert_eq!(body["error"], "ValidationError", "{body}");
    assert_eq!(body["details"]["field"], "content_hash", "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn matching_evidence_hash_with_raw_content_is_accepted() {
    let (url, pool) = connect().await;
    let agent = common::seed_system_agent(&pool).await;
    let claim = common::seed_claim(
        &pool,
        &format!("evidence hash claim {}", uuid::Uuid::new_v4()),
    )
    .await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, SCOPES).await;

    let raw = format!("evidence raw match-{}", uuid::Uuid::new_v4());
    // Uppercase hex of the right digest: the comparison is on the decoded
    // bytes, so the spelling of the hex must not matter.
    let hash = blake3::hash(raw.as_bytes()).to_hex().to_uppercase();

    let (status, body) = post_evidence(
        addr,
        &token,
        &serde_json::json!({
            "agent_id": agent,
            "claim_id": claim,
            "raw_content": raw,
            "evidence_type": document_type(),
            "content_hash": hash,
        }),
    )
    .await;
    assert_eq!(status, 201, "a matching hash must be accepted; body={body}");

    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT content_hash FROM evidence WHERE raw_content = $1")
            .bind(&raw)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, blake3::hash(raw.as_bytes()).as_bytes().to_vec());
}

#[tokio::test(flavor = "multi_thread")]
async fn external_evidence_hash_without_raw_content_is_stored_as_given() {
    let (url, pool) = connect().await;
    let agent = common::seed_system_agent(&pool).await;
    let claim = common::seed_claim(
        &pool,
        &format!("evidence hash claim {}", uuid::Uuid::new_v4()),
    )
    .await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, SCOPES).await;

    // External content: the server has nothing to hash, so the caller's
    // digest is the only one there is.
    let digest = *blake3::hash(format!("external {}", uuid::Uuid::new_v4()).as_bytes()).as_bytes();

    let (status, body) = post_evidence(
        addr,
        &token,
        &serde_json::json!({
            "agent_id": agent,
            "claim_id": claim,
            "raw_content": null,
            "evidence_type": document_type(),
            "content_hash": hex::encode(digest),
        }),
    )
    .await;
    assert_eq!(
        status, 201,
        "external evidence must be accepted; body={body}"
    );

    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT content_hash FROM evidence WHERE claim_id = $1 AND raw_content IS NULL",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        digest.to_vec(),
        "the caller's hash is stored as given"
    );
}
