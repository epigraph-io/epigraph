#![cfg(feature = "db")]
//! **`POST /api/v1/claims/:id/assess` embeds only a claim the caller may
//! write, and never a sealed one** — observed over HTTP.
//!
//! # Why this file exists (deferred-commitment key `embed-on-write-helper`)
//!
//! Step 9 of `assess_claim` ran its own `UPDATE claims SET embedding` on the
//! PATH's claim id, with no seal predicate and no write predicate. The step-1
//! read is viewer-filtered, so a caller could reach the write for any claim it
//! could READ, including a group claim where it holds only `reader`. For a
//! sealed claim, `get_by_id` returns the sealed content, so the vector was
//! derived from ciphertext and landed on a row CLAUDE.md's audit says must
//! carry none. The step now writes through
//! `ClaimRepository::store_embedding_vec_if_unsealed` with the handler's viewer.
//!
//! What is asserted is the EMBEDDING only. The handler's other writes (mass
//! functions, frame membership, edges) are outside this change's scope and are
//! not examined here.
//!
//! # The working directory
//!
//! `assess_claim` loads `calibration.toml` relative to the process's working
//! directory, and the file lives at the workspace root. A test binary runs with
//! the package root as its working directory, so every test here moves to the
//! workspace root first. That is a process-wide change, safe only because
//! every test in this binary wants the same directory. Do not add a test here
//! that needs a different one.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

fn at_workspace_root() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crates/epigraph-api has two ancestors");
    assert!(
        root.join("calibration.toml").is_file(),
        "calibration.toml must exist at the workspace root for assess_claim to run"
    );
    std::env::set_current_dir(root).expect("chdir to the workspace root");
}

async fn seed_group_claim(pool: &PgPool, author: Uuid, group: Uuid) -> Uuid {
    let claim_id = Uuid::new_v4();
    let hash: Vec<u8> = claim_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, owner_group_id, visibility) \
         VALUES ($1, $2, $3, $4, $5, 'group')",
    )
    .bind(claim_id)
    .bind(format!("assess embedding write-gate claim {claim_id}"))
    .bind(&hash)
    .bind(author)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    claim_id
}

async fn seal(pool: &PgPool, claim: Uuid, group: Uuid) {
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT (group_id, epoch) DO NOTHING",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("seed key epoch");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', $3)",
    )
    .bind(claim)
    .bind(group)
    .bind(vec![0xcdu8; 64])
    .execute(pool)
    .await
    .expect("seal the claim");
}

async fn vector_is_null(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding IS NULL FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read claim vector")
}

async fn assess(addr: std::net::SocketAddr, token: &str, claim: Uuid) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim}/assess"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "evidence_type": "empirical",
            "methodology": "instrumental",
            "confidence": 0.8,
            "supports": true,
        }))
        .send()
        .await
        .expect("POST assess");
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(serde_json::Value::Null);
    (status, body)
}

/// One principal: `admin` in its own group, `reader` in another. Three claims:
/// its own, its own sealed, and one it can only read. Only the first may get a
/// vector, and the first is the positive control that proves the other two
/// were refused by the gate rather than by a broken handler.
#[tokio::test(flavor = "multi_thread")]
async fn assess_embeds_only_an_unsealed_claim_the_caller_may_write() {
    at_workspace_root();
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");

    let (principal, own_group) =
        fixture::seed_agent_with_group(&pool, "assess-embed-principal").await;
    let (author, other_group) = fixture::seed_agent_with_group(&pool, "assess-embed-author").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(other_group)
    .bind(principal)
    .execute(&pool)
    .await
    .expect("seed reader membership");

    let own = seed_group_claim(&pool, principal, own_group).await;
    let sealed = seed_group_claim(&pool, principal, own_group).await;
    seal(&pool, sealed, own_group).await;
    let read_only = seed_group_claim(&pool, author, other_group).await;

    let (addr, _shutdown) = common::spawn_app_with_mock_embedding(&url).await;
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], principal);

    // ── positive control ───────────────────────────────────────────────────
    let (status, body) = assess(addr, &token, own).await;
    assert_eq!(
        status, 200,
        "assess on the caller's own claim failed: {body}"
    );
    assert_eq!(
        body["embedded"], true,
        "the owner's unsealed claim must be embedded: {body}"
    );
    assert!(
        !vector_is_null(&pool, own).await,
        "`embedded: true` must correspond to a vector on the row"
    );

    // ── read-only claim ────────────────────────────────────────────────────
    let (status, body) = assess(addr, &token, read_only).await;
    assert_eq!(
        status, 200,
        "the read-only claim is visible, so assess itself still runs: {body}"
    );
    assert_eq!(
        body["embedded"], false,
        "assess put a vector on a claim the caller may only READ: {body}"
    );
    assert!(
        vector_is_null(&pool, read_only).await,
        "the read-only group's claim must still carry no vector"
    );

    // ── sealed claim ───────────────────────────────────────────────────────
    // The seal here is the `claim_encryption` row alone, so the claim stays
    // visible to its owner and assess runs to step 9. Asserting the 200 keeps
    // this arm from passing vacuously on a handler that 404s sealed claims
    // before it reaches the write.
    let (status, body) = assess(addr, &token, sealed).await;
    assert_eq!(
        status, 200,
        "assess must reach its embedding step for this arm to mean anything: {body}"
    );
    assert_eq!(
        body["embedded"], false,
        "assess embedded a SEALED claim: {body}"
    );
    assert!(
        vector_is_null(&pool, sealed).await,
        "a sealed claim carrying a vector is CLAUDE.md's sealed_with_embedding \
         violation"
    );
}
