#![cfg(feature = "db")]
mod common;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// Seed an agent row and one active agent_key row.
/// Returns (agent_id, key_id).
async fn seed_agent_with_key(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
    let agent_id = Uuid::new_v4();
    // Derive a unique 32-byte public key from agent_id
    let pk: Vec<u8> = agent_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();

    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");

    let key_id = Uuid::new_v4();
    // Use a distinct 32-byte public key for the key row
    let key_pk: Vec<u8> = key_id.as_bytes().iter().copied().cycle().take(32).collect();

    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'signing', 'active', now())",
    )
    .bind(key_id)
    .bind(agent_id)
    .bind(&key_pk)
    .execute(pool)
    .await
    .expect("seed agent_key");

    (agent_id, key_id)
}

/// Issue a JWT where agent_id claim == target_agent_id (caller IS the agent).
fn token_as_agent(agent_id: Uuid, scopes: &[&str]) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(), // client_id (distinct from agent_id)
            scopes.iter().map(|s| s.to_string()).collect(),
            "agent",
            None,
            Some(agent_id), // agent_id claim = target agent
            chrono::Duration::minutes(60),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("test JWT issued");
    token
}

// ---------------------------------------------------------------------------
// update_agent — 401
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn update_agent_no_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_id = Uuid::new_v4();
    let body = serde_json::json!({"display_name": "x"});

    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/agents/{fake_id}"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// update_agent — 403 (wrong agent_id)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn update_agent_wrong_agent_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // Seed the target agent
    let (agent_id, _) = seed_agent_with_key(&pool).await;

    // Token claims a DIFFERENT agent_id
    let different_agent_id = Uuid::new_v4();
    let token = token_as_agent(different_agent_id, &["agents:write"]);

    let body = serde_json::json!({"display_name": "new name"});
    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/agents/{agent_id}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// update_agent — 200 (caller == target_agent_id)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn update_agent_self_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (agent_id, _) = seed_agent_with_key(&pool).await;

    // Token: agent_id claim == target agent
    let token = token_as_agent(agent_id, &["agents:write"]);

    let body = serde_json::json!({"display_name": "updated name"});
    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/agents/{agent_id}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// update_agent — 200 (admin override)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn update_agent_admin_override_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (agent_id, _) = seed_agent_with_key(&pool).await;

    // Admin token with a DIFFERENT agent_id (or None), but has claims:admin
    let token = common::test_bearer_token_with_scopes(&["agents:write", "claims:admin"]);

    let body = serde_json::json!({"display_name": "admin updated"});
    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/agents/{agent_id}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 for admin override, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// revoke_agent_key — 401
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_no_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_agent = Uuid::new_v4();
    let fake_key = Uuid::new_v4();
    let body = serde_json::json!({"reason": "test"});

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{fake_agent}/keys/{fake_key}/revoke"
        ))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// revoke_agent_key — 403 (wrong agent_id)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_wrong_agent_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (agent_id, key_id) = seed_agent_with_key(&pool).await;

    // Token claims a different agent_id
    let different_agent_id = Uuid::new_v4();
    let token = token_as_agent(different_agent_id, &["agents:write"]);

    let body = serde_json::json!({"reason": "test revocation"});
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{agent_id}/keys/{key_id}/revoke"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// revoke_agent_key — 200 (caller == target_agent_id)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_self_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (agent_id, key_id) = seed_agent_with_key(&pool).await;

    // Token with agent_id == target agent
    let token = token_as_agent(agent_id, &["agents:write"]);

    let body = serde_json::json!({"reason": "self-revocation test"});
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{agent_id}/keys/{key_id}/revoke"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 for self-revocation, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ---------------------------------------------------------------------------
// revoke_agent_key — 200 (admin override)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_admin_override_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (agent_id, key_id) = seed_agent_with_key(&pool).await;

    // Admin token — different agent_id but has claims:admin
    let token = common::test_bearer_token_with_scopes(&["agents:write", "claims:admin"]);

    let body = serde_json::json!({"reason": "admin revocation test"});
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{agent_id}/keys/{key_id}/revoke"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 for admin revocation, got {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ===========================================================================
// rotate_agent_key — caller must be the agent itself or hold claims:admin
// ===========================================================================
//
// The old-key signature cannot serve as the ownership proof on its own: an
// LLM agent's key is DERIVED from (model, prompt hash), both of which are
// public, so anyone can recompute the private half and produce a valid
// old-key signature. These tests therefore give the non-owner caller fully
// valid signatures; the only thing that can refuse it is the caller check.

/// An LLM agent seeded the way derived identities are: `agents.public_key`
/// and its one active `agent_keys` signing row are the derived key. The
/// prompt carries a fresh UUID so parallel tests never share a key.
struct DerivedAgent {
    id: Uuid,
    signer: epigraph_crypto::AgentSigner,
}

async fn seed_derived_llm_agent(pool: &sqlx::PgPool) -> DerivedAgent {
    let id = Uuid::new_v4();
    let signer = epigraph_crypto::keypair_from_llm_agent(
        "synthetic-model-1",
        &format!("synthetic system prompt {}", Uuid::new_v4()),
    );
    let pk = signer.public_key().to_vec();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, key_kind) \
         VALUES ($1, $2, 'llm', 'derived')",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed derived agent");
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'signing', 'active', now())",
    )
    .bind(Uuid::new_v4())
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed derived agent_key");
    DerivedAgent { id, signer }
}

/// The rotate endpoint's canonical message: "rotate:" ‖ agent uuid bytes ‖
/// ":" ‖ new public key bytes.
fn rotation_message(agent_id: Uuid, new_pk: &[u8; 32]) -> Vec<u8> {
    let mut m = b"rotate:".to_vec();
    m.extend_from_slice(agent_id.as_bytes());
    m.push(b':');
    m.extend_from_slice(new_pk);
    m
}

/// A rotation body whose old-key and new-key signatures both verify.
/// `old_signer` is whoever holds (or recomputed) the agent's current key.
fn valid_rotation_body(
    agent_id: Uuid,
    old_signer: &epigraph_crypto::AgentSigner,
    new_signer: &epigraph_crypto::AgentSigner,
) -> serde_json::Value {
    let new_pk = new_signer.public_key();
    let msg = rotation_message(agent_id, &new_pk);
    serde_json::json!({
        "new_public_key": hex::encode(new_pk),
        "old_key_signature": hex::encode(old_signer.sign(&msg)),
        "new_key_signature": hex::encode(new_signer.sign(&msg)),
        "reason": "rotation test",
    })
}

/// Every `agent_keys` column that a rotation could change, for one agent,
/// in a stable order.
type KeyRowSnapshot = (
    Uuid,
    Vec<u8>,
    String,
    String,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<String>,
    Option<Uuid>,
);

async fn key_rows(pool: &sqlx::PgPool, agent_id: Uuid) -> Vec<KeyRowSnapshot> {
    sqlx::query_as(
        "SELECT id, public_key, key_type::text, status::text, valid_until, \
                revocation_reason, revoked_by \
           FROM agent_keys WHERE agent_id = $1 ORDER BY id",
    )
    .bind(agent_id)
    .fetch_all(pool)
    .await
    .expect("read agent_keys")
}

async fn rows_holding_key(pool: &sqlx::PgPool, pk: &[u8]) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agent_keys WHERE public_key = $1")
        .bind(pk)
        .fetch_one(pool)
        .await
        .expect("count agent_keys by public_key")
}

async fn post_rotate(
    addr: std::net::SocketAddr,
    agent_id: Uuid,
    token: &str,
    body: &serde_json::Value,
) -> (reqwest::StatusCode, String) {
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{agent_id}/keys/rotate"
        ))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.text().await.unwrap_or_default())
}

/// After a successful rotation: the old key is `rotated`, and the agent has
/// exactly one active signing key, which is the new one.
async fn assert_rotated_to(pool: &sqlx::PgPool, agent: &DerivedAgent, new_pk: &[u8; 32]) {
    let rows = key_rows(pool, agent.id).await;
    let old_pk = agent.signer.public_key();
    let old: Vec<_> = rows.iter().filter(|r| r.1 == old_pk).collect();
    assert_eq!(old.len(), 1, "the old key row must still exist: {rows:?}");
    assert_eq!(old[0].3, "rotated", "the old key must be marked rotated");
    let active: Vec<_> = rows
        .iter()
        .filter(|r| r.2 == "signing" && r.3 == "active")
        .collect();
    assert_eq!(active.len(), 1, "exactly one active signing key: {rows:?}");
    assert_eq!(
        active[0].1.as_slice(),
        new_pk.as_slice(),
        "the active key must be the submitted new key"
    );
}

// ---------------------------------------------------------------------------
// rotate_agent_key — 403 for a different agent holding valid signatures
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rotate_agent_key_other_agent_with_valid_signatures_is_refused_and_keys_unchanged() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let victim = seed_derived_llm_agent(&pool).await;
    let before = key_rows(&pool, victim.id).await;

    // The attacker is a different agent with agents:write. It holds the
    // victim's current private key (derived keys are recomputable), so both
    // signatures it submits verify.
    let attacker_token = token_as_agent(Uuid::new_v4(), &["agents:write"]);
    let attacker_key = epigraph_crypto::AgentSigner::generate();
    let body = valid_rotation_body(victim.id, &victim.signer, &attacker_key);

    let (status, text) = post_rotate(addr, victim.id, &attacker_token, &body).await;
    assert_eq!(status, 403, "expected 403, got {status} — {text}");

    assert_eq!(
        key_rows(&pool, victim.id).await,
        before,
        "a refused rotation must leave the agent's key rows untouched"
    );
    assert_eq!(
        rows_holding_key(&pool, &attacker_key.public_key()).await,
        0,
        "the attacker's key must not be stored anywhere"
    );
}

// ---------------------------------------------------------------------------
// rotate_agent_key — the caller check precedes every read: no 404 oracle
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rotate_agent_key_other_agent_gets_403_not_404_for_unknown_agent() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // No agent and no key rows exist for this id. A well-formed body (valid
    // hex, valid lengths, self-consistent signatures) reaches the key lookup
    // unless the caller check runs first.
    let unknown = Uuid::new_v4();
    let some_old = epigraph_crypto::AgentSigner::generate();
    let some_new = epigraph_crypto::AgentSigner::generate();
    let body = valid_rotation_body(unknown, &some_old, &some_new);
    let token = token_as_agent(Uuid::new_v4(), &["agents:write"]);

    let (status, text) = post_rotate(addr, unknown, &token, &body).await;
    assert_eq!(
        status, 403,
        "a non-owner must be refused before the key lookup (no existence oracle); got {status} — {text}"
    );
}

// ---------------------------------------------------------------------------
// rotate_agent_key — the caller check precedes the hex decode
// ---------------------------------------------------------------------------
//
// The body below deserializes (every field is a string), so it reaches the
// handler; only `hex::decode` would refuse it. A body serde cannot decode is
// refused earlier, by the extractor, alike for every caller (see
// `rotate_agent_key_undecodable_body_is_422_for_owner_and_non_owner_alike`).

#[tokio::test(flavor = "multi_thread")]
async fn rotate_agent_key_other_agent_gets_403_not_400_for_malformed_body() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let victim = seed_derived_llm_agent(&pool).await;
    let body = serde_json::json!({
        "new_public_key": "not-hex",
        "old_key_signature": "not-hex",
        "new_key_signature": "not-hex",
    });
    let token = token_as_agent(Uuid::new_v4(), &["agents:write"]);

    let (status, text) = post_rotate(addr, victim.id, &token, &body).await;
    assert_eq!(
        status, 403,
        "a non-owner must be refused before the hex decode; got {status} — {text}"
    );
}

// ---------------------------------------------------------------------------
// rotate_agent_key — positive control: the agent itself rotates
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rotate_agent_key_self_rotates() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let agent = seed_derived_llm_agent(&pool).await;
    let new_key = epigraph_crypto::AgentSigner::generate();
    let body = valid_rotation_body(agent.id, &agent.signer, &new_key);
    let token = token_as_agent(agent.id, &["agents:write"]);

    let (status, text) = post_rotate(addr, agent.id, &token, &body).await;
    assert_eq!(
        status, 200,
        "expected 200 for self-rotation, got {status} — {text}"
    );
    assert_rotated_to(&pool, &agent, &new_key.public_key()).await;
}

// ---------------------------------------------------------------------------
// rotate_agent_key — positive control: claims:admin rotates another agent
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rotate_agent_key_admin_override_rotates() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let agent = seed_derived_llm_agent(&pool).await;
    let new_key = epigraph_crypto::AgentSigner::generate();
    let body = valid_rotation_body(agent.id, &agent.signer, &new_key);
    // Bound to a fresh principal that is NOT the target agent.
    let token = common::test_bearer_token_with_scopes(&["agents:write", "claims:admin"]);

    let (status, text) = post_rotate(addr, agent.id, &token, &body).await;
    assert_eq!(
        status, 200,
        "expected 200 for admin rotation, got {status} — {text}"
    );
    assert_rotated_to(&pool, &agent, &new_key.public_key()).await;
}

// ===========================================================================
// Key validity windows — a key taken out of service stops being valid
// ===========================================================================
//
// A key's validity window is [valid_from, valid_until). A verifier that binds
// a signature to "the key that was valid when the claim was made" can only do
// so if retiring a key closes its window. An open window (valid_until NULL)
// on a rotated or revoked key keeps binding signatures made after it was
// retired, including by whoever recomputed a derived key.

/// (valid_from, valid_until, status) of one key row.
async fn key_window(
    pool: &sqlx::PgPool,
    pk: &[u8],
) -> (
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
    String,
) {
    sqlx::query_as(
        "SELECT valid_from, valid_until, status::text FROM agent_keys WHERE public_key = $1",
    )
    .bind(pk)
    .fetch_one(pool)
    .await
    .expect("read key window")
}

#[tokio::test(flavor = "multi_thread")]
async fn rotate_agent_key_closes_the_old_keys_window_where_the_new_one_opens() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let agent = seed_derived_llm_agent(&pool).await;
    let (_, old_until_before, _) = key_window(&pool, &agent.signer.public_key()).await;
    assert_eq!(
        old_until_before, None,
        "fixture: the seeded key is open-ended"
    );

    let new_key = epigraph_crypto::AgentSigner::generate();
    let body = valid_rotation_body(agent.id, &agent.signer, &new_key);
    let token = token_as_agent(agent.id, &["agents:write"]);
    let (status, text) = post_rotate(addr, agent.id, &token, &body).await;
    assert_eq!(
        status, 200,
        "self-rotation must succeed; got {status} — {text}"
    );

    let (_, old_until, old_status) = key_window(&pool, &agent.signer.public_key()).await;
    let (new_from, new_until, new_status) = key_window(&pool, &new_key.public_key()).await;
    assert_eq!(old_status, "rotated");
    assert_eq!(new_status, "active");
    assert_eq!(new_until, None, "the new key is open-ended");
    let old_until = old_until.expect(
        "a rotated key's window must be closed (valid_until set), or it keeps binding \
         signatures made after the rotation",
    );
    assert!(
        old_until <= new_from,
        "the windows must not overlap: old key valid until {old_until}, new key valid from {new_from}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_closes_the_keys_window() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let agent = seed_derived_llm_agent(&pool).await;
    let pk = agent.signer.public_key();
    let key_id: Uuid = sqlx::query_scalar("SELECT id FROM agent_keys WHERE public_key = $1")
        .bind(pk.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    let (from, until_before, _) = key_window(&pool, &pk).await;
    assert_eq!(until_before, None, "fixture: the seeded key is open-ended");

    let token = token_as_agent(agent.id, &["agents:write"]);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{}/keys/{key_id}/revoke",
            agent.id
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({"reason": "window test"}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert_eq!(status, 200, "{}", resp.text().await.unwrap_or_default());

    let (from_after, until, status) = key_window(&pool, &pk).await;
    assert_eq!(status, "revoked");
    assert_eq!(from_after, from, "revocation must not move valid_from");
    let until = until.expect("a revoked key's window must be closed (valid_until set)");
    assert!(
        until >= from,
        "valid_until {until} precedes valid_from {from}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_never_reopens_or_extends_a_closed_window() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // An agent whose one key already expired an hour ago, still marked active.
    let agent = seed_derived_llm_agent(&pool).await;
    let pk = agent.signer.public_key();
    let expired_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "UPDATE agent_keys SET valid_from = now() - interval '2 hours', \
                valid_until = now() - interval '1 hour' \
          WHERE public_key = $1 RETURNING valid_until",
    )
    .bind(pk.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    let key_id: Uuid = sqlx::query_scalar("SELECT id FROM agent_keys WHERE public_key = $1")
        .bind(pk.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();

    let token = token_as_agent(agent.id, &["agents:write"]);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{}/keys/{key_id}/revoke",
            agent.id
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({"reason": "expired-key test"}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert_eq!(status, 200, "{}", resp.text().await.unwrap_or_default());

    let (_, until, status) = key_window(&pool, &pk).await;
    assert_eq!(status, "revoked");
    assert_eq!(
        until,
        Some(expired_at),
        "retiring a key may only shorten its window, never move an earlier end later"
    );
}

// ===========================================================================
// rotate_agent_key rotates the SIGNING key, whatever else is active
// ===========================================================================
//
// An agent can hold one active key per key_type (idx_agent_keys_active is
// unique on (agent_id, key_type) WHERE status = 'active'). Rotation always
// stores a 'signing' key, so the key it retires must be the active signing
// key, not merely the newest active key of any type.

#[tokio::test(flavor = "multi_thread")]
async fn rotate_agent_key_retires_the_signing_key_not_a_newer_key_of_another_type() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let agent = seed_derived_llm_agent(&pool).await;
    // A second active key of another type, created explicitly LATER than the
    // signing key (explicit timestamps; insert order is not relied on).
    let other_key = epigraph_crypto::AgentSigner::generate();
    let other_pk = other_key.public_key();
    sqlx::query("UPDATE agent_keys SET created_at = now() - interval '1 hour' WHERE agent_id = $1")
        .bind(agent.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from, created_at) \
         VALUES ($1, $2, $3, 'encryption', 'active', now(), now())",
    )
    .bind(Uuid::new_v4())
    .bind(agent.id)
    .bind(other_pk.as_slice())
    .execute(&pool)
    .await
    .expect("seed a newer active key of another type");
    let (_, other_until_before, _) = key_window(&pool, &other_pk).await;

    let new_key = epigraph_crypto::AgentSigner::generate();
    let body = valid_rotation_body(agent.id, &agent.signer, &new_key);
    let token = token_as_agent(agent.id, &["agents:write"]);
    let (status, text) = post_rotate(addr, agent.id, &token, &body).await;
    assert_eq!(
        status, 200,
        "rotation signed by the active signing key must succeed; got {status} — {text}"
    );

    assert_rotated_to(&pool, &agent, &new_key.public_key()).await;
    let (_, other_until, other_status) = key_window(&pool, &other_pk).await;
    assert_eq!(
        (other_status.as_str(), other_until),
        ("active", other_until_before),
        "the key of another type must be left exactly as it was"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rotate_agent_key_is_404_when_only_a_key_of_another_type_is_active() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // The agent's only active key is not a signing key; rotation signed by
    // that key must not convert it into a signing key.
    let agent = seed_derived_llm_agent(&pool).await;
    sqlx::query("UPDATE agent_keys SET key_type = 'encryption' WHERE agent_id = $1")
        .bind(agent.id)
        .execute(&pool)
        .await
        .unwrap();
    let before = key_rows(&pool, agent.id).await;

    let new_key = epigraph_crypto::AgentSigner::generate();
    let body = valid_rotation_body(agent.id, &agent.signer, &new_key);
    let token = token_as_agent(agent.id, &["agents:write"]);
    let (status, text) = post_rotate(addr, agent.id, &token, &body).await;
    assert_eq!(
        status, 404,
        "there is no active signing key to rotate; got {status} — {text}"
    );
    assert_eq!(
        key_rows(&pool, agent.id).await,
        before,
        "nothing may change"
    );
}

// ===========================================================================
// revoke_agent_key — `revoked_by` never names someone who did not revoke
// ===========================================================================

async fn revoked_by_of(pool: &sqlx::PgPool, key_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT revoked_by FROM agent_keys WHERE id = $1")
        .bind(key_id)
        .fetch_one(pool)
        .await
        .expect("read revoked_by")
}

async fn post_revoke(
    addr: std::net::SocketAddr,
    agent_id: Uuid,
    key_id: Uuid,
    token: &str,
) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/agents/{agent_id}/keys/{key_id}/revoke"
        ))
        .bearer_auth(token)
        .json(&serde_json::json!({"reason": "attribution test"}))
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_agent_key_records_the_agent_only_when_the_agent_revoked() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // Self-revocation: the agent did it, and the row says so.
    let (agent, key) = seed_agent_with_key(&pool).await;
    let status = post_revoke(addr, agent, key, &token_as_agent(agent, &["agents:write"])).await;
    assert_eq!(status, 200);
    assert_eq!(
        revoked_by_of(&pool, key).await,
        Some(agent),
        "a self-revocation is attributed to the agent"
    );

    // Admin override: a different principal did it. The row must not claim
    // the agent revoked its own key.
    let (agent, key) = seed_agent_with_key(&pool).await;
    let admin = common::test_bearer_token_with_scopes(&["agents:write", "claims:admin"]);
    let status = post_revoke(addr, agent, key, &admin).await;
    assert_eq!(status, 200);
    assert_ne!(
        revoked_by_of(&pool, key).await,
        Some(agent),
        "an admin revocation must not be recorded as the agent's own"
    );
}

// ===========================================================================
// rotate_agent_key — a body serde cannot decode is refused alike for all
// ===========================================================================
//
// The `Json<RotateKeyRequest>` extractor runs BEFORE the handler, so a body
// that does not deserialize is refused before the caller check. That is not
// an oracle only because the refusal depends on the caller's own input and
// is the same for the owner and a non-owner. This pins that sameness.

#[tokio::test(flavor = "multi_thread")]
async fn rotate_agent_key_undecodable_body_is_422_for_owner_and_non_owner_alike() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let agent = seed_derived_llm_agent(&pool).await;
    let before = key_rows(&pool, agent.id).await;
    let owner = token_as_agent(agent.id, &["agents:write"]);
    let other = token_as_agent(Uuid::new_v4(), &["agents:write"]);

    for body in [
        serde_json::json!({}),
        serde_json::json!({"new_public_key": 1, "old_key_signature": "", "new_key_signature": ""}),
    ] {
        let (owner_status, owner_text) = post_rotate(addr, agent.id, &owner, &body).await;
        let (other_status, other_text) = post_rotate(addr, agent.id, &other, &body).await;
        assert_eq!(
            owner_status, 422,
            "owner, body {body}: {owner_status} — {owner_text}"
        );
        assert_eq!(
            other_status, owner_status,
            "non-owner must get exactly the owner's refusal for body {body}: {other_text}"
        );
    }
    assert_eq!(
        key_rows(&pool, agent.id).await,
        before,
        "nothing may change"
    );
}

// ===========================================================================
// rotate_agent_key — armed admin-scope switch: claims:admin needs elevation
// ===========================================================================
//
// Once the admin-scope switch (migration 128) is armed, `claims:admin` on a
// non-elevated token is not honoured, and an elevated token carries no
// `agents:write`. The admin override on the key routes is then unreachable
// over HTTP. These run on a per-test database so arming never touches the
// shared one the unarmed admin tests above use.

/// The per-test database's URL, on the same server as `DATABASE_URL`.
async fn url_for(pool: &sqlx::PgPool) -> String {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database()");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let prefix = base
        .split_once('?')
        .map_or(base.as_str(), |(a, _)| a)
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0
        .to_string();
    format!("{prefix}/{db}")
}

/// Arm the switch, as the harness (superuser) through 128's setter.
async fn arm_admin_scopes(pool: &sqlx::PgPool) {
    sqlx::query(
        "SELECT * FROM public.epigraph_set_admin_scope_enforcement(true, 'agent_mutation_auth_test')",
    )
    .execute(pool)
    .await
    .expect("arm the admin-scope switch");
}

#[sqlx::test(migrations = "../../migrations")]
async fn armed_rotate_agent_key_refuses_a_non_elevated_admin(pool: sqlx::PgPool) {
    arm_admin_scopes(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url_for(&pool).await).await;

    let agent = seed_derived_llm_agent(&pool).await;
    let before = key_rows(&pool, agent.id).await;
    let new_key = epigraph_crypto::AgentSigner::generate();
    let body = valid_rotation_body(agent.id, &agent.signer, &new_key);
    let admin = common::test_bearer_token_with_scopes(&["agents:write", "claims:admin"]);

    let (status, text) = post_rotate(addr, agent.id, &admin, &body).await;
    assert_eq!(
        status, 403,
        "armed: claims:admin without elevation must not override; got {status} — {text}"
    );
    assert_eq!(
        key_rows(&pool, agent.id).await,
        before,
        "nothing may change"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn armed_rotate_agent_key_still_lets_the_agent_rotate(pool: sqlx::PgPool) {
    arm_admin_scopes(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url_for(&pool).await).await;

    let agent = seed_derived_llm_agent(&pool).await;
    let new_key = epigraph_crypto::AgentSigner::generate();
    let body = valid_rotation_body(agent.id, &agent.signer, &new_key);
    let token = token_as_agent(agent.id, &["agents:write"]);

    let (status, text) = post_rotate(addr, agent.id, &token, &body).await;
    assert_eq!(
        status, 200,
        "armed: self-rotation is unaffected; got {status} — {text}"
    );
    assert_rotated_to(&pool, &agent, &new_key.public_key()).await;
}
