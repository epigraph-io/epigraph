#![cfg(feature = "db")]
//! An approved `agent` OAuth client never ADOPTS an agent row whose key anyone
//! can compute (backlog 55fba366).
//!
//! An agent client's `client_id` is its hex Ed25519 public key, and
//! `AgentRepository::ensure_for_client` links the client to the `ed25519`
//! agent row holding that key, so the token speaks as the agent its own claims
//! are authored under. The client proves only that it holds the private half
//! of the key. For two shapes of legacy row that proves nothing, because the
//! private key is a function of public inputs and the row is still `ed25519`
//! (migration 230's `seed-derived` kind is set at insert, never backfilled):
//!
//! * an LLM identity written by the old epigraph-mcp create path: key
//!   `BLAKE3("llm-agent:{model}:{prompt hash}")`, `llm_model` recorded on the
//!   row by `set_llm_properties`;
//! * a document-ingest author node: key `did_key_for_author` of its own name
//!   or ORCID.
//!
//! Driven through the real `/oauth/token` route with a real assertion signed
//! by the COMPUTED private key, against an approved (active, unlinked) client,
//! the state an admin's approval of a hostile `/oauth/register` request
//! leaves. CALIBRATION: the same flow for a row with a random key links and
//! mints, so each refusal is the row's shape, not the fixture.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_core::Agent;
use epigraph_db::AgentRepository;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn config() -> ApiConfig {
    ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
        allow_all_identities: true,
    }
}

/// An ACTIVE, UNLINKED agent-type client whose `client_id` is `public_key`
/// (hex), with the human owner `agents_must_have_owner` requires. Returns the
/// client's row id and `client_id`.
async fn approved_unlinked_client(pool: &PgPool, public_key: [u8; 32]) -> (Uuid, String) {
    let client_id = hex::encode(public_key);
    let owner: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status) \
         VALUES ($1, 'owner', 'human', ARRAY['claims:read'], ARRAY['claims:read'], 'active') \
         RETURNING id",
    )
    .bind(format!("owner-{}", &client_id[..16]))
    .fetch_one(pool)
    .await
    .expect("owner client");
    let row: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, owner_id) \
         VALUES ($1, 'adoption-test', 'agent', ARRAY['claims:read'], ARRAY['claims:read'], \
                 'active', NULL, $2) \
         RETURNING id",
    )
    .bind(&client_id)
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("agent client");
    (row, client_id)
}

/// `timestamp(8B BE) || nonce(16B) || Ed25519(timestamp || nonce)`, base64.
fn assertion(key: &SigningKey) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let mut msg = Vec::with_capacity(88);
    msg.extend_from_slice(&ts.to_be_bytes());
    msg.extend_from_slice(Uuid::new_v4().as_bytes());
    let sig = key.sign(&msg);
    msg.extend_from_slice(&sig.to_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, msg)
}

async fn assertion_grant(pool: &PgPool, client_id: &str, key: &SigningKey) -> (StatusCode, Value) {
    let app = create_router(AppState::with_db(pool.clone(), config()));
    let body = json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_assertion_type": "urn:epigraph:ed25519",
        "client_assertion": assertion(key),
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn linked_agent(pool: &PgPool, client_row: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT agent_id FROM oauth_clients WHERE id = $1")
        .bind(client_row)
        .fetch_one(pool)
        .await
        .expect("client row")
}

async fn derived_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agents WHERE key_kind = 'derived'")
        .fetch_one(pool)
        .await
        .expect("count")
}

/// The adoption must be refused, and refused cleanly: 403 naming why, the
/// client left unlinked, no derived principal minted in the row's place.
async fn assert_not_adopted(pool: &PgPool, what: &str, signer: &SigningKey, needle: &str) {
    let (row, client_id) = approved_unlinked_client(pool, signer.verifying_key().to_bytes()).await;
    let derived_before = derived_rows(pool).await;
    let (status, body) = assertion_grant(pool, &client_id, signer).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{what}: a client holding a COMPUTED key minted a token as that agent: {body}"
    );
    assert!(
        body.to_string().contains(needle) && body.to_string().contains("not adopted"),
        "{what}: the refusal says why: {body}"
    );
    assert_eq!(
        linked_agent(pool, row).await,
        None,
        "{what}: the client must stay unlinked (the link is write-once)"
    );
    assert_eq!(
        derived_rows(pool).await,
        derived_before,
        "{what}: no derived principal may be minted in the refused row's place"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_client_never_adopts_a_row_whose_key_is_computable(pool: PgPool) {
    // CALIBRATION: a row with a random key, created the way the legacy MCP
    // create path created every server agent (`AgentRepository::create`, which
    // writes `ed25519`), is adopted and mints.
    let random = SigningKey::from_bytes(&[0x51; 32]);
    let plain = AgentRepository::create(
        &pool,
        &Agent::new(random.verifying_key().to_bytes(), Some("mcp-agent".into())),
    )
    .await
    .expect("plain agent");
    let (row, client_id) = approved_unlinked_client(&pool, random.verifying_key().to_bytes()).await;
    let (status, body) = assertion_grant(&pool, &client_id, &random).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CALIBRATION: an agent client holding its own random key mints: {body}"
    );
    assert_eq!(
        linked_agent(&pool, row).await,
        Some(plain.id.as_uuid()),
        "CALIBRATION: and speaks as its own ed25519 row"
    );

    // 1. A legacy LLM identity: the old create path, then `set_llm_properties`.
    //    Anyone who knows the model and the prompt hash computes the key.
    let prompt_hash = hex::encode(blake3::hash(b"a published system prompt").as_bytes());
    let llm = epigraph_crypto::keypair_from_llm_agent_prehashed("model-x", &prompt_hash);
    let llm_row = AgentRepository::create(
        &pool,
        &Agent::new(llm.public_key(), Some("mcp-agent".into())),
    )
    .await
    .expect("llm agent");
    AgentRepository::set_llm_properties(&pool, llm_row.id.as_uuid(), "model-x", &prompt_hash)
        .await
        .expect("llm properties");
    let kind: String = sqlx::query_scalar("SELECT key_kind FROM agents WHERE id = $1")
        .bind(llm_row.id.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("key_kind");
    assert_eq!(
        kind, "ed25519",
        "PREMISE: the legacy LLM row is still ed25519"
    );
    assert_not_adopted(
        &pool,
        "legacy LLM identity",
        &SigningKey::from_bytes(&llm.secret_key()),
        "LLM agent identity",
    )
    .await;

    // 2. A legacy author node keyed from its own name.
    let by_name = epigraph_crypto::did_key::keypair_from_name("Wren Halloway");
    AgentRepository::create(
        &pool,
        &Agent::new(by_name.public_key(), Some("Wren Halloway".into())),
    )
    .await
    .expect("name-derived author");
    assert_not_adopted(
        &pool,
        "name-derived author",
        &SigningKey::from_bytes(&by_name.secret_key()),
        "derived from its name or ORCID",
    )
    .await;

    // 3. A legacy author node keyed from its ORCID.
    let orcid = "0000-0002-1825-0097";
    let by_orcid = epigraph_crypto::did_key::keypair_from_orcid(orcid);
    let mut author = Agent::new(by_orcid.public_key(), Some("Josiah Carberry".into()));
    author.orcid = Some(orcid.to_string());
    AgentRepository::create(&pool, &author)
        .await
        .expect("orcid-derived author");
    assert_not_adopted(
        &pool,
        "ORCID-derived author",
        &SigningKey::from_bytes(&by_orcid.secret_key()),
        "derived from its name or ORCID",
    )
    .await;
}
