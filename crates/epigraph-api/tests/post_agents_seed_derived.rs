//! `POST /api/v1/agents` with `key_kind: "seed-derived"` (backlog 57943a39).
//!
//! `ingest_literature` registers one agent per author under the deterministic
//! key `BLAKE3("<doi>:<name>")`, whose private half anyone can compute. The
//! route stored every such key as an `ed25519` signer and auto-provisioned an
//! ACTIVE agent OAuth client for it, so whoever computed the key could sign
//! as the author and mint tokens. A caller now declares the key
//! `seed-derived`: the row is stored as no verifier and gets no client.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use epigraph_api::middleware::bearer::AuthContext;
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::agents::{create_agent, CreateAgentRequest};
use epigraph_api::state::{ApiConfig, AppState};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;

/// An `agents:write` caller whose `client_id` is a real (human) client row,
/// so the route's auto-provisioned agent client has a valid owner.
async fn caller(pool: &PgPool) -> AuthContext {
    let owner: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status) \
         VALUES ($1, 'owner', 'human', ARRAY['agents:write'], ARRAY['agents:write'], 'active') \
         RETURNING id",
    )
    .bind(format!("owner-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("owner client");
    AuthContext {
        client_id: owner,
        agent_id: None,
        owner_id: Some(owner),
        client_type: ClientType::Human,
        scopes: vec!["agents:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn post(
    pool: &PgPool,
    auth: &AuthContext,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    let req: CreateAgentRequest = serde_json::from_value(body).expect("request");
    let r = create_agent(State(state), Some(Extension(auth.clone())), Json(req)).await;
    let resp = r.into_response();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// `(key_kind, number of oauth_clients whose client_id is the key)`.
async fn stored(pool: &PgPool, key_hex: &str) -> (String, i64) {
    let kind: String = sqlx::query_scalar(
        "SELECT key_kind::text FROM agents WHERE public_key = decode($1, 'hex')",
    )
    .bind(key_hex)
    .fetch_one(pool)
    .await
    .expect("agent row");
    let clients: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_clients WHERE client_id = $1")
            .bind(key_hex)
            .fetch_one(pool)
            .await
            .expect("clients");
    (kind, clients)
}

fn key_of(seed: &str) -> String {
    let secret = blake3::hash(seed.as_bytes());
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(secret.as_bytes())
            .verifying_key()
            .to_bytes(),
    )
}

/// The declared author key is stored `seed-derived` with no OAuth client.
/// Paired, on the same caller: an undeclared key is still an `ed25519`
/// signer with its one active client, so the difference is the declaration.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_seed_derived_key_is_no_signer_and_gets_no_client(pool: PgPool) {
    let auth = caller(&pool).await;

    let author = key_of("10.0000/example.0001:Ada Example");
    let (status, body) = post(
        &pool,
        &auth,
        serde_json::json!({
            "public_key": author, "display_name": "Ada Example", "key_kind": "seed-derived"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        stored(&pool, &author).await,
        ("seed-derived".to_string(), 0),
        "a seed-derived author key was stored as a signer or given a client"
    );

    let control = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&rand::random())
            .verifying_key()
            .to_bytes(),
    );
    let (status, body) = post(
        &pool,
        &auth,
        serde_json::json!({ "public_key": control, "display_name": "a real signer" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        stored(&pool, &control).await,
        ("ed25519".to_string(), 1),
        "the undeclared control must stay an ed25519 signer with its client"
    );
}

/// An unknown declaration is refused (400, `key_kind`) before any insert; a
/// declaration on an EXISTING key changes nothing (no demotion, no client).
#[sqlx::test(migrations = "../../migrations")]
async fn a_key_kind_declaration_is_checked_and_never_rewrites_a_row(pool: PgPool) {
    let auth = caller(&pool).await;
    let agents_before: i64 = sqlx::query_scalar("SELECT count(*) FROM agents")
        .fetch_one(&pool)
        .await
        .unwrap();
    let key = key_of("10.0000/example.0002:Bo Example");
    for bad in ["derived", "Seed-Derived", ""] {
        let (status, body) = post(
            &pool,
            &auth,
            serde_json::json!({ "public_key": key, "key_kind": bad }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}: {body}");
        assert!(body.to_string().contains("key_kind"), "{bad:?}: {body}");
    }
    let agents_after: i64 = sqlx::query_scalar("SELECT count(*) FROM agents")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(agents_after, agents_before, "a refused request inserted");

    // First registered undeclared (an ed25519 signer with a client), then
    // declared: the find-hit returns the row as it is.
    let (status, _) = post(&pool, &auth, serde_json::json!({ "public_key": key })).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post(
        &pool,
        &auth,
        serde_json::json!({ "public_key": key, "key_kind": "seed-derived" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(stored(&pool, &key).await, ("ed25519".to_string(), 1));
}
