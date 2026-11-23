//! `POST /api/v1/agents` with `key_kind: "seed-derived"` (backlog 57943a39).
//!
//! `ingest_literature` registers one agent per author under the deterministic
//! key `BLAKE3("<doi>:<name>")`, whose private half anyone can compute. The
//! route stored every such key as an `ed25519` signer and auto-provisioned an
//! ACTIVE agent OAuth client for it, so whoever computed the key could sign
//! as the author and mint tokens. A caller now declares the key
//! `seed-derived`: the row is stored as no verifier and gets no client.

mod viewer_fixture;

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
    post_on(
        AppState::with_db(pool.clone(), ApiConfig::default()),
        auth,
        body,
    )
    .await
}

/// `create_agent` on `state`.
async fn post_on(
    state: AppState,
    auth: &AuthContext,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
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

fn signing_key_of(seed: &str) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(blake3::hash(seed.as_bytes()).as_bytes())
}

fn key_of(seed: &str) -> String {
    hex::encode(signing_key_of(seed).verifying_key().to_bytes())
}

/// The proof of possession for declaring `public_key` seed-derived, signed by
/// `signer` (the key's holder, or, to forge, someone else).
fn proof_by(signer: &ed25519_dalek::SigningKey, public_key_hex: &str) -> String {
    use ed25519_dalek::Signer;
    let key: [u8; 32] = hex::decode(public_key_hex).unwrap().try_into().unwrap();
    hex::encode(
        signer
            .sign(&epigraph_crypto::key_kind_declaration_message(
                "seed-derived",
                &key,
            ))
            .to_bytes(),
    )
}

/// The declaration body for the author key of `seed`, with its valid proof.
fn declared(seed: &str, display_name: &str) -> serde_json::Value {
    let key = key_of(seed);
    serde_json::json!({
        "public_key": key,
        "display_name": display_name,
        "key_kind": "seed-derived",
        "key_kind_proof": proof_by(&signing_key_of(seed), &key),
    })
}

/// The declared author key is stored `seed-derived` with no OAuth client.
/// Paired, on the same caller: an undeclared key is still an `ed25519`
/// signer with its one active client, so the difference is the declaration.
#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_seed_derived_key_is_no_signer_and_gets_no_client(pool: PgPool) {
    let auth = caller(&pool).await;

    let seed = "10.0000/example.0001:Ada Example";
    let author = key_of(seed);
    let (status, body) = post(&pool, &auth, declared(seed, "Ada Example")).await;
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
        serde_json::json!({ "public_key": control, "display_name": "a real signer", "login": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        stored(&pool, &control).await,
        ("ed25519".to_string(), 1),
        "an undeclared control asking for a login stays a signer with a client"
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
    let seed = "10.0000/example.0002:Bo Example";
    let key = key_of(seed);
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

    // First registered undeclared with a login (an ed25519 signer with a
    // client; a client is provisioned only on request, backlog 2f87eb08),
    // then declared: the find-hit returns the row as it is.
    let (status, _) = post(
        &pool,
        &auth,
        serde_json::json!({ "public_key": key, "login": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post(&pool, &auth, declared(seed, "Bo Example")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(stored(&pool, &key).await, ("ed25519".to_string(), 1));
}

/// The route writes on the raw application pool, which in production is the
/// non-bypassing `epigraph_app` login, not the superuser the tests above run
/// on. The seed-derived insert must pass row security there (migration 077's
/// `agents_provision` refuses only `derived`), or every author registration
/// would fail and `ingest_literature` only warns.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seed_derived_declaration_is_stored_on_the_application_role(pool: PgPool) {
    let auth = caller(&pool).await;
    let app_pool = viewer_fixture::downgraded_pool(&pool, "epigraph_app").await;
    let state = AppState::with_db(app_pool, ApiConfig::default());
    let seed = "10.0000/example.0003:Cy Example";
    let author = key_of(seed);
    let (status, body) = post_on(state, &auth, declared(seed, "Cy Example")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        stored(&pool, &author).await,
        ("seed-derived".to_string(), 0)
    );
}

/// The declaration is permanent (the application role cannot rewrite
/// `key_kind`), so it needs a proof of possession: without one, any
/// `agents:write` caller could declare another party's not yet registered key
/// (an `/oauth/register` agent client's key has no agents row) and lock its
/// holder out of every verifier for good. A missing, malformed or wrong-key
/// proof is refused (400, `key_kind_proof`) before any insert; the holder's
/// own proof is accepted for the same key afterwards, so the refusals are a
/// function of the proof.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seed_derived_declaration_needs_the_keys_own_proof(pool: PgPool) {
    let auth = caller(&pool).await;
    // A victim's random key, and a squatter who does not hold it.
    let victim = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let squatter = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let key = hex::encode(victim.verifying_key().to_bytes());

    for (label, proof) in [
        ("missing", serde_json::Value::Null),
        ("malformed", serde_json::Value::from("not-hex")),
        ("short", serde_json::Value::from("00".repeat(63))),
        (
            "squatter's",
            serde_json::Value::from(proof_by(&squatter, &key)),
        ),
    ] {
        let (status, body) = post(
            &pool,
            &auth,
            serde_json::json!({
                "public_key": key, "key_kind": "seed-derived", "key_kind_proof": proof
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label} proof: {body}");
        assert!(
            body.to_string().contains("key_kind_proof"),
            "{label} proof: {body}"
        );
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = decode($1, 'hex')")
                .bind(&key)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rows, 0, "a {label} proof registered the key");
    }

    let (status, body) = post(
        &pool,
        &auth,
        serde_json::json!({
            "public_key": key, "key_kind": "seed-derived",
            "key_kind_proof": proof_by(&victim, &key)
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the holder's own proof: {body}");
    assert_eq!(stored(&pool, &key).await, ("seed-derived".to_string(), 0));
}
