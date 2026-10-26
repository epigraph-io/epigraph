#![cfg(feature = "db")]
//! Ruling R-50 (backlog `dae795f8`): epigraph-api has its OWN entity signing
//! key, and the HTTP edge writers attest the edges they INSERT with it, the
//! twins of the MCP writers (R-49). The row carries the attestation digest, the
//! v1 edge signature and `signer_id` = the API's signer agent, and
//! `EdgeSignatureRepository::verify_conn` reports it signed, valid, v1 and
//! matching its row. A dedup hit writes nothing onto the existing row. With no
//! key configured the same writers insert unsigned (the ruling: no fail-closed
//! boot), and the key loader refuses a configured key it cannot use.
//!
//! Families: `POST /api/v1/edges` (symmetric, `if_not_exists` and default
//! arms; the twin of `link_epistemic`), `POST /api/v1/edges/hierarchical`
//! (`link_hierarchical`), `POST /api/v1/claims/:id/relate`, and
//! `POST /api/v1/claims`'s AUTHORED verb-edge (`submit_claim`'s).

use epigraph_api::edge_signer::{self, ApiEdgeSigner};
use epigraph_crypto::{AgentSigner, SignatureScheme};
use epigraph_db::repos::EdgeSignatureRepository;
use epigraph_db::visibility::Viewer;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

mod common;

async fn pool() -> (String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    (url, pool)
}

/// A fresh API key and its signer agent, resolved as `bin/server.rs` does.
async fn api_signer(pool: &PgPool) -> (ApiEdgeSigner, Uuid) {
    let signer = AgentSigner::generate();
    let id = edge_signer::resolve_signer_agent(pool, &signer)
        .await
        .expect("resolve the API signer agent");
    (ApiEdgeSigner::new(signer, id), id)
}

async fn spawn_signed(url: &str, signer: ApiEdgeSigner) -> (SocketAddr, oneshot::Sender<()>) {
    let app = epigraph_api::build_app_for_tests_with_edge_signer(url, signer)
        .await
        .expect("app builds");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (addr, tx)
}

/// The edge carries a verifying v1 attestation by `signer` over its row.
async fn assert_attested(pool: &PgPool, edge: Uuid, signer: Uuid, what: &str) {
    let viewer = Viewer::resolve(pool, Uuid::nil())
        .await
        .expect("public viewer");
    let mut conn = pool.acquire().await.expect("conn");
    let check = EdgeSignatureRepository::verify_conn(&mut conn, &viewer, edge)
        .await
        .expect("verify")
        .unwrap_or_else(|| panic!("{what}: edge {edge} not readable"));
    assert!(
        check.signed && check.signature_valid,
        "{what}: edge {edge}: {check:?}"
    );
    assert_eq!(
        check.signature_scheme,
        Some(SignatureScheme::V1),
        "{what}: {check:?}"
    );
    assert_eq!(check.content_matches, Some(true), "{what}: {check:?}");
    assert_eq!(check.signer_id, Some(signer), "{what}: {check:?}");
}

async fn stored_attestation(pool: &PgPool, edge: Uuid) -> (Option<Vec<u8>>, Option<Uuid>) {
    sqlx::query_as("SELECT signature, signer_id FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge row")
}

fn id_of(v: &serde_json::Value, key: &str) -> Uuid {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {v}"))
        .parse()
        .expect("uuid")
}

async fn post(
    addr: SocketAddr,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert!(status.is_success(), "{path}: {status}: {text}");
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}: {text}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_http_edge_writers_attest_their_edges_with_the_api_key() {
    let (url, pool) = pool().await;
    let (signer, signer_id) = api_signer(&pool).await;
    let (addr, _shutdown) = spawn_signed(&url, signer).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["edges:write"]).await;
    let tag = Uuid::new_v4();
    let mut c = Vec::new();
    for i in 0..9 {
        c.push(common::seed_claim(&pool, &format!("R-50 http endpoint {i} {tag}")).await);
    }

    // POST /api/v1/edges/hierarchical, then the same link again (dedup hit).
    let body = serde_json::json!({
        "source_claim_id": c[0], "target_claim_id": c[1], "relationship": "decomposes_to",
    });
    let first = post(addr, &token, "/api/v1/edges/hierarchical", body.clone()).await;
    let h = id_of(&first, "edge_id");
    assert_attested(&pool, h, signer_id, "edges/hierarchical").await;
    let before = stored_attestation(&pool, h).await;
    let again = post(addr, &token, "/api/v1/edges/hierarchical", body).await;
    assert_eq!(id_of(&again, "edge_id"), h);
    assert_eq!(stored_attestation(&pool, h).await, before);

    // POST /api/v1/edges: the symmetric, if_not_exists and default arms.
    for (i, (rel, if_not_exists, props)) in [
        (
            "CONTRADICTS",
            false,
            serde_json::json!({"why": "symmetric arm"}),
        ),
        (
            "elaborates",
            true,
            serde_json::json!({"why": "if_not_exists arm"}),
        ),
        ("supports", false, serde_json::json!({"why": "default arm"})),
    ]
    .into_iter()
    .enumerate()
    {
        let out = post(
            addr,
            &token,
            "/api/v1/edges",
            serde_json::json!({
                "source_id": c[2 + 2 * i], "target_id": c[3 + 2 * i],
                "source_type": "claim", "target_type": "claim",
                "relationship": rel, "properties": props,
                "if_not_exists": if_not_exists,
            }),
        )
        .await;
        assert_attested(&pool, id_of(&out, "id"), signer_id, &format!("edges {rel}")).await;
    }

    // POST /api/v1/claims/:id/relate: both RELATES_TO edges.
    let out = post(
        addr,
        &token,
        &format!("/api/v1/claims/{}/relate", c[8]),
        serde_json::json!({ "target_claim_id": c[0] }),
    )
    .await;
    let ids = out["edge_ids"].as_array().expect("edge_ids");
    assert_eq!(ids.len(), 2, "{out}");
    for e in ids {
        let e: Uuid = e.as_str().unwrap().parse().unwrap();
        assert_attested(&pool, e, signer_id, "claims/relate").await;
    }
}

/// `POST /api/v1/claims`'s AUTHORED edge (agent -> claim, world-owned): only
/// an INSERT-time attestation can sign it.
#[tokio::test(flavor = "multi_thread")]
async fn create_claim_attests_its_authored_edge() {
    let (url, pool) = pool().await;
    let (signer, signer_id) = api_signer(&pool).await;
    let (addr, _shutdown) = spawn_signed(&url, signer).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let author = common::seed_system_agent(&pool).await;
    let out = post(
        addr,
        &token,
        "/api/v1/claims",
        serde_json::json!({
            "content": format!("R-50: an HTTP claim's AUTHORED edge is signed {}", Uuid::new_v4()),
            "agent_id": author,
        }),
    )
    .await;
    let claim = id_of(&out, "id");
    let authored: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE target_id = $1 AND relationship = 'AUTHORED'",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("the AUTHORED edge");
    assert_attested(&pool, authored, signer_id, "claims AUTHORED").await;
    let author_is_not_signer: Option<Uuid> =
        sqlx::query_scalar("SELECT signer_id FROM edges WHERE id = $1")
            .bind(authored)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_ne!(
        author_is_not_signer,
        Some(author),
        "the signer is not the author"
    );
}

/// Control: with no key configured (every other fixture, and a server with
/// `EPIGRAPH_API_SIGNING_KEY_FILE` unset) the same writer inserts unsigned.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_key_the_http_writers_insert_unsigned() {
    let (url, pool) = pool().await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["edges:write"]).await;
    let tag = Uuid::new_v4();
    let a = common::seed_claim(&pool, &format!("R-50 unsigned a {tag}")).await;
    let b = common::seed_claim(&pool, &format!("R-50 unsigned b {tag}")).await;
    let out = post(
        addr,
        &token,
        "/api/v1/edges/hierarchical",
        serde_json::json!({"source_claim_id": a, "target_claim_id": b, "relationship": "decomposes_to"}),
    )
    .await;
    assert_eq!(
        stored_attestation(&pool, id_of(&out, "edge_id")).await,
        (None, None)
    );
}

/// The key loader: unset is `None` (unsigned, logged once at boot); a file
/// that is not a 32-byte hex key and an unreadable path are refused; a key
/// registered in `agent_keys` resolves only as an ACTIVE `signing` key, to
/// that agent (rotation: no code change); an unregistered key gets its own
/// signer agent named `epigraph-api-signer`.
#[tokio::test(flavor = "multi_thread")]
async fn the_key_loader_admits_only_a_usable_key() {
    let (_url, pool) = pool().await;
    assert!(edge_signer::load(&pool, None).await.unwrap().is_none());
    assert!(edge_signer::load(&pool, Some("  "))
        .await
        .unwrap()
        .is_none());

    let dir = std::env::temp_dir().join(format!("r50-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.key");
    std::fs::write(&bad, "not a key").unwrap();
    let err = edge_signer::load(&pool, Some(bad.to_str().unwrap()))
        .await
        .expect_err("malformed key file");
    assert!(err.contains("not a hex-encoded"), "{err}");
    let err = edge_signer::load(&pool, Some(dir.join("absent.key").to_str().unwrap()))
        .await
        .expect_err("unreadable key file");
    assert!(err.contains("cannot read the key file"), "{err}");

    // An unregistered key: a new signer agent carrying its public key.
    let fresh = AgentSigner::generate();
    let file = dir.join("fresh.key");
    std::fs::write(&file, format!("{}\n", hex::encode(fresh.secret_key()))).unwrap();
    let loaded = edge_signer::load(&pool, Some(file.to_str().unwrap()))
        .await
        .expect("loads")
        .expect("configured");
    let (pk, name): (Vec<u8>, Option<String>) =
        sqlx::query_as("SELECT public_key, display_name FROM agents WHERE id = $1")
            .bind(loaded.signer_id())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pk, fresh.public_key().to_vec());
    assert_eq!(name.as_deref(), Some(edge_signer::SIGNER_DISPLAY_NAME));
    // Loaded twice, the same agent.
    let again = edge_signer::load(&pool, Some(file.to_str().unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.signer_id(), loaded.signer_id());

    // A registered signing key resolves to its agent while ACTIVE, and is
    // refused once revoked.
    let owner = common::seed_system_agent(&pool).await;
    let rotated_in = AgentSigner::generate();
    let row_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'signing', 'active', now() - interval '1 minute')",
    )
    .bind(row_id)
    .bind(owner)
    .bind(rotated_in.public_key().as_slice())
    .execute(&pool)
    .await
    .expect("register the signing key (test superuser)");
    assert_eq!(
        edge_signer::resolve_signer_agent(&pool, &rotated_in)
            .await
            .expect("an active signing key resolves"),
        owner
    );
    sqlx::query("UPDATE agent_keys SET status = 'revoked' WHERE id = $1")
        .bind(row_id)
        .execute(&pool)
        .await
        .unwrap();
    let err = edge_signer::resolve_signer_agent(&pool, &rotated_in)
        .await
        .expect_err("a revoked key is refused");
    assert!(
        err.contains("not an active, in-window signing key"),
        "{err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
