#![cfg(feature = "db")]
//! Every HTTP route that files evidence stores the evidence's edge to its
//! claim, signed with the API key (backlog 2d60f619; operator ruling: the
//! Atlas leaf view draws stored `evidence -> claim` edges only).
//!
//! * `POST /api/v1/evidence` (`crud::create_evidence`): `supports`; a claim
//!   that does not exist is refused and nothing is written.
//! * `POST /api/v1/conventions` (`learn_convention`): `supports`, now written
//!   by the evidence write itself rather than a separate best-effort edge.
//! * `DELETE /api/v1/conventions/:id` (`forget_convention`): `refutes`, in the
//!   same caller-stamped transaction as the evidence row.
//! * `POST /api/v1/submit/packet` is pinned by
//!   `edge_signing_http_writers::submit_packet_attests_its_structural_edges`
//!   (exactly one attested `supports` edge per packet claim).

use epigraph_api::edge_signer::{self, ApiEdgeSigner};
use epigraph_crypto::AgentSigner;
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

async fn spawn_signed(pool: &PgPool, url: &str) -> (SocketAddr, oneshot::Sender<()>, Uuid) {
    let signer = AgentSigner::generate();
    let signer_id = edge_signer::resolve_signer_agent(pool, &signer)
        .await
        .expect("resolve the API signer agent");
    let app = epigraph_api::build_app_for_tests_with_edge_signer(
        url,
        ApiEdgeSigner::new(signer, signer_id),
    )
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
    (addr, tx, signer_id)
}

/// The one edge from evidence `ev`: it targets `claim` with `relationship`,
/// is no wider than the evidence row, and carries a verifying attestation
/// by the API's signer.
async fn assert_evidence_edge(
    pool: &PgPool,
    ev: Uuid,
    claim: Uuid,
    relationship: &str,
    signer: Uuid,
    what: &str,
) {
    let edges: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(
        "SELECT id, target_id, relationship, visibility::text FROM edges \
          WHERE source_type = 'evidence' AND source_id = $1",
    )
    .bind(ev)
    .fetch_all(pool)
    .await
    .expect("edges");
    assert_eq!(edges.len(), 1, "{what}: one edge from {ev}: {edges:?}");
    let (edge, target, rel, vis) = edges[0].clone();
    assert_eq!((target, rel.as_str()), (claim, relationship), "{what}");
    let ev_vis: String = sqlx::query_scalar("SELECT visibility::text FROM evidence WHERE id = $1")
        .bind(ev)
        .fetch_one(pool)
        .await
        .expect("evidence visibility");
    assert!(
        vis == ev_vis || ev_vis == "public",
        "{what}: the edge ({vis}) is never wider than its evidence ({ev_vis})"
    );
    let viewer = Viewer::resolve(pool, Uuid::nil())
        .await
        .expect("public viewer");
    let mut conn = pool.acquire().await.expect("conn");
    let check = EdgeSignatureRepository::verify_conn(&mut conn, &viewer, edge)
        .await
        .expect("verify")
        .unwrap_or_else(|| panic!("{what}: edge {edge} not readable"));
    assert!(
        check.signed && check.signature_valid && check.signer_id == Some(signer),
        "{what}: {check:?}"
    );
}

async fn post(
    addr: SocketAddr,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
    )
}

fn id_of(v: &serde_json::Value, key: &str) -> Uuid {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {v}"))
        .parse()
        .expect("uuid")
}

fn observation(body: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "observation", "observed_at": chrono::Utc::now(),
        "method": body, "location": null
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn post_evidence_stores_a_signed_supports_edge_and_refuses_no_claim() {
    let (url, pool) = pool().await;
    let (addr, _shutdown, signer) = spawn_signed(&pool, &url).await;
    let agent = common::seed_system_agent(&pool).await;
    let token = common::mint_token_with_agent(&["claims:write", "evidence:write"], agent);
    let claim = common::seed_claim(&pool, &format!("2d60f619 crud {}", Uuid::new_v4())).await;

    let (status, ev) = post(
        addr,
        &token,
        "/api/v1/evidence",
        serde_json::json!({
            "agent_id": agent, "claim_id": claim,
            "raw_content": format!("2d60f619 evidence {}", Uuid::new_v4()),
            "evidence_type": observation("test"),
        }),
    )
    .await;
    assert!(status.is_success(), "{status}: {ev}");
    assert_evidence_edge(
        &pool,
        id_of(&ev, "id"),
        claim,
        "supports",
        signer,
        "POST /evidence",
    )
    .await;

    let nowhere = Uuid::new_v4();
    let (status, body) = post(
        addr,
        &token,
        "/api/v1/evidence",
        serde_json::json!({
            "agent_id": agent, "claim_id": nowhere,
            "raw_content": "evidence that applies to no claim",
            "evidence_type": observation("test"),
        }),
    )
    .await;
    assert!(
        !status.is_success(),
        "evidence on no claim is refused: {status}: {body}"
    );
    let written: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM evidence WHERE claim_id = $1) \
              + (SELECT count(*) FROM edges WHERE target_id = $1)",
    )
    .bind(nowhere)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(written, 0, "nothing written");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_convention_routes_store_supports_then_refutes() {
    let (url, pool) = pool().await;
    let (addr, _shutdown, signer) = spawn_signed(&pool, &url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:admin"]).await;

    let (status, learned) = post(
        addr,
        &token,
        "/api/v1/conventions",
        serde_json::json!({
            "content": format!("2d60f619 convention {}", Uuid::new_v4()),
            "evidence": format!("2d60f619 seen {}", Uuid::new_v4()),
        }),
    )
    .await;
    assert_eq!(status.as_u16(), 201, "{learned}");
    let claim = id_of(&learned, "claim_id");
    let learned_ev: Uuid = sqlx::query_scalar("SELECT id FROM evidence WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("the learned convention's evidence");
    assert_evidence_edge(
        &pool,
        learned_ev,
        claim,
        "supports",
        signer,
        "learn_convention",
    )
    .await;

    let resp = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/conventions/{claim}"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert_eq!(status.as_u16(), 200, "{}", resp.text().await.unwrap());
    let forgot_ev: Uuid =
        sqlx::query_scalar("SELECT id FROM evidence WHERE claim_id = $1 AND id <> $2")
            .bind(claim)
            .bind(learned_ev)
            .fetch_one(&pool)
            .await
            .expect("the deprecation's evidence");
    assert_evidence_edge(
        &pool,
        forgot_ev,
        claim,
        "refutes",
        signer,
        "forget_convention",
    )
    .await;
}
