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

/// The ids of `claim`'s edges with `relationship` (either endpoint).
async fn edges_of(pool: &PgPool, endpoint: Uuid, relationship: &str) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM edges WHERE (source_id = $1 OR target_id = $1) AND relationship = $2",
    )
    .bind(endpoint)
    .bind(relationship)
    .fetch_all(pool)
    .await
    .expect("edges")
}

/// `POST /api/v1/submit/packet` (the HTTP twin of `submit_claim`):
/// `persist_packet`'s five structural edges, on its stamped claim-write
/// transaction.
#[tokio::test(flavor = "multi_thread")]
async fn submit_packet_attests_its_structural_edges() {
    let (url, pool) = pool().await;
    let (signer, signer_id) = api_signer(&pool).await;
    let (addr, _shutdown) = spawn_signed(&url, signer).await;
    let author = common::seed_system_agent(&pool).await;
    let token = common::mint_token_with_agent(&["claims:write"], author);
    let content = format!(
        "R-50: a packet's structural edges are signed {}",
        Uuid::new_v4()
    );
    let evidence = format!("evidence for {content}");
    let evidence_hash = epigraph_crypto::ContentHasher::to_hex(
        &epigraph_crypto::ContentHasher::hash(evidence.as_bytes()),
    );
    let out = post(
        addr,
        &token,
        "/api/v1/submit/packet",
        serde_json::json!({
            "claim": { "content": content, "initial_truth": 0.7, "agent_id": author },
            "evidence": [{
                "content_hash": evidence_hash,
                "evidence_type": {
                    "type": "observation", "observed_at": chrono::Utc::now(),
                    "method": "test", "location": null
                },
                "raw_content": evidence,
                "signature": null
            }],
            "reasoning_trace": {
                "methodology": "deductive",
                "inputs": [{"type": "evidence", "index": 0}],
                "confidence": 0.7, "explanation": "test", "signature": null
            },
            "signature": "0".repeat(128)
        }),
    )
    .await;
    let claim = id_of(&out, "claim_id");
    for rel in ["AUTHORED", "HAS_TRACE", "TRACES", "SUPPORTS"] {
        let edges = edges_of(&pool, claim, rel).await;
        assert_eq!(edges.len(), 1, "{rel}: {edges:?} ({out})");
        assert_attested(&pool, edges[0], signer_id, &format!("packet {rel}")).await;
    }
    let uses: Vec<Uuid> = sqlx::query_scalar(
        "SELECT e.id FROM edges e JOIN reasoning_traces t ON t.id = e.source_id \
          WHERE t.claim_id = $1 AND e.relationship = 'USES_EVIDENCE'",
    )
    .bind(claim)
    .fetch_all(&pool)
    .await
    .expect("USES_EVIDENCE");
    assert_eq!(uses.len(), 1, "{uses:?}");
    assert_attested(&pool, uses[0], signer_id, "packet USES_EVIDENCE").await;
}

/// `POST /api/v1/frames/:id/evidence` (`submit_evidence`): its WITHIN_FRAME
/// edge (claim -> frame, structural), under the stamped transaction's
/// savepoint. Its `evidence`-typed SUPPORTS / CONTRADICTS / GENERATED_BY edges
/// (and `assess_claim`'s) name a `mass_functions` id as `evidence`, which
/// `edges_validate_refs` refuses: dead writes (`unstamped_http_edge_writes.rs`),
/// so there is no row to check.
#[tokio::test(flavor = "multi_thread")]
async fn submit_evidence_attests_its_edges() {
    let (url, pool) = pool().await;
    let (signer, signer_id) = api_signer(&pool).await;
    let (addr, _shutdown) = spawn_signed(&url, signer).await;
    let agent = common::seed_system_agent(&pool).await;
    let claim =
        common::seed_claim(&pool, &format!("R-50 evidence target {}", Uuid::new_v4())).await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['TRUE','FALSE']::text[]) \
         RETURNING id",
    )
    .bind(format!("r50-frame-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let token = common::mint_token_with_agent(&["claims:read", "claims:write"], agent);
    post(
        addr,
        &token,
        &format!("/api/v1/frames/{frame}/evidence"),
        serde_json::json!({
            "claim_id": claim, "agent_id": agent,
            "masses": {"0": 0.8, "0,1": 0.2},
            "reliability": 1.0,
        }),
    )
    .await;
    let within: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 \
            AND relationship = 'WITHIN_FRAME'",
    )
    .bind(claim)
    .bind(frame)
    .fetch_all(&pool)
    .await
    .expect("WITHIN_FRAME");
    assert_eq!(within.len(), 1, "{within:?}");
    assert_attested(&pool, within[0], signer_id, "submit_evidence WITHIN_FRAME").await;
}

/// A writer on the UNSTAMPED raw pool (`POST /api/v1/perspectives`'s
/// PERSPECTIVE_OF, through `EdgeRepository::create_signed`): signed too.
#[tokio::test(flavor = "multi_thread")]
async fn a_raw_pool_writer_attests_its_edge() {
    let (url, pool) = pool().await;
    let (signer, signer_id) = api_signer(&pool).await;
    let (addr, _shutdown) = spawn_signed(&url, signer).await;
    let owner = common::seed_system_agent(&pool).await;
    let token = common::mint_token_with_agent(&["claims:write"], owner);
    let out = post(
        addr,
        &token,
        "/api/v1/perspectives",
        serde_json::json!({
            "name": format!("R-50 perspective {}", Uuid::new_v4()),
            "owner_agent_id": owner,
        }),
    )
    .await;
    let perspective = id_of(&out, "id");
    let edges = edges_of(&pool, perspective, "PERSPECTIVE_OF").await;
    assert_eq!(edges.len(), 1, "{edges:?}");
    assert_attested(&pool, edges[0], signer_id, "perspectives PERSPECTIVE_OF").await;
}

/// The single-edge CRUD and span writers, on the raw pool:
/// `POST /api/v1/evidence` (claim -> evidence DERIVED_FROM),
/// `POST /api/v1/reasoning-traces` (claim -> trace HAS_TRACE),
/// `POST /api/v1/spans` (agent -> span attributed_to) and
/// `PUT /api/v1/spans/:id/close` (span -> claim generated).
#[tokio::test(flavor = "multi_thread")]
async fn the_evidence_trace_and_span_writers_attest_their_edges() {
    let (url, pool) = pool().await;
    let (signer, signer_id) = api_signer(&pool).await;
    let (addr, _shutdown) = spawn_signed(&url, signer).await;
    let agent = common::seed_system_agent(&pool).await;
    let token = common::mint_token_with_agent(&["claims:write", "evidence:write"], agent);
    let claim = common::seed_claim(&pool, &format!("R-50 crud target {}", Uuid::new_v4())).await;
    let between = |s: Uuid, t: Uuid, rel: &'static str| {
        let pool = pool.clone();
        async move {
            let ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 \
                    AND relationship = $3",
            )
            .bind(s)
            .bind(t)
            .bind(rel)
            .fetch_all(&pool)
            .await
            .expect("edges");
            assert_eq!(ids.len(), 1, "{rel}: {ids:?}");
            ids[0]
        }
    };

    let ev = post(
        addr,
        &token,
        "/api/v1/evidence",
        serde_json::json!({
            "agent_id": agent, "claim_id": claim,
            "raw_content": "R-50 evidence body",
            "evidence_type": {
                "type": "observation", "observed_at": chrono::Utc::now(),
                "method": "test", "location": null
            },
        }),
    )
    .await;
    let e = between(claim, id_of(&ev, "id"), "DERIVED_FROM").await;
    assert_attested(&pool, e, signer_id, "evidence DERIVED_FROM").await;

    let tr = post(
        addr,
        &token,
        "/api/v1/reasoning-traces",
        serde_json::json!({
            "claim_id": claim, "agent_id": agent, "methodology": "deductive",
            "confidence": 0.7, "explanation": "R-50 trace",
        }),
    )
    .await;
    let e = between(claim, id_of(&tr, "id"), "HAS_TRACE").await;
    assert_attested(&pool, e, signer_id, "reasoning-traces HAS_TRACE").await;

    let span = post(
        addr,
        &token,
        "/api/v1/spans",
        serde_json::json!({
            "trace_id": Uuid::new_v4().simple().to_string(),
            "span_name": "r50-span", "agent_id": agent,
        }),
    )
    .await;
    let span_id = id_of(&span, "id");
    let e = between(agent, span_id, "attributed_to").await;
    assert_attested(&pool, e, signer_id, "spans attributed_to").await;

    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/spans/{span_id}/close"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "generated_ids": [claim] }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status.is_success(),
        "close span: {status}: {}",
        resp.text().await.unwrap()
    );
    let e = between(span_id, claim, "generated").await;
    assert_attested(&pool, e, signer_id, "spans/close generated").await;
}
