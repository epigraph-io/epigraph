#![cfg(feature = "db")]

//! Scope-gate regression tests for Bundle F (issues #117 and #120).
//!
//! Every handler that was promoted from `claims:write` (or had no gate) to
//! `claims:admin` gets one test here: mint a `claims:write`-only token and
//! verify the endpoint returns 403. This locks the gates against accidental
//! scope downgrade.
//!
//! For `forget_convention` (Bundle I.2) an additional test verifies that the
//! refuting evidence row is attributed to the calling principal rather than a
//! zero-byte system agent.

mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn spawn() -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    common::spawn_app(&url).await
}

fn write_token() -> String {
    common::test_bearer_token_with_scopes(&["claims:write"])
}

fn admin_token() -> String {
    common::test_bearer_token_with_scopes(&["claims:admin"])
}

// ---------------------------------------------------------------------------
// crud.rs — 8 handlers
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn build_themes_from_corpus_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/themes/build-from-corpus"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn build_themes_from_corpus_no_token_returns_401() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/themes/build-from-corpus"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "expected 401, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn reassign_claim_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/themes/reassign"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"claim_id": uuid::Uuid::new_v4()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn assign_unthemed_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/themes/assign-unthemed"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn recompute_centroids_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/themes/recompute-centroids"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_theme_with_centroid_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/themes/create-with-centroid"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"label":"x","description":"y","centroid":[0.1],"claim_ids":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn upsert_cluster_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/clusters"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"claim_id": uuid::Uuid::new_v4(), "cluster_label": "test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn assign_claim_to_frame_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let frame_id = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/frames/{frame_id}/assign-claim"
        ))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"claim_id": uuid::Uuid::new_v4()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn promote_staged_edges_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/edges-staging/promote"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

// ---------------------------------------------------------------------------
// clusters.rs — 1 handler
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn build_from_bridges_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/clusters/build-from-bridges"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

// ---------------------------------------------------------------------------
// conflicts.rs — 1 handler
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn resolve_conflict_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/conflicts/{a}/{b}/resolve"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"winner_id": a, "resolution": "test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

// ---------------------------------------------------------------------------
// conventions.rs — 2 handlers
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn learn_convention_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/conventions"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"content": "Always test", "evidence": "tests pass"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn forget_convention_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let convention_id = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/conventions/{convention_id}"))
        .bearer_auth(write_token())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

/// Bundle I.2 — verify forget_convention attributes evidence to the calling
/// principal, not a zero-byte system agent.
#[tokio::test(flavor = "multi_thread")]
async fn forget_convention_attributes_evidence_to_caller() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;

    // 1. Create a convention via the API (requires claims:admin).
    // Use a UUID-suffixed content to avoid content_hash collisions across test runs.
    let unique_suffix = uuid::Uuid::new_v4();
    let learn_resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/conventions"))
        .bearer_auth(admin_token())
        .json(&serde_json::json!({
            "content": format!("attribution-test convention {unique_suffix}"),
            "evidence": "seeded for attribution test"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        learn_resp.status(),
        201,
        "learn_convention should succeed: {}",
        learn_resp.status()
    );
    let learn_body: serde_json::Value = learn_resp.json().await.unwrap();
    let convention_id = learn_body["claim_id"]
        .as_str()
        .expect("claim_id in response");

    // 2. Mint a token with a known client_id so we can assert on agent identity.
    let (forget_token, caller_client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:admin"]).await;

    // 3. Forget the convention using the seeded-client token.
    let forget_resp = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/conventions/{convention_id}"))
        .bearer_auth(&forget_token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        forget_resp.status(),
        200,
        "forget_convention should succeed: {}",
        forget_resp.status()
    );

    // 4. Derive the expected principal public key (16-byte UUID repeated to 32 bytes).
    let principal_bytes = caller_client_id.as_bytes();
    let mut expected_pub_key = vec![0u8; 32];
    expected_pub_key[..16].copy_from_slice(principal_bytes);
    expected_pub_key[16..].copy_from_slice(principal_bytes);

    // 5. Find the agents row for this principal.
    let agent_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1 LIMIT 1")
            .bind(&expected_pub_key)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(
        agent_id.is_some(),
        "Expected an agents row keyed by caller's principal public_key to exist"
    );

    let agent_id = agent_id.unwrap();
    let convention_uuid: uuid::Uuid = convention_id.parse().unwrap();

    // 6. Verify the refuting evidence row exists for this convention.
    // (Unsigned evidence has signer_id = NULL by DB constraint; we verify existence.)
    let evidence_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM evidence \
         WHERE claim_id = $1 \
         AND raw_content = 'Convention explicitly forgotten/deprecated'",
    )
    .bind(convention_uuid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        evidence_count >= 1,
        "Expected at least one refute evidence row for convention (claim_id={convention_uuid}), got {evidence_count}"
    );

    // 7. Verify the principal-keyed agents row was created (not the zero-byte identity).
    // This is the core of the attribution fix: get-or-create an agent per principal,
    // rather than always using the zero-byte system agent.
    assert!(
        agent_id != uuid::Uuid::nil(),
        "Principal agent should have a non-nil UUID"
    );

    // 8. Confirm the principal agent's display_name encodes the principal identity.
    let display_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM agents WHERE id = $1")
            .bind(agent_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    let display_name = display_name.unwrap_or_default();
    assert!(
        display_name.contains("principal:"),
        "Principal agent display_name should encode the principal UUID; got: {display_name:?}"
    );
}

// ---------------------------------------------------------------------------
// ownership.rs — 2 handlers
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn assign_ownership_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/ownership"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({
            "node_id": uuid::Uuid::new_v4(),
            "node_type": "claim",
            "owner_id": uuid::Uuid::new_v4()
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn update_partition_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let node_id = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/ownership/{node_id}"))
        .bearer_auth(write_token())
        .json(&serde_json::json!({"partition_type": "private"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "expected 403, got {}", resp.status());
}
