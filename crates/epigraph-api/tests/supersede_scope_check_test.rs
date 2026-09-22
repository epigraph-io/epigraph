#![cfg(feature = "db")]
mod common;
use sqlx::postgres::PgPoolOptions;

/// POST /api/v1/claims/:id/supersede with no Authorization header must return 401.
/// Auth check fires before any DB lookup, so a non-existent UUID is sufficient.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let fake_id = uuid::Uuid::new_v4();
    let body = serde_json::json!({
        "content": "new content",
        "truth_value": 0.8,
        "reason": "test reason",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{fake_id}/supersede"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized, got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// POST /api/v1/claims/:id/supersede with a claims:read-only token must return 403.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_with_read_only_token_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:read"]);
    let fake_id = uuid::Uuid::new_v4();
    let body = serde_json::json!({
        "content": "new content",
        "truth_value": 0.8,
        "reason": "test reason",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{fake_id}/supersede"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 Forbidden, got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// POST /api/v1/claims/:id/supersede with a matching-owner token → 200/201.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_matching_owner_returns_success() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let claim_id = common::seed_claim_with_agent(&pool, "supersede owner match", client_id).await;

    let body = serde_json::json!({
        "content": "superseded content",
        "truth_value": 0.7,
        "reason": "ownership test",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim_id}/supersede"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert!(
        status == 200 || status == 201,
        "expected 200/201 for matching owner; got {status} — body={text}"
    );
}

/// POST /api/v1/claims/:id/supersede with a mismatched owner → 403.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_mismatched_owner_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    // Token for principal A
    let (token_a, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    // Claim owned by principal B
    let (_, client_b) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let claim_id = common::seed_claim_with_agent(&pool, "supersede owner mismatch", client_b).await;

    let body = serde_json::json!({
        "content": "unauthorized supersede",
        "truth_value": 0.7,
        "reason": "should fail",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim_id}/supersede"))
        .bearer_auth(&token_a)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 for mismatched owner; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// POST /api/v1/claims/:id/supersede with a valid claims:write token but
/// a non-existent claim UUID → 404.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_nonexistent_claim_returns_404() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;

    let nonexistent = uuid::Uuid::new_v4();
    let body = serde_json::json!({
        "content": "new content",
        "truth_value": 0.8,
        "reason": "test reason",
    });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/claims/{nonexistent}/supersede"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        404,
        "expected 404 for non-existent claim; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ── F-write-authz-reads-unfiltered: the owner lookup is viewer-filtered ─────
//
// `supersede_claim` decides ownership from the claim's `agent_id`. That read
// used to run on the raw pool with no visibility predicate, so a caller who
// cannot READ a claim still got an answer from it: 403 for a non-owner (which
// confirms the id exists) and, for a `claims:admin` token, a successful
// supersede of a claim it cannot see. The read now goes through
// `ClaimRepository::get_agent_id`, which splices `{VISIBILITY:claims}`.
//
// Each refusal is asserted on the ROW as well as the status: an unreadable
// claim must still be current and must have no successor.

/// Seed a claim authored by a fresh agent and make it private to that agent's
/// personal group. Returns `(owner, claim_id)`.
async fn seed_private_claim(pool: &sqlx::PgPool, content: &str) -> (uuid::Uuid, uuid::Uuid) {
    let owner = uuid::Uuid::new_v4();
    let claim_id = common::seed_claim_with_agent(pool, content, owner).await;
    common::seed_private_ownership(pool, claim_id, owner).await;
    (owner, claim_id)
}

/// `(is_current, successor_count)` for `claim_id`.
async fn supersede_state(pool: &sqlx::PgPool, claim_id: uuid::Uuid) -> (bool, i64) {
    sqlx::query_as(
        "SELECT c.is_current, \
                (SELECT COUNT(*) FROM claims s WHERE s.supersedes = c.id) \
           FROM claims c WHERE c.id = $1",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .expect("read supersede state")
}

async fn post_supersede(
    addr: std::net::SocketAddr,
    token: &str,
    claim_id: uuid::Uuid,
) -> (reqwest::StatusCode, String) {
    let body = serde_json::json!({
        "content": "a successor the caller should not be able to write",
        "truth_value": 0.7,
        "reason": "write-authz read filter",
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim_id}/supersede"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.text().await.unwrap_or_default())
}

/// A non-owner who cannot read the claim gets 404, not 403.
///
/// 403 was the owner gate answering from an unfiltered read: it told a stranger
/// that a claim with this id exists and belongs to someone else.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_of_an_unreadable_claim_is_404_not_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (_owner, claim_id) = seed_private_claim(&pool, "supersede unreadable 404").await;
    let stranger = common::test_bearer_token_for_principal(uuid::Uuid::new_v4(), &["claims:write"]);

    let (status, body) = post_supersede(addr, &stranger, claim_id).await;
    assert_eq!(
        status, 404,
        "a claim the caller cannot read must be absent (404), not forbidden (403); body={body}"
    );
    assert_eq!(
        supersede_state(&pool, claim_id).await,
        (true, 0),
        "the refused claim must stay current with no successor"
    );
}

/// `claims:admin` does not reach a claim the admin cannot read.
///
/// Before the fix this returned 201: the admin arm of the owner gate passed on
/// an unfiltered read, and the supersede went through on a claim private to a
/// group the admin is not in.
#[tokio::test(flavor = "multi_thread")]
async fn claims_admin_cannot_supersede_a_claim_it_cannot_read() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (_owner, claim_id) = seed_private_claim(&pool, "supersede unreadable admin").await;
    let admin = common::test_bearer_token_for_principal(
        uuid::Uuid::new_v4(),
        &["claims:write", "claims:admin"],
    );

    let (status, body) = post_supersede(addr, &admin, claim_id).await;
    assert_eq!(
        status, 404,
        "claims:admin must not supersede a claim outside its visibility; body={body}"
    );
    assert_eq!(
        supersede_state(&pool, claim_id).await,
        (true, 0),
        "the refused claim must stay current with no successor"
    );
}

/// Over-suppression guard: the OWNER of the same private claim can still
/// supersede it. Without this leg, a filter that hid every private claim from
/// everyone would pass both tests above.
#[tokio::test(flavor = "multi_thread")]
async fn the_owner_of_a_private_claim_can_still_supersede_it() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (owner, claim_id) = seed_private_claim(&pool, "supersede private owner").await;
    let token = common::test_bearer_token_for_principal(owner, &["claims:write"]);

    let (status, body) = post_supersede(addr, &token, claim_id).await;
    assert_eq!(
        status, 201,
        "the owner reads its own private claim and must be able to supersede it; body={body}"
    );
    assert_eq!(
        supersede_state(&pool, claim_id).await,
        (false, 1),
        "the owner's supersede must retire the claim and create one successor"
    );
}
