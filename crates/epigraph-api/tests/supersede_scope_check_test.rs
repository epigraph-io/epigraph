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
    // Authored by the token's graph agent, in a group that agent writes (batch
    // OA1: the claim act is decided by write authority, never by comparing the
    // token's `oauth_clients.id` with the claim's author).
    let claim_id =
        common::seed_claim_writable_by_client(&pool, "supersede owner match", client_id).await;

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

/// POST /api/v1/claims/:id/supersede carries the old claim's labels onto the
/// replacement except the novelty gate's per-submission `near-duplicate`
/// flag, which on the replacement would point at its own predecessor. The
/// route runs the shared `ClaimRepository::supersede_act_conn`; this is the
/// HTTP twin of its DB and MCP arms.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_route_does_not_carry_the_near_duplicate_flag() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let claim_id =
        common::seed_claim_writable_by_client(&pool, "supersede label carry", client_id).await;
    sqlx::query("UPDATE claims SET labels = ARRAY['backlog', 'near-duplicate'] WHERE id = $1")
        .bind(claim_id)
        .execute(&pool)
        .await
        .expect("label the claim");

    let body = serde_json::json!({
        "content": "supersede label carry, revised",
        "truth_value": 0.7,
        "reason": "label carry test",
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
        "calibration: the supersession commits; got {status} — body={text}"
    );

    let labels: Vec<String> =
        sqlx::query_scalar("SELECT labels FROM claims WHERE supersedes = $1 AND is_current")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("the replacement");
    assert_eq!(
        labels,
        vec!["backlog".to_string()],
        "every label carries except near-duplicate"
    );
}

/// A supersession whose retirement the database refuses, on a claim the
/// caller is authorised for and reads as current, is a 403 with nothing
/// written; not a 500, and not a successor inserted next to a still-current
/// claim.
///
/// The production producer is a session whose UPDATE policy hides the row
/// while its SELECT policy shows it (an elevated session:
/// `claims_elevated_no_update` / `claims_elevated_read`). A `BEFORE UPDATE`
/// trigger that skips only this claim's row stands in for it deterministically
/// on the shared test database, and is dropped before any assertion.
#[tokio::test(flavor = "multi_thread")]
async fn supersede_the_database_refuses_to_retire_returns_403_and_writes_nothing() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let claim_id = common::seed_claim_writable_by_client(
        &pool,
        &format!("supersede unretirable {}", uuid::Uuid::new_v4()),
        client_id,
    )
    .await;

    let tag = uuid::Uuid::new_v4().simple().to_string();
    let func = format!("aaa_test_skip_retire_{tag}");
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RETURN NULL; END $$; \
         CREATE TRIGGER {func} BEFORE UPDATE ON claims FOR EACH ROW \
         WHEN (OLD.id = '{claim_id}'::uuid) EXECUTE FUNCTION {func}();"
    ))
    .execute(&pool)
    .await
    .expect("install the retirement stand-in");

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{claim_id}/supersede"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "content": "a revision whose original cannot be retired",
            "truth_value": 0.7,
            "reason": "unretirable",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    sqlx::raw_sql(&format!(
        "DROP TRIGGER {func} ON claims; DROP FUNCTION {func}();"
    ))
    .execute(&pool)
    .await
    .expect("drop the retirement stand-in");

    assert_eq!(
        status, 403,
        "a refused retirement is a write refusal; got {status} - body={text}"
    );
    let still_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(still_current, "the original is untouched");
    let successors: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE supersedes = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(successors, 0, "no successor row was inserted");
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'supersedes'",
    )
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(edges, 0, "no supersedes edge was inserted");
}
