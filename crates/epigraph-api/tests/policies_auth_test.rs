#![cfg(feature = "db")]
mod common;

use uuid::Uuid;

// ── record_outcome ────────────────────────────────────────────────────────────

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn record_outcome_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let claim_id = Uuid::new_v4();
    let body = serde_json::json!({ "supports": true, "strength": 0.1 });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/{claim_id}/outcome"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:write token (insufficient) → 403.
#[tokio::test(flavor = "multi_thread")]
async fn record_outcome_with_wrong_scope_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let claim_id = Uuid::new_v4();
    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let body = serde_json::json!({ "supports": true, "strength": 0.1 });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/{claim_id}/outcome"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 Forbidden; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:admin token + valid policy claim → 200.
#[tokio::test(flavor = "multi_thread")]
async fn record_outcome_with_admin_scope_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // Seed a policy:active claim so the UPDATE WHERE finds a row.
    let claim_id = common::seed_claim_with_labels(
        &pool,
        "test network policy record_outcome",
        &["policy:active", "policy:network"],
    )
    .await;

    let token = common::test_bearer_token_with_scopes(&["claims:admin"]);
    let body = serde_json::json!({ "supports": true, "strength": 0.05 });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/{claim_id}/outcome"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 OK; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ── decay_sweep ───────────────────────────────────────────────────────────────

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn decay_sweep_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/decay-sweep"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:admin token → 200.
#[tokio::test(flavor = "multi_thread")]
async fn decay_sweep_with_admin_scope_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:admin"]);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/decay-sweep"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 OK; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ── create_challenge ──────────────────────────────────────────────────────────

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn create_challenge_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let body = serde_json::json!({ "host": "example.com", "port": 443 });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policy-challenges"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:write token → 200 (create_challenge needs claims:write).
#[tokio::test(flavor = "multi_thread")]
async fn create_challenge_with_claims_write_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let body = serde_json::json!({ "host": "example.com", "port": 443 });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policy-challenges"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 OK; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ── resolve_challenge ─────────────────────────────────────────────────────────

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn resolve_challenge_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let challenge_id = Uuid::new_v4();
    let body = serde_json::json!({ "approved": true });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/policy-challenges/{challenge_id}/resolve"
        ))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:write token (insufficient) → 403.
#[tokio::test(flavor = "multi_thread")]
async fn resolve_challenge_with_wrong_scope_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let challenge_id = Uuid::new_v4();
    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let body = serde_json::json!({ "approved": true });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/policy-challenges/{challenge_id}/resolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 Forbidden; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:admin token + valid challenge claim → 200.
#[tokio::test(flavor = "multi_thread")]
async fn resolve_challenge_with_admin_scope_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // Seed a challenge claim directly.
    let challenge_id = common::seed_claim_with_labels(
        &pool,
        "test policy challenge resolve_challenge",
        &["policy", "policy:challenge"],
    )
    .await;
    // Set status=pending in properties.
    sqlx::query(
        "UPDATE claims SET properties = '{\"host\":\"test.com\",\"port\":443,\"status\":\"pending\"}'::jsonb WHERE id = $1",
    )
    .bind(challenge_id)
    .execute(&pool)
    .await
    .unwrap();

    let token = common::test_bearer_token_with_scopes(&["claims:admin"]);
    let body = serde_json::json!({ "approved": true });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/policy-challenges/{challenge_id}/resolve"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 OK; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

// ── decide_match_candidate ──────────────────────────────────────────────────

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn decide_candidate_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let candidate_id = Uuid::new_v4();
    let body = serde_json::json!({ "verdict": "reject" });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/match_candidates/{candidate_id}/decide"
        ))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:read token (insufficient) → 403.
#[tokio::test(flavor = "multi_thread")]
async fn decide_candidate_with_wrong_scope_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let candidate_id = Uuid::new_v4();
    let token = common::test_bearer_token_with_scopes(&["claims:read"]);
    let body = serde_json::json!({ "verdict": "reject" });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/match_candidates/{candidate_id}/decide"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 Forbidden; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:write token + pending candidate → 200, status flips to rejected.
#[tokio::test(flavor = "multi_thread")]
async fn decide_candidate_reject_with_claims_write_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let claim_a = common::seed_claim_with_labels(&pool, "decide test claim a", &[]).await;
    let claim_b = common::seed_claim_with_labels(&pool, "decide test claim b", &[]).await;
    let (lo, hi) = if claim_a < claim_b {
        (claim_a, claim_b)
    } else {
        (claim_b, claim_a)
    };
    let candidate_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
         VALUES ($1, $2, 0.7, '{}'::jsonb, 'pending') RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .unwrap();

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let body = serde_json::json!({ "verdict": "reject" });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/match_candidates/{candidate_id}/decide"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "body={}",
        resp.text().await.unwrap_or_default()
    );

    let status: String = sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(candidate_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "rejected");
}

/// Deciding an already-decided candidate → 409 Conflict.
#[tokio::test(flavor = "multi_thread")]
async fn decide_candidate_already_decided_returns_409() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let claim_a = common::seed_claim_with_labels(&pool, "already decided a", &[]).await;
    let claim_b = common::seed_claim_with_labels(&pool, "already decided b", &[]).await;
    let (lo, hi) = if claim_a < claim_b {
        (claim_a, claim_b)
    } else {
        (claim_b, claim_a)
    };
    let candidate_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
         VALUES ($1, $2, 0.7, '{}'::jsonb, 'rejected') RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .unwrap();

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let body = serde_json::json!({ "verdict": "promote" });
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/match_candidates/{candidate_id}/decide"
        ))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        409,
        "body={}",
        resp.text().await.unwrap_or_default()
    );
}

/// Seed two fresh claims and a pending candidate carrying `verdict`.
/// Returns `(claim_a, claim_b, candidate_id)`.
async fn seed_pending_candidate_with_verdict(
    pool: &sqlx::PgPool,
    label: &str,
    verdict: &str,
) -> (Uuid, Uuid, Uuid) {
    let claim_a =
        common::seed_claim_with_labels(pool, &format!("{label} a {}", Uuid::new_v4()), &[]).await;
    let claim_b =
        common::seed_claim_with_labels(pool, &format!("{label} b {}", Uuid::new_v4()), &[]).await;
    let (lo, hi) = if claim_a < claim_b {
        (claim_a, claim_b)
    } else {
        (claim_b, claim_a)
    };
    let candidate_id: Uuid = sqlx::query_scalar(
        "INSERT INTO match_candidates
             (claim_a, claim_b, score, features, status, verifier_verdict, verifier_rationale)
         VALUES ($1, $2, 0.8, '{}'::jsonb, 'pending', $3, 'test rationale') RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .bind(verdict)
    .fetch_one(pool)
    .await
    .unwrap();
    (claim_a, claim_b, candidate_id)
}

async fn edge_relationships(pool: &sqlx::PgPool, a: Uuid, b: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT relationship FROM edges
         WHERE (source_id = $1 AND target_id = $2)
            OR (source_id = $2 AND target_id = $1)
         ORDER BY relationship",
    )
    .bind(a)
    .bind(b)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Promoting a pair the verifier judged CONTRADICTORY must record a
/// `contradicts` edge, not a corroboration.
///
/// The promote arm wrote `"CORROBORATES"` unconditionally and carried
/// `verifier_verdict` along only as an opaque props key, so approving a
/// contradiction asserted the exact inverse of what the verifier found.
///
/// Lowercase `contradicts` is load-bearing:
/// `epigraph_engine::matching::policy`'s `WriteContradicts` arm writes that
/// exact string on the automatic path, and
/// `EdgeRepository::create_symmetric_if_absent` dedups on an exact
/// `relationship =` comparison — a different casing here would double-write
/// pairs the automatic path had already handled.
#[tokio::test(flavor = "multi_thread")]
async fn decide_candidate_promote_contradicts_writes_contradicts_edge() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (claim_a, claim_b, candidate_id) =
        seed_pending_candidate_with_verdict(&pool, "decide contradicts", "contradicts").await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/match_candidates/{candidate_id}/decide"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "verdict": "promote" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "promoting a contradicts candidate must succeed; body={}",
        resp.text().await.unwrap_or_default()
    );

    let rels = edge_relationships(&pool, claim_a, claim_b).await;
    assert_eq!(
        rels.len(),
        1,
        "promote must write exactly one edge, got {rels:?}"
    );
    assert_eq!(
        rels[0], "contradicts",
        "a 'contradicts' verdict must record a contradiction, not a corroboration"
    );
}

/// `distinct` means the verifier found the pair unrelated — there is no edge
/// worth writing in either polarity, so promote must be refused (400) with no
/// edge written and the row left `pending` so it can still be rejected.
#[tokio::test(flavor = "multi_thread")]
async fn decide_candidate_promote_distinct_returns_400_and_writes_no_edge() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (claim_a, claim_b, candidate_id) =
        seed_pending_candidate_with_verdict(&pool, "decide distinct", "distinct").await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/match_candidates/{candidate_id}/decide"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "verdict": "promote" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "expected a refusal for a 'distinct' pair"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("distinct"),
        "refusal must name the verdict that blocked it: {body}"
    );

    let rels = edge_relationships(&pool, claim_a, claim_b).await;
    assert!(rels.is_empty(), "refused promote wrote edges: {rels:?}");

    // The refusal must short-circuit BEFORE set_status, or the row is left
    // `promoted` with no edge — the half-state the policy layer already fixed.
    let status: String = sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(candidate_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "pending",
        "a refused promote must not mark the row decided"
    );
}

/// Corroborating verdicts keep the historical relationship — pins the
/// unchanged half of the branch.
#[tokio::test(flavor = "multi_thread")]
async fn decide_candidate_promote_same_still_writes_corroborates() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let (claim_a, claim_b, candidate_id) =
        seed_pending_candidate_with_verdict(&pool, "decide same", "same").await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{addr}/api/v1/match_candidates/{candidate_id}/decide"
        ))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "verdict": "promote" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "body={}",
        resp.text().await.unwrap_or_default()
    );

    let rels = edge_relationships(&pool, claim_a, claim_b).await;
    assert_eq!(rels, vec!["CORROBORATES".to_string()]);
}

// ── list_match_candidates ───────────────────────────────────────────────────
//
// `list_candidates` reads pending cross-source match candidates *and* the
// verbatim content excerpts of both claims in each pair. It must fail closed
// on its own rather than relying on the router placing it behind the
// protected chain — the `#[cfg(not(feature = "db"))]` router registers this
// same path under `public`, which is exactly the placement that would make a
// scope-less handler fail open.

/// No token → 401.
#[tokio::test(flavor = "multi_thread")]
async fn list_candidates_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/match_candidates?status=pending&limit=10"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "expected 401 Unauthorized; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:write token (insufficient for a read endpoint) → 403.
///
/// `epigraph_auth::check_scopes` is strictly conjunctive with no read/write
/// ladder, so `claims:write` alone does NOT confer `claims:read`. Mirrors
/// `decide_candidate_with_wrong_scope_returns_403`, which asserts the dual.
#[tokio::test(flavor = "multi_thread")]
async fn list_candidates_with_wrong_scope_returns_403() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/match_candidates?status=pending&limit=10"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        403,
        "expected 403 Forbidden; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// claims:read token → 200 (positive control: the guard admits the right scope).
#[tokio::test(flavor = "multi_thread")]
async fn list_candidates_with_claims_read_returns_200() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let token = common::test_bearer_token_with_scopes(&["claims:read"]);
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/match_candidates?status=pending&limit=10"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 OK; got {} — body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}
