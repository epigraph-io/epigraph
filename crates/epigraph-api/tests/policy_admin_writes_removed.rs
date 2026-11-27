#![cfg(feature = "db")]
//! The three admin policy write routes are gone (backlog ec968070):
//! `POST /api/v1/policies/:claim_id/outcome`, `POST /api/v1/policies/decay-sweep`
//! and `POST /api/v1/policy-challenges/:id/resolve`.
//!
//! Their handlers ran four inline `UPDATE claims` statements on the unstamped
//! pool (a truth-value nudge, a bulk decay sweep, and a challenge resolve that
//! also strengthened every default-deny policy), with no audit row and no
//! viewer. They were deleted rather than given an audited admin write path
//! nobody calls; the challenge create/get routes stay.
//!
//! The arm sends each request with a `claims:admin` token, the scope the old
//! handlers required, and asserts both that it is not routed (404) and that
//! the rows each handler wrote are byte-for-byte what they were. On the old
//! router the outcome request answered 200 and moved the policy's truth value,
//! the sweep answered 200 and pulled the stale policy toward 0.5, and the
//! resolve answered 200, set the challenge's status and raised default-deny.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN: &[&str] = &["claims:read", "claims:write", "claims:admin"];

async fn send(
    router: &axum::Router,
    token: &str,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> StatusCode {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = match body {
        Some(v) => {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    router
        .clone()
        .oneshot(req.body(body).expect("request"))
        .await
        .expect("router")
        .status()
}

/// Turn a seeded public claim into what a handler keyed on: its labels, its
/// properties, its truth value, and an `updated_at` older than the sweep's
/// 90-day cut-off.
async fn shape(
    pool: &PgPool,
    id: Uuid,
    labels: &[&str],
    properties: serde_json::Value,
    truth: f64,
) {
    let labels: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query(
        "UPDATE claims SET labels = $2, properties = $3, truth_value = $4, \
         updated_at = NOW() - INTERVAL '120 days' WHERE id = $1",
    )
    .bind(id)
    .bind(&labels)
    .bind(properties)
    .bind(truth)
    .execute(pool)
    .await
    .expect("shape the policy claim");
}

/// Everything the three handlers wrote, as text so the comparison is exact.
async fn written_state(pool: &PgPool, id: Uuid) -> (String, String, String) {
    sqlx::query_as(
        "SELECT truth_value::text, properties::text, updated_at::text \
         FROM claims WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read the claim's written columns")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_policy_writes_are_not_routed(pool: PgPool) {
    let url = viewer_fixture::database_url_for(&pool).await;
    let router = epigraph_api::build_app_for_tests(&url)
        .await
        .expect("app builds for tests");
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "policy-writes").await;
    let token = common::mint_token_with_agent(ADMIN, agent);

    let policy = viewer_fixture::seed_public_claim(&pool, agent, "policy: example.org:443").await;
    shape(
        &pool,
        policy,
        &["policy:active", "policy:network"],
        serde_json::json!({ "host": "example.org", "port": 443, "protocol": "https" }),
        0.3,
    )
    .await;
    let default_deny =
        viewer_fixture::seed_public_claim(&pool, agent, "policy: default deny").await;
    shape(
        &pool,
        default_deny,
        &["policy:active", "policy:network"],
        serde_json::json!({ "host": "*", "port": 0, "protocol": "any" }),
        0.5,
    )
    .await;
    let challenge = viewer_fixture::seed_public_claim(
        &pool,
        agent,
        "Network access challenge: blocked.example:443 (https)",
    )
    .await;
    shape(
        &pool,
        challenge,
        &["policy", "policy:challenge"],
        serde_json::json!({
            "host": "blocked.example", "port": 443, "protocol": "https", "status": "pending",
        }),
        0.5,
    )
    .await;

    // Control: the kept challenge read answers this token, and the policy list
    // (also kept) still serves the seeded policy.
    let kept = send(
        &router,
        &token,
        Method::GET,
        &format!("/api/v1/policy-challenges/{challenge}"),
        None,
    )
    .await;
    assert_eq!(
        kept,
        StatusCode::OK,
        "CONTROL: GET /api/v1/policy-challenges/:id stays mounted and serves this token, \
         so a 404 below is the router's answer, not an auth refusal"
    );

    let before = [
        written_state(&pool, policy).await,
        written_state(&pool, default_deny).await,
        written_state(&pool, challenge).await,
    ];

    let mut routed = Vec::new();
    for (uri, body) in [
        (
            format!("/api/v1/policies/{policy}/outcome"),
            Some(serde_json::json!({ "supports": true, "strength": 0.5 })),
        ),
        ("/api/v1/policies/decay-sweep".to_string(), None),
        (
            format!("/api/v1/policy-challenges/{challenge}/resolve"),
            Some(serde_json::json!({ "approved": false })),
        ),
    ] {
        let status = send(&router, &token, Method::POST, &uri, body).await;
        if status != StatusCode::NOT_FOUND {
            routed.push(format!("POST {uri} -> {status}"));
        }
    }

    let after = [
        written_state(&pool, policy).await,
        written_state(&pool, default_deny).await,
        written_state(&pool, challenge).await,
    ];
    assert!(
        routed.is_empty(),
        "the three admin policy writes are removed and must answer 404; still routed: \
         {routed:#?}"
    );
    assert_eq!(
        after, before,
        "no policy, default-deny or challenge row may change: [policy, default-deny, challenge]"
    );
}
