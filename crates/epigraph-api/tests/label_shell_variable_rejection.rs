#![cfg(feature = "db")]
//! Regression test: an unexpanded shell variable reached `claims.labels`.
//!
//! Claim `2a0125e2` carries the literal label `group:$EPICLAW_GROUP_ID`. No
//! label-content validation existed on any write path, so the label array an
//! agent script built with an un-interpolated `$VAR` was stored verbatim — a
//! *silent* grouping failure: the label reads as a membership signal while
//! matching no group that can ever exist.
//!
//! These tests pin the HTTP contract of the fix, which is more than "an error
//! happens":
//!   * `POST /api/v1/claims` refuses BEFORE the row is written (400, no claim);
//!   * `PATCH /api/v1/claims/:id/labels` refuses with **400, not 500** — the
//!     handler matches on `DbError` explicitly, so without an `InvalidData` arm
//!     the rejection degrades into a database-fault 500; and
//!   * `remove` is still accepted for an already-corrupted value, because that
//!     is the only remediation path for the rows already in the graph.

mod common;
use sqlx::postgres::PgPoolOptions;

/// The exact corrupted value observed in the graph.
const BAD_LABEL: &str = "group:$EPICLAW_GROUP_ID";

/// The `oneshot::Sender` returned by `spawn_app` must stay alive for the whole
/// test — dropping it shuts the server down.
type ShutdownGuard = tokio::sync::oneshot::Sender<()>;

async fn pool_and_app() -> (sqlx::PgPool, std::net::SocketAddr, ShutdownGuard) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, shutdown) = common::spawn_app(&url).await;
    (pool, addr, shutdown)
}

/// `POST /api/v1/claims` must refuse labels-at-creation carrying `$VAR`, and
/// must not leave a claim row behind.
#[tokio::test(flavor = "multi_thread")]
async fn post_claims_rejects_unexpanded_label_and_writes_no_row() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let agent = common::seed_system_agent(&pool).await;
    let (token, _) = common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let content = format!("shell-var label rejection {}", uuid::Uuid::new_v4());

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "content": content,
            "agent_id": agent,
            "labels": ["fine-label", BAD_LABEL],
        }))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, 400,
        "an unexpanded shell variable in `labels` must be a 400; got {status} — body={text}"
    );

    // The refusal must happen before the INSERT, not after it.
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(&content)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        rows, 0,
        "the claim was written despite the 400 — validation is running too late"
    );
}

/// `PATCH /api/v1/claims/:id/labels` must answer 400 (caller error), NOT 500
/// (database fault), and must leave the stored label array untouched.
#[tokio::test(flavor = "multi_thread")]
async fn patch_labels_rejects_unexpanded_add_with_400_not_500() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let claim_id = common::seed_claim_with_agent(
        &pool,
        &format!("shell-var patch rejection {}", uuid::Uuid::new_v4()),
        client_id,
    )
    .await;

    // Give the claim a label so "unchanged" is a distinguishable state rather
    // than the empty array it starts in.
    let seeded = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{claim_id}/labels"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "add": ["keeper"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(seeded.status(), 200, "seeding a good label should succeed");

    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{claim_id}/labels"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "add": ["also-fine", BAD_LABEL] }))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, 400,
        "a refused label is caller error; 500 means the InvalidData arm is \
         missing from the handler's DbError match. got {status} — body={text}"
    );

    let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        labels,
        vec!["keeper".to_string()],
        "a refused array must be applied atomically-not-at-all; got {labels:?}"
    );
}

/// Removal of an already-corrupted label must keep working — it is the
/// remediation path for every row that already carries `group:$EPICLAW_GROUP_ID`.
#[tokio::test(flavor = "multi_thread")]
async fn patch_labels_can_still_remove_an_already_corrupted_label() {
    let (pool, addr, _shutdown) = pool_and_app().await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let claim_id = common::seed_claim_with_agent(
        &pool,
        &format!("shell-var remediation {}", uuid::Uuid::new_v4()),
        client_id,
    )
    .await;

    // Seed the corruption the way it actually arrived: a direct write, made
    // before the guard existed.
    sqlx::query("UPDATE claims SET labels = ARRAY['backlog', $2] WHERE id = $1")
        .bind(claim_id)
        .bind(BAD_LABEL)
        .execute(&pool)
        .await
        .unwrap();

    let resp = reqwest::Client::new()
        .patch(format!("http://{addr}/api/v1/claims/{claim_id}/labels"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "remove": [BAD_LABEL] }))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, 200,
        "validating the `remove` side would make the existing corruption \
         permanently unfixable through the API; got {status} — body={text}"
    );

    let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(labels, vec!["backlog".to_string()]);
}
