#![cfg(feature = "db")]
//! `POST /api/v1/claims/batch` answers 200 with one result per item, and a
//! failed item carries an `error` string. That string is in a SUCCESS body,
//! so the 500-body redaction in `errors.rs` never sees it: it used to be the
//! item's `ApiError` rendered with `to_string()`, which for a `DatabaseError`
//! is the server-side detail, including the driver's text that
//! `create_claim_core` interpolates (backlog f9acb220).
//!
//! The arm forces a real driver error at the commit of one item's
//! transaction (a deferred constraint trigger, created in this test's own
//! database) whose message carries a canary, and asserts the canary is not in
//! the 200 body, the item's slot reports the 500 it would have been, and its
//! text is the fixed literal the 500 body would have said. A calibration
//! batch before the trigger exists must succeed, so the refusal cannot come
//! from a broken fixture.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

mod common;

const CANARY: &str = "canary_f9acb220_internal relation detail";

async fn post_batch(pool: &PgPool, token: &str, body: Value) -> (StatusCode, String) {
    let app = create_router(AppState::with_db(pool.clone(), ApiConfig::default()));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/claims/batch")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_items_error_is_the_redacted_text_not_the_driver_error(pool: PgPool) {
    let agent = common::seed_system_agent(&pool).await;
    let (token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:write"], agent)
            .await;

    // Calibration: the same request shape succeeds before the fault exists.
    let (status, body) = post_batch(
        &pool,
        &token,
        json!({"claims": [{"content": format!("f9acb220 calibration {}", Uuid::new_v4()),
                           "truth_value": 0.6}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(v["created"], 1, "calibration: the item is created: {body}");

    // A driver error at COMMIT, whose text names something internal. Deferred,
    // so the insert succeeds and `create_claim_core`'s commit is what fails;
    // that arm interpolates the driver error into a `DatabaseError`.
    sqlx::query(&format!(
        "CREATE FUNCTION f9acb220_canary() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION '{CANARY}'; END $$"
    ))
    .execute(&pool)
    .await
    .expect("canary function");
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER f9acb220_canary AFTER INSERT ON claims \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION f9acb220_canary()",
    )
    .execute(&pool)
    .await
    .expect("canary trigger");

    let content = format!("f9acb220 faulted {}", Uuid::new_v4());
    let (status, body) = post_batch(
        &pool,
        &token,
        json!({"claims": [{"content": content, "truth_value": 0.6}]}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a batch answers 200 per item: {body}"
    );
    assert!(
        !body.contains("canary_f9acb220"),
        "the driver's error text reached the caller through a 200 per-item result: {body}"
    );
    let v: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(v["failed"], 1, "the faulted item failed: {body}");
    let item = &v["results"][0];
    assert_eq!(item["status"], 500, "the slot names the 500 it was: {body}");
    assert_eq!(
        item["error"].as_str(),
        Some(
            format!(
                "Database error: {}",
                epigraph_api::errors::DATABASE_ERROR_BODY
            )
            .as_str()
        ),
        "the slot carries the fixed literal a 500 body would: {body}"
    );
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(&content)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(stored, 0, "the faulted item's transaction did not commit");
}
