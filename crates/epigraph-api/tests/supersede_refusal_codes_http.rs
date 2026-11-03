#![cfg(feature = "db")]
//! SPEC §7.1 (SF-18b) and §11 phase 1 S-1 test (l), HTTP half: a
//! supersede-architecture refusal code (`epigraph_db::SUPERSEDE_REFUSAL_CODES`;
//! migration 194 introduces `SR09`) answers with its code and a 4xx, never the
//! redacted 500.
//!
//! MAPPER pin only: after K4a no shipped route deletes a retracted mass
//! function, so no route is expected to reach SR09. The refusal here is the
//! real one, raised by migration 194's guard on a maintenance-role DELETE of a
//! retracted row (made by migration 184's definer) and passed to
//! `From<DbError> for ApiError`. Fail closed: a message of the same shape whose
//! code is not listed (`SR99`) keeps the redacted 500.

mod viewer_fixture;

#[path = "../../epigraph-db/tests/support/retracted_bba_fixture.rs"]
mod retracted;

use axum::{http::StatusCode, response::IntoResponse};
use epigraph_api::ApiError;
use epigraph_db::MassFunctionRepository;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn http_answer(e: epigraph_db::DbError) -> (StatusCode, String) {
    let response = ApiError::from(e).into_response();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body.to_string())
}

/// A retracted mass function on a fresh claim (retracted through 184's
/// definer), and the database's answer to a maintenance-role DELETE of it.
async fn sr09_refusal(pool: &PgPool) -> (Uuid, sqlx::Error) {
    let (agent, group) = viewer_fixture::seed_agent_with_group(pool, "sr09-http").await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("sr09-http-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame");
    let claim = viewer_fixture::seed_group_claim(pool, agent, group, "sr09 mapper claim").await;
    let bba = MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA");
    retracted::retract_through_definer(pool, bba).await;
    let maintenance = viewer_fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let e = sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(bba)
        .execute(&maintenance)
        .await
        .expect_err("migration 194 refuses the delete of a retracted mass function");
    (bba, e)
}

#[sqlx::test(migrations = "../../migrations")]
async fn api_mapper_answers_sr09_with_403_and_its_code(pool: PgPool) {
    let (bba, e) = sr09_refusal(&pool).await;
    let (status, text) = http_answer(epigraph_db::DbError::from(e)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "SR09 is a denial (42501 -> 403), not a 500: {text}"
    );
    assert!(
        text.contains("SR09:") && text.contains("epigraph_purge_mass_functions"),
        "the body carries the refusal code and the remedy: {text}"
    );
    assert!(
        !text.contains(&bba.to_string()),
        "the row id stays in DETAIL, not in the reply: {text}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn api_mapper_keeps_an_unlisted_sr_code_redacted(pool: PgPool) {
    let e = sqlx::query(
        "DO $$ BEGIN RAISE EXCEPTION 'SR99: an unlisted refusal of the supersede shape' \
         USING ERRCODE = '42501'; END $$",
    )
    .execute(&pool)
    .await
    .expect_err("the DO block raises");
    let (status, text) = http_answer(epigraph_db::DbError::from(e)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{text}");
    assert!(
        !text.contains("SR99"),
        "an unlisted code is not relayed: {text}"
    );
}
