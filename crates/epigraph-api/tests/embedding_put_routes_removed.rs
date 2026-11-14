#![cfg(feature = "db")]
//! `PUT /api/v1/claims/:id/embedding` and `PUT /api/v1/evidence/:id/embedding`
//! are gone (backlog 9bef22f3).
//!
//! Both handlers took no scope, no viewer and no seal or currency check: they
//! embedded caller-supplied `text` and ran `UPDATE … SET embedding = $1` on
//! the unstamped pool by id. Any bearer could therefore overwrite any row's
//! vector with one derived from text of its choosing, which poisons semantic
//! recall for every reader, and could put a vector back on a sealed row.
//! Claims are embedded when they are written (`POST /api/v1/claims`,
//! `POST /api/v1/submit/packet`) and `epigraph-cli reembed` backfills claim
//! and evidence vectors, so the routes are deleted rather than hardened.
//!
//! Each arm sends the request with a `claims:write` token, the strongest an
//! ordinary writer holds, and asserts both that it is not routed and that the
//! row's stored vector is byte-for-byte what it was. On the old handlers the
//! same request answered `200` and replaced the vector.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const WRITER: &[&str] = &["claims:read", "claims:write"];

/// A 1536-d pgvector literal whose every component is `x`.
fn vector(x: f32) -> String {
    format!("[{}]", vec![x.to_string(); 1536].join(","))
}

async fn put(router: &axum::Router, agent: Uuid, uri: &str) -> StatusCode {
    let token = common::mint_token_with_agent(WRITER, agent);
    let req = Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "text": "attacker-chosen text" }).to_string(),
        ))
        .expect("request");
    router.clone().oneshot(req).await.expect("router").status()
}

async fn claim_vector(pool: &PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT embedding::text FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read claim vector")
}

async fn evidence_vector(pool: &PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT embedding::text FROM evidence WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read evidence vector")
}

#[sqlx::test(migrations = "../../migrations")]
async fn neither_vector_can_be_overwritten_by_id(pool: PgPool) {
    let url = viewer_fixture::database_url_for(&pool).await;
    let router = epigraph_api::build_app_for_tests(&url)
        .await
        .expect("app builds for tests");
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "embed-put").await;
    let claim = viewer_fixture::seed_public_claim(&pool, agent, "a claim with a vector").await;
    viewer_fixture::set_claim_embedding(&pool, claim, &vector(0.25)).await;
    let evidence = viewer_fixture::seed_evidence(&pool, claim, "document").await;
    sqlx::query("UPDATE evidence SET embedding = $2::vector WHERE id = $1")
        .bind(evidence)
        .bind(vector(0.5))
        .execute(&pool)
        .await
        .expect("plant an evidence vector");
    let claim_before = claim_vector(&pool, claim).await;
    let evidence_before = evidence_vector(&pool, evidence).await;
    assert!(
        claim_before.is_some() && evidence_before.is_some(),
        "CALIBRATION: both rows carry a vector to overwrite"
    );

    for (uri, what) in [
        (format!("/api/v1/claims/{claim}/embedding"), "claim"),
        (format!("/api/v1/evidence/{evidence}/embedding"), "evidence"),
    ] {
        let status = put(&router, agent, &uri).await;
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
            "PUT {uri}: the {what} embedding route is removed, got {status}"
        );
    }
    assert_eq!(
        claim_vector(&pool, claim).await,
        claim_before,
        "the claim's vector is unchanged"
    );
    assert_eq!(
        evidence_vector(&pool, evidence).await,
        evidence_before,
        "the evidence row's vector is unchanged"
    );
}
