#![cfg(feature = "db")]
//! `POST /api/v1/ingest/paper` takes no path from its caller (backlog
//! 0fd96e75).
//!
//! The body carried an `output_dir`, which the handler created with
//! `create_dir_all` before looking at anything else, and a `source` ending in
//! `.pdf` was read as a local file. Both were paths on the server chosen by
//! an admin token's holder, and both reached a `python3 -c` script as text.
//! Now an `output_dir` is an unknown field (422, nothing created) and a local
//! PDF, a traversal, an absolute path or a quote is not an arXiv id (400,
//! naming `source`). Every request here is refused before any download or
//! process runs; the id validator's full table is in `routes::ingest`'s unit
//! tests.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

const ADMIN: &[&str] = &["claims:read", "claims:write", "claims:admin"];

async fn post(pool: &PgPool, body: &Value) -> (StatusCode, String) {
    let url = viewer_fixture::database_url_for(pool).await;
    let router = epigraph_api::build_app_for_tests(&url)
        .await
        .expect("app builds for tests");
    let (agent, _group) = viewer_fixture::seed_agent_with_group(pool, "ingest-confine").await;
    let token = common::mint_token_with_agent(ADMIN, agent);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/ingest/paper")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.oneshot(req).await.expect("router");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn scratch_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("{label}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A local PDF the server can read is not a source: the old handler took any
/// existing `*.pdf` path and ran the pipeline on it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_local_pdf_path_is_refused(pool: PgPool) {
    let dir = scratch_dir("ingest-local-pdf");
    let pdf = dir.join("paper.pdf");
    std::fs::write(&pdf, b"%PDF-1.4 not really").expect("seed a local pdf");

    let (status, body) = post(&pool, &json!({ "source": pdf.display().to_string() })).await;
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a local PDF path must be refused as a source: {body}"
    );
    assert!(body.contains("source"), "the 400 names the field: {body}");
}

/// `output_dir` is gone: a body naming it is refused, and the directory it
/// names is never created. The old handler created it first, whatever the
/// source then turned out to be.
#[sqlx::test(migrations = "../../migrations")]
async fn an_output_dir_is_refused_and_never_created(pool: PgPool) {
    let dir = scratch_dir("ingest-output-dir");
    let target = dir.join("made-by-the-caller");

    let (status, body) = post(
        &pool,
        &json!({ "source": "../absent.pdf", "output_dir": target.display().to_string() }),
    )
    .await;
    let created = target.exists();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !created,
        "the caller's output_dir was created on the server (status {status}: {body})"
    );
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an unknown body field is refused: {body}"
    );
}

/// A traversal, an absolute path and a quote are not arXiv ids.
#[sqlx::test(migrations = "../../migrations")]
async fn a_traversal_an_absolute_path_or_a_quote_is_refused(pool: PgPool) {
    for source in [
        "../../../tmp/escaped",
        "/etc/passwd",
        "2508.16798'); __import__('os').system('id') #",
        "10.48550/arXiv.../../tmp/escaped",
    ] {
        let (status, body) = post(&pool, &json!({ "source": source })).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{source:?} must be refused before any download: {body}"
        );
        assert!(body.contains("source"), "{source:?}: {body}");
    }
}
