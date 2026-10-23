//! The MCP claim-writing tools refuse claim content over 65,536 bytes, the cap
//! the HTTP twins enforce (`epigraph-api` `routes/submit.rs` and
//! `routes/batch.rs`, `MAX_CLAIM_CONTENT_LENGTH`).
//!
//! The contract each test pins is the same one the label guard pins
//! (`label_shell_variable_rejection.rs`): **an INVALID_PARAMS error AND no row
//! for the submitted content.** The row count is what makes the guard's
//! placement load-bearing: a cap checked after the insert would still return
//! an error, but leave the oversized row behind.
//!
//! The limits are spelled as literals on purpose, not imported from the crate,
//! so the file states the contract independently of the constant it tests.
//!
//! `memorize` is not covered here: its module is being changed by an open
//! branch, and its guard is a follow-up.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
mod common;
use common::*;

/// The HTTP cap, in bytes.
const CAP: usize = 65_536;

/// Content of exactly `len` bytes: a unique, readable prefix padded with
/// spaced words (not one giant token), cut to the exact byte length. ASCII
/// only, so the cut never splits a character.
fn content_of_len(tag: &str, len: usize) -> String {
    let mut s = format!("content size cap {tag} {} ", uuid::Uuid::new_v4());
    while s.len() < len {
        s.push_str("lorem ipsum ");
    }
    s.truncate(len);
    assert_eq!(s.len(), len, "fixture: exact byte length");
    s
}

async fn claim_count_for_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count claims by content")
}

fn submit_params(content: &str) -> epigraph_mcp::types::SubmitClaimParams {
    epigraph_mcp::types::SubmitClaimParams {
        content: content.into(),
        methodology: "deductive_logic".into(),
        evidence_data: "ev".into(),
        evidence_type: "logical".into(),
        confidence: 0.8,
        source_url: None,
        reasoning: None,
        labels: vec![],
        novelty_threshold: None,
    }
}

fn batch_entry(content: &str) -> epigraph_mcp::types::BatchClaimEntry {
    epigraph_mcp::types::BatchClaimEntry {
        content: content.into(),
        methodology: None,
        source_url: None,
        reasoning: None,
        novelty_threshold: None,
        evidence_data: "ev".into(),
        evidence_type: "logical".into(),
        confidence: Some(0.6),
        labels: vec![],
    }
}

/// `submit_claim` with one byte over the cap: refused as the caller's error,
/// and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_rejects_content_over_64k_and_writes_no_claim(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = content_of_len("submit over", CAP + 1);

    let res =
        epigraph_mcp::tools::claims::submit_claim(&server, &viewer, submit_params(&content), None)
            .await;

    assert_eq!(
        claim_count_for_content(&pool, &content).await,
        0,
        "content over the cap must leave no claim row behind"
    );
    let err = res.expect_err("content over 65,536 bytes must be refused");
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "an oversized submission is the caller's error, not INTERNAL_ERROR; got {err:?}"
    );
    assert!(
        err.message.contains("65537") && err.message.contains("65536"),
        "the refusal must name the submitted length and the cap, got: {}",
        err.message
    );
}

/// The boundary: exactly the cap is still accepted and stored, so the guard is
/// `> cap`, not `>= cap` (the HTTP twins' predicate).
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_accepts_content_of_exactly_64k(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = content_of_len("submit at cap", CAP);

    epigraph_mcp::tools::claims::submit_claim(&server, &viewer, submit_params(&content), None)
        .await
        .expect("content of exactly 65,536 bytes is within the cap");

    assert_eq!(
        claim_count_for_content(&pool, &content).await,
        1,
        "the at-cap claim must actually be stored"
    );
}

/// `batch_submit_claims` reports the oversized entry as its own error, writes
/// nothing for it, and still ingests its neighbour.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_submit_claims_rejects_only_the_oversized_entry(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let good = format!("content size cap batch good {}", uuid::Uuid::new_v4());
    let big = content_of_len("batch over", CAP + 1);

    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        &viewer,
        epigraph_mcp::types::BatchSubmitClaimsParams {
            claims: vec![batch_entry(&good), batch_entry(&big)],
        },
        None,
    )
    .await
    .expect("the batch call itself succeeds; per-entry failures are in the payload");

    let json = first_text(&result);
    assert_eq!(
        claim_count_for_content(&pool, &big).await,
        0,
        "the oversized entry must leave no claim row; payload: {json}"
    );
    assert_eq!(json["submitted"], 1, "payload: {json}");
    assert_eq!(json["errors"], 1, "payload: {json}");
    assert_eq!(
        json["error_details"][0]["index"], 1,
        "the error must be reported against the oversized entry; payload: {json}"
    );
    assert_eq!(
        claim_count_for_content(&pool, &good).await,
        1,
        "one oversized entry must not block its well-formed neighbour"
    );
}

/// `supersede_claim` with replacement content over the cap: refused before the
/// act, so the old claim stays current and no replacement row exists.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_rejects_content_over_64k_and_retires_nothing(pool: PgPool) {
    let old = seed_claim(&pool, "content size cap supersede v1", 0.5).await;
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let (auth, admin_viewer) = common::granted_server_admin(&server, &pool).await;
    let content = content_of_len("supersede over", CAP + 1);

    let res = epigraph_mcp::tools::supersede::supersede_claim(
        &server,
        &admin_viewer,
        epigraph_mcp::types::SupersedeClaimParams {
            claim_id: old.to_string(),
            content: content.clone(),
            truth_value: 0.7,
            reason: "oversized replacement".into(),
        },
        Some(&auth),
    )
    .await;

    let (old_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .expect("old claim");
    assert!(
        old_current,
        "a refused supersede must not retire the claim it names"
    );
    assert_eq!(
        claim_count_for_content(&pool, &content).await,
        0,
        "a refused supersede must leave no replacement row"
    );
    let err = res.expect_err("replacement content over 65,536 bytes must be refused");
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "an oversized replacement is the caller's error; got {err:?}"
    );
}
