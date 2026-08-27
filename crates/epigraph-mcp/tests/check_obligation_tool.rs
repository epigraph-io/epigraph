//! `check_obligation` — the gap contract survives the session
//! (backlog 4b48ffb5).
//!
//! A verdict computed at write time is a snapshot, and snapshots decay:
//! `supersede` and `mark_duplicate` both flip `is_current = false`, so a
//! contract satisfied when its batch ran is a breach once one of its anchors
//! is retired. This is the end-to-end proof that the persisted contract is
//! recomputable rather than a stored number replayed back.

use sqlx::PgPool;
mod common;
use common::*;

use epigraph_mcp::types::{BatchClaimEntry, BatchSubmitClaimsParams, CheckObligationParams};

fn entry(content: &str) -> BatchClaimEntry {
    BatchClaimEntry {
        content: content.into(),
        evidence_data: format!("evidence for {content}"),
        evidence_type: "logical".into(),
        confidence: Some(0.6),
        labels: vec![],
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn check_obligation_reflows_the_verdict_after_a_claim_is_retired(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let batch = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        BatchSubmitClaimsParams {
            claims: vec![
                entry("decayable claim one"),
                entry("decayable claim two"),
                entry("decayable claim three"),
            ],
            coverage: None,
        },
    )
    .await
    .unwrap();

    let summary = first_text(&batch);
    assert_eq!(summary["coverage_verdict"], "satisfied", "{summary}");
    let obligation_id = summary["obligation_id"]
        .as_str()
        .expect("batch must return an obligation_id")
        .to_string();

    // Retire one anchor exactly as supersede/mark_duplicate do.
    let retired = sqlx::query_scalar::<_, uuid::Uuid>(
        "UPDATE claims SET is_current = false, embedding = NULL
         WHERE content = 'decayable claim three' RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("retire one anchor");

    let checked = epigraph_mcp::tools::obligations::check_obligation(
        &server,
        CheckObligationParams {
            obligation_id: obligation_id.clone(),
        },
    )
    .await
    .unwrap();

    let row = first_text(&checked);
    assert_eq!(row["obligation_id"], obligation_id, "{row}");
    assert_eq!(row["declared"], 3, "the contract is unchanged: {row}");
    assert_eq!(
        row["observed_total"], 2,
        "a retired anchor must stop counting: {row}"
    );
    assert_eq!(
        row["coverage_verdict"], "breach",
        "coverage decays; a satisfied contract can become a breach: {row}"
    );
    // The obligation still remembers what it was told to count.
    assert!(
        row["anchors"]
            .as_array()
            .is_some_and(|a| a.len() == 3 && a.iter().any(|v| v == &retired.to_string())),
        "the retired anchor id is retained, only uncounted: {row}"
    );

    // The recheck PERSISTED — this is why the tool needs claims:write and why
    // a later session sees the decayed verdict without recomputing it.
    let (verdict, observed): (String, i32) =
        sqlx::query_as("SELECT verdict, observed_total FROM obligations WHERE id = $1")
            .bind(obligation_id.parse::<uuid::Uuid>().unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((verdict.as_str(), observed), ("breach", 2));
}

/// An unknown obligation id is a parameter error, not a 500 and not a silent
/// empty result.
#[sqlx::test(migrations = "../../migrations")]
async fn check_obligation_rejects_an_unknown_id(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let err = epigraph_mcp::tools::obligations::check_obligation(
        &server,
        CheckObligationParams {
            obligation_id: uuid::Uuid::new_v4().to_string(),
        },
    )
    .await
    .expect_err("an unknown obligation must be an error");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");

    let err = epigraph_mcp::tools::obligations::check_obligation(
        &server,
        CheckObligationParams {
            obligation_id: "not-a-uuid".into(),
        },
    )
    .await
    .expect_err("a malformed id must be an error");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
}
