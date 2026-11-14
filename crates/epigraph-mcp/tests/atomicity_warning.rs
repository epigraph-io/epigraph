//! The warn-only atomicity gate on `submit_claim`, `batch_submit_claims` and
//! `memorize` (backlog `72850d43`): a compound text is WRITTEN as submitted
//! and the response says it screened compound; an atomic text's response
//! carries no `atomicity` field at all.
//!
//! The novelty-gate arm cannot be fired in a test process (its embedder
//! hard-codes OpenAI; see `novelty_gate_test.rs`); it builds the warning from
//! the same `AtomicityWarning::for_content` call on the same input.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::types::{MemorizeParams, SubmitClaimParams};
use sqlx::PgPool;

const COMPOUND: &str = "The b42 catalyst raised the yield, but it shortened the column life.";
const ATOMIC: &str = "The b42 catalyst raised the yield of the second run.";

fn submit(content: &str) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.into(),
        methodology: "direct_observation".into(),
        evidence_data: "b42 evidence".into(),
        evidence_type: "logical".into(),
        confidence: 0.8,
        source_url: None,
        reasoning: None,
        labels: vec![],
        novelty_threshold: None,
        visibility: Some("public".to_string()),
        group_id: None,
    }
}

async fn stored(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_writes_a_compound_claim_and_warns(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let first = first_text(
        &epigraph_mcp::tools::claims::submit_claim(&server, &viewer, submit(COMPOUND), None)
            .await
            .expect("a compound claim is not refused"),
    );
    assert_eq!(stored(&pool, COMPOUND).await, 1, "written as submitted");
    let a = first
        .get("atomicity")
        .unwrap_or_else(|| panic!("no atomicity warning: {first}"));
    assert_eq!(a["conjunct_count"], 2, "{a}");
    assert_eq!(a["clause_joins"], 1, "{a}");
    assert_eq!(a["sentences"], 1, "{a}");
    assert!(a["note"].as_str().unwrap().contains("nothing was refused"));

    // A content-hash resubmit (new evidence, same text) is answered with the
    // existing claim and still warns: the warning is about the submitted text.
    let mut resubmit = submit(COMPOUND);
    resubmit.evidence_data = "b42 second evidence".into();
    let again = first_text(
        &epigraph_mcp::tools::claims::submit_claim(&server, &viewer, resubmit, None)
            .await
            .unwrap(),
    );
    assert_eq!(again["deduplicated"]["by"], "content_hash", "{again}");
    assert_eq!(again["atomicity"]["conjunct_count"], 2, "{again}");

    let atomic = first_text(
        &epigraph_mcp::tools::claims::submit_claim(&server, &viewer, submit(ATOMIC), None)
            .await
            .unwrap(),
    );
    assert!(
        atomic.get("atomicity").is_none(),
        "an atomic claim carries no warning: {atomic}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn batch_entries_carry_their_own_warning(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let params: epigraph_mcp::types::BatchSubmitClaimsParams =
        serde_json::from_value(serde_json::json!({
            "claims": [
                {"content": ATOMIC, "visibility": "public", "evidence_data": "ev",
                 "evidence_type": "logical"},
                {"content": COMPOUND, "visibility": "public", "evidence_data": "ev",
                 "evidence_type": "logical"},
            ]
        }))
        .unwrap();
    let json = first_text(
        &epigraph_mcp::tools::batch::batch_submit_claims(&server, &viewer, params, None)
            .await
            .unwrap(),
    );
    assert_eq!(json["submitted"], 2, "{json}");
    assert!(json["results"][0].get("atomicity").is_none(), "{json}");
    assert_eq!(
        json["results"][1]["atomicity"]["conjunct_count"], 2,
        "{json}"
    );
    assert_eq!(stored(&pool, COMPOUND).await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn memorize_warns_on_a_compound_text(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let memorize = |content: &str| MemorizeParams {
        content: content.into(),
        confidence: Some(0.7),
        tags: None,
        novelty_threshold: None,
        visibility: Some("public".to_string()),
        group_id: None,
    };
    let compound = first_text(
        &epigraph_mcp::tools::memory::memorize(&server, &viewer, memorize(COMPOUND), None)
            .await
            .unwrap(),
    );
    assert_eq!(compound["atomicity"]["conjunct_count"], 2, "{compound}");
    assert_eq!(stored(&pool, COMPOUND).await, 1);
    let atomic = first_text(
        &epigraph_mcp::tools::memory::memorize(&server, &viewer, memorize(ATOMIC), None)
            .await
            .unwrap(),
    );
    assert!(atomic.get("atomicity").is_none(), "{atomic}");
}
