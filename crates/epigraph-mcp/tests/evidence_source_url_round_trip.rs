//! An evidence URL must survive the write and come back on a claim read
//! (backlog 43ab8c73, drain unit U036).
//!
//! Before this, every evidence INSERT bound `NULL` to `evidence.source_url`,
//! so the URL lived only inside `evidence.properties` — and for `empirical`
//! evidence (stored as `EvidenceType::Observation`, which has no URL slot) it
//! lived nowhere at all. The norcal-rfp monitor submits `empirical` evidence,
//! so its "Discovery URLs" were unrecoverable by any read.
//!
//! Every test here measures the stored row (or the tool's own JSON) rather than
//! a fixture's echo: the evidence row read back is the one `submit_claim`
//! wrote.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::types::SubmitClaimParams;
use sqlx::PgPool;
use uuid::Uuid;

const RFP_URL: &str = "https://example.org/u036/rfp-1";

fn rfp_submission(content: &str, evidence_type: &str, url: Option<&str>) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.into(),
        methodology: "direct_observation".into(),
        evidence_data: "listing seen".into(),
        evidence_type: evidence_type.into(),
        confidence: 0.8,
        source_url: url.map(String::from),
        reasoning: None,
        labels: vec!["u036-rfp".into()],
        novelty_threshold: None,
    }
}

async fn submit(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::Viewer,
    params: SubmitClaimParams,
) -> Uuid {
    let body = first_text(
        &epigraph_mcp::tools::claims::submit_claim(server, viewer, params, None)
            .await
            .expect("submit_claim"),
    );
    parse_uuid_field(&body, "claim_id")
}

async fn stored_source_urls(pool: &PgPool, claim_id: Uuid) -> Vec<Option<String>> {
    sqlx::query_scalar("SELECT source_url FROM evidence WHERE claim_id = $1")
        .bind(claim_id)
        .fetch_all(pool)
        .await
        .expect("read evidence.source_url")
}

/// The norcal-rfp path: `empirical` evidence with a `source_url`. The URL must
/// land in `evidence.source_url`, since the evidence type has nowhere else to
/// keep it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_empirical_submission_stores_its_source_url(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let claim_id = submit(
        &server,
        &viewer,
        rfp_submission("u036: rfp discovered", "empirical", Some(RFP_URL)),
    )
    .await;

    let stored = stored_source_urls(&pool, claim_id).await;
    assert!(
        stored.contains(&Some(RFP_URL.to_string())),
        "evidence.source_url for claim {claim_id} = {stored:?}; expected it to hold {RFP_URL}"
    );
}
