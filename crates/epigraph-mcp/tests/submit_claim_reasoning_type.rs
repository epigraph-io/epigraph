//! A `submit_claim` trace must record HOW the claim was derived (backlog
//! e207bb6d).
//!
//! `parse_methodology` collapses the whole observation family onto the
//! `Instrumental` trust bucket, and the enum-level trace mapping writes
//! `Instrumental` as `"statistical"`. So a claim submitted as
//! `direct_observation` got a trace saying it was a statistical inference —
//! observed on ef1ed679 (trace 4ec65c0e) and 4e325913 (trace cbd430a3).
//! Migration 121 admits `observational` in `reasoning_type_valid`; these tests
//! pin that the MCP write path now emits it, that the statistical family did
//! NOT move with it, and that the submitted string survives verbatim on the
//! trace.
//!
//! Every assertion reads the row the production write path produced, on the
//! superuser pool, never a value the test constructed.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::types::SubmitClaimParams;
use sqlx::PgPool;
use uuid::Uuid;

fn params(content: &str, methodology: &str) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.into(),
        methodology: methodology.into(),
        evidence_data: "ran it, watched it fail".into(),
        evidence_type: "empirical".into(),
        confidence: 0.8,
        source_url: None,
        reasoning: None,
        labels: vec![],
        novelty_threshold: None,
    }
}

struct Harness {
    pool: PgPool,
    server: epigraph_mcp::server::EpiGraphMcpFull,
    viewer: epigraph_db::visibility::Viewer,
}

async fn harness(pool: PgPool) -> Harness {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    Harness {
        pool,
        server,
        viewer,
    }
}

/// Submit through the real MCP tool and return the stored
/// `(reasoning_type, properties->>'submitted_methodology')` of the one trace
/// written for the new claim.
async fn submit_and_read_trace(
    h: &Harness,
    content: &str,
    methodology: &str,
) -> (String, Option<String>) {
    let out = first_text(
        &epigraph_mcp::tools::claims::submit_claim(
            &h.server,
            &h.viewer,
            params(content, methodology),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("submit_claim({methodology:?}) failed: {e:?}")),
    );
    let claim_id: Uuid = out["claim_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no claim_id in {out}"))
        .parse()
        .expect("claim_id is a uuid");

    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT reasoning_type, properties->>'submitted_methodology' \
         FROM reasoning_traces WHERE claim_id = $1",
    )
    .bind(claim_id)
    .fetch_all(&h.pool)
    .await
    .expect("read traces");
    assert_eq!(
        rows.len(),
        1,
        "a fresh submit writes exactly one trace, got {rows:?}"
    );
    rows.into_iter().next().expect("one row")
}

#[sqlx::test(migrations = "../../migrations")]
async fn direct_observation_is_persisted_as_an_observational_trace(pool: PgPool) {
    let h = harness(pool).await;
    let (reasoning_type, submitted) =
        submit_and_read_trace(&h, "u034: direct observation trace", "direct_observation").await;
    assert_eq!(
        reasoning_type, "observational",
        "a direct_observation submission must not be stored as a statistical inference"
    );
    assert_eq!(
        submitted.as_deref(),
        Some("direct_observation"),
        "the submitted methodology must be recorded verbatim on the trace"
    );
}

/// The submitted string is stored as the CALLER wrote it, not normalized —
/// "verbatim" is the point of the property.
#[sqlx::test(migrations = "../../migrations")]
async fn the_submitted_methodology_is_kept_verbatim_not_normalized(pool: PgPool) {
    let h = harness(pool).await;
    let (reasoning_type, submitted) =
        submit_and_read_trace(&h, "u034: verbatim spelling", "Direct-Observation").await;
    assert_eq!(reasoning_type, "observational");
    assert_eq!(submitted.as_deref(), Some("Direct-Observation"));
}

/// Guard against the rejected alternative (flipping the enum-level
/// `Instrumental` arm): the statistical family shares the Instrumental bucket
/// with direct observation, and must keep persisting `statistical`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_statistical_family_still_persists_statistical(pool: PgPool) {
    let h = harness(pool).await;
    for (i, m) in ["statistical_analysis", "computational", "instrumental"]
        .into_iter()
        .enumerate()
    {
        let (reasoning_type, submitted) =
            submit_and_read_trace(&h, &format!("u034: statistical family {i} {m}"), m).await;
        assert_eq!(
            reasoning_type, "statistical",
            "{m:?} must still persist as statistical"
        );
        assert_eq!(submitted.as_deref(), Some(m));
    }
}

/// One submit per distinct reasoning_type the vocabulary maps to: each must
/// pass `reasoning_type_valid` (a CHECK violation would surface as a failed
/// submit) and land on its expected value.
#[sqlx::test(migrations = "../../migrations")]
async fn every_distinct_mapped_reasoning_type_satisfies_the_check(pool: PgPool) {
    let h = harness(pool).await;
    for (methodology, expected) in [
        ("deductive_logic", "deductive"),
        ("formal_proof", "deductive"),
        ("inductive", "inductive"),
        ("abductive", "abductive"),
        ("expert_elicitation", "abductive"),
        ("statistical", "statistical"),
        ("extraction", "statistical"),
        ("direct_observation", "observational"),
        ("experimental_observation", "observational"),
    ] {
        let (reasoning_type, _) = submit_and_read_trace(
            &h,
            &format!("u034: distinct reasoning type via {methodology}"),
            methodology,
        )
        .await;
        assert_eq!(
            reasoning_type, expected,
            "{methodology:?} persisted the wrong reasoning_type"
        );
    }
}
