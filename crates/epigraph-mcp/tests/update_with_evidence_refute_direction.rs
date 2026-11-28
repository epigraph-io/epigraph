//! Backlog b191f198: a REFUTING `update_with_evidence` whose result is above
//! the claim's pre-call belief must say so, and the response must carry that
//! pre-call belief.
//!
//! `truth_before` is the claim's `truth_value`, which can diverge from its
//! cached `pignistic_prob` (the cache the fold's prior and the supporting
//! warning compare against). A refute folded with support-heavy stored BBAs,
//! on a claim whose cache sat far below their fold, was reported as moving
//! truth from 0.465 to 0.946 with no word: the only direction warning was for
//! supports=true lowering BetP.
//!
//! Fixture: a claim with a stale cached `pignistic_prob` of 0.465 and two
//! strong supporting binary BBAs (from two agents) that fold far above it. A
//! weak refute then re-folds them: BetP lands above 0.465.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::types::UpdateWithEvidenceParams;
use sqlx::PgPool;
use uuid::Uuid;

const STALE_CACHE: f64 = 0.465;

async fn run_update(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    strength: f64,
    supports: bool,
) -> serde_json::Value {
    let result = epigraph_mcp::tools::claims::update_with_evidence(
        server,
        viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: format!("b191f198 strength={strength} supports={supports} {claim_id}"),
            source_url: None,
            supports,
            strength,
            labels: Vec::new(),
        },
        None,
    )
    .await
    .expect("update_with_evidence ok");
    first_text(&result)
}

/// SOME case: the refute's result is above the stale cache, so the response
/// reports the pre-call pignistic and warns.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refute_that_leaves_belief_above_the_pre_call_cache_is_reported(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim = seed_claim_with_belief(&pool, 0.4, 0.55, Some(STALE_CACHE)).await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        let frame = epigraph_mcp::tools::ds_auto::ensure_binary_frame(&mut conn, &viewer)
            .await
            .expect("binary_truth frame");
        for _ in 0..2 {
            epigraph_db::MassFunctionRepository::store_with_perspective(
                &mut *conn,
                claim,
                frame,
                Some(seed_agent(&pool).await),
                None,
                &serde_json::json!({"0": 0.9, "0,1": 0.1}),
                None,
                None,
                None,
                Some("empirical"),
                "unknown",
                None,
            )
            .await
            .expect("store a strong supporting BBA");
        }
    }
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim, 0.3, false).await;

    let after = json["pignistic_prob"].as_f64().expect("pignistic_prob");
    assert!(
        after > STALE_CACHE,
        "fixture premise: the refute's fold of the support-heavy BBAs lands above the stale \
         cache {STALE_CACHE}; got {json}"
    );
    assert_eq!(
        json["pignistic_before"].as_f64(),
        Some(STALE_CACHE),
        "the response must carry the claim's pre-call cached pignistic_prob next to \
         truth_before, so the movement this call reports is unambiguous; got {json}"
    );
    let warning = json["warning"].as_str().unwrap_or_default();
    assert!(
        warning.contains("Refuting evidence left belief above"),
        "a refute whose result is above the pre-call belief must be named in `warning`; \
         got {json}"
    );
    assert!(
        !warning.contains("Supporting evidence decreased"),
        "the supporting-direction warning must not fire on a refute: {json}"
    );
}

/// NONE case: a refute on a claim whose prior is consistent with its BBAs
/// lowers belief, and no refute-direction warning appears. The claim has no
/// cache, so `pignistic_before` is null and the prior is its `truth_value`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refute_that_lowers_belief_is_not_warned(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim = seed_claim(&pool, "b191f198 consistent claim for a refute", 0.7).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim, 0.8, false).await;

    let after = json["pignistic_prob"].as_f64().expect("pignistic_prob");
    let before = json["truth_before"].as_f64().expect("truth_before");
    assert!(
        after < before,
        "precondition: a strong refute on a seeded claim lowers belief; before={before} \
         after={after}"
    );
    assert!(
        json.get("pignistic_before")
            .is_some_and(serde_json::Value::is_null),
        "a claim with no cache reports pignistic_before as null: {json}"
    );
    assert!(
        !json["warning"]
            .as_str()
            .unwrap_or_default()
            .contains("Refuting evidence"),
        "no refute-direction warning when the refute lowered belief: {json}"
    );
}
