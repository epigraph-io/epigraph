//! Regression for issue #139.
//!
//! Seeds a claim at (plausibility=1.0, belief=0.4) and calls
//! update_with_evidence with supporting evidence. The issue body asserts
//! Postgres returns claims_plausibility_bounds. Post-PR #149 the
//! auto_wire_ds_update path clamps, so this test may pass on main;
//! if so, Task 3 captures the still-unclamped surface.
//!
//! Outcome: PASSED — auto_wire_ds_update path already clamps post-#149.
//! Task 3 covers the still-unclamped BP apply path.

mod common;
use common::*;

use epigraph_mcp::types::UpdateWithEvidenceParams;

#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_does_not_violate_plausibility_bounds_at_one(pool: sqlx::PgPool) {
    let claim_id = seed_claim_with_belief(
        &pool,
        /* belief */ 0.4,
        /* plausibility */ 1.0,
        /* pignistic_prob */ Some(0.4),
    )
    .await;

    let server = build_test_server(pool.clone());

    let result = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        UpdateWithEvidenceParams {
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: "Supporting observation that narrows belief but \
                            does not require lowering plausibility."
                .into(),
            source_url: None,
            supports: true,
            strength: 0.8,
            labels: vec![],
        },
    )
    .await;

    assert!(
        result.is_ok(),
        "update_with_evidence on Pl=1.0 claim returned err: {result:?}"
    );
}
