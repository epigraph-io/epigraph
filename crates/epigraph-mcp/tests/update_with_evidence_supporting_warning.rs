//! Task 3.6 (backlog 3b60a785) regression: `update_with_evidence` must WARN
//! when SUPPORTING evidence *lowers* the pignistic probability.
//!
//! Weak supporting evidence carries high ignorance mass, widens the belief
//! interval, and pulls the pignistic toward 0.5 — correct Dempster-Shafer
//! combination, but counterintuitive. The handler surfaces a `warning` field
//! so callers don't mistake it for a bug.
//!
//! The pre-existing monotonicity clamp in `auto_wire_ds_update` bounds BetP
//! below by the prior `pignistic_prob` *column* for supports=true, so the drop
//! (and hence the warning) is only reachable on a claim with NO prior DS state
//! (NULL `pignistic_prob` column). `seed_claim` leaves that column NULL, so the
//! fresh BBA is combined against the claim's `truth_value`.

mod common;
use common::*;

use epigraph_mcp::types::UpdateWithEvidenceParams;

async fn run_update(
    server: &epigraph_mcp::EpiGraphMcpFull,
    claim_id: uuid::Uuid,
    strength: f64,
    supports: bool,
) -> serde_json::Value {
    let result = epigraph_mcp::tools::claims::update_with_evidence(
        server,
        UpdateWithEvidenceParams {
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: format!("evidence strength={strength} supports={supports}"),
            source_url: None,
            supports,
            strength,
            labels: Vec::new(),
        },
    )
    .await
    .expect("update_with_evidence ok");
    first_text(&result)
}

/// SOME case: moderate (~0.6) supporting evidence against an already-high-belief
/// claim pulls the pignistic below the prior belief → `warning` is present.
#[sqlx::test(migrations = "../../migrations")]
async fn supporting_evidence_lowers_belief_emits_warning(pool: sqlx::PgPool) {
    // High prior belief, NULL pignistic column (seed_claim leaves it NULL).
    let claim_id = seed_claim(&pool, "high-belief claim for warning test", 0.85).await;
    let server = build_test_server(pool.clone());

    let json = run_update(&server, claim_id, 0.6, true).await;

    let after = json["pignistic_prob"].as_f64().expect("pignistic_prob");
    let before = json["truth_before"].as_f64().expect("truth_before");
    assert!(
        after < before,
        "precondition: post pignistic {after} must be below prior belief {before}"
    );
    assert!(
        json.get("warning").and_then(|w| w.as_str()).is_some(),
        "warning must be present when supporting evidence lowers belief; got {json}"
    );
    assert!(
        json["warning"]
            .as_str()
            .unwrap()
            .contains("mathematically correct"),
        "warning text must explain this is correct DS combination"
    );
}

/// NONE case: strong (~0.95) supporting evidence against a lower-belief claim
/// raises the pignistic → belief does NOT drop → `warning` absent.
#[sqlx::test(migrations = "../../migrations")]
async fn supporting_evidence_raising_belief_emits_no_warning(pool: sqlx::PgPool) {
    let claim_id = seed_claim(&pool, "lower-belief claim for no-warning test", 0.4).await;
    let server = build_test_server(pool.clone());

    let json = run_update(&server, claim_id, 0.95, true).await;

    let after = json["pignistic_prob"].as_f64().expect("pignistic_prob");
    let before = json["truth_before"].as_f64().expect("truth_before");
    assert!(
        after >= before,
        "precondition: strong supporting evidence must not lower belief; \
         before={before} after={after}"
    );
    assert!(
        json.get("warning").is_none() || json["warning"].is_null(),
        "warning must be absent when belief does not drop; got {json}"
    );
}
