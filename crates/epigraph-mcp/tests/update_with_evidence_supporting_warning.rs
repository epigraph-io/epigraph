//! Task 3.6 (backlog 3b60a785) regression: `update_with_evidence` must WARN
//! when SUPPORTING evidence *lowers* the pignistic probability.
//!
//! The monotonicity clamp in `auto_wire_ds_update` bounds a supports=true
//! result below by the claim's prior (`pignistic_prob`, or `truth_value` when
//! that is NULL), but only up to the combined plausibility: `prior.min(pl)`
//! (backlog 0183a294). So the drop, and the warning, is reachable exactly when
//! the prior is above what the stored BBAs make plausible.
//!
//! This file used to reach it on a claim with NO prior DS state (`seed_claim`,
//! truth 0.85, NULL `pignistic_prob`): the fresh BBA was combined against
//! nothing, BetP fell to 0.80 and the warning fired. That was the defect of
//! backlog fc55465b, not the warning's legitimate case: such a claim is now
//! seeded from its `truth_value`, and
//! `update_with_evidence_truth_prior.rs::first_supporting_update_on_bba_less_claim_does_not_lower_betp_below_truth`
//! pins the inverse (BetP 0.94, no warning). The warning case below is built
//! the way it legitimately arises: a stored opposing BBA caps Pl below an
//! inflated cached prior.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::types::UpdateWithEvidenceParams;

async fn run_update(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: uuid::Uuid,
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
            evidence_data: format!("evidence strength={strength} supports={supports}"),
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

/// SOME case: the claim holds an opposing BBA {F 0.5, Θ 0.5} and a cached
/// `pignistic_prob` of 0.9 that its BBAs cannot support. Supporting evidence
/// {T e, Θ 1-e} combines to Pl(T) = 1 - 0.5(1-e)/(1-0.5e), which is below 0.9
/// for any e < 0.9 (e = 0.6 x the evidence-type weight here). The clamp lifts
/// BetP to min(0.9, Pl) = Pl, still below the prior 0.9, so belief dropped and
/// `warning` is present.
#[sqlx::test(migrations = "../../migrations")]
async fn supporting_evidence_lowers_belief_emits_warning(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim_with_belief(&pool, 0.8, 0.95, Some(0.9)).await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        let frame_id = epigraph_mcp::tools::ds_auto::ensure_binary_frame(&mut conn, &viewer)
            .await
            .expect("binary_truth frame");
        epigraph_db::MassFunctionRepository::store_with_perspective(
            &mut *conn,
            claim_id,
            frame_id,
            Some(seed_agent(&pool).await),
            None,
            &serde_json::json!({"1": 0.5, "0,1": 0.5}),
            None,
            None,
            None,
            Some("empirical"),
            "unknown",
            None,
        )
        .await
        .expect("store opposing BBA");
    }
    // Scoped: `update_with_evidence` now writes its evidence row and its
    // truth_value/labels update on author-stamped transactions, and a server
    // with no `ScopedPool` refuses the tool by name rather than writing on the
    // unstamped pool, where `evidence` and `claims` both refuse it with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim_id, 0.6, true).await;

    let after = json["pignistic_prob"].as_f64().expect("pignistic_prob");
    let evidence_id: uuid::Uuid = json["evidence_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("evidence_id");
    let ev: serde_json::Value =
        sqlx::query_scalar("SELECT masses FROM mass_functions WHERE evidence_id = $1")
            .bind(evidence_id)
            .fetch_one(&pool)
            .await
            .expect("the evidence's BBA");
    let e = ev["0"].as_f64().expect("a supporting evidence BBA");
    let pl = 1.0 - 0.5 * (1.0 - e) / (1.0 - 0.5 * e);
    assert!(pl < 0.9, "fixture: Pl {pl} must sit below the cached prior");
    assert!(
        (after - pl).abs() < 1e-9,
        "precondition: the clamp yields to Pl = {pl}; got {after}"
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
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, "lower-belief claim for no-warning test", 0.4).await;
    // Scoped: `update_with_evidence` now writes its evidence row and its
    // truth_value/labels update on author-stamped transactions, and a server
    // with no `ScopedPool` refuses the tool by name rather than writing on the
    // unstamped pool, where `evidence` and `claims` both refuse it with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim_id, 0.95, true).await;

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
