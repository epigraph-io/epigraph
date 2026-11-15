//! Backlog d33a5c9f: `submit_ds_evidence` on `claim_validity` after
//! `update_with_evidence` on the same claim, written by the claim's owner.
//!
//! `update_with_evidence` files its BBA on `binary_truth`, and the cache owner
//! rule (`MassFunctionRepository::cache_owner_frame_for_claim`) ranks
//! `binary_truth` first, so the rule says `binary_truth` owns this claim's
//! cache. `submit_ds_evidence` used to fold the frame it was handed
//! (`recompute_claim_belief_on_frame`) and, for a session that may write the
//! claim row, re-point the cache to that frame: the claim's served belief
//! became the one `claim_validity` BBA's fold while `truth_value` kept the
//! `update_with_evidence` value. It now refolds only when the filed frame is
//! the owner frame.
//!
//! What is pinned:
//!
//! * `submit_ds_evidence_on_claim_validity_keeps_the_update_with_evidence_cache`:
//!   the cache stays on `binary_truth` with its value, and the response
//!   reports the `claim_validity` combination with a warning that names the
//!   owner frame.
//! * `retracting_that_bba_restores_the_owner_frame_fold`: `retract_bba` on the
//!   `claim_validity` BBA recomputes the cache from the BBAs that remain (the
//!   `binary_truth` fold) and says so (`belief_recomputed`).
//! * `on_a_compound_neither_the_submit_nor_the_retract_writes_the_cache`: a
//!   COMPOUND (an in-force `decomposes_to` out-edge) has no cache owner (its
//!   belief is a query over its leaves). `submit_ds_evidence` used to write
//!   its cache from the named frame all the same, and the retraction, which
//!   neither refolds nor vacates a claim with no owner, then left the
//!   retracted BBA's value cached. Now the submit leaves the cache alone, so
//!   there is nothing for the retraction to leave behind.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_db::MassFunctionRepository;
use epigraph_engine::edge_factor::{
    ensure_binary_frame, preview_claim_belief_on_frame, resolve_claim_validity_frame,
};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x5du8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

/// (`pignistic_prob`, `belief_frame_id`, `truth_value`).
async fn cache(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<Uuid>, f64) {
    sqlx::query_as("SELECT pignistic_prob, belief_frame_id, truth_value FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the cache")
}

fn near(x: Option<f64>, y: f64) -> bool {
    x.is_some_and(|x| (x - y).abs() < 1e-9)
}

/// A public claim the server's own agent writes, strengthened through
/// `update_with_evidence`, then given one `submit_ds_evidence` BBA on
/// `claim_validity`. Returns (claim, binary_truth, claim_validity, the cache
/// after `update_with_evidence`, the `submit_ds_evidence` response).
async fn world(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
) -> (
    Uuid,
    Uuid,
    Uuid,
    (Option<f64>, Option<Uuid>, f64),
    serde_json::Value,
) {
    let submitted = first_text(
        &tools::claims::submit_claim(
            server,
            viewer,
            epigraph_mcp::types::SubmitClaimParams {
                content: format!("d33a5c9f owner claim {}", Uuid::new_v4()),
                methodology: "deductive_logic".into(),
                evidence_data: "seed evidence".into(),
                evidence_type: "logical".into(),
                confidence: 0.6,
                source_url: None,
                reasoning: None,
                labels: vec![],
                novelty_threshold: Some(0.0),
                visibility: Some("public".to_string()),
                group_id: None,
            },
            None,
        )
        .await
        .expect("submit_claim"),
    );
    let claim: Uuid = submitted["claim_id"]
        .as_str()
        .expect("claim_id")
        .parse()
        .expect("uuid");

    let updated = first_text(
        &tools::claims::update_with_evidence(
            server,
            viewer,
            epigraph_mcp::types::UpdateWithEvidenceParams {
                canonical_name: None,
                step_index: None,
                claim_id: claim.to_string(),
                evidence_type: "empirical".into(),
                evidence_data: format!("d33a5c9f strengthening result {}", Uuid::new_v4()),
                source_url: None,
                supports: true,
                strength: 0.9,
                labels: Vec::new(),
            },
            None,
        )
        .await
        .expect("update_with_evidence"),
    );
    assert_eq!(
        updated["evidence_owner"], "claim_owner",
        "PREMISE: the server's agent owns the claim it submitted: {updated}"
    );

    let mut conn = pool.acquire().await.expect("acquire");
    let binary = ensure_binary_frame(&mut conn, viewer)
        .await
        .expect("binary_truth");
    let validity = resolve_claim_validity_frame(&mut conn, viewer)
        .await
        .expect("claim_validity");
    drop(conn);
    let before = cache(pool, claim).await;
    assert_eq!(
        before.1,
        Some(binary),
        "PREMISE: update_with_evidence leaves a binary_truth cache ({before:?})"
    );
    assert!(
        before.0.is_some_and(|p| p > 0.8),
        "PREMISE: the strengthened claim's cached BetP is high ({before:?})"
    );

    let submitted_ds = first_text(
        &tools::ds::submit_ds_evidence(
            server,
            viewer,
            serde_json::from_value(serde_json::json!({
                "claim_id": claim.to_string(),
                "frame_id": validity.to_string(),
                "hypothesis_index": 0,
                "masses": {"0": 0.6, "0,1,2": 0.4},
            }))
            .expect("params"),
            None,
        )
        .await
        .expect("submit_ds_evidence"),
    );
    (claim, binary, validity, before, submitted_ds)
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_on_claim_validity_keeps_the_update_with_evidence_cache(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let (claim, binary, validity, before, out) = world(&pool, &server, &viewer).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let owner = MassFunctionRepository::cache_owner_frame_for_claim(&mut *conn, &viewer, claim)
        .await
        .expect("owner");
    let validity_fold = preview_claim_belief_on_frame(&mut conn, &viewer, claim, validity)
        .await
        .expect("preview")
        .expect("the claim_validity BBA folds");
    drop(conn);
    assert_eq!(
        owner,
        Some(binary),
        "PREMISE: the cache owner rule gives binary_truth this claim's cache"
    );
    assert!(
        (validity_fold.pignistic_prob - before.0.expect("a cached BetP")).abs() > 1e-3,
        "PREMISE: the claim_validity fold differs from the cache, so a replacement would show \
         ({validity_fold:?} vs {before:?})"
    );

    let after = cache(&pool, claim).await;
    assert_eq!(
        after, before,
        "submit_ds_evidence on a frame that does not own the cache must leave the owner frame's \
         cache (frame, BetP and truth_value) as it was (response {out})"
    );
    let reported = out["pignistic_prob"].as_f64();
    assert!(
        near(reported, validity_fold.pignistic_prob),
        "the response reports the claim_validity combination {validity_fold:?}, not the cache: \
         {out}"
    );
    let warned = out["warnings"].as_array().is_some_and(|ws| {
        ws.iter().any(|w| {
            w.as_str().is_some_and(|w| {
                w.contains("cached belief was NOT updated") && w.contains(&binary.to_string())
            })
        })
    });
    assert!(
        warned,
        "the response must say the cache was not updated and name the owner frame: {out}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn retracting_that_bba_restores_the_owner_frame_fold(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let (claim, binary, _validity, before, out) = world(&pool, &server, &viewer).await;
    let mf_id = out["mass_function_id"]
        .as_str()
        .expect("mass_function_id")
        .to_string();

    let retracted = first_text(
        &tools::bba_retract::retract_bba(
            &server,
            &viewer,
            tools::bba_retract::RetractBbaParams {
                mass_function_id: mf_id,
                reason: "d33a5c9f: the claim_validity BBA replaced the owner frame's cache"
                    .to_string(),
            },
            None,
        )
        .await
        .expect("retract_bba"),
    );
    assert_eq!(retracted["status"], "retracted", "{retracted}");
    assert_eq!(
        retracted["belief_recomputed"], true,
        "the retraction must report the recompute from the remaining BBAs: {retracted}"
    );

    let after = cache(&pool, claim).await;
    let owner_fold = preview_claim_belief_on_frame(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
        claim,
        binary,
    )
    .await
    .expect("preview")
    .expect("the binary_truth BBAs fold");
    assert_eq!(
        after.1,
        Some(binary),
        "the cache must return to the owner frame after the retraction: {after:?}"
    );
    assert!(
        near(after.0, owner_fold.pignistic_prob),
        "the cache must be the remaining binary_truth fold {owner_fold:?}, not the retracted \
         BBA's value: {after:?} (before the claim_validity BBA: {before:?})"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn on_a_compound_neither_the_submit_nor_the_retract_writes_the_cache(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let (claim, _binary, validity, before, _out) = world(&pool, &server, &viewer).await;
    // The claim decomposes into a current leaf: from now on it is a compound.
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("the claim's author");
    let leaf = fixture::seed_public_claim(&pool, author, "d33a5c9f compound leaf").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(claim)
    .bind(leaf)
    .execute(&pool)
    .await
    .expect("decompose the claim");
    assert_eq!(
        MassFunctionRepository::cache_owner_frame_for_claim(
            &mut *pool.acquire().await.expect("acquire"),
            &viewer,
            claim
        )
        .await
        .expect("owner"),
        None,
        "PREMISE: a compound has no cache owner"
    );
    // The agent's claim_validity BBA, re-stated with other masses (it replaces
    // the first one) while the claim is a compound.
    let second = first_text(
        &tools::ds::submit_ds_evidence(
            &server,
            &viewer,
            serde_json::from_value(serde_json::json!({
                "claim_id": claim.to_string(),
                "frame_id": validity.to_string(),
                "hypothesis_index": 0,
                "masses": {"0": 0.2, "0,1,2": 0.8},
            }))
            .expect("params"),
            None,
        )
        .await
        .expect("submit_ds_evidence on the compound"),
    );
    let written = cache(&pool, claim).await;
    assert_eq!(
        written, before,
        "a compound has no cache owner, so submit_ds_evidence must not fold its own BBAs into \
         its cache ({written:?}, before {before:?}, response {second})"
    );

    let retracted = first_text(
        &tools::bba_retract::retract_bba(
            &server,
            &viewer,
            tools::bba_retract::RetractBbaParams {
                mass_function_id: second["mass_function_id"]
                    .as_str()
                    .expect("mass_function_id")
                    .to_string(),
                reason: "d33a5c9f: compound residual".to_string(),
            },
            None,
        )
        .await
        .expect("retract_bba"),
    );
    let after = cache(&pool, claim).await;
    // A compound has no owner, so the retraction neither refolds nor vacates,
    // and with the submit no longer writing its cache that is now harmless:
    // the cache holds no fold of the retracted BBA.
    assert_eq!(
        (
            &retracted["belief_recomputed"],
            &retracted["belief_vacated"]
        ),
        (&serde_json::json!(false), &serde_json::json!(false)),
        "a compound's retraction neither refolds nor vacates its cache ({retracted})"
    );
    assert_eq!(
        after, before,
        "the compound's cache must hold no fold of the retracted BBA ({after:?}, before \
         {before:?})"
    );
}
