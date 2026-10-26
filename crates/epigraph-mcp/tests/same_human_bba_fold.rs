//! Ruling R-36 (backlog fe3ec493): agents of one human replace or contest,
//! never aggregate, on EVERY path that combines stored BBAs, not only on
//! `/claims/:id/assess`.
//!
//! # What was wrong, measured at origin/main before this file
//!
//! `submit_ds_evidence` and `update_with_evidence` key each BBA by the WRITING
//! agent, and every combine (`edge_factor::compute_combined_belief` behind the
//! former, `ds_auto::auto_wire_ds_update` for the latter) folded two sibling
//! agents' agreeing BBAs as independent evidence: Dempster's product, so one
//! human with two agents counted twice.
//!
//! # The oracle
//!
//! The stronger sibling's BBA ALONE, written by the same tool on a fresh claim
//! of the same shape. Under the rule the weaker sibling adds nothing, so the
//! two-sibling claim's cached BetP equals that baseline exactly; Dempster's
//! product is strictly higher. A control pins that agents of two DIFFERENT
//! humans still reinforce (the rule is about owners, not about any two
//! agents).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::types::{SubmitDsEvidenceParams, UpdateWithEvidenceParams};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

/// A server whose signing key names a fresh agent row; returns it and the
/// agent. Scoped (the DS tools write on an author-stamped transaction).
async fn server_for_new_agent(pool: &PgPool, seed: u8) -> (EpiGraphMcpFull, Uuid) {
    let signer = AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'mcp-agent') RETURNING id",
    )
    .bind(signer.public_key().as_slice())
    .fetch_one(pool)
    .await
    .expect("the server's agent row");
    let scoped = fixture::scoped_pool(pool).await;
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    let server =
        EpiGraphMcpFull::new(pool.clone(), signer, embedder, false).with_scoped_pool(scoped);
    (server, agent)
}

/// Link `agent` to human operator `human` (migration 107's live link).
async fn link(pool: &PgPool, agent: Uuid, human: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("link the agent to its human");
    assert!(out.link_live, "{out:?}");
}

/// A public claim authored by an agent bound to nobody in this test, so no
/// row the tools write (the truth-value seed included) belongs to a sibling.
async fn fresh_claim(pool: &PgPool, label: &str) -> Uuid {
    let (author, _) = fixture::seed_agent_with_group(pool, "same-human-author").await;
    fixture::seed_public_claim(pool, author, &format!("{label} {}", Uuid::new_v4())).await
}

async fn cached_betp(pool: &PgPool, claim: Uuid) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the cache")
        .expect("the DS write filled the cache")
}

async fn submit(server: &EpiGraphMcpFull, pool: &PgPool, claim: Uuid, frame: Uuid, t: f64) {
    let viewer = fixture::public_viewer(pool).await;
    tools::ds::submit_ds_evidence(
        server,
        &viewer,
        SubmitDsEvidenceParams {
            claim_id: claim.to_string(),
            frame_id: frame.to_string(),
            hypothesis_index: 0,
            // The open-world shape callers of this tool write.
            masses: serde_json::json!({"0": t, "~": 1.0 - t}),
            reliability: Some(1.0),
            combination_method: None,
            gamma: None,
            perspective_id: None,
            evidence_type: None,
            locality_tag: None,
        },
        None,
    )
    .await
    .expect("submit_ds_evidence");
}

async fn binary_frame(pool: &PgPool) -> Uuid {
    let viewer = fixture::public_viewer(pool).await;
    ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &viewer)
        .await
        .expect("binary frame")
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_ds_evidence_by_two_agents_of_one_human_does_not_aggregate(pool: PgPool) {
    let frame = binary_frame(&pool).await;
    let (human, _) = fixture::seed_human_operator(&pool, "same-human-ds").await;
    let (one, a1) = server_for_new_agent(&pool, 0x31).await;
    let (two, a2) = server_for_new_agent(&pool, 0x32).await;
    link(&pool, a1, human).await;
    link(&pool, a2, human).await;
    let (stranger, _) = server_for_new_agent(&pool, 0x33).await;

    let baseline_claim = fresh_claim(&pool, "same-human ds baseline").await;
    submit(&two, &pool, baseline_claim, frame, 0.7).await;
    let baseline = cached_betp(&pool, baseline_claim).await;

    let claim = fresh_claim(&pool, "same-human ds siblings").await;
    submit(&one, &pool, claim, frame, 0.6).await;
    submit(&two, &pool, claim, frame, 0.7).await;
    let siblings = cached_betp(&pool, claim).await;
    assert!(
        (siblings - baseline).abs() < 1e-9,
        "two agents of one human must keep the stronger BBA ({baseline}), not aggregate: \
         got {siblings}"
    );

    // Control: an agent of no human is its own owner, so it reinforces.
    let control = fresh_claim(&pool, "same-human ds control").await;
    submit(&stranger, &pool, control, frame, 0.6).await;
    submit(&two, &pool, control, frame, 0.7).await;
    let independent = cached_betp(&pool, control).await;
    assert!(
        independent > baseline + 1e-3,
        "agents of different owners must still reinforce: {independent} vs {baseline}"
    );
}

async fn update(server: &EpiGraphMcpFull, pool: &PgPool, claim: Uuid, strength: f64, note: &str) {
    let viewer = fixture::public_viewer(pool).await;
    tools::claims::update_with_evidence(
        server,
        &viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim.to_string(),
            evidence_type: "empirical".to_string(),
            evidence_data: format!("{note} {}", Uuid::new_v4()),
            source_url: None,
            supports: true,
            strength,
            labels: vec![],
        },
        None,
    )
    .await
    .expect("update_with_evidence");
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_by_two_agents_of_one_human_does_not_aggregate(pool: PgPool) {
    let (human, _) = fixture::seed_human_operator(&pool, "same-human-uwe").await;
    let (one, a1) = server_for_new_agent(&pool, 0x41).await;
    let (two, a2) = server_for_new_agent(&pool, 0x42).await;
    link(&pool, a1, human).await;
    link(&pool, a2, human).await;
    let (stranger, _) = server_for_new_agent(&pool, 0x43).await;

    let baseline_claim = fresh_claim(&pool, "same-human uwe baseline").await;
    update(&two, &pool, baseline_claim, 0.8, "baseline").await;
    let baseline = cached_betp(&pool, baseline_claim).await;

    // The weaker sibling first, so the supports=true monotonicity clamp (the
    // prior BetP) cannot be what holds the value down.
    let claim = fresh_claim(&pool, "same-human uwe siblings").await;
    update(&one, &pool, claim, 0.5, "first sibling").await;
    update(&two, &pool, claim, 0.8, "second sibling").await;
    let siblings = cached_betp(&pool, claim).await;
    assert!(
        (siblings - baseline).abs() < 1e-9,
        "two agents of one human must keep the stronger BBA ({baseline}), not aggregate: \
         got {siblings}"
    );

    let control = fresh_claim(&pool, "same-human uwe control").await;
    update(&stranger, &pool, control, 0.5, "stranger").await;
    update(&two, &pool, control, 0.8, "sibling").await;
    let independent = cached_betp(&pool, control).await;
    assert!(
        independent > baseline + 1e-3,
        "agents of different owners must still reinforce: {independent} vs {baseline}"
    );
}
