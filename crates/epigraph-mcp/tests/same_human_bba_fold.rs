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

/// Stored BBA rows of (claim, frame), counted per writing agent.
async fn rows_by_agent(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
) -> std::collections::BTreeMap<Uuid, i64> {
    let rows: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT source_agent_id, count(*) FROM mass_functions \
          WHERE claim_id = $1 AND frame_id = $2 AND source_agent_id IS NOT NULL \
          GROUP BY source_agent_id",
    )
    .bind(claim)
    .bind(frame)
    .fetch_all(pool)
    .await
    .expect("count rows");
    rows.into_iter().collect()
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

    // The STRONGER sibling first: if the second write replaced the first
    // ("the latest owner row wins"), the cache would read 0.6's value, not
    // the stronger sibling's.
    let claim = fresh_claim(&pool, "same-human ds siblings").await;
    submit(&two, &pool, claim, frame, 0.7).await;
    submit(&one, &pool, claim, frame, 0.6).await;
    let siblings = cached_betp(&pool, claim).await;
    let stored = rows_by_agent(&pool, claim, frame).await;
    assert_eq!(
        (stored.get(&a1).copied(), stored.get(&a2).copied()),
        (Some(1), Some(1)),
        "history kept: one stored row per sibling agent, none replaced"
    );
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

/// One stored BBA of `agent` on (claim, frame), seeded on the harness pool.
async fn seed_row(
    pool: &PgPool,
    agent: Uuid,
    claim: Uuid,
    frame: Uuid,
    masses: &serde_json::Value,
) {
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses, \
                                     source_strength) \
         VALUES ($1, $2, $3, $4, 1.0)",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(masses)
    .execute(pool)
    .await
    .expect("seed BBA row");
}

/// `compare_methods` on (claim, frame, hypothesis 0): per method name, its
/// `(belief, plausibility, pignistic_prob)`.
async fn compare(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
) -> std::collections::BTreeMap<String, (f64, f64, f64)> {
    let viewer = fixture::public_viewer(pool).await;
    let out = tools::ds::compare_methods(
        server,
        &viewer,
        epigraph_mcp::types::CompareMethodsParams {
            claim_id: claim.to_string(),
            frame_id: frame.to_string(),
            hypothesis_index: 0,
        },
    )
    .await
    .expect("compare_methods");
    let text = out
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("a text block");
    let body: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    body["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| {
            (
                r["method"].as_str().expect("method").to_string(),
                (
                    r["belief"].as_f64().expect("belief"),
                    r["plausibility"].as_f64().expect("plausibility"),
                    r["pignistic_prob"].as_f64().expect("pignistic_prob"),
                ),
            )
        })
        .collect()
}

/// Ruling R-36 on MCP `compare_methods` (the fe3ec493 residual): two sibling
/// agents of one human that stored the SAME masses are one owner's evidence,
/// so every combination method reports exactly what one of those BBAs alone
/// gives (the cautious rule is idempotent), never the methods' product of the
/// two. CONTROL: the same two rows by agents of two different owners still
/// combine (Dempster's belief rises above the single BBA's).
#[sqlx::test(migrations = "../../migrations")]
async fn compare_methods_does_not_aggregate_two_agents_of_one_human(pool: PgPool) {
    let (server, _) = server_for_new_agent(&pool, 0x51).await;
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("same-human-compare-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let (human, _) = fixture::seed_human_operator(&pool, "same-human-compare").await;
    let (a1, _) = fixture::seed_agent_with_group(&pool, "same-human-compare-one").await;
    let (a2, _) = fixture::seed_agent_with_group(&pool, "same-human-compare-two").await;
    link(&pool, a1, human).await;
    link(&pool, a2, human).await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "same-human-compare-x").await;
    let masses = serde_json::json!({"0": 0.7, "0,1": 0.3});

    let baseline_claim = fresh_claim(&pool, "same-human compare baseline").await;
    seed_row(&pool, a1, baseline_claim, frame, &masses).await;
    let baseline = compare(&server, &pool, baseline_claim, frame).await;
    assert!(
        (baseline["Dempster"].0 - 0.7).abs() < 1e-9,
        "calibration: one BBA's belief is its own mass: {baseline:?}"
    );

    let claim = fresh_claim(&pool, "same-human compare siblings").await;
    seed_row(&pool, a1, claim, frame, &masses).await;
    seed_row(&pool, a2, claim, frame, &masses).await;
    let siblings = compare(&server, &pool, claim, frame).await;
    assert_eq!(siblings.len(), baseline.len(), "{siblings:?}");
    for (method, single) in &baseline {
        let got = siblings[method];
        assert!(
            (got.0 - single.0).abs() < 1e-9
                && (got.1 - single.1).abs() < 1e-9
                && (got.2 - single.2).abs() < 1e-9,
            "{method}: two agents of one human must report one BBA's {single:?}, not \
             aggregate: got {got:?}"
        );
    }

    let control = fresh_claim(&pool, "same-human compare control").await;
    seed_row(&pool, a1, control, frame, &masses).await;
    seed_row(&pool, stranger, control, frame, &masses).await;
    let independent = compare(&server, &pool, control, frame).await;
    assert!(
        independent["Dempster"].0 > baseline["Dempster"].0 + 1e-3,
        "agents of different owners still combine: {independent:?} vs {baseline:?}"
    );
}
