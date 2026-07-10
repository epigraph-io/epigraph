//! Regression for backlog 2bffdfdc: `submit_ds_evidence`'s immediately
//! returned belief must match what a subsequent `recompute_beliefs` computes
//! for the same claim/frame with no new evidence in between.
//!
//! Root cause: `submit_ds_evidence` re-combined the raw stored masses with a
//! fixed-method `combine_two` loop and no dynamic reliability discount, while
//! `recompute_beliefs` (via `recompute_claim_belief_on_frame` /
//! `recompute_combined_belief`) applies the issue-197 Phase 2/4 dynamic
//! effective-reliability discount chain and the adaptive `combine_multiple`
//! rule selection before combining. Same BBA rows, two different answers.

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::types::{RecomputeBeliefsParams, SubmitDsEvidenceParams};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::RawContent;
use sqlx::PgPool;
use uuid::Uuid;

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x5du8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn result_json(out: rmcp::model::CallToolResult) -> serde_json::Value {
    let first = out.content.first().cloned().expect("first content");
    let text = match first.raw {
        RawContent::Text(t) => t.text,
        other => panic!("expected text content, got {other:?}"),
    };
    serde_json::from_str(&text).expect("result is JSON")
}

async fn insert_agent(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test'])
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn insert_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn cached_pignistic(pool: &PgPool, claim_id: Uuid) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("query pignistic_prob")
        .expect("pignistic_prob populated")
}

/// A single `submit_ds_evidence` call's immediately-returned pignistic must
/// match what `recompute_beliefs` computes right after, with no new evidence
/// submitted in between. Before the fix, `submit_ds_evidence` skipped the
/// dynamic reliability discount entirely (stored `evidence_type: None`,
/// `source_strength: None` => `effective_source_strength` falls to the 0.5
/// unknown-key fallback at recompute time), so the two numbers diverged even
/// for one BBA.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_beliefs_matches_submit_ds_evidence_immediate_result(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "ds-recompute-match").await;
    let claim = insert_claim(
        &pool,
        agent,
        &format!("ds-recompute-match-{}", Uuid::new_v4()),
    )
    .await;
    let frame_id = ensure_binary_frame(&pool).await.expect("binary frame");

    let submit_out = tools::ds::submit_ds_evidence(
        &server,
        SubmitDsEvidenceParams {
            claim_id: claim.to_string(),
            frame_id: frame_id.to_string(),
            hypothesis_index: 0,
            masses: serde_json::json!({"0": 0.8, "~": 0.2}),
            reliability: Some(0.8),
            combination_method: None,
            gamma: None,
            perspective_id: None,
        },
    )
    .await
    .expect("submit_ds_evidence");
    let submit_json = result_json(submit_out);
    let submit_pignistic = submit_json["pignistic_prob"]
        .as_f64()
        .expect("submit pignistic_prob is a number");

    // Cache written by submit_ds_evidence should already reflect that same value.
    let cached_after_submit = cached_pignistic(&pool, claim).await;
    assert!(
        (cached_after_submit - submit_pignistic).abs() < 1e-9,
        "submit_ds_evidence's own cache write ({cached_after_submit}) should match its \
         returned pignistic_prob ({submit_pignistic})"
    );

    // No new evidence submitted — recompute_beliefs must reproduce the exact
    // same number from the exact same stored BBA rows.
    let recompute_out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        RecomputeBeliefsParams {
            claim_ids: Some(vec![claim.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");
    let recompute_json = result_json(recompute_out);
    assert!(
        recompute_json["errors"].as_array().unwrap().is_empty(),
        "recompute_beliefs reported errors: {recompute_json:?}"
    );

    let recomputed_pignistic = cached_pignistic(&pool, claim).await;

    assert!(
        (recomputed_pignistic - submit_pignistic).abs() < 1e-9,
        "submit_ds_evidence returned pignistic_prob {submit_pignistic}, but a subsequent \
         recompute_beliefs with no new evidence produced {recomputed_pignistic} — the two \
         combine paths disagree on the same BBA set"
    );
}

/// Two-BBA variant: guards against the combine-method half of the
/// divergence (submit's fixed-method `combine_two` loop vs recompute's
/// adaptive `combine_multiple` rule selection), which a single-BBA test
/// cannot exercise since both paths no-op when there's only one row.
#[sqlx::test(migrations = "../../migrations")]
async fn recompute_beliefs_matches_submit_ds_evidence_after_two_submissions(pool: PgPool) {
    let server = make_server(pool.clone());
    let agent = insert_agent(&pool, "ds-recompute-match-2").await;
    let claim = insert_claim(
        &pool,
        agent,
        &format!("ds-recompute-match-2-{}", Uuid::new_v4()),
    )
    .await;
    let frame_id = ensure_binary_frame(&pool).await.expect("binary frame");

    for masses in [
        serde_json::json!({"0": 0.7, "~": 0.3}),
        serde_json::json!({"1": 0.4, "~": 0.6}),
    ] {
        tools::ds::submit_ds_evidence(
            &server,
            SubmitDsEvidenceParams {
                claim_id: claim.to_string(),
                frame_id: frame_id.to_string(),
                hypothesis_index: 0,
                masses,
                reliability: Some(0.9),
                combination_method: None,
                gamma: None,
                perspective_id: None,
            },
        )
        .await
        .expect("submit_ds_evidence");
    }

    let submit_pignistic = cached_pignistic(&pool, claim).await;

    let recompute_out = tools::cdst_maintenance::recompute_beliefs(
        &server,
        RecomputeBeliefsParams {
            claim_ids: Some(vec![claim.to_string()]),
            labels: None,
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("recompute_beliefs");
    let recompute_json = result_json(recompute_out);
    assert!(
        recompute_json["errors"].as_array().unwrap().is_empty(),
        "recompute_beliefs reported errors: {recompute_json:?}"
    );

    let recomputed_pignistic = cached_pignistic(&pool, claim).await;

    assert!(
        (recomputed_pignistic - submit_pignistic).abs() < 1e-9,
        "after two submit_ds_evidence calls, cached pignistic_prob {submit_pignistic} diverged \
         from recompute_beliefs's {recomputed_pignistic}"
    );
}
