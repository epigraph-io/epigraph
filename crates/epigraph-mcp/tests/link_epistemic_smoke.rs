//! End-to-end smoke test for the `link_epistemic` MCP tool.
//!
//! Drives `do_link_epistemic` directly against a `sqlx::test` pool so the
//! happy / belief-moves / idempotent / validation / 404-equivalent paths all
//! exercise the same repo + engine layer the production rmcp dispatcher uses.
//!
//! Unlike `link_hierarchical` (inert), this tool wires belief: a `supports`
//! edge must RAISE the target's combined `pignistic_prob`, a `contradicts`
//! edge must LOWER it, and an idempotent re-hit must NOT re-apply. The
//! belief-move assertions mirror the engine fixture
//! `crates/epigraph-engine/tests/intra_source_discount_regression.rs`:
//!
//!   * the SOURCE claim must carry a populated belief interval (belief =
//!     plausibility = 0.9), else `auto_wire_ds_for_edge` short-circuits to
//!     `SourceFactorless` and writes no BBA;
//!   * the move is asserted against the target's cached `pignistic_prob`
//!     column (the column the recompute writes), NOT the unframed
//!     `belief_query::get_belief`, which reads `truth_value` and would show no
//!     movement.

mod common;

use common::{build_test_server, seed_claim, seed_claim_with_belief};
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::types::LinkEpistemicParams;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(serde::Deserialize)]
struct Belief {
    #[allow(dead_code)]
    belief: f64,
    #[allow(dead_code)]
    plausibility: f64,
    pignistic_prob: f64,
}

#[derive(serde::Deserialize)]
struct LinkEpistemicResponse {
    edge_id: String,
    was_created: bool,
    relationship: String,
    belief_wired: bool,
    target_belief: Option<Belief>,
}

fn parse_response(result: &rmcp::model::CallToolResult) -> LinkEpistemicResponse {
    let text = result
        .content
        .first()
        .expect("at least one content block")
        .as_text()
        .expect("text content")
        .text
        .clone();
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("LinkEpistemicResponse JSON: {e}; raw={text}"))
}

/// Read the target's cached pignistic probability directly from the column the
/// edge-wiring recompute writes (mirrors `read_betp` in the engine fixture).
/// Returns `None` when the column is still NULL (no BBA combined yet).
async fn read_betp(pool: &PgPool, claim_id: Uuid) -> Option<f64> {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read pignistic_prob")
}

async fn edge_count(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM edges \
         WHERE source_id = $1 AND target_id = $2 AND relationship = $3 \
           AND source_type = 'claim' AND target_type = 'claim'",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("count edges")
}

// ── supports raises the target's belief, and is idempotent ──────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn supports_raises_target_belief_and_is_idempotent(pool: PgPool) {
    let server = build_test_server(pool.clone());
    // High-commitment source so the wire produces `Wired` (not SourceFactorless).
    let source = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    // Target starts neutral: NULL DS columns, truth_value 0.5.
    let target = seed_claim(&pool, "target claim", 0.5).await;

    assert!(
        read_betp(&pool, target).await.is_none(),
        "target must start with NULL pignistic_prob (no BBA yet)"
    );

    let first = do_link_epistemic(
        &server,
        LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "supports".to_string(),
            properties: Some(serde_json::json!({"note": "evidence A"})),
        },
    )
    .await
    .expect("supports wire succeeds");
    let first_resp = parse_response(&first);

    assert!(
        first_resp.was_created,
        "first call must report was_created=true"
    );
    assert!(
        first_resp.belief_wired,
        "supports from a high-belief source must wire belief (engine outcome Wired)"
    );
    assert_eq!(first_resp.relationship, "supports");

    // The target's combined belief must have moved UP from the 0.5 neutral
    // point — this is the whole point of an epistemic (vs hierarchical) edge.
    let betp = read_betp(&pool, target)
        .await
        .expect("target must have a computed pignistic_prob after the supports wire");
    assert!(
        betp > 0.5,
        "supports edge must raise the target's pignistic_prob above the 0.5 neutral point, got {betp}"
    );
    // The response's target_belief must reflect that same post-recompute value.
    let resp_betp = first_resp
        .target_belief
        .as_ref()
        .expect("response must carry target_belief after a successful wire")
        .pignistic_prob;
    assert!(
        (resp_betp - betp).abs() < 1e-9,
        "response target_belief.pignistic_prob ({resp_betp}) must match the DB column ({betp})"
    );

    // Edge row exists exactly once with the round-tripped properties.
    let props: serde_json::Value = sqlx::query_scalar(
        "SELECT properties FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'supports'",
    )
    .bind(source)
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("edge row");
    assert_eq!(
        props,
        serde_json::json!({"note": "evidence A"}),
        "properties must round-trip onto the edge row"
    );

    // ── Idempotent re-hit: same triple → was_created=false, no re-wire ──
    let pre_betp = read_betp(&pool, target).await.expect("betp present");
    let second = do_link_epistemic(
        &server,
        LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "supports".to_string(),
            properties: Some(serde_json::json!({"note": "evidence A"})),
        },
    )
    .await
    .expect("idempotent re-run succeeds");
    let second_resp = parse_response(&second);

    assert!(
        !second_resp.was_created,
        "second identical call must report was_created=false (dedup hit)"
    );
    assert!(
        !second_resp.belief_wired,
        "idempotent re-hit must NOT re-wire belief"
    );
    assert_eq!(
        second_resp.edge_id, first_resp.edge_id,
        "dedup hit must return the existing edge_id"
    );
    assert_eq!(
        edge_count(&pool, source, target, "supports").await,
        1,
        "exactly one edge row after the idempotent re-run"
    );
    let post_betp = read_betp(&pool, target).await.expect("betp present");
    assert!(
        (post_betp - pre_betp).abs() < 1e-9,
        "idempotent re-hit must NOT change the target's belief: before={pre_betp}, after={post_betp}"
    );
}

// ── contradicts lowers the target's belief ──────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn contradicts_lowers_target_belief(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let source = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let target = seed_claim(&pool, "target under attack", 0.5).await;

    let resp = parse_response(
        &do_link_epistemic(
            &server,
            LinkEpistemicParams {
                source_claim_id: source.to_string(),
                target_claim_id: target.to_string(),
                relationship: "contradicts".to_string(),
                properties: None,
            },
        )
        .await
        .expect("contradicts wire succeeds"),
    );

    assert!(resp.was_created);
    assert!(
        resp.belief_wired,
        "contradicts from a high-belief source must wire belief"
    );

    let betp = read_betp(&pool, target)
        .await
        .expect("target must have a computed pignistic_prob after the contradicts wire");
    assert!(
        betp < 0.5,
        "contradicts edge must lower the target's pignistic_prob below the 0.5 neutral point, got {betp}"
    );
}

// ── validation: relationship not in the epistemic set ───────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn structural_relationship_is_rejected(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let source = seed_claim(&pool, "s", 0.5).await;
    let target = seed_claim(&pool, "t", 0.5).await;

    let err = do_link_epistemic(
        &server,
        LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            // structural relationship — valid for link_hierarchical, rejected here
            relationship: "decomposes_to".to_string(),
            properties: None,
        },
    )
    .await
    .expect_err("decomposes_to must be rejected by the epistemic allow-list");
    let msg = err.message.to_string();
    assert!(msg.contains("invalid relationship"), "got: {msg}");
    assert!(
        msg.contains("supports"),
        "error should list the valid set; got: {msg}"
    );
    assert_eq!(
        edge_count(&pool, source, target, "decomposes_to").await,
        0,
        "no edge written on validation failure"
    );
}

// ── validation: supersedes is excluded (belongs to supersede_claim) ─────────

#[sqlx::test(migrations = "../../migrations")]
async fn supersedes_is_rejected(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let source = seed_claim(&pool, "newer", 0.5).await;
    let target = seed_claim(&pool, "older", 0.5).await;

    let err = do_link_epistemic(
        &server,
        LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "supersedes".to_string(),
            properties: None,
        },
    )
    .await
    .expect_err("supersedes must be rejected — it has dedicated semantics in supersede_claim");
    assert!(
        err.message.to_string().contains("invalid relationship"),
        "got: {}",
        err.message
    );
    assert_eq!(
        edge_count(&pool, source, target, "supersedes").await,
        0,
        "no supersedes edge written"
    );
}

// ── validation: self-loop ───────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn self_loop_is_rejected(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let claim = seed_claim(&pool, "loop", 0.5).await;

    let err = do_link_epistemic(
        &server,
        LinkEpistemicParams {
            source_claim_id: claim.to_string(),
            target_claim_id: claim.to_string(),
            relationship: "supports".to_string(),
            properties: None,
        },
    )
    .await
    .expect_err("self-loops must be rejected");
    assert!(
        err.message.to_lowercase().contains("self-loop"),
        "error should mention self-loops; got: {}",
        err.message
    );
}

// ── 404-equivalent: missing target claim ────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn missing_target_claim_is_rejected(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let source = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let bogus = Uuid::new_v4();

    let err = do_link_epistemic(
        &server,
        LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: bogus.to_string(),
            relationship: "supports".to_string(),
            properties: None,
        },
    )
    .await
    .expect_err("missing target claim must error");
    let msg = err.message.to_string();
    assert!(
        msg.contains("target_claim_id") && msg.contains(&bogus.to_string()),
        "error should identify the missing side and its UUID; got: {msg}"
    );
}
