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

// ── SourceFactorless: durable edge written even when belief is NOT wired ─────

/// The common production case: the SOURCE claim has an agent but no stored
/// belief interval (NULL DS columns), so `auto_wire_ds_for_edge` short-circuits
/// to `SourceFactorless` and materializes no BBA. The key resilience guarantee
/// (spec §7) is that the durable edge row + `edge.added` event are STILL written
/// and the call still succeeds — `was_created=true` WITH `belief_wired=false` —
/// while the target's belief is left untouched. The other belief tests only
/// reach `belief_wired=false` via the idempotent re-hit (where `was_created` is
/// also false), so this pins the distinct created-but-not-wired branch.
///
/// This is ONLY the first half of the lifecycle. See
/// `factorless_source_wakes_up_when_it_later_gains_belief` below for what must
/// happen when the source subsequently acquires a belief interval and the same
/// edge is re-asserted (backlog 8ef5cf61): the durable edge already exists
/// (`was_created=false` on the second call), and the fix under test wires the
/// edge anyway because no BBA has ever been materialized for it.
#[sqlx::test(migrations = "../../migrations")]
async fn factorless_source_writes_durable_edge_without_wiring(pool: PgPool) {
    let server = build_test_server(pool.clone());
    // `seed_claim` plants an agent_id but leaves belief/plausibility/pignistic
    // NULL → the engine finds no source interval → SourceFactorless.
    let source = seed_claim(&pool, "factorless source", 0.5).await;
    let target = seed_claim(&pool, "untouched target", 0.5).await;

    let resp = parse_response(
        &do_link_epistemic(
            &server,
            LinkEpistemicParams {
                source_claim_id: source.to_string(),
                target_claim_id: target.to_string(),
                relationship: "supports".to_string(),
                properties: Some(serde_json::json!({"note": "no source belief"})),
            },
        )
        .await
        .expect("link must succeed even when the source has no belief interval"),
    );

    assert!(
        resp.was_created,
        "the durable edge must be created even though belief is not wired"
    );
    assert!(
        !resp.belief_wired,
        "a source with no stored belief interval must short-circuit to \
         SourceFactorless — no BBA, no wire"
    );
    assert!(
        resp.target_belief.is_none(),
        "no BBA combined → response target_belief must be None"
    );
    assert!(
        read_betp(&pool, target).await.is_none(),
        "the target's pignistic_prob must remain NULL — no recompute happened"
    );
    assert_eq!(
        edge_count(&pool, source, target, "supports").await,
        1,
        "the durable edge row must persist exactly once despite the no-op wire"
    );

    // Properties still round-trip onto the durable edge.
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
        serde_json::json!({"note": "no source belief"}),
        "properties must round-trip even when belief is not wired"
    );
}

// ── Backlog 8ef5cf61: factorless edges must wake up once the source gains belief ─

/// Regression for backlog claim 8ef5cf61-7382-43a4-85cb-565d76ba3f06.
///
/// Sequence:
///   1. Write A --supports--> B while A has NO belief interval (factorless).
///      The durable edge is created but nothing is wired (asserted above,
///      mirroring `factorless_source_writes_durable_edge_without_wiring`).
///   2. A subsequently acquires a belief interval (e.g. it gains its own
///      evidence later in its lifecycle).
///   3. The SAME (A, supports, B) edge is re-asserted via `link_epistemic`.
///      The edge already exists, so `was_created=false` on this call — but
///      because no BBA has EVER been materialized for this edge_id, the fix
///      must still fire the wake-up wire: B's belief must move and
///      `belief_wired` must report `true`.
///
/// Before the fix, `auto_wire_edge_if_epistemic` (and its caller here) only
/// fired on `was_created=true`, so this second call was a permanent no-op —
/// B's belief would NEVER reflect A's later-acquired belief, even though the
/// edge exists durably. This test must FAIL against that code (RED) and PASS
/// once the gate is switched from "was this edge just created" to "does an
/// edge-factor BBA already exist for this edge_id" (GREEN).
#[sqlx::test(migrations = "../../migrations")]
async fn factorless_source_wakes_up_when_it_later_gains_belief(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let source = seed_claim(&pool, "will gain belief later", 0.5).await;
    let target = seed_claim(&pool, "dependent on source", 0.5).await;

    // ── Step 1: write the edge while A is still factorless ──────────────
    let first = parse_response(
        &do_link_epistemic(
            &server,
            LinkEpistemicParams {
                source_claim_id: source.to_string(),
                target_claim_id: target.to_string(),
                relationship: "supports".to_string(),
                properties: None,
            },
        )
        .await
        .expect("factorless link must still succeed"),
    );
    assert!(first.was_created, "first call creates the durable edge");
    assert!(
        !first.belief_wired,
        "factorless source must not wire belief on first write"
    );
    assert!(
        read_betp(&pool, target).await.is_none(),
        "target belief must remain untouched while the source is factorless"
    );

    // ── Step 2: the source LATER gains a belief interval ─────────────────
    sqlx::query(
        "UPDATE claims SET belief = 0.9, plausibility = 0.9, pignistic_prob = 0.9 WHERE id = $1",
    )
    .bind(source)
    .execute(&pool)
    .await
    .expect("give the source a belief interval");

    // ── Step 3: re-assert the SAME edge — must wake up and wire now ──────
    let second = parse_response(
        &do_link_epistemic(
            &server,
            LinkEpistemicParams {
                source_claim_id: source.to_string(),
                target_claim_id: target.to_string(),
                relationship: "supports".to_string(),
                properties: None,
            },
        )
        .await
        .expect("re-assert of the existing edge must succeed"),
    );

    assert!(
        !second.was_created,
        "the edge already exists — this call must not create a duplicate"
    );
    assert_eq!(
        edge_count(&pool, source, target, "supports").await,
        1,
        "re-asserting must not create a second edge row"
    );
    assert!(
        second.belief_wired,
        "backlog 8ef5cf61: a factorless edge must wake up and wire once its \
         source later gains belief, even though was_created=false on this call"
    );

    let betp = read_betp(&pool, target)
        .await
        .expect("target must now have a computed pignistic_prob");
    assert!(
        betp > 0.5,
        "the wake-up wire must raise the target's pignistic_prob above the \
         0.5 neutral point, got {betp}"
    );

    // Exactly one edge-factor BBA row must exist for this edge — the wake-up
    // must not be re-triggerable into duplicate rows on a further re-hit.
    let bba_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions mf \
         JOIN edges e ON e.id = mf.perspective_id \
         WHERE e.source_id = $1 AND e.target_id = $2 AND e.relationship = 'supports'",
    )
    .bind(source)
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("count edge-factor BBA rows");
    assert_eq!(
        bba_count, 1,
        "exactly one edge-factor BBA must exist after the wake-up wire"
    );

    // ── Step 4: a THIRD re-hit must be a stable no-op (idempotent wake-up) ─
    let pre_betp = read_betp(&pool, target).await.expect("betp present");
    let third = parse_response(
        &do_link_epistemic(
            &server,
            LinkEpistemicParams {
                source_claim_id: source.to_string(),
                target_claim_id: target.to_string(),
                relationship: "supports".to_string(),
                properties: None,
            },
        )
        .await
        .expect("third re-assert must succeed"),
    );
    assert!(!third.was_created);
    assert!(
        !third.belief_wired,
        "once wired, further re-hits must not re-wire (BBA already exists for this edge)"
    );
    let post_betp = read_betp(&pool, target).await.expect("betp present");
    assert!(
        (post_betp - pre_betp).abs() < 1e-9,
        "a third re-hit must not move belief again: before={pre_betp}, after={post_betp}"
    );
    let bba_count_after_third: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions mf \
         JOIN edges e ON e.id = mf.perspective_id \
         WHERE e.source_id = $1 AND e.target_id = $2 AND e.relationship = 'supports'",
    )
    .bind(source)
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("count edge-factor BBA rows after third hit");
    assert_eq!(
        bba_count_after_third, 1,
        "no duplicate BBA row after a third re-hit on an already-wired edge"
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

// ── cites is accepted (structural, non-belief-affecting) — backlog 47afad2e ──

/// `cites` is accepted via the separate `STRUCTURAL_RELATIONSHIPS` allow-list
/// (kept apart from `EPISTEMIC_RELATIONSHIPS` so the coverage guard's
/// all-non-Neutral invariant stays intact — see `link_epistemic.rs`'s
/// `cites_is_structural_and_maps_to_neutral` unit test for that half). This
/// test proves the END-TO-END behavior through the same MCP path
/// `supports_raises_target_belief_and_is_idempotent` exercises above: the
/// edge is created, but — unlike `supports` — the target's belief does NOT
/// move, because `cites` maps to `RestrictionKind::Neutral` and
/// `auto_wire_edge_if_epistemic` no-ops on Neutral relationships.
#[sqlx::test(migrations = "../../migrations")]
async fn cites_edge_is_created_but_does_not_move_belief(pool: PgPool) {
    let server = build_test_server(pool.clone());
    // Same high-commitment source as the `supports` test, so a failure to
    // no-op couldn't hide behind `SourceFactorless`.
    let source = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    let target = seed_claim(&pool, "cited claim", 0.5).await;

    assert!(
        read_betp(&pool, target).await.is_none(),
        "target must start with NULL pignistic_prob (no BBA yet)"
    );

    let result = do_link_epistemic(
        &server,
        LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "cites".to_string(),
            properties: None,
        },
    )
    .await
    .expect("cites must be accepted by link_epistemic");
    let resp = parse_response(&result);

    assert!(resp.was_created, "first cites call must create the edge");
    assert_eq!(resp.relationship, "cites");
    assert!(
        !resp.belief_wired,
        "cites is structural/Neutral — it must NOT wire belief"
    );
    assert_eq!(
        edge_count(&pool, source, target, "cites").await,
        1,
        "exactly one cites edge must exist"
    );
    assert!(
        read_betp(&pool, target).await.is_none(),
        "target's pignistic_prob must remain NULL — a cites edge must not materialize a BBA"
    );

    // Idempotent re-hit: same as the epistemic relationships, a second call
    // with the same (source, target, relationship) must not create a
    // duplicate edge or attempt to re-wire.
    let second = do_link_epistemic(
        &server,
        LinkEpistemicParams {
            source_claim_id: source.to_string(),
            target_claim_id: target.to_string(),
            relationship: "cites".to_string(),
            properties: None,
        },
    )
    .await
    .expect("re-hit must succeed (idempotent)");
    let second_resp = parse_response(&second);
    assert!(
        !second_resp.was_created,
        "re-hit must report was_created=false"
    );
    assert_eq!(
        edge_count(&pool, source, target, "cites").await,
        1,
        "re-hit must not create a duplicate edge"
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
