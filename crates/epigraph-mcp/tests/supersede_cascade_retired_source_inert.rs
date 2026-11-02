//! A superseded claim is inert: the supersede cascade invalidates the
//! edge-keyed BBAs the retired claim's OUTGOING edges froze onto current
//! targets, and re-derives those targets without re-wiring from the retired
//! claim (supersede SPEC §1 "inert", §11 K10(2); delivery council N5; backlog
//! 174ffd23, its belief half).
//!
//! Why the cascade missed them: the weakening edges (`refutes`,
//! `contradicts`) stay on the retired claim (#398), and the existing walk
//! (`cascade_after_supersede`) enumerates only the SUCCESSOR's targets, so a
//! retired refuter kept pushing its frozen mass onto its target forever.
//!
//! Driven through the real MCP `supersede_claim`, with edges wired through
//! `do_link_epistemic` (the path that writes the `perspective_id = edge_id`
//! BBAs). No test body calls a recompute.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_claim, seed_claim_with_belief};
use epigraph_mcp::tools::bba_retract::{retract_bba, RetractBbaParams};
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::tools::supersede::supersede_claim;
use epigraph_mcp::types::{LinkEpistemicParams, SupersedeClaimParams};
use sqlx::PgPool;
use uuid::Uuid;

async fn server(pool: &PgPool) -> epigraph_mcp::server::EpiGraphMcpFull {
    build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(pool)
            .await
            .with_maintenance_pool(pool.clone()),
    )
}

/// Wire `s --rel--> t` and return the edge id, checking the BBA landed on `t`.
async fn wire(
    pool: &PgPool,
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    s: Uuid,
    t: Uuid,
    rel: &str,
) -> Uuid {
    let viewer = fixture::public_viewer(pool).await;
    let result = do_link_epistemic(
        server,
        &viewer,
        LinkEpistemicParams {
            source_claim_id: s.to_string(),
            target_claim_id: t.to_string(),
            relationship: rel.to_string(),
            properties: None,
        },
        None,
    )
    .await
    .expect("link_epistemic");
    let body = common::first_text(&result);
    assert_eq!(
        body["belief_wired"],
        serde_json::Value::Bool(true),
        "PREMISE: {s} --{rel}--> {t} wires a BBA; got {body}"
    );
    let edge: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = $3",
    )
    .bind(s)
    .bind(t)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("the wired edge");
    assert_eq!(
        keyed_on(pool, edge).await,
        1,
        "PREMISE: one BBA keyed on edge {edge}"
    );
    edge
}

async fn keyed_on(pool: &PgPool, edge: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE perspective_id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("count edge-keyed rows")
}

/// Live BBAs keyed on an edge sourced at `retired`, held by a current claim:
/// what SPEC §11 K10(2) says must be empty after the cascade.
async fn live_rows_from_retired_source(pool: &PgPool, retired: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions mf \
           JOIN edges e ON e.id = mf.perspective_id \
           JOIN claims h ON h.id = mf.claim_id \
          WHERE e.source_type = 'claim' AND e.source_id = $1 \
            AND h.is_current AND mf.retracted_at IS NULL",
    )
    .bind(retired)
    .fetch_one(pool)
    .await
    .expect("count rows from the retired source")
}

async fn scalars(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>, Option<f64>) {
    sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read cached scalars")
}

async fn preview_betp(pool: &PgPool, claim: Uuid) -> Option<f64> {
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let frame = epigraph_engine::edge_factor::ensure_binary_frame(&mut conn, &viewer)
        .await
        .expect("binary frame");
    epigraph_engine::edge_factor::preview_claim_belief_on_frame(&mut conn, &viewer, claim, frame)
        .await
        .expect("preview")
        .map(|p| p.pignistic_prob)
}

async fn supersede(
    pool: &PgPool,
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    old: Uuid,
) -> serde_json::Value {
    let (auth, admin_viewer) = common::granted_server_admin(server, pool).await;
    let r = supersede_claim(
        server,
        &admin_viewer,
        SupersedeClaimParams {
            claim_id: old.to_string(),
            content: format!("k10 successor of {old}"),
            truth_value: 0.5,
            reason: "k10 inert fixture".to_string(),
        },
        Some(&auth),
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("supersede_claim succeeds");
    common::first_text(&r)
}

fn ids(report: &serde_json::Value, key: &str) -> Vec<Uuid> {
    report[key]
        .as_array()
        .unwrap_or_else(|| panic!("belief_cascade.{key} is an array: {report}"))
        .iter()
        .map(|v| v.as_str().and_then(|s| s.parse().ok()).expect("uuid"))
        .collect()
}

/// A retired refuter stops weighing on its target: the target's refutes BBA
/// is gone, its cache is re-derived from the supporter that remains (and is
/// coherent with the canonical fold), and a claim whose ONLY BBA came from the
/// retired claim is marked unbacked. The successor is not wired in the
/// retired claim's place (invalidate-only: no BBA keyed on the stayed edges
/// exists anywhere afterwards).
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_refuters_edge_bba_is_invalidated_and_its_target_rederived(pool: PgPool) {
    let server = server(&pool).await;
    let refuter = seed_claim_with_belief(&pool, 0.9, 0.95, Some(0.92)).await;
    let supporter = seed_claim_with_belief(&pool, 0.6, 0.7, Some(0.65)).await;
    let target = seed_claim(&pool, "k10 refuted target", 0.5).await;
    let lonely = seed_claim(&pool, "k10 only contradicted", 0.5).await;

    let refutes = wire(&pool, &server, refuter, target, "refutes").await;
    let supports = wire(&pool, &server, supporter, target, "supports").await;
    let contradicts = wire(&pool, &server, refuter, lonely, "contradicts").await;
    let (_, _, before) = scalars(&pool, target).await;
    let before = before.expect("PREMISE: the target has a cached BetP");
    assert!(scalars(&pool, lonely).await.2.is_some(), "PREMISE: cached");

    let body = supersede(&pool, &server, refuter).await;
    assert_eq!(body["cascade"]["status"], "applied", "{body}");

    assert_eq!(
        live_rows_from_retired_source(&pool, refuter).await,
        0,
        "no live BBA keyed on an edge sourced at the retired claim may remain on a current claim"
    );
    assert_eq!(keyed_on(&pool, refutes).await, 0, "the refutes BBA is gone");
    assert_eq!(
        keyed_on(&pool, contradicts).await,
        0,
        "the contradicts BBA is gone, and not re-minted from the successor"
    );
    assert_eq!(
        keyed_on(&pool, supports).await,
        1,
        "the supporter's BBA is untouched"
    );

    let (_, _, after) = scalars(&pool, target).await;
    let after = after.expect("the target keeps its supporter, so it keeps a cache");
    assert!(
        (after - before).abs() > 1e-9,
        "dropping the retired refuter must move the target's BetP: before={before}, after={after}"
    );
    let coherent = preview_betp(&pool, target)
        .await
        .expect("one BBA left on the target");
    assert!(
        (after - coherent).abs() < 1e-12,
        "the target's cache ({after}) is the fold of what survives ({coherent})"
    );
    assert_eq!(
        scalars(&pool, lonely).await,
        (None, None, None),
        "a claim whose only BBA came from the retired claim is unbacked"
    );

    let report = &body["belief_cascade"];
    let mut targets = ids(report, "targets");
    targets.sort();
    let mut expected = vec![target, lonely];
    expected.sort();
    assert_eq!(targets, expected, "the report names both re-derived claims");
    assert_eq!(ids(report, "unbacked"), vec![lonely], "{report}");
    assert!(ids(report, "errors").is_empty(), "{report}");
}

/// The invalidation never touches a RETRACTED row (K4a's rule, SPEC §4): a
/// retracted BBA keyed on an edge from the retired claim survives as a row,
/// while the same retired claim's live BBA on another target is invalidated
/// (so the cascade did run over this source).
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_bba_from_the_retired_source_survives_the_invalidation(pool: PgPool) {
    let server = server(&pool).await;
    let refuter = seed_claim_with_belief(&pool, 0.9, 0.95, Some(0.92)).await;
    let live_target = seed_claim(&pool, "k10 live target", 0.5).await;
    let kept_target = seed_claim(&pool, "k10 retracted-row target", 0.5).await;
    let live_edge = wire(&pool, &server, refuter, live_target, "refutes").await;
    let kept_edge = wire(&pool, &server, refuter, kept_target, "contradicts").await;

    let kept_row: Uuid =
        sqlx::query_scalar("SELECT id FROM mass_functions WHERE perspective_id = $1")
            .bind(kept_edge)
            .fetch_one(&pool)
            .await
            .expect("the row to retract");
    let (auth, admin_viewer) = common::granted_server_admin(&server, &pool).await;
    let retracted = retract_bba(
        &server,
        &admin_viewer,
        RetractBbaParams {
            mass_function_id: kept_row.to_string(),
            reason: "k10 fixture: a retracted edge BBA".to_string(),
        },
        Some(&auth),
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("retract the row through the real path");
    assert_eq!(
        common::first_text(&retracted)["status"],
        "retracted",
        "PREMISE: the row is retracted"
    );

    let body = supersede(&pool, &server, refuter).await;
    assert_eq!(body["cascade"]["status"], "applied", "{body}");

    assert_eq!(
        keyed_on(&pool, live_edge).await,
        0,
        "the retired claim's live BBA on another target is invalidated"
    );
    let survivor: Option<Option<chrono::DateTime<chrono::Utc>>> =
        sqlx::query_scalar("SELECT retracted_at FROM mass_functions WHERE id = $1")
            .bind(kept_row)
            .fetch_optional(&pool)
            .await
            .expect("read the retracted row");
    assert!(
        matches!(survivor, Some(Some(_))),
        "the retracted row survives as a row, still retracted: {survivor:?}"
    );
    assert!(
        ids(&body["belief_cascade"], "errors").is_empty(),
        "the cascade completes: {body}"
    );
}
