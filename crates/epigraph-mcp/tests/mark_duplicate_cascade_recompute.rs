//! MemTX I2 ("retracting a belief leaves no orphaned derived record") for
//! `mark_duplicate` — PREREGISTRATION.md criterion C5 / BCH-EG-K03.
//!
//! `mark_duplicate` mutates only `edges` and `claims`. Edge-factor BBAs are
//! stored on the edge's **target** claim keyed `perspective_id = edge_id`, so
//! the dedup leaves two distinct classes of wreckage behind:
//!
//!   (a) **orphaned** — the diamond-duplicate pre-delete removes an edge whose
//!       BBA survives (`mass_functions.perspective_id` FKs `perspectives(id)`,
//!       and `perspectives` has no FK back to `edges`, so nothing cascades).
//!       That phantom supporter keeps being combined forever.
//!
//!   (b) **stranded** — `UPDATE edges SET target_id = canonical` re-points an
//!       edge while its BBA stays on `dup`, so `canonical` under-counts that
//!       supporter permanently. It will never self-heal:
//!       `MassFunctionRepository::exists_for_perspective` is keyed on
//!       `perspective_id` alone and ignores `claim_id`, so
//!       `auto_wire_edge_if_epistemic` short-circuits forever.
//!
//! Checking only (a) — "no BBA whose perspective_id lacks a live edge" — passes
//! while (b) is still broken, which is why both invariants are asserted.

mod common;

use common::{admin_auth, build_test_server, seed_claim, seed_claim_with_belief};
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::tools::supersede::mark_duplicate;
use epigraph_mcp::types::{LinkEpistemicParams, MarkDuplicateParams};
use sqlx::PgPool;
use uuid::Uuid;

async fn wire(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    s: Uuid,
    t: Uuid,
    relationship: &str,
) {
    let result = do_link_epistemic(
        server,
        LinkEpistemicParams {
            source_claim_id: s.to_string(),
            target_claim_id: t.to_string(),
            relationship: relationship.to_string(),
            properties: None,
        },
    )
    .await
    .expect("link_epistemic");
    let text = result
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text
        .clone();
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("link response json");
    assert_eq!(
        parsed["belief_wired"],
        serde_json::Value::Bool(true),
        "fixture precondition: {s} --{relationship}--> {t} must materialize a BBA; raw={text}"
    );
}

/// Every edge-perspective BBA whose `perspective_id` no longer names a live
/// edge. Must be zero: it is a phantom supporter.
async fn orphaned_bba_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions mf \
         JOIN perspectives p ON p.id = mf.perspective_id AND p.perspective_type = 'edge' \
         WHERE NOT EXISTS (SELECT 1 FROM edges e WHERE e.id = mf.perspective_id)",
    )
    .fetch_one(pool)
    .await
    .expect("count orphaned BBAs")
}

/// Every edge-perspective BBA that no longer sits on its edge's current
/// target. Must be zero: it is an invisible supporter.
async fn stranded_bba_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM mass_functions mf \
         JOIN perspectives p ON p.id = mf.perspective_id AND p.perspective_type = 'edge' \
         JOIN edges e ON e.id = mf.perspective_id \
         WHERE e.target_type = 'claim' AND e.target_id <> mf.claim_id",
    )
    .fetch_one(pool)
    .await
    .expect("count stranded BBAs")
}

/// C5: after `mark_duplicate(dup, canonical)` the derived-record layer must be
/// repaired on BOTH axes, and `canonical`'s cached scalars must have been
/// recomputed AFTER those repairs.
#[sqlx::test(migrations = "../../migrations")]
async fn diamond_and_migration_leave_no_orphaned_or_stranded_bba(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    let dup = seed_claim(&pool, "duplicate claim", 0.5).await;
    // T corroborates BOTH sides — the diamond that trips the pre-delete guard.
    let t = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    // U supports only the duplicate — the plain migration case.
    let u = seed_claim_with_belief(&pool, 0.6, 0.7, Some(0.65)).await;

    wire(&server, t, dup, "corroborates").await;
    wire(&server, t, canonical, "corroborates").await;
    wire(&server, u, dup, "supports").await;

    assert_eq!(orphaned_bba_count(&pool).await, 0, "fixture starts clean");
    assert_eq!(stranded_bba_count(&pool).await, 0, "fixture starts clean");

    let dup_bbas_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("count dup BBAs");
    assert_eq!(
        dup_bbas_before, 2,
        "fixture: both T->dup and U->dup BBAs are stored on dup (edge factors \
         live on the edge's TARGET)"
    );

    mark_duplicate(
        &server,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: Some("cascade regression fixture".to_string()),
        },
        Some(&admin_auth()),
    )
    .await
    .expect("mark_duplicate succeeds");

    assert_eq!(
        orphaned_bba_count(&pool).await,
        0,
        "(a) the diamond pre-delete removed the T->dup edge; its BBA must go \
         with it, or it keeps being combined into dup's belief forever"
    );
    assert_eq!(
        stranded_bba_count(&pool).await,
        0,
        "(b) the U->dup edge was re-pointed at canonical; its BBA must move \
         too, or canonical under-counts U permanently (exists_for_perspective \
         ignores claim_id, so nothing will ever re-wire it)"
    );

    // The surviving supporter set on canonical is {T->canonical, U->canonical}.
    let canon_bbas: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1")
            .bind(canonical)
            .fetch_one(&pool)
            .await
            .expect("count canonical BBAs");
    assert_eq!(
        canon_bbas, 2,
        "canonical must end up carrying its own T BBA plus the migrated U BBA"
    );

    // ...and canonical's cache must reflect that merged set, not the pre-repair one.
    let frame_id = epigraph_engine::edge_factor::ensure_binary_frame(&pool)
        .await
        .expect("binary frame");
    let coherent =
        epigraph_engine::edge_factor::preview_claim_belief_on_frame(&pool, canonical, frame_id)
            .await
            .expect("preview")
            .expect("canonical has BBAs");
    let cached: Option<f64> = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(canonical)
        .fetch_one(&pool)
        .await
        .expect("read canonical BetP");
    let cached = cached.expect("canonical must have a cached BetP");
    assert!(
        (cached - coherent.pignistic_prob).abs() < 1e-12,
        "canonical's cached BetP ({cached}) must equal the canonical combine of \
         its POST-repair mass_functions set ({}) — recomputing before the \
         repairs bakes in the phantom/invisible supporters",
        coherent.pignistic_prob
    );
}
