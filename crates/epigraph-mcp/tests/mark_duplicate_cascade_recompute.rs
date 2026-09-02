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

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{admin_auth, build_test_server, seed_claim, seed_claim_with_belief};
use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::tools::supersede::mark_duplicate;
use epigraph_mcp::types::{LinkEpistemicParams, MarkDuplicateParams};
use sqlx::PgPool;
use uuid::Uuid;

async fn wire(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    s: Uuid,
    t: Uuid,
    relationship: &str,
) {
    let result = do_link_epistemic(
        server, viewer,
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

/// Create the edge without requiring a BBA to materialize. Used when the
/// source is deliberately factorless: the edge row is what the dedup's
/// collision guards inspect, and it exists either way.
async fn link_only(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    s: Uuid,
    t: Uuid,
    relationship: &str,
) {
    do_link_epistemic(
        server, viewer,
        LinkEpistemicParams {
            source_claim_id: s.to_string(),
            target_claim_id: t.to_string(),
            relationship: relationship.to_string(),
            properties: None,
        },
    )
    .await
    .expect("link_epistemic");
}

fn body(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text
        .clone();
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("response JSON: {e}; raw={text}"))
}

async fn dedup(
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    dup: Uuid,
    canonical: Uuid,
) -> serde_json::Value {
    let result = mark_duplicate(
        server, viewer,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: Some("cascade regression fixture".to_string()),
        },
        Some(&admin_auth()),
    )
    .await
    .expect("mark_duplicate succeeds");
    body(&result)
}

/// The single `(edge_id, masses)` pair for the claim→claim edge
/// `s --relationship--> t`, or `None` when the edge no longer carries a BBA.
///
/// Looked up through `edges` rather than a remembered edge id on purpose: the
/// dedup re-sources the edge, so the row must still be findable from its
/// *current* endpoints.
async fn edge_bba(
    pool: &PgPool,
    s: Uuid,
    t: Uuid,
    relationship: &str,
) -> Option<(Uuid, serde_json::Value)> {
    sqlx::query_as(
        "SELECT e.id, mf.masses FROM edges e \
         JOIN mass_functions mf ON mf.perspective_id = e.id \
         WHERE e.source_id = $1 AND e.target_id = $2 AND e.relationship = $3",
    )
    .bind(s)
    .bind(t)
    .bind(relationship)
    .fetch_optional(pool)
    .await
    .expect("read edge BBA")
}

/// The canonical combine pipeline's answer for `claim` on the binary frame,
/// computed WITHOUT writing.
async fn preview_betp(pool: &PgPool, claim_id: Uuid) -> Option<f64> {
    let viewer = fixture::public_viewer(pool).await;
    let frame_id = epigraph_engine::edge_factor::ensure_binary_frame(pool, &viewer)
        .await
        .expect("binary frame");
    epigraph_engine::edge_factor::preview_claim_belief_on_frame(pool, &viewer, claim_id, frame_id)
        .await
        .expect("preview")
        .map(|p| p.pignistic_prob)
}

async fn cached_betp(pool: &PgPool, claim_id: Uuid) -> Option<f64> {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read cached BetP")
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
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    let dup = seed_claim(&pool, "duplicate claim", 0.5).await;
    // T corroborates BOTH sides — the diamond that trips the pre-delete guard.
    let t = seed_claim_with_belief(&pool, 0.9, 0.9, Some(0.9)).await;
    // U supports only the duplicate — the plain migration case.
    let u = seed_claim_with_belief(&pool, 0.6, 0.7, Some(0.65)).await;

    wire(&server, &viewer, t, dup, "corroborates").await;
    wire(&server, &viewer, t, canonical, "corroborates").await;
    wire(&server, &viewer, u, dup, "supports").await;

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
        &server, &viewer,
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
    let frame_id = epigraph_engine::edge_factor::ensure_binary_frame(&pool, &viewer)
        .await
        .expect("binary frame");
    let coherent =
        epigraph_engine::edge_factor::preview_claim_belief_on_frame(&pool, &viewer, canonical, frame_id)
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

// ── phase 2: edges RE-SOURCED from `dup` onto `canonical` ───────────────────

/// The duplicate's **outgoing** epistemic edges survive the dedup, re-sourced
/// at `canonical` — but the BBA they materialized lives on the far end and was
/// frozen from `dup`'s interval at wire time. Recombining it is a numeric
/// no-op (PREREGISTRATION F2), so it has to be invalidated and re-derived from
/// `canonical`.
///
/// No fixture in the original commit gave `dup` an outgoing edge, so
/// `DedupRepair::resourced_edges` was empty in every test and the entire
/// phase-2 block could be deleted with the suite still green. This is the
/// fixture that discriminates.
#[sqlx::test(migrations = "../../migrations")]
async fn resourced_outgoing_edge_bba_is_re_derived_from_canonical(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    // `canonical` earns a HIGH interval from its own supporter W, so it is a
    // real (BBA-backed) interval rather than a hand-planted column value.
    let w = seed_claim_with_belief(&pool, 0.95, 0.98, Some(0.96)).await;
    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    wire(&server, &viewer, w, canonical, "supports").await;

    // `dup` carries a deliberately LOW interval, so a BBA frozen from it is
    // numerically distinguishable from one derived from `canonical`.
    let dup = seed_claim_with_belief(&pool, 0.15, 0.25, Some(0.2)).await;
    let v = seed_claim(&pool, "downstream claim V", 0.5).await;
    wire(&server, &viewer, dup, v, "supports").await;

    let (edge_before, masses_before) = edge_bba(&pool, dup, v, "supports")
        .await
        .expect("fixture: dup --supports--> V carries a BBA on V");

    let json = dedup(&server, &viewer, dup, canonical).await;

    // The edge itself moved to `canonical`...
    let (edge_after, masses_after) = edge_bba(&pool, canonical, v, "supports")
        .await
        .expect("the re-sourced edge must still carry a BBA — deleting it without re-deriving is evidence loss");
    assert_eq!(
        edge_before, edge_after,
        "the edge row is re-sourced in place, so its id (and therefore its \
         perspective) is stable"
    );

    // ...and its BBA now encodes CANONICAL's interval, not the duplicate's.
    assert_ne!(
        masses_before, masses_after,
        "the BBA was frozen from dup's interval ({masses_before}) at wire time; \
         after the dedup it must be re-derived from canonical's. An unchanged \
         mass map means the cascade recombined instead of invalidating."
    );

    let cached = cached_betp(&pool, v).await.expect("V keeps a cached BetP");
    let coherent = preview_betp(&pool, v).await.expect("V still has a BBA");
    assert!(
        (cached - coherent).abs() < 1e-12,
        "V's cached BetP ({cached}) must equal the canonical combine of its \
         POST-cascade mass_functions set ({coherent})"
    );

    let cascade = &json["belief_cascade"];
    assert!(
        cascade["targets"]
            .as_array()
            .expect("targets array")
            .iter()
            .any(|t| t.as_str() == Some(v.to_string().as_str())),
        "V's derived record was rebuilt; the report must say so; got {cascade}"
    );
    assert!(
        cascade["errors"]
            .as_array()
            .expect("errors array")
            .is_empty(),
        "healthy cascade must report no errors; got {cascade}"
    );
}

/// A claim can be **both** a phase-1 stale target (it lost a BBA to one of the
/// collision pre-deletes) **and** a phase-2 re-sourced-edge target (another of
/// the duplicate's outgoing edges survived and points at it). With a single
/// `visited` set shared between the two phases, such a claim is recomputed
/// *before* phase 2 mutates its BBA set and never after — and the report still
/// lists it under `targets`/`recomputed`, affirmatively claiming a repair that
/// did not happen.
///
/// The masking subtlety this fixture is built around: `auto_wire_ds_for_edge`
/// ends with its own `recompute_combined_belief(target)`, so whenever the
/// re-wire succeeds the missed recomputation is repaired by accident. The bug
/// is only observable when the re-derivation does **not** produce a BBA — and
/// `SourceFactorless` is the *common* case, because `canonical` need not carry
/// a belief interval at all. So `canonical` is deliberately factorless here:
/// phase 2 deletes V's last BBA and cannot replace it, and nothing recomputes
/// V afterwards.
#[sqlx::test(migrations = "../../migrations")]
async fn target_of_both_a_collision_delete_and_a_resourced_edge_is_recomputed_last(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    // Factorless canonical: NULL belief/plausibility, exactly as
    // `ClaimRepository::supersede` and a plain `submit_claim` leave a claim.
    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    let dup = seed_claim_with_belief(&pool, 0.15, 0.25, Some(0.2)).await;
    let v = seed_claim(&pool, "downstream claim V", 0.5).await;

    // (1) The collision pair. `canonical --supports--> V` wires no BBA (the
    //     source is factorless), but the EDGE exists, which is all the
    //     "outgoing dup-edge whose migrated triple already exists" pre-delete
    //     looks at. It drops `dup --supports--> V`, putting V into
    //     `DedupRepair::stale_claims`.
    link_only(&server, &viewer, canonical, v, "supports").await;
    wire(&server, &viewer, dup, v, "supports").await;
    // (2) The survivor: no `canonical --corroborates--> V` exists, so this edge
    //     is re-sourced rather than dropped, putting V into
    //     `DedupRepair::resourced_edges` as well.
    wire(&server, &viewer, dup, v, "corroborates").await;

    assert!(
        cached_betp(&pool, v).await.is_some(),
        "fixture: V starts with a cached BetP derived from dup's BBAs"
    );

    let json = dedup(&server, &viewer, dup, canonical).await;

    assert_eq!(orphaned_bba_count(&pool).await, 0);
    assert_eq!(stranded_bba_count(&pool).await, 0);

    // Phase 2 deleted the corroborates BBA and could not re-derive it —
    // canonical has no interval — so V now has no evidence at all.
    assert_eq!(
        preview_betp(&pool, v).await,
        None,
        "fixture precondition: V must end the dedup with an empty surviving \
         BBA set, which is what makes the missed recomputation observable"
    );

    let cascade = &json["belief_cascade"];
    assert_eq!(
        cached_betp(&pool, v).await,
        None,
        "V's last supporter was invalidated by phase 2 and never replaced, so \
         its cache must be cleared (C6's unbacked marker). A `visited` set \
         shared between the two phases marks V during phase 1 and then skips \
         it, leaving V believed at a number no surviving BBA produces — while \
         the report claims it was repaired: {cascade}"
    );
    let unbacked: Vec<String> = cascade["unbacked"]
        .as_array()
        .expect("unbacked array")
        .iter()
        .map(|x| x.as_str().expect("uuid string").to_string())
        .collect();
    assert!(
        unbacked.contains(&v.to_string()),
        "the report must name V as unbacked rather than as recomputed; \
         got {cascade}"
    );
    assert!(
        !cascade["recomputed"]
            .as_array()
            .expect("recomputed array")
            .iter()
            .any(|x| x.as_str() == Some(v.to_string().as_str())),
        "V has nothing left to combine; reporting it as recomputed asserts a \
         repair that did not happen; got {cascade}"
    );
}

// ── C3 (surgical) for the dedup path ────────────────────────────────────────

/// `DedupRepair::stale_claims` always contains both endpoints, whether or not
/// the dedup changed anything about their evidence. Collapsing two claims that
/// carry no edge-factor BBAs at all must therefore be a **no-op on the derived
/// layer** — not a rewrite of the survivor.
///
/// The failure this pins is quiet: `claims.mass_on_empty` and
/// `claims.mass_on_missing` are `DEFAULT 0.0` and the canonical insert omits
/// them, so an unconditional "clear the cache" pass flips a real `0.0` to NULL
/// and bumps `updated_at` on the surviving claim — visible through
/// `GET /api/v1/claims/{id}/belief` as `mass_on_conflict: 0.0 → null` — while
/// reporting both endpoints as `unbacked` when neither ever had a cache.
/// `sweep_semantic_duplicates` applies this to every collapsed pair in a bulk
/// run.
#[sqlx::test(migrations = "../../migrations")]
async fn bba_free_dedup_leaves_the_survivors_derived_columns_alone(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_test_server(pool.clone());

    let canonical = seed_claim(&pool, "canonical claim", 0.5).await;
    let dup = seed_claim(&pool, "duplicate claim", 0.5).await;

    type DerivedColumns = (
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    );
    let read = |id: Uuid, pool: PgPool| async move {
        sqlx::query_as::<_, DerivedColumns>(
            "SELECT belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing, \
                    classification, updated_at \
             FROM claims WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("read derived columns")
    };

    let before = read(canonical, pool.clone()).await;
    assert_eq!(
        (before.3, before.4),
        (Some(0.0), Some(0.0)),
        "fixture: the schema defaults are real values, not NULL — which is \
         exactly why an unconditional clear is a mutation"
    );

    let json = dedup(&server, &viewer, dup, canonical).await;

    let after = read(canonical, pool.clone()).await;
    assert_eq!(
        before, after,
        "the dedup touched no evidence, so the survivor's derived columns and \
         updated_at must be byte-identical"
    );

    let cascade = &json["belief_cascade"];
    assert!(
        cascade["unbacked"]
            .as_array()
            .expect("unbacked array")
            .is_empty(),
        "'unbacked' must mean 'had a cache, now has no evidence', not 'never \
         had one'; got {cascade}"
    );
    assert!(
        cascade["targets"]
            .as_array()
            .expect("targets array")
            .is_empty(),
        "nothing downstream was repaired, so nothing may be claimed as \
         repaired; got {cascade}"
    );
    assert!(
        cascade["errors"]
            .as_array()
            .expect("errors array")
            .is_empty(),
        "a BBA-free dedup is a healthy no-op, not a failure; got {cascade}"
    );
}
