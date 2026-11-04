//! The targeted rewire's per-edge guards (R-176(2), R-177(4) class E;
//! design §1.4, §1.11). `backfill_factors::rewire_edge_targeted` rewrites an
//! edge-factor row only when every guard holds, and otherwise leaves the edge
//! EXACTLY as it was, counted under a held bucket:
//!
//! * OD-E1, the interim F2 baseline of zero, enforced in code: an edge whose
//!   fresh wire would store nothing (vacuous restriction, factorless source),
//!   which the un-targeted phase deletes, is kept; a second live row that
//!   appeared after the selection is never merged away;
//! * OD-E2: a target whose cache is not the fold of its current rows is held;
//! * OD-E3: a stored row stale for a reason other than its source's move
//!   (row class `mixed`) is held;
//! * OD-E5: `supersedes`, compound ends and a retracted row on the edge are
//!   held, and the retracted row is never deleted or rewritten (the H10
//!   guard, migration 194, is applied on this database and never fires);
//! * `only_changed`: a row a fresh wire would not change is not rewritten.
//!
//! Each world is built by the real wire (`rewire_fixture`): the stored row is
//! what `auto_wire_ds_for_edge` wrote from the source's pre-move interval, and
//! the target was refolded by it, so a held edge is a guard firing on a real
//! row, not on a hand-made one. The un-targeted phase (`run_rewire_phase`)
//! keeps its behaviour; `backfill_factors_rewire.rs` pins it unchanged.
#![cfg(feature = "db")]

mod rewire_fixture;
mod viewer_fixture;

use std::collections::HashMap;

use epigraph_cli::backfill_factors::{
    rewire_edge_targeted, run_rewire_phase, select_targeted_edges, HeldBucket, RewireCapture,
    RewireEdge, RewireOptions, StoredEdgeRow, TargetedGuards, TargetedOutcome,
};
use epigraph_cli::belief_cache::WaveRecord;
use epigraph_cli::edge_rewire::{predict_targeted_rewire, seed_from_waves, TargetedRunOptions};
use epigraph_db::visibility::Viewer;
use rewire_fixture::*;
use sqlx::PgPool;
use uuid::Uuid;

/// `source —supports→ target`, both fresh, the edge wired from the source's
/// first value (EVIDENCE_A); then the wave moves the source to EVIDENCE_B.
struct World {
    frame: Uuid,
    author: Uuid,
    source: Uuid,
    target: Uuid,
    edge: Uuid,
    /// `(belief, plausibility)` the source held before the wave moved it.
    baseline: HashMap<Uuid, (f64, f64)>,
    /// The wave's record of the source's move (what a predict is seeded from).
    wave: Vec<WaveRecord>,
}

async fn world(
    pool: &PgPool,
    viewer: &Viewer,
    tag: &str,
    rel: &str,
    target_own_evidence: bool,
) -> World {
    let author = seed_agent(pool, &format!("targeted-{tag}")).await;
    let frame = binary_frame(pool, viewer).await;
    let source = fresh_claim(
        pool,
        viewer,
        author,
        frame,
        &format!("source {tag}"),
        EVIDENCE_A,
    )
    .await;
    let target = if target_own_evidence {
        fresh_claim(
            pool,
            viewer,
            author,
            frame,
            &format!("target {tag}"),
            TARGET_EVIDENCE,
        )
        .await
    } else {
        seed_claim(pool, author, &format!("edge-only target {tag}"), None, 0.0).await
    };
    let edge = wired_edge(pool, viewer, author, source, target, rel).await;
    let rec = move_claim(pool, viewer, source, EVIDENCE_B).await;
    let mut baseline = HashMap::new();
    baseline.insert(
        source,
        (
            rec.before.belief.expect("bel"),
            rec.before.plausibility.expect("pl"),
        ),
    );
    World {
        frame,
        author,
        source,
        target,
        edge,
        baseline,
        wave: vec![rec],
    }
}

async fn selected(pool: &PgPool, sources: &[Uuid]) -> Vec<RewireEdge> {
    let mut conn = pool.acquire().await.expect("conn");
    select_targeted_edges(&mut conn, sources, None)
        .await
        .expect("select")
}

async fn the_edge(pool: &PgPool, w: &World) -> RewireEdge {
    let edges = selected(pool, &[w.source]).await;
    assert_eq!(
        edges.len(),
        1,
        "the world's one edge is selected: {edges:?}"
    );
    assert_eq!(edges[0].edge_id, w.edge);
    edges.into_iter().next().unwrap()
}

/// Run one targeted rewire and return its outcome and the captures it
/// recorded before committing.
async fn rewire(
    pool: &PgPool,
    viewer: &Viewer,
    edge: &RewireEdge,
    baseline: &HashMap<Uuid, (f64, f64)>,
    only_changed: bool,
) -> (TargetedOutcome, Vec<RewireCapture>) {
    let own: HashMap<Uuid, StoredEdgeRow> = HashMap::new();
    let guards = TargetedGuards {
        baseline,
        own_rows: &own,
        only_changed,
    };
    let mut captured: Vec<RewireCapture> = Vec::new();
    let mut on_capture = |c: &RewireCapture| -> Result<(), String> {
        captured.push(c.clone());
        Ok(())
    };
    let out = rewire_edge_targeted(pool, viewer, edge, &guards, &mut on_capture)
        .await
        .expect("targeted rewire");
    (out, captured)
}

/// Everything a held edge must leave alone: the edge's rows (all columns,
/// retracted ones included) and the target's cache and `updated_at`.
async fn footprint(
    pool: &PgPool,
    w: &World,
) -> (
    Vec<RowText>,
    epigraph_cli::belief_cache::CacheColumns,
    chrono::DateTime<chrono::Utc>,
) {
    (
        edge_rows(pool, w.edge).await,
        cache(pool, w.target).await,
        updated_at(pool, w.target).await,
    )
}

fn assert_held(out: &TargetedOutcome, bucket: HeldBucket) {
    assert_eq!(
        out,
        &TargetedOutcome::Held(bucket),
        "expected held {}",
        bucket.name()
    );
}

/// Positive control: a fresh target and an `r173` row are rewired to what a
/// fresh wire from the source's new interval stores, and the target is
/// refolded; the capture records both sides.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_rewrites_an_r173_row_into_a_fresh_target(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "ok", "supports", true).await;
    let edge = the_edge(&pool, &w).await;
    let (rows_before, cache_before, _) = footprint(&pool, &w).await;

    let (out, captured) = rewire(&pool, &viewer, &edge, &w.baseline, false).await;

    let TargetedOutcome::Rewired(c) = out else {
        panic!("expected a rewrite, got {out:?}");
    };
    assert_eq!(captured.len(), 1, "recorded before commit");
    let rows_after = edge_rows(&pool, w.edge).await;
    assert_eq!(rows_after.len(), 1);
    assert_eq!(
        rows_after[0].0, rows_before[0].0,
        "rewritten in place (same row id)"
    );
    assert_ne!(
        rows_after[0].1, rows_before[0].1,
        "masses moved with the source"
    );
    assert_eq!(c.row_before.masses, rows_before[0].1);
    assert_eq!(c.row_after.masses, rows_after[0].1);

    // The oracle is the real wire on a twin edge from the same source into a
    // twin target: the rewrite stores exactly that row.
    let twin = fresh_claim(
        &pool,
        &viewer,
        w.author,
        w.frame,
        "twin target",
        TARGET_EVIDENCE,
    )
    .await;
    let twin_edge = wired_edge(&pool, &viewer, w.author, w.source, twin, "supports").await;
    let twin_row = &edge_rows(&pool, twin_edge).await[0];
    let twin_value: serde_json::Value = serde_json::from_str(&twin_row.1).unwrap();
    assert!(same_jsonb(&pool, &twin_value, &rows_after[0].1).await);
    assert_eq!(rows_after[0].2, twin_row.2, "source_strength");
    assert_eq!(c.target_before, cache_before);
    assert_eq!(
        cache(&pool, w.target).await,
        cache(&pool, twin).await,
        "same fold as the twin"
    );
    assert_ne!(
        cache(&pool, w.target).await,
        cache_before,
        "the target moved"
    );
}

/// OD-E1: the source turns vacuous after the edge was selected. The
/// un-targeted phase would delete the row and NULL this edge-only target's
/// cache; the targeted rewire keeps both and counts `held_would_remove`.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_keeps_an_edge_whose_wire_would_remove_it(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "f2", "supports", false).await;
    let edge = the_edge(&pool, &w).await;
    sqlx::query(
        "UPDATE claims SET belief = 0.0, plausibility = 1.0, pignistic_prob = 0.5 WHERE id = $1",
    )
    .bind(w.source)
    .execute(&pool)
    .await
    .expect("source turns vacuous");
    let before = footprint(&pool, &w).await;
    assert!(before.1.belief.is_some(), "fixture: the target has a cache");

    let (out, captured) = rewire(&pool, &viewer, &edge, &w.baseline, false).await;

    assert!(
        cache(&pool, w.target).await.belief.is_some(),
        "the target cache is not NULL"
    );
    assert_eq!(
        footprint(&pool, &w).await,
        before,
        "row and target cache unchanged"
    );
    assert_held(&out, HeldBucket::WouldRemove);
    assert!(captured.is_empty());
}

/// OD-E1 variant: a second live row for the edge appeared after the
/// selection (an off-key duplicate). The un-targeted phase merges it away;
/// the targeted rewire rolls back before any delete, so both rows survive.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_never_merges_away_a_row_that_appeared_after_selection(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "dup", "supports", true).await;
    let edge = the_edge(&pool, &w).await;
    let other_agent = seed_agent(&pool, "dup-wirer").await;
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, masses, \
                                     combination_method, source_strength, evidence_type, locality_tag) \
         VALUES ($1, $2, $3, $4, $5::jsonb, 'edge_factor', 0.8, 'derived_support', 'cross')",
    )
    .bind(w.target)
    .bind(w.frame)
    .bind(other_agent)
    .bind(w.edge)
    .bind(STALE_PRE_401)
    .execute(&pool)
    .await
    .expect("a second live row");
    let before = footprint(&pool, &w).await;
    assert_eq!(before.0.len(), 2);

    let (out, _) = rewire(&pool, &viewer, &edge, &w.baseline, false).await;
    assert_eq!(
        footprint(&pool, &w).await,
        before,
        "both rows survive untouched"
    );
    assert_held(&out, HeldBucket::OffKeyOrDuplicate);
}

/// OD-E2: the target's own row changed after its cache was folded, so its
/// cache is not the fold of its current rows. A rewire would land that
/// unaccepted drift too: held `target_stale`. The un-targeted phase still
/// rewires it (today's behaviour, unchanged).
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_holds_a_stale_target_and_the_untargeted_phase_does_not(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "stale", "supports", true).await;
    let edge = the_edge(&pool, &w).await;
    sqlx::query(
        "UPDATE mass_functions SET masses = $2::jsonb \
          WHERE claim_id = $1 AND perspective_id IS NULL",
    )
    .bind(w.target)
    .bind(EVIDENCE_C)
    .execute(&pool)
    .await
    .expect("the target's own row changes without a refold");
    let before = footprint(&pool, &w).await;

    let (out, _) = rewire(&pool, &viewer, &edge, &w.baseline, false).await;
    assert_eq!(footprint(&pool, &w).await, before);
    assert_held(&out, HeldBucket::TargetStale);

    let summary = run_rewire_phase(&pool, &viewer, &RewireOptions::default())
        .await
        .expect("un-targeted");
    assert!(summary.rewired >= 1, "{summary:?}");
    assert_ne!(
        edge_rows(&pool, w.edge).await[0].1,
        before.0[0].1,
        "the un-targeted phase rewrote it"
    );
}

/// OD-E3: the stored row is not what a wire from the source's pre-move
/// interval writes (it carries the pre-#401 shape), so it is stale for
/// another reason too: held `row_mixed`.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_holds_a_mixed_row(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "mixed", "supports", true).await;
    let edge = the_edge(&pool, &w).await;
    sqlx::query("UPDATE mass_functions SET masses = $2::jsonb WHERE perspective_id = $1")
        .bind(w.edge)
        .bind(STALE_PRE_401)
        .execute(&pool)
        .await
        .expect("an older row shape");
    refold(&pool, &viewer, w.target).await; // the target stays fresh
    let before = footprint(&pool, &w).await;

    let (out, _) = rewire(&pool, &viewer, &edge, &w.baseline, false).await;
    assert_eq!(footprint(&pool, &w).await, before);
    assert_held(&out, HeldBucket::RowMixed);
}

/// The row-class test needs the source's pre-move interval: a source the
/// baseline does not know is not decided `r173` on faith.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_holds_a_row_whose_source_has_no_baseline(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "nobase", "supports", true).await;
    let edge = the_edge(&pool, &w).await;
    let before = footprint(&pool, &w).await;

    let (out, _) = rewire(&pool, &viewer, &edge, &HashMap::new(), false).await;
    assert_eq!(footprint(&pool, &w).await, before);
    assert_held(&out, HeldBucket::RowMixed);
}

/// OD-E5 / E-b: a compound target, and separately a compound source, are
/// held `compound_end`: no row written or deleted, the cache unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_holds_compound_ends(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    for (tag, compound_target) in [("cmp-tgt", true), ("cmp-src", false)] {
        let w = world(&pool, &viewer, tag, "supports", true).await;
        let edge = the_edge(&pool, &w).await;
        make_compound(
            &pool,
            if compound_target { w.target } else { w.source },
            w.author,
        )
        .await;
        let before = footprint(&pool, &w).await;

        let (out, _) = rewire(&pool, &viewer, &edge, &w.baseline, false).await;
        assert_eq!(footprint(&pool, &w).await, before, "{tag}");
        assert_held(&out, HeldBucket::CompoundEnd);
    }
}

/// OD-E5 / K12b: `supersedes` lineage rows are X-3's decision, held.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_holds_supersedes(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "sup", "supersedes", true).await;
    let edge = the_edge(&pool, &w).await;
    let before = footprint(&pool, &w).await;

    let (out, _) = rewire(&pool, &viewer, &edge, &w.baseline, false).await;
    assert_eq!(footprint(&pool, &w).await, before);
    assert_held(&out, HeldBucket::Supersedes);
}

/// OD-E5 / K4a: a retracted row on the edge (off the wire key, so the live
/// row at the key alone would be rewritable). The edge is held
/// `retracted_on_edge`; the retracted row keeps its masses, `created_at` and
/// retraction; nothing is deleted, so migration 194's guard (applied here)
/// never fires.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_holds_an_edge_with_a_retracted_row_and_never_touches_it(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "retr", "supports", true).await;
    let edge = the_edge(&pool, &w).await;
    let other_frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("cal4-retracted-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("second frame");
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, masses, \
                                     combination_method, source_strength, evidence_type, locality_tag, \
                                     retracted_at, retracted_by, retract_reason) \
         VALUES ($1, $2, $3, $4, $5::jsonb, 'edge_factor', 0.8, 'derived_support', 'cross', \
                 now(), $3, 'cal4 fixture')",
    )
    .bind(w.target)
    .bind(other_frame)
    .bind(w.author)
    .bind(w.edge)
    .bind(STALE_PRE_401)
    .execute(&pool)
    .await
    .expect("a retracted off-key row");
    let applied_194: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 194 AND success)",
    )
    .fetch_one(&pool)
    .await
    .expect("migration ledger");
    assert!(
        applied_194,
        "the H10 guard (194) is applied on this database"
    );
    let before = footprint(&pool, &w).await;
    assert_eq!(before.0.iter().filter(|r| r.6).count(), 1);

    let (out, _) = rewire(&pool, &viewer, &edge, &w.baseline, false).await;
    assert_eq!(
        footprint(&pool, &w).await,
        before,
        "every row, the retracted one included"
    );
    assert_held(&out, HeldBucket::RetractedOnEdge);
}

/// `only_changed`: a row a fresh wire would write identically (the source
/// has not moved since the wire) is left alone: no `created_at` bump, no
/// target refold (its `updated_at` is unchanged).
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_only_changed_leaves_an_unchanged_row_alone(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let author = seed_agent(&pool, "unchanged").await;
    let frame = binary_frame(&pool, &viewer).await;
    let source = fresh_claim(
        &pool,
        &viewer,
        author,
        frame,
        "unchanged source",
        EVIDENCE_A,
    )
    .await;
    let target = fresh_claim(
        &pool,
        &viewer,
        author,
        frame,
        "unchanged target",
        TARGET_EVIDENCE,
    )
    .await;
    let edge_id = wired_edge(&pool, &viewer, author, source, target, "supports").await;
    let c = cache(&pool, source).await;
    let mut baseline = HashMap::new();
    baseline.insert(source, (c.belief.unwrap(), c.plausibility.unwrap()));
    let edge = selected(&pool, &[source]).await.remove(0);
    assert_eq!(edge.edge_id, edge_id);
    let rows = edge_rows(&pool, edge_id).await;
    let target_at = updated_at(&pool, target).await;

    let (out, captured) = rewire(&pool, &viewer, &edge, &baseline, true).await;

    assert_eq!(
        edge_rows(&pool, edge_id).await,
        rows,
        "created_at not bumped"
    );
    assert_eq!(
        updated_at(&pool, target).await,
        target_at,
        "the target was not refolded"
    );
    assert_eq!(out, TargetedOutcome::Unchanged);
    assert!(captured.is_empty());
}

/// The targeted selection takes only edges sourced at the listed claims
/// (and, with an accepted list, only the listed edges).
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_selection_is_restricted_to_the_listed_sources_and_edges(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "sel-a", "supports", true).await;
    let v = world(&pool, &viewer, "sel-b", "supports", true).await;
    let only_w: Vec<Uuid> = selected(&pool, &[w.source])
        .await
        .iter()
        .map(|e| e.edge_id)
        .collect();
    assert_eq!(only_w, vec![w.edge]);
    let mut conn = pool.acquire().await.unwrap();
    let listed = select_targeted_edges(&mut conn, &[w.source, v.source], Some(&[v.edge]))
        .await
        .unwrap();
    assert_eq!(
        listed.iter().map(|e| e.edge_id).collect::<Vec<_>>(),
        vec![v.edge]
    );
}

/// Narrow `edge` to `group` (both endpoints stay public), as
/// `epigraph-engine/tests/derivation_scope_admissibility.rs` does: its
/// edge-factor row may no longer enter the public target's cache.
async fn narrow_edge_to_group(pool: &PgPool, edge: Uuid, group: Uuid) {
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(edge)
    .bind(group)
    .execute(pool)
    .await
    .expect("narrow the edge to a group");
}

/// Design E-d / ruling R-80: the edge's row is the edge-only target's only
/// binary input, and it is no longer admissible for the target's cache (the
/// edge was narrowed to a group), so any refold of the target VACATES its
/// cache. The targeted rewire holds the edge as `would_vacate` (not as an
/// ordinary stale target), leaves the row, the cache and `updated_at` exactly
/// as they were, and the predict counts it (`totals.would_vacate`), so the
/// gate the design asks for is measured rather than assumed.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_holds_a_target_that_would_vacate(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "vacate", "supports", false).await;
    let edge = the_edge(&pool, &w).await;
    let (_member, group) = viewer_fixture::seed_agent_with_group(&pool, "cal4-vacate").await;
    narrow_edge_to_group(&pool, w.edge, group).await;
    let must_vacate = {
        let mut conn = pool.acquire().await.expect("conn");
        epigraph_engine::derivation_scope::must_vacate_cache(&mut conn, &viewer, w.target)
            .await
            .expect("derivation scope read")
    };
    assert!(
        must_vacate,
        "PREMISE: a refold of the target vacates its cache"
    );
    let before = footprint(&pool, &w).await;
    assert!(before.1.belief.is_some(), "fixture: the target has a cache");

    let o = TargetedRunOptions::default();
    let predicted =
        predict_targeted_rewire(&pool, &viewer, &seed_from_waves(&w.wave, o.epsilon), &o)
            .await
            .expect("predict");
    let (out, captured) = rewire(&pool, &viewer, &edge, &w.baseline, false).await;

    assert_eq!(
        footprint(&pool, &w).await,
        before,
        "row, target cache and updated_at unchanged"
    );
    assert!(captured.is_empty());
    assert_held(&out, HeldBucket::WouldVacate);
    let predicted_edge = predicted
        .edges
        .iter()
        .find(|e| e.edge_id == w.edge)
        .expect("the predict reached the edge");
    assert_eq!(predicted_edge.outcome, "would_vacate", "{predicted:?}");
    assert_eq!(predicted.totals.would_vacate, 1, "{:?}", predicted.totals);
    assert!(
        !predicted.targets[&w.target].fresh,
        "a target with no admissible fold is not reported fresh: {:?}",
        predicted.targets[&w.target]
    );
}

/// OD-E1, the factorless arm: the source lost its cache after the edge was
/// selected (NULL belief, plausibility and BetP). A fresh wire would store
/// nothing; the targeted rewire keeps the row and the edge-only target's
/// cache and counts `held_would_remove`. The control is the un-targeted
/// phase on the same edge: it DELETES the row and NULLs the cache, so the
/// "kept" assertions above are measured against the destructive behaviour.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_keeps_an_edge_whose_source_turned_factorless(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "factorless", "supports", false).await;
    let edge = the_edge(&pool, &w).await;
    sqlx::query(
        "UPDATE claims SET belief = NULL, plausibility = NULL, pignistic_prob = NULL \
          WHERE id = $1",
    )
    .bind(w.source)
    .execute(&pool)
    .await
    .expect("the source turns factorless");
    let before = footprint(&pool, &w).await;
    assert!(before.1.belief.is_some(), "fixture: the target has a cache");
    assert_eq!(before.0.len(), 1, "fixture: one live row");

    let (out, captured) = rewire(&pool, &viewer, &edge, &w.baseline, false).await;

    assert_eq!(
        footprint(&pool, &w).await,
        before,
        "row and target cache unchanged"
    );
    assert!(
        cache(&pool, w.target).await.belief.is_some(),
        "the target cache is not NULL"
    );
    assert!(captured.is_empty());
    assert_held(&out, HeldBucket::WouldRemove);

    // Control: the un-targeted phase removes the same row and NULLs the cache.
    let summary = run_rewire_phase(&pool, &viewer, &RewireOptions::default())
        .await
        .expect("un-targeted");
    assert!(summary.removed_source_factorless >= 1, "{summary:?}");
    assert!(
        edge_rows(&pool, w.edge).await.is_empty(),
        "the un-targeted phase deleted the row"
    );
    assert!(
        cache(&pool, w.target).await.belief.is_none(),
        "the un-targeted phase NULLed the target cache"
    );
}

/// A rewrite is recorded BEFORE it commits: when the snapshot record cannot
/// be written (here the capture callback fails as a full disk would), the
/// edge's transaction rolls back, so no committed rewrite lacks its restore
/// record. The row (masses, `created_at`), the target cache and its
/// `updated_at` are exactly as before.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_rolls_back_when_its_snapshot_record_cannot_be_written(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let w = world(&pool, &viewer, "disk-full", "supports", true).await;
    let edge = the_edge(&pool, &w).await;
    let before = footprint(&pool, &w).await;
    let own: HashMap<Uuid, StoredEdgeRow> = HashMap::new();
    let guards = TargetedGuards {
        baseline: &w.baseline,
        own_rows: &own,
        only_changed: false,
    };
    let mut calls = 0usize;
    let mut on_capture = |_: &RewireCapture| -> Result<(), String> {
        calls += 1;
        Err("disk full".to_string())
    };

    let out = rewire_edge_targeted(&pool, &viewer, &edge, &guards, &mut on_capture).await;

    assert_eq!(calls, 1, "the rewrite reached its capture: {out:?}");
    let err = out.expect_err("a failed snapshot record fails the edge");
    assert!(err.contains("disk full"), "{err}");
    assert_eq!(
        footprint(&pool, &w).await,
        before,
        "rolled back: row, created_at, target cache and updated_at unchanged"
    );
}
