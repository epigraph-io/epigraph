//! The single atom-cache writer folds under the same two rules as the claim
//! cache (backlog c2ef65a0): the derivation-scope rule (a BBA derived from a
//! source narrower than the atom never enters its cache) and the same-human
//! rule (sibling agents of one human never aggregate).
//!
//! # What was wrong, measured at origin/main before this file
//!
//! `recompute_atom_cache_with` folded the viewer's AEF rows straight through
//! `atom_items::atom_fold_under`. The claim-cache path filters its rows with
//! `derivation_scope::retain_for_cache` and folds them with
//! `source_dependence::combine_with_owner_dependence`; the atom path called
//! neither. So a group member's AEF write put its group's private edge factor
//! into a public atom's cache, and two agents of one human counted twice.
//!
//! # The oracles
//!
//! * scope: the atom's AEF fold from its public row alone, captured before the
//!   private-derived row exists; and, when no row is admissible, the explicit
//!   vacuous cache (or no cache at all for an atom that had none);
//! * same-human: absolute values. Two reliability-1 simple supports of .6 and
//!   .7 on TRUE give BetP .85 under the cautious rule (the stronger alone) and
//!   .94 under Dempster's product; agents of two different humans must still
//!   give .94.
//!
//! Every write runs the AEF arm (`AefStandalone` on a standalone claim): the
//! legacy arm delegates to the claim path, which already applies both rules.
//! On the `#[sqlx::test]` superuser pool the viewer predicates decide (row
//! security is bypassed), which is what pins the rules themselves.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::Viewer;
use epigraph_engine::atom_items::{
    atom_axiom_rows_under, atom_fold, AtomFoldMode, AxiomMode, AxiomRow, CompoundSourceEdges,
};
use epigraph_engine::belief_query::FramedBeliefContext;
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::edge_factor::{
    auto_wire_ds_for_edge, ensure_binary_frame, recompute_atom_cache_with, AtomCacheOutcome,
    AtomCacheSettings, CacheWriteCause, EdgeFactorOutcome, LegacyFold,
};
use sqlx::PgPool;
use uuid::Uuid;

const TOL: f64 = 1e-9;

fn settings() -> AtomCacheSettings {
    AtomCacheSettings {
        fold: AtomFoldMode::AefStandalone,
        compound_source_edges: CompoundSourceEdges::Frozen,
        vacate_on_evidence_removal: true,
    }
}

fn ctx() -> FramedBeliefContext {
    FramedBeliefContext::new(CalibrationConfig::default_for_phase2_fallback(), None)
}

/// The claim's cached (BetP, Bel, Pl), `None` per column when unset.
async fn cache(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>, Option<f64>) {
    sqlx::query_as("SELECT pignistic_prob, belief, plausibility FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the cache")
}

/// A cache value no fold of the fixture rows produces.
async fn set_sentinel(pool: &PgPool, claim: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = 0.123, plausibility = 0.877, pignistic_prob = 0.5, \
         mass_on_empty = 0, mass_on_missing = 0, belief_frame_id = NULL WHERE id = $1",
    )
    .bind(claim)
    .execute(pool)
    .await
    .expect("sentinel");
}

async fn clear_cache(pool: &PgPool, claim: Uuid) {
    sqlx::query(
        "UPDATE claims SET belief = NULL, plausibility = NULL, pignistic_prob = NULL, \
         belief_frame_id = NULL WHERE id = $1",
    )
    .bind(claim)
    .execute(pool)
    .await
    .expect("clear the cache");
}

/// A claim whose stored interval is (bel, pl), so an edge from it wires a BBA.
async fn with_interval(pool: &PgPool, claim: Uuid, bel: f64, pl: f64) {
    sqlx::query("UPDATE claims SET belief = $2, plausibility = $3 WHERE id = $1")
        .bind(claim)
        .bind(bel)
        .bind(pl)
        .execute(pool)
        .await
        .expect("set the source interval");
}

async fn wire(pool: &PgPool, viewer: &Viewer, signer: Uuid, edge: Uuid, from: Uuid, to: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = auto_wire_ds_for_edge(&mut conn, viewer, edge, signer, from, to, "supports")
        .await
        .expect("wire the edge factor");
    assert_eq!(
        out,
        EdgeFactorOutcome::Wired,
        "PREMISE: the edge wires a BBA"
    );
}

async fn write_as(pool: &PgPool, viewer: &Viewer, claim: Uuid) -> AtomCacheOutcome {
    let mut conn = pool.acquire().await.expect("acquire");
    let binary = ensure_binary_frame(&mut conn, viewer)
        .await
        .expect("binary_truth");
    recompute_atom_cache_with(
        &mut conn,
        viewer,
        claim,
        CacheWriteCause::Organic,
        LegacyFold::Frame(binary),
        settings(),
    )
    .await
    .expect("recompute_atom_cache")
}

async fn aef_rows(pool: &PgPool, viewer: &Viewer, claim: Uuid) -> Vec<AxiomRow> {
    let mut conn = pool.acquire().await.expect("acquire");
    atom_axiom_rows_under(
        &mut conn,
        viewer,
        &[claim],
        AxiomMode::Display,
        &ctx(),
        CompoundSourceEdges::Frozen,
    )
    .await
    .expect("atom_axiom_rows")
    .remove(&claim)
    .unwrap_or_default()
}

/// The `edge_factor` row edge `edge` wired on `target`.
async fn edge_row(pool: &PgPool, edge: Uuid, target: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM mass_functions WHERE perspective_id = $1 AND claim_id = $2 \
           AND combination_method = 'edge_factor'",
    )
    .bind(edge)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("the edge factor row")
}

struct Seeded {
    public: Viewer,
    member: Uuid,
    member_viewer: Viewer,
    author: Uuid,
    group: Uuid,
}

async fn seed(pool: &PgPool, label: &str) -> Seeded {
    let public = fixture::public_viewer(pool).await;
    let (member, group) = fixture::seed_agent_with_group(pool, &format!("{label}-member")).await;
    let (author, _) = fixture::seed_agent_with_group(pool, &format!("{label}-author")).await;
    let member_viewer = Viewer::resolve(pool, member).await.expect("member viewer");
    Seeded {
        public,
        member,
        member_viewer,
        author,
        group,
    }
}

/// A group-private edge factor (an edge from the member's group-private claim)
/// on public `target`, wired as the member; returns its row id.
async fn private_edge_factor(pool: &PgPool, s: &Seeded, target: Uuid) -> Uuid {
    let private_source =
        fixture::seed_group_claim(pool, s.member, s.group, "atom scope private source").await;
    with_interval(pool, private_source, 0.9, 0.95).await;
    let private_edge = fixture::seed_edge(pool, private_source, target).await;
    let edge_visibility: String =
        sqlx::query_scalar("SELECT visibility::text FROM edges WHERE id = $1")
            .bind(private_edge)
            .fetch_one(pool)
            .await
            .expect("edge");
    assert_ne!(
        edge_visibility, "public",
        "PREMISE: an edge from a group-private claim is not public"
    );
    wire(
        pool,
        &s.member_viewer,
        s.member,
        private_edge,
        private_source,
        target,
    )
    .await;
    edge_row(pool, private_edge, target).await
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_edge_factor_never_enters_a_public_atoms_cache(pool: PgPool) {
    let s = seed(&pool, "atom-scope").await;
    let target = fixture::seed_public_claim(&pool, s.author, "atom scope public target").await;
    let public_source =
        fixture::seed_public_claim(&pool, s.author, "atom scope public source").await;
    with_interval(&pool, public_source, 0.6, 0.8).await;
    let public_edge = fixture::seed_edge(&pool, public_source, target).await;
    wire(
        &pool,
        &s.public,
        s.author,
        public_edge,
        public_source,
        target,
    )
    .await;

    // The oracle: the AEF fold of the public row alone.
    let AtomCacheOutcome::Folded {
        interval: public_only,
        written: true,
    } = write_as(&pool, &s.public, target).await
    else {
        panic!("PREMISE: the public row folds and is written");
    };

    let private_row = private_edge_factor(&pool, &s, target).await;
    let member_rows = aef_rows(&pool, &s.member_viewer, target).await;
    assert!(
        member_rows.iter().any(|r| r.row_id() == private_row),
        "PREMISE: the member's AEF input carries the private-derived row"
    );
    let member_unscoped = atom_fold(&member_rows).expect("fold");
    assert!(
        member_unscoped.pignistic_prob() > public_only.pignistic_prob() + 1e-3,
        "PREMISE: folding the private row would move the value ({} vs {})",
        member_unscoped.pignistic_prob(),
        public_only.pignistic_prob()
    );

    set_sentinel(&pool, target).await;
    let out = write_as(&pool, &s.member_viewer, target).await;
    let AtomCacheOutcome::Folded {
        interval,
        written: true,
    } = out
    else {
        panic!("the member's AEF write folds and is written: {out:?}");
    };
    assert!(
        (interval.pignistic_prob() - public_only.pignistic_prob()).abs() < TOL
            && (interval.belief() - public_only.belief()).abs() < TOL
            && (interval.plausibility() - public_only.plausibility()).abs() < TOL,
        "the member's AEF write folded a group-private edge factor into a public atom's \
         cache: {public_only:?} -> {interval:?}"
    );
    let (betp, bel, pl) = cache(&pool, target).await;
    assert!(
        (betp.expect("betp") - public_only.pignistic_prob()).abs() < TOL
            && (bel.expect("bel") - public_only.belief()).abs() < TOL
            && (pl.expect("pl") - public_only.plausibility()).abs() < TOL,
        "the stored cache is the public-only fold"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_atom_whose_only_input_is_private_derived_is_vacated_or_left_without_a_cache(
    pool: PgPool,
) {
    let s = seed(&pool, "atom-scope-vacate").await;

    // With a cache: the explicit vacuous value replaces it.
    let cached = fixture::seed_public_claim(&pool, s.author, "atom scope vacate cached").await;
    private_edge_factor(&pool, &s, cached).await;
    assert!(
        !aef_rows(&pool, &s.member_viewer, cached).await.is_empty(),
        "PREMISE: the member sees the atom's AEF input"
    );
    set_sentinel(&pool, cached).await;
    let out = write_as(&pool, &s.member_viewer, cached).await;
    assert_eq!(
        out,
        AtomCacheOutcome::Vacated { written: true },
        "no admissible row: the cache folded from private sources is vacated"
    );
    let (betp, bel, pl) = cache(&pool, cached).await;
    assert_eq!(
        (betp, bel, pl),
        (Some(0.5), Some(0.0), Some(1.0)),
        "the explicit vacuous cache, never NULL and never the private fold"
    );

    // Without a cache: none is written.
    let bare = fixture::seed_public_claim(&pool, s.author, "atom scope vacate bare").await;
    private_edge_factor(&pool, &s, bare).await;
    clear_cache(&pool, bare).await;
    let out = write_as(&pool, &s.member_viewer, bare).await;
    assert_eq!(out, AtomCacheOutcome::KeptEmpty);
    assert_eq!(
        cache(&pool, bare).await,
        (None, None, None),
        "an atom with no cache gets none from rows its readers cannot see"
    );
}
