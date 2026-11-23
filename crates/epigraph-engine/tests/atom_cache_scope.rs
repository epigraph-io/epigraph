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

use epigraph_db::{MassFunctionRepository, Viewer};
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

/// The scope rule runs BEFORE the seed rule. A public atom whose only public
/// input is its reliability-1 `truth_value_seed` of .7 folds to BetP .85; a
/// group-private edge factor beside it is no input to the cache, so it must
/// not count against the seed either. Before the fix the read dropped the
/// seed (other input existed), the scope filter then dropped the private
/// row, and the writer vacated the atom to .5.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_seed_still_folds_beside_a_private_edge_factor(pool: PgPool) {
    let s = seed(&pool, "atom-scope-seed").await;
    let target = fixture::seed_public_claim(&pool, s.author, "atom scope seeded target").await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &s.public)
        .await
        .expect("binary_truth");
    let seed_row = MassFunctionRepository::store_with_perspective(
        &pool,
        target,
        frame,
        Some(s.author),
        None,
        &serde_json::json!({"0": 0.7, "0,1": 0.3}),
        None,
        Some("truth_value_seed"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store the seed");

    // The oracle: the seed alone.
    let AtomCacheOutcome::Folded {
        interval: seed_only,
        written: true,
    } = write_as(&pool, &s.public, target).await
    else {
        panic!("PREMISE: the seed folds and is written");
    };
    assert!(
        (seed_only.pignistic_prob() - 0.85).abs() < TOL,
        "PREMISE: a reliability-1 seed of .7 is BetP .85, got {}",
        seed_only.pignistic_prob()
    );

    let private_row = private_edge_factor(&pool, &s, target).await;
    let member_rows = aef_rows(&pool, &s.member_viewer, target).await;
    assert!(
        member_rows.iter().any(|r| r.row_id() == private_row)
            && member_rows.iter().all(|r| r.row_id() != seed_row),
        "PREMISE: the member's AEF input is the private row, which displaces the seed"
    );

    set_sentinel(&pool, target).await;
    let out = write_as(&pool, &s.member_viewer, target).await;
    let AtomCacheOutcome::Folded {
        interval,
        written: true,
    } = out
    else {
        panic!(
            "the seed is the atom's sole admissible input, so the write folds it; a private \
             row the cache never folds must not vacate it: {out:?}"
        );
    };
    assert!(
        (interval.pignistic_prob() - seed_only.pignistic_prob()).abs() < TOL
            && (interval.belief() - seed_only.belief()).abs() < TOL
            && (interval.plausibility() - seed_only.plausibility()).abs() < TOL,
        "the cache is the seed's fold: {seed_only:?} -> {interval:?}"
    );
    let (betp, bel, pl) = cache(&pool, target).await;
    assert!(
        (betp.expect("betp") - seed_only.pignistic_prob()).abs() < TOL
            && (bel.expect("bel") - seed_only.belief()).abs() < TOL
            && (pl.expect("pl") - seed_only.plausibility()).abs() < TOL,
        "the stored cache is the seed's fold"
    );
}

// ── the same-human rule ─────────────────────────────────────────────────────

async fn bare_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("agent")
}

/// Link `agent` to human operator `human` (migration 107's live link).
async fn link(pool: &PgPool, agent: Uuid, human: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("link the agent to its human");
    assert!(out.link_live, "{out:?}");
}

/// A reliability-1 simple support of `t` on TRUE by `agent`: no evidence and
/// no perspective, so each row is its own item (`row:` key).
async fn support(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, t: f64) {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &serde_json::json!({"0": t, "0,1": 1.0 - t}),
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store BBA");
}

/// The cached BetP after an AEF write of two supports (.6 by `a`, .7 by `b`)
/// on a fresh public standalone claim.
async fn two_support_betp(pool: &PgPool, author: Uuid, a: Uuid, b: Uuid) -> f64 {
    let public = fixture::public_viewer(pool).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary_truth");
    let claim =
        fixture::seed_public_claim(pool, author, &format!("atom same-human {}", Uuid::new_v4()))
            .await;
    support(pool, claim, frame, a, 0.6).await;
    support(pool, claim, frame, b, 0.7).await;
    let rows = aef_rows(pool, &public, claim).await;
    assert_eq!(rows.len(), 2, "PREMISE: both supports are AEF input");
    let out = write_as(pool, &public, claim).await;
    let AtomCacheOutcome::Folded {
        interval,
        written: true,
    } = out
    else {
        panic!("the AEF write folds and is written: {out:?}");
    };
    let cached = cache(pool, claim).await.0.expect("betp");
    assert!(
        (cached - interval.pignistic_prob()).abs() < TOL,
        "the cache stores the fold"
    );
    // The same value the pure fold of the rows gives: compound derivations
    // fold leaves through it, so they must agree with the cache.
    assert!(
        (atom_fold(&rows).expect("fold").pignistic_prob() - cached).abs() < TOL,
        "atom_fold agrees with the atom cache"
    );
    cached
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_agents_of_one_human_do_not_aggregate_in_the_atom_cache(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "atom-same-human-author").await;
    let (human, _) = fixture::seed_human_operator(&pool, "atom-same-human").await;
    let (a1, a2) = (bare_agent(&pool).await, bare_agent(&pool).await);
    link(&pool, a1, human).await;
    link(&pool, a2, human).await;

    let siblings = two_support_betp(&pool, author, a1, a2).await;
    assert!(
        (siblings - 0.85).abs() < TOL,
        "two agents of one human keep the stronger support (BetP .85), not Dempster's \
         product (.94): got {siblings}"
    );

    // Control: agents of no human are their own owners, so they reinforce.
    let (b1, b2) = (bare_agent(&pool).await, bare_agent(&pool).await);
    let independent = two_support_betp(&pool, author, b1, b2).await;
    assert!(
        (independent - 0.94).abs() < TOL,
        "agents of different owners reinforce by Dempster (BetP .94): got {independent}"
    );
}
