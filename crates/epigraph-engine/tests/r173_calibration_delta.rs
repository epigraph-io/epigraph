//! The `r173` item of the read-only dry-run delta (ruling R-173, Tier B):
//! what re-folding each claim's owner frame under the shipped calibration
//! changes on caches written under the empty calibration vocabulary.
//!
//! * The values E (empty vocabulary) and F (shipped calibration) are checked
//!   against HAND ARITHMETIC, never a second engine call. One discounted BBA
//!   `{h: m_h, Θ: m_t}` on a binary frame has `BetP = r·m_h + (r·m_t + 1 − r)/2`;
//!   two independent ones are folded here by Dempster's rule by hand.
//! * The value A (what a recompute writes) is checked against the REAL write:
//!   after the dry run, `recompute_claim_cached_belief` runs on every claim,
//!   and the cache it writes must be A.
//! * The fixture covers each way a row's weight differs between the regimes
//!   (no stored strength, an alias spelling, a stored strength under a typed
//!   row), a frame whose `belief_profile` patch changes the empty regime's
//!   fallback weight (only a fold of the empty BASE with the frame tier over
//!   it gets that right), a strict-key frame override (no change: check C7),
//!   a compound and a template-only claim (skipped), and an untyped-only
//!   claim (not a candidate). Each planted cache lands its claim in one
//!   regime and one apply list.
//! * The run writes nothing, a chunked run measures what one transaction
//!   measures, and two runs on one database are byte-identical once the
//!   per-transaction snapshots are set aside (check C4).
//! * A second, separate fixture ([`edges`]) reaches the branches the first
//!   one does not, one test each: a VACATE (every owner row cites a
//!   group-private evidence row, cache planted) and its no-cache twin
//!   (`scope_kept`), a superseded clean-calibration claim (listed apart from
//!   L1), a MULTI-input clean-calibration claim (in L1, not in the
//!   single-input share R-176(1) accepted), and two claims that are no
//!   candidate (their only typed row retracted, or a cached combination).
//! * `--only` restricts the population, and a run on the
//!   `epigraph_maintenance` login the binary connects as measures exactly
//!   what the superuser measures, a GROUP-private candidate included.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::derivation_scope::DerivationScopeRepository;
use epigraph_db::repos::mass_function::COMBINATION_METHOD_LABELS;
use epigraph_db::visibility::{SystemReason, Viewer};
use epigraph_db::{MassFunctionRepository, PgPool};
use epigraph_engine::belief_profile::BeliefProfile;
use epigraph_engine::edge_factor::{ensure_binary_frame, recompute_claim_cached_belief};
use epigraph_engine::supersede_delta::r173::{
    empty_vocabulary_profile, ApplyList, R173Claim, R173Options, R173Outcome, R173Report, Regime,
};
use epigraph_engine::supersede_delta::{run_read_only, DeltaItems, DeltaOptions};
use uuid::Uuid;

const THRESHOLDS: [f64; 3] = [0.3, 0.5, 0.75];
/// The patched frame's unknown-type weight (the empty regime's fallback).
const PATCHED_UNKNOWN_WEIGHT: f64 = 0.4;
/// The override frame's strict-key weight for `empirical`.
const OVERRIDE_EMPIRICAL: f64 = 0.9;

/// `BetP(TRUE)` of one discounted BBA `{0: m_h, Θ: m_t}` on a binary frame.
fn one(r: f64, m_h: f64, m_t: f64) -> f64 {
    r * m_h + (r * m_t + 1.0 - r) / 2.0
}

/// `BetP(TRUE)` of the l2 claim's two rows, by Dempster's rule by hand:
/// `{0: 0.6, Θ: 0.4}` at reliability `r` and `{1: 0.3, Θ: 0.7}` at 0.8.
fn l2_betp(r: f64) -> f64 {
    let a0 = 0.6 * r;
    let at = 1.0 - a0;
    let b1 = 0.3 * 0.8;
    let bt = 1.0 - b1;
    let k = a0 * b1;
    let m0 = a0 * bt / (1.0 - k);
    let mt = at * bt / (1.0 - k);
    m0 + mt / 2.0
}

struct World {
    _scoped: epigraph_db::ScopedPool,
    viewer: Viewer,
    /// S = E: written under the empty vocabulary. L1.
    l1: Uuid,
    /// S = F: already fresh. L3.
    l3: Uuid,
    /// Two inputs, S neither. L2.
    l2: Uuid,
    /// On a `belief_profile`-patched frame, S = E. L1.
    patched: Uuid,
    /// Its only row is keyed by the frame's strict-key override: unchanged.
    overridden: Uuid,
    compound: Uuid,
    template: Uuid,
    /// Only an untyped row: not a candidate.
    untyped: Uuid,
}

impl World {
    fn all(&self) -> Vec<Uuid> {
        vec![
            self.l1,
            self.l3,
            self.l2,
            self.patched,
            self.overridden,
            self.compound,
            self.template,
            self.untyped,
        ]
    }
}

async fn frame_with(pool: &PgPool, name: &str, hyps: &[&str], props: serde_json::Value) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, properties) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(name)
    .bind(hyps.iter().map(|h| (*h).to_string()).collect::<Vec<_>>())
    .bind(props)
    .fetch_one(pool)
    .await
    .expect("insert frame")
}

async fn research_validity(pool: &PgPool) -> Uuid {
    let found: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM frames WHERE name = 'research_validity'")
            .fetch_optional(pool)
            .await
            .expect("frame lookup");
    match found {
        Some(id) => id,
        None => {
            frame_with(
                pool,
                "research_validity",
                &["valid", "invalid"],
                serde_json::json!({}),
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    masses: serde_json::Value,
    method: Option<&str>,
    ss: Option<f64>,
    et: Option<&str>,
) {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &masses,
        None,
        method,
        ss,
        et,
        "cross",
        None,
    )
    .await
    .expect("store the BBA");
}

/// Plant a cache as a process of either regime would have written it.
async fn plant(pool: &PgPool, claim: Uuid, bel: f64, pl: f64, betp: f64) {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4 WHERE id = $1",
    )
    .bind(claim)
    .bind(bel)
    .bind(pl)
    .bind(betp)
    .execute(pool)
    .await
    .expect("plant a cache");
}

async fn world(pool: &PgPool) -> World {
    let (scoped, viewer) = fixture::bypass(pool).await;
    let public = fixture::public_viewer(pool).await;
    let (agent, _) = fixture::seed_agent_with_group(pool, "r173-a").await;
    let (agent2, _) = fixture::seed_agent_with_group(pool, "r173-b").await;
    let binary = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary frame");
    let patched_frame = frame_with(
        pool,
        "r173 patched",
        &["TRUE", "FALSE"],
        serde_json::json!({"belief_profile": {"reliability": {
            "unknown_evidence_type_weight": PATCHED_UNKNOWN_WEIGHT}}}),
    )
    .await;
    let override_frame = frame_with(
        pool,
        "r173 override",
        &["TRUE", "FALSE"],
        serde_json::json!({"evidence_type_weights": {"empirical": OVERRIDE_EMPIRICAL}}),
    )
    .await;
    let research = research_validity(pool).await;
    let lean = || serde_json::json!({"0": 0.6, "0,1": 0.4});

    // `empirical`, no stored strength: empty 0.5 (unknown type), full 1.0.
    let l1 = fixture::seed_public_claim(pool, agent, "r173 l1").await;
    bba(
        pool,
        l1,
        binary,
        agent,
        lean(),
        Some("auto_wire"),
        None,
        Some("empirical"),
    )
    .await;
    plant(pool, l1, 0.5 * 0.6, 1.0, one(0.5, 0.6, 0.4)).await;

    // The alias `observation`: empty resolves nothing (0.5), full -> empirical.
    let l3 = fixture::seed_public_claim(pool, agent, "r173 l3").await;
    let half = serde_json::json!({"0": 0.5, "0,1": 0.5});
    bba(
        pool,
        l3,
        binary,
        agent,
        half,
        None,
        None,
        Some("observation"),
    )
    .await;
    plant(pool, l3, 0.5, 1.0, one(1.0, 0.5, 0.5)).await;

    // `testimonial` with a stored 0.7 (empty: the stored strength; full: 0.6),
    // beside an untyped opposing row at 0.8 that does not move.
    let l2 = fixture::seed_public_claim(pool, agent, "r173 l2").await;
    bba(
        pool,
        l2,
        binary,
        agent,
        lean(),
        Some("auto_wire"),
        Some(0.7),
        Some("testimonial"),
    )
    .await;
    let against = serde_json::json!({"1": 0.3, "0,1": 0.7});
    bba(pool, l2, binary, agent2, against, None, Some(0.8), None).await;
    plant(pool, l2, 0.2, 0.9, 0.42).await;

    // The patched frame: empty falls to the PATCHED unknown weight 0.4.
    let patched = fixture::seed_public_claim(pool, agent, "r173 patched").await;
    bba(
        pool,
        patched,
        patched_frame,
        agent,
        lean(),
        None,
        None,
        Some("empirical"),
    )
    .await;
    plant(
        pool,
        patched,
        PATCHED_UNKNOWN_WEIGHT * 0.6,
        1.0,
        one(PATCHED_UNKNOWN_WEIGHT, 0.6, 0.4),
    )
    .await;

    // The strict-key override weighs `empirical` the same in both regimes.
    let overridden = fixture::seed_public_claim(pool, agent, "r173 overridden").await;
    bba(
        pool,
        overridden,
        override_frame,
        agent,
        lean(),
        None,
        None,
        Some("empirical"),
    )
    .await;

    // A compound: a typed row, and an in-force decomposition to a current claim.
    let compound = fixture::seed_public_claim(pool, agent, "r173 compound").await;
    bba(
        pool,
        compound,
        binary,
        agent,
        lean(),
        None,
        None,
        Some("empirical"),
    )
    .await;
    let child = fixture::seed_public_claim(pool, agent, "r173 child").await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(compound)
    .bind(child)
    .execute(pool)
    .await
    .expect("decomposition edge");
    plant(pool, compound, 0.1, 0.9, 0.5).await;

    // Template-only: the ingest placeholder, typed.
    let template = fixture::seed_public_claim(pool, agent, "r173 template").await;
    let placeholder = serde_json::json!({"0": 0.1, "0,1": 0.9});
    bba(
        pool,
        template,
        research,
        agent,
        placeholder,
        None,
        Some(0.3),
        Some("empirical"),
    )
    .await;

    let untyped = fixture::seed_public_claim(pool, agent, "r173 untyped").await;
    bba(pool, untyped, binary, agent, lean(), None, Some(0.8), None).await;

    World {
        _scoped: scoped,
        viewer,
        l1,
        l3,
        l2,
        patched,
        overridden,
        compound,
        template,
        untyped,
    }
}

fn opts(only: Option<Vec<Uuid>>, chunk: Option<usize>, canary: Option<Uuid>) -> DeltaOptions {
    DeltaOptions {
        items: DeltaItems {
            r173: true,
            ..DeltaItems::default()
        },
        top: 50,
        statement_timeout_ms: Some(60_000),
        r173: R173Options {
            thresholds: THRESHOLDS.to_vec(),
            chunk,
            canary,
            only,
        },
    }
}

async fn r173(pool: &PgPool, viewer: &Viewer, o: &DeltaOptions) -> R173Report {
    let mut conn = pool.acquire().await.expect("acquire");
    run_read_only(&mut conn, viewer, o)
        .await
        .expect("the r173 run")
        .r173
        .expect("the r173 block")
}

fn find(r: &R173Report, id: Uuid) -> &R173Claim {
    r.claims
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} is reported: {:?}", r.claims))
}

fn near(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

type Cache = (Option<f64>, Option<f64>, Option<f64>);

async fn caches(pool: &PgPool, ids: &[Uuid]) -> Vec<Cache> {
    let mut out = Vec::new();
    for id in ids {
        out.push(
            sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .expect("read a cache"),
        );
    }
    out
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_r173_delta_measures_each_regime_and_predicts_the_recompute(pool: PgPool) {
    // PREMISE: the served calibration is the shipped one.
    let served = BeliefProfile::served();
    assert_eq!(served.evidence_type_weight("empirical"), 1.0, "PREMISE");
    assert_eq!(served.evidence_type_weight("testimonial"), 0.6, "PREMISE");
    assert_eq!(served.evidence_type_weight("observation"), 1.0, "PREMISE");

    let w = world(&pool).await;
    let before = caches(&pool, &w.all()).await;
    let r = r173(&pool, &w.viewer, &opts(Some(w.all()), None, Some(w.l1))).await;
    assert_eq!(
        caches(&pool, &w.all()).await,
        before,
        "the dry run writes no cache"
    );

    // ── The run's identity ──
    assert!(!r.calibration.source.is_empty());
    assert_ne!(
        r.calibration.served_profile_hash, r.calibration.empty_profile_hash,
        "the two regimes are different profiles"
    );
    assert_eq!(r.calibration.served_profile_hash, served.profile_hash());
    assert_eq!(
        r.calibration.empty_profile_hash,
        empty_vocabulary_profile().profile_hash()
    );
    assert_eq!(r.snapshots.len(), 1, "one transaction, unchunked");
    assert_eq!(r.snapshots[0].transaction_read_only, "on");
    assert_eq!(r.snapshots[0].transaction_isolation, "repeatable read");

    // ── Population ──
    assert_eq!(
        r.counts.candidates, 7,
        "every typed claim, not the untyped one"
    );
    assert_eq!(
        (
            r.counts.entered,
            r.counts.entered_current,
            r.counts.unchanged,
            r.counts.skipped_compound,
            r.counts.skipped_template_only,
            r.counts.skipped_no_input
        ),
        (4, 4, 1, 1, 1, 0),
        "{:?}",
        r.counts
    );
    assert!(r
        .claims
        .iter()
        .all(|c| c.id != w.untyped && c.id != w.overridden));
    assert_eq!(find(&r, w.compound).outcome, R173Outcome::SkippedCompound);
    assert_eq!(
        find(&r, w.template).outcome,
        R173Outcome::SkippedTemplateOnly
    );

    // ── Values against hand arithmetic ──
    let l1 = find(&r, w.l1);
    let (e, f) = (l1.empty.as_ref().unwrap(), l1.full.as_ref().unwrap());
    assert!(
        near(e.betp, one(0.5, 0.6, 0.4)) && near(f.betp, one(1.0, 0.6, 0.4)),
        "{l1:?}"
    );
    assert!(near(e.belief, 0.3) && near(f.belief, 0.6));
    assert!(near(l1.d_cal.unwrap(), 0.15) && near(l1.d_other.unwrap(), 0.0));
    assert_eq!(l1.regime, Some(Regime::CacheEqEmpty));
    assert_eq!(l1.causes, vec!["auto_wire".to_string()]);
    assert_eq!(l1.owner_frame_name.as_deref(), Some("binary_truth"));
    let si = l1.single_input.as_ref().expect("single input");
    assert_eq!((si.r_empty, si.r_full), (0.5, 1.0));

    let l3 = find(&r, w.l3);
    assert!(
        near(l3.empty.as_ref().unwrap().betp, one(0.5, 0.5, 0.5)),
        "{l3:?}"
    );
    assert!(near(l3.full.as_ref().unwrap().betp, one(1.0, 0.5, 0.5)));
    assert_eq!(l3.regime, Some(Regime::CacheEqFull));
    assert_eq!(l3.causes, vec!["<null>".to_string()]);

    let l2 = find(&r, w.l2);
    assert!(
        near(l2.empty.as_ref().unwrap().betp, l2_betp(0.7)),
        "{l2:?}"
    );
    assert!(near(l2.full.as_ref().unwrap().betp, l2_betp(0.6)));
    assert_eq!((l2.owner_inputs, l2.changed_rows), (2, 1));
    assert_eq!(l2.regime, Some(Regime::Neither));
    assert!(l2.single_input.is_none());

    let p = find(&r, w.patched);
    assert!(
        near(
            p.empty.as_ref().unwrap().betp,
            one(PATCHED_UNKNOWN_WEIGHT, 0.6, 0.4)
        ),
        "E on a patched frame is the empty base with the frame tier over it \
         (0.65 would be the type-nulling approximation): {p:?}"
    );
    assert!(near(p.full.as_ref().unwrap().betp, one(1.0, 0.6, 0.4)));
    assert!(p.owner_frame_patched);
    assert_eq!(p.owner_frame_name.as_deref(), Some("r173 patched"));
    assert_eq!(p.regime, Some(Regime::CacheEqEmpty));

    // ── Apply lists ──
    let mut want_l1 = vec![w.l1, w.patched];
    want_l1.sort();
    assert_eq!(r.lists.l1, want_l1);
    assert_eq!(r.lists.l2, vec![w.l2]);
    assert_eq!(r.lists.l3, vec![w.l3]);
    assert_eq!(
        r.lists.l1_single_input,
        vec![w.l1],
        "R-176(1)'s population: L1 with one owner input in the closed-form shape, on an \
         unpatched frame (the patched claim is in L1 but not here)"
    );
    assert!(r.lists.l1_not_current.is_empty() && r.lists.vacate.is_empty());
    assert_eq!(l1.list, Some(ApplyList::L1));

    // ── Totals: crossings with `>=`, components, writers ──
    let x = |t: f64| {
        r.all
            .crossings
            .iter()
            .find(|c| c.threshold == t)
            .map(|c| (c.s_to_a_up, c.s_to_a_down, c.e_to_f_up, c.e_to_f_down))
            .expect("threshold")
    };
    // 0.75: S→A l1 0.65→0.80 and patched 0.62→0.80; E→F also l3 0.625→0.75.
    assert_eq!(x(0.75), (2, 0, 3, 0));
    // 0.50: S→A l2 0.42→0.566; E→F nothing (l2 0.600→0.566 stays above).
    assert_eq!(x(0.5), (1, 0, 0, 0));
    assert_eq!(x(0.3), (0, 0, 0, 0));
    assert_eq!((r.all.d_cal.n, r.all.d_cal.up, r.all.d_cal.down), (4, 3, 1));
    assert_eq!(r.all.by_writer.get("auto_wire"), Some(&2));
    assert_eq!(r.all.by_writer.get("<null>"), Some(&2));
    assert_eq!(
        r.all.classification_flips.values().sum::<usize>(),
        3,
        "the three binary-frame claims gain a classification: {:?}",
        r.all.classification_flips
    );
    assert_eq!(r.l1.claims, 2);
    assert_eq!(r.l1_single_input.claims, 1);
    assert_eq!(r.l1_single_input.by_regime.get("cache_eq_empty"), Some(&1));
    assert_eq!(r.a5_mirror.by_regime.get("cache_eq_empty"), Some(&1));
    assert_eq!(r.a5_mirror.by_regime.get("cache_eq_full"), Some(&1));
    assert_eq!(r.a5_mirror.claims, 2, "l1 and l3: single input, unpatched");

    // ── Consistency checks ──
    let c = &r.checks;
    assert_eq!(
        c.c3_checked, 4,
        "l1, l3, patched and the unchanged override claim"
    );
    assert!(c.c3_violations.is_empty(), "{c:?}");
    assert!(c.c5_violations.is_empty() && c.a_matches_f_violations.is_empty());
    assert_eq!((c.c7_checked, c.c7_predicate_claims), (1, 1));
    assert!(c.c7_violations.is_empty());
    let canary = c.c2_canary.as_ref().expect("canary");
    assert_eq!(canary.id, w.l1);
    assert_eq!(canary.e_equals_s, Some(true));

    // ── A against the real write ──
    let mut conn = pool.acquire().await.expect("acquire");
    for claim in r
        .claims
        .iter()
        .filter(|c| c.outcome == R173Outcome::Recomputed)
    {
        assert!(
            recompute_claim_cached_belief(&mut conn, &w.viewer, claim.id)
                .await
                .expect("recompute")
        );
        let (bel, pl, betp) = caches(&pool, &[claim.id]).await[0];
        let a = claim.apply.as_ref().expect("A");
        assert!(
            (bel.unwrap() - a.belief).abs() < 1e-12
                && (pl.unwrap() - a.plausibility).abs() < 1e-12
                && (betp.unwrap() - a.betp).abs() < 1e-12,
            "{}: the recompute wrote ({bel:?}, {pl:?}, {betp:?}); A was {a:?}",
            claim.id
        );
    }
    for skipped in [w.compound, w.template] {
        let before = caches(&pool, &[skipped]).await;
        assert!(
            !recompute_claim_cached_belief(&mut conn, &w.viewer, skipped)
                .await
                .expect("recompute"),
            "PREMISE: a recompute leaves a skipped claim untouched"
        );
        assert_eq!(caches(&pool, &[skipped]).await, before);
    }
}

fn without_snapshots(mut r: R173Report) -> R173Report {
    r.snapshots.clear();
    r.chunk = None;
    r
}

#[sqlx::test(migrations = "../../migrations")]
async fn chunked_and_repeated_runs_measure_the_same_thing(pool: PgPool) {
    let w = world(&pool).await;
    let one_tx = r173(&pool, &w.viewer, &opts(None, None, None)).await;
    let ids: Vec<Uuid> = one_tx.claims.iter().map(|c| c.id).collect();
    for id in [w.l1, w.l3, w.l2, w.patched, w.compound, w.template] {
        assert!(ids.contains(&id), "{id} is measured without a restriction");
    }
    assert!(
        !ids.contains(&w.untyped),
        "an untyped-only claim is no candidate"
    );

    let chunked = r173(&pool, &w.viewer, &opts(None, Some(2), None)).await;
    let n = one_tx.counts.candidates;
    assert_eq!(
        chunked.snapshots.len(),
        1 + n.div_ceil(2),
        "one transaction for the list, one per chunk"
    );
    assert!(chunked.snapshots[0].chunk.is_none());
    assert!(chunked
        .snapshots
        .iter()
        .all(|s| s.transaction_read_only == "on" && s.transaction_isolation == "repeatable read"));
    assert_eq!(
        chunked.snapshots[1..]
            .iter()
            .map(|s| s.claims)
            .sum::<usize>(),
        n
    );
    assert_eq!(chunked.chunk, Some(2));
    assert_eq!(
        without_snapshots(chunked),
        without_snapshots(one_tx.clone()),
        "a chunked run measures what one transaction measures"
    );

    // C4: two runs on one database, byte for byte, snapshots aside.
    let again = r173(&pool, &w.viewer, &opts(None, None, None)).await;
    assert_eq!(
        serde_json::to_vec(&without_snapshots(again)).expect("json"),
        serde_json::to_vec(&without_snapshots(one_tx.clone())).expect("json"),
    );

    // With the other items, r173 shares their one transaction and measures
    // the same.
    let mut every = opts(None, None, None);
    every.items = DeltaItems {
        r131: true,
        k10_retro: true,
        k12b: true,
        r173: true,
    };
    let mut conn = pool.acquire().await.expect("acquire");
    let report = run_read_only(&mut conn, &w.viewer, &every)
        .await
        .expect("every item");
    assert!(report.k10_retro.is_some() && report.r131.is_some());
    assert_eq!(
        without_snapshots(report.r173.expect("r173")),
        without_snapshots(one_tx)
    );
}

// ───────────────────────── the branches the main world does not reach ─────

/// The edge-case claims, built alone in their own database so the main
/// world's hand-counted totals stay as they are.
struct Edges {
    _scoped: epigraph_db::ScopedPool,
    viewer: Viewer,
    /// Its only owner row cites a group-private evidence row; cache planted.
    vacate: Uuid,
    /// The same inadmissible input, no cache.
    scope_kept: Uuid,
    /// As the main world's `l1` (S = E, one row), then superseded.
    not_current: Uuid,
    /// The main world's `l2` rows, cache planted at E: clean calibration,
    /// two inputs.
    multi: Uuid,
    /// Its only typed row retracted, beside a live untyped one.
    retracted_only: Uuid,
    /// Its only typed row a cached combination, beside a live untyped one.
    cached_only: Uuid,
}

/// The candidates [`edges`] builds: the four claims holding a live, typed,
/// non-cached-combination row.
const EDGE_CANDIDATES: usize = 4;

/// Stamp the session as `agent` (its groups and writable groups).
async fn stamp(conn: &mut sqlx::PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let csv = |g: &[Uuid]| g.iter().map(Uuid::to_string).collect::<Vec<_>>().join(",");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(csv(v.group_bind().expect("scoped viewer")))
    .bind(csv(v.writable_groups()))
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp the session");
}

/// A public claim owned by `group` (so `owner` may retract rows it holds).
async fn owned_claim(pool: &PgPool, owner: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(tag)
    .bind(&hash)
    .bind(owner)
    .bind(group)
    .execute(pool)
    .await
    .expect("a public claim owned by the owner's group");
    id
}

/// Retract `row` as `owner` through the real repository path.
async fn retract_as(pool: &PgPool, owner: Uuid, row: Uuid) {
    let p = pool.clone();
    let retracted = fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let r = MassFunctionRepository::retract_conn(&mut conn, row, "r173 fixture", None).await;
        (conn, r)
    })
    .await
    .expect("the owner retracts the row through the real path");
    assert_eq!(retracted.status.as_str(), "retracted", "PREMISE");
}

async fn retire(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
          WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("retire by a plain flip");
}

/// A typed `empirical` row with no stored strength (empty 0.5, full 1.0)
/// citing `evidence`; its id.
async fn bba_citing(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, evidence: Uuid) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("auto_wire"),
        None,
        Some("empirical"),
        "cross",
        Some(evidence),
    )
    .await
    .expect("store the evidence-derived BBA")
}

async fn edges(pool: &PgPool) -> Edges {
    let (scoped, viewer) = fixture::bypass(pool).await;
    let public = fixture::public_viewer(pool).await;
    let (agent, _) = fixture::seed_agent_with_group(pool, "r173-edge-a").await;
    let (agent2, _) = fixture::seed_agent_with_group(pool, "r173-edge-b").await;
    let (member, group) = fixture::seed_agent_with_group(pool, "r173-edge-member").await;
    let (owner, owner_group) = fixture::seed_agent_with_group(pool, "r173-edge-owner").await;
    let binary = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary frame");
    let lean = || serde_json::json!({"0": 0.6, "0,1": 0.4});
    let untyped = || serde_json::json!({"1": 0.2, "0,1": 0.8});

    // Evidence narrowed to a group: it inherits its group-private claim's
    // tenancy, so a PUBLIC claim's row citing it is inadmissible (R-22).
    let private_src = fixture::seed_group_claim(pool, member, group, "r173 private src").await;
    let hidden = fixture::seed_evidence(pool, private_src, "observation").await;
    let vis: String = sqlx::query_scalar("SELECT visibility::text FROM evidence WHERE id = $1")
        .bind(hidden)
        .fetch_one(pool)
        .await
        .expect("evidence visibility");
    assert_ne!(
        vis, "public",
        "PREMISE: the cited evidence is group-private"
    );

    let vacate = fixture::seed_public_claim(pool, agent, "r173 vacate").await;
    let vacate_row = bba_citing(pool, vacate, binary, agent, hidden).await;
    plant(pool, vacate, 0.3, 1.0, one(0.5, 0.6, 0.4)).await;
    let scope_kept = fixture::seed_public_claim(pool, agent, "r173 scope kept").await;
    let kept_row = bba_citing(pool, scope_kept, binary, agent, hidden).await;
    let admitted = DerivationScopeRepository::cache_admissible(pool, &[vacate_row, kept_row])
        .await
        .expect("cache_admissible");
    assert!(
        admitted.is_empty(),
        "PREMISE: neither row may enter its public claim's cache: {admitted:?}"
    );

    let not_current = fixture::seed_public_claim(pool, agent, "r173 not current").await;
    bba(
        pool,
        not_current,
        binary,
        agent,
        lean(),
        Some("auto_wire"),
        None,
        Some("empirical"),
    )
    .await;
    plant(pool, not_current, 0.3, 1.0, one(0.5, 0.6, 0.4)).await;
    retire(pool, not_current).await;

    let multi = fixture::seed_public_claim(pool, agent, "r173 multi").await;
    bba(
        pool,
        multi,
        binary,
        agent,
        lean(),
        Some("auto_wire"),
        Some(0.7),
        Some("testimonial"),
    )
    .await;
    let against = serde_json::json!({"1": 0.3, "0,1": 0.7});
    bba(pool, multi, binary, agent2, against, None, Some(0.8), None).await;
    plant(pool, multi, 0.3, 0.8, l2_betp(0.7)).await;

    let retracted_only = owned_claim(pool, owner, owner_group, "r173 retracted only").await;
    let typed_row = MassFunctionRepository::store_with_perspective(
        pool,
        retracted_only,
        binary,
        Some(owner),
        None,
        &lean(),
        None,
        Some("auto_wire"),
        None,
        Some("empirical"),
        "cross",
        None,
    )
    .await
    .expect("the typed row to retract");
    bba(
        pool,
        retracted_only,
        binary,
        agent2,
        untyped(),
        None,
        Some(0.8),
        None,
    )
    .await;
    retract_as(pool, owner, typed_row).await;

    let cached_only = fixture::seed_public_claim(pool, agent, "r173 cached only").await;
    // A stored combination: no source agent, no perspective, a combination
    // label (the shape `cached_combination_predicate` names).
    MassFunctionRepository::store_with_perspective(
        pool,
        cached_only,
        binary,
        None,
        None,
        &lean(),
        Some(0.0),
        Some(COMBINATION_METHOD_LABELS[1]),
        None,
        Some("empirical"),
        "cross",
        None,
    )
    .await
    .expect("the cached combination row");
    bba(
        pool,
        cached_only,
        binary,
        agent2,
        untyped(),
        None,
        Some(0.8),
        None,
    )
    .await;

    Edges {
        _scoped: scoped,
        viewer,
        vacate,
        scope_kept,
        not_current,
        multi,
        retracted_only,
        cached_only,
    }
}

fn ids_of(r: &R173Report) -> Vec<Uuid> {
    r.claims.iter().map(|c| c.id).collect()
}

/// Every list `id` is in.
fn lists_of(r: &R173Report, id: Uuid) -> Vec<&'static str> {
    let l = &r.lists;
    [
        ("l1", &l.l1),
        ("l1_single_input", &l.l1_single_input),
        ("l1_not_current", &l.l1_not_current),
        ("l2", &l.l2),
        ("l3", &l.l3),
        ("vacate", &l.vacate),
    ]
    .into_iter()
    .filter(|(_, v)| v.contains(&id))
    .map(|(n, _)| n)
    .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_vacate_is_listed_apart_and_its_no_cache_twin_is_kept(pool: PgPool) {
    let e = edges(&pool).await;
    let r = r173(&pool, &e.viewer, &opts(None, None, None)).await;

    let v = find(&r, e.vacate);
    assert_eq!(v.outcome, R173Outcome::Vacate, "{v:?}");
    assert_eq!(v.changed_rows, 1, "PREMISE: the cited row changes weight");
    assert!(
        v.empty.is_none() && v.full.is_none(),
        "the scope rule admits no row to E or F: {v:?}"
    );
    let a = v.apply.as_ref().expect("a vacate's A");
    assert!(
        near(a.betp, 0.5) && near(a.belief, 0.0) && near(a.plausibility, 1.0),
        "A is full ignorance on the binary frame: {a:?}"
    );
    assert_eq!(a.classification.as_deref(), Some("not_enough_info"));
    assert_eq!(v.list, None);
    assert_eq!(
        lists_of(&r, e.vacate),
        vec!["vacate"],
        "never applied under R-173"
    );

    let k = find(&r, e.scope_kept);
    assert_eq!(k.outcome, R173Outcome::ScopeKept, "{k:?}");
    assert!(k.stored.betp.is_none(), "PREMISE: no cache");
    assert!(k.apply.is_none() && k.list.is_none());
    assert!(lists_of(&r, e.scope_kept).is_empty());
    assert!(r.checks.a_matches_f_violations.is_empty(), "{:?}", r.checks);
    assert_eq!(r.counts.entered, EDGE_CANDIDATES, "{:?}", r.counts);

    // A against the real write: the vacate writes full ignorance, the twin
    // keeps no cache.
    let mut conn = pool.acquire().await.expect("acquire");
    recompute_claim_cached_belief(&mut conn, &e.viewer, e.vacate)
        .await
        .expect("recompute the vacate");
    let (bel, pl, betp) = caches(&pool, &[e.vacate]).await[0];
    assert!(
        (bel.unwrap() - a.belief).abs() < 1e-12
            && (pl.unwrap() - a.plausibility).abs() < 1e-12
            && (betp.unwrap() - a.betp).abs() < 1e-12,
        "the recompute wrote ({bel:?}, {pl:?}, {betp:?}); A was {a:?}"
    );
    recompute_claim_cached_belief(&mut conn, &e.viewer, e.scope_kept)
        .await
        .expect("recompute the twin");
    assert_eq!(
        caches(&pool, &[e.scope_kept]).await,
        vec![(None, None, None)]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_superseded_clean_calibration_claim_is_listed_apart_from_l1(pool: PgPool) {
    let e = edges(&pool).await;
    let r = r173(&pool, &e.viewer, &opts(None, None, None)).await;
    let c = find(&r, e.not_current);
    assert!(!c.is_current, "PREMISE: superseded");
    assert_eq!(
        (c.outcome, c.regime),
        (R173Outcome::Recomputed, Some(Regime::CacheEqEmpty)),
        "{c:?}"
    );
    assert_eq!(c.list, Some(ApplyList::L1NotCurrent));
    assert_eq!(
        lists_of(&r, e.not_current),
        vec!["l1_not_current"],
        "a superseded claim is never in the list R-177(3) applies"
    );
    assert_eq!(r.counts.entered_not_current, 1, "{:?}", r.counts);
    assert_eq!(r.l1.claims, 1, "L1's stats hold the multi-input claim only");
    assert_eq!(
        r.a5_mirror.claims, 0,
        "Tier A's A5 population is current claims only"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_multi_input_clean_calibration_claim_is_in_l1_not_in_its_single_input_share(
    pool: PgPool,
) {
    let e = edges(&pool).await;
    let r = r173(&pool, &e.viewer, &opts(None, None, None)).await;
    let m = find(&r, e.multi);
    assert_eq!((m.owner_inputs, m.changed_rows), (2, 1), "{m:?}");
    assert!(near(m.empty.as_ref().unwrap().betp, l2_betp(0.7)), "{m:?}");
    assert!(near(m.full.as_ref().unwrap().betp, l2_betp(0.6)));
    assert!(near(m.d_cal.unwrap(), l2_betp(0.6) - l2_betp(0.7)));
    assert_eq!(m.regime, Some(Regime::CacheEqEmpty));
    assert!(m.single_input.is_none(), "two inputs: no closed form");
    assert_eq!(
        lists_of(&r, e.multi),
        vec!["l1"],
        "clean calibration, but not the single-input population R-176(1) accepted"
    );
    assert!(r.lists.l1_single_input.is_empty());
    assert_eq!(r.l1_single_input.claims, 0);
    assert_eq!(r.a5_mirror.claims, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_whose_only_typed_row_is_retracted_is_no_candidate(pool: PgPool) {
    let e = edges(&pool).await;
    let r = r173(&pool, &e.viewer, &opts(None, None, None)).await;
    assert!(
        !ids_of(&r).contains(&e.retracted_only),
        "a retracted typed row makes no candidate: {:?}",
        r.claims
    );
    assert_eq!(r.counts.candidates, EDGE_CANDIDATES, "{:?}", r.counts);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_whose_only_typed_row_is_a_cached_combination_is_no_candidate(pool: PgPool) {
    let e = edges(&pool).await;
    let r = r173(&pool, &e.viewer, &opts(None, None, None)).await;
    assert!(
        !ids_of(&r).contains(&e.cached_only),
        "a cached combination row makes no candidate: {:?}",
        r.claims
    );
    assert_eq!(r.counts.candidates, EDGE_CANDIDATES, "{:?}", r.counts);
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_restricts_the_population_and_cannot_admit_a_non_candidate(pool: PgPool) {
    let w = world(&pool).await;
    let one_claim = r173(&pool, &w.viewer, &opts(Some(vec![w.l1]), None, None)).await;
    assert_eq!(one_claim.counts.candidates, 1, "{:?}", one_claim.counts);
    assert_eq!(one_claim.only, Some(1));
    assert_eq!(ids_of(&one_claim), vec![w.l1]);
    assert_eq!(one_claim.lists.l1, vec![w.l1]);

    let none = r173(&pool, &w.viewer, &opts(Some(vec![w.untyped]), None, None)).await;
    assert_eq!(none.counts.candidates, 0, "{:?}", none.counts);
    assert!(none.claims.is_empty());

    // The canary: a non-candidate is measured on its own; an unknown id is
    // reported as unreadable.
    let canary = r173(
        &pool,
        &w.viewer,
        &opts(Some(vec![w.l1]), None, Some(w.untyped)),
    )
    .await;
    let c = canary.checks.c2_canary.as_ref().expect("canary");
    let measured = c.claim.as_ref().expect("the untyped claim is read");
    assert_eq!(measured.outcome, R173Outcome::Unchanged, "{measured:?}");
    let ghost = Uuid::new_v4();
    let unknown = r173(
        &pool,
        &w.viewer,
        &opts(Some(vec![w.l1]), Some(1), Some(ghost)),
    )
    .await;
    let c = unknown.checks.c2_canary.as_ref().expect("canary");
    assert_eq!((c.id, c.claim.is_none(), c.e_equals_s), (ghost, true, None));
}

/// The run on the login the binary connects as (`epigraph_maintenance`:
/// NOSUPERUSER, no BYPASSRLS) measures exactly what the superuser measures,
/// a GROUP-private candidate in a group the session has no part in included:
/// a smaller population there would corrupt check C1 and every figure.
#[sqlx::test(migrations = "../../migrations")]
async fn r173_reads_every_row_on_the_maintenance_login(pool: PgPool) {
    let w = world(&pool).await;
    let (pagent, pgroup) = fixture::seed_agent_with_group(&pool, "r173-private").await;
    let binary = ensure_binary_frame(
        &mut pool.acquire().await.expect("acquire"),
        &fixture::public_viewer(&pool).await,
    )
    .await
    .expect("binary frame");
    let private = fixture::seed_group_claim(&pool, pagent, pgroup, "r173 private").await;
    bba(
        &pool,
        private,
        binary,
        pagent,
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
        Some("auto_wire"),
        None,
        Some("empirical"),
    )
    .await;
    plant(&pool, private, 0.3, 1.0, one(0.5, 0.6, 0.4)).await;

    let as_superuser = r173(&pool, &w.viewer, &opts(None, None, None)).await;
    let p = find(&as_superuser, private);
    assert_eq!(
        (p.outcome, p.list),
        (R173Outcome::Recomputed, Some(ApplyList::L1)),
        "PREMISE: the superuser run measures the private candidate: {p:?}"
    );

    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let scoped = fixture::scoped_pool(&pool)
        .await
        .with_maintenance_pool(maint);
    let mut session = scoped
        .maintenance_session(SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, viewer) = session.split();
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut *conn)
        .await
        .expect("current_user");
    assert_eq!(role, "epigraph_maintenance", "PREMISE: the run's login");
    let as_maintenance = run_read_only(conn, viewer, &opts(None, None, None))
        .await
        .expect("maintenance run")
        .r173
        .expect("the r173 block");

    assert!(ids_of(&as_maintenance).contains(&private));
    assert_eq!(
        serde_json::to_value(without_snapshots(as_maintenance)).expect("json"),
        serde_json::to_value(without_snapshots(as_superuser)).expect("json"),
        "the maintenance login measures exactly what the superuser measures"
    );
}
