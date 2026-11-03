//! The `r173` item of the read-only dry-run delta: the belief delta of
//! re-folding the claims whose cached belief may have been written under the
//! EMPTY calibration vocabulary (ruling R-173, Tier B of its dry-run plan).
//!
//! Before the calibration file was compiled into every binary, a process that
//! could not find `calibration.toml` served
//! [`CalibrationConfig::default_for_phase2_fallback`]: every scalar as
//! shipped, but EMPTY evidence-type weight and alias tables, so every typed
//! BBA combined at its stored strength or the unknown-type weight. The stored
//! masses are mostly intact; the caches folded from them are the target.
//!
//! For each candidate (a claim holding at least one live, typed,
//! non-cached-combination BBA) this reads, in a `REPEATABLE READ READ ONLY`
//! transaction ([`super::run_read_only`]; one per chunk with `chunk`), and
//! writes nothing:
//!
//! * the claim's cache owner frame, the frame a recompute would fold
//!   (`MassFunctionRepository::cache_owner_frame_for_claim`); none for a
//!   compound or a template-only claim, which a recompute leaves untouched;
//! * which of the owner frame's rows change weight between the two regimes,
//!   by the engine's own reliability rule
//!   ([`crate::edge_factor::effective_source_strength_profiled`]) under the
//!   shipped profile and under the empty one, each with the frame tier;
//! * for a claim with a changed row, four values on the owner frame, clamped
//!   as the cache write clamps them:
//!   * **S**, the stored cache;
//!   * **E**, the fold under the empty vocabulary, and **F**, the fold under
//!     the shipped calibration, both through
//!     [`crate::edge_factor::preview_claim_belief_on_frame_with_profile`], so
//!     they differ only in the global profile;
//!   * **A**, what a recompute would write
//!     ([`crate::edge_factor::preview_claim_belief_on_frame_vacating`], which
//!     also reports a vacate under ruling R-80);
//! * the components `d_other = E − S` (drift that is not the calibration),
//!   `d_cal = F − E` (the calibration delta) and `d_apply = A − S`, on BetP;
//! * the regime that wrote the cache (S equal to E, to F, to both, or to
//!   neither within [`REGIME_EPS`]) and the apply list the claim belongs to.
//!
//! The report carries no timestamp; the only per-run value is each
//! transaction's snapshot ([`R173Report::snapshots`]), kept in its own field.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use epigraph_db::repos::claim_role::ClaimRole;
use epigraph_db::{FrameRepository, MassFunctionRepository, MassFunctionRow};
use uuid::Uuid;

use crate::belief_profile::BeliefProfile;
use crate::calibration::CalibrationConfig;
use crate::edge_factor::{
    effective_source_strength_profiled, frame_fold_profile, preview_claim_belief_on_frame_vacating,
    preview_claim_belief_on_frame_with_profile, resolve_hypothesis_index, CombinedBeliefPreview,
};

/// Two BetP values within this are the same value (the regime test).
pub const REGIME_EPS: f64 = 1e-6;
/// A component whose magnitude exceeds this moved (`d_cal != 0`, up, down).
pub const MOVE_EPS: f64 = 1e-9;
/// The single-input closed form must equal the fold within this (check C3).
pub const C3_TOLERANCE: f64 = 1e-9;

/// The r173 options.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct R173Options {
    /// BetP thresholds whose crossings are counted (`value >= threshold` is
    /// above, as the recall `confirmed` gate tests its score).
    pub thresholds: Vec<f64>,
    /// Claims per read-only transaction. `None`: every claim in the one
    /// transaction the other items use.
    pub chunk: Option<usize>,
    /// A claim measured and reported in full whatever its outcome (check C2).
    pub canary: Option<Uuid>,
    /// Restrict the candidates to these ids (a re-run over an apply list).
    pub only: Option<Vec<Uuid>>,
}

/// Where the served calibration came from, and the two profiles' hashes.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct CalibrationIdentity {
    /// [`CalibrationConfig::cached_source`].
    pub source: String,
    /// [`BeliefProfile::served`]'s hash: the profile F and A fold under.
    pub served_profile_hash: String,
    /// The empty vocabulary's hash ([`empty_vocabulary_profile`]): E's.
    pub empty_profile_hash: String,
}

/// The global profile a process served when it could not load a
/// calibration: [`BeliefProfile::from_calibration`] over
/// [`CalibrationConfig::default_for_phase2_fallback`].
#[must_use]
pub fn empty_vocabulary_profile() -> BeliefProfile {
    BeliefProfile::from_calibration(&CalibrationConfig::default_for_phase2_fallback())
}

/// Refuse to measure when the served calibration has a startup problem
/// ([`CalibrationConfig::problems`]): F would not be the shipped calibration.
///
/// # Errors
/// Every problem, joined.
pub fn calibration_guard(problems: &[String]) -> Result<(), String> {
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "r173 refuses to measure: the served calibration has a problem: {}",
            problems.join("; ")
        ))
    }
}

/// [`calibration_guard`] over this process's calibration, then its identity.
///
/// # Errors
/// [`calibration_guard`]'s.
pub fn calibration_identity() -> Result<CalibrationIdentity, String> {
    calibration_guard(&CalibrationConfig::startup_problems())?;
    Ok(CalibrationIdentity {
        source: CalibrationConfig::cached_source().to_string(),
        served_profile_hash: BeliefProfile::served().profile_hash(),
        empty_profile_hash: empty_vocabulary_profile().profile_hash(),
    })
}

/// What happened to one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum R173Outcome {
    /// A recompute writes the owner frame's fold (A).
    Recomputed,
    /// A recompute VACATES the cache (ruling R-80): never applied under R-173.
    Vacate,
    /// The derivation scope rule admits no owner row and there is nothing to
    /// vacate: a recompute leaves the cache as it is.
    ScopeKept,
    /// No owner-frame row changes weight between the regimes.
    Unchanged,
    /// A compound: no owner, a recompute leaves it untouched.
    SkippedCompound,
    /// Only ingest-template input: no owner, left untouched.
    SkippedTemplateOnly,
    /// No combine input the run can read: no owner.
    SkippedNoInput,
}

impl R173Outcome {
    const fn key(self) -> &'static str {
        match self {
            Self::Recomputed => "recomputed",
            Self::Vacate => "vacate",
            Self::ScopeKept => "scope_kept",
            Self::Unchanged => "unchanged",
            Self::SkippedCompound => "skipped_compound",
            Self::SkippedTemplateOnly => "skipped_template_only",
            Self::SkippedNoInput => "skipped_no_input",
        }
    }
}

/// Which regime wrote the stored cache, by BetP within [`REGIME_EPS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Regime {
    /// S = E, S ≠ F: written under the empty vocabulary (the R-173 target).
    CacheEqEmpty,
    /// S = F, S ≠ E: already fresh.
    CacheEqFull,
    /// S = E = F: the calibration does not move this claim's BetP.
    CacheEqBoth,
    /// Neither: drift that is not (only) the calibration.
    Neither,
    /// No stored cache.
    NoCache,
}

impl Regime {
    const fn key(self) -> &'static str {
        match self {
            Self::CacheEqEmpty => "cache_eq_empty",
            Self::CacheEqFull => "cache_eq_full",
            Self::CacheEqBoth => "cache_eq_both",
            Self::Neither => "neither",
            Self::NoCache => "no_cache",
        }
    }
}

/// The apply list a claim belongs to (plan §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyList {
    /// Clean calibration delta on a current claim: recomputed, `d_cal != 0`,
    /// regime `cache_eq_empty`.
    L1,
    /// As [`Self::L1`], but the claim is not current: listed apart.
    L1NotCurrent,
    /// Mixed: recomputed, `d_cal != 0`, regime `neither` or `no_cache`.
    L2,
    /// Already fresh: recomputed, regime `cache_eq_full` or `cache_eq_both`.
    L3,
}

/// The stored cache (S).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct Stored {
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub betp: Option<f64>,
    pub classification: Option<String>,
    pub frame_id: Option<Uuid>,
}

/// A fold, clamped as the cache write clamps it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Folded {
    pub belief: f64,
    pub plausibility: f64,
    pub betp: f64,
    pub classification: Option<String>,
}

impl Folded {
    fn of(p: CombinedBeliefPreview) -> Self {
        // The write clamps exactly so (`update_claim_belief`).
        let (belief, plausibility, betp, _, _) = epigraph_ds::measures::clamp_claim_belief_measures(
            p.belief,
            p.plausibility,
            Some(p.pignistic_prob),
            p.conflict_k,
            p.missing_mass,
        );
        Self {
            belief,
            plausibility,
            betp: betp.unwrap_or(p.pignistic_prob),
            classification: p.classification,
        }
    }

    fn same(&self, other: &Self) -> bool {
        (self.belief - other.belief).abs() <= MOVE_EPS
            && (self.plausibility - other.plausibility).abs() <= MOVE_EPS
            && (self.betp - other.betp).abs() <= MOVE_EPS
    }
}

/// The closed form of a single-input owner frame (check C3): one BBA with
/// mass only on singletons and the whole frame, discounted at r, has
/// `BetP(h) = r·m_h + (r·m_Θ + 1 − r)/n`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SingleInput {
    /// The row's reliability under the empty vocabulary.
    pub r_empty: f64,
    /// The row's reliability under the shipped calibration.
    pub r_full: f64,
    pub e_closed: f64,
    pub f_closed: f64,
}

/// One candidate's measurement.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct R173Claim {
    pub id: Uuid,
    pub is_current: bool,
    pub outcome: R173Outcome,
    pub owner_frame: Option<Uuid>,
    pub owner_frame_name: Option<String>,
    /// The owner frame carries a `belief_profile` patch (E is still exact:
    /// it folds the empty base with the frame tier over it).
    pub owner_frame_patched: bool,
    /// Combine inputs on the owner frame.
    pub owner_inputs: usize,
    /// Of those, the rows whose weight differs between the regimes.
    pub changed_rows: usize,
    /// The writer buckets (`combination_method`, `<null>` when NULL) of the
    /// changed rows, sorted.
    pub causes: Vec<String>,
    /// Every owner row is untyped or keyed by the frame's strict-key weight
    /// override (check C7's population).
    pub owner_rows_untyped_or_override: bool,
    pub regime: Option<Regime>,
    pub stored: Stored,
    pub empty: Option<Folded>,
    pub full: Option<Folded>,
    pub apply: Option<Folded>,
    /// `E − S` on BetP.
    pub d_other: Option<f64>,
    /// `F − E` on BetP.
    pub d_cal: Option<f64>,
    /// `A − S` on BetP.
    pub d_apply: Option<f64>,
    pub list: Option<ApplyList>,
    pub single_input: Option<SingleInput>,
}

impl R173Claim {
    fn bare(id: Uuid, is_current: bool, outcome: R173Outcome, stored: Stored) -> Self {
        Self {
            id,
            is_current,
            outcome,
            owner_frame: None,
            owner_frame_name: None,
            owner_frame_patched: false,
            owner_inputs: 0,
            changed_rows: 0,
            causes: Vec::new(),
            owner_rows_untyped_or_override: false,
            regime: None,
            stored,
            empty: None,
            full: None,
            apply: None,
            d_other: None,
            d_cal: None,
            d_apply: None,
            list: None,
            single_input: None,
        }
    }

    /// The claim entered the block: it has an owner and a changed row.
    #[must_use]
    pub fn entered(&self) -> bool {
        matches!(
            self.outcome,
            R173Outcome::Recomputed | R173Outcome::Vacate | R173Outcome::ScopeKept
        )
    }
}

/// One component's distribution.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct ComponentStats {
    /// Claims with a value for this component.
    pub n: usize,
    pub up: usize,
    pub down: usize,
    pub max_abs: f64,
    pub moved_over_0_10: usize,
    pub moved_over_0_20: usize,
    /// `|d|` in `[0, .01)`, `[.01, .05)`, `[.05, .1)`, `[.1, .2)`, `[.2, .5)`,
    /// `[.5, 1]`.
    pub abs_histogram: [usize; 6],
}

impl ComponentStats {
    fn add(&mut self, d: f64) {
        self.n += 1;
        if d > MOVE_EPS {
            self.up += 1;
        } else if d < -MOVE_EPS {
            self.down += 1;
        }
        let a = d.abs();
        if a > 0.10 {
            self.moved_over_0_10 += 1;
        }
        if a > 0.20 {
            self.moved_over_0_20 += 1;
        }
        if a > self.max_abs {
            self.max_abs = a;
        }
        let bin = match a {
            x if x < 0.01 => 0,
            x if x < 0.05 => 1,
            x if x < 0.10 => 2,
            x if x < 0.20 => 3,
            x if x < 0.50 => 4,
            _ => 5,
        };
        self.abs_histogram[bin] += 1;
    }
}

/// Crossings of one threshold (`value >= threshold` is above).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct Crossing {
    pub threshold: f64,
    /// S below, A above.
    pub s_to_a_up: usize,
    /// S above, A below.
    pub s_to_a_down: usize,
    pub e_to_f_up: usize,
    pub e_to_f_down: usize,
}

/// Aggregates over a set of claims.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct BlockStats {
    pub claims: usize,
    pub by_outcome: BTreeMap<String, usize>,
    pub by_regime: BTreeMap<String, usize>,
    /// Claims per writer bucket of their changed rows.
    pub by_writer: BTreeMap<String, usize>,
    pub by_owner_frame: BTreeMap<String, usize>,
    pub d_other: ComponentStats,
    pub d_cal: ComponentStats,
    pub d_apply: ComponentStats,
    pub crossings: Vec<Crossing>,
    /// `"<S class> -> <A class>"` where they differ (`<none>` for NULL).
    pub classification_flips: BTreeMap<String, usize>,
    /// The stored cache names another frame than the owner a recompute folds.
    pub owner_frame_moves: usize,
    /// Up to `top` ids, largest `|d_apply|` first (ties by id).
    pub top_movers: Vec<Uuid>,
}

impl BlockStats {
    fn over<'a>(
        claims: impl Iterator<Item = &'a R173Claim>,
        thresholds: &[f64],
        top: usize,
    ) -> Self {
        let mut s = Self {
            crossings: thresholds
                .iter()
                .map(|&threshold| Crossing {
                    threshold,
                    ..Crossing::default()
                })
                .collect(),
            ..Self::default()
        };
        let mut movers: Vec<(f64, Uuid)> = Vec::new();
        for c in claims {
            s.claims += 1;
            *s.by_outcome.entry(c.outcome.key().to_string()).or_insert(0) += 1;
            if let Some(r) = c.regime {
                *s.by_regime.entry(r.key().to_string()).or_insert(0) += 1;
            }
            for w in &c.causes {
                *s.by_writer.entry(w.clone()).or_insert(0) += 1;
            }
            if let Some(name) = &c.owner_frame_name {
                *s.by_owner_frame.entry(name.clone()).or_insert(0) += 1;
            }
            if let Some(d) = c.d_other {
                s.d_other.add(d);
            }
            if let Some(d) = c.d_cal {
                s.d_cal.add(d);
            }
            if let Some(d) = c.d_apply {
                s.d_apply.add(d);
                movers.push((d.abs(), c.id));
            }
            for x in &mut s.crossings {
                let above = |v: f64| v >= x.threshold;
                if let (Some(sv), Some(a)) = (c.stored.betp, c.apply.as_ref()) {
                    match (above(sv), above(a.betp)) {
                        (false, true) => x.s_to_a_up += 1,
                        (true, false) => x.s_to_a_down += 1,
                        _ => {}
                    }
                }
                if let (Some(e), Some(f)) = (c.empty.as_ref(), c.full.as_ref()) {
                    match (above(e.betp), above(f.betp)) {
                        (false, true) => x.e_to_f_up += 1,
                        (true, false) => x.e_to_f_down += 1,
                        _ => {}
                    }
                }
            }
            if let Some(a) = &c.apply {
                if a.classification != c.stored.classification {
                    let name = |v: &Option<String>| v.clone().unwrap_or_else(|| "<none>".into());
                    let key = format!(
                        "{} -> {}",
                        name(&c.stored.classification),
                        name(&a.classification)
                    );
                    *s.classification_flips.entry(key).or_insert(0) += 1;
                }
                if c.stored.frame_id.is_some() && c.stored.frame_id != c.owner_frame {
                    s.owner_frame_moves += 1;
                }
            }
        }
        movers.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        s.top_movers = movers.into_iter().take(top).map(|(_, id)| id).collect();
        s
    }
}

/// Candidate counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct R173Counts {
    /// Claims with a live, typed, non-cached-combination BBA.
    pub candidates: usize,
    /// Owner and a changed row (outcomes `recomputed`, `vacate`,
    /// `scope_kept`); compare with Tier A's claim-level count (check C1).
    pub entered: usize,
    pub entered_current: usize,
    pub entered_not_current: usize,
    pub unchanged: usize,
    pub skipped_compound: usize,
    pub skipped_template_only: usize,
    pub skipped_no_input: usize,
}

/// The apply lists (plan §4.3), sorted. Ids only: the values are on each
/// claim.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ApplyLists {
    pub l1: Vec<Uuid>,
    pub l1_not_current: Vec<Uuid>,
    pub l2: Vec<Uuid>,
    pub l3: Vec<Uuid>,
    /// Outcome `vacate`: never applied under R-173.
    pub vacate: Vec<Uuid>,
}

/// The canary claim, reported in full (check C2).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Canary {
    pub id: Uuid,
    /// `None` when the claim cannot be read.
    pub claim: Option<R173Claim>,
    /// `|S − E| < REGIME_EPS` on BetP, when both exist.
    pub e_equals_s: Option<bool>,
}

/// The consistency checks the run can make itself (plan §4.2 C1–C7); the
/// external ones say what to compare.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct R173Checks {
    pub c1: &'static str,
    pub c2_canary: Option<Canary>,
    /// Single-input owner frames whose closed form was compared to the fold.
    pub c3_checked: usize,
    pub c3_max_abs_diff: f64,
    pub c3_violations: Vec<Uuid>,
    pub c4: &'static str,
    /// A value that is not finite or lies outside `[0, 1]`.
    pub c5_violations: Vec<Uuid>,
    pub c6: &'static str,
    /// Unchanged claims whose E and F were both folded and compared.
    pub c7_checked: usize,
    /// Of those, the claims whose every owner row is untyped or keyed by the
    /// frame's strict-key override.
    pub c7_predicate_claims: usize,
    /// An unchanged claim whose E and F differ.
    pub c7_violations: Vec<Uuid>,
    /// A recomputed claim whose A is not F (the write path and the measured
    /// fold disagree).
    pub a_matches_f_violations: Vec<Uuid>,
}

/// One read-only transaction of the run.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ChunkSnapshot {
    /// `None` for the candidate enumeration (or the whole run unchunked).
    pub chunk: Option<usize>,
    pub claims: usize,
    pub first: Option<Uuid>,
    pub last: Option<Uuid>,
    pub transaction_read_only: String,
    pub transaction_isolation: String,
    /// `pg_current_snapshot()`: the only per-run value in the report.
    pub snapshot: String,
}

/// The r173 measurement.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct R173Report {
    pub calibration: CalibrationIdentity,
    pub thresholds: Vec<f64>,
    pub chunk: Option<usize>,
    /// How many ids the run was restricted to, if it was.
    pub only: Option<usize>,
    pub snapshots: Vec<ChunkSnapshot>,
    pub counts: R173Counts,
    pub lists: ApplyLists,
    /// Every entered and skipped claim.
    pub all: BlockStats,
    pub l1: BlockStats,
    pub l2: BlockStats,
    /// Tier A's single-input population: current, entered, one owner input,
    /// closed form applicable, owner frame unpatched.
    pub a5_mirror: BlockStats,
    pub checks: R173Checks,
    pub not_measured: Vec<&'static str>,
    /// Entered and skipped claims, by id. Unchanged ones are counted only.
    pub claims: Vec<R173Claim>,
}

/// The frame tiers of one owner frame, resolved once per run.
struct FrameProfiles {
    name: String,
    hypotheses: usize,
    patched: bool,
    full: BeliefProfile,
    empty: BeliefProfile,
}

/// State shared by the chunks of one run.
pub(super) struct Run {
    empty_base: BeliefProfile,
    frames: HashMap<Uuid, FrameProfiles>,
}

impl Run {
    pub(super) fn new() -> Self {
        Self {
            empty_base: empty_vocabulary_profile(),
            frames: HashMap::new(),
        }
    }

    async fn frame(
        &mut self,
        conn: &mut sqlx::PgConnection,
        viewer: &epigraph_db::visibility::Viewer,
        frame_id: Uuid,
    ) -> Result<&FrameProfiles, String> {
        if !self.frames.contains_key(&frame_id) {
            let row = FrameRepository::get_by_id(&mut *conn, viewer, frame_id)
                .await
                .map_err(|e| format!("read frame {frame_id}: {e}"))?
                .ok_or_else(|| format!("frame {frame_id} not found"))?;
            let full =
                frame_fold_profile(&mut *conn, viewer, frame_id, BeliefProfile::served()).await?;
            let empty = frame_fold_profile(&mut *conn, viewer, frame_id, &self.empty_base).await?;
            self.frames.insert(
                frame_id,
                FrameProfiles {
                    name: row.name.clone(),
                    hypotheses: row.hypotheses.len(),
                    patched: crate::belief_profile::overrides_in(&row.properties).is_some(),
                    full,
                    empty,
                },
            );
        }
        Ok(&self.frames[&frame_id])
    }
}

/// The candidates: every claim (restricted to `only` when given) holding a
/// live, typed BBA that is not a cached combination, by id. A probe per
/// claim on the `(claim_id, …)` key, not a sort over `mass_functions`.
///
/// # Errors
/// The query's.
pub async fn candidates(
    conn: &mut sqlx::PgConnection,
    only: Option<&[Uuid]>,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let sql = format!(
        "-- VISIBILITY-EXEMPT: maintenance read; the r173 dry run reads every group's rows on the privileged connection.
         SELECT c.id FROM claims c
          WHERE ($1::uuid[] IS NULL OR c.id = ANY($1::uuid[]))
            AND EXISTS (SELECT 1 FROM mass_functions mf
                         WHERE mf.claim_id = c.id
                           AND mf.evidence_type IS NOT NULL
                           AND mf.retracted_at IS NULL
                           AND NOT {cached})
          ORDER BY c.id",
        cached = epigraph_db::repos::mass_function::cached_combination_predicate("mf.")
    );
    sqlx::query_scalar(&sql)
        .bind(only.map(<[Uuid]>::to_vec))
        .fetch_all(&mut *conn)
        .await
}

/// The transaction's mode and snapshot.
pub(super) async fn snapshot(
    conn: &mut sqlx::PgConnection,
    chunk: Option<usize>,
    ids: &[Uuid],
) -> Result<ChunkSnapshot, String> {
    let (read_only, isolation, snap): (String, String, String) = sqlx::query_as(
        "SELECT current_setting('transaction_read_only'), \
                current_setting('transaction_isolation'), \
                pg_current_snapshot()::text",
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| format!("read the transaction's snapshot: {e}"))?;
    Ok(ChunkSnapshot {
        chunk,
        claims: ids.len(),
        first: ids.first().copied(),
        last: ids.last().copied(),
        transaction_read_only: read_only,
        transaction_isolation: isolation,
        snapshot: snap,
    })
}

/// The stored caches and the roles of `ids`. A role picks a claim's skip
/// outcome when it has no owner (a compound is left untouched by design).
async fn stored_and_roles(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
) -> Result<(HashMap<Uuid, (Stored, bool)>, HashMap<Uuid, ClaimRole>), String> {
    type Row = (
        Uuid,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<String>,
        Option<Uuid>,
        Option<bool>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "-- VISIBILITY-EXEMPT: maintenance read; the r173 dry run reads every group's rows on the privileged connection.
         SELECT id, belief, plausibility, pignistic_prob, classification, belief_frame_id, is_current
           FROM claims WHERE id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("read the candidates' caches: {e}"))?;
    let stored = rows
        .into_iter()
        .map(
            |(id, belief, plausibility, betp, classification, frame_id, cur)| {
                (
                    id,
                    (
                        Stored {
                            belief,
                            plausibility,
                            betp,
                            classification,
                            frame_id,
                        },
                        cur.unwrap_or(true),
                    ),
                )
            },
        )
        .collect();
    let roles = epigraph_db::repos::claim_role::roles_batch(&mut *conn, viewer, ids)
        .await
        .map_err(|e| format!("read the candidates' roles: {e}"))?;
    Ok((stored, roles))
}

/// Measure `ids` in the current transaction.
pub(super) async fn measure_ids(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    run: &mut Run,
    ids: &[Uuid],
) -> Result<Vec<R173Claim>, String> {
    let (stored, roles) = stored_and_roles(&mut *conn, viewer, ids).await?;
    let mut out = Vec::with_capacity(ids.len());
    for &id in ids {
        let Some((s, is_current)) = stored.get(&id).cloned() else {
            // Unreadable (removed since enumeration, in a later chunk).
            out.push(R173Claim::bare(
                id,
                true,
                R173Outcome::SkippedNoInput,
                Stored::default(),
            ));
            continue;
        };
        let compound = matches!(roles.get(&id), Some(ClaimRole::Compound { .. }));
        out.push(measure_claim(&mut *conn, viewer, run, id, s, is_current, compound).await?);
    }
    Ok(out)
}

async fn fold_under(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim: Uuid,
    frame: Uuid,
    base: &BeliefProfile,
) -> Result<Option<Folded>, String> {
    Ok(
        preview_claim_belief_on_frame_with_profile(conn, viewer, claim, frame, base, |rows| rows)
            .await
            .map_err(|e| format!("fold {claim} on {frame}: {e}"))?
            .map(Folded::of),
    )
}

async fn measure_claim(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    run: &mut Run,
    id: Uuid,
    stored: Stored,
    is_current: bool,
    compound: bool,
) -> Result<R173Claim, String> {
    let owner = MassFunctionRepository::cache_owner_frame_for_claim(&mut *conn, viewer, id)
        .await
        .map_err(|e| format!("{id}: owner frame: {e}"))?;
    let Some(owner) = owner else {
        let outcome = if compound {
            R173Outcome::SkippedCompound
        } else if MassFunctionRepository::get_for_claim(&mut *conn, viewer, id)
            .await
            .map_err(|e| format!("{id}: inputs: {e}"))?
            .is_empty()
        {
            R173Outcome::SkippedNoInput
        } else {
            R173Outcome::SkippedTemplateOnly
        };
        return Ok(R173Claim::bare(id, is_current, outcome, stored));
    };
    let rows = MassFunctionRepository::get_for_claim_frame(&mut *conn, viewer, id, owner)
        .await
        .map_err(|e| format!("{id}: owner rows: {e}"))?;
    let (name, hypotheses, patched, weights, untyped_or_override) = {
        let fp = run.frame(&mut *conn, viewer, owner).await?;
        let weights: Vec<(f64, f64)> = rows
            .iter()
            .map(|r| {
                (
                    effective_source_strength_profiled(r, &fp.empty),
                    effective_source_strength_profiled(r, &fp.full),
                )
            })
            .collect();
        let untyped_or_override = rows.iter().all(|r| {
            r.evidence_type.as_ref().is_none_or(|t| {
                fp.full
                    .lens
                    .frame_evidence_type_weights
                    .contains_key(&t.to_lowercase())
            })
        });
        (
            fp.name.clone(),
            fp.hypotheses,
            fp.patched,
            weights,
            untyped_or_override,
        )
    };
    let mut causes = BTreeSet::new();
    let mut changed_rows = 0;
    for (r, (we, wf)) in rows.iter().zip(&weights) {
        if we != wf {
            changed_rows += 1;
            causes.insert(
                r.combination_method
                    .clone()
                    .unwrap_or_else(|| "<null>".to_string()),
            );
        }
    }
    let empty = fold_under(&mut *conn, viewer, id, owner, &run.empty_base).await?;
    let full = fold_under(&mut *conn, viewer, id, owner, BeliefProfile::served()).await?;

    let mut c = R173Claim::bare(id, is_current, R173Outcome::Unchanged, stored);
    c.owner_frame = Some(owner);
    c.owner_frame_name = Some(name);
    c.owner_frame_patched = patched;
    c.owner_inputs = rows.len();
    c.changed_rows = changed_rows;
    c.causes = causes.into_iter().collect();
    c.owner_rows_untyped_or_override = untyped_or_override;
    c.d_cal = match (&empty, &full) {
        (Some(e), Some(f)) => Some(f.betp - e.betp),
        _ => None,
    };
    c.d_other = match (&empty, c.stored.betp) {
        (Some(e), Some(s)) => Some(e.betp - s),
        _ => None,
    };
    c.regime = Some(match c.stored.betp {
        None => Regime::NoCache,
        Some(s) => {
            let eq =
                |v: &Option<Folded>| v.as_ref().is_some_and(|x| (s - x.betp).abs() < REGIME_EPS);
            match (eq(&empty), eq(&full)) {
                (true, true) => Regime::CacheEqBoth,
                (true, false) => Regime::CacheEqEmpty,
                (false, true) => Regime::CacheEqFull,
                (false, false) => Regime::Neither,
            }
        }
    });
    if rows.len() == 1 && empty.is_some() && full.is_some() {
        c.single_input = single_input(&mut *conn, viewer, &rows[0], hypotheses, weights[0]).await?;
    }
    c.empty = empty;
    c.full = full;
    if changed_rows == 0 {
        return Ok(c);
    }

    let apply = preview_claim_belief_on_frame_vacating(&mut *conn, viewer, id, owner)
        .await
        .map_err(|e| format!("{id}: the recompute's value: {e}"))?;
    let (outcome, apply) = match apply {
        None => (R173Outcome::ScopeKept, None),
        Some((p, true)) => (R173Outcome::Vacate, Some(Folded::of(p))),
        Some((p, false)) => (R173Outcome::Recomputed, Some(Folded::of(p))),
    };
    c.outcome = outcome;
    c.d_apply = match (&apply, c.stored.betp) {
        (Some(a), Some(s)) => Some(a.betp - s),
        _ => None,
    };
    c.apply = apply;
    c.list = if outcome == R173Outcome::Recomputed {
        match c.regime {
            Some(Regime::CacheEqFull | Regime::CacheEqBoth) => Some(ApplyList::L3),
            _ if !c.d_cal.is_some_and(|d| d.abs() > MOVE_EPS) => None,
            Some(Regime::CacheEqEmpty) if c.is_current => Some(ApplyList::L1),
            Some(Regime::CacheEqEmpty) => Some(ApplyList::L1NotCurrent),
            _ => Some(ApplyList::L2),
        }
    } else {
        None
    };
    Ok(c)
}

/// The closed form of a single owner row, when its masses sit only on
/// singletons and the whole frame (check C3); `None` otherwise.
async fn single_input(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    row: &MassFunctionRow,
    n: usize,
    (r_empty, r_full): (f64, f64),
) -> Result<Option<SingleInput>, String> {
    let Some(masses) = row.masses.as_object() else {
        return Ok(None);
    };
    let theta = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let shaped = masses.iter().all(|(k, v)| {
        v.is_number() && (*k == theta || (!k.is_empty() && k.bytes().all(|b| b.is_ascii_digit())))
    });
    if !shaped || n == 0 {
        return Ok(None);
    }
    let h = resolve_hypothesis_index(
        FrameRepository::get_claim_assignment(&mut *conn, viewer, row.claim_id, row.frame_id)
            .await
            .map_err(|e| format!("{}: assignment: {e}", row.claim_id))?
            .and_then(|a| a.hypothesis_index),
        n,
    );
    let mass = |k: &str| {
        masses
            .get(k)
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0)
    };
    let (m_h, m_t) = (mass(&h.to_string()), mass(&theta));
    #[allow(clippy::cast_precision_loss)]
    let n = n as f64;
    let closed = |r: f64| r * m_h + (r * m_t + 1.0 - r) / n;
    Ok(Some(SingleInput {
        r_empty,
        r_full,
        e_closed: closed(r_empty),
        f_closed: closed(r_full),
    }))
}

fn in_unit(v: f64) -> bool {
    v.is_finite() && (0.0..=1.0).contains(&v)
}

fn out_of_range(c: &R173Claim) -> bool {
    let stored = [c.stored.belief, c.stored.plausibility, c.stored.betp];
    let folded = [&c.empty, &c.full, &c.apply];
    stored.iter().flatten().any(|v| !in_unit(*v))
        || folded
            .iter()
            .filter_map(|f| f.as_ref())
            .any(|f| !(in_unit(f.belief) && in_unit(f.plausibility) && in_unit(f.betp)))
        || [c.d_other, c.d_cal, c.d_apply]
            .iter()
            .flatten()
            .any(|d| !d.is_finite())
}

/// Assemble the report from every measured candidate (in id order).
pub(super) fn report(
    identity: CalibrationIdentity,
    opts: &R173Options,
    top: usize,
    snapshots: Vec<ChunkSnapshot>,
    candidates: usize,
    measured: Vec<R173Claim>,
    canary: Option<Canary>,
) -> R173Report {
    let mut counts = R173Counts {
        candidates,
        ..R173Counts::default()
    };
    let mut checks = R173Checks {
        c1: "external: compare counts.entered (current + not current) with Tier A's \
             claim-level count of claims whose owner frame holds a changed row",
        c4: "the report carries no timestamp; ids and maps are sorted; snapshots are \
             the only per-run field",
        c6: "external: the k10-retro / k12b blocks' totals against X-3 Tier A",
        c2_canary: canary,
        ..R173Checks::default()
    };
    let mut lists = ApplyLists::default();
    let mut claims = Vec::new();
    for c in measured {
        if out_of_range(&c) {
            checks.c5_violations.push(c.id);
        }
        if let (Some(si), Some(e), Some(f)) = (&c.single_input, &c.empty, &c.full) {
            checks.c3_checked += 1;
            let diff = (si.e_closed - e.betp)
                .abs()
                .max((si.f_closed - f.betp).abs());
            if diff > checks.c3_max_abs_diff {
                checks.c3_max_abs_diff = diff;
            }
            if diff > C3_TOLERANCE {
                checks.c3_violations.push(c.id);
            }
        }
        match c.outcome {
            R173Outcome::Unchanged => {
                counts.unchanged += 1;
                checks.c7_checked += 1;
                if c.owner_rows_untyped_or_override {
                    checks.c7_predicate_claims += 1;
                }
                let same = match (&c.empty, &c.full) {
                    (Some(e), Some(f)) => e.same(f),
                    (None, None) => true,
                    _ => false,
                };
                if !same {
                    checks.c7_violations.push(c.id);
                }
                continue;
            }
            R173Outcome::SkippedCompound => counts.skipped_compound += 1,
            R173Outcome::SkippedTemplateOnly => counts.skipped_template_only += 1,
            R173Outcome::SkippedNoInput => counts.skipped_no_input += 1,
            R173Outcome::Recomputed | R173Outcome::Vacate | R173Outcome::ScopeKept => {
                counts.entered += 1;
                if c.is_current {
                    counts.entered_current += 1;
                } else {
                    counts.entered_not_current += 1;
                }
            }
        }
        if c.outcome == R173Outcome::Recomputed {
            if let (Some(a), Some(f)) = (&c.apply, &c.full) {
                if !(a.same(f) && a.classification == f.classification) {
                    checks.a_matches_f_violations.push(c.id);
                }
            }
        }
        if c.outcome == R173Outcome::Vacate {
            lists.vacate.push(c.id);
        }
        match c.list {
            Some(ApplyList::L1) => lists.l1.push(c.id),
            Some(ApplyList::L1NotCurrent) => lists.l1_not_current.push(c.id),
            Some(ApplyList::L2) => lists.l2.push(c.id),
            Some(ApplyList::L3) => lists.l3.push(c.id),
            None => {}
        }
        claims.push(c);
    }
    claims.sort_by_key(|c| c.id);
    for l in [
        &mut lists.l1,
        &mut lists.l1_not_current,
        &mut lists.l2,
        &mut lists.l3,
        &mut lists.vacate,
    ] {
        l.sort_unstable();
    }
    let t = &opts.thresholds;
    let pick = |want: ApplyList| claims.iter().filter(move |c| c.list == Some(want));
    let a5 = claims.iter().filter(|c| {
        c.is_current && c.entered() && c.single_input.is_some() && !c.owner_frame_patched
    });
    R173Report {
        calibration: identity,
        thresholds: t.clone(),
        chunk: opts.chunk,
        only: opts.only.as_ref().map(Vec::len),
        snapshots,
        counts,
        lists,
        all: BlockStats::over(claims.iter(), t, top),
        l1: BlockStats::over(pick(ApplyList::L1), t, top),
        l2: BlockStats::over(pick(ApplyList::L2), t, top),
        a5_mirror: BlockStats::over(a5, t, top),
        checks,
        not_measured: vec![
            "X / d_x3 (the owner-frame fold without the X-3 rows): not in this item",
            "the k10-retro / k12b blocks still fold the binary frame, not each claim's owner \
             frame (plan section 4.3 condition 1)",
        ],
        claims,
    }
}

/// The canary's full record and the C2 test.
pub(super) fn canary_of(id: Uuid, claim: Option<R173Claim>) -> Canary {
    let e_equals_s = claim
        .as_ref()
        .and_then(|c| match (c.stored.betp, &c.empty) {
            (Some(s), Some(e)) => Some((s - e.betp).abs() < REGIME_EPS),
            _ => None,
        });
    Canary {
        id,
        claim,
        e_equals_s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibration::CalibrationSource;

    #[test]
    fn the_guard_refuses_the_empty_vocabulary() {
        // The configuration every container process served before the fix.
        let problems = CalibrationConfig::problems(
            &CalibrationConfig::default_for_phase2_fallback(),
            &CalibrationSource::Embedded {
                failed_override: None,
            },
        );
        let err = calibration_guard(&problems).expect_err("an empty vocabulary is refused");
        assert!(
            err.contains("EMPTY"),
            "the refusal names the problem: {err}"
        );
        calibration_guard(&CalibrationConfig::problems(
            &CalibrationConfig::embedded(),
            &CalibrationSource::Embedded {
                failed_override: None,
            },
        ))
        .expect("the shipped calibration passes");
    }

    #[test]
    fn crossings_count_a_value_at_the_threshold_as_above() {
        let mut c = R173Claim::bare(
            Uuid::nil(),
            true,
            R173Outcome::Recomputed,
            Stored {
                betp: Some(0.74),
                ..Stored::default()
            },
        );
        let at = |betp: f64| Folded {
            belief: 0.0,
            plausibility: 1.0,
            betp,
            classification: None,
        };
        c.apply = Some(at(0.75));
        c.empty = Some(at(0.75));
        c.full = Some(at(0.749_999));
        let s = BlockStats::over(std::iter::once(&c), &[0.75], 10);
        assert_eq!(
            (
                s.crossings[0].s_to_a_up,
                s.crossings[0].e_to_f_down,
                s.crossings[0].e_to_f_up
            ),
            (1, 1, 0),
            "0.75 is above a 0.75 threshold, as the confirmed gate's `>=` reads it"
        );
    }
}
