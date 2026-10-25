//! The atom evidence fold (AEF): the ONE fold of an atom's own evidence
//! (atom-level belief program, SPEC §3.3, §3.4, §4.2, §11.4).
//!
//! An atom's belief is a fold of the rows that are evidence about IT. This
//! module reads those rows ([`atom_axiom_rows`]), keys each one by its
//! canonical source ([`crate::source_dependence::item_key`]) and folds them
//! by item ([`atom_fold`]): one key's pure-support rows count once (the max),
//! its refutations are a separate item, and distinct items combine by
//! Dempster. The result is an [`EvidencedInterval`], which only [`atom_fold`]
//! can build.
//!
//! Nothing on a served path calls this module yet: the single atom-cache
//! writer [`crate::edge_factor::recompute_atom_cache`] is wired to its call
//! sites separately, behind `EPIGRAPH_ATOM_FOLD` (default `legacy`).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use uuid::Uuid;

use epigraph_db::repos::atom_axiom::{atom_input_rows, AtomInputRow};
use epigraph_db::repos::claim_role::leaf_closure_batch;
use epigraph_db::{EvidenceRepository, FrameRepository};
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};

use crate::belief_profile::{overrides_in, BeliefProfile, FrameTier};
use crate::belief_query::FramedBeliefContext;
use crate::edge_factor::{
    effective_source_strength_profiled, resolve_hypothesis_index, CLAIM_VALIDITY_FRAME_ID,
};
use crate::sheaf::{restriction_kind_with_profile, RestrictionKind, RestrictionProfile};
use crate::source_dependence::{
    dempster_across_items, item_key, item_partition, ItemEvidence, ItemKey, KeyedBba,
    EDGE_FACTOR_METHOD,
};

/// Which rows of an atom's input a read takes (SPEC §3.4, §11.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AxiomMode {
    /// The stage-1 served fold: evidence, edge-factor rows from atom sources,
    /// compound-source edge-factor rows while
    /// [`CompoundSourceEdges::Frozen`], `propagated_*` and `auto_cdst`.
    Display,
    /// The engine's premise input: evidence only. No `edge_factor`, no
    /// `propagated_*`, no `auto_cdst`.
    Pure,
}

/// `EPIGRAPH_COMPOUND_SOURCE_EDGES` (SPEC §6.3, §10.2): whether edge-factor
/// rows whose edge SOURCE is a compound stay in the [`AxiomMode::Display`]
/// fold. Spelled as PR-G0's `belief_modes::CompoundSourceEdges`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CompoundSourceEdges {
    /// Kept, read one-sided on positive relationships (the default).
    #[default]
    Frozen,
    /// Dropped from every fold.
    Excluded,
}

impl CompoundSourceEdges {
    /// The environment variable this switch is read from.
    pub const ENV: &'static str = "EPIGRAPH_COMPOUND_SOURCE_EDGES";

    /// Parse one value: trimmed, case-insensitive; `None` when it is neither
    /// `frozen` nor `excluded`.
    #[must_use]
    pub fn parse_value(raw: &str) -> Option<Self> {
        let v = raw.trim();
        if v.eq_ignore_ascii_case("frozen") {
            Some(Self::Frozen)
        } else if v.eq_ignore_ascii_case("excluded") {
            Some(Self::Excluded)
        } else {
            None
        }
    }

    /// This process's setting: [`Self::ENV`], read once. Unset, blank or an
    /// unrecognised value is the default, [`Self::Frozen`] (an unrecognised
    /// one is logged).
    #[must_use]
    pub fn current() -> Self {
        static CELL: std::sync::OnceLock<CompoundSourceEdges> = std::sync::OnceLock::new();
        *CELL.get_or_init(|| read_flag(Self::ENV, Self::parse_value))
    }
}

/// `EPIGRAPH_ATOM_FOLD` (SPEC §10.2): which atoms the single cache writer
/// folds with the AEF. Spelled as PR-G0's `belief_modes::AtomFold`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AtomFoldMode {
    /// Today's per-site folds, for every atom (the default).
    #[default]
    Legacy,
    /// The AEF for standalone atoms; leaves keep the legacy fold.
    AefStandalone,
    /// The AEF for every atom.
    Aef,
}

impl AtomFoldMode {
    /// The environment variable this switch is read from.
    pub const ENV: &'static str = "EPIGRAPH_ATOM_FOLD";

    /// Parse one value: trimmed, case-insensitive; `None` when it is none of
    /// `legacy`, `aef_standalone`, `aef`.
    #[must_use]
    pub fn parse_value(raw: &str) -> Option<Self> {
        let v = raw.trim();
        [
            ("legacy", Self::Legacy),
            ("aef_standalone", Self::AefStandalone),
            ("aef", Self::Aef),
        ]
        .into_iter()
        .find(|(spelling, _)| v.eq_ignore_ascii_case(spelling))
        .map(|(_, mode)| mode)
    }

    /// This process's setting: [`Self::ENV`], read once. Unset, blank or an
    /// unrecognised value is the default, [`Self::Legacy`] (an unrecognised
    /// one is logged): a typo never enables the AEF.
    #[must_use]
    pub fn current() -> Self {
        static CELL: std::sync::OnceLock<AtomFoldMode> = std::sync::OnceLock::new();
        *CELL.get_or_init(|| read_flag(Self::ENV, Self::parse_value))
    }
}

/// Read one switch from the environment ([`flag_value`]).
pub(crate) fn read_flag<T: Default + std::fmt::Debug>(
    env: &str,
    parse: fn(&str) -> Option<T>,
) -> T {
    flag_value(env, std::env::var(env).ok().as_deref(), parse)
}

/// One switch's value from its raw setting: unset or blank is the default; an
/// unrecognised value is the default too, and is logged.
fn flag_value<T: Default + std::fmt::Debug>(
    env: &str,
    raw: Option<&str>,
    parse: fn(&str) -> Option<T>,
) -> T {
    match raw {
        Some(raw) if !raw.trim().is_empty() => parse(raw).unwrap_or_else(|| {
            let fallback = T::default();
            tracing::warn!(flag = env, value = %raw, ?fallback, "unrecognised belief mode; using the default");
            fallback
        }),
        _ => T::default(),
    }
}

/// What a row is, for the mode filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AxiomClass {
    /// Evidence about the atom: every row no other class names.
    Evidence,
    /// The author's `truth_value` seed (`combination_method =
    /// 'truth_value_seed'`).
    Seed,
    /// An edge-factor row; `compound_source` when the edge's source is a
    /// compound.
    EdgeFactor { compound_source: bool },
    /// `propagated_from_parent` / `propagated_from_neighbor`.
    Propagated,
    /// `auto_cdst`.
    AutoCdst,
}

/// One row of an atom's AEF input, on the `binary_truth` frame (index 0 =
/// TRUE), keyed and discounted.
///
/// Only [`atom_axiom_rows`] / [`atom_axiom_rows_under`] build one, from a
/// stored row of the atom, so [`atom_fold`] can only ever fold an atom's own
/// evidence: a cache value or a compound's derived value cannot be wrapped
/// as an `AxiomRow` (SPEC §3.5 / §11.4 type split). The fields are read-only:
///
/// ```compile_fail,E0451
/// use epigraph_engine::atom_items::AxiomRow;
/// let _forged = AxiomRow {
///     row_id: todo!(),
///     atom_id: todo!(),
///     key: todo!(),
///     class: todo!(),
///     coarse: todo!(),
///     bba: todo!(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct AxiomRow {
    row_id: Uuid,
    atom_id: Uuid,
    key: ItemKey,
    class: AxiomClass,
    coarse: MassFunction,
    bba: MassFunction,
}

impl AxiomRow {
    /// The `mass_functions` row.
    #[must_use]
    pub const fn row_id(&self) -> Uuid {
        self.row_id
    }

    /// The atom it is evidence about.
    #[must_use]
    pub const fn atom_id(&self) -> Uuid {
        self.atom_id
    }

    /// Its canonical item key (SPEC §3.3).
    #[must_use]
    pub const fn key(&self) -> &ItemKey {
        &self.key
    }

    /// Its class.
    #[must_use]
    pub const fn class(&self) -> AxiomClass {
        self.class
    }

    /// Coarsened to `binary_truth`, before the reliability discount.
    #[must_use]
    pub const fn coarse(&self) -> &MassFunction {
        &self.coarse
    }

    /// Coarsened and discounted by α under the read's lens.
    #[must_use]
    pub const fn bba(&self) -> &MassFunction {
        &self.bba
    }
}

/// An atom's folded evidence. Only [`atom_fold`] builds one, so a value of
/// this type is always the fold of an atom's own rows, never a cache read or
/// a compound's derived value.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidencedInterval {
    belief: f64,
    plausibility: f64,
    pignistic_prob: f64,
    pignistic_false: f64,
    mass_on_conflict: f64,
    mass_on_missing: f64,
    theta: f64,
    items: usize,
}

impl EvidencedInterval {
    /// The fold of nothing: Bel 0, Pl 1, BetP .5 (`unproven`). Also the
    /// explicit vacuous cache the single atom-cache writer stores for an atom
    /// whose AEF input a lifecycle act removed (SPEC §4.2).
    pub(crate) const fn unproven() -> Self {
        Self {
            belief: 0.0,
            plausibility: 1.0,
            pignistic_prob: 0.5,
            pignistic_false: 0.5,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.0,
            theta: 1.0,
            items: 0,
        }
    }

    /// Bel(TRUE).
    #[must_use]
    pub const fn belief(&self) -> f64 {
        self.belief
    }

    /// Pl(TRUE).
    #[must_use]
    pub const fn plausibility(&self) -> f64 {
        self.plausibility
    }

    /// BetP(TRUE).
    #[must_use]
    pub const fn pignistic_prob(&self) -> f64 {
        self.pignistic_prob
    }

    /// BetP(FALSE).
    #[must_use]
    pub const fn pignistic_false(&self) -> f64 {
        self.pignistic_false
    }

    /// The conflict the fold saw.
    #[must_use]
    pub const fn mass_on_conflict(&self) -> f64 {
        self.mass_on_conflict
    }

    /// Open-world (`~`) mass left in the fold.
    #[must_use]
    pub const fn mass_on_missing(&self) -> f64 {
        self.mass_on_missing
    }

    /// Closed-world ignorance m({TRUE, FALSE}) left in the fold.
    #[must_use]
    pub const fn theta(&self) -> f64 {
        self.theta
    }

    /// How many items were folded.
    #[must_use]
    pub const fn items(&self) -> usize {
        self.items
    }

    /// No item was folded: the atom has no AEF input (`unproven`).
    #[must_use]
    pub const fn is_unproven(&self) -> bool {
        self.items == 0
    }
}

/// The AEF input rows of each requested atom, as `viewer` sees them, in
/// `mode`, under the lens `ctx`. Reads the process's
/// [`CompoundSourceEdges::current`]; [`atom_axiom_rows_under`] takes it
/// explicitly.
///
/// # Errors
/// A database read.
pub async fn atom_axiom_rows(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    mode: AxiomMode,
    ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, Vec<AxiomRow>>, String> {
    atom_axiom_rows_under(conn, viewer, ids, mode, ctx, CompoundSourceEdges::current()).await
}

/// [`atom_axiom_rows`] under an explicit [`CompoundSourceEdges`] setting.
///
/// The rows come from `epigraph_db::repos::atom_axiom::atom_input_rows`
/// (every 2-hypothesis frame plus `claim_validity`; no cached combination, no
/// ingest template, no row of a compound, no `edge_factor` row whose edge the
/// viewer cannot see), and then, per claim:
///
/// 1. **Hypothesis promotion** (SPEC §11.4): a promoted hypothesis
///    (`properties.hypothesis_status = 'promoted'`) reads its
///    `research_validity` copy and no `hypothesis_assessment` row; any other
///    claim reads its `hypothesis_assessment` rows and no `error_derived`
///    `research_validity` copy. Never both.
/// 2. **Compound-source edge rows** (SPEC §6.3): dropped under
///    [`CompoundSourceEdges::Excluded`], and under `Frozen` when the edge's
///    source compound is an ancestor of the claim (the self-reference guard,
///    over the viewer's leaf closure). A kept one on a positive relationship
///    is read one-sided: its m(F) moves to Θ.
/// 3. **Seed** (ruling O16): a `truth_value_seed` row is kept only while it is
///    the claim's sole input. Decided over the rows steps 1 and 2 kept (a row
///    no fold reads is no input), and before the mode filter, so `Display`
///    and `Pure` agree on it: beside an inferred row (an atom-source
///    `edge_factor`, `propagated_*`, `auto_cdst`) the seed is dropped in both,
///    which leaves `Pure` empty there, as O16's "sole non-template input"
///    reads.
/// 4. **Mode**: [`AxiomMode::Pure`] keeps evidence and the seed only.
///
/// Each kept row is coarsened to `binary_truth` (a claim at hypothesis
/// index 1 of a 2-hypothesis frame has its literals swapped;
/// `claim_validity` maps supported → T, refuted → F, uncertain → Θ),
/// discounted by α = `effective_source_strength_profiled` under
/// [`FramedBeliefContext::profile_for_frame`] of the row's own frame (the
/// lens of `ctx`, with that frame's tier), and keyed by
/// [`crate::source_dependence::item_key`] over the cited evidence the viewer
/// can see. No `asserting_paper` is passed: the ingest rekey (SPEC §4.3)
/// resolves those rows' papers, so until then an `auto_wire` row is its own
/// item.
///
/// A claim with no row left is absent from the map. The frame tier of `ctx`
/// is not read: each row's own frame tier applies.
///
/// A stored row that cannot be parsed or coarsened is skipped and logged
/// (with its row id): it is no input, so it neither fails the batch nor
/// counts against a seed. The single atom-cache writer therefore folds an
/// atom's readable rows and ignores an unreadable one.
///
/// # Errors
/// A database read.
pub async fn atom_axiom_rows_under(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    mode: AxiomMode,
    ctx: &FramedBeliefContext,
    compound_source_edges: CompoundSourceEdges,
) -> Result<HashMap<Uuid, Vec<AxiomRow>>, String> {
    let inputs = atom_input_rows(&mut *conn, viewer, ids, CLAIM_VALIDITY_FRAME_ID)
        .await
        .map_err(|e| format!("atom_input_rows: {e}"))?;
    if inputs.is_empty() {
        return Ok(HashMap::new());
    }

    // Step 1, the class of each row, and its coarsening. A row that cannot be
    // read is skipped (and logged) here, before the seed rule, so it is no
    // input and never fails another row or another atom of the batch.
    let mut kept: Vec<ReadRow> = read_rows(
        inputs
            .into_iter()
            .filter(reads_this_side_of_promotion)
            .collect(),
    )?;

    // Step 2: compound-source edge rows. Under `Excluded` none is read.
    if compound_source_edges == CompoundSourceEdges::Excluded {
        kept.retain(|(_, class, _)| !is_compound_source(*class));
    }
    // The self-reference guard: a compound-source edge row whose source
    // decomposes (through the viewer's closure) into the row's own claim.
    let sources: Vec<Uuid> = kept
        .iter()
        .filter(|(_, c, _)| is_compound_source(*c))
        .filter_map(|(r, _, _)| r.edge_source_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let closures = if sources.is_empty() {
        HashMap::new()
    } else {
        leaf_closure_batch(&mut *conn, viewer, &sources)
            .await
            .map_err(|e| format!("leaf_closure_batch: {e}"))?
    };
    kept.retain(|(r, class, _)| {
        !is_compound_source(*class)
            || !r.edge_source_id.is_some_and(|s| {
                closures
                    .get(&s)
                    .is_some_and(|leaves| leaves.contains(&r.row.claim_id))
            })
    });

    // Step 3: the seed, over the rows some fold still reads.
    let with_other_input: BTreeSet<Uuid> = kept
        .iter()
        .filter(|(_, c, _)| *c != AxiomClass::Seed)
        .map(|(r, _, _)| r.row.claim_id)
        .collect();
    kept.retain(|(r, class, _)| {
        *class != AxiomClass::Seed || !with_other_input.contains(&r.row.claim_id)
    });

    // Step 4: the mode.
    if mode == AxiomMode::Pure {
        kept.retain(|(_, class, _)| matches!(class, AxiomClass::Evidence | AxiomClass::Seed));
    }
    if kept.is_empty() {
        return Ok(HashMap::new());
    }

    let mut out: HashMap<Uuid, Vec<AxiomRow>> = HashMap::new();
    for row in key_and_discount(conn, viewer, kept, ctx).await? {
        out.entry(row.atom_id).or_default().push(row);
    }
    Ok(out)
}

/// A stored row read for a fold: the row, its class, and its BBA coarsened to
/// `binary_truth`.
pub(crate) type ReadRow = (AtomInputRow, AxiomClass, MassFunction);

/// Classify each row and coarsen it to `binary_truth`. A row that cannot be
/// read is skipped and logged (with its row id): it is no input, so it never
/// fails another row or another claim of the batch.
///
/// # Errors
/// Only when the `binary_truth` frame itself cannot be built.
pub(crate) fn read_rows(inputs: Vec<AtomInputRow>) -> Result<Vec<ReadRow>, String> {
    let binary = binary_frame()?;
    Ok(inputs
        .into_iter()
        .filter_map(|r| match coarsen_to_binary(&r, &binary) {
            Ok(coarse) => {
                let class = classify(&r);
                Some((r, class, coarse))
            }
            Err(e) => {
                tracing::warn!(
                    row = %r.row.id,
                    claim = %r.row.claim_id,
                    error = %e,
                    "atom fold: skipping a stored BBA it cannot read"
                );
                None
            }
        })
        .collect())
}

/// Discount each read row by α under the lens of `ctx` (each row's own
/// frame's tier, [`FramedBeliefContext::profile_for_frame`]) and key it by
/// its canonical source, as `viewer` sees
/// the evidence it cites. A positive compound-source edge row is read
/// one-sided first. Rows come back in input order.
///
/// # Errors
/// A database read, or a discount that errors.
pub(crate) async fn key_and_discount(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    kept: Vec<ReadRow>,
    ctx: &FramedBeliefContext,
) -> Result<Vec<AxiomRow>, String> {
    if kept.is_empty() {
        return Ok(Vec::new());
    }
    // The profile each frame's rows fold under: the lens of `ctx` with that
    // frame's tier (its two dedicated keys and its `belief_profile` object),
    // resolved once per frame. The reads are best-effort like the framed
    // read's: a failed one is no override at that tier.
    let mut profiles: HashMap<Uuid, BeliefProfile> = HashMap::new();
    for frame_id in kept
        .iter()
        .map(|(r, _, _)| r.row.frame_id)
        .collect::<std::collections::BTreeSet<_>>()
    {
        let intra = FrameRepository::get_intra_evidence_locality_factor(&mut *conn, frame_id)
            .await
            .ok()
            .flatten();
        let weights = FrameRepository::get_per_frame_evidence_type_weights(&mut *conn, frame_id)
            .await
            .ok()
            .flatten();
        let frame_row = FrameRepository::get_by_id(&mut *conn, viewer, frame_id)
            .await
            .ok()
            .flatten();
        let profile = ctx.profile_for_frame(FrameTier {
            overrides: frame_row.as_ref().and_then(|f| overrides_in(&f.properties)),
            intra_evidence_locality_factor: intra,
            evidence_type_weights: weights.as_ref(),
        });
        profiles.insert(frame_id, profile);
    }

    // The cited evidence each row's key reads, as the viewer sees it.
    let cited: Vec<Uuid> = kept
        .iter()
        .filter_map(|(r, _, _)| cited_evidence(r))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let identities = EvidenceRepository::source_identity_by_id(&mut *conn, viewer, &cited)
        .await
        .map_err(|e| format!("evidence source identity: {e}"))?;

    let mut out: Vec<AxiomRow> = Vec::with_capacity(kept.len());
    for (r, class, mut coarse) in kept {
        if let AxiomClass::EdgeFactor {
            compound_source: true,
        } = class
        {
            if r.edge_relationship
                .as_deref()
                .is_some_and(is_positive_relationship)
            {
                coarse = without_disbelief(&coarse);
            }
        }
        let profile = profiles
            .get(&r.row.frame_id)
            .ok_or_else(|| format!("no profile resolved for frame {}", r.row.frame_id))?;
        let alpha = effective_source_strength_profiled(&r.row, profile);
        let bba = combination::discount(&coarse, alpha).map_err(|e| format!("discount: {e}"))?;
        let cited = cited_evidence(&r);
        let evidence = cited.and_then(|id| {
            identities.get(&id).map(|i| ItemEvidence {
                id,
                doi: i.doi.clone(),
                source_url: i.source_url.clone(),
            })
        });
        let key = match (evidence, cited) {
            (Some(ev), _) => item_key(&r.row, Some(&ev), None),
            // Evidence cited only through the row's evidence perspective,
            // hidden from this viewer: PR-4's rule 3 (`ev:<id>`), exactly as
            // `item_key` keys a hidden `evidence_id`. The id is already on the
            // visible row, and rows citing that one evidence row stay one
            // source for this viewer too.
            (None, Some(id)) if r.row.evidence_id.is_none() => ItemKey::Evidence(id),
            (None, _) => item_key(&r.row, None, None),
        };
        out.push(AxiomRow {
            row_id: r.row.id,
            atom_id: r.row.claim_id,
            key,
            class,
            coarse,
            bba,
        });
    }
    Ok(out)
}

/// `combination_method` of the author's `truth_value` seed
/// (`epigraph_mcp::tools::ds_auto::TRUTH_VALUE_SEED_METHOD`).
const SEED_METHOD: &str = "truth_value_seed";
/// `combination_method` of the CDST auto-assessment.
const AUTO_CDST_METHOD: &str = "auto_cdst";
/// `combination_method`s of propagated BBAs.
const PROPAGATED_METHODS: [&str; 2] = ["propagated_from_parent", "propagated_from_neighbor"];
/// `combination_method` of a hypothesis' experiment-derived BBA, and of its
/// promoted `research_validity` copy.
const ERROR_DERIVED_METHOD: &str = "error_derived";
/// The frame a hypothesis is assessed on until promotion.
const HYPOTHESIS_FRAME_NAME: &str = "hypothesis_assessment";
/// The frame promotion copies a hypothesis' assessment onto.
const PROMOTED_FRAME_NAME: &str = "research_validity";

/// Step 1: a promoted hypothesis reads its promoted copy, any other claim its
/// assessment; never both. A compound's own rows (`compound_belief`) follow
/// the same rule.
pub(crate) fn reads_this_side_of_promotion(r: &AtomInputRow) -> bool {
    if r.hypothesis_promoted {
        r.frame_name != HYPOTHESIS_FRAME_NAME
    } else {
        !(r.frame_name == PROMOTED_FRAME_NAME
            && r.row.combination_method.as_deref() == Some(ERROR_DERIVED_METHOD))
    }
}

/// An edge-factor row whose edge's source is a compound.
const fn is_compound_source(class: AxiomClass) -> bool {
    matches!(
        class,
        AxiomClass::EdgeFactor {
            compound_source: true
        }
    )
}

fn classify(r: &AtomInputRow) -> AxiomClass {
    match r.row.combination_method.as_deref() {
        Some(SEED_METHOD) => AxiomClass::Seed,
        Some(AUTO_CDST_METHOD) => AxiomClass::AutoCdst,
        Some(EDGE_FACTOR_METHOD) => AxiomClass::EdgeFactor {
            compound_source: r.edge_source_is_compound,
        },
        Some(m) if PROPAGATED_METHODS.contains(&m) => AxiomClass::Propagated,
        _ => AxiomClass::Evidence,
    }
}

/// The evidence row a BBA cites: its `evidence_id`, else its
/// `perspective_id` when that is an evidence perspective (which shares its
/// evidence row's id). Any other perspective names no evidence row.
fn cited_evidence(r: &AtomInputRow) -> Option<Uuid> {
    r.row.evidence_id.or(if r.perspective_is_evidence {
        r.row.perspective_id
    } else {
        None
    })
}

/// A positive-transfer relationship (supports, corroborates, ...), by the
/// same classification the edge-factor writer uses.
fn is_positive_relationship(relationship: &str) -> bool {
    matches!(
        restriction_kind_with_profile(relationship, &RestrictionProfile::scientific()),
        RestrictionKind::Positive(_)
    )
}

fn binary_frame() -> Result<FrameOfDiscernment, String> {
    FrameOfDiscernment::new(
        BINARY_FRAME_NAME.to_string(),
        vec!["TRUE".to_string(), "FALSE".to_string()],
    )
    .map_err(|e| format!("binary frame: {e}"))
}

/// The canonical `binary_truth` frame's name.
const BINARY_FRAME_NAME: &str = "binary_truth";

/// A stored row, on `binary_truth` with index 0 = "the claim holds".
///
/// * A 2-hypothesis frame at index 0 (or with no assignment) is read as it
///   is stored. At index 1 the two hypotheses swap, in positive and
///   complement focal elements alike (a bijection, so nothing is lost).
/// * `claim_validity` {supported, refuted, uncertain} maps supported → T,
///   refuted → F and uncertain → Θ: a positive set maps to the union of its
///   images. A complement set keeps its open-world share (exact CDST):
///   complement(A) maps to the binary complement element whose positive part
///   is the image of Ω \ A, so `~` stays `~`, complement(∅) stays the
///   open-world vacuous, and complement({refuted, uncertain}) is `~{F}`
///   ("TRUE or not in the frame"), never a closed T.
fn coarsen_to_binary(
    r: &AtomInputRow,
    binary: &FrameOfDiscernment,
) -> Result<MassFunction, String> {
    let source = FrameOfDiscernment::new(r.frame_name.clone(), r.frame_hypotheses.clone())
        .map_err(|e| format!("frame {}: {e}", r.frame_name))?;
    let stored = MassFunction::from_json_masses(source.clone(), &r.row.masses)
        .map_err(|e| format!("parse stored BBA {}: {e}", r.row.id))?;
    let mut out: BTreeMap<FocalElement, f64> = BTreeMap::new();
    if r.row.frame_id == CLAIM_VALIDITY_FRAME_ID {
        let full = source.full_set();
        let image = |s: &BTreeSet<usize>| -> BTreeSet<usize> {
            s.iter()
                .flat_map(|&i| match i {
                    0 => vec![0],
                    1 => vec![1],
                    _ => vec![0, 1],
                })
                .collect()
        };
        let binary_full = binary.full_set();
        for (fe, &m) in stored.focal_elements() {
            let to = if fe.complement {
                // complement(A) is "outside A, or not in the frame": the image
                // of the frame's own part (Ω \ A), plus the open world, which
                // on binary_truth is complement(Ω₂ \ image(Ω \ A)). A = Ω
                // gives `~` (missing), A = ∅ gives the open-world vacuous.
                let inside = image(&full.difference(&fe.subset).copied().collect());
                FocalElement::negative(binary_full.difference(&inside).copied().collect())
            } else {
                FocalElement::positive(image(&fe.subset))
            };
            *out.entry(to).or_insert(0.0) += m;
        }
    } else {
        let swap = resolve_hypothesis_index(r.hypothesis_index, 2) == 1;
        for (fe, &m) in stored.focal_elements() {
            let subset = if swap {
                fe.subset.iter().map(|&i| 1 - i.min(1)).collect()
            } else {
                fe.subset.clone()
            };
            let to = FocalElement {
                subset,
                complement: fe.complement,
            };
            *out.entry(to).or_insert(0.0) += m;
        }
    }
    Ok(MassFunction::from_raw(binary.clone(), out))
}

/// The one-sided read of a frozen positive compound-source row: m(F) moves
/// to Θ, so the row can raise its target's belief and never deny it.
fn without_disbelief(m: &MassFunction) -> MassFunction {
    let frame = m.frame().clone();
    let f = FocalElement::positive(BTreeSet::from([1]));
    let theta = FocalElement::theta(&frame);
    let mut out: BTreeMap<FocalElement, f64> = BTreeMap::new();
    for (fe, &v) in m.focal_elements() {
        let to = if *fe == f { theta.clone() } else { fe.clone() };
        *out.entry(to).or_insert(0.0) += v;
    }
    MassFunction::from_raw(frame, out)
}

/// Fold ONE atom's AEF rows by item (SPEC §3.3): the rows are partitioned by
/// [`crate::source_dependence::item_partition`] (one key's pure-support rows
/// keep their max, its refutations are a separate `#neg` item, a mixed row is
/// its own item), and the items combine by Dempster with exact CDST
/// open-world semantics (`~` meets anything else as conflict, which the fold
/// normalises away and reports as the conflict it saw).
///
/// No rows is the vacuous interval, [`EvidencedInterval::is_unproven`].
///
/// At total conflict between dogmatic items (K = 1) the fold does not fail:
/// `combine_multiple` falls back to Yager's closed rule, so the conflict mass
/// goes to Θ (Bel 0, Pl 1). A derivation that must agree with this fold on
/// one leaf (D11) has to use the same K = 1 convention.
///
/// # Errors
/// Rows of more than one atom, or a Dempster step that errors.
pub fn atom_fold(rows: &[AxiomRow]) -> Result<EvidencedInterval, String> {
    let Some(first) = rows.first() else {
        return Ok(EvidencedInterval::unproven());
    };
    let atom = first.atom_id;
    if rows.iter().any(|r| r.atom_id != atom) {
        return Err(format!(
            "atom_fold: rows of more than one atom (first {atom})"
        ));
    }
    let items = item_partition(
        rows.iter()
            .map(|r| KeyedBba {
                row_id: r.row_id,
                atom_id: atom,
                key: r.key.clone(),
                bba: r.bba.clone(),
            })
            .collect(),
    );
    let for_fold: Vec<MassFunction> = items.iter().filter_map(|it| it.on(atom).cloned()).collect();
    let n = for_fold.len();
    let (combined, conflict) =
        dempster_across_items(for_fold, 0.9).map_err(|e| format!("atom_fold: {e}"))?;
    let t = FocalElement::positive(BTreeSet::from([0]));
    Ok(EvidencedInterval {
        belief: measures::belief(&combined, &t),
        plausibility: measures::plausibility(&combined, &t),
        pignistic_prob: measures::pignistic_probability(&combined, 0),
        pignistic_false: measures::pignistic_probability(&combined, 1),
        mass_on_conflict: conflict,
        mass_on_missing: combined.mass_of_missing(),
        theta: combined.mass_of(&FocalElement::theta(combined.frame())),
        items: n,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_typo_never_selects_a_fold_mode() {
        for raw in ["aef ", " AEF", "Aef_Standalone", "LEGACY"] {
            assert!(AtomFoldMode::parse_value(raw).is_some(), "{raw:?}");
        }
        for raw in ["aef-standalone", "aefstandalone", "on", "true", "aef_all"] {
            assert_eq!(AtomFoldMode::parse_value(raw), None, "{raw:?}");
        }
        assert_eq!(
            CompoundSourceEdges::parse_value("excluded "),
            Some(CompoundSourceEdges::Excluded)
        );
        assert_eq!(CompoundSourceEdges::parse_value("exclude"), None);
    }

    /// The environment wrapper: unset, blank and unrecognised settings are
    /// the default; a recognised one is parsed (trimmed, any case).
    #[test]
    fn an_unset_blank_or_unrecognised_switch_is_the_default() {
        let fold = |raw| flag_value(AtomFoldMode::ENV, raw, AtomFoldMode::parse_value);
        let edges = |raw| {
            flag_value(
                CompoundSourceEdges::ENV,
                raw,
                CompoundSourceEdges::parse_value,
            )
        };
        for raw in [
            None,
            Some(""),
            Some("   "),
            Some("aef-standalone"),
            Some("on"),
        ] {
            assert_eq!(fold(raw), AtomFoldMode::Legacy, "{raw:?}");
        }
        assert_eq!(fold(Some(" AEF ")), AtomFoldMode::Aef);
        assert_eq!(fold(Some("aef_standalone")), AtomFoldMode::AefStandalone);
        for raw in [None, Some(" "), Some("exclude")] {
            assert_eq!(edges(raw), CompoundSourceEdges::Frozen, "{raw:?}");
        }
        assert_eq!(edges(Some("Excluded")), CompoundSourceEdges::Excluded);
    }

    /// Ruling O24 is ruled yes: the process settings vacate an atom whose AEF
    /// input a lifecycle act removed.
    #[test]
    fn the_process_settings_carry_ruling_o24() {
        assert!(crate::edge_factor::AtomCacheSettings::current().vacate_on_evidence_removal);
    }

    #[test]
    fn every_default_is_todays_behaviour() {
        assert_eq!(AtomFoldMode::default(), AtomFoldMode::Legacy);
        assert_eq!(CompoundSourceEdges::default(), CompoundSourceEdges::Frozen);
    }
}
