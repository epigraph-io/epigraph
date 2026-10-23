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
use epigraph_db::{EvidenceRepository, FrameRepository, MassFunctionRow};
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};

use crate::belief_query::FramedBeliefContext;
use crate::edge_factor::{
    effective_source_strength_with_perspective, resolve_hypothesis_index, PerspectiveReliability,
    CLAIM_VALIDITY_FRAME_ID,
};
use crate::sheaf::{restriction_kind_with_profile, RestrictionKind, RestrictionProfile};
use crate::source_dependence::{
    item_key, item_partition, ItemEvidence, ItemKey, KeyedBba, EDGE_FACTOR_METHOD,
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

/// Read one switch from the environment: unset or blank is the default; an
/// unrecognised value is the default too, and is logged.
fn read_flag<T: Default + std::fmt::Debug>(env: &str, parse: fn(&str) -> Option<T>) -> T {
    match std::env::var(env) {
        Ok(raw) if !raw.trim().is_empty() => parse(&raw).unwrap_or_else(|| {
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
#[derive(Debug, Clone)]
pub struct AxiomRow {
    /// The `mass_functions` row.
    pub row_id: Uuid,
    /// The atom it is evidence about.
    pub atom_id: Uuid,
    /// Its canonical item key (SPEC §3.3).
    pub key: ItemKey,
    /// Its class.
    pub class: AxiomClass,
    /// Coarsened to `binary_truth`, before the reliability discount.
    pub coarse: MassFunction,
    /// Coarsened and discounted by α under the read's lens.
    pub bba: MassFunction,
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
/// A database read or a stored BBA that cannot be parsed.
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
/// ingest template, no row of a compound), and then, per claim:
///
/// 1. **Hypothesis promotion** (SPEC §11.4): a promoted hypothesis
///    (`properties.hypothesis_status = 'promoted'`) reads its
///    `research_validity` copy and no `hypothesis_assessment` row; any other
///    claim reads its `hypothesis_assessment` rows and no `error_derived`
///    `research_validity` copy. Never both.
/// 2. **Seed** (ruling O16): a `truth_value_seed` row is kept only while it is
///    the claim's sole input. Decided over the whole input, before the mode
///    and compound-source filters, so `Display` and `Pure` agree on it.
/// 3. **Compound-source edge rows** (SPEC §6.3): dropped under
///    [`CompoundSourceEdges::Excluded`], and under `Frozen` when the edge's
///    source compound is an ancestor of the claim (the self-reference guard,
///    over the viewer's leaf closure). A kept one on a positive relationship
///    is read one-sided: its m(F) moves to Θ.
/// 4. **Mode**: [`AxiomMode::Pure`] keeps evidence and the seed only.
///
/// Each kept row is coarsened to `binary_truth` (a claim at hypothesis
/// index 1 of a 2-hypothesis frame has its literals swapped;
/// `claim_validity` maps supported → T, refuted → F, uncertain → Θ),
/// discounted by α = `effective_source_strength_with_perspective` on the
/// row's own frame under the lens of `ctx`, and keyed by
/// [`crate::source_dependence::item_key`] over the cited evidence the viewer
/// can see. No `asserting_paper` is passed: the ingest rekey (SPEC §4.3)
/// resolves those rows' papers, so until then an `auto_wire` row is its own
/// item.
///
/// A claim with no row left is absent from the map. The frame-scoped fields
/// of `ctx` are not read: each row's own frame overrides apply.
///
/// # Errors
/// A database read or a stored BBA that cannot be parsed.
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

    // Steps 1-4, per claim, before any further read.
    let mut by_claim: HashMap<Uuid, Vec<AtomInputRow>> = HashMap::new();
    for r in inputs {
        by_claim.entry(r.row.claim_id).or_default().push(r);
    }
    let mut kept: Vec<(AtomInputRow, AxiomClass)> = Vec::new();
    for (_, rows) in by_claim {
        let rows: Vec<(AtomInputRow, AxiomClass)> = rows
            .into_iter()
            .filter(reads_this_side_of_promotion)
            .map(|r| {
                let class = classify(&r);
                (r, class)
            })
            .collect();
        let has_other_input = rows.iter().any(|(_, c)| *c != AxiomClass::Seed);
        kept.extend(rows.into_iter().filter(|(_, class)| {
            !(has_other_input && *class == AxiomClass::Seed)
                && match class {
                    AxiomClass::EdgeFactor {
                        compound_source: true,
                    } => compound_source_edges == CompoundSourceEdges::Frozen,
                    _ => true,
                }
                && (mode == AxiomMode::Display
                    || matches!(class, AxiomClass::Evidence | AxiomClass::Seed))
        }));
    }

    // The self-reference guard: a compound-source edge row whose source
    // decomposes (through the viewer's closure) into the row's own claim.
    let sources: Vec<Uuid> = kept
        .iter()
        .filter(|(_, c)| {
            matches!(
                c,
                AxiomClass::EdgeFactor {
                    compound_source: true
                }
            )
        })
        .filter_map(|(r, _)| r.edge_source_id)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let closures = if sources.is_empty() {
        HashMap::new()
    } else {
        leaf_closure_batch(&mut *conn, viewer, &sources)
            .await
            .map_err(|e| format!("leaf_closure_batch: {e}"))?
    };
    kept.retain(|(r, class)| {
        !matches!(
            class,
            AxiomClass::EdgeFactor {
                compound_source: true
            }
        ) || !r.edge_source_id.is_some_and(|s| {
            closures
                .get(&s)
                .is_some_and(|leaves| leaves.contains(&r.row.claim_id))
        })
    });
    if kept.is_empty() {
        return Ok(HashMap::new());
    }

    // Per-frame reliability overrides, once per frame.
    let mut overrides: HashMap<Uuid, FrameOverrides> = HashMap::new();
    for frame_id in kept
        .iter()
        .map(|(r, _)| r.row.frame_id)
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
        overrides.insert(frame_id, (intra, weights));
    }

    // The cited evidence each row's key reads, as the viewer sees it.
    let cited: Vec<Uuid> = kept
        .iter()
        .filter_map(|(r, _)| cited_evidence(&r.row))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let identities = EvidenceRepository::source_identity_by_id(&mut *conn, viewer, &cited)
        .await
        .map_err(|e| format!("evidence source identity: {e}"))?;

    let binary = binary_frame()?;
    let no_lens = PerspectiveReliability::default();
    let mut out: HashMap<Uuid, Vec<AxiomRow>> = HashMap::new();
    for (r, class) in kept {
        let mut coarse = coarsen_to_binary(&r, &binary)?;
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
        let (intra, weights) = overrides.get(&r.row.frame_id).cloned().unwrap_or_default();
        let alpha = effective_source_strength_with_perspective(
            &r.row,
            intra,
            weights.as_ref(),
            &ctx.calibration,
            ctx.perspective.as_ref().unwrap_or(&no_lens),
        );
        let bba = combination::discount(&coarse, alpha).map_err(|e| format!("discount: {e}"))?;
        let evidence = cited_evidence(&r.row).and_then(|id| {
            identities.get(&id).map(|i| ItemEvidence {
                id,
                doi: i.doi.clone(),
                source_url: i.source_url.clone(),
            })
        });
        let key = item_key(&r.row, evidence.as_ref(), None);
        out.entry(r.row.claim_id).or_default().push(AxiomRow {
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

/// A frame's `(intra_evidence_locality_factor, evidence_type_weights)`.
type FrameOverrides = (Option<f64>, Option<HashMap<String, f64>>);

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
/// assessment; never both.
fn reads_this_side_of_promotion(r: &AtomInputRow) -> bool {
    if r.hypothesis_promoted {
        r.frame_name != HYPOTHESIS_FRAME_NAME
    } else {
        !(r.frame_name == PROMOTED_FRAME_NAME
            && r.row.combination_method.as_deref() == Some(ERROR_DERIVED_METHOD))
    }
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
/// `perspective_id` (an evidence perspective shares its evidence row's id; a
/// perspective that is not one names no evidence row and reads as none).
fn cited_evidence(row: &MassFunctionRow) -> Option<Uuid> {
    row.evidence_id.or(row.perspective_id)
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
///   images; open-world `~` stays `~`; any other complement set is read as
///   its classical complement first.
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
        for (fe, &m) in stored.focal_elements() {
            let to = if fe.complement && fe.subset == full {
                FocalElement::missing(binary)
            } else if fe.complement && fe.subset.is_empty() {
                FocalElement::vacuous()
            } else if fe.complement {
                FocalElement::positive(image(&full.difference(&fe.subset).copied().collect()))
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
/// # Errors
/// Rows of more than one atom, or a Dempster step that fails (total conflict
/// between dogmatic items).
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
    let mut for_fold: Vec<MassFunction> =
        items.iter().filter_map(|it| it.on(atom).cloned()).collect();
    let n = for_fold.len();
    let (combined, conflict) = if n == 1 {
        let only = for_fold.pop().expect("n == 1");
        let k = only.mass_of_conflict();
        (only, k)
    } else {
        let (combined, reports) =
            combination::combine_multiple(&for_fold, 0.9).map_err(|e| format!("atom_fold: {e}"))?;
        let k = combination::fold_conflict(&combined, &reports);
        (combined, k)
    };
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

    #[test]
    fn every_default_is_todays_behaviour() {
        assert_eq!(AtomFoldMode::default(), AtomFoldMode::Legacy);
        assert_eq!(CompoundSourceEdges::default(), CompoundSourceEdges::Frozen);
    }
}
