//! A compound's belief, derived per viewer from its visible leaves
//! (atom-level belief program, SPEC §2.2, §3.2, §3.3, §3.6, §7.1, §8).
//!
//! A compound carries no evidence of its own: its belief is the query "every
//! one of my leaves holds", answered by R-DEP
//! ([`epigraph_ds::conjunction::conj_belief`]) over the evidence items of the
//! leaves the viewer can see. This module reads, for one batch of claims:
//!
//! 1. the viewer-spliced leaf closure of each compound (PR-2), so a mid node
//!    is derived over its own flattened leaves and a hidden leaf is simply
//!    not there (SPEC §8 T1: no field counts it);
//! 2. ONE batched [`atom_axiom_rows`] read in [`AxiomMode::Display`] under the
//!    lens, the same rows each leaf's own fold reads (D11), partitioned into
//!    items ONCE for the batch by the canonical item key, so a compound's
//!    items never depend on which other compounds share the batch;
//! 3. for a leaf with no AEF input but a kept cache, one `legacy:<atom>`
//!    pseudo-item built from the cache interval;
//! 4. the compound's `not_all` valuation (SPEC §3.6): its own unmoved
//!    refutation rows and the live refuting edges into it, minus an edge
//!    whose source shares a visible leaf with the compound and an edge whose
//!    source already refutes one of its visible leaves through a wired edge
//!    (a retargeted parent), each counted.
//!
//! A spine compound (level 0/1, or more than 16 visible leaves) gets a
//! profile of its leaves, never a conjunction. Exactly one refuting edge
//! between two visible leaves uses the single-negative-sibling closed form;
//! two or more serve the Fréchet envelope, labelled `internally_contested`,
//! met by the compound's `not_all` valuation.
//!
//! Nothing here writes. The derived value is never stored and never fed to a
//! fold: it is a [`DerivedBelief`], not an
//! [`EvidencedInterval`](crate::atom_items::EvidencedInterval).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use uuid::Uuid;

use epigraph_db::repos::claim_role::{leaf_closure_batch, roles_batch, ClaimRole};
use epigraph_db::repos::compound_valuation::{
    atom_cache_batch, compound_own_rows, refuting_edges_into, AtomCache, RefutingEdge,
};
use epigraph_ds::conjunction::{
    conj_belief, joint_bel, not_all_closed_form, single_negative_sibling, ConjResult, Frechet,
    Item, Lit,
};
use epigraph_ds::{DsError, FocalElement, MassFunction};

use crate::atom_items::{
    atom_axiom_rows, atom_fold_under, key_and_discount, read_rows, reads_this_side_of_promotion,
    AxiomClass, AxiomMode, AxiomRow,
};
use crate::belief_profile::BeliefProfile;
use crate::belief_query::FramedBeliefContext;
use crate::belief_view::{
    compound_ready, Basis, BeliefView, DerivedBelief, Envelope, InputSummary, LeafProfile,
    LeafState, NotAll, Summary3, AEF_RULE, DEP_RULE, LEGACY_RULE, PRODUCT_FRAME_BETP, PROFILE_RULE,
};
use crate::edge_factor::CLAIM_VALIDITY_FRAME_ID;
use crate::sheaf::{restriction_kind_with_profile, RestrictionKind, RestrictionProfile};
use crate::source_dependence::{item_partition, ItemId, ItemKey, ItemSide, KeyedBba};

/// Tolerance for a mass that is zero.
const ZERO: f64 = 1e-12;

// ── per-leaf inputs ─────────────────────────────────────────────────────────

/// What a batch knows about each atom it reads: its Display rows, and for an
/// atom with none, its kept cache; and the profile of the lens they were read
/// under, which their fold takes.
struct AtomInputs {
    rows: HashMap<Uuid, Vec<AxiomRow>>,
    caches: HashMap<Uuid, AtomCache>,
    profile: BeliefProfile,
}

impl AtomInputs {
    async fn read(
        conn: &mut sqlx::PgConnection,
        viewer: &epigraph_db::visibility::Viewer,
        atoms: &BTreeSet<Uuid>,
        ctx: &FramedBeliefContext,
    ) -> Result<Self, String> {
        let ids: Vec<Uuid> = atoms.iter().copied().collect();
        let rows = atom_axiom_rows(&mut *conn, viewer, &ids, AxiomMode::Display, ctx).await?;
        let uncovered: Vec<Uuid> = ids
            .iter()
            .filter(|id| !rows.contains_key(id))
            .copied()
            .collect();
        let caches = atom_cache_batch(&mut *conn, viewer, &uncovered)
            .await
            .map_err(|e| format!("atom_cache_batch: {e}"))?;
        Ok(Self {
            rows,
            caches,
            profile: ctx.profile().clone(),
        })
    }

    /// The leaf's state for the readiness predicates (SPEC §7.1).
    fn state(&self, atom: Uuid) -> LeafState {
        if self.rows.contains_key(&atom) {
            LeafState::Axiom
        } else if self.caches.contains_key(&atom) {
            LeafState::Legacy
        } else {
            LeafState::Unproven
        }
    }

    /// The atom's served value as the derivation reads it: its fold, its kept
    /// cache, or nothing (Bel 0).
    fn view(&self, atom: Uuid) -> Result<BeliefView, String> {
        Ok(match self.state(atom) {
            LeafState::Axiom => {
                let rows = &self.rows[&atom];
                let f = atom_fold_under(rows, &self.profile)?;
                BeliefView {
                    claim_id: atom,
                    basis: Basis::Axiom,
                    bel: f.belief(),
                    pl: f.plausibility(),
                    betp: f.pignistic_prob(),
                    nr: (f.plausibility() + f.mass_on_missing()).min(1.0),
                    derived: None,
                    profile: None,
                    rule_version: AEF_RULE,
                    inputs: InputSummary {
                        items: f.items(),
                        legacy_compound_edge_items: count_compound_edge_keys(rows),
                    },
                }
            }
            LeafState::Legacy => {
                let c = self.caches[&atom];
                BeliefView {
                    claim_id: atom,
                    basis: Basis::Legacy,
                    bel: c.belief,
                    pl: c.plausibility,
                    betp: c.pignistic_prob.unwrap_or(c.belief),
                    nr: (c.plausibility + legacy_open_world(&c)).min(1.0),
                    derived: None,
                    profile: None,
                    rule_version: LEGACY_RULE,
                    inputs: InputSummary::default(),
                }
            }
            LeafState::Unproven => BeliefView {
                claim_id: atom,
                basis: Basis::Unproven,
                bel: 0.0,
                pl: 1.0,
                betp: 0.5,
                nr: 1.0,
                derived: None,
                profile: None,
                rule_version: AEF_RULE,
                inputs: InputSummary::default(),
            },
        })
    }
}

/// Whether a row is a frozen edge-factor row whose edge source is a compound.
const fn is_compound_edge(class: AxiomClass) -> bool {
    matches!(
        class,
        AxiomClass::EdgeFactor {
            compound_source: true
        }
    )
}

/// How many distinct item keys among an atom's rows carry a frozen
/// compound-source edge row.
fn count_compound_edge_keys(rows: &[AxiomRow]) -> usize {
    rows.iter()
        .filter(|r| is_compound_edge(r.class()))
        .map(AxiomRow::key)
        .collect::<BTreeSet<_>>()
        .len()
}

/// The open-world mass of a kept cache, capped so the pseudo-item stays a
/// mass function: `~` cannot exceed the mass outside Pl.
fn legacy_open_world(c: &AtomCache) -> f64 {
    c.mass_on_missing
        .unwrap_or(0.0)
        .clamp(0.0, (1.0 - c.plausibility).max(0.0))
}

/// The `legacy:<atom>` pseudo-item of a leaf served from its cache (SPEC §3.3).
///
/// The served measures exclude `~` from Pl (`measures::plausibility` sums
/// positive focal elements only), so a cache's 1 − Pl is m(F) + m(`~`). The
/// item is therefore {T: Bel, `~`: `mass_on_missing`, F: 1 − Pl − `~`,
/// Θ: Pl − Bel}, which reproduces the cache's Bel and Pl on a single-leaf
/// query (D11). Reading F as 1 − Pl, with `~` beside it, would count the
/// open-world mass twice and serve a lower Pl than the leaf shows.
fn legacy_item(atom: Uuid, c: &AtomCache) -> Result<Item<Uuid>, String> {
    let o = legacy_open_world(c);
    let f = (1.0 - c.plausibility - o).max(0.0);
    let t = c.belief.clamp(0.0, (1.0 - f - o).max(0.0));
    Item::mixed(atom, t, f, o).map_err(|e| format!("legacy item for {atom}: {e}"))
}

// ── items ───────────────────────────────────────────────────────────────────

/// One evidence item of the batch, ready for the conjunction.
struct BatchItem {
    id: ItemId,
    item: Item<Uuid>,
    atoms: BTreeSet<Uuid>,
    /// A frozen compound-source edge row is in it.
    compound_edge: bool,
    /// Some mass could not be represented exactly (moved to Θ).
    approximate: bool,
}

/// Read one coarsened, discounted `binary_truth` BBA as (t, f, o) for the
/// conjunction's alphabet, and whether any mass was not representable.
/// Conflict (∅) mass is normalized away, which is what Dempster does with it
/// in any fold; mass on any other element the alphabet cannot spell (a
/// complement set other than `~`) moves to Θ and is reported.
fn tfo(m: &MassFunction) -> (f64, f64, f64, bool) {
    let frame = m.frame();
    let t_e = FocalElement::positive(BTreeSet::from([0]));
    let f_e = FocalElement::positive(BTreeSet::from([1]));
    let theta = FocalElement::theta(frame);
    let missing = FocalElement::missing(frame);
    let (mut t, mut f, mut o, mut empty, mut other) = (0.0, 0.0, 0.0, 0.0, 0.0);
    for (fe, &v) in m.focal_elements() {
        if *fe == t_e {
            t += v;
        } else if *fe == f_e {
            f += v;
        } else if *fe == missing {
            o += v;
        } else if *fe == theta {
            // Θ is the rest.
        } else if fe.is_conflict() {
            empty += v;
        } else {
            other += v;
        }
    }
    let keep = 1.0 - empty;
    if empty > ZERO && keep > ZERO {
        (t, f, o) = (t / keep, f / keep, o / keep);
    }
    (t, f, o, other > ZERO)
}

/// Partition every Display row of the batch into items (ONE partition, so a
/// compound's items never depend on its batch) and convert each.
fn batch_items(rows: &HashMap<Uuid, Vec<AxiomRow>>) -> Result<Vec<BatchItem>, String> {
    let mut all: Vec<&AxiomRow> = rows.values().flatten().collect();
    // A fixed row order (atom, then row id), so an item lists its atoms in
    // the same order whatever the batch.
    all.sort_by_key(|r| (r.atom_id(), r.row_id()));
    let compound_edge_keys: BTreeSet<&ItemKey> = all
        .iter()
        .filter(|r| is_compound_edge(r.class()))
        .map(|r| r.key())
        .collect();
    let keyed = item_partition(
        all.iter()
            .map(|r| KeyedBba {
                row_id: r.row_id(),
                atom_id: r.atom_id(),
                key: r.key().clone(),
                bba: r.bba().clone(),
            })
            .collect(),
    );
    let mut out = Vec::with_capacity(keyed.len());
    for k in keyed {
        let mut approximate = false;
        let item = match k.id.side {
            ItemSide::Support | ItemSide::Refute => {
                let positive = k.id.side == ItemSide::Support;
                let mut entries = Vec::with_capacity(k.atoms.len());
                for (atom, m) in &k.atoms {
                    let (t, f, o, other) = tfo(m);
                    approximate |= other;
                    let lit = if positive {
                        Lit::pos(*atom)
                    } else {
                        Lit::neg(*atom)
                    };
                    entries.push((lit, if positive { t } else { f }, o));
                }
                Item::new(entries)
            }
            ItemSide::Own(_) => {
                let (atom, m) = &k.atoms[0];
                let (t, f, o, other) = tfo(m);
                approximate |= other;
                Item::mixed(*atom, t, f, o)
            }
        }
        .map_err(|e| format!("item {}: {e}", k.id.key))?;
        out.push(BatchItem {
            compound_edge: compound_edge_keys.contains(&k.id.key),
            atoms: k.atoms.iter().map(|(a, _)| *a).collect(),
            id: k.id,
            item,
            approximate,
        });
    }
    // A fixed item order, so the conjunction sums in the same order whatever
    // the batch.
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// The items of one query over `leaves`: every batch item touching a leaf,
/// minus the item keyed by `drop_edge`, plus a pseudo-item per `Legacy` leaf.
struct QueryItems {
    items: Vec<Item<Uuid>>,
    compound_edges: usize,
    approximate: bool,
}

fn query_items(
    leaves: &[Uuid],
    batch: &[BatchItem],
    inputs: &AtomInputs,
    drop_edge: Option<Uuid>,
) -> Result<QueryItems, String> {
    let set: BTreeSet<Uuid> = leaves.iter().copied().collect();
    let mut q = QueryItems {
        items: Vec::new(),
        compound_edges: 0,
        approximate: false,
    };
    for b in batch {
        if b.atoms.is_disjoint(&set) || drop_edge.is_some_and(|e| b.id.key == ItemKey::Edge(e)) {
            continue;
        }
        q.items.push(b.item.clone());
        q.compound_edges += usize::from(b.compound_edge);
        q.approximate |= b.approximate;
    }
    for &leaf in leaves {
        if inputs.state(leaf) == LeafState::Legacy {
            q.items.push(legacy_item(leaf, &inputs.caches[&leaf])?);
        }
    }
    Ok(q)
}

// ── the conjunction ─────────────────────────────────────────────────────────

/// R-DEP over `leaves`, with a `not_all` valuation of mass `m`.
///
/// At total conflict (K = 1 between dogmatic items) the atom fold does not
/// fail: it falls back to Yager's closed rule, which moves the conflict to
/// ignorance (Bel 0, Pl 1). The conjunction uses the same convention on the
/// whole joint (every leaf free: Bel 0, Pl 1, NR 1, product-frame `BetP`
/// 2⁻ⁿ, K 1, labelled inexact), then meets the `not_all` valuation, so a
/// single-leaf query agrees with the leaf's own fold (D11).
fn conj(leaves: &[Uuid], items: &[Item<Uuid>], m: f64) -> Result<ConjResult, String> {
    let query: Vec<Lit<Uuid>> = leaves.iter().copied().map(Lit::pos).collect();
    match conj_belief(&query, items, m) {
        Ok(r) => Ok(r),
        Err(DsError::TotalConflict) => {
            let n = i32::try_from(leaves.len()).unwrap_or(i32::MAX);
            let yager = ConjResult {
                bel: 0.0,
                pl: 1.0,
                nr: 1.0,
                betp: 0.5_f64.powi(n),
                bel_or: 0.0,
                k: 1.0,
                frechet: Frechet {
                    lo: 0.0,
                    hi: 1.0,
                    hi_nr: 1.0,
                },
                exact: false,
                open_world: false,
            };
            if m > 0.0 {
                not_all_closed_form(&yager, m).map_err(|e| format!("not_all: {e}"))
            } else {
                Ok(yager)
            }
        }
        Err(e) => Err(format!("conj_belief: {e}")),
    }
}

/// The negative restriction strength of a refuting relationship, from the
/// scientific profile the edge-factor writer uses (contradicts .9, refutes
/// .8).
fn negative_strength(relationship: &str) -> f64 {
    match restriction_kind_with_profile(relationship, &RestrictionProfile::scientific()) {
        RestrictionKind::Negative(f) => f,
        _ => 0.0,
    }
}

/// One compound's served conjunction, after its negative sibling edges.
struct Served {
    r: ConjResult,
    internally_contested: bool,
    compound_edges: usize,
    items: usize,
    approximate: bool,
}

/// The single-negative-sibling closed form (SPEC §3.3): drop the edge's own
/// frozen BBA from its target, run R-DEP, and meet the pair through the
/// closed form. `None` when it cannot be evaluated exactly (over the cap, or
/// a total conflict the closed form cannot meet).
fn one_sibling(
    leaves: &[Uuid],
    batch: &[BatchItem],
    inputs: &AtomInputs,
    edge: &RefutingEdge,
    m: f64,
) -> Result<Option<Served>, String> {
    let q = query_items(leaves, batch, inputs, Some(edge.id))?;
    let pos = |id: Uuid| leaves.iter().position(|l| *l == id);
    let (Some(i), Some(j)) = (pos(edge.source_id), pos(edge.target_id)) else {
        return Ok(None);
    };
    let query: Vec<Lit<Uuid>> = leaves.iter().copied().map(Lit::pos).collect();
    let Ok(base) = conj_belief(&query, &q.items, m) else {
        return Ok(None);
    };
    let Ok(pair) = joint_bel(&query, &q.items, m, &[i, j]) else {
        return Ok(None);
    };
    let Ok(r) = single_negative_sibling(&base, pair, negative_strength(&edge.relationship)) else {
        return Ok(None);
    };
    Ok(Some(Served {
        r,
        internally_contested: false,
        compound_edges: q.compound_edges,
        items: q.items.len(),
        approximate: q.approximate,
    }))
}

/// The Fréchet envelope of the leaves' marginals (SPEC §3.3, R-FRE), met by
/// the compound's `not_all` valuation of mass `m` (SPEC §3.6).
///
/// For any coupling of the marginals, the valuation's closed form (ow = 0)
/// gives Bel' = Bel·s(Bel), Pl' = Pl·s(Bel) and NR' = NR·s(Bel), with
/// s(b) = (1 − m)/(1 − m·b). Bel' grows with Bel, so the floor is `lo` met by
/// the valuation at Bel = `lo`. s grows with Bel, and Bel(∧L) ≤ min Belᵢ, so
/// the ceilings are `hi` and `hi_nr` scaled by s(min Belᵢ). The result still
/// contains every coupling's value; without the valuation (m = 0) it is the
/// plain envelope. Taking the envelope of the joint WITH the valuation instead
/// would lose it: each leaf's own marginal reads a `not_all` state as
/// unflagged, so `hi` and `hi_nr` stay where they were.
fn envelope_with_not_all(
    leaves: &[Uuid],
    items: &[Item<Uuid>],
    m: f64,
) -> Result<ConjResult, String> {
    let base = conj(leaves, items, 0.0)?;
    let Frechet { lo, hi, hi_nr } = base.frechet;
    let (lo, hi, hi_nr) = if m > 0.0 {
        let query: Vec<Lit<Uuid>> = leaves.iter().copied().map(Lit::pos).collect();
        // The largest Bel the conjunction can have: min Belᵢ (and never above
        // `hi`), each Belᵢ taken in the same joint as the envelope, or alone
        // when the joint cannot be evaluated.
        let mut bel_max = hi;
        for (i, &leaf) in leaves.iter().enumerate() {
            let bel_i = match joint_bel(&query, items, 0.0, &[i]) {
                Ok(b) => b,
                Err(_) => conj(&[leaf], items, 0.0)?.bel,
            };
            bel_max = bel_max.min(bel_i);
        }
        let s = |b: f64| {
            if m >= 1.0 {
                0.0
            } else {
                (1.0 - m) / (1.0 - m * b)
            }
        };
        (lo * s(lo), hi * s(bel_max), hi_nr * s(bel_max))
    } else {
        (lo, hi, hi_nr)
    };
    Ok(ConjResult {
        bel: lo,
        pl: hi,
        nr: hi_nr,
        betp: 0.5 * (lo + hi),
        frechet: Frechet { lo, hi, hi_nr },
        exact: false,
        ..base
    })
}

fn serve(
    leaves: &[Uuid],
    batch: &[BatchItem],
    inputs: &AtomInputs,
    siblings: &[&RefutingEdge],
    m: f64,
) -> Result<Served, String> {
    if let [edge] = siblings {
        if let Some(served) = one_sibling(leaves, batch, inputs, edge, m)? {
            return Ok(served);
        }
    }
    let q = query_items(leaves, batch, inputs, None)?;
    let contested = !siblings.is_empty();
    let r = if contested {
        // Two or more negative siblings (or one the closed form cannot meet):
        // the Fréchet envelope only (SPEC §3.3), met by `not_all`.
        envelope_with_not_all(leaves, &q.items, m)?
    } else {
        conj(leaves, &q.items, m)?
    };
    Ok(Served {
        r,
        internally_contested: contested,
        compound_edges: q.compound_edges,
        items: q.items.len(),
        approximate: q.approximate,
    })
}

// ── not_all ─────────────────────────────────────────────────────────────────

/// Each compound's own-row refutation masses (SPEC §3.6), per item key (the
/// max within a key), as the viewer sees them.
///
/// Every visible row of the compound that is evidence about it (not an
/// edge-factor, seed, propagated or `auto_cdst` row, nor the side of a
/// hypothesis' promotion its atom reader would not read; cached combinations
/// and the ingest template are never read) contributes its discounted
/// refutation mass α·f on ¬(∧ leaves): the f part of a textless (T2/T3) row,
/// of a mixed row, and of a pure refutation left on the compound (a
/// `conj_refute` decision writes no atom row).
///
/// A row whose refutation has moved is skipped: an `attributed_v1` row with
/// refutation mass cites it (readiness P3) on one of THIS compound's visible
/// leaves (`closures`), so the conjunction already reads it there. A citation
/// on another compound's leaf moves nothing off this one, and a citation that
/// carried only the support side (a mixed row decided "supports") leaves the
/// f on the compound (SPEC §5.3).
async fn own_row_valuations(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    compounds: &[Uuid],
    closures: &HashMap<Uuid, Vec<Uuid>>,
    ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, BTreeMap<ItemKey, f64>>, String> {
    let own = compound_own_rows(&mut *conn, viewer, compounds, CLAIM_VALIDITY_FRAME_ID)
        .await
        .map_err(|e| format!("compound_own_rows: {e}"))?;
    let moved: BTreeSet<Uuid> = own
        .iter()
        .filter(|r| {
            closures
                .get(&r.input.row.claim_id)
                .is_some_and(|leaves| r.refuting_citers.iter().any(|c| leaves.contains(c)))
        })
        .map(|r| r.input.row.id)
        .collect();
    let evidence = read_rows(
        own.into_iter()
            .map(|r| r.input)
            .filter(reads_this_side_of_promotion)
            .collect(),
    )?
    .into_iter()
    .filter(|(_, class, _)| *class == AxiomClass::Evidence)
    .collect();
    let mut out: HashMap<Uuid, BTreeMap<ItemKey, f64>> = HashMap::new();
    for r in key_and_discount(conn, viewer, evidence, ctx).await? {
        let (_, f, _, _) = tfo(r.bba());
        if f <= ZERO || moved.contains(&r.row_id()) {
            continue;
        }
        let slot = out
            .entry(r.atom_id())
            .or_default()
            .entry(r.key().clone())
            .or_insert(0.0);
        *slot = slot.max(f);
    }
    Ok(out)
}

// ── entry points ────────────────────────────────────────────────────────────

/// Each requested atom's [`LeafState`] as `viewer` sees it (SPEC §7.1): P1
/// (`Axiom`) when a visible AEF input row exists, else `Legacy` when it is not
/// a compound and keeps a cache, else `Unproven`. An id the viewer cannot
/// read is absent; a compound is never `Legacy`.
///
/// # Errors
/// A database read.
pub async fn leaf_states_batch(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, LeafState>, String> {
    let visible: BTreeSet<Uuid> = roles_batch(&mut *conn, viewer, ids)
        .await
        .map_err(|e| format!("roles_batch: {e}"))?
        .into_keys()
        .collect();
    let inputs = AtomInputs::read(conn, viewer, &visible, ctx).await?;
    Ok(visible.iter().map(|&id| (id, inputs.state(id))).collect())
}

/// P2 for each requested compound the viewer can read (SPEC §7.1): no leaf
/// the viewer can see is served `Legacy`. A non-compound id is absent.
///
/// # Errors
/// A database read.
pub async fn compound_ready_batch(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, bool>, String> {
    let compounds = compounds_of(conn, viewer, ids).await?;
    let ids: Vec<Uuid> = compounds.keys().copied().collect();
    let closures = leaf_closure_batch(&mut *conn, viewer, &ids)
        .await
        .map_err(|e| format!("leaf_closure_batch: {e}"))?;
    let atoms: BTreeSet<Uuid> = closures.values().flatten().copied().collect();
    let inputs = AtomInputs::read(conn, viewer, &atoms, ctx).await?;
    Ok(ids
        .iter()
        .map(|id| {
            let leaves = closures.get(id).map(Vec::as_slice).unwrap_or_default();
            (*id, compound_ready(leaves.iter().map(|&l| inputs.state(l))))
        })
        .collect())
}

/// The requested claims the viewer can read whose role is compound, with
/// their spine flag.
async fn compounds_of(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
) -> Result<BTreeMap<Uuid, bool>, String> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    Ok(roles_batch(&mut *conn, viewer, ids)
        .await
        .map_err(|e| format!("roles_batch: {e}"))?
        .into_iter()
        .filter_map(|(id, role)| match role {
            ClaimRole::Compound { spine } => Some((id, spine)),
            _ => None,
        })
        .collect())
}

/// The [`BeliefView`] of each requested atom or standalone the viewer can
/// read, under the lens `ctx`: `Axiom` from its AEF fold, `Legacy` from a
/// kept cache when it has no AEF input, `Unproven` otherwise. Any other role
/// is absent.
///
/// # Errors
/// A database read, or a fold that errors.
pub async fn atom_belief_view_batch(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, BeliefView>, String> {
    let atoms: BTreeSet<Uuid> = roles_batch(&mut *conn, viewer, ids)
        .await
        .map_err(|e| format!("roles_batch: {e}"))?
        .into_iter()
        .filter(|(_, role)| matches!(role, ClaimRole::Atom | ClaimRole::Standalone))
        .map(|(id, _)| id)
        .collect();
    let inputs = AtomInputs::read(conn, viewer, &atoms, ctx).await?;
    atoms
        .iter()
        .map(|&id| inputs.view(id).map(|v| (id, v)))
        .collect()
}

/// The derived [`BeliefView`] of each requested compound the viewer can read,
/// under the lens `ctx` (SPEC §3.2, §3.3, §3.5, §3.6). Any other id is
/// absent (a procedural tree keeps today's behaviour).
///
/// * Non-spine: `Basis::Derived`, R-DEP over the viewer's visible flattened
///   leaves with the compound's `not_all` valuation; `betp` is product-frame.
/// * Spine: `Basis::Profile`, the leaves' profile; `bel` / `pl` are the
///   Fréchet envelope and `betp` its midpoint, never a conjunction.
///
/// Leaf counts are visible leaves only; no field reports a hidden one.
///
/// # Errors
/// A database read, or a conjunction that cannot be evaluated.
pub async fn derive_compound_belief_batch(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, BeliefView>, String> {
    derive_batch(conn, viewer, ids, ctx, true).await
}

/// [`derive_compound_belief_batch`] without the `not_all` valuation: the
/// same leaves, items, sibling edges and spine profiles, with no refutation
/// of the whole read (`not_all` is [`NotAll::NONE`]). This is stage (c) of a
/// compound's drift decomposition (SPEC §10.4), the conjunction before its
/// `not_all`; it is never a value to serve.
///
/// # Errors
/// A database read, or a conjunction that cannot be evaluated.
pub async fn derive_compound_conjunction_batch(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    ctx: &FramedBeliefContext,
) -> Result<HashMap<Uuid, BeliefView>, String> {
    derive_batch(conn, viewer, ids, ctx, false).await
}

async fn derive_batch(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
    ctx: &FramedBeliefContext,
    with_not_all: bool,
) -> Result<HashMap<Uuid, BeliefView>, String> {
    let compounds = compounds_of(conn, viewer, ids).await?;
    if compounds.is_empty() {
        return Ok(HashMap::new());
    }
    let compound_ids: Vec<Uuid> = compounds.keys().copied().collect();
    let closures = leaf_closure_batch(&mut *conn, viewer, &compound_ids)
        .await
        .map_err(|e| format!("leaf_closure_batch: {e}"))?;
    let leaf_union: BTreeSet<Uuid> = closures.values().flatten().copied().collect();

    // Refuting edges into the compounds (not_all) and between their leaves
    // (negative siblings), as the viewer sees them.
    let targets: Vec<Uuid> = compound_ids
        .iter()
        .chain(leaf_union.iter())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let edges = refuting_edges_into(&mut *conn, viewer, &targets)
        .await
        .map_err(|e| format!("refuting_edges_into: {e}"))?;

    // The sources of refuting edges into a compound, and their leaves.
    let x_ids: Vec<Uuid> = edges
        .iter()
        .filter(|e| compounds.contains_key(&e.target_id))
        .map(|e| e.source_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let x_compounds = compounds_of(conn, viewer, &x_ids).await?;
    let x_closures = if x_compounds.is_empty() {
        HashMap::new()
    } else {
        let ids: Vec<Uuid> = x_compounds.keys().copied().collect();
        leaf_closure_batch(&mut *conn, viewer, &ids)
            .await
            .map_err(|e| format!("leaf_closure_batch: {e}"))?
    };
    let x_leaves = |x: Uuid| -> Vec<Uuid> {
        if x_compounds.contains_key(&x) {
            x_closures.get(&x).cloned().unwrap_or_default()
        } else {
            vec![x]
        }
    };

    // ONE read of every atom's Display rows, ONE partition into items.
    let mut atoms = leaf_union;
    for &x in &x_ids {
        atoms.extend(x_leaves(x));
    }
    let inputs = AtomInputs::read(conn, viewer, &atoms, ctx).await?;
    let batch = batch_items(&inputs.rows)?;

    let non_spine: Vec<Uuid> = compounds
        .iter()
        .filter(|(_, spine)| !**spine)
        .map(|(id, _)| *id)
        .collect();
    let own = if with_not_all {
        own_row_valuations(conn, viewer, &non_spine, &closures, ctx).await?
    } else {
        HashMap::new()
    };

    // Bel(X) for every edge source, as this derivation reads it.
    let mut x_bel: HashMap<Uuid, f64> = HashMap::new();
    for &x in &x_ids {
        let bel = if x_compounds.contains_key(&x) {
            let leaves = x_leaves(x);
            if leaves.is_empty() {
                0.0
            } else {
                let q = query_items(&leaves, &batch, &inputs, None)?;
                conj(&leaves, &q.items, 0.0)?.bel
            }
        } else {
            inputs.view(x)?.bel
        };
        x_bel.insert(x, bel);
    }

    // The refuting edges whose frozen BBA is one of the batch's items: their
    // refutation is already in a leaf's fold.
    let wired: BTreeSet<Uuid> = batch
        .iter()
        .filter_map(|b| match &b.id.key {
            ItemKey::Edge(e) => Some(*e),
            _ => None,
        })
        .collect();

    let mut out = HashMap::with_capacity(compounds.len());
    for (&id, &spine) in &compounds {
        let leaves = closures.get(&id).cloned().unwrap_or_default();
        let view = if spine {
            profile_view(id, &leaves, &batch, &inputs)?
        } else {
            let leaf_set: BTreeSet<Uuid> = leaves.iter().copied().collect();
            if !with_not_all {
                out.insert(
                    id,
                    derived_view(id, &leaves, &batch, &inputs, &edges, NotAll::NONE)?,
                );
                continue;
            }
            // not_all: own rows, then edges into the compound.
            let mut masses: Vec<f64> = own
                .get(&id)
                .map(|keys| keys.values().copied().collect())
                .unwrap_or_default();
            let (mut shared_leaf_skipped, mut leaf_edge_skipped) = (0, 0);
            for e in edges.iter().filter(|e| e.target_id == id) {
                if x_leaves(e.source_id).iter().any(|l| leaf_set.contains(l)) {
                    shared_leaf_skipped += 1;
                    continue;
                }
                // The same source already refutes one of K's visible leaves
                // through a wired edge (a retargeted parent edge stays in
                // force beside its atom edges): counting the parent as well
                // would refute K twice with one source.
                if edges.iter().any(|a| {
                    a.source_id == e.source_id
                        && leaf_set.contains(&a.target_id)
                        && wired.contains(&a.id)
                }) {
                    leaf_edge_skipped += 1;
                    continue;
                }
                let m = negative_strength(&e.relationship) * x_bel[&e.source_id];
                if m > ZERO {
                    masses.push(m);
                }
            }
            let not_all = NotAll {
                m: 1.0 - masses.iter().map(|m| 1.0 - m).product::<f64>(),
                sources: masses.len(),
                shared_leaf_skipped,
                leaf_edge_skipped,
            };
            derived_view(id, &leaves, &batch, &inputs, &edges, not_all)?
        };
        out.insert(id, view);
    }
    Ok(out)
}

fn derived_view(
    id: Uuid,
    leaves: &[Uuid],
    batch: &[BatchItem],
    inputs: &AtomInputs,
    edges: &[RefutingEdge],
    not_all: NotAll,
) -> Result<BeliefView, String> {
    let leaf_set: BTreeSet<Uuid> = leaves.iter().copied().collect();
    let siblings: Vec<&RefutingEdge> = edges
        .iter()
        .filter(|e| {
            e.source_id != e.target_id
                && leaf_set.contains(&e.source_id)
                && leaf_set.contains(&e.target_id)
        })
        .collect();
    let served = if leaves.is_empty() {
        // No leaf this viewer can see: nothing is proven, and only a
        // refutation of the whole can lower Pl.
        let vacuous = ConjResult {
            bel: 0.0,
            pl: 1.0,
            nr: 1.0,
            betp: 0.5,
            bel_or: 0.0,
            k: 0.0,
            frechet: Frechet {
                lo: 0.0,
                hi: 1.0,
                hi_nr: 1.0,
            },
            exact: true,
            open_world: false,
        };
        Served {
            r: not_all_closed_form(&vacuous, not_all.m).map_err(|e| format!("not_all: {e}"))?,
            internally_contested: false,
            compound_edges: 0,
            items: 0,
            approximate: false,
        }
    } else {
        serve(leaves, batch, inputs, &siblings, not_all.m)?
    };
    let r = served.r;
    let states: Vec<LeafState> = leaves.iter().map(|&l| inputs.state(l)).collect();
    Ok(BeliefView {
        claim_id: id,
        basis: Basis::Derived,
        bel: r.bel,
        pl: r.pl,
        betp: r.betp,
        nr: r.nr,
        derived: Some(DerivedBelief {
            rule: DEP_RULE,
            betp_kind: PRODUCT_FRAME_BETP,
            frechet: Envelope::from(r.frechet),
            conflict: r.k,
            exact: r.exact && !served.approximate,
            leaves_used: leaves.len(),
            evidenced: states.iter().filter(|s| s.is_evidenced()).count(),
            legacy_leaves: states.iter().filter(|s| **s == LeafState::Legacy).count(),
            internally_contested: served.internally_contested,
            not_all,
        }),
        profile: None,
        rule_version: DEP_RULE,
        inputs: InputSummary {
            items: served.items,
            legacy_compound_edge_items: served.compound_edges,
        },
    })
}

fn summary(mut values: Vec<f64>) -> Summary3 {
    values.sort_by(f64::total_cmp);
    let n = values.len();
    if n == 0 {
        return Summary3 {
            min: 0.0,
            median: 0.0,
            max: 0.0,
        };
    }
    let median = if n % 2 == 1 {
        values[n / 2]
    } else {
        0.5 * (values[n / 2 - 1] + values[n / 2])
    };
    Summary3 {
        min: values[0],
        median,
        max: values[n - 1],
    }
}

/// A spine compound's profile (SPEC §2.2): each visible leaf queried alone,
/// summarized, with the Fréchet envelope served as its interval.
fn profile_view(
    id: Uuid,
    leaves: &[Uuid],
    batch: &[BatchItem],
    inputs: &AtomInputs,
) -> Result<BeliefView, String> {
    let q = query_items(leaves, batch, inputs, None)?;
    let mut singles = Vec::with_capacity(leaves.len());
    for &leaf in leaves {
        singles.push(conj(&[leaf], &q.items, 0.0)?);
    }
    let envelope = if singles.is_empty() {
        Envelope {
            lo: 0.0,
            hi: 1.0,
            hi_nr: 1.0,
        }
    } else {
        // Fréchet floor: max(0, Σ Belᵢ − (n − 1)), summed as Σ (Belᵢ − 1) + 1.
        let lo = (singles.iter().map(|s| s.bel - 1.0).sum::<f64>() + 1.0).max(0.0);
        Envelope {
            lo,
            hi: singles.iter().map(|s| s.pl).fold(1.0, f64::min),
            hi_nr: singles.iter().map(|s| s.nr).fold(1.0, f64::min),
        }
    };
    let states: Vec<LeafState> = leaves.iter().map(|&l| inputs.state(l)).collect();
    Ok(BeliefView {
        claim_id: id,
        basis: Basis::Profile,
        bel: envelope.lo,
        pl: envelope.hi,
        betp: 0.5 * (envelope.lo + envelope.hi),
        nr: envelope.hi_nr,
        derived: None,
        profile: Some(LeafProfile {
            rule: PROFILE_RULE,
            n: leaves.len(),
            evidenced: states.iter().filter(|s| s.is_evidenced()).count(),
            legacy_leaves: states.iter().filter(|s| **s == LeafState::Legacy).count(),
            bel: summary(singles.iter().map(|s| s.bel).collect()),
            betp: summary(singles.iter().map(|s| s.betp).collect()),
            contested: singles.iter().filter(|s| s.pl < 0.5).count(),
            frechet: envelope,
        }),
        rule_version: PROFILE_RULE,
        inputs: InputSummary {
            items: q.items.len(),
            legacy_compound_edge_items: q.compound_edges,
        },
    })
}
