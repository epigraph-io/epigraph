//! The `digest` ranking: four query-independent-or-not slices of the atoms
//! that have left the quoted window (DESIGN §5.1).
//!
//! # Eligibility
//!
//! An atom is eligible only when it is current (not superseded), its turn is
//! applied (`mark_applied`), and its turn is below `exclude_turns_from`.
//!
//! `exclude_turns_from` is the FIRST TURN OF THE VERBATIM WINDOW (the oldest
//! of the last W completed turns). It is not "the oldest turn still quoted":
//! an evicted turn that is still pending sits below this bound and is kept
//! out by `applied` (its turn is not yet written), not by the bound. The
//! difference matters when a pending turn is stuck below a turn that has
//! since been written: with window 17–20, turn 15 stuck at `captured` and
//! turn 16 written, the runner passes 17, and turn 16's atoms are listed.
//! Passing 15 would drop turn 16 from the prompt altogether (it is neither
//! quoted nor listed). The only overlap this reading allows is a pending
//! turn that is written between the runner's quote decision and this call,
//! which is then both quoted and listed: a duplicate, never a loss.
//!
//! So a turn in the window, or evicted but still pending, is quoted in full
//! by the runner and its atoms never appear here (DONE criterion (1): the
//! prompt sees atoms only for turns that left the window).
//!
//! # Slices
//!
//! | slice | contents | order |
//! |---|---|---|
//! | `standing` | decision, preference, instruction, commitment atoms, whatever the query | BetP, then newer turn |
//! | `relevant` | BM25 top [`RELEVANT_BM25_TOP`], plus one hop from the top [`EXPANSION_SEEDS`] over [`EXPANSION_RELS`] at [`HOP_DECAY`] | blended score, then greedy coverage-vs-relevance selection |
//! | `recent` | atoms from the [`RECENT_TURNS`] turns below `exclude_turns_from` | newer turn, then BetP |
//! | `open` | CONTESTED atoms with their contradicting partners, each conflict once, then `question` atoms | latest conflict first; newer question first |
//!
//! Each slice holds at most `k_per_slice` entries. The slices may overlap;
//! the runner's packer (`digest.ts::packDigest`) removes duplicates and fits
//! the budget, rolling unused share into the next slice. Low-belief atoms are
//! listed with their numbers, never dropped (there is no belief floor).
//!
//! # The relevant slice's score
//!
//! `0.55·rel + 0.15·recency + 0.15·BetP + 0.15·kind_boost`, each term in
//! `[0, 1]`:
//!
//! * `rel`: the BM25 score over the best BM25 score; a one-hop neighbour gets
//!   `HOP_DECAY ×` its best seed's `rel` when that is higher than its own;
//! * `recency`: `0.5^(d / 40)`, `d = exclude_turns_from − turn` (a turn
//!   distance, never the clock);
//! * `kind_boost`: [`kind_boost`].
//!
//! Candidates are then picked by `epigraph_engine::diverse_select`, a greedy
//! coverage-versus-relevance selection (critic finding X19: it is not MMR)
//! over neighbour lists of token Jaccard ≥ [`JACCARD_NEIGHBOUR`], with
//! coverage weight [`DIVERSE_ALPHA`], so a near-restatement of an atom
//! already picked yields to a different atom of similar score.

use std::collections::{BTreeMap, BTreeSet};

use epigraph_engine::diverse_select::diverse_select;
use serde::Serialize;
use uuid::Uuid;

use super::belief::{AtomBelief, BeliefView};
use super::bm25;
use super::store::{AgentRole, AtomKind, Evidence, Relationship, ScratchAtom, ScratchStore};

/// BM25 hits considered for the relevant slice.
pub const RELEVANT_BM25_TOP: usize = 60;
/// Top BM25 hits whose neighbours are pulled in.
pub const EXPANSION_SEEDS: usize = 12;
/// Relevance kept per hop.
pub const HOP_DECAY: f64 = 0.7;
/// Edges the one-hop expansion follows, in either direction.
pub const EXPANSION_RELS: [Relationship; 5] = [
    Relationship::Supports,
    Relationship::Corroborates,
    Relationship::Elaborates,
    Relationship::Contradicts,
    Relationship::Refutes,
];
/// Turns for recency to halve.
pub const RECENCY_HALF_LIFE_TURNS: f64 = 40.0;
/// Weights of the relevant score: relevance, recency, BetP, kind.
pub const W_REL: f64 = 0.55;
pub const W_RECENCY: f64 = 0.15;
pub const W_BETP: f64 = 0.15;
pub const W_KIND: f64 = 0.15;
/// Token Jaccard at or above which two candidates are neighbours.
pub const JACCARD_NEIGHBOUR: f64 = 0.6;
/// Coverage weight passed to `diverse_select` (0 = pure relevance).
pub const DIVERSE_ALPHA: f32 = 0.3;
/// Evicted turns the recent slice covers.
pub const RECENT_TURNS: u64 = 8;
/// Default and largest `k_per_slice`.
pub const DEFAULT_K_PER_SLICE: usize = 20;
pub const MAX_K_PER_SLICE: usize = 200;

/// Kinds that are always shown in the standing slice.
pub const STANDING_KINDS: [AtomKind; 4] = [
    AtomKind::Decision,
    AtomKind::Preference,
    AtomKind::Instruction,
    AtomKind::Commitment,
];

/// The kind term of the relevant score. Knobs, like the reliability table:
/// what the operator decided or asked for outranks a passing fact at equal
/// relevance, and a failed-extraction stub ranks last.
pub fn kind_boost(kind: AtomKind) -> f64 {
    match kind {
        AtomKind::Decision
        | AtomKind::Preference
        | AtomKind::Instruction
        | AtomKind::Commitment
        | AtomKind::Correction => 1.0,
        AtomKind::Fact | AtomKind::Observation => 0.6,
        AtomKind::Question => 0.5,
        AtomKind::TurnStub => 0.2,
    }
}

/// `0.5^(distance / half-life)`; turns at or after the reference count as 0.
pub fn recency(turn: u64, reference: u64) -> f64 {
    let distance = reference.saturating_sub(turn) as f64;
    0.5_f64.powf(distance / RECENCY_HALF_LIFE_TURNS)
}

/// One listed atom.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DigestItem<'a> {
    pub id: Uuid,
    pub text: &'a str,
    pub kind: AtomKind,
    /// The speaker agent's display name (chat text).
    pub speaker: &'a str,
    pub speaker_agent: Uuid,
    pub role: AgentRole,
    pub turn: u64,
    pub bel: f64,
    pub pl: f64,
    pub betp: f64,
    pub contested: bool,
    pub evidence: &'a [Evidence],
    /// The relevant slice's blended score; absent elsewhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
}

/// A contradicting partner the digest does not list because it is not
/// eligible: its turn is at or after `exclude_turns_from` (in the window) or
/// not yet applied (evicted and pending). The runner renders an `ev:tN`
/// pointer to that turn; a window or quoted pending turn's text is already
/// in the prompt, and a pending turn past the quote cap is a pointer line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UnlistedPartner {
    pub id: Uuid,
    pub turn: u64,
}

/// One entry of the open slice: a CONTESTED atom with its partners, or a
/// question.
///
/// Every contested pair with at least one eligible side appears in exactly
/// one entry, headed by whichever side comes first in the slice's order
/// (latest conflict, then the older side). An entry lists only the pairs no
/// earlier entry showed, so an atom can appear as one entry's partner and
/// later head its own entry for a different conflict. A renderer must expect
/// that, and must not assume `vs` holds every partner of the head (the
/// head's `atom` belief carries the full `contested_with`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OpenEntry<'a> {
    #[serde(flatten)]
    pub item: DigestItem<'a>,
    /// Eligible partners whose conflict with the head no earlier entry
    /// showed, listed in full (both sides of a conflict are always shown).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vs: Vec<DigestItem<'a>>,
    /// Ineligible partners (in the window, or pending), same rule as `vs`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vs_unlisted: Vec<UnlistedPartner>,
}

/// A correction made in a recent turn: `old` was superseded by `new`.
///
/// It carries both texts so the runner can render "corrected in tN: X
/// changed from A to B" (DESIGN §5.2) without an `atom` round trip: the old
/// atom is superseded, so no slice lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RecentCorrection<'a> {
    pub old: Uuid,
    pub old_turn: u64,
    /// The superseded atom's text, present only when its turn has left the
    /// window and is applied. An old atom in a still-quoted turn is already
    /// in the prompt verbatim, and the digest never repeats such text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_text: Option<&'a str>,
    pub new: Uuid,
    pub new_text: &'a str,
    /// The turn of the correction (`new`'s turn).
    pub turn: u64,
}

/// The `digest` result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Digest<'a> {
    /// Every atom in the graph, current or not.
    pub atoms_total: usize,
    /// Eligible atoms (current, applied, before the window).
    pub eligible: usize,
    /// Applied turns before `exclude_turns_from` (the window's first turn).
    pub turns_archived: usize,
    pub standing: Vec<DigestItem<'a>>,
    pub relevant: Vec<DigestItem<'a>>,
    pub recent: Vec<DigestItem<'a>>,
    pub recent_corrections: Vec<RecentCorrection<'a>>,
    pub open: Vec<OpenEntry<'a>>,
}

fn item<'a>(
    store: &'a ScratchStore,
    atom: &'a ScratchAtom,
    belief: &AtomBelief,
    score: Option<f64>,
) -> DigestItem<'a> {
    let (speaker, role) = store
        .agent(&atom.speaker_agent)
        .map_or(("", AgentRole::Participant), |a| {
            (a.display_name.as_str(), a.role)
        });
    DigestItem {
        id: atom.id,
        text: &atom.text,
        kind: atom.kind,
        speaker,
        speaker_agent: atom.speaker_agent,
        role,
        turn: atom.turn,
        bel: belief.bel,
        pl: belief.pl,
        betp: belief.betp,
        contested: belief.contested,
        evidence: &atom.evidence,
        score,
    }
}

/// Belief by id; an id the view lacks (it was computed from another state of
/// the graph) reads as vacuous rather than failing the digest.
struct BeliefLookup<'v> {
    view: &'v BeliefView,
    vacuous: AtomBelief,
}

impl<'v> BeliefLookup<'v> {
    fn new(view: &'v BeliefView) -> Self {
        Self {
            view,
            vacuous: AtomBelief {
                bel: 0.0,
                pl: 1.0,
                betp: 0.5,
                contested: false,
                contested_with: Vec::new(),
            },
        }
    }

    fn of(&self, id: &Uuid) -> &AtomBelief {
        self.view.get(id).unwrap_or(&self.vacuous)
    }
}

fn token_set(text: &str) -> BTreeSet<String> {
    bm25::tokenize(text).into_iter().collect()
}

fn jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    let union = a.union(b).count();
    if union == 0 {
        return 0.0;
    }
    a.intersection(b).count() as f64 / union as f64
}

/// Rank the digest for one prompt.
///
/// `beliefs` must be computed from `store` (the caller holds both, so one
/// computation serves every slice).
pub fn digest<'a>(
    store: &'a ScratchStore,
    beliefs: &BeliefView,
    query: &str,
    exclude_turns_from: u64,
    k_per_slice: usize,
) -> Digest<'a> {
    let applied: BTreeSet<u64> = store.applied_turns().collect();
    let is_eligible =
        |a: &ScratchAtom| a.is_current && a.turn < exclude_turns_from && applied.contains(&a.turn);
    // Newest first, so every stable sort below breaks ties toward the newer
    // atom, and BM25 ties go to it too.
    let mut eligible: Vec<&ScratchAtom> = store.atoms().filter(|a| is_eligible(a)).collect();
    eligible.sort_by(|a, b| {
        b.turn
            .cmp(&a.turn)
            .then_with(|| b.created_at.cmp(&a.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    let eligible_ids: BTreeSet<Uuid> = eligible.iter().map(|a| a.id).collect();
    let beliefs = BeliefLookup::new(beliefs);

    Digest {
        atoms_total: store.stats().atoms,
        eligible: eligible.len(),
        turns_archived: applied.range(..exclude_turns_from).count(),
        standing: standing(store, &eligible, &beliefs, k_per_slice),
        relevant: relevant(
            store,
            &eligible,
            &eligible_ids,
            &beliefs,
            query,
            exclude_turns_from,
            k_per_slice,
        ),
        recent: recent(store, &eligible, &beliefs, exclude_turns_from, k_per_slice),
        recent_corrections: recent_corrections(store, &eligible_ids, &applied, exclude_turns_from),
        open: open(store, &eligible, &eligible_ids, &beliefs, k_per_slice),
    }
}

fn standing<'a>(
    store: &'a ScratchStore,
    eligible: &[&'a ScratchAtom],
    beliefs: &BeliefLookup<'_>,
    k: usize,
) -> Vec<DigestItem<'a>> {
    let mut list: Vec<&ScratchAtom> = eligible
        .iter()
        .copied()
        .filter(|a| STANDING_KINDS.contains(&a.kind))
        .collect();
    // Stable: equal BetP keeps the newest-first order.
    list.sort_by(|a, b| beliefs.of(&b.id).betp.total_cmp(&beliefs.of(&a.id).betp));
    list.into_iter()
        .take(k)
        .map(|a| item(store, a, beliefs.of(&a.id), None))
        .collect()
}

fn relevant<'a>(
    store: &'a ScratchStore,
    eligible: &[&'a ScratchAtom],
    eligible_ids: &BTreeSet<Uuid>,
    beliefs: &BeliefLookup<'_>,
    query: &str,
    reference: u64,
    k: usize,
) -> Vec<DigestItem<'a>> {
    if k == 0 {
        return Vec::new();
    }
    let docs: Vec<&str> = eligible.iter().map(|a| a.text.as_str()).collect();
    let hits = bm25::rank(&docs, query, RELEVANT_BM25_TOP);
    let Some(best) = hits.first().map(|h| h.1) else {
        return Vec::new();
    };
    let by_id: BTreeMap<Uuid, &'a ScratchAtom> = eligible.iter().map(|a| (a.id, *a)).collect();

    // rel per candidate: normalised BM25, raised by one-hop propagation.
    let mut rel: BTreeMap<Uuid, f64> = hits
        .iter()
        .map(|&(i, score)| (eligible[i].id, score / best))
        .collect();
    for &(i, score) in hits.iter().take(EXPANSION_SEEDS) {
        let seed = eligible[i].id;
        let carried = HOP_DECAY * score / best;
        for edge in store.edges() {
            if !EXPANSION_RELS.contains(&edge.relationship) {
                continue;
            }
            let other = if edge.source == seed {
                edge.target
            } else if edge.target == seed {
                edge.source
            } else {
                continue;
            };
            if !eligible_ids.contains(&other) {
                continue;
            }
            let entry = rel.entry(other).or_insert(0.0);
            if carried > *entry {
                *entry = carried;
            }
        }
    }

    let mut scored: Vec<(&'a ScratchAtom, f64)> = rel
        .iter()
        .filter_map(|(id, r)| by_id.get(id).map(|a| (*a, *r)))
        .map(|(a, r)| {
            let s = W_REL * r
                + W_RECENCY * recency(a.turn, reference)
                + W_BETP * beliefs.of(&a.id).betp
                + W_KIND * kind_boost(a.kind);
            (a, s)
        })
        .collect();
    scored.sort_by(|x, y| {
        y.1.total_cmp(&x.1)
            .then_with(|| y.0.turn.cmp(&x.0.turn))
            .then_with(|| x.0.id.cmp(&y.0.id))
    });

    let tokens: Vec<BTreeSet<String>> = scored.iter().map(|(a, _)| token_set(&a.text)).collect();
    let neighbours: Vec<Vec<usize>> = (0..scored.len())
        .map(|i| {
            (0..scored.len())
                .filter(|&j| j != i && jaccard(&tokens[i], &tokens[j]) >= JACCARD_NEIGHBOUR)
                .collect()
        })
        .collect();
    let similarities: Vec<f32> = scored.iter().map(|(_, s)| *s as f32).collect();
    diverse_select(&neighbours, &similarities, k, DIVERSE_ALPHA)
        .into_iter()
        .map(|i| {
            let (a, s) = scored[i];
            item(store, a, beliefs.of(&a.id), Some(s))
        })
        .collect()
}

fn recent<'a>(
    store: &'a ScratchStore,
    eligible: &[&'a ScratchAtom],
    beliefs: &BeliefLookup<'_>,
    exclude_turns_from: u64,
    k: usize,
) -> Vec<DigestItem<'a>> {
    let from = exclude_turns_from.saturating_sub(RECENT_TURNS);
    let mut list: Vec<&ScratchAtom> = eligible
        .iter()
        .copied()
        .filter(|a| a.turn >= from)
        .collect();
    list.sort_by(|a, b| {
        b.turn
            .cmp(&a.turn)
            .then_with(|| beliefs.of(&b.id).betp.total_cmp(&beliefs.of(&a.id).betp))
    });
    list.into_iter()
        .take(k)
        .map(|a| item(store, a, beliefs.of(&a.id), None))
        .collect()
}

fn recent_corrections<'a>(
    store: &'a ScratchStore,
    eligible_ids: &BTreeSet<Uuid>,
    applied: &BTreeSet<u64>,
    exclude_turns_from: u64,
) -> Vec<RecentCorrection<'a>> {
    let from = exclude_turns_from.saturating_sub(RECENT_TURNS);
    let mut out: Vec<RecentCorrection<'a>> = store
        .atoms()
        .filter_map(|old| {
            let new = store.atom(&old.superseded_by?)?;
            // The old side's turn must have left the window and be applied,
            // the same rule as eligibility minus `is_current`.
            let old_listable = old.turn < exclude_turns_from && applied.contains(&old.turn);
            (eligible_ids.contains(&new.id) && new.turn >= from).then_some(RecentCorrection {
                old: old.id,
                old_turn: old.turn,
                old_text: old_listable.then_some(old.text.as_str()),
                new: new.id,
                new_text: &new.text,
                turn: new.turn,
            })
        })
        .collect();
    out.sort_by(|a, b| b.turn.cmp(&a.turn).then_with(|| a.old.cmp(&b.old)));
    out
}

fn open<'a>(
    store: &'a ScratchStore,
    eligible: &[&'a ScratchAtom],
    eligible_ids: &BTreeSet<Uuid>,
    beliefs: &BeliefLookup<'_>,
    k: usize,
) -> Vec<OpenEntry<'a>> {
    // A conflict's recency is its newest side, wherever that side is.
    let partner_turn = |id: &Uuid| store.atom(id).map_or(0, |a| a.turn);
    let mut contested: Vec<(&'a ScratchAtom, u64)> = eligible
        .iter()
        .copied()
        .filter(|a| beliefs.of(&a.id).contested)
        .map(|a| {
            let newest = beliefs
                .of(&a.id)
                .contested_with
                .iter()
                .map(partner_turn)
                .chain([a.turn])
                .max()
                .unwrap_or(a.turn);
            (a, newest)
        })
        .collect();
    // Latest conflict first; within it the older side heads the entry, so
    // the later statement reads as the challenge to it.
    contested.sort_by(|x, y| {
        y.1.cmp(&x.1)
            .then_with(|| x.0.turn.cmp(&y.0.turn))
            .then_with(|| x.0.id.cmp(&y.0.id))
    });

    // Coverage is by PAIR, not by atom: an atom listed as one head's partner
    // can still head an entry of its own for a conflict no earlier entry
    // showed. Covering by atom lost a conflict between two atoms that were
    // each listed under a different head, and a shown partner's conflict with
    // a still-quoted atom (which never heads an entry) vanished entirely.
    let pair = |a: Uuid, b: Uuid| if a < b { (a, b) } else { (b, a) };
    let mut covered: BTreeSet<(Uuid, Uuid)> = BTreeSet::new();
    let mut out = Vec::new();
    let mut shown: BTreeSet<Uuid> = BTreeSet::new();
    for (head, _) in contested {
        if out.len() >= k {
            return out;
        }
        let mut vs = Vec::new();
        let mut vs_unlisted = Vec::new();
        for partner in &beliefs.of(&head.id).contested_with {
            let Some(p) = store.atom(partner) else {
                continue;
            };
            if !covered.insert(pair(head.id, p.id)) {
                continue;
            }
            if eligible_ids.contains(partner) {
                shown.insert(p.id);
                vs.push(item(store, p, beliefs.of(&p.id), None));
            } else {
                vs_unlisted.push(UnlistedPartner {
                    id: p.id,
                    turn: p.turn,
                });
            }
        }
        if vs.is_empty() && vs_unlisted.is_empty() {
            // Every conflict of this atom is already shown.
            continue;
        }
        shown.insert(head.id);
        out.push(OpenEntry {
            item: item(store, head, beliefs.of(&head.id), None),
            vs,
            vs_unlisted,
        });
    }
    // Then open questions, newest first (`eligible` is newest first).
    for q in eligible
        .iter()
        .copied()
        .filter(|a| a.kind == AtomKind::Question && !shown.contains(&a.id))
    {
        if out.len() >= k {
            break;
        }
        out.push(OpenEntry {
            item: item(store, q, beliefs.of(&q.id), None),
            vs: Vec::new(),
            vs_unlisted: Vec::new(),
        });
    }
    out
}
