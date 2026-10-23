//! Same-source dependence in BBA combination (backlog 4c42c0bf).
//!
//! Dempster's rule assumes every BBA it folds is an INDEPENDENT source. A
//! re-worded re-observation of the same page by the same agent is not: it is
//! one source read twice, and folding it as independent raises belief on every
//! repeat (claim fc5e6a60 went 0.672 -> 0.768 on a "still listed, nothing
//! changed" re-sighting). `update_with_evidence` refuses only a byte-identical
//! `evidence_data`, so the combine step is where this has to be answered.
//!
//! The rule here: BBAs that share a [`SourceKey`] — the same source agent AND
//! the same evidence `source_url` — and say the same thing (one simple-support
//! focal element) are folded with Denoeux's cautious rule
//! ([`combination::cautious_combine`]) into ONE BBA before the Dempster fold.
//! The cautious rule is idempotent, so N copies of one source's verdict carry
//! exactly the weight of one (the strongest of them). A source that changes
//! its verdict is changed content, not a repeat, and folds as before.
//!
//! What it deliberately does NOT key on:
//! - the agent alone. `report_workflow_outcome` reports every execution of a
//!   workflow through the same agent, and those are distinct trials; an edge
//!   auto-wire from N distinct source claims by one ingesting agent is N
//!   sources. A BBA whose evidence carries no `source_url` has no key and is
//!   folded as independent, exactly as before.
//! - provenance LCA between agents. The REST `routes/independence.rs` analysis
//!   does that, but it passes `mass_functions` row ids to `get_lca`, which
//!   walks claim lineage, so in practice it never finds a shared ancestor. It
//!   is left where it is.
//!
//! Every combine of stored BBAs goes through [`combine_with_source_dependence`]:
//! the MCP writes (`ds_auto::auto_wire_ds_update`), the recompute
//! (`edge_factor::compute_combined_belief`) and the compute-on-read readers
//! (`belief_query::combine_framed_bbas`, behind framed `get_belief`,
//! `get_perspective_belief` and its batch). For a viewer who can see the
//! evidence rows its BBAs reference, the next recompute therefore cannot
//! re-inflate what the write left honest, and those readers agree with the
//! cache. The REST combine paths (`routes/belief.rs`, `routes/assess.rs`) are
//! not routed here yet; they still Dempster-fold every BBA.
//!
//! Source keys are read through the caller's viewer
//! ([`source_keys_for_rows`]). A BBA can be visible while its evidence row is
//! not: `epigraph-operator hide-evidence` narrows evidence to a private group
//! and leaves `mass_functions.evidence_id` pointing at it (`epigraph-cli`
//! `operator/hide.rs`; migration 110 keeps the narrowing in place). For
//! a viewer who cannot see that evidence row, the BBA has no key and folds as
//! independent, as it did before this rule; a recompute run under such a
//! viewer can write that pre-rule value into the cache.
//!
//! Known limits of the URL key ([`normalize_source_url`]): query strings,
//! fragments and the scheme are kept, so one page reached through different
//! tracking parameters, `#anchors`, or `http` vs `https` counts as distinct
//! sources and still corroborates; those misses err toward the pre-fix
//! behaviour. The path is lowercased, which goes the other way: two URLs that
//! differ only in the case of a case-sensitive path are MERGED into one
//! source, a deliberate under-count of corroboration in exchange for catching
//! the common case-variant repeat.

use std::collections::HashMap;

use uuid::Uuid;

use epigraph_db::{EvidenceRepository, MassFunctionRow};
use epigraph_ds::{combination, DsError, FocalElement, MassFunction};

/// Frames larger than this are folded without the cautious pass: the rule
/// walks the power set twice (`O(4^n)`), and every BBA that can carry a
/// [`SourceKey`] today is written on the two-hypothesis `binary_truth` frame.
/// A computational guard, not a belief parameter: below it the result is the
/// cautious fold, above it the cost bound applies.
// belief-profile: allow-literal (O(4^n) complexity guard, never binds on keyed BBAs today)
const MAX_CAUTIOUS_HYPOTHESES: usize = 8;

/// Identity of an evidence source for the dependence test: the agent that
/// wrote the BBA and the normalized `source_url` of the evidence it came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceKey {
    pub agent_id: Uuid,
    pub source_url: String,
}

/// Normalize a `source_url` for the dependence test: trimmed, trailing `/`
/// removed, ASCII-lowercased. Lowercasing a case-sensitive path can only MERGE
/// two distinct URLs into one source, which errs toward under-counting a
/// corroboration rather than over-counting a repeat. `None` for a blank URL.
#[must_use]
pub fn normalize_source_url(url: &str) -> Option<String> {
    let t = url.trim().trim_end_matches('/');
    if t.is_empty() {
        None
    } else {
        Some(t.to_ascii_lowercase())
    }
}

/// The [`SourceKey`] of each row, in row order. A row has a key only when it
/// names both a source agent and an evidence row whose `source_url` is set and
/// visible to `viewer`. A row whose evidence `viewer` cannot see (a hidden
/// evidence row, see the module docs) has no key and folds as independent.
///
/// Read on the caller's executor, through `viewer`, so the write path's
/// stamped transaction, the recompute's connection and the compute-on-read
/// readers' pool (`crate::belief_query`) each see the evidence rows their own
/// BBAs reference. One query, and none at all when no row can carry a key.
///
/// # Errors
/// `DbError` if the evidence read fails.
pub async fn source_keys_for_rows<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    viewer: &epigraph_db::visibility::Viewer,
    rows: &[MassFunctionRow],
) -> Result<Vec<Option<SourceKey>>, epigraph_db::DbError> {
    let evidence_ids: Vec<Uuid> = rows
        .iter()
        .filter(|r| r.source_agent_id.is_some())
        .filter_map(|r| r.evidence_id)
        .collect();
    let urls: HashMap<Uuid, String> = if evidence_ids.is_empty() {
        HashMap::new()
    } else {
        EvidenceRepository::source_urls_by_id(executor, viewer, &evidence_ids).await?
    };
    Ok(rows
        .iter()
        .map(|r| {
            let agent_id = r.source_agent_id?;
            let url = urls.get(&r.evidence_id?)?;
            Some(SourceKey {
                agent_id,
                source_url: normalize_source_url(url)?,
            })
        })
        .collect())
}

/// The one non-Θ focal element of a simple-support BBA, or `None` when `m` is
/// not a simple support function the cautious rule can take: non-classical
/// (complement / open-world mass, which `cautious_combine` does not model), on
/// a frame larger than [`MAX_CAUTIOUS_HYPOTHESES`], vacuous, or carrying more
/// than one non-Θ focal element (legacy mixed BBAs, or conflict mass).
fn simple_support_focus(m: &MassFunction) -> Option<FocalElement> {
    if !m.is_classical() || m.frame().hypothesis_count() > MAX_CAUTIOUS_HYPOTHESES {
        return None;
    }
    let theta = FocalElement::theta(m.frame());
    let mut non_theta = m.focal_elements().filter(|(fe, _)| **fe != theta);
    let (focus, _) = non_theta.next()?;
    if non_theta.next().is_some() {
        return None;
    }
    Some(focus.clone())
}

/// Combine already-discounted BBAs, folding same-source repeats cautiously first.
///
/// `items` pairs each discounted BBA with its [`SourceKey`] (`None` = no
/// source identity, treated as independent). BBAs that share a key AND point
/// at the same focal element (the same source saying the same thing again) are
/// reduced to one by the cautious rule; for simple support functions on one
/// focal set the min-commonality fold IS Denoeux's cautious rule, i.e. the
/// strongest of the repeats. Everything else — unkeyed BBAs, a source that
/// changed its verdict (a different focal element), and BBAs that are not
/// simple support functions (see [`simple_support_focus`]) — is passed to
/// [`combination::combine_multiple`] as its own input, exactly as before.
///
/// A source that flips (supports, then refutes) is therefore folded as it was
/// on main: the cautious min-commonality rule would turn the refutation into
/// empty-set mass and normalise most of it away.
///
/// Returns the combined BBA and the conflict the fold saw: the single BBA's
/// own empty-set mass when one remains, [`combination::fold_conflict`]
/// otherwise — the same two arms both callers used before.
///
/// # Errors
/// Propagates `DsError` from the cautious or Dempster fold, including
/// `combine_multiple`'s error when `items` is empty.
pub fn combine_with_source_dependence(
    items: Vec<(Option<SourceKey>, MassFunction)>,
    conflict_threshold: f64,
) -> Result<(MassFunction, f64), DsError> {
    // One slot per (source, focal element), in first-appearance order so the
    // fold input is deterministic (both rules are order-independent; logs and
    // float rounding are not). Anything without a group key is its own slot.
    type GroupKey = (SourceKey, FocalElement);
    enum Slot {
        Grouped(GroupKey),
        Alone(MassFunction),
    }
    let mut slots: Vec<Slot> = Vec::new();
    let mut groups: HashMap<GroupKey, Vec<MassFunction>> = HashMap::new();
    for (key, mf) in items {
        let group_key = key.and_then(|k| simple_support_focus(&mf).map(|f| (k, f)));
        match group_key {
            Some(gk) => {
                let members = groups.entry(gk.clone()).or_default();
                if members.is_empty() {
                    slots.push(Slot::Grouped(gk));
                }
                members.push(mf);
            }
            None => slots.push(Slot::Alone(mf)),
        }
    }

    let mut for_fold: Vec<MassFunction> = Vec::with_capacity(slots.len());
    for slot in slots {
        match slot {
            Slot::Alone(mf) => for_fold.push(mf),
            Slot::Grouped(gk) => {
                let mut it = groups.remove(&gk).unwrap_or_default().into_iter();
                if let Some(first) = it.next() {
                    let folded =
                        it.try_fold(first, |acc, m| combination::cautious_combine(&acc, &m))?;
                    for_fold.push(folded);
                }
            }
        }
    }

    if for_fold.len() == 1 {
        let only = for_fold.pop().expect("len == 1");
        let k = only.mass_of_conflict();
        Ok((only, k))
    } else {
        let (combined, reports) = combination::combine_multiple(&for_fold, conflict_threshold)?;
        let k = combination::fold_conflict(&combined, &reports);
        Ok((combined, k))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_ds::{measures, FrameOfDiscernment};
    use std::collections::BTreeSet;

    fn frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("binary_truth", vec!["TRUE".into(), "FALSE".into()]).unwrap()
    }

    fn support(idx: usize, mass: f64, reliability: f64) -> MassFunction {
        let m = MassFunction::simple(frame(), BTreeSet::from([idx]), mass).unwrap();
        combination::discount(&m, reliability).unwrap()
    }

    fn key(agent: u128, url: &str) -> Option<SourceKey> {
        Some(SourceKey {
            agent_id: Uuid::from_u128(agent),
            source_url: normalize_source_url(url).unwrap(),
        })
    }

    fn total(m: &MassFunction) -> f64 {
        m.focal_elements().map(|(_, v)| *v).sum()
    }

    #[test]
    fn repeats_of_one_source_carry_one_copy_of_weight() {
        let one = support(0, 0.8, 0.9);
        let (single, _) =
            combine_with_source_dependence(vec![(key(1, "https://a/x"), one.clone())], 0.9)
                .unwrap();
        let (repeated, k) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), one.clone()),
                (key(1, "https://a/x/"), one.clone()),
                (key(1, "HTTPS://A/X"), one),
            ],
            0.9,
        )
        .unwrap();
        let b1 = measures::pignistic_probability(&single, 0);
        let bn = measures::pignistic_probability(&repeated, 0);
        assert!((b1 - bn).abs() < 1e-12, "{b1} vs {bn}");
        assert!((total(&repeated) - 1.0).abs() < 1e-9);
        assert!(
            k.abs() < 1e-12,
            "agreeing repeats carry no conflict, got {k}"
        );
    }

    #[test]
    fn distinct_urls_and_unkeyed_rows_still_reinforce() {
        let one = support(0, 0.8, 0.9);
        let b1 = measures::pignistic_probability(&one, 0);
        for items in [
            vec![
                (key(1, "https://a/x"), one.clone()),
                (key(1, "https://b/y"), one.clone()),
            ],
            vec![(None, one.clone()), (None, one.clone())],
            // Same URL, different agent: two observers, two sources.
            vec![
                (key(1, "https://a/x"), one.clone()),
                (key(2, "https://a/x"), one.clone()),
            ],
        ] {
            let (c, _) = combine_with_source_dependence(items, 0.9).unwrap();
            let b2 = measures::pignistic_probability(&c, 0);
            assert!(
                b2 > b1 + 1e-6,
                "independent sources must reinforce: {b1} -> {b2}"
            );
        }
    }

    #[test]
    fn a_source_that_flips_is_changed_content_and_folds_as_before() {
        // One source supports, then refutes. That is a changed verdict, not a
        // repeat: it must fold exactly as main's Dempster fold does, and the
        // cached triple must stay ordered Bel <= BetP <= Pl.
        let sup = support(0, 0.8, 0.9);
        let refute = support(1, 0.5, 0.9);
        let (dempster, _) =
            combination::combine_multiple(&[sup.clone(), refute.clone()], 0.9).unwrap();
        let (c, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), sup),
                (key(1, "https://a/x"), refute),
            ],
            0.9,
        )
        .unwrap();
        assert_eq!(c.masses(), dempster.masses());
        let target = FocalElement::positive(BTreeSet::from([0]));
        let bel = measures::belief(&c, &target);
        let pl = measures::plausibility(&c, &target);
        let betp = measures::pignistic_probability(&c, 0);
        assert!(
            bel <= betp + 1e-12 && betp <= pl + 1e-12,
            "Bel {bel} <= BetP {betp} <= Pl {pl}"
        );
    }

    #[test]
    fn repeats_inside_a_flipping_source_still_collapse_per_verdict() {
        // support, support, refute from one source == support, refute.
        let sup = support(0, 0.8, 0.9);
        let refute = support(1, 0.5, 0.9);
        let (once, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), sup.clone()),
                (key(1, "https://a/x"), refute.clone()),
            ],
            0.9,
        )
        .unwrap();
        let (twice, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), sup.clone()),
                (key(1, "https://a/x"), sup),
                (key(1, "https://a/x"), refute),
            ],
            0.9,
        )
        .unwrap();
        let a = measures::pignistic_probability(&once, 0);
        let b = measures::pignistic_probability(&twice, 0);
        assert!((a - b).abs() < 1e-12, "{a} vs {b}");
    }

    #[test]
    fn a_stronger_repeat_keeps_the_strongest_reading_not_the_product() {
        let weak = support(0, 0.6, 0.9);
        let strong = support(0, 0.8, 0.9);
        let (c, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), weak),
                (key(1, "https://a/x"), strong.clone()),
            ],
            0.9,
        )
        .unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!((c.mass_of(&fe0) - strong.mass_of(&fe0)).abs() < 1e-12);
        assert!((total(&c) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn non_classical_group_members_fall_back_to_independent_folding() {
        let one = support(0, 0.8, 0.9);
        let f = frame();
        let open = MassFunction::new(
            f.clone(),
            std::collections::BTreeMap::from([
                (FocalElement::missing(&f), 0.3),
                (FocalElement::theta(&f), 0.7),
            ]),
        )
        .unwrap();
        assert!(!open.is_classical());
        let independent = combination::combine_multiple(&[one.clone(), open.clone()], 0.9)
            .unwrap()
            .0;
        let (c, _) = combine_with_source_dependence(
            vec![(key(1, "https://a/x"), one), (key(1, "https://a/x"), open)],
            0.9,
        )
        .unwrap();
        assert_eq!(c.masses(), independent.masses());
    }

    #[test]
    fn a_keyed_mixed_bba_is_not_grouped_with_a_simple_support() {
        // A legacy mixed BBA (mass on {TRUE} AND {FALSE}) is not a simple
        // support function: the cautious rule's "strongest repeat" reading does
        // not apply to it, so it must fold as an independent input even when it
        // shares a source key with a simple support on either of its focal
        // elements. Both verdicts are present, so whichever focal element a
        // mis-grouping picked, it would land in a group.
        let f = frame();
        let sup = support(0, 0.8, 0.9);
        let refute = support(1, 0.5, 0.9);
        let mixed = MassFunction::new(
            f.clone(),
            std::collections::BTreeMap::from([
                (FocalElement::positive(BTreeSet::from([0])), 0.4),
                (FocalElement::positive(BTreeSet::from([1])), 0.2),
                (FocalElement::theta(&f), 0.4),
            ]),
        )
        .unwrap();
        let independent =
            combination::combine_multiple(&[sup.clone(), refute.clone(), mixed.clone()], 0.9)
                .unwrap()
                .0;
        let (c, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), sup),
                (key(1, "https://a/x"), refute),
                (key(1, "https://a/x"), mixed),
            ],
            0.9,
        )
        .unwrap();
        assert_eq!(c.masses(), independent.masses());
    }

    #[test]
    fn repeats_on_a_frame_too_large_for_the_cautious_pass_fold_as_before() {
        // Above MAX_CAUTIOUS_HYPOTHESES the cautious pass is skipped (it walks
        // the power set): keyed repeats on such a frame are Dempster-folded
        // exactly as they were before the rule.
        let big = FrameOfDiscernment::new(
            "nine",
            (0..=MAX_CAUTIOUS_HYPOTHESES)
                .map(|i| format!("H{i}"))
                .collect(),
        )
        .unwrap();
        assert!(big.hypothesis_count() > MAX_CAUTIOUS_HYPOTHESES);
        let m = combination::discount(
            &MassFunction::simple(big, BTreeSet::from([0]), 0.8).unwrap(),
            0.9,
        )
        .unwrap();
        let independent = combination::combine_multiple(&[m.clone(), m.clone()], 0.9)
            .unwrap()
            .0;
        let (c, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), m.clone()),
                (key(1, "https://a/x"), m),
            ],
            0.9,
        )
        .unwrap();
        assert_eq!(c.masses(), independent.masses());
    }

    #[test]
    fn normalize_rejects_blank_and_folds_trivial_variants() {
        assert_eq!(normalize_source_url("   "), None);
        assert_eq!(normalize_source_url("/"), None);
        assert_eq!(
            normalize_source_url(" https://Example.org/RFP/ "),
            Some("https://example.org/rfp".into())
        );
    }
}
