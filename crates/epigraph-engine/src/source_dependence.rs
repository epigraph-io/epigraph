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
//! the same evidence `source_url` — are folded with Denoeux's cautious rule
//! ([`combination::cautious_combine`]) into ONE BBA before the Dempster fold.
//! The cautious rule is idempotent, so N copies of one source's verdict carry
//! exactly the weight of one, and of differing verdicts from one source the
//! least-committed combination survives rather than their product.
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
//!   is left where it is; this module is the shared path both the MCP write
//!   (`ds_auto::auto_wire_ds_update`) and the recompute
//!   (`edge_factor::compute_combined_belief`) use, so the next recompute cannot
//!   re-inflate what the write left honest.

use std::collections::HashMap;

use uuid::Uuid;

use epigraph_db::{EvidenceRepository, MassFunctionRow};
use epigraph_ds::{combination, DsError, MassFunction};

/// Frames larger than this are folded without the cautious pass: the rule
/// walks the power set twice (`O(4^n)`), and every BBA that can carry a
/// [`SourceKey`] today is written on the two-hypothesis `binary_truth` frame.
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
/// visible to `viewer`.
///
/// Read on the caller's connection, through `viewer`, so the write path's
/// stamped transaction and the recompute's connection both see the evidence
/// rows their own BBAs reference.
///
/// # Errors
/// String error if the evidence read fails.
pub async fn source_keys_for_rows(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    rows: &[MassFunctionRow],
) -> Result<Vec<Option<SourceKey>>, String> {
    let evidence_ids: Vec<Uuid> = rows
        .iter()
        .filter(|r| r.source_agent_id.is_some())
        .filter_map(|r| r.evidence_id)
        .collect();
    let urls: HashMap<Uuid, String> = if evidence_ids.is_empty() {
        HashMap::new()
    } else {
        EvidenceRepository::source_urls_by_id(&mut *conn, viewer, &evidence_ids)
            .await
            .map_err(|e| format!("evidence source_url read: {e}"))?
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

/// Combine already-discounted BBAs, folding same-source BBAs cautiously first.
///
/// `items` pairs each discounted BBA with its [`SourceKey`] (`None` = no
/// source identity, treated as independent). Every group of two or more BBAs
/// sharing a key is reduced to one by the cautious rule; the group results and
/// the unkeyed BBAs are then Dempster-folded by
/// [`combination::combine_multiple`] exactly as before.
///
/// A group falls back to independent folding (today's behaviour) when any
/// member is not classical (complement or open-world mass, which
/// `cautious_combine` does not model) or the frame is larger than
/// [`MAX_CAUTIOUS_HYPOTHESES`].
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
    // One slot per source, in first-appearance order so the fold input is
    // deterministic (both rules are order-independent; logs and float
    // rounding are not). An unkeyed BBA is its own slot, as before.
    enum Slot {
        Keyed(SourceKey),
        Unkeyed(MassFunction),
    }
    let mut slots: Vec<Slot> = Vec::new();
    let mut groups: HashMap<SourceKey, Vec<MassFunction>> = HashMap::new();
    for (key, mf) in items {
        match key {
            Some(k) => {
                let members = groups.entry(k.clone()).or_default();
                if members.is_empty() {
                    slots.push(Slot::Keyed(k));
                }
                members.push(mf);
            }
            None => slots.push(Slot::Unkeyed(mf)),
        }
    }

    let mut for_fold: Vec<MassFunction> = Vec::with_capacity(slots.len());
    for slot in slots {
        let members = match slot {
            Slot::Unkeyed(mf) => {
                for_fold.push(mf);
                continue;
            }
            Slot::Keyed(k) => groups.remove(&k).unwrap_or_default(),
        };
        let cautious_ok = members.len() > 1
            && members.iter().all(|m| {
                m.is_classical() && m.frame().hypothesis_count() <= MAX_CAUTIOUS_HYPOTHESES
            });
        if cautious_ok {
            let mut it = members.into_iter();
            let first = it.next().expect("len > 1");
            let folded = it.try_fold(first, |acc, m| combination::cautious_combine(&acc, &m))?;
            for_fold.push(folded);
        } else {
            for_fold.extend(members);
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
    use epigraph_ds::{measures, FocalElement, FrameOfDiscernment};
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
    fn a_source_that_flips_surfaces_conflict_and_adds_no_support() {
        // One source supports at 0.72, then refutes at 0.45 (after discount).
        let sup = support(0, 0.8, 0.9);
        let refute = support(1, 0.5, 0.9);
        let (c, k) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), sup.clone()),
                (key(1, "https://a/x"), refute),
            ],
            0.9,
        )
        .unwrap();
        assert!((total(&c) - 1.0).abs() < 1e-9, "masses must sum to 1");
        assert!(
            k > 0.0,
            "a self-contradicting source must surface as conflict"
        );
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!(
            c.mass_of(&fe0) <= sup.mass_of(&fe0) + 1e-12,
            "a flip must never ADD support"
        );
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
    fn normalize_rejects_blank_and_folds_trivial_variants() {
        assert_eq!(normalize_source_url("   "), None);
        assert_eq!(normalize_source_url("/"), None);
        assert_eq!(
            normalize_source_url(" https://Example.org/RFP/ "),
            Some("https://example.org/rfp".into())
        );
    }
}
