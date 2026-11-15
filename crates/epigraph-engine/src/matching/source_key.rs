//! Provenance key used to filter cross-source pairs.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Provenance identity of a claim. Two claims are "same source" iff they share
/// an asserting paper, share a derivation root, or are both non-paper claims
/// by the same agent — see [`is_same_source`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceKey {
    /// DOIs of EVERY paper that asserts the claim or one of its
    /// `decomposes_to` ancestors, sorted and deduplicated. A claim asserted
    /// by several papers carries all of them, so a shared paper is never
    /// hidden behind an arbitrary single pick. Empty = non-paper claim.
    pub paper_dois: Vec<String>,
    pub agent_id: Uuid,
    /// Root of the claim's `derived_from` chain (`None` when it has no
    /// `derived_from` parent). SCOPE: this is claim-to-claim derivation
    /// lineage only. It does NOT model the intra-source closure that
    /// migration 041's `same_source_papers()` walks (`same_source`,
    /// `section_follows`, `continues_argument`, `decomposes_to`, in either
    /// direction): paper siblings are caught by `paper_dois` (asserting
    /// papers over the `decomposes_to` ancestry), and a claim reachable from
    /// a paper only through `section_follows` / `continues_argument` /
    /// `same_source` edges, with no `asserts` edge on it or an ancestor, is
    /// NOT seen as same-source here. The matcher derives one key per
    /// candidate endpoint, so the undirected closure walk is deliberately
    /// not repeated per claim.
    pub derivation_root: Option<Uuid>,
}

/// Configurable rule for what counts as "same source".
///
/// Default: provenance (paper / derivation), plus same agent for
/// pairs of non-paper claims (always on, see [`is_same_source`]). Set
/// `include_agent_id = true` to also treat any pair with a paper claim on it
/// (paper/paper or paper/non-paper) from the same agent as same-source
/// (stricter — filters out e.g. two papers by the same author).
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct SourceFilterConfig {
    #[serde(default)]
    pub include_agent_id: bool,
}

/// True when `a` and `b` share any asserting paper DOI or another non-null
/// source component, when both are
/// non-paper claims written by the same agent, or (if `cfg.include_agent_id`)
/// when they share an `agent_id` at all.
///
/// A non-paper claim (memorize, telemetry, RFP, ...) has no asserting paper,
/// so `paper_dois` is empty (`papers.doi` is NOT NULL, so empty means "no
/// `paper -asserts->` edge on the claim or on any `decomposes_to` ancestor",
/// never "a paper without a DOI"; see [`derive_source_key`]). For such a
/// claim the authoring agent is the only source signal besides the derivation
/// root, so two of them by one agent are a restatement,
/// not independent corroboration. A pair with a paper claim on either side
/// keeps the paper rule: same agent alone does not make it same-source.
pub fn is_same_source(a: &SourceKey, b: &SourceKey, cfg: SourceFilterConfig) -> bool {
    fn both_eq<T: PartialEq>(x: &Option<T>, y: &Option<T>) -> bool {
        matches!((x, y), (Some(xv), Some(yv)) if xv == yv)
    }
    // Both lists are sorted (see `derive_source_key`), but they are short, so
    // a nested scan is clearer than a merge walk and just as cheap.
    if a.paper_dois.iter().any(|d| b.paper_dois.contains(d)) {
        return true;
    }
    if both_eq(&a.derivation_root, &b.derivation_root) {
        return true;
    }
    let both_non_paper = a.paper_dois.is_empty() && b.paper_dois.is_empty();
    (both_non_paper || cfg.include_agent_id) && a.agent_id == b.agent_id
}

/// Look up a claim's [`SourceKey`] by querying its row, resolving the paper
/// that asserts it or its nearest `decomposes_to` ancestor, and chasing the
/// `derived_from` edge chain to a root (acyclic, capped at depth 32).
pub async fn derive_source_key(pool: &PgPool, claim_id: Uuid) -> Result<SourceKey, sqlx::Error> {
    // `properties->>'ingestion_run_id'` used to be read here as a third
    // provenance component, but no write path ever set it, so the branch was
    // permanently inert and implied coverage that did not exist (50b19b4e).
    // A real ingestion-run key needs a writer first; add it back with one.
    let agent_id: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await?;

    // Canonical paper provenance is relational: paper -asserts-> claim, with
    // the DOI on the papers row. The properties->>'paper_doi' JSON field is
    // never written anywhere in the repo, so reading it always yielded None,
    // making the same-source filter a silent no-op on real data. Resolve the
    // asserting paper's DOI via the edge instead.
    // DELIBERATELY NOT filtered on `valid_to`. This resolves the asserting
    // paper's DOI through a structural `paper --asserts--> claim` edge. Edge
    // retraction (see `EdgeRepository::retract`) is an EVIDENTIAL mechanism —
    // it withdraws a claim-to-claim assertion. Applying it to structural
    // provenance would make a claim's own source unresolvable, which is a
    // different and much worse failure than the one retraction exists to fix.
    // No code path retracts an `asserts` edge.
    //
    // DECOMPOSITION ANCESTRY. An atom that `decompose_claims` splits out of a
    // paper-asserted compound gets the parent's `agent_id` and a
    // `parent -decomposes_to-> atom` edge, but no `asserts` edge of its own
    // (its derivation link is an evidence row, not a walkable edge). Without
    // following `decomposes_to` upward, two atoms of different papers by the
    // ingesting agent would resolve no paper and be dropped as same-agent
    // non-paper claims, and two atoms of one paper by different agents would
    // pass as cross-source. So walk the ancestry (capped at depth 32, like
    // the derivation walk below) and collect EVERY asserting paper on it.
    // Keeping only one (the former `ORDER BY depth, doi LIMIT 1`) made a
    // claim asserted by several papers look independent of a claim sharing
    // any of the papers it did not keep. The `decomposes_to` edges are
    // lineage too, so they are not filtered on `valid_to` either.
    let paper_dois = sqlx::query_scalar::<_, String>(
        "WITH RECURSIVE ancestry(id, depth) AS ( \
             SELECT $1::uuid, 0 \
             UNION \
             SELECT d.source_id, a.depth + 1 \
             FROM edges d JOIN ancestry a ON d.target_id = a.id \
             WHERE d.relationship = 'decomposes_to' \
               AND d.source_type = 'claim' AND d.target_type = 'claim' \
               AND a.depth < 32 \
         ) \
         SELECT DISTINCT p.doi FROM ancestry a \
         JOIN edges e ON e.target_id = a.id AND e.source_type = 'paper' \
              AND e.relationship = 'asserts' \
         JOIN papers p ON p.id = e.source_id \
         ORDER BY p.doi",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await?;

    // Walk the derived_from chain. Stop when there's no parent, when we
    // detect a cycle (parent == current), or when we hit the depth cap.
    let mut current = claim_id;
    let mut depth = 0_usize;
    let derivation_root = loop {
        if depth >= 32 {
            break Some(current);
        }
        // Also deliberately unfiltered: `derived_from` is lineage, not evidence.
        // Retracting an evidential edge must not sever a decomposition chain.
        // `ORDER BY target_id` makes the walk deterministic for a claim with
        // several `derived_from` parents; without it `LIMIT 1` could pick a
        // different parent (and so a different root) on each run.
        let parent: Option<(Uuid,)> = sqlx::query_as(
            "SELECT target_id FROM edges
             WHERE source_id = $1 AND relationship = 'derived_from'
             ORDER BY target_id
             LIMIT 1",
        )
        .bind(current)
        .fetch_optional(pool)
        .await?;
        match parent {
            Some((p,)) if p != current => {
                current = p;
                depth += 1;
            }
            _ => break if depth == 0 { None } else { Some(current) },
        }
    };

    Ok(SourceKey {
        paper_dois,
        agent_id,
        derivation_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(p: Option<&str>, a: Uuid, dr: Option<Uuid>) -> SourceKey {
        SourceKey {
            paper_dois: p.into_iter().map(str::to_string).collect(),
            agent_id: a,
            derivation_root: dr,
        }
    }

    #[test]
    fn same_paper_doi_is_same_source() {
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let l = k(Some("10.1/x"), a1, None);
        let r = k(Some("10.1/x"), a2, None);
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    /// 50b19b4e: a claim asserted by two papers is same-source with a claim
    /// from EITHER of them, not only with whichever DOI sorted first.
    #[test]
    fn any_shared_doi_in_a_multi_paper_key_is_same_source() {
        let l = SourceKey {
            paper_dois: vec!["10.1/only-a".into(), "10.2/shared".into()],
            agent_id: Uuid::new_v4(),
            derivation_root: None,
        };
        let r = k(Some("10.2/shared"), Uuid::new_v4(), None);
        let other = k(Some("10.3/unrelated"), Uuid::new_v4(), None);
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
        assert!(is_same_source(&r, &l, SourceFilterConfig::default()));
        assert!(!is_same_source(&l, &other, SourceFilterConfig::default()));
    }

    #[test]
    fn different_paper_same_agent_is_cross_source_by_default() {
        let a = Uuid::new_v4();
        let l = k(Some("10.1/x"), a, None);
        let r = k(Some("10.1/y"), a, None);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn different_paper_same_agent_is_same_source_with_strict_flag() {
        let a = Uuid::new_v4();
        let l = k(Some("10.1/x"), a, None);
        let r = k(Some("10.1/y"), a, None);
        assert!(is_same_source(
            &l,
            &r,
            SourceFilterConfig {
                include_agent_id: true
            }
        ));
    }

    #[test]
    fn null_paper_doesnt_match_null_paper() {
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let l = k(None, a1, None);
        let r = k(None, a2, None);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    /// R-12: two NON-paper claims (no asserting paper on either side, e.g.
    /// memorize / RFP notes) written by the SAME agent are same-source under
    /// the default config, with no run id or derivation root to link them.
    #[test]
    fn non_paper_same_agent_is_same_source_by_default() {
        let a = Uuid::new_v4();
        let l = k(None, a, None);
        let r = k(None, a, None);
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    /// R-12 keeps the paper rule for any pair with a paper claim on it: a
    /// paper-backed claim and a non-paper claim by the same agent stay
    /// cross-source under the default config (no shared run or root).
    #[test]
    fn paper_vs_non_paper_same_agent_stays_cross_source_by_default() {
        let a = Uuid::new_v4();
        let l = k(Some("10.1/x"), a, None);
        let r = k(None, a, None);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
        assert!(!is_same_source(&r, &l, SourceFilterConfig::default()));
    }

    #[test]
    fn shared_derivation_root_is_same_source() {
        let root = Uuid::new_v4();
        let l = k(None, Uuid::new_v4(), Some(root));
        let r = k(None, Uuid::new_v4(), Some(root));
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }
}
