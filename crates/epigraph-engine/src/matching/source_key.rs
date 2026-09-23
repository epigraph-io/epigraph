//! Provenance key used to filter cross-source pairs.

use std::collections::BTreeSet;

use epigraph_db::repos::DerivationRepository;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Provenance identity of a claim. Two claims are "same source" iff any
/// non-null component matches, or their derivation lineages overlap — see
/// [`is_same_source`].
///
/// There is deliberately no ingestion-run component. The design spec's
/// `ingestion_run_id` was read from `claims.properties->>'ingestion_run_id'`,
/// which no write path ever sets, so it could never match; it was removed
/// rather than kept as a branch that looks like a control. Making it real needs
/// a recorded non-paper provenance signal on ingest (backlog c618e4fc).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceKey {
    pub paper_doi: Option<String>,
    pub agent_id: Uuid,
    /// The claim itself plus every claim it was derived from, transitively,
    /// over claim-to-claim `derived_from` edges of any spelling and case (see
    /// [`DerivationRepository::lineage_ids`]).
    ///
    /// A SET, compared by overlap, rather than the single `derivation_root`
    /// it replaced. The single root returned `None` for a claim with no parent,
    /// so a root never matched its own child; it followed one `LIMIT 1` parent
    /// per hop, so a multi-parent claim's root depended on the query plan; and
    /// it walked onto evidence ids. Overlap makes a parent/child pair, siblings
    /// under any shared ancestor, and a multi-parent claim's siblings through
    /// every parent all "same source", deterministically.
    pub derivation_lineage: BTreeSet<Uuid>,
}

/// Configurable rule for what counts as "same source".
///
/// Default: provenance-only (paper / derivation). Set
/// `include_agent_id = true` to also treat claims from the same agent as
/// same-source (stricter — filters out e.g. two papers by the same author).
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct SourceFilterConfig {
    #[serde(default)]
    pub include_agent_id: bool,
}

/// True when `a` and `b` share a non-null source component, when their
/// derivation lineages overlap, or (if `cfg.include_agent_id`) when they share
/// an `agent_id`.
pub fn is_same_source(a: &SourceKey, b: &SourceKey, cfg: SourceFilterConfig) -> bool {
    fn both_eq<T: PartialEq>(x: &Option<T>, y: &Option<T>) -> bool {
        matches!((x, y), (Some(xv), Some(yv)) if xv == yv)
    }
    if both_eq(&a.paper_doi, &b.paper_doi) {
        return true;
    }
    if !a.derivation_lineage.is_disjoint(&b.derivation_lineage) {
        return true;
    }
    if cfg.include_agent_id && a.agent_id == b.agent_id {
        return true;
    }
    false
}

/// Look up a claim's [`SourceKey`]: its row, its asserting paper's DOI, and its
/// derivation lineage.
pub async fn derive_source_key(pool: &PgPool, claim_id: Uuid) -> Result<SourceKey, sqlx::Error> {
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
    let paper_doi = sqlx::query_scalar::<_, Option<String>>(
        "SELECT p.doi FROM edges e JOIN papers p ON p.id = e.source_id \
         WHERE e.target_id = $1 AND e.source_type = 'paper' \
         AND e.relationship = 'asserts' LIMIT 1",
    )
    .bind(claim_id)
    .fetch_optional(pool)
    .await?
    .flatten();

    // Also deliberately unfiltered on `valid_to`: `derived_from` is lineage,
    // not evidence. Retracting an evidential edge must not sever a derivation
    // chain. Direction, spelling and the claim-to-claim restriction are
    // documented on `epigraph_db::repos::derivation`.
    let derivation_lineage = DerivationRepository::lineage_ids(pool, claim_id)
        .await?
        .into_iter()
        .collect();

    Ok(SourceKey {
        paper_doi,
        agent_id,
        derivation_lineage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(p: Option<&str>, a: Uuid, lineage: &[Uuid]) -> SourceKey {
        SourceKey {
            paper_doi: p.map(str::to_string),
            agent_id: a,
            derivation_lineage: lineage.iter().copied().collect(),
        }
    }

    #[test]
    fn same_paper_doi_is_same_source() {
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let l = k(Some("10.1/x"), a1, &[]);
        let r = k(Some("10.1/x"), a2, &[]);
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn different_paper_same_agent_is_cross_source_by_default() {
        let a = Uuid::new_v4();
        let l = k(Some("10.1/x"), a, &[]);
        let r = k(Some("10.1/y"), a, &[]);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn different_paper_same_agent_is_same_source_with_strict_flag() {
        let a = Uuid::new_v4();
        let l = k(Some("10.1/x"), a, &[]);
        let r = k(Some("10.1/y"), a, &[]);
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
        let l = k(None, a1, &[]);
        let r = k(None, a2, &[]);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn shared_derivation_ancestor_is_same_source() {
        let (x, y, root) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let l = k(None, Uuid::new_v4(), &[x, root]);
        let r = k(None, Uuid::new_v4(), &[y, root]);
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    /// A root's lineage is just itself, and its child's lineage contains it.
    /// The single-root key this replaced gave the root `None` and so never
    /// matched a parent with its own child.
    #[test]
    fn parent_and_child_are_same_source() {
        let (parent, child) = (Uuid::new_v4(), Uuid::new_v4());
        let l = k(None, Uuid::new_v4(), &[parent]);
        let r = k(None, Uuid::new_v4(), &[child, parent]);
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn disjoint_derivation_lineages_are_cross_source() {
        let l = k(None, Uuid::new_v4(), &[Uuid::new_v4(), Uuid::new_v4()]);
        let r = k(None, Uuid::new_v4(), &[Uuid::new_v4(), Uuid::new_v4()]);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
    }
}
