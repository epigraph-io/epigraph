//! Provenance key used to filter cross-source pairs.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Provenance identity of a claim. Two claims are "same source" iff any
/// non-null provenance component matches, or both are non-paper claims by the
/// same agent — see [`is_same_source`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceKey {
    pub paper_doi: Option<String>,
    pub agent_id: Uuid,
    pub ingestion_run_id: Option<Uuid>,
    pub derivation_root: Option<Uuid>,
}

/// Configurable rule for what counts as "same source".
///
/// Default: provenance (paper / ingestion / derivation), plus same agent for
/// pairs of non-paper claims (always on, see [`is_same_source`]). Set
/// `include_agent_id = true` to also treat any pair with a paper claim on it
/// (paper/paper or paper/non-paper) from the same agent as same-source
/// (stricter — filters out e.g. two papers by the same author).
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct SourceFilterConfig {
    #[serde(default)]
    pub include_agent_id: bool,
}

/// True when `a` and `b` share a non-null source component, when both are
/// non-paper claims written by the same agent, or (if `cfg.include_agent_id`)
/// when they share an `agent_id` at all.
///
/// A non-paper claim (memorize, telemetry, RFP, ...) has no asserting paper,
/// so `paper_doi` is `None` (`papers.doi` is NOT NULL, so `None` means "no
/// `paper -asserts->` edge on the claim or on any `decomposes_to` ancestor",
/// never "a paper without a DOI"; see [`derive_source_key`]). For such a
/// claim the authoring agent is the only source signal besides the ingestion
/// run and derivation root, so two of them by one agent are a restatement,
/// not independent corroboration. A pair with a paper claim on either side
/// keeps the paper rule: same agent alone does not make it same-source.
pub fn is_same_source(a: &SourceKey, b: &SourceKey, cfg: SourceFilterConfig) -> bool {
    fn both_eq<T: PartialEq>(x: &Option<T>, y: &Option<T>) -> bool {
        matches!((x, y), (Some(xv), Some(yv)) if xv == yv)
    }
    if both_eq(&a.paper_doi, &b.paper_doi) {
        return true;
    }
    if both_eq(&a.ingestion_run_id, &b.ingestion_run_id) {
        return true;
    }
    if both_eq(&a.derivation_root, &b.derivation_root) {
        return true;
    }
    let both_non_paper = a.paper_doi.is_none() && b.paper_doi.is_none();
    if (both_non_paper || cfg.include_agent_id) && a.agent_id == b.agent_id {
        return true;
    }
    false
}

/// Look up a claim's [`SourceKey`] by querying its row, resolving the paper
/// that asserts it or its nearest `decomposes_to` ancestor, and chasing the
/// `derived_from` edge chain to a root (acyclic, capped at depth 32).
pub async fn derive_source_key(pool: &PgPool, claim_id: Uuid) -> Result<SourceKey, sqlx::Error> {
    let (agent_id, props): (Uuid, serde_json::Value) =
        sqlx::query_as("SELECT agent_id, properties FROM claims WHERE id = $1")
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
    // the derivation walk below) and take the nearest asserting paper: a
    // direct `asserts` edge (depth 0) always wins, so a directly asserted
    // claim keeps exactly today's DOI. `ORDER BY depth, doi` makes the pick
    // deterministic for an atom with several parents. The `decomposes_to`
    // edges are lineage too, so they are not filtered on `valid_to` either.
    let paper_doi = sqlx::query_scalar::<_, Option<String>>(
        "WITH RECURSIVE ancestry(id, depth) AS ( \
             SELECT $1::uuid, 0 \
             UNION \
             SELECT d.source_id, a.depth + 1 \
             FROM edges d JOIN ancestry a ON d.target_id = a.id \
             WHERE d.relationship = 'decomposes_to' \
               AND d.source_type = 'claim' AND d.target_type = 'claim' \
               AND a.depth < 32 \
         ) \
         SELECT p.doi FROM ancestry a \
         JOIN edges e ON e.target_id = a.id AND e.source_type = 'paper' \
              AND e.relationship = 'asserts' \
         JOIN papers p ON p.id = e.source_id \
         ORDER BY a.depth, p.doi LIMIT 1",
    )
    .bind(claim_id)
    .fetch_optional(pool)
    .await?
    .flatten();

    let ingestion_run_id = props
        .get("ingestion_run_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

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
        let parent: Option<(Uuid,)> = sqlx::query_as(
            "SELECT target_id FROM edges
             WHERE source_id = $1 AND relationship = 'derived_from'
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
        paper_doi,
        agent_id,
        ingestion_run_id,
        derivation_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(p: Option<&str>, a: Uuid, ir: Option<Uuid>, dr: Option<Uuid>) -> SourceKey {
        SourceKey {
            paper_doi: p.map(str::to_string),
            agent_id: a,
            ingestion_run_id: ir,
            derivation_root: dr,
        }
    }

    #[test]
    fn same_paper_doi_is_same_source() {
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let l = k(Some("10.1/x"), a1, None, None);
        let r = k(Some("10.1/x"), a2, None, None);
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn different_paper_same_agent_is_cross_source_by_default() {
        let a = Uuid::new_v4();
        let l = k(Some("10.1/x"), a, None, None);
        let r = k(Some("10.1/y"), a, None, None);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn different_paper_same_agent_is_same_source_with_strict_flag() {
        let a = Uuid::new_v4();
        let l = k(Some("10.1/x"), a, None, None);
        let r = k(Some("10.1/y"), a, None, None);
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
        let l = k(None, a1, None, None);
        let r = k(None, a2, None, None);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    /// R-12: two NON-paper claims (no asserting paper on either side, e.g.
    /// memorize / RFP notes) written by the SAME agent are same-source under
    /// the default config, with no run id or derivation root to link them.
    #[test]
    fn non_paper_same_agent_is_same_source_by_default() {
        let a = Uuid::new_v4();
        let l = k(None, a, None, None);
        let r = k(None, a, None, None);
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    /// R-12 keeps the paper rule for any pair with a paper claim on it: a
    /// paper-backed claim and a non-paper claim by the same agent stay
    /// cross-source under the default config (no shared run or root).
    #[test]
    fn paper_vs_non_paper_same_agent_stays_cross_source_by_default() {
        let a = Uuid::new_v4();
        let l = k(Some("10.1/x"), a, None, None);
        let r = k(None, a, None, None);
        assert!(!is_same_source(&l, &r, SourceFilterConfig::default()));
        assert!(!is_same_source(&r, &l, SourceFilterConfig::default()));
    }

    /// Non-paper claims still link through a shared ingestion run even when
    /// written by different agents.
    #[test]
    fn non_paper_shared_ingestion_run_is_same_source() {
        let run = Uuid::new_v4();
        let l = k(None, Uuid::new_v4(), Some(run), None);
        let r = k(None, Uuid::new_v4(), Some(run), None);
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }

    #[test]
    fn shared_derivation_root_is_same_source() {
        let root = Uuid::new_v4();
        let l = k(None, Uuid::new_v4(), None, Some(root));
        let r = k(None, Uuid::new_v4(), None, Some(root));
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }
}
