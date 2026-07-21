//! Provenance key used to filter cross-source pairs.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Provenance identity of a claim. Two claims are "same source" iff any
/// non-null component matches — see [`is_same_source`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceKey {
    pub paper_doi: Option<String>,
    pub agent_id: Uuid,
    pub ingestion_run_id: Option<Uuid>,
    pub derivation_root: Option<Uuid>,
}

/// Configurable rule for what counts as "same source".
///
/// Default: provenance-only (paper / ingestion / derivation). Set
/// `include_agent_id = true` to also treat claims from the same agent as
/// same-source (stricter — filters out e.g. two papers by the same author).
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct SourceFilterConfig {
    #[serde(default)]
    pub include_agent_id: bool,
}

/// True when `a` and `b` share a non-null source component (or, if
/// `cfg.include_agent_id`, share an `agent_id`).
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
    if cfg.include_agent_id && a.agent_id == b.agent_id {
        return true;
    }
    false
}

/// Look up a claim's [`SourceKey`] by querying its row and chasing the
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
    let paper_doi = sqlx::query_scalar::<_, Option<String>>(
        "SELECT p.doi FROM edges e JOIN papers p ON p.id = e.source_id \
         WHERE e.target_id = $1 AND e.source_type = 'paper' \
         AND e.relationship = 'asserts' LIMIT 1",
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

    #[test]
    fn shared_derivation_root_is_same_source() {
        let root = Uuid::new_v4();
        let l = k(None, Uuid::new_v4(), None, Some(root));
        let r = k(None, Uuid::new_v4(), None, Some(root));
        assert!(is_same_source(&l, &r, SourceFilterConfig::default()));
    }
}
