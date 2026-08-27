#![allow(clippy::wildcard_imports)]

use std::collections::HashSet;

use rmcp::model::*;

use crate::errors::{internal_error, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::GetProvenanceParams;

use epigraph_db::{LineageRepository, LineageResult};

/// Preserves the value `get_provenance` hardcoded before this change.
const DEFAULT_MAX_DEPTH: i32 = 5;
/// Ceiling on the recursive CTE's depth bound; keeps one call's DB work bounded.
const MAX_MAX_DEPTH: i32 = 20;
/// Entity budget when the caller passes nothing. Mirrors `MAX_CHAIN_NODES = 500`
/// in `crates/epigraph-db/src/repos/provenance_chain.rs` so the two provenance
/// tools truncate at the same scale. (That const is not re-exported from
/// `epigraph_db`'s lib.rs, so it is defined locally rather than imported.)
const DEFAULT_MAX_NODES: usize = 500;
/// Hard ceiling: a caller cannot ask for an unbounded bundle.
const MAX_MAX_NODES: usize = 5_000;

/// `try_from` rather than `as`: a u32 above `i32::MAX` casts to a *negative*
/// i32, which would then clamp to the smallest depth instead of the largest.
fn resolve_max_depth(requested: Option<u32>) -> i32 {
    requested.map_or(DEFAULT_MAX_DEPTH, |d| {
        i32::try_from(d)
            .unwrap_or(MAX_MAX_DEPTH)
            .clamp(1, MAX_MAX_DEPTH)
    })
}

fn resolve_max_nodes(requested: Option<u32>) -> usize {
    requested.map_or(DEFAULT_MAX_NODES, |n| {
        usize::try_from(n)
            .unwrap_or(MAX_MAX_NODES)
            .clamp(1, MAX_MAX_NODES)
    })
}

/// The PROV-O entity list plus the bookkeeping needed to report truncation.
#[derive(Debug, Default)]
struct CappedBundle {
    entities: Vec<serde_json::Value>,
    topological_order: Vec<String>,
    claims_total: usize,
    claims_included: usize,
    evidence_total: usize,
    evidence_included: usize,
    traces_total: usize,
    traces_included: usize,
    truncated: bool,
}

/// Serialize `lineage` into PROV-O entities, keeping at most `max_nodes` of them.
///
/// Claims get the budget first: every evidence and trace entity references a
/// claim by id, so spending on claims first keeps the bundle's skeleton intact.
/// Within each category the sort is total and deterministic — claims by
/// `(depth, id)` so the root and its nearest ancestors survive the cut, evidence
/// and traces by `(claim_id, id)` — because `HashMap` iteration order is not.
fn build_capped_bundle(lineage: &LineageResult, max_nodes: usize) -> CappedBundle {
    let mut sorted_claims: Vec<_> = lineage.claims.values().collect();
    sorted_claims.sort_by_key(|c| (c.depth, c.id));
    let kept_claims = &sorted_claims[..max_nodes.min(sorted_claims.len())];
    let kept_ids: HashSet<_> = kept_claims.iter().map(|c| c.id).collect();
    let mut budget = max_nodes - kept_claims.len();

    let mut sorted_evidence: Vec<_> = lineage
        .evidence
        .values()
        .filter(|e| kept_ids.contains(&e.claim_id))
        .collect();
    sorted_evidence.sort_by_key(|e| (e.claim_id, e.id));
    let kept_evidence = &sorted_evidence[..budget.min(sorted_evidence.len())];
    budget -= kept_evidence.len();

    let mut sorted_traces: Vec<_> = lineage
        .traces
        .values()
        .filter(|t| kept_ids.contains(&t.claim_id))
        .collect();
    sorted_traces.sort_by_key(|t| (t.claim_id, t.id));
    let kept_traces = &sorted_traces[..budget.min(sorted_traces.len())];

    let mut entities =
        Vec::with_capacity(kept_claims.len() + kept_evidence.len() + kept_traces.len());

    for lc in kept_claims {
        entities.push(serde_json::json!({
            "@type": "prov:Entity",
            "@id": format!("claim:{}", lc.id),
            "content": lc.content,
            "truth_value": lc.truth_value,
            "depth": lc.depth,
            "parent_ids": lc.parent_ids.iter().map(|p| format!("claim:{p}")).collect::<Vec<_>>(),
            "evidence_ids": lc.evidence_ids.iter().map(|e| format!("evidence:{e}")).collect::<Vec<_>>(),
        }));
    }

    for le in kept_evidence {
        entities.push(serde_json::json!({
            "@type": "prov:Entity",
            "@id": format!("evidence:{}", le.id),
            "claim_id": format!("claim:{}", le.claim_id),
            "evidence_type": le.evidence_type,
        }));
    }

    for lt in kept_traces {
        entities.push(serde_json::json!({
            "@type": "prov:Activity",
            "@id": format!("trace:{}", lt.id),
            "claim_id": format!("claim:{}", lt.claim_id),
            "reasoning_type": lt.reasoning_type,
            "confidence": lt.confidence,
            "parent_trace_ids": lt.parent_trace_ids.iter().map(|p| format!("trace:{p}")).collect::<Vec<_>>(),
        }));
    }

    // Preserves the repo's depth-descending (ancestors-first) order, restricted
    // to the claims that survived the cut.
    let topological_order: Vec<String> = lineage
        .topological_order
        .iter()
        .filter(|id| kept_ids.contains(id))
        .map(|id| format!("claim:{id}"))
        .collect();

    let claims_total = lineage.claims.len();
    let evidence_total = lineage.evidence.len();
    let traces_total = lineage.traces.len();

    CappedBundle {
        entities,
        topological_order,
        claims_total,
        claims_included: kept_claims.len(),
        evidence_total,
        evidence_included: kept_evidence.len(),
        traces_total,
        traces_included: kept_traces.len(),
        truncated: kept_claims.len() < claims_total
            || kept_evidence.len() < evidence_total
            || kept_traces.len() < traces_total,
    }
}

pub async fn get_provenance(
    server: &EpiGraphMcpFull,
    params: GetProvenanceParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let max_depth = resolve_max_depth(params.max_depth);
    let max_nodes = resolve_max_nodes(params.max_nodes);

    let lineage = LineageRepository::get_lineage(&server.pool, claim_id, Some(max_depth))
        .await
        .map_err(internal_error)?;

    // Build W3C PROV-O style JSON-LD, bounded by the node budget.
    let bundle = build_capped_bundle(&lineage, max_nodes);

    let prov_bundle = serde_json::json!({
        "@context": "https://www.w3.org/ns/prov#",
        "root_claim": format!("claim:{claim_id}"),
        "entities": bundle.entities,
        "topological_order": bundle.topological_order,
        "cycle_detected": lineage.cycle_detected,
        "max_depth_reached": lineage.max_depth_reached,
        "truncated": bundle.truncated,
        "limits": {
            "max_depth": max_depth,
            "max_nodes": max_nodes,
        },
        "entity_counts": {
            "claims": {"total": bundle.claims_total, "included": bundle.claims_included},
            "evidence": {"total": bundle.evidence_total, "included": bundle.evidence_included},
            "traces": {"total": bundle.traces_total, "included": bundle.traces_included},
        },
    });

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&prov_bundle).map_err(internal_error)?,
    )]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_db::{LineageClaim, LineageEvidence, LineageTrace};
    use std::collections::HashMap;
    use uuid::Uuid;

    fn claim(id: Uuid, depth: i32) -> LineageClaim {
        LineageClaim {
            id,
            content: format!("c{depth}"),
            truth_value: 0.9,
            depth,
            parent_ids: vec![],
            evidence_ids: vec![],
            trace_id: None,
        }
    }

    fn evidence(id: Uuid, claim_id: Uuid) -> LineageEvidence {
        LineageEvidence {
            id,
            claim_id,
            evidence_type: "citation".into(),
            content_hash: vec![],
        }
    }

    fn trace(id: Uuid, claim_id: Uuid) -> LineageTrace {
        LineageTrace {
            id,
            claim_id,
            reasoning_type: "deduction".into(),
            confidence: 0.8,
            parent_trace_ids: vec![],
        }
    }

    /// Mirrors what `LineageRepository::get_lineage` returns: maps keyed by id,
    /// and a topological order sorted depth-DESCENDING (ancestors first).
    fn lineage(
        claims: Vec<LineageClaim>,
        ev: Vec<LineageEvidence>,
        tr: Vec<LineageTrace>,
    ) -> LineageResult {
        let mut topo: Vec<(Uuid, i32)> = claims.iter().map(|c| (c.id, c.depth)).collect();
        topo.sort_by_key(|b| std::cmp::Reverse(b.1));
        let max_depth_reached = claims.iter().map(|c| c.depth).max().unwrap_or(0);

        LineageResult {
            claims: claims
                .into_iter()
                .map(|c| (c.id, c))
                .collect::<HashMap<_, _>>(),
            evidence: ev.into_iter().map(|e| (e.id, e)).collect::<HashMap<_, _>>(),
            traces: tr.into_iter().map(|t| (t.id, t)).collect::<HashMap<_, _>>(),
            topological_order: topo.into_iter().map(|(id, _)| id).collect(),
            cycle_detected: false,
            max_depth_reached,
        }
    }

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn entity_ids(bundle: &CappedBundle) -> Vec<String> {
        bundle
            .entities
            .iter()
            .map(|e| e["@id"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn no_cap_hit_leaves_truncated_false() {
        let c0 = claim(id(1), 0);
        let c1 = claim(id(2), 1);
        let c2 = claim(id(3), 2);
        let lr = lineage(
            vec![c0, c1, c2],
            vec![evidence(id(10), id(1)), evidence(id(11), id(2))],
            vec![trace(id(20), id(1))],
        );

        let bundle = build_capped_bundle(&lr, 500);

        assert_eq!(bundle.entities.len(), 6);
        assert!(!bundle.truncated);
        assert_eq!(bundle.topological_order.len(), 3);
        assert_eq!(bundle.claims_included, bundle.claims_total);
        assert_eq!(bundle.evidence_included, bundle.evidence_total);
        assert_eq!(bundle.traces_included, bundle.traces_total);
    }

    #[test]
    fn claims_over_budget_keep_the_shallowest_and_set_truncated() {
        let claims: Vec<_> = (0..5u32)
            .map(|d| claim(id(u128::from(d) + 1), i32::try_from(d).unwrap()))
            .collect();
        let lr = lineage(claims, vec![], vec![]);

        let bundle = build_capped_bundle(&lr, 3);

        assert_eq!(bundle.entities.len(), 3);
        assert_eq!(
            entity_ids(&bundle),
            vec![
                format!("claim:{}", id(1)),
                format!("claim:{}", id(2)),
                format!("claim:{}", id(3)),
            ]
        );
        assert!(bundle.truncated);
        assert_eq!(bundle.claims_included, 3);
        assert_eq!(bundle.claims_total, 5);
    }

    #[test]
    fn budget_spends_on_claims_before_evidence_and_traces() {
        let lr = lineage(
            vec![claim(id(1), 0), claim(id(2), 1)],
            (0..4).map(|n| evidence(id(10 + n), id(1))).collect(),
            (0..4).map(|n| trace(id(20 + n), id(1))).collect(),
        );

        let bundle = build_capped_bundle(&lr, 3);

        assert_eq!(bundle.claims_included, 2);
        assert_eq!(bundle.evidence_included, 1);
        assert_eq!(bundle.traces_included, 0);
        assert!(bundle.truncated);
    }

    #[test]
    fn evidence_and_traces_of_dropped_claims_are_excluded() {
        let deep = id(2);
        let lr = lineage(
            vec![claim(id(1), 0), claim(deep, 3)],
            vec![evidence(id(10), id(1)), evidence(id(11), deep)],
            vec![trace(id(20), id(1)), trace(id(21), deep)],
        );

        // Budget of 1: only the depth-0 claim survives. Note the structural
        // consequence of spending on claims first — once any claim is dropped,
        // `kept_claims.len() == max_nodes`, so the remaining budget is 0 and no
        // evidence or trace is emitted at all. The `kept_ids` filter is the
        // belt-and-braces half of that invariant; this test pins the invariant
        // itself, so a later refactor that hands leftover budget to evidence
        // cannot start emitting evidence orphaned from its claim.
        let bundle = build_capped_bundle(&lr, 1);

        assert_eq!(bundle.claims_included, 1);
        assert_eq!(bundle.evidence_included, 0);
        assert_eq!(bundle.traces_included, 0);
        assert!(bundle.truncated);
        let orphan = format!("claim:{deep}");
        for entity in &bundle.entities {
            assert_ne!(entity["claim_id"].as_str(), Some(orphan.as_str()));
        }
        assert!(!entity_ids(&bundle).contains(&orphan));
    }

    #[test]
    fn topological_order_is_filtered_to_retained_claims() {
        let claims: Vec<_> = (0..4u32)
            .map(|d| claim(id(u128::from(d) + 1), i32::try_from(d).unwrap()))
            .collect();
        let lr = lineage(claims, vec![], vec![]);

        let bundle = build_capped_bundle(&lr, 2);

        // Retained = depths 0 and 1; repo order is depth-descending, so depth 1 first.
        assert_eq!(
            bundle.topological_order,
            vec![format!("claim:{}", id(2)), format!("claim:{}", id(1))]
        );
        let ids = entity_ids(&bundle);
        for topo_id in &bundle.topological_order {
            assert!(ids.contains(topo_id));
        }
    }

    #[test]
    fn entity_selection_is_deterministic() {
        let mk = |reversed: bool| {
            let mut claims = vec![claim(id(1), 0), claim(id(2), 1), claim(id(3), 2)];
            let mut ev = vec![evidence(id(10), id(1)), evidence(id(11), id(2))];
            let mut tr = vec![trace(id(20), id(1))];
            if reversed {
                claims.reverse();
                ev.reverse();
                tr.reverse();
            }
            lineage(claims, ev, tr)
        };

        let a = build_capped_bundle(&mk(false), 4);
        let b = build_capped_bundle(&mk(true), 4);

        assert_eq!(a.entities, b.entities);
        assert_eq!(a.topological_order, b.topological_order);
    }

    #[test]
    fn empty_lineage_yields_empty_bundle_untruncated() {
        let bundle = build_capped_bundle(&LineageResult::default(), 500);

        assert!(bundle.entities.is_empty());
        assert!(bundle.topological_order.is_empty());
        assert!(!bundle.truncated);
    }

    #[test]
    fn resolve_max_depth_defaults_to_five_and_clamps() {
        assert_eq!(resolve_max_depth(None), 5);
        assert_eq!(resolve_max_depth(Some(0)), 1);
        assert_eq!(resolve_max_depth(Some(3)), 3);
        assert_eq!(resolve_max_depth(Some(999)), 20);
        // A naive `as i32` cast would wrap this negative and clamp it to 1.
        assert_eq!(resolve_max_depth(Some(3_000_000_000)), 20);
    }

    #[test]
    fn resolve_max_nodes_defaults_and_clamps() {
        assert_eq!(resolve_max_nodes(None), 500);
        assert_eq!(resolve_max_nodes(Some(0)), 1);
        assert_eq!(resolve_max_nodes(Some(50)), 50);
        assert_eq!(resolve_max_nodes(Some(99_999)), 5_000);
    }
}
