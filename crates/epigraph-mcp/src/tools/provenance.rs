#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::GetProvenanceParams;

use std::collections::{HashMap, HashSet};

use epigraph_db::{LineageEvidence, LineageRepository, LineageResult, LineageTrace};
use uuid::Uuid;

/// Default ancestor depth. Unchanged from the previous hardcoded `Some(5)`.
const DEFAULT_MAX_DEPTH: i32 = 5;
/// Ceiling on `max_depth`, so a caller cannot ask for an effectively
/// unbounded walk.
const MAX_MAX_DEPTH: i32 = 20;

/// Default cap on claim nodes kept in the bundle.
///
/// Previously `None` — i.e. no cap at all — which is the first half of why
/// this tool emitted 145K-235K-character responses and exceeded the MCP tool
/// output token limit (backlog `0e6ec456`).
const DEFAULT_MAX_NODES: usize = 50;
/// Ceiling on `max_nodes`.
const MAX_MAX_NODES: usize = 500;

/// Default per-claim content budget, in characters.
///
/// The second half of the size bound, and the one that actually matters: node
/// count alone does not bound bytes, because the bundle emits the FULL
/// `lc.content` for every claim entity. Paragraph-level decomposition claims
/// run 1-2 KB each, so a 50-node cap with unbounded content would still land
/// at 50-100 KB and keep erroring out.
///
/// `DEFAULT_MAX_NODES * DEFAULT_MAX_CONTENT_CHARS` bounds only the claim TEXT
/// (50 * 500 = 25,000 characters). It does not bound the bundle: evidence and
/// trace entities carry no content field but are emitted per kept claim, and
/// an evidence-dense lineage still came to 83,074 characters at these
/// defaults (backlog `31c10a5a`, 2026-10-04: 50 claims ~36K, 151 evidence
/// ~27K, 36 traces ~8K). The bound on the whole response is
/// [`DEFAULT_MAX_OUTPUT_CHARS`].
const DEFAULT_MAX_CONTENT_CHARS: usize = 500;
/// Lower bound on `max_content_chars` — below this the content is useless for
/// the "assess evidence depth" workflow step this tool serves.
const MIN_MAX_CONTENT_CHARS: usize = 50;
/// Ceiling on `max_content_chars`.
const MAX_MAX_CONTENT_CHARS: usize = 20_000;

/// Default budget for the WHOLE serialised bundle, in bytes of compact JSON
/// (every byte is at least one character, so this also bounds characters).
///
/// Node and content caps multiply by evidence/trace fan-out, so no fixed node
/// cap bounds the size; this does. Claims are admitted nearest-first and the
/// walk stops at the first claim whose group (claim + its evidence + its
/// traces) would overrun the budget. 83,074 is the only measured failing
/// size; 40,000 is about half of it.
const DEFAULT_MAX_OUTPUT_CHARS: usize = 40_000;
/// Floor on `max_output_chars`, so a caller cannot starve the bundle below
/// the target claim plus a few ancestors.
const MIN_MAX_OUTPUT_CHARS: usize = 10_000;
/// Ceiling on `max_output_chars`.
const MAX_MAX_OUTPUT_CHARS: usize = 500_000;

/// Evidence entities emitted per claim. One claim with thousands of evidence
/// rows must not exhaust the budget on its own; the claim entity carries the
/// full `evidence_count` and `evidence_truncated`.
const MAX_EVIDENCE_PER_CLAIM: usize = 10;
/// Trace entities emitted per claim, for the same reason (`trace_count`,
/// `traces_truncated`).
const MAX_TRACES_PER_CLAIM: usize = 10;

/// Upper bound on one `"claim:<uuid>"` entry of `topological_order` in
/// compact JSON: 42 characters, two quotes and a separating comma.
const CLAIM_REF_CHARS: usize = "\"claim:\",".len() + 36;
/// Stand-in for the bundle's counters when the scaffold is measured; no
/// emitted count can have more digits than this.
const COUNT_PLACEHOLDER: usize = 9_999_999;

/// Truncate `content` to at most `max_chars` **characters** (not bytes, so a
/// multi-byte grapheme is never split into invalid UTF-8).
///
/// Returns `(text, was_truncated, original_char_count)`.
fn cap_content(content: &str, max_chars: usize) -> (String, bool, usize) {
    let total = content.chars().count();
    if total <= max_chars {
        return (content.to_string(), false, total);
    }
    (content.chars().take(max_chars).collect(), true, total)
}

/// Build a W3C PROV-O style JSON-LD bundle for a claim's lineage, bounded in
/// node count, per-claim content length, per-claim evidence/trace count, and
/// total serialised size.
///
/// # Why the bounds exist
///
/// This tool used to call
/// `LineageRepository::get_lineage(pool, claim_id, Some(5), None)` — the 4th
/// argument is `max_nodes`, and `None` disables the cap entirely — and then
/// emit every claim's full `content`. Against claims embedded in a dense
/// hierarchical document decomposition that produced 145K-235K-character
/// responses which exceeded the MCP tool output token limit and **errored the
/// call out entirely**, so a caller got nothing at all rather than a bounded
/// answer. That broke the documented tier2/tier3 enrichment step
/// ("get_claim + get_provenance to assess existing evidence depth and type"),
/// which then fell back to direct web verification (backlog `0e6ec456`).
///
/// The node and content caps did not finish the job: evidence and trace
/// entities were still emitted without a count cap, and an evidence-dense
/// lineage failed at 83,074 characters under the defaults (backlog
/// `31c10a5a`). [`build_bundle`] therefore enforces a total budget
/// (`max_output_chars`).
///
/// # Reporting
///
/// A bounded answer is only usable if the caller can tell it apart from a
/// complete one. `truncated` is true when the walk hit `max_depth`, the node
/// cap trimmed the set, the output budget stopped admitting claims
/// (`budget_exhausted`), or a claim's evidence or traces were capped (that
/// claim's `evidence_truncated` / `traces_truncated`). The applied `limits`
/// are echoed, and each trimmed entity carries `content_truncated: true` plus
/// the original `content_chars`.
pub async fn get_provenance(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetProvenanceParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let limits = Limits::from_params(&params);

    let lineage = LineageRepository::get_lineage(
        &server.pool,
        viewer,
        claim_id,
        Some(limits.max_depth),
        Some(limits.max_nodes),
    )
    .await
    .map_err(internal_error)?;

    Ok(CallToolResult::success(vec![Content::text(build_bundle(
        claim_id, &lineage, limits,
    ))]))
}

/// The clamped caps one call applies; echoed in the bundle's `limits`.
#[derive(Debug, Clone, Copy)]
struct Limits {
    max_depth: i32,
    max_nodes: usize,
    max_content_chars: usize,
    max_output_chars: usize,
}

impl Limits {
    /// Apply the defaults and clamp every caller-supplied cap into its range.
    /// The floors stop a caller starving the bundle (e.g. `max_output_chars:
    /// 1` would leave only the target); the ceilings keep it bounded.
    fn from_params(params: &GetProvenanceParams) -> Self {
        Self {
            max_depth: params
                .max_depth
                .unwrap_or(DEFAULT_MAX_DEPTH)
                .clamp(1, MAX_MAX_DEPTH),
            max_nodes: params
                .max_nodes
                .unwrap_or(DEFAULT_MAX_NODES)
                .clamp(1, MAX_MAX_NODES),
            max_content_chars: params
                .max_content_chars
                .unwrap_or(DEFAULT_MAX_CONTENT_CHARS)
                .clamp(MIN_MAX_CONTENT_CHARS, MAX_MAX_CONTENT_CHARS),
            max_output_chars: params
                .max_output_chars
                .unwrap_or(DEFAULT_MAX_OUTPUT_CHARS)
                .clamp(MIN_MAX_OUTPUT_CHARS, MAX_MAX_OUTPUT_CHARS),
        }
    }
}

/// One admitted claim with the evidence and trace entities emitted for it.
struct Group {
    claim_id: Uuid,
    /// Deduplicated parents that are in the lineage; pruned to the emitted
    /// claims in the closure pass.
    parents: Vec<Uuid>,
    claim_entity: serde_json::Value,
    evidence_entities: Vec<serde_json::Value>,
    /// `(trace id, its parent_trace_ids that are in the lineage, entity)`;
    /// pruned to the emitted traces in the closure pass.
    trace_entities: Vec<(Uuid, Vec<Uuid>, serde_json::Value)>,
    /// Some of this claim's evidence or traces were left out by the per-claim caps.
    capped: bool,
}

/// Compact-JSON length of `v` plus one separating comma.
fn entry_len(v: &serde_json::Value) -> usize {
    serde_json::to_string(v).map_or(0, |s| s.len()) + 1
}

/// Everything but the entities and `topological_order`, which the caller fills.
fn bundle_scaffold(
    root: Uuid,
    lineage: &LineageResult,
    limits: Limits,
    truncated: bool,
    budget_exhausted: bool,
    counts: [usize; 3],
) -> serde_json::Value {
    serde_json::json!({
        "@context": "https://www.w3.org/ns/prov#",
        "root_claim": format!("claim:{root}"),
        "entities": [],
        "topological_order": [],
        "cycle_detected": lineage.cycle_detected,
        "max_depth_reached": lineage.max_depth_reached,
        // The bundle stops short of the full lineage: `max_depth` cut the
        // walk, `max_nodes` trimmed it, the output budget stopped admitting
        // claims, or a claim's evidence/traces were capped. Without this a
        // caller cannot distinguish a bounded bundle from a complete one.
        "truncated": truncated,
        "budget_exhausted": budget_exhausted,
        "claim_node_count": counts[0],
        "evidence_entity_count": counts[1],
        "trace_entity_count": counts[2],
        "limits": {
            "max_depth": limits.max_depth,
            "max_nodes": limits.max_nodes,
            "max_content_chars": limits.max_content_chars,
            "max_output_chars": limits.max_output_chars,
        },
    })
}

/// Deterministic, budgeted, reference-closed serialisation of `lineage`.
///
/// * Claims are admitted nearest-first (`topological_order` reversed: the
///   target, then its nearest ancestors), never in `HashMap` order, so the
///   cut is deterministic.
/// * Each admitted claim brings its own evidence (sorted by id, at most
///   [`MAX_EVIDENCE_PER_CLAIM`]) and traces (sorted, at most
///   [`MAX_TRACES_PER_CLAIM`]).
/// * Each group is charged its compact-JSON size with its reference lists
///   before closure pruning (every in-lineage parent and parent trace), plus
///   its `topological_order` entry, against
///   `max_output_chars` minus a worst-case scaffold. The closure pass only
///   shrinks those lists, so the charge is an upper bound and the returned
///   string fits the budget. The one exception is a target claim whose group
///   alone overruns it: the target is always emitted, and the bundle then
///   reports `budget_exhausted`.
/// * Closure: `parent_ids`, `evidence_ids`, `parent_trace_ids` and
///   `topological_order` name only emitted entities.
fn build_bundle(root: Uuid, lineage: &LineageResult, limits: Limits) -> String {
    let mut evidence_by_claim: HashMap<Uuid, Vec<&LineageEvidence>> = HashMap::new();
    for e in lineage.evidence.values() {
        evidence_by_claim.entry(e.claim_id).or_default().push(e);
    }
    let mut traces_by_claim: HashMap<Uuid, Vec<&LineageTrace>> = HashMap::new();
    for t in lineage.traces.values() {
        traces_by_claim.entry(t.claim_id).or_default().push(t);
    }

    let scaffold_len = serde_json::to_string(&bundle_scaffold(
        root,
        lineage,
        limits,
        false,
        false,
        [COUNT_PLACEHOLDER; 3],
    ))
    .map_or(0, |s| s.len());
    let mut remaining = limits.max_output_chars.saturating_sub(scaffold_len);

    let mut groups: Vec<Group> = Vec::new();
    let mut budget_exhausted = false;
    for id in lineage.topological_order.iter().rev() {
        let Some(lc) = lineage.claims.get(id) else {
            continue;
        };

        let mut seen = HashSet::new();
        let parents: Vec<Uuid> = lc
            .parent_ids
            .iter()
            .copied()
            .filter(|p| lineage.claims.contains_key(p) && seen.insert(*p))
            .collect();

        let mut evidence = evidence_by_claim.remove(id).unwrap_or_default();
        evidence.sort_by_key(|e| e.id);
        let evidence_count = evidence.len();
        evidence.truncate(MAX_EVIDENCE_PER_CLAIM);
        let mut traces = traces_by_claim.remove(id).unwrap_or_default();
        traces.sort_by_key(|t| t.id);
        let trace_count = traces.len();
        traces.truncate(MAX_TRACES_PER_CLAIM);
        let evidence_truncated = evidence_count > evidence.len();
        let traces_truncated = trace_count > traces.len();

        let (content, content_truncated, content_chars) =
            cap_content(&lc.content, limits.max_content_chars);
        let claim_entity = serde_json::json!({
            "@type": "prov:Entity",
            "@id": format!("claim:{id}"),
            "content": content,
            "content_truncated": content_truncated,
            "content_chars": content_chars,
            "truth_value": lc.truth_value,
            "depth": lc.depth,
            "parent_ids": parents.iter().map(|p| format!("claim:{p}")).collect::<Vec<_>>(),
            "evidence_ids": evidence.iter().map(|e| format!("evidence:{}", e.id)).collect::<Vec<_>>(),
            "evidence_count": evidence_count,
            "evidence_truncated": evidence_truncated,
            "trace_count": trace_count,
            "traces_truncated": traces_truncated,
        });
        let evidence_entities: Vec<serde_json::Value> = evidence
            .iter()
            .map(|le| {
                serde_json::json!({
                    "@type": "prov:Entity",
                    "@id": format!("evidence:{}", le.id),
                    "claim_id": format!("claim:{}", le.claim_id),
                    "evidence_type": le.evidence_type,
                })
            })
            .collect();
        let trace_entities: Vec<(Uuid, Vec<Uuid>, serde_json::Value)> = traces
            .iter()
            .map(|lt| {
                // `trace_parents` is read unfiltered and can name traces
                // outside the lineage; the closure pass always drops those,
                // so charging them would only stop admission early. Keeping
                // the in-lineage ones keeps the charge an upper bound.
                let parent_trace_ids: Vec<Uuid> = lt
                    .parent_trace_ids
                    .iter()
                    .copied()
                    .filter(|p| lineage.traces.contains_key(p))
                    .collect();
                let entity = serde_json::json!({
                    "@type": "prov:Activity",
                    "@id": format!("trace:{}", lt.id),
                    "claim_id": format!("claim:{}", lt.claim_id),
                    "reasoning_type": lt.reasoning_type,
                    "confidence": lt.confidence,
                    "parent_trace_ids": parent_trace_ids.iter().map(|p| format!("trace:{p}")).collect::<Vec<_>>(),
                });
                (lt.id, parent_trace_ids, entity)
            })
            .collect();

        let cost = entry_len(&claim_entity)
            + evidence_entities.iter().map(entry_len).sum::<usize>()
            + trace_entities
                .iter()
                .map(|(_, _, v)| entry_len(v))
                .sum::<usize>()
            + CLAIM_REF_CHARS;
        if cost > remaining {
            budget_exhausted = true;
            if !groups.is_empty() {
                break;
            }
        }
        remaining = remaining.saturating_sub(cost);
        groups.push(Group {
            claim_id: *id,
            parents,
            claim_entity,
            evidence_entities,
            trace_entities,
            capped: evidence_truncated || traces_truncated,
        });
    }

    // ---- Reference closure over what the budget admitted ----
    let emitted_claims: HashSet<Uuid> = groups.iter().map(|g| g.claim_id).collect();
    let emitted_traces: HashSet<Uuid> = groups
        .iter()
        .flat_map(|g| g.trace_entities.iter().map(|(id, _, _)| *id))
        .collect();

    let mut entities = Vec::new();
    let mut evidence_entity_count = 0;
    let mut trace_entity_count = 0;
    let mut capped = false;
    for g in groups {
        capped |= g.capped;
        let mut claim_entity = g.claim_entity;
        claim_entity["parent_ids"] = g
            .parents
            .iter()
            .filter(|p| emitted_claims.contains(p))
            .map(|p| format!("claim:{p}"))
            .collect::<Vec<_>>()
            .into();
        entities.push(claim_entity);
        evidence_entity_count += g.evidence_entities.len();
        entities.extend(g.evidence_entities);
        for (_, parent_trace_ids, mut trace_entity) in g.trace_entities {
            trace_entity["parent_trace_ids"] = parent_trace_ids
                .iter()
                .filter(|p| emitted_traces.contains(p))
                .map(|p| format!("trace:{p}"))
                .collect::<Vec<_>>()
                .into();
            trace_entity_count += 1;
            entities.push(trace_entity);
        }
    }
    let topological_order: Vec<String> = lineage
        .topological_order
        .iter()
        .filter(|id| emitted_claims.contains(id))
        .map(|id| format!("claim:{id}"))
        .collect();

    let mut bundle = bundle_scaffold(
        root,
        lineage,
        limits,
        lineage.truncated || budget_exhausted || capped,
        budget_exhausted,
        [
            emitted_claims.len(),
            evidence_entity_count,
            trace_entity_count,
        ],
    );
    bundle["entities"] = entities.into();
    bundle["topological_order"] = topological_order.into();

    let out = serde_json::to_string(&bundle).unwrap_or_default();
    debug_assert!(
        out.len() <= limits.max_output_chars || emitted_claims.len() == 1,
        "budget accounting is not an upper bound: {} > {}",
        out.len(),
        limits.max_output_chars
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_db::LineageClaim;
    use serde_json::Value;

    fn limits(max_output_chars: usize) -> Limits {
        Limits {
            max_depth: DEFAULT_MAX_DEPTH,
            max_nodes: MAX_MAX_NODES,
            max_content_chars: DEFAULT_MAX_CONTENT_CHARS,
            max_output_chars,
        }
    }

    fn uuid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    /// In-memory lineage: claim `uuid(1)` is the target; `parents` direct
    /// parents `uuid(100 + i)` at depth 1; each claim gets `evidence` rows and
    /// one trace whose id is `uuid(3_000_000 + claim)`.
    fn lineage(parents: u128, evidence: u128, content_len: usize) -> LineageResult {
        let mut l = LineageResult::default();
        let target = uuid(1);
        let parent_ids: Vec<Uuid> = (0..parents).map(|i| uuid(100 + i)).collect();
        // ancestors first, target last
        l.topological_order.extend(parent_ids.iter().copied());
        l.topological_order.push(target);
        for (id, depth, ps) in std::iter::once((target, 0, parent_ids.clone()))
            .chain(parent_ids.iter().map(|p| (*p, 1, Vec::new())))
        {
            let ev: Vec<Uuid> = (0..evidence)
                .map(|k| uuid(1_000_000 + id.as_u128() * 1_000 + k))
                .collect();
            for e in &ev {
                l.evidence.insert(
                    *e,
                    LineageEvidence {
                        id: *e,
                        claim_id: id,
                        evidence_type: "testimony".into(),
                        content_hash: vec![],
                    },
                );
            }
            let trace = uuid(3_000_000 + id.as_u128());
            l.traces.insert(
                trace,
                LineageTrace {
                    id: trace,
                    claim_id: id,
                    reasoning_type: "deductive".into(),
                    confidence: 0.9,
                    parent_trace_ids: vec![],
                },
            );
            l.claims.insert(
                id,
                LineageClaim {
                    id,
                    content: "x".repeat(content_len),
                    truth_value: 0.5,
                    depth,
                    parent_ids: ps,
                    evidence_ids: ev,
                    trace_id: Some(trace),
                },
            );
        }
        l
    }

    fn ids_of(bundle: &Value) -> HashSet<String> {
        bundle["entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["@id"].as_str().unwrap().to_string())
            .collect()
    }

    /// Every reference the bundle emits resolves to an emitted entity.
    fn assert_closed(bundle: &Value) {
        let ids = ids_of(bundle);
        let mut refs: Vec<&Value> = vec![&bundle["root_claim"]];
        refs.extend(bundle["topological_order"].as_array().unwrap());
        for e in bundle["entities"].as_array().unwrap() {
            refs.push(&e["claim_id"]);
            for f in ["parent_ids", "evidence_ids", "parent_trace_ids"] {
                refs.extend(e[f].as_array().into_iter().flatten());
            }
        }
        for r in refs.into_iter().filter_map(Value::as_str) {
            assert!(ids.contains(r), "dangling reference {r}");
        }
    }

    #[test]
    fn budget_is_an_upper_bound_at_every_size_and_the_cut_is_nearest_first() {
        let l = lineage(80, 6, 2_000);
        // A fine sweep, so some budget lands just past a group boundary where
        // the accounting has no slack: an under-charge of even a few dozen
        // bytes then overruns it.
        for budget in (MIN_MAX_OUTPUT_CHARS..=100_000).step_by(89) {
            let raw = build_bundle(uuid(1), &l, limits(budget));
            assert!(raw.len() <= budget, "{} > {budget}", raw.len());
            let b: Value = serde_json::from_str(&raw).unwrap();
            assert_closed(&b);
            assert_eq!(b["budget_exhausted"], Value::Bool(true), "budget {budget}");
            assert_eq!(b["truncated"], Value::Bool(true));
            // The target comes first; the admitted parents are the FIRST n of
            // the nearest-first walk (topological_order reversed), not a
            // HashMap-order sample.
            let claims: Vec<String> = b["entities"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|e| e["@id"].as_str().filter(|i| i.starts_with("claim:")))
                .map(str::to_string)
                .collect();
            let expected: Vec<String> = l
                .topological_order
                .iter()
                .rev()
                .take(claims.len())
                .map(|id| format!("claim:{id}"))
                .collect();
            assert_eq!(claims, expected, "budget {budget}");
            assert!(claims.len() > 1, "budget {budget} admitted only the target");
            assert_eq!(b["claim_node_count"], Value::from(claims.len()));
            assert_eq!(
                b["limits"]["max_output_chars"],
                Value::from(budget),
                "limits must echo the budget"
            );
        }
        // Secondary check: two INDEPENDENTLY built lineages (separate
        // HashMaps, separate random hash seeds, so different iteration
        // orders) serialise byte-identically. The id pin in
        // `per_claim_caps_bound_evidence_and_traces_and_flag_the_cut` is the
        // real guard on which rows a cut keeps.
        let other = lineage(80, 6, 2_000);
        assert_eq!(
            build_bundle(uuid(1), &l, limits(DEFAULT_MAX_OUTPUT_CHARS)),
            build_bundle(uuid(1), &other, limits(DEFAULT_MAX_OUTPUT_CHARS))
        );
    }

    #[test]
    fn a_lineage_inside_every_cap_is_complete_and_not_flagged() {
        let l = lineage(3, 4, 100);
        let b: Value =
            serde_json::from_str(&build_bundle(uuid(1), &l, limits(DEFAULT_MAX_OUTPUT_CHARS)))
                .unwrap();
        assert_closed(&b);
        assert_eq!(b["truncated"], Value::Bool(false));
        assert_eq!(b["budget_exhausted"], Value::Bool(false));
        assert_eq!(b["claim_node_count"], Value::from(4));
        assert_eq!(b["evidence_entity_count"], Value::from(16));
        assert_eq!(b["trace_entity_count"], Value::from(4));
        let target = &b["entities"][0];
        assert_eq!(target["@id"], Value::from(format!("claim:{}", uuid(1))));
        assert_eq!(target["parent_ids"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn per_claim_caps_bound_evidence_and_traces_and_flag_the_cut() {
        let mut l = lineage(0, 25, 100);
        for k in 0..15u128 {
            let t = uuid(5_000_000 + k);
            l.traces.insert(
                t,
                LineageTrace {
                    id: t,
                    claim_id: uuid(1),
                    reasoning_type: "inductive".into(),
                    confidence: 0.5,
                    parent_trace_ids: vec![],
                },
            );
        }
        let b: Value =
            serde_json::from_str(&build_bundle(uuid(1), &l, limits(DEFAULT_MAX_OUTPUT_CHARS)))
                .unwrap();
        assert_closed(&b);
        let target = &b["entities"][0];
        assert_eq!(target["evidence_count"], Value::from(25));
        assert_eq!(target["evidence_truncated"], Value::Bool(true));
        assert_eq!(
            target["evidence_ids"].as_array().unwrap().len(),
            MAX_EVIDENCE_PER_CLAIM
        );
        assert_eq!(target["trace_count"], Value::from(16));
        assert_eq!(target["traces_truncated"], Value::Bool(true));
        assert_eq!(
            b["evidence_entity_count"],
            Value::from(MAX_EVIDENCE_PER_CLAIM)
        );
        assert_eq!(b["trace_entity_count"], Value::from(MAX_TRACES_PER_CLAIM));
        // WHICH rows the cap keeps: the smallest ids, in id order, not a
        // HashMap-order sample that changes from call to call. `from_u128`
        // is big-endian, so Uuid order is numeric order here.
        let expected_evidence: Vec<String> = (0..MAX_EVIDENCE_PER_CLAIM as u128)
            .map(|k| format!("evidence:{}", uuid(1_000_000 + 1_000 + k)))
            .collect();
        assert_eq!(target["evidence_ids"], serde_json::json!(expected_evidence));
        let emitted_evidence: Vec<&str> = b["entities"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["@id"].as_str().filter(|i| i.starts_with("evidence:")))
            .collect();
        assert_eq!(emitted_evidence, expected_evidence);
        // The target's own trace `uuid(3_000_001)` sorts before the 15 extra
        // `uuid(5_000_000 + k)`, so the kept ten are it plus k = 0..9.
        let expected_traces: Vec<String> = std::iter::once(uuid(3_000_001))
            .chain((0..MAX_TRACES_PER_CLAIM as u128 - 1).map(|k| uuid(5_000_000 + k)))
            .map(|t| format!("trace:{t}"))
            .collect();
        let emitted_traces: Vec<&str> = b["entities"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["@id"].as_str().filter(|i| i.starts_with("trace:")))
            .collect();
        assert_eq!(emitted_traces, expected_traces);
        // The lineage itself was not cut and the budget was not hit; the
        // per-claim cap alone must still mark the bundle incomplete.
        assert_eq!(b["budget_exhausted"], Value::Bool(false));
        assert_eq!(b["truncated"], Value::Bool(true));
    }

    #[test]
    fn parent_trace_ids_are_pruned_to_emitted_traces_only() {
        // Target trace names (a) the parent claim's trace, which is emitted,
        // and (b) a trace outside the lineage, which `trace_parents` can
        // legitimately return and the repo deliberately leaves in place.
        let mut l = lineage(1, 0, 100);
        let target_trace = uuid(3_000_001);
        let parent_trace = uuid(3_000_100);
        let outside = uuid(9_999);
        l.traces.get_mut(&target_trace).unwrap().parent_trace_ids = vec![parent_trace, outside];
        let b: Value =
            serde_json::from_str(&build_bundle(uuid(1), &l, limits(DEFAULT_MAX_OUTPUT_CHARS)))
                .unwrap();
        assert_closed(&b);
        let t = b["entities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["@id"] == format!("trace:{target_trace}").as_str())
            .unwrap();
        assert_eq!(
            t["parent_trace_ids"],
            serde_json::json!([format!("trace:{parent_trace}")])
        );
    }

    #[test]
    fn out_of_lineage_parent_traces_are_not_charged_against_the_budget() {
        // `trace_parents` is read unscoped and uncapped, and can name traces
        // outside the lineage. Those can never survive the closure pass, so
        // charging them only makes the budget stop early: 1,000 of them are
        // ~45K of `"trace:<uuid>",` and would collapse the bundle to the
        // target alone with `budget_exhausted` although the real output is a
        // few KB.
        let mut l = lineage(3, 4, 100);
        let target_trace = uuid(3_000_001);
        let in_lineage_parent_trace = uuid(3_000_100);
        let mut parents = vec![in_lineage_parent_trace];
        parents.extend((0..1_000u128).map(|k| uuid(10_000_000 + k)));
        l.traces.get_mut(&target_trace).unwrap().parent_trace_ids = parents;
        let raw = build_bundle(uuid(1), &l, limits(DEFAULT_MAX_OUTPUT_CHARS));
        assert!(raw.len() <= DEFAULT_MAX_OUTPUT_CHARS, "{}", raw.len());
        let b: Value = serde_json::from_str(&raw).unwrap();
        assert_closed(&b);
        assert_eq!(b["budget_exhausted"], Value::Bool(false));
        assert_eq!(b["truncated"], Value::Bool(false));
        assert_eq!(b["claim_node_count"], Value::from(4));
        let t = b["entities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["@id"] == format!("trace:{target_trace}").as_str())
            .unwrap();
        assert_eq!(
            t["parent_trace_ids"],
            serde_json::json!([format!("trace:{in_lineage_parent_trace}")])
        );
    }

    #[test]
    fn parent_ids_are_deduplicated_and_pruned_to_emitted_claims() {
        // Two edges between the same pair (different relationships) list the
        // parent twice; a parent the budget did not admit must not appear.
        let mut l = lineage(40, 6, 2_000);
        let first_parent = uuid(139); // nearest-first walk admits 139, 138, ...
        l.claims
            .get_mut(&uuid(1))
            .unwrap()
            .parent_ids
            .push(first_parent);
        let b: Value =
            serde_json::from_str(&build_bundle(uuid(1), &l, limits(MIN_MAX_OUTPUT_CHARS))).unwrap();
        assert_closed(&b);
        let parents = b["entities"][0]["parent_ids"].as_array().unwrap();
        let claim_count = b["claim_node_count"].as_u64().unwrap() as usize;
        assert_eq!(parents.len(), claim_count - 1, "{parents:?}");
        assert!(
            claim_count - 1 < 40,
            "the budget must have cut some parents"
        );
        assert_eq!(
            parents
                .iter()
                .filter(|p| **p == format!("claim:{first_parent}").as_str())
                .count(),
            1
        );
    }

    #[test]
    fn a_target_larger_than_the_budget_is_still_emitted_and_flagged() {
        let mut l = lineage(2, 0, 100);
        l.claims.get_mut(&uuid(1)).unwrap().content = "y".repeat(30_000);
        let mut lim = limits(MIN_MAX_OUTPUT_CHARS);
        lim.max_content_chars = MAX_MAX_CONTENT_CHARS;
        let b: Value = serde_json::from_str(&build_bundle(uuid(1), &l, lim)).unwrap();
        assert_closed(&b);
        assert_eq!(b["claim_node_count"], Value::from(1));
        assert_eq!(b["budget_exhausted"], Value::Bool(true));
        assert_eq!(b["truncated"], Value::Bool(true));
    }

    fn params(
        max_depth: Option<i32>,
        max_nodes: Option<usize>,
        max_content_chars: Option<usize>,
        max_output_chars: Option<usize>,
    ) -> GetProvenanceParams {
        GetProvenanceParams {
            claim_id: uuid(1).to_string(),
            max_depth,
            max_nodes,
            max_content_chars,
            max_output_chars,
        }
    }

    /// The applied caps, as the bundle echoes them in `limits`.
    fn echoed(p: &GetProvenanceParams) -> Value {
        let b: Value = serde_json::from_str(&build_bundle(
            uuid(1),
            &lineage(0, 0, 10),
            Limits::from_params(p),
        ))
        .unwrap();
        b["limits"].clone()
    }

    #[test]
    fn caller_caps_are_defaulted_and_clamped_into_range() {
        // Defaults only.
        assert_eq!(
            echoed(&params(None, None, None, None)),
            serde_json::json!({
                "max_depth": 5, "max_nodes": 50,
                "max_content_chars": 500, "max_output_chars": 40_000,
            })
        );
        // Below every floor: a 1-char output budget would starve the bundle
        // to the target alone, so it is raised to 10,000.
        assert_eq!(
            echoed(&params(Some(0), Some(0), Some(1), Some(1))),
            serde_json::json!({
                "max_depth": 1, "max_nodes": 1,
                "max_content_chars": 50, "max_output_chars": 10_000,
            })
        );
        // Above every ceiling: the response stays bounded.
        assert_eq!(
            echoed(&params(
                Some(1_000),
                Some(1_000_000),
                Some(10_000_000),
                Some(10_000_000)
            )),
            serde_json::json!({
                "max_depth": 20, "max_nodes": 500,
                "max_content_chars": 20_000, "max_output_chars": 500_000,
            })
        );
        // In range: passed through untouched.
        assert_eq!(
            echoed(&params(Some(3), Some(7), Some(80), Some(12_345))),
            serde_json::json!({
                "max_depth": 3, "max_nodes": 7,
                "max_content_chars": 80, "max_output_chars": 12_345,
            })
        );
    }

    #[test]
    fn cap_content_reports_original_length_and_never_splits_a_char() {
        // Under the cap: untouched, not flagged.
        let (text, truncated, chars) = cap_content("short", 10);
        assert_eq!(text, "short");
        assert!(!truncated);
        assert_eq!(chars, 5);

        // Over the cap: trimmed to exactly `max_chars` CHARACTERS, flagged,
        // and the ORIGINAL length reported so a caller knows what it is
        // missing.
        let (text, truncated, chars) = cap_content("abcdefghij", 4);
        assert_eq!(text, "abcd");
        assert!(truncated);
        assert_eq!(chars, 10);

        // Multi-byte: a byte-slice implementation would panic or produce
        // invalid UTF-8 here. 4 chars of "日本語テスト" is 12 bytes.
        let (text, truncated, chars) = cap_content("日本語テスト", 4);
        assert_eq!(text, "日本語テ");
        assert!(truncated);
        assert_eq!(chars, 6);
    }
}
