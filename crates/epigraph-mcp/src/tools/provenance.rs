#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::GetProvenanceParams;

use epigraph_db::LineageRepository;

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
/// The product is what is bounded: `DEFAULT_MAX_NODES * DEFAULT_MAX_CONTENT_CHARS`
/// = 50 * 500 = 25,000 characters of claim text, roughly 6 KB of JSON
/// scaffolding on top — an order of magnitude under the 145K low-water mark of
/// the observed failures, with headroom for the evidence and trace entities
/// (which carry no content field).
const DEFAULT_MAX_CONTENT_CHARS: usize = 500;
/// Lower bound on `max_content_chars` — below this the content is useless for
/// the "assess evidence depth" workflow step this tool serves.
const MIN_MAX_CONTENT_CHARS: usize = 50;
/// Ceiling on `max_content_chars`.
const MAX_MAX_CONTENT_CHARS: usize = 20_000;

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
/// both node count and per-claim content length.
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
/// # Reporting
///
/// A bounded answer is only usable if the caller can tell it apart from a
/// complete one, so the bundle now surfaces `LineageResult::truncated` (the
/// walk hit `max_depth`, or the node cap trimmed the set) alongside the
/// already-present `max_depth_reached`, echoes the applied `limits`, and marks
/// each trimmed entity with `content_truncated: true` plus the original
/// `content_chars`.
pub async fn get_provenance(
    server: &EpiGraphMcpFull,
    params: GetProvenanceParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;

    let max_depth = params
        .max_depth
        .unwrap_or(DEFAULT_MAX_DEPTH)
        .clamp(1, MAX_MAX_DEPTH);
    let max_nodes = params
        .max_nodes
        .unwrap_or(DEFAULT_MAX_NODES)
        .clamp(1, MAX_MAX_NODES);
    let max_content_chars = params
        .max_content_chars
        .unwrap_or(DEFAULT_MAX_CONTENT_CHARS)
        .clamp(MIN_MAX_CONTENT_CHARS, MAX_MAX_CONTENT_CHARS);

    let lineage =
        LineageRepository::get_lineage(&server.pool, claim_id, Some(max_depth), Some(max_nodes))
            .await
            .map_err(internal_error)?;

    // Build W3C PROV-O style JSON-LD
    let mut entities = Vec::new();

    for (id, lc) in &lineage.claims {
        let (content, content_truncated, content_chars) =
            cap_content(&lc.content, max_content_chars);
        entities.push(serde_json::json!({
            "@type": "prov:Entity",
            "@id": format!("claim:{id}"),
            "content": content,
            "content_truncated": content_truncated,
            "content_chars": content_chars,
            "truth_value": lc.truth_value,
            "depth": lc.depth,
            "parent_ids": lc.parent_ids.iter().map(|p| format!("claim:{p}")).collect::<Vec<_>>(),
            "evidence_ids": lc.evidence_ids.iter().map(|e| format!("evidence:{e}")).collect::<Vec<_>>(),
        }));
    }

    for (id, le) in &lineage.evidence {
        entities.push(serde_json::json!({
            "@type": "prov:Entity",
            "@id": format!("evidence:{id}"),
            "claim_id": format!("claim:{}", le.claim_id),
            "evidence_type": le.evidence_type,
        }));
    }

    for (id, lt) in &lineage.traces {
        entities.push(serde_json::json!({
            "@type": "prov:Activity",
            "@id": format!("trace:{id}"),
            "claim_id": format!("claim:{}", lt.claim_id),
            "reasoning_type": lt.reasoning_type,
            "confidence": lt.confidence,
            "parent_trace_ids": lt.parent_trace_ids.iter().map(|p| format!("trace:{p}")).collect::<Vec<_>>(),
        }));
    }

    let prov_bundle = serde_json::json!({
        "@context": "https://www.w3.org/ns/prov#",
        "root_claim": format!("claim:{claim_id}"),
        "entities": entities,
        "topological_order": lineage.topological_order.iter().map(|id| format!("claim:{id}")).collect::<Vec<_>>(),
        "cycle_detected": lineage.cycle_detected,
        "max_depth_reached": lineage.max_depth_reached,
        // The walk stopped short of the full lineage — either `max_depth` cut
        // the recursion or `max_nodes` trimmed the result. Without this a
        // caller cannot distinguish a capped bundle from a complete one.
        "truncated": lineage.truncated,
        "claim_node_count": lineage.claims.len(),
        "limits": {
            "max_depth": max_depth,
            "max_nodes": max_nodes,
            "max_content_chars": max_content_chars,
        },
    });

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&prov_bundle).map_err(internal_error)?,
    )]))
}

#[cfg(test)]
mod tests {
    use super::cap_content;

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
