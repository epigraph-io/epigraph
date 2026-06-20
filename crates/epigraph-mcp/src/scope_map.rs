//! Per-tool OAuth scope map.
//!
//! Every tool registered on `EpiGraphMcpFull` MUST have an entry here. The
//! coverage test at the bottom of this file enforces that — a new tool
//! without a scope mapping fails closed (`required_scope` returns `None`,
//! which `call_tool` translates into 403 Forbidden) AND fails the test
//! suite.

/// Look up the OAuth scope required to dispatch `tool_name`.
///
/// Returns `None` for unknown tools. The call site MUST treat `None` as a
/// hard 403 — never let an unmapped tool pass.
#[must_use]
pub fn required_scope(tool_name: &str) -> Option<&'static str> {
    SCOPE_MAP
        .iter()
        .find_map(|(name, scope)| (*name == tool_name).then_some(*scope))
}

/// Source-of-truth scope table. Keep alphabetised within each scope bucket.
///
/// **Adding a new tool?** Add it here and to the matching scope bucket. The
/// coverage test will fail until you do.
pub const SCOPE_MAP: &[(&str, &str)] = &[
    // ─── claims:read ───────────────────────────────────────────────────
    ("check_already_ingested", "claims:read"),
    ("check_sheaf_consistency", "claims:read"),
    ("compare_methods", "claims:read"),
    ("embedding_neighborhood_density", "claims:read"),
    ("entity_neighborhood", "claims:read"),
    ("evaluate_workflow_promotion", "claims:read"),
    ("find_cross_source_matches", "claims:read"),
    ("find_workflow", "claims:read"),
    ("find_workflow_hierarchical", "claims:read"),
    ("get_belief", "claims:read"),
    ("get_claim", "claims:read"),
    ("get_divergence", "claims:read"),
    ("get_neighborhood", "claims:read"),
    ("get_ownership", "claims:read"),
    ("get_perspective", "claims:read"),
    ("get_provenance", "claims:read"),
    ("get_workflow_executions", "claims:read"),
    ("list_challenges", "claims:read"),
    ("list_events", "claims:read"),
    ("list_frames", "claims:read"),
    ("list_match_candidates", "claims:read"),
    ("list_mcp_tools", "claims:read"),
    ("list_perspectives", "claims:read"),
    ("query_claims", "claims:read"),
    ("query_claims_by_evidence", "claims:read"),
    ("query_claims_by_label", "claims:read"),
    ("query_claims_by_methodology", "claims:read"),
    ("query_paper", "claims:read"),
    ("query_triples", "claims:read"),
    ("query_undecomposed_claims", "claims:read"),
    ("recall", "claims:read"),
    ("recall_with_context", "claims:read"),
    ("scoped_belief", "claims:read"),
    ("search_triples", "claims:read"),
    ("sheaf_cohomology", "claims:read"),
    ("structure_source", "claims:read"),
    ("suggest_alternative_sets", "claims:read"),
    ("system_stats", "claims:read"),
    ("traverse", "claims:read"),
    // ─── claims:write ──────────────────────────────────────────────────
    ("add_step", "claims:write"),
    ("assign_ownership", "claims:write"),
    ("backfill_embeddings", "claims:write"),
    ("batch_submit_claims", "claims:write"),
    ("challenge_claim", "claims:write"),
    ("create_frame", "claims:write"),
    ("create_perspective", "claims:write"),
    ("decide_match_candidate", "claims:write"),
    ("delete_step", "claims:write"),
    ("deprecate_workflow", "claims:write"),
    ("evolve_step", "claims:write"),
    ("improve_workflow_hierarchy", "claims:write"),
    ("ingest_document", "claims:write"),
    ("ingest_document_inline", "claims:write"),
    ("ingest_document_spine", "claims:write"),
    ("ingest_workflow", "claims:write"),
    ("link_epistemic", "claims:write"),
    ("link_hierarchical", "claims:write"),
    ("memorize", "claims:write"),
    ("patch_claim", "claims:write"),
    ("refresh_workflow_promotion", "claims:write"),
    ("publish_event", "claims:write"),
    ("recompute_beliefs", "claims:write"),
    ("reconcile_sheaf", "claims:write"),
    ("report_hierarchical_outcome", "claims:write"),
    ("report_workflow_outcome", "claims:write"),
    ("resolve_backlog_item", "claims:write"),
    ("set_source_reliability", "claims:write"),
    ("stage_claims", "claims:write"),
    ("store_workflow", "claims:write"),
    ("submit_claim", "claims:write"),
    ("submit_ds_evidence", "claims:write"),
    ("theme_cluster", "claims:write"),
    ("update_labels", "claims:write"),
    ("update_with_evidence", "claims:write"),
    ("verify_claim", "claims:write"),
    // ─── claims:admin ──────────────────────────────────────────────────
    ("mark_duplicate", "claims:admin"),
    ("supersede_claim", "claims:admin"),
    ("update_partition", "claims:admin"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EpiGraphMcpFull;

    /// Extract tool names from the JSON produced by `all_tools_json()`.
    fn registered_tool_names() -> Vec<String> {
        let json = EpiGraphMcpFull::all_tools_json();
        json.as_array()
            .expect("all_tools_json must return a JSON array")
            .iter()
            .map(|tool| {
                tool.get("name")
                    .and_then(|n| n.as_str())
                    .expect("each tool entry must have a string `name` field")
                    .to_string()
            })
            .collect()
    }

    /// Every tool registered on the MCP server has an entry in `SCOPE_MAP`.
    /// New tools added without a scope mapping fail this test loudly, so they
    /// cannot become covert auth bypasses.
    #[test]
    fn every_registered_tool_has_a_scope() {
        let registered = registered_tool_names();
        let missing: Vec<String> = registered
            .iter()
            .filter(|name| required_scope(name).is_none())
            .cloned()
            .collect();
        assert!(
            missing.is_empty(),
            "tools registered on EpiGraphMcpFull but missing from scope_map::SCOPE_MAP: {missing:?}\n\
             Add each one to crates/epigraph-mcp/src/scope_map.rs."
        );
    }

    /// Inverse direction: the scope map does not reference tools that don't
    /// exist anymore (catches deletions / renames).
    #[test]
    fn scope_map_has_no_stale_entries() {
        let registered: std::collections::HashSet<String> =
            registered_tool_names().into_iter().collect();
        let stale: Vec<&str> = SCOPE_MAP
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| !registered.contains(*name))
            .collect();
        assert!(
            stale.is_empty(),
            "scope_map entries reference tools not registered on EpiGraphMcpFull: {stale:?}"
        );
    }

    /// Sanity-check the three known mutation tools cited in issue #122 are
    /// gated on `claims:admin`.
    #[test]
    fn issue_122_admin_tools_are_admin_gated() {
        assert_eq!(required_scope("mark_duplicate"), Some("claims:admin"));
        assert_eq!(required_scope("supersede_claim"), Some("claims:admin"));
        assert_eq!(required_scope("update_partition"), Some("claims:admin"));
    }
}
