//! Partition-aware access control — relocated to `epigraph-db::access_control`
//! (the shared repo layer used by both HTTP routes and MCP tools, per the
//! repo CLAUDE.md "all SQL stays in crates/epigraph-db/src/repos"). This shim
//! preserves the `crate::access_control::*` import path for the HTTP routes.
pub use epigraph_db::access_control::{
    batch_check_content_access, check_content_access, ContentAccess, COARSE_EDGE_TYPES,
};

/// Redact claim content: keep id, truth_value, belief, plausibility, pignistic_prob
/// but replace content with "[REDACTED]".
pub fn redact_claim_content(content: &mut String) {
    *content = "[REDACTED]".to_string();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_claim_content_replaces() {
        let mut content = "Secret claim about something".to_string();
        redact_claim_content(&mut content);
        assert_eq!(content, "[REDACTED]");
    }
}
