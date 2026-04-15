//! Partition-aware access control (§3.3 StructuralQueryEngine)
//!
//! Enforces ownership partitions on read queries. Nodes without an ownership
//! record are treated as `public` (backward compatibility).
//!
//! Access rules:
//! - `public`    → full content returned to all requesters
//! - `community` → full content if requester's perspective is a member of the owning community; otherwise coarse metadata only
//! - `private` → full content only for the owner agent; coarse metadata for all others

#[cfg(feature = "db")]
use sqlx::PgPool;
use uuid::Uuid;

/// Coarse edge types from §1.2 — the only relationship types exposed
/// through privacy-preserving structural queries.
pub const COARSE_EDGE_TYPES: &[&str] = &[
    "SUPPORTS",
    "CONTRADICTS",
    "RELATES_TO",
    "DERIVED_FROM",
    "GENERATED_BY",
    "PERSPECTIVE_OF",
    "CONTRIBUTES_TO",
    "MEMBER_OF",
    "SCOPED_BY",
    "WITHIN_FRAME",
    // Political network monitoring edge types
    "ORIGINATED_BY",
    "AMPLIFIED_BY",
    "COORDINATED_WITH",
    "USES_TECHNIQUE",
    "MIRROR_NARRATIVE",
];

/// Result of a partition check for a single node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentAccess {
    /// Full content may be returned
    Full,
    /// Only coarse metadata (id, type, belief/plausibility) — no content text
    Redacted,
}

/// Check whether a requester can read the full content of a node.
///
/// Returns `ContentAccess::Full` when:
/// - No ownership record exists (backward compat → public)
/// - Partition is `public`
/// - Partition is `community` and requester has a perspective that is a member
/// - Partition is `private` and requester is the owner
#[cfg(feature = "db")]
pub async fn check_content_access(
    pool: &PgPool,
    node_id: Uuid,
    requester_agent_id: Option<Uuid>,
) -> ContentAccess {
    // 1. Look up ownership (partition_type, owner_id, encryption_key_id)
    // For community partitions, encryption_key_id stores the community UUID.
    let ownership: Option<(String, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT partition_type, owner_id, encryption_key_id FROM ownership WHERE node_id = $1",
    )
    .bind(node_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (partition, owner_id, encryption_key_id) = match ownership {
        Some(row) => row,
        None => return ContentAccess::Full, // No ownership → public
    };

    match partition.as_str() {
        "public" => ContentAccess::Full,
        "private" => match requester_agent_id {
            Some(agent) if agent == owner_id => ContentAccess::Full,
            _ => ContentAccess::Redacted,
        },
        "community" => {
            // For community-partition nodes, encryption_key_id stores the
            // community UUID. We check if the requester's agent has any
            // perspective that is a member of that community.
            let Some(agent_id) = requester_agent_id else {
                return ContentAccess::Redacted;
            };

            // Parse community_id from encryption_key_id
            let community_id = encryption_key_id
                .as_deref()
                .and_then(|s| Uuid::parse_str(s).ok());

            let Some(community_id) = community_id else {
                // No community_id stored → owner-only access as fallback
                return if agent_id == owner_id {
                    ContentAccess::Full
                } else {
                    ContentAccess::Redacted
                };
            };

            let is_member: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM community_members cm
                    JOIN perspectives p ON p.id = cm.perspective_id
                    WHERE cm.community_id = $1
                      AND p.owner_agent_id = $2
                )
                "#,
            )
            .bind(community_id)
            .bind(agent_id)
            .fetch_one(pool)
            .await
            .unwrap_or(false);

            if is_member {
                ContentAccess::Full
            } else {
                ContentAccess::Redacted
            }
        }
        _ => ContentAccess::Full, // Unknown partition → safe default
    }
}

/// Batch check content access for multiple node IDs.
///
/// Returns a list of `(node_id, ContentAccess)` in the same order as input.
#[cfg(feature = "db")]
pub async fn batch_check_content_access(
    pool: &PgPool,
    node_ids: &[Uuid],
    requester_agent_id: Option<Uuid>,
) -> Vec<(Uuid, ContentAccess)> {
    // For small batches, sequential is fine. For large batches a single SQL
    // query would be more efficient, but the access control logic involves
    // community membership checks that are hard to do in one query.
    let mut results = Vec::with_capacity(node_ids.len());
    for &nid in node_ids {
        let access = check_content_access(pool, nid, requester_agent_id).await;
        results.push((nid, access));
    }
    results
}

/// Redact claim content: keep id, truth_value, belief, plausibility, pignistic_prob
/// but replace content with "[REDACTED]".
pub fn redact_claim_content(content: &mut String) {
    *content = "[REDACTED]".to_string();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarse_edge_types_has_expected_count() {
        assert_eq!(COARSE_EDGE_TYPES.len(), 15);
        assert!(COARSE_EDGE_TYPES.contains(&"SUPPORTS"));
        assert!(COARSE_EDGE_TYPES.contains(&"CONTRADICTS"));
        assert!(COARSE_EDGE_TYPES.contains(&"SCOPED_BY"));
        assert!(COARSE_EDGE_TYPES.contains(&"WITHIN_FRAME"));
        assert!(COARSE_EDGE_TYPES.contains(&"ORIGINATED_BY"));
        assert!(COARSE_EDGE_TYPES.contains(&"AMPLIFIED_BY"));
        assert!(COARSE_EDGE_TYPES.contains(&"USES_TECHNIQUE"));
    }

    #[test]
    fn content_access_eq() {
        assert_eq!(ContentAccess::Full, ContentAccess::Full);
        assert_eq!(ContentAccess::Redacted, ContentAccess::Redacted);
        assert_ne!(ContentAccess::Full, ContentAccess::Redacted);
    }

    #[test]
    fn redact_claim_content_replaces() {
        let mut content = "Secret claim about something".to_string();
        redact_claim_content(&mut content);
        assert_eq!(content, "[REDACTED]");
    }
}
