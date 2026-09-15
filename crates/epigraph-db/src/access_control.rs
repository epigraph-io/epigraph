//! Partition-aware access control (§3.3 StructuralQueryEngine)
//!
//! Enforces ownership partitions on read queries. Nodes without an ownership
//! record are treated as `public` (backward compatibility).
//!
//! Access rules:
//! - `public`    → full content returned to all requesters
//! - `community` → full content if requester's perspective is a member of the owning community; otherwise coarse metadata only
//! - `private` → full content only for the owner agent; coarse metadata for all others

use std::collections::{HashMap, HashSet};

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

/// What the partition rules say about one ownership row before any
/// community-membership lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartitionDecision {
    Decided(ContentAccess),
    /// Community partition, known requester, parseable community id: `Full`
    /// iff the requester owns a perspective that is a member of `community_id`.
    NeedsMembership {
        community_id: Uuid,
        agent_id: Uuid,
    },
}

/// The partition rules shared by [`check_content_access`] and
/// [`batch_content_access`], so the single and batch paths cannot drift.
fn decide_partition(
    partition: &str,
    owner_id: Uuid,
    encryption_key_id: Option<&str>,
    requester_agent_id: Option<Uuid>,
) -> PartitionDecision {
    use PartitionDecision::{Decided, NeedsMembership};
    match partition {
        "public" => Decided(ContentAccess::Full),
        "private" => match requester_agent_id {
            Some(agent) if agent == owner_id => Decided(ContentAccess::Full),
            _ => Decided(ContentAccess::Redacted),
        },
        "community" => {
            // For community-partition nodes, encryption_key_id stores the
            // community UUID. We check if the requester's agent has any
            // perspective that is a member of that community.
            let Some(agent_id) = requester_agent_id else {
                return Decided(ContentAccess::Redacted);
            };

            // Parse community_id from encryption_key_id
            let community_id = encryption_key_id.and_then(|s| Uuid::parse_str(s).ok());

            match community_id {
                Some(community_id) => NeedsMembership {
                    community_id,
                    agent_id,
                },
                // No community_id stored → owner-only access as fallback
                None if agent_id == owner_id => Decided(ContentAccess::Full),
                None => Decided(ContentAccess::Redacted),
            }
        }
        _ => Decided(ContentAccess::Full), // Unknown partition → safe default
    }
}

/// Check whether a requester can read the full content of a node.
///
/// Returns `ContentAccess::Full` when:
/// - No ownership record exists (backward compat → public)
/// - Partition is `public`
/// - Partition is `community` and requester has a perspective that is a member
/// - Partition is `private` and requester is the owner
///
/// Fails closed: if the ownership or membership lookup errors (pool
/// exhaustion, statement timeout, dropped connection) the node is
/// `Redacted`, never `Full`.
///
/// For more than one node use [`batch_content_access`], which applies the same
/// rules in at most two queries.
pub async fn check_content_access(
    pool: &PgPool,
    node_id: Uuid,
    requester_agent_id: Option<Uuid>,
) -> ContentAccess {
    // 1. Look up ownership (partition_type, owner_id, encryption_key_id)
    // For community partitions, encryption_key_id stores the community UUID.
    let ownership: Option<(String, Uuid, Option<String>)> = match sqlx::query_as(
        "SELECT partition_type, owner_id, encryption_key_id FROM ownership WHERE node_id = $1",
    )
    .bind(node_id)
    .fetch_optional(pool)
    .await
    {
        Ok(row) => row,
        // A failed lookup is NOT "no ownership row": reading it as one would
        // serve a private node's content as public whenever the pool is
        // exhausted.
        Err(e) => {
            tracing::warn!(%node_id, error = %e, "ownership lookup failed; redacting");
            return ContentAccess::Redacted;
        }
    };

    let (partition, owner_id, encryption_key_id) = match ownership {
        Some(row) => row,
        None => return ContentAccess::Full, // No ownership → public
    };

    match decide_partition(
        &partition,
        owner_id,
        encryption_key_id.as_deref(),
        requester_agent_id,
    ) {
        PartitionDecision::Decided(access) => access,
        PartitionDecision::NeedsMembership {
            community_id,
            agent_id,
        } => {
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
            .unwrap_or(false); // lookup error → not a member → Redacted

            if is_member {
                ContentAccess::Full
            } else {
                ContentAccess::Redacted
            }
        }
    }
}

/// Set-based [`check_content_access`]: the access decision for every id in
/// `node_ids`, in one ownership query plus at most one membership query,
/// whatever the batch size.
///
/// The map has exactly one entry per distinct input id, and each entry equals
/// what `check_content_access(pool, id, requester_agent_id)` returns — same
/// rules (no ownership row → `Full`), same fail-closed behaviour: an
/// ownership-lookup error redacts every id, and a membership-lookup error
/// redacts the community nodes that needed it.
pub async fn batch_content_access(
    pool: &PgPool,
    node_ids: &[Uuid],
    requester_agent_id: Option<Uuid>,
) -> HashMap<Uuid, ContentAccess> {
    if node_ids.is_empty() {
        return HashMap::new();
    }

    let rows: Vec<(Uuid, String, Uuid, Option<String>)> = match sqlx::query_as(
        "SELECT node_id, partition_type, owner_id, encryption_key_id \
         FROM ownership WHERE node_id = ANY($1)",
    )
    .bind(node_ids)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                nodes = node_ids.len(),
                error = %e,
                "batch ownership lookup failed; redacting all"
            );
            return node_ids
                .iter()
                .map(|&id| (id, ContentAccess::Redacted))
                .collect();
        }
    };

    // Ids with no ownership row keep this default (backward compat → public).
    let mut access: HashMap<Uuid, ContentAccess> = node_ids
        .iter()
        .map(|&id| (id, ContentAccess::Full))
        .collect();
    let mut pending: Vec<(Uuid, Uuid)> = Vec::new(); // (node_id, community_id)
    for (node_id, partition, owner_id, encryption_key_id) in rows {
        match decide_partition(
            &partition,
            owner_id,
            encryption_key_id.as_deref(),
            requester_agent_id,
        ) {
            PartitionDecision::Decided(decision) => {
                access.insert(node_id, decision);
            }
            PartitionDecision::NeedsMembership { community_id, .. } => {
                pending.push((node_id, community_id));
            }
        }
    }

    // `NeedsMembership` only arises with a known requester, so `pending` is
    // empty whenever `requester_agent_id` is `None`.
    if let (Some(agent_id), false) = (requester_agent_id, pending.is_empty()) {
        let communities: Vec<Uuid> = pending
            .iter()
            .map(|&(_, community_id)| community_id)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let member_of: HashSet<Uuid> = match sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT DISTINCT cm.community_id FROM community_members cm
            JOIN perspectives p ON p.id = cm.perspective_id
            WHERE cm.community_id = ANY($1)
              AND p.owner_agent_id = $2
            "#,
        )
        .bind(&communities)
        .bind(agent_id)
        .fetch_all(pool)
        .await
        {
            Ok(ids) => ids.into_iter().collect(),
            // lookup error → not a member of anything → Redacted
            Err(e) => {
                tracing::warn!(
                    communities = communities.len(),
                    error = %e,
                    "batch community-membership lookup failed; redacting"
                );
                HashSet::new()
            }
        };
        for (node_id, community_id) in pending {
            let decision = if member_of.contains(&community_id) {
                ContentAccess::Full
            } else {
                ContentAccess::Redacted
            };
            access.insert(node_id, decision);
        }
    }

    access
}

/// Batch check content access for multiple node IDs.
///
/// Returns a list of `(node_id, ContentAccess)` in the same order as input
/// (duplicates kept). A thin ordered view over [`batch_content_access`].
pub async fn batch_check_content_access(
    pool: &PgPool,
    node_ids: &[Uuid],
    requester_agent_id: Option<Uuid>,
) -> Vec<(Uuid, ContentAccess)> {
    let access = batch_content_access(pool, node_ids, requester_agent_id).await;
    node_ids
        .iter()
        .map(|&nid| {
            // Every input id is in the map; an absent one would redact.
            let decision = access.get(&nid).copied().unwrap_or(ContentAccess::Redacted);
            (nid, decision)
        })
        .collect()
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
}
