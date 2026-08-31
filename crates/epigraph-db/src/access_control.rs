//! Partition-aware access control (§3.3 StructuralQueryEngine)
//!
//! Enforces ownership partitions on read queries. Nodes without an ownership
//! record are treated as `public` (backward compatibility).
//!
//! Access rules:
//! - `public`    → full content returned to all requesters
//! - `community` → full content if the requester's agent owns a perspective that
//!   is a member of `ownership.community_id`; otherwise coarse metadata only
//! - `private` → full content only for the owner agent; coarse metadata for all others
//! - anything else → coarse metadata only. The three arms above are not a total
//!   match on `text`; they are a total match on the values
//!   `ownership_partition_check` currently admits. That CHECK is a database
//!   constraint, not a type, so the `_` arm is reachable the moment the
//!   constraint is widened, dropped, or a row is written by a role that skips
//!   it. Locked decision D1 ("nothing is public by absence, omission, or
//!   default-on-error") forbids granting full content for a partition value
//!   this code cannot classify.

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
pub async fn check_content_access(
    pool: &PgPool,
    node_id: Uuid,
    requester_agent_id: Option<Uuid>,
) -> ContentAccess {
    // 1. Look up ownership (partition_type, owner_id, community_id).
    // `community_id` is the TYPED gate for community partitions. Before
    // migration 068 this value lived stringified in `encryption_key_id`, a
    // column whose name meant something else entirely; 068 drained it into a
    // real `uuid` column with an FK to `communities`. Nothing reads
    // `encryption_key_id` any more — it is dropped with the table in 084.
    //
    // A QUERY ERROR IS NOT "NO OWNERSHIP ROW". This used to be
    // `.unwrap_or(None)`, which laundered every `Err` into the same value that
    // means *public* — so a pool timeout, a reset connection or a schema that
    // predates `community_id` returned FULL CONTENT for a private or
    // community-gated claim. `EPIGRAPH_MIGRATE_ON_BOOT` is default-off, so a
    // binary rolled ahead of migration 068 is an operator-reachable state, and
    // the MCP server has no startup probe that would catch it. Fail closed and
    // say so in the log.
    let ownership: Option<(String, Uuid, Option<Uuid>)> = match sqlx::query_as(
        "SELECT partition_type, owner_id, community_id FROM ownership WHERE node_id = $1",
    )
    .bind(node_id)
    .fetch_optional(pool)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(
                node_id = %node_id,
                error = %e,
                "ownership lookup failed; redacting rather than assuming public"
            );
            return ContentAccess::Redacted;
        }
    };

    let (partition, owner_id, community_id) = match ownership {
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
            // For community-partition nodes, `community_id` names the gating
            // community directly (migration 068 made it a real `uuid` column;
            // there is no string to parse and no parse failure to handle). We
            // check whether the requester's agent owns any perspective that is
            // a member of that community.
            let Some(agent_id) = requester_agent_id else {
                return ContentAccess::Redacted;
            };

            let Some(community_id) = community_id else {
                // No gating community recorded → owner-only access as fallback.
                // Reached today when `community_id IS NULL` on a `community`
                // row; before 068 the same arm was reached by an unparseable
                // `encryption_key_id`.
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
            // `false` on error is already the closed direction here: not a
            // member -> Redacted. Unlike the lookup above, this default cannot
            // widen access.
            .unwrap_or(false);

            if is_member {
                ContentAccess::Full
            } else {
                ContentAccess::Redacted
            }
        }
        // UNRECOGNISED PARTITION. Not a "safe default" — the previous comment
        // claimed that while doing the opposite. A `partition_type` this match
        // does not name is a row this code does not understand, and D1 forbids
        // granting full content on a value we cannot classify. The arm is
        // unreachable *today* only because `ownership_partition_check`
        // (CHECK partition_type IN ('public','community','private')) narrows the
        // vocabulary — a database constraint, not a type. Widen the constraint,
        // drop it, or write through a role that bypasses it, and this arm
        // decides. It decides closed.
        //
        // Covered by `tenant_isolation.rs::unknown_partition_type_is_redacted`,
        // which drops the CHECK inside a throwaway `#[sqlx::test]` database.
        _ => ContentAccess::Redacted,
    }
}

/// Batch check content access for multiple node IDs.
///
/// Returns a list of `(node_id, ContentAccess)` in the same order as input.
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
