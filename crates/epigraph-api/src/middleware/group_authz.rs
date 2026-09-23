//! Group-level authorization: verify caller is an admin of the target group.

use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::AuthContext;

/// Verify the caller holds a live `role='admin'` membership in the given group.
///
/// Uses `GroupMembershipRepository::get_member_role`, whose `LIMIT 1` is made
/// deterministic by the `group_memberships_one_live` partial unique index
/// (migration 060).
///
/// This is a MEMBERSHIP check, not a scope check. The routes that call it
/// require `groups:admin` at extractor time as well: scope AND membership.
/// Neither alone is sufficient — a `groups:admin` token must still be an admin
/// of the specific target group.
#[cfg(feature = "db")]
pub async fn require_group_admin(
    auth: &AuthContext,
    group_id: Uuid,
    pool: &sqlx::PgPool,
) -> Result<(), ApiError> {
    use epigraph_db::repos::group_membership::GroupMembershipRepository;

    let agent_id = auth.agent_id.ok_or(ApiError::Forbidden {
        reason: "Only agents can manage groups".to_string(),
    })?;

    let role_str = GroupMembershipRepository::get_member_role(pool, group_id, agent_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::Forbidden {
            reason: "Not a member of this group".to_string(),
        })?;

    // ONE role vocabulary: admin | writer | reader.
    //
    // This used to also accept a fourth role that
    // `group_memberships_role_check` (migration 060) has never permitted — the
    // branch was unreachable, and it implied a role a reader might try to grant.
    // The group creator is stored as role=admin by
    // `GroupRepository::create_with_admin`.
    // `tests/group_lifecycle.rs::the_four_role_vocabularies_agree` asserts by
    // source inspection that the dead literal is gone; an unreachable branch
    // cannot be caught by any runtime test.
    if role_str != "admin" {
        return Err(ApiError::Forbidden {
            reason: "Admin role required for this operation".to_string(),
        });
    }

    Ok(())
}

/// [`require_group_admin`] over a borrowed connection.
///
/// `POST /api/v1/groups/:id/rotate` runs its whole body on one
/// `ScopedPool::begin_as` transaction, so the authorization decision has to be
/// taken on the same stamped connection as the writes it authorises rather than
/// on the raw application pool. Same vocabulary, same single-role check, same
/// `group_memberships_one_live` determinism argument as the pool version above.
///
/// # Errors
/// `ApiError::Forbidden` when the token carries no agent, when the agent holds
/// no live membership, or when that membership is not `admin`;
/// `ApiError::InternalError` when the read fails.
#[cfg(feature = "db")]
pub async fn require_group_admin_conn(
    auth: &AuthContext,
    group_id: Uuid,
    conn: &mut sqlx::PgConnection,
) -> Result<(), ApiError> {
    use epigraph_db::repos::group_membership::GroupMembershipRepository;

    let agent_id = auth.agent_id.ok_or(ApiError::Forbidden {
        reason: "Only agents can manage groups".to_string(),
    })?;

    let role_str = GroupMembershipRepository::get_member_role_conn(conn, group_id, agent_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::Forbidden {
            reason: "Not a member of this group".to_string(),
        })?;

    if role_str != "admin" {
        return Err(ApiError::Forbidden {
            reason: "Admin role required for this operation".to_string(),
        });
    }

    Ok(())
}
