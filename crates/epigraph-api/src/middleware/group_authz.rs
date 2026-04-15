//! Group-level authorization: verify caller is an admin of the target group.

use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::AuthContext;

/// Verify the caller is an admin of the given group.
/// Uses existing GroupMembershipRepository::get_member_role().
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

    // Admin and creator roles can manage members
    if role_str != "admin" && role_str != "creator" {
        return Err(ApiError::Forbidden {
            reason: "Admin role required for this operation".to_string(),
        });
    }

    Ok(())
}
