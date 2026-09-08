//! Instance-level authorization for D4 privatization.
//!
//! # Group admin is necessary but not sufficient
//!
//! A group admin who could privatize arbitrary public claims into their own
//! group would be performing a **seizure**: exclusive read control over other
//! authors' work, and under `seal`, unrecoverable. The `writable_groups` /
//! `GroupPolicyGate` model cannot express this, because the operation's
//! *subject* is public data owned by nobody in particular. So this check is not
//! a `PolicyGate` call and not a `Viewer`; it is its own gate.
//!
//! # Four conditions, checked in this order, ALL required
//!
//! 1. **Token scope `instance:admin`.** Necessary, never sufficient — a scope is
//!    a claim the token makes about itself, not an authorization the instance
//!    made. `instance:admin` is in `ADMIN_ONLY_SCOPES`. **Do not read that as
//!    "only an operator can hold it":** the doc comment on
//!    `epigraph_core::canonical_scopes::ADMIN_ONLY_SCOPES` records, already and
//!    in the tree, a further route by which the scope can reach a token, and
//!    says outright that it is pre-existing and not closed. That published
//!    record is the reference rather than a narrower restatement here, which an
//!    earlier revision of this list gave and which would have let a future author
//!    conclude the scope alone is a meaningful authority. **Condition 2 is what
//!    actually holds**, and it is why condition 1 never needs to.
//! 2. **A live row in `instance_admins`.** The instance's own record, seeded
//!    only by the `epigraph-instance-admin` CLI over `epigraph_maintenance`.
//!    **There is no HTTP route that writes that table.** This is the condition
//!    that makes step 1 insufficient rather than decorative.
//! 3. **Target-group maturity and plurality.** The group must be at least 24 h
//!    old and have at least two live admins other than the caller. Without
//!    these, condition 4 prevented nothing: `POST /api/v1/groups` needs only
//!    `groups:write` and `create_with_admin` inserts the creator as
//!    `role='admin'`, so a compliant target group was one request away and the
//!    actor was its sole admin by construction.
//! 4. **`role='admin'` in the target group.** Kept rather than deleted because
//!    it does real work an honest operator cares about: privatizing into a group
//!    you cannot administer means you cannot later unseal it, revert it, or add
//!    a member to it. That is a durability property, not a security one.
//!
//! # This is the HTTP-layer half, and it is NOT the authorization
//!
//! Migration 081's `epigraph_privatization_plan_guard` enforces **condition 3**
//! — and only condition 3 — in the database. It is armed `BEFORE INSERT OR
//! UPDATE` unqualified and short-circuits in its body on "nothing this guard
//! governs changed", so it runs on every INSERT and on every statement that
//! moves `target_group_id`, `mode` or `created_by`, whether or not the statement
//! names that column. `pp_four_eyes` (080) and
//! `epigraph_privatization_approver_guard` (081) enforce the approval rules
//! there too, the latter on the same unqualified arming.
//!
//! **Condition 4 has no database half.** `role='admin'` in the target group is a
//! durability property rather than a security one (see above), and no trigger
//! asserts it; if 18b ever removes this check, nothing underneath replaces it.
//!
//! Conditions 1 and 2 are HTTP-layer only by construction: a token scope and a
//! roster lookup have no meaning to a `plpgsql` trigger firing on a maintenance
//! connection. The handler re-validates what the database also checks; this
//! function exists so a refusal is a 403 with a reason rather than a 500
//! carrying a raw SQLSTATE.
//!
//! # Why this takes `pool` as a parameter
//!
//! `no_unscoped_pool.rs` scans all of `crates/epigraph-api/src` for `.db_pool`
//! against an exact per-file register with monotone ceilings. Taking the pool as
//! an argument — the `group_authz.rs` precedent — keeps this file off that
//! register entirely; the routes that will call it (PR-18b) are where the
//! connection-shape decision belongs.

use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::AuthContext;

/// Minimum age of a privatization target group.
///
/// Named rather than inlined, and pinned against migration 081's own text by
/// [`tests::the_thresholds_match_the_literals_migration_081_installs`]. "Compare
/// them by reading" was the earlier justification and it is not a control: this
/// tree pins the FORCE array in four places with a TOTAL catalog comparison and
/// keeps `DELIBERATELY_UNCOVERED` exact in both directions, so a duplicated
/// literal with prose in place of an assertion is the same drift shape the
/// series already refuses elsewhere.
#[cfg(feature = "db")]
pub const TARGET_GROUP_MIN_AGE_HOURS: i64 = 24;

/// Minimum number of live admins in the target group OTHER than the caller.
///
/// Pinned against 081 alongside [`TARGET_GROUP_MIN_AGE_HOURS`].
#[cfg(feature = "db")]
pub const TARGET_GROUP_MIN_OTHER_ADMINS: i64 = 2;

/// Verify the caller may run a privatization against `target_group_id`.
///
/// Returns the caller's `agent_id` on success, so a handler does not have to
/// re-unwrap `auth.agent_id` and cannot accidentally proceed with `None`.
///
/// # ⚠ `pool` must be stamped or maintenance — 18b's decision, stated here
///
/// On a BARE, UNSTAMPED `epigraph_app` pool, condition 2 is false for every
/// caller and this function denies everyone: `epigraph_is_instance_admin` binds
/// its subject to `epigraph.principal_id`, which only
/// [`epigraph_db::pool::ScopedPool`] sets. That is fail-CLOSED — there is no
/// configuration in which this admits a caller it should not — but it is a
/// silent, total denial rather than an error, so it would present as "the
/// operator's grant did not work".
///
/// The requirement is repeated here rather than left on
/// `InstanceAdminRepository::is_active` one crate away, because THIS is the item
/// a route will call and the connection shape is chosen at that call site. The
/// argument is a bare `&sqlx::PgPool` and therefore carries no such guarantee in
/// its type; see the header's last section for why the pool is a parameter at
/// all.
///
/// # Errors
///
/// * `ApiError::Forbidden` — any of the four conditions fails. Every failure is
///   a 403 with a distinct reason and none of them leaks whether the target
///   group exists to a caller who is not already an instance admin: conditions
///   1 and 2 are checked before the group is read at all.
/// * `ApiError::NotFound` — the target group does not exist. Only reachable by
///   a caller who has already cleared conditions 1 and 2.
/// * `ApiError::InternalError` — the database query failed. A failure is never
///   mapped to a pass.
#[cfg(feature = "db")]
pub async fn require_instance_admin_for_group(
    auth: &AuthContext,
    target_group_id: Uuid,
    pool: &sqlx::PgPool,
) -> Result<Uuid, ApiError> {
    use chrono::{Duration, Utc};
    use epigraph_db::repos::group::GroupRepository;
    use epigraph_db::repos::group_membership::GroupMembershipRepository;
    use epigraph_db::repos::instance_admin::InstanceAdminRepository;

    // 1. Token scope.
    if !auth.has_scope("instance:admin") {
        return Err(ApiError::Forbidden {
            reason: "instance:admin required".to_string(),
        });
    }

    // An `instance:admin` token with no agent identity is refused rather than
    // treated as an anonymous instance admin. D3: a request with no principal
    // gets nothing.
    let agent_id = auth.agent_id.ok_or(ApiError::Forbidden {
        reason: "instance:admin requires an agent identity".to_string(),
    })?;

    // 2. The instance's own record. Asked through
    // `epigraph_is_instance_admin(uuid)`, not by reading `instance_admins` —
    // see that repository's module docs.
    if !InstanceAdminRepository::is_active(pool, agent_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
    {
        return Err(ApiError::Forbidden {
            reason: "not an instance administrator".to_string(),
        });
    }

    // 3a. Maturity. `GroupRepository::get_by_id` — NOT `get`, which the plan's
    // sketch names and which does not exist.
    let group = GroupRepository::get_by_id(pool, target_group_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })?
        .ok_or(ApiError::NotFound {
            entity: "group".to_string(),
            id: target_group_id.to_string(),
        })?;

    if group.created_at > Utc::now() - Duration::hours(TARGET_GROUP_MIN_AGE_HOURS) {
        return Err(ApiError::Forbidden {
            reason: format!(
                "target group must pre-exist the plan by {TARGET_GROUP_MIN_AGE_HOURS}h"
            ),
        });
    }

    // 3b. Plurality.
    let other_admins =
        GroupMembershipRepository::count_live_admins_excluding(pool, target_group_id, agent_id)
            .await
            .map_err(|e| ApiError::InternalError {
                message: e.to_string(),
            })?;
    if other_admins < TARGET_GROUP_MIN_OTHER_ADMINS {
        return Err(ApiError::Forbidden {
            reason: format!(
                "target group needs >= {TARGET_GROUP_MIN_OTHER_ADMINS} live admins besides you"
            ),
        });
    }

    // 4. Group admin in the TARGET group. `role == "admin"` ONLY: `creator` is
    // unstorable under `group_memberships_role_check` and the branch that
    // accepted it was deleted in PR-02.
    match GroupMembershipRepository::get_member_role(pool, target_group_id, agent_id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: e.to_string(),
        })? {
        Some(role) if role == "admin" => Ok(agent_id),
        _ => Err(ApiError::Forbidden {
            reason: "admin role in the target group required".to_string(),
        }),
    }
}

#[cfg(all(test, feature = "db"))]
mod tests {
    use super::{TARGET_GROUP_MIN_AGE_HOURS, TARGET_GROUP_MIN_OTHER_ADMINS};

    /// The two constants above and migration 081's hardcoded literals are one
    /// decision stored twice. Pin them together.
    ///
    /// A source-text assertion is the right instrument for the same reason
    /// `tenancy_migration_shape.rs` uses one: the SQL literals live inside a
    /// `plpgsql` body, so there is no catalog column to read and no behaviour to
    /// observe without a database. Drift is not a bypass — the trigger is the
    /// control and it would still refuse — but it turns 18b's intended 403 into
    /// a 500 carrying a raw SQLSTATE, which is precisely the outcome this
    /// module's header says the function exists to prevent.
    #[test]
    fn the_thresholds_match_the_literals_migration_081_installs() {
        let sql = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migrations/081_privatization_guards.sql"
        ))
        .expect("migration 081 must be readable from the api crate");

        let age = format!("interval '{TARGET_GROUP_MIN_AGE_HOURS} hours'");
        assert!(
            sql.contains(&age),
            "middleware/instance_authz.rs says the maturity threshold is \
             {TARGET_GROUP_MIN_AGE_HOURS}h, but migration 081 does not contain {age:?}. The \
             database trigger is the control; this constant only shapes the refusal, so a \
             drifted pair produces a 500 with a raw SQLSTATE instead of a 403 with a reason."
        );

        let plurality = format!("n_other_admins < {TARGET_GROUP_MIN_OTHER_ADMINS}");
        assert!(
            sql.contains(&plurality),
            "middleware/instance_authz.rs says the target group needs \
             {TARGET_GROUP_MIN_OTHER_ADMINS} other live admins, but migration 081 does not \
             contain {plurality:?}."
        );

        // CALIBRATION. The needles above are only evidence if a WRONG value
        // would not also be found. 081 must not happen to mention the
        // neighbouring thresholds somewhere else in its text.
        assert!(
            !sql.contains("interval '25 hours'") && !sql.contains("n_other_admins < 3"),
            "the pin is vacuous if 081 also contains the off-by-one spellings"
        );
    }
}
