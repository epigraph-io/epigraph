//! Community repository
//!
//! CRUD operations for communities (groups of perspectives with shared epistemic standards)
//! and community membership management.
//!
//! # The R7 projection, and the drift PR-12 closes
//!
//! Migration 068 projects `communities` onto `groups` (ID-preservingly) and
//! `community_members ⋈ perspectives.owner_agent_id` onto `group_memberships`.
//! **That projection was a one-time snapshot.** Until PR-12 the three write
//! functions here — [`CommunityRepository::create`],
//! [`CommunityRepository::add_member`] and
//! [`CommunityRepository::remove_member`] — wrote only `communities` /
//! `community_members`, so the first `POST /api/v1/communities` after deploy
//! broke the invariant and nothing noticed.
//!
//! `crates/epigraph-db/tests/tenancy_coverage.rs::every_community_projects_onto_a_group_and_its_members_onto_memberships`
//! **cannot** observe that drift — it seeds, then REPLAYS migration 068, then
//! asserts, so it tests the migration's output rather than a standing
//! invariant. Its own doc comment says so. A green run there is not evidence
//! that these functions project.
//!
//! ## `remove_member` was the dangerous half
//!
//! The plan and `docs/tenancy/progress.json` describe the drift as affecting
//! `create` and `add_member`. There is a third, and it drifts in the direction
//! that **GRANTS**: `remove_member` deleted the `community_members` row and
//! left the projected `group_memberships` row live. An agent removed from a
//! community therefore kept its projected group membership and — once PR-17
//! turns the predicate on — kept read access to that group's private corpus.
//! Bounded (the projection is `role='reader'`), but a revocation that does not
//! revoke is a security defect, not a bookkeeping one.
//!
//! ## Why `create` projecting is load-bearing rather than tidy
//!
//! **CORRECTION.** An earlier revision of this comment said migration 071's
//! shim "resolves a `partition_type = 'community'` row to `groups WHERE id =
//! community_id AND kind = 'community'` and **RAISES** if it is absent". It
//! does neither. 071's community arm INSERTs the group from `communities` **on
//! demand**, replays 068's membership projection, and — when no live membership
//! results — sets `g := NULL` and falls through to the owner's personal group.
//! There is no RAISE for an absent projected group.
//!
//! **PR-22 UPDATE — the two tests this paragraph used to cite are gone.** They
//! were `tenancy_triggers.rs::an_empty_community_falls_back_to_the_owner_rather_than_a_black_hole`
//! and `::a_community_partition_projects_the_group_and_its_members`, and
//! migration 084 retires both the `ownership` table and 071's shim, so the
//! fallback they pinned is **no longer executable anywhere** — there is no
//! writer left to reach it. The correction above still stands as a statement
//! about what 071 did; it simply no longer has a live pin, and this note is here
//! so a reader who greps for those names does not conclude the coverage was
//! dropped silently. What survives is the projection itself, which is what makes
//! `create` load-bearing: `community_projection.rs::create_projects_the_community_onto_a_group`
//! and `tenancy_coverage.rs::every_community_projects_onto_a_group_and_its_members_onto_memberships`.
//!
//! The real justification is narrower and does not need a false premise: the
//! projection is a **standing invariant** that
//! `tenancy_coverage.rs::every_community_projects_onto_a_group_and_its_members_onto_memberships`
//! structurally cannot observe, because it replays 068 before asserting. If
//! `create` does not project, the invariant is broken by the first
//! `POST /api/v1/communities` after deploy and no test in the tree notices;
//! 071's on-demand INSERT then papers over it at ownership-write time, but with
//! `created_by_agent_id` NULL and therefore zero administrators — migration
//! 068's documented dead end.
//!
//! ## Membership is CLOSED, and PR-12 is why that had to change here
//!
//! `POST /api/v1/communities/:id/members` performed no authorization beyond two
//! existence checks (`F-PR11-community-membership-is-self-service`, deferred by
//! PR-11 to "the PR that owns community authorization"). Before PR-12 that hole
//! lived only in `access_control.rs::check_content_access`'s community arm — a
//! table PR-14 deletes. **PR-12 moves it into the control plane that SURVIVES
//! PR-14 and that PR-17 arms**: the membership projected here becomes a live
//! `group_memberships` row, and `Viewer::resolve` pushes every live membership
//! into `group_ids` regardless of role. A stranger could create a perspective,
//! POST it into any community, and read that community's private corpus. The
//! integrity twin is the same route's DELETE: self-service eviction of a
//! legitimate member.
//!
//! Gating only the *projection* would not have closed it — 071's shim REPLAYS
//! the projection from `community_members` on every community-partitioned
//! ownership write, so the `community_members` row itself is the grant. The
//! authorization therefore sits on the whole operation, in the repo layer where
//! both writers reach it:
//!
//! * **adding** requires the acting agent to hold a LIVE membership of the
//!   community's projected group — unless that group has NEVER had a membership
//!   row of any state (the bootstrap case: 068 left projected groups
//!   memberless, and refusing would freeze them). A group whose members were all
//!   removed has had rows, so it does NOT re-open (batch F, F4b);
//! * **removing** requires the acting agent to own the perspective (leaving) or
//!   to hold a LIVE `admin` membership (evicting), and never removes the group's
//!   LAST live admin (batch F, F4a) — the guard
//!   `GroupMembershipRepository::revoke_member_unless_last_admin` has.
//!
//! Adding is deliberately weaker than "only an admin may add members": most
//! community groups have no admins (068), and the admin backfill for them is an
//! operator task (PR-18). It is fail-closed in the direction that matters (a
//! stranger cannot let itself in).
//!
//! ## Where the rule runs (batch F)
//!
//! In two `SECURITY DEFINER` functions, `epigraph_community_add_member` and
//! `epigraph_community_remove_member` (migration 106), each of which takes the
//! roster lock, decides under it and writes, as ONE statement. It used to be a
//! pool read (`may_manage_membership`) followed by a separate write
//! transaction — a TOCTOU window between two first joiners — and under the
//! deployed role the rule could not even be expressed in the caller's own
//! statements: `group_memberships_tenancy`'s WITH CHECK admits only an admin, so
//! a member could not remove itself, and a non-member cannot see the revoked
//! rows "has this group ever had a member?" must count. The actor is the
//! connection's stamped principal; see the migration for when `acting_agent`
//! is honoured instead.
//!
//! ## The route-level half is now in place too
//!
//! Both handlers (`epigraph-api/src/routes/community.rs::add_member` and
//! `::remove_member`) additionally require the `groups:admin` scope, via an
//! extractor, mirroring `routes/groups.rs`. Scope AND membership, never OR. The
//! reasoning — why `groups:admin` and not `groups:write`, and what it costs in
//! availability — is on `add_member`'s doc comment there, not duplicated here.
//! What this repo layer owns is unchanged: it is still the membership rule, and
//! it is still the rule both writers reach.
//!
//! The bootstrap case above is a residual, not a closed question. It is tracked
//! in `docs/tenancy/progress.json`; location
//! `migrations/068_communities_to_groups.sql` and this file; owner PR-18.
//! Analysis held outside this repository, as
//! `2026-09-12-F-PR12-projected-community-groups.md` in the operator's private
//! record. The filename is named on purpose: a bare "held privately" is
//! unverifiable, and six earlier findings in this series were redacted into
//! pointers whose record was never written.

use crate::errors::DbError;
use crate::repos::perspective::PerspectiveRow;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the communities table
#[derive(Debug, Clone, FromRow)]
pub struct CommunityRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub governance_type: Option<String>,
    pub ownership_type: Option<String>,
    pub mass_override: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// A row from the community_members junction table
#[derive(Debug, Clone, FromRow)]
pub struct CommunityMemberRow {
    pub community_id: Uuid,
    pub perspective_id: Uuid,
    pub joined_at: DateTime<Utc>,
}

/// The outcome of a community-membership write.
///
/// A distinct type rather than a `bool`, and rather than a new `DbError`
/// variant: the caller must map "denied" to 403 and "not there" to 404, and a
/// bare boolean at a two-caller site is exactly how those get conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipOutcome {
    /// The write happened.
    Applied,
    /// The row was not present (`remove_member` only).
    NotFound,
    /// The acting agent may not make this change (see the module docs for the
    /// rule). Map to 403.
    DeniedNotAMember,
    /// `remove_member` would remove the group's LAST live admin, which would
    /// leave it unmanageable. Nothing was written. Map to 409.
    LastAdmin,
}

impl MembershipOutcome {
    fn from_sql(outcome: &str) -> Result<Self, DbError> {
        match outcome {
            "applied" => Ok(Self::Applied),
            "not_found" => Ok(Self::NotFound),
            "denied" => Ok(Self::DeniedNotAMember),
            "last_admin" => Ok(Self::LastAdmin),
            other => Err(DbError::InvalidData {
                reason: format!("unexpected community membership outcome {other:?}"),
            }),
        }
    }
}

/// Repository for Community operations
pub struct CommunityRepository;

impl CommunityRepository {
    /// Create a new community **and its projected group**, atomically.
    ///
    /// `created_by_agent_id`, when supplied, becomes `groups.created_by_agent_id`
    /// and is given a live `role='admin'` membership in the new group.
    ///
    /// # The zero-admin problem this only partly solves
    ///
    /// Migration 068 records: *"no member is projected as 'admin', and
    /// `groups.created_by_agent_id` is left NULL … A projected community group
    /// therefore has ZERO administrators until PR-12 gives it one — `POST
    /// /groups/:id/members` cannot be used on it, and PR-18's '≥2 other live
    /// admins' precondition is unsatisfiable by construction."*
    ///
    /// This closes it for communities created **through this function with a
    /// known creator**. It does NOT close it for the ~existing projected groups
    /// (068 left `communities` with no creator column to derive one from), and
    /// `POST /api/v1/communities` currently passes `None` because that handler
    /// extracts no `AuthContext` at all — wiring one is a route-authentication
    /// change owned by PR-16, and `viewer_route_table_lint.rs` ratchets that
    /// set exactly. The residual is recorded in the PR body rather than papered
    /// over by inventing an admin.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any statement fails.
    #[instrument(skip(pool))]
    pub async fn create(
        pool: &PgPool,
        name: &str,
        description: Option<&str>,
        governance_type: Option<&str>,
        ownership_type: Option<&str>,
        created_by_agent_id: Option<Uuid>,
    ) -> Result<CommunityRow, DbError> {
        let mut tx = pool.begin().await?;

        let row: CommunityRow = sqlx::query_as(
            r#"
            INSERT INTO communities (name, description, governance_type, ownership_type,
                                     visibility, owner_group_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, description, governance_type, ownership_type, mass_override, created_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(governance_type)
        .bind(ownership_type)
        // Tenancy declaration (PR-16): `communities` has no parent and no
        // author, so migration 074's `epigraph_root_require_tenancy` has
        // nothing to derive from and the write must name both columns. The
        // community's OWN group is projected below (migration 068's shape) and
        // is not the owner of the registry row -- a community that owned its
        // own directory entry would be invisible to anyone deciding whether to
        // join it.
        .bind(epigraph_core::TenancyDecl::instance_wide().visibility_bind())
        .bind(epigraph_core::TenancyDecl::instance_wide().owner_group_bind())
        .fetch_one(&mut *tx)
        .await?;

        // The projection, in the SAME transaction. Shapes copied from migration
        // 068 deliberately, so the two cannot drift: ID-preserving, the
        // `did:epigraph:community:` key, `kind='community'`, and
        // `public_key = ''::bytea` because `groups_public_key_shape`
        // (migration 060) requires `octet_length(public_key) = 0` for every
        // `kind <> 'team'`. Untargeted ON CONFLICT because `groups_did_key_key`
        // is a second unique constraint, exactly as 068 argues.
        sqlx::query(
            r#"
            INSERT INTO groups (id, display_name, did_key, public_key, kind, created_at, created_by_agent_id)
            VALUES ($1, $2, 'did:epigraph:community:' || $1::text, ''::bytea, 'community', $3, $4)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(row.id)
        .bind(&row.name)
        .bind(row.created_at)
        .bind(created_by_agent_id)
        .execute(&mut *tx)
        .await?;

        // Epoch 0, key-free — 068 creates one for every projected group and
        // `group_key_epochs` is what later key operations hang off.
        sqlx::query(
            r#"
            INSERT INTO group_key_epochs (group_id, epoch, wrapped_key, status)
            VALUES ($1, 0, NULL, 'active')
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(row.id)
        .execute(&mut *tx)
        .await?;

        if let Some(agent) = created_by_agent_id {
            sqlx::query(
                r#"
                INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role)
                VALUES ($1, $2, ''::bytea, 0, 'admin')
                ON CONFLICT DO NOTHING
                "#,
            )
            .bind(row.id)
            .bind(agent)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(row)
    }

    /// Get a community by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<Option<CommunityRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT id, name, description, governance_type, ownership_type, mass_override, created_at
            FROM communities
            WHERE id = $1
              /* {VISIBILITY:communities} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, CommunityRow>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: Option<CommunityRow> = q.fetch_optional(executor).await?;

        Ok(row)
    }

    /// List all communities with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CommunityRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT id, name, description, governance_type, ownership_type, mass_override, created_at
            FROM communities
            WHERE true /* {VISIBILITY:communities} */
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, CommunityRow>(&sql)
            .bind(limit)
            .bind(offset);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<CommunityRow> = q.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Add a perspective as a community member **and project the membership**.
    ///
    /// Uses ON CONFLICT to be idempotent.
    ///
    /// `role = 'reader'`, matching migration 068 and for its stated reason:
    /// `community_members` records that a perspective may READ a community's
    /// content and says nothing about write authority, while `Viewer::resolve`
    /// puts `admin|writer` into the WRITABLE set. Projecting `'writer'` here
    /// would silently hand every community member write authority over the
    /// whole group's corpus.
    ///
    /// A perspective with a NULL `owner_agent_id` produces **no** membership —
    /// there is no agent to grant it to. That is 068's behaviour too, and it is
    /// a silent no-op by necessity, not by choice.
    ///
    /// A REVOKED projected row is restored at the requested role, `reader` — a
    /// revoked admin re-added through here never comes back as admin (batch F,
    /// F4a: this used to be `DO UPDATE SET revoked_at = NULL` with the old role
    /// kept). A LIVE row is left exactly as it is.
    ///
    /// # Authorization
    ///
    /// Closed membership — see the module docs. The decision and the write are
    /// ONE statement, `epigraph_community_add_member` (migration 106), under
    /// the roster lock. `acting_agent` is the authenticated principal
    /// (`Viewer::principal()`); on a non-maintenance connection it must equal the
    /// principal the connection was stamped with, or the call is denied, so
    /// pass a transaction from `ScopedPool::begin_as` for that viewer.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the statement fails.
    #[instrument(skip(executor))]
    pub async fn add_member<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        acting_agent: Option<Uuid>,
        community_id: Uuid,
        perspective_id: Uuid,
    ) -> Result<MembershipOutcome, DbError> {
        let outcome: String =
            sqlx::query_scalar("SELECT public.epigraph_community_add_member($1, $2, $3)")
                .bind(community_id)
                .bind(perspective_id)
                .bind(acting_agent)
                .fetch_one(executor)
                .await?;
        MembershipOutcome::from_sql(&outcome)
    }

    /// Remove a perspective from a community **and revoke the projected
    /// membership**.
    ///
    /// # This is the grant-direction drift
    ///
    /// Deleting only the `community_members` row left the projected
    /// `group_memberships` row LIVE, so a removed member kept reading the
    /// group's private corpus once PR-17 armed the predicate. Revocation is
    /// `revoked_at = now()`, not a DELETE, because `group_memberships` is an
    /// auditable ledger and `Viewer::resolve` filters on `revoked_at IS NULL`.
    ///
    /// **The projected membership is revoked only if the agent is not a member
    /// via some OTHER perspective in the same community.** Two perspectives
    /// owned by one agent both project onto the single `(group, agent, epoch)`
    /// row, so revoking unconditionally would cut access the remaining
    /// perspective still justifies.
    ///
    /// # Authorization
    ///
    /// Leaving (the actor owns the perspective) or evicting (the actor holds a
    /// LIVE `admin` membership) — nothing else; a live `reader` can no longer
    /// evict (batch F, F4a). The group's LAST live admin is never removed:
    /// [`MembershipOutcome::LastAdmin`], nothing written. Decision and write are
    /// ONE statement, `epigraph_community_remove_member` (migration 106), under
    /// the roster lock; the `groups.reseal_required_at` and `group_key_epochs`
    /// marks (PR-20) are made in it when, and only when, a revoke happened, in
    /// the lock order `revoke_member_unless_last_admin` uses. See
    /// [`Self::add_member`] for how `acting_agent` is checked.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the statement fails.
    #[instrument(skip(executor))]
    pub async fn remove_member<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        acting_agent: Option<Uuid>,
        community_id: Uuid,
        perspective_id: Uuid,
    ) -> Result<MembershipOutcome, DbError> {
        // ONE statement: the definer decides and revokes, and — only when it
        // answered 'applied' — this statement deletes the `community_members`
        // row as the CALLER's role. The definer's owner holds no DELETE (070:
        // the maintenance role never destroys). The initplan over `o` runs the
        // function before the DELETE's scan.
        let outcome: String = sqlx::query_scalar(
            r#"
            WITH o AS (
                SELECT public.epigraph_community_remove_member($1, $2, $3) AS outcome
            ),
            d AS (
                DELETE FROM community_members
                 WHERE community_id = $1 AND perspective_id = $2
                   AND (SELECT outcome FROM o) = 'applied'
                RETURNING 1
            )
            SELECT o.outcome || CASE WHEN o.outcome = 'applied'
                                          AND NOT EXISTS (SELECT 1 FROM d)
                                     THEN '_undeleted' ELSE '' END
              FROM o
            "#,
        )
        .bind(community_id)
        .bind(perspective_id)
        .bind(acting_agent)
        .fetch_one(executor)
        .await?;
        MembershipOutcome::from_sql(&outcome)
    }

    /// Get all member perspectives for a community
    ///
    /// # The projection must match `PerspectiveRow` field for field
    ///
    /// `PerspectiveRow` is a `#[derive(FromRow)]` struct with TEN fields and
    /// this list projected nine, omitting `properties`. `fetch_all` therefore
    /// failed at decode with `no column found for name: properties` for every
    /// community that HAS a member — a hard 500 on
    /// `GET /api/v1/communities/:id`, not a subtle degradation. It was
    /// invisible because this function has exactly one caller and that endpoint
    /// had no test anywhere in the workspace; conversion shard 6 wrote the first
    /// one and it failed on its first run. Restoring the column discloses
    /// nothing new: the row is already viewer-filtered by the spliced predicate
    /// below, and `routes/community.rs::get_community` maps only
    /// `id`/`name`/`owner_agent_id` into its response.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_members<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        community_id: Uuid,
    ) -> Result<Vec<PerspectiveRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT p.id, p.name, p.description, p.owner_agent_id, p.perspective_type,
                   p.frame_ids, p.extraction_method, p.confidence_calibration,
                   p.properties, p.created_at
            FROM perspectives p
            JOIN community_members cm ON cm.perspective_id = p.id
            WHERE cm.community_id = $1
              /* {VISIBILITY:p} */
            ORDER BY cm.joined_at ASC
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, PerspectiveRow>(&sql).bind(community_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<PerspectiveRow> = q.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Get all community IDs that a perspective belongs to
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn communities_for_perspective(
        pool: &PgPool,
        perspective_id: Uuid,
    ) -> Result<Vec<Uuid>, DbError> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT community_id FROM community_members
            WHERE perspective_id = $1
            "#,
        )
        .bind(perspective_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Get all member perspective IDs for a community
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn member_perspective_ids(
        pool: &PgPool,
        community_id: Uuid,
    ) -> Result<Vec<Uuid>, DbError> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT perspective_id FROM community_members
            WHERE community_id = $1
            "#,
        )
        .bind(community_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn community_row_has_expected_fields() {
        let _row = CommunityRow {
            id: Uuid::new_v4(),
            name: "epistemic_community".to_string(),
            description: Some("A test community".to_string()),
            governance_type: Some("open".to_string()),
            ownership_type: Some("public".to_string()),
            mass_override: None,
            created_at: Utc::now(),
        };
    }

    #[test]
    fn community_row_allows_none_optionals() {
        let _row = CommunityRow {
            id: Uuid::new_v4(),
            name: "minimal".to_string(),
            description: None,
            governance_type: None,
            ownership_type: None,
            mass_override: None,
            created_at: Utc::now(),
        };
    }

    #[test]
    fn community_row_with_mass_override() {
        let _row = CommunityRow {
            id: Uuid::new_v4(),
            name: "overriding_community".to_string(),
            description: Some("Community with mass override".to_string()),
            governance_type: Some("delegated".to_string()),
            ownership_type: Some("community".to_string()),
            mass_override: Some(serde_json::json!({
                "frame_id_placeholder": {"0,1": 0.8, "": 0.2}
            })),
            created_at: Utc::now(),
        };
    }

    #[test]
    fn community_member_row_has_expected_fields() {
        let _row = CommunityMemberRow {
            community_id: Uuid::new_v4(),
            perspective_id: Uuid::new_v4(),
            joined_at: Utc::now(),
        };
    }
}
