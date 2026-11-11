//! Where a CALLER-authored workflow write lands: the owner group, and the
//! visibility, of the rows a workflow ingest or an `add_step` creates.
//!
//! Every workflow write is authored by, and stamped from, the CALLER's own
//! agent (the request's write identity), so the rows it creates must be owned
//! by a group the caller writes. The order, decided here once for every entry
//! point (the call sites handle steps 1 and 2 before asking):
//!
//! 1. A DECLARED tenancy (the `tenancy` parameter): `('group', G)` or, the
//!    explicit request to publish, `('public', G)`. The caller must write `G`,
//!    checked live inside the write's transaction.
//! 2. A GROUP-PRIVATE container (a new generation of a group lineage, a step
//!    added to a group plan) keeps its group (ruling R-98); the caller must
//!    write it. A declared public tenancy there is refused: it would publish
//!    the lineage.
//! 3. A PUBLIC container (a new generation of a public lineage, a step added
//!    to a public plan) stays public: in the container's own owner group when
//!    the caller writes it, else in the caller's own group (steps 4, 5), with
//!    the parent link (`parent_id`, the `variant_of` edge) kept by the plan walk.
//! 4. Otherwise the caller's ONE team group: exactly one live non-personal
//!    writer or admin membership
//!    (`GroupMembershipRepository::live_team_writer_groups_conn`):
//!    `('group', team)`.
//! 5. Otherwise the owner group of the caller's own default declaration
//!    (`ClaimRepository::default_decl_for_author`): its personal group, or its
//!    operator's for an operated agent, `('group', that group)`. Its refusals
//!    stand (`OPL01` for an unbound author, `OPL02` for an operated agent its
//!    operator does not let write there).
//!
//! An undeclared new workflow is therefore readable only by its owner group
//! (the team, or the person): public only when the caller asks for it.

use uuid::Uuid;

use crate::error::IngestExecutorError;

/// Which step of the order decided a [`CallerOwner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerSource {
    /// The existing public workflow or lineage's own owner group.
    Container,
    /// The caller's one live team group.
    Team,
    /// The caller's own default declaration (personal, or its operator's).
    Default,
}

/// The tenancy the rows of a caller-authored workflow write take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerOwner {
    pub decl: epigraph_core::TenancyDecl,
    pub source: OwnerSource,
}

/// Whether `caller` writes `group` NOW, on `conn` (the write's own
/// transaction): a live writer/admin membership through the live-membership
/// definer (direct or role-derived), AND the session stamp writes it (the
/// question every row's `WITH CHECK` asks). The first catches a membership
/// revoked after the caller's viewer was resolved, which the stamp still
/// carries; the second a membership granted after it, which the stamp lacks.
///
/// # Errors
/// `IngestExecutorError::Repository` if either read fails.
pub async fn caller_writes_group_now(
    conn: &mut sqlx::PgConnection,
    caller: Uuid,
    group: Uuid,
) -> Result<bool, IngestExecutorError> {
    Ok(
        epigraph_db::GroupMembershipRepository::agent_writes_group_conn(&mut *conn, caller, group)
            .await?
            && epigraph_db::GroupMembershipRepository::session_can_write_group_conn(
                &mut *conn, group,
            )
            .await?,
    )
}

/// Resolve the tenancy of a caller-authored workflow write with no declared
/// tenancy and no group-private container (the module doc's steps 3 to 5).
/// `public_container` is the owner group of the PUBLIC workflow or lineage
/// the write extends, if any: the rows stay public. With none they are
/// private to the caller's own owner group. Runs on the write's own
/// transaction, stamped from the caller.
///
/// # Errors
/// Whatever `default_decl_for_author` refuses (`OPL01` / `OPL02`, as
/// `Repository`); `Repository` for a failed read.
pub async fn resolve_caller_owner(
    conn: &mut sqlx::PgConnection,
    caller: Uuid,
    public_container: Option<Uuid>,
) -> Result<CallerOwner, IngestExecutorError> {
    if let Some(group) = public_container {
        if caller_writes_group_now(&mut *conn, caller, group).await? {
            return Ok(CallerOwner {
                decl: epigraph_core::TenancyDecl::public(group),
                source: OwnerSource::Container,
            });
        }
    }
    let (own, source) = callers_own_decl(&mut *conn, caller).await?;
    let decl = match own.owner_group_bind() {
        // A public container keeps its visibility wherever it lands.
        Some(group) if public_container.is_some() => epigraph_core::TenancyDecl::public(group),
        Some(group) => epigraph_core::TenancyDecl::group(group),
        // A declaration that names no owner group: passed through as is.
        None => own,
    };
    Ok(CallerOwner { decl, source })
}

/// The caller's OWN declaration: its one live team group (`Team`), else its
/// default declaration (`Default`: its personal group, or its operator's).
async fn callers_own_decl(
    conn: &mut sqlx::PgConnection,
    caller: Uuid,
) -> Result<(epigraph_core::TenancyDecl, OwnerSource), IngestExecutorError> {
    let teams =
        epigraph_db::GroupMembershipRepository::live_team_writer_groups_conn(&mut *conn, caller)
            .await?;
    if let [team] = teams.as_slice() {
        if epigraph_db::GroupMembershipRepository::session_can_write_group_conn(&mut *conn, *team)
            .await?
        {
            return Ok((epigraph_core::TenancyDecl::group(*team), OwnerSource::Team));
        }
    }
    Ok((
        epigraph_db::ClaimRepository::default_decl_for_author(&mut *conn, caller).await?,
        OwnerSource::Default,
    ))
}
