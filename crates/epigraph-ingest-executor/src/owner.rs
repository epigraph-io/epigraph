//! Where a CALLER-authored workflow write lands: the owner group of the rows
//! a workflow ingest or an `add_step` creates.
//!
//! Every workflow write is authored by, and stamped from, the CALLER's own
//! agent (the request's write identity), so the rows it creates must be owned
//! by a group the caller writes. The order, decided here once for every entry
//! point:
//!
//! 1. A DECLARED group (the `tenancy` parameter): `('group', G)`. The caller
//!    must write `G`, checked live inside the write's transaction.
//! 2. The CONTAINER's group, when the write extends an existing public
//!    workflow or lineage (an `add_step`, a new generation) whose owner group
//!    the caller writes: `('public', owner)`. A group-PRIVATE container is not
//!    decided here: its rows must stay in its group (ruling R-98), and the
//!    call sites refuse a caller that does not write it.
//! 3. The caller's ONE team group: exactly one live non-personal writer or
//!    admin membership (`GroupMembershipRepository::live_team_writer_groups_conn`):
//!    `('public', team)`.
//! 4. Otherwise the caller's own default declaration
//!    (`ClaimRepository::default_decl_for_author`): its personal group, or its
//!    operator's for an operated agent, public. This is the declaration every
//!    other claim the caller submits takes, with the same refusals (`OPL01` for
//!    an unbound author, `OPL02` for an operated agent its operator does not
//!    let write there).
//!
//! Step 2 is how a new generation of a public lineage whose group the caller
//! no longer writes is published: in the caller's own group (steps 3, 4), with
//! the parent link (`parent_id`, the `variant_of` edge) kept by the plan walk.
//!
//! The team and container answers are visibility `public`, as every
//! undeclared workflow write was before (the shared system agent's default
//! declaration was public): only the owner group moves. A caller that wants
//! the rows private to a group declares it (step 1).

use uuid::Uuid;

use crate::error::IngestExecutorError;

/// Which step of the order decided a [`CallerOwner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerSource {
    /// The caller declared the group.
    Declared,
    /// The existing workflow or lineage's own (public) owner group.
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

/// Resolve the owner of a caller-authored workflow write; see the module doc
/// for the order. `declared` is the caller's `tenancy` group; `public_container`
/// is the owner group of the PUBLIC workflow or lineage the write extends, if
/// any. Runs on the write's own transaction, stamped from the caller.
///
/// # Errors
/// [`IngestExecutorError::CallerNotGroupWriter`] for a declared group the
/// caller does not write now; whatever `default_decl_for_author` refuses
/// (`OPL01` / `OPL02`, as `Repository`); `Repository` for a failed read.
pub async fn resolve_caller_owner(
    conn: &mut sqlx::PgConnection,
    caller: Uuid,
    declared: Option<Uuid>,
    public_container: Option<Uuid>,
) -> Result<CallerOwner, IngestExecutorError> {
    if let Some(group) = declared {
        if !caller_writes_group_now(&mut *conn, caller, group).await? {
            return Err(IngestExecutorError::CallerNotGroupWriter { caller, group });
        }
        return Ok(CallerOwner {
            decl: epigraph_core::TenancyDecl::group(group),
            source: OwnerSource::Declared,
        });
    }
    if let Some(group) = public_container {
        if caller_writes_group_now(&mut *conn, caller, group).await? {
            return Ok(CallerOwner {
                decl: epigraph_core::TenancyDecl::public(group),
                source: OwnerSource::Container,
            });
        }
    }
    let teams =
        epigraph_db::GroupMembershipRepository::live_team_writer_groups_conn(&mut *conn, caller)
            .await?;
    if let [team] = teams.as_slice() {
        if epigraph_db::GroupMembershipRepository::session_can_write_group_conn(&mut *conn, *team)
            .await?
        {
            return Ok(CallerOwner {
                decl: epigraph_core::TenancyDecl::public(*team),
                source: OwnerSource::Team,
            });
        }
    }
    Ok(CallerOwner {
        decl: epigraph_db::ClaimRepository::default_decl_for_author(&mut *conn, caller).await?,
        source: OwnerSource::Default,
    })
}
