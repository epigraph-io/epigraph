//! Resolves the shared `workflow-ingest-system` agent identity, and the write
//! authority a caller must stamp a connection with before the executor may run.
//!
//! Both ingest call sites (MCP `do_ingest_workflow_via_pool` and
//! HTTP `ingest_workflow`) need to attribute persisted claims to a
//! deterministic system agent. This helper looks it up by deterministic
//! `did:key` and creates it on first use.

use uuid::Uuid;

use crate::error::IngestExecutorError;

/// Get-or-create the canonical `workflow-ingest-system` agent.
///
/// Idempotent across processes: derives a deterministic `did:key` from a
/// fixed seed and either fetches the matching `agents` row or inserts one.
///
/// # Why an executor rather than a pool
///
/// So the lookup rides the SAME connection as the plan walk it belongs to.
/// MEASURED as `epigraph_app` (`rolbypassrls = false`) on a database migrated
/// 001→head from empty: the `agents` INSERT is admitted both unstamped and
/// inside a tenancy-stamped transaction (migration 077's `agents` policy is
/// `USING (true)` — authorship has to render on a public claim), so moving it
/// onto the stamped connection changes nothing about whether it succeeds. It
/// changes only *which* transaction it is part of, which is the whole point:
/// an agent minted on a sibling checkout survives a rollback of the ingest
/// that minted it.
///
/// # Errors
/// [`IngestExecutorError::AgentCreation`] if the lookup or the insert fails.
pub async fn get_or_create_system_agent(
    conn: &mut sqlx::PgConnection,
) -> Result<Uuid, IngestExecutorError> {
    let (_did, pub_key_bytes) =
        epigraph_crypto::did_key::did_key_for_author(None, "workflow-ingest-system");

    if let Some(existing) =
        epigraph_db::AgentRepository::get_by_public_key(&mut *conn, &pub_key_bytes)
            .await
            .map_err(|e| IngestExecutorError::AgentCreation(format!("lookup: {e}")))?
    {
        return Ok(existing.id.into());
    }

    let agent =
        epigraph_core::Agent::new(pub_key_bytes, Some("workflow-ingest-system".to_string()));
    let created = epigraph_db::AgentRepository::create_conn(&mut *conn, &agent)
        .await
        .map_err(|e| IngestExecutorError::AgentCreation(format!("create: {e}")))?;
    Ok(created.id.into())
}

/// The system agent's id together with the viewer a caller must stamp a
/// connection with before calling [`crate::execute_workflow_ingest_plan`] or
/// [`crate::add_step`].
#[derive(Debug)]
pub struct SystemAgentAuthority {
    /// The `workflow-ingest-system` agent every executor-written row is
    /// authored by.
    pub agent_id: Uuid,
    /// That agent's own viewer. Its writable set is what
    /// [`epigraph_db::ScopedPool::begin_as`] stamps, and what migration 077's
    /// `WITH CHECK` on every claim-derived table is asking about.
    pub viewer: epigraph_db::visibility::Viewer,
}

/// Resolve the system agent and prove it can write the rows the executor is
/// about to own. **The single place the executor's tenancy identity is decided.**
///
/// # Why the SYSTEM agent's viewer and not the caller's
///
/// The executor stamps every claim it writes with
/// `ClaimRepository::default_decl_for_author(system_agent_id)`, so every
/// workflow claim and every step claim is owned by the *system agent's* personal
/// group — a group the MCP process's own agent is not a member of. Migration
/// 077's `claims_tenancy` `WITH CHECK` asks
/// `owner_group_id = ANY(epigraph_writable_groups())`, i.e. a question about the
/// ROW's owner, not about who called the tool.
///
/// MEASURED as `epigraph_app` (`rolbypassrls = false`) on a database migrated
/// 001→head from empty, attempting the executor's own `claims` INSERT with
/// `owner_group_id` = the system agent's personal group:
///
/// ```text
/// ARM 1  unstamped (what this executor did before)   -> ERROR: new row violates
///                                                       row-level security policy
///                                                       for table "claims"
/// ARM 2  stamped from the MCP server's own agent     -> ERROR: new row violates
///                                                       row-level security policy
///                                                       for table "claims"
/// ARM 3  stamped from the system agent               -> INSERT 0 1
/// ```
///
/// ARM 2 is the shape #496 rejected: a caller-supplied author stamps the wrong
/// writable group and is refused while looking converted. It is measured here
/// rather than inferred, because the sibling MCP tools (`submit_claim`,
/// `memorize`, `challenge_claim`) DO author as `server.agent_id()` and reading
/// the identity off them gives the wrong answer for this path.
///
/// # The personal group is checked, and minted ONLY when nothing could be revived
///
/// The group this function must prove writable is specifically the system
/// agent's PERSONAL group, because that is what
/// `ClaimRepository::default_decl_for_author` will stamp on every row. "Some
/// writable group" is not the same question: an agent live in some other group
/// but not in its personal one would pass it, and the executor's own
/// `personal_group_of` would then take its mint path INSIDE the ingest
/// transaction.
///
/// So the check runs on a connection stamped from the agent's own viewer
/// (principal = the system agent, groups = its live set), where both reads it
/// needs can see:
///
/// * [`epigraph_db::GroupMembershipRepository::visible_personal_group_conn`] —
///   visible iff the agent holds a LIVE membership of it (`groups_tenancy`'s
///   session-groups arm, or its roster-bounded creator arm). Visible and
///   writable is the steady state and mints nothing.
/// * [`epigraph_db::GroupMembershipRepository::count_own_revoked_rows_conn`] —
///   the agent's own REVOKED rows, through `group_memberships_tenancy`'s
///   `agent_id = epigraph_principal_id()` arm, which admits them even when the
///   stamped group set is empty.
///
/// # Why a revoked membership is REFUSED, not restored (hard constraint #3)
///
/// The first revision of this function minted whenever the live set was empty
/// and justified it with "an app-role connection cannot tell never-provisioned
/// from revoked". That premise was false — the own-row arm above tells them
/// apart — and the consequence was the exact harm constraint #3 exists for.
/// MEASURED with the real binary as `epigraph_app` on a database migrated
/// 001→head: revoke the system agent's personal membership, call
/// `store_workflow`:
///
/// ```text
/// before the call   live=0 revoked=1
/// after the call    live=1 revoked=0     <- revoked admin REVIVED, and the
///                                           ingest committed 3 claims under it
/// ```
///
/// Migration 077's `epigraph_ensure_personal_group` ended in `ON CONFLICT … DO
/// UPDATE SET revoked_at = NULL, role = 'admin'` — a privilege change — and an
/// operator's revocation is a decision this path has no standing to reverse. So
/// a revoked row makes the ingest refuse, loudly, with nothing written;
/// restoring the membership is an operator action. Since migration 105 the
/// provisioning function refuses a revoked row itself (`DbError::MembershipRevoked`),
/// so this check is no longer the only thing between the ingest and a revival;
/// it stays because it refuses with the operator-facing reason BEFORE any
/// transaction is spent, and because it also catches the live-`reader` case,
/// which the function now leaves alone rather than promoting.
///
/// The mint survives for the one case where it cannot revive anything: the agent
/// has never held a revoked row (a fresh install, or a crash between
/// `get_or_create_system_agent` and the first provisioning). Refusing there
/// instead would make `store_workflow` permanently unavailable on every fresh
/// install — a conversion that cannot succeed for its own target population.
/// It is the same provisioning call `EpiGraphMcpFull::agent_id`'s PR-09 block
/// makes for the server's own agent, and it runs in the stamped transaction
/// that did the discriminating reads, so the decision and the write see one
/// snapshot.
///
/// A live `reader` membership of the personal group is refused too: every row
/// the executor writes is owned by that group, and a reader cannot write it.
/// (077's `DO UPDATE` would also have silently promoted it to `admin`;
/// migration 105's function leaves a live row's role alone.)
///
/// # Errors
/// [`IngestExecutorError::AgentCreation`] if the agent or its viewer cannot be
/// resolved, if the connection cannot be stamped, if the personal group is live
/// but not writable, if a revoked membership exists, or if the personal group is
/// still not writable after provisioning — a loud refusal with nothing written,
/// never a fallback to the unstamped pool.
pub async fn system_agent_write_authority(
    scoped: &epigraph_db::ScopedPool,
) -> Result<SystemAgentAuthority, IngestExecutorError> {
    use epigraph_db::GroupMembershipRepository as Memberships;

    let refuse = |why: String| {
        tracing::error!(target: "tenancy.scoped_write", "{why}");
        IngestExecutorError::AgentCreation(why)
    };
    let db = |what: &'static str| {
        move |e: epigraph_db::DbError| {
            IngestExecutorError::AgentCreation(format!(
                "workflow-ingest-system write authority: {what}: {e}"
            ))
        }
    };

    let pool = scoped.inner();
    let mut boot = pool
        .acquire()
        .await
        .map_err(|e| IngestExecutorError::AgentCreation(format!("acquire: {e}")))?;
    let agent_id = get_or_create_system_agent(&mut boot).await?;
    drop(boot);

    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent_id)
        .await
        .map_err(db("could not resolve the agent's viewer"))?;

    // Stamped from the agent's OWN viewer: principal = agent, groups = its live
    // set (possibly empty). Both discriminating reads need exactly this stamp.
    let mut tx = scoped
        .begin_as(&viewer)
        .await
        .map_err(db("could not stamp a connection from the agent's viewer"))?;

    if let Some(group) = Memberships::visible_personal_group_conn(&mut tx, agent_id)
        .await
        .map_err(db("personal group read"))?
    {
        // Read-only transaction; dropping it rolls back, which is all it needs.
        drop(tx);
        if viewer.writable_groups().contains(&group) {
            return Ok(SystemAgentAuthority { agent_id, viewer });
        }
        return Err(refuse(format!(
            "the workflow-ingest-system agent ({agent_id}) holds a LIVE but read-only membership \
             of its personal group ({group}). Every row the ingest executor writes is owned by \
             that group, so nothing can be written. Refusing: promoting the membership is an \
             operator decision"
        )));
    }

    let revoked = Memberships::count_own_revoked_rows_conn(&mut tx, agent_id)
        .await
        .map_err(db("own revoked-membership read"))?;
    if revoked > 0 {
        drop(tx);
        return Err(refuse(format!(
            "the workflow-ingest-system agent ({agent_id}) has no live membership of its personal \
             group and holds {revoked} REVOKED membership row(s). Refusing: reversing a \
             revocation is an operator decision (epigraph_ensure_personal_group refuses it too, \
             since migration 105). Restore the membership explicitly to re-enable workflow \
             ingest"
        )));
    }

    tracing::warn!(
        target: "tenancy.scoped_write",
        agent_id = %agent_id,
        "the workflow-ingest-system agent has never been provisioned a personal group (no live \
         membership of it, and no revoked membership row anywhere that a provisioning call \
         could revive); provisioning it now. This is the ONE mint on this path."
    );
    let group = epigraph_db::AgentRepository::ensure_personal_group(&mut tx, agent_id)
        .await
        .map_err(db("could not provision the personal group"))?;
    tx.commit()
        .await
        .map_err(db("could not commit the personal-group provisioning"))?;

    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent_id)
        .await
        .map_err(db("could not re-resolve the agent's viewer"))?;
    if !viewer.writable_groups().contains(&group) {
        return Err(refuse(format!(
            "the workflow-ingest-system agent ({agent_id}) still cannot write its personal group \
             ({group}) after provisioning, so no connection can be stamped with write authority \
             for the rows this ingest would own"
        )));
    }
    Ok(SystemAgentAuthority { agent_id, viewer })
}
