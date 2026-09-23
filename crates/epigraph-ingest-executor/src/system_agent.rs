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
/// # Why the group is ensured here, and why that is not constraint #3's hazard
///
/// The hazard the programme has already paid for is a helper that *advertises
/// read-first* becoming an unconditional re-mint because its read is blind:
/// `ClaimRepository::personal_group_of` reads `groups` directly, and
/// `groups_tenancy`'s USING has no true arm on an unstamped app session, so it
/// returns 0 rows for a group that exists and falls through to
/// `epigraph_ensure_personal_group`'s reviving `ON CONFLICT … DO UPDATE SET
/// revoked_at = NULL, role = 'admin'` on EVERY call. MEASURED, same database and
/// role:
///
/// ```text
/// unstamped     SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:…'  -> 0 rows
/// system-stamped SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:…' -> 1 row
/// ```
///
/// That is what `execute_workflow_ingest_plan` did on every ingest, through
/// `default_decl_for_author_pool`. The read below is NOT that read:
/// [`epigraph_db::visibility::Viewer::resolve`] goes through
/// `epigraph_live_memberships(uuid)`, a SECURITY DEFINER function granted to
/// `epigraph_app` in migration 077, which returns the agent's real live
/// memberships on an unstamped connection — MEASURED at 1 row for an agent whose
/// direct `groups` read returns 0. So in the steady state this function mints
/// **nothing**, which is strictly less minting than the path it replaces.
///
/// The mint runs only when the live set is genuinely empty, and then it is the
/// same provisioning call `EpiGraphMcpFull::agent_id`'s PR-09 block makes for
/// the server's own agent and `oauth/token.rs` makes for every API principal —
/// one provisioning behaviour across the codebase. It is logged at WARN because
/// an app-role connection cannot distinguish "this group was never provisioned"
/// from "this membership was deliberately revoked" (the discriminating read is
/// the blind one above), so on the revoked branch this restores authority and
/// says so. The alternative — refusing — makes `store_workflow` permanently
/// unavailable on every fresh install, which is a conversion that cannot succeed
/// for its own target population.
///
/// # Errors
/// [`IngestExecutorError::AgentCreation`] if the agent cannot be resolved, if
/// its viewer cannot be resolved, or if it still has no writable group after the
/// provisioning attempt — a loud refusal with nothing written, never a fallback
/// to the unstamped pool.
pub async fn system_agent_write_authority(
    pool: &sqlx::PgPool,
) -> Result<SystemAgentAuthority, IngestExecutorError> {
    let mut boot = pool
        .acquire()
        .await
        .map_err(|e| IngestExecutorError::AgentCreation(format!("acquire: {e}")))?;
    let agent_id = get_or_create_system_agent(&mut boot).await?;
    drop(boot);

    let resolve = |id: Uuid| async move {
        epigraph_db::visibility::Viewer::resolve(pool, id)
            .await
            .map_err(|e| {
                IngestExecutorError::AgentCreation(format!(
                    "could not resolve the workflow-ingest-system agent's viewer: {e}"
                ))
            })
    };

    let viewer = resolve(agent_id).await?;
    if !viewer.writable_groups().is_empty() {
        return Ok(SystemAgentAuthority { agent_id, viewer });
    }

    tracing::warn!(
        target: "tenancy.scoped_write",
        agent_id = %agent_id,
        "the workflow-ingest-system agent has no live writable group membership; provisioning \
         its personal group. This is the ONE mint on this path. If the membership existed and \
         was REVOKED, this call restores it at role='admin' — an app-role connection cannot \
         tell the two apart, because the read that would (groups by did_key) is blind under \
         groups_tenancy on an unstamped session."
    );

    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| IngestExecutorError::AgentCreation(format!("acquire: {e}")))?;
    epigraph_db::AgentRepository::ensure_personal_group(&mut conn, agent_id)
        .await
        .map_err(|e| {
            IngestExecutorError::AgentCreation(format!(
                "could not provision the workflow-ingest-system agent's personal group: {e}"
            ))
        })?;
    drop(conn);

    let viewer = resolve(agent_id).await?;
    if viewer.writable_groups().is_empty() {
        return Err(IngestExecutorError::AgentCreation(format!(
            "the workflow-ingest-system agent ({agent_id}) still has no live writable group \
             membership after provisioning, so no connection can be stamped with write authority \
             for the rows this ingest would own. Nothing was written."
        )));
    }
    Ok(SystemAgentAuthority { agent_id, viewer })
}
