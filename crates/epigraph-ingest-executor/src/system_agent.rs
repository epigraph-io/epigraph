//! Resolves the shared `workflow-ingest-system` agent identity.
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
pub async fn get_or_create_system_agent(pool: &sqlx::PgPool) -> Result<Uuid, IngestExecutorError> {
    let (_did, pub_key_bytes) =
        epigraph_crypto::did_key::did_key_for_author(None, "workflow-ingest-system");

    if let Some(existing) = epigraph_db::AgentRepository::get_by_public_key(pool, &pub_key_bytes)
        .await
        .map_err(|e| IngestExecutorError::AgentCreation(format!("lookup: {e}")))?
    {
        return Ok(existing.id.into());
    }

    let agent =
        epigraph_core::Agent::new(pub_key_bytes, Some("workflow-ingest-system".to_string()));
    let created = epigraph_db::AgentRepository::create(pool, &agent)
        .await
        .map_err(|e| IngestExecutorError::AgentCreation(format!("create: {e}")))?;
    Ok(created.id.into())
}
