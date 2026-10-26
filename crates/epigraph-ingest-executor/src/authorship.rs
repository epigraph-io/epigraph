//! Authorship of the claims a workflow write creates, as a graph edge
//! (operator rulings, 2026-10-13: the agents writing workflow claims are
//! connected to their authorship "through a graph relationship rather than as
//! a parameter of the claim").
//!
//! Every row the executor writes is authored as, and stamped from, the shared
//! workflow-ingest system agent (`claims.agent_id`), so the claim says nothing
//! about the agent that called. [`record_caller_authorship`] records that agent
//! with the convention the claim-submission paths already use: an `AUTHORED`
//! edge, `source_type = 'agent'` -> `target_type = 'claim'`
//! (`epigraph-mcp`'s `claim_helper::create_claim_idempotent`, the REST
//! `POST /api/v1/claims` and packet routes). Authority traces from that agent
//! to its human through `OPERATED_BY` / the author binding, not through the
//! edge.
//!
//! * The edge is written with `EdgeRepository::create_if_not_exists_conn`, the
//!   same repo function the executor writes its plan edges with, on the
//!   caller's (system-stamped) transaction, so it commits or rolls back with
//!   the claims and a re-run never duplicates it.
//! * Tenancy is never bound here: `epigraph_edges_tenancy` computes it from the
//!   endpoints (an agent endpoint and a public claim give `('public', world)`,
//!   migration 120; a narrower claim gives its meet).
//! * Callers pass ONLY the claims the call CREATED. A claim the call merely
//!   reused (an operation atom shared with another workflow or a document, a
//!   step already present, a re-ingest) keeps the edge of the agent that
//!   created it and gets none from this call.
//! * Unlike the submit path's best-effort verb edge, a failure here is an
//!   error: the caller's write rolls back, so a workflow claim never lands
//!   without the record of who wrote it.

use uuid::Uuid;

/// The relationship, as the submit paths spell it (upper case; the lower-case
/// `authored` is the agent -> paper relationship).
pub const AUTHORED: &str = "AUTHORED";

/// Write one `AUTHORED` edge from `acting_agent` to each of `created_claims`,
/// idempotently, on `conn`. Returns how many edges this call inserted.
///
/// # Errors
/// `DbError` if an edge cannot be written; the caller's transaction must then
/// roll back.
pub async fn record_caller_authorship(
    conn: &mut sqlx::PgConnection,
    acting_agent: Uuid,
    created_claims: &[Uuid],
    tool: &str,
) -> Result<usize, epigraph_db::DbError> {
    let mut inserted = 0;
    for &claim in created_claims {
        let (_, was_created) = epigraph_db::EdgeRepository::create_if_not_exists_conn(
            &mut *conn,
            acting_agent,
            "agent",
            claim,
            "claim",
            AUTHORED,
            Some(serde_json::json!({"tool": tool, "was_created": true})),
            None,
            None,
        )
        .await?;
        inserted += usize::from(was_created);
    }
    Ok(inserted)
}
