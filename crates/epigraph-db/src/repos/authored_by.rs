//! Who filed a claim: the `authored_by` block of a claim read
//! (`GET /api/v1/claims/:id`, MCP `get_claim`).
//!
//! A claim names the agent that filed it (`claims.agent_id`). Who-said-what
//! shows, beside that agent, the HUMAN it acts for, and as a side note the
//! prompt state the agent ran with when it filed the claim. Each part has its
//! own audience, and each is decided under the CALLER's viewer, on the
//! caller's viewer-stamped connection ([`ScopedRead`]), so this block never
//! tells a caller anything it could not already read elsewhere:
//!
//! * **`agent`** `{id, display_name}`: every reader of the claim. `agents` is
//!   readable by every session (077's `agents_identity` policy), and
//!   `GET /api/v1/agents/:id` answers the same two fields for any id.
//! * **`human`** `{id, display_name}`: every reader of the claim. It is the
//!   agent's binding, migration 149's `epigraph_human_of(agent, false)`: its
//!   operator link, in ANY state, so the attribution outlives a retirement;
//!   else the operator of its allowlisted client. It is read from that
//!   binding and from nothing else. In particular no `OPERATED_BY` edge
//!   decides it: any edges:write caller can write one between two agents, so
//!   an edge proves nothing about who operates whom, and a forged edge
//!   changes nothing here. A registered human operator is bound to ITSELF;
//!   that is not an operator, so a human's own claim names no human (the
//!   agent part already names them), and the block never says who is a
//!   registered human operator. The link tables themselves
//!   (`operator_links`, `human_operators`, `author_binding_clients`) are
//!   never read here.
//! * **`prompt_snapshot`** `{snapshot_id, model, prompt_hash, started_at}`:
//!   the snapshot (161, design D4) the agent was running at the claim's
//!   `created_at`, read through migration 199's
//!   `epigraph_agent_prompt_snapshot_at`, whose gate is 161's prompt-history
//!   gate: the agent's linked human (any link state) and admins. Who else may
//!   see it is the owner's pending call, and it is ONE constant:
//!   [`PROMPT_SNAPSHOT_AUDIENCE`]. Prompt TEXT is never part of this block; it
//!   stays behind `GET /api/v1/agents/:id/prompt-history/blobs/:hash`.
//!
//! A part the caller may not see is `null`, byte for byte the same as a part
//! that does not exist (an agent that never registered a snapshot), so the
//! block is not an oracle for who may read an agent's prompt history.
//!
//! `prompt_hash` is the identity prompt hash (161: the identity key is a
//! function of the model and this hash, so both are the same for every
//! snapshot of one agent). Which files the agent ran with is named by
//! `snapshot_id`, which an admitted caller can look up in
//! `GET /api/v1/agents/:id/prompt-history`.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::errors::DbError;
use crate::pool::ScopedRead;
use crate::repos::agent::AgentRepository;
use crate::visibility::Viewer;

/// Who may see a claim's `authored_by.prompt_snapshot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptSnapshotAudience {
    /// Exactly the callers that may read the agent's prompt text (161's
    /// prompt-history gate, design D4): the human the agent is linked to, in
    /// any link state, and admins.
    OperatorAndAdmins,
    /// Every caller that can read the claim.
    ClaimReaders,
}

impl PromptSnapshotAudience {
    /// Migration 199's `p_open` argument.
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Self::ClaimReaders)
    }
}

/// THE OWNER'S CALL, IN ONE PLACE: who sees a claim's prompt snapshot.
/// Proposed: every reader of the claim
/// ([`PromptSnapshotAudience::ClaimReaders`]), prompt text staying gated.
/// The conservative setting, shipped while the call is pending, is
/// [`PromptSnapshotAudience::OperatorAndAdmins`] (the prompt-text gate).
/// Changing the value below is the whole change: the REST and MCP claim
/// tests read it and assert whichever setting is live, and the repo tests
/// drive both settings explicitly.
pub const PROMPT_SNAPSHOT_AUDIENCE: PromptSnapshotAudience =
    PromptSnapshotAudience::OperatorAndAdmins;

/// One agent, as `GET /api/v1/agents/:id` names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorRef {
    pub id: Uuid,
    pub display_name: Option<String>,
}

/// The prompt snapshot an agent was running at an instant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PromptSnapshotAt {
    /// The snapshot row (`GET /api/v1/agents/:id/prompt-history` lists it).
    pub snapshot_id: Uuid,
    pub model: String,
    /// The identity prompt hash (64 hex digits).
    pub prompt_hash: String,
    /// The snapshot's latest recorded start at or before the instant.
    pub started_at: DateTime<Utc>,
}

/// A claim's `authored_by` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthoredBy {
    pub agent: AuthorRef,
    /// The agent's operator (its binding), for every reader; `None` when the
    /// agent is bound to no human or only to itself.
    pub human: Option<AuthorRef>,
    /// `None` both when no snapshot was active and when the caller is not in
    /// the audience.
    pub prompt_snapshot: Option<PromptSnapshotAt>,
}

pub struct AuthoredByRepository;

impl AuthoredByRepository {
    /// The `authored_by` block of a claim filed by `agent_id` at
    /// `created_at`, as `viewer` may see it. `read` must be `viewer`'s own
    /// stamped connection (the snapshot gate reads its session principal). Call it only for a claim
    /// `viewer` has already read.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if a read fails, including on a database
    /// without migration 199 (42883).
    pub async fn for_claim(
        read: &mut ScopedRead<'_>,
        _viewer: &Viewer,
        agent_id: Uuid,
        created_at: DateTime<Utc>,
        audience: PromptSnapshotAudience,
    ) -> Result<AuthoredBy, DbError> {
        let conn: &mut sqlx::PgConnection = read;

        // The human: the agent's binding, for every reader. Never an edge.
        // A binding to the agent itself (a registered human operator) is not
        // an operator and is not shown.
        let human_id = AgentRepository::human_of(&mut *conn, agent_id, false)
            .await?
            .filter(|h| *h != agent_id);

        // Both names in one read; `agents` is readable by every session.
        let wanted: Vec<Uuid> = std::iter::once(agent_id).chain(human_id).collect();
        let names: Vec<(Uuid, Option<String>)> =
            sqlx::query_as("SELECT id, display_name FROM agents WHERE id = ANY($1)")
                .bind(&wanted)
                .fetch_all(&mut *conn)
                .await?;
        let name_of = |id: Uuid| {
            names
                .iter()
                .find(|(n, _)| *n == id)
                .and_then(|(_, d)| d.clone())
        };

        let prompt_snapshot = sqlx::query_as::<_, (Uuid, String, String, DateTime<Utc>)>(
            "SELECT snapshot_id, model, prompt_hash, started_at \
               FROM public.epigraph_agent_prompt_snapshot_at($1, $2, $3)",
        )
        .bind(agent_id)
        .bind(created_at)
        .bind(audience.is_open())
        .fetch_optional(&mut *conn)
        .await?
        .map(
            |(snapshot_id, model, prompt_hash, started_at)| PromptSnapshotAt {
                snapshot_id,
                model,
                prompt_hash,
                started_at,
            },
        );

        Ok(AuthoredBy {
            agent: AuthorRef {
                id: agent_id,
                display_name: name_of(agent_id),
            },
            human: human_id.map(|id| AuthorRef {
                id,
                display_name: name_of(id),
            }),
            prompt_snapshot,
        })
    }
}
