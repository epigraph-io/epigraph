//! `GET /api/v1/agents/:id/prompt-history` (agent identity lineage design D4):
//! the prompt files an agent ran with, per group, and its succession lineage.
//!
//! # Who may read it
//!
//! The agent's operator (any link, retired ones included, so the history
//! outlives a hand-over) and admins. The decision is the database's: migration
//! 161's `epigraph_agent_prompt_history` reads the SESSION principal, so the
//! call runs on the caller's viewer-stamped connection ([`AppState::read_as`]),
//! never on the raw pool, where the principal is unset and every caller is
//! refused. Under armed admin scopes the definer's admin arm needs an ELEVATED
//! session, which is why this takes [`ViewerExtractor`] and not
//! `UnelevatedViewer`.
//!
//! A caller who is neither gets **404, exactly as for an agent that does not
//! exist** (`AID06` is never surfaced), so the route does not tell a stranger
//! which agent ids are real. An admin asking for an id with no agent behind it
//! gets the same 404: the definer does not check existence (it would answer
//! one empty `self` row), so the handler does, after the gate, on the same
//! connection. Only callers the gate admitted ever reach that check.
//!
//! # Shape
//!
//! The definer returns one row per (lineage member, snapshot). This groups
//! them: the agent's own snapshots, then `lineage.ancestors` (up the
//! succession, `distance` 1 = a parent) and `lineage.descendants` (down it),
//! one entry per agent carrying all of its snapshots. A lineage member the
//! caller may not read is listed by id with `readable: false` and no
//! snapshots.
//!
//! A file field is `null` for three different reasons, told apart by two
//! lists: the file did not exist (named nowhere), the host refused to store it
//! (named in `blob_refused`), or its stored blob failed verification on this
//! read (named in `withheld_files`).
//!
//! # No registration route
//!
//! Registering an identity is the EpiClaw host's act, on a database role the
//! request servers do not hold (design D3). Nothing here, or anywhere in this
//! crate, writes a snapshot or a succession.

use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use epigraph_core::AgentId;
use epigraph_db::agent_identity::PROMPT_HISTORY_REFUSED;
use epigraph_db::{
    AgentIdentityRepository, AgentRepository, DbError, PromptBlob, PromptHistoryEntry,
    PromptSnapshot,
};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::{AuthContext, ViewerExtractor};
use crate::state::AppState;

/// The scope the route requires.
pub const REQUIRED_SCOPE: &str = "claims:read";

/// `GET /api/v1/agents/:id/prompt-history` response.
#[derive(Debug, Serialize)]
pub struct PromptHistoryResponse {
    /// The agent asked about.
    pub agent_id: Uuid,
    /// Its snapshots, oldest first (empty for an agent never registered).
    pub snapshots: Vec<SnapshotView>,
    /// Its succession lineage.
    pub lineage: LineageView,
}

/// The agents an agent succeeded, and the agents that succeeded it.
#[derive(Debug, Serialize)]
pub struct LineageView {
    /// Up the succession, nearest first.
    pub ancestors: Vec<LineageMember>,
    /// Down the succession, nearest first.
    pub descendants: Vec<LineageMember>,
}

/// One agent in the lineage.
#[derive(Debug, Serialize)]
pub struct LineageMember {
    pub agent_id: Uuid,
    /// Generations from the agent asked about: 1 is a parent or a child.
    pub distance: u32,
    /// False for a member the caller does not operate: listed by id only.
    pub readable: bool,
    /// Its snapshots, oldest first (always empty when not readable).
    pub snapshots: Vec<SnapshotView>,
}

/// What one agent ran in one group, and when.
#[derive(Debug, Serialize)]
pub struct SnapshotView {
    pub id: Uuid,
    pub group_folder: String,
    pub model: String,
    /// The identity prompt hash.
    pub prompt_hash: String,
    /// Which files actually reached the prompt.
    pub in_prompt: Value,
    pub files: SnapshotFiles,
    /// Files the host refused to store (its capture-time scan), by name.
    pub blob_refused: Vec<String>,
    /// Files whose stored blob failed verification on this read, by name.
    pub withheld_files: Vec<String>,
    /// The runner version and host build of the FIRST start in this state.
    pub runner_version: Option<String>,
    pub host_sha: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// The four prompt files of a snapshot.
#[derive(Debug, Serialize)]
pub struct SnapshotFiles {
    pub identity_md: Option<FileView>,
    pub global_claude_md: Option<FileView>,
    pub group_claude_md: Option<FileView>,
    pub learned_md: Option<FileView>,
}

/// One stored prompt file, decompressed and verified against its hash.
#[derive(Debug, Serialize)]
pub struct FileView {
    /// BLAKE3 of the raw bytes, hex.
    pub blob_hash: String,
    /// The raw size in bytes.
    pub raw_size: usize,
    /// The file's text.
    pub text: String,
    /// True when the file was not valid UTF-8, so `text` replaced the invalid
    /// sequences and is not byte-exact.
    pub lossy: bool,
}

impl From<PromptBlob> for FileView {
    fn from(b: PromptBlob) -> Self {
        let lossy = std::str::from_utf8(&b.bytes).is_err();
        Self {
            blob_hash: hex::encode(b.blob_hash),
            raw_size: b.bytes.len(),
            text: b.text().into_owned(),
            lossy,
        }
    }
}

impl From<PromptSnapshot> for SnapshotView {
    fn from(s: PromptSnapshot) -> Self {
        Self {
            id: s.id,
            group_folder: s.group_folder,
            model: s.model,
            prompt_hash: s.prompt_hash,
            in_prompt: s.in_prompt,
            files: SnapshotFiles {
                identity_md: s.identity_md.map(Into::into),
                global_claude_md: s.global_claude_md.map(Into::into),
                group_claude_md: s.group_claude_md.map(Into::into),
                learned_md: s.learned_md.map(Into::into),
            },
            blob_refused: s.blob_refused,
            withheld_files: s.withheld_files,
            runner_version: s.runner_version,
            host_sha: s.host_sha,
            first_seen: s.first_seen,
            last_seen: s.last_seen,
        }
    }
}

/// Group the definer's rows (one per lineage member and snapshot, ordered by
/// depth, then first seen) into the response: one entry per agent, each
/// carrying all of its snapshots in the order the definer gave them.
#[must_use]
pub fn group_history(agent_id: Uuid, rows: Vec<PromptHistoryEntry>) -> PromptHistoryResponse {
    let mut own = Vec::new();
    let mut members: Vec<(i32, LineageMember)> = Vec::new();
    let mut index: HashMap<Uuid, usize> = HashMap::new();
    for row in rows {
        if row.depth == 0 {
            own.extend(row.snapshot.map(SnapshotView::from));
            continue;
        }
        let at = *index.entry(row.agent_id).or_insert_with(|| {
            members.push((
                row.depth,
                LineageMember {
                    agent_id: row.agent_id,
                    distance: row.depth.unsigned_abs(),
                    readable: row.readable,
                    snapshots: Vec::new(),
                },
            ));
            members.len() - 1
        });
        members[at]
            .1
            .snapshots
            .extend(row.snapshot.map(SnapshotView::from));
    }
    let (mut ancestors, mut descendants) = (Vec::new(), Vec::new());
    for (depth, member) in members {
        if depth < 0 {
            ancestors.push(member);
        } else {
            descendants.push(member);
        }
    }
    // Nearest first; the definer orders by signed depth, which puts the
    // FARTHEST ancestor first.
    ancestors.sort_by_key(|m| m.distance);
    descendants.sort_by_key(|m| m.distance);
    PromptHistoryResponse {
        agent_id,
        snapshots: own,
        lineage: LineageView {
            ancestors,
            descendants,
        },
    }
}

/// True when the definer refused the caller (neither operator nor admin).
fn is_refused(e: &DbError) -> bool {
    match e {
        DbError::QueryFailed { source } => source
            .as_database_error()
            .and_then(|d| d.code())
            .is_some_and(|c| c == PROMPT_HISTORY_REFUSED),
        _ => false,
    }
}

fn not_found(id: Uuid) -> ApiError {
    ApiError::NotFound {
        entity: "Agent".to_string(),
        id: id.to_string(),
    }
}

fn internal(what: &str, e: &dyn std::fmt::Display) -> ApiError {
    tracing::error!(target: "agent.prompt_history", error = %e, "{what}");
    ApiError::InternalError {
        message: format!("prompt history: could not {what}"),
    }
}

/// `GET /api/v1/agents/:id/prompt-history`: the agent's prompt snapshots and
/// lineage, for its operator and admins (`claims:read`).
///
/// # Errors
/// 401 without a principal; 403 without `claims:read` (checked before any
/// lookup, so it does not depend on the id); 404 for a caller who is neither
/// the operator nor an admin, and for an agent that does not exist, with the
/// same body.
pub async fn get_prompt_history(
    State(state): State<AppState>,
    auth_ctx: Option<Extension<AuthContext>>,
    ViewerExtractor(viewer): ViewerExtractor,
    Path(id): Path<Uuid>,
) -> Result<Json<PromptHistoryResponse>, ApiError> {
    let Some(Extension(auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "prompt history requires authentication".into(),
        });
    };
    crate::middleware::scopes::check_scopes(&auth, &[REQUIRED_SCOPE])?;

    let mut read = state
        .read_as(&viewer)
        .await
        .map_err(|e| internal("acquire a viewer-stamped connection", &e))?;
    let rows = match AgentIdentityRepository::prompt_history(&mut read, id).await {
        Ok(rows) => rows,
        Err(e) if is_refused(&e) => {
            tracing::info!(
                target: "agent.prompt_history",
                principal = ?auth.agent_id,
                agent = %id,
                "prompt history refused: the caller is neither the operator nor an admin"
            );
            return Err(not_found(id));
        }
        Err(e) => return Err(internal("read the history", &e)),
    };
    // Only the operator or an admin gets here. The definer answers an admin's
    // id with no agent behind it as one empty `self` row; that is a 404.
    if AgentRepository::get_by_id(&mut *read, AgentId::from_uuid(id))
        .await
        .map_err(|e| internal("look the agent up", &e))?
        .is_none()
    {
        return Err(not_found(id));
    }
    read.commit()
        .await
        .map_err(|e| internal("finish the read", &e))?;
    Ok(Json(group_history(id, rows)))
}
