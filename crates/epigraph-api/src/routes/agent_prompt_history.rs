//! `GET /api/v1/agents/:id/prompt-history` and
//! `GET /api/v1/agents/:id/prompt-history/blobs/:hash` (agent identity lineage
//! design D4): the prompt files an agent ran with, per group, and its
//! succession lineage; then the content of one of those files.
//!
//! # Who may read it
//!
//! Whoever `epigraph_human_of(agent, false)` (migration 149) names, and
//! admins. That is: a human the agent is linked to, in ANY link state, a
//! retired link included, so the history outlives a hand-over; for an agent
//! with no link at all, the operator of its allowlisted client (149's
//! `author_binding_clients` arm); and a registered human operator asking about
//! itself. The decision is the database's: migration 161's
//! `epigraph_agent_prompt_history` reads the SESSION principal, so the call
//! runs on the caller's viewer-stamped connection ([`AppState::read_as`]),
//! never on the raw pool, where the principal is unset and every caller is
//! refused. Under armed admin scopes the definer's admin arm needs an ELEVATED
//! session, which is why this takes [`ViewerExtractor`] and not
//! `UnelevatedViewer`.
//!
//! A caller who is neither gets **404, with the body an agent that does not
//! exist gets** (`AID06` is never surfaced). That is uniformity, not secrecy:
//! agent ids are not secret (`agents` is readable by every session, and
//! `GET /api/v1/agents/:id` answers for any id), so the 404 protects the
//! history, not the agent's existence. An admin asking for an id with no agent
//! behind it gets the same 404: the definer does not check existence (it would
//! answer one empty `self` row), so the handler does, after the gate, on the
//! same connection. Only callers the gate admitted ever reach that check.
//!
//! # Shape
//!
//! The listing reads migration 268's `epigraph_agent_prompt_history_meta`,
//! which has 161's gate and walk but returns hashes and metadata only: no
//! prompt text is built in the database for a listing. It returns one row per
//! (lineage member, snapshot). The listing groups them: the agent's own
//! snapshots, then `lineage.ancestors` (up the succession, `distance` 1 = a
//! parent) and `lineage.descendants` (down it), one entry per agent carrying
//! its snapshots. A lineage member the caller may not read is listed by id
//! with `readable: false` and no snapshots. The walk goes
//! [`LINEAGE_DEPTH_LIMIT`] generations each way; `ancestors_at_limit` /
//! `descendants_at_limit` say it reached that limit, so farther generations,
//! if any, are not listed. Both flags describe the WHOLE walk on every page
//! that has rows; they are taken from the rows served, so an empty page (only
//! after a cursor this route did not issue, or after the lineage changed
//! between pages) reports both as `false`.
//!
//! # Pages
//!
//! The rows come nearest first (the agent itself, then distance 1, ancestors
//! before descendants, then distance 2, ...), each agent's snapshots
//! contiguous and oldest first, at most `limit` rows a page
//! ([`DEFAULT_PAGE_ROWS`], at most [`MAX_PAGE_ROWS`]) and at most
//! [`PAGE_BYTE_BUDGET`] bytes of snapshot metadata (a single row larger than
//! that is still served alone, so every page advances). A page that stops
//! before the end says so: `truncated: true` and a `next_cursor`, which the
//! caller passes back as `?after=` (with the same `limit`, or another) for
//! the next page; the last page has `truncated: false` and no cursor. A
//! member whose snapshots straddle a page boundary appears on both pages, so
//! a client reading every page merges members by `agent_id`. The cursor is a
//! position only: every page re-runs the gate and the walk, so a forged one
//! reads nothing the first page would not. Reading every page yields each row
//! once only while the lineage does not change between pages (keyset paging):
//! a snapshot registered for a member the cursor has passed is not on a later
//! page, and a new succession edge that brings a member nearer can move it
//! before the cursor, so it is skipped; re-read from the first page to see
//! such changes.
//!
//! The listing carries NO file content: each file is named by the BLAKE3 of
//! its raw bytes (`{"blob_hash": ..}`), so the listing grows with the number of
//! snapshots and never with the files (up to 8 MiB each, a LEARNED.md per
//! generation, a shared CLAUDE.md once per snapshot). A file field is `null`
//! when the file did not exist, or when the host refused to store it (then it
//! is named in `blob_refused`).
//!
//! The content of one file is
//! `GET /api/v1/agents/:id/prompt-history/blobs/:hash`: served only when a
//! snapshot the caller may READ in `:id`'s history names that hash (the
//! definer's gate, then its `readable` mark), decompressed and re-hashed to its
//! key, as `{blob_hash, raw_size, text, lossy}`. A hash no readable snapshot
//! names, an unreadable lineage member's included, is a 404; a stored blob that
//! fails verification is WITHHELD, a 500 naming the failure, and its bytes are
//! never served. The server holds at most one file's content per request. The
//! file read still goes through 161's definer, which builds the whole
//! lineage's content inside the database to return that one file.
//!
//! # No registration route
//!
//! Registering an identity is the EpiClaw host's act, on a database role the
//! request servers do not hold (design D3). Nothing here, or anywhere in this
//! crate, writes a snapshot or a succession.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use epigraph_core::AgentId;
use epigraph_db::agent_identity::PROMPT_HISTORY_REFUSED;
use epigraph_db::{
    AgentIdentityRepository, AgentRepository, DbError, PromptBlob, PromptBlobRead,
    PromptHistoryCursor, PromptHistoryIndexEntry, PromptSnapshotIndex,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::{AuthContext, ViewerExtractor};
use crate::state::AppState;

/// The scope the route requires.
pub const REQUIRED_SCOPE: &str = "claims:read";

/// How many generations migration 161's `epigraph_agent_prompt_history` walks
/// each way (its `v_level < 64`). It is the definer's literal, restated here
/// so the listing can say when the walk reached it;
/// `the_listing_says_when_the_lineage_walk_reached_its_depth_limit` fails if
/// the two drift apart.
pub const LINEAGE_DEPTH_LIMIT: u32 = 64;

/// Rows a page holds when the caller names no `limit`.
pub const DEFAULT_PAGE_ROWS: u32 = 200;
/// The largest `limit` honoured; a larger one is clamped to it.
pub const MAX_PAGE_ROWS: u32 = 500;
/// The most snapshot metadata a page carries, in serialised bytes (estimated
/// per row by [`row_bytes`]); the page stops before the row that would pass
/// it, unless that row is the page's first.
pub const PAGE_BYTE_BUDGET: usize = 512 * 1024;

const BAD_CURSOR: &str =
    "malformed `after` cursor; pass back the `next_cursor` of the previous page unchanged";

/// `GET /api/v1/agents/:id/prompt-history` query.
#[derive(Debug, Default, Deserialize)]
pub struct PromptHistoryQuery {
    /// The `next_cursor` of the previous page.
    #[serde(default)]
    pub after: Option<String>,
    /// Rows per page, clamped to `[1, MAX_PAGE_ROWS]`.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `GET /api/v1/agents/:id/prompt-history` response.
#[derive(Debug, Serialize)]
pub struct PromptHistoryResponse {
    /// The agent asked about.
    pub agent_id: Uuid,
    /// Its snapshots on this page, oldest first (empty for an agent never
    /// registered).
    pub snapshots: Vec<SnapshotView>,
    /// Its succession lineage, as far as this page reaches.
    pub lineage: LineageView,
    /// True when more rows follow this page: pass `next_cursor` back.
    pub truncated: bool,
    /// The `?after=` of the next page; `None` on the last page.
    pub next_cursor: Option<String>,
}

/// The agents an agent succeeded, and the agents that succeeded it.
#[derive(Debug, Serialize)]
pub struct LineageView {
    /// Up the succession, nearest first.
    pub ancestors: Vec<LineageMember>,
    /// Down the succession, nearest first.
    pub descendants: Vec<LineageMember>,
    /// How many generations the walk goes each way.
    pub depth_limit: u32,
    /// True when an ancestor is listed at `depth_limit`: the walk stopped
    /// there, so farther ancestors, if any, are not listed.
    pub ancestors_at_limit: bool,
    /// The same, down the succession.
    pub descendants_at_limit: bool,
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
    /// The runner version and host build of the FIRST start in this state.
    pub runner_version: Option<String>,
    pub host_sha: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// The four prompt files of a snapshot, each by key only.
#[derive(Debug, Serialize)]
pub struct SnapshotFiles {
    pub identity_md: Option<FileRef>,
    pub global_claude_md: Option<FileRef>,
    pub group_claude_md: Option<FileRef>,
    pub learned_md: Option<FileRef>,
}

/// One stored prompt file, named; its content is the blob endpoint's.
#[derive(Debug, Serialize)]
pub struct FileRef {
    /// BLAKE3 of the raw bytes, hex: the `:hash` of the blob endpoint.
    pub blob_hash: String,
}

/// `GET /api/v1/agents/:id/prompt-history/blobs/:hash` response: one stored
/// prompt file, decompressed and verified against its hash.
#[derive(Debug, Serialize)]
pub struct BlobView {
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

impl From<PromptBlob> for BlobView {
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

fn file_ref(key: Option<[u8; 32]>) -> Option<FileRef> {
    key.map(|k| FileRef {
        blob_hash: hex::encode(k),
    })
}

impl From<PromptSnapshotIndex> for SnapshotView {
    fn from(s: PromptSnapshotIndex) -> Self {
        Self {
            id: s.id,
            group_folder: s.group_folder,
            model: s.model,
            prompt_hash: s.prompt_hash,
            in_prompt: s.in_prompt,
            files: SnapshotFiles {
                identity_md: file_ref(s.identity_md),
                global_claude_md: file_ref(s.global_claude_md),
                group_claude_md: file_ref(s.group_claude_md),
                learned_md: file_ref(s.learned_md),
            },
            blob_refused: s.blob_refused,
            runner_version: s.runner_version,
            host_sha: s.host_sha,
            first_seen: s.first_seen,
            last_seen: s.last_seen,
        }
    }
}

/// What one row costs a page, in serialised bytes: its snapshot's metadata
/// as the response writes it, plus a fixed allowance for the member entry and
/// separators. A row with no snapshot costs the allowance alone.
#[must_use]
pub fn row_bytes(row: &PromptHistoryIndexEntry) -> usize {
    const MEMBER_ALLOWANCE: usize = 128;
    MEMBER_ALLOWANCE
        + row.snapshot.as_ref().map_or(0, |s| {
            serde_json::to_vec(&SnapshotView::from(s.clone())).map_or(0, |b| b.len())
        })
}

/// Cut a fetched page: keep rows while fewer than `limit` are kept and the
/// kept bytes (`size` per row) stay within `budget`, always keeping the first
/// row so a page advances. True as the second value when rows were left out,
/// so the caller emits a cursor from the LAST KEPT row.
pub fn cut_page<T>(
    mut rows: Vec<T>,
    limit: usize,
    budget: usize,
    size: impl Fn(&T) -> usize,
) -> (Vec<T>, bool) {
    let mut kept = 0usize;
    let mut bytes = 0usize;
    for row in &rows {
        let cost = size(row);
        if kept >= limit || (kept > 0 && bytes.saturating_add(cost) > budget) {
            break;
        }
        bytes = bytes.saturating_add(cost);
        kept += 1;
    }
    let truncated = kept < rows.len();
    rows.truncate(kept);
    (rows, truncated)
}

/// Group a page of the definer's rows (one per lineage member and snapshot,
/// nearest first, each agent's snapshots contiguous) into the response: one
/// entry per agent, each carrying its snapshots on this page in the order the
/// definer gave them. The depth-limit flags come from the WHOLE walk's
/// extent (its farthest ancestor and descendant depths), not from the page.
#[must_use]
pub fn group_history(
    agent_id: Uuid,
    rows: Vec<PromptHistoryIndexEntry>,
    extent: (Option<i32>, Option<i32>),
    next_cursor: Option<String>,
) -> PromptHistoryResponse {
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
    // Nearest first. The definer's order already is; the stable sort keeps
    // it whatever order the rows arrive in.
    ancestors.sort_by_key(|m| m.distance);
    descendants.sort_by_key(|m| m.distance);
    let at_limit = |d: Option<i32>| d.is_some_and(|d| d.unsigned_abs() >= LINEAGE_DEPTH_LIMIT);
    PromptHistoryResponse {
        agent_id,
        snapshots: own,
        lineage: LineageView {
            ancestors_at_limit: at_limit(extent.0),
            descendants_at_limit: at_limit(extent.1),
            ancestors,
            descendants,
            depth_limit: LINEAGE_DEPTH_LIMIT,
        },
        truncated: next_cursor.is_some(),
        next_cursor,
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

/// `GET /api/v1/agents/:id/prompt-history`: one page of the agent's prompt
/// snapshots and lineage, for its operator and admins (`claims:read`).
///
/// # Errors
/// 401 without a principal; 403 without `claims:read` (checked before any
/// lookup, so it does not depend on the id); 400 for an `after` this route
/// did not issue; 404 for a caller who is neither the operator nor an admin,
/// and for an agent that does not exist, with the same body.
pub async fn get_prompt_history(
    State(state): State<AppState>,
    auth_ctx: Option<Extension<AuthContext>>,
    ViewerExtractor(viewer): ViewerExtractor,
    Path(id): Path<Uuid>,
    Query(q): Query<PromptHistoryQuery>,
) -> Result<Json<PromptHistoryResponse>, ApiError> {
    let Some(Extension(auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "prompt history requires authentication".into(),
        });
    };
    crate::middleware::scopes::check_scopes(&auth, &[REQUIRED_SCOPE])?;
    let after = q
        .after
        .as_deref()
        .map(|raw| {
            PromptHistoryCursor::decode(raw).ok_or_else(|| ApiError::BadRequest {
                message: BAD_CURSOR.into(),
            })
        })
        .transpose()?;
    let limit = q.limit.unwrap_or(DEFAULT_PAGE_ROWS).clamp(1, MAX_PAGE_ROWS);

    let mut read = state
        .read_as(&viewer)
        .await
        .map_err(|e| internal("acquire a viewer-stamped connection", &e))?;
    // One row past the page: whether it comes back says whether a next page
    // exists.
    let page = match AgentIdentityRepository::prompt_history_page(
        &mut read,
        id,
        after.as_ref(),
        limit + 1,
    )
    .await
    {
        Ok(page) => page,
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
    let extent = (page.lineage_min_depth, page.lineage_max_depth);
    let (rows, truncated) = cut_page(page.rows, limit as usize, PAGE_BYTE_BUDGET, row_bytes);
    let next_cursor = if truncated {
        rows.last().map(|r| r.cursor().encode())
    } else {
        None
    };
    Ok(Json(group_history(id, rows, extent, next_cursor)))
}

/// `GET /api/v1/agents/:id/prompt-history/blobs/:hash`: one file named by a
/// snapshot the caller may read in `:id`'s history (`claims:read`).
///
/// # Errors
/// 401 without a principal; 403 without `claims:read`; 400 for a `:hash` that
/// is not 64 hex digits; 404 for a caller who is neither the operator nor an
/// admin (the history route's body), and for a hash no readable snapshot in
/// that history names; 500 for a stored blob that failed verification, which
/// is withheld.
pub async fn get_prompt_history_blob(
    State(state): State<AppState>,
    auth_ctx: Option<Extension<AuthContext>>,
    ViewerExtractor(viewer): ViewerExtractor,
    Path((id, hash)): Path<(Uuid, String)>,
) -> Result<Json<BlobView>, ApiError> {
    let Some(Extension(auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "prompt history requires authentication".into(),
        });
    };
    crate::middleware::scopes::check_scopes(&auth, &[REQUIRED_SCOPE])?;
    let key: [u8; 32] = hex::decode(&hash)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| ApiError::BadRequest {
            message: "a prompt file is named by the 64-hex-digit BLAKE3 of its bytes".into(),
        })?;

    let mut read = state
        .read_as(&viewer)
        .await
        .map_err(|e| internal("acquire a viewer-stamped connection", &e))?;
    let found = match AgentIdentityRepository::prompt_history_blob(&mut read, id, &key).await {
        Ok(found) => found,
        Err(e) if is_refused(&e) => {
            tracing::info!(
                target: "agent.prompt_history",
                principal = ?auth.agent_id,
                agent = %id,
                "prompt history blob refused: the caller is neither the operator nor an admin"
            );
            return Err(not_found(id));
        }
        Err(e) => return Err(internal("read the file", &e)),
    };
    read.commit()
        .await
        .map_err(|e| internal("finish the read", &e))?;
    match found {
        PromptBlobRead::Verified(blob) => Ok(Json(blob.into())),
        PromptBlobRead::NotNamed => Err(ApiError::NotFound {
            entity: "PromptBlob".to_string(),
            id: hex::encode(key),
        }),
        PromptBlobRead::Withheld(reason) => {
            tracing::error!(
                target: "agent.prompt_history",
                agent = %id,
                blob = %hex::encode(key),
                %reason,
                "a stored prompt file failed verification; withheld"
            );
            // Caller-facing by design, so `InternalErrorStatic`: an
            // `InternalError` body is redacted. The hash is the caller's own
            // `:hash` and is logged above.
            Err(ApiError::InternalErrorStatic {
                message: "prompt history: the stored file failed verification and is withheld",
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(agent_id: Uuid, depth: i32) -> PromptHistoryIndexEntry {
        PromptHistoryIndexEntry {
            agent_id,
            relation: if depth < 0 { "ancestor" } else { "descendant" }.to_string(),
            depth,
            readable: false,
            snapshot: None,
        }
    }

    fn ids_and_distances(members: &[LineageMember]) -> Vec<(Uuid, u32)> {
        members.iter().map(|m| (m.agent_id, m.distance)).collect()
    }

    /// Whatever order the rows arrive in, each direction comes out nearest
    /// first with its unsigned distance.
    #[test]
    fn grouping_orders_each_direction_nearest_first_whatever_the_row_order() {
        let ids: Vec<Uuid> = (0..6).map(|_| Uuid::new_v4()).collect();
        let rows = vec![
            member(ids[0], -3),
            member(ids[1], -1),
            member(ids[2], -2),
            member(ids[3], 3),
            member(ids[4], 1),
            member(ids[5], 2),
        ];
        let out = group_history(Uuid::new_v4(), rows, (Some(-3), Some(3)), None);
        assert_eq!(
            ids_and_distances(&out.lineage.ancestors),
            [(ids[1], 1), (ids[2], 2), (ids[0], 3)]
        );
        assert_eq!(
            ids_and_distances(&out.lineage.descendants),
            [(ids[4], 1), (ids[5], 2), (ids[3], 3)]
        );
        assert!(!out.lineage.ancestors_at_limit && !out.lineage.descendants_at_limit);
        assert!(!out.truncated && out.next_cursor.is_none());
    }

    /// The depth-limit flags are the WHOLE walk's, not the page's: a page that
    /// lists only the nearest generation still says the walk reached the
    /// limit when the extent does, and one short of the limit is not it.
    #[test]
    fn the_depth_limit_flags_come_from_the_walks_extent_not_the_page() {
        let limit = i32::try_from(LINEAGE_DEPTH_LIMIT).expect("small");
        let near = vec![member(Uuid::new_v4(), -1), member(Uuid::new_v4(), 1)];
        let out = group_history(
            Uuid::new_v4(),
            near.clone(),
            (Some(-limit), Some(limit - 1)),
            Some("c".into()),
        );
        assert!(out.lineage.ancestors_at_limit, "an ancestor at the limit");
        assert!(
            !out.lineage.descendants_at_limit,
            "a descendant one short of it"
        );
        assert!(out.truncated, "a cursor means more rows follow");
        let out = group_history(Uuid::new_v4(), near, (None, None), None);
        assert!(!out.lineage.ancestors_at_limit && !out.lineage.descendants_at_limit);
    }

    /// The cut keeps at most `limit` rows and stops before the row that would
    /// pass the byte budget, says when it left rows out, and always keeps the
    /// first row, even one larger than the whole budget, so a page advances.
    #[test]
    fn a_page_is_cut_by_rows_and_by_bytes_and_always_advances() {
        let sizes = |v: &[usize]| v.to_vec();
        let id = |n: &usize| *n;
        assert_eq!(
            cut_page(sizes(&[10, 10, 10]), 3, 1000, id),
            (vec![10, 10, 10], false),
            "everything fits"
        );
        assert_eq!(
            cut_page(sizes(&[10, 10, 10, 10]), 3, 1000, id),
            (vec![10, 10, 10], true),
            "the row cap"
        );
        assert_eq!(
            cut_page(sizes(&[40, 40, 30, 5]), 10, 100, id),
            (vec![40, 40], true),
            "the byte cap stops before the row that passes it, even if a later one fits"
        );
        assert_eq!(
            cut_page(sizes(&[50, 50]), 10, 100, id),
            (vec![50, 50], false),
            "exactly the budget fits"
        );
        assert_eq!(
            cut_page(sizes(&[5000, 1]), 10, 100, id),
            (vec![5000], true),
            "an oversized first row is served alone"
        );
        assert_eq!(cut_page(Vec::<usize>::new(), 10, 100, id), (vec![], false));
    }

    /// A snapshot's metadata is what a row costs: a row with a large
    /// `in_prompt` costs more than an empty member row by at least its size.
    #[test]
    fn a_rows_cost_grows_with_its_snapshot_metadata() {
        let bare = member(Uuid::new_v4(), 1);
        let mut big = member(Uuid::new_v4(), 1);
        big.snapshot = Some(PromptSnapshotIndex {
            id: Uuid::new_v4(),
            group_folder: "g".into(),
            model: "m".into(),
            prompt_hash: "0".repeat(64),
            identity_md: None,
            global_claude_md: None,
            group_claude_md: None,
            learned_md: Some([7; 32]),
            in_prompt: serde_json::json!({"note": "x".repeat(10_000)}),
            blob_refused: Vec::new(),
            runner_version: None,
            host_sha: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        });
        assert!(row_bytes(&big) >= row_bytes(&bare) + 10_000);
    }
}
