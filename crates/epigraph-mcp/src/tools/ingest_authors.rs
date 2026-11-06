//! Deterministic document-ingest authors (backlog 94cc12db).
//!
//! Shared by the two document walks (`do_ingest_document`, behind
//! `ingest_document` / `ingest_document_inline` and the CLI bin, and
//! `do_ingest_document_spine`), which used to carry two copies of the same
//! name-derived loop.
//!
//! # Resolution, per real (non-placeholder) author
//!
//! * `agent_id` given: the author IS that agent. It must exist and must not be
//!   a registered system identity, a role node, or hold a system role's
//!   legacy key (migration 148: a document never names a system identity as
//!   its author). Anything else refuses the whole ingest, naming
//!   `source.authors[i].agent_id`. `agents` rows are readable by every session
//!   (`agents_identity ... USING (true)`, as `GET /api/v1/agents/:id` answers
//!   for any id), so "exists" is "visible to the caller".
//! * `agent_id` absent: UNCHANGED. The author is the node
//!   `did_key_for_author(None, name)` derives (reused, or created). The walk
//!   never attaches the author to another agent that merely shares the name:
//!   a name collision would otherwise put every `asserts` edge of a stranger's
//!   paper on a real person's node. Those agents are reported as `candidates`
//!   (`status: "ambiguous"`) so the caller can re-ingest with an explicit
//!   `agent_id`.
//!
//! The report carries public fields only (id, `display_name`, match tier,
//! `created_at`), never a card's viewer-computed facts.

use std::collections::HashMap;

use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::types::{AuthorCandidate, IngestAuthorReport};
use epigraph_db::{AgentLookupRepository, AgentRepository, AuthorNode};
use epigraph_ingest::common::schema::AuthorEntry;

/// Most candidates listed per author.
pub const AUTHOR_CANDIDATE_LIMIT: usize = 10;

/// One author the walk will attach: its original index, the agent, and the
/// report entry.
pub(crate) struct ResolvedAuthor {
    pub idx: usize,
    pub agent_id: Uuid,
    pub report: IngestAuthorReport,
}

/// The caller-payload half of the check, before any database access: each
/// `agent_id` parses, is not on a placeholder name, and is not repeated.
pub(crate) fn parse_explicit_author_ids(
    authors: &[AuthorEntry],
) -> Result<Vec<Option<Uuid>>, McpError> {
    epigraph_ingest::common::schema::parse_author_agent_ids(authors).map_err(invalid_params)
}

/// The database half: every explicit `agent_id` names an agent that may be
/// attached as an author. Returns that agent's row by author index.
///
/// Runs on the connection the caller holds: the handlers' synchronous
/// preflight (so the queued path refuses before its eager `papers` row) and
/// the walk's own transaction.
pub(crate) async fn check_explicit_author_ids(
    conn: &mut sqlx::PgConnection,
    authors: &[AuthorEntry],
) -> Result<HashMap<usize, AuthorNode>, McpError> {
    let ids = parse_explicit_author_ids(authors)?;
    let given: Vec<(usize, Uuid)> = ids
        .iter()
        .enumerate()
        .filter_map(|(i, id)| id.map(|id| (i, id)))
        .collect();
    if given.is_empty() {
        return Ok(HashMap::new());
    }
    let wanted: Vec<Uuid> = given.iter().map(|(_, id)| *id).collect();
    let mut nodes: HashMap<Uuid, AuthorNode> = HashMap::new();
    for chunk in
        wanted.chunks(usize::try_from(epigraph_db::agent_lookup::CANDIDATE_POOL).unwrap_or(200))
    {
        for node in AgentLookupRepository::author_nodes(conn, chunk)
            .await
            .map_err(internal_error)?
        {
            nodes.insert(node.id, node);
        }
    }
    let mut out = HashMap::with_capacity(given.len());
    for (i, id) in given {
        let Some(node) = nodes.remove(&id) else {
            return Err(invalid_params(format!(
                "source.authors[{i}].agent_id {id}: no agent has this id (find one with \
                 find_agent, or omit agent_id to use the name)"
            )));
        };
        if node.is_registered_system || node.has_reserved_key {
            return Err(invalid_params(format!(
                "source.authors[{i}].agent_id {id}: a registered system identity cannot be a \
                 document's author"
            )));
        }
        if node.is_role_node {
            return Err(invalid_params(format!(
                "source.authors[{i}].agent_id {id}: a role node cannot be a document's author; \
                 name the person who holds the role"
            )));
        }
        out.insert(i, node);
    }
    Ok(out)
}

/// Resolve every author of a document to the agent its edges come from, on
/// the walk's transaction. Placeholder names and authors that resolve to a
/// system identity are skipped, as before (and logged); every other author
/// gets one [`ResolvedAuthor`].
pub(crate) async fn resolve_document_authors(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    authors: &[AuthorEntry],
    tool_name: &'static str,
    paper_title: &str,
) -> Result<Vec<ResolvedAuthor>, McpError> {
    let explicit = check_explicit_author_ids(conn, authors).await?;
    // Migration 148: a document never names a system identity as its author.
    // The legacy public-constant key is refused before the lookup (so it is
    // never adopted, and never re-minted after a rotation), and an author that
    // resolves to a REGISTERED system agent under any other key is skipped
    // after it. One registry read per document, and none without authors.
    let registered_system_agents = if authors.is_empty() {
        Vec::new()
    } else {
        epigraph_db::SystemAgentRepository::registered_agent_ids(conn)
            .await
            .map_err(internal_error)?
    };
    let mut out = Vec::new();
    for (idx, author) in authors.iter().enumerate() {
        // Empty or placeholder name: no agent, no `authored` edge. Same original
        // `idx` the planner skipped, so the walk's author map stays aligned.
        // (An `agent_id` on a placeholder was refused above.)
        if author.is_placeholder() {
            if !author.name.trim().is_empty() {
                tracing::warn!(
                    paper = %paper_title,
                    name = %author.name,
                    author_index = idx,
                    "{tool_name}: dropping placeholder author name"
                );
            }
            continue;
        }
        if let Some(node) = explicit.get(&idx) {
            out.push(ResolvedAuthor {
                idx,
                agent_id: node.id,
                report: IngestAuthorReport {
                    agent_id: node.id.to_string(),
                    name: author.name.clone(),
                    position: idx,
                    status: "explicit",
                    action: "attached_given",
                    display_name: node.display_name.clone(),
                    candidates: Vec::new(),
                    candidates_truncated: false,
                },
            });
            continue;
        }
        let (_did, pub_key_bytes) =
            epigraph_crypto::did_key::did_key_for_author(None, &author.name);
        if epigraph_db::is_reserved_author_key(&pub_key_bytes) {
            tracing::warn!(
                target: "ingest.authors",
                author_index = idx,
                "skipping an author whose name derives a system agent's legacy key: a document \
                 cannot name a system identity as its author (migration 148)"
            );
            continue;
        }
        let (agent_uuid, existed): (Uuid, bool) = if let Some(existing) =
            AgentRepository::get_by_public_key(&mut *conn, &pub_key_bytes)
                .await
                .map_err(internal_error)?
        {
            let id: Uuid = existing.id.into();
            if registered_system_agents.contains(&id) {
                tracing::warn!(
                    target: "ingest.authors",
                    author_index = idx,
                    "skipping an author that resolves to a registered system agent: a document \
                     cannot name a system identity as its author (migration 148)"
                );
                continue;
            }
            (id, true)
        } else {
            let author_agent = epigraph_core::Agent::new(pub_key_bytes, Some(author.name.clone()));
            let created = AgentRepository::create_conn(conn, &author_agent)
                .await
                .map_err(internal_error)?;
            (created.id.into(), false)
        };
        let (matches, candidates_truncated) = AgentLookupRepository::exact_name_candidates(
            conn,
            viewer,
            &author.name,
            agent_uuid,
            AUTHOR_CANDIDATE_LIMIT,
        )
        .await
        .map_err(internal_error)?;
        let candidates: Vec<AuthorCandidate> = matches
            .into_iter()
            .map(|m| AuthorCandidate {
                agent_id: m.agent_id.to_string(),
                display_name: m.display_name,
                tier: m.tier,
                created_at: m.created_at,
            })
            .collect();
        let status = match (candidates.is_empty() && !candidates_truncated, existed) {
            (true, true) => "matched",
            (true, false) => "created",
            (false, _) => "ambiguous",
        };
        out.push(ResolvedAuthor {
            idx,
            agent_id: agent_uuid,
            report: IngestAuthorReport {
                agent_id: agent_uuid.to_string(),
                name: author.name.clone(),
                position: idx,
                status,
                action: if existed {
                    "reused_name_key"
                } else {
                    "created_name_key"
                },
                display_name: None,
                candidates,
                candidates_truncated,
            },
        });
    }
    Ok(out)
}
