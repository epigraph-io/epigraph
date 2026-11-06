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
//!   its author), and it must not be another author's name-derived node in
//!   the same document. Anything else refuses the whole ingest, naming
//!   `source.authors[i].agent_id`. `agents` rows are readable by every session
//!   (`agents_identity ... USING (true)`, as `GET /api/v1/agents/:id` answers
//!   for any id), so "exists" is "visible to the caller".
//! * `agent_id` absent: the author is the node `did_key_for_author(None,
//!   name)` derives (reused, or created), as before. The walk never attaches
//!   the author to another agent that merely shares the name: a name
//!   collision would otherwise put every `asserts` edge of a stranger's paper
//!   on a real person's node. Those agents are reported as `candidates`
//!   (`status: "ambiguous"`). The one exception is a re-ingest of a document
//!   whose author an earlier ingest attached by `agent_id`: the name-only
//!   entry with that same spelling keeps the explicit author
//!   (`action: "kept_attached"`) instead of adding the name-derived node
//!   beside it.
//!
//! # Who asserts the claims (the explicit-author rule)
//!
//! Naming an agent as an author is the INGESTER's statement. It becomes that
//! agent's own `asserts` edges only when the ingester speaks for it: the
//! agent is the ingester's write identity (`attribution: "caller"`), or the
//! ingester is the human that agent acts for (`epigraph_human_of(agent,
//! true)`, `attribution: "operated_by_caller"`). For any other agent
//! (`attribution: "pending_countersign"`) the walk writes ONLY
//! `agent --authored--> paper`, marked with `pending_countersign: true` and
//! `ingested_by: <the ingester>`, and no `asserts` edge from that agent onto
//! any claim; the agent card does not count that paper until the person
//! countersigns. [`check_explicit_author_ids`] decides it, so the handlers'
//! preflight and the walk's transaction decide it the same way.
//!
//! # Replacing the name-derived author on a re-ingest
//!
//! An `ambiguous` result is fixed by re-ingesting with `agent_id`, which
//! REPLACES the name-derived author; it never adds the chosen agent beside
//! it. When the document already lists THIS entry's own name-derived node
//! (the node its spelling derives, attached by the name path), the walk
//! retracts that node's `authored` edge on this paper and its `asserts` edges
//! onto this paper's claims (never a claim another paper it authors also
//! asserts), and reports it in `replaced`.
//!
//! Those edges have an agent endpoint, so migration 120 leaves them
//! `('public', world)`: administrative, owned by no writer, and no
//! application session may retract them (117's owner-scoped UPDATE matches no
//! row). On an MCP server the replacement is therefore REFUSED, before
//! anything is written, with the remedy: re-run that ingest through the
//! operator `ingest-document` CLI, whose ingest runs on the maintenance
//! connection and performs it, or omit `agent_id`. Any other author already
//! at the same position is left alone and reported in `also_at_position`.
//!
//! The report carries public fields only (id, `display_name`, match tier,
//! `created_at`), never a card's viewer-computed facts.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::types::{AuthorCandidate, IngestAuthorReport, ReplacedAuthor};
use epigraph_db::visibility::Viewer;
use epigraph_db::{
    AgentLookupRepository, AgentRepository, AuthorNode, DbError, PaperAuthorEdge, PaperRepository,
    SpeaksFor,
};
use epigraph_ingest::common::schema::AuthorEntry;

/// Most candidates listed per author.
pub const AUTHOR_CANDIDATE_LIMIT: usize = 10;

/// The ingester's write identity is the named agent.
pub const ATTRIBUTION_CALLER: &str = "caller";
/// The ingester is the human the named agent acts for.
pub const ATTRIBUTION_OPERATED: &str = "operated_by_caller";
/// Anyone else: `authored` only, awaiting the person's countersignature.
pub const ATTRIBUTION_PENDING: &str = "pending_countersign";
/// The name path (no `agent_id`): the name-derived node, as always.
pub const ATTRIBUTION_NAME_DERIVED: &str = "name_derived";

/// An explicit `agent_id` that passed every check, and whether the ingester
/// speaks for it.
pub(crate) struct ExplicitAuthor {
    pub node: AuthorNode,
    /// [`ATTRIBUTION_CALLER`], [`ATTRIBUTION_OPERATED`] or
    /// [`ATTRIBUTION_PENDING`].
    pub attribution: &'static str,
}

/// One author the walk will attach: its original index, the agent, what to
/// write, and the report entry.
pub(crate) struct ResolvedAuthor {
    pub idx: usize,
    pub agent_id: Uuid,
    /// Write this agent's `asserts` edges onto the document's claims.
    pub asserts: bool,
    /// Mark the `authored` edge as an explicit attachment.
    pub explicit: bool,
    /// Mark the `authored` edge as awaiting the person's countersignature.
    pub pending: bool,
    pub report: IngestAuthorReport,
}

/// The `authored` edge properties for one resolved author.
pub(crate) fn authored_edge_properties(
    resolved: &ResolvedAuthor,
    author: &AuthorEntry,
    ingester: Uuid,
) -> serde_json::Value {
    let mut props = serde_json::json!({
        // The ORIGINAL extraction index: it can have gaps where a placeholder
        // author was dropped ([Unknown, Alice] gives Alice position 1 and no
        // edge position 0).
        "position": resolved.idx,
        "role": author.roles.first().map_or("author", String::as_str),
        "affiliations": author.affiliations,
    });
    // Name-derived edges keep the exact shape they always had.
    if resolved.explicit {
        props[epigraph_db::AUTHORED_EXPLICIT_KEY] = serde_json::Value::Bool(true);
        props[epigraph_db::AUTHORED_NAME_KEY] = serde_json::Value::String(author.name.clone());
    }
    if resolved.pending {
        props[epigraph_db::AUTHORED_PENDING_KEY] = serde_json::Value::Bool(true);
        props[epigraph_db::AUTHORED_INGESTED_BY_KEY] =
            serde_json::Value::String(ingester.to_string());
    }
    props
}

/// The caller-payload half of the check, before any database access: each
/// `agent_id` parses, is not on a placeholder name, and is not repeated.
pub(crate) fn parse_explicit_author_ids(
    authors: &[AuthorEntry],
) -> Result<Vec<Option<Uuid>>, McpError> {
    epigraph_ingest::common::schema::parse_author_agent_ids(authors).map_err(invalid_params)
}

/// The key the name path derives for `name`.
fn name_key(name: &str) -> [u8; 32] {
    epigraph_crypto::did_key::did_key_for_author(None, name).1
}

/// Which of `agents` the ingester `writer` speaks for, and how: the agent is
/// `writer` itself, or `writer` is the human it acts for through a binding in
/// force ([`AgentRepository::speaks_for`], the rule `POST /api/v1/edges`
/// applies to an agent-sourced `asserts` too).
async fn attributions(
    conn: &mut sqlx::PgConnection,
    writer: Uuid,
    agents: &[Uuid],
) -> Result<HashMap<Uuid, &'static str>, McpError> {
    let how = AgentRepository::speaks_for(&mut *conn, writer, agents)
        .await
        .map_err(internal_error)?;
    Ok(agents
        .iter()
        .map(|a| {
            let how = match how.get(a) {
                Some(SpeaksFor::Itself) => ATTRIBUTION_CALLER,
                Some(SpeaksFor::Operator) => ATTRIBUTION_OPERATED,
                None => ATTRIBUTION_PENDING,
            };
            (*a, how)
        })
        .collect())
}

/// The database half: every explicit `agent_id` names an agent that may be
/// attached as an author, and whether the ingester `writer` speaks for it
/// (the explicit-author rule, module doc). Returns it by author index.
///
/// Runs on the connection the caller holds: the handlers' synchronous
/// preflight (so the queued path refuses before its eager `papers` row) and
/// the walk's own transaction, so both decide the same way.
pub(crate) async fn check_explicit_author_ids(
    conn: &mut sqlx::PgConnection,
    authors: &[AuthorEntry],
    writer: Uuid,
) -> Result<HashMap<usize, ExplicitAuthor>, McpError> {
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
    // The name-derived key of every name-path entry: an explicit id equal to
    // one of them would make two entries one agent, and the walk would write
    // one `authored` edge for two positions.
    let name_path_keys: Vec<(usize, [u8; 32])> = authors
        .iter()
        .enumerate()
        .filter(|(i, a)| ids[*i].is_none() && !a.is_placeholder())
        .map(|(i, a)| (i, name_key(&a.name)))
        .collect();
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
        if let Some((j, _)) = name_path_keys
            .iter()
            .find(|(_, k)| k.as_slice() == node.public_key.as_slice())
        {
            return Err(invalid_params(format!(
                "source.authors[{i}].agent_id {id} is the name-derived author of \
                 source.authors[{j}] ({:?}): two authors cannot be one agent. Give \
                 source.authors[{j}] its own agent_id, or drop one of the two entries",
                authors[*j].name
            )));
        }
        out.insert(i, (node, ATTRIBUTION_PENDING));
    }
    let explicit_ids: Vec<Uuid> = out.values().map(|(n, _)| n.id).collect();
    let how = attributions(conn, writer, &explicit_ids).await?;
    Ok(out
        .into_iter()
        .map(|(i, (node, _))| {
            let attribution = how.get(&node.id).copied().unwrap_or(ATTRIBUTION_PENDING);
            (i, ExplicitAuthor { node, attribution })
        })
        .collect())
}

/// For each explicit author, retract THIS entry's own name-derived node from
/// `paper_id` when an earlier name-path ingest attached it (module doc), and
/// return what was retracted by author index. Run on the walk's transaction,
/// and on the preflight's (rolled back) so a refusal reaches the queued
/// caller. `edges` is [`PaperRepository::author_edges_conn`] of the paper.
async fn retract_replaced_name_nodes(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    paper_id: Uuid,
    authors: &[AuthorEntry],
    explicit: &HashMap<usize, ExplicitAuthor>,
    edges: &[PaperAuthorEdge],
) -> Result<HashMap<usize, ReplacedAuthor>, McpError> {
    let mut out = HashMap::new();
    if explicit.is_empty() || edges.is_empty() {
        return Ok(out);
    }
    // A node another name-path entry of THIS document resolves to stays.
    let name_path_keys: HashSet<[u8; 32]> = authors
        .iter()
        .enumerate()
        .filter(|(i, a)| !explicit.contains_key(i) && !a.is_placeholder())
        .map(|(_, a)| name_key(&a.name))
        .collect();
    let mut order: Vec<&usize> = explicit.keys().collect();
    order.sort_unstable();
    for &i in order {
        let chosen = explicit[&i].node.id;
        let key = name_key(&authors[i].name);
        if name_path_keys.contains(&key) {
            continue;
        }
        let Some(node) = AgentRepository::get_by_public_key(&mut *conn, &key)
            .await
            .map_err(internal_error)?
        else {
            continue;
        };
        let node_id: Uuid = node.id.into();
        // Only a node the NAME path attached: an explicit attachment of the
        // same agent is someone's deliberate choice and is never undone here.
        let attached_by_name = edges.iter().any(|e| e.agent_id == node_id && !e.explicit);
        if node_id == chosen || !attached_by_name {
            continue;
        }
        let (authored, asserts) =
            match PaperRepository::retract_author_conn(&mut *conn, viewer, paper_id, node_id).await
            {
                Ok(n) => n,
                Err(DbError::WriteRefused { .. }) => {
                    return Err(invalid_params(format!(
                        "source.authors[{i}].agent_id {chosen}: this document already lists \
                         {node_id}, the name-derived author for {:?}, and the agent_id would \
                         REPLACE it (retract its authored edge and its asserts edges on this \
                         document), not add a second author beside it. Those edges are \
                         administrative (an agent's edges belong to no writer), so this \
                         session cannot retract them, and nothing was written. To replace \
                         it, run this ingest through the operator ingest-document CLI (it \
                         runs on the maintenance connection); or omit agent_id to keep the \
                         name-derived author",
                        authors[i].name
                    )));
                }
                Err(e) => return Err(internal_error(e)),
            };
        out.insert(
            i,
            ReplacedAuthor {
                agent_id: node_id.to_string(),
                authored_edges_retracted: authored,
                asserts_edges_retracted: asserts,
            },
        );
    }
    Ok(out)
}

/// The handlers' synchronous preflight of the document's authors, on the
/// transaction it opens and rolls back: [`check_explicit_author_ids`], and,
/// when the document's `papers` row already exists, the replacement
/// [`resolve_document_authors`] will make, so an author whose name-derived
/// node this caller cannot retract is refused before anything is queued.
pub(crate) async fn preflight_document_authors(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    authors: &[AuthorEntry],
    writer: Uuid,
    paper_id: Option<Uuid>,
) -> Result<(), McpError> {
    let explicit = check_explicit_author_ids(conn, authors, writer).await?;
    if let (Some(paper_id), false) = (paper_id, explicit.is_empty()) {
        let edges = PaperRepository::author_edges_conn(conn, viewer, paper_id)
            .await
            .map_err(internal_error)?;
        retract_replaced_name_nodes(conn, viewer, paper_id, authors, &explicit, &edges).await?;
    }
    Ok(())
}

/// Resolve every author of a document to the agent its edges come from, on
/// the walk's transaction (module doc). Placeholder names and authors that
/// resolve to a system identity are skipped, as before (and logged); every
/// other author gets one [`ResolvedAuthor`]. `writer` is the ingester's write
/// identity; `paper_id` the document's `papers` row.
pub(crate) async fn resolve_document_authors(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    authors: &[AuthorEntry],
    writer: Uuid,
    paper_id: Uuid,
    tool_name: &'static str,
    paper_title: &str,
) -> Result<Vec<ResolvedAuthor>, McpError> {
    let explicit = check_explicit_author_ids(conn, authors, writer).await?;
    // The document's authors as earlier ingests left them.
    let edges = if authors.is_empty() {
        Vec::new()
    } else {
        PaperRepository::author_edges_conn(conn, viewer, paper_id)
            .await
            .map_err(internal_error)?
    };
    let mut replaced =
        retract_replaced_name_nodes(conn, viewer, paper_id, authors, &explicit, &edges).await?;
    let retracted: HashSet<Uuid> = replaced
        .values()
        .filter_map(|r| r.agent_id.parse().ok())
        .collect();
    let edges: Vec<PaperAuthorEdge> = edges
        .into_iter()
        .filter(|e| !retracted.contains(&e.agent_id))
        .collect();
    // An explicit attachment an earlier ingest made, by the spelling it was
    // made for: a name-only entry with that spelling keeps it. Each earlier
    // edge is kept by at most one entry (the one at its position first), and
    // never when this call names that agent explicitly itself: a re-run of the
    // same extraction must resolve exactly as the first run did.
    let this_call: HashSet<Uuid> = explicit.values().map(|e| e.node.id).collect();
    let mut taken: HashSet<Uuid> = HashSet::new();
    let mut kept: HashMap<usize, Uuid> = HashMap::new();
    for (i, a) in authors.iter().enumerate() {
        if explicit.contains_key(&i) || a.is_placeholder() {
            continue;
        }
        let mut found: Vec<&PaperAuthorEdge> = edges
            .iter()
            .filter(|e| {
                e.explicit
                    && e.author_name.as_deref() == Some(a.name.as_str())
                    && !this_call.contains(&e.agent_id)
                    && !taken.contains(&e.agent_id)
            })
            .collect();
        found.sort_by_key(|e| e.position != i64::try_from(i).ok());
        if let Some(e) = found.first() {
            taken.insert(e.agent_id);
            kept.insert(i, e.agent_id);
        }
    }
    let kept_ids: Vec<Uuid> = kept.values().copied().collect();
    let kept_how = attributions(conn, writer, &kept_ids).await?;
    let kept_nodes: HashMap<Uuid, AuthorNode> = AgentLookupRepository::author_nodes(
        conn,
        &kept_ids[..kept_ids
            .len()
            .min(usize::try_from(epigraph_db::agent_lookup::CANDIDATE_POOL).unwrap_or(200))],
    )
    .await
    .map_err(internal_error)?
    .into_iter()
    .map(|n| (n.id, n))
    .collect();

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
        let given = explicit
            .get(&idx)
            .map(|e| {
                (
                    e.node.id,
                    e.node.display_name.clone(),
                    e.attribution,
                    "attached_given",
                )
            })
            .or_else(|| {
                let id = *kept.get(&idx)?;
                let how = kept_how.get(&id).copied().unwrap_or(ATTRIBUTION_PENDING);
                let name = kept_nodes.get(&id).and_then(|n| n.display_name.clone());
                Some((id, name, how, "kept_attached"))
            });
        if let Some((id, display_name, attribution, action)) = given {
            let asserts = attribution != ATTRIBUTION_PENDING;
            out.push(ResolvedAuthor {
                idx,
                agent_id: id,
                asserts,
                explicit: true,
                pending: !asserts,
                report: IngestAuthorReport {
                    agent_id: id.to_string(),
                    name: author.name.clone(),
                    position: idx,
                    status: "explicit",
                    action,
                    attribution,
                    asserts_claims: asserts,
                    display_name,
                    replaced: replaced.remove(&idx),
                    also_at_position: Vec::new(),
                    candidates: Vec::new(),
                    candidates_truncated: false,
                },
            });
            continue;
        }
        let pub_key_bytes = name_key(&author.name);
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
        // The report is filled in below, once the whole list is resolved:
        // one candidates statement per document, not one per author.
        out.push(ResolvedAuthor {
            idx,
            agent_id: agent_uuid,
            asserts: true,
            explicit: false,
            pending: false,
            report: IngestAuthorReport {
                agent_id: agent_uuid.to_string(),
                name: author.name.clone(),
                position: idx,
                status: if existed { "matched" } else { "created" },
                action: if existed {
                    "reused_name_key"
                } else {
                    "created_name_key"
                },
                attribution: ATTRIBUTION_NAME_DERIVED,
                asserts_claims: true,
                display_name: None,
                replaced: None,
                also_at_position: Vec::new(),
                candidates: Vec::new(),
                candidates_truncated: false,
            },
        });
    }
    // An explicit author that another entry also resolves to would share one
    // `authored` edge with it: refuse. Two NAME-path entries with one name
    // (one node) are not refused: they always ingested, one edge, as before.
    let mut any_entry: HashMap<Uuid, usize> = HashMap::new();
    let mut explicit_entry: HashMap<Uuid, usize> = HashMap::new();
    for r in &out {
        let clash = if r.explicit {
            any_entry.get(&r.agent_id)
        } else {
            explicit_entry.get(&r.agent_id)
        };
        if let Some(&first) = clash {
            return Err(invalid_params(format!(
                "source.authors[{first}] and source.authors[{}] both resolve to agent {}: two \
                 authors cannot be one agent. Give one of them its own agent_id, or drop one",
                r.idx, r.agent_id
            )));
        }
        any_entry.entry(r.agent_id).or_insert(r.idx);
        if r.explicit {
            explicit_entry.entry(r.agent_id).or_insert(r.idx);
        }
    }
    // Whoever else the document already lists at an author's position.
    for r in &mut out {
        let pos = i64::try_from(r.idx).ok();
        r.report.also_at_position = edges
            .iter()
            .filter(|e| e.position == pos && e.agent_id != r.agent_id)
            .map(|e| e.agent_id.to_string())
            .collect();
        r.report.also_at_position.dedup();
    }
    // Other agents with each name-derived author's (folded) name: listed,
    // never chosen. An explicit author has no candidates.
    let pending: Vec<usize> = out
        .iter()
        .enumerate()
        .filter(|(_, r)| r.report.status != "explicit")
        .map(|(i, _)| i)
        .collect();
    if !pending.is_empty() {
        let names: Vec<String> = pending
            .iter()
            .map(|&i| out[i].report.name.clone())
            .collect();
        let attached: Vec<Uuid> = pending.iter().map(|&i| out[i].agent_id).collect();
        let found = AgentLookupRepository::exact_name_candidates(
            conn,
            &names,
            &attached,
            i64::try_from(AUTHOR_CANDIDATE_LIMIT).unwrap_or(10),
        )
        .await
        .map_err(internal_error)?;
        for (&i, (matches, total)) in pending.iter().zip(found) {
            if matches.is_empty() {
                continue;
            }
            let report = &mut out[i].report;
            report.status = "ambiguous";
            report.candidates_truncated =
                usize::try_from(total).map_or(true, |t| t > matches.len());
            report.candidates = matches
                .into_iter()
                .map(|m| AuthorCandidate {
                    agent_id: m.agent_id.to_string(),
                    display_name: m.display_name,
                    tier: m.tier,
                    created_at: m.created_at,
                })
                .collect();
        }
    }
    Ok(out)
}
