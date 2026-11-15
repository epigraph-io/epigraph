//! `GET /api/v1/claims/:id/context` — the document context of one claim:
//! the paper that asserts it, its section, its structural parents and parts,
//! its sibling claims, and its epistemic edges in both directions, each node
//! carrying `theme_id` so a client can label a neighbour from another theme.
//!
//! It is the HTTP twin of the structural block MCP `recall_with_context`
//! adds per hit. All SQL lives in `epigraph_db::ClaimContextRepository`.
//!
//! # What a viewer cannot see is absent
//!
//! A root claim the viewer may not read is a 404, byte-identical to the 404
//! for a uuid that names nothing. A hidden node or edge is never in any list,
//! never in any total or tally, never the primary parent, never the section,
//! and never the position a `next_cursor` names: every cursor is built from
//! the last row this response EMITTED, which the viewer could read by
//! construction. A caller-forged cursor is a position only; the read it
//! starts stays viewer-filtered.
//!
//! # Counts are visible counts
//!
//! Every `total` and every `by_relationship` count is computed in SQL inside
//! the same predicates that produce the rows, so it is never a true degree
//! minus whatever was dropped. A true degree beside a filtered list would
//! state how many rows the viewer may not see.
//!
//! # The primary chain is per viewer
//!
//! An atom's id is a content hash shared across documents, so it can have
//! several paragraph parents. `siblings.parent_id`, `section` and `paper` come
//! from the first VISIBLE parent at the expected level, so two viewers can be
//! shown different chains for the same shared atom. Each answer is a function
//! of rows that viewer may read; `parents` lists them all.
//!
//! # A claim node carries no cached BetP
//!
//! Nodes carry `truth_value` and no `belief`, `plausibility` or
//! `pignistic_prob`: a compound claim's cached belief columns are a fold of
//! its own BBAs, and a flat list has no role to dispatch on (the reason
//! `routes/ego.rs` gives). The panel's belief figure for the root comes from
//! `GET /api/v1/claims/:id/belief`, which is role-aware.
//!
//! # The 2 MB body bound
//!
//! Every unbounded text field is clipped in SQL and again here on a char
//! boundary (content 1500 characters, paper title 300, DOI 256), and every
//! page is capped (200 items in page mode; 5 + 10 + 50 + 50 + 80 in full
//! mode). The worst serialised character is a control character, which
//! `serde_json` writes as six bytes, so the largest body is under 2 MB by
//! construction. The unit test `worst_case_bodies_fit_the_2mb_cap` serialises
//! both maximal bodies and fails if a clip limit or a page size is raised
//! past the bound. Full text stays on `GET /api/v1/claims/:id`.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use epigraph_db::repos::claim::LabelCursor;
use epigraph_db::{
    ClaimContextRepository, ContextClaimRow, ContextEdgeRow, ContextEdgeTally, ContextPage,
    ContextPaperRow, Viewer,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::state::AppState;

const DEFAULT_PAPERS: u32 = 5;
const DEFAULT_PARENTS: u32 = 10;
const DEFAULT_PARTS: u32 = 50;
const DEFAULT_SIBLINGS: u32 = 50;
const DEFAULT_EDGES: u32 = 80;
/// Largest page `limit` accepts; larger values are clamped to it.
const MAX_PAGE: u32 = 200;
/// Longest claim `content` this route emits, in characters.
const MAX_CONTENT_CHARS: usize = 1500;
/// Longest paper `title` this route emits, in characters.
const MAX_TITLE_CHARS: usize = 300;
/// Longest paper `doi` this route emits, in characters.
const MAX_DOI_CHARS: usize = 256;
/// Most `decomposes_to` hops the section walk takes above the primary parent.
const MAX_SECTION_HOPS: usize = 3;
/// The body bound the clip limits and page sizes are chosen to meet. Read
/// only by the unit test; the handler needs no runtime check because the
/// bound is static (module docs).
#[cfg_attr(not(test), allow(dead_code))]
const MAX_BODY_BYTES: usize = 2_000_000;

const BAD_CURSOR: &str =
    "malformed `after` cursor; pass back the `next_cursor` of the previous page unchanged";

#[derive(Debug, Deserialize)]
pub struct ContextQuery {
    /// Page mode: return the root plus only this list.
    #[serde(default)]
    pub list: Option<String>,
    /// The `next_cursor` of that list's previous page. Requires `list`.
    #[serde(default)]
    pub after: Option<String>,
    /// Page size for `list`, clamped to `[1, 200]`. Requires `list`. `u32`
    /// as on `/ego`: a value in range is clamped; anything else is axum's
    /// plain-text 400, which runs before the handler body.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// The lists page mode can return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextList {
    Papers,
    Parents,
    Parts,
    Siblings,
    Edges,
}

impl ContextList {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "papers" => Some(Self::Papers),
            "parents" => Some(Self::Parents),
            "parts" => Some(Self::Parts),
            "siblings" => Some(Self::Siblings),
            "edges" => Some(Self::Edges),
            _ => None,
        }
    }

    const fn default_limit(self) -> u32 {
        match self {
            Self::Papers => DEFAULT_PAPERS,
            Self::Parents => DEFAULT_PARENTS,
            Self::Parts => DEFAULT_PARTS,
            Self::Siblings => DEFAULT_SIBLINGS,
            Self::Edges => DEFAULT_EDGES,
        }
    }
}

/// One claim node.
#[derive(Debug, Serialize)]
pub struct ContextNode {
    pub id: Uuid,
    pub content: String,
    pub content_truncated: bool,
    pub truth_value: f64,
    pub is_current: bool,
    /// Omitted when `properties.level` is absent or not an integer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<i32>,
    /// Always present; `null` when the claim has no theme.
    pub theme_id: Option<Uuid>,
}

/// One paper.
#[derive(Debug, Serialize)]
pub struct ContextPaper {
    pub id: Uuid,
    pub doi: String,
    pub title: Option<String>,
    /// `true` when `doi` or `title` was clipped.
    pub truncated: bool,
}

/// One epistemic edge, relative to the root.
#[derive(Debug, Serialize)]
pub struct ContextEdge {
    pub edge_id: Uuid,
    /// Lower-cased.
    pub relationship: String,
    /// `outgoing` when the root is the edge's source, `incoming` otherwise.
    pub direction: String,
    /// Omitted when absent or not a finite number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strength: Option<f64>,
    pub neighbor: ContextNode,
}

/// The wire twin of `epigraph_db::ContextEdgeTally`.
#[derive(Debug, Serialize)]
pub struct RelationshipCount {
    pub relationship: String,
    pub direction: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct NodePage {
    pub items: Vec<ContextNode>,
    pub total: i64,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PaperPage {
    pub items: Vec<ContextPaper>,
    pub total: i64,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SiblingPage {
    /// The primary parent the siblings hang off, or `null` when there is no
    /// visible one.
    pub parent_id: Option<Uuid>,
    pub items: Vec<ContextNode>,
    pub total: i64,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EdgePage {
    pub items: Vec<ContextEdge>,
    /// The sum of `by_relationship`.
    pub total: i64,
    pub by_relationship: Vec<RelationshipCount>,
    pub next_cursor: Option<String>,
}

/// Full mode: the first page of every list.
#[derive(Debug, Serialize)]
pub struct ContextResponse {
    pub claim: ContextNode,
    /// The paper of the primary chain's document; `null` when none is visible.
    pub paper: Option<ContextPaper>,
    pub papers: PaperPage,
    /// The level-1 ancestor on the primary chain; `null` when none is visible.
    pub section: Option<ContextNode>,
    pub parents: NodePage,
    pub parts: NodePage,
    pub siblings: SiblingPage,
    pub edges: EdgePage,
}

/// Page mode: the root plus exactly one list.
#[derive(Debug, Serialize)]
pub struct ContextPageResponse {
    pub claim: ContextNode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub papers: Option<PaperPage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parents: Option<NodePage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts: Option<NodePage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub siblings: Option<SiblingPage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges: Option<EdgePage>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ContextBody {
    Full(ContextResponse),
    Page(ContextPageResponse),
}

/// Cut `text` to `max_chars` characters, never mid-character; the flag says
/// whether anything was cut.
fn clip(text: &str, max_chars: usize) -> (String, bool) {
    match text.char_indices().nth(max_chars) {
        Some((byte, _)) => (text[..byte].to_string(), true),
        None => (text.to_string(), false),
    }
}

/// `properties->>'level'` as an integer, or `None` for absent or junk text.
fn parse_level(raw: Option<&str>) -> Option<i32> {
    raw?.trim().parse::<i32>().ok()
}

/// The level a structural parent of a claim at `level` carries, as the text
/// `properties->>'level'` compares against. `None` when the child's level is
/// unknown (the lookup is then unfiltered) and for a level below 1, which
/// has no structural parent (the caller skips the lookup).
fn expected_parent_level(level: Option<i32>) -> Option<String> {
    match level {
        Some(l) if l >= 1 => Some((l - 1).to_string()),
        _ => None,
    }
}

/// `properties->>'strength'` as a finite number, or `None`.
fn parse_strength(raw: Option<&str>) -> Option<f64> {
    raw?.trim().parse::<f64>().ok().filter(|v| v.is_finite())
}

/// The next-page cursor: the last EMITTED row's key when the page came back
/// full, `None` when it came back short.
fn cursor_after(len: usize, limit: i64, last: Option<(DateTime<Utc>, Uuid)>) -> Option<String> {
    if i64::try_from(len).unwrap_or(i64::MAX) < limit {
        return None;
    }
    last.map(|(created_at, id)| LabelCursor { created_at, id }.encode())
}

fn to_node(row: ContextClaimRow) -> ContextNode {
    let (content, content_truncated) = clip(&row.content, MAX_CONTENT_CHARS);
    ContextNode {
        id: row.id,
        content,
        content_truncated,
        truth_value: row.truth_value,
        is_current: row.is_current,
        level: parse_level(row.level.as_deref()),
        theme_id: row.theme_id,
    }
}

fn to_paper(row: ContextPaperRow) -> ContextPaper {
    let (doi, doi_cut) = clip(&row.doi, MAX_DOI_CHARS);
    let (title, title_cut) = match row.title.as_deref() {
        Some(t) => {
            let (t, cut) = clip(t, MAX_TITLE_CHARS);
            (Some(t), cut)
        }
        None => (None, false),
    };
    ContextPaper {
        id: row.id,
        doi,
        title,
        truncated: doi_cut || title_cut,
    }
}

fn to_edge(row: ContextEdgeRow) -> ContextEdge {
    let (content, content_truncated) = clip(&row.content, MAX_CONTENT_CHARS);
    ContextEdge {
        edge_id: row.edge_id,
        relationship: row.relationship,
        direction: row.direction,
        strength: parse_strength(row.strength.as_deref()),
        neighbor: ContextNode {
            id: row.neighbor_id,
            content,
            content_truncated,
            truth_value: row.truth_value,
            is_current: row.is_current,
            level: parse_level(row.level.as_deref()),
            theme_id: row.theme_id,
        },
    }
}

fn node_page(page: ContextPage<ContextClaimRow>, limit: i64) -> NodePage {
    let last = page.items.last().map(|r| (r.created_at, r.id));
    let next_cursor = cursor_after(page.items.len(), limit, last);
    NodePage {
        items: page.items.into_iter().map(to_node).collect(),
        total: page.total,
        next_cursor,
    }
}

fn paper_page(page: ContextPage<ContextPaperRow>, limit: i64) -> PaperPage {
    let last = page.items.last().map(|r| (r.order_at, r.id));
    let next_cursor = cursor_after(page.items.len(), limit, last);
    PaperPage {
        items: page.items.into_iter().map(to_paper).collect(),
        total: page.total,
        next_cursor,
    }
}

fn sibling_page(
    parent_id: Option<Uuid>,
    page: Option<ContextPage<ContextClaimRow>>,
    limit: i64,
) -> SiblingPage {
    match page {
        Some(page) => {
            let NodePage {
                items,
                total,
                next_cursor,
            } = node_page(page, limit);
            SiblingPage {
                parent_id,
                items,
                total,
                next_cursor,
            }
        }
        None => SiblingPage {
            parent_id: None,
            items: Vec::new(),
            total: 0,
            next_cursor: None,
        },
    }
}

fn edge_page(tallies: Vec<ContextEdgeTally>, rows: Vec<ContextEdgeRow>, limit: i64) -> EdgePage {
    let last = rows.last().map(|r| (r.edge_created_at, r.edge_id));
    let next_cursor = cursor_after(rows.len(), limit, last);
    let total = tallies.iter().map(|t| t.count).sum();
    EdgePage {
        items: rows.into_iter().map(to_edge).collect(),
        total,
        by_relationship: tallies
            .into_iter()
            .map(|t| RelationshipCount {
                relationship: t.relationship,
                direction: t.direction,
                count: t.count,
            })
            .collect(),
        next_cursor,
    }
}

/// The primary parent of `root`: the first visible `decomposes_to` parent at
/// the expected level (root level - 1), any level when the root's level is
/// unknown, and none for a root at level 0 or below.
async fn primary_parent(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    root: &ContextClaimRow,
) -> Result<Option<ContextClaimRow>, ApiError> {
    let level = parse_level(root.level.as_deref());
    if matches!(level, Some(l) if l < 1) {
        return Ok(None);
    }
    let expected = expected_parent_level(level);
    Ok(ClaimContextRepository::first_parent(conn, viewer, root.id, expected.as_deref()).await?)
}

/// Walk up from `primary` to the level-1 ancestor, filtering every hop by
/// its expected level. A hop that is not visible ends the walk with `None`
/// (fail closed: a visible section reached only through a hidden paragraph
/// is not shown).
async fn section_above(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    primary: Option<&ContextClaimRow>,
) -> Result<Option<ContextClaimRow>, ApiError> {
    let mut cur = primary.cloned();
    let mut hops = 0usize;
    loop {
        let Some(c) = cur else {
            return Ok(None);
        };
        let level = parse_level(c.level.as_deref());
        if level == Some(1) {
            return Ok(Some(c));
        }
        if matches!(level, Some(l) if l < 1) || hops == MAX_SECTION_HOPS {
            return Ok(None);
        }
        hops += 1;
        let expected = expected_parent_level(level);
        cur = ClaimContextRepository::first_parent(&mut *conn, viewer, c.id, expected.as_deref())
            .await?;
    }
}

/// The paper of the primary chain's document: the first visible asserting
/// paper of the section, then of the primary parent, then of the root
/// itself, the root only when it has no primary parent or is a thesis,
/// section or paragraph (whose ids are per document; an atom's id is shared
/// across documents, so an atom root is never asked).
async fn chain_paper(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    root: &ContextClaimRow,
    primary: Option<&ContextClaimRow>,
    section: Option<&ContextClaimRow>,
) -> Result<Option<ContextPaperRow>, ApiError> {
    let root_level = parse_level(root.level.as_deref());
    let mut candidates: Vec<Uuid> = Vec::with_capacity(3);
    for id in [section.map(|s| s.id), primary.map(|p| p.id)]
        .into_iter()
        .flatten()
    {
        if !candidates.contains(&id) {
            candidates.push(id);
        }
    }
    if (primary.is_none() || matches!(root_level, Some(0..=2))) && !candidates.contains(&root.id) {
        candidates.push(root.id);
    }
    for id in candidates {
        if let Some(paper) = ClaimContextRepository::first_paper(&mut *conn, viewer, id).await? {
            return Ok(Some(paper));
        }
    }
    Ok(None)
}

/// The edges list: the tallies (whose sum is the total) and one page.
async fn edges_list(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    root_id: Uuid,
    after: Option<LabelCursor>,
    limit: i64,
) -> Result<EdgePage, ApiError> {
    let tallies = ClaimContextRepository::epistemic_tallies(&mut *conn, viewer, root_id).await?;
    let rows =
        ClaimContextRepository::epistemic_edges(&mut *conn, viewer, root_id, after, limit).await?;
    Ok(edge_page(tallies, rows, limit))
}

/// The siblings list under `primary` at the root's own level, excluding the
/// root. `None` without a primary parent.
async fn siblings_list(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    root: &ContextClaimRow,
    primary: Option<&ContextClaimRow>,
    after: Option<LabelCursor>,
    limit: i64,
) -> Result<SiblingPage, ApiError> {
    let Some(parent) = primary else {
        return Ok(sibling_page(None, None, limit));
    };
    let page = ClaimContextRepository::children(
        &mut *conn,
        viewer,
        parent.id,
        root.level.as_deref(),
        Some(root.id),
        after,
        limit,
    )
    .await?;
    Ok(sibling_page(Some(parent.id), Some(page), limit))
}

/// Full mode, in the order the design fixes: papers, parents, the primary
/// chain (parent, section, paper), parts, siblings, tallies and edges.
async fn full_context(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    root: ContextClaimRow,
) -> Result<ContextResponse, ApiError> {
    let papers_limit = i64::from(DEFAULT_PAPERS);
    let papers =
        ClaimContextRepository::papers(&mut *conn, viewer, root.id, None, papers_limit).await?;

    let parents_limit = i64::from(DEFAULT_PARENTS);
    let parents =
        ClaimContextRepository::parents(&mut *conn, viewer, root.id, None, parents_limit).await?;

    let primary = primary_parent(&mut *conn, viewer, &root).await?;
    let root_level = parse_level(root.level.as_deref());
    let section = if matches!(root_level, Some(0 | 1)) {
        None
    } else {
        section_above(&mut *conn, viewer, primary.as_ref()).await?
    };
    let paper = chain_paper(
        &mut *conn,
        viewer,
        &root,
        primary.as_ref(),
        section.as_ref(),
    )
    .await?;

    let parts_limit = i64::from(DEFAULT_PARTS);
    let parts = ClaimContextRepository::children(
        &mut *conn,
        viewer,
        root.id,
        None,
        None,
        None,
        parts_limit,
    )
    .await?;

    let siblings_limit = i64::from(DEFAULT_SIBLINGS);
    let siblings = siblings_list(
        &mut *conn,
        viewer,
        &root,
        primary.as_ref(),
        None,
        siblings_limit,
    )
    .await?;

    let edges_limit = i64::from(DEFAULT_EDGES);
    let edges = edges_list(&mut *conn, viewer, root.id, None, edges_limit).await?;

    Ok(ContextResponse {
        claim: to_node(root),
        paper: paper.map(to_paper),
        papers: paper_page(papers, papers_limit),
        section: section.map(to_node),
        parents: node_page(parents, parents_limit),
        parts: node_page(parts, parts_limit),
        siblings,
        edges,
    })
}

/// Page mode: the root plus the one named list.
async fn page_context(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    root: ContextClaimRow,
    list: ContextList,
    after: Option<LabelCursor>,
    limit: i64,
) -> Result<ContextPageResponse, ApiError> {
    let mut out = ContextPageResponse {
        claim: to_node(root.clone()),
        papers: None,
        parents: None,
        parts: None,
        siblings: None,
        edges: None,
    };
    match list {
        ContextList::Papers => {
            let page =
                ClaimContextRepository::papers(&mut *conn, viewer, root.id, after, limit).await?;
            out.papers = Some(paper_page(page, limit));
        }
        ContextList::Parents => {
            let page =
                ClaimContextRepository::parents(&mut *conn, viewer, root.id, after, limit).await?;
            out.parents = Some(node_page(page, limit));
        }
        ContextList::Parts => {
            let page = ClaimContextRepository::children(
                &mut *conn, viewer, root.id, None, None, after, limit,
            )
            .await?;
            out.parts = Some(node_page(page, limit));
        }
        ContextList::Siblings => {
            let primary = primary_parent(&mut *conn, viewer, &root).await?;
            out.siblings = Some(
                siblings_list(&mut *conn, viewer, &root, primary.as_ref(), after, limit).await?,
            );
        }
        ContextList::Edges => {
            out.edges = Some(edges_list(&mut *conn, viewer, root.id, after, limit).await?);
        }
    }
    Ok(out)
}

/// The validated query: `None` for full mode, or the page-mode list with
/// its cursor and clamped limit. Every refusal is a JSON 400 raised before
/// any database statement, so it cannot depend on the root's visibility.
fn validate(
    params: &ContextQuery,
) -> Result<Option<(ContextList, Option<LabelCursor>, i64)>, ApiError> {
    let after_raw = params
        .after
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(list_raw) = params.list.as_deref() else {
        if after_raw.is_some() || params.limit.is_some() {
            return Err(ApiError::BadRequest {
                message: "`after` and `limit` page one list; pass `list` with them".to_string(),
            });
        }
        return Ok(None);
    };
    let list = ContextList::parse(list_raw.trim()).ok_or_else(|| ApiError::BadRequest {
        message: "unknown `list`; expected one of papers, parents, parts, siblings, edges"
            .to_string(),
    })?;
    let after = match after_raw {
        None => None,
        Some(token) => Some(
            LabelCursor::decode(token).ok_or_else(|| ApiError::BadRequest {
                message: BAD_CURSOR.to_string(),
            })?,
        ),
    };
    let limit = params
        .limit
        .unwrap_or_else(|| list.default_limit())
        .clamp(1, MAX_PAGE);
    Ok(Some((list, after, i64::from(limit))))
}

/// `GET /api/v1/claims/:id/context`
pub async fn claim_context(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<ContextQuery>,
) -> Result<Json<ContextBody>, ApiError> {
    let mode = validate(&params)?;

    // One viewer-stamped connection for every statement, so the root check,
    // the lists and their totals describe the same corpus.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "claim_context",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let Some(root) = ClaimContextRepository::root(&mut read, &viewer, claim_id).await? else {
        return Err(ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        });
    };

    let body = match mode {
        None => ContextBody::Full(full_context(&mut read, &viewer, root).await?),
        Some((list, after, limit)) => {
            ContextBody::Page(page_context(&mut read, &viewer, root, list, after, limit).await?)
        }
    };

    crate::routes::finish_scoped_read(read, "claim_context").await?;
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORST_F64: f64 = -1.234_567_890_123_456_7e-300;

    fn worst_text(chars: usize) -> String {
        "\u{1}".repeat(chars)
    }

    fn worst_node() -> ContextNode {
        ContextNode {
            id: Uuid::new_v4(),
            content: worst_text(MAX_CONTENT_CHARS),
            content_truncated: true,
            truth_value: WORST_F64,
            is_current: true,
            level: Some(i32::MIN),
            theme_id: Some(Uuid::new_v4()),
        }
    }

    fn worst_edge() -> ContextEdge {
        ContextEdge {
            edge_id: Uuid::new_v4(),
            relationship: "corroborates".to_string(),
            direction: "incoming".to_string(),
            strength: Some(WORST_F64),
            neighbor: worst_node(),
        }
    }

    fn worst_paper() -> ContextPaper {
        ContextPaper {
            id: Uuid::new_v4(),
            doi: worst_text(MAX_DOI_CHARS),
            title: Some(worst_text(MAX_TITLE_CHARS)),
            truncated: true,
        }
    }

    /// The longest token: Postgres's earliest timestamptz has the most
    /// digits plus a sign.
    fn worst_cursor() -> Option<String> {
        Some(
            LabelCursor {
                created_at: DateTime::<Utc>::from_timestamp_micros(-210_866_803_200_000_000)
                    .expect("in chrono's range"),
                id: Uuid::new_v4(),
            }
            .encode(),
        )
    }

    fn worst_node_page(n: u32) -> NodePage {
        NodePage {
            items: (0..n).map(|_| worst_node()).collect(),
            total: i64::MAX,
            next_cursor: worst_cursor(),
        }
    }

    #[test]
    fn worst_case_bodies_fit_the_2mb_cap() {
        let page = ContextBody::Page(ContextPageResponse {
            claim: worst_node(),
            papers: None,
            parents: None,
            parts: None,
            siblings: None,
            edges: Some(EdgePage {
                items: (0..MAX_PAGE).map(|_| worst_edge()).collect(),
                total: i64::MAX,
                by_relationship: (0..16)
                    .map(|_| RelationshipCount {
                        relationship: "corroborates".to_string(),
                        direction: "incoming".to_string(),
                        count: i64::MAX,
                    })
                    .collect(),
                next_cursor: worst_cursor(),
            }),
        });
        let page_len = serde_json::to_vec(&page).expect("serialise page").len();
        assert!(
            page_len <= MAX_BODY_BYTES,
            "a maximal page-mode body is {page_len} bytes, over the {MAX_BODY_BYTES} cap"
        );

        let full = ContextBody::Full(ContextResponse {
            claim: worst_node(),
            paper: Some(worst_paper()),
            papers: PaperPage {
                items: (0..DEFAULT_PAPERS).map(|_| worst_paper()).collect(),
                total: i64::MAX,
                next_cursor: worst_cursor(),
            },
            section: Some(worst_node()),
            parents: worst_node_page(DEFAULT_PARENTS),
            parts: worst_node_page(DEFAULT_PARTS),
            siblings: SiblingPage {
                parent_id: Some(Uuid::new_v4()),
                items: (0..DEFAULT_SIBLINGS).map(|_| worst_node()).collect(),
                total: i64::MAX,
                next_cursor: worst_cursor(),
            },
            edges: EdgePage {
                items: (0..DEFAULT_EDGES).map(|_| worst_edge()).collect(),
                total: i64::MAX,
                by_relationship: (0..16)
                    .map(|_| RelationshipCount {
                        relationship: "corroborates".to_string(),
                        direction: "incoming".to_string(),
                        count: i64::MAX,
                    })
                    .collect(),
                next_cursor: worst_cursor(),
            },
        });
        let full_len = serde_json::to_vec(&full).expect("serialise full").len();
        assert!(
            full_len <= MAX_BODY_BYTES,
            "a maximal full-mode body is {full_len} bytes, over the {MAX_BODY_BYTES} cap"
        );
        // The control character really is the six-byte worst case, so the
        // bound above is measured at the worst, not at a friendly input.
        assert!(page_len > MAX_PAGE as usize * MAX_CONTENT_CHARS * 6);
    }

    #[test]
    fn clip_counts_chars_and_cuts_on_a_boundary() {
        assert_eq!(clip("short", 10), ("short".to_string(), false));
        let exact = "x".repeat(10);
        assert_eq!(clip(&exact, 10), (exact.clone(), false));
        // Two-byte characters: a byte slice at the char limit would land
        // mid-character and panic.
        let long = "é".repeat(25);
        let (cut, truncated) = clip(&long, 10);
        assert!(truncated);
        assert_eq!(cut.chars().count(), 10);
        assert_eq!(cut, "é".repeat(10));
    }

    #[test]
    fn parse_level_and_strength_reject_junk() {
        assert_eq!(parse_level(Some("3")), Some(3));
        assert_eq!(parse_level(Some("3.0")), None);
        assert_eq!(parse_level(Some("x")), None);
        assert_eq!(parse_level(None), None);
        assert_eq!(parse_strength(Some("0.8")), Some(0.8));
        assert_eq!(parse_strength(Some("NaN")), None);
        assert_eq!(parse_strength(Some("inf")), None);
        assert_eq!(parse_strength(Some("x")), None);
        assert_eq!(parse_strength(None), None);
    }

    #[test]
    fn expected_parent_level_steps_down_one() {
        assert_eq!(expected_parent_level(Some(3)), Some("2".to_string()));
        assert_eq!(expected_parent_level(Some(1)), Some("0".to_string()));
        assert_eq!(expected_parent_level(Some(0)), None);
        assert_eq!(expected_parent_level(None), None);
    }

    #[test]
    fn a_cursor_is_emitted_only_for_a_full_page_and_names_the_last_row() {
        let ts = DateTime::<Utc>::from_timestamp_micros(1_730_700_000_000_000).unwrap();
        let id = Uuid::new_v4();
        assert_eq!(cursor_after(2, 3, Some((ts, id))), None);
        let tok = cursor_after(3, 3, Some((ts, id))).expect("full page");
        assert_eq!(
            LabelCursor::decode(&tok),
            Some(LabelCursor { created_at: ts, id })
        );
        assert_eq!(cursor_after(0, 1, None), None);
    }

    #[test]
    fn list_names_parse_exactly() {
        assert_eq!(ContextList::parse("parts"), Some(ContextList::Parts));
        assert_eq!(ContextList::parse("edges"), Some(ContextList::Edges));
        assert_eq!(ContextList::parse("Parts"), None);
        assert_eq!(ContextList::parse("bogus"), None);
    }
}
