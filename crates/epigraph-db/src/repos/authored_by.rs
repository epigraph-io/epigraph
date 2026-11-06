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
//!   gate: the agent's linked human (any link state) and admins. That is the
//!   owner's ruled audience (the model and snapshot stay behind the
//!   prompt-history gate, while the agent and its human are shown to every
//!   reader), set in ONE constant: [`PROMPT_SNAPSHOT_AUDIENCE`]. Prompt TEXT
//!   is never part of this block; it stays behind
//!   `GET /api/v1/agents/:id/prompt-history/blobs/:hash`.
//!
//! # Who is the author: the agent, or a document's authors
//!
//! The block is tagged by `source`:
//!
//! * **`source: "agent"`** `{agent, human, prompt_snapshot}`: a claim the
//!   agent stated itself. The three parts above.
//! * **`source: "literature"`** `{papers, papers_truncated, ingested_by}`: a
//!   claim a document asserts. Its PRIMARY authors are the document's
//!   authors, and the agent that filed the claim row is shown apart, as
//!   `ingested_by` (the same three parts, the same audiences). A claim is
//!   literature exactly when the caller can read an in-force
//!   `paper -asserts-> claim` edge to it; a caller who cannot read any such
//!   edge gets the `agent` block, byte for byte the block of a claim no
//!   document asserts, so the tag tells nothing about edges the caller may not
//!   read. Content-addressed claims converge, so several documents can assert
//!   one claim: `papers` lists every one the caller can see (at most
//!   [`MAX_PAPERS`], oldest paper row first, then id), each with its authors
//!   from the in-force `agent -authored-> paper` edges the caller can read
//!   (at most [`MAX_PAPER_AUTHORS`]), ordered by the edge's `position`
//!   (missing or non-integer last), then agent id, with the edge's `role` and
//!   `affiliations`. Positions are not unique (a re-ingest that names an
//!   author by id adds an author at a position another already holds), so
//!   both are listed. Agent-to-claim `asserts` edges are not read.
//!   `ingested_by` is the claim row's filer (`claims.agent_id`): for a claim
//!   first created by a document ingest, its ingester; a claim filed first by
//!   another path and later asserted by a document keeps that first filer. No
//!   per-document ingester is recorded.
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
/// RULED: [`PromptSnapshotAudience::OperatorAndAdmins`]. The model, prompt
/// hash and snapshot stay behind the prompt-history gate (design D4), the
/// same audience as the prompt text; the agent and its human are shown to
/// every reader regardless of this setting. The value below is the whole
/// switch: the REST and MCP claim tests read it and assert whichever setting
/// is live, and the repo tests drive both settings explicitly.
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

/// At most this many asserting documents are listed per claim.
pub const MAX_PAPERS: i64 = 10;

/// At most this many authors are listed per document.
pub const MAX_PAPER_AUTHORS: i64 = 50;

/// The agent that filed a claim row, with its human and prompt snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Filer {
    pub agent: AuthorRef,
    /// The agent's operator (its binding), for every reader; `None` when the
    /// agent is bound to no human or only to itself.
    pub human: Option<AuthorRef>,
    /// `None` both when no snapshot was active and when the caller is not in
    /// the audience.
    pub prompt_snapshot: Option<PromptSnapshotAt>,
}

/// A document node (`papers`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperRef {
    pub id: Uuid,
    /// The document key (`papers.doi`: a DOI, or another document key).
    pub doi: String,
    pub title: Option<String>,
}

/// One author of a document, from its `authored` edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperAuthor {
    pub id: Uuid,
    pub display_name: Option<String>,
    /// The edge's `position` (the extraction's author index), when it is a
    /// non-negative integer.
    pub position: Option<i64>,
    /// The edge's `role`, when it is a string.
    pub role: Option<String>,
    /// The edge's `affiliations`, when it is an array (non-null elements, as
    /// text).
    pub affiliations: Vec<String>,
}

/// A document that asserts the claim, and its authors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperAuthorship {
    pub paper: PaperRef,
    pub authors: Vec<PaperAuthor>,
    /// More than [`MAX_PAPER_AUTHORS`] readable authors exist.
    pub authors_truncated: bool,
}

/// A claim's `authored_by` block, tagged by `source`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AuthoredBy {
    /// The agent stated the claim itself.
    Agent(Filer),
    /// Documents assert the claim: their authors are its authors, and the
    /// agent that filed the claim row is shown apart.
    Literature {
        papers: Vec<PaperAuthorship>,
        /// More than [`MAX_PAPERS`] readable asserting documents exist.
        papers_truncated: bool,
        ingested_by: Filer,
    },
}

impl AuthoredBy {
    /// The agent that filed the claim row, with its human and snapshot:
    /// the whole block for `Agent`, `ingested_by` for `Literature`.
    #[must_use]
    pub fn filer(&self) -> &Filer {
        match self {
            Self::Agent(f) | Self::Literature { ingested_by: f, .. } => f,
        }
    }
}

pub struct AuthoredByRepository;

impl AuthoredByRepository {
    /// The `authored_by` block of claim `claim_id`, filed by `agent_id` at
    /// `created_at`, as `viewer` may see it. `read` must be `viewer`'s own
    /// stamped connection (the edge reads run under its row security, and the
    /// snapshot gate reads its session principal). Call it only for a claim
    /// `viewer` has already read.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if a read fails, including on a database
    /// without migration 199 (42883).
    pub async fn for_claim(
        read: &mut ScopedRead<'_>,
        viewer: &Viewer,
        claim_id: Uuid,
        agent_id: Uuid,
        created_at: DateTime<Utc>,
        audience: PromptSnapshotAudience,
    ) -> Result<AuthoredBy, DbError> {
        let conn: &mut sqlx::PgConnection = read;
        let filer = Self::filer(conn, agent_id, created_at, audience).await?;
        let (papers, papers_truncated) = Self::asserting_papers(conn, viewer, claim_id).await?;
        if papers.is_empty() {
            return Ok(AuthoredBy::Agent(filer));
        }
        Ok(AuthoredBy::Literature {
            papers,
            papers_truncated,
            ingested_by: filer,
        })
    }

    async fn filer(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
        created_at: DateTime<Utc>,
        audience: PromptSnapshotAudience,
    ) -> Result<Filer, DbError> {
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

        Ok(Filer {
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

    /// The documents with a readable, in-force `asserts` edge to the claim
    /// (at most [`MAX_PAPERS`]), each with its readable authors, and whether
    /// more documents exist.
    async fn asserting_papers(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
    ) -> Result<(Vec<PaperAuthorship>, bool), DbError> {
        let sql = viewer.splice(
            "SELECT p.id, p.doi, p.title \
               FROM papers p \
              WHERE EXISTS (SELECT 1 FROM edges e \
                             WHERE e.source_id = p.id AND e.source_type = 'paper' \
                               AND e.target_id = $1 AND e.target_type = 'claim' \
                               AND e.relationship = 'asserts' \
                               AND (e.valid_to IS NULL OR e.valid_to > now()) \
                               /* {EDGE_VISIBILITY:e} */) \
                AND EXISTS (SELECT 1 FROM claims ac WHERE ac.id = $1 /* {VISIBILITY:ac} */) \
              ORDER BY COALESCE(p.created_at, to_timestamp(0)), p.id \
              LIMIT $2",
            3,
        );
        let mut q = sqlx::query_as::<_, (Uuid, String, Option<String>)>(&sql)
            .bind(claim_id)
            .bind(MAX_PAPERS + 1);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let mut rows = q.fetch_all(&mut *conn).await?;
        if rows.is_empty() {
            return Ok((Vec::new(), false));
        }
        let truncated = rows.len() > usize::try_from(MAX_PAPERS).unwrap_or(usize::MAX);
        rows.truncate(usize::try_from(MAX_PAPERS).unwrap_or(usize::MAX));
        let ids: Vec<Uuid> = rows.iter().map(|(id, _, _)| *id).collect();

        // Every listed document's authors in one read, ranked per document.
        let sql = viewer.splice(
            "SELECT x.paper_id, x.id, x.display_name, x.position, x.role, x.affiliations, x.n \
               FROM (SELECT e.target_id AS paper_id, a.id, a.display_name, pos.position, \
                            CASE WHEN jsonb_typeof(e.properties -> 'role') = 'string' \
                                 THEN e.properties ->> 'role' END AS role, \
                            ARRAY(SELECT t FROM jsonb_array_elements_text( \
                                    CASE WHEN jsonb_typeof(e.properties -> 'affiliations') = 'array' \
                                         THEN e.properties -> 'affiliations' \
                                         ELSE '[]'::jsonb END) AS t \
                                   WHERE t IS NOT NULL) AS affiliations, \
                            row_number() OVER (PARTITION BY e.target_id \
                                               ORDER BY pos.position NULLS LAST, a.id) AS rn, \
                            count(*) OVER (PARTITION BY e.target_id) AS n \
                       FROM edges e \
                       JOIN agents a ON a.id = e.source_id \
                      CROSS JOIN LATERAL ( \
                            SELECT CASE WHEN jsonb_typeof(e.properties -> 'position') = 'number' \
                                         AND (e.properties ->> 'position') ~ '^[0-9]{1,9}$' \
                                        THEN (e.properties ->> 'position')::bigint END \
                                   AS position) pos \
                      WHERE e.target_id = ANY($1) AND e.target_type = 'paper' \
                        AND e.source_type = 'agent' AND e.relationship = 'authored' \
                        AND (e.valid_to IS NULL OR e.valid_to > now()) \
                        /* {EDGE_VISIBILITY:e} */) x \
              WHERE x.rn <= $2 \
              ORDER BY x.paper_id, x.rn",
            3,
        );
        type AuthorRow = (
            Uuid,
            Uuid,
            Option<String>,
            Option<i64>,
            Option<String>,
            Vec<String>,
            i64,
        );
        let mut q = sqlx::query_as::<_, AuthorRow>(&sql)
            .bind(&ids)
            .bind(MAX_PAPER_AUTHORS);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let authors: Vec<AuthorRow> = q.fetch_all(&mut *conn).await?;

        let papers = rows
            .into_iter()
            .map(|(id, doi, title)| {
                let mine: Vec<&AuthorRow> = authors.iter().filter(|r| r.0 == id).collect();
                PaperAuthorship {
                    paper: PaperRef { id, doi, title },
                    authors_truncated: mine.first().is_some_and(|r| r.6 > MAX_PAPER_AUTHORS),
                    authors: mine
                        .into_iter()
                        .map(|r| PaperAuthor {
                            id: r.1,
                            display_name: r.2.clone(),
                            position: r.3,
                            role: r.4.clone(),
                            affiliations: r.5.clone(),
                        })
                        .collect(),
                }
            })
            .collect();
        Ok((papers, truncated))
    }
}
