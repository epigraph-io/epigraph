//! Who filed a claim: the `authored_by` block of a claim read
//! (`GET /api/v1/claims/:id`, MCP `get_claim`).
//!
//! A claim names the agent that filed it (`claims.agent_id`). Who-said-what
//! shows, beside that agent, the HUMAN it was bound to, and as a side note the
//! prompt state the agent ran with when it filed the claim. Each part has its
//! own audience, and each is decided under the CALLER's viewer, on the
//! caller's viewer-stamped connection ([`ScopedRead`]), so this block never
//! tells a caller anything it could not already read elsewhere:
//!
//! * **`agent`** `{id, display_name}`: every reader of the claim. `agents` is
//!   readable by every session (077's `agents_identity` policy), and
//!   `GET /api/v1/agents/:id` answers the same two fields for any id.
//! * **`human`** `{id, display_name}`: every reader of the claim. The human
//!   the agent was BOUND to when it filed the claim (`created_at`), read from
//!   the binding RECORD through migration 199's `epigraph_operator_bound_at`:
//!   its operator link from creation until retirement (107; a claim filed
//!   while the link was live keeps naming the operator after it is retired,
//!   and a claim filed after names nobody), else the migration-149 client
//!   allowance in force then. At the present instant that is exactly the
//!   agent card's `operator_human`. No client, registration or membership
//!   STATUS is read, so a reader cannot watch a suspension. No `OPERATED_BY`
//!   edge decides it: any edges:write caller can write one between two
//!   agents, so an edge proves nothing about who operates whom, and a forged
//!   edge changes nothing here. A registered human's own claim names no
//!   human (a binding is never to the agent itself).
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
//! # Who is the author: the filer, or the document that created the claim
//!
//! Atoms are content-addressed, so one claim row can be stated directly by
//! an agent and asserted by any number of documents. Who its PRIMARY author
//! is was decided when the row was created, and the document ingest records
//! that at creation ([`ClaimIngestRepository`], a `paper -ingested_claim->
//! claim` record per (paper, claim, ingester), `created_claim: true` only on
//! the ingest that created the row). This block reads that record and
//! nothing else: never a bare `asserts` edge, never content convergence.
//!
//! The block is tagged by `source`:
//!
//! * **`source: "agent"`** `{agent, human, prompt_snapshot, ...}`: no
//!   readable creation record names a document, so the filer is the author
//!   (a claim stated directly, a claim a document later repeated, a claim
//!   ingested before the record existed). The three parts above.
//! * **`source: "literature"`** `{paper, ingested_by, ...}`: the readable
//!   creation record names the document whose ingest created the claim.
//!   `paper` is that document with its authors, the claim's PRIMARY authors;
//!   `ingested_by` is the filer (the creating ingest's agent, which the record
//!   contract requires to be the claim's filer), with its human and snapshot
//!   under the same rules, never presented as an author.
//!
//! Both carry, beside the tag:
//!
//! * **`corroborated_by`**: every OTHER document whose ingest recorded the
//!   claim (a converging document, the same document's later ingesters'
//!   records collapse into one entry), readable to the caller, in record
//!   order, at most [`MAX_PAPERS`]; `corroborated_by_truncated`;
//! * **`ingesters`**: EVERY readable ingest record, the creator's included,
//!   oldest first (at most `claim_ingest::RECORDS_PER_CLAIM_CAP`), each with
//!   its agent, the human that agent was bound to at the time of the ingest,
//!   the document and `created_claim`; `ingesters_truncated`.
//!
//! A record counts only while its document's `asserts` edge onto the claim is
//! in force and readable (the record read's contract), so a caller who cannot
//! read a document's assertion never learns it exists, and the tag tells
//! nothing about records the caller may not read.
//!
//! Each document's authors are read with the paper listing's own read
//! (`PaperRepository::list_authors`, the one `query_paper` uses): in-force
//! `authored` edges the caller can read, in position order. An author an
//! ingester named without speaking for them (`pending_countersign`) is
//! listed under `pending_authors`, with `named_by` (the ingester whose word
//! it is), and never under `authors`, so a pending author is never shown as
//! a primary author. At most [`MAX_PAPER_AUTHORS`] are listed per document
//! (both lists together, in position order).
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

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::errors::DbError;
use crate::pool::ScopedRead;
use crate::repos::claim_ingest::{ClaimIngestRecord, ClaimIngestRepository};
use crate::repos::paper::{PaperAuthorListing, PaperRepository};
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

/// At most this many corroborating documents are listed per claim.
pub const MAX_PAPERS: usize = 10;

/// At most this many authors (primary and pending together) are listed per
/// document.
pub const MAX_PAPER_AUTHORS: usize = 50;

/// An agent with the human it was bound to, and (for the filer only) the
/// prompt snapshot it ran: the filer of a claim row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Filer {
    pub agent: AuthorRef,
    /// The human the agent was bound to when it filed the claim (its binding
    /// record at `created_at`), for every reader; `None` when it was bound to
    /// no human then.
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

/// One author of a document, from its `authored` edge, as the paper listing
/// (`PaperRepository::list_authors`) reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperAuthor {
    pub id: Uuid,
    pub display_name: Option<String>,
    /// The edge's `position` (the extraction's author index), when it is a
    /// non-negative integer.
    pub position: Option<i64>,
    /// The edge's `role` (`"author"` when absent).
    pub role: String,
    /// The edge's `affiliations` (strings only).
    pub affiliations: Vec<String>,
    /// The authorship is an ingester's word, awaiting the person's
    /// countersignature: such an author is listed under `pending_authors`,
    /// never under `authors`.
    pub pending_countersign: bool,
    /// On a pending authorship, the ingester whose word it is.
    pub named_by: Option<AuthorRef>,
}

/// A document and its authors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperAuthorship {
    pub paper: PaperRef,
    /// The document's countersigned and name-derived authors, in position
    /// order (on the creating document: the claim's primary authors).
    pub authors: Vec<PaperAuthor>,
    /// Authors an ingester named without speaking for them, not yet
    /// countersigned, in position order. Never primary.
    pub pending_authors: Vec<PaperAuthor>,
    /// More than [`MAX_PAPER_AUTHORS`] readable authors exist.
    pub authors_truncated: bool,
}

/// One ingest of the claim (one readable ingest record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ingester {
    /// The ingesting agent.
    pub agent: AuthorRef,
    /// The human that agent was bound to when it ingested (its binding
    /// record at `recorded_at`), for every reader.
    pub human: Option<AuthorRef>,
    /// The document it ingested.
    pub paper_id: Uuid,
    /// This ingest created the claim.
    pub created_claim: bool,
    /// When the ingest recorded the claim.
    pub recorded_at: DateTime<Utc>,
}

/// What both kinds of block carry beside the tag.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Corroboration {
    /// Every other readable document whose ingest recorded the claim, in
    /// record order, at most [`MAX_PAPERS`].
    pub corroborated_by: Vec<PaperAuthorship>,
    /// More than [`MAX_PAPERS`] such documents are readable.
    pub corroborated_by_truncated: bool,
    /// Every readable ingest of the claim, the creating one included, oldest
    /// first.
    pub ingesters: Vec<Ingester>,
    /// More ingest records exist than are listed.
    pub ingesters_truncated: bool,
}

/// A claim its filer stated: no readable creation record names a document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentAuthorship {
    #[serde(flatten)]
    pub filer: Filer,
    #[serde(flatten)]
    pub corroboration: Corroboration,
}

/// A claim a document's ingest created: that document's authors are its
/// primary authors, and the filer (the creating ingest's agent) is shown
/// apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiteratureAuthorship {
    /// The creating document and its authors.
    pub paper: PaperAuthorship,
    /// The agent that ran the creating ingest (the claim's filer).
    pub ingested_by: Filer,
    #[serde(flatten)]
    pub corroboration: Corroboration,
}

/// A claim's `authored_by` block, tagged by `source`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AuthoredBy {
    /// The filer stated the claim.
    Agent(AgentAuthorship),
    /// A document's ingest created the claim.
    Literature(LiteratureAuthorship),
}

impl AuthoredBy {
    /// The agent that filed the claim row, with its human and snapshot:
    /// the author for `Agent`, `ingested_by` for `Literature`.
    #[must_use]
    pub fn filer(&self) -> &Filer {
        match self {
            Self::Agent(a) => &a.filer,
            Self::Literature(l) => &l.ingested_by,
        }
    }

    /// The corroborating documents and every ingester.
    #[must_use]
    pub fn corroboration(&self) -> &Corroboration {
        match self {
            Self::Agent(a) => &a.corroboration,
            Self::Literature(l) => &l.corroboration,
        }
    }
}

pub struct AuthoredByRepository;

impl AuthoredByRepository {
    /// The `authored_by` block of claim `claim_id`, filed by `agent_id` at
    /// `created_at`, as `viewer` may see it. `read` must be `viewer`'s own
    /// stamped connection (the record and edge reads run under its row
    /// security, and the snapshot gate reads its session principal). Call it
    /// only for a claim `viewer` has already read.
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

        // Every readable ingest of the claim, from the ingest's own records
        // (never a bare `asserts` edge).
        let ingests = ClaimIngestRepository::for_claim(&mut *conn, viewer, claim_id).await?;

        // The humans: the filer's at `created_at`, each ingester's at its
        // record's time, from the binding record (migration 199).
        let mut asks: Vec<(Uuid, DateTime<Utc>)> = vec![(agent_id, created_at)];
        asks.extend(
            ingests
                .records
                .iter()
                .map(|r| (r.ingested_by, r.recorded_at)),
        );
        let bound = Self::humans_bound_at(&mut *conn, &asks).await?;
        let filer_human = bound.first().copied().flatten();

        // The documents: the creator's first, then each other document once,
        // in record order.
        let creator_paper = ingests.creator.as_ref().map(|c| c.paper_id);
        let mut others: Vec<Uuid> = Vec::new();
        for r in &ingests.records {
            if Some(r.paper_id) != creator_paper && !others.contains(&r.paper_id) {
                others.push(r.paper_id);
            }
        }
        let corroborated_by_truncated = others.len() > MAX_PAPERS;
        others.truncate(MAX_PAPERS);
        let mut paper_ids: Vec<Uuid> = creator_paper.into_iter().collect();
        paper_ids.extend(others.iter().copied());
        let mut listings: HashMap<Uuid, (PaperRef, Vec<PaperAuthorListing>)> = HashMap::new();
        if !paper_ids.is_empty() {
            let rows: Vec<(Uuid, String, Option<String>)> =
                sqlx::query_as("SELECT id, doi, title FROM papers WHERE id = ANY($1)")
                    .bind(&paper_ids)
                    .fetch_all(&mut *conn)
                    .await?;
            for (id, doi, title) in rows {
                let authors = PaperRepository::list_authors(&mut *conn, viewer, id).await?;
                listings.insert(id, (PaperRef { id, doi, title }, authors));
            }
        }

        // Every name in one read; `agents` is readable by every session.
        let mut wanted: Vec<Uuid> = vec![agent_id];
        wanted.extend(bound.iter().flatten().copied());
        wanted.extend(ingests.records.iter().map(|r| r.ingested_by));
        for (_, authors) in listings.values() {
            wanted.extend(authors.iter().filter_map(|a| a.ingested_by));
        }
        wanted.sort_unstable();
        wanted.dedup();
        let names: HashMap<Uuid, Option<String>> = sqlx::query_as::<_, (Uuid, Option<String>)>(
            "SELECT id, display_name FROM agents WHERE id = ANY($1)",
        )
        .bind(&wanted)
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .collect();
        let author_ref = |id: Uuid| AuthorRef {
            id,
            display_name: names.get(&id).cloned().flatten(),
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

        let filer = Filer {
            agent: author_ref(agent_id),
            human: filer_human.filter(|h| *h != agent_id).map(author_ref),
            prompt_snapshot,
        };

        let authorship = |id: Uuid| -> Option<PaperAuthorship> {
            let (paper, listing) = listings.get(&id)?;
            let authors_truncated = listing.len() > MAX_PAPER_AUTHORS;
            let (pending, plain): (Vec<PaperAuthor>, Vec<PaperAuthor>) = listing
                .iter()
                .take(MAX_PAPER_AUTHORS)
                .map(|a| PaperAuthor {
                    id: a.agent_id,
                    display_name: a.display_name.clone(),
                    position: a.position,
                    role: a.role.clone(),
                    affiliations: a.affiliations.clone(),
                    pending_countersign: a.pending_countersign,
                    named_by: if a.pending_countersign {
                        a.ingested_by.map(author_ref)
                    } else {
                        None
                    },
                })
                .partition(|a| a.pending_countersign);
            Some(PaperAuthorship {
                paper: paper.clone(),
                authors: plain,
                pending_authors: pending,
                authors_truncated,
            })
        };

        let corroboration = Corroboration {
            corroborated_by: others.iter().filter_map(|id| authorship(*id)).collect(),
            corroborated_by_truncated,
            ingesters: ingests
                .records
                .iter()
                .zip(bound.iter().skip(1))
                .map(|(r, human): (&ClaimIngestRecord, &Option<Uuid>)| Ingester {
                    agent: author_ref(r.ingested_by),
                    human: human.filter(|h| *h != r.ingested_by).map(author_ref),
                    paper_id: r.paper_id,
                    created_claim: r.created_claim,
                    recorded_at: r.recorded_at,
                })
                .collect(),
            ingesters_truncated: ingests.truncated,
        };

        Ok(match creator_paper.and_then(authorship) {
            Some(paper) => AuthoredBy::Literature(LiteratureAuthorship {
                paper,
                ingested_by: filer,
                corroboration,
            }),
            None => AuthoredBy::Agent(AgentAuthorship {
                filer,
                corroboration,
            }),
        })
    }

    /// The human each `(agent, instant)` was bound to, in order (migration
    /// 199's `epigraph_operator_bound_at`, one round trip).
    async fn humans_bound_at(
        conn: &mut sqlx::PgConnection,
        asks: &[(Uuid, DateTime<Utc>)],
    ) -> Result<Vec<Option<Uuid>>, DbError> {
        let agents: Vec<Uuid> = asks.iter().map(|(a, _)| *a).collect();
        let instants: Vec<DateTime<Utc>> = asks.iter().map(|(_, t)| *t).collect();
        let rows: Vec<(i64, Option<Uuid>)> = sqlx::query_as(
            "SELECT u.n, public.epigraph_operator_bound_at(u.a, u.t) \
               FROM unnest($1::uuid[], $2::timestamptz[]) WITH ORDINALITY AS u(a, t, n) \
              ORDER BY u.n",
        )
        .bind(&agents)
        .bind(&instants)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows.into_iter().map(|(_, h)| h).collect())
    }
}
