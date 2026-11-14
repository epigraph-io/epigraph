//! The sources of the claims a viewer may read, with counts
//! (`GET /api/v1/sources/overview`, backlog da4a8bc1): "who said what" across
//! the corpus or one theme, in one cursor-paged read.
//!
//! Three kinds, listed in this order:
//!
//! * `paper`: one entry per paper, counted over the CURRENT claims the viewer
//!   may read that an in-force, ingest-written
//!   (`crate::ingest_written_edge_sql`) `paper -asserts-> claim` edge the
//!   viewer may read points at. The same edge predicate as
//!   [`PaperRepository::count_asserted_claims`]: an `asserts` edge written any
//!   other way is not a document ingest's word and attributes nothing here.
//! * `agent`: one entry per filing agent (`claims.agent_id`), counted over the
//!   current claims the viewer may read that have NO such edge the viewer may
//!   read. The edge probe is viewer-filtered on purpose: a claim whose only
//!   asserting edge is hidden from the viewer is counted under its filer, the
//!   same answer `GET /api/v1/claims/:id` gives that viewer
//!   (`AuthoredByRepository`), so a count never tells an edge the viewer
//!   cannot read from one that does not exist.
//! * `web`: one entry per host of an `http(s)` `evidence.source_url`, counted
//!   over the current claims the viewer may read that carry such an evidence
//!   row the viewer may read (filtered per evidence row, as
//!   `EvidenceRepository::source_urls_by_claim_ids` is). Only the column is
//!   read: a row written before the column was populated keeps its link in
//!   `properties` and is not counted. The host is lowercased, userinfo and
//!   port are dropped, and a host that is not `[a-z0-9.-]+` (an IPv6 literal,
//!   an unencoded IDN) is not listed.
//!
//! `paper` and `agent` split the viewer's readable current claims between
//! them (a claim two papers assert counts under each). `web` is a second view
//! of the same claims, not a third part: a claim counted under its paper or
//! filer is also counted under each host its evidence links to.
//!
//! Every statement splices the viewer predicate into `claims`, `edges` and
//! `evidence`, so a count is the number the viewer could reach by listing the
//! claims one at a time, and a source with no readable claim is absent.
//! `papers` and `agents` carry no tenancy columns (migration 062); a paper or
//! an agent is named only through a readable claim.
//!
//! # Order and cursor
//!
//! Within a kind: `claim_count DESC`, then the key (`id` as text, or the
//! host) in `"C"` collation. The cursor names the kind, count and key of the
//! last entry served. Counts are computed per request, so a count that
//! changes between two pages can move its source across the cut (served
//! twice, or not at all, in that walk); on a corpus at rest every source is
//! served exactly once.

use std::collections::HashMap;

use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::paper::PaperRepository;
use crate::visibility::Viewer;

/// Most sources one page returns.
pub const SOURCES_PAGE_MAX: i64 = 200;
/// The page size when the caller names none.
pub const SOURCES_PAGE_DEFAULT: i64 = 50;
/// Most authors listed per paper; `authors_truncated` says more exist.
pub const SOURCE_AUTHORS_MAX: i64 = 10;
/// Longest paper title or agent display name served, in characters.
pub const SOURCE_TEXT_MAX: i32 = 300;

/// A kind of source, in listing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Paper,
    Agent,
    Web,
}

impl SourceKind {
    /// Every kind, in listing order.
    pub const ALL: [SourceKind; 3] = [SourceKind::Paper, SourceKind::Agent, SourceKind::Web];

    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Paper => "paper",
            SourceKind::Agent => "agent",
            SourceKind::Web => "web",
        }
    }

    /// `None` for anything [`Self::as_str`] would not produce.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "paper" => Some(SourceKind::Paper),
            "agent" => Some(SourceKind::Agent),
            "web" => Some(SourceKind::Web),
            _ => None,
        }
    }

    /// Position in listing order.
    fn rank(self) -> u8 {
        match self {
            SourceKind::Paper => 0,
            SourceKind::Agent => 1,
            SourceKind::Web => 2,
        }
    }
}

/// Resume after the entry `(kind, claim_count, key)`. Token
/// `so1.<kind>.<count>.<key hex>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCursor {
    pub kind: SourceKind,
    pub claim_count: i64,
    /// The entry's key: a paper or agent id as text, or a web host.
    pub key: String,
}

impl SourceCursor {
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "so1.{}.{}.{}",
            self.kind.as_str(),
            self.claim_count,
            hex::encode(self.key.as_bytes())
        )
    }

    /// `None` for anything [`Self::encode`] would not produce.
    #[must_use]
    pub fn decode(token: &str) -> Option<Self> {
        let mut parts = token.strip_prefix("so1.")?.split('.');
        let kind = SourceKind::parse(parts.next()?)?;
        let claim_count: i64 = parts.next()?.parse().ok()?;
        let key = String::from_utf8(hex::decode(parts.next()?).ok()?).ok()?;
        if parts.next().is_some() || claim_count < 1 || key.is_empty() || key.len() > 255 {
            return None;
        }
        Some(Self {
            kind,
            claim_count,
            key,
        })
    }
}

/// One listed author of a paper source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAuthor {
    pub agent_id: Uuid,
    pub display_name: Option<String>,
    /// An ingester's word awaiting the person's countersignature
    /// (`PaperAuthorListing::pending_countersign`): show it as pending, never
    /// as a plain author.
    pub pending_countersign: bool,
}

/// What a source is, by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceDetail {
    Paper {
        id: Uuid,
        doi: String,
        /// Clipped to [`SOURCE_TEXT_MAX`] characters.
        title: Option<String>,
        /// At most [`SOURCE_AUTHORS_MAX`], as the ingests whose assertions
        /// the viewer may read wrote them.
        authors: Vec<SourceAuthor>,
        authors_truncated: bool,
    },
    Agent {
        id: Uuid,
        /// Clipped to [`SOURCE_TEXT_MAX`] characters.
        display_name: Option<String>,
    },
    Web {
        domain: String,
    },
}

/// One source and the number of current claims of it the viewer may read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    pub kind: SourceKind,
    /// The order key within the kind (see the module docs).
    pub key: String,
    pub claim_count: i64,
    pub detail: SourceDetail,
}

/// One page of [`SourceOverviewRepository::page`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourcePage {
    pub sources: Vec<SourceEntry>,
    /// `Some` when more may follow; pass it back as `after`.
    pub next: Option<SourceCursor>,
}

/// The keyset filter, order and cap every kind's statement ends with, over a
/// derived table `s(n, k, ..)`: `$2` / `$3` are the cursor's count and key
/// (both NULL on a first page), `$4` the row cap.
const PAGE_TAIL: &str = "WHERE ($2::bigint IS NULL OR s.n < $2::bigint \
            OR (s.n = $2::bigint AND s.k COLLATE \"C\" > $3::text)) \
      ORDER BY s.n DESC, s.k COLLATE \"C\" \
      LIMIT $4";

pub struct SourceOverviewRepository;

impl SourceOverviewRepository {
    /// One page of the sources of the current claims `viewer` may read,
    /// `paper` then `agent` then `web` (or the one `kind`), restricted to
    /// `theme_id`'s claims when given. `limit` is clamped to
    /// `1..=`[`SOURCES_PAGE_MAX`]. A cursor of a kind the page does not list
    /// (the caller changed `kind` between pages) resumes nothing: the caller
    /// refuses it first.
    ///
    /// At most one statement per kind, plus one for the page's paper authors.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if a database query fails.
    pub async fn page(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        theme_id: Option<Uuid>,
        kind: Option<SourceKind>,
        after: Option<&SourceCursor>,
        limit: i64,
    ) -> Result<SourcePage, DbError> {
        let limit = usize::try_from(limit.clamp(1, SOURCES_PAGE_MAX)).unwrap_or(1);
        let kinds: Vec<SourceKind> = match kind {
            Some(k) => vec![k],
            None => SourceKind::ALL.to_vec(),
        };
        let mut page = SourcePage::default();
        for (i, k) in kinds.iter().copied().enumerate() {
            // The cursor names the kind it stopped in: every kind before it
            // was served whole, every kind after it starts from the top.
            let resume = match after {
                Some(c) if c.kind.rank() > k.rank() => continue,
                Some(c) if c.kind == k => Some((c.claim_count, c.key.as_str())),
                _ => None,
            };
            let room = limit.saturating_sub(page.sources.len());
            // One row past the room says whether this kind has more.
            let cap = i64::try_from(room).unwrap_or(SOURCES_PAGE_MAX) + 1;
            let mut rows = match k {
                SourceKind::Paper => Self::papers(conn, viewer, theme_id, resume, cap).await?,
                SourceKind::Agent => Self::agents(conn, viewer, theme_id, resume, cap).await?,
                SourceKind::Web => Self::web(conn, viewer, theme_id, resume, cap).await?,
            };
            let more_of_kind = rows.len() > room;
            rows.truncate(room);
            page.sources.append(&mut rows);
            let full = page.sources.len() >= limit;
            // More of this kind, or a full page with kinds still to list: the
            // next page resumes after the last entry served. (A full page that
            // ends a kind resumes that kind, finds nothing, and moves on.)
            if more_of_kind || (full && i + 1 < kinds.len()) {
                page.next = page.sources.last().map(|s| SourceCursor {
                    kind: s.kind,
                    claim_count: s.claim_count,
                    key: s.key.clone(),
                });
            }
            if more_of_kind || full {
                break;
            }
        }
        Ok(page)
    }

    /// The `paper` kind: see the module docs.
    async fn papers(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        theme_id: Option<Uuid>,
        resume: Option<(i64, &str)>,
        cap: i64,
    ) -> Result<Vec<SourceEntry>, DbError> {
        let sql = viewer.splice(
            &format!(
                "SELECT s.id, s.k, s.doi, s.title, s.n, s.writers \
                   FROM (SELECT p.id, p.id::text AS k, p.doi, \
                                left(p.title, {SOURCE_TEXT_MAX}) AS title, \
                                COUNT(DISTINCT c.id) AS n, \
                                array_remove(array_agg(DISTINCT ({written_by})::text), NULL)::text[] \
                                    AS writers \
                           FROM edges e \
                           JOIN claims c ON c.id = e.target_id \
                           JOIN papers p ON p.id = e.source_id \
                          WHERE e.source_type = 'paper' AND e.target_type = 'claim' \
                            AND lower(e.relationship) = 'asserts' \
                            AND {in_force} AND {marked} \
                            AND COALESCE(c.is_current, true) \
                            AND ($1::uuid IS NULL OR c.theme_id = $1::uuid) \
                            /* {{EDGE_VISIBILITY:e}} */ /* {{VISIBILITY:c}} */ \
                          GROUP BY p.id, p.doi, p.title) s \
                  {PAGE_TAIL}",
                written_by = crate::repos::ingest_written::ingest_written_by_sql("e"),
                in_force = crate::repos::edge::EDGE_IN_FORCE,
                marked = crate::repos::ingest_written::ingest_written_edge_sql("e"),
            ),
            5,
        );
        type Row = (Uuid, String, String, Option<String>, i64, Vec<String>);
        let mut q = sqlx::query_as::<_, Row>(&sql)
            .bind(theme_id)
            .bind(resume.map(|(n, _)| n))
            .bind(resume.map(|(_, k)| k))
            .bind(cap);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<Row> = q.fetch_all(&mut *conn).await?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        // The page's authors in one bounded read, as the ingests whose
        // assertions this viewer read above wrote them (each principal's
        // ingest keeps its own authorship rows, `crate::ingest_written`).
        let paper_ids: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
        let mut writers: Vec<(Uuid, Uuid, i32)> = Vec::new();
        for (paper, _, _, _, _, by) in &rows {
            let mut rank: i32 = 0;
            for w in by {
                // A malformed marker names no principal and lists no author.
                if let Ok(w) = w.parse::<Uuid>() {
                    writers.push((*paper, w, rank));
                    rank = rank.saturating_add(1);
                }
            }
        }
        let mut authors: HashMap<Uuid, _> = PaperRepository::list_authors_bounded(
            &mut *conn,
            viewer,
            &paper_ids,
            SOURCE_AUTHORS_MAX,
            &writers,
            &[],
        )
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, k, doi, title, n, _)| {
                let (listed, authors_truncated) = authors.remove(&id).unwrap_or_default();
                SourceEntry {
                    kind: SourceKind::Paper,
                    key: k,
                    claim_count: n,
                    detail: SourceDetail::Paper {
                        id,
                        doi,
                        title,
                        authors: listed
                            .into_iter()
                            .map(|(a, _)| SourceAuthor {
                                agent_id: a.agent_id,
                                display_name: a.display_name,
                                pending_countersign: a.pending_countersign,
                            })
                            .collect(),
                        authors_truncated,
                    },
                }
            })
            .collect())
    }

    /// The `agent` kind: see the module docs.
    async fn agents(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        theme_id: Option<Uuid>,
        resume: Option<(i64, &str)>,
        cap: i64,
    ) -> Result<Vec<SourceEntry>, DbError> {
        let sql = viewer.splice(
            &format!(
                "SELECT s.id, s.k, s.display_name, s.n \
                   FROM (SELECT a.id, a.id::text AS k, \
                                left(a.display_name, {SOURCE_TEXT_MAX}) AS display_name, \
                                COUNT(*) AS n \
                           FROM claims c \
                           JOIN agents a ON a.id = c.agent_id \
                          WHERE COALESCE(c.is_current, true) \
                            AND ($1::uuid IS NULL OR c.theme_id = $1::uuid) \
                            /* {{VISIBILITY:c}} */ \
                            AND NOT EXISTS ( \
                                SELECT 1 FROM edges ae \
                                 WHERE ae.target_id = c.id \
                                   AND ae.target_type = 'claim' AND ae.source_type = 'paper' \
                                   AND lower(ae.relationship) = 'asserts' \
                                   AND (ae.valid_to IS NULL OR ae.valid_to > now()) \
                                   AND {marked} \
                                   /* {{EDGE_VISIBILITY:ae}} */) \
                          GROUP BY a.id, a.display_name) s \
                  {PAGE_TAIL}",
                marked = crate::repos::ingest_written::ingest_written_edge_sql("ae"),
            ),
            5,
        );
        type Row = (Uuid, String, Option<String>, i64);
        let mut q = sqlx::query_as::<_, Row>(&sql)
            .bind(theme_id)
            .bind(resume.map(|(n, _)| n))
            .bind(resume.map(|(_, k)| k))
            .bind(cap);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<Row> = q.fetch_all(&mut *conn).await?;
        Ok(rows
            .into_iter()
            .map(|(id, k, display_name, n)| SourceEntry {
                kind: SourceKind::Agent,
                key: k,
                claim_count: n,
                detail: SourceDetail::Agent { id, display_name },
            })
            .collect())
    }

    /// The `web` kind: see the module docs.
    async fn web(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        theme_id: Option<Uuid>,
        resume: Option<(i64, &str)>,
        cap: i64,
    ) -> Result<Vec<SourceEntry>, DbError> {
        // The host is taken from the lowercased URL: an optional userinfo
        // (never served: it can hold a credential) is skipped, and the capture
        // stops before a port, path, query or fragment.
        let sql = viewer.splice(
            &format!(
                "SELECT s.k, s.n \
                   FROM (SELECT d.host AS k, COUNT(DISTINCT d.claim_id) AS n \
                           FROM (SELECT c.id AS claim_id, \
                                        substring(lower(ev.source_url), \
                                                  '^https?://(?:[^/?#]*@)?([a-z0-9.-]+)') \
                                            AS host \
                                   FROM evidence ev \
                                   JOIN claims c ON c.id = ev.claim_id \
                                  WHERE ev.source_url ~* '^https?://' \
                                    AND COALESCE(c.is_current, true) \
                                    AND ($1::uuid IS NULL OR c.theme_id = $1::uuid) \
                                    /* {{VISIBILITY:ev}} */ /* {{VISIBILITY:c}} */) d \
                          WHERE d.host IS NOT NULL AND length(d.host) BETWEEN 1 AND 253 \
                          GROUP BY d.host) s \
                  {PAGE_TAIL}"
            ),
            5,
        );
        type Row = (String, i64);
        let mut q = sqlx::query_as::<_, Row>(&sql)
            .bind(theme_id)
            .bind(resume.map(|(n, _)| n))
            .bind(resume.map(|(_, k)| k))
            .bind(cap);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<Row> = q.fetch_all(&mut *conn).await?;
        Ok(rows
            .into_iter()
            .map(|(host, n)| SourceEntry {
                kind: SourceKind::Web,
                key: host.clone(),
                claim_count: n,
                detail: SourceDetail::Web { domain: host },
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{SourceCursor, SourceKind};

    #[test]
    fn a_cursor_round_trips_and_refuses_anything_else() {
        for (kind, key) in [
            (SourceKind::Paper, "6f1c2a34-0000-4000-8000-000000000001"),
            (SourceKind::Agent, "6f1c2a34-0000-4000-8000-000000000002"),
            (SourceKind::Web, "example.org"),
        ] {
            let c = SourceCursor {
                kind,
                claim_count: 7,
                key: key.to_string(),
            };
            assert_eq!(SourceCursor::decode(&c.encode()), Some(c));
        }
        for bad in [
            "",
            "so1",
            "so1.paper.7",
            "so1.book.7.6162",
            "so1.paper.0.6162",
            "so1.paper.x.6162",
            "so1.paper.7.zz",
            "so1.paper.7.",
            "so1.paper.7.6162.extra",
            "so2.paper.7.6162",
        ] {
            assert_eq!(SourceCursor::decode(bad), None, "{bad}");
        }
    }
}
