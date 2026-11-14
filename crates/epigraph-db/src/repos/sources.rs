//! Who said what across a scope: the sources of the caller's readable,
//! current claims, grouped by kind (`GET /api/v1/sources/overview`).
//!
//! A claim is counted under every source that stated it, each source once:
//!
//! * **`paper`**: a paper whose ingest-written, in-force `paper -asserts->
//!   claim` edge onto it the caller can read (key: the paper id). Only the
//!   document ingest writes that edge (`crate::ingest_written`), so a
//!   hand-written edge of the same shape credits no paper.
//! * **`web`**: the host of a readable evidence row's `source_url` (key: the
//!   lower-cased host, port and a leading `www.` dropped). Evidence without a
//!   URL, or with one that names no host, counts nowhere.
//! * **`agent`**: the filer (`claims.agent_id`) of a claim NO readable paper
//!   asserts: a claim filed directly. A claim whose only paper assertion the
//!   caller cannot read is the filer's for that caller, exactly as a claim's
//!   `authored_by` block falls back to the filer when the creating document is
//!   hidden; a reader of the assertion sees it under the paper instead.
//!
//! Every count is the caller's: the claim, the assertion and the evidence are
//! each under their own row's visibility, so a row the caller cannot read is
//! counted nowhere, and a count says nothing about a tenant it cannot read.
//!
//! Ordered by `(claim_count DESC, kind, key)`, a total order (a key is unique
//! within its kind), and paged by keyset ([`SourcesCursor`]). Counts are
//! computed per request, so a source whose count changes between two pages may
//! move across the boundary; the cursor never repeats a position it passed.
//!
//! Without a `theme_id` the overview aggregates EVERY readable current claim
//! on each page request (the grouping cannot be cut off before the `LIMIT`),
//! so [`SourcesRepository::overview`] runs under its own `statement_timeout`
//! ([`SOURCES_OVERVIEW_STATEMENT_TIMEOUT`] from the route) and puts the
//! connection's previous value back on every exit. An overrun is a `57014
//! query_canceled` the route answers with a 503.

use std::time::Duration;

use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::edge::EDGE_IN_FORCE;
use crate::repos::ingest_written::ingest_written_edge_sql;
use crate::visibility::Viewer;

/// The source kinds, in their sort order.
pub const SOURCE_KINDS: &[&str] = &["agent", "paper", "web"];

/// Most sources one page returns.
pub const MAX_SOURCES_PAGE: i64 = 200;

/// The bound on one overview statement. A placeholder until the unthemed
/// overview has been measured at production scale: the API's scoped pool
/// sets no pool-wide `statement_timeout`, so without this an unthemed request
/// in a loop is an unbounded aggregation of the corpus per call.
pub const SOURCES_OVERVIEW_STATEMENT_TIMEOUT: Duration = Duration::from_secs(10);

/// A keyset position in the overview's `(claim_count DESC, kind, key)`
/// order: the last row of the previous page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcesCursor {
    pub claim_count: i64,
    pub kind: String,
    pub key: String,
}

const SOURCES_CURSOR_PREFIX: &str = "s1.";

impl SourcesCursor {
    /// The opaque token: `s1.<count>.<kind>.<hex of key>`. URL-safe.
    #[must_use]
    pub fn encode(&self) -> String {
        let hex: String = self.key.bytes().map(|b| format!("{b:02x}")).collect();
        format!(
            "{SOURCES_CURSOR_PREFIX}{}.{}.{hex}",
            self.claim_count, self.kind
        )
    }

    /// Parse a token from [`Self::encode`]; `None` for anything else.
    #[must_use]
    pub fn decode(token: &str) -> Option<Self> {
        let rest = token.strip_prefix(SOURCES_CURSOR_PREFIX)?;
        let mut parts = rest.splitn(3, '.');
        let claim_count: i64 = parts.next()?.parse().ok()?;
        let kind = parts.next()?;
        let hex = parts.next()?;
        if claim_count < 0 || !SOURCE_KINDS.contains(&kind) || hex.len() % 2 != 0 {
            return None;
        }
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        Some(Self {
            claim_count,
            kind: kind.to_string(),
            key: String::from_utf8(bytes).ok()?,
        })
    }
}

/// What the overview covers.
#[derive(Debug, Clone, Default)]
pub struct SourcesQuery<'a> {
    /// Only claims in this theme.
    pub theme_id: Option<Uuid>,
    /// Only these kinds (each one of [`SOURCE_KINDS`]); `None` for all.
    pub kinds: Option<&'a [String]>,
    /// Start strictly after this position.
    pub after: Option<SourcesCursor>,
    /// Page size, clamped to `1..=MAX_SOURCES_PAGE`.
    pub limit: i64,
}

/// One source of the overview.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct SourceRow {
    /// `paper`, `web` or `agent`.
    pub kind: String,
    /// The paper id, the host, or the agent id, as text.
    pub key: String,
    /// The caller's readable current claims this source stated.
    pub claim_count: i64,
    /// For a paper: its document key (`papers.doi`).
    pub doi: Option<String>,
    /// For a paper: its title.
    pub title: Option<String>,
    /// For an agent: its display name (`agents` is readable by every
    /// session).
    pub display_name: Option<String>,
}

pub struct SourcesRepository;

impl SourcesRepository {
    /// One page of the overview (module doc) as `viewer` sees it, plus
    /// whether more sources follow. A paper row carries its document key and
    /// title, an agent row its display name (`papers` and `agents` carry no
    /// row security; only the sources this page lists are joined).
    ///
    /// The statement runs under `statement_timeout` (at least 1 ms: a zero
    /// would DISABLE the bound), and the connection's previous
    /// `statement_timeout` is restored on every exit, the error ones
    /// included, before the result is returned. On a transaction-mode
    /// connection a timed-out statement aborts the transaction, the restore
    /// then fails too, and the original error is the one returned (the
    /// rollback on drop undoes the `SET` with everything else).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails, including
    /// `57014 query_canceled` when `statement_timeout` is exceeded.
    pub async fn overview(
        conn: &mut PgConnection,
        viewer: &Viewer,
        query: &SourcesQuery<'_>,
        statement_timeout: Duration,
    ) -> Result<(Vec<SourceRow>, bool), DbError> {
        let previous = crate::pool::read_statement_timeout(conn)
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        crate::pool::apply_statement_timeout(conn, statement_timeout.max(Duration::from_millis(1)))
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        let page = Self::overview_page(&mut *conn, viewer, query).await;
        // Restored BEFORE the `?` on `page`, so a timeout leaves the
        // connection as it was found.
        let restored = crate::pool::restore_statement_timeout(conn, &previous).await;
        let page = page?;
        restored.map_err(|source| DbError::QueryFailed { source })?;
        Ok(page)
    }

    /// The overview's one statement, unbounded: [`Self::overview`] is its
    /// only caller.
    async fn overview_page(
        conn: &mut PgConnection,
        viewer: &Viewer,
        query: &SourcesQuery<'_>,
    ) -> Result<(Vec<SourceRow>, bool), DbError> {
        let limit = query.limit.clamp(1, MAX_SOURCES_PAGE);
        let in_force = |alias: &str| EDGE_IN_FORCE.replace("e.", &format!("{alias}."));
        let sql = viewer.splice(
            &format!(
                "WITH vc AS ( \
                     SELECT c.id, c.agent_id FROM claims c \
                      WHERE c.is_current \
                        AND ($1::uuid IS NULL OR c.theme_id = $1) \
                        /* {{VISIBILITY:c}} */), \
                 src AS ( \
                     SELECT 'paper'::text AS kind, e.source_id::text AS key, \
                            COUNT(DISTINCT vc.id) AS claim_count \
                       FROM vc JOIN edges e ON e.target_id = vc.id \
                      WHERE ($2::text[] IS NULL OR 'paper' = ANY($2)) \
                        AND e.source_type = 'paper' AND e.target_type = 'claim' \
                        AND e.relationship = 'asserts' \
                        AND {in_force_e} AND {marked_e} \
                        /* {{EDGE_VISIBILITY:e}} */ \
                      GROUP BY e.source_id \
                     UNION ALL \
                     SELECT 'web'::text, d.host, COUNT(DISTINCT d.claim_id) \
                       FROM (SELECT ev.claim_id, \
                                    regexp_replace(lower(substring(ev.source_url \
                                        FROM '^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#@]*@)?([^/?#:]+)')), \
                                        '^www\\.', '') AS host \
                               FROM vc JOIN evidence ev ON ev.claim_id = vc.id \
                              WHERE ($2::text[] IS NULL OR 'web' = ANY($2)) \
                                AND ev.source_url IS NOT NULL \
                                /* {{VISIBILITY:ev}} */) d \
                      WHERE d.host IS NOT NULL AND d.host <> '' \
                      GROUP BY d.host \
                     UNION ALL \
                     SELECT 'agent'::text, vc.agent_id::text, COUNT(*) \
                       FROM vc \
                      WHERE ($2::text[] IS NULL OR 'agent' = ANY($2)) \
                        AND NOT EXISTS ( \
                            SELECT 1 FROM edges pe \
                             WHERE pe.target_id = vc.id \
                               AND pe.source_type = 'paper' AND pe.target_type = 'claim' \
                               AND pe.relationship = 'asserts' \
                               AND {in_force_pe} AND {marked_pe} \
                               /* {{EDGE_VISIBILITY:pe}} */) \
                      GROUP BY vc.agent_id), \
                 page AS ( \
                     SELECT kind, key, claim_count FROM src \
                      WHERE $3::bigint IS NULL \
                         OR claim_count < $3 \
                         OR (claim_count = $3 AND (kind, key) > ($4::text, $5::text)) \
                      ORDER BY claim_count DESC, kind, key \
                      LIMIT $6) \
                 SELECT page.kind, page.key, page.claim_count, \
                        p.doi, p.title, a.display_name \
                   FROM page \
                   LEFT JOIN papers p ON page.kind = 'paper' AND p.id::text = page.key \
                   LEFT JOIN agents a ON page.kind = 'agent' AND a.id::text = page.key \
                  ORDER BY page.claim_count DESC, page.kind, page.key",
                in_force_e = in_force("e"),
                marked_e = ingest_written_edge_sql("e"),
                in_force_pe = in_force("pe"),
                marked_pe = ingest_written_edge_sql("pe"),
            ),
            7,
        );
        let mut q = sqlx::query_as::<_, SourceRow>(&sql)
            .bind(query.theme_id)
            .bind(query.kinds.map(<[String]>::to_vec))
            .bind(query.after.as_ref().map(|a| a.claim_count))
            .bind(query.after.as_ref().map(|a| a.kind.clone()))
            .bind(query.after.as_ref().map(|a| a.key.clone()))
            .bind(limit + 1);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let mut rows = q.fetch_all(conn).await?;
        let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
        rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok((rows, more))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_round_trips_any_key_and_refuses_anything_else() {
        let c = SourcesCursor {
            claim_count: 7,
            kind: "web".to_string(),
            key: "example.org/ä.b".to_string(),
        };
        let t = c.encode();
        assert!(
            t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'),
            "{t}"
        );
        assert_eq!(SourcesCursor::decode(&t), Some(c));
        for bad in [
            "",
            "s1.",
            "s1.x.web.00",
            "s1.-1.web.00",
            "s1.3.book.00",
            "s1.3.web.0",
            "s1.3.web.zz",
            "s1.3.web.ff",
            "k1.3.web.00",
        ] {
            assert_eq!(SourcesCursor::decode(bad), None, "{bad}");
        }
    }
}
