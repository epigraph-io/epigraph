//! Paper entity repository.
//!
//! Papers are first-class graph nodes (entity_type = "paper") used by
//! hierarchical document ingestion. The `papers` table has a UNIQUE
//! constraint on `doi`, so re-ingestion of the same DOI returns the
//! existing paper id (get-or-create semantics) rather than creating a
//! second row. Re-ingestion is gated separately via the `processed_by`
//! edge with a `pipeline` property.

use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

#[derive(Debug, Clone)]
pub struct PaperRow {
    pub id: Uuid,
    pub doi: String,
    pub title: Option<String>,
    pub journal: Option<String>,
}

pub struct PaperRepository;

impl PaperRepository {
    /// Insert a paper, or return the existing id if the DOI already exists.
    ///
    /// On conflict (UNIQUE doi), updates `title` and `journal` to the
    /// provided values when non-null. Idempotent for repeat ingestion.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_or_create(
        pool: &PgPool,
        doi: &str,
        title: Option<&str>,
        journal: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO papers (doi, title, journal)
            VALUES ($1, $2, $3)
            ON CONFLICT (doi) DO UPDATE SET
                title = COALESCE(EXCLUDED.title, papers.title),
                journal = COALESCE(EXCLUDED.journal, papers.journal)
            RETURNING id
            "#,
            doi,
            title,
            journal,
        )
        .fetch_one(pool)
        .await?;
        Ok(row.id)
    }

    /// Find a paper by DOI. Returns `None` if no paper has this DOI.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn find_by_doi(pool: &PgPool, doi: &str) -> Result<Option<PaperRow>, DbError> {
        // Use `as "title?"` to override sqlx introspection: the migration
        // declares `title` nullable; the dev DB has historical NOT NULL drift.
        let row = sqlx::query!(
            r#"
            SELECT id, doi, title as "title?", journal
            FROM papers
            WHERE doi = $1
            "#,
            doi
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|r| PaperRow {
            id: r.id,
            doi: r.doi,
            title: r.title,
            journal: r.journal,
        }))
    }

    /// Returns true if the paper has any outgoing `processed_by` edge whose
    /// `properties.pipeline` matches `pipeline_version`. Used as the
    /// re-ingestion version gate by hierarchical ingestion.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn has_processed_by_edge<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        pipeline_version: &str,
    ) -> Result<bool, DbError> {
        // MACRO SITE — the static three-bind spelling; `sqlx::query!` cannot be
        // spliced. See `ClaimRepository::get_by_id`.
        let row = sqlx::query!(
            r#"
            SELECT 1 AS exists_marker
            FROM edges
            WHERE source_id = $1
              AND source_type = 'paper'
              AND relationship = 'processed_by'
              AND properties ->> 'pipeline' = $2
              AND ($3::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($4::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($4::uuid[]))))
            LIMIT 1
            "#,
            paper_id,
            pipeline_version,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_optional(executor)
        .await?;
        Ok(row.is_some())
    }

    /// Every pipeline stamp in the `base` FAMILY that a visible `processed_by`
    /// edge from `paper_id` carries: `base` itself and each chunked
    /// `base:ch{n}` stamp, sorted.
    ///
    /// Backlog 02653c4a (G8). The ingest tools stamp `processed_by` with
    /// `ingestion.rs::effective_pipeline_version`, which appends `:ch{n}` for a
    /// chunked (per-chapter) ingest. A pre-flight that asks only for the bare
    /// `base` stamp therefore reported `already_ingested: false` for a document
    /// ingested chapter by chapter. This is the read that answers "has ANY
    /// ingest of this document at this pipeline landed, and which?".
    ///
    /// Deliberately NOT a replacement for [`Self::has_processed_by_edge`]: an
    /// exact-stamp check is how a caller asks about ONE chunk, and a family
    /// match would let chapter 1's stamp answer for chapter 2. Each chunk
    /// writes its own stamp
    /// ([`crate::EdgeRepository::create_processed_by_stamp_if_absent_conn`]),
    /// so both reads see every chunk that landed.
    ///
    /// `starts_with`, not `LIKE`: the stamp contains `_`, a `LIKE` wildcard.
    /// Edge visibility is the co-owner-aware `EDGE_VISIBILITY` predicate.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn processed_by_pipelines_in_family<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        base: &str,
    ) -> Result<Vec<String>, DbError> {
        let sql = viewer.splice(
            "SELECT DISTINCT e.properties ->> 'pipeline' AS pipeline \
             FROM edges e \
             WHERE e.source_id = $1 \
               AND e.source_type = 'paper' \
               AND e.relationship = 'processed_by' \
               AND (e.properties ->> 'pipeline' = $2 \
                    OR starts_with(e.properties ->> 'pipeline', $2 || ':ch')) \
               /* {EDGE_VISIBILITY:e} */ \
             ORDER BY 1",
            3,
        );
        let mut q = sqlx::query_scalar::<_, String>(&sql)
            .bind(paper_id)
            .bind(base);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Count the claims this paper asserts (`paper -asserts-> claim` edges).
    ///
    /// This alone under-counts a partially-ingested paper: `do_ingest_document`
    /// / `do_ingest_document_spine` label every claim `doi:<doi>` *before*
    /// writing that claim's `asserts` edge (evidence + reasoning-trace writes
    /// sit in between), so a crash or error mid-loop can leave claims with the
    /// doi label but no edge yet. Callers that need an accurate "has this DOI
    /// landed in the graph at all?" probe must combine this with
    /// [`Self::count_claims_by_doi_label`] (see `query_paper`) — trusting this
    /// alone as a duplicate-ingestion gate is the write-order race behind
    /// backlog 7c6ce1b3-b372-4727-a510-43e63001bf18 (the specific claims that
    /// prompted that report predate the `doi:<doi>` label entirely and were
    /// resolved separately by a full re-ingestion; this closes the gap for
    /// future partial ingestions under the current write order).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn count_asserted_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
    ) -> Result<i64, DbError> {
        // MACRO SITE — static three-bind spelling.
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "count!"
            FROM edges
            WHERE source_id = $1
              AND source_type = 'paper'
              AND target_type = 'claim'
              AND relationship = 'asserts'
              AND ($2::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($3::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($3::uuid[]))))
            "#,
            paper_id,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_one(executor)
        .await?;
        Ok(row.count)
    }

    /// Count current claims labelled `doi:<doi>`, independent of whether a
    /// `paper -asserts-> claim` edge exists yet for them.
    ///
    /// Every claim written by `do_ingest_document` / `do_ingest_document_spine`
    /// picks up this label as soon as the claim row itself is created — ahead
    /// of the `asserts` edge, which lands only after evidence + reasoning-trace
    /// writes succeed. This makes the label a more direct "does this DOI have
    /// node presence in the graph?" signal than the edge-based count, and is
    /// what `query_paper` uses to avoid mis-reporting `claim_count=0` for a
    /// paper that was partially ingested.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn count_claims_by_doi_label<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        doi: &str,
    ) -> Result<i64, DbError> {
        let label = format!("doi:{doi}");
        // MACRO SITE — static three-bind spelling. A count is still a
        // disclosure: it says how much of a DOI landed in a tenant the caller
        // cannot read.
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "count!"
            FROM claims
            WHERE is_current
              AND labels @> ARRAY[$1]::text[]
              AND ($2::bool OR visibility = 'public' OR owner_group_id = ANY($3::uuid[]))
            "#,
            label,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_one(executor)
        .await?;
        Ok(row.count)
    }

    /// List the authors of a paper as `(agent_id, display_name)` pairs,
    /// resolved via `agent -authored-> paper` edges.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list_authors<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
    ) -> Result<Vec<(Uuid, Option<String>)>, DbError> {
        // MACRO SITE — static three-bind spelling.
        let rows = sqlx::query!(
            r#"
            SELECT a.id AS "id!", a.display_name
            FROM edges e
            JOIN agents a ON a.id = e.source_id
            WHERE e.target_id = $1
              AND e.target_type = 'paper'
              AND e.source_type = 'agent'
              AND e.relationship = 'authored'
              AND ($2::bool OR e.visibility = 'public'
                   OR (e.owner_group_id = ANY($3::uuid[])
                       AND (e.co_owner_group_id IS NULL
                            OR e.co_owner_group_id = ANY($3::uuid[]))))
            ORDER BY a.display_name NULLS LAST, a.id
            "#,
            paper_id,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;
        Ok(rows.into_iter().map(|r| (r.id, r.display_name)).collect())
    }

    /// List claim summaries asserted by this paper — one page of `limit` rows
    /// starting at `offset` — reached via `paper -asserts-> claim` edges.
    /// Ordered by claim `created_at` ascending (ingest order), with an `id`
    /// tiebreaker so `LIMIT`/`OFFSET` paging is stable across the many claims
    /// a single ingestion writes with an identical timestamp.
    ///
    /// Returns `(id, content, truth_value, agent_id, content_hash, created_at,
    /// is_current, supersedes)` per claim — the shape `query_paper` needs for
    /// `ClaimResponse`.
    ///
    /// There is deliberately NO `is_current` filter: a superseded claim the
    /// paper asserted is still on the page, and `query_paper`'s `has_more`
    /// ("a short page is the end of the set") is computed over exactly this
    /// row set. The row's real retirement state is projected instead, so the
    /// caller can report it rather than claim every asserted row is current
    /// (drain unit U008, backlog `1e6efd2d` residual).
    ///
    /// `offset` exists because `query_paper` previously hardcoded
    /// `limit = 100` with no way to reach claim 101, and the resulting
    /// single-shot response exceeded the MCP tool output token limit on dense
    /// paper subgraphs (backlog `0e6ec456`). Pair it with
    /// [`Self::count_asserted_claims`] so a caller can tell a full page from
    /// the end of the set.
    ///
    /// Uses the runtime `query_as` form (no compile-time `.sqlx` cache entry),
    /// so adding `OFFSET` needs no `cargo sqlx prepare`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list_asserted_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        paper_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AssertedClaimRow>, DbError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            content: String,
            truth_value: f64,
            agent_id: Uuid,
            content_hash: Vec<u8>,
            created_at: chrono::DateTime<chrono::Utc>,
            is_current: bool,
            supersedes: Option<Uuid>,
        }

        let rows: Vec<Row> = sqlx::query_as(
            r#"
            SELECT
                c.id,
                c.content,
                c.truth_value,
                c.agent_id,
                c.content_hash,
                c.created_at,
                COALESCE(c.is_current, true) AS is_current,
                c.supersedes
            FROM edges e
            JOIN claims c ON c.id = e.target_id
            WHERE e.source_id = $1
              AND e.source_type = 'paper'
              AND e.target_type = 'claim'
              AND e.relationship = 'asserts'
              AND ($4::bool OR e.visibility = 'public'
                   OR (e.owner_group_id = ANY($5::uuid[])
                       AND (e.co_owner_group_id IS NULL
                            OR e.co_owner_group_id = ANY($5::uuid[]))))
              AND ($4::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($5::uuid[]))
            ORDER BY c.created_at ASC, c.id
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(paper_id) // $1
        .bind(limit) // $2
        .bind(offset) // $3
        // The STATIC three-bind visibility form, not `splice`: both binds are
        // unconditional, so `OFFSET $3` can sit ahead of them without the
        // arity of this statement depending on the viewer's shape. Renumbered
        // from HEAD's $3/$4 because the branch's new `offset` took $3 — left
        // as-is the bypass flag and the page offset would have shared a
        // placeholder, which typechecks and silently pages by a boolean.
        .bind(viewer.bypass_bind()) // $4
        .bind(viewer.group_bind().unwrap_or(&[])) // $5
        .fetch_all(executor)
        .await?;
        rows.into_iter()
            .map(|r| {
                let content_hash: [u8; 32] =
                    r.content_hash
                        .as_slice()
                        .try_into()
                        .map_err(|_| DbError::InvalidData {
                            reason: format!(
                                "claim {} has content_hash of length {} (expected 32)",
                                r.id,
                                r.content_hash.len()
                            ),
                        })?;
                Ok(AssertedClaimRow {
                    id: r.id,
                    content: r.content,
                    truth_value: r.truth_value,
                    agent_id: r.agent_id,
                    content_hash,
                    created_at: r.created_at,
                    is_current: r.is_current,
                    supersedes: r.supersedes,
                })
            })
            .collect()
    }
}

/// Minimal claim shape returned by [`PaperRepository::list_asserted_claims`].
#[derive(Debug, Clone)]
pub struct AssertedClaimRow {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub agent_id: Uuid,
    pub content_hash: [u8; 32],
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The row's real retirement state (`COALESCE(is_current, true)`); the
    /// query does not filter on it.
    pub is_current: bool,
    /// The claim this one superseded, if any.
    pub supersedes: Option<Uuid>,
}

// =============================================================================
// THE PAPER DOCUMENT KEY (backlog 90756d26)
// =============================================================================
//
// `papers.doi` is the document identity key. Every writer and every reader of
// it, on every transport, goes through the two functions below: the MCP
// ingestion and paper-query tools (`epigraph-mcp` `tools/ingestion.rs`) and the
// REST paper routes (`epigraph-api` `routes/papers.rs`). Before they were
// shared, the REST routes stored and matched the caller's spelling verbatim, so
// `https://doi.org/10.x/y`, `doi:10.x/y` and `10.x/y` were three keys there and
// one key over MCP.
//
// Pure functions, no SQL: they live here because this module owns the column
// they key, and both transports already depend on this crate.
//
// Deliberately NOT the belief engine's `normalize_doi`
// (`epigraph-engine` `source_dependence.rs`): that one lowercases, which is
// right for a belief source key and wrong for this one (see
// [`canonical_document_key`]).

/// Resolver prefixes a caller may put in front of a DOI. Matched
/// case-insensitively; `doi:` also tolerates whitespace before the DOI.
pub const DOI_KEY_PREFIXES: [&str; 7] = [
    "https://doi.org/",
    "http://doi.org/",
    "https://dx.doi.org/",
    "http://dx.doi.org/",
    "https://www.doi.org/",
    "http://www.doi.org/",
    "doi:",
];

/// True for a bare DOI: `10.` + a 4-9 digit registrant + `/` + a non-empty
/// suffix.
#[must_use]
pub fn is_bare_doi(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("10.") else {
        return false;
    };
    let Some((registrant, suffix)) = rest.split_once('/') else {
        return false;
    };
    (4..=9).contains(&registrant.len())
        && registrant.bytes().all(|b| b.is_ascii_digit())
        && !suffix.trim().is_empty()
}

/// The canonical spelling of a document identity key: trimmed, with a DOI
/// resolver prefix (`https://doi.org/`, `dx.doi.org`, `doi:`, ...) removed
/// when what follows is a bare DOI. Anything else is returned trimmed and
/// otherwise unchanged. This is the spelling every writer stores.
///
/// NOT lowercased: DOIs are case-insensitive, but existing rows and their
/// `doi:<key>` labels carry the caller's case, and folding it would re-key
/// them.
#[must_use]
pub fn canonical_document_key(raw: &str) -> String {
    let t = raw.trim();
    for prefix in DOI_KEY_PREFIXES {
        let Some(head) = t.get(..prefix.len()) else {
            continue;
        };
        if head.eq_ignore_ascii_case(prefix) {
            let rest = t[prefix.len()..].trim_start();
            if is_bare_doi(rest) {
                return rest.to_string();
            }
        }
    }
    t.to_string()
}

/// Every stored spelling a lookup for `raw` must match, most preferred first:
/// the [`canonical_document_key`], then the key as given (trimmed), then, for
/// a bare DOI, each [`DOI_KEY_PREFIXES`] spelling of it. Distinct, in that
/// order.
///
/// The legacy spellings are what make a row written under a resolver URL
/// before keys were canonicalized findable by the bare DOI. They are
/// exact-match: a row keyed on a case variant of a prefix
/// (`HTTPS://DOI.ORG/...`) is found only as given.
#[must_use]
pub fn document_key_spellings(raw: &str) -> Vec<String> {
    let canonical = canonical_document_key(raw);
    let as_given = raw.trim().to_string();
    let bare = is_bare_doi(&canonical);
    let mut out = vec![canonical.clone()];
    if as_given != canonical {
        out.push(as_given);
    }
    if bare {
        for prefix in DOI_KEY_PREFIXES {
            let legacy = format!("{prefix}{canonical}");
            if !out.contains(&legacy) {
                out.push(legacy);
            }
        }
    }
    out
}

#[cfg(test)]
mod document_key_tests {
    use super::*;

    const BARE: &str = "10.1021/acsnano.9b05650";

    #[test]
    fn every_resolver_spelling_canonicalizes_to_the_bare_doi() {
        for raw in [
            "https://doi.org/10.1021/acsnano.9b05650",
            "http://dx.doi.org/10.1021/acsnano.9b05650",
            "HTTPS://WWW.DOI.ORG/10.1021/acsnano.9b05650",
            "doi:10.1021/acsnano.9b05650",
            "doi: 10.1021/acsnano.9b05650",
            "  10.1021/acsnano.9b05650  ",
        ] {
            assert_eq!(canonical_document_key(raw), BARE, "{raw:?}");
        }
    }

    #[test]
    fn non_doi_keys_are_kept_verbatim_but_trimmed() {
        for raw in [
            "https://doi.org/about",
            "https://doi.org/10.1021",
            "https://doi.org/10.12/short-registrant",
            "https://example.org/paper.pdf",
            "urn:epigraph:doc:some-title-abc",
        ] {
            assert_eq!(canonical_document_key(&format!(" {raw} ")), raw);
        }
    }

    #[test]
    fn spellings_put_the_canonical_key_first_and_cover_every_legacy_prefix() {
        let s = document_key_spellings("https://doi.org/10.1021/acsnano.9b05650");
        assert_eq!(s[0], BARE);
        for prefix in DOI_KEY_PREFIXES {
            let legacy = format!("{prefix}{BARE}");
            assert_eq!(
                s.iter().filter(|x| **x == legacy).count(),
                1,
                "{legacy} exactly once in {s:?}"
            );
        }
        assert_eq!(s.len(), 1 + DOI_KEY_PREFIXES.len(), "{s:?}");
    }

    #[test]
    fn a_case_variant_prefix_is_matched_as_given_too() {
        let raw = "HTTPS://DOI.ORG/10.1021/acsnano.9b05650";
        let s = document_key_spellings(raw);
        assert_eq!(s[0], BARE);
        assert_eq!(s[1], raw);
    }

    #[test]
    fn a_non_doi_key_has_exactly_one_spelling() {
        assert_eq!(
            document_key_spellings("https://doi.org/about"),
            vec!["https://doi.org/about".to_string()]
        );
    }
}
