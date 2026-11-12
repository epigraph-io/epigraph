//! Claim theme persistence for hierarchical retrieval.
//! Themes are topic clusters; each claim belongs to at most one theme.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimThemeRow {
    pub id: Uuid,
    pub label: String,
    pub description: String,
    pub claim_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Read-path projection of a theme: everything a caller needs to decide
/// whether to open it, without writing anything.
///
/// Deliberately a SEPARATE struct from [`ClaimThemeRow`] rather than extra
/// fields on it. `sqlx::FromRow` resolves columns by name at RUNTIME, so
/// adding `member_count` / `centroid_dim` to `ClaimThemeRow` would make every
/// existing `query_as::<_, ClaimThemeRow>` whose SELECT omits them fail when
/// executed, not when compiled — the same hazard documented on `ClaimRow` in
/// `claim.rs::list_by_belief_range`.
///
/// ## `member_count` vs `stored_claim_count`
///
/// `stored_claim_count` is the denormalised `claim_themes.claim_count` column.
/// It is **not maintained** by the assignment writers: `assign_claim`,
/// `bulk_assign` and `unassign_claim` all write `claims.theme_id` and never
/// touch it; only [`ClaimThemeRepository::update_count`] does, and only the
/// `create-with-centroid` route calls that (the retired k-means prototype was
/// the other caller). `member_count` is the live
/// `COUNT(*) FROM claims WHERE theme_id = t.id AND is_current` and is the
/// authoritative figure. The two are both reported so a caller (or an
/// operator auditing drift) can see the divergence instead of silently
/// trusting a stale number.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ThemeSummaryRow {
    pub id: Uuid,
    pub label: String,
    pub description: String,
    /// Denormalised `claim_themes.claim_count` — stale by construction.
    pub stored_claim_count: i32,
    /// Live count of `is_current` claims assigned to this theme.
    pub member_count: i64,
    /// Derived from which centroid column is populated: `3072`, `1536`, or
    /// `None` when the theme has no centroid at all (created but never
    /// fitted). `claim_themes` has no `centroid_dim` column.
    pub centroid_dim: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One member of a theme, as returned by
/// [`ClaimThemeRepository::member_claim_ids`]. Carries no `content` — see
/// that method's docstring for why.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ThemeMemberRow {
    pub claim_id: Uuid,
    pub truth_value: f64,
    pub created_at: DateTime<Utc>,
}

/// Most themes one [`ClaimThemeRepository::overview_page`] call returns. The
/// HTTP handler clamps `limit` to it, and the repo clamps again so a direct
/// caller cannot exceed it.
pub const THEME_OVERVIEW_PAGE_MAX: i64 = 200;

/// One theme of [`ClaimThemeRepository::overview_page`]: a theme the viewer can
/// read at least one current member of, with that count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemeOverviewRow {
    pub id: Uuid,
    /// Stored label. NOT viewer-derived: for a theme with members the viewer
    /// cannot read it may summarise their text (the theme scripts that name
    /// themes and clusters sample members with no visibility predicate,
    /// except claims the bug-report intake group owns, which none of them
    /// samples: `scripts/theme_lib.py::not_intake_owned` lists every such
    /// path; the label residual on `D-PR16-theme-cluster-viewer-scope`). Cut
    /// to 200 characters.
    pub label: String,
    /// Current claims assigned to this theme that the viewer can read. `>= 1`.
    pub member_count: i64,
}

/// One page of [`ClaimThemeRepository::overview_page`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemeOverviewPage {
    pub themes: Vec<ThemeOverviewRow>,
    /// Themes with at least one member this viewer can read (all pages).
    pub total: i64,
    /// Position after the last row, when more rows follow.
    pub next: Option<ThemeOverviewCursor>,
}

/// Keyset position in the overview's `member_count DESC, id ASC` order.
///
/// Callers see it only as the opaque token from [`Self::encode`], which
/// `GET /api/v1/graph/themes/overview` hands out as `next_cursor` and accepts
/// back as `after`. A forged token only moves the starting point of a read
/// that stays viewer-filtered: the keyset predicate is a pure position, so a
/// count or id that matches no row is not an existence signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThemeOverviewCursor {
    pub member_count: i64,
    pub id: Uuid,
}

/// Version prefix of [`ThemeOverviewCursor`]'s token, so a later format (or a
/// `LabelCursor`'s `k1.`) is refused rather than half-parsed.
const THEME_OVERVIEW_CURSOR_PREFIX: &str = "t1.";

impl ThemeOverviewCursor {
    /// The cursor of `row`, the last row of a page.
    #[must_use]
    pub const fn of(row: &ThemeOverviewRow) -> Self {
        Self {
            member_count: row.member_count,
            id: row.id,
        }
    }

    /// The opaque token: `t1.<member_count>.<id hex>`. URL-safe.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{THEME_OVERVIEW_CURSOR_PREFIX}{}.{}",
            self.member_count,
            self.id.simple()
        )
    }

    /// Parse a token from [`Self::encode`]. `None` for anything else,
    /// including a count below 1: no listed theme has fewer than one readable
    /// member, so such a token was not handed out.
    #[must_use]
    pub fn decode(token: &str) -> Option<Self> {
        let rest = token.strip_prefix(THEME_OVERVIEW_CURSOR_PREFIX)?;
        let (count, id) = rest.split_once('.')?;
        // `i64::from_str` accepts a leading `+`; the encoder never writes one.
        if !count.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let member_count: i64 = count.parse().ok()?;
        if member_count < 1 {
            return None;
        }
        let id = Uuid::try_parse(id).ok()?;
        Some(Self { member_count, id })
    }
}

/// Raw row of the overview statement. Private, and a separate struct rather
/// than fields bolted onto [`ThemeSummaryRow`]: `FromRow` resolves columns by
/// name at run time (the hazard documented on [`ThemeSummaryRow`]). `id`,
/// `label` and `member_count` are `NULL` on the empty-page sentinel row.
#[derive(sqlx::FromRow)]
struct ThemeOverviewSqlRow {
    total_themes: i64,
    id: Option<Uuid>,
    label: Option<String>,
    member_count: Option<i64>,
}

/// Treat a blank/whitespace-only `label_prefix` as "no filter".
///
/// `starts_with(label, '')` is true for every row, so an empty prefix is
/// already a no-op — normalising it to `NULL` just keeps the planner on the
/// unfiltered path and makes the intent explicit at the call site.
fn normalize_prefix(label_prefix: Option<&str>) -> Option<String> {
    label_prefix
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(ToString::to_string)
}

/// A claim flagged as potentially misplaced by cluster-level metrics.
#[derive(Debug, Clone)]
pub struct BoundaryClaimRow {
    pub claim_id: Uuid,
    pub theme_id: Option<Uuid>,
    pub boundary_ratio: f64,
    pub centroid_distance: f64,
    pub content_preview: String,
}

/// A theme that may need splitting due to high intra-cluster variance.
#[derive(Debug, Clone)]
pub struct SplitCandidateRow {
    pub theme_id: Uuid,
    pub label: String,
    pub claim_count: i32,
    pub avg_distance: f64,
    pub max_distance: f64,
}

/// A theme with distant assigned claims, suggesting a new theme may be needed.
#[derive(Debug, Clone)]
pub struct DistantClaimsRow {
    pub source_theme: String,
    pub distant_claims: i64,
    pub avg_distance: f64,
}

/// Result of a centroid recomputation for a single theme.
#[derive(Debug, Clone)]
pub struct RecomputedThemeRow {
    pub id: Uuid,
    pub label: String,
    pub claim_count: i32,
}

/// Validate `centroid_dim` and return the `(theme_centroid_col,
/// claim_embedding_col)` pair for the SQL builders below.
///
/// Returns `None` for unsupported dims. This is the *only* path by which a
/// pgvector column name reaches the dim-aware `format!`-interpolated SQL in
/// this module — keeping the mapping here means the layering test in
/// `epigraph-engine` does not need to know column names exist, while the
/// SQL stays injection-safe.
#[must_use]
pub fn centroid_columns_for_dim(centroid_dim: u32) -> Option<(&'static str, &'static str)> {
    match centroid_dim {
        1536 => Some(("centroid", "embedding")),
        3072 => Some(("centroid_3072", "embedding_3072")),
        _ => None,
    }
}

/// Theme membership of a query's nearest neighbourhood, measured by
/// [`ClaimThemeRepository::nearest_theme_coverage_since`].
///
/// The input to the diverse-retrieval coverage guard: diverse mode draws its
/// candidates ONLY from members of the themes it shortlisted, so if most of the
/// claims nearest a query are outside that shortlist (unthemed, or in a theme
/// that was not shortlisted), diverse mode cannot see them and should not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighbourhoodThemeCoverage {
    /// Rows the probe actually returned. At most the requested `k`, and fewer
    /// when the viewer can see fewer candidates, or when an approximate (HNSW)
    /// index scan returns a truncated candidate list — so a coverage fraction
    /// must be computed over THIS, never over the requested `k`.
    pub probed: i64,
    /// How many of the probed rows diverse mode could actually return: members
    /// of one of the shortlisted themes that also carry an embedding at the
    /// dimension diverse mode ranks by. A claim that is unthemed, in a theme
    /// outside the shortlist, or missing that embedding is unreachable and
    /// does not count.
    pub reachable: i64,
}

pub struct ClaimThemeRepository;

impl ClaimThemeRepository {
    /// Create a new theme (centroid stored separately via raw SQL for vector type)
    ///
    /// Executor-generic, like the other writes the HTTP `create-with-centroid`
    /// route makes, so a caller can put the theme row, its
    /// centroid and its claim assignment in ONE transaction. Written separately
    /// on a pool, a refused assignment left the theme row behind (batch H-a
    /// review: `claim_themes +1` with the call reported as failed).
    pub async fn create<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        label: &str,
        description: &str,
    ) -> Result<ClaimThemeRow, DbError> {
        let row = sqlx::query_as::<_, ClaimThemeRow>(
            "INSERT INTO claim_themes (label, description) VALUES ($1, $2) \
             RETURNING id, label, description, claim_count, created_at, updated_at",
        )
        .bind(label)
        .bind(description)
        .fetch_one(executor)
        .await
        .map_err(DbError::from)?;
        Ok(row)
    }

    /// Store the centroid vector for a theme.
    /// `centroid_pgvec` is a pgvector string literal, e.g. "[0.1,0.2,...]"
    pub async fn set_centroid<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        theme_id: Uuid,
        centroid_pgvec: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE claim_themes SET centroid = $2::vector, updated_at = NOW() WHERE id = $1",
        )
        .bind(theme_id)
        .bind(centroid_pgvec)
        .execute(executor)
        .await
        .map_err(DbError::from)?;
        Ok(())
    }

    /// Set a theme's centroid to the mean of the given claims' 1536-d
    /// embeddings, computed in the database.
    ///
    /// # Why this exists
    ///
    /// `scripts/maintain_themes.py` used to compute sub-theme centroids
    /// client-side from the raw vectors `GET /themes/:id/embeddings` handed
    /// back. PR-07 stops that endpoint disclosing raw vectors (plan §4.9 row
    /// 4), so the averaging moves here — the server already holds the vectors,
    /// and this is the only remaining reason a caller needed them.
    ///
    /// The read is viewer-filtered: a centroid is an aggregate *of claim
    /// content*, so averaging rows the caller cannot see would leak their
    /// position in embedding space. `Bypass` viewers average everything, which
    /// is what a maintenance job wants.
    ///
    /// Returns the number of claims that contributed. Zero means no visible
    /// claim in `claim_ids` had an embedding, and the centroid is left unset
    /// rather than written as NULL.
    pub async fn set_centroid_from_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        theme_id: Uuid,
        claim_ids: &[Uuid],
    ) -> Result<i64, DbError> {
        let sql = viewer.splice(
            "UPDATE claim_themes t \
             SET centroid = agg.centroid, updated_at = NOW() \
             FROM ( \
                 SELECT AVG(c.embedding)::vector AS centroid, COUNT(*) AS n \
                 FROM claims c \
                 WHERE c.id = ANY($2) AND c.embedding IS NOT NULL \
                   /* {VISIBILITY:c} */ \
             ) agg \
             WHERE t.id = $1 AND agg.n > 0 \
             RETURNING agg.n",
            3,
        );
        let mut q = sqlx::query_scalar::<_, i64>(&sql)
            .bind(theme_id)
            .bind(claim_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let n = q.fetch_optional(executor).await.map_err(DbError::from)?;
        Ok(n.unwrap_or(0))
    }

    /// Assign a single claim to a theme
    pub async fn assign_claim(
        pool: &PgPool,
        claim_id: Uuid,
        theme_id: Uuid,
    ) -> Result<(), DbError> {
        sqlx::query("UPDATE claims SET theme_id = $2, updated_at = NOW() WHERE id = $1")
            .bind(claim_id)
            .bind(theme_id)
            .execute(pool)
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    /// Bulk assign a slice of claims to a theme
    ///
    /// An `UPDATE claims`, so `claims_tenancy`'s `WITH CHECK` governs it: on an
    /// unstamped session it is refused (`42501`) for any row it can see.
    pub async fn bulk_assign<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        claim_ids: &[Uuid],
        theme_id: Uuid,
    ) -> Result<u64, DbError> {
        let result =
            sqlx::query("UPDATE claims SET theme_id = $2, updated_at = NOW() WHERE id = ANY($1)")
                .bind(claim_ids)
                .bind(theme_id)
                .execute(executor)
                .await
                .map_err(DbError::from)?;
        Ok(result.rows_affected())
    }

    /// Update the denormalized claim count for a theme
    pub async fn update_count<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        theme_id: Uuid,
        count: i32,
    ) -> Result<(), DbError> {
        sqlx::query("UPDATE claim_themes SET claim_count = $2, updated_at = NOW() WHERE id = $1")
            .bind(theme_id)
            .bind(count)
            .execute(executor)
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    /// List all themes ordered by claim_count DESC
    pub async fn list(pool: &PgPool) -> Result<Vec<ClaimThemeRow>, DbError> {
        let rows = sqlx::query_as::<_, ClaimThemeRow>(
            "SELECT id, label, description, claim_count, created_at, updated_at \
             FROM claim_themes ORDER BY claim_count DESC",
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;
        Ok(rows)
    }

    /// Paged theme summaries for the READ path, newest-first by live member
    /// count. `label_prefix` filters on `starts_with(label, prefix)`; `None`
    /// (or an empty string) means no filter.
    ///
    /// See [`ThemeSummaryRow`] for why this does not reuse [`Self::list`]:
    /// `list` reports the denormalised `claim_count`, which the assignment
    /// writers do not maintain.
    ///
    /// Ordering is `member_count DESC, label ASC, id ASC`. The `id` tiebreaker
    /// is load-bearing, not cosmetic: `label` carries no UNIQUE constraint, so
    /// without it two same-label themes could swap places between two pages of
    /// the same walk and a caller would see one twice and the other never.
    /// `member_count` is an aggregate over `claims`, so it is viewer-filtered:
    /// an unfiltered count is an exact cardinality oracle over rows the caller
    /// may not read, and it also drives `ORDER BY`, which would leak the
    /// relative sizes of invisible partitions. `claim_themes` itself is NOT a
    /// tenancy table (migration 062's `tier_a` does not list it), so the theme
    /// ROWS are corpus-wide by design and only the counts narrow — which is
    /// what keeps this consistent with [`Self::count_summaries`].
    pub async fn list_summaries<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        label_prefix: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ThemeSummaryRow>, DbError> {
        let prefix = normalize_prefix(label_prefix);
        let sql = viewer.splice(
            "SELECT t.id, t.label, t.description, \
                    t.claim_count AS stored_claim_count, \
                    COALESCE(m.member_count, 0)::int8 AS member_count, \
                    CASE WHEN t.centroid_3072 IS NOT NULL THEN 3072 \
                         WHEN t.centroid IS NOT NULL THEN 1536 \
                         ELSE NULL END::int4 AS centroid_dim, \
                    t.created_at, t.updated_at \
             FROM claim_themes t \
             LEFT JOIN LATERAL ( \
                 SELECT COUNT(*) AS member_count FROM claims c \
                 WHERE c.theme_id = t.id AND COALESCE(c.is_current, true) \
                   /* {VISIBILITY:c} */ \
             ) m ON TRUE \
             WHERE ($1::text IS NULL OR starts_with(t.label, $1::text)) \
             ORDER BY member_count DESC, t.label ASC, t.id ASC \
             LIMIT $2 OFFSET $3",
            4,
        );
        let mut q = sqlx::query_as::<_, ThemeSummaryRow>(&sql)
            .bind(prefix.as_deref()) // $1
            .bind(limit) // $2
            .bind(offset); // $3
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g); // $4
        }
        let rows = q.fetch_all(executor).await.map_err(DbError::from)?;
        Ok(rows)
    }

    /// Total themes matching the same `label_prefix` predicate
    /// [`Self::list_summaries`] applies, so a caller can tell a short page
    /// from the end of the list.
    ///
    /// Takes NO `&Viewer`, and that is what keeps it CONSISTENT with its
    /// paging twin rather than inconsistent with it. This counts `claim_themes`
    /// rows and touches `claims` not at all; `claim_themes` is absent from
    /// migration 062's `tier_a`, so it carries neither `visibility` nor
    /// `owner_group_id` and there is no predicate to write. `list_summaries`
    /// filters only the member COUNT it projects, never which theme rows it
    /// returns, so both halves still describe the same population of themes.
    pub async fn count_summaries(
        pool: &PgPool,
        label_prefix: Option<&str>,
    ) -> Result<i64, DbError> {
        let prefix = normalize_prefix(label_prefix);
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::int8 FROM claim_themes t \
             WHERE ($1::text IS NULL OR starts_with(t.label, $1::text))",
        )
        .bind(prefix.as_deref())
        .fetch_one(pool)
        .await
        .map_err(DbError::from)?;
        Ok(count)
    }

    /// Single theme summary by id. `None` when no such theme exists — the
    /// caller decides whether that is a 404 or a silent skip.
    /// `member_count` is viewer-filtered for the reason given on
    /// [`Self::list_summaries`]; the theme row itself is not a tenancy row.
    ///
    /// Generic over [`sqlx::PgExecutor`] so a caller holding a viewer-stamped
    /// connection (`routes/search.rs::semantic_search`'s theme pin) runs it on
    /// that connection; `&PgPool` still satisfies the bound, so the MCP callers
    /// compile unchanged. The same widening PR-29 gave
    /// [`Self::find_similar_themes_at_dim`].
    ///
    /// `label` is derived from member content with no visibility filter (the
    /// labelling script samples the members nearest the stored centroid), so a
    /// caller that answers a viewer who may not read every member must not
    /// return it; the REST theme pin reads only `member_count`.
    pub async fn get_summary<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        theme_id: Uuid,
    ) -> Result<Option<ThemeSummaryRow>, DbError> {
        let sql = viewer.splice(
            "SELECT t.id, t.label, t.description, \
                    t.claim_count AS stored_claim_count, \
                    COALESCE(m.member_count, 0)::int8 AS member_count, \
                    CASE WHEN t.centroid_3072 IS NOT NULL THEN 3072 \
                         WHEN t.centroid IS NOT NULL THEN 1536 \
                         ELSE NULL END::int4 AS centroid_dim, \
                    t.created_at, t.updated_at \
             FROM claim_themes t \
             LEFT JOIN LATERAL ( \
                 SELECT COUNT(*) AS member_count FROM claims c \
                 WHERE c.theme_id = t.id AND COALESCE(c.is_current, true) \
                   /* {VISIBILITY:c} */ \
             ) m ON TRUE \
             WHERE t.id = $1",
            2,
        );
        let mut q = sqlx::query_as::<_, ThemeSummaryRow>(&sql).bind(theme_id); // $1
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g); // $2
        }
        let row = q.fetch_optional(executor).await.map_err(DbError::from)?;
        Ok(row)
    }

    /// Every theme carrying EXACTLY this label, oldest first.
    ///
    /// Returns a `Vec`, not an `Option`, on purpose: `claim_themes` has no
    /// `UNIQUE(label)` constraint, and the retired k-means tool's additive runs
    /// (`theme_cluster(wipe_first=false)`) left duplicate `auto-00` rows. A resolver that returned "the first match" would silently
    /// pick one of several distinct themes; callers must see the ambiguity and
    /// refuse rather than guess.
    pub async fn find_by_label(pool: &PgPool, label: &str) -> Result<Vec<Uuid>, DbError> {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM claim_themes WHERE label = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind(label)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;
        Ok(ids)
    }

    /// One page of a theme's member claims — **ids and metadata only, never
    /// `content`**.
    ///
    /// Withholding content is a deliberate scope decision, not an oversight:
    /// every content-returning read in this system runs the PRIVATE-visibility
    /// redaction pass (`batch_check_content_access` in
    /// `epigraph-mcp/src/tools/claims.rs`), and a membership listing that
    /// returned previews would be a second, unredacted content surface.
    /// Callers resolve ids through `get_claim`, which redacts.
    ///
    /// Restricted to `is_current` members so the count and the page agree with
    /// each other and with what the retrieval path can actually return
    /// (migration 052 forces `embedding IS NULL` on retired rows, so a retired
    /// member is unreachable by semantic recall anyway).
    ///
    /// Ordered `created_at ASC, id ASC` — the `id` tiebreaker makes the walk
    /// stable across pages for claims sharing a timestamp (bulk ingest writes
    /// many rows within the same microsecond).
    /// Viewer-filtered. Withholding `content` (see above) bounds the damage of
    /// an unfiltered read but does not remove it: claim IDs, truth values and
    /// timestamps for rows the caller cannot read are themselves a disclosure,
    /// and every id returned here is directly resolvable via `get_claim`.
    pub async fn member_claim_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        theme_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ThemeMemberRow>, DbError> {
        let sql = viewer.splice(
            "SELECT c.id AS claim_id, c.truth_value, c.created_at \
             FROM claims c \
             WHERE c.theme_id = $1 AND COALESCE(c.is_current, true) \
               /* {VISIBILITY:c} */ \
             ORDER BY c.created_at ASC, c.id ASC \
             LIMIT $2 OFFSET $3",
            4,
        );
        let mut q = sqlx::query_as::<_, ThemeMemberRow>(&sql)
            .bind(theme_id) // $1
            .bind(limit) // $2
            .bind(offset); // $3
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g); // $4
        }
        let rows = q.fetch_all(executor).await.map_err(DbError::from)?;
        Ok(rows)
    }

    /// Find themes whose centroids are most similar to the query vector.
    ///
    /// Returns `(theme_id, label, similarity)` tuples ordered by descending similarity.
    /// Uses the pgvector `<=>` cosine distance operator; similarity = 1 - distance.
    ///
    /// Legacy 1536d-only convenience over [`Self::find_similar_themes_at_dim`].
    /// New callers should use the dim-aware variant.
    pub async fn find_similar_themes(
        pool: &PgPool,
        query_vec: &str,
        limit: i32,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        Self::find_similar_themes_at_dim(pool, query_vec, limit, 1536).await
    }

    /// Dim-aware variant of [`Self::find_similar_themes`] for the diverse-retrieval
    /// pipeline.
    ///
    /// `centroid_dim` selects the pgvector column inside `claim_themes`:
    /// `1536` → `centroid`, `3072` → `centroid_3072`. Any other value returns
    /// `DbError::InvalidData` — the dim gate is the *only* path by which a
    /// column name is interpolated, which is what makes the `format!`-built
    /// SQL injection-safe.
    ///
    /// # Executor, and why this one takes no `Viewer`
    ///
    /// Generic over [`sqlx::PgExecutor`] so a caller holding a viewer-stamped
    /// connection can run this statement on it instead of the raw pool. PR-29
    /// widened it for `routes/search.rs::semantic_search`; `&PgPool` still
    /// satisfies the bound, so [`Self::find_similar_themes`] and the
    /// `epigraph-engine` wrapper compile unchanged.
    ///
    /// It takes no `&Viewer` because `claim_themes` carries no tenancy to filter
    /// on — see the `EXECUTOR_WITHOUT_VIEWER` entry in
    /// `epigraph-db/tests/visibility_lint.rs`, which records the measurement.
    pub async fn find_similar_themes_at_dim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        query_vec: &str,
        limit: i32,
        centroid_dim: u32,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        let (theme_col, _) =
            centroid_columns_for_dim(centroid_dim).ok_or_else(|| DbError::InvalidData {
                reason: format!("unsupported centroid_dim: {centroid_dim} (must be 1536 or 3072)"),
            })?;

        let sql = format!(
            "SELECT id, label, (1 - ({theme_col} <=> $1::vector))::float8 AS similarity \
             FROM claim_themes \
             WHERE {theme_col} IS NOT NULL \
             ORDER BY {theme_col} <=> $1::vector \
             LIMIT $2"
        );

        let rows = sqlx::query(&sql)
            .bind(query_vec)
            .bind(limit)
            .fetch_all(executor)
            .await
            .map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| {
                let id: Uuid = row.get("id");
                let label: String = row.get("label");
                let similarity: f64 = row.get("similarity");
                (id, label, similarity)
            })
            .collect();
        Ok(results)
    }

    /// Get claims within the specified themes, ranked by similarity to the query vector.
    ///
    /// Returns `(claim_id, content, similarity)` tuples ordered by descending similarity.
    ///
    /// Legacy 1536d-only convenience over [`Self::claims_in_themes_at_dim`].
    pub async fn claims_in_themes(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        theme_ids: &[Uuid],
        query_vec: &str,
        limit: i32,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        Self::claims_in_themes_at_dim(pool, viewer, theme_ids, query_vec, limit, 1536, false).await
    }

    /// Dim-aware variant of [`Self::claims_in_themes`].
    ///
    /// `centroid_dim` selects the per-claim embedding column: `1536` →
    /// `claims.embedding`, `3072` → `claims.embedding_3072`. Any other value
    /// returns `DbError::InvalidData`. The same dim gate that protects
    /// `find_similar_themes_at_dim` protects this method — column names
    /// reach the SQL only through the `1536|3072` match in
    /// [`centroid_columns_for_dim`], so the `format!`-interpolated string
    /// cannot carry user input.
    ///
    /// When `paragraph_only` is true, restricts to `level=2` claims (the
    /// hierarchical-paragraph level). MCP `recall_with_context` passed `true`
    /// until drain U082 made its seed the whole corpus; it and REST now both
    /// pass `false`.
    ///
    /// Retained at its original arity as a delegating wrapper over
    /// [`Self::claims_in_themes_at_dim_since`].
    ///
    /// The rationale that arity was retained FOR no longer applies, and saying
    /// so is cheaper than letting the next reader re-derive it: the REST
    /// `/api/v1/search/semantic?diverse=true` route used to reach this through
    /// `epigraph_engine::diverse_retrieval::candidates_in_themes_at_dim`, and
    /// PR-29 re-pointed it at [`Self::claims_in_themes_at_dim_since`] directly
    /// on a viewer-stamped connection. This method is still called — by
    /// [`Self::claims_in_themes`], the legacy 1536d convenience above — so it is
    /// not orphaned; only the REST justification is spent.
    pub async fn claims_in_themes_at_dim(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        theme_ids: &[Uuid],
        query_vec: &str,
        limit: i32,
        centroid_dim: u32,
        paragraph_only: bool,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        Self::claims_in_themes_at_dim_since(
            pool,
            viewer,
            theme_ids,
            query_vec,
            limit,
            centroid_dim,
            paragraph_only,
            None,
        )
        .await
    }

    /// [`Self::claims_in_themes_at_dim`] plus an optional
    /// `created_at >= since` window.
    ///
    /// This is the diverse-retrieval candidate source, and it bypasses
    /// `ClaimRepository::search_by_embedding` entirely — so a `since` wired
    /// only into the flat ANN would be silently ignored whenever
    /// `diverse=true`. That is precisely the bug class the existing
    /// `paper_doi_filter` `TODO(diverse-recall)` already exhibits on this
    /// path; the window must not become the second instance of it.
    #[allow(clippy::too_many_arguments)]
    pub async fn claims_in_themes_at_dim_since<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        theme_ids: &[Uuid],
        query_vec: &str,
        limit: i32,
        centroid_dim: u32,
        paragraph_only: bool,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        let (_, claim_col) =
            centroid_columns_for_dim(centroid_dim).ok_or_else(|| DbError::InvalidData {
                reason: format!("unsupported centroid_dim: {centroid_dim} (must be 1536 or 3072)"),
            })?;

        let level_clause = if paragraph_only {
            " AND (c.properties->>'level')::int = 2"
        } else {
            ""
        };

        let sql = format!(
            "SELECT c.id, c.content, (1 - (c.{claim_col} <=> $2::vector))::float8 AS similarity \
             FROM claims c \
             WHERE c.theme_id = ANY($1) \
               AND c.{claim_col} IS NOT NULL \
               AND ($4::timestamptz IS NULL OR c.created_at >= $4::timestamptz)\
               {level_clause} \
               /* {{VISIBILITY:c}} */ \
             ORDER BY c.{claim_col} <=> $2::vector \
             LIMIT $3"
        );
        // Doubled braces above: this is a `format!` template, so `{{` emits the
        // single brace `Viewer::splice` looks for.
        let sql = viewer.splice(&sql, 5);

        let mut vq = sqlx::query(&sql)
            .bind(theme_ids)
            .bind(query_vec)
            .bind(limit)
            .bind(since);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(executor).await.map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| {
                let id: Uuid = row.get("id");
                let content: String = row.get("content");
                let similarity: f64 = row.get("similarity");
                (id, content, similarity)
            })
            .collect();
        Ok(results)
    }

    /// Candidates for a PINNED diverse request: one theme's members,
    /// viewer-filtered, ranked by exact distance at `centroid_dim`.
    ///
    /// Exact because the member set is materialized before ordering: the
    /// `members` CTE is `MATERIALIZED` and carries no `ORDER BY`, so no HNSW
    /// scan (and its post-filter under-fill, which makes
    /// [`Self::claims_in_themes_at_dim_since`] lossy for a large theme at 1536)
    /// can serve it. `min_similarity` and `since` are applied in SQL, inside
    /// the candidate set and above the `LIMIT`.
    ///
    /// Returns `(claim_id, content, similarity)` ordered by descending
    /// similarity, ties broken by id. Reads no belief column. The column comes
    /// from [`centroid_columns_for_dim`], the only path by which a name reaches
    /// the `format!`-built SQL; any dim other than 1536 or 3072 is
    /// `DbError::InvalidData`.
    #[allow(clippy::too_many_arguments)]
    pub async fn claims_in_theme_exact_at_dim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        theme_id: Uuid,
        query_vec: &str,
        limit: i32,
        centroid_dim: u32,
        since: Option<DateTime<Utc>>,
        min_similarity: f64,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        let (_, claim_col) =
            centroid_columns_for_dim(centroid_dim).ok_or_else(|| DbError::InvalidData {
                reason: format!("unsupported centroid_dim: {centroid_dim} (must be 1536 or 3072)"),
            })?;

        let sql = format!(
            "WITH members AS MATERIALIZED ( \
                 SELECT c.id, (c.{claim_col} <=> $2::vector) AS dist \
                 FROM claims c \
                 WHERE c.theme_id = $1 \
                   AND c.{claim_col} IS NOT NULL \
                   AND ($4::timestamptz IS NULL OR c.created_at >= $4::timestamptz) \
                   /* {{VISIBILITY:c}} */ \
             ), \
             top AS ( \
                 SELECT id, dist FROM members \
                 WHERE 1 - dist >= $5 \
                 ORDER BY dist, id \
                 LIMIT $3 \
             ) \
             SELECT c.id, c.content, (1 - t.dist)::float8 AS similarity \
             FROM top t JOIN claims c ON c.id = t.id \
             WHERE c.{claim_col} IS NOT NULL /* {{VISIBILITY:c}} */ \
             ORDER BY t.dist, t.id"
        );
        // Doubled braces above: a `format!` template. Both markers bind `$6`.
        let sql = viewer.splice(&sql, 6);

        let mut vq = sqlx::query(&sql)
            .bind(theme_id) // $1
            .bind(query_vec) // $2
            .bind(limit) // $3
            .bind(since) // $4
            .bind(min_similarity); // $5
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g); // $6
        }
        let rows = vq.fetch_all(executor).await.map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| {
                let id: Uuid = row.get("id");
                let content: String = row.get("content");
                let similarity: f64 = row.get("similarity");
                (id, content, similarity)
            })
            .collect();
        Ok(results)
    }

    /// Measure how much of a query's nearest neighbourhood diverse mode can
    /// reach through its theme shortlist.
    ///
    /// Takes the `k` claims nearest `query_vec` in the candidate space
    /// [`Self::claims_in_themes_at_dim_since`] draws from — same
    /// `paragraph_only` level filter, same `since` window, same viewer
    /// predicate — but WITHOUT the theme restriction, and reports how many of
    /// them diverse mode could return: members of `shortlist` (the themes the
    /// theme lookup picked) that carry an embedding at `reachable_dim`, the
    /// dimension the candidate query ranks by. See
    /// [`NeighbourhoodThemeCoverage`].
    ///
    /// Counting shortlist membership, not membership in any theme, is
    /// deliberate: the candidate query is `theme_id = ANY(shortlist)`, so a
    /// neighbour that sits in a theme outside the shortlist is exactly as
    /// invisible to diverse mode as an unthemed one.
    ///
    /// `neighbourhood_dim` picks the embedding column the neighbourhood is
    /// ordered by. It may differ from `reachable_dim`: the REST route probes
    /// on the 1536-d column (which carries the ANN index; the 3072-d column
    /// has none, so ordering by it scans every row that has one) and checks
    /// 3072-d reachability per probed row. `query_vec` must be at
    /// `neighbourhood_dim`.
    ///
    /// Per-query rather than a corpus-wide ratio on purpose: a corpus can be
    /// mostly unthemed while a given query's neighbourhood is fully themed, and
    /// vice versa. It is also tenancy-neutral — it counts only rows the viewer
    /// can see — and data-independent (no stored statistic to go stale).
    ///
    /// Generic over [`sqlx::PgExecutor`] so the REST route can run it on its
    /// viewer-stamped connection, like the two theme reads above.
    #[allow(clippy::too_many_arguments)]
    pub async fn nearest_theme_coverage_since<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        query_vec: &str,
        neighbourhood_dim: u32,
        shortlist: &[Uuid],
        reachable_dim: u32,
        k: i32,
        paragraph_only: bool,
        since: Option<DateTime<Utc>>,
    ) -> Result<NeighbourhoodThemeCoverage, DbError> {
        let unsupported = |dim: u32| DbError::InvalidData {
            reason: format!("unsupported centroid_dim: {dim} (must be 1536 or 3072)"),
        };
        let (_, nn_col) = centroid_columns_for_dim(neighbourhood_dim)
            .ok_or_else(|| unsupported(neighbourhood_dim))?;
        let (_, reach_col) =
            centroid_columns_for_dim(reachable_dim).ok_or_else(|| unsupported(reachable_dim))?;

        let level_clause = if paragraph_only {
            " AND (c.properties->>'level')::int = 2"
        } else {
            ""
        };

        // The nearest-k subquery is ordered and limited BEFORE anything is
        // counted, so the reachability test cannot change which rows are
        // probed. An unthemed claim has a NULL theme_id, for which `= ANY`
        // yields NULL and the FILTER excludes it.
        let sql = format!(
            "SELECT COUNT(*)::int8 AS probed, \
                    COUNT(*) FILTER (WHERE nn.reachable)::int8 AS reachable \
             FROM ( \
                 SELECT (c.theme_id = ANY($4::uuid[]) AND c.{reach_col} IS NOT NULL) AS reachable \
                 FROM claims c \
                 WHERE c.{nn_col} IS NOT NULL \
                   AND ($3::timestamptz IS NULL OR c.created_at >= $3::timestamptz)\
                   {level_clause} \
                   /* {{VISIBILITY:c}} */ \
                 ORDER BY c.{nn_col} <=> $1::vector \
                 LIMIT $2 \
             ) nn"
        );
        let sql = viewer.splice(&sql, 5);

        let mut q = sqlx::query(&sql)
            .bind(query_vec)
            .bind(k)
            .bind(since)
            .bind(shortlist);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row = q.fetch_one(executor).await.map_err(DbError::from)?;
        Ok(NeighbourhoodThemeCoverage {
            probed: row.get("probed"),
            reachable: row.get("reachable"),
        })
    }

    /// Delete all themes and unassign all claims (for re-clustering).
    ///
    /// Returns the number of deleted theme rows.
    pub async fn delete_all(pool: &PgPool) -> Result<u64, DbError> {
        let mut tx = pool.begin().await.map_err(DbError::from)?;
        let n = Self::delete_all_conn(&mut tx).await?;
        tx.commit().await.map_err(DbError::from)?;
        Ok(n)
    }

    /// [`Self::delete_all`] on a connection the caller owns, so a re-cluster
    /// can wipe and rebuild in ONE transaction: a wipe that commits before a
    /// rebuild that fails leaves the corpus with no themes at all.
    pub async fn delete_all_conn(conn: &mut sqlx::PgConnection) -> Result<u64, DbError> {
        // Unassign claims first to satisfy the foreign-key constraint
        sqlx::query("UPDATE claims SET theme_id = NULL WHERE theme_id IS NOT NULL")
            .execute(&mut *conn)
            .await
            .map_err(DbError::from)?;

        let result = sqlx::query("DELETE FROM claim_themes")
            .execute(&mut *conn)
            .await
            .map_err(DbError::from)?;

        Ok(result.rows_affected())
    }

    /// Find claims with high boundary_ratio and centroid_distance from claim_clusters.
    ///
    /// These are candidates for theme reassignment — they sit on cluster boundaries
    /// and are far from their assigned centroid.
    pub async fn find_boundary_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        min_boundary_ratio: f64,
        min_centroid_distance: f64,
        limit: i64,
    ) -> Result<Vec<BoundaryClaimRow>, DbError> {
        let sql = viewer.splice(
            "SELECT cc.claim_id, c.theme_id, cc.boundary_ratio, cc.centroid_distance, \
                    LEFT(c.content, 120) AS content_preview \
             FROM claim_clusters cc \
             JOIN claims c ON c.id = cc.claim_id \
             WHERE cc.boundary_ratio > $1 \
               AND cc.centroid_distance > $2 \
               /* {VISIBILITY:c} */ /* {VISIBILITY:cc} */ \
             ORDER BY cc.boundary_ratio DESC \
             LIMIT $3",
            4,
        );
        let mut vq = sqlx::query(&sql)
            .bind(min_boundary_ratio)
            .bind(min_centroid_distance)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(executor).await.map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| BoundaryClaimRow {
                claim_id: row.get("claim_id"),
                theme_id: row.get("theme_id"),
                boundary_ratio: row.get("boundary_ratio"),
                centroid_distance: row.get("centroid_distance"),
                content_preview: row.get("content_preview"),
            })
            .collect();
        Ok(results)
    }

    /// Unassign a claim from its theme (set theme_id = NULL).
    ///
    /// Used when no existing theme is a good fit — the claim becomes an outlier
    /// that Phase 5 (detect new theme candidates) can pick up.
    pub async fn unassign_claim(pool: &PgPool, claim_id: Uuid) -> Result<(), DbError> {
        sqlx::query("UPDATE claims SET theme_id = NULL, updated_at = NOW() WHERE id = $1")
            .bind(claim_id)
            .execute(pool)
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    /// Get the cosine distance from a claim's embedding to its current theme centroid.
    ///
    /// Returns `None` if the claim has no theme, no embedding, or the theme has no centroid.
    pub async fn get_claim_theme_distance<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Option<f64>, DbError> {
        let sql = viewer.splice(
            "SELECT (ct.centroid <=> c.embedding)::float8 AS distance \
             FROM claims c \
             JOIN claim_themes ct ON c.theme_id = ct.id \
             WHERE c.id = $1 \
               AND c.embedding IS NOT NULL \
               AND ct.centroid IS NOT NULL \
               /* {VISIBILITY:c} */",
            2,
        );
        let mut vq = sqlx::query(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let row = vq.fetch_optional(executor).await.map_err(DbError::from)?;

        Ok(row.map(|r| r.get::<f64, _>("distance")))
    }

    /// Get a claim's embedding as a pgvector string for use in find_similar_themes.
    ///
    /// Returns `None` if the claim has no embedding.
    pub async fn get_claim_embedding_str<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let sql = viewer.splice(
            "SELECT embedding::text AS emb_str FROM claims WHERE id = $1 AND embedding IS NOT NULL /* {VISIBILITY:claims} */",
            2,
        );
        let mut vq = sqlx::query(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let row = vq.fetch_optional(executor).await.map_err(DbError::from)?;

        Ok(row.map(|r| r.get::<String, _>("emb_str")))
    }

    /// Assign one batch of unthemed claims to their nearest theme centroid.
    ///
    /// Uses a CTE: find claims with embeddings but no theme_id, assign each
    /// to the nearest theme centroid via pgvector `<=>`. Returns count assigned.
    /// Call in a loop until it returns 0.
    pub async fn assign_unthemed_batch<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        _viewer: &crate::visibility::Viewer,
        batch_size: i64,
    ) -> Result<i64, DbError> {
        let row = sqlx::query(
            "-- VISIBILITY-EXEMPT: corpus-wide theme clustering maintenance, SystemReason::ThemeClustering.\n             -- A theme centroid is an average over EVERY member claim; computing it\n             -- per-viewer would give each tenant a different, wrong centroid for the\n             -- same theme row and make assignment non-deterministic. Takes a viewer\n             -- so the exemption is visible at the call site.\n             WITH unthemed AS ( \
                SELECT id, embedding \
                FROM claims \
                WHERE embedding IS NOT NULL AND theme_id IS NULL \
                LIMIT $1 \
            ), \
            nearest AS ( \
                SELECT u.id AS claim_id, \
                       (SELECT ct.id FROM claim_themes ct \
                        WHERE ct.centroid IS NOT NULL \
                        ORDER BY ct.centroid <=> u.embedding \
                        LIMIT 1) AS theme_id \
                FROM unthemed u \
            ) \
            UPDATE claims c \
            SET theme_id = n.theme_id, updated_at = NOW() \
            FROM nearest n \
            WHERE c.id = n.claim_id AND n.theme_id IS NOT NULL \
            RETURNING c.id",
        )
        .bind(batch_size)
        .fetch_all(executor)
        .await
        .map_err(DbError::from)?;

        Ok(row.len() as i64)
    }

    /// Recompute centroid and claim_count for a single theme.
    ///
    /// Centroid = avg(member embeddings)::vector(1536). Returns (label, count).
    /// Returns None if the theme has no claims with embeddings.
    pub async fn recompute_centroid_for_theme(
        pool: &PgPool,
        _viewer: &crate::visibility::Viewer,
        theme_id: Uuid,
    ) -> Result<Option<(String, i32)>, DbError> {
        let count_row = sqlx::query(
            "-- VISIBILITY-EXEMPT: corpus-wide theme clustering maintenance, SystemReason::ThemeClustering.\n             -- A theme centroid is an average over EVERY member claim; computing it\n             -- per-viewer would give each tenant a different, wrong centroid for the\n             -- same theme row and make assignment non-deterministic. Takes a viewer\n             -- so the exemption is visible at the call site.\n             SELECT ct.label, COUNT(c.id)::int4 AS n \
             FROM claim_themes ct \
             LEFT JOIN claims c ON c.theme_id = ct.id AND c.embedding IS NOT NULL \
             WHERE ct.id = $1 \
             GROUP BY ct.label",
        )
        .bind(theme_id)
        .fetch_optional(pool)
        .await
        .map_err(DbError::from)?;

        let (label, count): (String, i32) = match count_row {
            Some(row) => (row.get("label"), row.get("n")),
            None => return Ok(None),
        };

        if count == 0 {
            return Ok(Some((label, 0)));
        }

        sqlx::query(
            "-- VISIBILITY-EXEMPT: corpus-wide theme clustering maintenance, SystemReason::ThemeClustering.\n             -- A theme centroid is an average over EVERY member claim; computing it\n             -- per-viewer would give each tenant a different, wrong centroid for the\n             -- same theme row and make assignment non-deterministic. Takes a viewer\n             -- so the exemption is visible at the call site.\n             UPDATE claim_themes SET \
                centroid = (SELECT avg(c.embedding)::vector(1536) \
                            FROM claims c \
                            WHERE c.theme_id = $1 AND c.embedding IS NOT NULL), \
                claim_count = $2, \
                updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(theme_id)
        .bind(count)
        .execute(pool)
        .await
        .map_err(DbError::from)?;

        Ok(Some((label, count)))
    }

    /// Recompute centroids for all themes. Returns list of (id, label, count).
    pub async fn recompute_all_centroids(
        pool: &PgPool,
        _viewer: &crate::visibility::Viewer,
    ) -> Result<Vec<RecomputedThemeRow>, DbError> {
        let themes = sqlx::query(
            "-- VISIBILITY-EXEMPT: corpus-wide theme clustering maintenance, SystemReason::ThemeClustering.\n             -- A theme centroid is an average over EVERY member claim.\n             SELECT ct.id, ct.label, COUNT(c.id)::int4 AS n \
             FROM claim_themes ct \
             LEFT JOIN claims c ON c.theme_id = ct.id AND c.embedding IS NOT NULL \
             GROUP BY ct.id, ct.label \
             ORDER BY n DESC",
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        let mut results = Vec::new();
        for row in &themes {
            let id: Uuid = row.get("id");
            let label: String = row.get("label");
            let count: i32 = row.get("n");

            if count > 0 {
                sqlx::query(
                    "-- VISIBILITY-EXEMPT: corpus-wide theme clustering maintenance, SystemReason::ThemeClustering.\n             -- A theme centroid is an average over EVERY member claim; computing it\n             -- per-viewer would give each tenant a different, wrong centroid for the\n             -- same theme row and make assignment non-deterministic. Takes a viewer\n             -- so the exemption is visible at the call site.\n             UPDATE claim_themes SET \
                        centroid = (SELECT avg(c.embedding)::vector(1536) \
                                    FROM claims c \
                                    WHERE c.theme_id = $1 AND c.embedding IS NOT NULL), \
                        claim_count = $2, \
                        updated_at = NOW() \
                     WHERE id = $1",
                )
                .bind(id)
                .bind(count)
                .execute(pool)
                .await
                .map_err(DbError::from)?;
            }

            results.push(RecomputedThemeRow {
                id,
                label,
                claim_count: count,
            });
        }

        Ok(results)
    }

    /// One page of the themes overview for `viewer`: every theme with at least
    /// one CURRENT member the viewer can read, with that live count, ordered
    /// `member_count DESC, id ASC` (backlog 57917c13).
    ///
    /// Themes with no readable member are ABSENT, not zero (owner ruling A1):
    /// a zero row would publish the id and label of an all-private theme. The
    /// stale `claim_themes.claim_count` column is not read, under any name.
    /// `claim_themes` is not a tenancy table; only the counts, and through them
    /// which theme rows appear, narrow. The LABEL is not narrowed and may be
    /// derived from members the viewer cannot read (the label residual on
    /// `D-PR16-theme-cluster-viewer-scope`).
    ///
    /// `limit` is clamped to `1..=THEME_OVERVIEW_PAGE_MAX`. `after` is a pure
    /// keyset position: one naming a count or id that no longer exists returns
    /// the rows after that position, possibly none. `total` is reported on
    /// every page, an empty one included.
    ///
    /// One statement: one `GROUP BY theme_id` pass over the themed current
    /// claims (served by migration 196's covering partial index), the page
    /// cut from it, and the total counted from the same materialised CTE.
    pub async fn overview_page<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        after: Option<ThemeOverviewCursor>,
        limit: i64,
    ) -> Result<ThemeOverviewPage, DbError> {
        let limit = limit.clamp(1, THEME_OVERVIEW_PAGE_MAX);
        // `c.is_current`, not the `COALESCE(c.is_current, true)` the
        // neighbouring reads use: the column is `NOT NULL DEFAULT true`
        // (001_initial_schema.sql), so the two agree on every row, and only
        // the bare form lets the planner prove migration 196's partial-index
        // predicate (implication is checked syntactically).
        //
        // `visible` is referenced twice, so it is materialised once. The LEFT
        // JOIN from a one-row relation keeps `total_themes` on an empty page.
        let sql = viewer.splice(
            "WITH counts AS ( \
                 SELECT c.theme_id, COUNT(*)::int8 AS member_count \
                 FROM claims c \
                 WHERE c.theme_id IS NOT NULL \
                   AND c.is_current \
                   /* {VISIBILITY:c} */ \
                 GROUP BY c.theme_id \
             ), \
             visible AS ( \
                 SELECT t.id, left(t.label, 200) AS label, k.member_count \
                 FROM counts k \
                 JOIN claim_themes t ON t.id = k.theme_id \
             ), \
             page AS ( \
                 SELECT id, label, member_count \
                 FROM visible \
                 WHERE $1::int8 IS NULL \
                    OR member_count < $1::int8 \
                    OR (member_count = $1::int8 AND id > $2::uuid) \
                 ORDER BY member_count DESC, id ASC \
                 LIMIT $3 \
             ) \
             SELECT (SELECT COUNT(*) FROM visible)::int8 AS total_themes, \
                    p.id, p.label, p.member_count \
             FROM (SELECT 1) AS one \
             LEFT JOIN page p ON TRUE \
             ORDER BY p.member_count DESC NULLS LAST, p.id ASC",
            4,
        );
        // One row past the cap tells "cut" from "exactly fit".
        let mut q = sqlx::query_as::<_, ThemeOverviewSqlRow>(&sql)
            .bind(after.map(|c| c.member_count))
            .bind(after.map(|c| c.id))
            .bind(limit + 1);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await.map_err(DbError::from)?;

        let total = rows.first().map_or(0, |r| r.total_themes);
        let mut themes: Vec<ThemeOverviewRow> = rows
            .into_iter()
            .filter_map(|r| match (r.id, r.label, r.member_count) {
                (Some(id), Some(label), Some(member_count)) => Some(ThemeOverviewRow {
                    id,
                    label,
                    member_count,
                }),
                // The empty-page sentinel of the LEFT JOIN.
                _ => None,
            })
            .collect();
        let cap = usize::try_from(limit).unwrap_or(usize::MAX);
        let next = if themes.len() > cap {
            themes.truncate(cap);
            themes.last().map(ThemeOverviewCursor::of)
        } else {
            None
        };
        Ok(ThemeOverviewPage {
            themes,
            total,
            next,
        })
    }

    /// Find themes with high intra-cluster variance (candidates for splitting).
    pub async fn find_split_candidates<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        variance_threshold: f64,
        min_claims: i64,
        limit: i64,
    ) -> Result<Vec<SplitCandidateRow>, DbError> {
        let sql = viewer.splice(
            "SELECT ct.id, ct.label, ct.claim_count, \
                    avg(ct.centroid <=> c.embedding)::float8 AS avg_distance, \
                    max(ct.centroid <=> c.embedding)::float8 AS max_distance \
             FROM claim_themes ct \
             JOIN claims c ON c.theme_id = ct.id AND c.embedding IS NOT NULL \
             WHERE ct.claim_count >= $1 AND ct.centroid IS NOT NULL \
               /* {VISIBILITY:c} */ \
             GROUP BY ct.id, ct.label, ct.claim_count \
             HAVING avg(ct.centroid <=> c.embedding) > $2 \
             ORDER BY avg(ct.centroid <=> c.embedding) DESC \
             LIMIT $3",
            4,
        );
        let mut vq = sqlx::query(&sql)
            .bind(min_claims)
            .bind(variance_threshold)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(executor).await.map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| SplitCandidateRow {
                theme_id: row.get("id"),
                label: row.get("label"),
                claim_count: row.get("claim_count"),
                avg_distance: row.get("avg_distance"),
                max_distance: row.get("max_distance"),
            })
            .collect();
        Ok(results)
    }

    /// Find themes with many claims far from their centroid (new theme candidates).
    pub async fn find_distant_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        distance_threshold: f64,
        min_cluster_size: i64,
        limit: i64,
    ) -> Result<Vec<DistantClaimsRow>, DbError> {
        let sql = viewer.splice(
            "SELECT ct.label, COUNT(*)::int8 AS n_distant, \
                    avg(ct.centroid <=> c.embedding)::float8 AS avg_dist \
             FROM claims c \
             JOIN claim_themes ct ON c.theme_id = ct.id \
             WHERE c.embedding IS NOT NULL \
               AND ct.centroid IS NOT NULL \
               AND (ct.centroid <=> c.embedding) > $1 \
               /* {VISIBILITY:c} */ \
             GROUP BY ct.id, ct.label \
             HAVING COUNT(*) >= $2 \
             ORDER BY COUNT(*) DESC \
             LIMIT $3",
            4,
        );
        let mut vq = sqlx::query(&sql)
            .bind(distance_threshold)
            .bind(min_cluster_size)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(executor).await.map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| DistantClaimsRow {
                source_theme: row.get("label"),
                distant_claims: row.get("n_distant"),
                avg_distance: row.get("avg_dist"),
            })
            .collect();
        Ok(results)
    }

    /// Get claim IDs and embeddings for a theme (for client-side k-means).
    ///
    /// Returns embeddings as pgvector text format. The API handler converts
    /// to JSON arrays for the response.
    pub async fn get_theme_embeddings<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        theme_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        let sql = viewer.splice(
            "SELECT id, embedding::text AS emb_str \
             FROM claims \
             WHERE theme_id = $1 AND embedding IS NOT NULL \
               /* {VISIBILITY:claims} */ \
             LIMIT $2",
            3,
        );
        let mut vq = sqlx::query(&sql).bind(theme_id).bind(limit);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(executor).await.map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| {
                let id: Uuid = row.get("id");
                let emb: String = row.get("emb_str");
                (id, emb)
            })
            .collect();
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centroid_columns_validates_dim() {
        assert_eq!(
            centroid_columns_for_dim(1536),
            Some(("centroid", "embedding"))
        );
        assert_eq!(
            centroid_columns_for_dim(3072),
            Some(("centroid_3072", "embedding_3072"))
        );
        assert!(centroid_columns_for_dim(1024).is_none());
        assert!(centroid_columns_for_dim(0).is_none());
    }

    #[test]
    fn theme_overview_cursor_round_trips() {
        let id = Uuid::parse_str("6f1c0b2e-9d3a-4c55-a1b2-c3d4e5f60718").unwrap();
        let c = ThemeOverviewCursor {
            member_count: 41,
            id,
        };
        let token = c.encode();
        assert_eq!(token, "t1.41.6f1c0b2e9d3a4c55a1b2c3d4e5f60718");
        assert_eq!(ThemeOverviewCursor::decode(&token), Some(c));

        let big = ThemeOverviewCursor {
            member_count: i64::MAX,
            id: Uuid::max(),
        };
        assert_eq!(ThemeOverviewCursor::decode(&big.encode()), Some(big));
    }

    #[test]
    fn theme_overview_cursor_refuses_anything_it_did_not_encode() {
        let hex = "6f1c0b2e9d3a4c55a1b2c3d4e5f60718";
        for bad in [
            String::new(),
            "garbage".to_string(),
            // No prefix, and a LabelCursor's prefix.
            format!("41.{hex}"),
            format!("k1.41.{hex}"),
            format!("t2.41.{hex}"),
            // A count no listed theme can have.
            format!("t1.0.{hex}"),
            format!("t1.-3.{hex}"),
            format!("t1.+3.{hex}"),
            // Not a number, or past i64.
            format!("t1.abc.{hex}"),
            format!("t1..{hex}"),
            format!("t1.99999999999999999999.{hex}"),
            // Bad or missing uuid, extra segments.
            "t1.3.".to_string(),
            "t1.3".to_string(),
            "t1.3.not-a-uuid".to_string(),
            format!("t1.3.{hex}.4"),
            format!("t1.3.{hex}x"),
        ] {
            assert_eq!(ThemeOverviewCursor::decode(&bad), None, "{bad:?}");
        }
    }
}
