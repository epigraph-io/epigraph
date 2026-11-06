//! The Atlas theme layout (migration 197): the shared positions of themes and
//! regions, the public link counts between them, and the per-viewer reads that
//! serve them (`GET /api/v1/graph/themes/layout`, `GET /api/v1/graph/links`,
//! and the `layout` block of `GET /api/v1/claims/:id/placement`).
//!
//! # Two halves, two authorities
//!
//! **The build** runs in the operator CLI `atlas_layout` on the maintenance
//! connection. [`AtlasLayoutRepository::read_public_inputs`] reads ONLY public
//! current claims and public in-force edges between them (the literal
//! `visibility = 'public'` is in each statement, beside the spliced
//! predicate), so every number a layout run stores is an aggregate of rows
//! every viewer may read. [`AtlasLayoutRepository::write_run`] and
//! [`AtlasLayoutRepository::prune_runs`] write the four untenanted layout
//! tables; the application role holds SELECT only on them.
//!
//! **The serve** runs on the caller's viewer-stamped connection. Positions,
//! region labels and link counts are shared; WHICH themes and regions appear,
//! their member counts, and the theme pairs a bundle sums over are decided per
//! viewer by one spliced aggregate over `claims` (`visible_themes`). A theme
//! appears only if the viewer can read one of its current members; a region
//! only if it holds such a theme; a bundle only sums pairs whose two themes
//! the viewer can see.
//!
//! # The visibility epoch
//!
//! A run is served only while `atlas_layout_runs.visibility_epoch` equals
//! `atlas_layout_epoch.n`. Migration 197's definer trigger bumps `n` in the
//! same transaction that turns any public claim or edge non-public, so no
//! stored aggregate outlives the publicity of a row it counted.
//! [`LayoutRunRow::current`] carries that comparison; the epoch number itself
//! is never handed to a caller (it counts narrowed rows corpus-wide).
//!
//! # The theme-pair drill-down reads live
//!
//! [`AtlasLayoutRepository::links_between`] reads the claim pairs behind a
//! bundle from `edges` and `claims` directly, through the viewer predicate on
//! all three aliases, and counts them inside that predicate. A shared bundle
//! count and a viewer's drill-down count can differ (a deleted, superseded or
//! reassigned row since the build); they never differ by a row the viewer may
//! not read.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::cluster_run::ClusterRunRepository;
use crate::visibility::Viewer;

/// The algorithm name a run built by `atlas_layout` records.
pub const ATLAS_LAYOUT_ALGO: &str = "pca2-ward-v1";

/// Half-width of the layout's coordinate frame: every region centre lies within
/// `0.8 * ATLAS_LAYOUT_EXTENT` of the origin.
pub const ATLAS_LAYOUT_EXTENT: f64 = 1000.0;

/// The cap on every list the layout and links reads return in one page.
pub const ATLAS_PAGE_MAX: i64 = 200;

/// The relationships a layout bundle and a drill-down count by default:
/// `edge::EPISTEMIC_RELATIONSHIPS` plus `cites`, lower-case (the build stores
/// `lower(relationship)` and every reader here matches `lower(e.relationship)`).
pub const ATLAS_DEFAULT_RELATIONSHIPS: &[&str] = &[
    "supports",
    "corroborates",
    "elaborates",
    "generalizes",
    "specializes",
    "contradicts",
    "refutes",
    "cites",
];

/// Structural relationships, added to the default set on request only: a
/// decomposition can match tens of thousands of edges between two regions.
pub const ATLAS_STRUCTURE_RELATIONSHIPS: &[&str] = &["decomposes_to"];

/// The most candidate themes the viewer-placement statement takes at once.
/// Candidates are themes with no public member, so there are few; any beyond
/// the cap are reported as unplaced rather than read.
const VIEWER_PLACEMENT_CAP: usize = 1000;

/// Postgres `timestamptz`'s earliest value in Unix microseconds (the same guard
/// `claim.rs`'s `LabelCursor` applies), so every decoded cursor binds.
const PG_TIMESTAMPTZ_MIN_MICROS: i64 = -210_866_803_200_000_000;

/// Longest label key, in bytes, an unplaced-theme cursor carries. The unplaced
/// list is ordered by this key (the label cut at a char boundary), so the
/// cursor stays short and the keyset stays exact.
const UNPLACED_LABEL_KEY_BYTES: usize = 64;

// ── build side ───────────────────────────────────────────────────────────────

/// One theme's public-only centroid, from [`AtlasLayoutRepository::read_public_inputs`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PublicThemeCentroid {
    pub theme_id: Uuid,
    pub label: String,
    /// Public current members of the theme.
    pub public_member_count: i64,
    /// Of those, the members that carry an embedding.
    pub embedded_count: i64,
    /// `AVG(embedding)::text` over the embedded public members, in pgvector
    /// text form; `None` when `embedded_count` is 0.
    pub centroid: Option<String>,
}

/// Public in-force claim-to-claim edges between two themes, per relationship.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PublicThemeLinkCount {
    /// The smaller theme id (`theme_a < theme_b`).
    pub theme_a: Uuid,
    pub theme_b: Uuid,
    /// Lower-cased.
    pub relationship: String,
    pub link_count: i64,
}

/// Everything one layout build reads, from one REPEATABLE READ snapshot.
#[derive(Debug, Clone)]
pub struct PublicLayoutInputs {
    /// Ordered by `theme_id` ascending.
    pub themes: Vec<PublicThemeCentroid>,
    pub links: Vec<PublicThemeLinkCount>,
    /// The newest `graph_cluster_runs.run_id` at build time (informational).
    pub cluster_run_id: Option<Uuid>,
    /// `atlas_layout_epoch.n` in the snapshot.
    pub visibility_epoch: i64,
}

/// One region of a build, as `write_run` stores it.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutRegionOut {
    pub id: Uuid,
    pub ordinal: i32,
    pub label: String,
    pub x: f64,
    pub y: f64,
    pub r: f64,
    /// 1536 components.
    pub centroid: Vec<f32>,
}

/// One placed theme of a build.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutThemeOut {
    pub theme_id: Uuid,
    pub region_id: Uuid,
    pub rank_in_region: i32,
    pub x: f64,
    pub y: f64,
    pub public_member_count: i64,
}

/// One theme-pair link count of a build (`theme_a < theme_b`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutLinkOut {
    pub theme_a: Uuid,
    pub theme_b: Uuid,
    pub relationship: String,
    pub link_count: i64,
}

/// A whole layout run, ready to write.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutBuild {
    pub algo: String,
    pub params: serde_json::Value,
    pub cluster_run_id: Option<Uuid>,
    pub visibility_epoch: i64,
    pub public_claim_count: i64,
    pub public_link_count: i64,
    pub theme_set_digest: String,
    pub regions: Vec<LayoutRegionOut>,
    pub themes: Vec<LayoutThemeOut>,
    pub theme_links: Vec<LayoutLinkOut>,
}

// ── serve side: rows ─────────────────────────────────────────────────────────

/// A layout run, with whether it may be served.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LayoutRunRow {
    pub id: Uuid,
    pub completed_at: DateTime<Utc>,
    pub algo: String,
    pub cluster_run_id: Option<Uuid>,
    pub theme_count: i32,
    /// A theme was created after the build, or a placed theme was deleted.
    pub stale: bool,
    /// No public row has been narrowed since the build: the run may be served.
    pub current: bool,
}

/// How a visible theme is placed for this viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemePlacement {
    /// A shared position from the run.
    Shared,
    /// No shared position; assigned to the region nearest the centroid of the
    /// members THIS viewer can read. Served to this viewer only, without x/y.
    Viewer,
    /// No shared position and no embedded member this viewer can read.
    Unplaced,
}

impl ThemePlacement {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Viewer => "viewer",
            Self::Unplaced => "unplaced",
        }
    }
}

/// A theme the viewer can read, with the viewer's own member count.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VisibleTheme {
    theme_id: Uuid,
    n: i64,
    region_id: Option<Uuid>,
    rank: Option<i32>,
    placement: ThemePlacement,
}

impl VisibleTheme {
    /// The shared theme order: shared themes by rank, then viewer-placed ones
    /// (no rank) by id.
    fn order_key(&self) -> (i32, Uuid) {
        (self.rank.unwrap_or(i32::MAX), self.theme_id)
    }
}

/// A region the viewer can see, with per-viewer counts.
#[derive(Debug, Clone, PartialEq)]
pub struct VisibleRegionRow {
    pub id: Uuid,
    pub ordinal: i32,
    pub label: String,
    pub x: f64,
    pub y: f64,
    pub r: f64,
    /// At most [`ATLAS_PAGE_MAX`], in the region's theme order.
    pub theme_ids: Vec<Uuid>,
    /// Every theme of the region this viewer sees (uncapped).
    pub theme_count: i64,
    /// Current members of those themes this viewer can read.
    pub member_count: i64,
}

/// A theme the viewer can see, as a region page or the unplaced list lists it.
#[derive(Debug, Clone, PartialEq)]
pub struct VisibleThemeRow {
    pub theme_id: Uuid,
    /// `left(label, 200)`.
    pub label: String,
    pub region_id: Option<Uuid>,
    pub placement: ThemePlacement,
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub member_count: i64,
}

/// One relationship's count inside one bundle. A bundle is the consecutive
/// rows sharing `(kind, a, b)`; `total` is the bundle's sum, repeated.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LayoutLinkRow {
    /// `region`, `theme` or `theme_region`.
    pub kind: String,
    pub a: Uuid,
    pub b: Uuid,
    pub relationship: String,
    pub link_count: i64,
    pub total: i64,
}

/// The top level of the layout, as one viewer sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutOverview {
    pub regions: Vec<VisibleRegionRow>,
    pub links: Vec<LayoutLinkRow>,
    pub unplaced_theme_count: i64,
    pub next_links: Option<LayoutLinkCursor>,
}

/// One region of the layout, as one viewer sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct RegionDetail {
    pub region: VisibleRegionRow,
    pub themes: Vec<VisibleThemeRow>,
    pub links: Vec<LayoutLinkRow>,
    pub next_themes: Option<ThemePageCursor>,
    pub next_links: Option<LayoutLinkCursor>,
}

/// Which part of a region page to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailPart {
    Both,
    ThemesAfter(ThemePageCursor),
    LinksAfter(LayoutLinkCursor),
}

/// The viewer's unplaced themes, one page.
#[derive(Debug, Clone, PartialEq)]
pub struct UnplacedPage {
    pub themes: Vec<VisibleThemeRow>,
    pub next: Option<UnplacedCursor>,
}

/// One side of a drill-down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSideKind {
    Theme,
    Region,
}

impl LinkSideKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Theme => "theme",
            Self::Region => "region",
        }
    }
}

/// A resolved drill-down side: a theme, or a region's shared themes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSide {
    pub id: Uuid,
    pub kind: LinkSideKind,
    pub theme_ids: Vec<Uuid>,
}

/// One claim pair behind a bundle, as the viewer may read it.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct LinkPairRow {
    pub edge_id: Uuid,
    pub source_id: Uuid,
    pub source_truth_value: f64,
    pub source_theme_id: Option<Uuid>,
    pub target_id: Uuid,
    pub target_truth_value: f64,
    pub target_theme_id: Option<Uuid>,
    /// `left(content, 200)`; the route cuts it to its label length.
    pub source_content: String,
    pub target_content: String,
    /// Lower-cased.
    pub relationship: String,
    pub created_at: DateTime<Utc>,
    /// The source claim's theme is on the `from` side.
    pub from_is_source: bool,
    /// `properties.strength` if a JSON number, else `properties.confidence`
    /// if a JSON number, else `None`.
    pub strength: Option<f64>,
}

/// One drill-down page.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkPage {
    pub items: Vec<LinkPairRow>,
    /// Per-relationship counts of every pair this viewer may read between the
    /// two sides, counted inside the viewer predicate (all pages, not this one).
    pub counts: Vec<(String, i64)>,
    pub next: Option<LinkPairCursor>,
}

/// Where a theme sits in the current layout, for `/claims/:id/placement`.
#[derive(Debug, Clone, PartialEq)]
pub struct PlacementLayoutRow {
    pub run_id: Uuid,
    pub region_id: Uuid,
    pub placement: ThemePlacement,
    pub x: Option<f64>,
    pub y: Option<f64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct LayoutRegionRow {
    id: Uuid,
    ordinal: i32,
    label: String,
    x: f64,
    y: f64,
    r: f64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct ThemeLabelRow {
    id: Uuid,
    label: String,
    x: Option<f64>,
    y: Option<f64>,
}

// ── cursors ──────────────────────────────────────────────────────────────────

/// Resume a region's themes after `(rank_key, theme_id)`; a viewer-placed
/// theme's `rank_key` is `i32::MAX`. Token `lt2.<rank_key>.<theme hex>`.
///
/// It carries the shared rank, never a count, so it discloses nothing the
/// page did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThemePageCursor {
    pub rank_key: i32,
    pub theme_id: Uuid,
}

impl ThemePageCursor {
    #[must_use]
    pub fn encode(&self) -> String {
        format!("lt2.{}.{}", self.rank_key, self.theme_id.simple())
    }

    /// `None` for anything [`Self::encode`] would not produce.
    #[must_use]
    pub fn decode(token: &str) -> Option<Self> {
        let rest = token.strip_prefix("lt2.")?;
        let (rank, id) = rest.split_once('.')?;
        let rank_key: i32 = rank.parse().ok()?;
        if rank_key < 0 {
            return None;
        }
        Some(Self {
            rank_key,
            theme_id: parse_simple_uuid(id)?,
        })
    }
}

/// Resume a bundle list after `(total, kind, a, b)` in `total DESC, kind DESC,
/// a DESC, b DESC` order. `kind` is 1 for a theme pair and 0 for a
/// theme-to-region stub at region level, and 2 for a region pair at the top
/// level. Token `ll1.<total>.<kind>.<a hex>.<b hex>`; the total is the one the
/// page itself showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutLinkCursor {
    pub total: i64,
    pub kind: u8,
    pub a: Uuid,
    pub b: Uuid,
}

impl LayoutLinkCursor {
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "ll1.{}.{}.{}.{}",
            self.total,
            self.kind,
            self.a.simple(),
            self.b.simple()
        )
    }

    /// `None` for anything [`Self::encode`] would not produce.
    #[must_use]
    pub fn decode(token: &str) -> Option<Self> {
        let mut parts = token.strip_prefix("ll1.")?.split('.');
        let total: i64 = parts.next()?.parse().ok()?;
        let kind: u8 = parts.next()?.parse().ok()?;
        let a = parse_simple_uuid(parts.next()?)?;
        let b = parse_simple_uuid(parts.next()?)?;
        if parts.next().is_some() || total < 1 || kind > 2 {
            return None;
        }
        Some(Self { total, kind, a, b })
    }
}

/// Resume the unplaced list after `(label_key, id)`, where `label_key` is the
/// label cut to 64 bytes at a char boundary (the order IS that key, then id).
/// Token `lu1.<label key hex>.<id hex>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnplacedCursor {
    pub label_key: String,
    pub id: Uuid,
}

impl UnplacedCursor {
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "lu1.{}.{}",
            hex::encode(self.label_key.as_bytes()),
            self.id.simple()
        )
    }

    /// `None` for anything [`Self::encode`] would not produce.
    #[must_use]
    pub fn decode(token: &str) -> Option<Self> {
        let rest = token.strip_prefix("lu1.")?;
        let (label, id) = rest.split_once('.')?;
        let bytes = hex::decode(label).ok()?;
        if bytes.len() > UNPLACED_LABEL_KEY_BYTES {
            return None;
        }
        Some(Self {
            label_key: String::from_utf8(bytes).ok()?,
            id: parse_simple_uuid(id)?,
        })
    }
}

/// The unplaced list's sort key for `label`: at most 64 bytes, cut on a char
/// boundary.
#[must_use]
pub fn unplaced_label_key(label: &str) -> String {
    let mut end = label.len().min(UNPLACED_LABEL_KEY_BYTES);
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    label[..end].to_string()
}

/// Resume a drill-down after an edge in `strength DESC NULLS LAST, created_at
/// DESC, id DESC` order. Token `gl2.<s|n>.<f64 bits hex>.<micros>.<edge hex>`;
/// `n` (no strength) carries zero bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkPairCursor {
    pub has_strength: bool,
    pub strength_bits: u64,
    pub created_at_micros: i64,
    pub edge_id: Uuid,
}

impl LinkPairCursor {
    /// The cursor of `row`, the last row of a page.
    #[must_use]
    pub fn of(row: &LinkPairRow) -> Self {
        Self {
            has_strength: row.strength.is_some(),
            strength_bits: row.strength.map_or(0, f64::to_bits),
            created_at_micros: row.created_at.timestamp_micros(),
            edge_id: row.edge_id,
        }
    }

    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "gl2.{}.{:016x}.{}.{}",
            if self.has_strength { 's' } else { 'n' },
            self.strength_bits,
            self.created_at_micros,
            self.edge_id.simple()
        )
    }

    /// `None` for anything [`Self::encode`] would not produce, including a
    /// non-finite strength and a time Postgres cannot represent.
    #[must_use]
    pub fn decode(token: &str) -> Option<Self> {
        let mut parts = token.strip_prefix("gl2.")?.split('.');
        let has_strength = match parts.next()? {
            "s" => true,
            "n" => false,
            _ => return None,
        };
        let bits_hex = parts.next()?;
        if bits_hex.len() != 16 {
            return None;
        }
        let strength_bits = u64::from_str_radix(bits_hex, 16).ok()?;
        let created_at_micros: i64 = parts.next()?.parse().ok()?;
        let edge_id = parse_simple_uuid(parts.next()?)?;
        if parts.next().is_some() || created_at_micros < PG_TIMESTAMPTZ_MIN_MICROS {
            return None;
        }
        if has_strength && !f64::from_bits(strength_bits).is_finite() {
            return None;
        }
        if !has_strength && strength_bits != 0 {
            return None;
        }
        DateTime::<Utc>::from_timestamp_micros(created_at_micros)?;
        Some(Self {
            has_strength,
            strength_bits,
            created_at_micros,
            edge_id,
        })
    }

    fn strength(&self) -> f64 {
        f64::from_bits(self.strength_bits)
    }

    fn created_at(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_micros(self.created_at_micros).unwrap_or_default()
    }
}

/// A 32-hex-digit uuid, the only form the cursors write.
fn parse_simple_uuid(s: &str) -> Option<Uuid> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Uuid::try_parse(s).ok()
}

fn clamp_limit(limit: i64) -> usize {
    usize::try_from(limit.clamp(1, ATLAS_PAGE_MAX)).unwrap_or(1)
}

fn pgvector_text(v: &[f32]) -> String {
    let parts: Vec<String> = v.iter().map(ToString::to_string).collect();
    format!("[{}]", parts.join(","))
}

/// Fold consecutive bundle rows into pages of whole bundles: keep the first
/// `limit` bundles, and return the cursor of the last one kept when more
/// followed.
fn page_bundles(
    rows: Vec<LayoutLinkRow>,
    limit: usize,
    kind_code: impl Fn(&str) -> u8,
) -> (Vec<LayoutLinkRow>, Option<LayoutLinkCursor>) {
    let mut out: Vec<LayoutLinkRow> = Vec::with_capacity(rows.len());
    let mut bundles = 0usize;
    let mut last: Option<(String, Uuid, Uuid)> = None;
    let mut more = false;
    for row in rows {
        let key = (row.kind.clone(), row.a, row.b);
        if last.as_ref() != Some(&key) {
            if bundles == limit {
                more = true;
                break;
            }
            bundles += 1;
            last = Some(key);
        }
        out.push(row);
    }
    let next = if more {
        out.last().map(|r| LayoutLinkCursor {
            total: r.total,
            kind: kind_code(&r.kind),
            a: r.a,
            b: r.b,
        })
    } else {
        None
    };
    (out, next)
}

pub struct AtlasLayoutRepository;

impl AtlasLayoutRepository {
    // ── build ────────────────────────────────────────────────────────────────

    /// Read the public layout inputs in ONE REPEATABLE READ snapshot.
    ///
    /// MUST be the first call on a fresh transaction: its first statement is
    /// `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`, which Postgres
    /// refuses once the transaction has run a query. The epoch is the first
    /// read, so it fixes the snapshot: a narrowing still uncommitted when the
    /// snapshot is taken leaves the old epoch here, and its commit then moves
    /// the epoch past the run this build writes (invalid on arrival).
    ///
    /// Every statement names `visibility = 'public'` for its claims and edges
    /// besides the spliced predicate, so a bypass viewer on the maintenance
    /// connection (which splices to nothing) still reads public rows only.
    ///
    /// # Errors
    /// `DbError::QueryFailed` on any statement, including the isolation level
    /// on a transaction that already ran a statement.
    pub async fn read_public_inputs(
        conn: &mut PgConnection,
        viewer: &Viewer,
    ) -> Result<PublicLayoutInputs, DbError> {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *conn)
            .await?;
        let visibility_epoch: i64 =
            sqlx::query_scalar("SELECT n FROM atlas_layout_epoch WHERE singleton")
                .fetch_one(&mut *conn)
                .await?;

        let centroid_sql = viewer.splice(
            "SELECT t.id AS theme_id, t.label, \
                    COUNT(*)::int8 AS public_member_count, \
                    COUNT(c.embedding)::int8 AS embedded_count, \
                    (AVG(c.embedding)::vector)::text AS centroid \
             FROM claims c \
             JOIN claim_themes t ON t.id = c.theme_id \
             WHERE c.theme_id IS NOT NULL AND c.is_current \
               AND c.visibility = 'public' \
               /* {VISIBILITY:c} */ \
             GROUP BY t.id, t.label \
             ORDER BY t.id",
            1,
        );
        let mut q = sqlx::query_as::<_, PublicThemeCentroid>(&centroid_sql);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let themes = q.fetch_all(&mut *conn).await?;

        let link_sql = viewer.splice(
            "SELECT LEAST(cs.theme_id, ct.theme_id) AS theme_a, \
                    GREATEST(cs.theme_id, ct.theme_id) AS theme_b, \
                    lower(e.relationship) AS relationship, COUNT(*)::int8 AS link_count \
             FROM edges e \
             JOIN claims cs ON cs.id = e.source_id \
             JOIN claims ct ON ct.id = e.target_id \
             WHERE e.source_type = 'claim' AND e.target_type = 'claim' \
               AND (e.valid_to IS NULL OR e.valid_to > now()) \
               AND e.visibility = 'public' AND cs.visibility = 'public' \
               AND ct.visibility = 'public' \
               AND cs.is_current AND ct.is_current \
               AND cs.theme_id IS NOT NULL AND ct.theme_id IS NOT NULL \
               AND cs.theme_id <> ct.theme_id \
               /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:cs} */ /* {VISIBILITY:ct} */ \
             GROUP BY 1, 2, 3 \
             ORDER BY 1, 2, 3",
            1,
        );
        let mut q = sqlx::query_as::<_, PublicThemeLinkCount>(&link_sql);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let links = q.fetch_all(&mut *conn).await?;

        let cluster_run_id = ClusterRunRepository::latest(&mut *conn)
            .await?
            .map(|r| r.run_id);

        Ok(PublicLayoutInputs {
            themes,
            links,
            cluster_run_id,
            visibility_epoch,
        })
    }

    /// Write one layout run: the run row, then its regions, themes and links,
    /// four statements. Returns the run id.
    ///
    /// # Errors
    /// `DbError::QueryFailed` on any statement (a CHECK or FK violation
    /// included); the caller's transaction then rolls the whole run back.
    pub async fn write_run(conn: &mut PgConnection, build: &LayoutBuild) -> Result<Uuid, DbError> {
        let theme_count = i32::try_from(build.themes.len()).unwrap_or(i32::MAX);
        let region_count = i32::try_from(build.regions.len()).unwrap_or(i32::MAX);
        let run_id: Uuid = sqlx::query_scalar(
            "INSERT INTO atlas_layout_runs \
                 (algo, params, cluster_run_id, visibility_epoch, theme_count, region_count, \
                  public_claim_count, public_link_count, theme_set_digest) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             RETURNING id",
        )
        .bind(&build.algo)
        .bind(&build.params)
        .bind(build.cluster_run_id)
        .bind(build.visibility_epoch)
        .bind(theme_count)
        .bind(region_count)
        .bind(build.public_claim_count)
        .bind(build.public_link_count)
        .bind(&build.theme_set_digest)
        .fetch_one(&mut *conn)
        .await?;

        let r = &build.regions;
        sqlx::query(
            "INSERT INTO atlas_layout_regions (id, run_id, ordinal, label, x, y, r, centroid) \
             SELECT u.id, $1, u.ordinal, u.label, u.x, u.y, u.r, u.centroid::vector(1536) \
             FROM UNNEST($2::uuid[], $3::int4[], $4::text[], $5::float8[], $6::float8[], \
                         $7::float8[], $8::text[]) \
                  AS u(id, ordinal, label, x, y, r, centroid)",
        )
        .bind(run_id)
        .bind(r.iter().map(|x| x.id).collect::<Vec<_>>())
        .bind(r.iter().map(|x| x.ordinal).collect::<Vec<_>>())
        .bind(r.iter().map(|x| x.label.clone()).collect::<Vec<_>>())
        .bind(r.iter().map(|x| x.x).collect::<Vec<_>>())
        .bind(r.iter().map(|x| x.y).collect::<Vec<_>>())
        .bind(r.iter().map(|x| x.r).collect::<Vec<_>>())
        .bind(
            r.iter()
                .map(|x| pgvector_text(&x.centroid))
                .collect::<Vec<_>>(),
        )
        .execute(&mut *conn)
        .await?;

        let t = &build.themes;
        sqlx::query(
            "INSERT INTO atlas_layout_themes \
                 (run_id, theme_id, region_id, rank_in_region, x, y, public_member_count) \
             SELECT $1, u.theme_id, u.region_id, u.rank_in_region, u.x, u.y, u.n \
             FROM UNNEST($2::uuid[], $3::uuid[], $4::int4[], $5::float8[], $6::float8[], \
                         $7::int8[]) \
                  AS u(theme_id, region_id, rank_in_region, x, y, n)",
        )
        .bind(run_id)
        .bind(t.iter().map(|x| x.theme_id).collect::<Vec<_>>())
        .bind(t.iter().map(|x| x.region_id).collect::<Vec<_>>())
        .bind(t.iter().map(|x| x.rank_in_region).collect::<Vec<_>>())
        .bind(t.iter().map(|x| x.x).collect::<Vec<_>>())
        .bind(t.iter().map(|x| x.y).collect::<Vec<_>>())
        .bind(t.iter().map(|x| x.public_member_count).collect::<Vec<_>>())
        .execute(&mut *conn)
        .await?;

        let l = &build.theme_links;
        sqlx::query(
            "INSERT INTO atlas_layout_theme_links \
                 (run_id, theme_a, theme_b, relationship, link_count) \
             SELECT $1, u.a, u.b, u.rel, u.n \
             FROM UNNEST($2::uuid[], $3::uuid[], $4::text[], $5::int8[]) AS u(a, b, rel, n)",
        )
        .bind(run_id)
        .bind(l.iter().map(|x| x.theme_a).collect::<Vec<_>>())
        .bind(l.iter().map(|x| x.theme_b).collect::<Vec<_>>())
        .bind(l.iter().map(|x| x.relationship.clone()).collect::<Vec<_>>())
        .bind(l.iter().map(|x| x.link_count).collect::<Vec<_>>())
        .execute(&mut *conn)
        .await?;

        Ok(run_id)
    }

    /// Delete every run but the newest `keep` (at least one); child rows go
    /// with them through the foreign keys. Returns the runs deleted.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn prune_runs(conn: &mut PgConnection, keep: i64) -> Result<u64, DbError> {
        let done = sqlx::query(
            "DELETE FROM atlas_layout_runs WHERE id NOT IN \
                 (SELECT id FROM atlas_layout_runs \
                   ORDER BY completed_at DESC, id DESC LIMIT $1)",
        )
        .bind(keep.max(1))
        .execute(&mut *conn)
        .await?;
        Ok(done.rows_affected())
    }

    // ── serve: run ───────────────────────────────────────────────────────────

    /// The run `run_id` names, or the latest when `None`, with its `stale`
    /// and `current` flags. One statement.
    ///
    /// Takes no viewer: `atlas_layout_runs`, `atlas_layout_themes`,
    /// `atlas_layout_epoch` and `claim_themes` carry no tenancy columns, and
    /// the row holds no claim content or claim id.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn run<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        run_id: Option<Uuid>,
    ) -> Result<Option<LayoutRunRow>, DbError> {
        let row = sqlx::query_as::<_, LayoutRunRow>(
            "SELECT r.id, r.completed_at, r.algo, r.cluster_run_id, r.theme_count, \
                    ( EXISTS (SELECT 1 FROM claim_themes t WHERE t.created_at > r.completed_at) \
                      OR (SELECT COUNT(*) FROM atlas_layout_themes lt WHERE lt.run_id = r.id) \
                         < r.theme_count ) AS stale, \
                    (r.visibility_epoch = e.n) AS current \
             FROM atlas_layout_runs r CROSS JOIN atlas_layout_epoch e \
             WHERE ($1::uuid IS NULL OR r.id = $1) \
             ORDER BY r.completed_at DESC, r.id DESC \
             LIMIT 1",
        )
        .bind(run_id)
        .fetch_optional(executor)
        .await?;
        Ok(row)
    }

    // ── serve: the per-viewer theme set ──────────────────────────────────────

    /// Every theme the viewer can read (a current member the viewer may
    /// read), with the viewer's count, and its region in `run_id`: the shared
    /// row when there is one, else the viewer's own placement.
    async fn visible_themes(
        conn: &mut PgConnection,
        viewer: &Viewer,
        run_id: Uuid,
    ) -> Result<Vec<VisibleTheme>, DbError> {
        let sql = viewer.splice(
            "WITH vis AS ( \
                 SELECT c.theme_id, COUNT(*)::int8 AS n \
                 FROM claims c \
                 WHERE c.theme_id IS NOT NULL AND c.is_current \
                   /* {VISIBILITY:c} */ \
                 GROUP BY c.theme_id \
             ) \
             SELECT vis.theme_id, vis.n, lt.region_id, lt.rank_in_region \
             FROM vis \
             LEFT JOIN atlas_layout_themes lt ON lt.run_id = $1 AND lt.theme_id = vis.theme_id \
             ORDER BY vis.theme_id",
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, i64, Option<Uuid>, Option<i32>)>(&sql).bind(run_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(&mut *conn).await?;

        let mut out: Vec<VisibleTheme> = Vec::with_capacity(rows.len());
        let mut candidates: Vec<Uuid> = Vec::new();
        for (theme_id, n, region_id, rank) in rows {
            let placement = if region_id.is_some() {
                ThemePlacement::Shared
            } else {
                candidates.push(theme_id);
                ThemePlacement::Unplaced
            };
            out.push(VisibleTheme {
                theme_id,
                n,
                region_id,
                rank,
                placement,
            });
        }
        if candidates.is_empty() {
            return Ok(out);
        }
        candidates.truncate(VIEWER_PLACEMENT_CAP);
        let assigned: HashMap<Uuid, Uuid> = Self::viewer_regions(conn, viewer, run_id, &candidates)
            .await?
            .into_iter()
            .collect();
        for t in &mut out {
            if t.placement == ThemePlacement::Unplaced {
                if let Some(region) = assigned.get(&t.theme_id) {
                    t.region_id = Some(*region);
                    t.placement = ThemePlacement::Viewer;
                }
            }
        }
        Ok(out)
    }

    /// For each of `theme_ids`, the region of `run_id` whose centroid is
    /// nearest (cosine) the mean embedding of the theme's current members
    /// THIS viewer can read. A theme with no such embedded member has no row.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn viewer_regions(
        conn: &mut PgConnection,
        viewer: &Viewer,
        run_id: Uuid,
        theme_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, Uuid)>, DbError> {
        if theme_ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            "WITH cen AS ( \
                 SELECT c.theme_id, AVG(c.embedding) AS v \
                 FROM claims c \
                 WHERE c.theme_id = ANY($2::uuid[]) AND c.is_current \
                   AND c.embedding IS NOT NULL \
                   /* {VISIBILITY:c} */ \
                 GROUP BY c.theme_id \
             ) \
             SELECT cen.theme_id, \
                    (SELECT r.id FROM atlas_layout_regions r WHERE r.run_id = $1 \
                      ORDER BY r.centroid <=> cen.v, r.ordinal LIMIT 1) AS region_id \
             FROM cen \
             ORDER BY cen.theme_id",
            3,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(&sql)
            .bind(run_id)
            .bind(theme_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(&mut *conn).await?;
        Ok(rows
            .into_iter()
            .filter_map(|(t, r)| r.map(|r| (t, r)))
            .collect())
    }

    // ── serve: untenanted helpers (each one statement, no viewer) ────────────

    /// The regions of `run_id` in ordinal order.
    async fn region_rows<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        run_id: Uuid,
    ) -> Result<Vec<LayoutRegionRow>, DbError> {
        Ok(sqlx::query_as::<_, LayoutRegionRow>(
            "SELECT id, ordinal, label, x, y, r FROM atlas_layout_regions \
             WHERE run_id = $1 ORDER BY ordinal",
        )
        .bind(run_id)
        .fetch_all(executor)
        .await?)
    }

    /// Labels of `theme_ids`, and their shared positions in `run_id` if any.
    async fn theme_rows<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        run_id: Uuid,
        theme_ids: &[Uuid],
    ) -> Result<Vec<ThemeLabelRow>, DbError> {
        Ok(sqlx::query_as::<_, ThemeLabelRow>(
            "SELECT t.id, left(t.label, 200) AS label, lt.x, lt.y \
             FROM claim_themes t \
             LEFT JOIN atlas_layout_themes lt ON lt.run_id = $1 AND lt.theme_id = t.id \
             WHERE t.id = ANY($2::uuid[])",
        )
        .bind(run_id)
        .bind(theme_ids)
        .fetch_all(executor)
        .await?)
    }

    /// Region-pair bundles over the theme pairs whose two themes are in
    /// `shared_visible` (the caller's visible shared set) and sit in
    /// different regions; one keyset page of whole bundles (`limit + 1`).
    async fn region_bundle_rows<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        run_id: Uuid,
        shared_visible: &[Uuid],
        rels: Option<Vec<String>>,
        after: Option<LayoutLinkCursor>,
        limit_plus_one: i64,
    ) -> Result<Vec<LayoutLinkRow>, DbError> {
        Ok(sqlx::query_as::<_, LayoutLinkRow>(
            "WITH per_rel AS ( \
                 SELECT LEAST(ta.region_id, tb.region_id) AS a, \
                        GREATEST(ta.region_id, tb.region_id) AS b, \
                        l.relationship, SUM(l.link_count)::int8 AS link_count \
                 FROM atlas_layout_theme_links l \
                 JOIN atlas_layout_themes ta ON ta.run_id = l.run_id AND ta.theme_id = l.theme_a \
                 JOIN atlas_layout_themes tb ON tb.run_id = l.run_id AND tb.theme_id = l.theme_b \
                 WHERE l.run_id = $1 \
                   AND l.theme_a = ANY($2::uuid[]) AND l.theme_b = ANY($2::uuid[]) \
                   AND ta.region_id <> tb.region_id \
                   AND ($3::text[] IS NULL OR l.relationship = ANY($3::text[])) \
                 GROUP BY 1, 2, 3 \
             ), pairs AS ( \
                 SELECT a, b, SUM(link_count)::int8 AS total FROM per_rel GROUP BY 1, 2 \
             ), page AS ( \
                 SELECT a, b, total FROM pairs \
                 WHERE $4::int8 IS NULL OR (total, a, b) < ($4::int8, $5::uuid, $6::uuid) \
                 ORDER BY total DESC, a DESC, b DESC \
                 LIMIT $7 \
             ) \
             SELECT 'region'::text AS kind, p.a, p.b, x.relationship, x.link_count, p.total \
             FROM page p JOIN per_rel x ON x.a = p.a AND x.b = p.b \
             ORDER BY p.total DESC, p.a DESC, p.b DESC, x.relationship",
        )
        .bind(run_id)
        .bind(shared_visible)
        .bind(rels)
        .bind(after.map(|c| c.total))
        .bind(after.map(|c| c.a))
        .bind(after.map(|c| c.b))
        .bind(limit_plus_one)
        .fetch_all(executor)
        .await?)
    }

    /// A region's bundles: `theme` pairs with both themes in `region_id`, and
    /// `theme_region` stubs from a theme in `region_id` to another region,
    /// summed per (theme, other region). Both themes of every counted pair
    /// are in `shared_visible`. One keyset page of whole bundles.
    async fn region_link_rows<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        run_id: Uuid,
        region_id: Uuid,
        shared_visible: &[Uuid],
        rels: Option<Vec<String>>,
        after: Option<LayoutLinkCursor>,
        limit_plus_one: i64,
    ) -> Result<Vec<LayoutLinkRow>, DbError> {
        Ok(sqlx::query_as::<_, LayoutLinkRow>(
            "WITH pl AS ( \
                 SELECT lt.theme_id, lt.region_id FROM atlas_layout_themes lt \
                 WHERE lt.run_id = $1 AND lt.theme_id = ANY($2::uuid[]) \
             ), inner_links AS ( \
                 SELECT 1 AS kind, l.theme_a AS a, l.theme_b AS b, l.relationship, \
                        l.link_count::int8 AS link_count \
                 FROM atlas_layout_theme_links l \
                 JOIN pl pa ON pa.theme_id = l.theme_a \
                 JOIN pl pb ON pb.theme_id = l.theme_b \
                 WHERE l.run_id = $1 AND pa.region_id = $3 AND pb.region_id = $3 \
                   AND ($4::text[] IS NULL OR l.relationship = ANY($4::text[])) \
             ), stubs AS ( \
                 SELECT 0 AS kind, \
                        CASE WHEN pa.region_id = $3 THEN l.theme_a ELSE l.theme_b END AS a, \
                        CASE WHEN pa.region_id = $3 THEN pb.region_id ELSE pa.region_id END AS b, \
                        l.relationship, SUM(l.link_count)::int8 AS link_count \
                 FROM atlas_layout_theme_links l \
                 JOIN pl pa ON pa.theme_id = l.theme_a \
                 JOIN pl pb ON pb.theme_id = l.theme_b \
                 WHERE l.run_id = $1 AND (pa.region_id = $3) <> (pb.region_id = $3) \
                   AND ($4::text[] IS NULL OR l.relationship = ANY($4::text[])) \
                 GROUP BY 1, 2, 3, 4 \
             ), per_rel AS ( \
                 SELECT kind, a, b, relationship, link_count FROM inner_links \
                 UNION ALL \
                 SELECT kind, a, b, relationship, link_count FROM stubs \
             ), pairs AS ( \
                 SELECT kind, a, b, SUM(link_count)::int8 AS total FROM per_rel GROUP BY 1, 2, 3 \
             ), page AS ( \
                 SELECT kind, a, b, total FROM pairs \
                 WHERE $5::int8 IS NULL \
                    OR (total, kind, a, b) < ($5::int8, $6::int4, $7::uuid, $8::uuid) \
                 ORDER BY total DESC, kind DESC, a DESC, b DESC \
                 LIMIT $9 \
             ) \
             SELECT CASE p.kind WHEN 1 THEN 'theme' ELSE 'theme_region' END AS kind, \
                    p.a, p.b, x.relationship, x.link_count, p.total \
             FROM page p JOIN per_rel x ON x.kind = p.kind AND x.a = p.a AND x.b = p.b \
             ORDER BY p.total DESC, p.kind DESC, p.a DESC, p.b DESC, x.relationship",
        )
        .bind(run_id)
        .bind(shared_visible)
        .bind(region_id)
        .bind(rels)
        .bind(after.map(|c| c.total))
        .bind(after.map(|c| i32::from(c.kind)))
        .bind(after.map(|c| c.a))
        .bind(after.map(|c| c.b))
        .bind(limit_plus_one)
        .fetch_all(executor)
        .await?)
    }

    // ── serve: the layout route ──────────────────────────────────────────────

    /// The top level of `run_id` as `viewer` sees it: the regions holding a
    /// theme the viewer can read, with the viewer's counts, and one page of
    /// region-pair bundles summed over the theme pairs the viewer can see.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if any statement fails.
    pub async fn overview(
        conn: &mut PgConnection,
        viewer: &Viewer,
        run_id: Uuid,
        rels: Option<&[String]>,
        links_after: Option<LayoutLinkCursor>,
        limit: i64,
    ) -> Result<LayoutOverview, DbError> {
        let limit = clamp_limit(limit);
        let visible = Self::visible_themes(&mut *conn, viewer, run_id).await?;
        let regions = Self::region_rows(&mut *conn, run_id).await?;

        let mut out_regions = Vec::new();
        for region in regions {
            if let Some(row) = visible_region(&region, &visible) {
                out_regions.push(row);
            }
        }
        let unplaced_theme_count = i64::try_from(
            visible
                .iter()
                .filter(|t| t.placement == ThemePlacement::Unplaced)
                .count(),
        )
        .unwrap_or(i64::MAX);

        let shared: Vec<Uuid> = visible
            .iter()
            .filter(|t| t.placement == ThemePlacement::Shared)
            .map(|t| t.theme_id)
            .collect();
        let rows = Self::region_bundle_rows(
            &mut *conn,
            run_id,
            &shared,
            rels.map(<[String]>::to_vec),
            links_after,
            i64::try_from(limit).unwrap_or(ATLAS_PAGE_MAX) + 1,
        )
        .await?;
        let (links, next_links) = page_bundles(rows, limit, |_| 2);

        Ok(LayoutOverview {
            regions: out_regions,
            links,
            unplaced_theme_count,
            next_links,
        })
    }

    /// Region `region_id` of `run_id` as `viewer` sees it, or `None` when it
    /// is not a region of the run OR holds no theme the viewer can see (the
    /// same `None`, so the route's 404 cannot tell the two apart).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if any statement fails.
    pub async fn region_detail(
        conn: &mut PgConnection,
        viewer: &Viewer,
        run_id: Uuid,
        region_id: Uuid,
        rels: Option<&[String]>,
        part: DetailPart,
        limit: i64,
    ) -> Result<Option<RegionDetail>, DbError> {
        let limit = clamp_limit(limit);
        let visible = Self::visible_themes(&mut *conn, viewer, run_id).await?;
        let regions = Self::region_rows(&mut *conn, run_id).await?;
        let Some(region) = regions.into_iter().find(|r| r.id == region_id) else {
            return Ok(None);
        };
        let Some(region_row) = visible_region(&region, &visible) else {
            return Ok(None);
        };

        let (themes, next_themes) = match &part {
            DetailPart::LinksAfter(_) => (Vec::new(), None),
            DetailPart::Both | DetailPart::ThemesAfter(_) => {
                let after = match &part {
                    DetailPart::ThemesAfter(c) => Some((c.rank_key, c.theme_id)),
                    _ => None,
                };
                let mut in_region: Vec<&VisibleTheme> = visible
                    .iter()
                    .filter(|t| t.region_id == Some(region_id))
                    .filter(|t| match after {
                        Some(a) => t.order_key() > a,
                        None => true,
                    })
                    .collect();
                in_region.sort_by_key(|t| t.order_key());
                let more = in_region.len() > limit;
                in_region.truncate(limit);
                let ids: Vec<Uuid> = in_region.iter().map(|t| t.theme_id).collect();
                let labels: HashMap<Uuid, ThemeLabelRow> =
                    Self::theme_rows(&mut *conn, run_id, &ids)
                        .await?
                        .into_iter()
                        .map(|r| (r.id, r))
                        .collect();
                let rows: Vec<VisibleThemeRow> = in_region
                    .iter()
                    .map(|t| theme_row(t, labels.get(&t.theme_id)))
                    .collect();
                let next = if more {
                    in_region.last().map(|t| {
                        let (rank_key, theme_id) = t.order_key();
                        ThemePageCursor { rank_key, theme_id }
                    })
                } else {
                    None
                };
                (rows, next)
            }
        };

        let (links, next_links) = match &part {
            DetailPart::ThemesAfter(_) => (Vec::new(), None),
            DetailPart::Both | DetailPart::LinksAfter(_) => {
                let after = match &part {
                    DetailPart::LinksAfter(c) => Some(*c),
                    _ => None,
                };
                let shared: Vec<Uuid> = visible
                    .iter()
                    .filter(|t| t.placement == ThemePlacement::Shared)
                    .map(|t| t.theme_id)
                    .collect();
                let rows = Self::region_link_rows(
                    &mut *conn,
                    run_id,
                    region_id,
                    &shared,
                    rels.map(<[String]>::to_vec),
                    after,
                    i64::try_from(limit).unwrap_or(ATLAS_PAGE_MAX) + 1,
                )
                .await?;
                page_bundles(rows, limit, |k| u8::from(k == "theme"))
            }
        };

        Ok(Some(RegionDetail {
            region: region_row,
            themes,
            links,
            next_themes,
            next_links,
        }))
    }

    /// The viewer's unplaced themes in `run_id`: visible, with no shared row
    /// and no embedded member the viewer can read. Ordered by the label key
    /// (`unplaced_label_key`) then id.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if any statement fails.
    pub async fn unplaced_themes(
        conn: &mut PgConnection,
        viewer: &Viewer,
        run_id: Uuid,
        after: Option<UnplacedCursor>,
        limit: i64,
    ) -> Result<UnplacedPage, DbError> {
        let limit = clamp_limit(limit);
        let visible = Self::visible_themes(&mut *conn, viewer, run_id).await?;
        let unplaced: Vec<&VisibleTheme> = visible
            .iter()
            .filter(|t| t.placement == ThemePlacement::Unplaced)
            .collect();
        if unplaced.is_empty() {
            return Ok(UnplacedPage {
                themes: Vec::new(),
                next: None,
            });
        }
        let ids: Vec<Uuid> = unplaced.iter().map(|t| t.theme_id).collect();
        let labels: HashMap<Uuid, ThemeLabelRow> = Self::theme_rows(&mut *conn, run_id, &ids)
            .await?
            .into_iter()
            .map(|r| (r.id, r))
            .collect();
        let mut keyed: Vec<((String, Uuid), &VisibleTheme)> = unplaced
            .into_iter()
            .map(|t| {
                let label = labels.get(&t.theme_id).map_or("", |r| r.label.as_str());
                ((unplaced_label_key(label), t.theme_id), t)
            })
            .filter(|(k, _)| match &after {
                Some(c) => (k.0.as_str(), k.1) > (c.label_key.as_str(), c.id),
                None => true,
            })
            .collect();
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        let more = keyed.len() > limit;
        keyed.truncate(limit);
        let next = if more {
            keyed.last().map(|((label_key, id), _)| UnplacedCursor {
                label_key: label_key.clone(),
                id: *id,
            })
        } else {
            None
        };
        let themes = keyed
            .iter()
            .map(|(_, t)| theme_row(t, labels.get(&t.theme_id)))
            .collect();
        Ok(UnplacedPage { themes, next })
    }

    /// Where `theme_id` sits in the latest servable layout for `viewer`: its
    /// shared position, else the viewer's own region for it, else `None`
    /// (no run, an invalidated run, or no embedded member the viewer reads).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if any statement fails.
    pub async fn placement_layout(
        conn: &mut PgConnection,
        viewer: &Viewer,
        theme_id: Uuid,
    ) -> Result<Option<PlacementLayoutRow>, DbError> {
        let Some(run) = Self::run(&mut *conn, None).await? else {
            return Ok(None);
        };
        if !run.current {
            return Ok(None);
        }
        // The shared position, served only while the viewer can read some
        // member of the theme (the caller has just read one claim of it).
        let sql = viewer.splice(
            "SELECT lt.region_id, lt.x, lt.y FROM atlas_layout_themes lt \
             WHERE lt.run_id = $1 AND lt.theme_id = $2 \
               AND EXISTS (SELECT 1 FROM claims c WHERE c.theme_id = lt.theme_id \
                           /* {VISIBILITY:c} */)",
            3,
        );
        let mut q = sqlx::query_as::<_, (Uuid, f64, f64)>(&sql)
            .bind(run.id)
            .bind(theme_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        if let Some((region_id, x, y)) = q.fetch_optional(&mut *conn).await? {
            return Ok(Some(PlacementLayoutRow {
                run_id: run.id,
                region_id,
                placement: ThemePlacement::Shared,
                x: Some(x),
                y: Some(y),
            }));
        }
        let assigned = Self::viewer_regions(conn, viewer, run.id, &[theme_id]).await?;
        Ok(assigned
            .into_iter()
            .next()
            .map(|(_, region_id)| PlacementLayoutRow {
                run_id: run.id,
                region_id,
                placement: ThemePlacement::Viewer,
                x: None,
                y: None,
            }))
    }

    // ── serve: the links route ───────────────────────────────────────────────

    /// Resolve `from` and `to` in ONE statement: a region of `run_id` gives
    /// its shared themes, else a `claim_themes` id gives that theme. `None`
    /// for an id that is neither. `run_id = None` resolves themes only.
    ///
    /// Takes no viewer: `claim_themes` and `atlas_layout_*` carry no tenancy
    /// columns. The caller checks each side for a member the viewer can read
    /// (`any_visible_member`) before it acts on the answer.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn resolve_sides<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        run_id: Option<Uuid>,
        from: Uuid,
        to: Uuid,
    ) -> Result<(Option<LinkSide>, Option<LinkSide>), DbError> {
        let rows: Vec<(Uuid, String, Uuid)> = sqlx::query_as(
            "SELECT s.id AS side_id, 'region'::text AS kind, lt.theme_id \
             FROM unnest($2::uuid[]) AS s(id) \
             JOIN atlas_layout_themes lt ON lt.run_id = $1 AND lt.region_id = s.id \
             UNION ALL \
             SELECT s.id, 'theme'::text, t.id \
             FROM unnest($2::uuid[]) AS s(id) \
             JOIN claim_themes t ON t.id = s.id \
             WHERE NOT EXISTS (SELECT 1 FROM atlas_layout_regions r \
                               WHERE r.run_id = $1 AND r.id = s.id)",
        )
        .bind(run_id)
        .bind(vec![from, to])
        .fetch_all(executor)
        .await?;
        let side = |id: Uuid| -> Option<LinkSide> {
            let mine: Vec<&(Uuid, String, Uuid)> = rows.iter().filter(|r| r.0 == id).collect();
            let first = mine.first()?;
            let kind = if first.1 == "region" {
                LinkSideKind::Region
            } else {
                LinkSideKind::Theme
            };
            let mut theme_ids: Vec<Uuid> = mine.iter().map(|r| r.2).collect();
            theme_ids.sort_unstable();
            theme_ids.dedup();
            Some(LinkSide {
                id,
                kind,
                theme_ids,
            })
        };
        Ok((side(from), side(to)))
    }

    /// Does any of `theme_ids` have a current member `viewer` can read?
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn any_visible_member(
        conn: &mut PgConnection,
        viewer: &Viewer,
        theme_ids: &[Uuid],
    ) -> Result<bool, DbError> {
        if theme_ids.is_empty() {
            return Ok(false);
        }
        let sql = viewer.splice(
            "SELECT EXISTS (SELECT 1 FROM claims c \
                            WHERE c.theme_id = ANY($1::uuid[]) AND c.is_current \
                            /* {VISIBILITY:c} */)",
            2,
        );
        let mut q = sqlx::query_scalar::<_, bool>(&sql).bind(theme_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_one(&mut *conn).await?)
    }

    /// The claim pairs between `from_themes` and `to_themes` that `viewer`
    /// may read (the edge and both endpoints through the predicate), in
    /// `strength DESC NULLS LAST, created_at DESC, id DESC` order, one keyset
    /// page, plus their per-relationship counts.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if either statement fails.
    pub async fn links_between(
        conn: &mut PgConnection,
        viewer: &Viewer,
        from_themes: &[Uuid],
        to_themes: &[Uuid],
        rels: Option<&[String]>,
        after: Option<LinkPairCursor>,
        limit: i64,
    ) -> Result<LinkPage, DbError> {
        let limit = clamp_limit(limit);
        let rels: Option<Vec<String>> = rels.map(<[String]>::to_vec);

        let page_sql = viewer.splice(
            "SELECT e.id AS edge_id, \
                    cs.id AS source_id, cs.truth_value AS source_truth_value, \
                    cs.theme_id AS source_theme_id, \
                    ct.id AS target_id, ct.truth_value AS target_truth_value, \
                    ct.theme_id AS target_theme_id, \
                    left(cs.content, 200) AS source_content, \
                    left(ct.content, 200) AS target_content, \
                    lower(e.relationship) AS relationship, e.created_at, \
                    (cs.theme_id = ANY($1::uuid[])) AS from_is_source, \
                    s.strength \
             FROM edges e \
             JOIN claims cs ON cs.id = e.source_id \
             JOIN claims ct ON ct.id = e.target_id \
             CROSS JOIN LATERAL (SELECT COALESCE( \
                 CASE WHEN jsonb_typeof(e.properties->'strength') = 'number' \
                      THEN (e.properties->>'strength')::float8 END, \
                 CASE WHEN jsonb_typeof(e.properties->'confidence') = 'number' \
                      THEN (e.properties->>'confidence')::float8 END \
               ) AS strength) s \
             WHERE e.source_type = 'claim' AND e.target_type = 'claim' \
               AND (e.valid_to IS NULL OR e.valid_to > now()) \
               AND ($3::text[] IS NULL OR lower(e.relationship) = ANY($3::text[])) \
               AND cs.is_current AND ct.is_current \
               AND ( (cs.theme_id = ANY($1::uuid[]) AND ct.theme_id = ANY($2::uuid[])) \
                  OR (cs.theme_id = ANY($2::uuid[]) AND ct.theme_id = ANY($1::uuid[])) ) \
               AND ( $4::bool IS NULL \
                  OR ($4::bool AND ( s.strength IS NULL \
                                  OR s.strength < $5::float8 \
                                  OR (s.strength = $5::float8 \
                                      AND (e.created_at, e.id) < ($6::timestamptz, $7::uuid)) )) \
                  OR (NOT $4::bool AND s.strength IS NULL \
                      AND (e.created_at, e.id) < ($6::timestamptz, $7::uuid)) ) \
               /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:cs} */ /* {VISIBILITY:ct} */ \
             ORDER BY s.strength DESC NULLS LAST, e.created_at DESC, e.id DESC \
             LIMIT $8",
            9,
        );
        let mut q = sqlx::query_as::<_, LinkPairRow>(&page_sql)
            .bind(from_themes)
            .bind(to_themes)
            .bind(rels.clone())
            .bind(after.map(|c| c.has_strength))
            .bind(after.map(|c| c.strength()))
            .bind(after.map(|c| c.created_at()))
            .bind(after.map(|c| c.edge_id))
            .bind(i64::try_from(limit).unwrap_or(ATLAS_PAGE_MAX) + 1);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let mut items = q.fetch_all(&mut *conn).await?;
        let more = items.len() > limit;
        items.truncate(limit);
        let next = if more {
            items.last().map(LinkPairCursor::of)
        } else {
            None
        };

        let count_sql = viewer.splice(
            "SELECT lower(e.relationship) AS relationship, COUNT(*)::int8 AS n \
             FROM edges e \
             JOIN claims cs ON cs.id = e.source_id \
             JOIN claims ct ON ct.id = e.target_id \
             WHERE e.source_type = 'claim' AND e.target_type = 'claim' \
               AND (e.valid_to IS NULL OR e.valid_to > now()) \
               AND ($3::text[] IS NULL OR lower(e.relationship) = ANY($3::text[])) \
               AND cs.is_current AND ct.is_current \
               AND ( (cs.theme_id = ANY($1::uuid[]) AND ct.theme_id = ANY($2::uuid[])) \
                  OR (cs.theme_id = ANY($2::uuid[]) AND ct.theme_id = ANY($1::uuid[])) ) \
               /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:cs} */ /* {VISIBILITY:ct} */ \
             GROUP BY 1 \
             ORDER BY 1",
            4,
        );
        let mut q = sqlx::query_as::<_, (String, i64)>(&count_sql)
            .bind(from_themes)
            .bind(to_themes)
            .bind(rels);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let counts = q.fetch_all(&mut *conn).await?;

        Ok(LinkPage {
            items,
            counts,
            next,
        })
    }
}

/// `region` as the viewer sees it, or `None` when it holds no visible theme.
fn visible_region(region: &LayoutRegionRow, visible: &[VisibleTheme]) -> Option<VisibleRegionRow> {
    let mut members: Vec<&VisibleTheme> = visible
        .iter()
        .filter(|t| t.region_id == Some(region.id))
        .collect();
    if members.is_empty() {
        return None;
    }
    members.sort_by_key(|t| t.order_key());
    let theme_count = i64::try_from(members.len()).unwrap_or(i64::MAX);
    let member_count = members.iter().map(|t| t.n).sum();
    let cap = clamp_limit(ATLAS_PAGE_MAX);
    let theme_ids = members.iter().take(cap).map(|t| t.theme_id).collect();
    Some(VisibleRegionRow {
        id: region.id,
        ordinal: region.ordinal,
        label: region.label.clone(),
        x: region.x,
        y: region.y,
        r: region.r,
        theme_ids,
        theme_count,
        member_count,
    })
}

fn theme_row(t: &VisibleTheme, label: Option<&ThemeLabelRow>) -> VisibleThemeRow {
    let shared = t.placement == ThemePlacement::Shared;
    VisibleThemeRow {
        theme_id: t.theme_id,
        label: label.map(|r| r.label.clone()).unwrap_or_default(),
        region_id: t.region_id,
        placement: t.placement,
        x: if shared {
            label.and_then(|r| r.x)
        } else {
            None
        },
        y: if shared {
            label.and_then(|r| r.y)
        } else {
            None
        },
        member_count: t.n,
    }
}

/// Do the two theme sets share a theme? (A drill-down between a region and a
/// theme inside it has no cross links to list.)
#[must_use]
pub fn theme_sets_overlap(a: &[Uuid], b: &[Uuid]) -> bool {
    let set: HashSet<&Uuid> = a.iter().collect();
    b.iter().any(|t| set.contains(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_relationships_are_the_epistemic_set_plus_cites() {
        let mut want: Vec<&str> = crate::repos::edge::EPISTEMIC_RELATIONSHIPS.to_vec();
        want.push("cites");
        assert_eq!(ATLAS_DEFAULT_RELATIONSHIPS, want.as_slice());
    }

    #[test]
    fn cursors_round_trip_and_refuse_garbage() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let t = ThemePageCursor {
            rank_key: i32::MAX,
            theme_id: a,
        };
        assert_eq!(ThemePageCursor::decode(&t.encode()), Some(t));
        let l = LayoutLinkCursor {
            total: 46,
            kind: 1,
            a,
            b,
        };
        assert_eq!(LayoutLinkCursor::decode(&l.encode()), Some(l));
        let u = UnplacedCursor {
            label_key: unplaced_label_key("Électrode notes"),
            id: a,
        };
        assert_eq!(UnplacedCursor::decode(&u.encode()), Some(u));
        let g = LinkPairCursor {
            has_strength: true,
            strength_bits: 0.8_f64.to_bits(),
            created_at_micros: 1_730_700_000_000_000,
            edge_id: b,
        };
        assert_eq!(LinkPairCursor::decode(&g.encode()), Some(g));
        let n = LinkPairCursor {
            has_strength: false,
            strength_bits: 0,
            created_at_micros: 0,
            edge_id: b,
        };
        assert_eq!(LinkPairCursor::decode(&n.encode()), Some(n));
        for bad in [
            "",
            "lt2.",
            "lt2.-1.00000000000000000000000000000000",
            "lt1.3.00000000000000000000000000000000",
            "ll1.0.1.00000000000000000000000000000000.00000000000000000000000000000000",
            "ll1.3.7.00000000000000000000000000000000.00000000000000000000000000000000",
            "lu1.zz.00000000000000000000000000000000",
            "gl2.s.7ff0000000000000.0.00000000000000000000000000000000",
            "gl2.n.3fe999999999999a.0.00000000000000000000000000000000",
            "gl2.s.3fe999999999999a.-999999999999999999.00000000000000000000000000000000",
        ] {
            assert!(ThemePageCursor::decode(bad).is_none(), "{bad}");
            assert!(LayoutLinkCursor::decode(bad).is_none(), "{bad}");
            assert!(UnplacedCursor::decode(bad).is_none(), "{bad}");
            assert!(LinkPairCursor::decode(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn every_cursor_fits_the_explorer_token_shape() {
        let id = Uuid::new_v4();
        let long = "\u{1F600}".repeat(200);
        let tokens = [
            ThemePageCursor {
                rank_key: i32::MAX,
                theme_id: id,
            }
            .encode(),
            LayoutLinkCursor {
                total: i64::MAX,
                kind: 2,
                a: id,
                b: id,
            }
            .encode(),
            UnplacedCursor {
                label_key: unplaced_label_key(&long),
                id,
            }
            .encode(),
            LinkPairCursor {
                has_strength: true,
                strength_bits: (-1.5_f64).to_bits(),
                created_at_micros: i64::MAX,
                edge_id: id,
            }
            .encode(),
        ];
        for t in tokens {
            assert!(t.len() <= 256, "{t}");
            assert!(
                t.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c)),
                "{t}"
            );
        }
    }

    #[test]
    fn the_label_key_cuts_on_a_char_boundary() {
        let s = "é".repeat(40);
        let k = unplaced_label_key(&s);
        assert!(k.len() <= UNPLACED_LABEL_KEY_BYTES);
        assert!(s.starts_with(&k));
        assert_eq!(unplaced_label_key("short"), "short");
    }

    #[test]
    fn page_bundles_keeps_whole_bundles() {
        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        let row = |a: usize, rel: &str, total: i64| LayoutLinkRow {
            kind: "region".into(),
            a: ids[a],
            b: ids[2],
            relationship: rel.into(),
            link_count: 1,
            total,
        };
        let rows = vec![
            row(0, "cites", 2),
            row(0, "supports", 2),
            row(1, "supports", 1),
        ];
        let (page, next) = page_bundles(rows.clone(), 1, |_| 2);
        assert_eq!(page.len(), 2);
        assert_eq!(
            next,
            Some(LayoutLinkCursor {
                total: 2,
                kind: 2,
                a: ids[0],
                b: ids[2]
            })
        );
        let (page, next) = page_bundles(rows, 2, |_| 2);
        assert_eq!(page.len(), 3);
        assert_eq!(next, None);
    }
}
