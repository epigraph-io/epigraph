//! `/bff/atlas/*`: the Atlas Topics view (phase P3a). OWNED BY THE ATLAS
//! AREA.
//!
//! Six read-only JSON routes, each listed by name (no generic passthrough):
//!
//! | Route | Upstream |
//! |---|---|
//! | `layout` | `GET /graph/themes/layout` (packed fallback: `/bff/themes`) |
//! | `theme/{id}/claims` | `POST /search/semantic` (`theme_core`), then `POST /claims/batch-get` |
//! | `claim/{id}` | `GET /claims/:id/context` + `/claims/:id/placement` (fallback `GET /claims/:id`) |
//! | `links` | `GET /graph/links` |
//! | `search` | `POST /search/semantic` or `GET /claims/by-labels` |
//! | `resolve/{key}` | `GET /claims/:id/placement` |
//!
//! # Tenancy
//!
//! Every route takes [`SignedIn`] and every upstream call carries the
//! viewer's own bearer through [`crate::upstream::Api`]; there is no service
//! token. The rules this module adds on top of viewer-filtered upstreams:
//!
//! - Every response is `Cache-Control: private, no-store` with no ETag.
//!   Only default-shape layout decodes are cached server-side, keyed per
//!   viewer ([`RequestAuth::cache_key`]) for [`ATLAS_LAYOUT_TTL`].
//! - Colour comes from `truth_value` alone. No body carries `belief`,
//!   `plausibility`, `pignistic_prob`, `mean_betp` or `epistemic`, and no
//!   `truth_value` is ever sorted, compared or folded here.
//! - Id-addressed routes answer "absent", "unreadable" and "forbidden" with
//!   one byte-identical 404 ([`atlas_id_err`]).
//! - A second-line drop rule removes every layout link whose endpoint the
//!   response does not carry and the viewer cannot otherwise see
//!   ([`filter_layout_links`]). Counts are passed through, never subtracted.
//! - Theme labels come only from the viewer's own theme directory (the
//!   `/bff/themes` body), which lists only themes with a readable member.
//!
//! Deep-link keys are `c-<32 hex>` claim keys only: themes are rebuilt with
//! every clustering run, so a theme id is never a durable key.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{RequestAuth, SignedIn};
use crate::bff::graph::{one_line, parse_id, relationship_family, themes_body_cached, LABEL_CHARS};
use crate::error::AppError;
use crate::links::Links;
use crate::pages::core::relationships::{fold, heading};
use crate::pages::core::search_view::{label_list, MAX_QUERY_CHARS};
use crate::pages::core::vocab::doi_url;
use crate::state::AppState;
use crate::upstream::atlas::{
    BatchGetClaim, ClaimContext, ContextEdge, ContextList, ContextListName, ContextNode,
    ContextPaper, GraphLinks, LayoutLink, LayoutQuery, LayoutRegion, LayoutRun, LinkEnd,
    LinksQuery, RelCount, ThemesLayout, BATCH_GET_MAX_IDS,
};
use crate::upstream::core::{LabelHit, SemanticHit};
use crate::upstream::{
    Api, ClaimResponse, Degraded, EdgeDirection, PlacementResponse, UpstreamError,
};

/// Most items in any one array of a BFF body.
pub const ATLAS_ITEM_CAP: usize = 200;
/// Largest BFF body (a tripwire: the caps below keep every body under it).
pub const ATLAS_BODY_CAP: usize = 2_000_000;
/// Per-viewer lifetime of a cached default-shape layout decode.
pub const ATLAS_LAYOUT_TTL: Duration = Duration::from_secs(30);
/// `/bff/atlas/layout?limit=` default (and the U5 maximum).
pub const LAYOUT_DEFAULT_LIMIT: u32 = 200;
/// Themes per packed-mode page.
pub const PACKED_PAGE: usize = 200;
pub const THEME_CLAIMS_DEFAULT: u32 = 60;
pub const THEME_CLAIMS_MAX: u32 = 100;
pub const LINKS_DEFAULT: u32 = 50;
pub const SEARCH_DEFAULT: u32 = 20;
/// The BFF-wide search cap (`upstream::core::MAX_SEARCH_LIMIT`).
pub const SEARCH_MAX: u32 = crate::upstream::core::MAX_SEARCH_LIMIT;
/// Centre-claim text carried by the claim panel.
pub const CENTRE_CONTENT_CHARS: usize = 1500;
/// Batch-get calls per theme page (the first plus resubmits of `remaining`).
pub const MAX_BATCH_GET_ROUNDS: usize = 3;
/// Highest `l.<n>` offset of the label search.
pub const MAX_LABEL_OFFSET: u64 = 1000;
/// Highest `o:<n>` offset (U2 refuses offsets of 1000 and more).
pub const MAX_SEMANTIC_OFFSET: u64 = 999;
/// Route budget, as a multiple of the per-call upstream timeout.
pub const ROUTE_BUDGET_FACTOR: f64 = 1.5;
/// Page size range of the U5 and U4 list routes.
const PAGE_MAX: u32 = 200;
const MAX_REL_TOKENS: usize = 12;
const MAX_REL_CHARS: usize = 40;
const MAX_CURSOR_CHARS: usize = 256;
const PAPER_TITLE_CHARS: usize = 300;
const PAPER_DOI_CHARS: usize = 256;
const ALGO_CHARS: usize = 64;

const STALE_LINK: &str = "That page link is no longer valid. Start again from the map.";
const SHORT_KEY: &str =
    "This link was shortened and cannot be followed. Ask for a full Atlas link.";
const OVERLAP: &str = "These two areas overlap, so there are no links between them to list.";
const NOTICE_STALE: &str =
    "The layout predates the latest clustering run; positions may be out of date.";
const NOTICE_PACKED: &str = "There is no layout run yet, so themes are packed by size and their positions carry no meaning.";
const NOTICE_TRUNCATED: &str = "Showing the 500 largest themes.";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/bff/atlas/layout", get(layout))
        .route("/bff/atlas/theme/{id}/claims", get(theme_claims))
        .route("/bff/atlas/claim/{id}", get(claim))
        .route("/bff/atlas/links", get(links))
        .route("/bff/atlas/search", get(search))
        .route("/bff/atlas/resolve/{key}", get(resolve))
}

// ---- shared helpers ---------------------------------------------------------------

/// The deep-link key of a claim: `c-<32 lower-case hex>`.
pub fn claim_key(id: Uuid) -> String {
    format!("c-{}", id.simple())
}

/// Why a deep-link key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// `c-` plus 8 hex digits: a prototype's shortened key.
    Short,
    /// Anything else, every `t-` key included.
    Malformed,
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `c-` followed by 32 lower-case hex digits or a hyphenated lower-case
/// UUID. The answer depends on the key's syntax alone.
pub fn parse_key(raw: &str) -> Result<Uuid, KeyError> {
    let rest = raw.strip_prefix("c-").ok_or(KeyError::Malformed)?;
    if rest.len() == 8 && is_lower_hex(rest) {
        return Err(KeyError::Short);
    }
    let simple = match rest.len() {
        32 if is_lower_hex(rest) => rest.to_string(),
        36 => {
            let b = rest.as_bytes();
            let hyphens_ok = [8, 13, 18, 23].iter().all(|&i| b[i] == b'-');
            let hex: String = rest.chars().filter(|c| *c != '-').collect();
            if !hyphens_ok || hex.len() != 32 || !is_lower_hex(&hex) {
                return Err(KeyError::Malformed);
            }
            hex
        }
        _ => return Err(KeyError::Malformed),
    };
    Uuid::parse_str(&simple).map_err(|_| KeyError::Malformed)
}

/// One line of at most [`LABEL_CHARS`] chars (ellipsis included).
fn label_of(s: &str) -> String {
    let line = one_line(s, LABEL_CHARS);
    if line.chars().count() > LABEL_CHARS {
        one_line(s, LABEL_CHARS - 1)
    } else {
        line
    }
}

/// Cut to `max` chars on a char boundary, without an ellipsis; `true` when
/// something was cut.
fn clip(s: &str, max: usize) -> (String, bool) {
    match s.char_indices().nth(max) {
        Some((idx, _)) => (s[..idx].to_string(), true),
        None => (s.to_string(), false),
    }
}

fn finite(v: Option<f64>) -> Option<f64> {
    v.filter(|x| x.is_finite())
}

fn bad(what: &str) -> AppError {
    AppError::BadRequest(format!("The `{what}` parameter is not valid."))
}

/// A trimmed, non-blank query parameter.
fn present(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|s| !s.is_empty())
}

/// An opaque upstream cursor: `^[A-Za-z0-9._:-]{1,256}$`. Upstream owns its
/// meaning; the BFF only refuses what could not be one.
pub fn opaque_cursor<'a>(raw: Option<&'a str>, what: &str) -> Result<Option<&'a str>, AppError> {
    match present(raw) {
        None => Ok(None),
        Some(c)
            if c.len() <= MAX_CURSOR_CHARS
                && c.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)) =>
        {
            Ok(Some(c))
        }
        Some(_) => Err(bad(what)),
    }
}

fn small_number(digits: &str) -> Option<u64> {
    (!digits.is_empty() && digits.len() <= 4 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

/// U2's positional cursor `o:<n>` with `n < 1000`.
pub fn parse_offset_cursor(raw: &str) -> Option<u64> {
    raw.strip_prefix("o:")
        .and_then(small_number)
        .filter(|n| *n <= MAX_SEMANTIC_OFFSET)
}

/// The packed-mode cursor: `p.0`, `p.200` or `p.400`.
pub fn parse_packed_cursor(raw: &str) -> Option<usize> {
    match raw {
        "p.0" => Some(0),
        "p.200" => Some(200),
        "p.400" => Some(400),
        _ => None,
    }
}

/// The label-search cursor `l.<n>` with `n <= 1000`.
pub fn parse_label_cursor(raw: &str) -> Option<u64> {
    raw.strip_prefix("l.")
        .and_then(small_number)
        .filter(|n| *n <= MAX_LABEL_OFFSET)
}

/// `rel`: `*`, or at most 12 comma-separated tokens, each `^[a-z_]{1,40}$`
/// after trimming and lower-casing. Blank is absent.
pub fn parse_rel(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(r) = present(raw) else {
        return Ok(None);
    };
    if r == "*" {
        return Ok(Some("*".into()));
    }
    let tokens: Vec<String> = r
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    let ok = tokens.len() <= MAX_REL_TOKENS
        && tokens.iter().all(|t| {
            !t.is_empty()
                && t.len() <= MAX_REL_CHARS
                && t.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        });
    if !ok {
        return Err(bad("rel"));
    }
    Ok(Some(tokens.join(",")))
}

/// `1`/`true` → true; absent, `0` or `false` → false; anything else is 400.
fn parse_flag(raw: Option<&str>, what: &str) -> Result<bool, AppError> {
    match present(raw) {
        None | Some("0") | Some("false") => Ok(false),
        Some("1") | Some("true") => Ok(true),
        Some(_) => Err(bad(what)),
    }
}

/// An integer `limit`, defaulted and clamped to `1..=max`; non-numeric is 400.
fn parse_limit(raw: Option<&str>, default: u32, max: u32) -> Result<u32, AppError> {
    match present(raw) {
        None => Ok(default),
        Some(s) => s
            .parse::<i64>()
            .map(|n| n.clamp(1, i64::from(max)) as u32)
            .map_err(|_| bad("limit")),
    }
}

fn parse_uuid_param(raw: Option<&str>, what: &str) -> Result<Option<Uuid>, AppError> {
    match present(raw) {
        None => Ok(None),
        Some(s) => Uuid::parse_str(s).map(Some).map_err(|_| bad(what)),
    }
}

/// For the first, id-keyed upstream call of an id-addressed route: absent,
/// unreadable and forbidden all become one `NotFound(what)`, so a 403 can
/// never tell a visitor that an id exists.
pub fn atlas_id_err(what: &'static str) -> impl Fn(UpstreamError) -> AppError {
    move |e| match e {
        UpstreamError::NotFound { .. } | UpstreamError::Forbidden { .. } => {
            AppError::NotFound(what.into())
        }
        other => atlas_err(other),
    }
}

/// [`atlas_id_err`] without the `Forbidden` collapse, for calls whose 403
/// depends on the token rather than on an id.
pub fn atlas_err(e: UpstreamError) -> AppError {
    match e {
        UpstreamError::Rejected { status: 400, .. } => AppError::BadRequest(STALE_LINK.into()),
        other => other.into(),
    }
}

/// Serialise `body` as a `private, no-store` JSON response with no ETag.
/// The caps make the size check unreachable; it is a tripwire.
fn finish<T: Serialize>(body: &T) -> Result<Response, AppError> {
    let bytes = serde_json::to_vec(body)
        .map_err(|e| AppError::Internal(format!("encoding an atlas body: {e}")))?;
    if bytes.len() > ATLAS_BODY_CAP {
        tracing::error!(
            bytes = bytes.len(),
            "atlas body over its cap; the item caps should have prevented this"
        );
        return Err(AppError::Internal("atlas body over its cap".into()));
    }
    let mut resp = (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        bytes,
    )
        .into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(resp)
}

/// `now + 1.5 × upstream_timeout`. Optional follow-up calls (batch-get
/// rounds, the claim fallback) are skipped once it has passed.
fn route_deadline(state: &AppState) -> tokio::time::Instant {
    tokio::time::Instant::now() + state.upstream.timeout().mul_f64(ROUTE_BUDGET_FACTOR)
}

// ---- theme directory ----------------------------------------------------------------

/// The viewer's own theme id → label map (the `/bff/themes` body). A failed
/// directory only nulls labels; an ended session still ends the request.
type Directory = Degraded<HashMap<Uuid, String>>;

async fn theme_directory(state: &AppState, user: &SignedIn) -> Result<Directory, AppError> {
    match themes_body_cached(state, user).await {
        Ok(body) => Ok(Degraded::ok(
            body.themes
                .iter()
                .map(|t| (t.id, label_of(&t.label)))
                .collect(),
        )),
        Err(AppError::SessionExpired) => Err(AppError::SessionExpired),
        Err(e) => {
            tracing::warn!(error = %e, "atlas theme directory unavailable; labels left null");
            Ok(Degraded::unavailable(e.public_message()))
        }
    }
}

/// A theme reference: the id is the viewer's own upstream data; the label
/// comes only from the viewer's directory (null when it is not there).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ThemeRef {
    pub id: Uuid,
    pub label: Option<String>,
}

fn theme_ref(dir: &Directory, id: Option<Uuid>) -> Option<ThemeRef> {
    id.map(|id| ThemeRef {
        id,
        label: dir.get().and_then(|m| m.get(&id)).cloned(),
    })
}

// ---- the shared claim node ----------------------------------------------------------

/// A claim reference on the map, in a panel list or in a link list.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AtlasNode {
    pub id: Uuid,
    pub key: String,
    pub label: String,
    pub truth_value: Option<f64>,
    pub is_current: Option<bool>,
    pub theme: Option<ThemeRef>,
    /// The node lies in another theme than the panel's centre claim.
    pub cross_theme: bool,
    pub href: String,
}

impl AtlasNode {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: Uuid,
        text: &str,
        truth_value: Option<f64>,
        is_current: Option<bool>,
        theme_id: Option<Uuid>,
        centre_theme: Option<Uuid>,
        dir: &Directory,
        links: &Links,
    ) -> Self {
        let label = label_of(text);
        AtlasNode {
            id,
            key: claim_key(id),
            label: if label.is_empty() {
                id.to_string()
            } else {
                label
            },
            truth_value: finite(truth_value),
            is_current,
            cross_theme: theme_id.is_some() && theme_id != centre_theme,
            theme: theme_ref(dir, theme_id),
            href: links.claim(id),
        }
    }

    fn from_context(n: &ContextNode, centre: Option<Uuid>, dir: &Directory, links: &Links) -> Self {
        Self::new(
            n.id,
            &n.content,
            n.truth_value,
            n.is_current,
            n.theme_id,
            centre,
            dir,
            links,
        )
    }

    fn from_link_end(e: &LinkEnd, dir: &Directory, links: &Links) -> Self {
        let mut n = Self::new(
            e.id,
            &e.label,
            e.truth_value,
            None,
            e.theme_id,
            None,
            dir,
            links,
        );
        n.cross_theme = false;
        n
    }
}

// ---- /bff/atlas/layout --------------------------------------------------------------

#[derive(Deserialize, Default)]
struct LayoutParams {
    region: Option<String>,
    run: Option<String>,
    rel: Option<String>,
    structure: Option<String>,
    themes_after: Option<String>,
    links_after: Option<String>,
    after: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegionSel {
    Top,
    Region(Uuid),
    Unplaced,
}

impl RegionSel {
    fn cache_part(self) -> String {
        match self {
            RegionSel::Top => "top".into(),
            RegionSel::Region(id) => id.to_string(),
            RegionSel::Unplaced => "unplaced".into(),
        }
    }
}

/// One layout request as it goes upstream.
#[derive(Debug, Clone, PartialEq)]
struct LayoutFetch {
    region: RegionSel,
    run: Option<Uuid>,
    rel: Option<String>,
    structure: bool,
    themes_after: Option<String>,
    links_after: Option<String>,
    limit: u32,
}

impl LayoutFetch {
    /// Only default shapes are cached: a bounded number of keys per viewer.
    fn is_default_shape(&self) -> bool {
        self.rel.is_none()
            && self.themes_after.is_none()
            && self.links_after.is_none()
            && self.limit == LAYOUT_DEFAULT_LIMIT
    }

    fn cache_key(&self, auth: &RequestAuth) -> String {
        format!(
            "atlas:layout:{}:{}:{}:{}",
            auth.cache_key(),
            self.region.cache_part(),
            self.run.map_or_else(|| "-".to_string(), |r| r.to_string()),
            u8::from(self.structure)
        )
    }

    fn top_of(&self) -> LayoutFetch {
        LayoutFetch {
            region: RegionSel::Top,
            run: self.run,
            rel: None,
            structure: self.structure,
            themes_after: None,
            links_after: None,
            limit: LAYOUT_DEFAULT_LIMIT,
        }
    }
}

/// Every parameter is checked before any upstream call.
fn validate_layout(p: &LayoutParams) -> Result<(LayoutFetch, usize), AppError> {
    let region = match present(p.region.as_deref()) {
        None => RegionSel::Top,
        Some("unplaced") => RegionSel::Unplaced,
        Some(s) => RegionSel::Region(Uuid::parse_str(s).map_err(|_| bad("region"))?),
    };
    let run = parse_uuid_param(p.run.as_deref(), "run")?;
    let rel = parse_rel(p.rel.as_deref())?;
    let structure = parse_flag(p.structure.as_deref(), "structure")?;
    let themes_after = opaque_cursor(p.themes_after.as_deref(), "themes_after")?;
    let links_after = opaque_cursor(p.links_after.as_deref(), "links_after")?;
    if themes_after.is_some() && region == RegionSel::Top {
        return Err(AppError::BadRequest(
            "`themes_after` needs a `region`.".into(),
        ));
    }
    if themes_after.is_some() && links_after.is_some() {
        return Err(AppError::BadRequest(
            "Page themes or links, not both at once.".into(),
        ));
    }
    let packed_offset = match present(p.after.as_deref()) {
        None => 0,
        Some(a) => parse_packed_cursor(a).ok_or_else(|| bad("after"))?,
    };
    let limit = parse_limit(p.limit.as_deref(), LAYOUT_DEFAULT_LIMIT, PAGE_MAX)?;
    Ok((
        LayoutFetch {
            region,
            run,
            rel,
            structure,
            themes_after: themes_after.map(str::to_string),
            links_after: links_after.map(str::to_string),
            limit,
        },
        packed_offset,
    ))
}

/// A U5 answer that means "the layout route is not deployed": a top-level
/// 404 without `run` (U5 never sends one), or a 405.
fn route_missing(e: &UpstreamError, f: &LayoutFetch) -> bool {
    match e {
        UpstreamError::Rejected { status: 405, .. } => true,
        UpstreamError::NotFound { .. } => f.region == RegionSel::Top && f.run.is_none(),
        _ => false,
    }
}

fn no_run(status: &str) -> ThemesLayout {
    ThemesLayout {
        status: Some(status.to_string()),
        ..Default::default()
    }
}

/// The decoded U5 answer, from the per-viewer cache for default shapes.
/// Only `Ok` decodes are cached (the synthetic route-missing value too).
async fn fetch_layout(
    state: &AppState,
    user: &SignedIn,
    api: &Api<'_>,
    f: &LayoutFetch,
) -> Result<Arc<ThemesLayout>, UpstreamError> {
    let key = f.is_default_shape().then(|| f.cache_key(&user.auth));
    if let Some(k) = &key {
        if let Some(hit) = state.cache.get::<ThemesLayout>(k) {
            return Ok(hit);
        }
    }
    let region_s;
    let region_id = match f.region {
        RegionSel::Top => None,
        RegionSel::Region(id) => {
            region_s = id.to_string();
            Some(region_s.as_str())
        }
        RegionSel::Unplaced => Some("unplaced"),
    };
    let q = LayoutQuery {
        run_id: f.run,
        region_id,
        rel: f.rel.as_deref(),
        include_structure: f.structure,
        themes_after: f.themes_after.as_deref(),
        links_after: f.links_after.as_deref(),
        limit: f.limit,
    };
    let decoded = match api.themes_layout(&q).await {
        Ok(l) => l,
        Err(e) if route_missing(&e, f) => {
            tracing::warn!(error = %e, "the layout route looks undeployed; packing themes by size");
            no_run("no_layout_run")
        }
        Err(e) => return Err(e),
    };
    let decoded = Arc::new(decoded);
    if let Some(k) = key {
        state
            .cache
            .insert(k, Arc::clone(&decoded), ATLAS_LAYOUT_TTL);
    }
    Ok(decoded)
}

fn layout_err(f: &LayoutFetch) -> impl Fn(UpstreamError) -> AppError + '_ {
    move |e| match e {
        UpstreamError::NotFound { .. } | UpstreamError::Forbidden { .. } => {
            if f.run.is_some() {
                AppError::NotFound("map version".into())
            } else if f.region == RegionSel::Top {
                AppError::NotFound("map".into())
            } else {
                AppError::NotFound("region".into())
            }
        }
        other => atlas_err(other),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct RunOut {
    run_id: Uuid,
    completed_at: Option<DateTime<Utc>>,
    algo: String,
    stale: bool,
    extent: Option<f64>,
}

fn run_out(r: &LayoutRun) -> RunOut {
    RunOut {
        run_id: r.run_id,
        completed_at: r.completed_at,
        algo: one_line(&r.algo, ALGO_CHARS),
        stale: r.stale,
        extent: finite(r.extent),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct RegionOut {
    id: Uuid,
    label: String,
    x: f64,
    y: f64,
    r: f64,
    theme_count: i64,
    member_count: i64,
}

fn region_out(r: &LayoutRegion) -> RegionOut {
    let fin = |v: f64| if v.is_finite() { v } else { 0.0 };
    RegionOut {
        id: r.id,
        label: label_of(&r.label),
        x: fin(r.x),
        y: fin(r.y),
        r: fin(r.r).max(0.0),
        theme_count: r.theme_count,
        member_count: r.member_count,
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LinkOut {
    pub kind: String,
    pub a: Uuid,
    pub b: Uuid,
    pub counts: BTreeMap<String, i64>,
    pub total: i64,
    pub refute_share: f64,
}

/// Fold relationship spellings (`SUPPORTS`, `supports`) and merge their counts.
pub fn fold_counts(counts: &BTreeMap<String, i64>) -> BTreeMap<String, i64> {
    let mut out: BTreeMap<String, i64> = BTreeMap::new();
    for (k, v) in counts {
        let e = out.entry(fold(k)).or_insert(0);
        *e = e.saturating_add(*v);
    }
    out
}

/// `(contradicts + refutes) / total` of one public count, 0 when `total`
/// is 0; rounded to four places.
pub fn refute_share(folded: &BTreeMap<String, i64>, total: i64) -> f64 {
    if total <= 0 {
        return 0.0;
    }
    let weakening = folded.get("contradicts").copied().unwrap_or(0)
        + folded.get("refutes").copied().unwrap_or(0);
    let share = (weakening as f64 / total as f64).clamp(0.0, 1.0);
    (share * 10_000.0).round() / 10_000.0
}

fn link_out(l: &LayoutLink) -> LinkOut {
    let counts = fold_counts(&l.counts);
    LinkOut {
        kind: l.kind.clone(),
        a: l.a,
        b: l.b,
        refute_share: refute_share(&counts, l.total),
        counts,
        total: l.total,
    }
}

/// Which endpoints a layout response may name.
pub enum LinkScope<'a> {
    /// Both ends must be among the emitted regions.
    Top { regions: &'a HashSet<Uuid> },
    /// `theme` links need both ends in `themes`; `theme_region` links need
    /// `a` in `themes` and `b` in `regions` (`None`: the viewer's top level
    /// could not be read, so every `theme_region` link is dropped).
    Region {
        themes: &'a HashSet<Uuid>,
        regions: Option<&'a HashSet<Uuid>>,
    },
}

/// The second-line drop rule: keep only links whose endpoints this response
/// carries or this viewer can otherwise see, first of each `(kind, a, b)`.
/// Rows are removed; no count is ever changed.
pub fn filter_layout_links<'l>(
    links: &'l [LayoutLink],
    scope: &LinkScope<'_>,
) -> Vec<&'l LayoutLink> {
    let mut seen: HashSet<(&str, Uuid, Uuid)> = HashSet::new();
    links
        .iter()
        .filter(|l| match scope {
            LinkScope::Top { regions } => regions.contains(&l.a) && regions.contains(&l.b),
            LinkScope::Region { themes, regions } => match l.kind.as_str() {
                "theme" => themes.contains(&l.a) && themes.contains(&l.b),
                "theme_region" => {
                    themes.contains(&l.a) && regions.is_some_and(|g| g.contains(&l.b))
                }
                _ => false,
            },
        })
        .filter(|l| seen.insert((l.kind.as_str(), l.a, l.b)))
        .take(ATLAS_ITEM_CAP)
        .collect()
}

fn relationships_out(rels: &[String]) -> Vec<String> {
    rels.iter()
        .take(ATLAS_ITEM_CAP)
        .map(|r| one_line(r, MAX_REL_CHARS))
        .collect()
}

#[derive(Serialize)]
struct TopNext {
    links: Option<String>,
}

#[derive(Serialize)]
struct TopBody {
    mode: &'static str,
    run: Option<RunOut>,
    status: Option<String>,
    relationships: Vec<String>,
    regions: Vec<RegionOut>,
    links: Vec<LinkOut>,
    unplaced_theme_count: i64,
    next: TopNext,
    notice: Option<&'static str>,
}

fn top_body(l: &ThemesLayout) -> TopBody {
    let mut seen = HashSet::new();
    let regions: Vec<RegionOut> = l
        .regions
        .iter()
        .filter(|r| seen.insert(r.id))
        .take(ATLAS_ITEM_CAP)
        .map(region_out)
        .collect();
    let ids: HashSet<Uuid> = regions.iter().map(|r| r.id).collect();
    let links = filter_layout_links(&l.links, &LinkScope::Top { regions: &ids })
        .into_iter()
        .map(link_out)
        .collect();
    let stale = l.run.as_ref().is_some_and(|r| r.stale);
    TopBody {
        mode: "layout",
        run: l.run.as_ref().map(run_out),
        status: l.status.clone(),
        relationships: relationships_out(&l.relationships),
        regions,
        links,
        unplaced_theme_count: l.unplaced_theme_count.max(0),
        next: TopNext {
            links: l.next.links.clone(),
        },
        notice: stale.then_some(NOTICE_STALE),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct ThemeOut {
    id: Uuid,
    label: String,
    region_id: Option<Uuid>,
    placement: Option<String>,
    x: Option<f64>,
    y: Option<f64>,
    member_count: i64,
}

#[derive(Serialize)]
struct RegionNext {
    themes: Option<String>,
    links: Option<String>,
}

#[derive(Serialize)]
struct RegionBody {
    mode: &'static str,
    run: Option<RunOut>,
    status: Option<String>,
    relationships: Vec<String>,
    region: Option<RegionOut>,
    themes: Vec<ThemeOut>,
    links: Vec<LinkOut>,
    next: RegionNext,
}

fn region_body(
    l: &ThemesLayout,
    sel: RegionSel,
    dir: &Directory,
    top_regions: Option<&HashSet<Uuid>>,
) -> RegionBody {
    let mut seen = HashSet::new();
    let themes: Vec<ThemeOut> = l
        .themes
        .iter()
        .filter(|t| seen.insert(t.id))
        .take(ATLAS_ITEM_CAP)
        .map(|t| ThemeOut {
            id: t.id,
            label: label_of(&t.label),
            region_id: t.region_id,
            placement: t
                .placement
                .clone()
                .filter(|p| p == "shared" || p == "viewer"),
            x: finite(t.x),
            y: finite(t.y),
            member_count: t.member_count,
        })
        .collect();
    let mut visible: HashSet<Uuid> = themes.iter().map(|t| t.id).collect();
    if let Some(d) = dir.get() {
        visible.extend(d.keys().copied());
    }
    let links = filter_layout_links(
        &l.links,
        &LinkScope::Region {
            themes: &visible,
            regions: top_regions,
        },
    )
    .into_iter()
    .map(link_out)
    .collect();
    RegionBody {
        mode: "layout",
        run: l.run.as_ref().map(run_out),
        status: l.status.clone(),
        relationships: relationships_out(&l.relationships),
        region: match sel {
            RegionSel::Unplaced => None,
            _ => l.region.as_ref().map(region_out),
        },
        themes,
        links,
        next: RegionNext {
            themes: l.next.themes.clone(),
            links: l.next.links.clone(),
        },
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct PackedTheme {
    id: Uuid,
    label: String,
    member_count: i64,
}

#[derive(Serialize)]
struct PackedBody {
    mode: &'static str,
    status: String,
    run: Option<RunOut>,
    themes: Vec<PackedTheme>,
    total: usize,
    truncated: bool,
    next: Option<String>,
    notice: String,
}

#[derive(Serialize)]
struct PackedRegionBody {
    mode: &'static str,
    status: String,
    themes: Vec<PackedTheme>,
    next: Option<String>,
}

/// Packed paging over `len` themes: the slice for `offset` and the next
/// cursor. An offset past the end is an empty page, never an error.
pub fn packed_page(len: usize, offset: usize) -> (std::ops::Range<usize>, Option<String>) {
    let start = offset.min(len);
    let end = (offset + PACKED_PAGE).min(len);
    let next_offset = offset + PACKED_PAGE;
    let next = (next_offset < len && parse_packed_cursor(&format!("p.{next_offset}")).is_some())
        .then(|| format!("p.{next_offset}"));
    (start..end, next)
}

async fn packed_top(
    state: &AppState,
    user: &SignedIn,
    l: &ThemesLayout,
    offset: usize,
) -> Result<Response, AppError> {
    let body = themes_body_cached(state, user).await?;
    let (range, next) = packed_page(body.themes.len(), offset);
    let themes = body.themes[range]
        .iter()
        .map(|t| PackedTheme {
            id: t.id,
            label: label_of(&t.label),
            member_count: t.claim_count,
        })
        .collect();
    let mut notice = NOTICE_PACKED.to_string();
    if body.truncated {
        notice.push(' ');
        notice.push_str(NOTICE_TRUNCATED);
    }
    finish(&PackedBody {
        mode: "packed",
        status: l.status.clone().unwrap_or_else(|| "no_layout_run".into()),
        run: None,
        themes,
        total: body.total,
        truncated: body.truncated,
        next,
        notice,
    })
}

async fn layout(
    State(state): State<AppState>,
    user: SignedIn,
    Query(p): Query<LayoutParams>,
) -> Result<Response, AppError> {
    let (f, packed_offset) = validate_layout(&p)?;
    let api = user.api(&state);

    if f.region == RegionSel::Top {
        let l = fetch_layout(&state, &user, &api, &f)
            .await
            .map_err(layout_err(&f))?;
        if l.run.is_none() {
            return packed_top(&state, &user, &l, packed_offset).await;
        }
        return finish(&top_body(&l));
    }

    let top = f.top_of();
    let (main, dir, top_decode) = tokio::join!(
        fetch_layout(&state, &user, &api, &f),
        theme_directory(&state, &user),
        fetch_layout(&state, &user, &api, &top),
    );
    let l = main.map_err(layout_err(&f))?;
    let dir = dir?;
    if l.run.is_none() {
        return finish(&PackedRegionBody {
            mode: "packed",
            status: l.status.clone().unwrap_or_else(|| "no_layout_run".into()),
            themes: Vec::new(),
            next: None,
        });
    }
    let top_regions: Option<HashSet<Uuid>> = match top_decode {
        Ok(t) => Some(t.regions.iter().map(|r| r.id).collect()),
        Err(UpstreamError::SessionExpired) => return Err(AppError::SessionExpired),
        Err(e) => {
            tracing::warn!(error = %e, "top-level layout unavailable; dropping theme_region links");
            None
        }
    };
    finish(&region_body(&l, f.region, &dir, top_regions.as_ref()))
}

// ---- /bff/atlas/theme/{id}/claims ---------------------------------------------------

#[derive(Deserialize, Default)]
struct ThemeClaimsParams {
    after: Option<String>,
    limit: Option<String>,
}

/// `after` as `(cursor sent upstream, offset)`; `o:0` when absent.
fn semantic_cursor(raw: Option<&str>) -> Result<(String, u64), AppError> {
    match present(raw) {
        None => Ok(("o:0".into(), 0)),
        Some(c) => parse_offset_cursor(c)
            .map(|n| (format!("o:{n}"), n))
            .ok_or_else(|| bad("after")),
    }
}

/// U2's `next_cursor`, passed through only when it is an `o:<n>` cursor.
fn checked_next(next: Option<String>) -> Option<String> {
    next.filter(|n| {
        let ok = parse_offset_cursor(n).is_some();
        if !ok {
            tracing::warn!(cursor = %n, "dropping a malformed upstream next_cursor");
        }
        ok
    })
}

#[derive(Default)]
struct BatchOutcome {
    found: HashMap<Uuid, BatchGetClaim>,
    gone: HashSet<Uuid>,
}

/// Batch-get `ids` (at most 100, rank order), resubmitting `remaining` while
/// rounds and the route budget last. A missing route, a 5xx or a timeout
/// leaves the rest to be emitted from hit data; an ended session ends the
/// request.
async fn batch_rounds(
    api: &Api<'_>,
    ids: &[Uuid],
    deadline: tokio::time::Instant,
) -> Result<BatchOutcome, AppError> {
    let mut out = BatchOutcome::default();
    let mut pending: Vec<Uuid> = ids.iter().copied().take(BATCH_GET_MAX_IDS).collect();
    let mut rounds = 0;
    while !pending.is_empty() && rounds < MAX_BATCH_GET_ROUNDS {
        if tokio::time::Instant::now() >= deadline {
            tracing::info!(
                left = pending.len(),
                "batch-get rounds stopped at the route budget"
            );
            break;
        }
        rounds += 1;
        let asked: HashSet<Uuid> = pending.iter().copied().collect();
        let res = match tokio::time::timeout_at(deadline, api.claims_batch_get(&pending)).await {
            Ok(r) => r,
            Err(_) => {
                tracing::info!(
                    left = pending.len(),
                    "batch-get cut off at the route budget"
                );
                break;
            }
        };
        match res {
            Ok(r) => {
                for c in r.claims {
                    if asked.contains(&c.claim.id) {
                        out.found.entry(c.claim.id).or_insert(c);
                    }
                }
                out.gone
                    .extend(r.not_found.into_iter().filter(|g| asked.contains(g)));
                let mut again = HashSet::new();
                pending = r
                    .remaining
                    .into_iter()
                    .filter(|x| {
                        asked.contains(x)
                            && !out.found.contains_key(x)
                            && !out.gone.contains(x)
                            && again.insert(*x)
                    })
                    .collect();
            }
            Err(e @ (UpstreamError::SessionExpired | UpstreamError::Unauthorized { .. })) => {
                return Err(atlas_err(e));
            }
            Err(e) => {
                tracing::warn!(error = %e, "batch-get unavailable; emitting hit data");
                break;
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct RankedClaim {
    id: Uuid,
    key: String,
    label: String,
    truth_value: Option<f64>,
    is_current: Option<bool>,
    similarity: Option<f64>,
    rank: u64,
    href: String,
}

#[derive(Serialize)]
struct ThemeClaimsBody {
    theme: ThemeRef,
    member_count: i64,
    claims: Vec<RankedClaim>,
    next: Option<String>,
    truncated: bool,
}

/// Hits in search order. A hit batch-get returned takes its `truth_value`
/// and `is_current` from there; one it reported `not_found` is dropped (it
/// became unreadable between the calls); the rest keep their hit data.
/// Ranks are `offset + position`, so a drop leaves a gap.
fn ranked_claims(
    hits: &[SemanticHit],
    batch: &BatchOutcome,
    offset: u64,
    links: &Links,
) -> Vec<RankedClaim> {
    let mut seen = HashSet::new();
    hits.iter()
        .enumerate()
        .filter(|(_, h)| seen.insert(h.claim_id))
        .filter(|(_, h)| !batch.gone.contains(&h.claim_id))
        .map(|(pos, h)| {
            let (truth, current) = match batch.found.get(&h.claim_id) {
                Some(c) => (c.claim.truth_value, c.is_current),
                None => (h.epistemic.truth_value, None),
            };
            let text = if h.statement.trim().is_empty() {
                batch
                    .found
                    .get(&h.claim_id)
                    .map(|c| c.claim.content.as_str())
                    .unwrap_or("")
            } else {
                h.statement.as_str()
            };
            let label = label_of(text);
            RankedClaim {
                id: h.claim_id,
                key: claim_key(h.claim_id),
                label: if label.is_empty() {
                    h.claim_id.to_string()
                } else {
                    label
                },
                truth_value: finite(truth),
                is_current: current,
                similarity: finite(h.similarity),
                rank: offset + pos as u64,
                href: links.claim(h.claim_id),
            }
        })
        .collect()
}

async fn theme_claims(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    Query(p): Query<ThemeClaimsParams>,
) -> Result<Response, AppError> {
    let deadline = route_deadline(&state);
    let id = parse_id(&raw, "theme")?;
    let (cursor, offset) = semantic_cursor(p.after.as_deref())?;
    let limit = parse_limit(p.limit.as_deref(), THEME_CLAIMS_DEFAULT, THEME_CLAIMS_MAX)?;

    let api = user.api(&state);
    let (found, dir) = tokio::join!(
        api.search_semantic_in_theme(Some(id), "theme_core", None, limit, Some(cursor.as_str())),
        theme_directory(&state, &user),
    );
    let found = found.map_err(atlas_id_err("theme"))?;
    let dir = dir?;

    let hits: Vec<SemanticHit> = found
        .results
        .into_iter()
        .take(THEME_CLAIMS_MAX as usize)
        .collect();
    let mut seen = HashSet::new();
    let ids: Vec<Uuid> = hits
        .iter()
        .map(|h| h.claim_id)
        .filter(|i| seen.insert(*i))
        .collect();
    let batch = batch_rounds(&api, &ids, deadline).await?;

    finish(&ThemeClaimsBody {
        theme: ThemeRef {
            id,
            label: dir.get().and_then(|m| m.get(&id)).cloned(),
        },
        member_count: found.theme_scope.map_or(0, |s| s.member_count),
        claims: ranked_claims(&hits, &batch, offset, &state.links),
        next: checked_next(found.next_cursor),
        truncated: found.truncated,
    })
}

// ---- /bff/atlas/claim/{id} ----------------------------------------------------------

#[derive(Deserialize, Default)]
struct ClaimParams {
    list: Option<String>,
    after: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct CentreOut {
    id: Uuid,
    key: String,
    content: String,
    content_truncated: bool,
    truth_value: Option<f64>,
    is_current: Option<bool>,
    theme: Option<ThemeRef>,
    href: String,
    history_href: String,
    graph_href: String,
    embed_url: String,
}

#[allow(clippy::too_many_arguments)]
fn centre_out(
    id: Uuid,
    content: &str,
    flagged: bool,
    truth_value: Option<f64>,
    is_current: Option<bool>,
    theme_id: Option<Uuid>,
    dir: &Directory,
    links: &Links,
) -> CentreOut {
    let (content, cut) = clip(content.trim(), CENTRE_CONTENT_CHARS);
    CentreOut {
        id,
        key: claim_key(id),
        content,
        content_truncated: flagged || cut,
        truth_value: finite(truth_value),
        is_current,
        theme: theme_ref(dir, theme_id),
        href: links.claim(id),
        history_href: links.claim_history(id),
        graph_href: links.claim_graph(id),
        embed_url: links.absolute(&links.atlas_claim(id)),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Contested {
    pub contested: bool,
    /// Sum of the incoming `contradicts`/`refutes` tallies.
    pub incoming: i64,
}

/// Incoming `contradicts` or `refutes` edges, from the viewer's own tallies
/// (the weakening set of the kernel's `WEAKENING_RELATIONSHIPS`).
pub fn contested_from(rows: &[RelCount]) -> Contested {
    let incoming: i64 = rows
        .iter()
        .filter(|r| r.direction == "incoming")
        .filter(|r| matches!(fold(&r.relationship).as_str(), "contradicts" | "refutes"))
        .map(|r| r.count.max(0))
        .fold(0i64, i64::saturating_add);
    Contested {
        contested: incoming > 0,
        incoming,
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct PlacementOut {
    theme_id: Option<Uuid>,
    region_id: Option<Uuid>,
    placement: Option<String>,
    x: Option<f64>,
    y: Option<f64>,
    run_id: Option<Uuid>,
}

fn placement_out(p: &PlacementResponse) -> PlacementOut {
    let l = p.layout.as_ref();
    PlacementOut {
        theme_id: p.theme_id,
        region_id: l.and_then(|l| l.region_id),
        placement: l
            .map(|l| l.placement.clone())
            .filter(|p| p == "shared" || p == "viewer"),
        x: finite(l.and_then(|l| l.x)),
        y: finite(l.and_then(|l| l.y)),
        run_id: l.map(|l| l.run_id),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct PaperOut {
    id: Uuid,
    doi: Option<String>,
    doi_href: Option<String>,
    title: Option<String>,
}

fn paper_out(p: &ContextPaper) -> PaperOut {
    let doi = p
        .doi
        .as_deref()
        .map(|d| clip(d.trim(), PAPER_DOI_CHARS).0)
        .filter(|d| !d.is_empty());
    PaperOut {
        id: p.id,
        doi_href: doi.as_deref().and_then(doi_url),
        doi,
        title: p
            .title
            .as_deref()
            .map(|t| one_line(t, PAPER_TITLE_CHARS))
            .filter(|t| !t.is_empty()),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct ListOut {
    items: Vec<AtlasNode>,
    total: i64,
    next: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct SiblingsOut {
    parent_id: Option<Uuid>,
    #[serde(flatten)]
    list: ListOut,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct EdgeOut {
    edge_id: Uuid,
    relationship: String,
    words: String,
    family: &'static str,
    direction: &'static str,
    strength: Option<f64>,
    neighbor: AtlasNode,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct RelCountOut {
    relationship: String,
    direction: &'static str,
    words: String,
    count: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct EdgesOut {
    items: Vec<EdgeOut>,
    total: i64,
    next: Option<String>,
    by_relationship: Vec<RelCountOut>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct Ring {
    paper: Option<PaperOut>,
    section: Option<AtlasNode>,
    parents: ListOut,
    parts: ListOut,
    siblings: SiblingsOut,
    edges: EdgesOut,
}

/// Context ctx shared by the list builders.
struct RingCtx<'a> {
    centre: Option<Uuid>,
    dir: &'a Directory,
    links: &'a Links,
}

fn direction_of(raw: &str) -> (EdgeDirection, &'static str) {
    if raw.eq_ignore_ascii_case("incoming") {
        (EdgeDirection::In, "incoming")
    } else {
        (EdgeDirection::Out, "outgoing")
    }
}

fn list_out(l: Option<&ContextList<ContextNode>>, cx: &RingCtx<'_>) -> ListOut {
    let Some(l) = l else {
        return ListOut {
            items: Vec::new(),
            total: 0,
            next: None,
        };
    };
    let mut seen = HashSet::new();
    ListOut {
        items: l
            .items
            .iter()
            .filter(|n| seen.insert(n.id))
            .take(ATLAS_ITEM_CAP)
            .map(|n| AtlasNode::from_context(n, cx.centre, cx.dir, cx.links))
            .collect(),
        total: l.total,
        next: l.next_cursor.clone(),
    }
}

fn edge_out(e: &ContextEdge, cx: &RingCtx<'_>) -> EdgeOut {
    let rel = fold(&e.relationship);
    let (dir, direction) = direction_of(&e.direction);
    EdgeOut {
        edge_id: e.edge_id,
        words: heading(&rel, dir),
        family: relationship_family(&rel),
        relationship: one_line(&rel, MAX_REL_CHARS),
        direction,
        strength: finite(e.strength),
        neighbor: AtlasNode::from_context(&e.neighbor, cx.centre, cx.dir, cx.links),
    }
}

fn edges_out(l: Option<&crate::upstream::atlas::EdgeList>, cx: &RingCtx<'_>) -> EdgesOut {
    let Some(l) = l else {
        return EdgesOut {
            items: Vec::new(),
            total: 0,
            next: None,
            by_relationship: Vec::new(),
        };
    };
    let mut seen = HashSet::new();
    EdgesOut {
        items: l
            .list
            .items
            .iter()
            .filter(|e| seen.insert(e.edge_id))
            .take(ATLAS_ITEM_CAP)
            .map(|e| edge_out(e, cx))
            .collect(),
        total: l.list.total,
        next: l.list.next_cursor.clone(),
        by_relationship: l
            .by_relationship
            .iter()
            .take(ATLAS_ITEM_CAP)
            .map(|r| {
                let rel = fold(&r.relationship);
                let (dir, direction) = direction_of(&r.direction);
                RelCountOut {
                    words: heading(&rel, dir),
                    relationship: one_line(&rel, MAX_REL_CHARS),
                    direction,
                    count: r.count,
                }
            })
            .collect(),
    }
}

fn ring_out(c: &ClaimContext, cx: &RingCtx<'_>) -> Ring {
    Ring {
        paper: c.paper.as_ref().map(paper_out),
        section: c
            .section
            .as_ref()
            .map(|n| AtlasNode::from_context(n, cx.centre, cx.dir, cx.links)),
        parents: list_out(c.parents.as_ref(), cx),
        parts: list_out(c.parts.as_ref(), cx),
        siblings: SiblingsOut {
            parent_id: c.siblings.as_ref().and_then(|s| s.parent_id),
            list: list_out(c.siblings.as_ref().map(|s| &s.list), cx),
        },
        edges: edges_out(c.edges.as_ref(), cx),
    }
}

#[derive(Serialize)]
struct ClaimFullBody {
    claim: CentreOut,
    contested: Degraded<Contested>,
    placement: Degraded<PlacementOut>,
    ring: Degraded<Ring>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PageItems {
    Nodes(Vec<AtlasNode>),
    Edges(Vec<EdgeOut>),
}

#[derive(Serialize)]
struct ClaimPageBody {
    list: &'static str,
    items: PageItems,
    total: i64,
    next: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<Option<Uuid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    by_relationship: Option<Vec<RelCountOut>>,
}

async fn claim(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    Query(p): Query<ClaimParams>,
) -> Result<Response, AppError> {
    let deadline = route_deadline(&state);
    let id = parse_id(&raw, "claim")?;
    let list = match present(p.list.as_deref()) {
        None => None,
        Some(l) => Some(ContextListName::parse(l).ok_or_else(|| bad("list"))?),
    };
    let after = opaque_cursor(p.after.as_deref(), "after")?;
    let limit = match present(p.limit.as_deref()) {
        None => None,
        Some(_) => Some(parse_limit(p.limit.as_deref(), PAGE_MAX, PAGE_MAX)?),
    };
    match list {
        None if after.is_some() || limit.is_some() => Err(AppError::BadRequest(
            "`after` and `limit` page one list; name it with `list`.".into(),
        )),
        None => claim_full(&state, &user, id, deadline).await,
        Some(list) => claim_page(&state, &user, id, list, after, limit).await,
    }
}

fn placement_section(
    r: Result<PlacementResponse, UpstreamError>,
) -> Result<Degraded<PlacementOut>, AppError> {
    match r {
        Ok(p) => Ok(Degraded::ok(placement_out(&p))),
        Err(UpstreamError::SessionExpired) => Err(AppError::SessionExpired),
        Err(e @ (UpstreamError::NotFound { .. } | UpstreamError::Forbidden { .. })) => {
            tracing::debug!(error = %e, "placement unavailable");
            Ok(Degraded::unavailable(
                UpstreamError::NotFound {
                    message: String::new(),
                }
                .user_message(),
            ))
        }
        Err(e) => {
            tracing::warn!(error = %e, "placement unavailable");
            Ok(Degraded::unavailable(e.user_message()))
        }
    }
}

async fn claim_full(
    state: &AppState,
    user: &SignedIn,
    id: Uuid,
    deadline: tokio::time::Instant,
) -> Result<Response, AppError> {
    let api = user.api(state);
    let (ctx, placement, dir) = tokio::join!(
        api.claim_context(id),
        api.placement(id),
        theme_directory(state, user),
    );
    let dir = dir?;
    let placement = placement_section(placement)?;
    let links = &state.links;

    let ctx = match ctx {
        Ok(c) => c,
        Err(e @ UpstreamError::Forbidden { .. }) => return Err(atlas_id_err("claim")(e)),
        Err(
            e @ (UpstreamError::NotFound { .. }
            | UpstreamError::Server { .. }
            | UpstreamError::Timeout
            | UpstreamError::Transport(_)
            | UpstreamError::Decode(_)),
        ) => {
            // The context route may not be deployed, or failed: fall back
            // to the viewer-filtered `GET /claims/:id`, which 404s an
            // unreadable claim exactly as it does an absent one.
            tracing::info!(error = %e, "claim context unavailable; falling back to the claim");
            if tokio::time::Instant::now() >= deadline {
                return Err(atlas_id_err("claim")(e));
            }
            let fallback: ClaimResponse =
                match tokio::time::timeout_at(deadline, api.claim(id)).await {
                    Ok(r) => r.map_err(atlas_id_err("claim"))?,
                    Err(_) => return Err(atlas_id_err("claim")(e)),
                };
            let reason = match e {
                UpstreamError::NotFound { .. } => {
                    "Linked claims are not available from this EpiGraph API yet."
                }
                other => other.user_message(),
            };
            let theme_id = placement.get().and_then(|p| p.theme_id);
            return finish(&ClaimFullBody {
                claim: centre_out(
                    id,
                    &fallback.content,
                    false,
                    fallback.truth_value,
                    None,
                    theme_id,
                    &dir,
                    links,
                ),
                contested: Degraded::unavailable(reason),
                placement,
                ring: Degraded::unavailable(reason),
            });
        }
        Err(other) => return Err(atlas_id_err("claim")(other)),
    };

    let cx = RingCtx {
        centre: ctx.claim.theme_id,
        dir: &dir,
        links,
    };
    let contested = match &ctx.edges {
        Some(e) => Degraded::ok(contested_from(&e.by_relationship)),
        None => Degraded::unavailable("Linked claims are not available right now."),
    };
    finish(&ClaimFullBody {
        claim: centre_out(
            id,
            &ctx.claim.content,
            ctx.claim.content_truncated,
            ctx.claim.truth_value,
            ctx.claim.is_current,
            ctx.claim.theme_id,
            &dir,
            links,
        ),
        contested,
        placement,
        ring: Degraded::ok(ring_out(&ctx, &cx)),
    })
}

async fn claim_page(
    state: &AppState,
    user: &SignedIn,
    id: Uuid,
    list: ContextListName,
    after: Option<&str>,
    limit: Option<u32>,
) -> Result<Response, AppError> {
    let api = user.api(state);
    let (ctx, dir) = tokio::join!(
        api.claim_context_page(id, list, after, limit),
        theme_directory(state, user),
    );
    let ctx = ctx.map_err(atlas_id_err("claim"))?;
    let dir = dir?;
    let cx = RingCtx {
        centre: ctx.claim.theme_id,
        dir: &dir,
        links: &state.links,
    };
    let body = match list {
        ContextListName::Edges => {
            let e = edges_out(ctx.edges.as_ref(), &cx);
            ClaimPageBody {
                list: list.as_str(),
                items: PageItems::Edges(e.items),
                total: e.total,
                next: e.next,
                parent_id: None,
                by_relationship: Some(e.by_relationship),
            }
        }
        ContextListName::Siblings => {
            let s = ctx.siblings.as_ref();
            let l = list_out(s.map(|s| &s.list), &cx);
            ClaimPageBody {
                list: list.as_str(),
                items: PageItems::Nodes(l.items),
                total: l.total,
                next: l.next,
                parent_id: Some(s.and_then(|s| s.parent_id)),
                by_relationship: None,
            }
        }
        ContextListName::Parents | ContextListName::Parts => {
            let src = if list == ContextListName::Parents {
                ctx.parents.as_ref()
            } else {
                ctx.parts.as_ref()
            };
            let l = list_out(src, &cx);
            ClaimPageBody {
                list: list.as_str(),
                items: PageItems::Nodes(l.items),
                total: l.total,
                next: l.next,
                parent_id: None,
                by_relationship: None,
            }
        }
    };
    finish(&body)
}

// ---- /bff/atlas/links ---------------------------------------------------------------

#[derive(Deserialize, Default)]
struct LinksParams {
    from: Option<String>,
    to: Option<String>,
    run: Option<String>,
    rel: Option<String>,
    structure: Option<String>,
    after: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct SideOut {
    id: Uuid,
    kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct LinkItemOut {
    edge_id: Uuid,
    strength: Option<f64>,
    direction: String,
    created_at: Option<DateTime<Utc>>,
    source: AtlasNode,
    target: AtlasNode,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct GroupOut {
    relationship: String,
    words: String,
    family: &'static str,
    count: Option<i64>,
    items: Vec<LinkItemOut>,
}

#[derive(Serialize)]
struct LinksBody {
    from: SideOut,
    to: SideOut,
    status: Option<String>,
    relationships: Vec<String>,
    total: Option<i64>,
    groups: Vec<GroupOut>,
    next: Option<String>,
}

fn side_kind(side: Option<&crate::upstream::atlas::LinkSide>, id: Uuid) -> Option<String> {
    side.filter(|s| s.id == id)
        .and_then(|s| s.kind.clone())
        .filter(|k| k == "theme" || k == "region")
}

/// Group a links page by folded relationship. On the first page (`counts`
/// present) groups are ordered by those counts, descending, then by name;
/// on later pages by the page's own item counts. Items keep upstream order
/// and are de-duplicated by `edge_id`; nothing is re-sorted by truth value.
fn group_links(g: &GraphLinks, dir: &Directory, links: &Links) -> Vec<GroupOut> {
    let counts = g.counts.as_ref().map(fold_counts);
    let mut seen = HashSet::new();
    let mut groups: Vec<GroupOut> = Vec::new();
    for item in g.items.iter().take(ATLAS_ITEM_CAP) {
        if !seen.insert(item.edge_id) {
            continue;
        }
        let rel = fold(&item.relationship);
        let out = LinkItemOut {
            edge_id: item.edge_id,
            strength: finite(item.strength),
            direction: one_line(&item.direction, MAX_REL_CHARS),
            created_at: item.created_at,
            source: AtlasNode::from_link_end(&item.source, dir, links),
            target: AtlasNode::from_link_end(&item.target, dir, links),
        };
        match groups.iter_mut().find(|grp| grp.relationship == rel) {
            Some(grp) => grp.items.push(out),
            None => groups.push(GroupOut {
                words: heading(&rel, EdgeDirection::Out),
                family: relationship_family(&rel),
                count: counts.as_ref().and_then(|c| c.get(&rel).copied()),
                relationship: one_line(&rel, MAX_REL_CHARS),
                items: vec![out],
            }),
        }
    }
    let first_page = counts.is_some();
    groups.sort_by(|a, b| {
        let weight = |g: &GroupOut| {
            if first_page {
                g.count.unwrap_or(0)
            } else {
                g.items.len() as i64
            }
        };
        weight(b)
            .cmp(&weight(a))
            .then_with(|| a.relationship.cmp(&b.relationship))
    });
    groups
}

async fn links(
    State(state): State<AppState>,
    user: SignedIn,
    Query(p): Query<LinksParams>,
) -> Result<Response, AppError> {
    let from = parse_uuid_param(p.from.as_deref(), "from")?.ok_or_else(|| bad("from"))?;
    let to = parse_uuid_param(p.to.as_deref(), "to")?.ok_or_else(|| bad("to"))?;
    if from == to {
        return Err(AppError::BadRequest(
            "Pick two different areas to list the links between them.".into(),
        ));
    }
    let run = parse_uuid_param(p.run.as_deref(), "run")?;
    let rel = parse_rel(p.rel.as_deref())?;
    let structure = parse_flag(p.structure.as_deref(), "structure")?;
    let after = opaque_cursor(p.after.as_deref(), "after")?;
    let limit = parse_limit(p.limit.as_deref(), LINKS_DEFAULT, PAGE_MAX)?;

    let api = user.api(&state);
    let q = LinksQuery {
        from,
        to,
        run_id: run,
        rel: rel.as_deref(),
        include_structure: structure,
        after,
        limit,
    };
    let (res, dir) = tokio::join!(api.graph_links(&q), theme_directory(&state, &user));
    let g = res.map_err(|e| match e {
        UpstreamError::Rejected { status: 400, .. } => AppError::BadRequest(OVERLAP.into()),
        other => atlas_id_err("link")(other),
    })?;
    let dir = dir?;

    let invalidated = g.status.as_deref() == Some("layout_invalidated");
    finish(&LinksBody {
        from: SideOut {
            id: from,
            kind: side_kind(g.from.as_ref(), from),
        },
        to: SideOut {
            id: to,
            kind: side_kind(g.to.as_ref(), to),
        },
        status: g.status.as_ref().map(|s| one_line(s, MAX_REL_CHARS)),
        relationships: relationships_out(&g.relationships),
        total: if invalidated { None } else { g.total },
        groups: if invalidated {
            Vec::new()
        } else {
            group_links(&g, &dir, &state.links)
        },
        next: if invalidated { None } else { g.next.clone() },
    })
}

// ---- /bff/atlas/search ----------------------------------------------------------------

#[derive(Deserialize, Default)]
struct SearchParams {
    q: Option<String>,
    mode: Option<String>,
    theme: Option<String>,
    after: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct SearchTheme {
    id: Uuid,
    label: Option<String>,
    member_count: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct SearchResult {
    claim_id: Uuid,
    key: String,
    label: String,
    similarity: Option<f64>,
    truth_value: Option<f64>,
    theme_id: Option<Uuid>,
    href: String,
}

#[derive(Serialize)]
struct SearchBody {
    q: String,
    mode: &'static str,
    theme: Option<SearchTheme>,
    results: Vec<SearchResult>,
    next: Option<String>,
    truncated: bool,
}

fn result_of(
    id: Uuid,
    text: &str,
    similarity: Option<f64>,
    truth: Option<f64>,
    theme_id: Option<Uuid>,
    links: &Links,
) -> SearchResult {
    let label = label_of(text);
    SearchResult {
        claim_id: id,
        key: claim_key(id),
        label: if label.is_empty() {
            id.to_string()
        } else {
            label
        },
        similarity: finite(similarity),
        truth_value: finite(truth),
        theme_id,
        href: links.claim(id),
    }
}

async fn search(
    State(state): State<AppState>,
    user: SignedIn,
    Query(p): Query<SearchParams>,
) -> Result<Response, AppError> {
    let q = present(p.q.as_deref())
        .ok_or_else(|| AppError::BadRequest("Type something to search for.".into()))?;
    if q.chars().count() > MAX_QUERY_CHARS {
        return Err(AppError::BadRequest(format!(
            "Searches are limited to {MAX_QUERY_CHARS} characters."
        )));
    }
    let label_mode = match present(p.mode.as_deref()) {
        None | Some("semantic") => false,
        Some("label") => true,
        Some(_) => return Err(bad("mode")),
    };
    let theme = parse_uuid_param(p.theme.as_deref(), "theme")?;
    if label_mode && theme.is_some() {
        return Err(AppError::BadRequest(
            "Label search cannot be limited to a theme.".into(),
        ));
    }
    let limit = parse_limit(p.limit.as_deref(), SEARCH_DEFAULT, SEARCH_MAX)?;
    let api = user.api(&state);
    let links = &state.links;

    if label_mode {
        let offset = match present(p.after.as_deref()) {
            None => 0,
            Some(a) => parse_label_cursor(a).ok_or_else(|| bad("after"))?,
        };
        let labels = label_list(q);
        if labels.is_empty() {
            return Err(AppError::BadRequest(
                "Name at least one label to search for.".into(),
            ));
        }
        let hits: Vec<LabelHit> = api
            .search_by_labels(&labels, limit, offset)
            .await
            .map_err(atlas_err)?;
        let next_offset = offset + u64::from(limit);
        let next = (hits.len() as u64 >= u64::from(limit) && next_offset <= MAX_LABEL_OFFSET)
            .then(|| format!("l.{next_offset}"));
        let mut seen = HashSet::new();
        let results = hits
            .iter()
            .filter(|h| seen.insert(h.id))
            .take(SEARCH_MAX as usize)
            .map(|h| result_of(h.id, &h.content, None, h.truth_value, None, links))
            .collect();
        return finish(&SearchBody {
            q: q.to_string(),
            mode: "label",
            theme: None,
            results,
            next,
            truncated: false,
        });
    }

    let (cursor, _) = semantic_cursor(p.after.as_deref())?;
    let call = api.search_semantic_in_theme(theme, "query", Some(q), limit, Some(cursor.as_str()));
    let (found, dir) = match theme {
        Some(_) => {
            let (f, d) = tokio::join!(call, theme_directory(&state, &user));
            (f.map_err(atlas_id_err("theme"))?, Some(d?))
        }
        None => (call.await.map_err(atlas_err)?, None),
    };
    let mut seen = HashSet::new();
    let results = found
        .results
        .iter()
        .filter(|h| seen.insert(h.claim_id))
        .take(SEARCH_MAX as usize)
        .map(|h| {
            result_of(
                h.claim_id,
                &h.statement,
                h.similarity,
                h.epistemic.truth_value,
                theme.and(h.theme_id),
                links,
            )
        })
        .collect();
    let theme_out = match (theme, &found.theme_scope) {
        (Some(id), Some(s)) => Some(SearchTheme {
            id,
            label: dir
                .as_ref()
                .and_then(|d| d.get())
                .and_then(|m| m.get(&id))
                .cloned(),
            member_count: s.member_count,
        }),
        _ => None,
    };
    finish(&SearchBody {
        q: q.to_string(),
        mode: "semantic",
        theme: theme_out,
        results,
        next: checked_next(found.next_cursor),
        truncated: found.truncated,
    })
}

// ---- /bff/atlas/resolve/{key} -------------------------------------------------------

#[derive(Serialize)]
struct ResolveBody {
    key: String,
    kind: &'static str,
    claim_id: Uuid,
    theme: Option<ThemeRef>,
    region_id: Option<Uuid>,
    placement: Option<String>,
    x: Option<f64>,
    y: Option<f64>,
    run_id: Option<Uuid>,
}

async fn resolve(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
) -> Result<Response, AppError> {
    let id = match parse_key(raw.trim()) {
        Ok(id) => id,
        Err(KeyError::Short) => return Err(AppError::BadRequest(SHORT_KEY.into())),
        Err(KeyError::Malformed) => return Err(AppError::NotFound("link".into())),
    };
    let api = user.api(&state);
    let (placement, dir) = tokio::join!(api.placement(id), theme_directory(&state, &user));
    let placement = placement.map_err(atlas_id_err("claim"))?;
    let dir = dir?;
    let p = placement_out(&placement);
    finish(&ResolveBody {
        key: claim_key(id),
        kind: "claim",
        claim_id: id,
        theme: theme_ref(&dir, placement.theme_id),
        region_id: p.region_id,
        placement: p.placement,
        x: p.x,
        y: p.y,
        run_id: p.run_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn link(kind: &str, a: Uuid, b: Uuid) -> LayoutLink {
        LayoutLink {
            kind: kind.into(),
            a,
            b,
            counts: BTreeMap::new(),
            total: 1,
        }
    }

    #[test]
    fn keys_parse_full_ids_only() {
        let id = Uuid::parse_str("0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10").unwrap();
        let k = claim_key(id);
        assert_eq!(k, "c-0b9a5a4e5f434c4b9a523f0d1e2c7a10");
        assert_eq!(parse_key(&k), Ok(id), "round trip");
        assert_eq!(
            parse_key("c-0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10"),
            Ok(id),
            "hyphenated"
        );
        assert_eq!(
            parse_key("c-0B9A5A4E5F434C4B9A523F0D1E2C7A10"),
            Err(KeyError::Malformed),
            "upper case is not a key"
        );
        assert_eq!(parse_key("c-0b9a5a4e"), Err(KeyError::Short));
        for t in [
            "t-0b9a5a4e",
            "t-0b9a5a4e5f434c4b9a523f0d1e2c7a10",
            "t-0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
        ] {
            assert_eq!(parse_key(t), Err(KeyError::Malformed), "{t}");
        }
        for junk in [
            "",
            "c-",
            "c-0b9a5a4g",
            "c-0b9a5a4e5f434c4b9a523f0d1e2c7a1",
            "c-0b9a5a4e5f434c4b9a523f0d1e2c7a100",
            "c-0b9a5a4e-5f43-4c4b-9a52_3f0d1e2c7a10",
            "c--b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
            "x-0b9a5a4e",
            "0b9a5a4e5f434c4b9a523f0d1e2c7a10",
            "c-0b9a5a4e5f434c4b9a523f0d1e2c7a1é",
        ] {
            assert_eq!(parse_key(junk), Err(KeyError::Malformed), "{junk:?}");
        }
    }

    #[test]
    fn cursors_are_checked_by_syntax() {
        assert_eq!(opaque_cursor(None, "a").unwrap(), None);
        assert_eq!(opaque_cursor(Some("  "), "a").unwrap(), None);
        assert_eq!(
            opaque_cursor(Some("k1.1730700000000000.3f2c:ab-c_"), "a").unwrap(),
            Some("k1.1730700000000000.3f2c:ab-c_")
        );
        for bad in ["x y", "a$b", "a/b", "a%2Fb", "é"] {
            assert!(opaque_cursor(Some(bad), "a").is_err(), "{bad}");
        }
        assert!(opaque_cursor(Some(&"a".repeat(256)), "a").is_ok());
        assert!(opaque_cursor(Some(&"a".repeat(257)), "a").is_err());

        assert_eq!(parse_offset_cursor("o:0"), Some(0));
        assert_eq!(parse_offset_cursor("o:999"), Some(999));
        for bad in ["o:1000", "o:", "o:abc", "o:-1", "o:00001", "p.0", "o:1 "] {
            assert_eq!(parse_offset_cursor(bad), None, "{bad}");
        }
        assert_eq!(parse_packed_cursor("p.0"), Some(0));
        assert_eq!(parse_packed_cursor("p.400"), Some(400));
        for bad in ["p.7", "p.600", "p.", "o:0"] {
            assert_eq!(parse_packed_cursor(bad), None, "{bad}");
        }
        assert_eq!(parse_label_cursor("l.1000"), Some(1000));
        assert_eq!(parse_label_cursor("l.20"), Some(20));
        for bad in ["l.1001", "l.", "l.x", "l.10000"] {
            assert_eq!(parse_label_cursor(bad), None, "{bad}");
        }
    }

    #[test]
    fn rel_is_validated_and_lower_cased() {
        assert_eq!(parse_rel(None).unwrap(), None);
        assert_eq!(parse_rel(Some(" ")).unwrap(), None);
        assert_eq!(parse_rel(Some("*")).unwrap().as_deref(), Some("*"));
        assert_eq!(
            parse_rel(Some("Supports, cites")).unwrap().as_deref(),
            Some("supports,cites")
        );
        for bad in ["a;b", "a,,b", "decomposes-to", "a1", &"x,".repeat(13)] {
            assert!(parse_rel(Some(bad)).is_err(), "{bad}");
        }
        assert!(parse_rel(Some(&"a".repeat(41))).is_err());
        assert!(parse_rel(Some(&["a"; 12].join(","))).is_ok());
    }

    #[test]
    fn counts_fold_and_refute_share() {
        let mut c = BTreeMap::new();
        c.insert("SUPPORTS".to_string(), 30);
        c.insert("supports".to_string(), 10);
        c.insert("Contradicts".to_string(), 4);
        c.insert("refutes".to_string(), 2);
        let f = fold_counts(&c);
        assert_eq!(f["supports"], 40);
        assert_eq!(f["contradicts"], 4);
        assert_eq!(f.len(), 3);
        assert_eq!(refute_share(&f, 46), 0.1304);
        assert_eq!(refute_share(&f, 0), 0.0, "an empty bundle");
        assert_eq!(refute_share(&BTreeMap::new(), 5), 0.0);
    }

    #[test]
    fn contested_counts_incoming_weakening_only() {
        let row = |r: &str, d: &str, n: i64| RelCount {
            relationship: r.into(),
            direction: d.into(),
            count: n,
        };
        let c = contested_from(&[
            row("CONTRADICTS", "incoming", 1),
            row("refutes", "incoming", 1),
            row("refutes", "outgoing", 5),
            row("supports", "incoming", 9),
        ]);
        assert_eq!(
            c,
            Contested {
                contested: true,
                incoming: 2
            }
        );
        assert!(!contested_from(&[row("refutes", "outgoing", 3)]).contested);
        assert!(!contested_from(&[]).contested);
    }

    #[test]
    fn layout_links_name_only_what_the_viewer_sees() {
        let (r1, r2, r3) = (u(1), u(2), u(3));
        let (t1, t2, hidden) = (u(11), u(12), u(13));
        let regions: HashSet<Uuid> = [r1, r2].into_iter().collect();
        let top = vec![
            link("region", r1, r2),
            link("region", r1, r3),
            link("region", r1, r2),
        ];
        let kept = filter_layout_links(&top, &LinkScope::Top { regions: &regions });
        assert_eq!(kept.len(), 1, "unknown region dropped, duplicate dropped");

        let themes: HashSet<Uuid> = [t1, t2].into_iter().collect();
        let page = vec![
            link("theme", t1, t2),
            link("theme", t1, hidden),
            link("theme_region", t1, r2),
            link("theme_region", t1, r3),
            link("theme_region", hidden, r2),
            link("region", r1, r2),
        ];
        let kept = filter_layout_links(
            &page,
            &LinkScope::Region {
                themes: &themes,
                regions: Some(&regions),
            },
        );
        let kinds: Vec<(&str, Uuid)> = kept.iter().map(|l| (l.kind.as_str(), l.b)).collect();
        assert_eq!(kinds, vec![("theme", t2), ("theme_region", r2)]);

        let kept = filter_layout_links(
            &page,
            &LinkScope::Region {
                themes: &themes,
                regions: None,
            },
        );
        assert!(
            kept.iter().all(|l| l.kind == "theme"),
            "no top level: every theme_region link goes"
        );
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn packed_paging() {
        assert_eq!(packed_page(250, 0), (0..200, Some("p.200".into())));
        assert_eq!(packed_page(250, 200), (200..250, None));
        assert_eq!(packed_page(250, 400), (250..250, None), "past the end");
        assert_eq!(packed_page(500, 200), (200..400, Some("p.400".into())));
        assert_eq!(packed_page(500, 400), (400..500, None));
        assert_eq!(packed_page(0, 0), (0..0, None));
    }

    #[test]
    fn upstream_errors_collapse_for_id_routes() {
        let m = atlas_id_err("claim");
        let nf = |e: AppError| matches!(e, AppError::NotFound(w) if w == "claim");
        assert!(nf(m(UpstreamError::Forbidden {
            message: "x".into()
        })));
        assert!(nf(m(UpstreamError::NotFound {
            message: "y".into()
        })));
        assert!(matches!(
            m(UpstreamError::Rejected {
                status: 400,
                kind: None,
                message: "bad cursor".into()
            }),
            AppError::BadRequest(_)
        ));
        assert!(matches!(
            m(UpstreamError::Server {
                status: 500,
                message: "boom".into()
            }),
            AppError::Upstream(_)
        ));
        assert!(matches!(
            atlas_err(UpstreamError::Forbidden {
                message: "x".into()
            }),
            AppError::Forbidden(_)
        ));
    }

    #[test]
    fn labels_stay_within_160_chars() {
        let long = "𝄞".repeat(400);
        let l = label_of(&long);
        assert_eq!(l.chars().count(), LABEL_CHARS);
        assert!(l.ends_with('…'));
        let exact = "a".repeat(160);
        assert_eq!(label_of(&exact), exact);
        assert_eq!(label_of("  two\n lines "), "two lines");
        let (c, cut) = clip(&"é".repeat(1501), CENTRE_CONTENT_CHARS);
        assert!(cut && c.chars().count() == CENTRE_CONTENT_CHARS);
    }
}
