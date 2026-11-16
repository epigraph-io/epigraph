//! The guest read surface (backlog `1deb9dbf`): anonymous, read-only reads of
//! the PUBLIC graph under `/api/v1/guest/`.
//!
//! A guest is a caller with no bearer: a signed-out visitor, or a link-card
//! fetcher that unfurls a pasted claim link without any user token. Every
//! handler here reads as [`Viewer::public_only`], a scoped viewer over no
//! group, so it reads `visibility = 'public'` rows and nothing else. On the
//! production pool both migration 077's row policies and the in-query `$V`
//! predicate apply, as for a signed-in principal that has joined nothing,
//! less that principal's personal group. A valid bearer the request happens to carry does not widen what
//! these routes read (a signed-in caller reads its own graph through the
//! authenticated routes); it only moves the rate-limit charge from the client
//! address to the principal. A present but invalid bearer is refused 401 by the
//! `public` router's optional bearer layer, as on every route of that router.
//!
//! # The routes
//!
//! | Route | Answer |
//! |---|---|
//! | `GET /api/v1/guest/claims/:id` | [`GuestClaimCard`] |
//! | `GET /api/v1/guest/claims/:id/ego` | the authenticated ego body, read as the guest |
//! | `GET /api/v1/guest/graph/themes/overview` | [`GuestThemesOverview`]: ids and public counts, no labels |
//! | `GET /api/v1/guest/graph/themes/layout` | the authenticated layout body, read as the guest, with no theme or region label; the unplaced list is refused |
//!
//! # Off unless the operator switches it on
//!
//! The routes answer only when [`AppState::guest_reads`] is
//! [`GuestReads::On`], which `bin/server.rs` reads from
//! `EPIGRAPH_GUEST_READS=on`. Off (the default in every constructor), each
//! answers a bare 404 with no body, as an unrouted path does. Rows were stored
//! as `public` while that meant "any signed-in agent" (`docs/tenancy.md`, D3),
//! so opening them to the internet is a deliberate act and not a side effect
//! of a deploy.
//!
//! # A non-public id is an absent one
//!
//! The card and the ego answer a claim the guest may not read with the same
//! `NotFound` 404 as an id that names nothing: same status, content type and
//! body (which echoes only the caller's own id). The card reads its row
//! through the viewer predicate, so "private" and "absent" are one `None`.
//!
//! # What a guest does not get
//!
//! * **Who filed it.** The card carries no `agent_id`, no `trace_id`, no
//!   tenancy or encryption field and no `authored_by` block, which names
//!   humans and prompt snapshots. Its `sources` are the documents the claim
//!   came from (key and title), as read under the guest viewer. The ego hides
//!   every edge to an `agent` ([`GUEST_EGO_HIDDEN_TYPES`]): the edges a claim
//!   write leaves (`AUTHORED`, `asserts`, `generated`, …) would otherwise name
//!   the filer's id and display name, so they are left out of the count, the
//!   edges and the nodes alike.
//! * **A stored theme or region label.** The theme labeller samples members
//!   with no visibility predicate, so a stored label may be derived from text
//!   the guest cannot read (residual `D-PR16-theme-cluster-viewer-scope`), and
//!   a region label is built from its themes' labels. The overview and the
//!   layout therefore withhold both, and the layout refuses the unplaced list,
//!   which is ordered by label and whose cursor carries the label bytes.
//! * **A sealed claim.** Never public, so never served: the database forbids
//!   `(public, sealed)` in both directions (migration 081 refuses a seal on a
//!   public claim, and `epigraph_claims_block_widening`, migration 074,
//!   refuses publishing a sealed one).
//!   The card therefore reads no seal record, which the guest's session could
//!   not see anyway (`claim_encryption` rows are read by group membership).
//!
//! # The envelope
//!
//! The routes sit on the `public` router (`routes/mod.rs`), so they carry its
//! layers: the anonymous body limit and, when the operator configured one
//! (it is off unless `EPIGRAPH_RATE_LIMIT*` is set), the rate limiter, which
//! charges a request without a token to its client address. Every answer is
//! `Cache-Control: no-store`, so a claim made private stops being served at
//! once rather than when a cache expires.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::{AuthoredBy, AuthoredByRepository, ClaimRepository};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::routes::{finish_scoped_read, open_scoped_read};
use crate::state::{AppState, GuestReads};

/// The far-endpoint types the guest ego never shows. An `agent` is the filer,
/// asserter or ingester of a claim; its display name is what the card leaves
/// out.
pub(crate) const GUEST_EGO_HIDDEN_TYPES: &[&str] = &["agent"];

/// The answer of every guest route while the switch is off: a bare 404, the
/// same status and empty body as a path no route matches.
fn switched_off(state: &AppState) -> Option<Response> {
    (state.guest_reads != GuestReads::On).then(|| no_store(StatusCode::NOT_FOUND.into_response()))
}

/// Mark a guest answer, success or error, as never stored by any cache.
fn no_store(mut res: Response) -> Response {
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn guest_answer<T: IntoResponse>(r: Result<T, ApiError>) -> Response {
    no_store(match r {
        Ok(body) => body.into_response(),
        Err(e) => e.into_response(),
    })
}

fn claim_not_found(id: Uuid) -> ApiError {
    ApiError::NotFound {
        entity: "Claim".to_string(),
        id: id.to_string(),
    }
}

// ── The claim card ──

/// One document a public claim came from.
#[derive(Debug, Serialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct GuestSource {
    /// The document key (a DOI, or another document key).
    pub doi: String,
    pub title: Option<String>,
}

/// `GET /api/v1/guest/claims/:id`: a public claim's card.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GuestClaimCard {
    pub id: Uuid,
    pub content: String,
    /// The claim's stored truth value, the figure the ego's nodes carry.
    pub truth_value: f64,
    pub labels: Vec<String>,
    pub created_at: DateTime<Utc>,
    /// The documents the claim was ingested from, creating document first.
    pub sources: Vec<GuestSource>,
}

/// The documents an [`AuthoredBy`] names, creating document first, each once.
fn sources_of(authored: &AuthoredBy) -> Vec<GuestSource> {
    let mut out: Vec<GuestSource> = Vec::new();
    let mut push = |doi: &str, title: Option<&String>| {
        if !out.iter().any(|s| s.doi == doi) {
            out.push(GuestSource {
                doi: doi.to_string(),
                title: title.cloned(),
            });
        }
    };
    if let AuthoredBy::Literature(l) = authored {
        push(&l.paper.paper.doi, l.paper.paper.title.as_ref());
    }
    for p in &authored.corroboration().corroborated_by {
        push(&p.paper.doi, p.paper.title.as_ref());
    }
    out
}

/// The card of `id` as `viewer` reads it. Every guest handler passes
/// [`Viewer::public_only`]; the parameter is a `&Viewer` so
/// `tests/viewer_spend_lint.rs` measures this body like any other read.
async fn read_claim_card(
    state: &AppState,
    viewer: &Viewer,
    id: Uuid,
) -> Result<Json<GuestClaimCard>, ApiError> {
    let mut read = open_scoped_read(state, viewer, "guest_claim_card").await?;

    let Some((claim, labels)) =
        ClaimRepository::get_by_id_with_labels(&mut *read, viewer, ClaimId::from_uuid(id)).await?
    else {
        return Err(claim_not_found(id));
    };
    let authored = AuthoredByRepository::for_claim(
        &mut read,
        viewer,
        id,
        claim.agent_id.as_uuid(),
        claim.created_at,
        epigraph_db::PROMPT_SNAPSHOT_AUDIENCE,
    )
    .await?;
    finish_scoped_read(read, "guest_claim_card").await?;

    Ok(Json(GuestClaimCard {
        id,
        content: claim.content,
        truth_value: claim.truth_value.value(),
        labels,
        created_at: claim.created_at,
        sources: sources_of(&authored),
    }))
}

/// `GET /api/v1/guest/claims/:id`
pub async fn claim_card(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    if let Some(off) = switched_off(&state) {
        return off;
    }
    guest_answer(read_claim_card(&state, &Viewer::public_only(), id).await)
}

// ── Ego ──

/// `GET /api/v1/guest/claims/:id/ego`: [`crate::routes::ego::claim_ego`] read
/// as the guest, with every edge to a [`GUEST_EGO_HIDDEN_TYPES`] endpoint left
/// out.
pub async fn claim_ego(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<crate::routes::ego::EgoQuery>,
) -> Response {
    if let Some(off) = switched_off(&state) {
        return off;
    }
    guest_answer(
        crate::routes::ego::claim_ego_as(
            &Viewer::public_only(),
            &state,
            id,
            params,
            GUEST_EGO_HIDDEN_TYPES,
        )
        .await,
    )
}

// ── The theme overview ──

/// Query of `GET /api/v1/guest/graph/themes/overview`.
#[derive(Debug, Deserialize)]
pub struct GuestOverviewParams {
    /// Page size, clamped to `1..=200` (the default).
    #[serde(default)]
    pub limit: Option<i64>,
    /// The previous page's `next_cursor`, unchanged.
    #[serde(default)]
    pub after: Option<String>,
}

/// One theme with a public member, without its stored label.
#[derive(Debug, Serialize)]
pub struct GuestThemeOut {
    pub id: Uuid,
    /// Current PUBLIC members of the theme.
    pub claim_count: i64,
}

#[derive(Debug, Serialize)]
pub struct GuestThemesOverview {
    pub themes: Vec<GuestThemeOut>,
    /// Themes with at least one current public member.
    pub total: i64,
    pub next_cursor: Option<String>,
}

/// The overview page as `viewer` reads it; a `&Viewer` for the same reason
/// as [`read_claim_card`].
async fn read_overview(
    state: &AppState,
    viewer: &Viewer,
    params: GuestOverviewParams,
) -> Result<Json<GuestThemesOverview>, ApiError> {
    use epigraph_db::repos::claim_theme::{ThemeOverviewCursor, THEME_OVERVIEW_PAGE_MAX};

    let limit = params
        .limit
        .unwrap_or(THEME_OVERVIEW_PAGE_MAX)
        .clamp(1, THEME_OVERVIEW_PAGE_MAX);
    let after = match params.after.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(token) => Some(ThemeOverviewCursor::decode(token).ok_or_else(|| {
            ApiError::BadRequest {
                message: "malformed `after` cursor; pass back `next_cursor` of the previous \
                          page unchanged"
                    .to_string(),
            }
        })?),
    };

    let mut read = open_scoped_read(state, viewer, "guest_themes_overview").await?;
    let page =
        epigraph_db::ClaimThemeRepository::overview_page(&mut *read, viewer, after, limit).await?;
    finish_scoped_read(read, "guest_themes_overview").await?;

    Ok(Json(GuestThemesOverview {
        themes: page
            .themes
            .into_iter()
            .map(|t| GuestThemeOut {
                id: t.id,
                claim_count: t.member_count,
            })
            .collect(),
        total: page.total,
        next_cursor: page.next.map(|c| c.encode()),
    }))
}

/// `GET /api/v1/guest/graph/themes/overview`
pub async fn themes_overview(
    State(state): State<AppState>,
    Query(params): Query<GuestOverviewParams>,
) -> Response {
    if let Some(off) = switched_off(&state) {
        return off;
    }
    guest_answer(read_overview(&state, &Viewer::public_only(), params).await)
}

// ── The layout ──

/// `GET /api/v1/guest/graph/themes/layout`:
/// [`crate::routes::graph_layout::themes_layout`] read as the guest, with
/// labels withheld.
pub async fn themes_layout(
    State(state): State<AppState>,
    Query(q): Query<crate::routes::graph_layout::LayoutQuery>,
) -> Response {
    if let Some(off) = switched_off(&state) {
        return off;
    }
    guest_answer(
        crate::routes::graph_layout::themes_layout_as(
            &Viewer::public_only(),
            &state,
            q,
            crate::routes::graph_layout::Labels::Withheld,
        )
        .await,
    )
}
