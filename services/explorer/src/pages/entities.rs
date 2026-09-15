//! `/claim/:id/history`, `/claim/:id/provenance`, `/agent/:id`, `/frame/:id`,
//! `/evidence/:id` (plan §3.4). OWNED BY THE ENTITIES AREA.
//!
//! Every page requires a signed-in viewer. The `{id}` segment is parsed here,
//! not by `Path<Uuid>`: a malformed id is a 404 for the entity and never
//! reaches upstream. The page's own entity is a required call (upstream 404
//! → 404 page, other failures → 502/504); everything else is a degraded
//! section. Presentation logic lives in [`present`].

use askama::Template;
use axum::extract::{Path, RawQuery, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use uuid::Uuid;

use crate::auth::{PageCtx, SignedIn};
use crate::error::{not_found_as, AppError};
use crate::links::Links;
use crate::state::AppState;
use crate::upstream::entities::VersionHistoryResponse;
use crate::upstream::{degrade, Degraded, PROVENANCE_DEPTH_RANGE};
use crate::view::{render, stub_page};

mod present;

use present::{
    claim_text, duplicate_of, fmt_prob, fmt_time, layout_chain, parse_depth, query_param, short_id,
    ChainLayout, ClaimText, DEFAULT_PROVENANCE_DEPTH,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/claim/{id}/history", get(history))
        .route("/claim/{id}/provenance", get(provenance))
        .route("/agent/{id}", get(agent))
        .route("/frame/{id}", get(frame))
        .route("/evidence/{id}", get(evidence))
}

/// Longest claim text in a list row.
const LIST_TEXT_CHARS: usize = 320;
/// Longest claim text in a page heading.
const HEADING_TEXT_CHARS: usize = 500;

/// A `{id}` path segment as a UUID; malformed → 404 for `what`.
fn parse_id(raw: &str, what: &'static str) -> Result<Uuid, AppError> {
    Uuid::parse_str(raw.trim()).map_err(|_| AppError::NotFound(what.into()))
}

// ---- /claim/:id/history ------------------------------------------------------

#[derive(Template)]
#[template(path = "entities/history.html")]
struct HistoryPage {
    ctx: PageCtx,
    claim_url: String,
    provenance_url: String,
    heading: ClaimText,
    history: Degraded<HistoryView>,
}

struct HistoryView {
    rows: Vec<VersionRow>,
    has_duplicates: bool,
}

struct VersionRow {
    version: u32,
    url: String,
    short: String,
    text: ClaimText,
    is_current: bool,
    is_requested: bool,
    /// `(version, url)` of the claim this one duplicates.
    duplicate_of: Option<(u32, String)>,
    /// Retired by a newer version (not current, not a duplicate).
    superseded: bool,
    created: String,
    truth: String,
}

fn history_view(h: &VersionHistoryResponse, requested: Uuid, links: &Links) -> HistoryView {
    let dups = duplicate_of(&h.versions);
    let rows: Vec<VersionRow> = h
        .versions
        .iter()
        .zip(&dups)
        .enumerate()
        .map(|(i, (v, dup))| {
            let version = if v.version > 0 {
                v.version
            } else {
                i as u32 + 1
            };
            let duplicate_of = dup.map(|j| {
                let canon = &h.versions[j];
                let n = if canon.version > 0 {
                    canon.version
                } else {
                    j as u32 + 1
                };
                (n, links.claim(canon.claim_id))
            });
            VersionRow {
                version,
                url: links.claim(v.claim_id),
                short: short_id(v.claim_id),
                text: claim_text(&v.content, LIST_TEXT_CHARS),
                is_current: v.is_current,
                is_requested: v.claim_id == requested,
                superseded: !v.is_current && duplicate_of.is_none(),
                duplicate_of,
                created: fmt_time(v.created_at.as_deref()),
                truth: fmt_prob(v.truth_value),
            }
        })
        .collect();
    HistoryView {
        has_duplicates: rows.iter().any(|r| r.duplicate_of.is_some()),
        rows,
    }
}

async fn history(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
) -> Result<Html<String>, AppError> {
    let id = parse_id(&raw, "claim")?;
    let api = user.api(&state);
    let claim = api.claim(id).await.map_err(not_found_as("claim"))?;
    // `/history` does not redact upstream (until the §2.6 sweep): a claim
    // hidden from this viewer gets no content-bearing sub-call (plan §3.4).
    let history = if claim.is_redacted() {
        Degraded::unavailable(
            "This claim's content is hidden from you, so its version history is not shown.",
        )
    } else {
        degrade(api.claim_versions(id).await)?.map(|h| history_view(&h, id, &state.links))
    };
    render(&HistoryPage {
        claim_url: state.links.claim(id),
        provenance_url: state.links.claim_provenance(id),
        heading: claim_text(&claim.content, HEADING_TEXT_CHARS),
        history,
        ctx: user.ctx,
    })
}

// ---- /claim/:id/provenance ---------------------------------------------------

#[derive(Template)]
#[template(path = "entities/provenance.html")]
struct ProvenancePage {
    ctx: PageCtx,
    claim_url: String,
    history_url: String,
    /// This page without a query (the depth form's action).
    self_url: String,
    depth: u32,
    depth_options: Vec<(u32, bool)>,
    heading: ClaimText,
    layout: ChainLayout,
    truncated: bool,
    /// A link one step deeper when the flag says there may be more.
    deeper_url: Option<(u32, String)>,
}

async fn provenance(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Html<String>, AppError> {
    let id = parse_id(&raw, "claim")?;
    let (lo, hi) = PROVENANCE_DEPTH_RANGE;
    let depth = parse_depth(
        query_param(query.as_deref(), "max_depth").as_deref(),
        DEFAULT_PROVENANCE_DEPTH,
        PROVENANCE_DEPTH_RANGE,
    );
    let chain = user
        .api(&state)
        .provenance_chain(id, depth, None)
        .await
        .map_err(not_found_as("claim"))?;
    let layout = layout_chain(&chain, &state.links);
    let heading = layout
        .levels
        .first()
        .filter(|l| l.depth == 0)
        .and_then(|l| l.nodes.iter().find(|n| n.id == chain.root))
        .map(|n| n.text.clone())
        .unwrap_or_else(|| claim_text("", HEADING_TEXT_CHARS));
    let self_url = state.links.claim_provenance(id);
    let deeper_url = (chain.truncated && depth < hi).then(|| {
        let next = (depth + 2).min(hi);
        (next, format!("{self_url}?max_depth={next}"))
    });
    render(&ProvenancePage {
        claim_url: state.links.claim(id),
        history_url: state.links.claim_history(id),
        self_url,
        depth,
        depth_options: (lo..=hi).map(|d| (d, d == depth)).collect(),
        heading,
        layout,
        truncated: chain.truncated,
        deeper_url,
        ctx: user.ctx,
    })
}

// STUB: `/agents/:id`, `/agents/:id/claims`, `/agents/:id/epistemic-profile`.
async fn agent(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Agent", "entities")
}

// STUB: `/frames/:id`, `/frames/:id/claims`.
async fn frame(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Frame", "entities")
}

// STUB: `/evidence/:id`.
async fn evidence(user: SignedIn) -> Result<Html<String>, AppError> {
    stub_page(user.ctx, "Evidence", "entities")
}
