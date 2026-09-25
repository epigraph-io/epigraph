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
use crate::upstream::entities::{
    AgentClaimsPage, EpistemicProfileResponse, FrameClaimRow, FrameDetailResponse,
    VersionHistoryResponse, FRAME_CLAIM_ORDERS, FRAME_CLAIM_SORTS,
};
use crate::upstream::{
    degrade, truncate_chars, ClaimResponse, Degraded, UpstreamError, PROVENANCE_DEPTH_RANGE,
    REDACTED,
};
use crate::view::render;

mod present;

use present::{
    claim_text, duplicate_of, evidence_kind, fmt_pct, fmt_prob, fmt_time, humanise_key,
    layout_chain, one_of, orcid_url, parse_depth, parse_page, query_param, ror_url, share_rows,
    short_id, source_links, ChainLayout, ClaimText, EvidenceKind, ExtLink, ShareRow,
    DEFAULT_PROVENANCE_DEPTH,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/claim/{id}/history", get(history))
        .route("/claim/{id}/provenance", get(provenance))
        .route("/agent/{id}", get(agent))
        .route("/frame/{id}", get(frame))
        .route("/evidence/{id}", get(evidence))
}

/// Attributed claims per page on `/agent/:id`.
const AGENT_CLAIMS_PER_PAGE: u32 = 20;
/// Claims per page on `/frame/:id`.
const FRAME_CLAIMS_PER_PAGE: u32 = 25;
/// Longest claim text in a list row.
const LIST_TEXT_CHARS: usize = 320;
/// Longest claim text in a page heading.
const HEADING_TEXT_CHARS: usize = 500;
/// Topics shown on the epistemic profile (upstream sends every label).
const PROFILE_TOPICS: usize = 40;
/// Rows per distribution table on the epistemic profile.
const PROFILE_SHARE_ROWS: usize = 12;
/// Longest evidence content shown before cutting.
const EVIDENCE_TEXT_CHARS: usize = 20_000;

/// A `{id}` path segment as a UUID; malformed → 404 for `what`.
fn parse_id(raw: &str, what: &'static str) -> Result<Uuid, AppError> {
    Uuid::parse_str(raw.trim()).map_err(|_| AppError::NotFound(what.into()))
}

/// Previous / next links for an offset-paged list.
struct Pager {
    summary: String,
    prev_url: Option<String>,
    next_url: Option<String>,
}

/// `?page=` links on `base` (a browser path without a query) that keep
/// `extra` query pairs.
fn page_url(base: &str, page: u32, extra: &[(&str, &str)]) -> String {
    let mut qs = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in extra {
        qs.append_pair(k, v);
    }
    if page > 1 {
        qs.append_pair("page", &page.to_string());
    }
    let qs = qs.finish();
    if qs.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{qs}")
    }
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
    // Since the §2.6 sweep `/history` redacts per version upstream
    // (`versioning::claim_history`), so this is belt and braces rather than
    // the only guard: a claim hidden from this viewer still gets no
    // content-bearing sub-call at all (plan §3.4), which also saves the call.
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

// ---- /agent/:id --------------------------------------------------------------

#[derive(Template)]
#[template(path = "entities/agent.html")]
struct AgentPage {
    ctx: PageCtx,
    name: String,
    named: bool,
    id: Uuid,
    public_key: Option<String>,
    created: String,
    labels: Vec<String>,
    orcid: Option<ExtLink>,
    ror: Option<ExtLink>,
    claims: Degraded<AttributedView>,
    profile: Degraded<ProfileView>,
}

struct AttributedView {
    rows: Vec<ClaimRow>,
    pager: Pager,
}

struct ClaimRow {
    url: String,
    text: ClaimText,
    truth: String,
    created: String,
}

struct ProfileView {
    claim_count: u64,
    mean_truth: String,
    refutation_rate: String,
    first: String,
    last: String,
    evidence: Vec<ShareRow>,
    statuses: Vec<ShareRow>,
    topics: Vec<String>,
    more_topics: usize,
}

fn attributed_view(p: &AgentClaimsPage, page: u32, base: &str, links: &Links) -> AttributedView {
    let total = u64::try_from(p.total).unwrap_or(0);
    let offset = u64::from(page - 1) * u64::from(AGENT_CLAIMS_PER_PAGE);
    let shown = p.items.len() as u64;
    let summary = if shown == 0 {
        if total == 0 {
            "No claims are attributed to this agent.".to_string()
        } else {
            format!("No attributed claims on this page ({total} in total).")
        }
    } else {
        format!("Showing {}–{} of {total}.", offset + 1, offset + shown)
    };
    AttributedView {
        rows: p
            .items
            .iter()
            .map(|c| ClaimRow {
                url: links.claim(c.id),
                text: claim_text(&c.content, LIST_TEXT_CHARS),
                truth: fmt_prob(c.truth_value),
                created: fmt_time(c.created_at.as_deref()),
            })
            .collect(),
        pager: Pager {
            summary,
            prev_url: (page > 1).then(|| page_url(base, page - 1, &[])),
            next_url: (offset + shown < total && shown > 0).then(|| page_url(base, page + 1, &[])),
        },
    }
}

fn profile_view(p: &EpistemicProfileResponse) -> ProfileView {
    let range = p.time_range.as_ref();
    ProfileView {
        claim_count: p.claim_count,
        mean_truth: fmt_prob(p.mean_truth_value),
        refutation_rate: p.refutation_rate.map_or_else(|| "—".into(), fmt_pct),
        first: fmt_time(range.and_then(|r| r.first.as_deref())),
        last: fmt_time(range.and_then(|r| r.last.as_deref())),
        evidence: share_rows(&p.evidence_distribution, PROFILE_SHARE_ROWS, |k| {
            evidence_kind(Some(k)).label
        }),
        statuses: share_rows(
            &p.epistemic_status_distribution,
            PROFILE_SHARE_ROWS,
            humanise_key,
        ),
        topics: p
            .topics
            .iter()
            .take(PROFILE_TOPICS)
            .map(|t| truncate_chars(t, 60))
            .collect(),
        more_topics: p.topics.len().saturating_sub(PROFILE_TOPICS),
    }
}

async fn agent(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Html<String>, AppError> {
    let id = parse_id(&raw, "agent")?;
    let page = parse_page(query_param(query.as_deref(), "page").as_deref());
    let offset = u64::from(page - 1) * u64::from(AGENT_CLAIMS_PER_PAGE);
    let api = user.api(&state);
    // The profile is unbounded upstream and may time out; it degrades alone.
    let (detail, claims, profile) = tokio::join!(
        api.agent_detail(id),
        api.agent_attributed_claims(id, AGENT_CLAIMS_PER_PAGE, offset),
        api.agent_epistemic_profile(id),
    );
    let detail = detail.map_err(not_found_as("agent"))?;
    let base = state.links.agent(id);
    let claims = degrade(claims)?.map(|p| attributed_view(&p, page, &base, &state.links));
    let profile = degrade(profile)?.map(|p| profile_view(&p));

    let name = detail
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(|n| truncate_chars(n, 200));
    let ext = |kind: &'static str, raw: &Option<String>, f: fn(&str) -> Option<String>| {
        raw.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| ExtLink {
                kind,
                href: f(s),
                text: truncate_chars(s, 80),
            })
    };
    render(&AgentPage {
        named: name.is_some(),
        name: name.unwrap_or_else(|| format!("Agent {}", short_id(id))),
        id,
        public_key: detail
            .public_key
            .as_deref()
            .filter(|k| !k.is_empty())
            .map(|k| truncate_chars(k, 130)),
        created: fmt_time(detail.created_at.as_deref()),
        labels: detail
            .labels
            .iter()
            .map(|l| truncate_chars(l, 60))
            .collect(),
        orcid: ext("ORCID", &detail.orcid, orcid_url),
        ror: ext("ROR", &detail.ror_id, ror_url),
        claims,
        profile,
        ctx: user.ctx,
    })
}

// ---- /frame/:id --------------------------------------------------------------

#[derive(Template)]
#[template(path = "entities/frame.html")]
struct FramePage {
    ctx: PageCtx,
    id: Uuid,
    title: String,
    self_url: String,
    definition: Degraded<FrameView>,
    claims: Degraded<FrameClaimsView>,
    sort_options: Vec<(&'static str, bool)>,
    order_options: Vec<(&'static str, bool)>,
}

struct FrameView {
    description: Option<String>,
    hypotheses: Vec<(usize, String)>,
    parent_url: Option<String>,
    is_refinable: bool,
    version: String,
    created: String,
    claim_count: u64,
}

struct FrameClaimsView {
    rows: Vec<FrameClaimView>,
    pager: Pager,
}

struct FrameClaimView {
    url: String,
    text: ClaimText,
    hypothesis: Option<String>,
    belief: String,
    plausibility: String,
    ignorance: String,
}

fn frame_view(d: &FrameDetailResponse, links: &Links) -> FrameView {
    let f = &d.frame;
    FrameView {
        description: f
            .description
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| truncate_chars(s, 4000)),
        hypotheses: f
            .hypotheses
            .iter()
            .enumerate()
            .map(|(i, h)| (i, truncate_chars(h, 300)))
            .collect(),
        parent_url: f.parent_frame_id.map(|p| links.frame(p)),
        is_refinable: f.is_refinable,
        version: f.version.map_or_else(|| "—".into(), |v| v.to_string()),
        created: fmt_time(f.created_at.as_deref()),
        claim_count: d.claim_count,
    }
}

/// `rows` was fetched with one extra row: its presence means a next page.
fn frame_claims_view(
    mut rows: Vec<FrameClaimRow>,
    hypotheses: Option<&[String]>,
    page: u32,
    base: &str,
    extra: &[(&str, &str)],
    links: &Links,
) -> FrameClaimsView {
    let per_page = FRAME_CLAIMS_PER_PAGE as usize;
    let has_next = rows.len() > per_page;
    rows.truncate(per_page);
    let offset = (page as usize - 1) * per_page;
    let summary = if rows.is_empty() {
        if page > 1 {
            "No claims on this page.".to_string()
        } else {
            "No claims are in this frame.".to_string()
        }
    } else {
        format!(
            "Showing {}–{}{}.",
            offset + 1,
            offset + rows.len(),
            if has_next { " (more follow)" } else { "" }
        )
    };
    FrameClaimsView {
        rows: rows
            .iter()
            .map(|r| FrameClaimView {
                url: links.claim(r.claim_id),
                text: claim_text(&r.content, LIST_TEXT_CHARS),
                hypothesis: r.hypothesis_index.map(|i| {
                    usize::try_from(i)
                        .ok()
                        .and_then(|i| hypotheses.and_then(|h| h.get(i)))
                        .map_or_else(|| format!("#{i}"), |h| truncate_chars(h, 120))
                }),
                belief: fmt_prob(r.belief),
                plausibility: fmt_prob(r.plausibility),
                ignorance: fmt_prob(r.ignorance),
            })
            .collect(),
        pager: Pager {
            summary,
            prev_url: (page > 1).then(|| page_url(base, page - 1, extra)),
            next_url: has_next.then(|| page_url(base, page + 1, extra)),
        },
    }
}

async fn frame(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Html<String>, AppError> {
    let id = parse_id(&raw, "frame")?;
    let q = query.as_deref();
    let page = parse_page(query_param(q, "page").as_deref());
    let sort = one_of(query_param(q, "sort").as_deref(), FRAME_CLAIM_SORTS);
    let order = one_of(query_param(q, "order").as_deref(), FRAME_CLAIM_ORDERS);
    let offset = u64::from(page - 1) * u64::from(FRAME_CLAIMS_PER_PAGE);
    let api = user.api(&state);
    let (detail, rows) = tokio::join!(
        api.frame_detail(id),
        // One extra row tells us whether a next page exists (no `total`).
        api.frame_claims_page(id, sort, order, FRAME_CLAIMS_PER_PAGE + 1, offset),
    );

    // `/frames/:id` also returns every membership row, unpaginated; for a
    // huge frame it can fail (size cap, timeout) while the paged claims
    // succeed. Either source proves the frame exists, so its definition
    // degrades only when the claims came back.
    let detail = match detail {
        Ok(d) => Degraded::ok(d),
        Err(e @ UpstreamError::NotFound { .. }) => return Err(not_found_as("frame")(e)),
        Err(e) if rows.is_ok() => degrade(Err(e))?,
        Err(e) => return Err(e.into()),
    };
    let rows = match rows {
        Err(e @ UpstreamError::NotFound { .. }) if !detail.is_available() => {
            return Err(not_found_as("frame")(e))
        }
        other => degrade(other)?,
    };

    let self_url = state.links.frame(id);
    let mut extra: Vec<(&str, &str)> = Vec::new();
    if sort != FRAME_CLAIM_SORTS[0] {
        extra.push(("sort", sort));
    }
    if order != FRAME_CLAIM_ORDERS[0] {
        extra.push(("order", order));
    }
    let hypotheses = detail.get().map(|d| d.frame.hypotheses.as_slice());
    let claims =
        rows.map(|r| frame_claims_view(r, hypotheses, page, &self_url, &extra, &state.links));
    let title = detail
        .get()
        .map(|d| d.frame.name.trim())
        .filter(|n| !n.is_empty())
        .map_or_else(
            || format!("Frame {}", short_id(id)),
            |n| truncate_chars(n, 200),
        );
    render(&FramePage {
        id,
        title,
        definition: detail.map(|d| frame_view(&d, &state.links)),
        claims,
        sort_options: FRAME_CLAIM_SORTS.iter().map(|s| (*s, *s == sort)).collect(),
        order_options: FRAME_CLAIM_ORDERS
            .iter()
            .map(|o| (*o, *o == order))
            .collect(),
        self_url,
        ctx: user.ctx,
    })
}

// ---- /evidence/:id -----------------------------------------------------------

#[derive(Template)]
#[template(path = "entities/evidence.html")]
struct EvidencePage {
    ctx: PageCtx,
    id: Uuid,
    kind: EvidenceKind,
    content: Option<ClaimText>,
    sources: Vec<ExtLink>,
    /// `(label, value)` metadata rows; only fields upstream sent.
    meta: Vec<(&'static str, String)>,
    content_hash: Option<String>,
    agent_url: Option<String>,
    linked_claim: Option<LinkedClaim>,
}

struct LinkedClaim {
    url: String,
    short: String,
    text: Degraded<ClaimText>,
}

async fn evidence(
    State(state): State<AppState>,
    user: SignedIn,
    Path(raw): Path<String>,
) -> Result<Html<String>, AppError> {
    let id = parse_id(&raw, "evidence")?;
    let api = user.api(&state);
    let ev = api
        .evidence_detail(id)
        .await
        .map_err(not_found_as("evidence"))?;
    let redacted = ev.content.as_deref().map(str::trim) == Some(REDACTED);

    // `/evidence/:id` redacts only when its linked claim is hidden, so a
    // redacted row gets no claim sub-call (plan §3.4 "Rules for rendering").
    let linked_claim = match ev.claim_id {
        None => None,
        Some(cid) => {
            let text = if redacted {
                Degraded::ok(claim_text(REDACTED, LIST_TEXT_CHARS))
            } else {
                degrade(api.claim(cid).await)?
                    .map(|c: ClaimResponse| claim_text(&c.content, HEADING_TEXT_CHARS))
            };
            Some(LinkedClaim {
                url: state.links.claim(cid),
                short: short_id(cid),
                text,
            })
        }
    };

    let mut meta: Vec<(&'static str, String)> = Vec::new();
    let mut push = |label: &'static str, v: Option<String>| {
        if let Some(v) = v.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
            meta.push((label, truncate_chars(&v, 500)));
        }
    };
    push("Recorded", Some(fmt_time(ev.created_at.as_deref())));
    push("Caption", ev.caption.clone());
    push("Figure", ev.figure_id.clone());
    push("Page", ev.page.map(|p| p.to_string()));
    push("Pages", ev.page_range.clone());
    push("Extraction target", ev.extraction_target.clone());
    push("Media type", ev.mime_type.clone());

    render(&EvidencePage {
        id,
        kind: evidence_kind(ev.evidence_type.as_deref()),
        content: ev
            .content
            .as_deref()
            .filter(|c| !c.trim().is_empty())
            .map(|c| claim_text(c, EVIDENCE_TEXT_CHARS)),
        sources: source_links(ev.source_url.as_deref(), ev.doi.as_deref()),
        meta,
        content_hash: ev
            .content_hash
            .as_deref()
            .filter(|h| !h.is_empty())
            .map(|h| truncate_chars(h, 130)),
        agent_url: ev.agent_id.map(|a| state.links.agent(a)),
        linked_claim,
        ctx: user.ctx,
    })
}
