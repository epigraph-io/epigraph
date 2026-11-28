//! Theme READ tools: `list_themes` and `get_theme` (and the theme selector
//! `memory.rs`'s theme-scoped recall shares).
//!
//! The theme layer is maintained by the UMAP theme pipeline
//! (`scripts/cluster_claims.py`, `scripts/maintain_themes.py` and the REST
//! routes they call). The `theme_cluster` tool this module used to implement
//! wrapped the k-means prototype (`epigraph_engine::theme_kmeans`), retired by
//! backlog a0ed0180: no MCP tool rebuilds or wipes themes. The name was then
//! kept registered as a refusal that named the replacement; backlog 90993e95
//! (ruling ea3a3d0c) removed the tool outright, superseding that refusal. A
//! stale caller now gets the kernel's unknown-tool routing error, and the
//! replacement jobs are documented in `docs/deploy.md` (Step 10) and
//! `docs/ops/theme-v2-promotion-runbook.md`.

#![allow(clippy::wildcard_imports)]

use rmcp::model::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;

use epigraph_db::{ClaimThemeRepository, ThemeSummaryRow};

// ─────────────────────────────────────────────────────────────────────────
// READ SIDE — `list_themes` / `get_theme`
//
// Backlog c40689c9 / ac4d02b9: before these, `theme_cluster` (the retired
// k-means wrapper) was the ONLY theme tool, so the only way to learn what the
// current themes contain was to rebuild (and by default wipe) them. Both tools here are pure reads:
// they never call `reject_if_read_only`, take `claims:read`, and issue no
// statement that is not a SELECT.
//
// The auditor note on ac4d02b9 suggested wrapping the HTTP handlers
// `graph::themes_overview` / `graph::themes_expand` instead. That was
// re-measured and rejected: `themes_expand` reads `graph_neighborhoods` keyed
// on `graph_cluster_runs.run_id` (the Louvain neighborhood layer) and degrades
// to `synthesize_pre_run_response` when no run exists — it returns no theme
// membership at all, which is what both backlog texts actually ask for. And an
// axum handler is not callable from MCP. These wrap the repo layer, per the
// CLAUDE.md rule that routes and MCP tools both call `epigraph-db/src/repos/`.
// ─────────────────────────────────────────────────────────────────────────

/// Default / maximum page sizes for the theme reader. The cap bounds what one
/// tool call can pull into a response body; no vectors are returned here.
const THEME_PAGE_DEFAULT: u32 = 50;
const THEME_PAGE_MAX: u32 = 500;
const MEMBER_PAGE_DEFAULT: u32 = 50;
const MEMBER_PAGE_MAX: u32 = 500;

/// Wire shape of one theme on the read path.
#[derive(Debug, Serialize)]
pub struct ThemeSummaryOut {
    pub theme_id: String,
    pub label: String,
    pub description: String,
    /// Live `COUNT(*)` of the `is_current` claims assigned to this theme that
    /// the caller can read. Always at least 1: a theme with no readable
    /// member is not returned at all. The stored, corpus-wide
    /// `claim_themes.claim_count` is deliberately not on this shape (backlog
    /// 06f5c5b2): it disclosed the size of members the caller cannot read.
    pub member_count: i64,
    /// `1536`, `3072`, or `null` when the theme has no centroid at all.
    /// Derived from which centroid column is populated — `claim_themes` has no
    /// `centroid_dim` column.
    pub centroid_dim: Option<i32>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<ThemeSummaryRow> for ThemeSummaryOut {
    fn from(r: ThemeSummaryRow) -> Self {
        Self {
            theme_id: r.id.to_string(),
            label: r.label,
            description: r.description,
            member_count: r.member_count,
            centroid_dim: r.centroid_dim,
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

/// A theme selector resolved to a concrete row, shared by `get_theme` and
/// theme-scoped `recall`.
#[derive(Debug, Clone)]
pub struct ResolvedTheme {
    pub id: Uuid,
    pub label: String,
    pub member_count: i64,
}

/// Resolve a `theme_id` / `theme_label` selector to exactly one theme.
///
/// `Ok(None)` means "no selector supplied" — the caller decides whether that
/// is legal (it is for `recall`, where the theme filter is optional; it is not
/// for `get_theme`).
///
/// Every other ambiguity is an ERROR, never a silently-dropped filter. That
/// choice mirrors `memory.rs::parse_agent_filter`: a scope filter that fails
/// open widens the result set while the caller believes it is scoped, which is
/// worse than a rejected call. Concretely:
///
/// - a malformed `theme_id` is rejected, not ignored;
/// - a `theme_label` matching nothing is rejected, not treated as "no filter"
///   (that is the difference between an empty answer and the whole corpus);
/// - a `theme_label` matching MORE THAN ONE theme is rejected with all the
///   candidate ids. `claim_themes` has no `UNIQUE(label)` constraint, and the
///   retired k-means tool's additive runs left duplicate `auto-00` rows, so
///   picking the first match would silently scope to one of several distinct
///   themes.
///
/// Only themes the caller can see resolve (backlog 06f5c5b2): a theme is
/// visible when the caller can read at least one of its current members, the
/// rule `list_themes` lists by. An unknown id and a hidden one get the same
/// error, and a label lookup never names a hidden theme's id, neither in the
/// duplicate-label candidates nor in a miss.
///
/// `conn` is the caller's viewer-stamped read (`EpiGraphMcpFull::read_as`),
/// and both lookups run on it: each is a claim-derived read, which row
/// security filters.
pub async fn resolve_theme_selector(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    theme_id: Option<&str>,
    theme_label: Option<&str>,
) -> Result<Option<ResolvedTheme>, McpError> {
    let id_raw = theme_id.map(str::trim).filter(|s| !s.is_empty());
    let label_raw = theme_label.map(str::trim).filter(|s| !s.is_empty());

    let unmatched_label = |label: &str| {
        invalid_params(format!(
            "no theme has label {label:?}. Call list_themes to see the current themes; \
             an unmatched label is rejected rather than treated as \"no filter\", \
             which would widen the query to the whole corpus."
        ))
    };

    let resolved_id =
        match (id_raw, label_raw) {
            (None, None) => return Ok(None),
            (Some(_), Some(_)) => return Err(invalid_params(
                "pass either theme_id or theme_label, not both: they can name different themes \
                 and there is no defensible precedence between them",
            )),
            (Some(raw), None) => Uuid::parse_str(raw)
                .map_err(|e| invalid_params(format!("invalid theme_id {raw:?}: {e}")))?,
            (None, Some(label)) => {
                let matches = ClaimThemeRepository::find_by_label(&mut *conn, viewer, label)
                    .await
                    .map_err(internal_error)?;
                match matches.len() {
                    0 => return Err(unmatched_label(label)),
                    1 => matches[0],
                    n => {
                        let ids: Vec<String> = matches.iter().map(ToString::to_string).collect();
                        return Err(invalid_params(format!(
                        "label {label:?} matches {n} distinct themes ({}). claim_themes has no \
                         UNIQUE(label) constraint, so pass one of these as theme_id instead.",
                        ids.join(", ")
                    )));
                    }
                }
            }
        };

    // `None` here means unknown or hidden, indistinguishably. On the label
    // path it can only be a member retired between the two statements; the
    // answer is still the label miss, so no id reaches the caller.
    let summary = ClaimThemeRepository::get_summary(&mut *conn, viewer, resolved_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| match label_raw {
            Some(label) => unmatched_label(label),
            None => invalid_params(format!("no theme with id {resolved_id}")),
        })?;

    Ok(Some(ResolvedTheme {
        id: summary.id,
        label: summary.label,
        member_count: summary.member_count,
    }))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListThemesParams {
    /// Return only themes whose `label` starts with this string (e.g. `"auto"`
    /// for the k-means-generated `auto-00`, `auto-01`, … family). Omit or pass
    /// an empty string for no filter.
    #[serde(default)]
    pub label_prefix: Option<String>,
    /// Page size. Default 50, clamped to 1..=500.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Skip the first N matching themes. Default 0. Combine with `limit` to
    /// page; compare `returned` against `total` to know when to stop.
    #[serde(default)]
    pub offset: Option<u32>,
}

/// `list_themes` — paged, read-only inventory of the theme layer.
pub async fn list_themes(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ListThemesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params
        .limit
        .unwrap_or(THEME_PAGE_DEFAULT)
        .clamp(1, THEME_PAGE_MAX);
    let offset = params.offset.unwrap_or(0);
    let prefix = params.label_prefix.as_deref();

    let mut read = server.read_as(viewer, "list_themes").await?;
    let rows = ClaimThemeRepository::list_summaries(
        &mut *read,
        viewer,
        prefix,
        i64::from(limit),
        i64::from(offset),
    )
    .await
    .map_err(internal_error)?;

    // Same viewer, same connection, same predicate as the page: only themes
    // with a current member the caller can read are counted (backlog
    // 06f5c5b2), so `has_more` never promises hidden themes.
    let total = ClaimThemeRepository::count_summaries(&mut *read, viewer, prefix)
        .await
        .map_err(internal_error)?;
    read.commit().await.map_err(internal_error)?;

    let themes: Vec<ThemeSummaryOut> = rows.into_iter().map(Into::into).collect();
    let returned = themes.len() as i64;
    let body = serde_json::json!({
        "themes": themes,
        // `total` applies the SAME label_prefix predicate as the page, so
        // `offset + returned < total` is an exact "there is more" signal
        // rather than a guess.
        "total": total,
        "returned": returned,
        "limit": limit,
        "offset": offset,
        "has_more": i64::from(offset) + returned < total,
    });

    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetThemeParams {
    /// UUID of the theme (from `list_themes`). Mutually exclusive with
    /// `theme_label`. A malformed UUID is rejected, not ignored.
    #[serde(default)]
    pub theme_id: Option<String>,
    /// Exact theme label. Mutually exclusive with `theme_id`. Rejected when it
    /// matches zero themes, or more than one — `claim_themes` has no
    /// `UNIQUE(label)` constraint.
    #[serde(default)]
    pub theme_label: Option<String>,
    /// Size of the member-claim-id page. Default 50, clamped to 0..=500. Pass
    /// 0 for the summary alone.
    #[serde(default)]
    pub members_limit: Option<u32>,
    /// Skip the first N members. Default 0. Members come back in
    /// `created_at ASC, id ASC` order — a total order, so a limit/offset walk
    /// yields each member exactly once.
    #[serde(default)]
    pub members_offset: Option<u32>,
}

/// `get_theme` — one theme's summary plus a page of its member claim IDs.
///
/// Returns ids only, never claim `content`: see
/// `ClaimThemeRepository::member_claim_ids` for why. Resolve the ids through
/// `get_claim`, which applies PRIVATE-visibility redaction.
pub async fn get_theme(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: GetThemeParams,
) -> Result<CallToolResult, McpError> {
    let mut read = server.read_as(viewer, "get_theme").await?;
    let resolved = resolve_theme_selector(
        &mut read,
        viewer,
        params.theme_id.as_deref(),
        params.theme_label.as_deref(),
    )
    .await?
    .ok_or_else(|| invalid_params("get_theme requires either theme_id or theme_label"))?;

    let members_limit = params
        .members_limit
        .unwrap_or(MEMBER_PAGE_DEFAULT)
        .min(MEMBER_PAGE_MAX);
    let members_offset = params.members_offset.unwrap_or(0);

    // Re-read the full summary: `resolve_theme_selector` keeps only the three
    // fields the recall path needs, and duplicating the projection there would
    // let the two diverge.
    let summary: ThemeSummaryOut =
        ClaimThemeRepository::get_summary(&mut *read, viewer, resolved.id)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| invalid_params(format!("no theme with id {}", resolved.id)))?
            .into();

    let members = if members_limit == 0 {
        Vec::new()
    } else {
        ClaimThemeRepository::member_claim_ids(
            &mut *read,
            viewer,
            resolved.id,
            i64::from(members_limit),
            i64::from(members_offset),
        )
        .await
        .map_err(internal_error)?
    };

    let members_json: Vec<serde_json::Value> = members
        .iter()
        .map(|m| {
            serde_json::json!({
                "claim_id": m.claim_id.to_string(),
                "truth_value": m.truth_value,
                "created_at": m.created_at.to_rfc3339(),
            })
        })
        .collect();

    let members_total = summary.member_count;
    let members_returned = members_json.len() as i64;
    let body = serde_json::json!({
        "theme": summary,
        "members": members_json,
        // `members_total` is the same live count reported as `member_count`,
        // so `members_offset + members_returned < members_total` terminates
        // the walk exactly.
        "members_total": members_total,
        "members_returned": members_returned,
        "members_limit": members_limit,
        "members_offset": members_offset,
        "members_has_more": i64::from(members_offset) + members_returned < members_total,
    });

    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}
