//! Theme k-means MCP tool. Wraps
//! [`epigraph_engine::theme_kmeans::run_theme_kmeans`] so MCP clients (e.g.
//! EpiClaw) can trigger server-side theme clustering instead of falling back
//! to manual sampling. Mirrors the HTTP route
//! `POST /api/v1/themes/build-from-corpus` (`build_themes_from_corpus` in
//! `epigraph-api/src/routes/crud.rs`) with the same defaults.
//!
//! ## Safety
//! - `limit` is capped at 500 (per `feedback_memory_limits.md`: VM OOMs at
//!   ~2000 embeddings).
//! - `wipe_first` defaults to `true`. Rationale: the `claim_themes` table
//!   currently has no `UNIQUE(label)` constraint and `ClaimThemeRepository::create`
//!   has no `ON CONFLICT` clause, so the additive path (`wipe_first=false`)
//!   silently accumulates duplicate `auto-00`, `auto-01`, ... rows on every
//!   call. Because this MCP tool is invoked by automated scheduled tasks, the
//!   safe-by-default behaviour is a clean rebuild on each call. Callers that
//!   genuinely want additive runs (e.g. with a unique `label_prefix` per call)
//!   can pass `wipe_first=false` and will receive a warning in the response
//!   when new themes are created. See backlog: missing UNIQUE constraint on
//!   `claim_themes.label`.

#![allow(clippy::wildcard_imports)]

use rmcp::model::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;

use epigraph_db::{ClaimThemeRepository, ThemeSummaryRow};
use epigraph_engine::theme_kmeans::{run_theme_kmeans, RunThemeKmeansConfig, ThemeKmeansError};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ThemeClusterParams {
    /// Explicit k. When omitted, runs elbow-penalised search over `k_min..=k_max`.
    pub k: Option<u32>,
    /// Lower bound for k search (inclusive). Default 4.
    pub k_min: Option<u32>,
    /// Upper bound for k search (inclusive). Default 16.
    pub k_max: Option<u32>,
    /// Drop clusters with fewer than this many claims. Default 5.
    pub min_claims_per_theme: Option<u32>,
    /// Cap on number of `claims` rows pulled. Default 500; capped at 500
    /// regardless of input to defend against VM OOM at ~2000 embeddings.
    pub limit: Option<u32>,
    /// Theme label prefix. Default `"auto"` (produces `auto-00`, `auto-01`, …).
    pub label_prefix: Option<String>,
    /// Embedding dimensionality. Must be 1536 or 3072. Default 1536.
    pub centroid_dim: Option<u32>,
    /// Whether to wipe existing themes with this `label_prefix` before
    /// clustering. **Default `true`** — see module docstring. Pass `false`
    /// only for additive runs with a unique `label_prefix`; otherwise
    /// duplicate themes accumulate (no UNIQUE constraint on
    /// `claim_themes.label`).
    pub wipe_first: Option<bool>,
}

const MCP_LIMIT_CAP: u32 = 500;

pub async fn theme_cluster(
    server: &EpiGraphMcpFull,
    params: ThemeClusterParams,
) -> Result<CallToolResult, McpError> {
    let wipe_first = params.wipe_first.unwrap_or(true);

    let config = RunThemeKmeansConfig {
        k: params.k,
        k_min: params.k_min.unwrap_or(4),
        k_max: params.k_max.unwrap_or(16),
        min_claims_per_theme: params.min_claims_per_theme.unwrap_or(5),
        limit: params.limit.unwrap_or(500).clamp(1, MCP_LIMIT_CAP),
        label_prefix: params.label_prefix.unwrap_or_else(|| "auto".to_string()),
        wipe_first,
        centroid_dim: params.centroid_dim.unwrap_or(1536),
    };

    let summary = run_theme_kmeans(&server.pool, &config)
        .await
        .map_err(|e| match e {
            ThemeKmeansError::BadRequest(msg) => crate::errors::invalid_params(msg),
            ThemeKmeansError::Centroid3072Empty => crate::errors::invalid_params(e.to_string()),
            other => internal_error(other),
        })?;

    // Mirror the HTTP handler's JSON shape so EpiClaw and the route share a
    // single observable contract.
    let mut body = if let Some(k_used) = summary.k_used {
        serde_json::json!({
            "themes_created": summary.themes_created,
            "claims_assigned": summary.claims_assigned,
            "k_used": k_used,
            "claims_with_embeddings": summary.claims_with_embeddings,
            "centroid_dim": summary.centroid_dim,
        })
    } else {
        serde_json::json!({
            "themes_created": summary.themes_created,
            "claims_assigned": summary.claims_assigned,
            "k_used": serde_json::Value::Null,
            "claims_with_embeddings": summary.claims_with_embeddings,
            "centroid_dim": summary.centroid_dim,
            "skipped_reason": summary.skipped_reason.unwrap_or_default(),
        })
    };

    // Warn callers that opted out of `wipe_first`: with no DB-level UNIQUE
    // constraint on `claim_themes.label`, repeated calls with the same
    // `label_prefix` proliferate duplicate rows.
    if !wipe_first && summary.themes_created > 0 {
        body["warning"] = serde_json::json!(
            "wipe_first=false: created themes are additive. Repeated calls with the same label_prefix will produce duplicate rows. See claim_themes UNIQUE constraint backlog."
        );
    }

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}

// ─────────────────────────────────────────────────────────────────────────
// READ SIDE — `list_themes` / `get_theme`
//
// Backlog c40689c9 / ac4d02b9: before these, `theme_cluster` above was the
// ONLY theme tool, so the only way to learn what the current themes contain
// was to rebuild (and by default wipe) them. Both tools here are pure reads:
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

/// Default / maximum page sizes for the theme reader. The cap exists for the
/// same reason `MCP_LIMIT_CAP` above does — bounding what one tool call can
/// pull into a response body — but is unrelated to the OOM-at-~2000-embeddings
/// concern, since no vectors are returned here.
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
    /// Live `COUNT(*)` of `is_current` claims assigned to this theme. This is
    /// the authoritative figure.
    pub member_count: i64,
    /// The denormalised `claim_themes.claim_count` column. Reported ONLY so
    /// drift is visible: the assignment writers (`assign_claim`,
    /// `bulk_assign`, `unassign_claim`) never update it, so it is stale
    /// whenever anything other than a full k-means run touched membership.
    /// Do not rank or budget on it.
    pub stored_claim_count: i32,
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
            stored_claim_count: r.stored_claim_count,
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
///   candidate ids. `claim_themes` has no `UNIQUE(label)` constraint and
///   `theme_cluster(wipe_first=false)` actively produces duplicate `auto-00`
///   rows, so picking the first match would silently scope to one of several
///   distinct themes.
pub async fn resolve_theme_selector(
    pool: &PgPool,
    theme_id: Option<&str>,
    theme_label: Option<&str>,
) -> Result<Option<ResolvedTheme>, McpError> {
    let id_raw = theme_id.map(str::trim).filter(|s| !s.is_empty());
    let label_raw = theme_label.map(str::trim).filter(|s| !s.is_empty());

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
                let matches = ClaimThemeRepository::find_by_label(pool, label)
                    .await
                    .map_err(internal_error)?;
                match matches.len() {
                    0 => {
                        return Err(invalid_params(format!(
                        "no theme has label {label:?}. Call list_themes to see the current themes; \
                         an unmatched label is rejected rather than treated as \"no filter\", \
                         which would widen the query to the whole corpus."
                    )))
                    }
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

    let summary = ClaimThemeRepository::get_summary(pool, resolved_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("no theme with id {resolved_id}")))?;

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
    params: ListThemesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params
        .limit
        .unwrap_or(THEME_PAGE_DEFAULT)
        .clamp(1, THEME_PAGE_MAX);
    let offset = params.offset.unwrap_or(0);
    let prefix = params.label_prefix.as_deref();

    let rows = ClaimThemeRepository::list_summaries(
        &server.pool,
        prefix,
        i64::from(limit),
        i64::from(offset),
    )
    .await
    .map_err(internal_error)?;

    let total = ClaimThemeRepository::count_summaries(&server.pool, prefix)
        .await
        .map_err(internal_error)?;

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

    Ok(CallToolResult::success(vec![Content::text(
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
    params: GetThemeParams,
) -> Result<CallToolResult, McpError> {
    let resolved = resolve_theme_selector(
        &server.pool,
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
    let summary: ThemeSummaryOut = ClaimThemeRepository::get_summary(&server.pool, resolved.id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("no theme with id {}", resolved.id)))?
        .into();

    let members = if members_limit == 0 {
        Vec::new()
    } else {
        ClaimThemeRepository::member_claim_ids(
            &server.pool,
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

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}
