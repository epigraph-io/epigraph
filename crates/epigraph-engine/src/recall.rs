//! Library-level `recall` function.
//!
//! Lifted from `epigraph-mcp/src/tools/memory.rs` so episcience and other
//! crates can call it with `(pool, scoped, viewer, embedder, query, limit,
//! min_truth)` without spawning MCP-over-stdio.
//!
//! The MCP `recall` tool (`tools/memory.rs::recall`) does NOT delegate here: it
//! runs its own hybrid / lexical pipeline. This function has no production
//! caller in this workspace; its consumer is episcience's synthesis pipeline.
//!
//! # Fallback behaviour
//!
//! If `embedder.generate_query` fails (e.g. no API key), the function falls
//! back to an ILIKE text search over **current** claims via
//! `ClaimRepository::list_filtered`. Both legs serve current rows only: the
//! semantic leg reads `search_by_embedding_current`, and the fallback filters
//! `is_current` in SQL before `LIMIT` (supersede SPEC K11).
//!
//! # Routes (backlog a47df8ed)
//!
//! [`recall_routed`] takes a [`RecallRoute`]; [`recall`] is
//! [`RecallRoute::Similarity`], so its existing callers (episcience synthesis
//! seeding) keep the page they had before the theme leg existed. Auto and
//! Hierarchical are opt-in through [`recall_routed`]; `RecallRoute` has no
//! `Default`, so a caller that offers a route must choose its default itself.
//!
//! - **Similarity** is the System-1 leg alone: ANN over `claims.embedding`.
//! - **Hierarchical** is the System-2 leg alone: the query's nearest themes
//!   by centroid ([`ClaimThemeRepository::find_similar_themes_at_dim`]), then
//!   those themes' current members ranked by similarity
//!   ([`ClaimThemeRepository::claims_in_themes_at_dim`], viewer-scoped).
//! - **Auto** runs the ANN leg and adds the theme leg only when the ANN page
//!   is sparse ([`ann_page_is_sparse`]): fewer than
//!   [`SPARSE_MIN_HITS`] hits (capped at `limit`), or a best similarity
//!   below [`SPARSE_MAX_SIMILARITY`]. The two ranked lists are then fused by
//!   reciprocal rank ([`rrf_merge`], `k = `[`RRF_K`]) and cut to `limit`.
//!
//! A theme leg hit is a claim the ANN page did not rank this high: its theme
//! sits near the query even though the claim itself does not. Both legs read
//! on `pool` under the caller's `viewer`, so the merge cannot widen what the
//! viewer may see; theme rows carry no tenancy, and only their ids are used.
//! A failed theme leg degrades to the ANN page on Auto, and to the text
//! fallback on Hierarchical, the same way a failed ANN leg does. A query
//! vector at a dimension other than 1536 fails the 1536-d ANN read first, so
//! Auto and Similarity drop to the text fallback before the theme leg runs;
//! on Hierarchical the theme read refuses any dimension but 1536 or 3072 and
//! drops to the text fallback the same way.

use epigraph_core::ClaimId;
use epigraph_db::{ClaimListFilter, ClaimRepository, ClaimThemeRepository, PgPool, ScopedPool};
use epigraph_embeddings::EmbeddingService;
use thiserror::Error;

/// Errors from the library-level `recall` function.
///
/// Embedding failures (e.g. no API key, mock mode) trigger silent fallback to
/// text search; they are not surfaced as a `RecallError`. The only failure
/// mode this function can return is a database error from the fallback path.
#[derive(Debug, Error)]
pub enum RecallError {
    /// Database access failed (either embedding-search or text-search fallback).
    #[error("database error: {0}")]
    Db(#[from] epigraph_db::DbError),
}

/// A single result from a recall query.
#[derive(Debug, Clone)]
pub struct RecallResult {
    /// The claim's UUID, serialised as a string for JSON compatibility.
    pub claim_id: String,
    /// The claim's text content.
    pub content: String,
    /// Bayesian truth value (0.0–1.0) — the claim's independently authored
    /// scalar, reported unchanged. NOT what `min_truth` gates on; see
    /// [`RecallResult::belief_score`].
    pub truth_value: f64,
    /// The scalar `min_truth` was actually compared against (backlog
    /// `14b98adc`): the Dempster–Shafer pignistic probability when the claim
    /// carries a DS cache, and `truth_value` when it does not.
    ///
    /// `belief_score == truth_value` therefore means "this claim has no DS
    /// state, the gate fell back"; a divergence means epistemic edges have
    /// moved the claim away from its authored value.
    pub belief_score: f64,
    /// Cosine similarity to the query embedding (0.0 if text-search fallback).
    pub similarity: f64,
    /// Number of `is_current` claims contesting this one via
    /// `contradicts`/`refutes` (backlog 34d3400d). `0` when uncontested.
    pub dispute_count: u32,
    /// `true` iff `dispute_count > 0`. Surfaced alongside `truth_value`, not
    /// instead of it — contested does not mean false, it means unsettled.
    pub is_contested: bool,
    /// The three strongest contesters (by their own `truth_value`).
    pub contesting_claim_ids: Vec<uuid::Uuid>,
    /// The claim row's own `is_current`, as read on the row this result was
    /// built from (never a literal). Both legs select current rows only, so it
    /// is `true` unless the claim was retired between the semantic leg's ANN
    /// page and its `get_by_id` read; it is carried so that a consumer can
    /// check currency without a second read rather than assume it.
    pub is_current: bool,
    /// `true` iff the theme-traversal leg ranked this claim (backlog
    /// a47df8ed), alone or together with the ANN leg. Always `false` on the
    /// similarity route and on the text fallback.
    pub via_theme_traversal: bool,
}

/// Which retrieval legs a recall runs (backlog a47df8ed). See the module docs.
///
/// Deliberately no `Default`: [`recall`] pins `Similarity`, and which route a
/// caller-facing `route=` parameter defaults to is that surface's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecallRoute {
    /// ANN, plus the theme leg RRF-merged in when the ANN page is sparse.
    Auto,
    /// ANN only: the behaviour before the theme leg existed, and [`recall`]'s.
    Similarity,
    /// Theme traversal only.
    Hierarchical,
}

impl RecallRoute {
    /// The audit-row spelling, also the `route=` parameter spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Similarity => "similarity",
            Self::Hierarchical => "hierarchical",
        }
    }
}

impl std::str::FromStr for RecallRoute {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "similarity" => Ok(Self::Similarity),
            "hierarchical" => Ok(Self::Hierarchical),
            other => Err(format!(
                "unknown recall route {other:?}: expected auto, similarity or hierarchical"
            )),
        }
    }
}

/// Auto traverses themes when the ANN page has fewer hits than this (or than
/// `limit`, whichever is smaller).
pub const SPARSE_MIN_HITS: usize = 5;
/// Auto traverses themes when the ANN page's best cosine similarity is below
/// this.
pub const SPARSE_MAX_SIMILARITY: f64 = 0.4;
/// How many nearest themes the theme leg draws members from.
pub const THEME_LEG_THEMES: i32 = 3;
/// The reciprocal-rank-fusion constant, the same `k = 60` the MCP hybrid
/// recall fuses with.
pub const RRF_K: f64 = 60.0;

/// Whether an ANN page is sparse enough for Auto to add the theme leg.
///
/// The hit floor is capped at `limit`: a caller asking for 2 results who got
/// 2 has a full page, and only the similarity test can call it weak.
pub fn ann_page_is_sparse(hits: &[(uuid::Uuid, f64)], limit: usize) -> bool {
    if hits.len() < SPARSE_MIN_HITS.min(limit.max(1)) {
        return true;
    }
    let best = hits.iter().map(|h| h.1).fold(f64::NEG_INFINITY, f64::max);
    best < SPARSE_MAX_SIMILARITY
}

/// One fused candidate from [`rrf_merge`].
#[derive(Debug, Clone, PartialEq)]
pub struct MergedCandidate {
    pub claim_id: uuid::Uuid,
    /// The fused score: the sum of `1 / (RRF_K + rank)` over the legs that
    /// ranked this claim (rank 1 = best).
    pub rrf_score: f64,
    /// The claim's cosine similarity to the query. Both legs rank on the same
    /// column, so where both carry it the value is the same; the larger is kept.
    pub similarity: f64,
    pub via_ann: bool,
    pub via_theme: bool,
}

/// Reciprocal-rank fusion of the ANN and theme legs, best first, cut to
/// `limit`.
///
/// Each list must be ordered best first. A claim on both lists sums its two
/// terms, so theme membership lifts an ANN hit and a theme-only claim enters
/// at the rank its theme list gave it. Ties are broken by similarity, then by
/// claim id, so the page is deterministic.
pub fn rrf_merge(
    ann: &[(uuid::Uuid, f64)],
    theme: &[(uuid::Uuid, f64)],
    limit: usize,
) -> Vec<MergedCandidate> {
    let mut by_id: std::collections::HashMap<uuid::Uuid, MergedCandidate> =
        std::collections::HashMap::new();
    for (leg, hits) in [(false, ann), (true, theme)] {
        for (idx, (id, sim)) in hits.iter().enumerate() {
            let term = 1.0 / (RRF_K + idx as f64 + 1.0);
            let e = by_id.entry(*id).or_insert(MergedCandidate {
                claim_id: *id,
                rrf_score: 0.0,
                similarity: *sim,
                via_ann: false,
                via_theme: false,
            });
            // A list repeating an id counts it once, at its best rank.
            let seen = if leg { e.via_theme } else { e.via_ann };
            if !seen {
                e.rrf_score += term;
            }
            e.similarity = e.similarity.max(*sim);
            if leg {
                e.via_theme = true;
            } else {
                e.via_ann = true;
            }
        }
    }
    let mut merged: Vec<MergedCandidate> = by_id.into_values().collect();
    merged.sort_by(|a, b| {
        b.rrf_score
            .total_cmp(&a.rrf_score)
            .then(b.similarity.total_cmp(&a.similarity))
            .then(a.claim_id.cmp(&b.claim_id))
    });
    merged.truncate(limit);
    merged
}

/// The theme-traversal leg: the query's nearest themes, then their current
/// members visible to `viewer`, best first.
async fn theme_leg(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    pgvec: &str,
    dim: usize,
    limit: usize,
) -> Result<Vec<(uuid::Uuid, f64)>, epigraph_db::DbError> {
    let dim = u32::try_from(dim).unwrap_or(0);
    let themes =
        ClaimThemeRepository::find_similar_themes_at_dim(pool, pgvec, THEME_LEG_THEMES, dim)
            .await?;
    if themes.is_empty() {
        return Ok(Vec::new());
    }
    let theme_ids: Vec<uuid::Uuid> = themes.iter().map(|t| t.0).collect();
    let page = i32::try_from(limit).unwrap_or(i32::MAX);
    let members = ClaimThemeRepository::claims_in_themes_at_dim(
        pool, viewer, &theme_ids, pgvec, page, dim, false,
    )
    .await?;
    Ok(members.into_iter().map(|(id, _, sim)| (id, sim)).collect())
}

/// Format a `Vec<f32>` as a pgvector string literal `[a,b,c,...]`.
///
/// Mirrors the same helper in `epigraph-mcp/src/embed.rs` — kept private here
/// to avoid a cross-crate dependency on the MCP crate.
fn format_pgvector(vec: &[f32]) -> String {
    let inner: Vec<String> = vec.iter().map(|v| format!("{v}")).collect();
    format!("[{}]", inner.join(","))
}

/// Semantic recall: embed the query, find similar claims, filter by truth.
///
/// Runs [`RecallRoute::Similarity`], the ANN leg alone; use [`recall_routed`]
/// for the theme-traversal routes.
///
/// Falls back to an ILIKE text search over current claims
/// ([`text_search_fallback`]) when `embedder` returns an error (e.g.
/// embeddings disabled, no API key).
///
/// # Parameters
/// - `pool`      — live database connection pool the recall READS on
/// - `scoped`    — the caller's tenancy-aware pool, which the audit row is
///   WRITTEN through (backlog 41841f7b). Required, not optional: as the
///   application role `recall_events_tenancy` admits an audit row only on a
///   connection stamped with the principal the row names, and `pool` is not
///   stamped. See [`log_recall_event`].
/// - `viewer`    — who the recall runs as; its principal is the audit row's
///   `agent_id`. A `Bypass` viewer has no principal: its audit row is
///   agent-less and is written on `pool`, so a `Bypass` viewer MUST be paired
///   with the maintenance connection pool its lease came from. On an
///   application-role `pool` that row is refused by `recall_events_tenancy`
///   (the recall is still served; the audit row is lost with a warning).
/// - `embedder`  — embedding service; only `generate_query` is called
/// - `query`     — natural-language query string
/// - `limit`     — maximum number of results to return (clamped 1–50 by callers)
/// - `min_truth` — minimum **belief** threshold; results below are dropped.
///   Compared against [`RecallResult::belief_score`] — the DS pignistic
///   probability when the claim carries a DS cache, else `truth_value` — NOT
///   against the raw `claims.truth_value`, which no DS write path refreshes
///   (backlog `14b98adc`).
///
/// # Errors
/// Returns `RecallError::Db` if the fallback text search fails.
/// Embedding errors cause silent fallback, not a returned error.
pub async fn recall(
    pool: &PgPool,
    scoped: &ScopedPool,
    viewer: &epigraph_db::visibility::Viewer,
    embedder: &dyn EmbeddingService,
    query: &str,
    limit: usize,
    min_truth: f64,
) -> Result<Vec<RecallResult>, RecallError> {
    recall_routed(
        pool,
        scoped,
        viewer,
        embedder,
        query,
        limit,
        min_truth,
        RecallRoute::Similarity,
    )
    .await
}

/// [`recall`] with an explicit [`RecallRoute`] (backlog a47df8ed).
///
/// Same parameters, errors and fallback as [`recall`], which is this function
/// at [`RecallRoute::Similarity`].
#[allow(clippy::too_many_arguments)]
pub async fn recall_routed(
    pool: &PgPool,
    scoped: &ScopedPool,
    viewer: &epigraph_db::visibility::Viewer,
    embedder: &dyn EmbeddingService,
    query: &str,
    limit: usize,
    min_truth: f64,
    route: RecallRoute,
) -> Result<Vec<RecallResult>, RecallError> {
    let limit_i64 = limit as i64;

    // Try semantic search first.
    let mut pgvec_for_audit: Option<String> = None;
    let mut theme_leg_ran = false;
    let results = if let Ok(embedding) = embedder.generate_query(query).await {
        let pgvec = format_pgvector(&embedding);
        pgvec_for_audit = Some(pgvec.clone());
        // ANN over `claims.embedding` (is_current, all levels) — NOT
        // `evidence.embedding`, which is a permanently-empty column: searching
        // it made this semantic leg always return nothing and silently starved
        // downstream callers (episcience synthesis stage-1 seeding).
        let ann = match route {
            RecallRoute::Hierarchical => Ok(Vec::new()),
            RecallRoute::Auto | RecallRoute::Similarity => {
                ClaimRepository::search_by_embedding_current(pool, viewer, &pgvec, limit_i64)
                    .await
                    .map(|hits| {
                        hits.into_iter()
                            .map(|h| (h.claim_id, h.similarity))
                            .collect::<Vec<_>>()
                    })
            }
        };
        let candidates = match ann {
            Err(e) => {
                tracing::warn!("embedding search failed, falling back to text search: {e}");
                None
            }
            Ok(ann) => {
                let traverse = match route {
                    RecallRoute::Similarity => false,
                    RecallRoute::Hierarchical => true,
                    RecallRoute::Auto => ann_page_is_sparse(&ann, limit),
                };
                if !traverse {
                    Some(rrf_merge(&ann, &[], limit))
                } else {
                    theme_leg_ran = true;
                    match theme_leg(pool, viewer, &pgvec, embedding.len(), limit).await {
                        Ok(theme) => Some(rrf_merge(&ann, &theme, limit)),
                        // Auto still holds a valid ANN page: serve it.
                        Err(e) if route == RecallRoute::Auto => {
                            tracing::warn!(
                                error = %e,
                                "recall theme leg failed; serving the ANN page alone"
                            );
                            Some(rrf_merge(&ann, &[], limit))
                        }
                        Err(e) => {
                            tracing::warn!(
                                "recall theme leg failed, falling back to text search: {e}"
                            );
                            None
                        }
                    }
                }
            }
        };
        match candidates {
            Some(candidates) => materialize(pool, viewer, candidates, min_truth).await,
            None => text_search_fallback(pool, viewer, query, limit_i64, min_truth).await?,
        }
    } else {
        // Embedding generation failed (no API key, mock mode, etc.) — fall back
        // to the current-only text search. The theme leg needs the query
        // vector too, so no route has anything else to run.
        text_search_fallback(pool, viewer, query, limit_i64, min_truth).await?
    };

    let mut results = results;
    annotate_disputes(pool, viewer, &mut results).await;

    // Recall audit log (backlog 8cbffa0e). This is the LIBRARY path —
    // episcience synthesis calls it directly, with no MCP request — but not a
    // principal-less one: the caller's `viewer` names who the recall ran as, and
    // that principal owns the row (backlog 41841f7b). `tool` distinguishes it
    // from the MCP surfaces.
    log_recall_event(
        pool,
        scoped,
        viewer,
        query,
        pgvec_for_audit.as_deref(),
        serde_json::json!({
            "limit": limit,
            "min_truth": min_truth,
            // Recorded because the route, and whether Auto traversed, change
            // which claims a query returns: without them the row cannot be
            // replayed.
            "route": route.as_str(),
            "theme_leg": theme_leg_ran,
        }),
        &results,
    )
    .await;

    Ok(results)
}

/// Resolve a fused page into results: one batched DS-belief read, then the
/// `min_truth` gate per claim, in fused order.
async fn materialize(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    candidates: Vec<MergedCandidate>,
    min_truth: f64,
) -> Vec<RecallResult> {
    // ONE round-trip for the whole page's DS state, resolved BEFORE the loop
    // (backlog 14b98adc). Per-hit would re-introduce an N+1 on top of the
    // get_by_id this loop already does.
    let scores = effective_beliefs(
        pool,
        viewer,
        &candidates.iter().map(|h| h.claim_id).collect::<Vec<_>>(),
    )
    .await;
    let mut results = Vec::new();
    for hit in candidates {
        if let Ok(Some(claim)) =
            ClaimRepository::get_by_id(pool, viewer, ClaimId::from_uuid(hit.claim_id)).await
        {
            let tv = claim.truth_value.value();
            // Absent key == not visible to this viewer / deleted mid-page.
            // Fall back to the `truth_value` already in hand so a claim with
            // no DS state behaves exactly as it did before this change.
            let score = scores.get(&hit.claim_id).copied().unwrap_or(tv);
            if score >= min_truth {
                results.push(RecallResult {
                    claim_id: hit.claim_id.to_string(),
                    content: claim.content,
                    truth_value: tv,
                    belief_score: score,
                    similarity: hit.similarity,
                    // Annotated by the batched dispute post-pass in
                    // `recall_routed`, keyed by claim_id.
                    dispute_count: 0,
                    is_contested: false,
                    contesting_claim_ids: Vec::new(),
                    // `get_by_id` post-fixes the row's real state.
                    is_current: claim.is_current,
                    via_theme_traversal: hit.via_theme,
                });
            }
        }
    }
    results
}

/// Why an engine recall audit row was not written. Either way the recall is
/// served.
#[derive(Debug)]
enum AuditNotWritten {
    /// The principal holds no live membership of a personal group, so nothing
    /// can own the row: it is DROPPED, never widened to instance-wide.
    NoLivePersonalGroup,
    /// The owner lookup, the insert or the commit failed.
    Write(epigraph_db::DbError),
}

/// Best-effort recall audit write for the library path.
///
/// Best-effort like its MCP siblings: a failed audit write warns and leaves the
/// already-computed results untouched. Awaited rather than spawned: the
/// library's callers are background jobs, not a request path.
///
/// # Where the row is written (backlog 41841f7b)
///
/// `recall_events_tenancy` (migration 077) admits a non-bypass insert only when
/// `epigraph_principal_id() IS NOT NULL AND agent_id = epigraph_principal_id()`.
/// This function used to write `agent_id = NULL` on the caller's unstamped
/// `pool`, which that check refuses STRUCTURALLY for `epigraph_app`: the
/// episcience worker logged `new row violates row-level security policy for
/// table "recall_events"` on every synthesis and the audit trail was empty.
///
/// For a viewer with a principal the row is now `(agent_id = principal,
/// ('group', <principal's personal group>))`, resolved and inserted on ONE
/// transaction of `scoped` stamped from that principal's own scoped viewer, so
/// the policy is satisfied by construction. This mirrors the MCP surfaces'
/// `tools/recall.rs::write_recall_audit`. `Viewer::detach_scoped` drops an
/// elevation (an elevated viewer may not open a write transaction); the
/// personal group must be in the viewer's live group set, as the MCP twin
/// checks, so a revoked principal's row is dropped rather than owned by the
/// group it lost.
///
/// A `Bypass` viewer has no principal: its row stays agent-less and
/// instance-wide, written on `pool`. That is the only agent-less row this path
/// writes, and it is admitted only through the bypass arm, so it lands only
/// when the caller honours [`recall`]'s contract and passes the maintenance
/// pool with a `Bypass` viewer. It is not routed through `scoped` instead:
/// `ScopedPool::begin_as` refuses a `Bypass` viewer, and minting a maintenance
/// lease inside this library would grant a bypass the caller never asked for.
#[allow(clippy::too_many_arguments)]
async fn log_recall_event(
    pool: &PgPool,
    scoped: &ScopedPool,
    viewer: &epigraph_db::visibility::Viewer,
    query: &str,
    pgvec: Option<&str>,
    params: serde_json::Value,
    results: &[RecallResult],
) {
    let returned_claim_ids: Vec<uuid::Uuid> = results
        .iter()
        .filter_map(|r| uuid::Uuid::parse_str(&r.claim_id).ok())
        .collect();
    let event = |agent_id: Option<uuid::Uuid>, owner_group_id: Option<uuid::Uuid>| {
        epigraph_db::NewRecallEvent {
            id: uuid::Uuid::new_v4(),
            agent_id,
            tool: "engine::recall".to_string(),
            query_text: query.to_string(),
            query_pgvector: pgvec.map(ToString::to_string),
            params: params.clone(),
            returned_claim_ids,
            owner_group_id,
        }
    };
    let written = match viewer.detach_scoped() {
        Some(own) => {
            write_as_principal(scoped, &own, |principal, group| {
                event(Some(principal), Some(group))
            })
            .await
        }
        None => epigraph_db::RecallEventRepository::log(pool, event(None, None))
            .await
            .map(|_| ())
            .map_err(AuditNotWritten::Write),
    };
    match written {
        Ok(()) => {}
        Err(AuditNotWritten::NoLivePersonalGroup) => tracing::warn!(
            "engine recall audit skipped rather than widened: the principal holds no live \
             personal group; recall unaffected"
        ),
        Err(AuditNotWritten::Write(e)) => {
            tracing::warn!(error = %e, "engine recall audit log failed; recall unaffected");
        }
    }
}

/// Resolve `own`'s personal group and insert the audit row on ONE transaction
/// of `scoped` stamped from `own`, then commit. See [`log_recall_event`].
async fn write_as_principal(
    scoped: &ScopedPool,
    own: &epigraph_db::visibility::Viewer,
    build: impl FnOnce(uuid::Uuid, uuid::Uuid) -> epigraph_db::NewRecallEvent,
) -> Result<(), AuditNotWritten> {
    let Some(principal) = own.principal() else {
        // `detach_scoped` only returns principal-bearing viewers.
        return Err(AuditNotWritten::NoLivePersonalGroup);
    };
    let mut tx = scoped.begin_as(own).await.map_err(AuditNotWritten::Write)?;
    let group =
        epigraph_db::GroupMembershipRepository::visible_personal_group_conn(&mut tx, principal)
            .await
            .map_err(AuditNotWritten::Write)?;
    let group = match group {
        Some(g) if own.group_bind().is_some_and(|live| live.contains(&g)) => g,
        _ => return Err(AuditNotWritten::NoLivePersonalGroup),
    };
    epigraph_db::RecallEventRepository::log(&mut *tx, build(principal, group))
        .await
        .map_err(AuditNotWritten::Write)?;
    tx.commit().await.map_err(AuditNotWritten::Write)
}

/// Batched dispute annotation (backlog 34d3400d), shared by the semantic and
/// text-fallback paths so the two cannot drift.
///
/// Best-effort by design: a dispute-lookup failure warns and serves the page
/// unannotated rather than failing a recall that already has its results. The
/// signal informs the caller; it never re-ranks and never gates retrieval.
async fn annotate_disputes(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    results: &mut [RecallResult],
) {
    let claim_ids: Vec<uuid::Uuid> = results
        .iter()
        .filter_map(|r| uuid::Uuid::parse_str(&r.claim_id).ok())
        .collect();
    match ClaimRepository::dispute_batch(pool, viewer, &claim_ids).await {
        Ok(mut by_claim) => {
            for r in results.iter_mut() {
                let Ok(cid) = uuid::Uuid::parse_str(&r.claim_id) else {
                    continue;
                };
                // Absent key == uncontested, per the repo contract.
                if let Some(d) = by_claim.remove(&cid) {
                    r.dispute_count = d.dispute_count.max(0) as u32;
                    r.is_contested = d.dispute_count > 0;
                    r.contesting_claim_ids = d.contesting_claim_ids;
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "dispute batch failed; serving recall page without dispute annotations"
            );
        }
    }
}

/// Batched DS-belief lookup for a page of claim ids (backlog `14b98adc`).
///
/// Best-effort by design, and it degrades the SAME way an absent key does: a
/// failed lookup warns and yields an empty map, so every caller falls back to
/// the `truth_value` it already holds and the gate behaves exactly as it did
/// before this change. Failing the recall instead would trade a stale filter
/// for no results at all.
async fn effective_beliefs(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_ids: &[uuid::Uuid],
) -> std::collections::HashMap<uuid::Uuid, f64> {
    match ClaimRepository::effective_belief_batch(pool, viewer, claim_ids).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "DS belief batch failed; min_truth falls back to claims.truth_value for this page"
            );
            std::collections::HashMap::new()
        }
    }
}

/// Text-search fallback: `content ILIKE '%query%'` over **current** claims,
/// newest first.
///
/// The currency predicate is `ClaimListFilter::is_current`, which
/// `ClaimRepository::list_filtered` applies in SQL before `LIMIT`. It must not
/// move after the fetch: the page is ordered by `created_at`, so a retired
/// revision is usually NEWER than the current match it competes with, and a
/// filter over the already-cut page would drop it and leave the page short or
/// empty instead of serving the current match (supersede SPEC K11).
/// `ClaimRepository::list`, which this used to call, has no currency
/// predicate at all.
async fn text_search_fallback(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    query: &str,
    limit: i64,
    min_truth: f64,
) -> Result<Vec<RecallResult>, RecallError> {
    let filter = ClaimListFilter {
        search: Some(query),
        is_current: Some(true),
        ..ClaimListFilter::default()
    };
    let claims = ClaimRepository::list_filtered(pool, viewer, &filter, limit, 0).await?;
    // Same one-round-trip DS resolution the semantic leg does, so the two legs
    // cannot gate on different columns (backlog 14b98adc).
    let scores = effective_beliefs(
        pool,
        viewer,
        &claims.iter().map(|c| c.id.as_uuid()).collect::<Vec<_>>(),
    )
    .await;
    Ok(claims
        .into_iter()
        .filter_map(|c| {
            let tv = c.truth_value.value();
            let score = scores.get(&c.id.as_uuid()).copied().unwrap_or(tv);
            (score >= min_truth).then_some((c, tv, score))
        })
        .map(|(c, tv, score)| RecallResult {
            claim_id: c.id.as_uuid().to_string(),
            content: c.content,
            truth_value: tv,
            belief_score: score,
            similarity: 0.0,
            // Annotated by `annotate_disputes` once the caller has the page —
            // the fallback path returns into `recall`, which runs the pass.
            dispute_count: 0,
            is_contested: false,
            contesting_claim_ids: Vec::new(),
            is_current: c.is_current,
            via_theme_traversal: false,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_embeddings::{config::EmbeddingConfig, providers::MockProvider};

    // NOTE on deferred behavioral tests:
    //
    // Plan Task 0.4 specified `#[sqlx::test]`-based behavioral assertions
    // (e.g. `recall_returns_results_above_min_truth`) seeded via a helper
    // `epigraph_test_helpers::ingest_claim_via_api`. That helper does not
    // exist yet — `feedback_no_raw_sql` rules out direct INSERTs, and the
    // public `POST /claims` route requires a running API server and a valid
    // service token, neither of which is in scope for Task 0.4.
    //
    // Phase 1 introduces episcience's API client (`EpigraphEdgesClient` and
    // friends) plus a test fixture that spins up the API server with seeded
    // service credentials. The full behavioral suite for `recall` lands in
    // `crates/epigraph-engine/tests/recall_test.rs` at that point.
    //
    // Until then, the tests below cover the trait-bound and wiring layer
    // only. They will not catch a regression where, e.g., the `min_truth`
    // filter is applied at the wrong place — that gap closes in Phase 1.

    fn id(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    /// A theme-only claim enters at the rank its theme list gave it, and a
    /// claim on both lists sums its two terms (backlog a47df8ed).
    #[test]
    fn rrf_merge_sums_shared_ids_and_admits_theme_only_hits() {
        let ann = [(id(1), 0.35), (id(2), 0.33), (id(3), 0.30)];
        let theme = [(id(3), 0.30), (id(9), 0.20)];
        let got = rrf_merge(&ann, &theme, 3);
        let order: Vec<_> = got.iter().map(|m| m.claim_id).collect();
        // id3 sums 1/63 + 1/61 and beats id1's lone 1/61. id9 (theme rank 2,
        // 1/62) ties id2 (ANN rank 2, 1/62) and loses the tie on similarity
        // (0.20 < 0.33), so id2 keeps the third slot.
        assert_eq!(order, vec![id(3), id(1), id(2)]);
        let shared = &got[0];
        assert!(shared.via_ann && shared.via_theme);
        assert!((shared.rrf_score - (1.0 / 63.0 + 1.0 / 61.0)).abs() < 1e-12);
        let page4 = rrf_merge(&ann, &theme, 4);
        let tail = page4.last().unwrap();
        assert_eq!(tail.claim_id, id(9));
        assert!(tail.via_theme && !tail.via_ann);
        assert!((tail.similarity - 0.20).abs() < 1e-12);
    }

    /// With no theme leg the fused order IS the ANN order, so the similarity
    /// route serves exactly the page it served before the merge existed.
    #[test]
    fn rrf_merge_of_ann_alone_preserves_ann_order() {
        let ann = [(id(5), 0.9), (id(2), 0.8), (id(7), 0.7)];
        let got = rrf_merge(&ann, &[], 10);
        let order: Vec<_> = got.iter().map(|m| m.claim_id).collect();
        assert_eq!(order, vec![id(5), id(2), id(7)]);
        assert!(got.iter().all(|m| m.via_ann && !m.via_theme));
    }

    /// A list repeating an id counts it once, at its best rank: a duplicated
    /// row must not double its own score past a genuinely shared one.
    #[test]
    fn rrf_merge_counts_a_repeated_id_once_per_leg() {
        let ann = [(id(1), 0.5), (id(1), 0.5), (id(2), 0.4)];
        let got = rrf_merge(&ann, &[], 10);
        assert_eq!(got.len(), 2);
        assert!((got[0].rrf_score - 1.0 / 61.0).abs() < 1e-12);
    }

    #[test]
    fn sparse_when_short_or_weak_but_not_when_full_and_strong() {
        let strong: Vec<_> = (0..5).map(|n| (id(n), 0.8)).collect();
        assert!(!ann_page_is_sparse(&strong, 10), "5 strong hits is dense");
        assert!(ann_page_is_sparse(&strong[..4], 10), "4 < 5 hits is sparse");
        assert!(
            !ann_page_is_sparse(&strong[..2], 2),
            "a full page of 2 for limit 2 is not short"
        );
        let weak: Vec<_> = (0..5).map(|n| (id(n), 0.39)).collect();
        assert!(ann_page_is_sparse(&weak, 10), "best 0.39 < 0.4 is weak");
        assert!(ann_page_is_sparse(&[], 10));
    }

    #[test]
    fn route_parses_its_own_spelling_and_refuses_others() {
        for r in [
            RecallRoute::Auto,
            RecallRoute::Similarity,
            RecallRoute::Hierarchical,
        ] {
            assert_eq!(r.as_str().parse::<RecallRoute>(), Ok(r));
        }
        assert!("ann".parse::<RecallRoute>().is_err());
    }

    /// Confirm `MockProvider` satisfies the `EmbeddingService` bound required by
    /// `recall`. This is a compile-time wiring test; it panics with a DB error
    /// rather than a trait error if the trait bound is wrong.
    #[test]
    fn mock_provider_satisfies_embedding_service_bound() {
        // Confirm the type implements the trait at compile time.
        fn assert_embedding_service<T: EmbeddingService>(_: &T) {}
        let config = EmbeddingConfig::local(64);
        let provider = MockProvider::new(config);
        assert_embedding_service(&provider);
    }

    /// Confirm that `format_pgvector` produces a pgvector-compatible string.
    #[test]
    fn format_pgvector_roundtrip() {
        let vec = vec![0.1f32, 0.2, 0.3];
        let s = format_pgvector(&vec);
        assert!(s.starts_with('['), "should start with [");
        assert!(s.ends_with(']'), "should end with ]");
        // Three floats → two commas
        assert_eq!(s.matches(',').count(), 2);
    }

    /// Confirm `recall` is callable with a `&dyn EmbeddingService` by checking
    /// that `MockProvider` can be coerced to the trait object type.
    ///
    /// Integration tests against a real DB are deferred until episcience adds
    /// API-based seeding helpers in Phase 1+.
    #[test]
    fn recall_accepts_dyn_embedding_service() {
        // Just confirm the coercion compiles; no async runtime needed.
        let config = EmbeddingConfig::local(64);
        let provider = MockProvider::new(config);
        let _: &dyn EmbeddingService = &provider;
        // If this compiles, recall(&pool, &scoped, &viewer, &provider, ...) will also compile.
    }
}
