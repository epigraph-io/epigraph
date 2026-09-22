//! Shared theme k-means helper.
//!
//! Powers both `POST /api/v1/themes/build-from-corpus` (the HTTP handler in
//! `epigraph-api`) and the scheduled `theme_cluster_rebuild` job (in
//! `epigraph-jobs`).  The body of this module was originally inline in
//! `crates/epigraph-api/src/routes/crud.rs::build_themes_from_corpus`; it is
//! lifted here verbatim so the cron job and the route share one
//! implementation and identical observable behaviour.
//!
//! ## What it does
//! 1. Validate `centroid_dim ∈ {1536, 3072}`, `k_min`, `k_max`.
//! 2. Optionally wipe `claim_themes` (`wipe_first`).
//! 3. Pull `(claim_id, embedding)` rows from `claims.embedding` (1536d) or
//!    `claims.embedding_3072` (3072d).
//! 4. Reject if 3072d was requested but no rows are populated (operator
//!    forgot to run `epigraph-cli reembed --target claims`).
//! 5. Build a dense `ndarray::Array2<f64>`, run linfa k-means with
//!    elbow-penalised k search.
//! 6. Per cluster ≥ `min_claims_per_theme`: create a theme, write the
//!    centroid (1536 → repo `set_centroid`, 3072 → direct UPDATE on
//!    `claim_themes.centroid_3072`), bulk-assign claims, update count.
//! 7. Return [`RunThemeKmeansSummary`].
//!
//! ## Skip path
//! When fewer than `k_min` claims have embeddings, returns a summary with
//! `themes_created = 0`, `claims_assigned = 0`, `k_used = None`,
//! `skipped_reason = Some(...)`.  The `centroid_dim` field on the skip
//! path mirrors the *requested* config dim (we have no measured rows to
//! inspect).  The HTTP handler relies on this distinction to keep its JSON
//! response byte-identical pre/post refactor.

use linfa::prelude::*;
use linfa_clustering::KMeans;
use ndarray::Array2;
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_db::{ClaimThemeRepository, DbError};

/// Configuration for [`run_theme_kmeans`].
///
/// Mirrors `BuildThemesFromCorpusRequest` from the HTTP handler with
/// defaults already applied.  Callers (the route handler, the scheduled
/// job) are responsible for unwrapping `Option`s.
#[derive(Debug, Clone)]
pub struct RunThemeKmeansConfig {
    /// Explicit k. When `None`, runs elbow-penalized search over
    /// `k_min..=k_max`.
    pub k: Option<u32>,
    /// Lower bound for k search (inclusive).  Must be ≥ 1.
    pub k_min: u32,
    /// Upper bound for k search (inclusive).  Must be ≥ `k_min`.
    pub k_max: u32,
    /// Drop clusters with fewer than this many claims.
    pub min_claims_per_theme: u32,
    /// Cap on number of `claims` rows pulled (defends OOM on large corpora).
    pub limit: u32,
    /// Theme label prefix; e.g. `"auto"` produces `auto-00`, `auto-01`, …
    pub label_prefix: String,
    /// When `true`, drops all existing themes first (`ClaimThemeRepository::delete_all`).
    pub wipe_first: bool,
    /// Embedding dimensionality.  Must be `1536` or `3072`.
    /// 1536 reads `claims.embedding`; 3072 reads `claims.embedding_3072`.
    pub centroid_dim: u32,
}

/// Outcome of a k-means rebuild run.
#[derive(Debug, Clone)]
pub struct RunThemeKmeansSummary {
    /// Number of themes that were created.
    pub themes_created: usize,
    /// Total claims assigned across all created themes.
    pub claims_assigned: usize,
    /// Chosen `k`.  `None` when the run was skipped (insufficient claims).
    pub k_used: Option<u32>,
    /// Number of claims with embeddings observed in the corpus.
    pub claims_with_embeddings: usize,
    /// Embedding dimension.  On the success path this is the *measured*
    /// dim from `rows[0].1.len()`; on the skip path this is the
    /// *requested* dim from `config.centroid_dim` (since no rows were
    /// observed).  Callers wanting to forward the legacy JSON shape should
    /// use this value as-is.
    pub centroid_dim: u32,
    /// Human-readable reason, populated only on the skip path.
    pub skipped_reason: Option<String>,
}

/// Errors produced by [`run_theme_kmeans`].
#[derive(Debug, thiserror::Error)]
pub enum ThemeKmeansError {
    /// Caller-supplied configuration is invalid (e.g. bad k bounds, bad
    /// centroid_dim, or 3072d requested with empty `embedding_3072`).  The
    /// HTTP handler maps this to `ApiError::BadRequest`.
    #[error("{0}")]
    BadRequest(String),

    /// A raw `sqlx` query failed (the row-fetch + the 3072d `UPDATE` go
    /// through `sqlx::query` rather than the typed repo).
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// A `ClaimThemeRepository` call failed.
    #[error("repository error: {0}")]
    Repo(#[from] DbError),

    /// linfa returned a fit error.
    #[error("k-means fit failed: {0}")]
    KMeansFit(String),

    /// One row's embedding had a different dimension than the first row.
    /// Indicates corrupt data; should never happen in normal operation.
    #[error("embedding dim mismatch at claim {claim_id}: got {got}, expected {expected}")]
    EmbeddingDimMismatch {
        claim_id: Uuid,
        got: usize,
        expected: usize,
    },

    /// `centroid_dim = 3072` was requested but no rows have
    /// `embedding_3072` populated; the operator must run
    /// `epigraph-cli reembed --target claims` first.
    #[error("centroid_dim=3072 requires populated claims.embedding_3072; run `epigraph-cli reembed --target claims` first")]
    Centroid3072Empty,
}

/// Run a full theme rebuild via k-means.
///
/// See module docs for what this does.  Both the HTTP handler and the
/// scheduled cron job call this with their own `config`.
///
/// # Tenancy: NOT viewer-scoped, and the residual is PERSISTED (PR-09)
///
/// This function takes no [`Viewer`](epigraph_db::visibility::Viewer) and runs
/// `SELECT id, embedding … FROM claims` corpus-wide. Plan §2.4 registers
/// `claim_themes` as `tenancy_exempt` and names viewer-scoped clustering — i.e.
/// threading a viewer through here — as its compensating control. **PR-09 did
/// not deliver it.** Every place that cites the control now says so instead of
/// asserting it (`epigraph-mcp/src/tools/recall.rs::compute_corpus_scope`'s
/// `VISIBILITY-EXEMPT` annotation, `tests/tool_viewer_coverage.rs`), and it is
/// ledgered as `D-PR16-theme-cluster-viewer-scope`.
///
/// **Read the residual as a persisted one, not as an unfiltered read.** This
/// function does not merely return corpus-wide rows to its caller; it
/// materialises content-derived data from them into two tables that other,
/// unrelated reads then serve:
///
/// * the cluster centroid — a mean of the member embeddings — into
///   `claim_themes.centroid` / `.centroid_3072`, and
/// * the membership list, via `ClaimThemeRepository::bulk_assign`, into
///   `claim_theme_members`.
///
/// Neither table is in migration 062's `tier_a`, so neither can carry a
/// predicate. `epigraph-api/tests/viewer_route_table_lint.rs` treats
/// `claims.embedding` as approximately invertible to content, which is why the
/// centroid counts as content-derived rather than as a statistic.
///
/// The consequence for sequencing: once PR-12's backfill writes the first
/// `visibility = 'group'` row, the *scheduled rebuild job* — not an interactive
/// `theme_cluster` call — is what creates the leak, and it persists in the
/// database rather than being confined to one response. The job must be gated,
/// or `claim_themes` / `claim_theme_members` given tenancy columns, **before**
/// that backfill runs.
///
/// # PR-12's interim gate: `AND visibility = 'public'` on the corpus read
///
/// **PR-12 is the PR that first gives this pre-existing leak something to
/// leak.** Before it, `ownership` writes landed in a table no read path
/// consulted, so the corpus was uniformly public and this function's input
/// contained no private content — the leak was real but empty. Migration 071
/// changes that on its first firing: every `ownership` write now transcribes
/// into `claims.owner_group_id / visibility`, and 070 propagates it. So
/// "PR-12 does not increase the exposure" is **false**, and the exposure it
/// creates is not hypothetical: a centroid is a mean of its members'
/// embeddings, and `viewer_route_table_lint.rs` already treats
/// `claims.embedding` as approximately invertible to content. A
/// nearest-neighbour probe against a published centroid is an information
/// channel about the private text that fed it.
///
/// The holding change is therefore made **here**, in the one place both the
/// MCP tool, the HTTP handler and the scheduled `epigraph-jobs` rebuild share:
/// the corpus read is restricted to `visibility = 'public'`. That is
/// fail-closed, it lands all three callers together by construction (so it
/// cannot cause the MCP/HTTP parity break plan §8.4 #16 exists to catch), and
/// it needs no `Viewer` — which matters because the scheduled rebuild has no
/// principal to supply one from and is the caller a signature change could not
/// have reached anyway.
///
/// What it costs: themes are computed over public claims only, so a
/// group-private claim is not clustered. That is the correct default for an
/// untenanted output table, and it is strictly better than the alternative of
/// clustering private content into a world-readable centroid.
///
/// **This is a holding change, not the control.** The real fix — a `Viewer`
/// threaded through, or tenancy columns on `claim_themes` /
/// `claim_theme_members` — remains `D-PR16-theme-cluster-viewer-scope`, and the
/// two-callers-together constraint still binds whoever lands it.
pub async fn run_theme_kmeans(
    pool: &PgPool,
    config: &RunThemeKmeansConfig,
) -> Result<RunThemeKmeansSummary, ThemeKmeansError> {
    if !matches!(config.centroid_dim, 1536 | 3072) {
        return Err(ThemeKmeansError::BadRequest(format!(
            "centroid_dim must be 1536 or 3072 (got {})",
            config.centroid_dim
        )));
    }

    if config.k_min == 0 || config.k_max < config.k_min {
        return Err(ThemeKmeansError::BadRequest(
            "k_min must be ≥1 and k_max ≥ k_min".to_string(),
        ));
    }

    let limit = config.limit.max(1);

    if config.wipe_first {
        ClaimThemeRepository::delete_all(pool).await?;
    }

    // 1. Pull claims with embeddings. Branch on centroid_dim: 1536 reads
    //    `claims.embedding`; 3072 reads `claims.embedding_3072`.
    let source_col = if config.centroid_dim == 3072 {
        "embedding_3072"
    } else {
        "embedding"
    };
    // `AND visibility = 'public'` IS THE PR-12 INTERIM GATE — see the
    // "Tenancy" section of this function's doc comment. It is fail-closed, it
    // costs nothing while the corpus is still overwhelmingly public, and it
    // does NOT require threading a `Viewer` (which the scheduled rebuild job
    // has no principal to supply).
    let select_sql = format!(
        "SELECT id, {source_col}::real[] \
         FROM claims \
         WHERE {source_col} IS NOT NULL \
           AND visibility = 'public' \
         ORDER BY id \
         LIMIT $1"
    );
    let rows: Vec<(Uuid, Vec<f32>)> = sqlx::query_as(&select_sql)
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await?;

    // Reject when 3072d was requested but no claims have it populated.
    if config.centroid_dim == 3072 && rows.is_empty() {
        return Err(ThemeKmeansError::Centroid3072Empty);
    }

    let n_claims = rows.len();
    if n_claims < config.k_min as usize {
        return Ok(RunThemeKmeansSummary {
            themes_created: 0,
            claims_assigned: 0,
            k_used: None,
            claims_with_embeddings: n_claims,
            // Skip path: forward the *requested* dim (no rows to measure).
            centroid_dim: config.centroid_dim,
            skipped_reason: Some(format!(
                "only {} claims with embeddings (need ≥ k_min={})",
                n_claims, config.k_min
            )),
        });
    }

    // 2. Build the dense matrix.
    let dim = rows[0].1.len();
    let mut data = Array2::<f64>::zeros((n_claims, dim));
    for (i, (claim_id, emb)) in rows.iter().enumerate() {
        if emb.len() != dim {
            return Err(ThemeKmeansError::EmbeddingDimMismatch {
                claim_id: *claim_id,
                got: emb.len(),
                expected: dim,
            });
        }
        for (j, &v) in emb.iter().enumerate() {
            data[[i, j]] = f64::from(v);
        }
    }
    let dataset = linfa::DatasetBase::from(data.view());

    // 3. Pick k. Either explicit or elbow-penalized search.
    let actual_k_max = (config.k_max as usize).min(n_claims);
    let k_min_usize = config.k_min as usize;
    let chosen_k = if let Some(k) = config.k {
        let k = k as usize;
        if k == 0 || k > n_claims {
            return Err(ThemeKmeansError::BadRequest(format!(
                "k must be in 1..={n_claims}"
            )));
        }
        k
    } else {
        let mut best_k = k_min_usize;
        let mut best_score = f64::NEG_INFINITY;
        for k in k_min_usize..=actual_k_max {
            let model = KMeans::params(k)
                .max_n_iterations(100)
                .tolerance(1e-4)
                .fit(&dataset)
                .map_err(|e| {
                    ThemeKmeansError::KMeansFit(format!("k-means fit failed at k={k}: {e}"))
                })?;
            let labels: Vec<usize> = model.predict(&dataset).iter().copied().collect();
            let centroids = model.centroids();
            let mut total_dist = 0.0;
            for (i, label) in labels.iter().enumerate() {
                let centroid = centroids.row(*label);
                let point = data.row(i);
                let dist: f64 = point
                    .iter()
                    .zip(centroid.iter())
                    .map(|(a, b)| (a - b).powi(2))
                    .sum();
                total_dist += dist;
            }
            let inertia = -total_dist / n_claims as f64;
            // Elbow penalty: discourage runaway k.
            let penalized = inertia * (1.0 - 0.05 * k as f64);
            if penalized > best_score {
                best_score = penalized;
                best_k = k;
            }
        }
        best_k
    };

    // 4. Final fit at chosen_k.
    let model = KMeans::params(chosen_k)
        .max_n_iterations(200)
        .tolerance(1e-5)
        .fit(&dataset)
        .map_err(|e| {
            ThemeKmeansError::KMeansFit(format!("Final k-means fit failed at k={chosen_k}: {e}"))
        })?;
    let labels: Vec<usize> = model.predict(&dataset).iter().copied().collect();
    let centroids = model.centroids();

    // 5. Persist: theme per cluster, then bulk-assign claim_ids.
    let mut themes_created = 0_usize;
    let mut claims_assigned = 0_usize;
    let min_claims = config.min_claims_per_theme as usize;

    for cluster_idx in 0..chosen_k {
        let cluster_claim_ids: Vec<Uuid> = labels
            .iter()
            .enumerate()
            .filter(|(_, &l)| l == cluster_idx)
            .map(|(i, _)| rows[i].0)
            .collect();

        if cluster_claim_ids.len() < min_claims {
            continue;
        }

        let theme_label = format!("{}-{:02}", config.label_prefix, cluster_idx);
        let theme_description = format!(
            "Auto-built from {} claims by k-means at k={} ({}d embedding)",
            cluster_claim_ids.len(),
            chosen_k,
            config.centroid_dim,
        );
        let theme = ClaimThemeRepository::create(pool, &theme_label, &theme_description).await?;

        let centroid_row = centroids.row(cluster_idx);
        let centroid_str = format!(
            "[{}]",
            centroid_row
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        if config.centroid_dim == 3072 {
            // Direct UPDATE to claim_themes.centroid_3072 (no repo helper —
            // the existing set_centroid targets the legacy 1536d column).
            sqlx::query(
                "UPDATE claim_themes SET centroid_3072 = $2::vector, updated_at = NOW() WHERE id = $1",
            )
            .bind(theme.id)
            .bind(&centroid_str)
            .execute(pool)
            .await?;
        } else {
            ClaimThemeRepository::set_centroid(pool, theme.id, &centroid_str).await?;
        }

        let assigned =
            ClaimThemeRepository::bulk_assign(pool, &cluster_claim_ids, theme.id).await?;
        // update_count runs LAST per-cluster so claim_themes.updated_at is
        // bumped strictly after the per-claim updates.  The scheduled
        // `theme_cluster_rebuild` job's skip-check relies on this ordering.
        ClaimThemeRepository::update_count(pool, theme.id, assigned as i32).await?;

        themes_created += 1;
        claims_assigned += assigned as usize;
    }

    Ok(RunThemeKmeansSummary {
        themes_created,
        claims_assigned,
        k_used: Some(chosen_k as u32),
        claims_with_embeddings: n_claims,
        // Success path: forward the *measured* dim (matches legacy route response).
        centroid_dim: dim as u32,
        skipped_reason: None,
    })
}
