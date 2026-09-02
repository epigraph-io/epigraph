//! Structural feature extractor endpoint (§3.2 Privacy-Preserving Features)
//!
//! Computes statistical graph features without exposing content.
//! Enables ML training on private subgraph topology.
//!
//! Authenticated (GET), on the `protected` router:
//! - `GET /api/v1/structural-features/:owner_id` — statistical features for
//!   owner's subgraph, restricted to the caller's visible set.
//!
//! The plan's PR-08 evidence line says this route is registered *"inside the
//! `public` Router (`mod.rs:671`)"* and must be moved. It is already on
//! `protected`, in BOTH `create_router` variants (`routes/mod.rs`, the
//! registrations enclosed by the `let protected` blocks). `routes/mod.rs` is
//! therefore untouched by PR-08 and the anonymous→401 acceptance criterion is
//! *tested* rather than implemented. Which PR moved it is not attributable from
//! the history: `git log -S/-G 'structural-features' -- routes/mod.rs` returns
//! only the initial public release, because the registration LINE never
//! changed — the surrounding `public`/`protected` block boundary moved around
//! it, which a line-based search cannot see.
//!
//! # PR-08: what the caller actually gets
//!
//! Every statement lives in `epigraph_db::repos::structural` and takes the
//! request's [`Viewer`](epigraph_db::Viewer), so the aggregates are
//! *visible-set* aggregates: a node the caller cannot read contributes to no
//! count, no bin and no distribution. The plan said three queries; there are
//! nine, and all nine are converted.
//!
//! # What the Laplace mechanism covers: the rule, not a count
//!
//! **Every COUNT-shaped field of the response is noised**, in one place —
//! [`noise_all_counts`]. That is `node_counts`, `edge_counts`, `temporal_bins`,
//! `frame_coverage`, `community_membership_count`, and the four count
//! components of the moment blocks: `degree_stats.total_nodes`,
//! `belief_stats.claims_with_belief`, `clustering_stats.eligible_nodes` and
//! `conflict_stats.entries`.
//!
//! The rule is stated as a rule rather than as "five of nine" because the count
//! was the defect. `degree_stats.total_nodes` is the row count of
//! `StructuralRepository::degrees` — the same quantity as the sum of the
//! nominally-noised `node_counts`. Leaving it exact meant a caller refused
//! exact counts by the `claims:admin` gate simply read them two fields further
//! down the same JSON body, so the gate withheld nothing.
//!
//! What stays exact at every epsilon, and why: the **means, variances and
//! maxima** — `degree_stats.mean` / `variance` / `max_degree`,
//! `belief_stats.mean_interval_width` / `variance_interval_width` /
//! `mean_pignistic`, `clustering_stats.mean` / `variance`, and
//! `conflict_stats.mean` / `max`. The sensitivity-1 Laplace mechanism is
//! defined for a count; it is not the right mechanism for a mean or a maximum,
//! and adding count-shaped noise to a mean would be a worse lie than leaving it
//! exact. Open finding `F-structural-moments-exact`.
//!
//! # Two disclosures the mechanism does NOT cover
//!
//! * **Histogram support is exact at every epsilon.** `node_counts`,
//!   `edge_counts` and `temporal_bins` are `GROUP BY` results, so a key with a
//!   true visible count of zero produces no row and is never noised. The
//!   *absence* of a key is therefore an exact zero: a caller learns which node
//!   types the owner owns and which weeks had activity, at any epsilon. Open
//!   finding `F-structural-support-exact`.
//! * **There is no privacy budget.** Nothing tracks cumulative epsilon across
//!   requests, so the true count of any field is recoverable by averaging
//!   repeated queries. The [`MAX_UNPRIVILEGED_EPSILON`] ceiling below closes the
//!   *single-request* exact read; it does not make the endpoint
//!   repeated-query-safe. Open finding `F-structural-no-privacy-budget`.
//!
//! `noise_applied: true` therefore means "the count fields carry Laplace noise
//! at the stated epsilon", not "this response is differentially private".

use crate::errors::ApiError;
use crate::middleware::bearer::{AuthContext, ViewerExtractor};
#[cfg(feature = "db")]
use crate::state::AppState;
#[cfg(feature = "db")]
use axum::extract::State;
use axum::{
    extract::{Path, Query},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// Query parameters for structural feature extraction
#[derive(Debug, Deserialize)]
pub struct StructuralFeaturesQuery {
    /// Differential privacy epsilon (higher = less noise, less privacy).
    ///
    /// **Default: 1.0 — noise ON.** It used to default to `0.0`, which turned
    /// the mechanism off for every caller that omitted the parameter; plan §4.8:
    /// "a differential-privacy parameter whose default disables the mechanism is
    /// not a mechanism".
    ///
    /// Any value that does *not* engage the mechanism — zero, negative,
    /// infinite, NaN, or **above [`MAX_UNPRIVILEGED_EPSILON`]** — is an
    /// exact-counts request and requires `claims:admin`. See
    /// [`get_structural_features`].
    #[serde(default = "default_epsilon")]
    pub epsilon: f64,
}

/// The largest `epsilon` an unprivileged caller may ask for — and, by
/// construction, the default.
///
/// **The default is also the ceiling: a caller may buy more privacy, never
/// less.** Less noise than the default is an administrative capability, which
/// is the same principle the `claims:admin` gate already encodes for
/// `epsilon = 0`.
///
/// A lower bound alone is not a gate. `epsilon` scales the Laplace parameter as
/// `b = 1/epsilon`, so a large *finite positive* epsilon passes an
/// `epsilon > 0.0` check and still returns the exact count: at `epsilon = 1e300`
/// the noise term is `1e-300` and rounds away entirely; even at `epsilon = 10`,
/// `b = 0.1` and `P(|noise| > 0.5) = e^-5 = 0.0067`, so 99.3% of draws are
/// already exact. A ceiling anywhere in the conventional "usable" DP range
/// would therefore have closed almost nothing. At the default of `1.0`,
/// `b = 1.0` and `P(|noise| > 0.5) = e^-0.5 = 0.61`, so the mechanism actually
/// moves the answer.
///
/// This ceiling is a **deliberate addition to PR-08's scope**: the plan's
/// acceptance line asks only that `epsilon = 0.0` require `claims:admin`.
/// Closing three of the four ways to disable the mechanism and shipping the
/// fourth would have been a gate with a documented hole, so the fourth is
/// closed here and the deviation is recorded in `docs/tenancy/progress.json`
/// rather than left silent. Blast radius is nil: no in-repo client calls this
/// endpoint, and it carries no OpenAPI entry (both verified by grep).
///
/// It does **not** make the endpoint repeated-query-safe — there is no privacy
/// budget. See the module docs.
pub const MAX_UNPRIVILEGED_EPSILON: f64 = 1.0;

/// The `epsilon` default: noise ON, at the ceiling.
///
/// Defined as [`MAX_UNPRIVILEGED_EPSILON`] rather than as a second literal
/// `1.0`, so "the default is also the ceiling" cannot drift into being false at
/// the next edit. Pinned by `the_default_is_the_ceiling`.
fn default_epsilon() -> f64 {
    MAX_UNPRIVILEGED_EPSILON
}

/// Does this `epsilon` actually engage the Laplace mechanism?
///
/// The gate is written as "the mechanism engaged", not as a comparison against
/// zero, because four values defeat a comparison-based gate:
///
/// * `epsilon = -1` — negative, so the noise term is never computed and the
///   value comes back unchanged. A gate written `epsilon == 0.0` misses it.
/// * `epsilon = NaN` — **fails `<= 0.0` AND fails `> 0.0`.** A gate written
///   `epsilon <= 0.0` demands no scope while noise is silently off. This is the
///   one a comparison gate gets wrong in the dangerous direction.
/// * `epsilon = inf` — `b = 1/inf = 0`, so the noise term is ±0.0 and the count
///   comes back exact.
/// * `epsilon = 1e300` — **finite and positive**, so it passes every check the
///   three above motivated, while `b = 1e-300` rounds away and the count comes
///   back exact anyway. This is the one that needs no special float semantics
///   at all, and it is why the predicate needs an upper bound as well as a
///   lower one. See [`MAX_UNPRIVILEGED_EPSILON`].
///
/// Returning "did the mechanism engage" and gating on its negation makes all
/// four require `claims:admin` without enumerating them at the call site.
/// [`maybe_add_noise`] guards on this same predicate, so "was a scope demanded"
/// and "was noise actually added" cannot disagree.
fn noise_engages(epsilon: f64) -> bool {
    epsilon.is_finite() && epsilon > 0.0 && epsilon <= MAX_UNPRIVILEGED_EPSILON
}

/// Statistical features of a subgraph (no content exposed)
#[derive(Debug, Serialize)]
pub struct StructuralFeaturesResponse {
    pub owner_id: Uuid,
    /// Node counts by type
    pub node_counts: Vec<NodeTypeCount>,
    /// Edge counts by relationship type (coarse schema only)
    pub edge_counts: Vec<EdgeTypeCount>,
    /// Degree distribution statistics
    pub degree_stats: DegreeStats,
    /// Belief interval width distribution (mean, variance)
    pub belief_stats: BeliefStats,
    /// Number of distinct frames touched by owned claims
    pub frame_coverage: i64,
    /// Temporal activity: binned update frequency (last 30 days, 7-day bins)
    pub temporal_bins: Vec<TemporalBin>,
    /// Local clustering coefficient (mean, variance)
    pub clustering_stats: ClusteringStats,
    /// Number of distinct communities the owner's perspectives belong to
    pub community_membership_count: i64,
    /// Conflict coefficient distribution across owned claims' combined beliefs
    pub conflict_stats: ConflictStats,
    /// Whether Laplacian noise was applied — **to every COUNT-shaped field**,
    /// including the count components of the four moment blocks
    /// (`degree_stats.total_nodes`, `belief_stats.claims_with_belief`,
    /// `clustering_stats.eligible_nodes`, `conflict_stats.entries`). See
    /// [`noise_all_counts`], which is the single place any of them is noised.
    ///
    /// The means, variances and maxima beside those counts are exact at every
    /// epsilon, as is the *support* of the three histograms. `true` here does
    /// not mean "this response is differentially private"; see the module docs.
    pub noise_applied: bool,
}

/// Count of nodes by type
#[derive(Debug, Serialize)]
pub struct NodeTypeCount {
    pub node_type: String,
    pub count: i64,
}

/// Count of edges by relationship type
#[derive(Debug, Serialize)]
pub struct EdgeTypeCount {
    pub relationship: String,
    pub count: i64,
}

/// Degree distribution statistics
#[derive(Debug, Serialize)]
pub struct DegreeStats {
    pub mean: f64,
    pub variance: f64,
    pub max_degree: i64,
    pub total_nodes: i64,
}

/// Belief interval width statistics
#[derive(Debug, Serialize)]
pub struct BeliefStats {
    /// Mean of (plausibility - belief) across owned claims
    pub mean_interval_width: f64,
    /// Variance of interval width
    pub variance_interval_width: f64,
    /// Mean pignistic probability
    pub mean_pignistic: f64,
    /// Number of claims with belief data
    pub claims_with_belief: i64,
}

/// Temporal activity bin
#[derive(Debug, Serialize)]
pub struct TemporalBin {
    pub bin_label: String,
    pub count: i64,
}

/// Local clustering coefficient statistics
#[derive(Debug, Serialize)]
pub struct ClusteringStats {
    /// Mean local clustering coefficient across owned nodes with degree >= 2
    pub mean: f64,
    /// Variance of local clustering coefficient
    pub variance: f64,
    /// Number of nodes with degree >= 2 (eligible for clustering)
    pub eligible_nodes: i64,
}

/// Conflict coefficient distribution statistics
#[derive(Debug, Serialize)]
pub struct ConflictStats {
    /// Mean conflict coefficient across owned claims' global combined beliefs
    pub mean: f64,
    /// Maximum conflict coefficient
    pub max: f64,
    /// Number of combined belief entries with conflict data
    pub entries: i64,
}

// =============================================================================
// HANDLERS (db feature)
// =============================================================================

/// Compute structural features for an owner's subgraph
///
/// `GET /api/v1/structural-features/:owner_id`
///
/// Returns statistical aggregates over the nodes and edges that `owner_id` owns
/// **and the caller can see**. No content (claim text, evidence bodies, etc.) is
/// exposed.
///
/// # Authorization
///
/// * **Anonymous → 401.** The route sits on the `protected` router, so
///   `bearer_auth_middleware` rejects the request before any extractor runs.
///   [`ViewerExtractor`] is a second fail-closed refusal, not a 401 backstop:
///   `axum::Extension<AuthContext>` is declared first and `FromRequestParts`
///   extractors run in declaration order, so if the registration ever moved to
///   `public` the missing-extension rejection would fire first and that is a
///   **500**, not a 401. Refused either way; the status code would differ. The
///   extractors are deliberately left in this order — `viewer_route_table_lint`
///   reads handler signature shape, and re-baselining a lint in the same change
///   that fixes a mechanism defect would hide one behind the other.
/// * **Authenticated → visible-set aggregates.** `:owner_id` keeps its meaning —
///   it is still the `ownership.owner_id` / `perspectives.owner_agent_id` being
///   asked about. The viewer predicate is an additional `AND`, never a
///   reinterpretation of the path parameter as a group id.
/// * **An epsilon that disables the noise → `claims:admin` or 403.** Exact
///   counts are an administrative capability, not a query-string option.
///
/// The scope check is unconditional on a REQUIRED `Extension<AuthContext>`, not
/// `if let Some(..) = auth_ctx { .. }`: the latter is the fail-open idiom
/// `viewer_route_table_lint.rs::fail_open_scope_check_sites_do_not_increase`
/// ratchets, and it authorizes nothing when the extension is absent.
///
/// `claims:admin` buys noise-off. It does **not** widen the viewer: an admin
/// still holds a `Scoped` viewer and still sees only its own visible set.
///
/// # Errors
///
/// 401 without a principal, 403 for exact counts without `claims:admin`, 500 on
/// a database error. The clustering and conflict statements used to end
/// `.unwrap_or_default()` and rendered a query failure as "no data"; they now
/// propagate.
#[cfg(feature = "db")]
pub async fn get_structural_features(
    State(state): State<AppState>,
    axum::Extension(auth): axum::Extension<AuthContext>,
    ViewerExtractor(viewer): ViewerExtractor,
    Path(owner_id): Path<Uuid>,
    Query(params): Query<StructuralFeaturesQuery>,
) -> Result<Json<StructuralFeaturesResponse>, ApiError> {
    use epigraph_db::StructuralRepository;

    let pool = &state.db_pool;
    let apply_noise = noise_engages(params.epsilon);
    if !apply_noise {
        crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;
    }

    // 1. Node counts by type
    let node_type_counts: Vec<NodeTypeCount> =
        StructuralRepository::node_counts(pool, &viewer, owner_id)
            .await?
            .into_iter()
            .map(|(node_type, count)| NodeTypeCount { node_type, count })
            .collect();

    // 2. Edge counts by coarse relationship type
    let edge_type_counts: Vec<EdgeTypeCount> =
        StructuralRepository::edge_counts(pool, &viewer, owner_id)
            .await?
            .into_iter()
            .map(|(relationship, count)| EdgeTypeCount {
                relationship,
                count,
            })
            .collect();

    // 3. Degree distribution
    let degree_rows = StructuralRepository::degrees(pool, &viewer, owner_id).await?;
    let degrees: Vec<f64> = degree_rows.iter().map(|(d,)| *d as f64).collect();
    let degree_stats = compute_degree_stats(&degrees);

    // 4. Belief interval widths
    let belief_rows = StructuralRepository::belief_intervals(pool, &viewer, owner_id).await?;
    let belief_stats = compute_belief_stats(&belief_rows);

    // 5. Frame coverage
    let frame_coverage = StructuralRepository::frame_coverage(pool, &viewer, owner_id).await?;

    // 6. Temporal activity (last 30 days, 7-day bins)
    let temporal_bins: Vec<TemporalBin> =
        StructuralRepository::temporal_bins(pool, &viewer, owner_id)
            .await?
            .into_iter()
            .map(|(bin_label, count)| TemporalBin { bin_label, count })
            .collect();

    // 7. Local clustering coefficients
    let clustering_rows =
        StructuralRepository::clustering_coefficients(pool, &viewer, owner_id).await?;
    let clustering_stats = compute_clustering_stats(&clustering_rows);

    // 8. Community membership count
    let community_count =
        StructuralRepository::community_membership_count(pool, &viewer, owner_id).await?;

    // 9. Conflict coefficient distribution
    let conflict_rows =
        StructuralRepository::conflict_coefficients(pool, &viewer, owner_id).await?;
    let conflict_stats = compute_conflict_stats(&conflict_rows);

    // Every count-shaped field is noised in ONE place, after the response is
    // assembled from exact rows. Noising at each construction site is what let
    // `degree_stats.total_nodes` and its three siblings ship exact while the
    // five histogram/scalar counts were noised — the response is the unit the
    // gate is about, so the response is where the mechanism is applied.
    let mut response = StructuralFeaturesResponse {
        owner_id,
        node_counts: node_type_counts,
        edge_counts: edge_type_counts,
        degree_stats,
        belief_stats,
        frame_coverage,
        temporal_bins,
        clustering_stats,
        community_membership_count: community_count,
        conflict_stats,
        noise_applied: apply_noise,
    };
    noise_all_counts(&mut response, apply_noise, params.epsilon);

    Ok(Json(response))
}

/// Apply [`maybe_add_noise`] to **every count-shaped field** of the response.
///
/// This is the single point at which the Laplace mechanism touches the
/// response, and the reason it exists as a named function rather than as a
/// `map` at each construction site: PR-08's first pass noised the five obvious
/// counts and left `degree_stats.total_nodes`,
/// `belief_stats.claims_with_belief`, `clustering_stats.eligible_nodes` and
/// `conflict_stats.entries` exact. `total_nodes` is the row count of
/// `StructuralRepository::degrees`, i.e. the same quantity as the sum of the
/// noised `node_counts`, so a caller refused exact counts by the `claims:admin`
/// gate read them two fields further down the same body. One function that
/// names all nine is auditable; nine scattered call sites were not.
///
/// The means, variances and maxima are deliberately NOT touched — the
/// sensitivity-1 count mechanism is not defined for them. See the module docs.
#[cfg(feature = "db")]
fn noise_all_counts(resp: &mut StructuralFeaturesResponse, apply: bool, epsilon: f64) {
    for row in &mut resp.node_counts {
        row.count = maybe_add_noise(row.count, apply, epsilon);
    }
    for row in &mut resp.edge_counts {
        row.count = maybe_add_noise(row.count, apply, epsilon);
    }
    for row in &mut resp.temporal_bins {
        row.count = maybe_add_noise(row.count, apply, epsilon);
    }
    resp.frame_coverage = maybe_add_noise(resp.frame_coverage, apply, epsilon);
    resp.community_membership_count =
        maybe_add_noise(resp.community_membership_count, apply, epsilon);
    resp.degree_stats.total_nodes = maybe_add_noise(resp.degree_stats.total_nodes, apply, epsilon);
    resp.belief_stats.claims_with_belief =
        maybe_add_noise(resp.belief_stats.claims_with_belief, apply, epsilon);
    resp.clustering_stats.eligible_nodes =
        maybe_add_noise(resp.clustering_stats.eligible_nodes, apply, epsilon);
    resp.conflict_stats.entries = maybe_add_noise(resp.conflict_stats.entries, apply, epsilon);
}

#[cfg(feature = "db")]
fn compute_degree_stats(degrees: &[f64]) -> DegreeStats {
    if degrees.is_empty() {
        return DegreeStats {
            mean: 0.0,
            variance: 0.0,
            max_degree: 0,
            total_nodes: 0,
        };
    }

    let n = degrees.len() as f64;
    let mean = degrees.iter().sum::<f64>() / n;
    let variance = degrees.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / n;
    let max_degree = degrees.iter().cloned().fold(0.0_f64, f64::max) as i64;

    DegreeStats {
        mean,
        variance,
        max_degree,
        total_nodes: degrees.len() as i64,
    }
}

#[cfg(feature = "db")]
fn compute_belief_stats(rows: &[(Option<f64>, Option<f64>, Option<f64>)]) -> BeliefStats {
    if rows.is_empty() {
        return BeliefStats {
            mean_interval_width: 0.0,
            variance_interval_width: 0.0,
            mean_pignistic: 0.0,
            claims_with_belief: 0,
        };
    }

    let widths: Vec<f64> = rows
        .iter()
        .filter_map(|(bel, pl, _)| match (bel, pl) {
            (Some(b), Some(p)) => Some(p - b),
            _ => None,
        })
        .collect();

    let pignistics: Vec<f64> = rows.iter().filter_map(|(_, _, betp)| *betp).collect();

    let n = widths.len() as f64;
    let mean_width = if n > 0.0 {
        widths.iter().sum::<f64>() / n
    } else {
        0.0
    };
    let var_width = if n > 0.0 {
        widths.iter().map(|w| (w - mean_width).powi(2)).sum::<f64>() / n
    } else {
        0.0
    };
    let mean_pignistic = if !pignistics.is_empty() {
        pignistics.iter().sum::<f64>() / pignistics.len() as f64
    } else {
        0.0
    };

    BeliefStats {
        mean_interval_width: mean_width,
        variance_interval_width: var_width,
        mean_pignistic,
        claims_with_belief: rows.len() as i64,
    }
}

#[cfg(feature = "db")]
fn compute_clustering_stats(rows: &[(f64,)]) -> ClusteringStats {
    if rows.is_empty() {
        return ClusteringStats {
            mean: 0.0,
            variance: 0.0,
            eligible_nodes: 0,
        };
    }
    let n = rows.len() as f64;
    let values: Vec<f64> = rows.iter().map(|(cc,)| *cc).collect();
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    ClusteringStats {
        mean,
        variance,
        eligible_nodes: rows.len() as i64,
    }
}

#[cfg(feature = "db")]
fn compute_conflict_stats(rows: &[(Option<f64>,)]) -> ConflictStats {
    let values: Vec<f64> = rows.iter().filter_map(|(v,)| *v).collect();
    if values.is_empty() {
        return ConflictStats {
            mean: 0.0,
            max: 0.0,
            entries: 0,
        };
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let max = values.iter().cloned().fold(0.0_f64, f64::max);
    ConflictStats {
        mean,
        max,
        entries: values.len() as i64,
    }
}

/// Add Laplacian noise to a count.
///
/// Laplace mechanism, sensitivity 1: `noise ~ Lap(b)` with `b = 1/epsilon`,
/// sampled by inverse transform as `-b * sign(u) * ln(1 - 2|u|)` for
/// `u ~ Uniform(-0.5, 0.5)`.
///
/// # The `u` source, and the bug that made this function return zero half the
/// # time
///
/// This previously drew from a hand-rolled `rand_simple` documented as
/// "[0, 1)". It was not. It computed
/// `((seed.wrapping_mul(1103515245).wrapping_add(12345) >> 16) as f64) / 32768.0`
/// on a `u32` seed; `>> 16` of a `u32` lies in `[0, 65536)`, so dividing by
/// `32768` yielded **`[0, 2)`** — the divisor was wrong by a factor of two.
/// Then `u = r - 0.5` reached `[-0.5, 1.5)`, and for every `u > 0.5` the term
/// `1 - 2|u|` was negative, `ln` of it was `NaN`, and
/// `(value as f64 + NaN).round().max(0.0)` returned **`0`** — because Rust's
/// `f64::max` returns the non-NaN operand, laundering the NaN into a
/// plausible-looking zero. Measured over 1,000,000 seeds: 500,001 returned `0`
/// instead of ~42, and 15 hit the `|u| == 0.5` boundary where `ln(0) = -inf`
/// saturates the cast to `i64::MAX`.
///
/// That is the same launder-an-error-into-a-benign-answer shape this PR removed
/// from `clustering_coefficients`'s `.unwrap_or_default()`, and PR-08 is what
/// made it reachable: flipping the `epsilon` default from `0.0` to `1.0` moved
/// it from a path no caller took to the path every caller takes. The endpoint
/// would have reported roughly half of an owner's counts as `0` — reading as
/// "this owner has nothing" rather than as obvious garbage — with no test able
/// to see it, because the old `maybe_add_noise_never_negative` asserted only
/// `noisy >= 0` and `0` *is* the failure output.
///
/// The fix is `rand`, already a non-optional dependency of this crate
/// (`oauth/authorize.rs`, `spans.rs`): `Rng::gen::<f64>()` is uniform on
/// `[0, 1)` by contract. That closes the range defect and, at the same time, the
/// separate defect that `rand_simple` reseeded an LCG from
/// `SystemTime::now().subsec_nanos()` on *every* call, making successive draws
/// within one request correlated and predictable from the request time.
///
/// `ThreadRng` is `!Send`, so the generator is constructed and dropped entirely
/// inside this synchronous function and never held across an `.await`.
///
/// # No non-finite path survives
///
/// `r == 0.0` is representable (probability 2^-53), which gives `u == -0.5`,
/// `1 - 2|u| == 0`, `ln(0) == -inf`. The `arg > 0.0` guard returns the
/// unnoised value on that draw rather than letting `.max(0.0)` absorb an
/// infinity into `i64::MAX`. The `is_finite` check after it is belt-and-braces:
/// with `epsilon` bounded by [`noise_engages`] it is unreachable, and it is
/// there so that no future edit can reintroduce a NaN that `.max(0.0)` would
/// silently swallow.
fn maybe_add_noise(value: i64, apply: bool, epsilon: f64) -> i64 {
    // Guarded on the SAME predicate as the scope gate, so "a scope was demanded"
    // and "noise was actually added" cannot disagree. Written as `epsilon <= 0.0`
    // this would have added noise at `epsilon = 1e300` (b = 1e-300, rounds away)
    // while `noise_engages` refused it — two answers to one question.
    if !apply || !noise_engages(epsilon) {
        return value;
    }
    use rand::Rng;
    let b = 1.0 / epsilon;
    let u: f64 = rand::thread_rng().gen::<f64>() - 0.5;
    let arg = 1.0 - 2.0 * u.abs();
    if arg <= 0.0 {
        return value;
    }
    let noise = -b * u.signum() * arg.ln();
    if !noise.is_finite() {
        return value;
    }
    (value as f64 + noise).round().max(0.0) as i64
}

// =============================================================================
// HANDLERS (non-db stubs)
// =============================================================================

/// The `not(feature = "db")` counterpart.
///
/// It takes the SAME extractors and enforces the SAME two preconditions as the
/// `db` handler — a resolvable viewer, and `claims:admin` for an epsilon that
/// disables the mechanism — because `bearer.rs`'s contract is that the two
/// builds must not disagree about when a read is refused. Only the corpus is
/// absent: there is no pool, so there are no aggregates and every field is zero.
///
/// `AuthContext`, `check_scopes` and [`noise_engages`] are all feature-agnostic,
/// so nothing here is a second, weaker implementation of the gate.
///
/// # Errors
///
/// 401 without a principal, 403 for exact counts without `claims:admin`.
#[cfg(not(feature = "db"))]
pub async fn get_structural_features(
    axum::Extension(auth): axum::Extension<AuthContext>,
    ViewerExtractor(_viewer): ViewerExtractor,
    Path(owner_id): Path<Uuid>,
    Query(params): Query<StructuralFeaturesQuery>,
) -> Result<Json<StructuralFeaturesResponse>, ApiError> {
    if !noise_engages(params.epsilon) {
        crate::middleware::scopes::check_scopes(&auth, &["claims:admin"])?;
    }

    Ok(Json(StructuralFeaturesResponse {
        owner_id,
        node_counts: Vec::new(),
        edge_counts: Vec::new(),
        degree_stats: DegreeStats {
            mean: 0.0,
            variance: 0.0,
            max_degree: 0,
            total_nodes: 0,
        },
        belief_stats: BeliefStats {
            mean_interval_width: 0.0,
            variance_interval_width: 0.0,
            mean_pignistic: 0.0,
            claims_with_belief: 0,
        },
        frame_coverage: 0,
        temporal_bins: Vec::new(),
        clustering_stats: ClusteringStats {
            mean: 0.0,
            variance: 0.0,
            eligible_nodes: 0,
        },
        community_membership_count: 0,
        conflict_stats: ConflictStats {
            mean: 0.0,
            max: 0.0,
            entries: 0,
        },
        // Mirrors the `db` handler's `apply_noise` rather than hardcoding
        // `false`, so the two builds do not disagree about a field a client uses
        // to decide whether to trust the numbers. `noise_all_counts` is NOT
        // called: every count here is a structural zero (there is no pool), and
        // noising them would make the two builds disagree about the numbers
        // themselves, which is strictly worse than the flag mismatch this fixes.
        noise_applied: noise_engages(params.epsilon),
    }))
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// PR-08 flips the default. A `0.0` default disabled the mechanism for every
    /// caller that omitted the parameter, which is the defect §4.8 names.
    #[test]
    fn structural_features_query_defaults_to_noise_on() {
        let q: StructuralFeaturesQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.epsilon, 1.0);
        assert!(
            noise_engages(q.epsilon),
            "the default must actually engage the mechanism, not merely be non-zero"
        );
    }

    /// Parse a query string exactly the way the route does — through
    /// `axum::extract::Query`, not `serde_json`. A `#[serde(default = ..)]` that
    /// worked for one deserializer and not the other would leave the endpoint on
    /// the old default while the json test above stayed green.
    fn parse_query(qs: &str) -> StructuralFeaturesQuery {
        let uri: axum::http::Uri = format!("/api/v1/structural-features/x?{qs}")
            .parse()
            .expect("uri");
        axum::extract::Query::<StructuralFeaturesQuery>::try_from_uri(&uri)
            .unwrap_or_else(|e| panic!("`?{qs}` must parse to reach the gate: {e}"))
            .0
    }

    #[test]
    fn empty_query_string_yields_the_noise_on_default() {
        assert_eq!(parse_query("").epsilon, 1.0);
    }

    /// Every epsilon that fails to engage the mechanism must be gated, and the
    /// gate is `!noise_engages`, not `epsilon <= 0.0`.
    ///
    /// `NaN` is the case a comparison gate gets wrong in the dangerous
    /// direction: it fails `<= 0.0` (so no scope is demanded) *and* fails
    /// `> 0.0` (so noise is off). `inf` gives `b = 1/inf = 0` and therefore an
    /// exact count. Both are reachable from a query string, which the parses
    /// below assert rather than assume.
    ///
    /// `1e300` and `1.0000001` are the FOURTH case, and the one that needs no
    /// special float semantics: both are finite and positive, so both passed
    /// every check the first three motivated, while `b = 1/epsilon` rounds away
    /// and the count comes back exact. `1.0000001` pins the boundary
    /// immediately above [`MAX_UNPRIVILEGED_EPSILON`]; `epsilon=1` below is the
    /// non-vacuity control that the boundary is inclusive.
    #[test]
    fn epsilon_values_that_disable_the_mechanism_are_all_gated() {
        for raw in [
            "epsilon=0",
            "epsilon=-1",
            "epsilon=NaN",
            "epsilon=inf",
            "epsilon=1e300",
            "epsilon=1.0000001",
        ] {
            let q = parse_query(raw);
            assert!(
                !noise_engages(q.epsilon),
                "{raw} does not engage the Laplace mechanism, so it must require \
                 claims:admin; noise_engages said otherwise"
            );
            assert_eq!(
                maybe_add_noise(42, noise_engages(q.epsilon), q.epsilon),
                42,
                "{raw} must leave the count exact — that is why it is gated"
            );
        }
    }

    /// Non-vacuity for the test above: a normal epsilon is NOT gated.
    ///
    /// All three are at or below [`MAX_UNPRIVILEGED_EPSILON`]. `10.0` used to be
    /// in this list; it is now gated, which is the point of the ceiling.
    #[test]
    fn a_positive_finite_epsilon_engages_the_mechanism() {
        for eps in [0.001_f64, 0.1, 1.0] {
            assert!(
                noise_engages(eps),
                "epsilon={eps} must engage the mechanism"
            );
        }
    }

    /// The default and the ceiling are the same number by construction. If
    /// someone re-introduces a literal in `default_epsilon`, this fails.
    #[test]
    fn the_default_is_the_ceiling() {
        assert_eq!(default_epsilon(), MAX_UNPRIVILEGED_EPSILON);
        assert!(
            noise_engages(default_epsilon()),
            "the default must sit INSIDE the admitted range, not on the wrong \
             side of its own ceiling"
        );
    }

    #[test]
    fn maybe_add_noise_no_noise_when_disabled() {
        assert_eq!(maybe_add_noise(42, false, 1.0), 42);
        assert_eq!(maybe_add_noise(42, true, 0.0), 42);
        // Gated by the ceiling, and `maybe_add_noise` agrees with the gate
        // rather than adding an underflowing 1e-300 noise term.
        assert_eq!(maybe_add_noise(42, true, 1e300), 42);
    }

    /// The regression test for the `rand_simple` range defect.
    ///
    /// The assertion this replaces was `noisy >= 0` over 100 draws — which the
    /// broken code SATISFIED, because its failure output was exactly `0`. A
    /// distribution test is the only shape that can see the defect: with
    /// `rand_simple` returning `[0, 2)`, ~50% of draws produced `NaN` that
    /// `.max(0.0)` laundered into `0`, so both the zero-rate and the median
    /// assertions below fail on the old code (measured: 500,001 zeros per
    /// 1,000,000 seeds).
    #[test]
    fn maybe_add_noise_is_centred_on_the_true_value_and_almost_never_zeroes_it() {
        const TRUE_COUNT: i64 = 100;
        const DRAWS: usize = 2000;

        let mut samples: Vec<i64> = (0..DRAWS)
            .map(|_| maybe_add_noise(TRUE_COUNT, true, 1.0))
            .collect();

        // No draw may be negative, and none may saturate the cast. The old
        // `|u| == 0.5` boundary produced `ln(0) = -inf` -> `i64::MAX`.
        for s in &samples {
            assert!(*s >= 0, "a noised count must not be negative, got {s}");
            assert!(
                *s < i64::MAX,
                "a noised count must never saturate the i64 cast: {s}"
            );
        }

        let zeros = samples.iter().filter(|s| **s == 0).count();
        assert!(
            zeros * 100 < DRAWS,
            "fewer than 1% of draws may zero a true count of {TRUE_COUNT}; got \
             {zeros}/{DRAWS}. Laplace(b=1) needs |noise| >= 99.5 for that, which \
             has probability e^-99.5. A high zero rate means the mechanism is \
             producing NaN and `.max(0.0)` is hiding it — the PR-08 blocker."
        );

        samples.sort_unstable();
        let median = samples[DRAWS / 2];
        assert!(
            (median - TRUE_COUNT).abs() <= 2,
            "the median of {DRAWS} Laplace(b=1) draws must sit within 2 of the \
             true value {TRUE_COUNT}; got {median}. The median of a Laplace is \
             its location parameter, so this is a centredness assertion, not a \
             tail one."
        );
    }

    /// Drive the whole `[0, 1)` draw range through the mechanism's arithmetic
    /// and assert no input produces a non-finite intermediate.
    ///
    /// `maybe_add_noise` samples internally, so this reproduces its expression
    /// over an exhaustive sweep including both endpoints — `u = -0.5` (the
    /// `ln(0) = -inf` case) and `u -> +0.5`. It is the deterministic complement
    /// to the statistical test above.
    #[test]
    fn no_draw_in_the_unit_interval_produces_a_non_finite_noise_term() {
        for i in 0..=10_000u32 {
            let r = f64::from(i) / 10_000.0; // [0, 1], deliberately including 1.0
            let u = r - 0.5;
            let arg = 1.0 - 2.0 * u.abs();
            // b = 1.0, so the scale factor is elided; the shape is
            // `-b * sign(u) * ln(arg)` exactly as in `maybe_add_noise`.
            let noise = if arg > 0.0 {
                -u.signum() * arg.ln()
            } else {
                0.0
            };
            assert!(
                noise.is_finite(),
                "r={r} produced a non-finite noise term ({noise}); \
                 `.max(0.0)` would launder it into 0 or i64::MAX"
            );
            let out = (100.0 + noise).round().max(0.0) as i64;
            assert!((0..i64::MAX).contains(&out), "r={r} produced {out}");
        }
    }

    /// Every count-shaped field is noised; no mean, variance or maximum is.
    ///
    /// Deterministic despite sampling: at `epsilon = 1e-6` the scale is
    /// `b = 1e6`, so `P(|noise| < 0.5) = 1 - e^(-0.5/1e6) ~ 5e-7`. Each of the
    /// nine assertions below therefore fails spuriously with probability ~5e-7.
    /// Do not "stabilise" this by widening the tolerance — the point is that a
    /// field left OUT of `noise_all_counts` is unchanged with probability 1.
    #[test]
    #[cfg(feature = "db")]
    fn noise_all_counts_covers_every_count_and_no_moment() {
        let mut resp = sample_response();
        noise_all_counts(&mut resp, true, 1e-6);

        assert_ne!(resp.node_counts[0].count, 10, "node_counts not noised");
        assert_ne!(resp.edge_counts[0].count, 5, "edge_counts not noised");
        assert_ne!(resp.temporal_bins[0].count, 4, "temporal_bins not noised");
        assert_ne!(resp.frame_coverage, 3, "frame_coverage not noised");
        assert_ne!(
            resp.community_membership_count, 2,
            "community_membership_count not noised"
        );
        assert_ne!(
            resp.degree_stats.total_nodes, 10,
            "degree_stats.total_nodes is the row count of \
             StructuralRepository::degrees — the same quantity as the sum of \
             node_counts. Leaving it exact hands a claims:read caller the exact \
             count the claims:admin gate exists to withhold."
        );
        assert_ne!(
            resp.belief_stats.claims_with_belief, 8,
            "belief_stats.claims_with_belief not noised"
        );
        assert_ne!(
            resp.clustering_stats.eligible_nodes, 6,
            "clustering_stats.eligible_nodes not noised"
        );
        assert_ne!(
            resp.conflict_stats.entries, 4,
            "conflict_stats.entries not noised"
        );

        // The moments are deliberately untouched — the sensitivity-1 count
        // mechanism is not defined for a mean, a variance or a maximum.
        assert_eq!(resp.degree_stats.mean, 2.5);
        assert_eq!(resp.degree_stats.variance, 1.2);
        assert_eq!(resp.degree_stats.max_degree, 8);
        assert_eq!(resp.belief_stats.mean_interval_width, 0.3);
        assert_eq!(resp.clustering_stats.mean, 0.4);
        assert_eq!(resp.conflict_stats.max, 0.3);
    }

    /// Non-vacuity for the test above: with the mechanism off, nothing moves.
    /// Without this, a `noise_all_counts` that corrupted every field
    /// unconditionally would pass.
    #[test]
    #[cfg(feature = "db")]
    fn noise_all_counts_is_a_no_op_when_the_mechanism_is_off() {
        let mut resp = sample_response();
        noise_all_counts(&mut resp, false, 1.0);
        assert_eq!(resp.node_counts[0].count, 10);
        assert_eq!(resp.degree_stats.total_nodes, 10);
        assert_eq!(resp.belief_stats.claims_with_belief, 8);
        assert_eq!(resp.clustering_stats.eligible_nodes, 6);
        assert_eq!(resp.conflict_stats.entries, 4);
        assert_eq!(resp.frame_coverage, 3);
        assert_eq!(resp.community_membership_count, 2);
    }

    /// A response with a DISTINCT non-zero value in every count-shaped field,
    /// so `noise_all_counts` coverage is decidable field by field.
    fn sample_response() -> StructuralFeaturesResponse {
        StructuralFeaturesResponse {
            owner_id: Uuid::new_v4(),
            node_counts: vec![NodeTypeCount {
                node_type: "claim".to_string(),
                count: 10,
            }],
            edge_counts: vec![EdgeTypeCount {
                relationship: "SUPPORTS".to_string(),
                count: 5,
            }],
            degree_stats: DegreeStats {
                mean: 2.5,
                variance: 1.2,
                max_degree: 8,
                total_nodes: 10,
            },
            belief_stats: BeliefStats {
                mean_interval_width: 0.3,
                variance_interval_width: 0.05,
                mean_pignistic: 0.75,
                claims_with_belief: 8,
            },
            frame_coverage: 3,
            temporal_bins: vec![TemporalBin {
                bin_label: "2026-02-17".to_string(),
                count: 4,
            }],
            clustering_stats: ClusteringStats {
                mean: 0.4,
                variance: 0.05,
                eligible_nodes: 6,
            },
            community_membership_count: 2,
            conflict_stats: ConflictStats {
                mean: 0.15,
                max: 0.3,
                entries: 4,
            },
            noise_applied: false,
        }
    }

    #[test]
    fn structural_features_response_serializes() {
        let resp = sample_response();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("node_counts"));
        assert!(json.contains("edge_counts"));
        assert!(json.contains("degree_stats"));
        assert!(json.contains("belief_stats"));
        assert!(json.contains("frame_coverage"));
        assert!(json.contains("clustering_stats"));
        assert!(json.contains("community_membership_count"));
        assert!(json.contains("conflict_stats"));
    }

    // `coarse_edge_types_used_in_filter` moved with the filter it guards, to
    // `epigraph_db::repos::structural::tests`. It asserted a property of a
    // constant this file no longer names: PR-08 moved both the constant and the
    // `relationship = ANY($2)` filter into the repo layer, so a test living here
    // would have asserted nothing about the query it was written for.

    #[test]
    fn degree_stats_serializes() {
        let stats = DegreeStats {
            mean: 3.5,
            variance: 2.1,
            max_degree: 12,
            total_nodes: 50,
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("3.5"));
        assert!(json.contains("2.1"));
    }
}
