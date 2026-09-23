//! Knowledge void detection endpoints.
//!
//! ## Endpoints
//!
//! - `POST /api/v1/voids/detect`   - Detect knowledge voids for a list of concepts
//! - `GET  /api/v1/voids/density`  - Measure embedding neighborhood density

#[cfg(feature = "db")]
use axum::{
    extract::{Query, State},
    Json,
};
#[cfg(feature = "db")]
use serde::Deserialize;

#[cfg(feature = "db")]
use crate::errors::ApiError;
#[cfg(feature = "db")]
use crate::state::AppState;

// ── Request types ──

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct DetectVoidsRequest {
    pub concepts: Vec<String>,
    pub threshold: Option<f64>,
}

#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct DensityQuery {
    pub query: String,
    pub radius: Option<f64>,
}

// ── Handlers ──

/// POST /api/v1/voids/detect - Detect knowledge voids for concepts.
///
/// For each concept, finds the nearest claim embedding and classifies
/// as void (< 0.50), sparse (0.50-threshold), or covered (>= threshold).
///
/// # Viewer
///
/// PR-07's headline find was a caller-supplied probe vector ranked against the
/// whole corpus, returning content, unfiltered. It was fixed in
/// `search.rs::semantic_search` and left standing in four siblings running a
/// near-identical statement, of which this is one: it returned
/// `content.chars().take(200)` — a 200-character excerpt of the corpus claim
/// nearest an arbitrary caller-supplied point in embedding space.
///
/// The handler previously took **no auth argument at all**, so unlike the
/// `if let Some(auth_ctx)` sites there was not even a scope check to be
/// fail-open about; the only gate was the router's `bearer_auth_middleware`.
/// The `ViewerExtractor` is therefore a deliberate behaviour change: a bearer
/// token that resolves to no `agents.id` now 401s here.
///
/// # Tenancy: ONE viewer-stamped connection for the whole request
///
/// PR-29 is conversion shard 3 against
/// `D-PR17-request-path-never-stamps-session-gucs`. It moves this handler's
/// single raw-pool read onto [`AppState::read_as`]. `read_as` and not
/// `acquire_as`: the latter hard-refuses `EPIGRAPH_SESSION_GUC_MODE=transaction`,
/// the pooler fallback `bin/server.rs` advertises to operators.
///
/// The read is `ClaimRepository::semantic_search_flat`, which PR-27 had already
/// widened to `<'e, E: sqlx::PgExecutor<'e>>`, so this file authors NO new repo
/// form and changes NO SQL. The reborrow is explicit at the call site on
/// purpose: deref coercion does not fire against a generic `E`, so `&mut read`
/// would infer `E = &mut ScopedRead<'_>` and fail the bound.
///
/// # Footprint: one connection across N embed round trips
///
/// The acquire is hoisted above the concept loop so that every concept in one
/// request is answered from the same stamped session — a request that returned
/// `void` for one concept and `covered` for another because the two sampled
/// different sessions would be describing two different corpora. The cost is
/// that the connection is held across `request.concepts.len()` outbound
/// embedding calls, and `concepts` is caller-supplied and unbounded. That is a
/// real footprint cost and it is recorded here rather than left implicit; it is
/// the same shape `F-PR26-lineage-holds-one-connection-for-n-round-trips`
/// names, and this shard does NOT discharge that finding.
#[cfg(feature = "db")]
pub async fn detect_voids(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Json(request): Json<DetectVoidsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;

    let threshold = request.threshold.unwrap_or(0.70);
    let sparse_threshold = 0.50;

    let mut voids = Vec::new();
    let mut sparse = Vec::new();
    let mut covered = Vec::new();

    // THE ERROR SHAPE IS PART OF THE TEMPLATE (see `routes/claims_query.rs`).
    // `read_as`'s refusal reason is internal design prose aimed at whoever
    // mis-built the `AppState`; `errors.rs` serialises
    // `ApiError::InternalError { message }` verbatim into the response body, so
    // it is logged in full and answered with an opaque message.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "detect_voids",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    for concept in &request.concepts {
        let embedding = embedder
            .generate(concept)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to embed concept '{concept}': {e}"),
            })?;

        // Find nearest VISIBLE claim. `min_similarity = NO_SIMILARITY_FLOOR`
        // reproduces the old unbounded `ORDER BY embedding <=> $1 LIMIT 1`:
        // cosine similarity is bounded below by -1, so the floor excludes
        // nothing, and `ORDER BY similarity DESC` is `ORDER BY distance ASC`.
        let nearest = epigraph_db::ClaimRepository::semantic_search_flat(
            &mut *read,
            &viewer,
            &format_embedding(&embedding),
            NO_SIMILARITY_FLOOR,
            None,
            None,
            None,
            None,
            1,
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to search embeddings: {e}"),
        })?;

        let (sim, nearest_claim) = match nearest.first() {
            Some(row) => (
                row.similarity,
                Some(row.statement.chars().take(200).collect::<String>()),
            ),
            None => (0.0, None),
        };

        let entry = serde_json::json!({
            "concept": concept,
            "nearest_similarity": sim,
            "nearest_claim": nearest_claim,
        });

        if sim < sparse_threshold {
            voids.push(entry);
        } else if sim < threshold {
            sparse.push(entry);
        } else {
            covered.push(entry);
        }
    }

    crate::routes::finish_scoped_read(read, "detect_voids").await?;

    Ok(Json(serde_json::json!({
        "total_concepts": request.concepts.len(),
        "void_concepts": voids,
        "sparse_concepts": sparse,
        "covered_concepts": covered,
    })))
}

/// GET /api/v1/voids/density - Measure embedding neighborhood density.
///
/// Counts how many claims fall within a cosine similarity radius of the query.
///
/// # Viewer
///
/// Two unfiltered corpus scans lived here: a `COUNT(*)`/`AVG(similarity)`
/// cardinality oracle over an arbitrary probe neighbourhood, and the same
/// nearest-claim 200-character excerpt as [`detect_voids`]. Both are now
/// viewer-scoped, so `claim_count` is the reader's count. Same deliberate
/// behaviour change as [`detect_voids`]: this handler took no auth argument.
///
/// # Tenancy: ONE viewer-stamped connection for the whole request
///
/// PR-29 moves both of this handler's raw-pool reads onto
/// [`AppState::read_as`], acquired once below. `claim_count` and `nearest_claim`
/// are two statements describing one neighbourhood; running them on one stamped
/// handle is what makes the pair internally consistent, and under
/// `SessionGucMode::Transaction` they are also one transaction. Both callees
/// (`ClaimRepository::embedding_density_stats`, `::semantic_search_flat`) were
/// already generic over [`sqlx::PgExecutor`] from PR-27, so no new repo form and
/// no SQL change.
///
/// The acquire sits AFTER the outbound embedding call rather than at the top of
/// the handler, so the connection is not held across the network round trip.
/// This handler embeds exactly one string, unlike [`detect_voids`], so the
/// hoist that handler needs is not needed here.
#[cfg(feature = "db")]
pub async fn embedding_density(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Query(params): Query<DensityQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;

    let radius = params.radius.unwrap_or(0.60);

    let embedding =
        embedder
            .generate(&params.query)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("Failed to embed query: {e}"),
            })?;

    // See the acquire in `detect_voids` for why the reason is logged rather than
    // rendered into the response body.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "embedding_density",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Count visible claims within radius and get stats
    let (claim_count, avg_similarity) = epigraph_db::ClaimRepository::embedding_density_stats(
        &mut *read,
        &viewer,
        &format_embedding(&embedding),
        radius,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to compute density: {e}"),
    })?;

    // Get nearest visible claim
    let nearest = epigraph_db::ClaimRepository::semantic_search_flat(
        &mut *read,
        &viewer,
        &format_embedding(&embedding),
        NO_SIMILARITY_FLOOR,
        None,
        None,
        None,
        None,
        1,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to find nearest: {e}"),
    })?;
    let nearest = nearest.first();

    crate::routes::finish_scoped_read(read, "embedding_density").await?;

    Ok(Json(serde_json::json!({
        "query": params.query,
        "radius": radius,
        "claim_count": claim_count,
        "avg_similarity": avg_similarity.unwrap_or(0.0),
        "nearest_claim": nearest.map(|n| n.statement.chars().take(200).collect::<String>()),
        "nearest_similarity": nearest.map_or(0.0, |n| n.similarity),
    })))
}

// ── Internal helpers ──

/// A `min_similarity` that excludes nothing.
///
/// Cosine similarity `1 - (a <=> b)` is bounded below by `-1`, so passing this
/// to `semantic_search_flat` reproduces the unbounded `ORDER BY ... LIMIT 1`
/// nearest-neighbour lookup these handlers used to run inline. Named rather
/// than written as a bare `-1.0` so the reason is at the call site.
#[cfg(feature = "db")]
const NO_SIMILARITY_FLOOR: f64 = -1.0;

#[cfg(feature = "db")]
fn format_embedding(embedding: &[f32]) -> String {
    format!(
        "[{}]",
        embedding
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

// ── Internal types ──
//
// `NearestClaimRow` and `DensityStatsRow` were deleted with the inline scans
// they decoded. Both statements now live in `crates/epigraph-db/src/repos/`
// (`ClaimRepository::semantic_search_flat` and
// `ClaimRepository::embedding_density_stats`), where the
// `/* {VISIBILITY:c} */` marker convention applies and `Viewer::splice`'s
// missing-marker panic can enforce it.
