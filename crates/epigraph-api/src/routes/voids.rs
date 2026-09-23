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

/// Body of `POST /api/v1/voids/detect`.
///
/// `concepts` is bounded by [`MAX_DETECT_VOIDS_CONCEPTS`] and each entry by
/// [`MAX_CONCEPT_BYTES`]; see [`detect_voids`]'s `# Footprint` for why.
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
/// # Footprint: embed everything first, then N short statements on one handle
///
/// Every concept in one request is still answered from the SAME stamped
/// session — a request that returned `void` for one concept and `covered` for
/// another because the two sampled different sessions would be describing two
/// different corpora. What changed is WHEN that session is taken.
///
/// PR-29 acquired it above the concept loop and embedded inside the loop, so
/// the connection sat idle across `request.concepts.len()` outbound embedding
/// round trips (and across any rate-limiter sleep inside them), with `concepts`
/// caller-supplied and unbounded. The request pool is shared by every route, so
/// a handful of large requests could pin all of it for as long as the provider
/// took. That was `F-PR29-A1`, a second instance of the shape
/// `F-PR26-lineage-holds-one-connection-for-n-round-trips` names. The order is
/// now:
///
/// 1. **Bound the request** before any other work: at most
///    [`MAX_DETECT_VOIDS_CONCEPTS`] concepts, each non-blank and at most
///    [`MAX_CONCEPT_BYTES`] bytes. A violation is a 400, and no embedding call
///    and no acquire happen.
/// 2. **Embed with no connection checked out**: one
///    [`EmbeddingService::batch_generate`](epigraph_embeddings::EmbeddingService::batch_generate)
///    call for the whole request, then each vector formatted into its probe
///    literal.
/// 3. **Only then acquire**, run exactly one nearest-claim statement per
///    concept back to back, and release.
///
/// So the handle spans at most [`MAX_DETECT_VOIDS_CONCEPTS`] short statements
/// and no external I/O. This discharges `F-PR29-A1` and the `detect_voids`
/// instance of `F-PR26`; `F-PR26` itself stays open for `routes/lineage.rs`.
#[cfg(feature = "db")]
pub async fn detect_voids(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Json(request): Json<DetectVoidsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let embedder = state.embedding_service().ok_or(ApiError::InternalError {
        message: "Embedding service not configured".into(),
    })?;

    // Step 1 of `# Footprint`: nothing below runs for an out-of-bounds request.
    validate_concepts(&request.concepts)?;

    let threshold = request.threshold.unwrap_or(0.70);
    let sparse_threshold = 0.50;

    // Step 2: every outbound call happens HERE, before the acquire, so no
    // connection is checked out while the provider (or its rate limiter) runs.
    let probes: Vec<String> = embed_concepts(embedder.as_ref(), &request.concepts)
        .await?
        .iter()
        .map(Vec::as_slice)
        .map(format_embedding)
        .collect();

    let mut voids = Vec::new();
    let mut sparse = Vec::new();
    let mut covered = Vec::new();

    // Step 3: acquire only now.
    //
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

    for (concept, probe) in request.concepts.iter().zip(&probes) {
        // Find nearest VISIBLE claim. `min_similarity = NO_SIMILARITY_FLOOR`
        // reproduces the old unbounded `ORDER BY embedding <=> $1 LIMIT 1`:
        // cosine similarity is bounded below by -1, so the floor excludes
        // nothing, and `ORDER BY similarity DESC` is `ORDER BY distance ASC`.
        let nearest = epigraph_db::ClaimRepository::semantic_search_flat(
            &mut *read,
            &viewer,
            probe,
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
/// [`detect_voids`] follows the same order for its whole batch.
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

// ── Request bounds ──

/// The most concepts one `POST /api/v1/voids/detect` may carry.
///
/// This caps the only caller-controlled multiplier in the handler: the number
/// of texts in its one embedding batch and the number of statements its one
/// stamped handle runs. Before it existed the only limit was the router's
/// `DefaultBodyLimit` (10 MB by default), room for roughly 10^5 short concepts,
/// each a separate paid embedding call. 100 matches `routes/batch.rs`'s
/// `MAX_BATCH_SIZE` and sits far under the 2048-text batch ceiling the OpenAI
/// and Jina providers enforce, so a bounded request can never be refused by
/// the provider for its size.
#[cfg(feature = "db")]
pub const MAX_DETECT_VOIDS_CONCEPTS: usize = 100;

/// The longest single concept, in bytes.
///
/// A concept is a short phrase. The bound keeps the one batched provider call
/// small: a BPE token covers at least one byte, so a concept of at most 512
/// bytes is at most 512 tokens, which is within the smallest per-input
/// `max_tokens` any `EmbeddingConfig` preset sets (`local`, 512). A bounded
/// request therefore cannot fail the provider's own length check (which would
/// otherwise surface as a 500) and totals at most
/// `MAX_DETECT_VOIDS_CONCEPTS * 512` tokens.
#[cfg(feature = "db")]
pub const MAX_CONCEPT_BYTES: usize = 512;

/// Reject a request whose concept list is out of bounds, before any embedding
/// call or acquire.
///
/// A blank concept is refused here as a 400 rather than passed on: the
/// providers refuse an empty text with `EmbeddingError::EmptyText`, which would
/// otherwise reach the caller as a 500, and a whitespace-only concept has no
/// meaning to measure coverage for.
#[cfg(feature = "db")]
fn validate_concepts(concepts: &[String]) -> Result<(), ApiError> {
    if concepts.len() > MAX_DETECT_VOIDS_CONCEPTS {
        return Err(ApiError::ValidationError {
            field: "concepts".to_string(),
            reason: format!(
                "Too many concepts: {}, maximum is {MAX_DETECT_VOIDS_CONCEPTS}",
                concepts.len()
            ),
        });
    }
    for (i, concept) in concepts.iter().enumerate() {
        if concept.trim().is_empty() {
            return Err(ApiError::ValidationError {
                field: "concepts".to_string(),
                reason: format!("Concept {i} is empty or whitespace-only"),
            });
        }
        if concept.len() > MAX_CONCEPT_BYTES {
            return Err(ApiError::ValidationError {
                field: "concepts".to_string(),
                reason: format!(
                    "Concept {i} is too long: {} bytes, maximum is {MAX_CONCEPT_BYTES} bytes",
                    concept.len()
                ),
            });
        }
    }
    Ok(())
}

/// Embed every concept in ONE provider call, with no connection checked out.
///
/// An empty list returns an empty result without calling the provider, because
/// not every provider accepts an empty batch (Jina would send an API request
/// with no input).
///
/// Both failure paths answer with an opaque message and log the detail. The
/// per-concept loop this replaced rendered `"Failed to embed concept '<c>': <e>"`
/// into the response body, where `errors.rs` serialises `InternalError`
/// verbatim, which handed provider error text to the caller.
#[cfg(feature = "db")]
async fn embed_concepts(
    embedder: &dyn epigraph_embeddings::EmbeddingService,
    concepts: &[String],
) -> Result<Vec<Vec<f32>>, ApiError> {
    if concepts.is_empty() {
        return Ok(Vec::new());
    }
    let texts: Vec<&str> = concepts.iter().map(String::as_str).collect();
    let embeddings = embedder.batch_generate(&texts).await.map_err(|e| {
        tracing::error!(
            error = %e,
            handler = "detect_voids",
            concepts = concepts.len(),
            "could not embed the request's concepts"
        );
        ApiError::InternalError {
            message: "Failed to embed concepts".to_string(),
        }
    })?;

    // The zip in `detect_voids` pairs concept i with vector i. A provider that
    // returned a different count would silently drop concepts from the
    // response (or pair them with the wrong vector), so a mismatch is an
    // error rather than something the zip is allowed to absorb.
    if embeddings.len() != concepts.len() {
        tracing::error!(
            handler = "detect_voids",
            expected = concepts.len(),
            actual = embeddings.len(),
            "embedding provider returned a batch of the wrong length"
        );
        return Err(ApiError::InternalError {
            message: "Failed to embed concepts".to_string(),
        });
    }
    Ok(embeddings)
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
