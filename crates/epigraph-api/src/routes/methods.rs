//! Method lookup endpoint for external tooling.

#[cfg(feature = "db")]
use axum::{
    extract::{Path, State},
    Json,
};
#[cfg(feature = "db")]
use uuid::Uuid;

#[cfg(feature = "db")]
use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
#[cfg(feature = "db")]
use crate::state::AppState;

/// GET /api/v1/methods/:id — Method details with evidence strength.
///
/// # Tenancy: ONE viewer-stamped connection for the whole request
///
/// PR-29 is conversion shard 3 against
/// `D-PR17-request-path-never-stamps-session-gucs`. It moves this handler's two
/// raw-pool reads onto [`AppState::read_as`], acquired ONCE below and threaded
/// into both statements. Both are READS; this handler writes nothing.
///
/// `read_as` and not `acquire_as`: the latter hard-refuses
/// `EPIGRAPH_SESSION_GUC_MODE=transaction`, the pooler fallback `bin/server.rs`
/// advertises to operators, so a site converted that way is unservable in a
/// configuration this project supports.
///
/// The two statements have different tenancy postures, and only one of them can
/// have a predicate:
///
/// - `MethodRepository::get` reads `methods` alone and joins nothing. `methods`
///   has no tenancy columns and no row-level security, so this site has no
///   predicate to add to the table it reads and the function takes no
///   `&Viewer`. PR-29 widened it to `<'e, E: sqlx::PgExecutor<'e>>` — the ONE new
///   repo form the shard was budgeted, plus one the budget missed (see the PR
///   body). The reason it holds no viewer is recorded in
///   `epigraph-db/tests/visibility_lint.rs::EXECUTOR_WITHOUT_VIEWER` rather than
///   left to inference.
/// - `MethodRepository::get_evidence_strength` joins `claims` and `edges`, both
///   of which ARE row-level-secured, and it already takes and splices a
///   `&Viewer`. PR-27 had already made it generic, so it needed no new form.
///
/// Running both on one stamped handle is what makes the response internally
/// consistent: `evidence` describes the corpus this reader can see, not a
/// different one sampled a connection later.
#[cfg(feature = "db")]
pub async fn get_method(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // THE ERROR SHAPE IS PART OF THE TEMPLATE (see `routes/claims_query.rs`).
    // `read_as`'s refusal reason is a paragraph of internal design prose aimed
    // at whoever mis-built the `AppState`; `errors.rs` serialises
    // `ApiError::InternalError { message }` verbatim into the response body, so
    // it is logged in full and answered with an opaque message.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_method",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let method = epigraph_db::MethodRepository::get(&mut *read, id)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("{e}"),
        })?
        .ok_or(ApiError::NotFound {
            entity: "method".into(),
            id: id.to_string(),
        })?;

    let evidence = epigraph_db::MethodRepository::get_evidence_strength(&mut *read, &viewer, id)
        .await
        .ok();

    crate::routes::finish_scoped_read(read, "get_method").await?;

    Ok(Json(serde_json::json!({
        "id": method.id,
        "name": method.name,
        "canonical_name": method.canonical_name,
        "technique_type": method.technique_type,
        "measures": method.measures,
        "typical_conditions": method.typical_conditions,
        "limitations": method.limitations,
        "source_claim_ids": method.source_claim_ids,
        "evidence": evidence.map(|e| serde_json::json!({
            "avg_belief": e.avg_belief,
            "claim_count": e.claim_count,
            "source_count": e.source_count,
        })),
    })))
}
