//! `GET /api/v1/claims/:id/placement` (plan §2.3) — the missing link from a
//! claim to the theme, graph cluster and neighbourhood views.
//!
//! Nothing else maps a claim to its neighbourhood: `claims.theme_id` surfaces
//! only in diverse-mode `POST /search/semantic`, `ClaimResponse` carries
//! neither, and `claim_neighborhood_membership` was read only inside
//! `routes/graph_neighborhood.rs`. Without this route the Explorer's
//! `/theme/:id`, `/community/:id` and `/neighborhood/:id` pages are
//! unreachable from a claim.
//!
//! The run is resolved by `ClusterRunRepository::latest`, the function the
//! three `expand` routes now share, so an id returned here is one `expand`
//! accepts at that moment. None of these ids are permalinks — every run mints
//! new cluster, neighbourhood and (on a theme rebuild) theme ids.

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use epigraph_db::ClusterRunRepository;
use serde::Serialize;
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::state::AppState;

/// Nulls are serialised, not omitted: "this claim has no neighbourhood" is the
/// common answer here and the caller has to be able to tell it apart from a
/// field it forgot to read.
#[derive(Debug, Serialize)]
pub struct PlacementResponse {
    pub claim_id: Uuid,
    pub theme_id: Option<Uuid>,
    pub cluster_run_id: Option<Uuid>,
    pub cluster_id: Option<Uuid>,
    pub neighborhood_id: Option<Uuid>,
    pub run_completed_at: Option<DateTime<Utc>>,
}

/// `GET /api/v1/claims/:id/placement`
pub async fn claim_placement(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<PlacementResponse>, ApiError> {
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "claim_placement",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // There is no content here, but a theme or cluster id is a pointer into a
    // view that renders the claim's text, so this still has to be gated on the
    // VIEWER. A claim the viewer cannot read is reported ABSENT, identically to
    // one that does not exist (the convention `claim_compound_neighborhood`
    // sets); the pre-tenancy spelling returned the all-null body an unclustered
    // claim gets, which told the caller the claim existed.
    //
    // Read on the STAMPED connection, not merely with a viewer argument. The
    // `/* {VISIBILITY:c} */` splice narrows the query, but row-level security
    // evaluates its group functions from session state, so an unstamped
    // connection sees an empty set and the endpoint would quietly answer
    // public-only. Both halves are required.
    if epigraph_db::ClaimRepository::get_by_id(
        &mut *read,
        &viewer,
        epigraph_core::ClaimId::from_uuid(claim_id),
    )
    .await?
    .is_none()
    {
        return Err(ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        });
    }

    let placement = ClusterRunRepository::claim_placement(&mut read, claim_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        })?;

    Ok(Json(PlacementResponse {
        claim_id: placement.claim_id,
        theme_id: placement.theme_id,
        cluster_run_id: placement.cluster_run_id,
        cluster_id: placement.cluster_id,
        neighborhood_id: placement.neighborhood_id,
        run_completed_at: placement.run_completed_at,
    }))
}
