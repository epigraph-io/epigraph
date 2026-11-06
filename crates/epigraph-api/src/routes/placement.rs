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
//! The run is resolved by `ClusterRunRepository::latest`, the same spelling the
//! `expand` routes use, so an id returned here is one `expand` accepts at that
//! moment. None of these ids are permalinks — every run mints new cluster,
//! neighbourhood and (on a theme rebuild) theme ids.
//!
//! A claim the viewer may not read is a 404, byte-identical to the 404 for a
//! uuid that names nothing. There is no claim text in this response, but a
//! theme or cluster id is a pointer into a view that renders that text, and the
//! all-null-fields 200 this route used to return echoed the id back, which
//! confirms the claim exists. The repo's `None` is now the whole answer.
//!
//! `layout` (Atlas P3a) resolves the claim's theme to its place in the latest
//! servable Atlas layout run, so a deep link goes claim -> theme -> region ->
//! position in one call: a shared position (`placement: "shared"`), or, for a
//! theme with no public member, the region nearest the members THIS caller
//! can read (`placement: "viewer"`, no `x`/`y`). `null` when the claim has no
//! theme, there is no run, the run was invalidated by a narrowing, or the
//! theme has no position for this caller.

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use epigraph_db::{AtlasLayoutRepository, ClusterRunRepository};
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
    pub layout: Option<PlacementLayout>,
}

/// Where the claim's theme sits in the latest servable Atlas layout.
#[derive(Debug, Serialize)]
pub struct PlacementLayout {
    pub run_id: Uuid,
    pub region_id: Uuid,
    /// `shared` or `viewer`.
    pub placement: &'static str,
    pub x: Option<f64>,
    pub y: Option<f64>,
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

    let placement = ClusterRunRepository::claim_placement(&mut read, &viewer, claim_id).await?;
    let layout = match placement.as_ref().and_then(|p| p.theme_id) {
        Some(theme_id) => {
            AtlasLayoutRepository::placement_layout(&mut read, &viewer, theme_id).await?
        }
        None => None,
    };

    crate::routes::finish_scoped_read(read, "claim_placement").await?;

    let placement = placement.ok_or_else(|| ApiError::NotFound {
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
        layout: layout.map(|l| PlacementLayout {
            run_id: l.run_id,
            region_id: l.region_id,
            placement: l.placement.as_str(),
            x: l.x,
            y: l.y,
        }),
    }))
}
