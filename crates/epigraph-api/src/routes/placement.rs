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

use crate::access_control::{check_content_access, ContentAccess};
use crate::errors::ApiError;
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
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
) -> Result<Json<PlacementResponse>, ApiError> {
    let pool = &state.db_pool;

    let requester = auth_ctx
        .as_ref()
        .and_then(|axum::Extension(ctx)| ctx.agent_id.or(Some(ctx.client_id)));

    let placement = ClusterRunRepository::claim_placement(pool, claim_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        })?;

    // There is no content to redact here, but a theme or cluster id is a
    // pointer into a view that renders the claim's text. A caller who may not
    // read the claim gets the all-null answer an unclustered claim gets.
    if check_content_access(pool, claim_id, requester).await == ContentAccess::Redacted {
        return Ok(Json(PlacementResponse {
            claim_id,
            theme_id: None,
            cluster_run_id: None,
            cluster_id: None,
            neighborhood_id: None,
            run_completed_at: None,
        }));
    }

    Ok(Json(PlacementResponse {
        claim_id: placement.claim_id,
        theme_id: placement.theme_id,
        cluster_run_id: placement.cluster_run_id,
        cluster_id: placement.cluster_id,
        neighborhood_id: placement.neighborhood_id,
        run_completed_at: placement.run_completed_at,
    }))
}
