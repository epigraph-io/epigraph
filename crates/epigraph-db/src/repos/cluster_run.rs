//! The "latest cluster run" lookup, and where a claim sits inside it.
//!
//! Every graph `expand` route resolves the run the same way — newest
//! `graph_cluster_runs.completed_at` — and answers 404 for anything that is
//! not in *that* run. The lookup used to be copy-pasted into
//! `routes/graph.rs` (three times: `overview`, `expand` and `themes_expand`)
//! and `routes/graph_neighborhood.rs`, one of them as a subquery. It lives
//! here now so `GET /claims/:id/placement` cannot drift from the routes whose
//! ids it hands out: a `cluster_id` or `neighborhood_id` from
//! `claim_placement` is one `expand` accepts at that moment, and both go stale
//! together when the next run lands.
//!
//! `themes_expand` was the last holdout — it kept its own inlined
//! `ORDER BY completed_at DESC LIMIT 1` after the other three were converted,
//! which made this paragraph false and left the route free to diverge from
//! the `neighborhood_id`s `claim_placement` promises it will accept.
//!
//! Note what the lookup does NOT do: it does not filter on
//! `graph_cluster_runs.algo` (migration 028). A `louvain_bridge` run from
//! `POST /api/v1/clusters/build-from-bridges` therefore becomes "latest" and
//! has no neighborhoods. That is pre-existing behaviour, preserved
//! deliberately so this function and the expand routes agree; filtering is a
//! separate decision for all five call sites at once.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::DbError;

/// The most recent completed clustering run.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClusterRunRow {
    pub run_id: Uuid,
    pub completed_at: DateTime<Utc>,
    pub degraded: bool,
}

/// Where a claim sits in the theme / cluster / neighbourhood hierarchy.
///
/// Every field but `claim_id` is optional and frequently all-null: clustering
/// is operator-triggered rather than scheduled, theme assignment covers a
/// bounded number of claims per run, and only leaf claims (a `theme_id` and no
/// outgoing `decomposes_to`) are given a neighbourhood at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimPlacement {
    pub claim_id: Uuid,
    pub theme_id: Option<Uuid>,
    pub cluster_run_id: Option<Uuid>,
    pub cluster_id: Option<Uuid>,
    pub neighborhood_id: Option<Uuid>,
    pub run_completed_at: Option<DateTime<Utc>>,
}

pub struct ClusterRunRepository;

impl ClusterRunRepository {
    /// The run every graph `expand` route treats as current, or `None` when
    /// no run has ever completed.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the lookup fails.
    pub async fn latest(pool: &PgPool) -> Result<Option<ClusterRunRow>, DbError> {
        let row = sqlx::query_as::<_, ClusterRunRow>(
            "SELECT run_id, completed_at, degraded
             FROM graph_cluster_runs
             ORDER BY completed_at DESC
             LIMIT 1",
        )
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    /// Resolve `claim_id` to its theme, cluster and neighbourhood.
    ///
    /// Returns `None` when the claim does not exist — the caller's 404. The
    /// run fields are populated only when the claim is actually a member of
    /// something in the latest run, so "no run yet" and "clustered, but this
    /// claim was left out" both read as all-null rather than dangling a run
    /// id and a timestamp off a claim with no placement.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any of the lookups fails.
    pub async fn claim_placement(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Option<ClaimPlacement>, DbError> {
        // `theme_id` is a column on the claim, so this doubles as the
        // existence check.
        let claim: Option<(Option<Uuid>,)> =
            sqlx::query_as("SELECT theme_id FROM claims WHERE id = $1")
                .bind(claim_id)
                .fetch_optional(pool)
                .await?;
        let Some((theme_id,)) = claim else {
            return Ok(None);
        };

        let Some(run) = Self::latest(pool).await? else {
            return Ok(Some(ClaimPlacement {
                claim_id,
                theme_id,
                cluster_run_id: None,
                cluster_id: None,
                neighborhood_id: None,
                run_completed_at: None,
            }));
        };

        let cluster_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT cluster_id FROM claim_cluster_membership \
             WHERE claim_id = $1 AND run_id = $2",
        )
        .bind(claim_id)
        .bind(run.run_id)
        .fetch_optional(pool)
        .await?;

        let neighborhood_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT neighborhood_id FROM claim_neighborhood_membership \
             WHERE claim_id = $1 AND run_id = $2",
        )
        .bind(claim_id)
        .bind(run.run_id)
        .fetch_optional(pool)
        .await?;

        let placed = cluster_id.is_some() || neighborhood_id.is_some();
        Ok(Some(ClaimPlacement {
            claim_id,
            theme_id,
            cluster_run_id: placed.then_some(run.run_id),
            cluster_id,
            neighborhood_id,
            run_completed_at: placed.then_some(run.completed_at),
        }))
    }
}
