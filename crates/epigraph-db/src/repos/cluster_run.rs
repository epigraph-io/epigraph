//! The "latest cluster run" lookup, and where a claim sits inside it.
//!
//! Every graph `expand` route resolves the run the same way and answers 404
//! for anything that is not in *that* run: `routes/graph.rs` `overview`,
//! `expand` and `themes_expand`, `routes/graph_neighborhood.rs` `expand`, and
//! `GET /claims/:id/placement` all call [`ClusterRunRepository::latest`]
//! (`epigraph-api/tests/cluster_run_lookup_is_shared_test.rs` pins that none
//! of them inlines its own spelling). So the ids `placement` hands out are ones
//! `expand` accepts at that moment, and both go stale together when the next
//! run lands. `atlas_layout.rs` records the same run id on a layout run.
//!
//! "Latest" means the newest **Louvain** run: `graph_cluster_runs.algo =
//! 'louvain'` (migration 028's column default, which the `cluster_graph` jobs
//! runner relies on by not naming the column). `POST
//! /api/v1/clusters/build-from-bridges` writes `algo = 'louvain_bridge'` rows
//! into the same table; those runs have no neighbourhoods, and before the
//! filter a bridge run completing after the Louvain run became "latest" and
//! every expand route answered 404 for the real run's clusters and
//! neighbourhoods (backlog 523dcb4f). Migration 028's
//! `(algo, completed_at DESC)` index serves the filtered lookup.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

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
    /// The run every graph `expand` route treats as current: the newest
    /// completed run with `algo = 'louvain'`, or `None` when no Louvain run
    /// has completed. A `louvain_bridge` run is never current, however recent
    /// (see the module doc).
    ///
    /// # This function takes no `Viewer`, deliberately
    ///
    /// `graph_cluster_runs` is not in migration 062's `tier_a` array — it holds
    /// `(run_id, completed_at, degraded)`, an operational record of when the
    /// clusterer last finished, with no `visibility` or `owner_group_id` column
    /// a predicate could be spliced onto and no claim content in any row. The
    /// tenancy decision belongs to the membership tables this run id is then
    /// used against ([`Self::claim_placement`] below, and the `expand` routes),
    /// which ARE in `tier_a` and are filtered there.
    ///
    /// Generic over the executor rather than taking `&PgPool` so a caller
    /// holding a viewer-stamped connection can pass `&mut *read` and keep every
    /// statement of its request on the one connection.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the lookup fails.
    pub async fn latest<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
    ) -> Result<Option<ClusterRunRow>, DbError> {
        let row = sqlx::query_as::<_, ClusterRunRow>(
            "SELECT run_id, completed_at, degraded
             FROM graph_cluster_runs
             WHERE algo = 'louvain'
             ORDER BY completed_at DESC
             LIMIT 1",
        )
        .fetch_optional(executor)
        .await?;
        Ok(row)
    }

    /// Resolve `claim_id` to its theme, cluster and neighbourhood, as `viewer`
    /// may see them.
    ///
    /// Returns `None` when the claim does not exist **or** when the viewer may
    /// not read it — the caller's 404, and deliberately the same 404 either
    /// way. There is no claim text in this response, but a theme, cluster or
    /// neighbourhood id is a pointer into a view that renders that text, and an
    /// answer echoing the id back confirms the claim exists.
    ///
    /// The run fields are populated only when the claim is actually a member of
    /// something in the latest run, so "no run yet" and "clustered, but this
    /// claim was left out" both read as all-null rather than dangling a run
    /// id and a timestamp off a claim with no placement.
    ///
    /// All three statements are viewer-filtered: `claim_cluster_membership` and
    /// `claim_neighborhood_membership` are both in migration 062's `tier_a`
    /// array and carry `owner_group_id`, so a membership row is as much a
    /// tenanted row as the claim it names.
    ///
    /// `&mut PgConnection` rather than a generic executor because it runs four
    /// statements and they must describe one corpus on one stamped connection.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any of the lookups fails.
    pub async fn claim_placement(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
    ) -> Result<Option<ClaimPlacement>, DbError> {
        // `theme_id` is a column on the claim, so this doubles as the
        // existence check — and, now that it carries the predicate, as the
        // visibility check. `None` means "no such claim" and "not yours"
        // indistinguishably, which is the point.
        let claim_sql = viewer.splice(
            "SELECT c.theme_id FROM claims c WHERE c.id = $1 /* {VISIBILITY:c} */",
            2,
        );
        let mut claim_q = sqlx::query_as::<_, (Option<Uuid>,)>(&claim_sql).bind(claim_id);
        // Guarded, not `unwrap_or(&[])`: a Bypass viewer renders no `$2`, and
        // an unconditional bind is an arity error rather than a wider read.
        if let Some(g) = viewer.group_bind() {
            claim_q = claim_q.bind(g);
        }
        let claim: Option<(Option<Uuid>,)> = claim_q.fetch_optional(&mut *conn).await?;
        let Some((theme_id,)) = claim else {
            return Ok(None);
        };

        let Some(run) = Self::latest(&mut *conn).await? else {
            return Ok(Some(ClaimPlacement {
                claim_id,
                theme_id,
                cluster_run_id: None,
                cluster_id: None,
                neighborhood_id: None,
                run_completed_at: None,
            }));
        };

        let cluster_sql = viewer.splice(
            "SELECT m.cluster_id FROM claim_cluster_membership m \
             WHERE m.claim_id = $1 AND m.run_id = $2 /* {VISIBILITY:m} */",
            3,
        );
        let mut cluster_q = sqlx::query_scalar::<_, Uuid>(&cluster_sql)
            .bind(claim_id)
            .bind(run.run_id);
        if let Some(g) = viewer.group_bind() {
            cluster_q = cluster_q.bind(g);
        }
        let cluster_id: Option<Uuid> = cluster_q.fetch_optional(&mut *conn).await?;

        let neighborhood_sql = viewer.splice(
            "SELECT n.neighborhood_id FROM claim_neighborhood_membership n \
             WHERE n.claim_id = $1 AND n.run_id = $2 /* {VISIBILITY:n} */",
            3,
        );
        let mut neighborhood_q = sqlx::query_scalar::<_, Uuid>(&neighborhood_sql)
            .bind(claim_id)
            .bind(run.run_id);
        if let Some(g) = viewer.group_bind() {
            neighborhood_q = neighborhood_q.bind(g);
        }
        let neighborhood_id: Option<Uuid> = neighborhood_q.fetch_optional(&mut *conn).await?;

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
