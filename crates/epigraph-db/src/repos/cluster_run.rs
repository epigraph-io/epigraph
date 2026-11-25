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
//!
//! # The bridge run (`algo = 'louvain_bridge'`)
//!
//! [`ClusterRunRepository::bridge_edges`], [`ClusterRunRepository::bridge_paragraphs`],
//! [`ClusterRunRepository::insert_bridge_run`] and
//! [`ClusterRunRepository::gc_bridge_runs`] are the SQL of `POST
//! /api/v1/clusters/build-from-bridges`, which used to run them inline in the
//! route on the raw pool with no viewer (backlog 67c905a3 and 04ab6607). The
//! handler now runs all four on ONE transaction stamped with the caller's
//! viewer: the two reads splice it, so a paragraph the caller cannot read is
//! not a node and an edge it cannot read is not a bridge, and the writes are
//! decided by row security against the same stamp. A membership row inherits
//! its claim's tenancy (migration 070's `epigraph_inherit_tenancy_stmt`), so a
//! run can only be committed by a caller who may write every paragraph it
//! clusters; a refusal (`42501`) aborts the whole transaction.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

/// `graph_cluster_runs.algo` for a bridge run, distinguishing it from the
/// nightly SUPPORTS/CONTRADICTS Louvain run (`algo = 'louvain'`, which
/// [`ClusterRunRepository::latest`] serves).
pub const ALGO_LOUVAIN_BRIDGE: &str = "louvain_bridge";

/// One bridge between two paragraph-level claims: the number of atoms both
/// decompose into. `para_a < para_b`, so each unordered pair appears once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct BridgeEdgeRow {
    pub para_a: Uuid,
    pub para_b: Uuid,
    pub weight: i64,
}

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

    /// The bridge graph's edges, as `viewer` may see them: for each pair of
    /// paragraph-level claims (`properties->>'level' = 2`), the number of atom
    /// children they share through `decomposes_to`, kept when it is at least
    /// `min_shared_atoms`.
    ///
    /// Both the `decomposes_to` edge (`{EDGE_VISIBILITY:e}`) and the paragraph
    /// (`{VISIBILITY:p}`) are filtered, inside the CTE, so a bridge exists only
    /// through edges the viewer can read between paragraphs it can read. The
    /// atom itself is not joined: an edge to an atom private to another group
    /// is stamped with that group by the edge trigger, so the edge marker is
    /// what hides it.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn bridge_edges(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        min_shared_atoms: i64,
    ) -> Result<Vec<BridgeEdgeRow>, DbError> {
        let sql = viewer.splice(
            "WITH atom_parents AS (
                SELECT e.target_id AS atom_id, e.source_id AS paragraph_id
                FROM edges e
                JOIN claims p ON p.id = e.source_id
                WHERE e.relationship = 'decomposes_to'
                  AND (p.properties->>'level')::int = 2
                  /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:p} */
            )
            SELECT
                a.paragraph_id  AS para_a,
                b.paragraph_id  AS para_b,
                COUNT(*)::bigint AS weight
            FROM atom_parents a
            JOIN atom_parents b
                ON a.atom_id = b.atom_id
               AND a.paragraph_id < b.paragraph_id
            GROUP BY a.paragraph_id, b.paragraph_id
            HAVING COUNT(*) >= $1",
            2,
        );
        let mut q = sqlx::query_as::<_, BridgeEdgeRow>(&sql).bind(min_shared_atoms);
        // Guarded: a Bypass viewer renders no `$2`, and an unconditional bind
        // is an arity error rather than a wider read.
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }

    /// The bridge graph's nodes, as `viewer` may see them: every
    /// paragraph-level claim with at least one `decomposes_to` atom child,
    /// through an edge the viewer can read. A paragraph with no bridge is still
    /// a node (it gets a cluster of its own).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn bridge_paragraphs(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
    ) -> Result<Vec<Uuid>, DbError> {
        let sql = viewer.splice(
            "SELECT DISTINCT e.source_id
             FROM edges e
             JOIN claims p ON p.id = e.source_id
             WHERE e.relationship = 'decomposes_to'
               AND (p.properties->>'level')::int = 2
               /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:p} */",
            1,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }

    /// Write one bridge run: a `graph_cluster_runs` row with
    /// `algo = 'louvain_bridge'`, one `graph_clusters` row per community, and
    /// one `claim_cluster_membership` row per `(paragraph, community)` in
    /// `assignments`. Returns the new run id.
    ///
    /// Runs on the caller's connection, which the route has stamped. The
    /// membership rows take their tenancy from the paragraph (migration 070),
    /// so row security admits them only for paragraphs the stamp may write.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any insert fails, including a `42501`
    /// refusal from row security.
    pub async fn insert_bridge_run(
        conn: &mut sqlx::PgConnection,
        assignments: &[(Uuid, u32)],
    ) -> Result<Uuid, DbError> {
        use std::collections::BTreeMap;

        let run_id = Uuid::new_v4();

        // Community -> its cluster id, in community order so the rows are
        // written deterministically.
        let mut sizes: BTreeMap<u32, i32> = BTreeMap::new();
        for (_, comm) in assignments {
            *sizes.entry(*comm).or_default() += 1;
        }

        // `degraded` is FALSE for bridge runs: an empty graph is zero
        // clusters, the truthful answer, not a fallback.
        sqlx::query(
            "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded, algo)
             VALUES ($1, $2, FALSE, $3)",
        )
        .bind(run_id)
        .bind(i32::try_from(sizes.len()).unwrap_or(i32::MAX))
        .bind(ALGO_LOUVAIN_BRIDGE)
        .execute(&mut *conn)
        .await?;

        let mut cluster_ids: BTreeMap<u32, Uuid> = BTreeMap::new();
        let mut ids: Vec<Uuid> = Vec::with_capacity(sizes.len());
        let mut labels: Vec<String> = Vec::with_capacity(sizes.len());
        let mut cluster_sizes: Vec<i32> = Vec::with_capacity(sizes.len());
        for (comm, size) in &sizes {
            let id = Uuid::new_v4();
            cluster_ids.insert(*comm, id);
            ids.push(id);
            labels.push(format!("bridge-cluster-{comm}"));
            cluster_sizes.push(*size);
        }
        if !ids.is_empty() {
            sqlx::query(
                "INSERT INTO graph_clusters
                 (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded)
                 SELECT u.id, $2, u.label, u.size, NULL, 'paragraph', NULL, FALSE
                 FROM UNNEST($1::uuid[], $3::text[], $4::int[]) AS u(id, label, size)",
            )
            .bind(&ids)
            .bind(run_id)
            .bind(&labels)
            .bind(&cluster_sizes)
            .execute(&mut *conn)
            .await?;
        }

        if !assignments.is_empty() {
            let claim_ids: Vec<Uuid> = assignments.iter().map(|(id, _)| *id).collect();
            let member_clusters: Vec<Uuid> = assignments
                .iter()
                .map(|(_, comm)| cluster_ids[comm])
                .collect();
            sqlx::query(
                "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id)
                 SELECT u.claim_id, u.cluster_id, $3
                 FROM UNNEST($1::uuid[], $2::uuid[]) AS u(claim_id, cluster_id)",
            )
            .bind(&claim_ids)
            .bind(&member_clusters)
            .bind(run_id)
            .execute(&mut *conn)
            .await?;
        }

        Ok(run_id)
    }

    /// Garbage-collect old bridge runs, keeping the newest `retain` by
    /// `completed_at`. Scoped by `algo`, so the nightly Louvain runs are never
    /// touched.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any delete fails.
    pub async fn gc_bridge_runs(conn: &mut sqlx::PgConnection, retain: u32) -> Result<(), DbError> {
        sqlx::query(
            "WITH old AS (
                SELECT run_id FROM graph_cluster_runs
                WHERE algo = $2
                ORDER BY completed_at DESC
                OFFSET $1
            )
            DELETE FROM graph_cluster_runs WHERE run_id IN (SELECT run_id FROM old)",
        )
        .bind(i64::from(retain))
        .bind(ALGO_LOUVAIN_BRIDGE)
        .execute(&mut *conn)
        .await?;

        // Cascade by hand: `graph_clusters.run_id` and
        // `claim_cluster_membership.run_id` are not foreign keys to
        // `graph_cluster_runs`; only `claim_cluster_membership.cluster_id`
        // cascades.
        //
        // ZERO ROWS IS FINE HERE (W10 sweep). On the application role this
        // membership DELETE is owner-scoped (migration 115) and may match
        // nothing without an error. Nothing is lost: every membership row hangs
        // off a `graph_clusters` row of the same run, and the `graph_clusters`
        // DELETE below removes those memberships through
        // `claim_cluster_membership_cluster_id_fkey ON DELETE CASCADE`, a
        // referential action that consults no policy. This statement runs
        // first only so a privileged session does the work without the
        // cascade.
        sqlx::query(
            "DELETE FROM claim_cluster_membership
             WHERE run_id NOT IN (SELECT run_id FROM graph_cluster_runs)",
        )
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "DELETE FROM graph_clusters
             WHERE run_id NOT IN (SELECT run_id FROM graph_cluster_runs)",
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
}
