//! Structural (topology-only) aggregates for one owner's subgraph.
//!
//! Backs `GET /api/v1/structural-features/:owner_id`
//! (`epigraph_api::routes::structural::get_structural_features`). The endpoint
//! returns node/edge counts, degree and clustering distributions, belief-interval
//! and conflict statistics — no claim text — with an optional Laplace mechanism
//! applied in the route layer.
//!
//! # Why these nine functions exist here rather than in the route
//!
//! Until PR-08 all nine statements were inline `sqlx::query_as` calls in
//! `crates/epigraph-api/src/routes/structural.rs`, and none of them filtered by
//! visibility: every one keyed only on `ownership.owner_id`. The repo CLAUDE.md
//! requires SQL to live here, and — more to the point — a `&Viewer` cannot be
//! spent by a statement the repo layer never sees.
//!
//! **The plan (§4.8) says "three queries". There are nine.** The three it names
//! are the three that join `ownership`; five more join `ownership` too, and a
//! ninth (`community_membership_count`) reaches the owner through
//! `perspectives.owner_agent_id` and never touches `ownership` at all. Filtering
//! three and leaving six is the `belief_at_time` single-spend shape, so all nine
//! are converted.
//!
//! # DEVIATION from plan §4.8: the `ownership` join is KEPT, not replaced
//!
//! Plan §4.8 step 2 says, verbatim: *"the `ownership` join is replaced by
//! `claims.owner_group_id` / `claims.agent_id`"*, and gives its rationale in the
//! same paragraph — `ownership` *"is dropped by PR-22"*.
//!
//! **That instruction is not followed here, deliberately.** All eight
//! `ownership`-touching functions still read `FROM ownership o WHERE
//! o.owner_id = $1` or `JOIN ownership o`; what changed is that each now
//! additionally requires the owned node to be visible in its own table (the
//! `node_type`-dispatched `EXISTS` described below). Two reasons the
//! substitution is not available:
//!
//! * The endpoint returns a **breakdown by `ownership.node_type`** across six
//!   tables (`claims`, `evidence`, `perspectives`, `communities`, `contexts`,
//!   `frames`). `claims.owner_group_id` / `claims.agent_id` describe claims
//!   only, so they cannot produce that breakdown at all — five of the seven
//!   node types would silently vanish from `node_counts`.
//! * [`temporal_bins`] bins on **`ownership.created_at`**, which has no
//!   counterpart on `claims`; `claims.created_at` is the claim's creation, not
//!   the ownership assertion's.
//!
//! The deviation is recorded here AND in `docs/tenancy/progress.json`
//! (`prs.done` PR-08 `files_line_reconciliation`), with a `deferred_obligations`
//! entry, because the consequence outlives this PR: **when PR-22 drops
//! `ownership`, all eight functions in this module must be rewritten**, and
//! nothing else in the tree records that.
//!
//! # `ownership` is not `tier_a`, and that shapes four of the nine
//!
//! Migration 062 gives `visibility` / `owner_group_id` to `claims`, `evidence`,
//! `edges`, `frames`, `contexts`, `perspectives`, `communities`,
//! `claim_frames`, `ds_combined_beliefs` and the rest of `tier_a`. It does NOT
//! give them to `ownership`, to `community_members`, or to `agents`. So
//! `Viewer::predicate_fragment` — which names `{alias}.visibility` and
//! `{alias}.owner_group_id` — has nothing to bind to on an `ownership` row.
//!
//! [`StructuralRepository::node_counts`], [`temporal_bins`], [`degrees`] and
//! [`clustering_coefficients`] enumerate `ownership` directly. Rather than
//! annotate them `VISIBILITY-EXEMPT:` — which `visibility_lint.rs` says is
//! presumptively "a leak being annotated rather than fixed" on a read path —
//! each requires the owned node to be visible **in its own table**, via a
//! `node_type`-dispatched `EXISTS` over the six `tier_a` tables
//! `ownership_node_type_check` admits (`claims`, `evidence`, `perspectives`,
//! `communities`, `contexts`, `frames`).
//!
//! Two classes of row therefore drop out of those four counts, deliberately and
//! fail-closed:
//!
//! * `node_type = 'agent'` — `agents` carries no tenancy columns, so there is no
//!   predicate that could decide it. D1 forbids treating "cannot classify" as
//!   public.
//! * an `ownership` row whose `node_id` names no surviving row — `ownership` has
//!   no FK to the tables it points at, so these exist. The `EXISTS` drops them.
//!
//! [`temporal_bins`]: StructuralRepository::temporal_bins
//! [`degrees`]: StructuralRepository::degrees
//! [`clustering_coefficients`]: StructuralRepository::clustering_coefficients
//!
//! # Recorded residual: `edges` — the co-ownership half is closed
//!
//! [`edge_counts`], [`degrees`] and [`clustering_coefficients`] now filter
//! `edges` with [`Viewer::edge_predicate_fragment`], through the
//! `/* {EDGE_VISIBILITY:<alias>} */` spelling (PR-13). An edge whose two
//! endpoints belong to different groups G and H is therefore visible only to a
//! principal in BOTH, rather than to anyone in the single group the edge row's
//! `owner_group_id` happened to name.
//!
//! What is NOT fixed here is `F-edge-count-double-counts`: [`edge_counts`]
//! joins `ownership` on `(e.source_id = o.node_id OR e.target_id = o.node_id)`,
//! so an edge whose two endpoints are both owned by `owner_id` is counted
//! twice, and `maybe_add_noise` assumes a Laplace sensitivity of 1. PR-08
//! declined it because fixing it rewrites the acceptance numbers in
//! `structural_features_authz.rs`; PR-13 declines it for the same reason plus
//! one more — PR-22's migration 084 retires `ownership`, so a rewrite of this
//! join now is work that gets thrown away. Still open in
//! `docs/tenancy/progress.json`, re-assigned there.
//!
//! [`edge_counts`]: StructuralRepository::edge_counts
//! [`Viewer::edge_predicate_fragment`]: crate::visibility::Viewer::edge_predicate_fragment
//!
//! # No write path
//!
//! Every function here is a `SELECT`. PR-16 owns the write-side predicate and
//! nothing in this module touches it.
//!
//! # Why the `node_type` disjunction is copy-pasted four times
//!
//! `visibility_lint.rs::every_spliced_statement_carries_the_canonical_marker_spelling`
//! requires the marker text to appear in the **body of the function that calls
//! `splice`**. Hoisting the shared fragment into a module-level `const` would
//! move it out of all four bodies and make that check pass vacuously while the
//! statements still carried markers. The duplication is the price of keeping the
//! lint honest.

use crate::errors::DbError;
use crate::visibility::Viewer;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Coarse edge types from §1.2 — the only relationship types exposed through
/// privacy-preserving structural queries.
///
/// Moved here from `crate::access_control` by PR-08 (plan §4.8: "the constant
/// survives"), because after the SQL moved into this module
/// [`StructuralRepository::edge_counts`] is its only consumer.
///
/// PR-08 left three re-export hops behind so the old paths kept resolving, and
/// registered the cost as `F-coarse-edge-types-reexport-shim` on the grounds
/// that `access_control.rs` was annotated for deletion in PR-14 and the unwind
/// belonged in one place. **PR-14 deleted the module and all three hops.** This
/// declaration and `epigraph_db::COARSE_EDGE_TYPES` (re-exported from
/// `repos::mod`) are now the only ways to name it.
pub const COARSE_EDGE_TYPES: &[&str] = &[
    "SUPPORTS",
    "CONTRADICTS",
    "RELATES_TO",
    "DERIVED_FROM",
    "GENERATED_BY",
    "PERSPECTIVE_OF",
    "CONTRIBUTES_TO",
    "MEMBER_OF",
    "SCOPED_BY",
    "WITHIN_FRAME",
    // Political network monitoring edge types
    "ORIGINATED_BY",
    "AMPLIFIED_BY",
    "COORDINATED_WITH",
    "USES_TECHNIQUE",
    "MIRROR_NARRATIVE",
];

/// One visible owned claim's Dempster-Shafer interval:
/// `(belief, plausibility, pignistic_prob)`.
///
/// A transparent alias for the tuple, not a new struct. The route layer's
/// `compute_belief_stats` consumes `&[(Option<f64>, Option<f64>, Option<f64>)]`
/// and is unchanged by PR-08; naming the tuple satisfies
/// `clippy::type_complexity` without moving statistics code the PR has no
/// reason to touch.
pub type BeliefIntervalRow = (Option<f64>, Option<f64>, Option<f64>);

/// Read-only structural aggregates over one owner's subgraph.
pub struct StructuralRepository;

impl StructuralRepository {
    /// Node counts by `ownership.node_type`, restricted to nodes the viewer can
    /// see in the node's own table.
    ///
    /// `node_type = 'agent'` rows and rows pointing at a deleted node are
    /// excluded — see the module docs.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn node_counts(
        pool: &PgPool,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<(String, i64)>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT o.node_type, COUNT(*) as count
            FROM ownership o
            WHERE o.owner_id = $1
              AND (
                   (o.node_type = 'claim'
                    AND EXISTS (SELECT 1 FROM claims vc
                                WHERE vc.id = o.node_id /* {VISIBILITY:vc} */))
                OR (o.node_type = 'evidence'
                    AND EXISTS (SELECT 1 FROM evidence ve
                                WHERE ve.id = o.node_id /* {VISIBILITY:ve} */))
                OR (o.node_type = 'perspective'
                    AND EXISTS (SELECT 1 FROM perspectives vp
                                WHERE vp.id = o.node_id /* {VISIBILITY:vp} */))
                OR (o.node_type = 'community'
                    AND EXISTS (SELECT 1 FROM communities vm
                                WHERE vm.id = o.node_id /* {VISIBILITY:vm} */))
                OR (o.node_type = 'context'
                    AND EXISTS (SELECT 1 FROM contexts vx
                                WHERE vx.id = o.node_id /* {VISIBILITY:vx} */))
                OR (o.node_type = 'frame'
                    AND EXISTS (SELECT 1 FROM frames vf
                                WHERE vf.id = o.node_id /* {VISIBILITY:vf} */))
              )
            GROUP BY o.node_type
            ORDER BY count DESC
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (String, i64)>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
    }

    /// Edge counts by relationship, restricted to [`COARSE_EDGE_TYPES`], to
    /// edges the viewer can see, and to edges incident on a node the viewer can
    /// see.
    ///
    /// # The count is per (edge, owned endpoint) pair, NOT per edge
    ///
    /// The join is `ON (e.source_id = o.node_id OR e.target_id = o.node_id)`, so
    /// an edge whose source AND target are both owned by `owner_id` is counted
    /// **twice**. This is inherited verbatim from the pre-PR-08 inline statement
    /// and is not introduced here, but PR-08 is the first thing to pin it as
    /// expected output (`structural_features_authz.rs` asserts `SUPPORTS == 4`
    /// for two seeded edges), so it is stated rather than left for the next
    /// reader to rediscover from "edge counts by relationship".
    ///
    /// One consequence for the route layer: the Laplace sensitivity of this
    /// field is 2, not 1, because adding one both-endpoints-owned edge changes
    /// the count by two. `maybe_add_noise` assumes sensitivity 1. Still open as
    /// `F-edge-count-double-counts`. PR-13 rewrote this statement's `edges`
    /// PREDICATE and deliberately not its `ownership` JOIN — see the module docs
    /// for why (the acceptance numbers, and PR-22 retiring `ownership`).
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn edge_counts(
        pool: &PgPool,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<(String, i64)>, DbError> {
        let coarse_types: Vec<String> =
            COARSE_EDGE_TYPES.iter().map(|s| (*s).to_string()).collect();
        // $1 = owner_id, $2 = coarse relationship names, so the viewer's group
        // array binds at $3. This is the only statement in the module with two
        // pre-existing binds.
        let sql = viewer.splice(
            r#"
            SELECT e.relationship, COUNT(*) as count
            FROM edges e
            JOIN ownership o ON (e.source_id = o.node_id OR e.target_id = o.node_id)
            WHERE o.owner_id = $1
              AND e.relationship = ANY($2)
              /* {EDGE_VISIBILITY:e} */
              AND (
                   (o.node_type = 'claim'
                    AND EXISTS (SELECT 1 FROM claims vc
                                WHERE vc.id = o.node_id /* {VISIBILITY:vc} */))
                OR (o.node_type = 'evidence'
                    AND EXISTS (SELECT 1 FROM evidence ve
                                WHERE ve.id = o.node_id /* {VISIBILITY:ve} */))
                OR (o.node_type = 'perspective'
                    AND EXISTS (SELECT 1 FROM perspectives vp
                                WHERE vp.id = o.node_id /* {VISIBILITY:vp} */))
                OR (o.node_type = 'community'
                    AND EXISTS (SELECT 1 FROM communities vm
                                WHERE vm.id = o.node_id /* {VISIBILITY:vm} */))
                OR (o.node_type = 'context'
                    AND EXISTS (SELECT 1 FROM contexts vx
                                WHERE vx.id = o.node_id /* {VISIBILITY:vx} */))
                OR (o.node_type = 'frame'
                    AND EXISTS (SELECT 1 FROM frames vf
                                WHERE vf.id = o.node_id /* {VISIBILITY:vf} */))
              )
            GROUP BY e.relationship
            ORDER BY count DESC
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, (String, i64)>(&sql)
            .bind(owner_id)
            .bind(&coarse_types);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
    }

    /// One row per visible owned node, carrying that node's degree counted over
    /// visible edges only.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn degrees(
        pool: &PgPool,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<(i64,)>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2. The degree
        // subquery's `OR` is parenthesised so the spliced ` AND (...)` applies
        // to the whole disjunction rather than only to its right arm.
        let sql = viewer.splice(
            r#"
            SELECT COALESCE(deg, 0) as degree FROM (
                SELECT o.node_id,
                       (SELECT COUNT(*) FROM edges e
                         WHERE (e.source_id = o.node_id OR e.target_id = o.node_id)
                           /* {EDGE_VISIBILITY:e} */) as deg
                FROM ownership o
                WHERE o.owner_id = $1
                  AND (
                       (o.node_type = 'claim'
                        AND EXISTS (SELECT 1 FROM claims vc
                                    WHERE vc.id = o.node_id /* {VISIBILITY:vc} */))
                    OR (o.node_type = 'evidence'
                        AND EXISTS (SELECT 1 FROM evidence ve
                                    WHERE ve.id = o.node_id /* {VISIBILITY:ve} */))
                    OR (o.node_type = 'perspective'
                        AND EXISTS (SELECT 1 FROM perspectives vp
                                    WHERE vp.id = o.node_id /* {VISIBILITY:vp} */))
                    OR (o.node_type = 'community'
                        AND EXISTS (SELECT 1 FROM communities vm
                                    WHERE vm.id = o.node_id /* {VISIBILITY:vm} */))
                    OR (o.node_type = 'context'
                        AND EXISTS (SELECT 1 FROM contexts vx
                                    WHERE vx.id = o.node_id /* {VISIBILITY:vx} */))
                    OR (o.node_type = 'frame'
                        AND EXISTS (SELECT 1 FROM frames vf
                                    WHERE vf.id = o.node_id /* {VISIBILITY:vf} */))
                  )
            ) sub
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (i64,)>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
    }

    /// `(belief, plausibility, pignistic_prob)` for every visible owned claim
    /// that carries a belief interval.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn belief_intervals(
        pool: &PgPool,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<BeliefIntervalRow>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT c.belief, c.plausibility, c.pignistic_prob
            FROM claims c
            JOIN ownership o ON o.node_id = c.id
            WHERE o.owner_id = $1
              AND o.node_type = 'claim'
              AND c.belief IS NOT NULL
              AND c.plausibility IS NOT NULL
              /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, BeliefIntervalRow>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
    }

    /// Number of distinct frames touched by the owner's visible claims.
    ///
    /// Both the membership row (`claim_frames`, `tier_a`) and the claim it names
    /// must be visible: a group-private membership row is itself a disclosure
    /// about the claim's placement in the graph.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn frame_coverage(
        pool: &PgPool,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<i64, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT COUNT(DISTINCT cf.frame_id) as count
            FROM claim_frames cf
            JOIN ownership o ON o.node_id = cf.claim_id
            JOIN claims c ON c.id = cf.claim_id
            WHERE o.owner_id = $1
              AND o.node_type = 'claim'
              /* {VISIBILITY:cf} */
              /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_one(pool).await?)
    }

    /// Weekly bins of `ownership.created_at` over the last 30 days, restricted
    /// to visible owned nodes.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn temporal_bins(
        pool: &PgPool,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<(String, i64)>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT
                TO_CHAR(DATE_TRUNC('week', o.created_at), 'YYYY-MM-DD') as bin_label,
                COUNT(*) as count
            FROM ownership o
            WHERE o.owner_id = $1
              AND o.created_at >= NOW() - INTERVAL '30 days'
              AND (
                   (o.node_type = 'claim'
                    AND EXISTS (SELECT 1 FROM claims vc
                                WHERE vc.id = o.node_id /* {VISIBILITY:vc} */))
                OR (o.node_type = 'evidence'
                    AND EXISTS (SELECT 1 FROM evidence ve
                                WHERE ve.id = o.node_id /* {VISIBILITY:ve} */))
                OR (o.node_type = 'perspective'
                    AND EXISTS (SELECT 1 FROM perspectives vp
                                WHERE vp.id = o.node_id /* {VISIBILITY:vp} */))
                OR (o.node_type = 'community'
                    AND EXISTS (SELECT 1 FROM communities vm
                                WHERE vm.id = o.node_id /* {VISIBILITY:vm} */))
                OR (o.node_type = 'context'
                    AND EXISTS (SELECT 1 FROM contexts vx
                                WHERE vx.id = o.node_id /* {VISIBILITY:vx} */))
                OR (o.node_type = 'frame'
                    AND EXISTS (SELECT 1 FROM frames vf
                                WHERE vf.id = o.node_id /* {VISIBILITY:vf} */))
              )
            GROUP BY DATE_TRUNC('week', o.created_at)
            ORDER BY DATE_TRUNC('week', o.created_at) ASC
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (String, i64)>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
    }

    /// Local clustering coefficient for every visible owned node of visible
    /// degree >= 2, computed over visible edges only.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    ///
    /// Before PR-08 this statement ended `.unwrap_or_default()`, so a database
    /// error rendered as "this owner has no clustering" — the same
    /// laundering-Err-into-a-benign-answer shape PR-05 removed from
    /// `check_content_access`. With a spliced predicate in the statement that is
    /// no longer merely untidy: a bind or splice mistake would return silent
    /// zeros instead of failing.
    ///
    /// # The `::double precision` casts are load-bearing, and finding out why is
    /// # what removing `.unwrap_or_default()` bought
    ///
    /// `2.0` and `1.0` are `numeric` literals in Postgres, so the original
    /// `COALESCE(2.0 * tri_count / (deg * (deg - 1.0)), 0.0)` had type `numeric`
    /// — which `sqlx` cannot decode into `f64`. Every request over a subgraph
    /// containing an actual triangle therefore returned `Err`, and
    /// `.unwrap_or_default()` turned it into an empty distribution. The endpoint
    /// has always reported `clustering_stats: {mean: 0, variance: 0,
    /// eligible_nodes: 0}` for exactly the graphs the statistic was written to
    /// describe, and no test could see it. The casts fix the decode; propagating
    /// the error is what made the bug observable at all.
    #[instrument(skip(pool, viewer))]
    pub async fn clustering_coefficients(
        pool: &PgPool,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<(f64,)>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2. Note the extra
        // parentheses around `e3`'s two-armed disjunction: without them the
        // spliced ` AND (...)` would bind to the second arm only.
        let sql = viewer.splice(
            r#"
            WITH owned_nodes AS (
                SELECT o.node_id
                FROM ownership o
                WHERE o.owner_id = $1
                  AND (
                       (o.node_type = 'claim'
                        AND EXISTS (SELECT 1 FROM claims vc
                                    WHERE vc.id = o.node_id /* {VISIBILITY:vc} */))
                    OR (o.node_type = 'evidence'
                        AND EXISTS (SELECT 1 FROM evidence ve
                                    WHERE ve.id = o.node_id /* {VISIBILITY:ve} */))
                    OR (o.node_type = 'perspective'
                        AND EXISTS (SELECT 1 FROM perspectives vp
                                    WHERE vp.id = o.node_id /* {VISIBILITY:vp} */))
                    OR (o.node_type = 'community'
                        AND EXISTS (SELECT 1 FROM communities vm
                                    WHERE vm.id = o.node_id /* {VISIBILITY:vm} */))
                    OR (o.node_type = 'context'
                        AND EXISTS (SELECT 1 FROM contexts vx
                                    WHERE vx.id = o.node_id /* {VISIBILITY:vx} */))
                    OR (o.node_type = 'frame'
                        AND EXISTS (SELECT 1 FROM frames vf
                                    WHERE vf.id = o.node_id /* {VISIBILITY:vf} */))
                  )
            ),
            node_degrees AS (
                SELECT o.node_id, COUNT(*) as deg
                FROM owned_nodes o
                JOIN edges e ON (e.source_id = o.node_id OR e.target_id = o.node_id)
                             /* {EDGE_VISIBILITY:e} */
                GROUP BY o.node_id
                HAVING COUNT(*) >= 2
            ),
            triangles AS (
                SELECT nd.node_id, nd.deg,
                       COUNT(*) as tri_count
                FROM node_degrees nd
                JOIN edges e1 ON (e1.source_id = nd.node_id OR e1.target_id = nd.node_id)
                              /* {EDGE_VISIBILITY:e1} */
                JOIN edges e2 ON (e2.source_id = nd.node_id OR e2.target_id = nd.node_id)
                             AND e2.id > e1.id
                              /* {EDGE_VISIBILITY:e2} */
                WHERE EXISTS (
                    SELECT 1 FROM edges e3
                    WHERE ((e3.source_id = CASE WHEN e1.source_id = nd.node_id THEN e1.target_id ELSE e1.source_id END
                       AND e3.target_id = CASE WHEN e2.source_id = nd.node_id THEN e2.target_id ELSE e2.source_id END)
                       OR (e3.source_id = CASE WHEN e2.source_id = nd.node_id THEN e2.target_id ELSE e2.source_id END
                       AND e3.target_id = CASE WHEN e1.source_id = nd.node_id THEN e1.target_id ELSE e1.source_id END))
                       /* {EDGE_VISIBILITY:e3} */
                )
                GROUP BY nd.node_id, nd.deg
            )
            SELECT COALESCE(
                     2.0::double precision * tri_count
                       / (deg * (deg - 1.0::double precision)),
                     0.0::double precision) as cc
            FROM triangles
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (f64,)>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
    }

    /// Number of distinct communities the owner's visible perspectives belong
    /// to.
    ///
    /// The only statement here that never touches `ownership`: it keys on
    /// `perspectives.owner_agent_id`. `community_members` carries no tenancy
    /// columns, so both ends of the two-hop join are filtered instead — the
    /// perspective and the community are both `tier_a`.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn community_membership_count(
        pool: &PgPool,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<i64, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT COUNT(DISTINCT cm.community_id) as count
            FROM community_members cm
            JOIN perspectives p ON p.id = cm.perspective_id
            JOIN communities cy ON cy.id = cm.community_id
            WHERE p.owner_agent_id = $1
              /* {VISIBILITY:p} */
              /* {VISIBILITY:cy} */
            "#,
            2,
        );
        let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_one(pool).await?)
    }

    /// Conflict coefficients of the global combined beliefs of the owner's
    /// visible claims.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    ///
    /// Like [`Self::clustering_coefficients`], this replaced an
    /// `.unwrap_or_default()` that turned a query error into an empty
    /// distribution.
    #[instrument(skip(pool, viewer))]
    pub async fn conflict_coefficients(
        pool: &PgPool,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<(Option<f64>,)>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT dcb.conflict_k
            FROM ds_combined_beliefs dcb
            JOIN ownership o ON o.node_id = dcb.claim_id
            JOIN claims c ON c.id = dcb.claim_id
            WHERE o.owner_id = $1
              AND o.node_type = 'claim'
              AND dcb.scope_type = 'global'
              AND dcb.conflict_k IS NOT NULL
              /* {VISIBILITY:dcb} */
              /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (Option<f64>,)>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Moved here from `access_control.rs` with the constant (plan PR-08:
    /// "the two existing `COARSE_EDGE_TYPES` assertions move with the
    /// constant").
    #[test]
    fn coarse_edge_types_has_expected_count() {
        assert_eq!(COARSE_EDGE_TYPES.len(), 15);
        assert!(COARSE_EDGE_TYPES.contains(&"SUPPORTS"));
        assert!(COARSE_EDGE_TYPES.contains(&"CONTRADICTS"));
        assert!(COARSE_EDGE_TYPES.contains(&"SCOPED_BY"));
        assert!(COARSE_EDGE_TYPES.contains(&"WITHIN_FRAME"));
        assert!(COARSE_EDGE_TYPES.contains(&"ORIGINATED_BY"));
        assert!(COARSE_EDGE_TYPES.contains(&"AMPLIFIED_BY"));
        assert!(COARSE_EDGE_TYPES.contains(&"USES_TECHNIQUE"));
    }

    /// Moved here from `epigraph_api::routes::structural` with the filter it
    /// guards: `edge_counts` binds this list as `$2`, so a lower-case or
    /// mis-cased entry would silently match nothing.
    #[test]
    fn coarse_edge_types_used_in_filter() {
        for t in COARSE_EDGE_TYPES {
            assert!(
                t.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "Edge type should be SCREAMING_SNAKE: {t}"
            );
        }
    }

    // A third test lived here until PR-14: `access_control_reexport_is_the_same
    // _constant`, a pointer-identity assertion that `crate::access_control`'s
    // re-export still named THIS constant. PR-08 moved the constant here and
    // left that re-export hop in place because the file map annotated
    // `access_control.rs` as deleted-in-PR-14 and the unwind belonged in one
    // place (`progress.json::F-coarse-edge-types-reexport-shim`). PR-14 deleted
    // the module, so the hop and its guard are both gone; the two tests above
    // are the ones that were ever about the constant's CONTENT.
}
