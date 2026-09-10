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
//! **The plan (§4.8) says "three queries". There are nine.**
//!
//! # PR-22: the `ownership` join is gone, and the owner relation CHANGED IN BOTH
//! # DIRECTIONS
//!
//! Migration 084 retires `public.ownership`, so the eight functions that joined
//! it were rewritten here — the obligation PR-08 recorded as
//! `D-PR22-structural-ownership-join` in `docs/tenancy/progress.json`. PR-08
//! declined the plan's prescribed substitution because `ownership` carried a
//! `node_type` breakdown across six tables that `claims.owner_group_id` /
//! `claims.agent_id` cannot express. That objection was correct and it is not
//! answered here; it is **conceded**, because after 084 there is no relation
//! left that could answer it.
//!
//! **Exactly two tables name an owning agent: `claims.agent_id` and
//! `perspectives.owner_agent_id`.** Measured against the schema at migration
//! 084: `evidence`, `frames`, `contexts` and `communities` carry
//! `(visibility, owner_group_id)` and no agent column at all. So the owned-node
//! set is a two-arm `UNION ALL` over those two tables, and four `node_type`
//! values that `ownership_node_type_check` used to admit — `evidence`,
//! `community`, `context`, `frame` — can no longer appear in any count.
//!
//! That is the same fail-closed rule this module already applied to
//! `node_type = 'agent'`: a node whose owner cannot be determined is not
//! counted, because D1 forbids treating "cannot classify" as public. What
//! changed is only how many node types it reaches. **It is a narrowing of the
//! endpoint's contract and it is stated in the PR body**; the response *shape*
//! is unchanged, because `node_counts` is a list of `(node_type, count)` pairs
//! and a type with no rows simply produces none.
//!
//! Deriving evidence ownership through its parent claim's author was considered
//! and rejected: it would attribute to the owner evidence that a *different*
//! agent attached to the owner's claim, which is a wrong answer rather than a
//! missing one.
//!
//! ## …AND THE DOMINANT DIRECTION IS A WIDENING
//!
//! The four lost node types are the *visible* half of the change and the
//! smaller one. Nothing ever auto-populated `ownership`: not one of the 90
//! migration files inserts a row into it, and its only writers were
//! `OwnershipRepository::assign` / `assign_with_community`, whose HTTP route and
//! MCP tools PR-14 deleted. So the OLD owned set was "nodes for which somebody
//! explicitly wrote an ownership row" — in practice near-empty on a database
//! that never called those writers — and the NEW one is the agent's entire
//! authored corpus. [`node_counts`], [`degrees`], [`edge_counts`],
//! [`temporal_bins`], [`clustering_coefficients`], [`belief_intervals`],
//! [`frame_coverage`] and [`conflict_coefficients`] all move that way.
//!
//! **The direction is certain; the magnitude is exactly the unmeasured M1.** An
//! operator's numbers can go from near-zero to full-corpus in a single release,
//! and no test in the tree can catch it — `structural_features_authz.rs`'s
//! corpus called `seed_ownership` for every node it created, so the old and new
//! statements agree exactly on that fixture. Stating it here is the only place a
//! reader will find it before deploying.
//!
//! [`node_counts`]: StructuralRepository::node_counts
//! [`belief_intervals`]: StructuralRepository::belief_intervals
//! [`frame_coverage`]: StructuralRepository::frame_coverage
//! [`conflict_coefficients`]: StructuralRepository::conflict_coefficients
//!
//! ## THE NEW KEY IS AN AUTHOR FIELD, AND IT IS NOT A CREDENTIAL
//!
//! `claims.agent_id` is inserted from the **request body** by
//! `epigraph_api::routes::claims::create_claim`, whose own comment says at
//! length that "the body's `agent_id` is NOT a credential and never was, and
//! nothing downstream may treat it as one". `GET
//! /api/v1/structural-features/:owner_id` is now a downstream consumer of it: a
//! caller holding `claims:write` who posts a public claim naming a victim's
//! agent id has that claim counted in every subsequent structural read for the
//! victim.
//!
//! **That is attribution injection into a caller-facing read, not a
//! confidentiality leak.** Every statement here is still `AND`-ed with a
//! correctly spliced viewer predicate, so no private row and no private
//! *existence* is disclosed by it; what an attacker can do is inflate someone
//! else's public counts.
//!
//! It was accepted rather than solved because no other key preserves the
//! subject. `:owner_id` is an agent uuid and `claims.owner_group_id` is a GROUP
//! uuid, so substituting it would silently turn this into a different endpoint.
//! The honest framing of the change is not "trustworthy key → untrustworthy
//! key" but **dead-but-not-caller-settable → live-but-uncredentialed**:
//! `ownership` had no writer at all after PR-14. Recorded as a new consumer of
//! the open half of `D-PR16-claim-authorship-is-not-a-credential` in
//! `docs/tenancy/progress.json`, owned by the write-side gate.
//!
//! The two arms cannot overlap — `claims.id` and `perspectives.id` are distinct
//! primary keys in distinct tables — so `UNION ALL` neither double-counts nor
//! needs a `DISTINCT`, and [`clustering_coefficients`]' `GROUP BY node_id` sees
//! one row per node.
//!
//! ## A NODE IS A ROW, NOT A LINEAGE — and that is a change worth stating
//!
//! `ownership.node_id` named a claim **version**, not a lineage — `claims` gives
//! every version its own `id` (`claims_pkey PRIMARY KEY (id)`, plus `supersedes`
//! and `is_current`), so the `node_id PRIMARY KEY` permitted one row per
//! version and bounded nothing about a lineage. Whatever multiplicity
//! `ownership` actually carried per lineage was a property of who called
//! `assign_ownership`, not of the constraint. (An earlier revision of this
//! paragraph derived "at most one row per lineage" from the PK; that derivation
//! is wrong and the conclusion below never depended on it.)
//!
//! What matters is the `claims` arm, which has no `is_current` filter: every
//! version of a superseded lineage is a node. An author with deep lineages
//! therefore reports more nodes than before.
//!
//! No filter is added, deliberately. `edges.source_id` / `target_id` name a
//! specific claim VERSION, so counting rows is what keeps [`degrees`],
//! [`edge_counts`] and [`clustering_coefficients`] internally consistent with
//! each other: a node that can carry an edge is a node that must appear in the
//! degree distribution. Restricting to `is_current` would have been a new
//! semantic invented here, and it would have made a superseded claim's edges
//! incident on nothing.
//!
//! [`degrees`]: StructuralRepository::degrees
//!
//! ## [`temporal_bins`] now bins the NODE's `created_at`
//!
//! It used to bin `ownership.created_at`, the moment the ownership assertion was
//! written. That column is gone and has no counterpart, so the bins are now the
//! moment the node itself was created (`claims.created_at` /
//! `perspectives.created_at`). For a corpus whose ownership rows were written at
//! node creation the two agree; for one where a node changed hands they do not.
//!
//! [`temporal_bins`]: StructuralRepository::temporal_bins
//! [`clustering_coefficients`]: StructuralRepository::clustering_coefficients
//!
//! # `F-edge-count-double-counts` is CLOSED here
//!
//! [`edge_counts`] used to join `ownership` on
//! `(e.source_id = o.node_id OR e.target_id = o.node_id)`, so an edge with both
//! endpoints owned by `owner_id` was counted twice and the Laplace sensitivity
//! of the field was 2 while `maybe_add_noise` assumed 1. PR-08 and PR-13 both
//! deferred the fix to this PR — PR-13's stated reason was that 084 retires the
//! join anyway, so rewriting it earlier was work that would be thrown away.
//! The rewritten statement tests ownership with a single `EXISTS`, so each
//! visible edge contributes exactly once and the sensitivity is 1. The
//! acceptance numbers in
//! `crates/epigraph-api/tests/structural_features_authz.rs` were re-derived from
//! the corpus rather than adjusted.
//!
//! [`edge_counts`]: StructuralRepository::edge_counts
//!
//! # Every count is a VISIBLE-SET count
//!
//! Both arms of the owned-node set carry `/* {VISIBILITY:<alias>} */`, and the
//! `edges` legs carry [`Viewer::edge_predicate_fragment`] through the
//! `/* {EDGE_VISIBILITY:<alias>} */` spelling (PR-13). An edge whose two
//! endpoints belong to different groups G and H is therefore visible only to a
//! principal in BOTH, rather than to anyone in the single group the edge row's
//! `owner_group_id` happened to name.
//!
//! [`Viewer::edge_predicate_fragment`]: crate::visibility::Viewer::edge_predicate_fragment
//!
//! # No write path
//!
//! Every function here is a `SELECT`. PR-16 owns the write-side predicate and
//! nothing in this module touches it.
//!
//! # Why the owned-node union is copy-pasted rather than hoisted
//!
//! `visibility_lint.rs::every_spliced_statement_carries_the_canonical_marker_spelling`
//! requires the marker text to appear in the **body of the function that calls
//! `splice`**. Hoisting the shared fragment into a module-level `const` would
//! move it out of every body and make that check pass vacuously while the
//! statements still carried markers. The duplication is the price of keeping the
//! lint honest.

use crate::errors::DbError;
use crate::visibility::Viewer;
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
    /// Node counts by node type, restricted to nodes the viewer can see.
    ///
    /// Two types can appear — `claim` and `perspective` — because those are the
    /// only two tables that name an owning agent after migration 084. See the
    /// module docs for what left with `ownership` and why nothing replaces it.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn node_counts<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<(String, i64)>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT o.node_type, COUNT(*) as count
            FROM (
                SELECT 'claim'::text AS node_type
                FROM claims c
                WHERE c.agent_id = $1
                  /* {VISIBILITY:c} */
                UNION ALL
                SELECT 'perspective'::text
                FROM perspectives p
                WHERE p.owner_agent_id = $1
                  /* {VISIBILITY:p} */
            ) o
            GROUP BY o.node_type
            ORDER BY count DESC
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (String, i64)>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Edge counts by relationship, restricted to [`COARSE_EDGE_TYPES`], to
    /// edges the viewer can see, and to edges incident on a node the viewer can
    /// see.
    ///
    /// # One row per EDGE, not per (edge, owned endpoint) pair
    ///
    /// Ownership is tested with a single `EXISTS`, so an edge whose source AND
    /// target are both owned by `owner_id` contributes **once**. The
    /// `ownership` join this replaced was `ON (e.source_id = o.node_id OR
    /// e.target_id = o.node_id)` and counted such an edge twice, which made the
    /// Laplace sensitivity of this field 2 while `maybe_add_noise` assumed 1.
    /// That is `F-edge-count-double-counts`, deferred by PR-08 and PR-13 and
    /// closed here; see the module docs.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn edge_counts<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
            WHERE e.relationship = ANY($2)
              /* {EDGE_VISIBILITY:e} */
              AND EXISTS (
                    SELECT 1
                    FROM claims c
                    WHERE c.agent_id = $1
                      AND (c.id = e.source_id OR c.id = e.target_id)
                      /* {VISIBILITY:c} */
                    UNION ALL
                    SELECT 1
                    FROM perspectives p
                    WHERE p.owner_agent_id = $1
                      AND (p.id = e.source_id OR p.id = e.target_id)
                      /* {VISIBILITY:p} */
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
        Ok(q.fetch_all(executor).await?)
    }

    /// One row per visible owned node, carrying that node's degree counted over
    /// visible edges only.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn degrees<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
                FROM (
                    SELECT c.id AS node_id
                    FROM claims c
                    WHERE c.agent_id = $1
                      /* {VISIBILITY:c} */
                    UNION ALL
                    SELECT p.id
                    FROM perspectives p
                    WHERE p.owner_agent_id = $1
                      /* {VISIBILITY:p} */
                ) o
            ) sub
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (i64,)>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// `(belief, plausibility, pignistic_prob)` for every visible owned claim
    /// that carries a belief interval.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn belief_intervals<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<BeliefIntervalRow>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT c.belief, c.plausibility, c.pignistic_prob
            FROM claims c
            WHERE c.agent_id = $1
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
        Ok(q.fetch_all(executor).await?)
    }

    /// Number of distinct frames touched by the owner's visible claims.
    ///
    /// Both the membership row (`claim_frames`, `tier_a`) and the claim it names
    /// must be visible: a group-private membership row is itself a disclosure
    /// about the claim's placement in the graph.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn frame_coverage<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<i64, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT COUNT(DISTINCT cf.frame_id) as count
            FROM claim_frames cf
            JOIN claims c ON c.id = cf.claim_id
            WHERE c.agent_id = $1
              /* {VISIBILITY:cf} */
              /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_one(executor).await?)
    }

    /// Weekly bins of the owner's visible nodes over the last 30 days, by the
    /// NODE's `created_at`.
    ///
    /// It binned `ownership.created_at` — the moment the ownership assertion was
    /// written — until migration 084 retired that column. See the module docs
    /// for what the two differ on.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn temporal_bins<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<(String, i64)>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT
                TO_CHAR(DATE_TRUNC('week', o.created_at), 'YYYY-MM-DD') as bin_label,
                COUNT(*) as count
            FROM (
                SELECT c.created_at
                FROM claims c
                WHERE c.agent_id = $1
                  AND c.created_at >= NOW() - INTERVAL '30 days'
                  /* {VISIBILITY:c} */
                UNION ALL
                SELECT p.created_at
                FROM perspectives p
                WHERE p.owner_agent_id = $1
                  AND p.created_at >= NOW() - INTERVAL '30 days'
                  /* {VISIBILITY:p} */
            ) o
            GROUP BY DATE_TRUNC('week', o.created_at)
            ORDER BY DATE_TRUNC('week', o.created_at) ASC
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (String, i64)>(&sql).bind(owner_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
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
    #[instrument(skip(executor, viewer))]
    pub async fn clustering_coefficients<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<(f64,)>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2. Note the extra
        // parentheses around `e3`'s two-armed disjunction: without them the
        // spliced ` AND (...)` would bind to the second arm only.
        let sql = viewer.splice(
            r#"
            WITH owned_nodes AS (
                SELECT c.id AS node_id
                FROM claims c
                WHERE c.agent_id = $1
                  /* {VISIBILITY:c} */
                UNION ALL
                SELECT p.id
                FROM perspectives p
                WHERE p.owner_agent_id = $1
                  /* {VISIBILITY:p} */
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
        Ok(q.fetch_all(executor).await?)
    }

    /// Number of distinct communities the owner's visible perspectives belong
    /// to.
    ///
    /// The one statement migration 084 did not change: it always keyed on
    /// `perspectives.owner_agent_id`, which is now one of the two surviving
    /// owner relations the rest of the module was rewritten onto.
    /// `community_members` carries no tenancy
    /// columns, so both ends of the two-hop join are filtered instead — the
    /// perspective and the community are both `tier_a`.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn community_membership_count<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        Ok(q.fetch_one(executor).await?)
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
    #[instrument(skip(executor, viewer))]
    pub async fn conflict_coefficients<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        owner_id: Uuid,
    ) -> Result<Vec<(Option<f64>,)>, DbError> {
        // $1 = owner_id, so the viewer's group array binds at $2.
        let sql = viewer.splice(
            r#"
            SELECT dcb.conflict_k
            FROM ds_combined_beliefs dcb
            JOIN claims c ON c.id = dcb.claim_id
            WHERE c.agent_id = $1
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
        Ok(q.fetch_all(executor).await?)
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
