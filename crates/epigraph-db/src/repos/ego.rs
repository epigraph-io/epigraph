//! Depth-1 ego neighbourhood of a claim: a balanced, degree-capped edge fetch
//! plus one hydration query per entity table.
//!
//! This exists because `GET /api/v1/claims/:id/neighborhood`
//! (`routes/edges.rs`) returns edge rows and bare UUIDs, so rendering link text
//! costs one `GET /claims/:id` per neighbour against a 10-connection pool, and
//! because its 500-edge cut collects outgoing rows first and therefore drops
//! backlinks wholesale. Here both directions are capped independently, so an
//! outbound-heavy claim cannot hide every inbound edge.
//!
//! Retracted edges (`valid_to` set and already past) are excluded everywhere,
//! including from [`EgoEdges::total_edges`].
//!
//! Relationship filtering is case-insensitive: the corpus holds both
//! `supports` and `SUPPORTS`, and `CORROBORATES` alongside `corroborates`
//! (see `routes/graph.rs` `GRAPH_VIEW_RELATIONSHIPS`), so a case-sensitive
//! filter would silently hide half the graph.
//!
//! # Hydrated claims carry no cached BetP
//!
//! The claim hydration SELECT reads `content`, `truth_value`, `labels` and
//! `is_current` — deliberately NOT `pignistic_prob` (nor `belief` /
//! `plausibility`). A compound claim's cached belief columns are a fold of its
//! own BBAs, not a value derived from its leaves, so a reader that serves them
//! must know the claim's role; this hydration is a flat `id = ANY($1)` fetch
//! across whatever types the edge rows named, and has no role to dispatch on.
//! Serving the number anyway would hand a caller a figure that does not mean
//! what a compound node implies it means.
//!
//! `truth_value` is projected, never compared, ordered on or folded, which is
//! the distinction `crates/epigraph-db/tests/no_role_blind_belief_reads.rs`
//! draws. Anything that needs a claim's belief should ask
//! `GET /api/v1/claims/:id/belief`, which is role-aware and frame-scoped. Do
//! not re-add a belief column here.
//!
//! # Tenancy
//!
//! Every statement is filtered in SQL against the caller's [`Viewer`]. The
//! three `edges` reads carry `/* {EDGE_VISIBILITY:e} */` — the co-ownership
//! spelling, because migration 072 stores an edge between two differently-owned
//! endpoints as `(owner = G, co_owner = H)` and the single-owner predicate
//! would show it to a principal in G alone. Each of them ALSO carries
//! `/* {VISIBILITY:fc} */` on an `EXISTS` over the FAR endpoint's `claims` row,
//! so an edge is counted and listed only when the claim at its other end is one
//! the viewer may read. Both markers in one statement resolve to the same bind
//! index, which `Viewer::splice` asserts.
//!
//! That second marker is what makes [`EgoEdges::total_edges`] safe to serialise
//! as-is. An unfiltered degree beside a filtered edge list states exactly how
//! many neighbours the viewer cannot see — the same metadata leak, dressed as a
//! count. Computing the number inside the same predicate that produces the rows
//! makes it a function only of visible rows by construction, rather than
//! something every caller has to remember to correct afterwards.
//!
//! # The far endpoint is constrained per TYPE, not only when it is a claim
//!
//! Guarding only the `claims` far endpoint was a leak, and the count was the
//! loud half of it. `evidence` and `reasoning_traces` carry their own
//! `(visibility, owner_group_id)` — migration 062's `tier_a` array includes
//! both — so an edge to a group-private trace passed the claims-only guard,
//! was counted in [`EgoEdges::total_edges`], and arrived at the caller with the
//! far id and its declared type on it. A uuid plus a relationship name is a
//! disclosure with no content attached.
//!
//! The three `edges` statements therefore dispatch on the far endpoint's type:
//!
//! * `claim` / `evidence` / `trace` — the three tenanted tables
//!   [`EgoRepository::hydrate`] actually reads — must pass a viewer-filtered
//!   `EXISTS` on their own table, so the edge is counted and listed only when
//!   the row at its other end is one the viewer may read;
//! * any other type must be positively known to carry NO tenancy of its own,
//!   i.e. be a member of [`EgoRepository::untenanted_entity_types`]. That
//!   excludes the remaining `tenancy_tier = 'columns'` types (`perspective`,
//!   `context`, `community`, `frame`) outright: this module hydrates none of
//!   them, so it cannot tell a public one from a private one, and a type it
//!   cannot check is a type it must not report.
//!
//! The set is a bind, not a second subquery per row, and the SAME value the
//! caller sees on [`EgoEdges::untenanted_types`] — so the predicate that
//! counted an edge and the rule that decides whether its far node may be
//! rendered cannot drift apart.

use std::collections::HashSet;

use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

/// One depth-1 edge, reported exactly as stored.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EgoEdgeRow {
    pub id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub source_type: String,
    pub target_type: String,
    pub relationship: String,
}

/// The capped depth-1 edge set around a centre claim.
#[derive(Debug, Clone)]
pub struct EgoEdges {
    /// Edges whose source is the centre, newest first.
    pub outbound: Vec<EgoEdgeRow>,
    /// Edges whose target is the centre, newest first.
    pub inbound: Vec<EgoEdgeRow>,
    /// Every depth-1 edge matching the relationship filter **that this viewer
    /// may see**, before the degree cap.
    ///
    /// Counted in the database inside the same viewer predicate that produces
    /// [`Self::outbound`] and [`Self::inbound`], so it is unaffected by the cap
    /// and is already the visible count — a caller serialises it as-is. It is
    /// deliberately NOT the claim's true degree: that number is a count of the
    /// neighbours the viewer is not allowed to know about.
    pub total_edges: i64,
    /// `true` when the degree cap cut the set — never when tenancy did. The
    /// pair therefore distinguishes "the cap cut the list" from "there is more
    /// you cannot see", and only the first of those is reported at all.
    pub truncated: bool,
    /// The entity types that carry no tenancy of their own, as
    /// [`EgoRepository::untenanted_entity_types`] read them from the registry
    /// on this same connection.
    ///
    /// Returned rather than left for the caller to re-derive because the three
    /// statements above already used it: a far endpoint of any other type is
    /// counted and listed only after a viewer-filtered `EXISTS` on its own
    /// table. A caller deciding what to do with a far id that did not hydrate
    /// must ask the same question of the same set, or the count and the node
    /// list answer to two different rules.
    pub untenanted_types: HashSet<String>,
}

/// A hydrated neighbour. `label` is the full display text; callers truncate it
/// to their own contract length. The claim-only fields are `None` for every
/// other entity type.
#[derive(Debug, Clone)]
pub struct EgoEntity {
    pub id: Uuid,
    pub entity_type: String,
    pub label: String,
    pub content: Option<String>,
    pub truth_value: Option<f64>,
    pub labels: Option<Vec<String>>,
    pub is_current: Option<bool>,
}

/// Hydration row for `claims`.
#[derive(sqlx::FromRow)]
struct ClaimHydrationRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    labels: Vec<String>,
    is_current: bool,
}

/// Hydration row for `evidence`. `caption` and `doi` come out of
/// `properties`, which is where the writers put them.
#[derive(sqlx::FromRow)]
struct EvidenceHydrationRow {
    id: Uuid,
    caption: Option<String>,
    doi: Option<String>,
    source_url: Option<String>,
}

pub struct EgoRepository;

impl EgoRepository {
    /// Fetch the depth-1 edges around `center` that `viewer` may see, balanced
    /// across directions.
    ///
    /// Each direction gets up to `max_degree.div_ceil(2)` edges, newest first;
    /// budget one side cannot use goes to the other, so a claim with 40
    /// outbound and 3 inbound edges still returns 40 edges in total rather
    /// than 23.
    ///
    /// `relationships`, when supplied non-empty, filters case-insensitively.
    ///
    /// Takes a `&mut PgConnection` rather than a generic executor because it
    /// runs three statements and they must describe the same corpus on the
    /// caller's one viewer-stamped connection (the `ClaimRepository::
    /// get_by_id_conn` precedent).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the count or either edge query fails.
    pub async fn edges(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        center: Uuid,
        max_degree: usize,
        relationships: Option<&[String]>,
    ) -> Result<EgoEdges, DbError> {
        // `None` binds as SQL NULL, which the `$2 IS NULL` guard reads as
        // "no filter"; an empty slice would filter everything out instead.
        let filter: Option<Vec<String>> = relationships
            .filter(|r| !r.is_empty())
            .map(|r| r.iter().map(|s| s.to_lowercase()).collect());

        // The ONE rule for the far endpoint, read on this connection so the
        // count, the two edge fetches and the caller's bare-node decision all
        // answer to the same set (module docs, "constrained per TYPE").
        let untenanted: Vec<String> = Self::untenanted_entity_types(&mut *conn)
            .await?
            .into_iter()
            .collect();

        // The far endpoint has to be computed before it can be constrained,
        // because this statement walks both directions at once: `far` is the
        // target for an edge leaving the centre and the source for one arriving
        // at it. The three tenanted tables `hydrate` reads get a viewer-filtered
        // EXISTS on their own table; every other type must be in `$3`, the
        // positively-untenanted set, which is what keeps a `perspective` /
        // `context` / `community` / `frame` far endpoint — tenanted, and not
        // hydrated here — out of the count instead of in it unchecked.
        let count_sql = viewer.splice(
            r#"
            SELECT COUNT(*)
            FROM edges e
            CROSS JOIN LATERAL (
                SELECT CASE WHEN e.source_id = $1 AND e.source_type = 'claim'
                            THEN e.target_id ELSE e.source_id END AS id,
                       CASE WHEN e.source_id = $1 AND e.source_type = 'claim'
                            THEN e.target_type ELSE e.source_type END AS entity_type
            ) far
            WHERE (e.valid_to IS NULL OR e.valid_to > now())
              AND ( (e.source_id = $1 AND e.source_type = 'claim')
                 OR (e.target_id = $1 AND e.target_type = 'claim') )
              AND ($2::text[] IS NULL OR lower(e.relationship) = ANY($2))
              AND ( CASE far.entity_type
                      WHEN 'claim' THEN EXISTS (SELECT 1 FROM claims fc
                                WHERE fc.id = far.id /* {VISIBILITY:fc} */)
                      WHEN 'evidence' THEN EXISTS (SELECT 1 FROM evidence fev
                                WHERE fev.id = far.id /* {VISIBILITY:fev} */)
                      WHEN 'trace' THEN EXISTS (SELECT 1 FROM reasoning_traces frt
                                WHERE frt.id = far.id /* {VISIBILITY:frt} */)
                      ELSE far.entity_type = ANY($3::text[])
                    END )
              /* {EDGE_VISIBILITY:e} */
            "#,
            4,
        );
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql)
            .bind(center)
            .bind(&filter)
            .bind(&untenanted);
        // Guarded, not `unwrap_or(&[])`: a Bypass viewer renders no `$4` at
        // all, so an unconditional bind sends one parameter more than the
        // rendered statement references and Postgres rejects it on arity.
        if let Some(g) = viewer.group_bind() {
            count_q = count_q.bind(g);
        }
        let total_edges: i64 = count_q.fetch_one(&mut *conn).await?;

        // Fetch up to the whole budget on each side, then decide the split in
        // memory: the unused half of one side is only knowable after both
        // sides are counted.
        let limit = max_degree as i64;

        let outbound_sql = viewer.splice(
            r#"
            SELECT e.id, e.source_id, e.target_id, e.source_type, e.target_type, e.relationship
            FROM edges e
            WHERE e.source_id = $1 AND e.source_type = 'claim'
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND ($2::text[] IS NULL OR lower(e.relationship) = ANY($2))
              AND ( CASE e.target_type
                      WHEN 'claim' THEN EXISTS (SELECT 1 FROM claims fc
                                WHERE fc.id = e.target_id /* {VISIBILITY:fc} */)
                      WHEN 'evidence' THEN EXISTS (SELECT 1 FROM evidence fev
                                WHERE fev.id = e.target_id /* {VISIBILITY:fev} */)
                      WHEN 'trace' THEN EXISTS (SELECT 1 FROM reasoning_traces frt
                                WHERE frt.id = e.target_id /* {VISIBILITY:frt} */)
                      ELSE e.target_type = ANY($4::text[])
                    END )
              /* {EDGE_VISIBILITY:e} */
            ORDER BY e.created_at DESC, e.id DESC
            LIMIT $3
            "#,
            5,
        );
        let mut out_q = sqlx::query_as::<_, EgoEdgeRow>(&outbound_sql)
            .bind(center)
            .bind(&filter)
            .bind(limit)
            .bind(&untenanted);
        if let Some(g) = viewer.group_bind() {
            out_q = out_q.bind(g);
        }
        let outbound: Vec<EgoEdgeRow> = out_q.fetch_all(&mut *conn).await?;

        // `NOT (source_id = $1 AND source_type = 'claim')` keeps a degenerate
        // self-edge out of both lists, so no edge is counted twice.
        let inbound_sql = viewer.splice(
            r#"
            SELECT e.id, e.source_id, e.target_id, e.source_type, e.target_type, e.relationship
            FROM edges e
            WHERE e.target_id = $1 AND e.target_type = 'claim'
              AND NOT (e.source_id = $1 AND e.source_type = 'claim')
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND ($2::text[] IS NULL OR lower(e.relationship) = ANY($2))
              AND ( CASE e.source_type
                      WHEN 'claim' THEN EXISTS (SELECT 1 FROM claims fc
                                WHERE fc.id = e.source_id /* {VISIBILITY:fc} */)
                      WHEN 'evidence' THEN EXISTS (SELECT 1 FROM evidence fev
                                WHERE fev.id = e.source_id /* {VISIBILITY:fev} */)
                      WHEN 'trace' THEN EXISTS (SELECT 1 FROM reasoning_traces frt
                                WHERE frt.id = e.source_id /* {VISIBILITY:frt} */)
                      ELSE e.source_type = ANY($4::text[])
                    END )
              /* {EDGE_VISIBILITY:e} */
            ORDER BY e.created_at DESC, e.id DESC
            LIMIT $3
            "#,
            5,
        );
        let mut in_q = sqlx::query_as::<_, EgoEdgeRow>(&inbound_sql)
            .bind(center)
            .bind(&filter)
            .bind(limit)
            .bind(&untenanted);
        if let Some(g) = viewer.group_bind() {
            in_q = in_q.bind(g);
        }
        let inbound: Vec<EgoEdgeRow> = in_q.fetch_all(&mut *conn).await?;

        let (out_take, in_take) = balanced_split(outbound.len(), inbound.len(), max_degree);
        let mut outbound = outbound;
        let mut inbound = inbound;
        outbound.truncate(out_take);
        inbound.truncate(in_take);

        let kept = (outbound.len() + inbound.len()) as i64;
        Ok(EgoEdges {
            outbound,
            inbound,
            total_edges,
            truncated: kept < total_edges,
            untenanted_types: untenanted.into_iter().collect(),
        })
    }

    /// The registered entity types that carry NO tenancy of their own: a row
    /// of one of these tables is readable by anyone who may read the edge that
    /// names it, so its id and type may be reported for a far endpoint that
    /// did not hydrate.
    ///
    /// # Why this is not `tenancy_tier = 'columns'` alone
    ///
    /// `entity_types.tenancy_tier` (migration 069) is the DECLARED shape, and
    /// for one type it is narrower than the table: 069 seeds `'columns'` for
    /// the six D1 roots (claim, evidence, frame, context, perspective,
    /// community) and sweeps everything else into `'derived'` — `trace`
    /// included. But `reasoning_traces` is in migration 062's `tier_a` array
    /// and carries NOT NULL `(visibility, owner_group_id)` of its own, so a
    /// group-private reasoning trace is exactly the row this function must not
    /// call untenanted. Keying off the declared tier alone would leave that
    /// leak open while looking principled.
    ///
    /// So the question is asked of the table: a type is untenanted when it is
    /// not declared `'columns'` AND its backing table has no `owner_group_id`
    /// column. The two conditions are an AND, not an OR — either one alone
    /// fails open on a disagreement between the declaration and the schema.
    ///
    /// `pg_attribute`, not `information_schema.columns`: the latter shows only
    /// columns the connected role holds some privilege on, so a role without
    /// privileges there would see a tenanted table as column-less and this
    /// function would widen. `pg_catalog` has no such filter. A `table_name`
    /// of `NULL` (the abstract `node` type) concatenates to `NULL`,
    /// `to_regclass(NULL)` is `NULL`, and the type is reported untenanted —
    /// correct, because it has no table and therefore no rows to withhold.
    ///
    /// Takes no `&Viewer`: `entity_types` is the type registry, not tenanted
    /// content, and every row of it is already public to every caller through
    /// `GET /api/v1/entity-types`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the registry query fails.
    pub async fn untenanted_entity_types(
        conn: &mut sqlx::PgConnection,
    ) -> Result<HashSet<String>, DbError> {
        let rows: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT et.type_name
            FROM entity_types et
            WHERE et.tenancy_tier <> 'columns'
              AND NOT EXISTS (
                    SELECT 1
                    FROM pg_attribute a
                    WHERE a.attrelid = to_regclass(
                              quote_ident(et.schema_name) || '.' || quote_ident(et.table_name))
                      AND a.attname = 'owner_group_id'
                      AND a.attnum > 0
                      AND NOT a.attisdropped)
            "#,
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Hydrate the centre claim, or `None` when it does not exist **or** the
    /// viewer may not read it — the caller's 404, and the same 404 either way.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the hydration query fails.
    pub async fn center(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        id: Uuid,
    ) -> Result<Option<EgoEntity>, DbError> {
        Ok(Self::hydrate(conn, viewer, &[id])
            .await?
            .into_iter()
            .find(|e| e.entity_type == "claim"))
    }

    /// Hydrate `ids` across the entity tables that carry display text:
    /// claims, agents, evidence, reasoning traces and papers.
    ///
    /// Ids that match nothing — and ids naming a row this viewer may not read,
    /// which is the same outcome — are simply absent from the result; the
    /// caller knows the declared entity type from the edge row and decides
    /// whether to render those as bare typed nodes or drop them.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any of the per-table queries fails.
    pub async fn hydrate(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        ids: &[Uuid],
    ) -> Result<Vec<EgoEntity>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut out: Vec<EgoEntity> = Vec::new();

        let claims_sql = viewer.splice(
            "SELECT c.id, c.content, c.truth_value, c.labels, c.is_current \
             FROM claims c WHERE c.id = ANY($1) /* {VISIBILITY:c} */",
            2,
        );
        let mut claims_q = sqlx::query_as::<_, ClaimHydrationRow>(&claims_sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            claims_q = claims_q.bind(g);
        }
        let claims: Vec<ClaimHydrationRow> = claims_q.fetch_all(&mut *conn).await?;
        for row in claims {
            out.push(EgoEntity {
                id: row.id,
                entity_type: "claim".to_string(),
                // A claim's label IS its content; there is no second spelling
                // of it to build, because a claim the viewer cannot read never
                // reaches this loop.
                label: row.content.clone(),
                content: Some(row.content),
                truth_value: Some(row.truth_value),
                labels: Some(row.labels),
                is_current: Some(row.is_current),
            });
        }

        // `agents` is not in migration 062's `tier_a` array — 062 gives it
        // `profile_visibility` and `default_group_id`, not `owner_group_id` —
        // so there is no predicate a viewer could be spent on here. This
        // function spends its viewer on the three tier_a tables it does read
        // (claims, evidence, reasoning_traces), so it needs no exemption
        // marker; writing one would enter it in `visibility_lint.rs`'s
        // `EXPECTED_EXEMPTIONS`, which is an exact set reserved for functions
        // that filter NOTHING.
        let agents: Vec<(Uuid, Option<String>)> =
            sqlx::query_as("SELECT id, display_name FROM agents WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(&mut *conn)
                .await?;
        for (id, display_name) in agents {
            let label = display_name.unwrap_or_else(|| short_id("Agent", id));
            out.push(EgoEntity {
                id,
                entity_type: "agent".to_string(),
                label,
                content: None,
                truth_value: None,
                labels: None,
                is_current: None,
            });
        }

        // `properties->>'caption'` / `'doi'` mirror the label rules in
        // `routes/graph_query_utils.rs::load_subgraph`, so the two graph
        // surfaces name the same evidence the same way.
        let evidence_sql = viewer.splice(
            "SELECT ev.id, ev.properties->>'caption' AS caption, \
             ev.properties->>'doi' AS doi, ev.source_url \
             FROM evidence ev WHERE ev.id = ANY($1) /* {VISIBILITY:ev} */",
            2,
        );
        let mut evidence_q = sqlx::query_as::<_, EvidenceHydrationRow>(&evidence_sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            evidence_q = evidence_q.bind(g);
        }
        let evidence: Vec<EvidenceHydrationRow> = evidence_q.fetch_all(&mut *conn).await?;
        for row in evidence {
            let id = row.id;
            let label = match (
                row.caption.filter(|s| !s.is_empty()),
                row.doi.filter(|s| !s.is_empty()),
                row.source_url.filter(|s| !s.is_empty()),
            ) {
                (Some(caption), _, _) => caption,
                (None, Some(doi), _) => format!("Evidence: {doi}"),
                (None, None, Some(url)) => format!("Evidence: {url}"),
                (None, None, None) => short_id("Evidence", id),
            };
            out.push(EgoEntity {
                id,
                entity_type: "evidence".to_string(),
                label,
                content: None,
                truth_value: None,
                labels: None,
                is_current: None,
            });
        }

        // `trace`, not `frame`: the `edges_validate_refs` trigger's
        // `validate_edge_reference` (migrations/001_initial_schema.sql:270-291)
        // has no `frame` branch, so no edge can point at a frame, while
        // claim→trace edges are the ordinary provenance shape. Label rule
        // copied from `routes/graph_query_utils.rs::load_subgraph`.
        let traces_sql = viewer.splice(
            "SELECT rt.id, rt.reasoning_type, rt.confidence \
             FROM reasoning_traces rt WHERE rt.id = ANY($1) /* {VISIBILITY:rt} */",
            2,
        );
        let mut traces_q = sqlx::query_as::<_, (Uuid, String, f64)>(&traces_sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            traces_q = traces_q.bind(g);
        }
        let traces: Vec<(Uuid, String, f64)> = traces_q.fetch_all(&mut *conn).await?;
        for (id, reasoning_type, confidence) in traces {
            out.push(EgoEntity {
                id,
                entity_type: "trace".to_string(),
                label: format!("{reasoning_type} ({confidence:.2})"),
                content: None,
                truth_value: None,
                labels: None,
                is_current: None,
            });
        }

        // `papers` is not in migration 062's `tier_a` array either, for the
        // same reason as `agents`: bibliographic metadata, no owner_group_id.
        let papers: Vec<(Uuid, Option<String>, String)> =
            sqlx::query_as("SELECT id, title, doi FROM papers WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(&mut *conn)
                .await?;
        for (id, title, doi) in papers {
            let label = title.filter(|t| !t.is_empty()).unwrap_or(doi);
            out.push(EgoEntity {
                id,
                entity_type: "paper".to_string(),
                label,
                content: None,
                truth_value: None,
                labels: None,
                is_current: None,
            });
        }

        Ok(out)
    }
}

/// `"<kind> <first 8 hex of id>"` — the fallback label for a row with no text
/// of its own.
fn short_id(kind: &str, id: Uuid) -> String {
    let s = id.to_string();
    format!("{kind} {}", &s[..8])
}

/// How many edges to keep from each side given a total budget.
///
/// Each side is entitled to half the budget (rounded up); whatever one side
/// leaves unused is offered to the other, outbound first.
fn balanced_split(outbound: usize, inbound: usize, max_degree: usize) -> (usize, usize) {
    let half = max_degree.div_ceil(2);
    let mut out_take = outbound.min(half);
    let mut in_take = inbound.min(half);
    // Rounding both halves up overshoots an odd budget; trim inbound so the
    // total is never more than the caller asked for.
    if out_take + in_take > max_degree {
        in_take = max_degree - out_take;
    }

    let mut spare = max_degree - out_take - in_take;
    if spare > 0 {
        let extra = (outbound - out_take).min(spare);
        out_take += extra;
        spare -= extra;
    }
    if spare > 0 {
        in_take += (inbound - in_take).min(spare);
    }
    (out_take, in_take)
}

#[cfg(test)]
mod tests {
    use super::balanced_split;

    #[test]
    fn split_is_even_when_both_sides_are_rich() {
        assert_eq!(balanced_split(100, 100, 40), (20, 20));
        // Odd budget: the rounded-up half goes to each side, then the total
        // caps it — outbound is served first.
        assert_eq!(balanced_split(100, 100, 5), (3, 2));
    }

    #[test]
    fn unused_budget_moves_to_the_other_side() {
        // The bug this route exists to avoid: an outbound-heavy claim must not
        // spend its whole budget on outbound edges, but must still fill up.
        assert_eq!(balanced_split(100, 3, 40), (37, 3));
        assert_eq!(balanced_split(3, 100, 40), (3, 37));
    }

    #[test]
    fn small_sets_are_returned_whole() {
        assert_eq!(balanced_split(2, 2, 40), (2, 2));
        assert_eq!(balanced_split(0, 0, 40), (0, 0));
        assert_eq!(balanced_split(0, 7, 40), (0, 7));
    }

    #[test]
    fn a_budget_of_one_still_returns_one_edge() {
        assert_eq!(balanced_split(5, 5, 1), (1, 0));
        assert_eq!(balanced_split(0, 5, 1), (0, 1));
    }
}
