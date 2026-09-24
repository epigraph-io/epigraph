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

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::DbError;

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
    /// Every matching depth-1 edge, before the degree cap. Counted in the
    /// database, so it is unaffected by the cap and by any redaction the
    /// caller applies afterwards.
    ///
    /// That last part is why a caller that redacts must NOT serialise this
    /// number as-is: it is the claim's true degree, and next to a redacted
    /// edge list it states exactly how many neighbours the viewer may not see.
    /// `routes/ego.rs` subtracts what it dropped before putting it on the
    /// wire; a new caller has to do the same.
    pub total_edges: i64,
    /// `true` when the degree cap cut the set — NOT when redaction did.
    pub truncated: bool,
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
    pub pignistic_prob: Option<f64>,
    pub labels: Option<Vec<String>>,
    pub is_current: Option<bool>,
}

/// Hydration row for `claims`.
#[derive(sqlx::FromRow)]
struct ClaimHydrationRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    pignistic_prob: Option<f64>,
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
    /// Fetch the depth-1 edges around `center`, balanced across directions.
    ///
    /// Each direction gets up to `max_degree.div_ceil(2)` edges, newest first;
    /// budget one side cannot use goes to the other, so a claim with 40
    /// outbound and 3 inbound edges still returns 40 edges in total rather
    /// than 23.
    ///
    /// `relationships`, when supplied non-empty, filters case-insensitively.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the count or either edge query fails.
    pub async fn edges(
        pool: &PgPool,
        center: Uuid,
        max_degree: usize,
        relationships: Option<&[String]>,
    ) -> Result<EgoEdges, DbError> {
        // `None` binds as SQL NULL, which the `$2 IS NULL` guard reads as
        // "no filter"; an empty slice would filter everything out instead.
        let filter: Option<Vec<String>> = relationships
            .filter(|r| !r.is_empty())
            .map(|r| r.iter().map(|s| s.to_lowercase()).collect());

        let total_edges: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM edges
            WHERE (valid_to IS NULL OR valid_to > now())
              AND ( (source_id = $1 AND source_type = 'claim')
                 OR (target_id = $1 AND target_type = 'claim') )
              AND ($2::text[] IS NULL OR lower(relationship) = ANY($2))
            "#,
        )
        .bind(center)
        .bind(&filter)
        .fetch_one(pool)
        .await?;

        // Fetch up to the whole budget on each side, then decide the split in
        // memory: the unused half of one side is only knowable after both
        // sides are counted.
        let limit = max_degree as i64;

        let outbound: Vec<EgoEdgeRow> = sqlx::query_as(
            r#"
            SELECT id, source_id, target_id, source_type, target_type, relationship
            FROM edges
            WHERE source_id = $1 AND source_type = 'claim'
              AND (valid_to IS NULL OR valid_to > now())
              AND ($2::text[] IS NULL OR lower(relationship) = ANY($2))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(center)
        .bind(&filter)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        // `NOT (source_id = $1 AND source_type = 'claim')` keeps a degenerate
        // self-edge out of both lists, so no edge is counted twice.
        let inbound: Vec<EgoEdgeRow> = sqlx::query_as(
            r#"
            SELECT id, source_id, target_id, source_type, target_type, relationship
            FROM edges
            WHERE target_id = $1 AND target_type = 'claim'
              AND NOT (source_id = $1 AND source_type = 'claim')
              AND (valid_to IS NULL OR valid_to > now())
              AND ($2::text[] IS NULL OR lower(relationship) = ANY($2))
            ORDER BY created_at DESC, id DESC
            LIMIT $3
            "#,
        )
        .bind(center)
        .bind(&filter)
        .bind(limit)
        .fetch_all(pool)
        .await?;

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
        })
    }

    /// Hydrate `ids` across the entity tables that carry display text:
    /// claims, agents, evidence, reasoning traces and papers. Ids that match
    /// nothing are simply absent from the result; the caller knows the
    /// declared entity type from the edge row and renders those as bare typed
    /// nodes.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any of the per-table queries fails.
    /// Hydrate ego-graph node ids into entities, reading `claims` through the
    /// caller's [`Viewer`].
    ///
    /// The viewer is NOT optional and NOT a post-filter: this projects
    /// `claims.content`, so a claim the viewer may not read must never be
    /// returned at all. The `/* {VISIBILITY:c} */` splice does that in SQL, so an
    /// invisible node simply does not come back and the caller renders the ego
    /// graph without it — absent, not blanked. Before the redaction model was
    /// removed, this returned every row and the API layer overwrote the text
    /// afterwards; that post-pass no longer exists.
    ///
    /// `agents` are not filtered: an agent row carries no claim content, and the
    /// ids reaching here already survived the edge walk.
    pub async fn hydrate(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        ids: &[Uuid],
    ) -> Result<Vec<EgoEntity>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut out: Vec<EgoEntity> = Vec::new();

        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, c.truth_value, c.pignistic_prob, c.labels,
                   c.is_current
            FROM claims c
            WHERE c.id = ANY($1)
              /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, ClaimHydrationRow>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let claims: Vec<ClaimHydrationRow> = q.fetch_all(pool).await?;
        for row in claims {
            out.push(EgoEntity {
                id: row.id,
                entity_type: "claim".to_string(),
                // Provisional: a caller that redacts the content must rebuild
                // the label from the redacted text.
                label: row.content.clone(),
                content: Some(row.content),
                truth_value: Some(row.truth_value),
                pignistic_prob: row.pignistic_prob,
                labels: Some(row.labels),
                is_current: Some(row.is_current),
            });
        }

        let agents: Vec<(Uuid, Option<String>)> =
            sqlx::query_as("SELECT id, display_name FROM agents WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(pool)
                .await?;
        for (id, display_name) in agents {
            let label = display_name.unwrap_or_else(|| short_id("Agent", id));
            out.push(EgoEntity {
                id,
                entity_type: "agent".to_string(),
                label,
                content: None,
                truth_value: None,
                pignistic_prob: None,
                labels: None,
                is_current: None,
            });
        }

        // `properties->>'caption'` / `'doi'` mirror the label rules in
        // `routes/graph_query_utils.rs::load_subgraph`, so the two graph
        // surfaces name the same evidence the same way.
        let evidence: Vec<EvidenceHydrationRow> = sqlx::query_as(
            "SELECT id, properties->>'caption' AS caption, properties->>'doi' AS doi, source_url \
             FROM evidence WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(pool)
        .await?;
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
                pignistic_prob: None,
                labels: None,
                is_current: None,
            });
        }

        // `trace`, not `frame`: the `edges_validate_refs` trigger's
        // `validate_edge_reference` (migrations/001_initial_schema.sql:270-291)
        // has no `frame` branch, so no edge can point at a frame, while
        // claim→trace edges are the ordinary provenance shape. Label rule
        // copied from `routes/graph_query_utils.rs::load_subgraph`.
        let traces: Vec<(Uuid, String, f64)> = sqlx::query_as(
            "SELECT id, reasoning_type, confidence FROM reasoning_traces WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(pool)
        .await?;
        for (id, reasoning_type, confidence) in traces {
            out.push(EgoEntity {
                id,
                entity_type: "trace".to_string(),
                label: format!("{reasoning_type} ({confidence:.2})"),
                content: None,
                truth_value: None,
                pignistic_prob: None,
                labels: None,
                is_current: None,
            });
        }

        let papers: Vec<(Uuid, Option<String>, String)> =
            sqlx::query_as("SELECT id, title, doi FROM papers WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(pool)
                .await?;
        for (id, title, doi) in papers {
            let label = title.filter(|t| !t.is_empty()).unwrap_or(doi);
            out.push(EgoEntity {
                id,
                entity_type: "paper".to_string(),
                label,
                content: None,
                truth_value: None,
                pignistic_prob: None,
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
