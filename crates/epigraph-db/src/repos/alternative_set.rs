//! Candidate `alternative_of` pair discovery — the read behind MCP
//! `suggest_alternative_sets`.
//!
//! # Why this moved here (PR-09)
//!
//! The scan lived inline in `epigraph-mcp/src/tools/alternative_sets.rs`, whose
//! module doc said it would "promote to a repo helper if a second caller ever
//! appears". A second caller is not the criterion CLAUDE.md states — "all SQL
//! stays in `crates/epigraph-db/src/repos/`" — and the tenancy work supplies the
//! reason the rule exists: the statement joins `claims` three ways and returned
//! `pignistic_prob`, `labels` and the ids of every contradicting pair in the
//! corpus to any caller, with no viewer in the function at all.
//!
//! All three claims in a candidate — both supporters and the shared target —
//! must be visible before the pair is surfaced. Filtering only the supporters
//! would still hand back a private target's id in `target_claim`, and the
//! `reason` string interpolates that id.
//!
//! # The edges are filtered too, and the `existing` join deliberately is not
//!
//! `edges` IS in migration 062's `tier_a`, so `s1`, `s2` and `contr` all carry
//! `visibility` / `owner_group_id` and all three are spliced. An earlier
//! revision filtered only the three `claims` aliases, which is not enough:
//! three public claims joined by a group-private `contradicts` edge would have
//! been returned to a stranger with `reason` = "contradicts edge between
//! supporters of &lt;id&gt;" — a response that literally asserts the existence of
//! an edge the caller cannot read. `match_candidate.rs::corroborates_edges_for_claim`,
//! written in the same change, states the same rule ("the edge predicate alone
//! is not enough") and it applies symmetrically here.
//!
//! Per `visibility.rs`'s module doc these use [`Viewer::predicate_fragment`],
//! not the co-ownership `edge_predicate_fragment` that PR-13's migration makes
//! possible.
//!
//! The `existing` LEFT JOIN on `alternative_of` is left UNFILTERED, and that is
//! a decision rather than an omission. Its role is suppression: a pair already
//! linked is not re-suggested. Filtering it would mean a viewer who cannot see
//! the existing `alternative_of` edge is offered the pair again and, on
//! accepting, writes a duplicate link. Leaving it unfiltered means a private
//! link can suppress a suggestion the viewer would otherwise get — the result
//! set is shaped by a row the caller cannot see, but only ever *narrowed* by
//! it, which is the fail-closed direction and discloses nothing.

use sqlx::PgPool;
use uuid::Uuid;

use crate::visibility::Viewer;

/// One suggested `alternative_of` pair.
#[derive(Debug, Clone)]
pub struct AlternativePairRow {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub target_claim: Uuid,
    pub score: f64,
    pub reason: String,
}

pub struct AlternativeSetRepository;

impl AlternativeSetRepository {
    /// Find pairs `(A, B)` such that
    /// - both `A` and `B` have a `supports` edge to a common target `T`,
    /// - there exists a `contradicts` edge between `A` and `B` in either
    ///   direction,
    /// - no explicit `alternative_of` edge between `A` and `B` already exists,
    ///   and
    /// - `min(BetP_A, BetP_B) >= min_strength`.
    ///
    /// Pairs are de-duplicated symmetrically with `s1.source_id < s2.source_id`
    /// in the WHERE clause; the SELECT's `LEAST`/`GREATEST` keep the returned
    /// `(claim_a, claim_b)` ordering canonical even if the upstream invariant
    /// ever drifts. Ordered by `score DESC`, capped at 200 rows per call.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`sqlx::Error`] if the query fails.
    pub async fn scan_candidates(
        pool: &PgPool,
        viewer: &Viewer,
        target_filter: Option<Uuid>,
        min_strength: f64,
        exclude_settled: bool,
        surface_reconsiderations: bool,
    ) -> Result<Vec<AlternativePairRow>, sqlx::Error> {
        // $1..$4 are the caller's binds; $5 is the viewer group array.
        //
        // The three markers sit in the CTE's WHERE, not in the outer query:
        // the outer SELECT reads only columns the CTE already produced, so a
        // predicate there would filter the projection rather than the scan and
        // `labels_a` / `bp_a` would have been computed from rows the viewer
        // cannot see. `visibility_lint.rs` cannot check marker PLACEMENT — this
        // comment is the human half of that check.
        let sql = viewer.splice(
            r#"
        WITH base AS (
            SELECT
                LEAST(s1.source_id, s2.source_id)    AS claim_a,
                GREATEST(s1.source_id, s2.source_id) AS claim_b,
                s1.target_id                         AS target_claim,
                LEAST(
                    COALESCE(ca.pignistic_prob, 0.0),
                    COALESCE(cb.pignistic_prob, 0.0)
                ) AS score,
                COALESCE(ca.pignistic_prob, 0.0) AS bp_a,
                COALESCE(cb.pignistic_prob, 0.0) AS bp_b,
                COALESCE(ca.labels, ARRAY[]::text[]) AS labels_a,
                COALESCE(cb.labels, ARRAY[]::text[]) AS labels_b
            FROM edges s1
            JOIN edges s2
              ON s2.target_id = s1.target_id
             AND s2.relationship = 'supports'
             AND s2.source_id <> s1.source_id
            JOIN edges contr
              ON ((contr.source_id = s1.source_id AND contr.target_id = s2.source_id)
               OR (contr.source_id = s2.source_id AND contr.target_id = s1.source_id))
             AND contr.relationship = 'contradicts'
            JOIN claims ca ON ca.id = s1.source_id
            JOIN claims cb ON cb.id = s2.source_id
            JOIN claims ct ON ct.id = s1.target_id
            LEFT JOIN edges existing
              ON existing.relationship = 'alternative_of'
             AND ((existing.source_id = s1.source_id AND existing.target_id = s2.source_id)
               OR (existing.source_id = s2.source_id AND existing.target_id = s1.source_id))
            WHERE s1.relationship = 'supports'
              AND s1.source_id < s2.source_id
              AND ($1::uuid IS NULL OR s1.target_id = $1)
              AND existing.id IS NULL
              /* {VISIBILITY:ca} */ /* {VISIBILITY:cb} */ /* {VISIBILITY:ct} */
              /* {VISIBILITY:s1} */ /* {VISIBILITY:s2} */ /* {VISIBILITY:contr} */
        )
        SELECT
            claim_a, claim_b, target_claim, score,
            CASE
                WHEN $4 AND ('alt-rejected' = ANY(labels_a) OR 'alt-rejected' = ANY(labels_b))
                  THEN format(
                      'reconsider: one supporter is alt-rejected; rivals'' BetPs are %s and %s',
                      bp_a::text, bp_b::text)
                ELSE format('contradicts edge between supporters of %s', target_claim::text)
            END AS reason
        FROM base
        WHERE
            -- Pure heuristic gate: at least one supporter has BetP >= threshold
            score >= $2
            -- Exclusion of settled pairs (chosen/rejected) when exclude_settled = true,
            -- unless surface_reconsiderations is on and exactly one member is alt-rejected
            -- with a sufficient BetP gap to its rival.
            AND (
                NOT $3                     -- if exclude_settled is false, accept everything past score
                OR (
                    NOT ('alt-chosen'   = ANY(labels_a) OR 'alt-chosen'   = ANY(labels_b))
                    AND (
                        NOT ('alt-rejected' = ANY(labels_a) OR 'alt-rejected' = ANY(labels_b))
                        OR (
                            $4  -- surface_reconsiderations
                            AND (
                                -- exactly-one rejected
                                ('alt-rejected' = ANY(labels_a)) <> ('alt-rejected' = ANY(labels_b))
                            )
                            AND abs(bp_a - bp_b) >= $2
                        )
                    )
                )
            )
        ORDER BY score DESC
        LIMIT 200
        "#,
            5,
        );

        let mut q = sqlx::query_as::<_, (Uuid, Uuid, Uuid, f64, String)>(&sql)
            .bind(target_filter)
            .bind(min_strength)
            .bind(exclude_settled)
            .bind(surface_reconsiderations);
        // Guarded, not `unwrap_or(&[])`: a `Bypass` viewer renders no
        // predicate, so an unconditional bind sends a parameter the statement
        // does not reference and Postgres rejects it on arity.
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(pool).await?;

        Ok(rows
            .into_iter()
            .map(|(a, b, t, score, reason)| AlternativePairRow {
                claim_a: a,
                claim_b: b,
                target_claim: t,
                score,
                reason,
            })
            .collect())
    }
}
