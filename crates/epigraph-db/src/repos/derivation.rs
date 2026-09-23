//! Claim-to-claim derivation lineage for corpus-wide jobs.
//!
//! One read: the set of claims a claim was derived from, transitively,
//! including the claim itself. Its only consumer is the cross-source matcher's
//! same-source filter (`epigraph_engine::matching::source_key`), which treats
//! two claims as the same source when their lineages overlap.
//!
//! # Edge direction
//!
//! An edge `source --derived_from--> target` is read as "`source` was derived
//! FROM `target`": the source is the descendant, the target the ancestor. That
//! is the reading of every writer and invariant that states a direction for a
//! claim-to-claim derivation edge:
//!
//! * migration 011: the 36,791 UPPERCASE `DERIVED_FROM` rows written by
//!   `paraphrase_full_sweep.py` point paraphrase -> source atom;
//! * the privatization closure invariant (`epigraph-api/tests/privatization_resume.rs`)
//!   joins `child = source_id`, `parent = target_id` over
//!   `lower(relationship) = 'derived_from'`;
//! * `epigraph_core::edge` documents `DERIVED_FROM` as "Claim was derived from
//!   this `ReasoningTrace`", and every claim -> evidence writer points from the
//!   derived claim to what it rests on.
//!
//! `epigraph_engine::export::prov` and [`crate::LineageRepository`] assume the
//! opposite (ancestor -> descendant) for the lowercase spelling. The overlap
//! test this read feeds is tolerant of that disagreement where it matters most:
//! a parent and its child are found either way, because one's lineage contains
//! the other. Only SIBLING detection depends on the direction, and it follows
//! the majority reading above.
//!
//! # What is walked
//!
//! * **Claim to claim only** (`source_type = 'claim' AND target_type = 'claim'`).
//!   Every MCP `submit_claim` / HTTP `create_claim` / crud write emits an
//!   UPPERCASE `DERIVED_FROM` claim -> evidence edge, and the caller-less
//!   `ClaimRepository::inherit_evidence` left lowercase ones in older rows.
//!   Case-folding the relationship without this filter would walk onto evidence
//!   ids and make every pair of claims sharing an inherited evidence row "the
//!   same source".
//! * **Every spelling**, compared case-insensitively: see
//!   [`DERIVATION_RELATIONSHIPS`].
//! * **Every parent**, not `LIMIT 1` of them. A claim derived from two parents
//!   shares a source with the descendants of both, and a single chosen parent
//!   would make the answer depend on the query plan.
//! * **Retracted edges included** (no `valid_to` filter). `derived_from` is
//!   lineage, not evidence: retracting an evidential edge must not sever a
//!   derivation chain.

use sqlx::PgPool;
use uuid::Uuid;

/// Relationship spellings that mean "`source_id` was derived from `target_id`",
/// lowercased. Compared against `lower(edges.relationship)`, because the table
/// carries both `derived_from` and `DERIVED_FROM` (migration 011) and a
/// case-sensitive match silently skips one of them.
pub const DERIVATION_RELATIONSHIPS: &[&str] = &["derived_from", "derives_from"];

/// Hops walked from the starting claim before the walk stops.
pub const MAX_DERIVATION_DEPTH: i32 = 32;

/// Derivation-lineage reads. See the module docs for what is walked and why.
pub struct DerivationRepository;

impl DerivationRepository {
    /// `claim_id` plus every claim it was derived from, transitively, up to
    /// [`MAX_DERIVATION_DEPTH`] hops, sorted by id.
    ///
    /// The starting id is always included, so a claim with no derivation edges
    /// returns `[claim_id]` and overlaps only with its own descendants. That is
    /// what makes a root and its direct child the same source.
    ///
    /// Cycles terminate: rows are deduplicated on `(id, depth)` and depth is
    /// bounded, so at most `reachable * (MAX_DERIVATION_DEPTH + 1)` rows are
    /// produced before the final `DISTINCT`.
    ///
    /// # Visibility
    ///
    /// Takes no `Viewer`, on purpose. "Same source" is a property of the
    /// corpus, not of whoever runs the matcher: a viewer-scoped walk would let
    /// an invisible intermediate claim sever a lineage and re-admit a
    /// same-source pair as cross-source corroboration. The ids are consumed
    /// in-process by the matcher and never returned to a caller. Like every
    /// other matcher read, the result is only as complete as what the pool's
    /// role can see; it must not be called from a request path.
    ///
    /// # Errors
    /// Returns the underlying `sqlx::Error` if the query fails.
    pub async fn lineage_ids(pool: &PgPool, claim_id: Uuid) -> sqlx::Result<Vec<Uuid>> {
        sqlx::query_scalar::<_, Uuid>(
            "-- VISIBILITY-EXEMPT: corpus-wide same-source determination for the cross-source matcher; a viewer-scoped walk would let an invisible intermediate claim sever a lineage. See DerivationRepository::lineage_ids.
             WITH RECURSIVE lineage(id, depth) AS (
                 SELECT $1::uuid, 0
                 UNION
                 SELECT e.target_id, l.depth + 1
                   FROM lineage l
                   JOIN edges e
                     ON e.source_id = l.id
                    AND e.source_type = 'claim'
                    AND e.target_type = 'claim'
                    AND lower(e.relationship::text) = ANY($2::text[])
                  WHERE l.depth < $3
             )
             SELECT DISTINCT id FROM lineage ORDER BY id",
        )
        .bind(claim_id)
        .bind(DERIVATION_RELATIONSHIPS)
        .bind(MAX_DERIVATION_DEPTH)
        .fetch_all(pool)
        .await
    }
}
