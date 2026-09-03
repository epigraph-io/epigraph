//! Corpus cardinality reads for `system_stats` (MCP) — viewer-scoped.
//!
//! # Why this module exists
//!
//! `crates/epigraph-mcp/src/tools/batch.rs::system_stats` took a `&Viewer` and
//! spent it on exactly one call (`TripleRepository::index_counts`) while issuing
//! eight raw `SELECT COUNT(*)` statements against `claims`, `evidence`, `edges`,
//! `agents`, `frames` and `challenges` directly from the tool. That is two
//! defects at once: inline SQL in `crates/epigraph-mcp/src/tools/` (CLAUDE.md
//! forbids it) and a viewer parameter that the compiler could not tell was being
//! ignored. A non-member learned the exact global corpus size.
//!
//! The counts move here and split into two functions on the one axis that
//! matters — whether the underlying table carries the migration-062 tenancy
//! columns:
//!
//! * [`CorpusStatsRepository::tenant_counts`] covers `claims`, `evidence`,
//!   `edges`, `frames` and `challenges`, all of which are in 062's `tier_a`
//!   array and therefore have `visibility` / `owner_group_id`. Every subselect
//!   carries a marker and the whole statement is spliced, so all of them read
//!   the same `$1` group array.
//! * [`CorpusStatsRepository::agent_count`] covers `agents`, which is **not**
//!   in `tier_a` — 062 gives it `profile_visibility` and `default_group_id`
//!   instead, and there is no `owner_group_id` to filter on. It is exempt, with
//!   the reason at the function, and is named in `visibility_lint.rs`'s
//!   `EXPECTED_EXEMPTIONS`.
//!
//! # A note on what these numbers now mean
//!
//! `tenant_counts` is a real behaviour change for every `system_stats` caller:
//! the headline numbers become "rows this viewer can read", not "rows that
//! exist". That is the point — the previous value was a membership oracle over
//! the whole corpus. Migration 062 defaults `visibility` to `'public'` and
//! backfills nothing, so until PR-12's backfill runs the two are numerically
//! identical on a production corpus; the change is latent, and it bites exactly
//! when the first `visibility='group'` row is written.
//!
//! The assertion is load-bearing today rather than in six months because
//! `epigraph-mcp/tests/tenant_isolation_mcp.rs` seeds `visibility='group'`
//! rows explicitly (`fixture::seed_group_claim`) and asserts both directions:
//! `system_stats_hides_a_group_private_claim_from_a_stranger`,
//! `system_stats_shows_the_owner_its_own_group_private_claim`,
//! `system_stats_counts_a_public_claim_for_both_tenants`, and — for the
//! `detailed` branch's second spliced statement —
//! `system_stats_detailed_counts_narrow_for_a_stranger_and_widen_for_the_owner`.
//! (An earlier revision of this note cited `tests/system_stats_tenancy.rs`,
//! which does not exist in this tree. A doc reference that resolves to nothing
//! is the same defect class as an untested acceptance line.)

use sqlx::PgPool;

use crate::errors::DbError;
use crate::visibility::Viewer;

/// The viewer-visible cardinalities `system_stats` reports.
///
/// `workflow_claims`, `challenges` and `embedded_claims` are only populated on
/// the `detailed` path; the caller decides, and pays for, the extra subselects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorpusCounts {
    pub claims: i64,
    pub evidence: i64,
    pub edges: i64,
    pub frames: i64,
    /// `None` when `detailed` was false.
    pub workflow_claims: Option<i64>,
    /// `None` when `detailed` was false.
    pub challenges: Option<i64>,
    /// `None` when `detailed` was false.
    pub embedded_claims: Option<i64>,
}

pub struct CorpusStatsRepository;

impl CorpusStatsRepository {
    /// Viewer-scoped cardinalities for the five tenancy-bearing tables
    /// `system_stats` reports (plus the three `detailed` extras).
    ///
    /// One round trip. Every subselect aliases its table and carries a
    /// `/* {VISIBILITY:<alias>} */` marker, so `splice` renders the same `$1`
    /// group-array bind into all of them — the multi-marker/one-bind property
    /// `Viewer::splice` documents and asserts.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the query fails.
    pub async fn tenant_counts(
        pool: &PgPool,
        viewer: &Viewer,
        detailed: bool,
    ) -> Result<CorpusCounts, DbError> {
        // `WHERE true` gives every marker a preceding predicate to append
        // ` AND (...)` to; `predicate_fragment` deliberately starts with AND.
        let base = r"
            SELECT
              (SELECT COUNT(*) FROM claims c
                 WHERE true /* {VISIBILITY:c} */)    AS claims,
              (SELECT COUNT(*) FROM evidence ev
                 WHERE true /* {VISIBILITY:ev} */)   AS evidence,
              (SELECT COUNT(*) FROM edges eg
                 WHERE true /* {VISIBILITY:eg} */)   AS edges,
              (SELECT COUNT(*) FROM frames f
                 WHERE true /* {VISIBILITY:f} */)    AS frames
        ";
        let sql = viewer.splice(base, 1);
        let mut q = sqlx::query_as::<_, (i64, i64, i64, i64)>(&sql);
        // Guarded, not `unwrap_or(&[])`. `render_predicate` emits nothing at
        // all for a `Bypass` viewer, so an unconditional bind sends one more
        // parameter than the rendered statement references and Postgres
        // rejects the statement on arity. Unreachable today (every caller's
        // viewer comes from `request_viewer`), but this is the form the other
        // 165 sites in the repo layer use and there is no reason for a new one
        // to differ.
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let (claims, evidence, edges, frames) = q.fetch_one(pool).await?;

        let mut out = CorpusCounts {
            claims,
            evidence,
            edges,
            frames,
            workflow_claims: None,
            challenges: None,
            embedded_claims: None,
        };

        if detailed {
            let detail_base = r"
                SELECT
                  (SELECT COUNT(*) FROM claims c
                     WHERE 'workflow' = ANY(c.labels) /* {VISIBILITY:c} */)   AS workflow_claims,
                  (SELECT COUNT(*) FROM challenges ch
                     WHERE true /* {VISIBILITY:ch} */)                        AS challenges,
                  (SELECT COUNT(*) FROM claims c2
                     WHERE c2.embedding IS NOT NULL /* {VISIBILITY:c2} */)    AS embedded_claims
            ";
            let detail_sql = viewer.splice(detail_base, 1);
            let mut dq = sqlx::query_as::<_, (i64, i64, i64)>(&detail_sql);
            if let Some(g) = viewer.group_bind() {
                dq = dq.bind(g);
            }
            let (workflow_claims, challenges, embedded_claims) = dq.fetch_one(pool).await?;
            out.workflow_claims = Some(workflow_claims);
            out.challenges = Some(challenges);
            out.embedded_claims = Some(embedded_claims);
        }

        Ok(out)
    }

    /// Registered-principal cardinality.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the query fails.
    pub async fn agent_count(pool: &PgPool, _viewer: &Viewer) -> Result<i64, DbError> {
        let count: (i64,) = sqlx::query_as(
            "-- VISIBILITY-EXEMPT: `agents` is not in migration 062's tier_a array and
             -- has no owner_group_id to filter on — 062 gives it profile_visibility
             -- and default_group_id instead. One scalar leaves this function and no
             -- row content does; it is the principal-directory cardinality, the same
             -- category as triple.rs::index_counts. Revisit if agents ever gain
             -- owner_group_id, or if this count is ever exposed per-agent.
             SELECT COUNT(*) FROM agents",
        )
        .fetch_one(pool)
        .await?;
        Ok(count.0)
    }
}
