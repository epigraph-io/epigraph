//! Repository for `match_candidates` (cross-source matcher review queue).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct MatchCandidateRow {
    pub id: Uuid,
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub score: f32,
    pub features: serde_json::Value,
    pub verifier_verdict: Option<String>,
    pub verifier_rationale: Option<String>,
    pub status: String,
    pub matcher_run_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<Uuid>,
}

/// Result of [`MatchCandidateRepo::upsert`].
#[derive(Debug, Clone)]
pub struct UpsertOutcome {
    pub id: Uuid,
    /// The verdict on the row *after* the statement ran. Compare against the
    /// verdict the caller attempted to write: a mismatch means the row was
    /// already decided and the gate preserved the decided verdict.
    pub verifier_verdict: Option<String>,
}

impl UpsertOutcome {
    /// True when `attempted` was a real verdict that the gate refused to store.
    /// `None` (pair not verified this pass) is never a suppression.
    pub fn verdict_write_suppressed(&self, attempted: Option<&str>) -> bool {
        match attempted {
            Some(a) => self.verifier_verdict.as_deref() != Some(a),
            None => false,
        }
    }
}

#[derive(Clone)]
pub struct MatchCandidateRepo {
    pool: PgPool,
}

impl MatchCandidateRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert or update a candidate. Caller MUST pass `claim_a < claim_b`.
    ///
    /// A row that has already been *decided* (`decided_at IS NOT NULL`) keeps
    /// its `status` **and its verifier verdict/rationale**: the nightly matcher
    /// re-touches most pairs every run and always upserts `pending`, so an
    /// unguarded `status = EXCLUDED.status` silently reverts operator rulings
    /// days after the fact. Matcher telemetry (`score`, `features`,
    /// `matcher_run_id`) still refreshes — those describe the *pair*, not the
    /// *decision*.
    ///
    /// The discriminator is `decided_at`, not `status != 'pending'`, because
    /// [`crate::repos::match_candidate::MatchCandidateRepo::set_status`] is the
    /// only writer of `decided_at`, while the matcher itself writes
    /// `status = 'rejected'` with `decided_at` NULL. Keying on status would
    /// freeze matcher-set rejections forever and defeat re-scoring.
    ///
    /// `verifier_verdict` / `verifier_rationale` are written **here**, in the
    /// same statement and under the same guard, rather than by a follow-up
    /// `UPDATE` in the engine's policy layer. Two separate statements meant two
    /// separate guards: the status guard above landed while the verdict write
    /// stayed unconditional, so a re-scan preserved the operator's ruling but
    /// destroyed the verdict that ruling was based on. That stopped being
    /// merely an audit-trail loss once `promotion_disposition_for_column` made
    /// `verifier_verdict` determine the polarity of the edge a promotion
    /// writes. Folding them also removes the window *between* the two
    /// statements, during which a concurrent operator tap could read a verdict
    /// that was about to be overwritten.
    ///
    /// The two verdict columns are gated together on purpose: freezing one
    /// without the other yields a row whose rationale describes a verdict it no
    /// longer carries, which is worse than either alone.
    ///
    /// `verdict`/`rationale` of `None` mean "this pair was not verified on this
    /// pass" and leave any existing values intact (hence `COALESCE`) — they do
    /// not mean "erase what is there".
    ///
    /// Returns the row id plus the verdict **as actually persisted**. When that
    /// differs from the `verdict` argument, the gate suppressed the write;
    /// callers surface that as telemetry rather than an error, because a
    /// 1000-candidate sweep must not abort on a routine expected condition.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert(
        &self,
        claim_a: Uuid,
        claim_b: Uuid,
        score: f32,
        features: serde_json::Value,
        status: &str,
        run_id: Option<Uuid>,
        verdict: Option<&str>,
        rationale: Option<&str>,
    ) -> sqlx::Result<UpsertOutcome> {
        debug_assert!(claim_a < claim_b, "callers must pass canonical order");
        let (id, verifier_verdict): (Uuid, Option<String>) = sqlx::query_as(
            "INSERT INTO match_candidates
                (claim_a, claim_b, score, features, status, matcher_run_id,
                 verifier_verdict, verifier_rationale)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (claim_a, claim_b) DO UPDATE SET
                score = EXCLUDED.score,
                features = EXCLUDED.features,
                status = CASE
                    WHEN match_candidates.decided_at IS NOT NULL
                    THEN match_candidates.status
                    ELSE EXCLUDED.status
                END,
                matcher_run_id = EXCLUDED.matcher_run_id,
                verifier_verdict = CASE
                    WHEN match_candidates.decided_at IS NOT NULL
                    THEN match_candidates.verifier_verdict
                    ELSE COALESCE(EXCLUDED.verifier_verdict,
                                  match_candidates.verifier_verdict)
                END,
                verifier_rationale = CASE
                    WHEN match_candidates.decided_at IS NOT NULL
                    THEN match_candidates.verifier_rationale
                    ELSE COALESCE(EXCLUDED.verifier_rationale,
                                  match_candidates.verifier_rationale)
                END
             -- decided_at / decided_by are deliberately absent from this SET
             -- list: omitted columns are left untouched by ON CONFLICT, which
             -- is exactly the desired behaviour. Do not add them.
             RETURNING id, verifier_verdict",
        )
        .bind(claim_a)
        .bind(claim_b)
        .bind(score)
        .bind(Json(features))
        .bind(status)
        .bind(run_id)
        .bind(verdict)
        .bind(rationale)
        .fetch_one(&self.pool)
        .await?;
        Ok(UpsertOutcome {
            id,
            verifier_verdict,
        })
    }

    /// Stage a candidate pair **only if the pair has no row yet**. Caller MUST
    /// pass `claim_a < claim_b`. Returns the new row's id, or `None` when a row
    /// for the pair already existed (in which case nothing was written).
    ///
    /// Deliberately NOT [`MatchCandidateRepo::upsert`]. `upsert` unconditionally
    /// overwrites `score`, `features` and `matcher_run_id` — that is correct for
    /// the nightly matcher, whose whole job is to re-score pairs, but it is
    /// destructive for a write-time enqueue: a submission that happens to
    /// rediscover a pair the matcher already scored would replace the matcher's
    /// 9-feature blend with a raw cosine and erase the `features` payload an
    /// operator's ruling was based on. `ON CONFLICT DO NOTHING` makes this write
    /// path strictly additive — it either creates a fresh pending row or leaves
    /// the existing row byte-identical.
    ///
    /// `matcher_run_id`, `verifier_verdict` and `verifier_rationale` are absent
    /// from the column list on purpose, so they land NULL: this is not a matcher
    /// run, and a lexical heuristic is not a verdict. See
    /// `epigraph_engine::matching::verifier::is_unverified_write_time_scan` for
    /// the guard that stops a NULL verdict from being read as "corroborates".
    pub async fn insert_if_absent(
        &self,
        claim_a: Uuid,
        claim_b: Uuid,
        score: f32,
        features: serde_json::Value,
        status: &str,
    ) -> sqlx::Result<Option<Uuid>> {
        debug_assert!(claim_a < claim_b, "callers must pass canonical order");
        sqlx::query_scalar(
            "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (claim_a, claim_b) DO NOTHING
             RETURNING id",
        )
        .bind(claim_a)
        .bind(claim_b)
        .bind(score)
        .bind(Json(features))
        .bind(status)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn get(&self, id: Uuid) -> sqlx::Result<MatchCandidateRow> {
        sqlx::query_as("SELECT * FROM match_candidates WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
    }

    pub async fn set_status(&self, id: Uuid, status: &str, by: Option<Uuid>) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE match_candidates
             SET status = $2, decided_at = now(), decided_by = $3
             WHERE id = $1",
        )
        .bind(id)
        .bind(status)
        .bind(by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_pending(&self, limit: i64) -> sqlx::Result<Vec<MatchCandidateRow>> {
        sqlx::query_as(
            "SELECT * FROM match_candidates
             WHERE status = 'pending'
             ORDER BY score DESC
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Rows in any status, sorted by score desc, optionally filtered by status.
    pub async fn list(
        &self,
        status: Option<&str>,
        limit: i64,
    ) -> sqlx::Result<Vec<MatchCandidateRow>> {
        match status {
            Some(s) => {
                sqlx::query_as(
                    "SELECT * FROM match_candidates
                 WHERE status = $1
                 ORDER BY score DESC
                 LIMIT $2",
                )
                .bind(s)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as(
                    "SELECT * FROM match_candidates
                 ORDER BY score DESC
                 LIMIT $1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
        }
    }

    /// All rows where `claim_id` is either side of the pair. Used by the
    /// per-claim "find cross-source matches" API/MCP read paths.
    pub async fn list_for_claim(&self, claim_id: Uuid) -> sqlx::Result<Vec<MatchCandidateRow>> {
        sqlx::query_as(
            "SELECT * FROM match_candidates
             WHERE claim_a = $1 OR claim_b = $1
             ORDER BY score DESC",
        )
        .bind(claim_id)
        .fetch_all(&self.pool)
        .await
    }
}
