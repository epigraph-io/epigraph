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

/// What [`MatchCandidateRepo::retire`] actually removed.
///
/// Every count is reported rather than summed into one number so a caller can
/// tell "there was no promotion to undo" (all zero) from "the edge went but its
/// factor was already gone" — the two look identical if only the edge count is
/// surfaced, and the second is the orphan-factor state this method exists to
/// prevent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetirementOutcome {
    /// The candidate's status before the retirement flipped it to `stale`.
    pub previous_status: String,
    /// Both endpoints of the retired pair, for the caller's follow-up.
    pub affected_claims: Vec<Uuid>,
    pub edges_retired: u64,
    pub factors_deleted: u64,
    pub bp_messages_deleted: u64,
    /// Edge-keyed BBAs removed. Structurally 0 on today's promote path — see
    /// [`MatchCandidateRepo::retire`] for why the statement runs anyway.
    pub bbas_invalidated: u64,
    /// The deleted edges, captured before the DELETE. This is the **undo
    /// record**, and it is why the outcome is not just counts: the edge's
    /// `properties` carry the promotion's whole provenance (`candidate_id`,
    /// `score`, `features`, `verifier_verdict`, `decided_by`) and the delete is
    /// irreversible. The `retire_match_candidates` operator binary writes the
    /// same thing to its `--dump` file for exactly this reason; without it the
    /// online path would silently be the lossier of the two.
    pub deleted_edges: Vec<RetiredEdge>,
}

/// One matcher edge as it existed immediately before
/// [`MatchCandidateRepo::retire`] deleted it — enough to reconstruct the row.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RetiredEdge {
    pub edge_id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub relationship: String,
    pub properties: serde_json::Value,
    pub created_at: DateTime<Utc>,
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

    /// Retract a candidate's promotion: delete every matcher-created edge
    /// between its claim pair together with the derived records that hang off
    /// those edges, then flip the row to `stale`. One transaction.
    ///
    /// # Why this is not `set_status(id, "stale", by)`
    ///
    /// The `edges_auto_factor` AFTER INSERT trigger (migration
    /// `001_initial_schema.sql`, matcher-score strength added in `038`)
    /// derives a `factors` row from every claim→claim edge, keyed
    /// `properties->>'source_edge_id'`, and there is **no** delete trigger. So
    /// dropping the edge alone leaves the factor — and its `bp_messages` —
    /// corroborating in the belief graph permanently. This mirrors the proven
    /// cull order of migration `012_cull_low_similarity_corroborates`:
    /// `bp_messages` → `factors` → `edges`, all keyed by `source_edge_id`.
    ///
    /// `mass_functions` keyed `perspective_id = <edge id>` are deleted too.
    /// The promote paths
    /// (`epigraph-api/src/routes/cross_source.rs::decide_candidate`,
    /// `epigraph-mcp/src/tools/matching.rs::decide_match_candidate`) call
    /// `EdgeRepository::create_symmetric_if_absent` and never
    /// `auto_wire_edge_if_epistemic`, so today that count is 0 — but
    /// `epigraph-engine/src/retraction_cascade.rs` documents why leaving one
    /// behind is unrecoverable: `auto_wire_edge_if_epistemic` short-circuits on
    /// `exists_for_perspective`, so a stale BBA makes any future re-wire of a
    /// re-promoted pair a permanent no-op, and recompute cannot remove it
    /// because the combine path reads `mass_functions.masses` verbatim.
    /// Deleting zero rows is free; omitting the statement would make this
    /// method correct only by accident of the current promote path.
    ///
    /// # Scoping
    ///
    /// Edges are matched by **claim pair + the
    /// `properties->>'source' = 'cross_source_matcher'` marker**, not by
    /// `relationship` (a `contradicts` promotion is equally retirable) and not
    /// by `candidate_id` (reversed-duplicate candidates share a single edge
    /// stamped with only one of their ids). Same scoping the
    /// `retire_match_candidates` operator binary uses.
    ///
    /// # Status
    ///
    /// Writes `stale`, the fourth value of the
    /// `match_candidates_status_valid` CHECK (migration `036`), and the value
    /// the CLI already writes. `verifier_verdict` / `verifier_rationale` are
    /// deliberately left intact: they record what the *verifier* found, not
    /// what the operator decided, and overwriting the rationale alone would
    /// leave a row whose rationale contradicts the verdict beside it — the
    /// exact inconsistency [`Self::upsert`]'s paired guard exists to prevent.
    /// Attribution of the retirement lives in `decided_by` / `decided_at`.
    ///
    /// Tolerates any starting status (the CLI does the same): a candidate that
    /// is `pending`, `rejected` or already `stale` simply has no matcher edge
    /// to delete, and the flip to `stale` is idempotent.
    pub async fn retire(&self, id: Uuid, by: Option<Uuid>) -> sqlx::Result<RetirementOutcome> {
        let mut tx = self.pool.begin().await?;

        // Row-lock the candidate. This serialises retirement against a
        // *subsequent* decide — that path's first write is `set_status`, which
        // blocks here — and against a concurrent retire of the same row.
        //
        // It does NOT close the window against a promote already in flight:
        // `decide_candidate`'s promote arm runs `set_status` and
        // `create_symmetric_if_absent` as two separate statements in two
        // implicit transactions, so one that has already committed
        // `set_status` and is mid-INSERT is not held by this lock. Its edge is
        // invisible to the SELECT below and survives the retirement, leaving
        // the row `stale` with a live matcher edge. Retiring again cleans it
        // up. Making that impossible means folding the promote arm's two
        // statements into one transaction, which is a change to the promote
        // path, not to this one.
        let (claim_a, claim_b, previous_status): (Uuid, Uuid, String) = sqlx::query_as(
            "SELECT claim_a, claim_b, status FROM match_candidates
             WHERE id = $1
             FOR UPDATE",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

        // Capture the full rows, not just their ids: this SELECT is the undo
        // record (see `RetirementOutcome::deleted_edges`).
        let deleted_edges: Vec<RetiredEdge> = sqlx::query_as(
            "SELECT id AS edge_id, source_id, target_id, relationship, properties, created_at
             FROM edges
             WHERE ((source_id = $1 AND target_id = $2)
                 OR (source_id = $2 AND target_id = $1))
               AND properties->>'source' = 'cross_source_matcher'",
        )
        .bind(claim_a)
        .bind(claim_b)
        .fetch_all(&mut *tx)
        .await?;

        let edge_ids: Vec<Uuid> = deleted_edges.iter().map(|e| e.edge_id).collect();

        // `factors.properties->>'source_edge_id'` is text (the trigger builds
        // it with `jsonb_build_object('source_edge_id', NEW.id)`), so compare
        // against the text form of the ids.
        let edge_id_texts: Vec<String> = edge_ids.iter().map(Uuid::to_string).collect();

        let bp_messages_deleted = sqlx::query(
            "DELETE FROM bp_messages WHERE factor_id IN
             (SELECT id FROM factors WHERE properties->>'source_edge_id' = ANY($1))",
        )
        .bind(&edge_id_texts)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        let factors_deleted =
            sqlx::query("DELETE FROM factors WHERE properties->>'source_edge_id' = ANY($1)")
                .bind(&edge_id_texts)
                .execute(&mut *tx)
                .await?
                .rows_affected();

        let bbas_invalidated =
            sqlx::query("DELETE FROM mass_functions WHERE perspective_id = ANY($1)")
                .bind(&edge_ids)
                .execute(&mut *tx)
                .await?
                .rows_affected();

        let edges_retired = sqlx::query("DELETE FROM edges WHERE id = ANY($1)")
            .bind(&edge_ids)
            .execute(&mut *tx)
            .await?
            .rows_affected();

        sqlx::query(
            "UPDATE match_candidates
             SET status = 'stale', decided_at = now(), decided_by = $2
             WHERE id = $1",
        )
        .bind(id)
        .bind(by)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(RetirementOutcome {
            previous_status,
            affected_claims: vec![claim_a, claim_b],
            edges_retired,
            factors_deleted,
            bp_messages_deleted,
            bbas_invalidated,
            deleted_edges,
        })
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
