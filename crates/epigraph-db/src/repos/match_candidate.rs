//! Repository for `match_candidates` (cross-source matcher review queue).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::edge::EdgeRepository;

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

/// Outcome of a conditional decide ([`MatchCandidateRepo::promote_if_pending`],
/// [`MatchCandidateRepo::reject_if_pending`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecideOutcome {
    /// The candidate was `pending` and is now decided.
    Decided,
    /// The candidate was no longer `pending` when the write ran: decided by a
    /// concurrent caller after this one read it. Nothing was written.
    /// `status` is the candidate's status as read after the refused write.
    AlreadyDecided { status: String },
    /// Promote only: the candidate is still `pending`, but its
    /// `verifier_verdict` is no longer the one the caller resolved the edge's
    /// polarity from (a matcher re-score landed in between). Nothing was
    /// written. `verdict` is the candidate's verdict as read after the refused
    /// write.
    VerdictChanged { verdict: Option<String> },
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
    pub edges_retracted: u64,
    pub factors_deleted: u64,
    pub bp_messages_deleted: u64,
    /// Edge-keyed BBAs removed. Structurally 0 on today's promote path — see
    /// [`MatchCandidateRepo::retire`] for why the statement runs anyway.
    pub bbas_invalidated: u64,
    /// The retracted edges, captured before `valid_to` was closed.
    ///
    /// Retained as a convenience snapshot, NOT as an undo record — retraction is
    /// reversible and the rows survive, so the authoritative record is now the
    /// `edges` table itself (`SELECT ... WHERE valid_to IS NOT NULL`). Before the
    /// switch from DELETE this field was load-bearing, because the promotion's
    /// provenance (`candidate_id`, `score`, `features`, `verifier_verdict`,
    /// `decided_by`) existed nowhere else afterwards.
    pub retracted_edges: Vec<RetiredEdge>,
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
    /// only the decide and retire writers ([`Self::set_status`],
    /// [`Self::promote_if_pending`], [`Self::reject_if_pending`] and the
    /// retirement's `mark_retired_on`) write `decided_at`, while the matcher
    /// itself writes `status = 'rejected'` with `decided_at` NULL. Keying on status would
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
    /// A re-score of a still-`pending` row can still land between a promote's
    /// read and its write; [`Self::promote_if_pending`] is conditional on the
    /// verdict the promote read, so that promote is refused
    /// ([`DecideOutcome::VerdictChanged`]) rather than writing an edge whose
    /// polarity the row no longer supports.
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

    /// Reject a candidate only if it is still `pending`: the conditional
    /// write behind the `reject` arm of both decide transports
    /// (`epigraph-mcp` `tools/matching.rs::decide_match_candidate`,
    /// `epigraph-api` `routes/cross_source.rs::decide_candidate`).
    ///
    /// The callers' early "already decided" check reads the row and gates on
    /// the in-memory status, so two concurrent decides can both pass it. The
    /// `AND status = 'pending'` here is what decides the race: under READ
    /// COMMITTED an UPDATE that waited on a concurrent writer's row lock
    /// re-evaluates its WHERE against the committed version, so the loser
    /// matches no row and is refused rather than overwriting a promotion and
    /// orphaning its matcher edge (backlog b3f95bea's end state).
    ///
    /// Not [`Self::set_status`], which stays unconditional: other writers
    /// (and migration 118's MC01 lockdown test) rely on it writing any status.
    ///
    /// # Errors
    /// The query's error; a candidate that does not exist is `RowNotFound`.
    pub async fn reject_if_pending(
        &self,
        id: Uuid,
        by: Option<Uuid>,
    ) -> Result<DecideOutcome, DbError> {
        let mut conn = self.pool.acquire().await?;
        let rejected = sqlx::query(
            "UPDATE match_candidates
             SET status = 'rejected', decided_at = now(), decided_by = $2
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(id)
        .bind(by)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if rejected == 1 {
            return Ok(DecideOutcome::Decided);
        }
        let (status, _) = current_decision(&mut conn, id).await?;
        Ok(DecideOutcome::AlreadyDecided { status })
    }

    /// Promote a candidate only if it is still `pending`, and write its
    /// matcher edge on the SAME transaction as the status flip.
    ///
    /// Two windows close here, both of which leave a matcher edge that no
    /// candidate decision accounts for:
    ///
    /// - **A concurrent reject.** The flip is conditional on `pending`, exactly
    ///   as in [`Self::reject_if_pending`], so whichever decide commits second
    ///   matches no row and is refused.
    /// - **A concurrent retirement.** The candidate's row lock, taken by the
    ///   flip, is held until the edge INSERT commits, so `mark_retired_on`'s
    ///   `SELECT ... FOR UPDATE` waits for the promotion to finish and then
    ///   retracts its edge. With the two as separate autocommit statements a
    ///   committed `promoted` with its edge still in flight let the retirement
    ///   run first and the edge land afterwards under a `stale` row.
    ///
    /// - **A concurrent verdict re-score.** The caller resolved `relationship`
    ///   from the `verifier_verdict` it read (`read_verdict`), and
    ///   [`Self::upsert`] may rewrite the verdict of a row that is still
    ///   `pending`. The flip is also conditional on the verdict being
    ///   `read_verdict` (`IS NOT DISTINCT FROM`, so a NULL verdict compares
    ///   equal to NULL); otherwise the promote is refused with
    ///   [`DecideOutcome::VerdictChanged`] instead of recording a polarity the
    ///   row no longer supports.
    ///
    /// The claim pair comes from the row the flip updated (`RETURNING`), not
    /// from the caller. The edge is written by
    /// [`EdgeRepository::create_symmetric_if_absent_conn`], the same INSERT
    /// the promote paths always ran, any-state dedup included. On
    /// `AlreadyDecided` or `VerdictChanged` nothing is written (the
    /// transaction rolls back).
    ///
    /// # Errors
    /// The query's error; a candidate that does not exist is `RowNotFound`.
    pub async fn promote_if_pending(
        &self,
        id: Uuid,
        by: Option<Uuid>,
        read_verdict: Option<&str>,
        relationship: &str,
        properties: serde_json::Value,
    ) -> Result<DecideOutcome, DbError> {
        use sqlx::Acquire;
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let pair: Option<(Uuid, Uuid)> = sqlx::query_as(
            "UPDATE match_candidates
             SET status = 'promoted', decided_at = now(), decided_by = $2
             WHERE id = $1 AND status = 'pending'
               AND verifier_verdict IS NOT DISTINCT FROM $3
             RETURNING claim_a, claim_b",
        )
        .bind(id)
        .bind(by)
        .bind(read_verdict)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((claim_a, claim_b)) = pair else {
            drop(tx);
            let (status, verdict) = current_decision(&mut conn, id).await?;
            if status == "pending" {
                return Ok(DecideOutcome::VerdictChanged { verdict });
            }
            return Ok(DecideOutcome::AlreadyDecided { status });
        };
        EdgeRepository::create_symmetric_if_absent_conn(
            &mut tx,
            claim_a,
            claim_b,
            relationship,
            properties,
        )
        .await?;
        tx.commit().await?;
        Ok(DecideOutcome::Decided)
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
    ///
    /// # Migrations 117 and 118: an administrative act, on a privileged session
    ///
    /// Retirement is administrative end to end. Its cascade retracts a matcher
    /// edge that, between two public claims, nobody owns (117), and its act,
    /// the flip to `stale`, is refused on a non-privileged session by 118's
    /// `match_candidates_stale_guard` (MC01). So the flip and the cascade run
    /// together, in ONE transaction, on a privileged (maintenance) session:
    /// this method on a pool, [`Self::retire_conn`] on a connection. A request
    /// path with no maintenance connection records the retirement as a
    /// deferred request instead and leaves the candidate untouched
    /// (`epigraph_engine::admin_cascade`).
    pub async fn retire(&self, id: Uuid, by: Option<Uuid>) -> sqlx::Result<RetirementOutcome> {
        let mut conn = self.pool.acquire().await?;
        Self::retire_conn(&mut conn, id, by, None).await
    }

    /// [`Self::retire`] on a connection the caller owns: the maintenance
    /// connection of a request path, or of the operator's replay.
    ///
    /// `expected_status`, when given, is the status the candidate had when the
    /// retirement was requested. The retirement goes ahead only if the
    /// candidate still has that status (or is already `stale`, when the flip is
    /// idempotent); otherwise the candidate was decided again in between, and
    /// retiring it would withdraw a decision the requester never saw. The
    /// refusal is loud and nothing is written.
    ///
    /// # Errors
    /// A protocol error on a non-privileged session, or when the candidate's
    /// status is no longer `expected_status`; the query's error otherwise (a
    /// missing candidate is `RowNotFound`).
    pub async fn retire_conn(
        conn: &mut sqlx::PgConnection,
        id: Uuid,
        by: Option<Uuid>,
        expected_status: Option<&str>,
    ) -> sqlx::Result<RetirementOutcome> {
        use sqlx::Acquire;
        let mut tx = conn.begin().await?;
        require_privileged(&mut tx, "MatchCandidateRepo::retire_conn").await?;
        let previous_status = mark_retired_on(&mut tx, id, by, expected_status).await?;
        let mut outcome = retract_candidate_edges(&mut tx, id).await?;
        tx.commit().await?;
        outcome.previous_status = previous_status;
        Ok(outcome)
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
    ///
    /// # Tenancy (PR-09)
    ///
    /// `match_candidates` is **not** in migration 062's `tier_a` array, so it
    /// carries no `visibility` / `owner_group_id` of its own. Visibility is
    /// therefore derived from the pair it names: a row is returned only when the
    /// viewer can read **both** `claim_a` and `claim_b`. Deriving from one side
    /// would leak the other's id, and the row's `verifier_rationale` is free
    /// text written from both claims' content — it is the leakiest column in the
    /// table, not an identifier.
    ///
    /// Both joins are INNER, so a candidate naming a claim the viewer cannot see
    /// is absent rather than partially rendered (§8.5's existence-oracle rule).
    pub async fn list(
        &self,
        viewer: &crate::visibility::Viewer,
        status: Option<&str>,
        limit: i64,
    ) -> sqlx::Result<Vec<MatchCandidateRow>> {
        match status {
            Some(s) => {
                let sql = viewer.splice(
                    "SELECT mc.* FROM match_candidates mc
                     JOIN claims ca ON ca.id = mc.claim_a
                     JOIN claims cb ON cb.id = mc.claim_b
                     WHERE mc.status = $1 /* {VISIBILITY:ca} */ /* {VISIBILITY:cb} */
                     ORDER BY mc.score DESC
                     LIMIT $2",
                    3,
                );
                let mut q = sqlx::query_as(&sql).bind(s).bind(limit);
                if let Some(g) = viewer.group_bind() {
                    q = q.bind(g);
                }
                q.fetch_all(&self.pool).await
            }
            None => {
                let sql = viewer.splice(
                    "SELECT mc.* FROM match_candidates mc
                     JOIN claims ca ON ca.id = mc.claim_a
                     JOIN claims cb ON cb.id = mc.claim_b
                     WHERE true /* {VISIBILITY:ca} */ /* {VISIBILITY:cb} */
                     ORDER BY mc.score DESC
                     LIMIT $1",
                    2,
                );
                let mut q = sqlx::query_as(&sql).bind(limit);
                if let Some(g) = viewer.group_bind() {
                    q = q.bind(g);
                }
                q.fetch_all(&self.pool).await
            }
        }
    }

    /// All rows where `claim_id` is either side of the pair. Used by the
    /// per-claim "find cross-source matches" API/MCP read paths.
    ///
    /// Same both-sides-visible rule as [`Self::list`]; see its doc.
    pub async fn list_for_claim(
        &self,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> sqlx::Result<Vec<MatchCandidateRow>> {
        let sql = viewer.splice(
            "SELECT mc.* FROM match_candidates mc
             JOIN claims ca ON ca.id = mc.claim_a
             JOIN claims cb ON cb.id = mc.claim_b
             WHERE (mc.claim_a = $1 OR mc.claim_b = $1)
               /* {VISIBILITY:ca} */ /* {VISIBILITY:cb} */
             ORDER BY mc.score DESC",
            2,
        );
        let mut q = sqlx::query_as(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_all(&self.pool).await
    }

    /// Cross-source **sweep coverage** for one claim: the value of
    /// `claims.last_match_scan_at` (migration `037`), which
    /// `epigraph-cli/src/bin/cross_source_sweep.rs` stamps over every seed it
    /// scans.
    ///
    /// # Why this lives here
    ///
    /// It reads `claims`, not `match_candidates`, but it is the third leg of
    /// the same per-claim read as [`Self::list_for_claim`] and
    /// [`Self::corroborates_edges_for_claim`] — the cross-source match view of
    /// a claim — and [`Self::corroborates_edges_for_claim`] already sets the
    /// precedent of querying another table from this repo. Putting it on
    /// `ClaimRepository` instead would mean widening a claim row struct, which
    /// `claim_from_row`'s ~20 callers make a much larger change than this is.
    ///
    /// # Three-state return
    ///
    /// `Option<Option<_>>` on purpose; flattening loses the distinction the
    /// caller exists to make.
    ///
    /// - `Ok(None)` — **no row this viewer may read**. Either the claim does
    ///   not exist or it is not visible. The caller must report NOTHING about
    ///   sweep coverage in this case: saying "never swept" about a row the
    ///   viewer has no right to read is both a false statement (it may well
    ///   have been swept) and an assertion about the existence of that row.
    /// - `Ok(Some(None))` — visible, and `last_match_scan_at IS NULL`: the
    ///   matcher has never scanned this claim. An empty candidate list here
    ///   means "not looked at yet", not "looked at and found nothing".
    /// - `Ok(Some(Some(ts)))` — visible, last scanned at `ts`.
    ///
    /// # Tenancy
    ///
    /// Same `{VISIBILITY:…}` predicate every other claim read on this branch
    /// carries. A timestamp is a small datum, but "was this id scanned" is
    /// still an existence oracle over `claims`.
    pub async fn last_match_scan_at(
        &self,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> sqlx::Result<Option<Option<DateTime<Utc>>>> {
        let sql = viewer.splice(
            "SELECT c.last_match_scan_at FROM claims c
             WHERE c.id = $1 /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_optional(&self.pool).await
    }

    /// `CORROBORATES` edges incident on `claim_id` — the already-promoted half
    /// of a cross-source match read.
    ///
    /// # Tenancy (PR-09)
    ///
    /// This SQL previously lived inline in **two** places —
    /// `epigraph-mcp/src/tools/matching.rs::find_cross_source_matches` and
    /// `epigraph-api/src/routes/cross_source.rs::get_cross_source_matches` —
    /// duplicated, unfiltered, and returning the id of the claim on the far end
    /// of every edge. It is one function now, which is what CLAUDE.md's
    /// "do not duplicate SQL between them" asks for, and it filters.
    ///
    /// The predicate is on `edges` (`Viewer::edge_predicate_fragment`, the
    /// co-ownership INTERSECTION, since PR-13 created the column it names)
    /// **and** on the far-side claim. The edge
    /// predicate alone is not enough: `edges.owner_group_id` today defaults to
    /// the world group for every pre-062 row, so a public edge would still hand
    /// back a private claim's id.
    pub async fn corroborates_edges_for_claim(
        &self,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> sqlx::Result<Vec<(Uuid, Uuid, Uuid, serde_json::Value)>> {
        let sql = viewer.splice(
            "SELECT e.id, e.source_id, e.target_id, e.properties
             FROM edges e
             JOIN claims far
               ON far.id = CASE WHEN e.source_id = $1 THEN e.target_id ELSE e.source_id END
             WHERE e.relationship IN ('CORROBORATES', 'corroborates')
               AND (e.source_id = $1 OR e.target_id = $1)
               /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:far} */",
            2,
        );
        let mut q = sqlx::query_as(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_all(&self.pool).await
    }
}

/// The candidate's committed status and verdict, read after a conditional
/// decide matched no row: for the refusal's message, and to tell a promote
/// that lost to a decision from one that lost to a verdict re-score.
async fn current_decision(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
) -> sqlx::Result<(String, Option<String>)> {
    sqlx::query_as("SELECT status, verifier_verdict FROM match_candidates WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *conn)
        .await
}

/// Refuse a non-privileged session (migration 114's
/// `epigraph_session_is_privileged_writer()`), naming the caller.
async fn require_privileged(conn: &mut sqlx::PgConnection, what: &str) -> sqlx::Result<()> {
    let privileged: bool =
        sqlx::query_scalar("SELECT public.epigraph_session_is_privileged_writer()")
            .fetch_one(&mut *conn)
            .await?;
    if privileged {
        return Ok(());
    }
    Err(sqlx::Error::Protocol(format!(
        "{what} runs only on a privileged (maintenance) connection: a promoted matcher edge \
         between two public claims is owned by nobody (migration 117), and the flip to \
         `stale` is an administrative act (migration 118)"
    )))
}

/// The act of [`MatchCandidateRepo::retire_conn`]: row-lock the candidate,
/// check it still has `expected_status` (when given), flip it to `stale`, and
/// return its previous status.
///
/// The row lock serialises retirement against a concurrent decide and against
/// a concurrent retire of the same row. A decide's write is
/// [`MatchCandidateRepo::promote_if_pending`] / `reject_if_pending`: a decide
/// that arrives after this lock waits for it, re-reads the row as `stale` and
/// is refused. A promote already in flight holds the row lock from its status
/// flip until its edge INSERT commits (one transaction), so this `FOR UPDATE`
/// waits for it, reads `promoted`, and the cascade below retracts the edge it
/// wrote. (Before `promote_if_pending`, the flip and the INSERT were two
/// autocommit statements and a retirement could run between them, leaving the
/// row `stale` with a live matcher edge.)
///
/// The flip is checked (`rows_affected == 1`): on a privileged session nothing
/// filters the row, so a flip that changed nothing means the row vanished
/// under the lock, and the retirement must not report success.
async fn mark_retired_on(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    by: Option<Uuid>,
    expected_status: Option<&str>,
) -> sqlx::Result<String> {
    let previous_status: String =
        sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    if let Some(expected) = expected_status {
        if previous_status != expected && previous_status != "stale" {
            return Err(sqlx::Error::Protocol(format!(
                "match candidate {id} was {expected} when its retirement was requested and is \
                 {previous_status} now: it was decided again in between, so the request is not \
                 carried out; nothing was changed"
            )));
        }
    }
    let flipped = sqlx::query(
        "UPDATE match_candidates
         SET status = 'stale', decided_at = now(), decided_by = $2
         WHERE id = $1",
    )
    .bind(id)
    .bind(by)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if flipped != 1 {
        return Err(sqlx::Error::Protocol(format!(
            "match candidate {id}: the flip to stale changed {flipped} rows, not 1; nothing was \
             retired"
        )));
    }
    Ok(previous_status)
}

/// The cascade of [`MatchCandidateRepo::retire`], unchecked: the callers
/// establish the privilege and own the transaction. `previous_status` is left
/// empty for the caller to fill.
///
/// Edges are matched by **claim pair + the `properties->>'source' =
/// 'cross_source_matcher'` marker**, not by `relationship` (a `contradicts`
/// promotion is equally retirable) and not by `candidate_id` (reversed-duplicate
/// candidates share a single edge stamped with only one of their ids).
async fn retract_candidate_edges(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
) -> sqlx::Result<RetirementOutcome> {
    let (claim_a, claim_b): (Uuid, Uuid) =
        sqlx::query_as("SELECT claim_a, claim_b FROM match_candidates WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;

    // Capture the full rows, not just their ids: this SELECT is the snapshot
    // (see `RetirementOutcome::retracted_edges`).
    let retracted_edges: Vec<RetiredEdge> = sqlx::query_as(
        "SELECT id AS edge_id, source_id, target_id, relationship, properties, created_at
         FROM edges
         WHERE ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))
           AND properties->>'source' = 'cross_source_matcher'",
    )
    .bind(claim_a)
    .bind(claim_b)
    .fetch_all(&mut *conn)
    .await?;

    let edge_ids: Vec<Uuid> = retracted_edges.iter().map(|e| e.edge_id).collect();

    // `factors.properties->>'source_edge_id'` is text (the trigger builds it
    // with `jsonb_build_object('source_edge_id', NEW.id)`), so compare against
    // the text form of the ids.
    let edge_id_texts: Vec<String> = edge_ids.iter().map(Uuid::to_string).collect();

    let bp_messages_deleted = sqlx::query(
        "DELETE FROM bp_messages WHERE factor_id IN
         (SELECT id FROM factors WHERE properties->>'source_edge_id' = ANY($1))",
    )
    .bind(&edge_id_texts)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    let factors_deleted =
        sqlx::query("DELETE FROM factors WHERE properties->>'source_edge_id' = ANY($1)")
            .bind(&edge_id_texts)
            .execute(&mut *conn)
            .await?
            .rows_affected();

    // RETRACT, do not DELETE. The edge is a primary epistemic record -- the
    // assertion "the matcher claimed these two claims match, and someone
    // promoted it" -- carrying `properties.decided_by`, the signature and the
    // content hash. Closing `valid_to` removes the edge from every reader that
    // honours `EDGE_IN_FORCE` while keeping the row queryable and the
    // retirement reversible. The derived rows -- bp_messages and factors above,
    // mass_functions below -- are materializations, so removing them is cache
    // invalidation and they regenerate from live edges.
    //
    // `AND valid_to IS NULL` makes this idempotent: retiring twice does not
    // advance an existing retraction's timestamp.
    let edges_retracted =
        sqlx::query("UPDATE edges SET valid_to = now() WHERE id = ANY($1) AND valid_to IS NULL")
            .bind(&edge_ids)
            .execute(&mut *conn)
            .await?
            .rows_affected();

    // The edge-keyed BBAs, routinely somebody else's rows (the writer who
    // wired the edge, or the target claim's group). This runs on a privileged
    // session, so `delete_edge_bbas` is the plain statement (migration 117).
    let bbas_invalidated = crate::repos::mass_function::delete_edge_bbas(
        &mut *conn,
        &edge_ids,
        crate::repos::mass_function::EdgeBbaCascade::MatchCandidateRetire,
    )
    .await?;

    Ok(RetirementOutcome {
        previous_status: String::new(),
        affected_claims: vec![claim_a, claim_b],
        edges_retracted,
        factors_deleted,
        bp_messages_deleted,
        bbas_invalidated,
        retracted_edges,
    })
}
