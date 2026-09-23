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

/// Result of [`MatchCandidateRepo::promote`] / [`MatchCandidateRepo::reject`].
///
/// Every refusal is an `Ok` variant rather than an error: each is an expected
/// outcome of a race the caller lost, and each surface maps it to its own
/// client-error shape (HTTP 409 / 400, MCP `invalid_params`). A `DbError` from
/// these methods is a genuine database failure, and it always means the
/// transaction rolled back — the row is still `pending` and no edge exists.
#[derive(Debug, Clone)]
pub enum DecisionOutcome {
    /// The row was `pending` under the lock and is now decided. Carries the row
    /// as committed, so the caller reports what THIS call did rather than a
    /// re-read that a later writer may already have moved.
    Decided(MatchCandidateRow),
    /// The row was not `pending` once locked. Nothing was written.
    AlreadyDecided { status: String },
    /// `promote` only: the row's `verifier_verdict` under the lock differs from
    /// the one the caller resolved the edge relationship from. Nothing was
    /// written — the relationship the caller passed may no longer be the one the
    /// verdict calls for.
    VerdictChanged { current: Option<String> },
    /// `promote` only: an endpoint was superseded, marked duplicate or removed
    /// between the caller's check and the lock. Nothing was written.
    ClaimsNotCurrent,
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
    /// the operator-decision writers ([`Self::promote`], [`Self::reject`],
    /// [`Self::retire`] and [`Self::set_status`]) are the only writers of
    /// `decided_at`, while the matcher itself writes `status = 'rejected'` with
    /// `decided_at` NULL. Keying on status would freeze matcher-set rejections
    /// forever and defeat re-scoring.
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

    /// Unconditionally overwrite a row's decision. NOT the decide path: it
    /// neither gates on `pending` nor writes an edge, so a promote built from it
    /// is exactly the two-statement shape [`Self::promote`] replaced. Kept for
    /// fixtures that need a decided row without the edge.
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

    /// Promote a `pending` candidate: flip it to `promoted` AND write its
    /// matcher edge, in ONE transaction, under the candidate's row lock.
    ///
    /// # Why one transaction
    ///
    /// The decide paths used to run `set_status` and
    /// `EdgeRepository::create_symmetric_if_absent` as two autocommit
    /// statements. A [`Self::retire`] that took the row lock between them saw
    /// `promoted` with no edge yet, retracted nothing, flipped the row to
    /// `stale` — and then the promote's INSERT landed, leaving a `stale` row
    /// with a live matcher edge whose derived factor kept biasing belief
    /// propagation. With both writes inside this transaction, `retire`'s
    /// `SELECT … FOR UPDATE` blocks until the edge is committed and therefore
    /// sees (and retracts) it. The same lock serialises two concurrent decides:
    /// the second blocks, then reads the first one's status and is refused.
    ///
    /// # Everything the edge says comes from the LOCKED row
    ///
    /// * `status` must be `pending`, else [`DecisionOutcome::AlreadyDecided`].
    ///   The unlocked read a caller does first is a fast path, not the gate.
    /// * `relationship` is resolved by the caller from `verifier_verdict`
    ///   (the mapping lives in `epigraph-engine`, which this crate cannot
    ///   depend on). `expected_verdict` is the verdict it resolved from; if the
    ///   locked row carries a different one — [`Self::upsert`] rewrites the
    ///   verdict of an undecided row — the call is refused with
    ///   [`DecisionOutcome::VerdictChanged`] rather than writing a polarity the
    ///   row no longer supports.
    /// * The edge `properties` (`score`, `features`, `verifier_verdict`) are
    ///   built here from the locked row, and the `"source":
    ///   "cross_source_matcher"` marker that migration 090's
    ///   `edges_symmetric_relationship_uniq` and [`Self::retire`] both key on
    ///   is stamped here, so no decide caller can omit it.
    ///
    /// # Current-ness, re-checked under lock
    ///
    /// Both endpoints are re-read `FOR SHARE`, which conflicts with the
    /// `UPDATE claims SET is_current = false` of a supersede or
    /// `mark_duplicate`, so an endpoint cannot be retired between this check
    /// and the edge commit ([`DecisionOutcome::ClaimsNotCurrent`]). This is
    /// ADDITIVE to the caller's viewer-scoped `ClaimRepository::are_all_current`
    /// check, never a replacement: this read carries no `Viewer` and so says
    /// nothing about whether the caller may see the claims. Lock order is
    /// candidate row, then claim rows; no writer takes them in the other order
    /// (nothing outside this repository writes `match_candidates`).
    ///
    /// A dedup hit on the edge (the `create_symmetric_if_absent` statement
    /// inserting zero rows, e.g. a reversed-duplicate candidate already linked
    /// the pair) is success. Any `Err` — the tenancy trigger's RAISE,
    /// `edges_validate_refs`, a CHECK — rolls the status flip back with it.
    pub async fn promote(
        &self,
        id: Uuid,
        by: Option<Uuid>,
        expected_verdict: Option<&str>,
        relationship: &str,
    ) -> Result<DecisionOutcome, crate::errors::DbError> {
        let mut tx = self.pool.begin().await?;

        let locked: MatchCandidateRow =
            sqlx::query_as("SELECT * FROM match_candidates WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        if locked.status != "pending" {
            return Ok(DecisionOutcome::AlreadyDecided {
                status: locked.status,
            });
        }
        if locked.verifier_verdict.as_deref() != expected_verdict {
            return Ok(DecisionOutcome::VerdictChanged {
                current: locked.verifier_verdict,
            });
        }

        let endpoints = [locked.claim_a, locked.claim_b];
        let live: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM claims
             WHERE id = ANY($1) AND COALESCE(is_current, true) = true
             FOR SHARE",
        )
        .bind(&endpoints[..])
        .fetch_all(&mut *tx)
        .await?;
        let distinct: std::collections::HashSet<&Uuid> = endpoints.iter().collect();
        if live.len() != distinct.len() {
            return Ok(DecisionOutcome::ClaimsNotCurrent);
        }

        // `AND status = 'pending'` is redundant under the lock taken above; it
        // is kept so the gate is also in the statement that writes.
        let decided: MatchCandidateRow = sqlx::query_as(
            "UPDATE match_candidates
             SET status = 'promoted', decided_at = now(), decided_by = $2
             WHERE id = $1 AND status = 'pending'
             RETURNING *",
        )
        .bind(id)
        .bind(by)
        .fetch_one(&mut *tx)
        .await?;

        let props = serde_json::json!({
            "candidate_id":     id,
            "score":            decided.score,
            "features":         decided.features,
            "verifier_verdict": decided.verifier_verdict,
            "decided_by":       by,
            "source":           "cross_source_matcher",
        });
        // The same statement `EdgeRepository::create_symmetric_if_absent`
        // runs, executed on this transaction. Zero rows is a dedup hit, not an
        // error; see this method's doc.
        crate::repos::edge::EdgeRepository::symmetric_insert_if_absent(
            decided.claim_a,
            decided.claim_b,
            relationship,
            props,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(DecisionOutcome::Decided(decided))
    }

    /// Reject a `pending` candidate under the same row lock as
    /// [`Self::promote`], so a reject cannot overwrite a promotion (or a
    /// retirement) that committed after the caller's unlocked read — that is
    /// the state that leaves a matcher edge in force under a `rejected` row.
    /// Returns [`DecisionOutcome::Decided`] or
    /// [`DecisionOutcome::AlreadyDecided`]; the other variants are
    /// promote-only.
    pub async fn reject(&self, id: Uuid, by: Option<Uuid>) -> sqlx::Result<DecisionOutcome> {
        let mut tx = self.pool.begin().await?;

        let status: String =
            sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        if status != "pending" {
            return Ok(DecisionOutcome::AlreadyDecided { status });
        }

        let decided: MatchCandidateRow = sqlx::query_as(
            "UPDATE match_candidates
             SET status = 'rejected', decided_at = now(), decided_by = $2
             WHERE id = $1 AND status = 'pending'
             RETURNING *",
        )
        .bind(id)
        .bind(by)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(DecisionOutcome::Decided(decided))
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
        // decide on the same row — in EITHER order — and against a concurrent
        // retire of the same row.
        //
        // The in-flight-promote window this comment used to record as a known
        // limit is DISCHARGED (deferred-commitment key
        // match-candidate-promote-tx): `Self::promote` now writes the status
        // flip and the matcher edge in one transaction under this same row
        // lock, so a promote that has flipped the status still holds the lock
        // until its edge is committed. This SELECT therefore blocks until then
        // and the edge SELECT below sees the edge it has to retract.
        // Pinned by `match_candidate_repo.rs::
        // retire_waits_for_an_in_flight_promote_and_retracts_its_edge`.
        let (claim_a, claim_b, previous_status): (Uuid, Uuid, String) = sqlx::query_as(
            "SELECT claim_a, claim_b, status FROM match_candidates
             WHERE id = $1
             FOR UPDATE",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

        // Capture the full rows, not just their ids: this SELECT is the undo
        // snapshot (see `RetirementOutcome::retracted_edges`).
        let retracted_edges: Vec<RetiredEdge> = sqlx::query_as(
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

        let edge_ids: Vec<Uuid> = retracted_edges.iter().map(|e| e.edge_id).collect();

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

        // RETRACT, do not DELETE. The edge is a primary epistemic record — the
        // assertion "the matcher claimed these two claims match, and someone
        // promoted it" — carrying `properties.decided_by`, the signature and the
        // content hash. A DELETE here destroys who made the original promotion,
        // because `match_candidates.decided_by` is overwritten with the RETIRER
        // twenty lines below; nothing persisted would record the promoter.
        //
        // Closing `valid_to` removes the edge from every reader that honours
        // `EDGE_IN_FORCE` (the derivation selector and the auto-wire guard) while
        // keeping the row queryable and the retirement reversible. The derived rows
        // above — bp_messages, factors, mass_functions — are still deleted: those
        // are materializations (factors come from the `edges_auto_factor` trigger,
        // BBAs are keyed `perspective_id = edge_id`), so removing them is cache
        // invalidation and they regenerate from live edges.
        //
        // `AND valid_to IS NULL` makes this idempotent: retiring twice does not
        // advance an existing retraction's timestamp.
        let edges_retracted = sqlx::query(
            "UPDATE edges SET valid_to = now() WHERE id = ANY($1) AND valid_to IS NULL",
        )
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
            edges_retracted,
            factors_deleted,
            bp_messages_deleted,
            bbas_invalidated,
            retracted_edges,
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
             WHERE e.relationship = 'CORROBORATES'
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
